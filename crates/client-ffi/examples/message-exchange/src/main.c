/*
 * message-exchange: Saro-Raya message exchange written entirely in C.
 *
 * Demonstrates that the client-ffi C API is straightforward to consume
 * directly — no Rust glue required.  Build with the provided Makefile.
 */

#include "client_ffi.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------
 * Convenience macros for building slice_ref_uint8_t values.
 * SLICE(p, n) — arbitrary pointer + length.
 * STR(s)      — string literal (length computed at compile time).
 * ------------------------------------------------------------------ */

#define SLICE(p, n) ((slice_ref_uint8_t){ .ptr = (const uint8_t *)(p), .len = (n) })
#define STR(s)      SLICE(s, sizeof(s) - 1)

/* ------------------------------------------------------------------
 * In-memory delivery bus (shared by all clients, like InProcessDelivery)
 * ------------------------------------------------------------------ */

#define MAX_ENVELOPES   32
#define MAX_ENVELOPE_SZ 2048

typedef struct {
    uint8_t data[MAX_ENVELOPE_SZ];
    size_t  len;
} Envelope;

typedef struct {
    Envelope items[MAX_ENVELOPES];
    int      head;
    int      tail;
    int      count;
} Queue;

static Queue bus;

static void queue_init(Queue *q)
{
    memset(q, 0, sizeof(*q));
}

static void queue_push(Queue *q, const uint8_t *data, size_t len)
{
    assert(q->count < MAX_ENVELOPES && "delivery queue overflow");
    assert(len <= MAX_ENVELOPE_SZ  && "envelope too large");
    memcpy(q->items[q->tail].data, data, len);
    q->items[q->tail].len = len;
    q->tail  = (q->tail + 1) % MAX_ENVELOPES;
    q->count++;
}

static int queue_pop(Queue *q, const uint8_t **data_out, size_t *len_out)
{
    if (q->count == 0) return 0;
    *data_out = q->items[q->head].data;
    *len_out  = q->items[q->head].len;
    q->head   = (q->head + 1) % MAX_ENVELOPES;
    q->count--;
    return 1;
}

/* ------------------------------------------------------------------
 * Delivery callback: all clients share one bus.
 * ------------------------------------------------------------------ */

static int32_t deliver_cb(
    const uint8_t *addr_ptr, size_t addr_len,
    const uint8_t *data_ptr, size_t data_len)
{
    (void)addr_ptr; (void)addr_len;
    queue_push(&bus, data_ptr, data_len);
    return 0;
}

/* ------------------------------------------------------------------
 * Helper: pop one envelope from the bus, hand it to receiver's worker,
 * then wait for the worker to produce events. Returns a heap-allocated
 * event list; caller frees with event_list_free().
 * ------------------------------------------------------------------ */

static EventList_t *route(ClientHandle_t *receiver)
{
    const uint8_t *data;
    size_t         len;
    int ok = queue_pop(&bus, &data, &len);
    assert(ok && "expected an envelope in the bus");
    client_push_inbound(receiver, SLICE(data, len));

    /* Block until the worker decrypts the payload and produces events. */
    EventList_t *evs = client_wait_events(receiver, 5000);
    assert(event_list_len(evs) > 0 && "timed out waiting for events");
    return evs;
}

/* ------------------------------------------------------------------
 * Helper: locate the first MessageReceived event in a list and copy
 * its content into the caller-supplied buffer. Returns -1 if not found.
 * ------------------------------------------------------------------ */
static int find_message(EventList_t *evs, char *out, size_t out_cap, size_t *out_len)
{
    size_t n = event_list_len(evs);
    for (size_t i = 0; i < n; ++i) {
        if (event_list_kind_at(evs, i) == EVENT_KIND_MESSAGE_RECEIVED) {
            slice_ref_uint8_t s = event_list_content_at(evs, i);
            assert(s.len <= out_cap && "content buffer too small");
            memcpy(out, s.ptr, s.len);
            *out_len = s.len;
            return (int)i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(void)
{
    queue_init(&bus);

    /* Create clients — both share the same delivery bus */
    ClientHandle_t *saro = client_create(STR("saro"), deliver_cb);
    ClientHandle_t *raya = client_create(STR("raya"), deliver_cb);

    assert(saro && "client_create returned NULL for saro");
    assert(raya && "client_create returned NULL for raya");

    /* Raya generates an intro bundle */
    CreateIntroResult_t *raya_intro = client_create_intro_bundle(raya);
    assert(create_intro_result_error_code(raya_intro) == 0);
    slice_ref_uint8_t intro_bytes = create_intro_result_bytes(raya_intro);

    /* Saro initiates a conversation with Raya */
    CreateConvoResult_t *saro_convo = client_create_conversation(
        saro, intro_bytes, STR("hello raya"));
    assert(create_convo_result_error_code(saro_convo) == 0);
    create_intro_result_free(raya_intro);

    /* Route saro -> raya: expect [ConversationStarted, MessageReceived] */
    EventList_t *evs = route(raya);
    assert(event_list_len(evs) == 2 && "expected 2 events for invite");
    assert(event_list_kind_at(evs, 0) == EVENT_KIND_CONVERSATION_STARTED
           && "first event should be ConversationStarted");
    assert(event_list_conversation_class_at(evs, 0) == FFI_CONVERSATION_CLASS_PRIVATE
           && "expected Private convo class");

    char    msg[64];
    size_t  msg_len;
    int idx = find_message(evs, msg, sizeof(msg), &msg_len);
    assert(idx >= 0 && "expected MessageReceived from saro");
    assert(msg_len == 10 && memcmp(msg, "hello raya", 10) == 0);
    printf("Raya received: \"%.*s\"\n", (int)msg_len, msg);

    /* Copy Raya's convo_id from the ConversationStarted event */
    slice_ref_uint8_t cid_ref = event_list_convo_id_at(evs, 0);
    uint8_t raya_cid[256];
    size_t  raya_cid_len = cid_ref.len;
    if (raya_cid_len >= sizeof(raya_cid)) {
        fprintf(stderr, "conversation id too long (%zu bytes)\n", raya_cid_len);
        return 1;
    }
    memcpy(raya_cid, cid_ref.ptr, raya_cid_len);
    event_list_free(evs);

    /* Raya replies */
    ErrorCode_t rc = client_send_message(
        raya, SLICE(raya_cid, raya_cid_len), STR("hi saro"));
    assert(rc == ERROR_CODE_NONE);

    evs = route(saro);
    assert(event_list_len(evs) == 1 && "expected MessageReceived only");
    assert(event_list_kind_at(evs, 0) == EVENT_KIND_MESSAGE_RECEIVED);
    idx = find_message(evs, msg, sizeof(msg), &msg_len);
    assert(idx >= 0);
    assert(msg_len == 7 && memcmp(msg, "hi saro", 7) == 0);
    printf("Saro received: \"%.*s\"\n", (int)msg_len, msg);
    event_list_free(evs);

    /* Multiple back-and-forth rounds */
    slice_ref_uint8_t saro_cid = create_convo_result_id(saro_convo);
    for (int i = 0; i < 3; i++) {
        char text[32];
        int  tlen = snprintf(text, sizeof(text), "msg %d", i);

        rc = client_send_message(saro, saro_cid, SLICE(text, (size_t)tlen));
        assert(rc == ERROR_CODE_NONE);

        evs = route(raya);
        idx = find_message(evs, msg, sizeof(msg), &msg_len);
        assert(idx >= 0);
        assert((int)msg_len == tlen);
        assert(memcmp(msg, text, (size_t)tlen) == 0);
        event_list_free(evs);

        char reply[32];
        int  rlen = snprintf(reply, sizeof(reply), "reply %d", i);

        rc = client_send_message(
            raya, SLICE(raya_cid, raya_cid_len), SLICE(reply, (size_t)rlen));
        assert(rc == ERROR_CODE_NONE);

        evs = route(saro);
        idx = find_message(evs, msg, sizeof(msg), &msg_len);
        assert(idx >= 0);
        assert((int)msg_len == rlen);
        assert(memcmp(msg, reply, (size_t)rlen) == 0);
        event_list_free(evs);
    }

    /* Cleanup */
    create_convo_result_free(saro_convo);
    client_destroy(saro);
    client_destroy(raya);

    printf("Message exchange complete.\n");
    return 0;
}
