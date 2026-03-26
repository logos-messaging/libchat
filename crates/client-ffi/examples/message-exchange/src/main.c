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
 * Helper: pop one envelope from the bus and push it into receiver.
 * Returns a heap-allocated result; caller frees with
 * push_inbound_result_free().
 * ------------------------------------------------------------------ */

static PushInboundResult_t *route(ClientHandle_t *receiver)
{
    const uint8_t *data;
    size_t         len;
    int ok = queue_pop(&bus, &data, &len);
    assert(ok && "expected an envelope in the bus");
    PushInboundResult_t *r = client_receive(receiver, SLICE(data, len));
    assert(push_inbound_result_error_code(r) == 0 && "push_inbound failed");
    return r;
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

    /* Route saro -> raya */
    PushInboundResult_t *recv = route(raya);

    assert(push_inbound_result_has_content(recv)  && "expected content from saro");
    assert(push_inbound_result_is_new_convo(recv) && "expected new-conversation flag");

    slice_ref_uint8_t content = push_inbound_result_content(recv);
    assert(content.len == 10);
    assert(memcmp(content.ptr, "hello raya", 10) == 0);
    printf("Raya received: \"%.*s\"\n", (int)content.len, content.ptr);

    /* Copy Raya's convo_id before freeing recv */
    slice_ref_uint8_t cid_ref = push_inbound_result_convo_id(recv);
    uint8_t raya_cid[256];
    size_t  raya_cid_len = cid_ref.len;
    if (raya_cid_len >= sizeof(raya_cid)) {
        fprintf(stderr, "conversation id too long (%zu bytes)\n", raya_cid_len);
        return 1;
    }
    memcpy(raya_cid, cid_ref.ptr, raya_cid_len);
    push_inbound_result_free(recv);

    /* Raya replies */
    ErrorCode_t rc = client_send_message(
        raya, SLICE(raya_cid, raya_cid_len), STR("hi saro"));
    assert(rc == ERROR_CODE_NONE);

    recv = route(saro);
    assert(push_inbound_result_has_content(recv)   && "expected content from raya");
    assert(!push_inbound_result_is_new_convo(recv) && "unexpected new-convo flag");
    content = push_inbound_result_content(recv);
    assert(content.len == 7);
    assert(memcmp(content.ptr, "hi saro", 7) == 0);
    printf("Saro received: \"%.*s\"\n", (int)content.len, content.ptr);
    push_inbound_result_free(recv);

    /* Multiple back-and-forth rounds */
    slice_ref_uint8_t saro_cid = create_convo_result_id(saro_convo);
    for (int i = 0; i < 3; i++) {
        char msg[32];
        int  mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        rc = client_send_message(saro, saro_cid, SLICE(msg, (size_t)mlen));
        assert(rc == ERROR_CODE_NONE);

        recv = route(raya);
        assert(push_inbound_result_has_content(recv));
        content = push_inbound_result_content(recv);
        assert((int)content.len == mlen);
        assert(memcmp(content.ptr, msg, (size_t)mlen) == 0);
        push_inbound_result_free(recv);

        char reply[32];
        int  rlen = snprintf(reply, sizeof(reply), "reply %d", i);

        rc = client_send_message(
            raya, SLICE(raya_cid, raya_cid_len), SLICE(reply, (size_t)rlen));
        assert(rc == ERROR_CODE_NONE);

        recv = route(saro);
        assert(push_inbound_result_has_content(recv));
        content = push_inbound_result_content(recv);
        assert((int)content.len == rlen);
        assert(memcmp(content.ptr, reply, (size_t)rlen) == 0);
        push_inbound_result_free(recv);
    }

    /* Cleanup */
    create_convo_result_free(saro_convo);
    client_destroy(saro);
    client_destroy(raya);

    printf("Message exchange complete.\n");
    return 0;
}
