//! The behaviour every `KvStore` implementation owes its callers.

use crate::{KvPair, KvStore, KvTx, Namespace, Scope};

/// Asserts the substrate contract against a store, taking a fresh one per case.
pub fn assert_kv_contract<S: KvStore>(new_store: impl Fn() -> S) {
    scopes_are_isolated(&new_store());
    a_key_holds_one_value(&new_store());
    keys_and_values_are_arbitrary_bytes(&new_store());
    prefixes_bound_scan_and_delete(&new_store());
    a_scan_is_in_key_order(&new_store());
    delete_scope_empties_one_scope(&new_store());
    delete_namespace_empties_every_instance(&new_store());
    a_transaction_lands_on_commit_and_is_discarded_on_drop(&new_store());
    a_transaction_reads_its_own_writes(&new_store());
    a_transaction_stages_the_destructive_verbs(&new_store());
    a_second_transaction_is_refused(&new_store());
    a_bare_verb_is_refused_while_a_transaction_is_open(&new_store());
}

const ALPHA: Namespace = Namespace::new("alpha");
const BETA: Namespace = Namespace::new("beta");

const CONVO: Scope<'static> = Scope {
    ns: ALPHA,
    instance: Some("convo"),
};

const SIBLING: Scope<'static> = Scope {
    ns: ALPHA,
    instance: Some("sibling"),
};

const OTHER_PROTOCOL: Scope<'static> = Scope {
    ns: BETA,
    instance: Some("convo"),
};

const PROTOCOL_LEVEL: Scope<'static> = Scope {
    ns: ALPHA,
    instance: None,
};

fn scopes_are_isolated<S: KvStore>(store: &S) {
    for (scope, value) in scopes_with_values() {
        store.put(&scope, b"shared", value).unwrap();
    }

    for (scope, value) in scopes_with_values() {
        assert_eq!(
            store.get(&scope, b"shared").unwrap().as_deref(),
            Some(value),
            "a scope must read back its own value under a key its neighbours also use"
        );
    }

    store.put(&CONVO, b"private", b"v").unwrap();
    for scope in [SIBLING, OTHER_PROTOCOL, PROTOCOL_LEVEL] {
        assert!(
            store.get(&scope, b"private").unwrap().is_none(),
            "a key must be invisible outside the scope that wrote it"
        );
    }
}

fn a_key_holds_one_value<S: KvStore>(store: &S) {
    for (scope, _) in scopes_with_values() {
        store.put(&scope, b"key", b"first").unwrap();
        store.put(&scope, b"key", b"second").unwrap();

        assert_eq!(
            store.get(&scope, b"key").unwrap().as_deref(),
            Some(&b"second"[..]),
            "writing a key twice must leave the later value"
        );
        assert_eq!(
            scan(store, &scope, b"key").len(),
            1,
            "writing a key twice must leave one entry, in a scope that names a conversation and in one that does not"
        );
    }
}

fn keys_and_values_are_arbitrary_bytes<S: KvStore>(store: &S) {
    let key = b"\x00key\xff";
    store.put(&CONVO, key, b"\x00\xff").unwrap();
    assert_eq!(
        store.get(&CONVO, key).unwrap().as_deref(),
        Some(&b"\x00\xff"[..]),
        "a key and a value are bytes, NUL and non-UTF-8 included"
    );
    assert_eq!(
        scan(store, &CONVO, b"\x00"),
        vec![(key.to_vec(), b"\x00\xff".to_vec())],
        "a prefix is bytes too"
    );

    store.put(&CONVO, b"empty", b"").unwrap();
    assert_eq!(
        store.get(&CONVO, b"empty").unwrap().as_deref(),
        Some(&b""[..]),
        "an empty value is a value, not an absent one"
    );
}

fn prefixes_bound_scan_and_delete<S: KvStore>(store: &S) {
    for scope in [CONVO, SIBLING] {
        for key in keys_around_a_prefix() {
            store.put(&scope, key, key).unwrap();
        }
    }

    assert_eq!(
        scan(store, &CONVO, b"mls/"),
        pairs(&[b"mls/context", b"mls/tree"]),
        "scan_prefix must return every key under the prefix and its value, and nothing else"
    );
    assert_eq!(
        scan(store, &CONVO, b"mls%"),
        pairs(&[b"mls%wildcard"]),
        "a prefix is compared byte for byte, so % in it matches only itself"
    );
    assert_eq!(
        scan(store, &CONVO, b"mls_"),
        pairs(&[b"mls_wildcard"]),
        "a prefix is compared byte for byte, so _ in it matches only itself"
    );
    assert_eq!(
        scan(store, &CONVO, b""),
        pairs(keys_around_a_prefix()),
        "an empty prefix must scan the whole scope"
    );

    store.delete_prefix(&CONVO, b"mls/").unwrap();
    assert_eq!(
        scan(store, &CONVO, b""),
        pairs(&[b"", b"mls%wildcard", b"mls_wildcard", b"other"]),
        "delete_prefix must remove every key under the prefix and nothing else"
    );

    store.delete_prefix(&CONVO, b"").unwrap();
    assert!(
        scan(store, &CONVO, b"").is_empty(),
        "an empty prefix must delete the whole scope"
    );
    assert_eq!(
        scan(store, &SIBLING, b""),
        pairs(keys_around_a_prefix()),
        "delete_prefix must not reach beyond its scope"
    );
}

fn a_scan_is_in_key_order<S: KvStore>(store: &S) {
    for key in [b"b", b"c", b"a"] {
        store.put(&CONVO, key, key).unwrap();
    }

    assert_eq!(
        scan(store, &CONVO, b""),
        pairs(&[b"a", b"b", b"c"]),
        "scan_prefix must return keys in byte order, whatever order they were written in"
    );
}

fn delete_scope_empties_one_scope<S: KvStore>(store: &S) {
    for (scope, value) in scopes_with_values() {
        store.put(&scope, b"shared", value).unwrap();
    }

    store.delete_scope(&CONVO).unwrap();

    assert!(
        scan(store, &CONVO, b"").is_empty(),
        "delete_scope must empty the scope it names"
    );
    for scope in [SIBLING, OTHER_PROTOCOL, PROTOCOL_LEVEL] {
        assert!(
            store.get(&scope, b"shared").unwrap().is_some(),
            "delete_scope must leave every other scope intact"
        );
    }
}

fn delete_namespace_empties_every_instance<S: KvStore>(store: &S) {
    for (scope, value) in scopes_with_values() {
        store.put(&scope, b"shared", value).unwrap();
    }

    store.delete_namespace(ALPHA).unwrap();

    for scope in [CONVO, SIBLING, PROTOCOL_LEVEL] {
        assert!(
            scan(store, &scope, b"").is_empty(),
            "delete_namespace must empty every scope under the protocol, instance-level and not"
        );
    }
    assert!(
        store.get(&OTHER_PROTOCOL, b"shared").unwrap().is_some(),
        "delete_namespace must leave another protocol's state intact"
    );
}

fn a_transaction_lands_on_commit_and_is_discarded_on_drop<S: KvStore>(store: &S) {
    let tx = store.begin().unwrap();
    tx.put(&CONVO, b"committed", b"v").unwrap();
    tx.commit().unwrap();
    assert!(
        store.get(&CONVO, b"committed").unwrap().is_some(),
        "commit must land the transaction's writes"
    );

    let tx = store.begin().unwrap();
    tx.put(&CONVO, b"dropped", b"v").unwrap();
    tx.delete(&CONVO, b"committed").unwrap();
    drop(tx);
    assert!(
        store.get(&CONVO, b"dropped").unwrap().is_none(),
        "dropping a transaction must discard what it wrote"
    );
    assert!(
        store.get(&CONVO, b"committed").unwrap().is_some(),
        "dropping a transaction must restore what it deleted"
    );
}

fn a_transaction_reads_its_own_writes<S: KvStore>(store: &S) {
    let tx = store.begin().unwrap();

    tx.put(&CONVO, b"key", b"v").unwrap();
    assert_eq!(
        tx.get(&CONVO, b"key").unwrap().as_deref(),
        Some(&b"v"[..]),
        "a read inside a transaction must see the transaction's own write"
    );
    assert_eq!(
        tx.scan_prefix(&CONVO, b"").unwrap().len(),
        1,
        "a scan inside a transaction must see the transaction's own write"
    );

    tx.delete(&CONVO, b"key").unwrap();
    assert!(
        tx.get(&CONVO, b"key").unwrap().is_none(),
        "a read inside a transaction must see the transaction's own delete"
    );

    tx.commit().unwrap();
}

fn a_transaction_stages_the_destructive_verbs<S: KvStore>(store: &S) {
    for key in [b"mls/tree".as_slice(), b"other".as_slice()] {
        store.put(&CONVO, key, key).unwrap();
    }
    store.put(&OTHER_PROTOCOL, b"key", b"key").unwrap();

    let tx = store.begin().unwrap();
    empty_both_scopes(tx.as_ref());
    drop(tx);
    assert_eq!(
        scan(store, &CONVO, b""),
        pairs(&[b"mls/tree", b"other"]),
        "dropping a transaction must restore what its destructive verbs removed"
    );
    assert!(
        store.get(&OTHER_PROTOCOL, b"key").unwrap().is_some(),
        "dropping a transaction must restore the namespace it dropped"
    );

    let tx = store.begin().unwrap();
    empty_both_scopes(tx.as_ref());
    tx.commit().unwrap();
    assert!(
        scan(store, &CONVO, b"").is_empty(),
        "commit must land the transaction's destructive verbs"
    );
    assert!(
        store.get(&OTHER_PROTOCOL, b"key").unwrap().is_none(),
        "commit must land the namespace the transaction dropped"
    );
}

fn a_second_transaction_is_refused<S: KvStore>(store: &S) {
    let tx = store.begin().unwrap();
    assert!(
        store.begin().is_err(),
        "opening a transaction while one is open must be an error, not a panic"
    );
    drop(tx);

    assert!(
        store.begin().is_ok(),
        "a transaction must be openable once the previous one is done"
    );
}

fn a_bare_verb_is_refused_while_a_transaction_is_open<S: KvStore>(store: &S) {
    store.put(&CONVO, b"key", b"before").unwrap();

    let tx = store.begin().unwrap();
    assert!(
        store.put(&CONVO, b"key", b"beside").is_err(),
        "a bare write while a transaction is open must be refused, not left to the transaction's outcome"
    );
    assert!(
        store.get(&CONVO, b"key").is_err(),
        "a bare read while a transaction is open must be refused, since a transaction's writes are its own"
    );
    drop(tx);

    assert_eq!(
        store.get(&CONVO, b"key").unwrap().as_deref(),
        Some(&b"before"[..]),
        "a refused bare write must leave the stored value, and the store must answer once the transaction is done"
    );
}

/// Empties `CONVO` by prefix and then by scope, `OTHER_PROTOCOL` by namespace, reading each back.
fn empty_both_scopes(tx: &dyn KvTx) {
    tx.delete_prefix(&CONVO, b"mls/").unwrap();
    assert_eq!(
        tx.scan_prefix(&CONVO, b"").unwrap(),
        pairs(&[b"other"]),
        "a read inside a transaction must see the transaction's own delete_prefix"
    );

    tx.delete_scope(&CONVO).unwrap();
    assert!(
        tx.scan_prefix(&CONVO, b"").unwrap().is_empty(),
        "a read inside a transaction must see the transaction's own delete_scope"
    );

    tx.delete_namespace(OTHER_PROTOCOL.ns).unwrap();
    assert!(
        tx.scan_prefix(&OTHER_PROTOCOL, b"").unwrap().is_empty(),
        "a read inside a transaction must see the transaction's own delete_namespace"
    );
}

/// Four scopes that differ in protocol or instance, each with a value of its own.
fn scopes_with_values() -> [(Scope<'static>, &'static [u8]); 4] {
    [
        (CONVO, b"convo"),
        (SIBLING, b"sibling"),
        (OTHER_PROTOCOL, b"other protocol"),
        (PROTOCOL_LEVEL, b"protocol level"),
    ]
}

/// Keys around the prefix `mls/`, byte-sorted, the empty key first and two wildcards under `LIKE`.
fn keys_around_a_prefix() -> &'static [&'static [u8]] {
    &[
        b"",
        b"mls%wildcard",
        b"mls/context",
        b"mls/tree",
        b"mls_wildcard",
        b"other",
    ]
}

fn scan<S: KvStore>(store: &S, scope: &Scope, prefix: &[u8]) -> Vec<KvPair> {
    store.scan_prefix(scope, prefix).unwrap()
}

fn pairs(keys: &[&[u8]]) -> Vec<KvPair> {
    keys.iter()
        .map(|key| (key.to_vec(), key.to_vec()))
        .collect()
}
