// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The keys the program's objects hold in the session's key arena: one block with the session's
//! own record of the same key, given back with the last holder, refused past the arena or past the
//! session's key bound, and shared and let go of after the session closed with no lock taken.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{KeyNotHeld, SessionDrive, SessionEngine, SessionKeys, SubscriberSink, WireKey};
use wz_session_core::key_arena::block_bytes;
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::entity_tables::{lowered, open_under};
use super::{open, CatchAll, Engine, Router};

/// The engine's key arena, which the cooperative engine always keeps.
fn keys(engine: &Engine) -> &dyn SessionKeys {
    engine
        .key_arena()
        .expect("the cooperative engine keeps a key arena")
}

/// A subscriber's sink that counts the callbacks it mints.
fn sink(minted: &Arc<AtomicUsize>) -> SubscriberSink {
    let minted = minted.clone();
    Arc::new(move || {
        minted.fetch_add(1, Ordering::SeqCst);
        Box::new(|_sample: &dyn SampleView| {}) as Box<dyn FnMut(&dyn SampleView) + Send>
    })
}

/// A held key reads back as its text and takes one block; a share takes none, and the block goes
/// back with the last holder.
#[test]
fn a_held_key_reads_back_and_its_last_holder_gives_the_block_back() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let held = keys(&engine)
        .hold_key("demo/held/one")
        .expect("room for a key");
    assert_eq!(held.as_str(), "demo/held/one");
    let block = block_bytes("demo/held/one".len()).expect("a short key");
    assert_eq!(engine.key_counts().used, before + block);
    let shared = keys(&engine).share_key(&held);
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "a share takes no block"
    );
    keys(&engine).release_key(held);
    assert_eq!(shared.as_str(), "demo/held/one", "the share still reads it");
    assert_eq!(engine.key_counts().used, before + block);
    keys(&engine).release_key(shared);
    assert_eq!(
        engine.key_counts().used,
        before,
        "the last holder gave the block back"
    );
}

/// A key the session's record keeps already is held in the record's block: the program's object
/// and the declaration take one block between them, and the hold keeps it when the declaration
/// goes.
#[test]
fn a_key_the_record_keeps_is_held_in_the_same_block() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let id = engine
        .acquire_keyexpr("demo/held/shared")
        .expect("a declaration");
    let declared = engine.key_counts().used;
    assert_eq!(
        declared,
        before + block_bytes("demo/held/shared".len()).expect("a short key")
    );
    let held = keys(&engine)
        .hold_key("demo/held/shared")
        .expect("room for a key");
    assert_eq!(
        engine.key_counts().used,
        declared,
        "the record's block is shared"
    );
    engine.release_keyexpr(id);
    assert_eq!(
        held.as_str(),
        "demo/held/shared",
        "the hold keeps the block"
    );
    assert_eq!(engine.key_counts().used, declared);
    keys(&engine).release_key(held);
    assert_eq!(engine.key_counts().used, before);
}

/// A key the key arena has no room for is refused and counted, and takes nothing; a key past the
/// session's `MAX_KEYEXPR_BYTES` is refused as too long before any room is asked.
#[test]
fn a_key_past_the_arena_or_the_bound_is_refused_and_takes_nothing() {
    let block = block_bytes("demo/k/1".len()).expect("a short key");
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, lowered(|l| l.select_key_arena_bytes(2 * block)));
    let first = keys(&engine).hold_key("demo/k/1").expect("room for one");
    let second = keys(&engine).hold_key("demo/k/2").expect("room for two");
    let full = engine.key_counts();
    assert_eq!(
        keys(&engine).hold_key("demo/k/3").err(),
        Some(KeyNotHeld::NoRoom)
    );
    let refused = engine.key_counts();
    assert_eq!(refused.used, full.used, "a refusal takes nothing");
    assert_eq!(refused.refused, full.refused + 1, "and is counted");
    keys(&engine).release_key(first);
    let third = keys(&engine)
        .hold_key("demo/k/3")
        .expect("the block given back takes it");
    keys(&engine).release_key(second);
    keys(&engine).release_key(third);

    let other = Router::start(CatchAll::None);
    let bounded = open_under(
        &other,
        lowered(|l| l.select_max_keyexpr_bytes(Quota::at_most(8))),
    );
    let asked = bounded.key_counts();
    assert_eq!(
        keys(&bounded).hold_key("demo/k/too/long").err(),
        Some(KeyNotHeld::TooLong)
    );
    assert_eq!(bounded.key_counts(), asked, "a key too long asks no room");
    assert!(keys(&bounded).hold_key("demo/k/1").is_ok(), "CONTROL");
}

/// Holds let go of, and subscribers declared and undeclared, many times past what the key arena
/// holds at once, each take the room the one before gave back: none is refused, and the arena ends
/// as it began.
#[test]
fn holds_and_declarations_past_the_arena_leave_it_as_they_found_it() {
    let block = block_bytes("demo/c/0".len()).expect("a short key");
    // Room for one subscriber at a time: the engine's record and the application's table each
    // keep its key.
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, lowered(|l| l.select_key_arena_bytes(2 * block)));
    let before = engine.key_counts();
    let minted = Arc::new(AtomicUsize::new(0));
    for round in 0..10 {
        let key = format!("demo/c/{round}");
        let held = keys(&engine).hold_key(&key).expect("the room given back");
        keys(&engine).release_key(held);
        let id = engine
            .declare_subscriber_on_wire(
                &key,
                WireKey::literal(),
                Locality::Any,
                None,
                sink(&minted),
            )
            .expect("the room given back takes the subscriber");
        engine.undeclare_subscriber(id);
    }
    let after = engine.key_counts();
    assert_eq!(after.used, before.used, "every block went back");
    assert_eq!(after.refused, before.refused, "none was refused");
    assert_eq!(minted.load(Ordering::SeqCst), 10);
}

/// After the session closed, a held key still reads, a share of it reads, and letting go of either
/// gives nothing back and takes no lock; a key asked for then is refused as the session's.
#[test]
fn a_closed_sessions_keys_are_read_shared_and_let_go_of() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let held = keys(&engine)
        .hold_key("demo/closed/key")
        .expect("room for a key");
    SessionDrive::close(&*engine);
    assert_eq!(held.as_str(), "demo/closed/key");
    let shared = keys(&engine).share_key(&held);
    assert_eq!(shared.as_str(), "demo/closed/key");
    let closed = engine.key_counts();
    keys(&engine).release_key(shared);
    keys(&engine).release_key(held);
    assert_eq!(
        engine.key_counts().used,
        closed.used,
        "a closed session gives no block back"
    );
    assert_eq!(
        keys(&engine).hold_key("demo/closed/other").err(),
        Some(KeyNotHeld::Closed)
    );
}
