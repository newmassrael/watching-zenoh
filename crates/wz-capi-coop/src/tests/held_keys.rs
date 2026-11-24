// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The keys the program's objects hold in the session's key arena: one block with the session's
//! own record of the same key, given back with the last holder, refused past the arena or past the
//! session's key bound, and shared and let go of after the session closed with no lock taken.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{
    HeldKey, KeyAsk, KeyNotHeld, SessionDrive, SessionEngine, SessionKeys, SubscriberSink, WireKey,
};
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

/// `text` held in the engine's key arena, or why not.
fn hold(engine: &Engine, text: &str) -> Result<HeldKey, KeyNotHeld> {
    keys(engine)
        .key(KeyAsk::Hold(text))
        .map(|key| key.expect("a hold answers its key"))
}

/// Another holder of `key`.
fn share(engine: &Engine, key: &HeldKey) -> HeldKey {
    keys(engine)
        .key(KeyAsk::Share(key))
        .ok()
        .flatten()
        .expect("a share answers its key")
}

/// Let go of `key`.
fn release(engine: &Engine, key: HeldKey) {
    assert!(matches!(keys(engine).key(KeyAsk::Release(key)), Ok(None)));
}

/// Counts its own drop.
struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A subscriber's callback that counts its drop in `dropped`.
fn sink(dropped: &Arc<AtomicUsize>) -> SubscriberSink {
    let guard = Dropped(dropped.clone());
    SubscriberSink::shared(move |_sample: &dyn SampleView| {
        let _held = &guard;
    })
}

/// A held key reads back as its text and takes one block; a share takes none, and the block goes
/// back with the last holder.
#[test]
fn a_held_key_reads_back_and_its_last_holder_gives_the_block_back() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let held = hold(&engine, "demo/held/one").expect("room for a key");
    assert_eq!(held.as_str(), "demo/held/one");
    let block = block_bytes("demo/held/one".len()).expect("a short key");
    assert_eq!(engine.key_counts().used, before + block);
    let shared = share(&engine, &held);
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "a share takes no block"
    );
    release(&engine, held);
    assert_eq!(shared.as_str(), "demo/held/one", "the share still reads it");
    assert_eq!(engine.key_counts().used, before + block);
    release(&engine, shared);
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
    let held = hold(&engine, "demo/held/shared").expect("room for a key");
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
    release(&engine, held);
    assert_eq!(engine.key_counts().used, before);
}

/// A key the key arena has no room for is refused and counted, and takes nothing; a key past the
/// session's `MAX_KEYEXPR_BYTES` is refused as too long before any room is asked.
#[test]
fn a_key_past_the_arena_or_the_bound_is_refused_and_takes_nothing() {
    let block = block_bytes("demo/k/1".len()).expect("a short key");
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, lowered(|l| l.select_key_arena_bytes(2 * block)));
    let first = hold(&engine, "demo/k/1").expect("room for one");
    let second = hold(&engine, "demo/k/2").expect("room for two");
    let full = engine.key_counts();
    assert_eq!(hold(&engine, "demo/k/3").err(), Some(KeyNotHeld::NoRoom));
    let refused = engine.key_counts();
    assert_eq!(refused.used, full.used, "a refusal takes nothing");
    assert_eq!(refused.refused, full.refused + 1, "and is counted");
    release(&engine, first);
    let third = hold(&engine, "demo/k/3").expect("the block given back takes it");
    release(&engine, second);
    release(&engine, third);

    let other = Router::start(CatchAll::None);
    let bounded = open_under(
        &other,
        lowered(|l| l.select_max_keyexpr_bytes(Quota::at_most(8))),
    );
    let asked = bounded.key_counts();
    assert_eq!(
        hold(&bounded, "demo/k/too/long").err(),
        Some(KeyNotHeld::TooLong)
    );
    assert_eq!(bounded.key_counts(), asked, "a key too long asks no room");
    assert!(hold(&bounded, "demo/k/1").is_ok(), "CONTROL");
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
    let dropped = Arc::new(AtomicUsize::new(0));
    for round in 0..10 {
        let key = format!("demo/c/{round}");
        let held = hold(&engine, &key).expect("the room given back");
        release(&engine, held);
        let id = engine
            .declare_subscriber_on_wire(
                &key,
                WireKey::literal(),
                Locality::Any,
                None,
                sink(&dropped),
            )
            .expect("the room given back takes the subscriber");
        engine.undeclare_subscriber(id);
    }
    let after = engine.key_counts();
    assert_eq!(after.used, before.used, "every block went back");
    assert_eq!(after.refused, before.refused, "none was refused");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        10,
        "each callback let go of with its undeclaration"
    );
}

/// After the session closed, a held key still reads, a share of it reads, and letting go of either
/// gives nothing back and takes no lock; a key asked for then is refused as the session's.
#[test]
fn a_closed_sessions_keys_are_read_shared_and_let_go_of() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let held = hold(&engine, "demo/closed/key").expect("room for a key");
    SessionDrive::close(&*engine);
    assert_eq!(held.as_str(), "demo/closed/key");
    let shared = share(&engine, &held);
    assert_eq!(shared.as_str(), "demo/closed/key");
    let closed = engine.key_counts();
    release(&engine, shared);
    release(&engine, held);
    assert_eq!(
        engine.key_counts().used,
        closed.used,
        "a closed session gives no block back"
    );
    assert_eq!(
        hold(&engine, "demo/closed/other").err(),
        Some(KeyNotHeld::Closed)
    );
}

/// Two holds of one text, and a declaration of it, take one block between them, whichever came
/// first: the arena finds a text it keeps already whoever holds it. The block goes back with the
/// last of them.
#[test]
fn holds_of_one_text_share_its_block_whoever_holds_it() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let first = hold(&engine, "demo/held/twice").expect("room for a key");
    let block = block_bytes("demo/held/twice".len()).expect("a short key");
    let second = hold(&engine, "demo/held/twice").expect("the same block");
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "one block for both holds"
    );
    let id = engine
        .acquire_keyexpr("demo/held/twice")
        .expect("a declaration");
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "the declaration finds the held block"
    );
    let other = hold(&engine, "demo/held/other").expect("room for a key");
    assert_eq!(
        engine.key_counts().used,
        before + block + block_bytes("demo/held/other".len()).expect("a short key"),
        "CONTROL: another text takes a block of its own"
    );
    release(&engine, first);
    engine.release_keyexpr(id);
    assert_eq!(second.as_str(), "demo/held/twice");
    release(&engine, second);
    release(&engine, other);
    assert_eq!(engine.key_counts().used, before, "every block went back");
}
