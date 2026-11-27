// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose tables take their memory at their first row (`tables-on-use`), against the
//! router stand-in: its keys are counted against a budget of the session's `KEY_ARENA_BYTES`, a
//! declaration's key as the block the key arena would give it, given back with the declaration;
//! the keys the program's objects hold are copies of their own; and a subscriber declared after the
//! open is told to the router and handed what it pushes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{KeyAsk, KeyNotHeld, SessionEngine, SessionKeys, SubscriberSink, WireKey};
use wz_session_core::key_arena::block_bytes;
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Command, Engine, Router};

/// What the engine answers its objects' keys through.
fn keys(engine: &Engine) -> &dyn SessionKeys {
    engine
        .key_arena()
        .expect("the engine answers its objects' keys")
}

/// The session's keys are counted against a budget of its `KEY_ARENA_BYTES`: a key expression it
/// declares takes the block the key arena would give it, and gives it back with its last hold.
/// Turned red by an open that hands the session's state a budget of other bytes than its limits
/// state (`StateRegion::place`), by a declaration whose key the budget does not count, or by one
/// whose bytes do not go back with it.
#[test]
fn a_declarations_key_is_counted_against_the_sessions_budget_and_given_back() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let opened = engine.key_counts();
    assert_eq!(
        opened.bytes,
        SessionLimits::defaults().key_arena_bytes(),
        "the budget is the session's KEY_ARENA_BYTES"
    );
    let declaration = engine
        .acquire_keyexpr("demo/on-use/key")
        .expect("a declaration");
    let block = block_bytes("demo/on-use/key".len()).expect("a short key's block");
    assert_eq!(
        engine.key_counts().used,
        opened.used + block,
        "the key is counted as its block"
    );
    declaration.release(&*engine);
    assert_eq!(
        engine.key_counts().used,
        opened.used,
        "and given back with the declaration"
    );
}

/// The program's objects hold their keys as copies of their own where the session keeps no key
/// arena: a hold reads back its text and takes nothing of the session's budget, a share is another
/// copy, a release lets each go, and a key past the session's `MAX_KEYEXPR_BYTES` is refused as too
/// long, as the arena refuses it. Turned red by a hold that is not a copy of its own, by one counted
/// against the budget, or by a hold past the bound that is kept.
#[test]
fn an_objects_key_is_a_copy_of_its_own_and_refused_past_the_sessions_bound() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let held = keys(&engine)
        .key(KeyAsk::Hold("demo/held"))
        .expect("room for a copy")
        .expect("a hold answers its key");
    assert!(held.is_own());
    assert_eq!(held.as_str(), "demo/held");
    assert_eq!(
        engine.key_counts().used,
        before,
        "a copy takes nothing of the budget"
    );
    let shared = keys(&engine)
        .key(KeyAsk::Share(&held))
        .expect("room for a copy")
        .expect("a share answers its key");
    assert!(shared.is_own());
    assert_eq!(shared.as_str(), "demo/held");
    assert!(matches!(keys(&engine).key(KeyAsk::Release(held)), Ok(None)));
    assert!(matches!(
        keys(&engine).key(KeyAsk::Release(shared)),
        Ok(None)
    ));
    let long = "k".repeat(wz_session_core::caps::MAX_KEYEXPR_BYTES + 1);
    assert!(matches!(
        keys(&engine).key(KeyAsk::Hold(&long)),
        Err(KeyNotHeld::TooLong)
    ));
}

/// A subscriber declared on a session whose tables took no row at the open is told to the router
/// and handed what the router pushes on its key when the program steps the session. Turned red by
/// a registry whose subscribers' table refuses its first row (a table counted none), or by a
/// receive that does not reach a table of the on-use policy.
#[test]
fn a_subscriber_declared_after_the_open_is_told_and_handed_a_push() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let declares = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let received = received.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                assert_eq!(sample.payload(), b"hello");
                received.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares
    });
    router.send(Command::Push("demo/a", b"hello"));
    until(&engine, "the push", || received.load(Ordering::SeqCst) == 1);
}
