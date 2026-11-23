// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables of the session's own declarations, lent from its arena at open: each holds as many
//! rows as the limit the open resolved, and the declaration past them is refused before an id is
//! taken, a callback minted or anything sent; a row given back takes the next declaration.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{
    FilterId, FilterPlane, MatchingSink, Refusal, SessionDrive, SessionEngine, SubId,
    SubscriberSink, WireKey,
};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::limit_binding::{OutsideLimitDomain, Quota};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{client_config, config, open_with, until, CatchAll, Engine, Router};
use crate::arena::ArenaPlan;
use crate::CoopConfig;

/// The build's limits with `select` applied. Every build these tests run in lets a test lower a
/// limit; one that keeps a limit to its own value (`WZ_LIMIT_DOMAINS=defaults`, a target with no
/// operating system) refuses the lowering, and the test fails naming the limit rather than passing
/// without having opened the session it is about.
pub(super) fn lowered(
    select: impl FnOnce(&mut SessionLimits) -> Result<(), OutsideLimitDomain>,
) -> SessionLimits {
    let mut limits = SessionLimits::defaults();
    if let Err(refused) = select(&mut limits) {
        panic!("this build refuses the limits the test lowers: {refused}");
    }
    limits
}

/// A session open to `router` under `limits`.
pub(super) fn open_under(router: &Router, limits: SessionLimits) -> Arc<Engine> {
    open_with(CoopConfig {
        limits,
        ..config(router)
    })
}

/// Step `engine` a few times, so whatever it would send has been sent.
fn settle(engine: &Engine) {
    for _ in 0..20 {
        let _ = SessionDrive::read(engine, false);
    }
}

/// A subscriber's sink that counts the callbacks it mints: one for each declaration it is taken
/// into, none for one refused.
fn subscriber_sink(minted: &Arc<AtomicUsize>) -> SubscriberSink {
    let minted = minted.clone();
    Arc::new(move || {
        minted.fetch_add(1, Ordering::SeqCst);
        Box::new(|_sample: &dyn SampleView| {}) as Box<dyn FnMut(&dyn SampleView) + Send>
    })
}

fn declare_subscriber(
    engine: &Engine,
    key: &str,
    minted: &Arc<AtomicUsize>,
) -> Result<SubId, Refusal> {
    engine.declare_subscriber_on_wire(
        key,
        WireKey::literal(),
        Locality::Any,
        None,
        subscriber_sink(minted),
    )
}

/// A write filter that asks for `key`, on `plane`.
fn filter(engine: &Engine, plane: FilterPlane, key: &str) -> Result<FilterId, Refusal> {
    engine.declare_write_filter(
        plane,
        key,
        &WireKey::literal(),
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some(key.to_owned()),
            aggregate: false,
        }),
        false,
    )
}

/// Each declaration asked of a closed session is refused as closed, with its callback let go of and
/// no id taken. The CONTROL is the same declarations while the session is open.
#[test]
fn a_declaration_on_a_closed_session_is_refused_as_closed() {
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, SessionLimits::defaults());
    let minted = Arc::new(AtomicUsize::new(0));
    assert!(
        declare_subscriber(&engine, "demo/c/s", &minted).is_ok(),
        "CONTROL"
    );
    assert!(engine.acquire_keyexpr("demo/c/k").is_ok(), "CONTROL");
    SessionDrive::close(&*engine);

    let sink = subscriber_sink(&minted);
    let held = Arc::downgrade(&sink);
    assert_eq!(
        engine.declare_subscriber_on_wire(
            "demo/c/s2",
            WireKey::literal(),
            Locality::Any,
            None,
            sink,
        ),
        Err(Refusal::Closed)
    );
    assert!(held.upgrade().is_none(), "the refused sink is let go of");
    assert_eq!(engine.acquire_keyexpr("demo/c/k2"), Err(Refusal::Closed));
    #[cfg(feature = "liveliness")]
    assert_eq!(
        engine.declare_liveliness_token_on_wire("demo/c/t", WireKey::literal(), None),
        Err(Refusal::Closed)
    );
}

/// A write filter asked of a closed session is refused as closed: no id stands for it.
#[test]
fn a_write_filter_on_a_closed_session_is_refused_as_closed() {
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, SessionLimits::defaults());
    assert!(
        filter(&engine, FilterPlane::Subscribers, "demo/c/1").is_ok(),
        "CONTROL: the open session declares"
    );
    SessionDrive::close(&*engine);
    assert_eq!(
        filter(&engine, FilterPlane::Subscribers, "demo/c/2"),
        Err(Refusal::Closed)
    );
}

/// The plan lends each table of the session's own declarations the value of its limit the open
/// resolved: lowered, its row is the lowered count, and the write filters' row is a publisher's
/// and a querier's each.
#[test]
fn the_plan_lends_each_declaration_table_its_limit() {
    let limits = lowered(|l| {
        l.select_max_subscriptions(Quota::at_most(2))?;
        l.select_max_publishers(Quota::at_most(3))?;
        l.select_max_queriers(Quota::at_most(4))?;
        l.select_max_matching_listeners(Quota::at_most(5))?;
        l.select_max_declared_keyexprs(Quota::at_most(6))
    });
    let plan = ArenaPlan::of(&client_config(), &limits).expect("lays an arena out");
    let rows = plan.entities();
    assert_eq!(rows.subscribers, 2);
    assert_eq!(rows.publishers, 3);
    assert_eq!(rows.queriers, 4);
    assert_eq!(rows.matching_listeners, 5);
    assert_eq!(rows.keyexprs, 6);
    assert_eq!(rows.filters(), Some(7));
    assert_eq!(rows.interests(), Some(12));
    let count = |part: &str| {
        plan.rows()
            .iter()
            .find(|row| row.part == part)
            .map(|row| row.count)
    };
    assert_eq!(count("subscribers"), Some(2));
    assert_eq!(
        count("subscriber declarations"),
        None,
        "a subscriber is one row, the session core's"
    );
    assert_eq!(count("key expressions"), Some(6));
    assert_eq!(count("write filters"), Some(7));
    assert_eq!(count("matching listeners"), Some(5));
    assert_eq!(count("interests"), Some(12));
}

/// The subscribers' table at its limit refuses one more: no id, no callback minted, nothing sent.
/// Undeclaring one gives its row back, and the next declaration takes it.
#[test]
fn a_subscriber_past_its_table_is_refused_and_sends_nothing() {
    let limits = lowered(|l| l.select_max_subscriptions(Quota::at_most(2)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let minted = Arc::new(AtomicUsize::new(0));
    let before = router.seen(|s| s.declares);
    let first = declare_subscriber(&engine, "demo/s/1", &minted).expect("a row is free");
    declare_subscriber(&engine, "demo/s/2", &minted).expect("the last row is free");
    until(&engine, "the router to see both subscribers", || {
        router.seen(|s| s.declares) >= before + 2
    });
    let seen = router.seen(|s| s.declares);
    assert_eq!(minted.load(Ordering::SeqCst), 2);

    assert_eq!(
        declare_subscriber(&engine, "demo/s/3", &minted),
        Err(Refusal::TableFull)
    );
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        2,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");

    engine.undeclare_subscriber(first);
    assert!(
        declare_subscriber(&engine, "demo/s/3", &minted).is_ok(),
        "the row the undeclaration gave back takes the next one"
    );
}

/// A key expression takes a row only while no declaration holds it: a second hold on a held key
/// takes none, a new key past the table is refused with nothing sent, and the row comes back
/// when the last hold goes.
#[test]
fn a_key_expression_past_its_table_is_refused_and_sends_nothing() {
    let limits = lowered(|l| l.select_max_declared_keyexprs(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let before = router.seen(|s| s.declares);
    let id = engine.acquire_keyexpr("demo/k/a").expect("a row is free");
    assert_eq!(
        engine.acquire_keyexpr("demo/k/a"),
        Ok(id),
        "a held key is held again, in its row"
    );
    until(&engine, "the router to see the key", || {
        router.seen(|s| s.declares) > before
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(engine.acquire_keyexpr("demo/k/b"), Err(Refusal::TableFull));
    settle(&engine);
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");
    assert_eq!(engine.keyexpr_declarations().len(), 1);

    engine.release_keyexpr(id);
    assert_eq!(
        engine.acquire_keyexpr("demo/k/b"),
        Err(Refusal::TableFull),
        "one hold is left on the first key"
    );
    engine.release_keyexpr(id);
    assert!(
        engine.acquire_keyexpr("demo/k/b").is_ok(),
        "the last hold gone, its row takes the next key"
    );
}

/// The engine is handed a key as the caller's borrow and keeps its own copy in its row: a key read
/// out of a buffer the caller then writes over is declared, listed and held again as it was.
#[test]
fn a_key_handed_as_a_borrow_is_kept_in_the_sessions_own_row() {
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, SessionLimits::defaults());
    let mut buffer = *b"demo/k/borrowed";
    let key = core::str::from_utf8(&buffer).expect("the key is text");
    let id = engine.acquire_keyexpr(key).expect("a row is free");
    buffer.copy_from_slice(b"xxxx/x/xxxxxxxx");
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/k/borrowed".to_owned())],
        "the row holds its own copy of the key"
    );
    assert_eq!(
        engine.acquire_keyexpr("demo/k/borrowed"),
        Ok(id),
        "the held key is held again by its text"
    );
}

/// A publisher's write filter is held to MAX_PUBLISHERS and a querier's to MAX_QUERIERS: one past
/// a plane's count is refused before its Interest is asked, while the other plane still takes
/// its own.
#[test]
fn a_write_filter_past_its_planes_count_is_refused_and_asks_nothing() {
    let limits = lowered(|l| {
        l.select_max_publishers(Quota::at_most(1))?;
        l.select_max_queriers(Quota::at_most(1))
    });
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let publisher =
        filter(&engine, FilterPlane::Subscribers, "demo/p/1").expect("a publisher's row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    assert_eq!(
        filter(&engine, FilterPlane::Subscribers, "demo/p/2"),
        Err(Refusal::TableFull)
    );
    settle(&engine);
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    let querier = FilterPlane::Queryables {
        complete_required: false,
    };
    if cfg!(any(feature = "query", feature = "queryable")) {
        assert!(
            filter(&engine, querier, "demo/q/1").is_ok(),
            "a querier's row is its own"
        );
        assert_eq!(
            filter(&engine, querier, "demo/q/2"),
            Err(Refusal::TableFull)
        );
    } else {
        assert_eq!(
            filter(&engine, querier, "demo/q/1"),
            Err(Refusal::NotBuilt),
            "a build without the queryables plane holds no querier's filter"
        );
    }

    engine.undeclare_write_filter(publisher);
    assert!(
        filter(&engine, FilterPlane::Subscribers, "demo/p/2").is_ok(),
        "the row the undeclaration gave back takes the next publisher"
    );
}

/// The matching listeners' table at its limit refuses one more as a full table, before its Interest
/// is asked; its sink goes with the refusal.
#[test]
fn a_matching_listener_past_its_table_is_refused_and_asks_nothing() {
    let limits = lowered(|l| l.select_max_matching_listeners(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let first_sink: MatchingSink = Arc::new(|_matching: bool| {});
    let first = engine
        .declare_matching_listener(FilterPlane::Subscribers, "demo/m/1", first_sink, false)
        .expect("a row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    let refused_sink: MatchingSink = Arc::new(|_matching: bool| {});
    let held = Arc::downgrade(&refused_sink);
    let refused =
        engine.declare_matching_listener(FilterPlane::Subscribers, "demo/m/2", refused_sink, false);
    assert_eq!(refused, Err(Refusal::TableFull));
    assert!(
        held.upgrade().is_none(),
        "the refused listener's sink is let go"
    );
    settle(&engine);
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    engine.undeclare_matching_listener(first);
    let again: MatchingSink = Arc::new(|_matching: bool| {});
    assert!(
        engine
            .declare_matching_listener(FilterPlane::Subscribers, "demo/m/2", again, false)
            .is_ok(),
        "the row the undeclaration gave back takes the next listener"
    );
}

/// The queryables' table at its limit refuses one more: no callback minted, nothing sent.
#[cfg(feature = "queryable")]
#[test]
fn a_queryable_past_its_table_is_refused_and_sends_nothing() {
    use wz_capi_port::{QueryCallback, QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let limits = lowered(|l| l.select_max_queryables(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let minted = Arc::new(AtomicUsize::new(0));
    let sink = |minted: &Arc<AtomicUsize>| -> QueryableSink {
        let minted = minted.clone();
        Arc::new(move |_holder: Arc<dyn QueryHolder>| {
            minted.fetch_add(1, Ordering::SeqCst);
            Box::new(|_query: &dyn QueryView, _out: &mut dyn ReplyOut| {}) as QueryCallback
        })
    };
    let declare = |key: &str| {
        engine.declare_queryable_on_wire(
            key,
            WireKey::literal(),
            false,
            Locality::Remote,
            None,
            sink(&minted),
        )
    };
    let before = router.seen(|s| s.declares);
    let first = declare("demo/qbl/1").expect("a row is free");
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) > before
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(declare("demo/qbl/2"), Err(Refusal::TableFull));
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        1,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");

    engine.undeclare_queryable(first);
    assert!(declare("demo/qbl/2").is_ok(), "the row given back takes it");
}

/// The tokens' table at its limit refuses one more, sending nothing.
#[cfg(feature = "liveliness")]
#[test]
fn a_token_past_its_table_is_refused_and_sends_nothing() {
    let limits = lowered(|l| l.select_max_local_tokens(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let first = engine
        .declare_liveliness_token_on_wire("demo/t/1", WireKey::literal(), None)
        .expect("a row is free");
    until(&engine, "the router to see the token", || {
        router.seen(|s| s.tokens.len()) == 1
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(
        engine.declare_liveliness_token_on_wire("demo/t/2", WireKey::literal(), None),
        Err(Refusal::TableFull)
    );
    settle(&engine);
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");
    assert_eq!(router.seen(|s| s.tokens.len()), 1);

    engine.undeclare_liveliness_token(first);
    assert!(
        engine
            .declare_liveliness_token_on_wire("demo/t/2", WireKey::literal(), None)
            .is_ok(),
        "the row given back takes it"
    );
}

/// The liveliness subscribers' table at its limit refuses one more: no callback minted, no
/// Interest asked.
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscriber_past_its_table_is_refused_and_asks_nothing() {
    use wz_capi_port::LivelinessSink;
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let limits = lowered(|l| l.select_max_liveliness_subscriptions(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let minted = Arc::new(AtomicUsize::new(0));
    let sink = |minted: &Arc<AtomicUsize>| -> LivelinessSink {
        let minted = minted.clone();
        Arc::new(move || {
            minted.fetch_add(1, Ordering::SeqCst);
            Box::new(|_sample: LivelinessSample<'_>| {})
                as Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send>
        })
    };
    let declare = |key: &str| {
        engine.declare_liveliness_subscriber_on_wire(key, WireKey::literal(), false, sink(&minted))
    };
    let first = declare("demo/ls/1").expect("a row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    assert_eq!(declare("demo/ls/2"), Err(Refusal::TableFull));
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        1,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    engine.undeclare_subscriber(first);
    assert!(declare("demo/ls/2").is_ok(), "the row given back takes it");
}

/// A key longer than a row holds (`MAX_KEYEXPR_BYTES`) is refused, before an id is taken, a
/// callback minted or anything sent; the key of the bound itself is taken.
#[test]
fn a_key_past_its_row_is_refused_and_sends_nothing() {
    use wz_session_core::caps::MAX_KEYEXPR_BYTES;

    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, SessionLimits::defaults());
    let minted = Arc::new(AtomicUsize::new(0));
    let past = "k".repeat(MAX_KEYEXPR_BYTES + 1);
    let before = router.seen(|s| s.declares);
    assert_eq!(
        declare_subscriber(&engine, &past, &minted),
        Err(Refusal::KeyTooLong)
    );
    assert_eq!(engine.acquire_keyexpr(&past), Err(Refusal::KeyTooLong));
    assert_eq!(
        filter(&engine, FilterPlane::Subscribers, &past),
        Err(Refusal::KeyTooLong)
    );
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        0,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), before, "nothing was sent");

    let at = "k".repeat(MAX_KEYEXPR_BYTES);
    assert!(
        declare_subscriber(&engine, &at, &minted).is_ok(),
        "a key of the bound itself is taken"
    );
}

/// A key past the session's own `MAX_KEYEXPR_BYTES`, lowered under the build's, is refused as one
/// past the build's is, before an id is taken, a callback minted or anything sent; a key of the
/// session's bound is taken.
#[test]
fn a_key_past_the_sessions_bound_is_refused_and_sends_nothing() {
    let limits = lowered(|l| l.select_max_keyexpr_bytes(Quota::at_most(8)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let minted = Arc::new(AtomicUsize::new(0));
    let past = "demo/k/10";
    let before = router.seen(|s| s.declares);
    assert_eq!(
        declare_subscriber(&engine, past, &minted),
        Err(Refusal::KeyTooLong)
    );
    assert_eq!(engine.acquire_keyexpr(past), Err(Refusal::KeyTooLong));
    assert_eq!(
        filter(&engine, FilterPlane::Subscribers, past),
        Err(Refusal::KeyTooLong)
    );
    let listener: MatchingSink = Arc::new(|_matching: bool| {});
    assert_eq!(
        engine.declare_matching_listener(FilterPlane::Subscribers, past, listener, false),
        Err(Refusal::KeyTooLong),
        "a listener on the key is refused for its length"
    );
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        0,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), before, "nothing was sent");

    assert!(
        declare_subscriber(&engine, "demo/k/9", &minted).is_ok(),
        "a key of the session's bound is taken"
    );
}

/// The keyed rows of the session keep their keys in one key arena of `KEY_ARENA_BYTES`: a key
/// that finds no room there is refused as a full table refuses, before an id is taken, a callback
/// minted or anything sent, and the keys an undeclaration gives back are taken by the next
/// declaration.
#[test]
fn a_key_past_the_key_arena_is_refused_and_a_key_given_back_is_taken_again() {
    use wz_session_core::key_arena::block_bytes;

    // Room for exactly two subscribers of eight-byte keys: each is one row of the session core's
    // table, which keeps its key in one block.
    let room = 2 * block_bytes("demo/k/1".len()).expect("a short key");
    let limits = lowered(|l| l.select_key_arena_bytes(room));
    let plan = ArenaPlan::of(&client_config(), &limits).expect("lays an arena out");
    assert_eq!(plan.key_bytes(), room);
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let minted = Arc::new(AtomicUsize::new(0));
    let before = router.seen(|s| s.declares);
    let first = declare_subscriber(&engine, "demo/k/1", &minted).expect("room for a key");
    declare_subscriber(&engine, "demo/k/2", &minted).expect("room for the second key");
    until(&engine, "the router to see both subscribers", || {
        router.seen(|s| s.declares) >= before + 2
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(
        declare_subscriber(&engine, "demo/k/3", &minted),
        Err(Refusal::TableFull)
    );
    let listener: MatchingSink = Arc::new(|_matching: bool| {});
    assert_eq!(
        engine.declare_matching_listener(FilterPlane::Subscribers, "demo/k/3", listener, false),
        Err(Refusal::TableFull),
        "a key of the bound with no room left in the arena is refused as a full table"
    );
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        2,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");

    engine.undeclare_subscriber(first);
    assert!(
        declare_subscriber(&engine, "demo/k/3", &minted).is_ok(),
        "the key given back takes it"
    );
}

/// A wild key reaches the router as any other: the tables lent at open canonize it in a working
/// buffer of their own, and a declaration the observer refused would answer `None`, not an id
/// that was never announced.
#[test]
fn a_wild_key_is_declared_and_reaches_the_router() {
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, SessionLimits::defaults());
    let minted = Arc::new(AtomicUsize::new(0));
    let before = router.seen(|s| s.declares);
    declare_subscriber(&engine, "demo/wild/**", &minted).expect("a wild subscriber is declared");
    until(&engine, "the router to see the wild subscriber", || {
        router.seen(|s| s.declares) > before
    });
    assert_eq!(minted.load(Ordering::SeqCst), 1);
}
