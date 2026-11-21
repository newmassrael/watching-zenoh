// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables of the session's own declarations, lent from its arena at open: each holds as many
//! rows as the limit the open resolved, and the declaration past them is refused before an id is
//! taken, a callback minted or anything sent; a row given back takes the next declaration.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{
    FilterId, FilterPlane, MatchingSink, SessionDrive, SessionEngine, SubId, SubscriberSink,
    WireKey,
};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{client_config, config, open_with, until, CatchAll, Engine, Router};
use crate::arena::ArenaPlan;
use crate::CoopConfig;

/// The build's limits with `select` applied, or `None` on a build whose domain of the limit is its
/// own value alone, which a test cannot lower.
fn lowered(select: impl FnOnce(&mut SessionLimits) -> bool) -> Option<SessionLimits> {
    let mut limits = SessionLimits::defaults();
    select(&mut limits).then_some(limits)
}

/// A session open to `router` under `limits`.
fn open_under(router: &Router, limits: SessionLimits) -> Arc<Engine> {
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

fn declare_subscriber(engine: &Engine, key: &str, minted: &Arc<AtomicUsize>) -> Option<SubId> {
    engine.declare_subscriber_on_wire(
        key.to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        subscriber_sink(minted),
    )
}

/// A write filter that asks for `key`, on `plane`.
fn filter(engine: &Engine, plane: FilterPlane, key: &str) -> Option<FilterId> {
    engine.declare_write_filter(
        plane,
        key.to_owned(),
        &WireKey::literal(),
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some(key.to_owned()),
            aggregate: false,
        }),
        false,
    )
}

/// The plan lends each table of the session's own declarations the value of its limit the open
/// resolved: lowered, its row is the lowered count, and the write filters' row is a publisher's
/// and a querier's each.
#[test]
fn the_plan_lends_each_declaration_table_its_limit() {
    let Some(limits) = lowered(|l| {
        l.select_max_subscriptions(Quota::at_most(2)).is_ok()
            && l.select_max_publishers(Quota::at_most(3)).is_ok()
            && l.select_max_queriers(Quota::at_most(4)).is_ok()
            && l.select_max_matching_listeners(Quota::at_most(5)).is_ok()
            && l.select_max_declared_keyexprs(Quota::at_most(6)).is_ok()
    }) else {
        return;
    };
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
    assert_eq!(count("subscriber declarations"), Some(2));
    assert_eq!(count("key expressions"), Some(6));
    assert_eq!(count("write filters"), Some(7));
    assert_eq!(count("matching listeners"), Some(5));
    assert_eq!(count("interests"), Some(12));
}

/// The subscribers' table at its limit refuses one more: no id, no callback minted, nothing sent.
/// Undeclaring one gives its row back, and the next declaration takes it.
#[test]
fn a_subscriber_past_its_table_is_refused_and_sends_nothing() {
    let Some(limits) = lowered(|l| l.select_max_subscriptions(Quota::at_most(2)).is_ok()) else {
        return;
    };
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

    assert_eq!(declare_subscriber(&engine, "demo/s/3", &minted), None);
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        2,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");

    engine.undeclare_subscriber(first);
    assert!(
        declare_subscriber(&engine, "demo/s/3", &minted).is_some(),
        "the row the undeclaration gave back takes the next one"
    );
}

/// A key expression takes a row only while no declaration holds it: a second hold on a held key
/// takes none, a new key past the table is refused with nothing sent, and the row comes back
/// when the last hold goes.
#[test]
fn a_key_expression_past_its_table_is_refused_and_sends_nothing() {
    let Some(limits) = lowered(|l| l.select_max_declared_keyexprs(Quota::at_most(1)).is_ok())
    else {
        return;
    };
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let before = router.seen(|s| s.declares);
    let id = engine
        .acquire_keyexpr("demo/k/a".to_owned())
        .expect("a row is free");
    assert_eq!(
        engine.acquire_keyexpr("demo/k/a".to_owned()),
        Some(id),
        "a held key is held again, in its row"
    );
    until(&engine, "the router to see the key", || {
        router.seen(|s| s.declares) > before
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(engine.acquire_keyexpr("demo/k/b".to_owned()), None);
    settle(&engine);
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");
    assert_eq!(engine.keyexpr_declarations().len(), 1);

    engine.release_keyexpr(id);
    assert_eq!(
        engine.acquire_keyexpr("demo/k/b".to_owned()),
        None,
        "one hold is left on the first key"
    );
    engine.release_keyexpr(id);
    assert!(
        engine.acquire_keyexpr("demo/k/b".to_owned()).is_some(),
        "the last hold gone, its row takes the next key"
    );
}

/// A publisher's write filter is held to MAX_PUBLISHERS and a querier's to MAX_QUERIERS: one past
/// a plane's count is refused before its Interest is asked, while the other plane still takes
/// its own.
#[test]
fn a_write_filter_past_its_planes_count_is_refused_and_asks_nothing() {
    let Some(limits) = lowered(|l| {
        l.select_max_publishers(Quota::at_most(1)).is_ok()
            && l.select_max_queriers(Quota::at_most(1)).is_ok()
    }) else {
        return;
    };
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let publisher =
        filter(&engine, FilterPlane::Subscribers, "demo/p/1").expect("a publisher's row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    assert_eq!(filter(&engine, FilterPlane::Subscribers, "demo/p/2"), None);
    settle(&engine);
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    let querier = FilterPlane::Queryables {
        complete_required: false,
    };
    assert!(
        filter(&engine, querier, "demo/q/1").is_some(),
        "a querier's row is its own"
    );
    assert_eq!(filter(&engine, querier, "demo/q/2"), None);

    engine.undeclare_write_filter(publisher);
    assert!(
        filter(&engine, FilterPlane::Subscribers, "demo/p/2").is_some(),
        "the row the undeclaration gave back takes the next publisher"
    );
}

/// The matching listeners' table at its limit refuses one more, as a listener the session cannot
/// hold (id 0), before its Interest is asked; its sink goes with the refusal.
#[test]
fn a_matching_listener_past_its_table_is_refused_and_asks_nothing() {
    let Some(limits) = lowered(|l| l.select_max_matching_listeners(Quota::at_most(1)).is_ok())
    else {
        return;
    };
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let first_sink: MatchingSink = Arc::new(|_matching: bool| {});
    let first = engine.declare_matching_listener(
        FilterPlane::Subscribers,
        "demo/m/1".to_owned(),
        first_sink,
        false,
    );
    assert_ne!(first, 0, "a row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    let refused_sink: MatchingSink = Arc::new(|_matching: bool| {});
    let held = Arc::downgrade(&refused_sink);
    let refused = engine.declare_matching_listener(
        FilterPlane::Subscribers,
        "demo/m/2".to_owned(),
        refused_sink,
        false,
    );
    assert_eq!(refused, 0);
    assert!(
        held.upgrade().is_none(),
        "the refused listener's sink is let go"
    );
    settle(&engine);
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    engine.undeclare_matching_listener(first);
    let again: MatchingSink = Arc::new(|_matching: bool| {});
    assert_ne!(
        engine.declare_matching_listener(
            FilterPlane::Subscribers,
            "demo/m/2".to_owned(),
            again,
            false,
        ),
        0,
        "the row the undeclaration gave back takes the next listener"
    );
}

/// The queryables' table at its limit refuses one more: no callback minted, nothing sent.
#[cfg(feature = "queryable")]
#[test]
fn a_queryable_past_its_table_is_refused_and_sends_nothing() {
    use wz_capi_port::{QueryCallback, QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let Some(limits) = lowered(|l| l.select_max_queryables(Quota::at_most(1)).is_ok()) else {
        return;
    };
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
            key.to_owned(),
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

    assert_eq!(declare("demo/qbl/2"), None);
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        1,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");

    engine.undeclare_queryable(first);
    assert!(
        declare("demo/qbl/2").is_some(),
        "the row given back takes it"
    );
}

/// The tokens' table at its limit refuses one more, sending nothing.
#[cfg(feature = "liveliness")]
#[test]
fn a_token_past_its_table_is_refused_and_sends_nothing() {
    let Some(limits) = lowered(|l| l.select_max_local_tokens(Quota::at_most(1)).is_ok()) else {
        return;
    };
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let first = engine
        .declare_liveliness_token_on_wire("demo/t/1".to_owned(), WireKey::literal(), None)
        .expect("a row is free");
    until(&engine, "the router to see the token", || {
        router.seen(|s| s.tokens.len()) == 1
    });
    let seen = router.seen(|s| s.declares);

    assert_eq!(
        engine.declare_liveliness_token_on_wire("demo/t/2".to_owned(), WireKey::literal(), None),
        None
    );
    settle(&engine);
    assert_eq!(router.seen(|s| s.declares), seen, "nothing was sent");
    assert_eq!(router.seen(|s| s.tokens.len()), 1);

    engine.undeclare_liveliness_token(first);
    assert!(
        engine
            .declare_liveliness_token_on_wire("demo/t/2".to_owned(), WireKey::literal(), None)
            .is_some(),
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

    let Some(limits) = lowered(|l| {
        l.select_max_liveliness_subscriptions(Quota::at_most(1))
            .is_ok()
    }) else {
        return;
    };
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
        engine.declare_liveliness_subscriber_on_wire(
            key.to_owned(),
            WireKey::literal(),
            false,
            sink(&minted),
        )
    };
    let first = declare("demo/ls/1").expect("a row is free");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    let asked = router.seen(|s| s.interests);

    assert_eq!(declare("demo/ls/2"), None);
    settle(&engine);
    assert_eq!(
        minted.load(Ordering::SeqCst),
        1,
        "no callback for a refusal"
    );
    assert_eq!(router.seen(|s| s.interests), asked, "nothing was asked");

    engine.undeclare_subscriber(first);
    assert!(
        declare("demo/ls/2").is_some(),
        "the row given back takes it"
    );
}
