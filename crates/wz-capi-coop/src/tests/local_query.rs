// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Delivery of the session's own get to the session's own queryables: the get reaches them
//! inside the call, after it has gone out on the link, by the destination it is made with and
//! the origin each queryable admits, and ends once the link's peer and every queryable of the
//! session have answered; and a querier's write filter or matching listener that counts the
//! session's own entities counts them.

use std::sync::{Arc, Mutex};

use wz_capi_port::{
    FilterPlane, HeldQuery, QblId, QueryCallback, QueryHolder, SessionEngine, WireKey,
};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::locality::Locality;
use wz_session_core::query_mode::ConsolidationMode;
use wz_session_core::query_options::QueryOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyKind;

use super::get::{ask, settle};
use super::{open, until, CatchAll, Command, Engine, Router};

/// Declare a queryable on `keyexpr` that admits `origin` and whose callback is `answer`.
fn declare(
    engine: &Engine,
    keyexpr: &str,
    origin: Locality,
    answer: impl Fn(&Arc<dyn QueryHolder>, &dyn QueryView, &mut dyn ReplyOut) + Send + Sync + 'static,
) -> QblId {
    let answer = Arc::new(answer);
    engine
        .declare_queryable_on_wire(
            keyexpr.to_owned(),
            WireKey::literal(),
            false,
            origin,
            None,
            Arc::new(move |holder: Arc<dyn QueryHolder>| {
                let answer = answer.clone();
                Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    answer(&holder, query, out)
                }) as QueryCallback
            }),
        )
        .expect("the engine has queryables in this build")
}

/// A queryable that answers each query with `payload`, on the query's own key.
fn answering(engine: &Engine, keyexpr: &str, origin: Locality, payload: &'static [u8]) -> QblId {
    declare(engine, keyexpr, origin, move |_, query, out| {
        out.reply_keyed(query.keyexpr(), payload)
            .expect("a reply on the query's own key");
    })
}

/// A get that hands each reply over as it comes: the default consolidation keeps the latest
/// reply of a key until the get is over, which would hide the order the tests look at.
fn get_unconsolidated() -> QueryOptions {
    QueryOptions::get().with_consolidation(ConsolidationMode::None)
}

fn get_for(destination: Locality) -> QueryOptions {
    get_unconsolidated().with_allowed_destination(destination)
}

/// A get made for the session alone reaches its own queryables inside the call and ends there,
/// with nothing stepped and no router asked: the one that admits any origin and the one that
/// admits only the session's own answer, and not the one that admits only a peer's.
#[test]
fn a_get_for_the_session_alone_is_answered_by_its_own_queryables_inside_the_call() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    answering(&engine, "demo/lq/**", Locality::Any, b"any");
    answering(&engine, "demo/lq/**", Locality::SessionLocal, b"own");
    answering(&engine, "demo/lq/**", Locality::Remote, b"peer");

    let (issued, leg) = ask(
        &engine,
        "demo/lq/a",
        &get_for(Locality::SessionLocal),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1));
    let leg = leg.lock().unwrap();
    assert!(
        leg.ended,
        "the callbacks ran and the Final came inside the get"
    );
    let mut payloads: Vec<_> = leg.replies.iter().map(|r| r.2.clone()).collect();
    payloads.sort();
    assert_eq!(
        payloads,
        [b"any".to_vec(), b"own".to_vec()],
        "not the queryable that admits only a peer's query"
    );
    assert!(leg.replies.iter().all(|r| r.0 == ReplyKind::Put));
    drop(leg);
    settle(&router, &engine, Command::Silence);
    assert_eq!(
        router.seen(|s| s.queries),
        0,
        "CONTROL: a get for the session alone goes out on no link"
    );
}

/// A get made for any destination goes out and reaches the session's own queryables, and ends
/// when both have answered: the own reply is there when the call returns, the leg is still open
/// for the router's Final, and the router's reply and Final come with the steps.
#[test]
fn a_get_for_any_destination_waits_for_the_peer_and_the_session() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Answer("demo/lq/**", b"peer"));
    answering(&engine, "demo/lq/**", Locality::Any, b"own");

    let (issued, leg) = ask(
        &engine,
        "demo/lq/a",
        &get_unconsolidated(),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1));
    {
        let leg = leg.lock().unwrap();
        assert!(!leg.ended, "CONTROL: the router's Final is still owed");
        assert_eq!(
            leg.replies,
            [(ReplyKind::Put, "demo/lq/a".to_owned(), b"own".to_vec())],
            "the own reply came inside the call"
        );
    }
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    let mut payloads: Vec<_> = leg
        .lock()
        .unwrap()
        .replies
        .iter()
        .map(|r| r.2.clone())
        .collect();
    payloads.sort();
    assert_eq!(payloads, [b"own".to_vec(), b"peer".to_vec()]);
    assert_eq!(router.seen(|s| s.queries), 1);
}

/// A get made for peers alone asks no queryable of the session, which is the control of the
/// destination, and a get for the session alone with no queryable that matches ends at once with
/// no reply.
#[test]
fn a_get_for_peers_alone_asks_no_queryable_of_the_session() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let asked = Arc::new(Mutex::new(0usize));
    let into = asked.clone();
    declare(&engine, "demo/lq/**", Locality::Any, move |_, _, _| {
        *into.lock().unwrap() += 1;
    });

    let (_, leg) = ask(
        &engine,
        "demo/lq/a",
        &get_for(Locality::Remote),
        None,
        None,
        None,
    );
    until(&engine, "the query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });
    assert_eq!(*asked.lock().unwrap(), 0, "the queryable was not asked");
    drop(leg);

    let (issued, leg) = ask(
        &engine,
        "demo/other/a",
        &get_for(Locality::SessionLocal),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1));
    let leg = leg.lock().unwrap();
    assert!(leg.ended && leg.replies.is_empty(), "{:?}", leg.replies);
}

/// A query a queryable of the session keeps holds the get's Final until the C program lets go of
/// it, and a reply made in between reaches the get at once. The CONTROL is the wait: with the
/// query kept, the get stays open however long the session is stepped.
#[test]
fn a_kept_local_query_holds_its_get_open_until_it_is_dropped() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let kept: Arc<Mutex<Option<Box<dyn HeldQuery>>>> = Arc::new(Mutex::new(None));
    let slot = kept.clone();
    declare(
        &engine,
        "demo/lq/**",
        Locality::Any,
        move |holder, query, _out| {
            *slot.lock().unwrap() = Some(holder.hold_query(query));
        },
    );

    let (_, leg) = ask(
        &engine,
        "demo/lq/a",
        &get_for(Locality::SessionLocal),
        None,
        None,
        Some(engine.clone()),
    );
    assert!(
        kept.lock().unwrap().is_some(),
        "the callback kept the query"
    );
    let quiet = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < quiet {
        let _ = wz_capi_port::SessionDrive::read(&*engine, false);
    }
    assert!(
        !leg.lock().unwrap().ended,
        "CONTROL: a kept query's Final waits for it"
    );

    let held = kept.lock().unwrap().take().expect("the kept query");
    held.reply(&mut |out| {
        out.reply_keyed("demo/lq/a", b"later")
            .expect("a reply on the query's own key");
    });
    {
        let leg = leg.lock().unwrap();
        assert!(!leg.ended);
        assert_eq!(
            leg.replies,
            [(ReplyKind::Put, "demo/lq/a".to_owned(), b"later".to_vec())]
        );
    }
    drop(held);
    assert!(leg.lock().unwrap().ended, "the last hold let go: the Final");
}

/// A matching listener and a write filter on the queryables' plane that count the session's own
/// queryables match once one is declared and no more once it is retracted, with no peer declaring
/// any; the ones that do not count them match nothing, and a queryable that admits only a peer's
/// query is no match for the session's own get.
#[test]
fn a_filter_and_a_listener_count_the_sessions_own_queryables_when_asked() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let plane = FilterPlane::Queryables {
        complete_required: false,
    };
    let listen = |count_local: bool| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        engine.declare_matching_listener(
            plane,
            "demo/lq/x".to_owned(),
            Arc::new(move |matching| into.lock().unwrap().push(matching)),
            count_local,
        );
        log
    };
    let counting = listen(true);
    let blind = listen(false);
    let filter = |count_local: bool| {
        engine.declare_write_filter(
            plane,
            "demo/lq/x".to_owned(),
            &WireKey::literal(),
            Some(InterestForm {
                mapping_id: 0,
                suffix: Some("demo/lq/x".to_owned()),
                aggregate: false,
            }),
            count_local,
        )
    };
    let counting_filter = filter(true);
    let blind_filter = filter(false);
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    assert!(
        engine.write_filter_active(counting_filter),
        "nothing matches yet"
    );

    let id = answering(&engine, "demo/lq/**", Locality::Any, b"v");
    assert_eq!(
        *counting.lock().unwrap(),
        [true],
        "the session's own queryable matches"
    );
    assert!(
        blind.lock().unwrap().is_empty(),
        "one that does not count it hears nothing"
    );
    assert!(!engine.write_filter_active(counting_filter));
    assert!(
        engine.write_filter_active(blind_filter),
        "CONTROL: a filter that does not count it still suppresses"
    );

    engine.undeclare_queryable(id);
    assert_eq!(*counting.lock().unwrap(), [true, false]);
    assert!(engine.write_filter_active(counting_filter));
    assert!(blind.lock().unwrap().is_empty());

    answering(&engine, "demo/lq/**", Locality::Remote, b"v");
    assert_eq!(*counting.lock().unwrap(), [true, false]);
    assert!(engine.write_filter_active(counting_filter));
}
