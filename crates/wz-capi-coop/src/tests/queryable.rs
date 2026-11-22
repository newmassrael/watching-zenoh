// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The answering end of a query: the router asks, the session's queryable answers outside the
//! session's lock, and the Final follows the replies.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_port::{HeldQuery, QueryCallback, QueryHolder, SessionDrive, SessionEngine, WireKey};
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::query_sink::{QueryView, ReplyOut};

use super::{open, until, CatchAll, Command, Engine, Router};

/// Declare a queryable on `keyexpr` whose callback is `answer`, given what the session holds
/// queries through.
fn declare(
    engine: &Engine,
    keyexpr: &str,
    answer: impl Fn(&Arc<dyn QueryHolder>, &dyn QueryView, &mut dyn ReplyOut) + Send + Sync + 'static,
) {
    let answer = Arc::new(answer);
    engine
        .declare_queryable_on_wire(
            keyexpr.to_owned(),
            WireKey::literal(),
            false,
            Locality::Remote,
            None,
            Arc::new(move |holder: Arc<dyn QueryHolder>| {
                let answer = answer.clone();
                Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    answer(&holder, query, out)
                }) as QueryCallback
            }),
        )
        .expect("the engine has queryables in this build");
}

/// The router's query is answered by the session's queryable, and the Final follows the reply.
/// The callback runs where the deliveries are handed out, with nothing of the session held: it
/// steps the session again from inside itself, which would wait on the session's own lock if
/// the callback ran under it.
#[test]
fn a_query_is_answered_and_its_final_follows_the_reply() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let reentered = engine.clone();
    declare(&engine, "demo/q/**", move |_, query, out| {
        // A step from inside the callback: the session's lock is free.
        let _ = SessionDrive::read(&*reentered, false);
        out.reply_keyed(query.keyexpr(), b"one")
            .expect("a reply on the query's own key");
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    router.send(Command::Query(7, "demo/q/a"));
    until(&engine, "the reply and the final", || {
        router.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(router.seen(|s| s.answers.clone()), vec!["reply", "final"]);
}

/// A query the callback keeps holds its Final until the C program lets go of it, and a reply made
/// in between goes out before the Final. The CONTROL is the wait: with the query kept, no Final
/// reaches the router however long the session is stepped.
#[test]
fn a_kept_query_holds_its_final_until_it_is_dropped() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let kept: Arc<Mutex<Option<Box<dyn HeldQuery>>>> = Arc::new(Mutex::new(None));
    let slot = kept.clone();
    declare(&engine, "demo/k/**", move |holder, query, _out| {
        *slot.lock().unwrap() = Some(holder.hold_query(query));
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    router.send(Command::Query(9, "demo/k/a"));
    until(&engine, "the callback to keep the query", || {
        kept.lock().unwrap().is_some()
    });
    let quiet = std::time::Instant::now() + Duration::from_millis(400);
    while std::time::Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert!(
        router.seen(|s| s.answers.is_empty()),
        "CONTROL: a kept query's Final waits for it"
    );

    let held = kept.lock().unwrap().take().expect("the kept query");
    held.reply(&mut |out| {
        out.reply_keyed("demo/k/a", b"later")
            .expect("a reply on the query's own key");
    });
    until(&engine, "the late reply", || {
        router.seen(|s| s.answers.len()) >= 1
    });
    drop(held);
    until(&engine, "the final", || {
        router.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(router.seen(|s| s.answers.clone()), vec!["reply", "final"]);
}

/// Held to two Finals, a session that keeps two queries refuses the third: its callback never
/// runs, it is counted, and no Final answers it, as zenoh-pico refuses a query it cannot build
/// (it returns before any callback and sends no Final). A kept query let go frees its row, and the
/// next query is held again. The CONTROL is the two kept queries, whose Finals both reach the
/// router.
#[test]
fn a_query_past_the_finals_held_is_refused_without_a_final() {
    let limits = super::entity_tables::lowered(|l| l.select_max_pending_finals(Quota::at_most(2)));
    let router = Router::start(CatchAll::None);
    let engine = super::entity_tables::open_under(&router, limits);
    let kept: Arc<Mutex<Vec<Box<dyn HeldQuery>>>> = Arc::default();
    let slot = kept.clone();
    declare(&engine, "demo/f/**", move |holder, query, _out| {
        slot.lock().unwrap().push(holder.hold_query(query));
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    let held = || kept.lock().unwrap().len();
    router.send(Command::Query(1, "demo/f/a"));
    router.send(Command::Query(2, "demo/f/b"));
    until(&engine, "the callbacks to keep two queries", || held() == 2);
    router.send(Command::Query(3, "demo/f/c"));
    until(&engine, "the third query to be refused", || {
        engine.queries_refused() >= 1
    });
    let quiet = std::time::Instant::now() + Duration::from_millis(400);
    while std::time::Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(held(), 2, "the third query's callback never runs");
    assert_eq!(
        engine.queries_refused(),
        1,
        "the third query is counted once"
    );
    assert!(
        router.seen(|s| s.answers.is_empty()),
        "nothing answers a refused query, and the kept ones wait"
    );

    drop(kept.lock().unwrap().remove(0));
    until(&engine, "the first kept query's final", || {
        router.seen(|s| s.answers.len()) >= 1
    });
    router.send(Command::Query(4, "demo/f/d"));
    until(&engine, "the freed row to hold the next query", || {
        held() == 2
    });

    kept.lock().unwrap().clear();
    until(&engine, "the kept queries' finals", || {
        router.seen(|s| s.answers.len()) >= 3
    });
    let quiet = std::time::Instant::now() + Duration::from_millis(400);
    while std::time::Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        vec!["final", "final", "final"],
        "three Finals for the three queries held, none for the refused one"
    );
}
