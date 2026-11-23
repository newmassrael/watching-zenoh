// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Delivery of the session's own get to the session's own queryables: the get reaches them
//! inside the call, after it has gone out on the link, by the destination it is made with and
//! the origin each queryable admits, and ends once the link's peer and every queryable of the
//! session have answered; and a querier's write filter or matching listener that counts the
//! session's own entities counts them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{
    FilterPlane, HeldQuery, NoRoomToHold, QblId, QueryCallback, QueryHolder, ReplyCallback,
    SessionDrive, SessionEngine, WireKey,
};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::query_mode::ConsolidationMode;
use wz_session_core::query_options::QueryOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::{ReplyKind, ReplyView};

use super::get::{ask, settle, Leg};
use super::{open, until, CatchAll, Command, Engine, Router};

/// What the queryable of `a_get_made_inside_a_queryables_own_callback_is_answered_once_it_returns`
/// saw of the get it made from inside its callback: whether it was issued, whether it was still
/// open with no reply when the get returned, and its leg.
type InnerGet = Arc<Mutex<Option<(Option<usize>, bool, Arc<Mutex<Leg>>)>>>;

/// What a queryable was shown of each get: its parameters, payload and attachment, and whether it
/// had an encoding.
type Shown = Arc<Mutex<Vec<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, bool)>>>;

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
            keyexpr,
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

/// Run `body` on a thread of its own and wait at most five seconds for what it returns: a call
/// that waits on a lock it holds fails the test by name instead of holding the run for ever.
fn within_five_seconds<R: Send + 'static>(
    what: &str,
    body: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(body());
    });
    outcome
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} did not return within five seconds"))
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
    assert_eq!(
        issued,
        Some(2),
        "a leg to the peer and one to the session's own"
    );
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
            "demo/lq/x",
            Arc::new(move |matching| into.lock().unwrap().push(matching)),
            count_local,
        );
        log
    };
    let counting = listen(true);
    let blind = listen(false);
    let filter = |count_local: bool| {
        engine
            .declare_write_filter(
                plane,
                "demo/lq/x",
                &WireKey::literal(),
                Some(InterestForm {
                    mapping_id: 0,
                    suffix: Some("demo/lq/x".to_owned()),
                    aggregate: false,
                }),
                count_local,
            )
            .expect("a session with ids left declares")
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

/// A get a queryable of the session makes from inside its own callback, on a key that queryable
/// answers, cannot reach that callback while it runs: its query waits for the callback to return
/// and is answered then, still inside the outer get. The CONTROL is the inner get as the callback
/// saw it: issued, and open with no reply.
#[test]
fn a_get_made_inside_a_queryables_own_callback_is_answered_once_it_returns() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let session = Arc::downgrade(&engine);
    let inner: InnerGet = Arc::default();
    let into = inner.clone();
    declare(
        &engine,
        "demo/lq/**",
        Locality::Any,
        move |_, query, out| {
            out.reply_keyed(query.keyexpr(), b"own")
                .expect("a reply on the query's own key");
            if query.keyexpr() != "demo/lq/outer" {
                return;
            }
            let Some(engine) = session.upgrade() else {
                return;
            };
            let (issued, leg) = ask(
                &engine,
                "demo/lq/inner",
                &get_for(Locality::SessionLocal),
                None,
                None,
                None,
            );
            let open = {
                let seen = leg.lock().unwrap();
                !seen.ended && seen.replies.is_empty()
            };
            *into.lock().unwrap() = Some((issued, open, leg));
        },
    );

    let (issued, outer) = ask(
        &engine,
        "demo/lq/outer",
        &get_for(Locality::SessionLocal),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1));
    {
        let outer = outer.lock().unwrap();
        assert!(outer.ended, "the outer get ended inside its call");
        assert_eq!(
            outer.replies,
            [(ReplyKind::Put, "demo/lq/outer".to_owned(), b"own".to_vec())]
        );
    }
    let (inner_issued, open_inside, leg) = inner
        .lock()
        .unwrap()
        .take()
        .expect("the callback made its get");
    assert_eq!(inner_issued, Some(1));
    assert!(
        open_inside,
        "CONTROL: inside the callback the inner get was asked and not answered"
    );
    let leg = leg.lock().unwrap();
    assert!(
        leg.ended,
        "answered once the callback returned, inside the outer get"
    );
    assert_eq!(
        leg.replies,
        [(ReplyKind::Put, "demo/lq/inner".to_owned(), b"own".to_vec())]
    );
}

/// A session with no row left to hold a Final refuses a get of its own whole: no queryable is
/// asked, nothing is sent to the peer and no leg is minted, and the row given back holds the next.
/// The CONTROL is the first get, whose query a queryable keeps in the one row.
#[test]
fn a_get_of_its_own_with_no_row_for_its_final_is_refused_whole() {
    let limits = super::entity_tables::lowered(|l| l.select_max_pending_finals(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = super::entity_tables::open_under(&router, limits);
    settle(&router, &engine, Command::Silence);
    let kept: Arc<Mutex<Option<Box<dyn HeldQuery>>>> = Arc::new(Mutex::new(None));
    let asked = Arc::new(AtomicUsize::new(0));
    let (slot, count) = (kept.clone(), asked.clone());
    declare(
        &engine,
        "demo/lq/**",
        Locality::Any,
        move |holder, query, _out| {
            count.fetch_add(1, Ordering::SeqCst);
            *slot.lock().unwrap() = Some(holder.hold_query(query));
        },
    );
    let (issued, first) = ask(
        &engine,
        "demo/lq/a",
        &get_for(Locality::SessionLocal),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1));
    assert!(
        kept.lock().unwrap().is_some() && !first.lock().unwrap().ended,
        "CONTROL: the kept query holds the one row"
    );

    let minted = Arc::new(AtomicUsize::new(0));
    let counting = minted.clone();
    let asking = engine.clone();
    let refused = within_five_seconds("the refused get", move || {
        asking.get_held(
            "demo/lq/b",
            &WireKey::literal(),
            &get_unconsolidated(),
            None,
            &mut || {
                counting.fetch_add(1, Ordering::SeqCst);
                ReplyCallback::shared(|_view: &dyn ReplyView| {})
            },
        )
    });
    assert_eq!(refused, Err(NoRoomToHold));
    assert_eq!(minted.load(Ordering::SeqCst), 0, "no leg was minted");
    assert_eq!(asked.load(Ordering::SeqCst), 1, "no queryable was asked");
    let quiet = Instant::now() + Duration::from_millis(100);
    while Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(router.seen(|s| s.queries), 0, "nothing was sent");

    let held = kept.lock().unwrap().take();
    drop(held);
    assert!(
        first.lock().unwrap().ended,
        "the kept query let go: its Final"
    );
    let (issued, _next) = ask(
        &engine,
        "demo/lq/c",
        &get_for(Locality::SessionLocal),
        None,
        None,
        None,
    );
    assert_eq!(issued, Some(1), "the row given back holds the next");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// A queryable of the session is shown its own get's parameters, value and attachment as a peer's
/// queryable reads them off the wire, and none of them for a get that carries none: an empty
/// value with no encoding of its own is no value, as the wire elides it.
#[test]
fn a_queryable_of_the_session_reads_what_its_own_get_carries() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let shown: Shown = Arc::default();
    let into = shown.clone();
    declare(&engine, "demo/lq/**", Locality::Any, move |_, query, _| {
        into.lock().unwrap().push((
            query.parameters().map(<[u8]>::to_vec),
            query.payload().map(<[u8]>::to_vec),
            query.attachment().map(<[u8]>::to_vec),
            query.encoding().is_some(),
        ));
    });
    let carrying = get_for(Locality::SessionLocal)
        .with_parameters(b"x=1".to_vec())
        .with_payload(b"v".to_vec())
        .with_attachment(b"a".to_vec());
    let (issued, _) = ask(&engine, "demo/lq/a", &carrying, None, None, None);
    assert_eq!(issued, Some(1));
    let empty = get_for(Locality::SessionLocal).with_payload(Vec::new());
    let (issued, _) = ask(&engine, "demo/lq/b", &empty, None, None, None);
    assert_eq!(issued, Some(1));
    assert_eq!(
        *shown.lock().unwrap(),
        [
            (
                Some(b"x=1".to_vec()),
                Some(b"v".to_vec()),
                Some(b"a".to_vec()),
                true
            ),
            (None, None, None, false),
        ]
    );
}
