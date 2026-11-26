// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The answering end of a query: the router asks, the session's queryable answers outside the
//! session's lock, and the Final follows the replies.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_port::{HeldQueryId, QueryHolder, QueryableSink, SessionDrive, SessionEngine, WireKey};
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::query_sink::{QueryView, ReplyOut};

use super::{open, until, CatchAll, Command, Engine, Router};
use crate::EngineHold;

/// Declare a queryable on `keyexpr` whose callback is `answer`, given what the session holds
/// queries through.
fn declare(
    engine: &Engine,
    keyexpr: &str,
    answer: impl Fn(&dyn QueryHolder, &dyn QueryView, &mut dyn ReplyOut) + Send + Sync + 'static,
) {
    engine
        .declare_queryable_on_wire(
            keyexpr,
            WireKey::literal(),
            false,
            Locality::Remote,
            None,
            QueryableSink::shared(move |query, out, holder| answer(holder, query, out)),
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

/// A turn of an answer holds its link's replies from its first reply and lets them go after its
/// Final, so the replies and the Final leave in one send, in the order they were made. A read
/// that steps its one link itself holds them across its callbacks instead (`queries`), so the
/// count is read where the query is handed out of the round. The CONTROL is the order: two
/// replies, then the Final. Turned red by a first reply that raises no hold (the count stays
/// where it was), or by an answer that never lets it go (the Final then never reaches the router).
#[cfg(all(
    feature = "std",
    any(feature = "threads", feature = "listen", feature = "group")
))]
#[test]
fn an_answers_replies_are_held_to_leave_with_its_final() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    declare(&engine, "demo/h/**", move |_, query, out| {
        out.reply_keyed(query.keyexpr(), b"one")
            .expect("a reply on the query's own key");
        out.reply_keyed(query.keyexpr(), b"two")
            .expect("a reply on the query's own key");
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    let held = engine.answers_held();
    router.send(Command::Query(5, "demo/h/a"));
    until(&engine, "the replies and the final", || {
        router.seen(|s| s.answers.len()) >= 3
    });
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        vec!["reply", "reply", "final"],
        "CONTROL: the replies, then the Final"
    );
    assert_eq!(
        engine.answers_held() - held,
        1,
        "one hold for the turn, raised by its first reply and let go after its Final"
    );
}

/// A query asked in one frame between two Pushes is answered as one asked alone is: its reply,
/// then its Final, each once. Its Final is owed by its own record's dispatch and taken there, so the
/// drain after the Push that follows it in the frame finds none owed, which a debug build asserts
/// (`RegistryOf::settle`). Turned red by a Final left owed past its Request's record, or by
/// a drain after a run of Pushes that sends one again.
#[cfg(feature = "std")]
#[test]
fn a_query_between_pushes_is_answered_then_finalled_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    declare(&engine, "demo/between/**", move |_, query, out| {
        out.reply_keyed(query.keyexpr(), b"one")
            .expect("a reply on the query's own key");
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    let (alone, ..) = engine.push_dispatches();
    let within = engine.drains_within_frames();
    router.send(Command::QueryBetweenPushes(
        "demo/pushed",
        11,
        "demo/between/a",
    ));
    until(&engine, "both Pushes, the reply and the final", || {
        engine.push_dispatches().0 >= alone + 2 && router.seen(|s| s.answers.len()) >= 2
    });
    let quiet = std::time::Instant::now() + Duration::from_millis(400);
    while std::time::Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(router.seen(|s| s.answers.clone()), vec!["reply", "final"]);
    assert!(
        engine.drains_within_frames() > within,
        "the Request came in the frame of the Push before it"
    );
}

/// A query the callback keeps holds its Final until the C program lets go of it, and a reply made
/// in between goes out before the Final. The CONTROL is the wait: with the query kept, no Final
/// reaches the router however long the session is stepped.
#[test]
fn a_kept_query_holds_its_final_until_it_is_dropped() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let kept: Arc<Mutex<Option<HeldQueryId>>> = Arc::default();
    let slot = kept.clone();
    declare(&engine, "demo/k/**", move |holder, query, _out| {
        *slot.lock().unwrap() = holder.keep_query(query).expect("room to keep the query");
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
    engine.reply_held(held, "demo/k/a", &mut |out| {
        out.reply_keyed("demo/k/a", b"later")
            .expect("a reply on the query's own key");
    });
    until(&engine, "the late reply", || {
        router.seen(|s| s.answers.len()) >= 1
    });
    engine.release_held(held);
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
    let kept: Arc<Mutex<Vec<HeldQueryId>>> = Arc::default();
    let slot = kept.clone();
    declare(&engine, "demo/f/**", move |holder, query, _out| {
        let held = holder.keep_query(query).expect("room to keep the query");
        slot.lock()
            .unwrap()
            .push(held.expect("the query this callback answers"));
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

    let first = kept.lock().unwrap().remove(0);
    engine.release_held(first);
    until(&engine, "the first kept query's final", || {
        router.seen(|s| s.answers.len()) >= 1
    });
    router.send(Command::Query(4, "demo/f/d"));
    until(&engine, "the freed row to hold the next query", || {
        held() == 2
    });

    let rest: Vec<HeldQueryId> = kept.lock().unwrap().drain(..).collect();
    for held in rest {
        engine.release_held(held);
    }
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

/// A query's replies go out as its callback makes them, more of them than the build's
/// `MAX_PENDING_REPLIES`, as nothing stages them; one whose payload is past the session's
/// `MAX_REPLY_PAYLOAD_BYTES` is refused to the callback and not sent, and the Final follows the
/// last reply sent. A kept query's late reply goes out the same way. The CONTROL is the replies
/// under the bound, each reaching the router.
#[test]
fn replies_go_out_as_they_are_made_with_no_count_and_the_payload_bound() {
    use wz_session_core::query_sink::ReplyError;

    let limits =
        super::entity_tables::lowered(|l| l.select_max_reply_payload_bytes(Quota::at_most(16)));
    let router = Router::start(CatchAll::None);
    let engine = super::entity_tables::open_under(&router, limits);
    let many = wz_session_core::caps::MAX_PENDING_REPLIES + 2;
    let refused: Arc<Mutex<Option<Result<(), ReplyError>>>> = Arc::default();
    let kept: Arc<Mutex<Option<HeldQueryId>>> = Arc::default();
    let (refusal, slot) = (refused.clone(), kept.clone());
    declare(&engine, "demo/r/**", move |holder, query, out| {
        for _ in 0..many {
            out.reply_keyed(query.keyexpr(), b"small")
                .expect("a reply under the bound");
        }
        *refusal.lock().unwrap() = Some(out.reply_keyed(query.keyexpr(), &[0u8; 17]));
        *slot.lock().unwrap() = holder.keep_query(query).expect("room to keep the query");
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    router.send(Command::Query(1, "demo/r/a"));
    until(&engine, "every reply under the bound", || {
        router.seen(|s| s.answers.len()) >= many
    });
    assert_eq!(
        *refused.lock().unwrap(),
        Some(Err(ReplyError::PayloadTooLarge)),
        "a payload past the bound is refused to the callback"
    );
    let held = kept.lock().unwrap().take().expect("the kept query");
    engine.reply_held(held, "demo/r/a", &mut |out| {
        out.reply_keyed("demo/r/a", b"later")
            .expect("a reply on the query's own key");
    });
    engine.release_held(held);
    until(&engine, "the late reply and the final", || {
        router.seen(|s| s.answers.len()) >= many + 2
    });
    let mut expected = vec!["reply"; many + 1];
    expected.push("final");
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        expected,
        "every reply under the bound, none past it, then the final"
    );
}

/// A kept query holds nothing of its session but its id: the session's last handle lets the
/// engine go with a query still kept, the rows of its held Finals before its arena, a reply to it
/// once the session is closed answers nothing, and the close leaves the session reached by
/// nothing. The CONTROL is the session standing while its handle is held. Turned red by a closed
/// session that still answers a kept query or is still reached, or by a keep that holds the
/// engine, and so its arena, alive.
#[test]
fn a_query_kept_past_its_session_holds_none_of_it() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let kept: Arc<Mutex<Option<HeldQueryId>>> = Arc::default();
    let slot = kept.clone();
    declare(&engine, "demo/p/**", move |holder, query, _out| {
        *slot.lock().unwrap() = holder.keep_query(query).expect("room to keep the query");
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    router.send(Command::Query(5, "demo/p/a"));
    until(&engine, "the callback to keep the query", || {
        kept.lock().unwrap().is_some()
    });
    let held = kept.lock().unwrap().take().expect("the kept query");
    assert!(
        !SessionEngine::is_closed(&*engine),
        "CONTROL: the session stands while its handle is held"
    );

    let gone = EngineHold::downgrade(&engine);
    SessionDrive::close(&*engine);
    assert!(
        gone.upgrade().is_none(),
        "closed, the session is reached by nothing"
    );
    let mut answered = false;
    engine.reply_held(held, "demo/p/a", &mut |_out| answered = true);
    assert!(!answered, "a query of a closed session answers nothing");
    assert_eq!(
        EngineHold::holders(&engine),
        1,
        "the kept query keeps nothing of the engine alive"
    );
    engine.release_held(held);
    drop(engine);
}

/// Keeping a query, answering it later and letting it go take no memory of the heap: the hold is a
/// row the session lent at its open, which keeps what the replies are built from beside the key,
/// the caller hands the key to the reply, and the program holds plain values. The allocations
/// counted are the calling thread's, which keeps the query from inside its callback and answers
/// and lets it go after. The CONTROL is the reply and the Final reaching the router: the counted
/// calls did their work. Turned red by a keep that copies the query's key or parameters onto the
/// heap, or boxes what it holds.
#[test]
fn keeping_answering_and_letting_go_of_a_query_allocate_nothing() {
    use super::redial_heap::counted;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let kept: Arc<Mutex<Option<(HeldQueryId, u64)>>> = Arc::default();
    let slot = kept.clone();
    declare(&engine, "demo/z/**", move |holder, query, _out| {
        let mut held = None;
        let allocations = counted(|| {
            held = holder.keep_query(query).expect("room to keep the query");
        });
        *slot.lock().unwrap() = held.map(|held| (held, allocations));
    });
    until(&engine, "the router to see the queryable", || {
        router.seen(|s| s.declares) >= 1
    });
    router.send(Command::Query(11, "demo/z/a"));
    until(&engine, "the callback to keep the query", || {
        kept.lock().unwrap().is_some()
    });
    let (held, keeping) = kept.lock().unwrap().take().expect("the kept query");
    let answering = counted(|| {
        engine.reply_held(held, "demo/z/a", &mut |out| {
            out.reply_keyed("demo/z/a", b"late")
                .expect("a reply on the query's own key");
        });
    });
    let letting_go = counted(|| engine.release_held(held));
    until(&engine, "the reply and the final", || {
        router.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        vec!["reply", "final"],
        "CONTROL: the kept query was answered and let go"
    );
    assert_eq!(
        (keeping, answering, letting_go),
        (0, 0, 0),
        "a kept query takes no memory of the heap"
    );
}
