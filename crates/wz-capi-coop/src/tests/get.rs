// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query: the session asks the router, its replies reach the leg's
//! callback outside the session's lock, and the leg ends when its Final comes, its deadline
//! passes, its token is cancelled or its link goes, each time as the drop of its callback.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::cancellation::{register_fan, CancellableFan, CancellationToken, TokenRef};
use wz_capi_port::lodge::Strong;
use wz_capi_port::{Refusal, ReplyCallback, SessionDrive, SessionEngine, WireKey};
use wz_session_core::limit_binding::Quota;
use wz_session_core::query_options::QueryOptions;
use wz_session_core::reply_sink::{ReplyKind, ReplyView};

use super::{open, until, CatchAll, Command, Engine, Router};
use crate::EngineHold;

/// What the callbacks of a get's legs saw: each reply as its kind, key and payload, and whether
/// every callback has been dropped, which is when the get is over.
#[derive(Default)]
pub(super) struct Leg {
    pub(super) replies: Vec<(ReplyKind, String, Vec<u8>)>,
    pub(super) ended: bool,
    /// The callbacks minted and not yet dropped.
    open: usize,
}

/// Owned by a leg's callback: the get is marked ended when the last callback is dropped.
struct Ends(Arc<Mutex<Leg>>);

impl Ends {
    fn mint(leg: &Arc<Mutex<Leg>>) -> Self {
        leg.lock().unwrap().open += 1;
        Self(leg.clone())
    }
}

impl Drop for Ends {
    fn drop(&mut self) {
        let mut leg = self.0.lock().unwrap();
        leg.open -= 1;
        leg.ended = leg.open == 0;
    }
}

/// Options for a get of the link's peer alone: the session's own queryables are not asked, so the
/// get has the one leg a test of the peer's part is about.
pub(super) fn remote_get() -> QueryOptions {
    let mut opts = QueryOptions::get();
    opts.allowed_destination = wz_session_core::locality::Locality::Remote;
    opts
}

/// Ask a get on `keyexpr` with `opts`, its legs recorded in what is returned, each holding
/// `registration` (the get's fan, which is its registration on its token) when there is one, as a
/// C get's callbacks hold theirs. `step`, when given, is stepped from inside each reply callback.
pub(super) fn ask(
    engine: &Engine,
    keyexpr: &str,
    opts: &QueryOptions,
    fan: Option<&CancellableFan>,
    registration: Option<Strong<CancellableFan>>,
    step: Option<EngineHold<Engine>>,
) -> (Result<usize, Refusal>, Arc<Mutex<Leg>>) {
    let leg = Arc::new(Mutex::new(Leg::default()));
    let seen = leg.clone();
    let issued = engine.get_on_wire(keyexpr, &WireKey::literal(), opts, fan, &mut || {
        let ends = Ends::mint(&seen);
        let registration = registration.clone();
        let step = step.clone();
        ReplyCallback::shared(move |view: &dyn ReplyView| {
            let _held = &registration;
            if let Some(engine) = &step {
                // A step from inside the callback: the session's lock is free.
                let _ = SessionDrive::read(&**engine, false);
            }
            ends.0.lock().unwrap().replies.push((
                view.kind(),
                view.keyexpr().to_owned(),
                view.payload().to_vec(),
            ));
        })
    });
    (issued, leg)
}

pub(super) fn settle(router: &Router, engine: &Engine, command: Command) {
    router.send(command);
    until(engine, "the router to settle", || {
        router.seen(|s| s.settled)
    });
}

/// The router's queryable answers, the reply reaches the leg's callback, and the Final ends the
/// leg. The callback runs with nothing of the session held: it steps the session again from
/// inside itself. The CONTROL is the leg before any step: nothing is delivered between two
/// calls, and the leg is open.
#[test]
fn a_get_is_answered_and_ends_with_its_final() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Answer("demo/g/**", b"r"));
    let (issued, leg) = ask(
        &engine,
        "demo/g/a",
        &remote_get(),
        None,
        None,
        Some(engine.clone()),
    );
    assert_eq!(issued, Ok(1), "one leg: the link's peer");
    {
        let leg = leg.lock().unwrap();
        assert!(
            leg.replies.is_empty() && !leg.ended,
            "CONTROL: nothing is delivered before a step"
        );
    }
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    assert_eq!(
        leg.lock().unwrap().replies,
        vec![(ReplyKind::Put, "demo/g/a".to_owned(), b"r".to_vec())]
    );
    assert_eq!(router.seen(|s| s.queries), 1);
}

/// A get that keeps the latest reply of each key holds its replies to its Final and hands each to
/// its callback after it, from the rows it held them in, before its end: one reply on each of three
/// keys, one of them deeper than the others. Turned red by a held reply put back in the round of
/// deliveries, which a build that reads a reply only where it lies has no place for, and whose gate
/// admits the room of one record where the Final releases three.
#[test]
fn a_latest_get_hands_each_key_it_held_after_its_final() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(
        &router,
        &engine,
        Command::AnswerOnKeys(
            "demo/m/**",
            &["demo/m/a", "demo/m/b", "demo/m/b/c/deeper"],
            b"v",
        ),
    );
    let opts =
        remote_get().with_consolidation(wz_session_core::query_mode::ConsolidationMode::Latest);
    let (issued, leg) = ask(&engine, "demo/m/**", &opts, None, None, None);
    assert_eq!(issued, Ok(1));
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    let leg = leg.lock().unwrap();
    let mut keys: Vec<&str> = leg
        .replies
        .iter()
        .map(|(kind, key, payload)| {
            assert_eq!((*kind, payload.as_slice()), (ReplyKind::Put, &b"v"[..]));
            key.as_str()
        })
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["demo/m/a", "demo/m/b", "demo/m/b/c/deeper"]);
    // A build whose read hands each reply to its get itself keeps no round to refuse one a place.
    #[cfg(wz_round)]
    assert_eq!(
        engine.round_counts().held_over,
        0,
        "no reply was refused a place"
    );
}

/// A get that consolidates nothing hands its replies to its callback in the order its peer sent
/// them, each once, and ends once, after the last: three replies on three keys. Read without a
/// round of deliveries where the read hands each reply to its get itself, and through one
/// elsewhere. Turned red by a reply handed out of its order, lost or handed twice, or by anything
/// handed after the end.
#[test]
fn a_gets_replies_come_in_their_order_and_its_end_after_them_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(
        &router,
        &engine,
        Command::AnswerOnKeys("demo/o/**", &["demo/o/1", "demo/o/2", "demo/o/3"], b"v"),
    );
    let opts =
        remote_get().with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
    let (issued, leg) = ask(&engine, "demo/o/**", &opts, None, None, None);
    assert_eq!(issued, Ok(1), "one leg: the link's peer");
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    let in_order = vec![
        (ReplyKind::Put, "demo/o/1".to_owned(), b"v".to_vec()),
        (ReplyKind::Put, "demo/o/2".to_owned(), b"v".to_vec()),
        (ReplyKind::Put, "demo/o/3".to_owned(), b"v".to_vec()),
    ];
    assert_eq!(leg.lock().unwrap().replies, in_order);
    // Reads past the end hand the ended leg nothing more: no second end's timeout, no reply.
    for _ in 0..8 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        leg.lock().unwrap().replies,
        in_order,
        "nothing after the end"
    );
    assert_eq!(router.seen(|s| s.queries), 1);
}

/// A get nobody answers ends at its deadline with zenoh's timeout reply, swept by the step that
/// comes due, not one idle wait later. The CONTROL is the leg halfway: it is still open.
#[test]
fn a_get_nobody_answers_ends_at_its_deadline() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let mut opts = remote_get();
    opts.timeout_ms = 300;
    let asked = Instant::now();
    let (issued, leg) = ask(&engine, "demo/g/a", &opts, None, None, None);
    assert_eq!(issued, Ok(1));
    while asked.elapsed() < Duration::from_millis(150) {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert!(
        !leg.lock().unwrap().ended,
        "CONTROL: open before its deadline"
    );
    until(&engine, "the deadline", || leg.lock().unwrap().ended);
    let took = asked.elapsed();
    assert!(took >= Duration::from_millis(300), "ended early: {took:?}");
    let replies = leg.lock().unwrap().replies.clone();
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0].0, ReplyKind::Err);
    assert_eq!(replies[0].2, b"Timeout");
    assert_eq!(router.seen(|s| s.queries), 1, "the query went out");
}

/// A get asked between two reads of a session whose reads wait long ends at its deadline, and a
/// later get asked before it bounds the wait after it: the legs held lower the ledger a read's
/// wait reads, and the service that sweeps the first settles it to the deadline left. The
/// CONTROL is the wait before any get, which no deadline bounds. Turned red by a leg held without
/// lowering the ledger, by a read whose wait does not read it (the get ends an idle wait late),
/// or by a settling that keeps the deadline of the get swept.
#[test]
fn a_get_between_long_reads_ends_at_its_deadline() {
    let router = Router::start(CatchAll::None);
    let mut config = super::config(&router);
    config.idle_wait_ms = 2_000;
    let engine = super::open_with(config);
    settle(&router, &engine, Command::Silence);
    assert_eq!(
        engine.get_wait_ms(),
        None,
        "CONTROL: no get bounds a read's wait"
    );
    let mut later = remote_get();
    later.timeout_ms = 4_000;
    let (issued, later_leg) = ask(&engine, "demo/g/later", &later, None, None, None);
    assert_eq!(issued, Ok(1));
    let mut sooner = remote_get();
    sooner.timeout_ms = 200;
    let asked = Instant::now();
    let (issued, leg) = ask(&engine, "demo/g/sooner", &sooner, None, None, None);
    assert_eq!(issued, Ok(1));
    let wait = engine.get_wait_ms().expect("the legs bound a read's wait");
    assert!(
        wait <= 201,
        "a read waits past the earlier leg's deadline: {wait} ms"
    );
    until(&engine, "the earlier deadline", || {
        leg.lock().unwrap().ended
    });
    let took = asked.elapsed();
    assert!(took >= Duration::from_millis(200), "ended early: {took:?}");
    assert!(
        took < Duration::from_millis(1_500),
        "ended an idle wait late: {took:?}"
    );
    let replies = leg.lock().unwrap().replies.clone();
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0].2, b"Timeout");
    let left = engine
        .get_wait_ms()
        .expect("the later leg still bounds a read's wait");
    assert!(
        left > 1_000 && left <= 4_001,
        "the deadline left is not the later leg's: {left} ms"
    );
    assert!(!later_leg.lock().unwrap().ended, "the later leg is open");
}

/// A cancelled token ends the get's leg at once, though nothing steps the session: `cancel`
/// returns only once the leg's callback is dropped.
#[test]
fn a_cancelled_get_ends_without_a_step() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let token = CancellationToken::new().expect("a token place is free");
    let fan = register_fan(&token)
        .expect("the test's heap")
        .expect("a fresh token registers");
    let (issued, leg) = ask(
        &engine,
        "demo/g/a",
        &remote_get(),
        Some(&fan),
        Some(fan.clone()),
        None,
    );
    drop(fan);
    assert_eq!(issued, Ok(1));
    assert!(
        !leg.lock().unwrap().ended,
        "CONTROL: open before the cancel"
    );
    token.cancel();
    let leg = leg.lock().unwrap();
    assert!(leg.ended, "cancel returns once the leg is over");
    assert!(leg.replies.is_empty(), "{:?}", leg.replies);
    assert_eq!(token.active(), 0);
}

/// A raw leg's call: the tests of a get's cost read no reply.
pub(super) unsafe fn ignore_reply(_context: *mut core::ffi::c_void, _reply: &dyn ReplyView) {}

/// A raw leg's end: one more on the counter its context names.
pub(super) unsafe fn count_end(context: *mut core::ffi::c_void) {
    // SAFETY: the context is the test's counter, which outlives every leg it was minted for.
    unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::SeqCst);
}

/// A get whose fan is registered on a token lying in its owner's place, as a querier's is, is
/// asked with no allocation: the fan is the token's registration and the engine tags the leg with
/// the fan's key, keeping no undo of it. Cancelling the fan ends the leg at once, though nothing
/// steps the session, and lets go of the token. The CONTROL is the leg open before the cancel.
#[test]
fn a_cancellable_get_allocates_nothing_and_its_fan_ends_it() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let token = CancellationToken::new().expect("a token place is free");
    let fan = CancellableFan::new();
    // SAFETY: the fan does not move until its drop below, and the token outlives it.
    assert!(unsafe { fan.register(TokenRef::placed(&token)) });
    let ended = AtomicUsize::new(0);
    let context = core::ptr::from_ref(&ended)
        .cast_mut()
        .cast::<core::ffi::c_void>();
    let opts = remote_get();
    let mut issued = Ok(0);
    let allocations = super::redial_heap::counted(|| {
        issued = engine.get_on_wire(
            "demo/g/a",
            &WireKey::literal(),
            &opts,
            Some(&fan),
            &mut || {
                // SAFETY: the counter outlives the leg: the test reads its end below.
                unsafe { ReplyCallback::raw(ignore_reply, context, Some(count_end)) }
            },
        );
    });
    assert_eq!(issued, Ok(1));
    assert_eq!(
        allocations, 0,
        "a cancellable get is asked with no allocation"
    );
    assert_eq!(
        ended.load(Ordering::SeqCst),
        0,
        "CONTROL: open before the cancel"
    );
    fan.cancel();
    assert_eq!(ended.load(Ordering::SeqCst), 1, "the cancel ended the leg");
    drop(fan);
    assert_eq!(token.active(), 0);
}

/// The legs of the get that accepts any key, ended: a counter of its own, as the leg may end after
/// its test returns.
static ANY_KEY_ENDS: AtomicUsize = AtomicUsize::new(0);

/// A get that accepts replies on any key, its parameters lent, is asked with no allocation: the
/// reply-keyexpr-any flag is written after the parameters where the query is written, so neither
/// is copied. The CONTROL is the query reaching the router.
#[test]
fn a_get_that_accepts_any_key_allocates_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let opts = remote_get().with_parameters_lent_anyke(b"_sn=7..", true);
    let context = core::ptr::from_ref(&ANY_KEY_ENDS)
        .cast_mut()
        .cast::<core::ffi::c_void>();
    let mut issued = Ok(0);
    let allocations = super::redial_heap::counted(|| {
        issued = engine.get_on_wire("demo/g/a", &WireKey::literal(), &opts, None, &mut || {
            // SAFETY: the counter is a static, which outlives every leg.
            unsafe { ReplyCallback::raw(ignore_reply, context, Some(count_end)) }
        });
    });
    assert_eq!(issued, Ok(1));
    assert_eq!(allocations, 0, "an any-key get is asked with no allocation");
    until(&engine, "the query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });
}

/// A get whose fan was cancelled before it is asked issues no leg: no callback is minted and no
/// query sent. The CONTROL is a get asked after it with no fan, the one query the router sees.
#[test]
fn a_get_whose_fan_was_cancelled_asks_nobody() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let cancelled = CancellableFan::new();
    cancelled.cancel();
    let minted = AtomicUsize::new(0);
    let refused = engine.get_on_wire(
        "demo/g/a",
        &WireKey::literal(),
        &remote_get(),
        Some(&cancelled),
        &mut || {
            minted.fetch_add(1, Ordering::SeqCst);
            ReplyCallback::shared(|_view: &dyn ReplyView| {})
        },
    );
    assert_eq!(refused, Ok(0));
    assert_eq!(minted.load(Ordering::SeqCst), 0, "no leg was minted");
    let (issued, _leg) = ask(&engine, "demo/g/b", &remote_get(), None, None, None);
    assert_eq!(issued, Ok(1), "CONTROL: a get with no fan is asked");
    until(&engine, "the query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });
}

/// The face's table of pending gets holds `MAX_PENDING_QUERIES` of them: a get past it is
/// refused whole, before a leg's callback is minted or its query sent, and the row the first gives
/// back at its deadline holds the next. The CONTROL is the first get, held and sent.
#[test]
fn a_get_past_its_table_is_refused_and_sends_nothing() {
    let limits = super::entity_tables::lowered(|l| l.select_max_pending_queries(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = super::entity_tables::open_under(&router, limits);
    settle(&router, &engine, Command::Silence);
    let mut opts = remote_get();
    opts.timeout_ms = 300;
    let (issued, first) = ask(&engine, "demo/g/a", &opts, None, None, None);
    assert_eq!(issued, Ok(1), "CONTROL: the one row holds the first get");
    until(&engine, "the first query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });

    let minted = Arc::new(Mutex::new(0usize));
    let counting = minted.clone();
    let refused = engine.get_on_wire(
        "demo/g/b",
        &WireKey::literal(),
        &remote_get(),
        None,
        &mut || {
            *counting.lock().unwrap() += 1;
            ReplyCallback::shared(|_view: &dyn ReplyView| {})
        },
    );
    assert_eq!(
        refused,
        Err(Refusal::TableFull),
        "refused whole, not answered as a get that reached nobody"
    );
    assert_eq!(*minted.lock().unwrap(), 0, "no leg was minted");
    let quiet = Instant::now() + Duration::from_millis(100);
    while Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(router.seen(|s| s.queries), 1, "nothing was sent");

    until(&engine, "the first get to end at its deadline", || {
        first.lock().unwrap().ended
    });
    let (issued, _next) = ask(&engine, "demo/g/c", &remote_get(), None, None, None);
    assert_eq!(issued, Ok(1), "the row the first gave back holds the next");
}

/// A get asked of a closed session is refused as closed and mints no leg: it is not answered as
/// a get that reached nobody. The CONTROL is the same get asked while the session is open.
#[test]
fn a_get_on_a_closed_session_is_refused_as_closed() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let (issued, _) = ask(&engine, "demo/g/a", &remote_get(), None, None, None);
    assert_eq!(issued, Ok(1), "CONTROL: the open session asks");

    SessionDrive::close(&*engine);
    let (issued, leg) = ask(&engine, "demo/g/b", &remote_get(), None, None, None);
    assert_eq!(issued, Err(Refusal::Closed));
    assert_eq!(leg.lock().unwrap().open, 0, "no leg was minted");
}

/// A get whose link goes ends with it, long before its deadline: the peer that owed its Final is
/// gone.
#[test]
fn a_get_ends_with_its_link() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let (issued, leg) = ask(&engine, "demo/g/a", &remote_get(), None, None, None);
    assert_eq!(issued, Ok(1));
    until(&engine, "the query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });
    router.send(Command::Close);
    until(&engine, "the leg to end with the link", || {
        leg.lock().unwrap().ended
    });
    assert!(leg.lock().unwrap().replies.is_empty());
}
