// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query: the session asks the router, its replies reach the leg's
//! callback outside the session's lock, and the leg ends when its Final comes, its deadline
//! passes, its token is cancelled or its link goes, each time as the drop of its callback.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::cancellation::{register_fan, CancellableFan, CancellationToken, Registration};
use wz_capi_port::{ReplyCallback, SessionDrive, SessionEngine, WireKey};
use wz_session_core::query_options::QueryOptions;
use wz_session_core::reply_sink::{ReplyKind, ReplyView};

use super::{open, until, CatchAll, Command, Engine, Router};

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
/// `registration` when there is one, as a C get's callbacks hold theirs. `step`, when given, is
/// stepped from inside each reply callback.
pub(super) fn ask(
    engine: &Engine,
    keyexpr: &str,
    opts: &QueryOptions,
    fan: Option<&CancellableFan>,
    registration: Option<Arc<Registration>>,
    step: Option<Arc<Engine>>,
) -> (Option<usize>, Arc<Mutex<Leg>>) {
    let leg = Arc::new(Mutex::new(Leg::default()));
    let seen = leg.clone();
    let issued = engine.get_on_wire(keyexpr, &WireKey::literal(), opts, fan, &mut || {
        let ends = Ends::mint(&seen);
        let registration = registration.clone();
        let step = step.clone();
        Box::new(move |view: &dyn ReplyView| {
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
        }) as ReplyCallback
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
    assert_eq!(issued, Some(1), "one leg: the link's peer");
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
    assert_eq!(issued, Some(1));
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

/// A cancelled token ends the get's leg at once, though nothing steps the session: `cancel`
/// returns only once the leg's callback is dropped.
#[test]
fn a_cancelled_get_ends_without_a_step() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let token = CancellationToken::new();
    let (fan, registration) = register_fan(&token).expect("a fresh token registers");
    let registration = Arc::new(registration);
    let (issued, leg) = ask(
        &engine,
        "demo/g/a",
        &remote_get(),
        Some(&fan),
        Some(registration.clone()),
        None,
    );
    drop(registration);
    assert_eq!(issued, Some(1));
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

/// A get whose link goes ends with it, long before its deadline: the peer that owed its Final is
/// gone.
#[test]
fn a_get_ends_with_its_link() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Silence);
    let (issued, leg) = ask(&engine, "demo/g/a", &remote_get(), None, None, None);
    assert_eq!(issued, Some(1));
    until(&engine, "the query to reach the router", || {
        router.seen(|s| s.queries) == 1
    });
    router.send(Command::Close);
    until(&engine, "the leg to end with the link", || {
        leg.lock().unwrap().ended
    });
    assert!(leg.lock().unwrap().replies.is_empty());
}
