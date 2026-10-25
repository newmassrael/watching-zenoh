// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness get: the session asks the router which tokens are alive, each answers as a
//! reply carrying the token's key, and the leg ends when the router's DeclFinal comes, its
//! deadline passes, its token is cancelled or its link goes, each time as the drop of its
//! callback.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::cancellation::{register_fan, CancellableFan, CancellationToken, Registration};
use wz_capi_port::{ReplyCallback, SessionDrive, SessionEngine, WireKey};
use wz_session_core::reply_sink::{ReplyKind, ReplyView};

use super::{open, until, CatchAll, Command, Engine, Router};

/// What a leg's callback saw: each reply as its kind, key and payload, and whether the callback
/// has been dropped.
#[derive(Default)]
struct Leg {
    replies: Vec<(ReplyKind, String, Vec<u8>)>,
    ended: bool,
}

/// Owned by a leg's callback, so the leg is marked ended when the callback is dropped.
struct Ends(Arc<Mutex<Leg>>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.lock().unwrap().ended = true;
    }
}

/// Ask which tokens are alive on `keyexpr`, its legs recorded in what is returned, each holding
/// `registration` when there is one, as a C get's callbacks hold theirs.
fn ask(
    engine: &Engine,
    keyexpr: &str,
    timeout_ms: u32,
    fan: Option<&CancellableFan>,
    registration: Option<Arc<Registration>>,
) -> (Option<usize>, Arc<Mutex<Leg>>) {
    let leg = Arc::new(Mutex::new(Leg::default()));
    let seen = leg.clone();
    let issued =
        engine.liveliness_get_on_wire(keyexpr, &WireKey::literal(), timeout_ms, fan, &mut || {
            let ends = Ends(seen.clone());
            let registration = registration.clone();
            Box::new(move |view: &dyn ReplyView| {
                let _held = &registration;
                ends.0.lock().unwrap().replies.push((
                    view.kind(),
                    view.keyexpr().to_owned(),
                    view.payload().to_vec(),
                ));
            }) as ReplyCallback
        });
    (issued, leg)
}

fn keys(leg: &Arc<Mutex<Leg>>) -> Vec<String> {
    let mut keys: Vec<String> = leg
        .lock()
        .unwrap()
        .replies
        .iter()
        .map(|(_, key, _)| key.clone())
        .collect();
    keys.sort();
    keys
}

/// The router holds three tokens and answers the snapshot with the two on the asked key, each
/// as a reply carrying the token's key and no payload, then its DeclFinal ends the leg. The
/// CONTROL is the third token, on a key the snapshot does not name, which must not come back; and
/// the leg before any step, which is open with nothing delivered.
#[test]
fn a_snapshot_lists_the_tokens_alive_and_ends_with_its_final() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::HoldToken(10, "demo/snap/a"));
    router.send(Command::HoldToken(11, "demo/snap/b"));
    router.send(Command::HoldToken(12, "other/c"));
    until(&engine, "the router to hold its tokens", || {
        router.seen(|s| s.held == 3)
    });
    let (issued, leg) = ask(&engine, "demo/snap/**", 0, None, None);
    assert_eq!(issued, Some(1), "one leg: the link's peer");
    {
        let leg = leg.lock().unwrap();
        assert!(
            leg.replies.is_empty() && !leg.ended,
            "CONTROL: nothing is delivered before a step"
        );
    }
    until(&engine, "the snapshot to end", || leg.lock().unwrap().ended);
    assert_eq!(keys(&leg), ["demo/snap/a", "demo/snap/b"]);
    assert!(
        leg.lock()
            .unwrap()
            .replies
            .iter()
            .all(|(kind, _, payload)| *kind != ReplyKind::Err && payload.is_empty()),
        "a token is a reply with no payload"
    );
}

/// A snapshot of a key nothing is alive on ends with the DeclFinal alone: no reply, no timeout.
#[test]
fn a_snapshot_of_nothing_alive_ends_with_the_final_alone() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::HoldToken(13, "other/held"));
    until(&engine, "the router to hold its token", || {
        router.seen(|s| s.held == 1)
    });
    let (issued, leg) = ask(&engine, "demo/nothing/**", 0, None, None);
    assert_eq!(issued, Some(1));
    until(&engine, "the snapshot to end", || leg.lock().unwrap().ended);
    assert!(leg.lock().unwrap().replies.is_empty());
}

/// A snapshot the router never answers ends at its deadline with zenoh's timeout reply, swept by
/// the step that comes due. The CONTROL is the leg halfway, still open, and the Interest, which
/// did reach the router.
#[test]
fn a_snapshot_nobody_answers_ends_at_its_deadline() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::MuteInterests);
    until(&engine, "the router to go quiet", || {
        router.seen(|s| s.settled)
    });
    let before = router.seen(|s| s.interests);
    let asked = Instant::now();
    let (issued, leg) = ask(&engine, "demo/snap/a", 300, None, None);
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
    assert_eq!(
        router.seen(|s| s.interests),
        before + 1,
        "the Interest went out"
    );
}

/// A cancelled token ends the snapshot's leg at once, though nothing steps the session: `cancel`
/// returns only once the leg's callback is dropped.
#[test]
fn a_cancelled_snapshot_ends_without_a_step() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::MuteInterests);
    until(&engine, "the router to go quiet", || {
        router.seen(|s| s.settled)
    });
    let token = CancellationToken::new();
    let (fan, registration) = register_fan(&token).expect("a fresh token registers");
    let registration = Arc::new(registration);
    let (issued, leg) = ask(
        &engine,
        "demo/snap/a",
        0,
        Some(&fan),
        Some(registration.clone()),
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

/// A snapshot whose link goes ends with it, long before its deadline: the peer that owed its
/// DeclFinal is gone.
#[test]
fn a_snapshot_ends_with_its_link() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::MuteInterests);
    until(&engine, "the router to go quiet", || {
        router.seen(|s| s.settled)
    });
    let before = router.seen(|s| s.interests);
    let (issued, leg) = ask(&engine, "demo/snap/a", 0, None, None);
    assert_eq!(issued, Some(1));
    until(&engine, "the Interest to reach the router", || {
        router.seen(|s| s.interests) == before + 1
    });
    router.send(Command::Close);
    until(&engine, "the leg to end with the link", || {
        leg.lock().unwrap().ended
    });
    assert!(leg.lock().unwrap().replies.is_empty());
}
