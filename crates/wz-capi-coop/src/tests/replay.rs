//! The declarations of a link told in turns (`docs/declaration-sync-pacing.md`): a paced replay
//! sends a burst a turn and waits the interval between turns, a declaration made while it goes on
//! is told once, in its turn, a retraction is sent only if the peer was told of the entry, a
//! replay is not resumed on another link, and an unpaced one is a single turn.

use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, SubId, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::replay_pacing::ReplayPacing;
use wz_session_core::sink::SampleView;

use super::{config, open_with, until, CatchAll, Command, Engine, Router};
use crate::CoopConfig;

/// Declare a subscriber on `key` that hears nothing, for the declaration it makes.
fn subscribe(engine: &Engine, key: &str) -> SubId {
    engine.declare_subscriber_on_wire(
        key.to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(|| Box::new(|_: &dyn SampleView| {})),
    )
}

/// How many declarations the router has been told.
fn told(router: &Router) -> usize {
    router.seen(|seen| seen.declares)
}

/// A session that holds `keys` as subscribers, whose link is lost and dialled again with the
/// declarations paced as `pacing` says: the new router, the session, and the subscribers' ids, as
/// soon as the new link is established and its first turn is sent.
fn reconnected(keys: &[&str], pacing: Option<ReplayPacing>) -> (Router, Arc<Engine>, Vec<SubId>) {
    let first = Router::start(CatchAll::None);
    let port = first.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&first)
    });
    let ids: Vec<SubId> = keys.iter().map(|key| subscribe(&engine, key)).collect();
    until(&engine, "the router to be told every subscriber", || {
        told(&first) == keys.len()
    });
    first.send(Command::Close);
    drop(first);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    engine.set_replay_pacing(pacing);
    let second = Router::start_on(port, CatchAll::None);
    until(&engine, "the first turn of the replay", || {
        told(&second) >= 1
    });
    (second, engine, ids)
}

/// Step `engine` for `span`, so what the router is going to be told by then has been sent.
fn step_for(engine: &Engine, span: Duration) {
    let until = Instant::now() + span;
    while Instant::now() < until {
        let _ = SessionDrive::read(engine, false);
    }
}

/// A paced replay tells a burst, then waits the interval: five subscribers at two a turn reach the
/// router as two, two and one, and the session is not synced until the last turn. The CONTROL is
/// that every declaration did arrive, once.
#[test]
fn a_paced_replay_tells_a_burst_a_turn_and_waits_between_turns() {
    let interval_ms = 400;
    let pace = ReplayPacing::new(2, interval_ms);
    let (router, engine, _) = reconnected(&["a/1", "a/2", "a/3", "a/4", "a/5"], pace);
    let first_seen = Instant::now();
    assert!(
        told(&router) <= 2,
        "the first turn is a burst of two, not the five the session holds"
    );
    assert!(
        !engine.declarations_synced(),
        "three declarations are still owed"
    );
    // Well inside the first interval nothing more has gone out.
    step_for(&engine, Duration::from_millis(interval_ms / 2));
    assert_eq!(told(&router), 2, "the second turn is an interval away");
    until(&engine, "the replay to finish", || {
        engine.declarations_synced()
    });
    // Three turns are two intervals long; the first turn was sent before the router was seen to
    // hold it, so the span measured from there is shorter by that detection, which is a
    // fraction of an interval. One interval would be two turns and none would be an unpaced one.
    assert!(
        first_seen.elapsed() >= Duration::from_millis(interval_ms + interval_ms / 2),
        "three turns take two intervals, took {:?}",
        first_seen.elapsed()
    );
    until(&engine, "every declaration to arrive", || {
        told(&router) == 5
    });
    step_for(&engine, Duration::from_millis(interval_ms));
    assert_eq!(told(&router), 5, "each was told once");
}

/// A declaration made while the replay goes on is told once, in its turn: it is stored behind the
/// cursor and the replay reaches it, so it is not sent at once and not sent twice.
#[test]
fn a_declaration_made_during_the_replay_is_told_once_in_its_turn() {
    let pace = ReplayPacing::new(1, 300);
    let (router, engine, _) = reconnected(&["b/1", "b/2", "b/3"], pace);
    assert_eq!(told(&router), 1, "one declaration a turn");
    subscribe(&engine, "b/4");
    step_for(&engine, Duration::from_millis(100));
    assert_eq!(
        told(&router),
        1,
        "the new subscriber waits for its turn behind the ones not yet told"
    );
    until(&engine, "the replay to finish", || {
        engine.declarations_synced()
    });
    until(&engine, "every declaration to arrive", || {
        told(&router) == 4
    });
    step_for(&engine, Duration::from_millis(600));
    assert_eq!(told(&router), 4, "three held and one made, each told once");
}

/// A retraction made while the replay goes on is sent only if the peer was told of the entry: the
/// subscriber the replay has passed is retracted on the wire, the one it has not reached is
/// dropped and the peer never hears of it.
#[test]
fn a_retraction_during_the_replay_is_sent_only_if_the_peer_was_told() {
    let pace = ReplayPacing::new(1, 300);
    let (router, engine, ids) = reconnected(&["c/1", "c/2", "c/3", "c/4"], pace);
    assert_eq!(told(&router), 1, "only c/1 was told");
    // The one the peer was told of: its retraction goes out at once.
    engine.undeclare_subscriber(ids[0]);
    until(&engine, "the retraction of the told subscriber", || {
        told(&router) == 2
    });
    // The one the replay has not reached: nothing is sent, now or later.
    engine.undeclare_subscriber(ids[3]);
    until(&engine, "the replay to finish", || {
        engine.declarations_synced()
    });
    step_for(&engine, Duration::from_millis(600));
    assert_eq!(
        told(&router),
        4,
        "c/1 and its retraction, then c/2 and c/3; c/4 was never told, so is not retracted"
    );
}

/// A replay is not resumed on another link: one cut short by a lost link begins again from the
/// first entry on the next, whose peer holds nothing.
#[test]
fn a_replay_cut_short_by_a_lost_link_begins_again_on_the_next() {
    let pace = ReplayPacing::new(1, 500);
    let (router, engine, _) = reconnected(&["d/1", "d/2", "d/3"], pace);
    let port = router.port;
    assert_eq!(told(&router), 1);
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    assert!(
        engine.declarations_synced(),
        "a session with no link established owes nothing yet"
    );
    let next = Router::start_on(port, CatchAll::None);
    until(&engine, "the first turn on the new link", || {
        told(&next) >= 1
    });
    until(&engine, "the replay to finish", || {
        engine.declarations_synced()
    });
    until(&engine, "every declaration to reach the new peer", || {
        told(&next) == 3
    });
    step_for(&engine, Duration::from_millis(600));
    assert_eq!(told(&next), 3, "the new peer was told all three, once");
}

/// Without a pace the replay is one turn: everything the session holds goes out when the link
/// comes up, and the session is synced at once.
#[test]
fn an_unpaced_replay_is_one_turn() {
    let (router, engine, _) = reconnected(&["e/1", "e/2", "e/3", "e/4"], None);
    until(&engine, "every declaration to arrive", || {
        told(&router) == 4
    });
    assert!(engine.declarations_synced());
}
