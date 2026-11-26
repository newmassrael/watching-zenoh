//! The declarations of a link told in turns (`declaration-sync-pacing`): a paced replay
//! sends a burst a turn and waits the interval between turns, a declaration made while it goes on
//! is told once, in its turn, a retraction is sent only if the peer was told of the entry, a
//! replay is not resumed on another link, and an unpaced one is a single turn. Both forms tell a
//! new peer the same declarations in the same order, in a build of either domain of the policy.
//! A replay to a peer the session meets as the peer hat's two north-bound peers ends, when the
//! config says so, with the `DeclareFinal` of the initial interest, once and after the last turn.

use crate::EngineHold;
use std::time::{Duration, Instant};

use wz_capi_port::{PeerLists, SessionDrive, SessionEngine, SubId, SubscriberSink, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::replay_pacing::ReplayPacing;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::{config, open_with, router_port, until, CatchAll, Command, Engine, Router, ROUTER_ZID};
use crate::CoopConfig;

/// Declare a subscriber on `key` that hears nothing, for the declaration it makes.
fn subscribe(engine: &Engine, key: &str) -> SubId {
    engine
        .declare_subscriber_on_wire(
            key,
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(|_: &dyn SampleView| {}),
        )
        .expect("a session with ids left declares")
        .id
}

/// How many declarations the router has been told.
fn told(router: &Router) -> usize {
    router.seen(|seen| seen.declares)
}

/// The ids of the subscribers `router` was declared, in the order the declarations arrived.
fn told_subscribers(router: &Router) -> Vec<u64> {
    router.seen(|seen| seen.subscribers.clone())
}

/// A session that holds `keys` as subscribers, whose link is lost and dialled again with the
/// declarations paced as `pacing` says: the new router, the session, and the subscribers' ids, as
/// soon as the new link is established and its first turn is sent.
fn reconnected(
    keys: &[&str],
    pacing: Option<ReplayPacing>,
) -> (Router, EngineHold<Engine>, Vec<SubId>) {
    let (router, engine, ids, _) = reconnected_after(keys, pacing);
    (router, engine, ids)
}

/// [`reconnected`], and the ids of the subscribers the first router was declared as the session
/// made them, in the order it made them.
fn reconnected_after(
    keys: &[&str],
    pacing: Option<ReplayPacing>,
) -> (Router, EngineHold<Engine>, Vec<SubId>, Vec<u64>) {
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
    let live = told_subscribers(&first);
    first.send(Command::Close);
    drop(first);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    engine
        .set_replay_pacing(pacing)
        .expect("a test states a pace only where the build reaches one");
    let second = Router::start_on(port, CatchAll::None);
    until(&engine, "the first turn of the replay", || {
        told(&second) >= 1
    });
    (second, engine, ids, live)
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
    // A build that reaches no pace replays in one lap whatever is stated.
    if !ReplayPacing::REACHABLE {
        return;
    }
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
    // A build that reaches no pace replays in one lap whatever is stated.
    if !ReplayPacing::REACHABLE {
        return;
    }
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
    // A build that reaches no pace replays in one lap whatever is stated.
    if !ReplayPacing::REACHABLE {
        return;
    }
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
    // A build that reaches no pace replays in one lap whatever is stated.
    if !ReplayPacing::REACHABLE {
        return;
    }
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

/// A session opened under a snapshot holds that snapshot and replays at the pace it states, not
/// at the build's; the open that resolves its own snapshot holds the build's.
#[test]
fn a_session_replays_at_the_pace_of_the_snapshot_it_is_handed() {
    use wz_session_core::policy::{DeclarationSyncPacing, SessionPolicy};
    let build = SessionPolicy::defaults();
    let other = if build.declaration_sync_pacing() {
        DeclarationSyncPacing::Off
    } else {
        DeclarationSyncPacing::On
    };
    let mut handed = SessionPolicy::defaults();
    if handed.select_declaration_sync_pacing(other).is_err() {
        // The build allows one value: there is no other snapshot to hand.
        return;
    }
    let router = Router::start(CatchAll::None);
    let engine = Engine::open_with_policy(
        super::host_links(super::LOOPBACK, super::PosixTcpDial).waited_by_owner(),
        super::PosixClock,
        super::PosixEntropy,
        config(&router),
        handed,
    )
    .expect("the session opens");
    let limits = wz_session_core::limits::SessionLimits::defaults();
    let (pacing, held) = engine.policy_in_force().expect("the session is open");
    assert_eq!(held, handed);
    assert_eq!(pacing, ReplayPacing::of_snapshot(&handed, &limits));
    assert_ne!(pacing, ReplayPacing::of_snapshot(&build, &limits));
    SessionDrive::close(&*engine);

    // Control: the open that resolves its own snapshot holds the build's and its pace.
    let second = Router::start(CatchAll::None);
    let own = open_with(config(&second));
    let (pacing, held) = own.policy_in_force().expect("the session is open");
    assert_eq!(held, build);
    assert_eq!(pacing, ReplayPacing::of_snapshot(&build, &limits));
    SessionDrive::close(&*own);
}

/// The pace limits of the snapshot a session opens with are the pace it replays at: a burst the
/// config's limits state is the burst of the dial face's pace, not the build's.
#[test]
fn a_session_replays_at_the_pace_limits_of_the_snapshot_it_is_handed() {
    use wz_session_core::policy::{DeclarationSyncPacing, SessionPolicy};
    let mut paced = SessionPolicy::defaults();
    if paced
        .select_declaration_sync_pacing(DeclarationSyncPacing::On)
        .is_err()
    {
        // The build keeps pacing off: no snapshot paces a replay.
        return;
    }
    let mut limits = wz_session_core::limits::SessionLimits::defaults();
    if limits.select_declaration_sync_burst_messages(3).is_err() {
        // A build of one value refuses another: there is no other snapshot to hand.
        return;
    }
    let router = Router::start(CatchAll::None);
    let engine = Engine::open_with_policy(
        super::host_links(super::LOOPBACK, super::PosixTcpDial).waited_by_owner(),
        super::PosixClock,
        super::PosixEntropy,
        CoopConfig {
            limits,
            ..config(&router)
        },
        paced,
    )
    .expect("the session opens");
    let (pacing, _) = engine.policy_in_force().expect("the session is open");
    assert_eq!(pacing.map(|pace| pace.burst()), Some(3));
    SessionDrive::close(&*engine);
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

/// Each form of the replay tells the new peer the declarations the first peer was told as the
/// session made them, every one and in the same order: the one turn of an unpaced session, which
/// a build that reaches no pace makes as one lap when the link comes up, and the turns of a paced
/// one, which a build that reaches no pace holds no code of. The CONTROL is that the first peer
/// was told every subscriber, so the order compared is a whole one.
#[test]
fn every_form_of_the_replay_tells_the_new_peer_the_same_declarations_in_the_same_order() {
    let keys = ["f/1", "f/2", "f/3", "f/4", "f/5"];
    let mut forms = vec![None];
    if ReplayPacing::REACHABLE {
        forms.push(ReplayPacing::new(2, 50));
    }
    for pacing in forms {
        let (router, engine, ids, live) = reconnected_after(&keys, pacing);
        assert_eq!(
            live.len(),
            keys.len(),
            "{pacing:?}: the first peer was told each"
        );
        until(&engine, "the replay to finish", || {
            engine.declarations_synced() && told(&router) == keys.len()
        });
        assert_eq!(
            told_subscribers(&router),
            live,
            "{pacing:?}: the new peer is told what the first was, in its order"
        );
        let held: Vec<u64> = ids.iter().map(|&id| u64::from(id)).collect();
        assert_eq!(live, held, "{pacing:?}: the order the session made them in");
        SessionDrive::close(&*engine);
    }
}

/// A pace the build cannot reach is refused as a snapshot that selects the policy's `on` is
/// refused there, and the session keeps the pace it had; a build that reaches one takes it, and
/// no pace is taken by every build. The CONTROL is the build's own selection of the policy: the
/// refusal holds exactly where that selection is refused.
#[test]
fn a_pace_the_build_cannot_reach_is_refused_and_changes_nothing() {
    use wz_session_core::policy::{DeclarationSyncPacing, SessionPolicy};
    use wz_session_core::policy_binding::OutsideDomain;
    let mut policy = SessionPolicy::defaults();
    let selectable = policy
        .select_declaration_sync_pacing(DeclarationSyncPacing::On)
        .is_ok();
    let router = Router::start(CatchAll::None);
    let engine = open_with(config(&router));
    let (before, _) = engine.policy_in_force().expect("the session is open");
    let pace = ReplayPacing::new(2, 50);
    let stated = engine.set_replay_pacing(pace);
    let (after, _) = engine.policy_in_force().expect("the session is open");
    if selectable {
        assert_eq!(stated, Ok(()));
        assert_eq!(after, pace, "the stated pace is the session's");
    } else {
        assert_eq!(
            stated,
            Err(OutsideDomain {
                value: DeclarationSyncPacing::On
            })
        );
        assert_eq!(after, before, "a refused pace changes nothing");
    }
    assert_eq!(
        engine.set_replay_pacing(None),
        Ok(()),
        "every build sends the declarations in one turn"
    );
    SessionDrive::close(&*engine);
}

/// The places among the declarations `router` was told of each `DeclareFinal` of the initial
/// interest, in the order they arrived.
fn initial_finals(router: &Router) -> Vec<usize> {
    router.seen(|seen| seen.initial_finals.clone())
}

/// A stand-in on `port` that announces itself a peer, which a peer session meets as the peer hat's
/// two north-bound peers.
fn peer_on(port: u16) -> Router {
    Router::start_announcing(port, ROUTER_ZID, WhatAmI::Peer, CatchAll::None)
}

/// A peer session's config for `router` that ends a new face's replay with the Final of the
/// initial interest as `initial_interest` says.
fn peer_config(router: &Router, initial_interest: bool) -> CoopConfig {
    CoopConfig {
        whatami: WhatAmI::Peer,
        initial_interest,
        ..config(router)
    }
}

/// A peer session that ends its replays with the Final, holding `keys` as subscribers, whose link
/// to a peer is lost and dialled again with the declarations paced as `pacing` says: the new
/// peer and the session, as soon as the new link's first turn is sent. The CONTROL is that the
/// first peer was told every subscriber and one Final.
fn reconnected_peer(keys: &[&str], pacing: Option<ReplayPacing>) -> (Router, EngineHold<Engine>) {
    let first = peer_on(router_port());
    let port = first.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..peer_config(&first, true)
    });
    for key in keys {
        subscribe(&engine, key);
    }
    until(
        &engine,
        "the first peer to be told every subscriber and the Final",
        || told(&first) == keys.len() + 1,
    );
    assert_eq!(
        initial_finals(&first).len(),
        1,
        "the first peer was sent one Final"
    );
    first.send(Command::Close);
    drop(first);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    engine
        .set_replay_pacing(pacing)
        .expect("a test states a pace only where the build reaches one");
    let second = peer_on(port);
    until(&engine, "the first turn of the replay", || {
        told(&second) >= 1
    });
    (second, engine)
}

/// A link that comes up to a peer the session meets as a peer is told the Final of the initial
/// interest once, after every declaration the replay owed it, and a declaration the session makes
/// later is followed by no second Final. Turned red by a Final sent before the replay
/// (`end_initial_interest` called before the turn), not sent at all, or sent again by a later
/// declaration.
#[test]
fn a_peer_face_is_sent_the_initial_final_once_after_its_replay() {
    let (router, engine) = reconnected_peer(&["g/1", "g/2"], None);
    until(&engine, "the replay and its Final", || told(&router) == 3);
    step_for(&engine, Duration::from_millis(100));
    assert_eq!(
        initial_finals(&router),
        vec![3],
        "the Final follows both subscribers, once"
    );
    subscribe(&engine, "g/3");
    until(&engine, "the later subscriber", || told(&router) == 4);
    step_for(&engine, Duration::from_millis(100));
    assert_eq!(
        initial_finals(&router),
        vec![3],
        "a later declaration is followed by no second Final"
    );
    SessionDrive::close(&*engine);
}

/// A paced replay sends the Final only in the turn that tells its last declaration: none while
/// turns are owed, and one after the last. Turned red by a Final sent by the first turn of a
/// paced replay.
#[test]
fn a_paced_replay_sends_the_initial_final_after_its_last_turn() {
    // A build that reaches no pace replays in one lap whatever is stated.
    if !ReplayPacing::REACHABLE {
        return;
    }
    let (router, engine) = reconnected_peer(&["h/1", "h/2", "h/3"], ReplayPacing::new(1, 300));
    assert!(
        initial_finals(&router).is_empty(),
        "two turns are still owed"
    );
    until(&engine, "the replay to finish", || {
        engine.declarations_synced()
    });
    until(&engine, "the Final", || told(&router) == 4);
    step_for(&engine, Duration::from_millis(400));
    assert_eq!(
        initial_finals(&router),
        vec![4],
        "the Final follows the last turn, once"
    );
    SessionDrive::close(&*engine);
}

/// No Final goes to a face the peer hat does not push to, nor from a session whose config does not
/// end a push so: a client meeting a peer, a peer meeting a router, and a peer meeting a peer with
/// the switch off are each told the subscriber alone. The CONTROL is the peer meeting a peer with
/// the switch on, told the Final beside it. Turned red by a Final sent without reading the switch
/// (`config.initial_interest` in `begin_link_replay`) or the roles
/// (`meets_remote_as_peer_hat`).
#[test]
fn no_initial_final_goes_to_a_face_that_is_not_a_peer_or_when_the_switch_is_off() {
    let cases = [
        (
            "a client meeting a peer",
            WhatAmI::Client,
            WhatAmI::Peer,
            true,
        ),
        (
            "a peer meeting a router",
            WhatAmI::Peer,
            WhatAmI::Router,
            true,
        ),
        (
            "a peer with the switch off",
            WhatAmI::Peer,
            WhatAmI::Peer,
            false,
        ),
        (
            "CONTROL: a peer meeting a peer",
            WhatAmI::Peer,
            WhatAmI::Peer,
            true,
        ),
    ];
    for (what, role, remote, initial_interest) in cases {
        let router = Router::start_announcing(router_port(), ROUTER_ZID, remote, CatchAll::None);
        let engine = open_with(CoopConfig {
            whatami: role,
            initial_interest,
            ..config(&router)
        });
        subscribe(&engine, "i/1");
        until(&engine, "the subscriber", || told(&router) >= 1);
        step_for(&engine, Duration::from_millis(100));
        let owed = role == WhatAmI::Peer && remote == WhatAmI::Peer && initial_interest;
        assert_eq!(
            initial_finals(&router).len(),
            usize::from(owed),
            "{what}: a Final only where both ends are peers and the switch is on"
        );
        assert_eq!(
            told(&router),
            1 + usize::from(owed),
            "{what}: the subscriber, and the Final where it is owed"
        );
        SessionDrive::close(&*engine);
    }
}
