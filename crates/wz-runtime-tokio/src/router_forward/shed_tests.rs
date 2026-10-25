// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The router closing the newest sessions when it holds more than it can keep ([`super::shed`]).

use super::egress_tests::{client_over, zid, RoomLink};
use super::*;

/// A router holding `faces` sessions, ids 0 to `faces - 1`, and the actions of each.
fn router_holding(faces: u8) -> (RouterForwarder, Vec<Arc<SessionLinkActions>>) {
    let fwd = RouterForwarder::new(zid(0x01));
    let link = RoomLink::new(false);
    let held: Vec<_> = (0..faces)
        .map(|n| {
            let actions = client_over(&link, zid(0x10 + n));
            fwd.register(FaceId(u64::from(n)), &actions);
            actions
        })
        .collect();
    (fwd, held)
}

/// The newest sessions are the ones closed, as many as it takes to keep the number asked, and the
/// close is the one a session gets for a message that could not wait.
#[test]
fn the_newest_sessions_are_ordered_closed_and_the_oldest_are_kept() {
    let (fwd, held) = router_holding(5);
    let registry = fwd.shed_registry();
    assert_eq!(registry.live(), 5);
    assert_eq!(registry.shed_newest(3), 2, "five held, three kept: two go");
    let closing: Vec<bool> = held
        .iter()
        .map(|actions| actions.take_congestion_close())
        .collect();
    assert_eq!(
        closing,
        [false, false, false, true, true],
        "the two accepted last"
    );
    assert_eq!(registry.live(), 3, "those closing are not among those kept");
    assert_eq!(registry.total(), 2);
}

/// Asking again for the number already kept closes nothing: a session on its way out is not
/// ordered out again, and the sessions that have not left the table yet are not counted as kept.
#[test]
fn asking_twice_for_the_same_number_closes_nothing_the_second_time() {
    let (fwd, held) = router_holding(5);
    let registry = fwd.shed_registry();
    assert_eq!(registry.shed_newest(3), 2);
    for actions in &held {
        let _ = actions.take_congestion_close();
    }
    assert_eq!(registry.shed_newest(3), 0);
    assert!(
        held.iter().all(|actions| !actions.take_congestion_close()),
        "no session was asked a second time"
    );
    assert_eq!(registry.total(), 2, "and the count does not move");
    // A lower number closes the newest of those still kept, not the ones already closing.
    assert_eq!(registry.shed_newest(1), 2);
    let closing: Vec<bool> = held
        .iter()
        .map(|actions| actions.take_congestion_close())
        .collect();
    assert_eq!(closing, [false, true, true, false, false]);
    assert_eq!(registry.total(), 4);
}

/// A router holding no more than it was asked to keep closes nothing.
#[test]
fn a_router_holding_no_more_than_it_keeps_closes_nothing() {
    let (fwd, held) = router_holding(3);
    let registry = fwd.shed_registry();
    assert_eq!(registry.shed_newest(3), 0);
    assert_eq!(registry.shed_newest(10), 0);
    assert!(held.iter().all(|actions| !actions.take_congestion_close()));
    assert_eq!(registry.total(), 0);
}

/// A session ordered closed stops asking for keepalives at once and its peer is told on the wire at
/// once, without waiting for the session's own drive loop: the sessions being closed are the load
/// the cut was meant to take off, and a peer that heard nothing would wait out its lease.
#[cfg(all(feature = "transport-keepalive", feature = "codec-close"))]
#[test]
fn a_session_ordered_closed_stops_its_keepalives_and_tells_its_peer_at_once() {
    use crate::runtime_impl::TokioRuntime;
    use wz_runtime_core::runtime::Runtime;

    let fwd = RouterForwarder::new(zid(0x01));
    let (kept_link, shed_link) = (RoomLink::new(false), RoomLink::new(false));
    let kept = client_over(&kept_link, zid(0x10));
    let shed = client_over(&shed_link, zid(0x11));
    fwd.register(FaceId(0), &kept);
    fwd.register(FaceId(1), &shed);
    for actions in [&kept, &shed] {
        TokioRuntime::with_mutex_mut(&actions.link.keepalive_armed, |armed| *armed = true);
    }
    let (kept_before, shed_before) = (kept_link.sent(), shed_link.sent());

    assert_eq!(fwd.shed_registry().shed_newest(1), 1);

    let armed = |actions: &SessionLinkActions| {
        TokioRuntime::with_mutex_mut(&actions.link.keepalive_armed, |armed| *armed)
    };
    assert!(
        armed(&kept),
        "the session that is kept goes on with its keepalives"
    );
    assert!(
        !armed(&shed),
        "the one ordered closed does not ask for another"
    );
    assert_eq!(
        kept_link.sent(),
        kept_before,
        "and the kept one is not written to"
    );
    assert_eq!(shed_link.sent(), shed_before + 1, "the peer is told, once");
    assert_eq!(
        shed_link.bytes().last(),
        Some(&(wz_session_core::close_reason::CloseReason::Unresponsive as u8)),
        "with the reason a node gives a session it cannot serve"
    );
    assert!(
        shed.take_congestion_close(),
        "and the machine is asked to take the session down"
    );
}

/// A session the router deregisters is no longer held by the registry, so that the registry holds
/// no handle to a session that is gone and does not count it among those it keeps.
#[test]
fn a_session_that_leaves_the_router_leaves_the_registry() {
    let (fwd, _held) = router_holding(4);
    let registry = fwd.shed_registry();
    fwd.deregister(FaceId(3));
    assert_eq!(registry.live(), 3);
    assert_eq!(registry.shed_newest(3), 0, "three held, three kept");
}
