// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publish sent under room it reserved (`Session::reserve_wire`, `Session::publish_reserved`
//! and its aliased forms), which is what a publish that reaches all of its links or none is made
//! of: the promise a link gives, what a send under it skips, and that the frame it writes is the
//! frame the publish that waits writes.

use super::*;
use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomPermit, RoomWait};

/// A lane that can promise `free` more frames and counts the promises that are held.
struct Lane {
    free: AtomicUsize,
    held: AtomicUsize,
}

impl Lane {
    fn new(free: usize) -> Arc<Self> {
        Arc::new(Self {
            free: AtomicUsize::new(free),
            held: AtomicUsize::new(0),
        })
    }

    fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    fn take(self: &Arc<Self>) -> Option<RoomPermit> {
        self.free
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |free| {
                free.checked_sub(1)
            })
            .ok()?;
        self.held.fetch_add(1, Ordering::SeqCst);
        Some(RoomPermit::held(Promise(Arc::clone(self))))
    }
}

/// One promise of a [`Lane`]: given back when it drops.
struct Promise(Arc<Lane>);

impl Drop for Promise {
    fn drop(&mut self) {
        self.0.held.fetch_sub(1, Ordering::SeqCst);
        self.0.free.fetch_add(1, Ordering::SeqCst);
    }
}

/// A link whose lane promises room as its [`Lane`] says, that answers the old question
/// ("is there room") as the test says, and that counts the frames it was handed and the times it
/// was asked.
struct ReservingDriver {
    lane: Arc<Lane>,
    full: AtomicBool,
    sent: AtomicUsize,
    asked: AtomicUsize,
    mtu: usize,
}

impl ReservingDriver {
    fn new(free: usize) -> Arc<Self> {
        Self::with_mtu(free, wz_session_core::link::DEFAULT_LINK_MTU)
    }

    /// A driver whose link takes frames of at most `mtu` bytes, so a payload past it is a chain.
    fn with_mtu(free: usize, mtu: usize) -> Arc<Self> {
        Arc::new(Self {
            lane: Lane::new(free),
            full: AtomicBool::new(false),
            sent: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
            mtu,
        })
    }

    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    fn set_full(&self, full: bool) {
        self.full.store(full, Ordering::SeqCst);
    }
}

impl crate::session_glue::BoxedLinkDriver for ReservingDriver {
    fn send_blocking(
        &self,
        _bytes: &[u8],
        _reliability: crate::Reliability,
    ) -> crate::session_glue::LinkSendOutcome {
        self.sent.fetch_add(1, Ordering::SeqCst);
        crate::session_glue::LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
    fn wait_for_room(
        &self,
        _priority: wz_session_core::qos::Priority,
        _wait: RoomWait,
    ) -> RoomAnswer {
        self.asked.fetch_add(1, Ordering::SeqCst);
        RoomAnswer::at_once(if self.full.load(Ordering::SeqCst) {
            LinkRoom::Congested
        } else {
            LinkRoom::Free
        })
    }
    fn try_reserve_room(&self, _priority: wz_session_core::qos::Priority) -> Option<RoomPermit> {
        self.lane.take()
    }

    fn link_mtu(&self) -> usize {
        self.mtu
    }
}

fn session_over(driver: &Arc<ReservingDriver>) -> TokioSession {
    let actions = crate::session_glue::new_session_actions(
        driver.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    TokioSession::new(actions, observer, Arc::new(TokioTime::new()))
}

/// A session whose link records the frames it is handed and has no queue to reserve in.
fn recording_session() -> (TokioSession, Arc<RecordingLinkDriver>) {
    let (actions, driver) = recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    (
        TokioSession::new(actions, observer, Arc::new(TokioTime::new())),
        driver,
    )
}

fn remote() -> PublishOptions<'static> {
    PublishOptions::put().with_locality(Locality::Remote)
}

/// The reservation `session` grants for `opts`; the test fails when the lane had none.
fn reserved(session: &TokioSession, opts: &PublishOptions) -> WireReservation {
    match session.reserve_wire(opts) {
        Ok(WireRoom::Granted(reservation)) => reservation,
        Ok(WireRoom::NoRoom) => panic!("the lane had no room to promise"),
        Err(e) => panic!("the session could not reserve: {e:?}"),
    }
}

#[test]
fn a_reservation_is_granted_while_the_lane_has_room_and_given_back_when_dropped() {
    let driver = ReservingDriver::new(1);
    let session = session_over(&driver);
    let held = reserved(&session, &remote());
    assert!(held.is_held(), "the link's own promise, not a trivial one");
    assert_eq!(driver.lane.held(), 1);
    assert!(
        matches!(session.reserve_wire(&remote()), Ok(WireRoom::NoRoom)),
        "a lane at its bound after one reservation refuses a second"
    );
    assert_eq!(driver.lane.held(), 1, "a refusal takes nothing");
    drop(held);
    assert_eq!(driver.lane.held(), 0, "dropping gives the room back");
    assert!(
        matches!(session.reserve_wire(&remote()), Ok(WireRoom::Granted(_))),
        "and the room is there for the next"
    );
}

#[test]
fn a_publish_under_a_reservation_asks_for_no_room_and_writes_the_frame() {
    let driver = ReservingDriver::new(1);
    let session = session_over(&driver);
    let held = reserved(&session, &remote());
    // The old question would be answered "no room" now: the reservation is what makes the send
    // possible, and it must not be asked.
    driver.set_full(true);
    assert_eq!(
        session.publish_reserved("home/temp", b"22.5", remote(), held),
        Ok(())
    );
    assert_eq!(driver.sent(), 1, "the frame is on the link");
    assert_eq!(
        driver.asked(),
        0,
        "the reservation is the room, so the link is not asked for any"
    );
    assert_eq!(driver.lane.held(), 0, "the promise is given back after it");
}

#[test]
fn a_reserved_publish_puts_the_frame_the_waiting_publish_puts_on_the_link() {
    let (reserving, reserving_driver) = recording_session();
    let (waiting, waiting_driver) = recording_session();
    let held = reserved(&reserving, &remote());
    assert!(!held.is_held(), "a link with no queue promises nothing");
    reserving
        .publish_reserved("home/temp", b"22.5", remote(), held)
        .expect("the reserved publish");
    waiting
        .publish("home/temp", b"22.5", remote())
        .expect("the waiting publish");
    assert_eq!(reserving_driver.frame_count(), 1);
    assert_eq!(
        reserving_driver.frame_bytes(0),
        waiting_driver.frame_bytes(0),
        "the reserved send puts the same bytes on the link as the publish that waits"
    );
}

#[test]
fn a_reservation_dropped_unused_leaves_no_trace_in_the_sequence() {
    let (abandoning, abandoning_driver) = recording_session();
    let (plain, plain_driver) = recording_session();
    drop(reserved(&abandoning, &remote()));
    assert_eq!(abandoning_driver.frame_count(), 0, "nothing was written");
    abandoning
        .publish("home/temp", b"22.5", remote())
        .expect("a publish after the abandoned reservation");
    plain
        .publish("home/temp", b"22.5", remote())
        .expect("a publish on a session that reserved nothing");
    assert_eq!(
        abandoning_driver.frame_bytes(0),
        plain_driver.frame_bytes(0),
        "the first frame after an abandoned reservation carries the first sequence number"
    );
}

#[test]
fn a_publish_that_may_not_go_remote_owes_the_link_nothing() {
    let driver = ReservingDriver::new(1);
    let session = session_over(&driver);
    let local = PublishOptions::put().with_locality(Locality::SessionLocal);
    let held = reserved(&session, &local);
    assert!(!held.is_held(), "no room of the lane is taken");
    assert_eq!(driver.lane.held(), 0);
    assert_eq!(
        session.publish_reserved("home/temp", b"22.5", local, held),
        Ok(())
    );
    assert_eq!(driver.sent(), 0, "nothing is written to the link");
    assert!(
        matches!(session.reserve_wire(&remote()), Ok(WireRoom::Granted(_))),
        "and the lane's one frame of room was never touched"
    );
}

#[cfg(all(feature = "codec-declare", feature = "declare-keyexpr"))]
#[test]
fn an_aliased_reserved_publish_needs_the_declaration_and_gives_the_room_back_when_refused() {
    let driver = ReservingDriver::new(1);
    let session = session_over(&driver);

    // An id the table does not hold is refused before the link is offered anything, and the
    // reservation is given back with the refusal.
    let held = reserved(&session, &remote());
    assert_eq!(driver.lane.held(), 1);
    assert_eq!(
        session.publish_aliased_auto_reserved(42, None, b"x", remote(), held),
        Err(PublishAliasError::UnknownMapping(42))
    );
    assert_eq!(driver.lane.held(), 0);
    assert_eq!(driver.sent(), 0);

    session
        .actions()
        .send_declare_keyexpr(7, "home/temp")
        .expect("hardcoded canonical literal keyexpr");
    let declared = driver.sent();
    let asked = driver.asked();
    driver.set_full(true);
    let held = reserved(&session, &remote());
    assert_eq!(
        session.publish_aliased_auto_reserved(7, Some("/kitchen"), b"x", remote(), held),
        Ok(())
    );
    assert_eq!(driver.sent(), declared + 1, "the push is on the link");
    assert_eq!(driver.asked(), asked, "and asked it for no room");
    assert_eq!(driver.lane.held(), 0);
}

/// The reservation of a whole chain `session` grants for `payload`; the test fails when the lane
/// had no room for it.
#[cfg(feature = "transport-fragmentation")]
fn chain_reserved(session: &TokioSession, payload: &[u8]) -> WireReservation {
    match session.reserve_wire_chain("home/chain", payload, &remote()) {
        Ok(WireRoom::Granted(reservation)) => reservation,
        Ok(WireRoom::NoRoom) => panic!("the lane had no room for the chain"),
        Err(e) => panic!("the session could not reserve: {e:?}"),
    }
}

/// A payload past the link's frame budget is a chain of frames, and its reservation takes the
/// room of every one of them at once, or of none: a lane one frame short promises nothing, and
/// one with exactly the chain's room takes it. Sent under it, no frame of the chain asks for
/// room, so none waits for room the publish itself holds, and the promise is given back after.
#[cfg(feature = "transport-fragmentation")]
#[test]
fn a_chain_reservation_takes_the_room_of_every_frame_or_of_none() {
    const MTU: usize = 64;
    let payload = vec![0x5a_u8; 400];

    let roomy = ReservingDriver::with_mtu(1_000, MTU);
    let session = session_over(&roomy);
    let whole = chain_reserved(&session, &payload);
    let frames = roomy.lane.held();
    assert!(
        frames >= 2,
        "the payload is a chain at this budget, and every frame of it is promised: {frames}"
    );
    assert!(whole.is_whole_chain());
    drop(whole);
    assert_eq!(roomy.lane.held(), 0, "dropping gives every frame back");

    let short = ReservingDriver::with_mtu(frames - 1, MTU);
    let session = session_over(&short);
    assert!(
        matches!(
            session.reserve_wire_chain("home/chain", &payload, &remote()),
            Ok(WireRoom::NoRoom)
        ),
        "a lane one frame short of the chain promises nothing"
    );
    assert_eq!(
        short.lane.held(),
        0,
        "the frames promised before the one that found no room are given back"
    );
    assert_eq!(short.sent(), 0, "and nothing was sent");

    let exact = ReservingDriver::with_mtu(frames, MTU);
    let session = session_over(&exact);
    let held = chain_reserved(&session, &payload);
    // The old question would be answered "no room" now: the reservation is the room of every
    // frame, and no frame may ask.
    exact.set_full(true);
    assert_eq!(
        session.publish_reserved("home/chain", &payload, remote(), held),
        Ok(())
    );
    let sent = exact.sent();
    assert!(
        (2..=frames).contains(&sent),
        "the whole chain is on the link, within what was promised: {sent} of {frames}"
    );
    assert_eq!(exact.asked(), 0, "no frame of the chain asked for room");
    assert_eq!(exact.lane.held(), 0, "the promise is given back after it");
}

/// A link with no queue promises a chain trivially, as it promises a frame.
#[test]
fn a_link_with_no_queue_promises_a_chain_trivially() {
    let (session, _driver) = recording_session();
    let reservation = match session.reserve_wire_chain("home/chain", b"v", &remote()) {
        Ok(WireRoom::Granted(reservation)) => reservation,
        other => panic!("a link with no queue grants: {other:?}"),
    };
    assert!(!reservation.is_held());
    assert!(reservation.is_whole_chain());
}
