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
}

impl ReservingDriver {
    fn new(free: usize) -> Arc<Self> {
        Arc::new(Self {
            lane: Lane::new(free),
            full: AtomicBool::new(false),
            sent: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
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

fn remote() -> PublishOptions {
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
