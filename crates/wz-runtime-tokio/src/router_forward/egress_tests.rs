// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The credit-based egress of the router ([`super::egress`]): what a destination that has no room
//! holds, which faces that gates, and when the destination is closed.
//!
//! The destination's link is a driver whose room a test switches, so that every case is decided
//! by what the driver answers and by a clock the test moves, and none by a socket or a sleep.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::egress::EGRESS_CREDIT;
use super::*;
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session_glue::{new_session_actions, BoxedLinkDriver, LinkSendOutcome};
use crate::Reliability;
use wz_runtime_core::runtime::Runtime;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::declare_build::build_declare_subscriber;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::metadata::PushMetadata;
use wz_session_core::push_build::{build_push_literal, build_push_literal_with_meta};
use wz_session_core::qos::CongestionControl;
use wz_session_core::sample::QosLevel;

/// A link whose queue is full or not as the test says, and that keeps the frames it was given.
struct RoomLink {
    full: AtomicBool,
    frames: Mutex<Vec<Vec<u8>>>,
    sent: AtomicUsize,
}

impl RoomLink {
    fn new(full: bool) -> Arc<Self> {
        Arc::new(Self {
            full: AtomicBool::new(full),
            frames: Mutex::new(Vec::new()),
            sent: AtomicUsize::new(0),
        })
    }

    fn set_full(&self, full: bool) {
        self.full.store(full, Ordering::SeqCst);
    }

    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    /// Every byte the link was given, in the order it was given.
    fn bytes(&self) -> Vec<u8> {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .flatten()
            .copied()
            .collect()
    }
}

impl BoxedLinkDriver for RoomLink {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.frames.lock().expect("frames").push(bytes.to_vec());
        self.sent.fetch_add(1, Ordering::SeqCst);
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
    fn wait_for_room(&self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        RoomAnswer::at_once(if self.full.load(Ordering::SeqCst) {
            LinkRoom::Congested
        } else {
            LinkRoom::Free
        })
    }
}

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A client face over `link`, whose remote peer is `peer`.
fn client_over(link: &Arc<RoomLink>, peer: Zid) -> Arc<SessionLinkActions> {
    let actions = new_session_actions(
        link.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    actions
}

fn forward_frame(fwd: &RouterForwarder, face: FaceId, messages: Vec<NetworkMessage>) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(face, IterationEvent::Poll(&outcome));
}

/// A Put under `demo/x` that may not be dropped: the kind of message the credit stage holds.
fn blocking_put(payload: &[u8]) -> NetworkMessage {
    let meta = PushMetadata {
        qos: Some(QosLevel::DEFAULT.with_congestion(CongestionControl::Block)),
        ..PushMetadata::default()
    };
    NetworkMessage::Push(Box::new(
        build_push_literal_with_meta("demo/x", payload, &meta).expect("build push"),
    ))
}

/// The same Put with the default congestion control, which drops.
fn droppable_put(payload: &[u8]) -> NetworkMessage {
    NetworkMessage::Push(Box::new(
        build_push_literal("demo/x", payload).expect("build push"),
    ))
}

const SOURCE: FaceId = FaceId(1);
const OTHER_SOURCE: FaceId = FaceId(3);
const DEST: FaceId = FaceId(2);

/// A router with two publishing faces and one face subscribed to `demo/x`, whose link is full or
/// not as the test says. `now` moves the router's clock.
struct Rig {
    fwd: RouterForwarder,
    link: Arc<RoomLink>,
    dest: Arc<SessionLinkActions>,
    now: Rc<Cell<Duration>>,
    /// Frames the destination's link had been given once the subscription was in place.
    baseline: usize,
}

impl Rig {
    fn new(full: bool) -> Self {
        let base = Instant::now();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let clock = {
            let now = Rc::clone(&now);
            Box::new(move || base + now.get())
        };
        let fwd = RouterForwarder::with_clock(zid(0x01), clock);
        let link = RoomLink::new(false);
        let dest = client_over(&link, zid(0xCC));
        let quiet = RoomLink::new(false);
        fwd.register(SOURCE, &client_over(&quiet, zid(0xAA)));
        fwd.register(OTHER_SOURCE, &client_over(&quiet, zid(0xAB)));
        fwd.register(DEST, &dest);
        forward_frame(
            &fwd,
            DEST,
            vec![NetworkMessage::Declare(Box::new(
                build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
            ))],
        );
        link.set_full(full);
        let baseline = link.sent();
        Self {
            fwd,
            link,
            dest,
            now,
            baseline,
        }
    }

    fn advance(&self, by: Duration) {
        self.now.set(self.now.get() + by);
    }
}

/// A message that finds no room is held, whole, and leaves when the destination has room: it is
/// neither dropped nor waited for inside the loop.
#[test]
fn a_blocking_put_that_finds_no_room_is_held_and_leaves_when_there_is_room() {
    let rig = Rig::new(true);
    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(b"first")]);
    assert_eq!(
        rig.link.sent(),
        rig.baseline,
        "nothing left a link that has no room"
    );
    assert_eq!(rig.fwd.egress_held(), 1, "it is held");
    assert_eq!(
        rig.fwd.egress_gated_faces(),
        0,
        "one is far from the credit"
    );

    rig.link.set_full(false);
    rig.fwd.drain_egress();
    assert_eq!(
        rig.link.sent(),
        rig.baseline + 1,
        "it left when there was room"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_released(), 1);
    assert_eq!(rig.fwd.egress_abandoned(), 0, "and nothing was lost");
}

/// What a destination holds leaves in the order it arrived, and a message that arrives when the
/// destination has room again still goes behind what it holds: one source's messages to one
/// destination are not reordered by the stage.
#[test]
fn held_messages_leave_in_the_order_they_arrived_and_a_later_one_waits_behind_them() {
    let rig = Rig::new(true);
    forward_frame(
        &rig.fwd,
        SOURCE,
        vec![blocking_put(b"AAAA-1"), blocking_put(b"BBBB-2")],
    );
    rig.link.set_full(false);
    // Room has come back, but nothing has drained yet: the next message must not pass the two.
    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(b"CCCC-3")]);
    rig.fwd.drain_egress();
    assert_eq!(rig.fwd.egress_held(), 0);

    let bytes = rig.link.bytes();
    let at = |needle: &[u8]| {
        bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap_or_else(|| panic!("{:?} was sent", String::from_utf8_lossy(needle)))
    };
    assert!(
        at(b"AAAA-1") < at(b"BBBB-2") && at(b"BBBB-2") < at(b"CCCC-3"),
        "in the order they arrived"
    );
}

/// A destination that holds its credit gates the face that filled it, and only that face; the
/// face is read again when the destination has drained.
#[test]
fn a_destination_at_its_credit_gates_the_face_that_fed_it_and_no_other() {
    let rig = Rig::new(true);
    let frame: Vec<NetworkMessage> = (0..EGRESS_CREDIT)
        .map(|i| blocking_put(format!("m-{i}").as_bytes()))
        .collect();
    forward_frame(&rig.fwd, SOURCE, frame);
    assert_eq!(rig.fwd.egress_held(), EGRESS_CREDIT);
    assert_eq!(rig.fwd.egress_gated_faces(), 1);
    assert!(
        rig.fwd.read_gate(SOURCE).is_some(),
        "the face that filled the destination is not read"
    );
    assert!(
        rig.fwd.read_gate(OTHER_SOURCE).is_none(),
        "a face that fed nothing is read"
    );
    assert!(
        rig.fwd.read_gate(DEST).is_none(),
        "and so is the destination"
    );

    rig.link.set_full(false);
    assert!(
        rig.fwd.read_gate(SOURCE).is_none(),
        "the face is read again once the destination has taken what it held"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_gated_faces(), 0);
    assert_eq!(rig.link.sent(), rig.baseline + EGRESS_CREDIT);
}

/// A destination that does not take its oldest message within `wait_before_close` is closed as
/// unresponsive, and its held messages and the gates on it go; before that it is not.
#[test]
fn a_destination_that_does_not_take_its_oldest_message_in_time_is_closed() {
    let rig = Rig::new(true);
    let frame: Vec<NetworkMessage> = (0..EGRESS_CREDIT)
        .map(|i| blocking_put(format!("m-{i}").as_bytes()))
        .collect();
    forward_frame(&rig.fwd, SOURCE, frame);
    let deadline = rig.dest.wait_before_close();

    rig.advance(deadline - Duration::from_millis(1));
    rig.fwd.tick();
    assert!(
        !rig.dest.take_congestion_close(),
        "one millisecond short of the deadline the destination is not closed"
    );
    assert_eq!(rig.fwd.egress_held(), EGRESS_CREDIT);

    rig.advance(Duration::from_millis(2));
    rig.fwd.tick();
    assert!(
        rig.dest.take_congestion_close(),
        "past the deadline it is closed, as a send that waited that long closes it"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_abandoned(), EGRESS_CREDIT);
    assert_eq!(rig.fwd.egress_destinations_closed(), 1);
    assert!(
        rig.fwd.read_gate(SOURCE).is_none(),
        "and the face it gated is read again"
    );
}

/// A message that may be dropped keeps the send it had: it is not held, so a destination with no
/// room costs the loop no more than it did.
#[test]
fn a_droppable_put_is_not_held() {
    let rig = Rig::new(true);
    forward_frame(&rig.fwd, SOURCE, vec![droppable_put(b"best-effort")]);
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(
        rig.link.sent(),
        rig.baseline,
        "it was dropped for want of room"
    );
}

/// A face that leaves takes what it held, and the faces gated on it are released.
#[test]
fn a_destination_that_leaves_takes_what_it_held_and_releases_the_faces_gated_on_it() {
    let rig = Rig::new(true);
    let frame: Vec<NetworkMessage> = (0..EGRESS_CREDIT)
        .map(|i| blocking_put(format!("m-{i}").as_bytes()))
        .collect();
    forward_frame(&rig.fwd, SOURCE, frame);
    assert_eq!(rig.fwd.egress_gated_faces(), 1);

    rig.fwd.deregister(DEST);
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_abandoned(), EGRESS_CREDIT);
    assert_eq!(rig.fwd.egress_gated_faces(), 0);
    assert!(rig.fwd.read_gate(SOURCE).is_none());
}

/// Only a message sent on behalf of a face that can be gated, reliable, with a congestion control
/// that blocks, goes through the stage: anything else keeps its send.
#[test]
fn only_a_reliable_blocking_put_from_a_face_goes_through_the_credit_stage() {
    let rig = Rig::new(false);
    let block = blocking_put(b"x");
    let drop = droppable_put(b"x");
    assert!(
        !rig.fwd.is_credited(&block, true),
        "a message with no face behind it cannot gate anything, so it keeps its send"
    );
    let _routing = rig.fwd.credit.routing_from(SOURCE);
    assert!(rig.fwd.is_credited(&block, true));
    assert!(
        !rig.fwd.is_credited(&block, false),
        "best effort is droppable"
    );
    assert!(
        !rig.fwd.is_credited(&drop, true),
        "so is congestion control Drop"
    );
}
