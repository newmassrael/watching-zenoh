// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The credit-based egress of the router ([`super::egress`]): what a destination that has no room
//! holds, which faces that gates, and when the destination is closed.
//!
//! The destination's link is a driver whose room a test switches, so that every case is decided
//! by what the driver answers and by a clock the test moves, and none by a socket or a sleep.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::egress::{message_cost, EgressBudget};
use super::*;
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session_glue::{new_session_actions, BoxedLinkDriver, LinkSendOutcome};
use crate::sync::PlainCell;
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
pub(super) struct RoomLink {
    full: AtomicBool,
    frames: Mutex<Vec<Vec<u8>>>,
    sent: AtomicUsize,
    /// What the router asked to be called when the link makes room, as a real writer's queue
    /// keeps it.
    waker: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl RoomLink {
    pub(super) fn new(full: bool) -> Arc<Self> {
        Arc::new(Self {
            full: AtomicBool::new(full),
            frames: Mutex::new(Vec::new()),
            sent: AtomicUsize::new(0),
            waker: Mutex::new(None),
        })
    }

    /// Whether the router is waiting to be told of room on this link.
    fn is_watched(&self) -> bool {
        self.waker.lock().expect("waker").is_some()
    }

    /// The link makes room, as its writer does when it takes a frame: the queue is no longer full
    /// and whoever asked is called.
    fn make_room(&self) {
        self.set_full(false);
        let waker = self.waker.lock().expect("waker").clone();
        if let Some(waker) = waker {
            waker();
        }
    }

    fn set_full(&self, full: bool) {
        self.full.store(full, Ordering::SeqCst);
    }

    pub(super) fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    /// Every byte the link was given, in the order it was given.
    pub(super) fn bytes(&self) -> Vec<u8> {
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
    fn watch_room(&self, waker: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.waker.lock().expect("waker") = waker;
    }
    fn wait_for_room(&self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        RoomAnswer::at_once(if self.full.load(Ordering::SeqCst) {
            LinkRoom::Congested
        } else {
            LinkRoom::Free
        })
    }
}

pub(super) fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A client face over `link`, whose remote peer is `peer`.
pub(super) fn client_over(link: &Arc<RoomLink>, peer: Zid) -> Arc<SessionLinkActions> {
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

/// How many messages of [`filler`] fill a destination's budget in the tests that fill one.
const FILL: usize = 8;

/// A message of a fixed size, so that `FILL` of them cost exactly what a destination may hold.
fn filler(i: usize) -> NetworkMessage {
    blocking_put(format!("m-{i:04}").as_bytes())
}

/// A budget a destination reaches with `FILL` messages of [`filler`], and a pool nothing in the
/// tests reaches unless it is the case under test.
fn filling_budget() -> EgressBudget {
    EgressBudget {
        per_destination_bytes: FILL * message_cost(&filler(0)),
        pool_bytes: usize::MAX / 2,
    }
}

/// `FILL` messages, which fill a destination under [`filling_budget`].
fn a_destinations_worth() -> Vec<NetworkMessage> {
    (0..FILL).map(filler).collect()
}

/// A router with two publishing faces and one face subscribed to `demo/x`, whose link is full or
/// not as the test says. `now` moves the router's clock.
struct Rig {
    fwd: RouterForwarder,
    link: Arc<RoomLink>,
    dest: Arc<SessionLinkActions>,
    now: Arc<PlainCell<Duration>>,
    /// Frames the destination's link had been given once the subscription was in place.
    baseline: usize,
}

impl Rig {
    fn new(full: bool) -> Self {
        Self::with_budget(full, EgressBudget::default())
    }

    /// A rig whose destination holds [`FILL`] messages of [`filler`] before its sources are gated.
    fn filling(full: bool) -> Self {
        Self::with_budget(full, filling_budget())
    }

    fn with_budget(full: bool, budget: EgressBudget) -> Self {
        let base = Instant::now();
        let now = Arc::new(PlainCell::new(Duration::ZERO));
        let clock = {
            let now = Arc::clone(&now);
            Box::new(move || base + now.get())
        };
        let fwd = RouterForwarder::with_clock(zid(0x01), clock).with_egress_budget(budget);
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

    /// Another face subscribed to `demo/x`, whose link is full or not, so that one Put has two
    /// destinations. The link is the test's to switch.
    fn add_destination(&self, face: FaceId, peer: Zid, full: bool) -> Arc<RoomLink> {
        let link = RoomLink::new(false);
        self.fwd.register(face, &client_over(&link, peer));
        forward_frame(
            &self.fwd,
            face,
            vec![NetworkMessage::Declare(Box::new(
                build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
            ))],
        );
        link.set_full(full);
        link
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
    rig.fwd.on_tables().drain_egress();
    assert_eq!(
        rig.link.sent(),
        rig.baseline + 1,
        "it left when there was room"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_released(), 1);
    assert_eq!(rig.fwd.egress_abandoned(), 0, "and nothing was lost");
}

/// The view the capacity report reads says what the router holds, in the units the report names,
/// and goes on saying it as the router holds and releases: it is a handle on the router's own
/// counters and not a copy taken when it was made.
#[test]
fn the_egress_view_reads_what_the_router_holds_as_it_holds_and_releases() {
    let rig = Rig::new(true);
    let view = rig.fwd.egress_view();
    let none = wz_session_core::capacity::EgressCounts {
        pool_bytes: EgressBudget::default().pool_bytes,
        ..Default::default()
    };
    assert_eq!(
        view.counts(),
        none,
        "a router that holds nothing says zeros"
    );

    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(b"first")]);
    let held = view.counts();
    assert_eq!(held.held, 1);
    assert_eq!(held.held_bytes, rig.fwd.egress_held_bytes());
    assert!(held.held_bytes > 0, "a held message costs bytes");
    assert_eq!(held.released, 0);

    rig.link.set_full(false);
    rig.fwd.on_tables().drain_egress();
    let after = view.counts();
    assert_eq!((after.held, after.held_bytes), (0, 0));
    assert_eq!(after.released, 1);
    assert_eq!(after.abandoned, 0);
    assert_eq!(
        after.pool_bytes, held.pool_bytes,
        "the budget does not move"
    );
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
    rig.fwd.on_tables().drain_egress();
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
fn a_destination_at_its_budget_gates_the_face_that_fed_it_and_no_other() {
    let rig = Rig::filling(true);
    forward_frame(&rig.fwd, SOURCE, a_destinations_worth());
    assert_eq!(rig.fwd.egress_held(), FILL);
    assert_eq!(
        rig.fwd.egress_held_bytes(),
        FILL * message_cost(&filler(0)),
        "the pool holds what the messages cost, in bytes"
    );
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
    assert_eq!(rig.fwd.egress_held_bytes(), 0, "and the pool is given back");
    assert_eq!(rig.fwd.egress_gated_faces(), 0);
    assert_eq!(rig.link.sent(), rig.baseline + FILL);
}

/// A destination that does not take its oldest message within `wait_before_close` is closed as
/// unresponsive, and its held messages and the gates on it go; before that it is not.
#[test]
fn a_destination_that_does_not_take_its_oldest_message_in_time_is_closed() {
    let rig = Rig::filling(true);
    forward_frame(&rig.fwd, SOURCE, a_destinations_worth());
    let deadline = rig.dest.wait_before_close();

    rig.advance(deadline - Duration::from_millis(1));
    rig.fwd.tick();
    assert!(
        !rig.dest.take_congestion_close(),
        "one millisecond short of the deadline the destination is not closed"
    );
    assert_eq!(rig.fwd.egress_held(), FILL);

    rig.advance(Duration::from_millis(2));
    rig.fwd.tick();
    assert!(
        rig.dest.take_congestion_close(),
        "past the deadline it is closed, as a send that waited that long closes it"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_held_bytes(), 0, "and the pool is given back");
    assert_eq!(rig.fwd.egress_abandoned(), FILL);
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
    let rig = Rig::filling(true);
    forward_frame(&rig.fwd, SOURCE, a_destinations_worth());
    assert_eq!(rig.fwd.egress_gated_faces(), 1);

    rig.fwd.deregister(DEST);
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_held_bytes(), 0, "and the pool is given back");
    assert_eq!(rig.fwd.egress_abandoned(), FILL);
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

/// A link over a REAL outbound queue, the one every unicast driver of the runtime writes
/// through: its room answer, its notice and its frames are the queue's.
struct QueueLink {
    tx: crate::writer_queue::OutboundTx,
}

impl BoxedLinkDriver for QueueLink {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        match self.tx.send(Priority::DEFAULT, bytes.to_vec()) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(wz_session_core::link::LinkDropCause::WriterGone),
        }
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
    fn wait_for_room(&self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        self.tx.link_room(priority, wait)
    }
    fn watch_room(&self, waker: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.tx.watch_room(waker)
    }
}

/// A router whose one destination is a session over a real queue of two batches of 65 535 bytes
/// in every lane, and the queue's reading end. The destination is returned to be kept alive: the
/// router holds a face by reference.
fn router_over_a_queue() -> (RouterForwarder, impl Sized, crate::writer_queue::OutboundRx) {
    let (tx, mut rx) =
        crate::writer_queue::outbound_channel_with_capacity([2; Priority::NUM], 65_535);
    let link = Arc::new(QueueLink { tx });
    let dest = new_session_actions(link, fixture_session_init_params(), TokioTime::new());
    TokioRuntime::with_mutex_mut(&dest.remote_peer_zid, |s| {
        *s = Some(zid(0xCC).as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&dest.peer_whatami, |s| *s = Some(0b10));
    let fwd = RouterForwarder::new(zid(0x01));
    let quiet = RoomLink::new(false);
    fwd.register(SOURCE, &client_over(&quiet, zid(0xAA)));
    fwd.register(DEST, &dest);
    forward_frame(
        &fwd,
        DEST,
        vec![NetworkMessage::Declare(Box::new(
            build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
        ))],
    );
    while rx.try_recv().is_some() {}
    (fwd, dest, rx)
}

/// A message that is a chain of fragments the lane can hold is not waited for when the lane is
/// full: the router holds it, as it holds a message that is one frame, and goes on.
///
/// Only a chain the lane can NEVER hold has to be sent waiting (the test below). A router that
/// sent every chain waiting would stop its one loop for as long as a stopped subscriber took to
/// be closed, which is what holding messages back exists to prevent.
#[test]
fn a_chain_the_lane_can_hold_is_held_and_not_waited_for_when_the_lane_is_full() {
    // Two fragments of one message: the first of 65 535 bytes and the second the rest. The lane
    // holds two batches, so the first message goes in whole, and the second finds the lane full
    // at its second fragment.
    const PAYLOAD: usize = 100_000;
    let (fwd, _dest, _rx) = router_over_a_queue();
    let started = Instant::now();
    forward_frame(&fwd, SOURCE, vec![blocking_put(&vec![0x5A; PAYLOAD])]);
    assert_eq!(fwd.egress_held(), 0, "the first chain fits the empty lane");
    forward_frame(&fwd, SOURCE, vec![blocking_put(&vec![0x5A; PAYLOAD])]);
    assert_eq!(
        fwd.egress_held(),
        1,
        "the second chain finds the lane full and is held"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the router did not wait for room: {:?}",
        started.elapsed()
    );
}

/// A message that is a chain of fragments, longer than the lane that carries it, is delivered
/// whole through a real queue whose writer takes what is there between the router's tries.
///
/// A chain is wire-atomic: it cannot be put down half way and picked up again, because the peer
/// has to be told to drop what it staged. A router that tried each fragment without waiting would
/// put two fragments in a lane of two batches, find it full at the third, abandon the chain and
/// try the whole message again at the next notice, for ever: every try gets as far as the lane is
/// deep and no further. The router has to leave a message that is a chain to the send that waits
/// for room under the chain's own lock, as it did before it held anything back.
#[test]
fn a_message_longer_than_the_lane_is_delivered_whole_through_a_real_queue() {
    use wz_session_core::put_payload::payload_len;
    const PAYLOAD: usize = 600_000;
    let (fwd, _dest, mut rx) = router_over_a_queue();

    // The link's writer is a thread of its own, as it is in the runtime: a send that waits for
    // room waits for it, and a test that drained on the thread that sends would wait out the
    // deadline for a writer that is itself. It is SLOWER than the sender, as a socket is slower
    // than a memory copy: a writer that kept up would take every fragment as it was queued, and
    // a sender that never waits would then get a chain through by luck.
    let written = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (written, stop) = (Arc::clone(&written), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match rx.try_recv() {
                    Some(frame) => {
                        written.fetch_add(frame.len(), Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    None => std::thread::yield_now(),
                }
            }
            while let Some(frame) = rx.try_recv() {
                written.fetch_add(frame.len(), Ordering::SeqCst);
            }
        })
    };

    let message = blocking_put(&vec![0x5A; PAYLOAD]);
    let NetworkMessage::Push(push) = &message else {
        unreachable!("built as a Push");
    };
    let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
        unreachable!("built as a Put");
    };
    assert_eq!(
        payload_len(put),
        PAYLOAD,
        "the case under test is a long message"
    );
    forward_frame(&fwd, SOURCE, vec![message]);

    // The router is told as its loop is, and tries what it holds, until the writer has taken the
    // message or a generous time is up. A router that gets nowhere gets nowhere however long.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10)
        && !(fwd.egress_held() == 0 && written.load(Ordering::SeqCst) >= PAYLOAD)
    {
        fwd.woken();
        std::thread::yield_now();
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().expect("the writer thread");
    let written = written.load(Ordering::SeqCst);
    assert_eq!(fwd.egress_held(), 0, "nothing is left held");
    assert!(
        (PAYLOAD..2 * PAYLOAD).contains(&written),
        "the message arrived once, in {written} bytes of frames for a payload of {PAYLOAD}: a chain \
         that is begun and abandoned and begun again writes the same fragments many times over"
    );
}

/// The whole path, with nothing standing in for the writer's queue: a message that finds the
/// queue full is held, the queue's writer taking a frame is what tells the router, and the router
/// then sends what it held, in the queue.
#[tokio::test(flavor = "current_thread")]
async fn a_real_write_queue_tells_the_router_when_its_writer_makes_room() {
    // A lane that holds one frame: any frame fills it.
    let (tx, mut rx) = crate::writer_queue::outbound_channel_with_capacity([1; Priority::NUM], 4);
    let link = Arc::new(QueueLink { tx });
    let dest = new_session_actions(link, fixture_session_init_params(), TokioTime::new());
    TokioRuntime::with_mutex_mut(&dest.remote_peer_zid, |s| {
        *s = Some(zid(0xCC).as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&dest.peer_whatami, |s| *s = Some(0b10));
    let fwd = RouterForwarder::new(zid(0x01));
    let quiet = RoomLink::new(false);
    fwd.register(SOURCE, &client_over(&quiet, zid(0xAA)));
    fwd.register(DEST, &dest);
    forward_frame(
        &fwd,
        DEST,
        vec![NetworkMessage::Declare(Box::new(
            build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
        ))],
    );
    // Whatever the router said to the destination while it was set up is read off the queue,
    // so that what follows is the puts.
    while rx.try_recv().is_some() {}

    forward_frame(&fwd, SOURCE, vec![blocking_put(b"first-put")]);
    forward_frame(&fwd, SOURCE, vec![blocking_put(b"second-put")]);
    assert_eq!(
        fwd.egress_held(),
        1,
        "the first fills the queue and the second is held"
    );
    let loop_wake = fwd.wake_signal().expect("the router asks to be woken");
    // The permit raised when the second was held, which the link did not give.
    tokio::time::timeout(Duration::from_secs(1), loop_wake.notified())
        .await
        .expect("holding woke the loop once");

    // The writer takes the first frame, and asks for the next: that is room.
    assert!(rx.try_recv().is_some(), "the writer takes the first put");
    assert!(rx.try_recv().is_none(), "and finds nothing more queued");
    tokio::time::timeout(Duration::from_secs(1), loop_wake.notified())
        .await
        .expect("the queue told the router, with nothing but its own notice");

    fwd.woken();
    assert_eq!(fwd.egress_held(), 0, "what was held left");
    let frame = rx.try_recv().expect("the held put is in the queue now");
    assert!(
        frame
            .windows(b"second-put".len())
            .any(|w| w == b"second-put"),
        "and it is the second put"
    );
}

/// A destination asks its link to tell the router of room for exactly as long as it holds
/// something, so that a writer whose queue nobody waits on pays nothing for the notice.
#[test]
fn a_destination_asks_its_link_for_room_while_it_holds_and_not_after() {
    let rig = Rig::new(true);
    assert!(
        !rig.link.is_watched(),
        "nothing is held, so nothing is asked"
    );

    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(b"held")]);
    assert!(
        rig.link.is_watched(),
        "a held message asks the link to say when it has room"
    );

    rig.link.set_full(false);
    rig.fwd.on_tables().drain_egress();
    assert_eq!(rig.fwd.egress_held(), 0);
    assert!(
        !rig.link.is_watched(),
        "and the request is withdrawn when nothing is held"
    );

    // The control: a destination whose held messages are dropped with it withdraws it too.
    rig.link.set_full(true);
    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(b"again")]);
    assert!(rig.link.is_watched());
    rig.advance(rig.dest.wait_before_close() + Duration::from_millis(1));
    rig.fwd.tick();
    assert!(
        !rig.link.is_watched(),
        "a destination that was closed for not taking its messages asks for nothing"
    );
}

/// The notice a link gives when it makes room reaches both who waits for it: a face gated on the
/// destination, which is told at once and asks again, and the loop, which is woken (with a
/// permit, so that a notice raised while it is busy is not lost) and sends what is held.
#[tokio::test(flavor = "current_thread")]
async fn a_links_room_wakes_the_gated_face_and_the_loop_and_what_is_held_leaves() {
    let rig = Rig::filling(true);
    forward_frame(&rig.fwd, SOURCE, a_destinations_worth());
    let gate = rig.fwd.read_gate(SOURCE).expect("the face is gated");

    // Holding the first message woke the loop once, for room made between the probe and the
    // request for notice. That permit is taken here, so that what follows is the link's.
    let loop_wake = rig.fwd.wake_signal().expect("the router asks to be woken");
    tokio::time::timeout(Duration::from_secs(1), loop_wake.notified())
        .await
        .expect("holding woke the loop once");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), loop_wake.notified())
            .await
            .is_err(),
        "and once only: nothing else woke it"
    );

    // The face registers as a waiter, as the drive does, and the link then makes room.
    let notified = gate.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    rig.link.make_room();
    tokio::time::timeout(Duration::from_secs(1), notified)
        .await
        .expect("the gated face was told, and did not have to wait for a timer");

    tokio::time::timeout(Duration::from_secs(1), loop_wake.notified())
        .await
        .expect("the loop was woken by the link, and the permit was kept for it");

    rig.fwd.woken();
    assert_eq!(rig.fwd.egress_held(), 0, "what was held left");
    assert_eq!(rig.link.sent(), rig.baseline + FILL);
    assert!(
        rig.fwd.read_gate(SOURCE).is_none(),
        "and the face is read again"
    );
}

/// What a held message costs is the entry that carries it and its payload, so that two messages of
/// the same kind differ by exactly the bytes of their payloads, and the entry itself is not free.
#[test]
fn a_messages_cost_is_its_entry_and_its_payload() {
    let small = message_cost(&blocking_put(&[0u8; 10]));
    let large = message_cost(&blocking_put(&[0u8; 10_010]));
    assert_eq!(large - small, 10_000, "the payload, byte for byte");
    assert!(
        small > 10 + 100,
        "and the entry that holds a message is more than its payload: {small}"
    );
}

/// The budget is bytes and not messages: the number of messages the credit used to gate at, held
/// by a destination, is no reason to gate a face when they are small.
#[test]
fn many_small_messages_are_not_a_destinations_budget() {
    let rig = Rig::new(true);
    let many = 64;
    assert!(
        many * message_cost(&filler(0)) < EgressBudget::DEFAULT_PER_DESTINATION_BYTES,
        "the case under test is small messages"
    );
    forward_frame(&rig.fwd, SOURCE, (0..many).map(filler).collect());
    assert_eq!(rig.fwd.egress_held(), many, "they are all held");
    assert_eq!(
        rig.fwd.egress_gated_faces(),
        0,
        "and the face that sent them is read"
    );
}

/// A message larger than the whole budget of a destination is held, alone: a queue that refused it
/// could never send it. It gates the face that sent it all the same, and leaves when there is room.
#[test]
fn a_message_larger_than_a_destinations_whole_budget_is_held_alone_and_gates_its_face() {
    let rig = Rig::new(true);
    let size = EgressBudget::DEFAULT_PER_DESTINATION_BYTES + 1;
    forward_frame(&rig.fwd, SOURCE, vec![blocking_put(&vec![0xAB; size])]);
    assert_eq!(
        rig.fwd.egress_held(),
        1,
        "held, though it is more than the budget"
    );
    assert!(rig.fwd.egress_held_bytes() > size);
    assert_eq!(
        rig.fwd.egress_gated_faces(),
        1,
        "one message was enough to gate its face"
    );
    assert!(rig.fwd.read_gate(SOURCE).is_some());

    rig.link.set_full(false);
    assert!(
        rig.fwd.read_gate(SOURCE).is_none(),
        "when the destination has room the message leaves and the face is read"
    );
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_held_bytes(), 0);
    // A message this large leaves as a chain of fragments, so it is the bytes that are counted:
    // every byte of the payload is on the link.
    assert!(rig.link.sent() > rig.baseline, "it was written");
    assert!(
        rig.link.bytes().len() > size,
        "all of it: {} bytes written for a payload of {size}",
        rig.link.bytes().len()
    );
}

/// The router's pool is a budget of its own: destinations that are each under their budget, but
/// hold together as much as the pool, gate the faces that feed them, including a face that
/// feeds a destination nothing is held for yet, until the pool is down.
#[test]
fn the_pool_gates_faces_when_destinations_are_each_under_their_budget() {
    let rig = Rig::with_budget(
        true,
        EgressBudget {
            per_destination_bytes: usize::MAX / 2,
            pool_bytes: FILL * message_cost(&filler(0)),
        },
    );
    let second = rig.add_destination(FaceId(4), zid(0xCD), true);

    // Four puts, each to two destinations: eight held, which is the whole pool.
    forward_frame(&rig.fwd, SOURCE, (0..FILL / 2).map(filler).collect());
    assert_eq!(rig.fwd.egress_held(), FILL);
    assert_eq!(rig.fwd.egress_held_bytes(), FILL * message_cost(&filler(0)));
    assert_eq!(
        rig.fwd.egress_gated_faces(),
        1,
        "the face that filled the pool"
    );
    assert!(rig.fwd.read_gate(SOURCE).is_some());
    assert!(
        rig.fwd.read_gate(OTHER_SOURCE).is_none(),
        "a face that has sent nothing is read"
    );

    // With the pool full, another source's message is gated as well: that face adds to what the
    // router holds.
    forward_frame(&rig.fwd, OTHER_SOURCE, vec![filler(99)]);
    assert_eq!(rig.fwd.egress_gated_faces(), 2);

    rig.link.set_full(false);
    second.set_full(false);
    assert!(
        rig.fwd.read_gate(SOURCE).is_none(),
        "released once the pool is given back"
    );
    assert!(rig.fwd.read_gate(OTHER_SOURCE).is_none());
    assert_eq!(rig.fwd.egress_held(), 0);
    assert_eq!(rig.fwd.egress_held_bytes(), 0);
    assert_eq!(rig.fwd.egress_gated_faces(), 0);
}

/// The credit stage is what many faces' tasks reach at once (`docs/router-task-per-face.md`,
/// phase 3), and the handle the capacity report reads it through is read from another thread: both
/// are `Send + Sync`. The proof is the compile.
#[test]
fn the_credit_stage_and_its_view_can_be_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<super::egress::Credit>();
    shared::<EgressView>();
    shared::<crate::sync::PlainMutex<super::egress::EgressQueue>>();
}

/// The face whose frame is being routed belongs to the call that routes it and to the thread that
/// runs it: another thread that routes another face at the same moment sees its own, a credit stage
/// that is not the one being routed for sees none, and a routing that ends gives back what was being
/// routed before it.
#[test]
fn the_face_being_routed_is_the_threads_own_for_this_credit_stage_and_is_put_back() {
    let credit = Arc::new(super::egress::Credit::default());
    let other_credit = super::egress::Credit::default();
    assert_eq!(credit.source(), None);
    let outer = credit.routing_from(FaceId(1));
    assert_eq!(credit.source(), Some(FaceId(1)));
    assert_eq!(
        other_credit.source(),
        None,
        "a credit stage that is not the one routed for has no face being routed"
    );
    {
        let _inner = credit.routing_from(FaceId(2));
        assert_eq!(credit.source(), Some(FaceId(2)));
    }
    assert_eq!(
        credit.source(),
        Some(FaceId(1)),
        "the routing that ended gave back the one it interrupted"
    );

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let there = {
        let (credit, barrier) = (Arc::clone(&credit), Arc::clone(&barrier));
        std::thread::spawn(move || {
            assert_eq!(credit.source(), None, "another thread routes nothing yet");
            let _mine = credit.routing_from(FaceId(9));
            barrier.wait();
            assert_eq!(credit.source(), Some(FaceId(9)));
            barrier.wait();
        })
    };
    barrier.wait();
    assert_eq!(
        credit.source(),
        Some(FaceId(1)),
        "the face another thread is routing is not this thread's"
    );
    barrier.wait();
    there.join().expect("the routing thread ends");
    drop(outer);
    assert_eq!(credit.source(), None);
}
