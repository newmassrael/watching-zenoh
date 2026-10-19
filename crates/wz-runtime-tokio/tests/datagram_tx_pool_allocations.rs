// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the AP DATAGRAM links, counted by the allocator:
//! under `runtime-zero-copy` a datagram lives in a slot of its link's transmit
//! pool (one slot per datagram, the smallest of two size classes that holds it)
//! from the lend to the end of the send.
//!
//! - UDP, end to end over a real loopback socket with the production writer
//!   task: a steady state, a burst past the link's slot budget (the sender WAITS
//!   for the writer to free a slot rather than allocating), and datagrams past
//!   the small class (they take the large one), through the lend and through the
//!   byte door; each datagram the peer reads is the payload, byte for byte, as
//!   the heap path sends it. NOTHING is allocated.
//! - The queue alone, filled to the link's whole slot budget: a lane holding
//!   every slot the link may take allocates nothing either (R3247). The UDP
//!   burst reaches that depth only when the writer happens to lag; this reaches
//!   it every time.
//! - QUIC datagram, at the library seam: quinn's `send_datagram` takes
//!   `bytes::Bytes`, and the slot becomes the `Bytes`' owner with no copy of its
//!   bytes. `Bytes::from_owner` boxes its owner, so each datagram costs exactly
//!   ONE allocation there, which is counted here and stated at the seam.
//! - Websocket: tungstenite 0.29 takes `Message::Binary(Bytes)`, but it formats
//!   whatever it sends into a write buffer of its own, a copy of the payload, so
//!   the link frames each message itself (R3264). It writes the RFC 6455 header
//!   in front of the message where it lies in the slot (and masks it there, on a
//!   client) and the writer writes the slot as it is: a steady state, a burst
//!   and messages past the small class allocate NOTHING, and every frame
//!   decodes through tungstenite's own reader.
//! - Multicast, through the group's pipeline as a producer pushes onto it: the
//!   push encodes each datagram straight into a slot the lanes lend (the small
//!   class first, the large one for a frame past it), so a steady state, a burst
//!   up to the group's slot budget (past it a push finds no room and is dropped,
//!   as a multicast push is) and datagrams past the small class allocate
//!   NOTHING between the item and the wire, and the datagrams are byte for byte
//!   the heap queue's. Measured beside it and left as they are: the item itself
//!   (its boxed Push, built before the push), and a frame past the group's batch,
//!   which is fragmented from the heap as on the unicast send.
//!
//! R3247 — the count is ATTRIBUTED to the measurement's own threads, not
//! process-wide: a [`Measurement`] counts what its test thread allocates and
//! what the threads of the runtime its writer task runs on allocate (a runtime
//! built for it, each of whose threads takes the measurement's tally as it
//! starts), and only while its window is open. The tests of this binary run in
//! parallel threads of one process, and libtest starts, reports and fails them
//! on threads of its own; none of those is a measurement's, so none can move a
//! number. Measured before this harness, when the count was process-wide and a
//! lock serialised only the windows: a sibling test's runtime starting its
//! workers inside a window read as one allocation, and a failed sibling's
//! backtrace, printed after it released the lock, as thousands. Host-test
//! level.
#![cfg(all(
    feature = "runtime-zero-copy",
    any(
        feature = "transport-link-udp",
        feature = "transport-link-ws",
        feature = "transport-link-quic-datagram",
        feature = "transport-multicast"
    )
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use wz_runtime_tokio::writer_queue::{
    outbound_channel_datagram, OutboundRx, OutboundTx, WireFrame,
};
use wz_session_core::link::TxQueueShape;
use wz_session_core::qos::Priority;

/// Counts the allocations of the measurement the allocating thread works for.
struct CountingAllocator;

/// One measurement's count: whether its window is open, and what its threads
/// allocated while it was.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
}

thread_local! {
    /// The measurement this thread works for, if any.
    static OWNER: Cell<Option<&'static Tally>> = const { Cell::new(None) };
}

/// One allocation, counted against the allocating thread's measurement when
/// that measurement's window is open.
fn count_one() {
    if let Some(tally) = OWNER.with(Cell::get) {
        if tally.open.load(Ordering::SeqCst) {
            tally.allocations.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// read of a thread-local without a destructor and an atomic bump, neither of
// which allocates or unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// A measurement owned by the test thread that made it, with a tally of its
/// own.
struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The
    /// tally is leaked, a few bytes per test, because a runtime thread of the
    /// measurement may outlive it and still reads it.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// A multi-thread runtime every thread of which (its worker, and any
    /// blocking thread it starts) works for this measurement.
    #[cfg(feature = "transport-link-udp")]
    fn runtime(&self) -> tokio::runtime::Runtime {
        let tally = self.tally;
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .on_thread_start(move || OWNER.with(|owner| owner.set(Some(tally))))
            .build()
            .expect("the measurement's runtime")
    }

    /// The allocations this measurement's threads make while `f` runs.
    fn count(&self, f: impl FnOnce()) -> usize {
        let before = self.tally.allocations.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        f();
        self.tally.open.store(false, Ordering::SeqCst);
        self.tally.allocations.load(Ordering::SeqCst) - before
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
}

const P: Priority = Priority::DEFAULT;

/// The shape an established UDP session without QoS gives its queue: one lane
/// of 2 x 1450 bytes, so a slot budget of 3 small and 2 large.
fn udp_shape() -> TxQueueShape {
    TxQueueShape {
        sizes: [2; Priority::NUM],
        qos: false,
        batch_bytes: 1450,
    }
}

/// Queue one datagram of `payload` through a lend, as a write half does.
fn lend_one(tx: &OutboundTx, payload: &[u8]) {
    let lend = tx.lend(P, payload.len()).expect("lent");
    // SAFETY: the lend is this test's, and `payload.len()` <= its capacity.
    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), lend.base(), payload.len()) };
    tx.commit(lend, payload.len()).expect("queued");
}

fn take(rx: &mut OutboundRx) -> WireFrame {
    rx.try_recv_wire_tagged().expect("queued").1
}

/// R3247 — a lane holding the link's whole slot budget allocates nothing. The
/// lane is an entry per slot, and before R3247 it grew the first time it held
/// more entries than it ever had, which on a UDP link is whenever a burst
/// meets a writer lagging further than it had before: measured as one
/// allocation in the UDP burst below, about one run in three on two loaded
/// cores. Here the writer does not take until the lane holds every slot.
#[test]
fn a_lane_filled_to_its_slot_budget_allocates_nothing() {
    let measurement = Measurement::new();
    let (tx, mut rx) = outbound_channel_datagram();
    tx.reshape(udp_shape());
    // One datagram through first, so whatever a first use builds exists.
    lend_one(&tx, &[0x55; 64]);
    drop(take(&mut rx));
    let budget = 5;
    let count = measurement.count(|| {
        for _ in 0..budget {
            lend_one(&tx, &[0x66; 64]);
        }
    });
    assert_eq!(count, 0, "the lane had room for every slot");
    for _ in 0..budget {
        assert_eq!(take(&mut rx), [0x66u8; 64]);
    }
}

#[cfg(feature = "transport-link-udp")]
mod udp {
    use super::*;
    use std::net::UdpSocket as PeerSocket;
    use std::sync::Arc;
    use std::time::Duration;

    use wz_runtime_tokio::udp_pipeline::{
        dial_udp, udp_writer_task, DatagramWriteFault, UdpWriteDriver,
    };
    use wz_runtime_tokio::writer_queue::{datagram_outbound_channel, WriterHandle};
    use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, LinkSubject};
    use wz_session_core::reliability::Reliability;
    use wz_session_core::tx_buf::TxBuf;
    use wz_session_core::tx_lease::TxLease;

    struct Link {
        driver: UdpWriteDriver,
        peer: PeerSocket,
        _writer: WriterHandle,
    }

    /// A UDP link over the production parts (the datagram queue constructor,
    /// the write half and the writer task, as `wire_udp_socket` puts them
    /// together), with the writer on the measurement's runtime rather than the
    /// process-wide transmit one, so what the writer allocates is counted and
    /// nothing else is. Shaped as an established session without QoS, its slot
    /// budget is 3 small and 2 large: a burst of twelve is far past it.
    fn link(rt: &tokio::runtime::Runtime) -> Link {
        let peer = PeerSocket::bind("127.0.0.1:0").expect("peer");
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let addr = peer.local_addr().expect("addr");
        let socket = rt
            .block_on(dial_udp(
                addr,
                &wz_runtime_tokio::link_socket::LinkSocket::NONE,
            ))
            .expect("dial");
        let socket = Arc::new(socket);
        let (tx, rx) = datagram_outbound_channel();
        // Nothing here reads the link's read half, so the watch on the write
        // latch is dropped: a failed write would still trip it.
        let (fault, _watch) = DatagramWriteFault::channel();
        let writer = WriterHandle::spawn_on(rt.handle().clone(), rx, move |queue| {
            udp_writer_task(socket, addr, queue, fault)
        });
        let driver = UdpWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        driver.shape_tx_queue(udp_shape());
        Link {
            driver,
            peer,
            _writer: writer,
        }
    }

    fn send_lent(driver: &UdpWriteDriver, payload: &[u8]) {
        let mut lease =
            TxLease::acquire(driver, payload.len(), Priority::DEFAULT).expect("the link lends");
        lease.append(payload).expect("the slot holds it");
        assert_eq!(
            lease.send(Reliability::BestEffort, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );
    }

    fn send_bytes(driver: &UdpWriteDriver, payload: &[u8]) {
        assert_eq!(
            driver.send_blocking(payload, Reliability::BestEffort),
            LinkSendOutcome::Sent
        );
    }

    /// Read one datagram into `buf` and check it is `payload`.
    fn receive(peer: &PeerSocket, buf: &mut [u8], payload: &[u8]) {
        let n = peer.recv(buf).expect("the datagram arrives");
        assert_eq!(
            &buf[..n],
            payload,
            "the wire is the payload, as the heap path sends it"
        );
    }

    fn round(
        link: &Link,
        send: fn(&UdpWriteDriver, &[u8]),
        payload: &[u8],
        frames: usize,
        burst: bool,
        buf: &mut [u8],
    ) {
        for _ in 0..frames {
            send(&link.driver, payload);
            if !burst {
                receive(&link.peer, buf, payload);
            }
        }
        if burst {
            for _ in 0..frames {
                receive(&link.peer, buf, payload);
            }
        }
    }

    /// The sender is this test's thread, outside any runtime, so a sender past
    /// the slot budget blocks on the queue until the writer, on the
    /// measurement's runtime, frees a slot.
    fn measure(
        send: fn(&UdpWriteDriver, &[u8]),
        payload: &[u8],
        frames: usize,
        burst: bool,
    ) -> usize {
        let measurement = Measurement::new();
        let rt = measurement.runtime();
        let link = link(&rt);
        let mut buf = vec![0u8; 65536];
        round(&link, send, payload, frames, burst, &mut buf);
        measurement.count(|| round(&link, send, payload, frames, burst, &mut buf))
    }

    static SMALL: [u8; 64] = [0x5A; 64];
    static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

    #[test]
    fn a_steady_state_of_lent_datagrams_allocates_nothing() {
        assert_eq!(measure(send_lent, &SMALL, 32, false), 0);
    }

    #[test]
    fn a_burst_of_lent_datagrams_past_the_slot_budget_allocates_nothing() {
        assert_eq!(measure(send_lent, &SMALL, 12, true), 0);
    }

    #[test]
    fn lent_datagrams_past_the_small_class_allocate_nothing() {
        assert_eq!(measure(send_lent, &LARGE, 4, false), 0);
    }

    #[test]
    fn a_steady_state_through_the_byte_door_allocates_nothing() {
        assert_eq!(measure(send_bytes, &SMALL, 32, false), 0);
    }

    #[test]
    fn a_burst_through_the_byte_door_past_the_budget_allocates_nothing() {
        assert_eq!(measure(send_bytes, &SMALL, 12, true), 0);
    }

    #[test]
    fn datagrams_past_the_small_class_through_the_byte_door_allocate_nothing() {
        assert_eq!(measure(send_bytes, &LARGE, 4, false), 0);
    }
}

/// The seam of the library that takes ownership of the buffer it sends (quinn).
#[cfg(feature = "transport-link-quic-datagram")]
mod seam {
    use super::*;

    /// quinn takes `Bytes`: the slot becomes the `Bytes`' owner, the `Bytes`
    /// reads the slot in place (same address, no copy), and the one allocation
    /// is `from_owner`'s box; the slot goes home when quinn would drop it.
    #[cfg(feature = "transport-link-quic-datagram")]
    #[test]
    fn a_pooled_datagram_becomes_bytes_without_a_copy_and_one_allocation() {
        let measurement = Measurement::new();
        let (tx, mut rx) = outbound_channel_datagram();
        for (frames, payload) in [(1usize, &[0x11u8; 64][..]), (4, &[0x22u8; 9000][..])] {
            let mut addresses = Vec::with_capacity(frames);
            let mut held = Vec::with_capacity(frames);
            for _ in 0..frames {
                lend_one(&tx, payload);
            }
            let count = measurement.count(|| {
                for _ in 0..frames {
                    let wire = take(&mut rx);
                    let at = wire.as_ptr() as usize;
                    let bytes = wire.into_bytes();
                    addresses.push((at, bytes.as_ptr() as usize));
                    held.push(bytes);
                }
            });
            assert_eq!(
                count, frames,
                "one owner box per datagram, and nothing else"
            );
            for (slot, bytes) in addresses {
                assert_eq!(slot, bytes, "the Bytes reads the slot in place");
            }
            for bytes in &held {
                assert_eq!(&bytes[..], payload);
            }
            let (_, free_held) = tx.tx_pool_stats().expect("pooled");
            drop(held);
            let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
            assert_eq!(
                free_now,
                free_held + frames,
                "the slots came home with the Bytes"
            );
            assert_eq!(stats.failed, 0, "completed as written");
        }
        assert_eq!(
            tx.tx_pool_stats().expect("pooled").1,
            tx.tx_pool_capacity().expect("pooled")
        );
    }
}

/// The websocket link's write half, which FRAMES each message itself (R3264):
/// tungstenite formats whatever it sends into a write buffer of its own, a copy
/// of the payload that the slot's own memory avoids, so the link writes the
/// RFC 6455 header in front of the message where it lies in the slot (and masks
/// it there, on a client) and the writer writes the slot as it is. The frames
/// are read back through tungstenite's own reader, so what is counted is also
/// what a peer decodes.
#[cfg(feature = "transport-link-ws")]
mod ws {
    use super::*;
    use std::io::Cursor;
    use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket};
    use tokio_tungstenite::tungstenite::Message;
    use wz_runtime_tokio::writer_queue::{
        outbound_channel, outbound_channel_datagram, OutboundRx, WireFrame,
    };
    use wz_runtime_tokio::ws_pipeline::{WsEnd, WsWriteDriver};
    use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, LinkSubject};
    use wz_session_core::qos::Priority;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::tx_buf::TxBuf;
    use wz_session_core::tx_lease::TxLease;

    const ENDS: [WsEnd; 2] = [WsEnd::Client, WsEnd::Server];

    fn pooled(end: WsEnd) -> (WsWriteDriver, OutboundRx) {
        let (tx, rx) = outbound_channel_datagram();
        (WsWriteDriver::new(tx, end, LinkSubject::UNKNOWN, None), rx)
    }

    /// The role of the peer that reads what `end` sends.
    fn reader_of(end: WsEnd) -> Role {
        match end {
            WsEnd::Client => Role::Server,
            WsEnd::Server => Role::Client,
        }
    }

    fn send_lent(driver: &WsWriteDriver, payload: &[u8]) {
        let mut lease =
            TxLease::acquire(driver, payload.len(), Priority::DEFAULT).expect("the link lends");
        lease.append(payload).expect("the slot holds it");
        assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );
    }

    fn send_bytes(driver: &WsWriteDriver, payload: &[u8]) {
        assert_eq!(
            driver.send_blocking(payload, Reliability::Reliable),
            LinkSendOutcome::Sent
        );
    }

    fn take(rx: &mut OutboundRx) -> WireFrame {
        rx.try_recv_wire_tagged().expect("queued").1
    }

    /// What a peer of role `reader` decodes from `frame`.
    fn decoded(frame: &[u8], reader: Role) -> Vec<u8> {
        let mut peer = WebSocket::from_raw_socket(Cursor::new(frame.to_vec()), reader, None);
        match peer.read().expect("a whole frame") {
            Message::Binary(bytes) => bytes.to_vec(),
            other => panic!("a binary message was sent, read {other:?}"),
        }
    }

    /// The frame's size on the wire: two header bytes, a 16-bit length from 126
    /// bytes, and a client's four key bytes.
    fn frame_size(end: WsEnd, len: usize) -> usize {
        let extended = if len >= 126 { 2 } else { 0 };
        let key = if end == WsEnd::Client { 4 } else { 0 };
        2 + extended + key + len
    }

    static SMALL: [u8; 64] = [0x5A; 64];
    static MEDIUM: [u8; 300] = [0x33; 300];
    static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

    /// The allocations of `frames` sends of `payload` and the reads the writer
    /// would make of each (started, then home), after one unmeasured round;
    /// with whether every frame lay in a slot and had the size it must have.
    fn measure(
        end: WsEnd,
        send: fn(&WsWriteDriver, &[u8]),
        payload: &[u8],
        frames: usize,
        burst: bool,
    ) -> (usize, bool) {
        let measurement = Measurement::new();
        let (driver, mut rx) = pooled(end);
        let mut shaped = true;
        let mut round = |rx: &mut OutboundRx| {
            let mut write_out = |rx: &mut OutboundRx| {
                let mut frame = take(rx);
                shaped &= frame.is_pooled() && frame.len() == frame_size(end, payload.len());
                frame.begin_write();
                rx.recycle_wire(frame);
            };
            for _ in 0..frames {
                send(&driver, payload);
                if !burst {
                    write_out(rx);
                }
            }
            if burst {
                for _ in 0..frames {
                    write_out(rx);
                }
            }
        };
        round(&mut rx);
        let count = measurement.count(|| round(&mut rx));
        (count, shaped)
    }

    #[test]
    fn a_steady_state_of_lent_ws_messages_allocates_nothing() {
        for end in ENDS {
            assert_eq!(
                measure(end, send_lent, &SMALL, 32, false),
                (0, true),
                "{end:?}"
            );
        }
    }

    /// A burst the pool's budget holds: the queue has three small slots here,
    /// and each message takes one until the writer has read it.
    #[test]
    fn a_burst_of_lent_ws_messages_allocates_nothing() {
        for end in ENDS {
            assert_eq!(
                measure(end, send_lent, &MEDIUM, 2, true),
                (0, true),
                "{end:?}"
            );
        }
    }

    #[test]
    fn lent_ws_messages_past_the_small_class_allocate_nothing() {
        for end in ENDS {
            assert_eq!(
                measure(end, send_lent, &LARGE, 4, false),
                (0, true),
                "{end:?}"
            );
        }
    }

    #[test]
    fn a_steady_state_through_the_ws_byte_door_allocates_nothing() {
        for end in ENDS {
            assert_eq!(
                measure(end, send_bytes, &MEDIUM, 32, false),
                (0, true),
                "{end:?}"
            );
            assert_eq!(
                measure(end, send_bytes, &LARGE, 4, false),
                (0, true),
                "{end:?}"
            );
        }
    }

    /// The heap queue's frames are made in a vector each: the figure the pool
    /// removes, and the same bytes.
    #[test]
    fn the_heap_queue_allocates_each_ws_frame() {
        let measurement = Measurement::new();
        let (tx, mut rx) = outbound_channel();
        let driver = WsWriteDriver::new(tx, WsEnd::Server, LinkSubject::UNKNOWN, None);
        send_bytes(&driver, &MEDIUM);
        drop(take(&mut rx));
        let count = measurement.count(|| {
            for _ in 0..12 {
                send_bytes(&driver, &MEDIUM);
                drop(take(&mut rx));
            }
        });
        assert_eq!(count, 12, "one vector per frame");
    }

    /// Every frame, from either door and either queue, decodes to the message
    /// through tungstenite's reader; a client's frames are masked and a
    /// server's are not (the reader's role refuses the other way round).
    #[test]
    fn every_ws_frame_decodes_to_its_message_through_tungstenite() {
        for end in ENDS {
            for payload in [&SMALL[..], &[7u8; 125][..], &[8u8; 126][..], &LARGE[..]] {
                let (driver, mut rx) = pooled(end);
                send_lent(&driver, payload);
                send_bytes(&driver, payload);
                let (tx, mut heap_rx) = outbound_channel();
                let heap = WsWriteDriver::new(tx, end, LinkSubject::UNKNOWN, None);
                send_bytes(&heap, payload);
                for (queue, frame) in [
                    ("lent", take(&mut rx)),
                    ("byte door", take(&mut rx)),
                    ("heap", take(&mut heap_rx)),
                ] {
                    let masked = frame[1] & 0x80 != 0;
                    assert_eq!(masked, end == WsEnd::Client, "{end:?} {queue}");
                    assert_eq!(frame[0], 0x82, "FIN and the binary opcode");
                    assert_eq!(
                        decoded(&frame, reader_of(end)),
                        payload,
                        "{end:?} {queue} {}",
                        payload.len()
                    );
                }
            }
        }
    }

    /// RFC 6455 section 5.3: each client frame carries a key of its own.
    #[test]
    fn a_client_masks_each_frame_with_a_fresh_key() {
        let (driver, mut rx) = pooled(WsEnd::Client);
        let mut keys = Vec::new();
        for _ in 0..8 {
            send_lent(&driver, &SMALL);
            let frame = take(&mut rx);
            keys.push(<[u8; 4]>::try_from(&frame[2..6]).expect("a short frame has its key at 2"));
        }
        keys.sort_unstable();
        keys.dedup();
        assert!(keys.len() > 1, "eight frames, one key");
    }

    /// The frame is made IN the slot the session wrote the message into: the
    /// bytes the writer reads start inside the lent slot, at the header, with
    /// the message where the session put it behind the headroom.
    #[test]
    fn the_frame_is_made_in_the_slot_the_message_was_encoded_into() {
        for end in ENDS {
            let (driver, mut rx) = pooled(end);
            let grant = driver
                .tx_slot_acquire(MEDIUM.len(), Priority::DEFAULT)
                .expect("the link lends");
            assert_eq!(grant.headroom, end.headroom());
            let (base, capacity) = driver.tx_slot_storage(grant.slot);
            assert!(capacity >= grant.headroom + MEDIUM.len());
            // SAFETY: the slot is lent to this test, `capacity` bytes from `base`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    MEDIUM.as_ptr(),
                    base.add(grant.headroom),
                    MEDIUM.len(),
                )
            };
            assert_eq!(
                driver.tx_slot_send(
                    grant.slot,
                    grant.headroom,
                    MEDIUM.len(),
                    Reliability::Reliable,
                    Priority::DEFAULT
                ),
                LinkSendOutcome::Sent
            );
            let frame = take(&mut rx);
            let header = frame_size(end, MEDIUM.len()) - MEDIUM.len();
            assert_eq!(
                frame.as_ptr() as usize + header,
                base as usize + grant.headroom,
                "{end:?}: the message was not moved"
            );
            assert_eq!(decoded(&frame, reader_of(end)), MEDIUM);
        }
    }

    /// The pool's own counts after a mixed run: each frame a lent slot (the
    /// byte door copies the message into its lend, not into a second buffer),
    /// started and completed by the writer, every slot home.
    #[test]
    fn every_ws_slot_comes_home_through_its_lifecycle() {
        let (driver, mut rx) = pooled(WsEnd::Client);
        for _ in 0..3 {
            send_lent(&driver, &MEDIUM);
        }
        send_bytes(&driver, &SMALL);
        for _ in 0..4 {
            let mut frame = take(&mut rx);
            frame.begin_write();
            rx.recycle_wire(frame);
        }
        let (stats, free, capacity) = rx.tx_pool_stats().expect("pooled");
        assert_eq!(stats.lent, 4, "the byte door lends its slot as well");
        assert_eq!(
            stats.copied, 0,
            "no frame is copied into a slot after the fact"
        );
        assert_eq!(
            (stats.armed, stats.started, stats.completed, stats.failed),
            (4, 4, 4, 0)
        );
        assert_eq!(free, capacity, "every slot is home");
    }

    /// A message past what one frame carries is refused and its slot goes home.
    #[test]
    fn an_oversize_ws_message_is_refused_and_its_slot_goes_home() {
        let (driver, rx) = pooled(WsEnd::Server);
        let huge = vec![0u8; 70_000];
        assert!(matches!(
            driver.send_blocking(&huge, Reliability::Reliable),
            LinkSendOutcome::Dropped(_)
        ));
        let (_, free, capacity) = rx.tx_pool_stats().expect("pooled");
        assert_eq!(free, capacity);
    }
}

/// A multicast group's pipeline, read through its tap as a transmit task would
/// write it: [`MulticastTxTap::attach_pooled`] over the lanes the drive loop's
/// pipeline is built over, [`MulticastTxTap::attach`] over the heap queue.
#[cfg(feature = "transport-multicast")]
mod multicast {
    use super::*;
    use wz_runtime_tokio::multicast_glue::{MulticastTxProducer, MulticastTxTap};
    use wz_runtime_tokio::writer_queue::WireFrame;
    use wz_session_core::multicast_params::MulticastParams;
    use wz_session_core::multicast_tx::{multicast_put_literal, MulticastTxItem};
    use wz_session_core::tx_deadline::PushOutcome;

    type Attach = fn(&MulticastParams) -> (MulticastTxProducer, MulticastTxTap);

    /// A non-QoS group with a 2048-byte batch: a frame of up to 1472 bytes
    /// takes the small class, one up to the batch the large one, and one past
    /// the batch is fragmented.
    fn params() -> MulticastParams {
        MulticastParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
            lease_ms: 5_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        }
    }

    fn items(payload: &[u8], frames: usize) -> Vec<MulticastTxItem> {
        (0..frames)
            .map(|_| multicast_put_literal("demo/mc", payload).expect("the Put builds"))
            .collect()
    }

    /// Push `items` and write out what reached the lanes: after each push
    /// (steady), or once all are pushed (burst). Answers how many were pushed.
    fn round(
        producer: &MulticastTxProducer,
        tap: &mut MulticastTxTap,
        items: Vec<MulticastTxItem>,
        burst: bool,
        out: &mut Vec<usize>,
    ) -> usize {
        let mut pushed = 0;
        for item in items {
            match producer.push(item).expect("linked") {
                PushOutcome::Pushed => pushed += 1,
                PushOutcome::Congested => {}
            }
            if !burst {
                drain(tap, out);
            }
        }
        drain(tap, out);
        pushed
    }

    /// Write out every datagram the lanes hold, noting each one's length.
    fn drain(tap: &mut MulticastTxTap, out: &mut Vec<usize>) {
        while let Some(datagram) = tap.try_next_wire() {
            out.push(datagram.len());
            tap.written(datagram);
        }
    }

    /// The allocations of one measured round of `frames` pushes of `payload`
    /// after one unmeasured round, the items built outside the count; with how
    /// many the measured round pushed and how many datagrams it wrote.
    fn measure(
        attach: Attach,
        payload: &[u8],
        frames: usize,
        burst: bool,
    ) -> (usize, usize, usize) {
        let measurement = Measurement::new();
        let (producer, mut tap) = attach(&params());
        let mut out = Vec::with_capacity(4 * frames + 16);
        round(&producer, &mut tap, items(payload, frames), burst, &mut out);
        out.clear();
        let built = items(payload, frames);
        let mut pushed = 0;
        let count = measurement.count(|| {
            pushed = round(&producer, &mut tap, built, burst, &mut out);
        });
        (count, pushed, out.len())
    }

    static SMALL: [u8; 64] = [0x5A; 64];
    static LARGE: [u8; 1_800] = [0xC3; 1_800];
    static PAST_BATCH: [u8; 5_000] = [0x96; 5_000];

    #[test]
    fn a_steady_state_of_pooled_multicast_pushes_allocates_nothing() {
        let (count, pushed, wrote) = measure(MulticastTxTap::attach_pooled, &SMALL, 32, false);
        assert_eq!((pushed, wrote), (32, 32));
        assert_eq!(count, 0, "the push encodes into a slot, the slot goes home");
    }

    /// A burst with nothing written meanwhile: every push up to the group's
    /// slot budget lands in a slot, and one past it finds no room and is
    /// dropped, as a multicast push is; neither allocates.
    #[test]
    fn a_burst_of_pooled_multicast_pushes_allocates_nothing() {
        let (count, pushed, wrote) = measure(MulticastTxTap::attach_pooled, &SMALL, 12, true);
        assert!(pushed > 0, "the budget holds some of the burst");
        assert_eq!(wrote, pushed, "each pushed datagram reached the wire");
        assert_eq!(count, 0, "neither a slot nor a refusal allocates");
    }

    #[test]
    fn pooled_multicast_datagrams_past_the_small_class_allocate_nothing() {
        let (count, pushed, wrote) = measure(MulticastTxTap::attach_pooled, &LARGE, 8, false);
        assert_eq!((pushed, wrote), (8, 8));
        assert_eq!(count, 0, "the frame takes a large slot, not a vector");
    }

    /// The heap queue the pipeline used before, measured the same way: each
    /// datagram is a vector of its own. The figure the pool removes.
    #[test]
    fn the_heap_queue_allocates_each_datagram() {
        let (count, pushed, wrote) = measure(MulticastTxTap::attach, &SMALL, 32, false);
        assert_eq!((pushed, wrote), (32, 32));
        assert_eq!(count, 32, "one vector per datagram");
    }

    /// The item a producer hands the push is built before it: its boxed Push
    /// and the Push's own buffers. A separate allocation from the datagram's,
    /// measured here so it is not mistaken for one.
    #[test]
    fn the_item_is_allocated_by_its_builder_before_the_push() {
        let measurement = Measurement::new();
        drop(items(&SMALL, 1));
        let mut held = Vec::with_capacity(8);
        let count = measurement.count(|| {
            for _ in 0..8 {
                held.push(multicast_put_literal("demo/mc", &SMALL).expect("the Put builds"));
            }
        });
        assert_eq!(count, 8 * ITEM_ALLOCATIONS);
    }

    /// The allocations one `multicast_put_literal` makes, as measured: the
    /// boxed Push, its key and its payload.
    const ITEM_ALLOCATIONS: usize = 3;

    /// A frame past the batch is fragmented from the heap, as on the unicast
    /// send: the residue this path keeps, counted so it cannot grow unseen.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn a_frame_past_the_batch_is_fragmented_from_the_heap() {
        let (count, pushed, wrote) = measure(MulticastTxTap::attach_pooled, &PAST_BATCH, 4, false);
        assert_eq!(pushed, 4);
        assert_eq!(
            wrote,
            4 * 3,
            "5000 bytes over a 2048-byte batch is three fragments"
        );
        assert_eq!(count, 4 * FRAGMENTED_ALLOCATIONS);
    }

    /// The allocations one fragmented push makes, as measured (5000 bytes over a
    /// 2048-byte batch: the whole frame, then the chain of three fragments).
    #[cfg(feature = "transport-fragmentation")]
    const FRAGMENTED_ALLOCATIONS: usize = 5;

    /// Every datagram written, read through the pool and through the heap
    /// queue from fresh groups, is the same bytes: one envelope encoder writes
    /// both, and the sequence numbers are minted alike.
    #[test]
    fn pooled_multicast_datagrams_are_the_heap_queues_bytes() {
        let mut payloads: Vec<&[u8]> = vec![&SMALL, &LARGE];
        if cfg!(feature = "transport-fragmentation") {
            payloads.push(&PAST_BATCH);
        }
        let read = |attach: Attach| {
            let (producer, mut tap) = attach(&params());
            let mut wire: Vec<Vec<u8>> = Vec::new();
            for payload in &payloads {
                for item in items(payload, 3) {
                    assert_eq!(producer.push(item), Ok(PushOutcome::Pushed));
                    while let Some(datagram) = tap.try_next_wire() {
                        wire.push(datagram.to_vec());
                        tap.written(datagram);
                    }
                }
            }
            wire
        };
        let pooled = read(MulticastTxTap::attach_pooled);
        let heap = read(MulticastTxTap::attach);
        assert!(pooled.len() >= 6);
        assert_eq!(pooled, heap);
    }

    /// The pool's own counts after a mixed run: every slot taken was lent a
    /// frame or given back unwritten (a frame tried in the small class first
    /// and found too large), every slot lent was armed, started and completed
    /// without a failure, and every slot is home.
    #[test]
    fn every_pooled_multicast_slot_comes_home_through_its_lifecycle() {
        let (producer, mut tap) = MulticastTxTap::attach_pooled(&params());
        let mut out = Vec::new();
        round(&producer, &mut tap, items(&SMALL, 5), false, &mut out);
        // Two large frames: the group's budget is two large slots, and a burst
        // past it waits for the writer (the next test).
        round(&producer, &mut tap, items(&LARGE, 2), true, &mut out);
        let (stats, free, capacity) = tap.tx_pool_stats().expect("pooled");
        assert_eq!(stats.lent, 7, "each datagram was encoded into its slot");
        assert_eq!(stats.copied, 0, "nothing came through the byte door");
        assert_eq!(
            stats.returned, 2,
            "each large frame first tried a small slot"
        );
        assert_eq!(stats.acquired, stats.lent + stats.returned);
        assert_eq!(
            (stats.armed, stats.started, stats.completed, stats.failed),
            (7, 7, 7, 0)
        );
        assert_eq!(stats.unarmed, 0);
        assert_eq!(free, capacity, "every slot is home");
    }

    /// A burst of frames only the large class holds, past that class's budget
    /// while the small class has slots to spare: the push that finds no large
    /// slot WAITS for the writer to free one and goes on when it does. It is
    /// the burst that spun a thread at full CPU forever when nothing wrote,
    /// because the wait ended as soon as ANY class had a slot.
    #[test]
    fn a_burst_past_the_large_budget_waits_for_the_writer() {
        use std::time::{Duration, Instant};
        let (producer, mut tap) = MulticastTxTap::attach_pooled(&params());
        let mut wrote = 0;
        let pushed = std::thread::scope(|scope| {
            let pushing = scope.spawn(|| {
                items(&LARGE, 3)
                    .into_iter()
                    .map(|item| producer.push(item))
                    .filter(|outcome| matches!(outcome, Ok(PushOutcome::Pushed)))
                    .count()
            });
            let deadline = Instant::now() + Duration::from_secs(30);
            while !pushing.is_finished()
                || tap.tx_pool_stats().is_some_and(|(_, free, cap)| free < cap)
            {
                assert!(Instant::now() < deadline, "the burst never got its slot");
                match tap.try_next_wire() {
                    Some(datagram) => {
                        wrote += 1;
                        tap.written(datagram);
                    }
                    None => std::thread::sleep(Duration::from_millis(1)),
                }
            }
            pushing.join().expect("the pushing thread ends")
        });
        assert_eq!(pushed, 3, "every push got a slot in the end");
        assert_eq!(wrote, 3, "and every datagram was written");
    }

    /// A datagram the holder drops instead of writing goes home too, counted
    /// as a write that never began.
    #[test]
    fn a_pooled_multicast_datagram_dropped_unwritten_comes_home() {
        let (producer, mut tap) = MulticastTxTap::attach_pooled(&params());
        for item in items(&SMALL, 2) {
            assert_eq!(producer.push(item), Ok(PushOutcome::Pushed));
        }
        let datagram: WireFrame = tap.try_next_wire().expect("queued");
        assert!(datagram.is_pooled(), "the datagram lies in a slot");
        drop(datagram);
        drop(tap.try_next_wire().expect("queued"));
        let (stats, free, capacity) = tap.tx_pool_stats().expect("pooled");
        assert_eq!((stats.lent, stats.started, stats.completed), (2, 0, 0));
        assert_eq!(stats.armed, stats.unarmed, "armed and returned unstarted");
        assert_eq!(free, capacity, "both slots are home");
    }
}
