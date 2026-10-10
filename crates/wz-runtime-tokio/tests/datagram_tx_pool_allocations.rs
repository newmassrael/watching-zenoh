// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   every slot the link may take allocates nothing either (R3250). The UDP
//!   burst reaches that depth only when the writer happens to lag; this reaches
//!   it every time.
//! - QUIC datagram, at the library seam: quinn's `send_datagram` takes
//!   `bytes::Bytes`, and the slot becomes the `Bytes`' owner with no copy of its
//!   bytes. `Bytes::from_owner` boxes its owner, so each datagram costs exactly
//!   ONE allocation there, which is counted here and stated at the seam.
//! - Websocket, at the library seam: tungstenite 0.24's `Message::Binary` owns a
//!   `Vec<u8>`, so a lent message is copied into one there (one allocation and
//!   one copy), and the byte door hands its vector straight in (one
//!   allocation); exactly one per message either way, counted here.
//!
//! R3250 — the count is ATTRIBUTED to the measurement's own threads, not
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
        feature = "transport-link-quic-datagram"
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

/// R3250 — a lane holding the link's whole slot budget allocates nothing. The
/// lane is an entry per slot, and before R3250 it grew the first time it held
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

    use wz_runtime_tokio::udp_pipeline::{dial_udp, udp_writer_task, UdpWriteDriver};
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
        let writer = WriterHandle::spawn_on(rt.handle().clone(), rx, move |queue| {
            udp_writer_task(socket, addr, queue)
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

/// The seam of the two libraries that take ownership of the buffer they send.
#[cfg(any(
    feature = "transport-link-ws",
    feature = "transport-link-quic-datagram"
))]
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

    /// tungstenite 0.24 takes a `Vec<u8>`: a lent message is copied into one at
    /// the seam (one allocation per message, counted), and its slot goes home.
    #[cfg(feature = "transport-link-ws")]
    #[test]
    fn a_pooled_ws_message_costs_one_allocation_at_the_library_seam() {
        let measurement = Measurement::new();
        let (tx, mut rx) = outbound_channel_datagram();
        let payload = [0x33u8; 300];
        for _ in 0..12 {
            lend_one(&tx, &payload);
        }
        let mut messages = Vec::with_capacity(12);
        let count = measurement.count(|| {
            for _ in 0..12 {
                messages.push(take(&mut rx).into_vec());
            }
        });
        assert_eq!(
            count, 12,
            "the seam's one copy per message, and nothing else"
        );
        for message in &messages {
            assert_eq!(&message[..], &payload[..]);
        }
        assert_eq!(
            tx.tx_pool_stats().expect("pooled").1,
            tx.tx_pool_capacity().expect("pooled"),
            "every slot came home once copied"
        );
    }

    /// The byte door keeps its vector on a pooled websocket queue: the one
    /// allocation per message is the vector the library takes, and it moves to
    /// the seam with no second copy.
    #[cfg(feature = "transport-link-ws")]
    #[test]
    fn the_ws_byte_door_costs_one_allocation_and_moves_it_to_the_seam() {
        use wz_runtime_tokio::ws_pipeline::WsWriteDriver;
        use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, LinkSubject};
        use wz_session_core::reliability::Reliability;
        let measurement = Measurement::new();
        let (tx, mut rx) = outbound_channel_datagram();
        let driver = WsWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        let payload = [0x44u8; 300];
        // One unmeasured message first, so whatever a first use builds exists.
        assert_eq!(
            driver.send_blocking(&payload, Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        drop(take(&mut rx));
        let mut messages = Vec::with_capacity(12);
        let count = measurement.count(|| {
            for _ in 0..12 {
                assert_eq!(
                    driver.send_blocking(&payload, Reliability::Reliable),
                    LinkSendOutcome::Sent
                );
                messages.push(take(&mut rx).into_vec());
            }
        });
        assert_eq!(
            count, 12,
            "one vector per message, handed to the seam as it is"
        );
        for message in &messages {
            assert_eq!(&message[..], &payload[..]);
        }
    }
}
