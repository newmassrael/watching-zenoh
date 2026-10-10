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
//! - QUIC datagram, at the library seam: quinn's `send_datagram` takes
//!   `bytes::Bytes`, and the slot becomes the `Bytes`' owner with no copy of its
//!   bytes. `Bytes::from_owner` boxes its owner, so each datagram costs exactly
//!   ONE allocation there, which is counted here and stated at the seam.
//! - Websocket, at the library seam: tungstenite 0.24's `Message::Binary` owns a
//!   `Vec<u8>`, so a lent message is copied into one there (one allocation and
//!   one copy), and the byte door hands its vector straight in (one
//!   allocation); exactly one per message either way, counted here.
//!
//! The counter is process-wide, because the writer task runs on the transmit
//! runtime's own threads, and the tests of this binary are serialised by a lock
//! so they cannot move each other's numbers. Host-test level.
#![cfg(all(
    feature = "runtime-zero-copy",
    any(
        feature = "transport-link-udp",
        feature = "transport-link-ws",
        feature = "transport-link-quic-datagram"
    )
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to `System` unchanged; the only addition is an
// atomic counter bump, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
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

/// One measurement at a time in this binary.
/// An async lock, because the UDP measurements hold it across their setup's
/// awaits; the synchronous tests take it with `blocking_lock`.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn allocations() -> usize {
    ALLOCATIONS.load(Ordering::SeqCst)
}

#[cfg(feature = "transport-link-udp")]
mod udp {
    use super::*;
    use std::net::UdpSocket as PeerSocket;
    use std::sync::Arc;
    use std::time::Duration;

    use wz_runtime_tokio::udp_pipeline::{dial_udp, wire_udp_socket, UdpWriteDriver};
    use wz_runtime_tokio::writer_queue::WriterHandle;
    use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, TxQueueShape};
    use wz_session_core::qos::Priority;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::tx_buf::TxBuf;
    use wz_session_core::tx_lease::TxLease;

    struct Link {
        driver: Arc<UdpWriteDriver>,
        peer: PeerSocket,
        _writer: WriterHandle,
    }

    /// A UDP link over the production wiring, shaped as an established session
    /// without QoS shapes it (one lane of 2 x 1450 bytes), so its slot budget is
    /// 3 small and 2 large: a burst of twelve is far past it.
    async fn link() -> Link {
        let peer = PeerSocket::bind("127.0.0.1:0").expect("peer");
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let socket = dial_udp(
            peer.local_addr().expect("addr"),
            &wz_runtime_tokio::link_socket::LinkSocket::NONE,
        )
        .await
        .expect("dial");
        let addr = peer.local_addr().expect("addr");
        let (_read, driver, writer) = wire_udp_socket(socket, addr);
        driver.shape_tx_queue(TxQueueShape {
            sizes: [2; Priority::NUM],
            qos: false,
            batch_bytes: 1450,
        });
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

    async fn measure(
        send: fn(&UdpWriteDriver, &[u8]),
        payload: &[u8],
        frames: usize,
        burst: bool,
    ) -> usize {
        // Held across the setup too: another test building its link while this
        // one measures would be counted here.
        let _one = SERIAL.lock().await;
        let link = link().await;
        let mut buf = vec![0u8; 65536];
        round(&link, send, payload, frames, burst, &mut buf);
        let before = allocations();
        round(&link, send, payload, frames, burst, &mut buf);
        allocations() - before
    }

    static SMALL: [u8; 64] = [0x5A; 64];
    static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_steady_state_of_lent_datagrams_allocates_nothing() {
        assert_eq!(measure(send_lent, &SMALL, 32, false).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_of_lent_datagrams_past_the_slot_budget_allocates_nothing() {
        assert_eq!(measure(send_lent, &SMALL, 12, true).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lent_datagrams_past_the_small_class_allocate_nothing() {
        assert_eq!(measure(send_lent, &LARGE, 4, false).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_steady_state_through_the_byte_door_allocates_nothing() {
        assert_eq!(measure(send_bytes, &SMALL, 32, false).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_through_the_byte_door_past_the_budget_allocates_nothing() {
        assert_eq!(measure(send_bytes, &SMALL, 12, true).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn datagrams_past_the_small_class_through_the_byte_door_allocate_nothing() {
        assert_eq!(measure(send_bytes, &LARGE, 4, false).await, 0);
    }
}

/// The seam of the two libraries that take ownership of the buffer they send.
#[cfg(any(
    feature = "transport-link-ws",
    feature = "transport-link-quic-datagram"
))]
mod seam {
    use super::*;
    use wz_runtime_tokio::writer_queue::{outbound_channel_datagram, OutboundRx, OutboundTx};
    use wz_session_core::qos::Priority;

    const P: Priority = Priority::DEFAULT;

    /// Queue one datagram of `payload` through a lend, as a write half does.
    fn lend_one(tx: &OutboundTx, payload: &[u8]) {
        let lend = tx.lend(P, payload.len()).expect("lent");
        // SAFETY: the lend is this test's, and `payload.len()` <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), lend.base(), payload.len()) };
        tx.commit(lend, payload.len()).expect("queued");
    }

    fn take(rx: &mut OutboundRx) -> wz_runtime_tokio::writer_queue::WireFrame {
        rx.try_recv_wire_tagged().expect("queued").1
    }

    /// quinn takes `Bytes`: the slot becomes the `Bytes`' owner, the `Bytes`
    /// reads the slot in place (same address, no copy), and the one allocation
    /// is `from_owner`'s box; the slot goes home when quinn would drop it.
    #[cfg(feature = "transport-link-quic-datagram")]
    #[test]
    fn a_pooled_datagram_becomes_bytes_without_a_copy_and_one_allocation() {
        let _one = SERIAL.blocking_lock();
        let (tx, mut rx) = outbound_channel_datagram();
        for (frames, payload) in [(1usize, &[0x11u8; 64][..]), (4, &[0x22u8; 9000][..])] {
            let mut addresses = Vec::with_capacity(frames);
            let mut held = Vec::with_capacity(frames);
            for _ in 0..frames {
                lend_one(&tx, payload);
            }
            let before = allocations();
            for _ in 0..frames {
                let wire = take(&mut rx);
                let at = wire.as_ptr() as usize;
                let bytes = wire.into_bytes();
                addresses.push((at, bytes.as_ptr() as usize));
                held.push(bytes);
            }
            let count = allocations() - before;
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
        let _one = SERIAL.blocking_lock();
        let (tx, mut rx) = outbound_channel_datagram();
        let payload = [0x33u8; 300];
        for _ in 0..12 {
            lend_one(&tx, &payload);
        }
        let mut messages = Vec::with_capacity(12);
        let before = allocations();
        for _ in 0..12 {
            messages.push(take(&mut rx).into_vec());
        }
        let count = allocations() - before;
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
        let _one = SERIAL.blocking_lock();
        let (tx, mut rx) = outbound_channel_datagram();
        let driver = WsWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        let payload = [0x44u8; 300];
        // One unmeasured message first: the lane's own queue grows on its first
        // entry, once, and that is the queue's and not a message's.
        assert_eq!(
            driver.send_blocking(&payload, Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        drop(take(&mut rx));
        let mut messages = Vec::with_capacity(12);
        let before = allocations();
        for _ in 0..12 {
            assert_eq!(
                driver.send_blocking(&payload, Reliability::Reliable),
                LinkSendOutcome::Sent
            );
            messages.push(take(&mut rx).into_vec());
        }
        let count = allocations() - before;
        assert_eq!(
            count, 12,
            "one vector per message, handed to the seam as it is"
        );
        for message in &messages {
            assert_eq!(&message[..], &payload[..]);
        }
    }
}
