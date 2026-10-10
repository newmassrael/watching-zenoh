// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.2 on the AP DATAGRAM receive, counted by the
//! allocator: under `runtime-zero-copy` a UDP datagram is received INTO a slot of
//! the node's receive pool and handed to the session as that slot, on the three
//! read paths a UDP link has:
//!
//! - the DIAL read half (`wire_udp_socket`), which reads its own socket;
//! - the ACCEPT face (`bind_udp_demux` + `wire_udp_demuxed`), whose datagrams the
//!   listener's demux pump reads and routes to the face;
//! - the `UdpDriver` read, which is what a multicast group link and the scouting
//!   socket receive through (`UdpDriver::bind_multicast_link` returns one; the
//!   test builds it over a unicast socket, which runs the same `poll_event`).
//!
//! Each path is driven over a real loopback socket, in a steady state (one
//! datagram sent, read and dropped at a time), in a burst (a run of datagrams
//! queued in the kernel before the first is read) and with the frames HELD
//! until the whole run is read (the slots stay out while the session keeps
//! them). NOTHING is allocated per datagram. And what the session sees is what
//! the copying path sees: every frame is byte-identical to the datagram a plain
//! `recv_from` into a buffer of its own reads, and carries the sender's address.
//!
//! The counter is process-wide, because the demux pump runs on the acceptor
//! runtime's own threads, and the tests of this binary are serialised by a lock
//! so they cannot move each other's numbers. Host-test level.
#![cfg(all(feature = "runtime-zero-copy", feature = "transport-link-udp"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{SocketAddr, UdpSocket as PeerSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::link_rx_datagram::{DatagramRxPool, RxClassId};
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::udp_pipeline::{
    bind_udp_demux, dial_udp, wire_udp_demuxed, wire_udp_socket, UdpDemux, UdpWriteDriver,
};
use wz_runtime_tokio::writer_queue::WriterHandle;
use wz_runtime_tokio::{LinkDriver, LinkEvent, RxFrame, UdpDriver};

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

/// One measurement at a time in this binary, held across each test's setup too:
/// another test building its link while this one measures would be counted here.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn allocations() -> usize {
    ALLOCATIONS.load(Ordering::SeqCst)
}

/// The read half of one UDP link, whichever path built it, and what keeps the
/// rest of that link alive while it reads.
enum Reader {
    Dial {
        read: wz_runtime_tokio::udp_pipeline::UdpReadDriver,
        _write: Arc<UdpWriteDriver>,
        _writer: WriterHandle,
    },
    Accept {
        read: wz_runtime_tokio::udp_pipeline::UdpReadDriver,
        _write: Arc<UdpWriteDriver>,
        _writer: WriterHandle,
        _listener: UdpDemux,
    },
    Group(UdpDriver),
}

impl Reader {
    async fn frame(&mut self) -> RxFrame {
        let event = tokio::time::timeout(Duration::from_secs(5), async {
            match self {
                Reader::Dial { read, .. } | Reader::Accept { read, .. } => read.poll_event().await,
                Reader::Group(driver) => driver.poll_event().await,
            }
        })
        .await
        .expect("the datagram arrives");
        match event {
            LinkEvent::Rx(frame) => frame,
            other => panic!("a datagram is an Rx, got {other:?}"),
        }
    }
}

/// One UDP link under test: the peer that sends to it, the address it sends
/// to, and the read half.
struct Link {
    peer: PeerSocket,
    target: SocketAddr,
    reader: Reader,
}

#[derive(Clone, Copy)]
enum Path {
    Dial,
    Accept,
    Group,
}

async fn link(path: Path) -> Link {
    let peer = PeerSocket::bind("127.0.0.1:0").expect("peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    match path {
        Path::Dial => {
            let socket = dial_udp(peer_addr, &LinkSocket::NONE).await.expect("dial");
            let target = socket.local_addr().expect("dial addr");
            let (read, write, writer) = wire_udp_socket(socket, peer_addr);
            Link {
                peer,
                target,
                reader: Reader::Dial {
                    read,
                    _write: write,
                    _writer: writer,
                },
            }
        }
        Path::Accept => {
            let mut listener = bind_udp_demux("127.0.0.1:0".parse().unwrap(), &LinkSocket::NONE)
                .await
                .expect("listen");
            let target = listener.local_addr();
            // The first datagram from a new source opens the face; it is read
            // here, before any measurement, with the rest of the setup.
            peer.send_to(b"hello", target).expect("first datagram");
            let face = tokio::time::timeout(Duration::from_secs(5), listener.recv_new_face())
                .await
                .expect("the face opens")
                .expect("the pump is alive");
            assert_eq!(face.peer, peer_addr);
            let inputs = listener.wire_inputs(face.inbound_rx);
            let (read, write, writer) = wire_udp_demuxed(inputs, face.peer);
            let mut reader = Reader::Accept {
                read,
                _write: write,
                _writer: writer,
                _listener: listener,
            };
            assert_eq!(&reader.frame().await.bytes[..], b"hello");
            Link {
                peer,
                target,
                reader,
            }
        }
        Path::Group => {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let target = socket.local_addr().expect("addr");
            Link {
                peer,
                target,
                reader: Reader::Group(UdpDriver::from_socket(socket, peer_addr)),
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// One datagram sent, read and dropped at a time.
    Steady,
    /// The whole run queued in the kernel before the first is read; each frame
    /// is dropped once read.
    Burst,
    /// The whole run queued, and every frame kept until the last is read.
    Held,
}

async fn round(
    link: &mut Link,
    payload: &[u8],
    frames: usize,
    mode: Mode,
    held: &mut Vec<RxFrame>,
) {
    match mode {
        Mode::Steady => {
            for _ in 0..frames {
                link.peer.send_to(payload, link.target).expect("send");
                let frame = link.reader.frame().await;
                assert_eq!(&frame.bytes[..], payload);
            }
        }
        Mode::Burst | Mode::Held => {
            for _ in 0..frames {
                link.peer.send_to(payload, link.target).expect("send");
            }
            for _ in 0..frames {
                let frame = link.reader.frame().await;
                assert_eq!(&frame.bytes[..], payload);
                if matches!(mode, Mode::Held) {
                    held.push(frame);
                }
            }
            held.clear();
        }
    }
}

/// Allocations over one measured run, after an unmeasured run of the same shape
/// (the link's first datagrams settle what is built once per link: the channel
/// blocks, the pool tables, the runtime's own state).
async fn measure(path: Path, payload: &[u8], frames: usize, mode: Mode) -> usize {
    let _one = SERIAL.lock().await;
    let mut link = link(path).await;
    let mut held = Vec::with_capacity(frames);
    round(&mut link, payload, frames, mode, &mut held).await;
    let before = allocations();
    round(&mut link, payload, frames, mode, &mut held).await;
    allocations() - before
}

static SMALL: [u8; 64] = [0x5A; 64];
static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

macro_rules! zero_allocation_tests {
    ($($name:ident: $path:expr, $payload:expr, $frames:expr, $mode:expr;)*) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let count = measure($path, &$payload, $frames, $mode).await;
            assert_eq!(count, 0, "allocations over {} received datagrams", $frames);
        }
    )*};
}

zero_allocation_tests! {
    a_steady_state_of_dialed_datagrams_allocates_nothing: Path::Dial, SMALL, 32, Mode::Steady;
    a_burst_of_dialed_datagrams_allocates_nothing: Path::Dial, SMALL, 48, Mode::Burst;
    dialed_datagrams_held_by_the_session_allocate_nothing: Path::Dial, SMALL, 48, Mode::Held;
    dialed_datagrams_past_the_small_class_allocate_nothing: Path::Dial, LARGE, 8, Mode::Steady;
    a_steady_state_of_accepted_datagrams_allocates_nothing: Path::Accept, SMALL, 32, Mode::Steady;
    a_burst_of_accepted_datagrams_allocates_nothing: Path::Accept, SMALL, 48, Mode::Burst;
    accepted_datagrams_held_by_the_session_allocate_nothing: Path::Accept, SMALL, 48, Mode::Held;
    accepted_datagrams_past_the_small_class_allocate_nothing: Path::Accept, LARGE, 8, Mode::Steady;
    a_steady_state_of_group_datagrams_allocates_nothing: Path::Group, SMALL, 32, Mode::Steady;
    a_burst_of_group_datagrams_allocates_nothing: Path::Group, SMALL, 48, Mode::Burst;
    group_datagrams_held_by_the_session_allocate_nothing: Path::Group, SMALL, 48, Mode::Held;
    group_datagrams_past_the_small_class_allocate_nothing: Path::Group, LARGE, 8, Mode::Steady;
}

/// What the session sees is what the copying path sees.
///
/// Every datagram is sent twice, to the link under test and to a plain socket
/// that reads it with `recv_from` into a buffer of its own, which is exactly the
/// copy the pooled read replaces. The frame must be those bytes and carry the
/// sender's address, across the class boundary (1471 is the largest datagram the
/// small class takes, 1472 the smallest the large one does), the empty datagram,
/// and the largest a UDP/IPv4 datagram can be.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_path_delivers_what_the_copying_path_reads() {
    let _one = SERIAL.lock().await;
    let twin = PeerSocket::bind("127.0.0.1:0").expect("twin");
    twin.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let twin_addr = twin.local_addr().expect("twin addr");
    let mut copied = vec![0u8; 65536];
    for path in [Path::Dial, Path::Accept, Path::Group] {
        let mut link = link(path).await;
        let sender = link.peer.local_addr().expect("peer addr");
        for len in [0usize, 1, 63, 1450, 1471, 1472, 1473, 9000, 20_000, 65_507] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            link.peer
                .send_to(&payload, twin_addr)
                .expect("send to the twin");
            link.peer
                .send_to(&payload, link.target)
                .expect("send to the link");
            let (n, from) = twin.recv_from(&mut copied).expect("the twin reads it");
            assert_eq!(from, sender);
            let frame = link.reader.frame().await;
            assert_eq!(
                &frame.bytes[..],
                &copied[..n],
                "the frame of {len} bytes is what the copying path read"
            );
            assert_eq!(frame.src, Some(sender), "and it names its sender");
            if len > 0 {
                let (class, _) = DatagramRxPool::node()
                    .slot_of(frame.bytes.as_ptr())
                    .expect("the frame's bytes ARE a slot of the node's pool, by its own answer");
                let small = len < wz_runtime_tokio::session_rx_pool_ap_small::SLOT_SIZE;
                assert_eq!(
                    class,
                    if small {
                        RxClassId::Small
                    } else {
                        RxClassId::Large
                    },
                    "a datagram of {len} bytes takes the smallest class whose slot exceeds it"
                );
            }
        }
    }
    // Every frame is gone, so every slot the run took is home, by the emits'
    // own freelists, and each class's counters balance: what was armed was
    // completed or abandoned, and what was completed was returned.
    let pool = DatagramRxPool::node();
    for class in [RxClassId::Small, RxClassId::Large] {
        let s = pool.stats(class);
        assert_eq!(pool.live(class), 0, "{class:?}");
        assert_eq!(pool.free_slots(class), pool.capacity(class), "{class:?}");
        assert_eq!(s.armed, s.completed + s.abandoned, "{class:?}: {s:?}");
        assert_eq!(s.completed, s.returned, "{class:?}: {s:?}");
        assert_eq!((s.faults, s.stray_releases), (0, 0), "{class:?}: {s:?}");
    }
    assert_eq!((pool.refused(), pool.truncated()), (0, 0));
}
