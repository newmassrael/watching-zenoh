// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! R3260 — the count is ATTRIBUTED to the measurement's own threads, as R3247
//! made it for the transmit suite: the test thread, every thread of a runtime
//! built for the measurement, and the worker of the process-wide ACCEPTOR
//! runtime, on which `bind_udp_demux` spawns the demux pump. That worker belongs
//! to no test, so a measurement ADOPTS it (a task run on it takes the
//! measurement's tally) while holding [`SERIAL`], which every test of this
//! binary holds for its whole body, runtime start included: one test at a time
//! owns the acceptor's worker and touches the node's pool. libtest starts,
//! reports and fails the tests on threads of its own, and a test waiting for
//! [`SERIAL`] has started its thread outside any window; none of those threads
//! works for a measurement, so none can move a number. Measured before this
//! harness, when the count was process-wide and a lock serialised only the
//! windows: 35 of 40 runs on two cores with four test threads failed, with
//! counts from 1 to 1343. The two controls at the end pin both halves of the
//! attribution. Host-test level.
#![cfg(all(feature = "runtime-zero-copy", feature = "transport-link-udp"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket as PeerSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use wz_runtime_tokio::link_rx_datagram::{DatagramRxPool, RxClassId};
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::runtime_pool::WzRuntime;
use wz_runtime_tokio::udp_pipeline::{
    bind_udp_demux, dial_udp, wire_udp_demuxed, wire_udp_socket, UdpDemux, UdpWriteDriver,
};
use wz_runtime_tokio::writer_queue::WriterHandle;
use wz_runtime_tokio::{LinkDriver, LinkEvent, RxFrame, UdpDriver};

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

/// One test at a time in this binary, for its whole body. Two things here are
/// process-wide and a test must have them to itself: the acceptor's worker,
/// which a measurement adopts, and the node's receive pool, whose counters the
/// copying-path test balances.
static SERIAL: Mutex<()> = Mutex::new(());

/// Take [`SERIAL`]. A test that failed while holding it poisons it; the next
/// test still runs, so one red does not cascade into every test after it.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A measurement owned by the test thread that made it, with a tally of its
/// own.
struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The
    /// tally is leaked, a few bytes per test, because a thread of the
    /// measurement (a runtime worker, the acceptor's worker) may outlive it and
    /// still reads it.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// A multi-thread runtime every thread of which (its workers, and any
    /// blocking thread it starts) works for this measurement. Two workers, the
    /// shape the suite ran on before the count was attributed.
    fn runtime(&self) -> tokio::runtime::Runtime {
        let tally = self.tally;
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || OWNER.with(|owner| owner.set(Some(tally))))
            .build()
            .expect("the measurement's runtime")
    }

    /// The acceptor's worker works for this measurement from here on: a task
    /// run on it takes the tally. Only a worker polls a runtime's tasks, so
    /// with one worker that thread is where the demux pump runs; a partition
    /// configured with more (`WZ_RUNTIME`) would leave a worker unowned, so the
    /// measurement refuses rather than counting partly blind. The adoption
    /// outlives the measurement, harmlessly: a closed window counts nothing,
    /// and the next test adopts the worker again before it measures.
    async fn adopt_the_acceptor(&self) {
        let handle = WzRuntime::Acceptor.handle();
        assert_eq!(
            handle.metrics().num_workers(),
            1,
            "the demux pump's runtime must have the one worker this measurement adopts"
        );
        let tally = self.tally;
        handle
            .spawn(async move { OWNER.with(|owner| owner.set(Some(tally))) })
            .await
            .expect("the acceptor's worker takes the tally");
    }

    /// The allocations this measurement's threads make while `f` runs.
    async fn count(&self, f: impl Future<Output = ()>) -> usize {
        let before = self.tally.allocations.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        f.await;
        self.tally.open.store(false, Ordering::SeqCst);
        self.tally.allocations.load(Ordering::SeqCst) - before
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
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
/// (the link's first datagrams settle what is built once per link: the pool
/// tables, the runtime's own state). Everything, the runtime included, is built
/// and torn down while this test holds [`SERIAL`].
fn measure(path: Path, payload: &'static [u8], frames: usize, mode: Mode) -> usize {
    let _one = serial();
    let measurement = Measurement::new();
    let rt = measurement.runtime();
    rt.block_on(async {
        measurement.adopt_the_acceptor().await;
        let mut link = link(path).await;
        let mut held = Vec::with_capacity(frames);
        round(&mut link, payload, frames, mode, &mut held).await;
        measurement
            .count(round(&mut link, payload, frames, mode, &mut held))
            .await
    })
}

static SMALL: [u8; 64] = [0x5A; 64];
static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

macro_rules! zero_allocation_tests {
    ($($name:ident: $path:expr, $payload:expr, $frames:expr, $mode:expr;)*) => {$(
        #[test]
        fn $name() {
            let count = measure($path, &$payload, $frames, $mode);
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
#[test]
fn every_path_delivers_what_the_copying_path_reads() {
    let _one = serial();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
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
                    let (class, _) = DatagramRxPool::node().slot_of(frame.bytes.as_ptr()).expect(
                        "the frame's bytes ARE a slot of the node's pool, by its own answer",
                    );
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
    });
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

/// CONTROL for the adoption: an allocation the acceptor's worker makes inside
/// the window is counted, exactly once. Without it every accept-path zero above
/// could be the pump going uncounted. The task is spawned and its channels made
/// before the window opens, so the one allocation in the window is the task's.
#[test]
fn the_window_counts_an_allocation_on_the_acceptors_worker() {
    let _one = serial();
    let measurement = Measurement::new();
    let rt = measurement.runtime();
    let count = rt.block_on(async {
        measurement.adopt_the_acceptor().await;
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let task = WzRuntime::Acceptor.handle().spawn(async move {
            go_rx.await.expect("go");
            drop(std::hint::black_box(Box::new([0u8; 64])));
            done_tx.send(()).expect("done");
        });
        let count = measurement
            .count(async move {
                go_tx.send(()).expect("go");
                done_rx.await.expect("done");
            })
            .await;
        task.await.expect("the task ran");
        count
    });
    assert_eq!(
        count, 1,
        "the acceptor's worker allocated once inside the window"
    );
}

/// CONTROL for the exclusion: an allocation by a thread that works for no
/// measurement (a sibling test, libtest's own threads) is not counted, even
/// inside the window. The thread is started and parked before the window opens.
#[test]
fn the_window_does_not_count_a_thread_that_is_not_the_measurements() {
    let _one = serial();
    let measurement = Measurement::new();
    let go = Arc::new(Barrier::new(2));
    let done = Arc::new(Barrier::new(2));
    let stranger = {
        let (go, done) = (go.clone(), done.clone());
        std::thread::spawn(move || {
            go.wait();
            drop(std::hint::black_box(Box::new([0u8; 64])));
            done.wait();
        })
    };
    let rt = measurement.runtime();
    let count = rt.block_on(measurement.count(async {
        go.wait();
        done.wait();
    }));
    stranger.join().expect("the stranger ran");
    assert_eq!(
        count, 0,
        "a thread outside the measurement allocated, uncounted"
    );
}
