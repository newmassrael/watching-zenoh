// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the AP stream links, counted by the allocator:
//! under `runtime-zero-copy` an outbound frame lives in a slot of the link's
//! generated transmit pool from the moment the session is lent it until the
//! writer task has written it, so the transmit path asks the allocator for
//! NOTHING per frame.
//!
//! Before the pool the writer queue's item was an owned vector, and the lend drew
//! that vector from a spare list of at most four buffers of at most 16 KiB. That
//! is allocation-free in a steady state of small frames and nowhere else. The
//! three measurements here are the three places it was not:
//!
//! - a STEADY STATE of small frames, which the spare list already covered and the
//!   pool must not regress;
//! - a BURST past the four spare buffers, frames lent and sent while the writer
//!   cannot run, which allocated one vector per frame past the fourth;
//! - frames PAST 16 KiB, which the spare list never kept, so each allocated.
//!
//! and the byte door (`send_blocking`, which every frame that is not lent goes
//! through) for the same three shapes, which built a fresh framed vector for every
//! frame whatever its size.
//!
//! The counter is per thread, and the whole transmit path runs on the test's
//! thread: the runtime is current-thread and the writer task is spawned on it, so
//! the allocations of the sender AND of the writer are both counted, and the
//! parallel tests of this binary cannot move each other's numbers.
//!
//! The writer writes into a sink that keeps every byte in memory reserved before
//! the measurement starts, so the sink itself allocates nothing and the bytes are
//! there to be compared with the heap path's. Host-test level: no board runs it.
#![cfg(all(feature = "transport-link-tcp", feature = "runtime-zero-copy"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use wz_codecs::stream_envelope::StreamEnvelope;
use wz_runtime_tokio::stream_link::{stream_outbound_channel, writer_task, StreamWriteDriver};
use wz_runtime_tokio::writer_queue::WriterHandle;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, LinkSubject};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::tx_buf::TxBuf;
use wz_session_core::tx_lease::TxLease;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
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

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// What the writer wrote, in a buffer reserved up front so that recording it is
/// not an allocation.
#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

/// Room for everything one test writes; a test that writes more fails its
/// own capacity assertion instead of being counted as an allocation.
const SINK_CAPACITY: usize = 4 << 20;

impl Sink {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(SINK_CAPACITY))))
    }

    fn len(&self) -> usize {
        self.0.lock().expect("sink").len()
    }

    fn take(&self) -> Vec<u8> {
        let mut bytes = self.0.lock().expect("sink");
        let out = bytes.clone();
        bytes.clear();
        out
    }
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bytes = self.0.lock().expect("sink");
        assert!(
            bytes.len() + buf.len() <= SINK_CAPACITY,
            "the sink was sized for this test; growing it would be counted"
        );
        bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A stream link's write half over the production queue constructor, with its
/// writer task on THIS thread, so the writer's allocations are counted too.
struct Link {
    driver: StreamWriteDriver,
    sink: Sink,
    _writer: WriterHandle,
}

fn link() -> Link {
    let (tx, rx) = stream_outbound_channel();
    let driver = StreamWriteDriver::new(
        tx,
        Arc::new(AtomicBool::new(false)),
        LinkSubject::UNKNOWN,
        None,
    );
    let sink = Sink::new();
    let writer_sink = sink.clone();
    let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, move |queue| {
        writer_task(writer_sink, queue)
    });
    Link {
        driver,
        sink,
        _writer: writer,
    }
}

/// Lend a slot, encode `payload` into it the way the session does, send it.
fn send_lent(driver: &StreamWriteDriver, payload: &[u8]) {
    let mut lease =
        TxLease::acquire(driver, payload.len(), Priority::DEFAULT).expect("the link lends");
    lease
        .append(payload)
        .expect("the lent slot holds the frame");
    assert_eq!(
        lease.send(Reliability::Reliable, Priority::DEFAULT),
        LinkSendOutcome::Sent
    );
}

/// Send `payload` through the byte door.
fn send_bytes(driver: &StreamWriteDriver, payload: &[u8]) {
    assert_eq!(
        driver.send_blocking(payload, Reliability::Reliable),
        LinkSendOutcome::Sent
    );
}

/// Let the writer task run until the sink holds `bytes` bytes.
async fn written(sink: &Sink, bytes: usize) {
    for _ in 0..10_000 {
        if sink.len() >= bytes {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the writer wrote {} of {bytes} bytes", sink.len());
}

/// The u16 envelope of `payload`, by the codec's own encoder.
fn envelope(payload: &[u8]) -> Vec<u8> {
    StreamEnvelope {
        payload_len: payload.len() as u16,
        payload,
    }
    .encode_to_vec()
}

/// One round: `frames` frames of `payload` through `send`, and the writer let
/// run until every one of them is in the sink.
async fn round(
    link: &Link,
    send: fn(&StreamWriteDriver, &[u8]),
    payload: &[u8],
    frames: usize,
    burst: bool,
) {
    let wire = 2 + payload.len();
    let start = link.sink.len();
    for i in 0..frames {
        send(&link.driver, payload);
        if !burst {
            written(&link.sink, start + (i + 1) * wire).await;
        }
    }
    written(&link.sink, start + frames * wire).await;
}

/// The three shapes, sent `rounds` times each through `send`, with the writer
/// allowed to drain between frames (`burst == false`) or only after all of them
/// (`burst == true`). Returns the allocations of the measured rounds, after one
/// unmeasured round that lets every lazily built structure exist.
async fn measure(
    send: fn(&StreamWriteDriver, &[u8]),
    payload: &[u8],
    frames: usize,
    burst: bool,
) -> usize {
    let link = link();
    let wire = 2 + payload.len();
    round(&link, send, payload, frames, burst).await;
    let before = allocations();
    round(&link, send, payload, frames, burst).await;
    let count = allocations() - before;
    // The bytes the measured round wrote are the frames, each the codec's own
    // envelope of the payload: the pooled path changes where the bytes are, not
    // what they are.
    let bytes = link.sink.take();
    let expected = envelope(payload);
    assert_eq!(bytes.len(), 2 * frames * wire);
    for frame in bytes.chunks(wire) {
        assert_eq!(frame, &expected[..]);
    }
    count
}

static SMALL: [u8; 64] = [0x5A; 64];
static LARGE: [u8; 20 * 1024] = [0xC3; 20 * 1024];

#[tokio::test(flavor = "current_thread")]
async fn a_steady_state_of_small_lent_frames_allocates_nothing() {
    assert_eq!(measure(send_lent, &SMALL, 32, false).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_burst_of_lent_frames_past_four_buffers_allocates_nothing() {
    assert_eq!(measure(send_lent, &SMALL, 12, true).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn lent_frames_past_sixteen_kibibytes_allocate_nothing() {
    assert_eq!(measure(send_lent, &LARGE, 4, false).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_burst_of_lent_frames_past_sixteen_kibibytes_allocates_nothing() {
    assert_eq!(measure(send_lent, &LARGE, 3, true).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_steady_state_through_the_byte_door_allocates_nothing() {
    assert_eq!(measure(send_bytes, &SMALL, 32, false).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_burst_through_the_byte_door_allocates_nothing() {
    assert_eq!(measure(send_bytes, &SMALL, 12, true).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn frames_past_sixteen_kibibytes_through_the_byte_door_allocate_nothing() {
    assert_eq!(measure(send_bytes, &LARGE, 4, false).await, 0);
}

/// Frames per second through a write half and its writer task over a real
/// loopback TCP connection, the heap queue against the pooled one, for small
/// and large frames, lent and through the byte door. A MEASUREMENT, printed and
/// not asserted (wall-clock rates are the host's, not the code's): run with
/// `--ignored --nocapture` to read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a throughput measurement to read, not a verdict"]
async fn throughput_of_the_heap_and_the_pooled_queue() {
    use tokio::io::AsyncReadExt;
    use wz_runtime_tokio::writer_queue::{outbound_channel, OutboundRx, OutboundTx};

    async fn run(
        channel: fn() -> (OutboundTx, OutboundRx),
        send: fn(&StreamWriteDriver, &[u8]),
        payload: &[u8],
        frames: usize,
    ) -> f64 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Through the production constructors, so the sockets are tuned as a
        // wz link's are.
        let dialed = wz_runtime_tokio::link_pipeline::dial_tcp(
            addr,
            &wz_runtime_tokio::link_socket::LinkSocket::NONE,
        )
        .await
        .expect("dial");
        let (mut accepted, _) = wz_runtime_tokio::link_pipeline::accept_tcp_on(&listener)
            .await
            .expect("accept");
        let (_read, write) = dialed.into_split();
        let (tx, rx) = channel();
        let driver = StreamWriteDriver::new(
            tx,
            Arc::new(AtomicBool::new(false)),
            LinkSubject::UNKNOWN,
            None,
        );
        let writer = WriterHandle::spawn(rx, move |queue| writer_task(write, queue));
        let total = frames * (2 + payload.len());
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 1 << 16];
            let mut got = 0;
            while got < total {
                let n = accepted.read(&mut buf).await.expect("read");
                assert!(n > 0, "the peer read to the end");
                got += n;
            }
        });
        let started = std::time::Instant::now();
        for _ in 0..frames {
            send(&driver, payload);
        }
        reader.await.expect("reader");
        let rate = frames as f64 / started.elapsed().as_secs_f64();
        drop(driver);
        writer.drain().await;
        rate
    }

    for (name, payload, frames) in [
        ("64 B", &SMALL[..], 200_000),
        ("20 KiB", &LARGE[..], 20_000),
    ] {
        for (door, send) in [
            ("lend", send_lent as fn(&StreamWriteDriver, &[u8])),
            ("byte door", send_bytes),
        ] {
            let heap = run(outbound_channel, send, payload, frames).await;
            let pooled = run(stream_outbound_channel, send, payload, frames).await;
            println!(
                "{name} frames, {door}: heap queue {heap:.0} frames/s, pooled queue {pooled:.0} frames/s ({:.2}x)",
                pooled / heap
            );
        }
    }
}
