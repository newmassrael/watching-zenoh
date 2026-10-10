// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the AP serial link, counted by the allocator:
//! under `runtime-zero-copy` the serial write half COBS-frames each payload
//! straight into a slot of the link's transmit pool, the writer writes the slot,
//! and the slot goes home through the pool's completion edge. The LINK adds no
//! allocation to a frame, in a steady state, in a burst, or at the serial MTU:
//! what remains is the generated COBS stuffer's own (see
//! `stuffer_allocations`), which these tests subtract exactly and pin.
//!
//! Before the pool the serial writer queue's item was an owned copy of the raw
//! payload, and the writer framed it through `encode_to_vec` into a vector and
//! copied the stuffed bytes into another, on top of the stuffer's own. Measured
//! on that shape with this harness: 256 allocations for 32 small frames, 96 for
//! a burst of 12, 48 for 4 frames at the MTU; the link's own share of those is
//! now zero.
//!
//! The counter is per thread and the whole path runs on the test's thread (a
//! current-thread runtime, with the writer spawned on it), so the writer's
//! allocations are counted with the sender's. The device is an in-memory sink
//! whose buffer is reserved before the measurement. Host-test level.
#![cfg(all(feature = "transport-link-serial", feature = "runtime-zero-copy"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use wz_runtime_tokio::serial_pipeline::{
    serial_outbound_channel, serial_writer_task, BoxedSerialStream, SerialByteStream,
    SerialWriteDriver,
};
use wz_runtime_tokio::writer_queue::WriterHandle;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, LinkSubject};
use wz_session_core::reliability::Reliability;
use wz_session_core::serial_link::{encode_frame, SERIAL_MTU};

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

/// Room for everything one test writes, reserved up front.
const SINK_CAPACITY: usize = 1 << 20;

/// A serial device that keeps what is written to it and never has anything to
/// read.
#[derive(Clone)]
struct Device(Arc<Mutex<Vec<u8>>>);

impl Device {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(SINK_CAPACITY))))
    }

    fn len(&self) -> usize {
        self.0.lock().expect("device").len()
    }

    fn take(&self) -> Vec<u8> {
        let mut bytes = self.0.lock().expect("device");
        let out = bytes.clone();
        bytes.clear();
        out
    }
}

impl AsyncRead for Device {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Device {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bytes = self.0.lock().expect("device");
        assert!(
            bytes.len() + buf.len() <= SINK_CAPACITY,
            "the device was sized for this test; growing it would be counted"
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

impl SerialByteStream for Device {
    fn take_received(&mut self) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct Link {
    driver: SerialWriteDriver,
    device: Device,
    _writer: WriterHandle,
}

fn link() -> Link {
    let device = Device::new();
    let stream: BoxedSerialStream = Box::new(device.clone());
    let (_read, write) = tokio::io::split(stream);
    let (tx, rx) = serial_outbound_channel();
    let driver = SerialWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
    let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, move |queue| {
        serial_writer_task(write, queue, None)
    });
    Link {
        driver,
        device,
        _writer: writer,
    }
}

async fn written(device: &Device, bytes: usize) {
    for _ in 0..10_000 {
        if device.len() >= bytes {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the writer wrote {} of {bytes} bytes", device.len());
}

async fn round(link: &Link, payload: &[u8], wire: usize, frames: usize, burst: bool) {
    let start = link.device.len();
    for i in 0..frames {
        assert_eq!(
            link.driver.send_blocking(payload, Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        if !burst {
            written(&link.device, start + (i + 1) * wire).await;
        }
    }
    written(&link.device, start + frames * wire).await;
}

/// What the GENERATED COBS stuffer itself asks the allocator for, framing one
/// `payload`: the pre-COBS frame built on the stack, then `cobs_encode` alone.
///
/// The stuffer is SCE's `sce:kind="algorithm"` emit of
/// `sources/codecs/cobs_encode.scxml`, whose bounded `bytes` output is the
/// build's default byte storage, a growable heap list on an allocating build,
/// grown push by push. That is the codec's, not the link's, and wz does not
/// re-implement the codec to avoid it; so these tests pin that the link adds
/// NOTHING to it: the measured total is exactly this, frame for frame.
fn stuffer_allocations(payload: &[u8]) -> usize {
    use sce_forge_runtime::codec::SliceSink;
    let env = wz_codecs::serial_envelope::SerialEnvelope {
        header: 0x00,
        payload_len: payload.len() as u16,
        payload,
        crc32: wz_codecs::crc32::crc32(payload),
    };
    let mut pre = [0u8; wz_session_core::serial_link::SERIAL_MFS];
    let mut sink = SliceSink::new(&mut pre);
    env.encode(&mut sink).expect("fits");
    let len = sink.position();
    let before = allocations();
    let stuffed = wz_codecs::cobs_encode::cobs_encode(&pre[..len]).expect("stuffs");
    let count = allocations() - before;
    drop(stuffed);
    count
}

/// Allocations of a measured round of `frames` frames of `payload`, after one
/// unmeasured round, LESS what the generated stuffer itself allocates for
/// them; and the bytes of both rounds are the codec's frames.
async fn measure(payload: &[u8], frames: usize, burst: bool) -> usize {
    let stuffer = frames * stuffer_allocations(payload);
    measure_total(payload, frames, burst).await - stuffer
}

/// Every allocation of a measured round.
async fn measure_total(payload: &[u8], frames: usize, burst: bool) -> usize {
    let expected = encode_frame(0x00, payload).expect("a serial frame");
    let link = link();
    round(&link, payload, expected.len(), frames, burst).await;
    let before = allocations();
    round(&link, payload, expected.len(), frames, burst).await;
    let count = allocations() - before;
    let bytes = link.device.take();
    assert_eq!(bytes.len(), 2 * frames * expected.len());
    for frame in bytes.chunks(expected.len()) {
        assert_eq!(frame, &expected[..], "the wire is the codec's frame");
    }
    count
}

static SMALL: [u8; 64] = [0x5A; 64];
static FULL: [u8; SERIAL_MTU] = [0x00; SERIAL_MTU];

#[tokio::test(flavor = "current_thread")]
async fn a_steady_state_of_serial_frames_adds_nothing_to_the_stuffer() {
    assert_eq!(measure(&SMALL, 32, false).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_burst_of_serial_frames_adds_nothing_to_the_stuffer() {
    assert_eq!(measure(&SMALL, 12, true).await, 0);
}

/// A payload of zeroes at the MTU is the COBS worst case: every byte stuffed.
#[tokio::test(flavor = "current_thread")]
async fn serial_frames_at_the_mtu_add_nothing_to_the_stuffer() {
    assert_eq!(measure(&FULL, 4, false).await, 0);
}

/// The residual, stated as a measurement so it cannot go stale silently: the
/// generated stuffer DOES allocate on this build. When the SCE emit gives a
/// bounded `bytes` variable fixed storage, this reds, and the three tests above
/// become "allocates nothing" outright.
#[test]
fn the_generated_stuffer_still_allocates_on_an_allocating_build() {
    assert!(stuffer_allocations(&SMALL) > 0);
}
