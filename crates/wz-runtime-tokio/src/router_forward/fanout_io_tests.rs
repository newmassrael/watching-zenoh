// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where a router's fan-out is written: by each destination's own writer, in batches, and never
//! on the thread that routes it (`docs/router-fanout-cost.md`, row 1).
//!
//! Each face is a session over the production stream driver and its queue, wired as a TCP face
//! is (`crate::link_pipeline::wire_tcp_stream_with_lowlatency`), with the two ways the queue puts
//! bytes on the link replaced by recorders: the sender's own write ([`InlineWrite`]) and the
//! write half of the face's writer task.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;
use wz_runtime_core::runtime::Runtime;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::declare_build::build_declare_subscriber;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::link::LinkSubject;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::build_push_literal_with_meta;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::sample::QosLevel;

use super::{hold_face_link, RouterForwarder, WhatAmI, Zid};
use crate::accept_loop::{FaceForwarder, FaceId};
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session_glue::{new_session_actions, IterationEvent, SessionLinkActions};
use crate::stream_link::{stream_outbound_channel, writer_task, StreamWriteDriver};
use crate::writer_queue::{InlineWrite, OutboundRx, WriterHandle};

/// The payload of every put, counted in what reaches a link to tell how many puts did.
const MARK: &[u8] = b"fan-out-burst-put";

const PUBLISHER: FaceId = FaceId(1);

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// How many puts `bytes` carry.
fn puts_in(bytes: &[u8]) -> usize {
    bytes.windows(MARK.len()).filter(|w| *w == MARK).count()
}

/// The sender's own write on a face's link: what it was asked to write, from whichever thread.
#[derive(Default)]
struct SenderWrite {
    writes: AtomicUsize,
    bytes: Mutex<Vec<u8>>,
}

impl SenderWrite {
    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn puts(&self) -> usize {
        puts_in(&self.bytes.lock().expect("sender bytes"))
    }
}

impl InlineWrite for SenderWrite {
    fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.bytes
            .lock()
            .expect("sender bytes")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
}

/// Holds every write of the faces' writers until the test opens it, so that a writer cannot
/// take each message alone by keeping pace with the routing thread: how many writes a face
/// costs is then decided by what was staged for it, and not by the scheduler.
#[derive(Default)]
struct Gate {
    open: AtomicBool,
    waiting: Mutex<Vec<Waker>>,
}

impl Gate {
    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        for waker in self.waiting.lock().expect("gate").drain(..) {
            waker.wake();
        }
    }

    fn poll_open(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        self.waiting.lock().expect("gate").push(cx.waker().clone());
        // Read again once registered: an opening between the first read and the registration
        // drained the list before this waker was in it.
        if self.open.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// What a face's writer wrote: the thread of each write, and the bytes.
#[derive(Default)]
struct Wire {
    threads: Mutex<Vec<ThreadId>>,
    bytes: Mutex<Vec<u8>>,
}

impl Wire {
    fn threads(&self) -> Vec<ThreadId> {
        self.threads.lock().expect("wire threads").clone()
    }

    fn puts(&self) -> usize {
        puts_in(&self.bytes.lock().expect("wire bytes"))
    }
}

/// The write half a face's writer task writes to, behind the gate.
struct WriteHalf {
    gate: Arc<Gate>,
    wire: Arc<Wire>,
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.poll_open(cx).is_pending() {
            return Poll::Pending;
        }
        self.wire
            .threads
            .lock()
            .expect("wire threads")
            .push(std::thread::current().id());
        self.wire
            .bytes
            .lock()
            .expect("wire bytes")
            .extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A session of a client `peer` over a stream driver and its queue, whose sender's own write
/// is `sender`, and the reading end of the queue.
fn face_over(sender: &Arc<SenderWrite>, peer: Zid) -> (Arc<SessionLinkActions>, OutboundRx) {
    let (tx, rx) = stream_outbound_channel();
    tx.set_inline_write(sender.clone());
    let driver = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(AtomicBool::new(false)),
        LinkSubject::UNKNOWN,
        None,
    ));
    let actions = new_session_actions(driver, fixture_session_init_params(), TokioTime::new());
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(wz_session_core::session_init_params::zid_bytes(
            peer.as_slice(),
        ))
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    (actions, rx)
}

/// The writer task of a face over `rx`, on `rt`, writing behind `gate`; what it writes is
/// recorded in the wire returned. The handle keeps the queue open while it is held.
fn writer_of(
    rt: &tokio::runtime::Runtime,
    rx: OutboundRx,
    gate: &Arc<Gate>,
) -> (Arc<Wire>, WriterHandle) {
    let wire = Arc::new(Wire::default());
    let half = WriteHalf {
        gate: Arc::clone(gate),
        wire: Arc::clone(&wire),
    };
    let writer = WriterHandle::spawn_on(rt.handle().clone(), rx, move |queue| {
        writer_task(half, queue)
    });
    (wire, writer)
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

/// A put that may not be dropped, as the throughput publisher of the router cells sends.
fn blocking_put() -> NetworkMessage {
    let meta = PushMetadata {
        qos: Some(QosLevel::DEFAULT.with_congestion(CongestionControl::Block)),
        ..PushMetadata::default()
    };
    NetworkMessage::Push(Box::new(
        build_push_literal_with_meta("demo/x", MARK, &meta).expect("build push"),
    ))
}

/// Sixteen client faces subscribed and one publishing, and a burst of puts routed on this
/// thread. The routing thread writes to none of the faces: every put reaches each subscriber's
/// link through that face's writer, on the runtime's threads, and a subscriber is written far
/// fewer times than it is sent puts, because its writer takes what was staged for it at once.
///
/// The gate holds the writers until the burst is routed. The routing thread is then the first
/// to reach every quiet link, so a router that let a sender write its own message wrote there,
/// and a writer cannot take the puts one by one by keeping pace with it.
#[test]
fn a_router_fan_out_is_written_by_the_faces_writers_and_not_by_the_routing_thread() {
    const SUBSCRIBERS: usize = 16;
    const BURST: usize = 64;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let routing_thread = std::thread::current().id();
    let gate = Arc::new(Gate::default());
    let sender = Arc::new(SenderWrite::default());
    let fwd = RouterForwarder::new(zid(0x01));

    // Every session and writer stays alive to the end: a writer's handle dropped seals its queue.
    let mut held = Vec::new();
    let (publisher, rx) = face_over(&sender, zid(0xAA));
    let (_, writer) = writer_of(&rt, rx, &gate);
    fwd.register(PUBLISHER, &publisher);
    held.push((publisher, writer));

    let mut wires = Vec::new();
    for i in 0..SUBSCRIBERS {
        let (actions, rx) = face_over(&sender, zid(0xB0 + i as u8));
        let (wire, writer) = writer_of(&rt, rx, &gate);
        let face = FaceId(100 + i as u64);
        fwd.register(face, &actions);
        forward_frame(
            &fwd,
            face,
            vec![NetworkMessage::Declare(Box::new(
                build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
            ))],
        );
        wires.push(wire);
        held.push((actions, writer));
    }

    for _ in 0..BURST {
        forward_frame(&fwd, PUBLISHER, vec![blocking_put()]);
    }
    gate.open();

    let deadline = Instant::now() + Duration::from_secs(30);
    for (i, wire) in wires.iter().enumerate() {
        while wire.puts() < BURST {
            assert!(
                Instant::now() < deadline,
                "subscriber {i} was written {} of the {BURST} puts",
                wire.puts()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    assert_eq!(
        sender.writes(),
        0,
        "the routing thread wrote to a face's link itself"
    );
    for (i, wire) in wires.iter().enumerate() {
        let threads = wire.threads();
        assert_eq!(
            wire.puts(),
            BURST,
            "subscriber {i} was written each put once"
        );
        assert!(
            threads.iter().all(|thread| *thread != routing_thread),
            "subscriber {i} was written on the routing thread"
        );
        assert!(
            threads.len() * 8 <= BURST,
            "subscriber {i} took {} writes for {BURST} puts: its writer did not batch them",
            threads.len()
        );
    }
    drop(held);
}

/// The rule the fan-out rests on, by the role of the node: a router takes the sender's own
/// write from each face it holds, and a peer or a client node leaves it, so that a lone put on
/// a quiet link, which is what that write is for, is written by the thread that sends it.
#[test]
fn only_a_router_takes_the_senders_own_write_from_the_faces_it_holds() {
    for (role, mode, written_by_sender) in [
        ("router", WhatAmI::Router, false),
        ("peer", WhatAmI::Peer, true),
        ("client", WhatAmI::Client, true),
    ] {
        let sender = Arc::new(SenderWrite::default());
        let (actions, mut rx) = face_over(&sender, zid(0xB0));
        hold_face_link(mode, &actions);

        actions
            .send_push_literal("demo/x", MARK, true)
            .expect("push");

        if written_by_sender {
            assert_eq!(sender.writes(), 1, "{role}: the sender wrote its put");
            assert_eq!(sender.puts(), 1, "{role}: the write carried the put");
            assert!(rx.try_recv().is_none(), "{role}: nothing is left");
        } else {
            assert_eq!(sender.writes(), 0, "{role}: the sender wrote nothing");
            assert!(
                rx.try_recv().is_none(),
                "{role}: the put waits for the writer's flush"
            );
            let _ = actions.flush_staged();
            let frame = rx
                .try_recv()
                .expect("the writer's flush hands the put over");
            assert_eq!(puts_in(&frame), 1, "{role}: the frame carries the put");
        }
    }
}
