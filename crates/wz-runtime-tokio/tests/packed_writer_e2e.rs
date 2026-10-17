// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-qos",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! A stream writer that takes everything queued as ONE buffer must put the same
//! bytes on the wire as one write per frame: the receiving session reads the
//! same frames, in the same order within each priority, every payload intact.
//!
//! The writer's unit tests (`writer_queue`) show the buffer it builds; this is
//! the other end of the claim. Two wz sessions open over a loopback TCP link
//! with QoS negotiated, the initiator publishes a burst across three priorities
//! in sizes from one byte to a couple of kilobytes (so the queue holds several
//! frames whenever the writer is behind, which is when it packs), and the
//! acceptor's subscribers must see every message exactly once, uncorrupted, and
//! in publish order within its priority. A frame cut at the wrong place, a frame
//! dropped or doubled by the join, or a stream that lost its length prefix, would
//! fail the session or one of those counts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_qos, connect_and_open_session_with_qos, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::qos::Priority;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
/// Messages per priority; the burst is `LANES * PER_LANE`.
const PER_LANE: u32 = 1500;
const LANES: [(&str, Priority); 3] = [
    ("demo/pack/high", Priority::InteractiveHigh),
    ("demo/pack/data", Priority::Data),
    ("demo/pack/background", Priority::Background),
];

/// The length message `index` of a lane carries: from 1 byte up to a little under 2 KiB, spread
/// by a multiplicative hash so neighbours differ and no size repeats in a pattern the join could
/// hide behind.
fn length_of(index: u32) -> usize {
    4 + (index.wrapping_mul(2_654_435_761) >> 16) as usize % 2000
}

/// Message `index`: its number, then a fill that depends on the number.
fn payload_of(index: u32) -> Vec<u8> {
    let mut payload = vec![(index % 251) as u8; length_of(index)];
    payload[..4].copy_from_slice(&index.to_le_bytes());
    payload
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_burst_over_a_packing_stream_writer_arrives_whole_and_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_qos(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with qos offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        connect_and_open_session_with_qos(
            locator,
            fixture_params_with_zid(0x01),
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with qos offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);
    assert!(opened_init.actions.is_qos(), "initiator negotiated qos on");
    assert!(opened_acc.actions.is_qos(), "acceptor negotiated qos on");

    // What each lane's subscriber saw, in arrival order, and how many payloads were not the ones
    // sent. A violation is counted and read after the run: a panic in a callback would end the
    // drive task and leave the test reporting a stalled delivery instead of the corruption.
    let arrived: Arc<[Mutex<Vec<u32>>; 3]> = Arc::new([
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
        Mutex::new(Vec::new()),
    ]);
    let corrupt = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    for (lane, (keyexpr, _)) in LANES.iter().enumerate() {
        let (arrived, corrupt, total) = (arrived.clone(), corrupt.clone(), total.clone());
        observer.subscribers.register(*keyexpr, move |sample| {
            let bytes = sample.payload();
            let intact = bytes.len() >= 4 && {
                let index = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
                bytes == &payload_of(index)[..]
            };
            if intact {
                let index = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
                arrived[lane].lock().expect("arrival log").push(index);
            } else {
                corrupt.fetch_add(1, Ordering::SeqCst);
            }
            total.fetch_add(1, Ordering::SeqCst);
        });
    }

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let init_actions = opened_init.actions.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let expected_total = LANES.len() * PER_LANE as usize;
    let total_probe = total.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The burst goes out from a blocking thread, in one run with no pause between messages:
        // the writer is behind whenever the producer is faster, and that is when it packs.
        tokio::task::spawn_blocking(move || {
            for index in 0..PER_LANE {
                for (keyexpr, priority) in LANES {
                    init_actions
                        .send_push_literal_qos(keyexpr, &payload_of(index), true, priority)
                        .expect("a burst publish routes through the QoS send seam");
                }
            }
        })
        .await
        .expect("the publishing thread");
        for _ in 0..1000 {
            if total_probe.load(Ordering::SeqCst) >= expected_total {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "only {} of {expected_total} messages arrived within the 20 s budget",
            total_probe.load(Ordering::SeqCst)
        );
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        corrupt.load(Ordering::SeqCst),
        0,
        "every payload arrived byte for byte as sent"
    );
    assert_eq!(
        total.load(Ordering::SeqCst),
        expected_total,
        "no message was lost or delivered twice"
    );
    for (lane, (keyexpr, _)) in LANES.iter().enumerate() {
        let seen = arrived[lane].lock().expect("arrival log");
        let in_order: Vec<u32> = (0..PER_LANE).collect();
        assert_eq!(
            *seen, in_order,
            "{keyexpr}: every message once, in publish order within its priority"
        );
    }
}

/// A key declaration reaches the peer BEFORE the puts that name its alias, however fast the
/// puts fill their frames.
///
/// With the link's writer pulling what the conduits stage, each priority's open frame leaves
/// on its own. A declaration is a Control message, so it sat in the Control conduit's open
/// frame until the writer next had nothing to write, while a data frame that filled left at
/// once: kilobyte puts on the alias filled their frame within sixteen messages, and the peer
/// read them before it knew the alias, dropped them, and (zenoh-c) logged `Route data with
/// unknown scope`. Measured against a zenoh-c subscriber at 1 KiB; this is the same fault
/// between two wz sessions, where the peer drops the unresolved Push silently.
#[cfg(feature = "declare-keyexpr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn puts_on_a_declared_alias_never_overtake_its_declaration() {
    const ALIAS_KEY: &str = "demo/alias/overtake";
    const COUNT: u32 = 600;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_qos(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with qos offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        connect_and_open_session_with_qos(
            locator,
            fixture_params_with_zid(0x01),
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with qos offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);
    assert!(opened_init.actions.is_qos(), "initiator negotiated qos on");

    let received = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let received = received.clone();
        observer.subscribers.register(ALIAS_KEY, move |_sample| {
            received.fetch_add(1, Ordering::SeqCst);
        });
    }

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let init_actions = opened_init.actions.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let received_probe = received.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        tokio::task::spawn_blocking(move || {
            // The writer must be BUSY when the declaration is staged: a writer that is idle
            // flushes the declaration on waking, before any data frame can fill, and the
            // fault never shows. A stream of kilobyte puts on another key keeps it taking
            // frames, as it is whenever a face comes up (the declarations are replayed) while
            // traffic already flows.
            let warm = vec![0x5au8; 1024];
            for _ in 0..4000 {
                init_actions
                    .send_push_literal_qos("demo/alias/warm", &warm, true, Priority::Data)
                    .expect("a warm-up put routes");
            }
            init_actions
                .send_declare_keyexpr(7, ALIAS_KEY)
                .expect("the alias is declared");
            // Kilobyte puts, back to back, straight after the declaration: sixteen of them
            // fill a frame, so the first frame leaves long before the writer is idle.
            let payload = vec![0xa5u8; 1024];
            for _ in 0..COUNT {
                init_actions
                    .send_push_aliased(7, None, &payload, true)
                    .expect("an aliased put routes");
            }
        })
        .await
        .expect("the publishing thread");
        for _ in 0..500 {
            if received_probe.load(Ordering::SeqCst) >= COUNT as usize {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "only {} of {COUNT} aliased puts arrived: the first frames were read before the \
             declaration of their alias",
            received_probe.load(Ordering::SeqCst)
        );
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }
    assert_eq!(
        received.load(Ordering::SeqCst),
        COUNT as usize,
        "every aliased put arrived once"
    );
}

/// A long stream of kilobyte messages from one thread is delivered whole: the sender and the
/// link's writer never wait for each other.
///
/// The sender holds its conduit's lock across its wait for room on the link, and room is made by
/// the writer sending what is queued; the writer's idle flush took the same lock to send the
/// frames the session had open. With frames filling every sixteen messages the two met within
/// seconds and neither ever moved again (measured with a C publisher against zenoh-c at 1 KiB:
/// both threads asleep, the connection established and idle). The writer now skips a conduit
/// whose lock a sender holds and is asked to come back when the sender is done.
///
/// The stream is BLOCKING, not droppable: a droppable message that finds no room within
/// `wait_before_drop` is dropped, which is the congestion policy and not a fault, and a
/// stream of them delivers fewer than it sent however the locks are taken. A blocking one is
/// delivered or the session is closed, so "every message arrived" is the claim.
#[cfg(all(feature = "declare-keyexpr", not(feature = "transport-stats")))]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_long_kilobyte_stream_is_never_stalled_by_the_writers_flush() {
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::sample::QosLevel;

    const STREAM_KEY: &str = "demo/stream/kib";
    const COUNT: usize = 120_000;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_qos(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with qos offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        connect_and_open_session_with_qos(
            locator,
            fixture_params_with_zid(0x01),
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with qos offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    let received = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let received = received.clone();
        observer.subscribers.register(STREAM_KEY, move |_sample| {
            received.fetch_add(1, Ordering::SeqCst);
        });
    }

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let init_actions = opened_init.actions.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let received_probe = received.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sender = tokio::task::spawn_blocking(move || {
            init_actions
                .send_declare_keyexpr(7, STREAM_KEY)
                .expect("the stream's key is declared");
            let block = QosLevel::from_parts(Priority::Data, CongestionControl::Block, false);
            let payload = vec![0x3cu8; 1024];
            for _ in 0..COUNT {
                init_actions
                    .send_plain_put_qos(7, None, &payload, Some(block), true, false, Priority::Data)
                    .expect("a stream put routes");
            }
        });
        // Progress is watched, not only the end: a stream that stalls leaves the count where it
        // was, and that is what fails here, in seconds, instead of at a long deadline.
        let mut last = 0usize;
        let mut still_for = 0u32;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = received_probe.load(Ordering::SeqCst);
            if now >= COUNT {
                break;
            }
            if now == last {
                still_for += 1;
                assert!(
                    still_for < 40,
                    "the stream stood still for 4 s at {now} of {COUNT}: the sender and the \
                     writer are waiting for each other"
                );
            } else {
                still_for = 0;
                last = now;
            }
        }
        sender.await.expect("the publishing thread");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }
    assert_eq!(received.load(Ordering::SeqCst), COUNT);
}
