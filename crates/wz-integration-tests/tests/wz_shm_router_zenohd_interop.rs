// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport-shm` through a ROUTER: the legs of the other two shared-memory files
//! put the two ends in contact, and this one puts upstream's own shared-memory
//! `zenohd` between them.
//!
//! ## What was unmeasured
//!
//! Every wz-to-zenoh leg of `wz_shm_payload_zenohd_interop` and
//! `wz_shm_query_reply_zenohd_interop` dials the upstream program directly. A router
//! is not a relay of bytes: it reads each message it routes, maps the shared-memory
//! buffers it carries (`io/zenoh-transport/src/common/shm/interop.rs` @
//! `pub fn map_zmsg_to_shmbuf(`), and writes the message again to each face, which
//! takes its own reference to the buffer. Whether a descriptor wz wrote survives
//! that, so that the program on the far side maps wz's own segment, is a different
//! question from whether the far side can read a descriptor, and the direct legs
//! cannot answer it.
//!
//! ## The legs
//!
//! ```text
//!   [ wz publisher ]  --SHM--> zenohd (shared memory) --> zenoh z_sub_shm
//!   zenoh z_pub_shm   --SHM--> zenohd (shared memory) --> [ wz subscriber ]
//!   [ wz getter, value in SHM ] --> zenohd (shared memory) --> zenoh z_queryable_shm
//! ```
//!
//! Requires `ZENOHD_SHM=1 scripts/build-zenohd.sh`. SKIPs where the oracle is
//! absent: hosted CI does not provision a source build for it.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, zenoh_shm_example_binary, zenohd_shm_binary, ChildGuard,
    PortReservation, ZENOHD_LISTENER_LINE,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, QueryOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, WhatAmI};
use wz_runtime_tokio::session_open::{
    connect_and_open_session, connect_and_open_session_with_shm, DialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::shm_provider::{PosixShmResolver, ShmBackedPayload};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::extshm::{ShmDescriptor, ShmResolver};
use wz_session_core::link::RxBytes;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// What `z_sub_shm` prints for a sample that arrived through shared memory, as
/// opposed to `[RAW]`: the front of either of its two SHM labels.
const ZENOH_SAW_SHM: &str = "[SHM (";

/// Start an upstream SHM example with the flags every leg shares, its output going
/// to one capture file.
fn spawn_zenoh(
    binary: &std::path::Path,
    name: &str,
    args: &[String],
) -> (ChildGuard, std::fs::File) {
    let log = tempfile::tempfile().expect("capture");
    let child = Command::new(binary)
        .args(args)
        .args(["--no-multicast-scouting", "--enable-shm"])
        .env(
            "RUST_LOG",
            "zenoh=info,zenoh_shm=debug,zenoh_transport=debug",
        )
        .stdout(Stdio::from(log.try_clone().expect("dup")))
        .stderr(Stdio::from(log.try_clone().expect("dup")))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    (ChildGuard::wrap(name.to_string(), child), log)
}

/// A shared-memory `zenohd` listening on a port of its own, with its log.
struct Router {
    port: u16,
    log: std::fs::File,
    _guard: ChildGuard,
}

/// Run upstream's shared-memory `zenohd` and wait for its listener.
fn spawn_router(zenohd: &std::path::Path) -> Router {
    let port = PortReservation::pick();
    let listen_port = port.port();
    let log = tempfile::tempfile().expect("capture");
    let mut log_read = log.try_clone().expect("dup");
    let guard = ChildGuard::wrap(
        "zenohd (shared-memory oracle)".to_string(),
        Command::new(zenohd)
            .args(["-l", &format!("tcp/127.0.0.1:{listen_port}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            // The readiness needle below is a `debug!`; see `ZENOHD_LISTENER_LINE`.
            .env("RUST_LOG", "z=debug")
            .stdout(Stdio::from(log.try_clone().expect("dup")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn shm zenohd"),
    );
    if let Err(c) = wait_for_substring(&mut log_read, ZENOHD_LISTENER_LINE, Duration::from_secs(20))
    {
        panic!("the shm zenohd never announced its listener within 20s\n--- zenohd ---\n{c}");
    }
    drop(port);
    Router {
        port: listen_port,
        log: log_read,
        _guard: guard,
    }
}

/// A wz session dialled to the router, with SHM offered when `offer_shm` says so,
/// returned with its `negotiated` verdict. A session that offers nothing is the
/// control of a leg: the router must then send what it routes as bytes.
async fn wz_dials_router(
    router: &mut Router,
    zid_tail: u8,
    offer_shm: bool,
) -> (wz_runtime_tokio::session_open::OpenedSession, bool) {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{}", router.port)).expect("locator");
    let params = zenoh_interop_session_init_params(WhatAmI::Peer, vec![0x0b, 0x0a, 0x10, zid_tail]);
    let opened = if offer_shm {
        connect_and_open_session_with_shm(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    } else {
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    };
    let opened = opened.unwrap_or_else(|e| {
        panic!(
            "the wz dialer did not reach Established (offering SHM: {offer_shm}): {e:?}\n{}",
            read_captured(&mut router.log)
        )
    });
    let negotiated = opened.actions.is_shm();
    (opened, negotiated)
}

/// A wz PUBLISHER puts a payload through shared memory to a shared-memory `zenohd`,
/// and `z_sub_shm`, a client of that router, prints what it received. Returns what
/// the subscriber printed and what the router printed, and whether wz's session
/// with the router negotiated shared memory.
async fn wz_publishes_through_router(key: &str, text: &str) -> Option<(bool, String, String)> {
    let (Some(zenohd), Some(z_sub)) = (zenohd_shm_binary(), zenoh_shm_example_binary("z_sub_shm"))
    else {
        eprintln!(
            "SKIP: no shared-memory zenohd or z_sub_shm at target/zenohd-shm \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let mut router = spawn_router(&zenohd);
    let (_sub, mut sub_log) = spawn_zenoh(
        &z_sub,
        "z_sub_shm",
        &[
            "-m".into(),
            "client".into(),
            "-e".into(),
            format!("tcp/127.0.0.1:{}", router.port),
            "-k".into(),
            "demo/example/**".into(),
        ],
    );
    wait_for_substring(
        &mut sub_log,
        "Press CTRL-C to quit",
        Duration::from_secs(20),
    )
    .unwrap_or_else(|e| panic!("z_sub_shm never became ready: {e}"));

    let (mut opened, negotiated) = wz_dials_router(&mut router, 0x04, true).await;
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session.dispatch_iteration_event(event),
    );

    let key = key.to_string();
    let bytes = text.as_bytes().to_vec();
    let mut probe = sub_log.try_clone().expect("dup");
    let held: Arc<StdMutex<Vec<ShmBackedPayload>>> = Arc::default();
    let scenario = async {
        // The subscriber's declaration has to reach the router before a put is
        // routed to it, so publish again until the subscriber prints one.
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let mut payload = ShmBackedPayload::alloc(bytes.len()).expect("alloc a payload");
            payload.write(&bytes);
            session
                .publish_shm(&key, &payload, PublishOptions::put())
                .expect("publish_shm");
            held.lock().expect("held").push(payload);
            if read_captured(&mut probe).contains("Received") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    let mut drive_log = sub_log.try_clone().expect("dup");
    tokio::select! {
        outcome = drive => panic!(
            "the wz drive loop ended before the scenario did ({outcome:?}):\n{}",
            read_captured(&mut drive_log)
        ),
        () = scenario => {},
    }
    let printed = read_captured(&mut sub_log);
    let routed = read_captured(&mut router.log);
    Some((negotiated, printed, routed))
}

/// A wz publisher puts a payload through shared memory to a shared-memory router and
/// the far subscriber, which is a client of the router and not of wz, reads it.
///
/// What the leg asserts is what a node that follows upstream does: the payload
/// arrives, and it arrives AS A SHARED-MEMORY BUFFER, which `z_sub_shm` reports by
/// the label it prints. A router that could not map wz's segment would either drop
/// the message or copy it onwards, and the far side would print the bytes with the
/// label RAW or nothing at all.
// wz-proves: transport-shm wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: zenohd + z_sub_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_router_relays_a_wz_publishers_payload_to_a_subscriber_through_shared_memory() {
    let text = "wz-through-the-router";
    let Some((negotiated, printed, routed)) =
        wz_publishes_through_router("demo/example/wz-router", text).await
    else {
        return;
    };
    assert!(
        negotiated,
        "wz and the router did not negotiate SHM, so this leg measured nothing about shared \
         memory:\n{routed}"
    );
    assert!(
        printed.contains(&format!(
            "('demo/example/wz-router': '{text}') {ZENOH_SAW_SHM}"
        )),
        "the far subscriber did not report wz's payload as a shared-memory buffer:\n--- \
         z_sub_shm ---\n{printed}\n--- zenohd ---\n{routed}"
    );
}

/// A resolver that counts what the registry asked it to resolve, through both
/// paths, so a leg can tell a payload that crossed as shared memory from one that
/// merely arrived.
struct CountingResolver {
    inner: PosixShmResolver,
    resolved: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
}

impl CountingResolver {
    fn count<T>(&self, resolved: &Option<T>) {
        let counter = if resolved.is_some() {
            &self.resolved
        } else {
            &self.refused
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl ShmResolver for CountingResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let bytes = self.inner.resolve(descriptor);
        self.count(&bytes);
        bytes
    }

    fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<RxBytes> {
        let bytes = self.inner.resolve_shared(descriptor);
        self.count(&bytes);
        bytes
    }
}

/// What a wz SUBSCRIBER behind a shared-memory router was handed by a zenoh
/// publisher that is also a client of that router.
struct SubscriberRun {
    /// Whether wz's session with the router negotiated shared memory.
    negotiated: bool,
    /// The payload of every sample the wz subscriber was handed.
    received: Vec<Vec<u8>>,
    /// Descriptors the resolver turned into bytes.
    resolved: usize,
    /// Descriptors the resolver refused.
    refused: usize,
    /// Everything the router printed.
    router_log: String,
    /// Everything the publisher printed.
    publisher_log: String,
}

/// Run `z_pub_shm` as a client of a shared-memory router and a wz subscriber behind
/// the same router. `offer_shm` says whether wz offers shared memory to it; when it
/// does not, the router must send what it routes as bytes, which is this helper's
/// own control.
async fn zenoh_publishes_through_router_to_wz(offer_shm: bool) -> Option<SubscriberRun> {
    let (Some(zenohd), Some(z_pub)) = (zenohd_shm_binary(), zenoh_shm_example_binary("z_pub_shm"))
    else {
        eprintln!(
            "SKIP: no shared-memory zenohd or z_pub_shm at target/zenohd-shm \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let mut router = spawn_router(&zenohd);
    let (mut opened, negotiated) = wz_dials_router(&mut router, 0x05, offer_shm).await;
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let resolved = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    session.set_shm_resolver(Box::new(CountingResolver {
        inner: PosixShmResolver,
        resolved: resolved.clone(),
        refused: refused.clone(),
    }));
    let received: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = received.clone();
    // The routed declaration: a zenoh publisher sends nothing to a peer that has not
    // told it there is a subscriber.
    let _subscriber = session.declare_subscriber(
        "demo/example/**",
        SubscribeOptions::default(),
        move |sample| {
            sink.lock()
                .expect("received")
                .push(sample.payload().to_vec());
        },
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session.dispatch_iteration_event(event),
    );

    // The subscriber is declared a moment after the session opens, so the publisher
    // starts once the declaration has had time to reach the router.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_publisher, mut publisher_log) = spawn_zenoh(
        &z_pub,
        "z_pub_shm",
        &[
            "-m".into(),
            "client".into(),
            "-e".into(),
            format!("tcp/127.0.0.1:{}", router.port),
        ],
    );
    let probe = received.clone();
    let mut drive_log = router.log.try_clone().expect("dup");
    let scenario = async {
        for _ in 0..400 {
            if probe.lock().expect("received").len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::select! {
        outcome = drive => panic!(
            "the wz drive loop ended before the scenario did ({outcome:?}):\n{}",
            read_captured(&mut drive_log)
        ),
        () = scenario => {},
    }
    let received = received.lock().expect("received").clone();
    Some(SubscriberRun {
        negotiated,
        received,
        resolved: resolved.load(Ordering::SeqCst),
        refused: refused.load(Ordering::SeqCst),
        router_log: read_captured(&mut router.log),
        publisher_log: read_captured(&mut publisher_log),
    })
}

/// A zenoh publisher puts a payload through shared memory to a shared-memory router
/// and a wz subscriber, which is a client of that router and not of the publisher,
/// is handed it. The counting resolver is what shows the payload crossed as a
/// descriptor wz resolved and not as bytes the router copied onwards: a router that
/// un-swapped it would deliver the payload with the resolver never asked.
// wz-proves: transport-shm zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: zenohd + z_pub_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_router_relays_a_zenoh_publishers_payload_to_a_wz_subscriber_through_shared_memory(
) {
    let Some(run) = zenoh_publishes_through_router_to_wz(true).await else {
        return;
    };
    assert!(
        run.negotiated,
        "wz and the router did not negotiate SHM, so this leg measured nothing about shared \
         memory:\n{}",
        run.router_log
    );
    assert!(
        run.received.len() >= 3,
        "wz was handed {} of the three samples the publisher sent through the router:\n--- \
         z_pub_shm ---\n{}\n--- zenohd ---\n{}",
        run.received.len(),
        run.publisher_log,
        run.router_log
    );
    let text = "Pub from Rust SHM!";
    assert!(
        run.received
            .iter()
            .all(|sample| String::from_utf8_lossy(sample).ends_with(text)),
        "a sample was not the publisher's text: {:?}",
        run.received
    );
    assert!(
        run.resolved >= 3 && run.refused == 0,
        "the resolver was asked for {} descriptor(s) and refused {}, so the router did not hand \
         wz the publisher's shared-memory buffers:\n--- z_pub_shm ---\n{}\n--- zenohd ---\n{}",
        run.resolved,
        run.refused,
        run.publisher_log,
        run.router_log
    );
}

/// Control for the leg above -- the same publisher, router and subscriber, against a
/// wz session that does not offer shared memory. The router must send the payload as
/// bytes, so the samples arrive with the resolver never asked: the count is what
/// tells a payload that crossed as a descriptor from one that merely arrived, so a
/// zero here is what gives the leg above its three. If this arm fails, that leg's
/// count says nothing about shared memory.
// wz-proves: none -- the raw control for the router leg above: wz offers no shared memory, so a delivery proves the topology and not the layout
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: zenohd + z_pub_shm); Layer Z runs via --ignored"]
async fn zenohd_router_sends_a_zenoh_publishers_payload_to_a_wz_subscriber_raw_when_shm_is_not_offered(
) {
    let Some(run) = zenoh_publishes_through_router_to_wz(false).await else {
        return;
    };
    assert!(
        !run.negotiated,
        "the session negotiated SHM although wz offered none:\n{}",
        run.router_log
    );
    assert!(
        run.received.len() >= 3,
        "wz was handed {} of the three samples the publisher sent through the router:\n--- \
         z_pub_shm ---\n{}\n--- zenohd ---\n{}",
        run.received.len(),
        run.publisher_log,
        run.router_log
    );
    assert!(
        run.resolved == 0 && run.refused == 0,
        "the resolver was asked about {} descriptor(s) on a session that offered no shared \
         memory, so the count of the leg above does not separate a descriptor from a payload that \
         merely arrived",
        run.resolved + run.refused
    );
}

/// What a wz GETTER whose query carries a value in shared memory saw behind a
/// shared-memory router, to a zenoh queryable that is also a client of it.
struct GetterRun {
    /// Whether wz's session with the router negotiated shared memory.
    negotiated: bool,
    /// The payload of every reply the wz getter was handed.
    replies: Vec<Vec<u8>>,
    /// Everything the queryable printed.
    queryable_log: String,
    /// Everything the router printed.
    router_log: String,
}

/// What the wz getter sends as the value of its query.
const WZ_QUERY_VALUE: &str = "Query from wz through the router";

async fn wz_getter_through_router() -> Option<GetterRun> {
    let (Some(zenohd), Some(z_queryable)) = (
        zenohd_shm_binary(),
        zenoh_shm_example_binary("z_queryable_shm"),
    ) else {
        eprintln!(
            "SKIP: no shared-memory zenohd or z_queryable_shm at target/zenohd-shm \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let mut router = spawn_router(&zenohd);
    let (_queryable, mut queryable_log) = spawn_zenoh(
        &z_queryable,
        "z_queryable_shm",
        &[
            "-m".into(),
            "client".into(),
            "-e".into(),
            format!("tcp/127.0.0.1:{}", router.port),
        ],
    );
    let (mut opened, negotiated) = wz_dials_router(&mut router, 0x06, true).await;
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    session.set_shm_resolver(Box::new(PosixShmResolver));
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session.dispatch_iteration_event(event),
    );

    let replies: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let mut drive_log = queryable_log.try_clone().expect("dup");
    let scenario = async {
        // The queryable's declaration has to reach the router before a query is
        // routed to it, so ask again until a reply arrives.
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let mut held = ShmBackedPayload::alloc(WZ_QUERY_VALUE.len()).expect("alloc a value");
            held.write(WZ_QUERY_VALUE.as_bytes());
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            session
                .query_shm(
                    "demo/example/zenoh-rs-queryable",
                    QueryOptions::default(),
                    &held,
                    move |reply| {
                        let _ = tx.send(reply.payload().to_vec());
                    },
                    |_| {},
                )
                .expect("query_shm");
            if let Ok(Some(payload)) =
                tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
            {
                replies.lock().expect("replies").push(payload);
                break;
            }
        }
    };
    tokio::select! {
        outcome = drive => panic!(
            "the wz drive loop ended before the scenario did ({outcome:?}):\n{}",
            read_captured(&mut drive_log)
        ),
        () = scenario => {},
    }
    let replies = replies.lock().expect("replies").clone();
    Some(GetterRun {
        negotiated,
        replies,
        queryable_log: read_captured(&mut queryable_log),
        router_log: read_captured(&mut router.log),
    })
}

/// A wz getter sends the value of its query through shared memory to a shared-memory
/// router, and `z_queryable_shm`, a client of that router, prints the value with the
/// buffer type it arrived in. `SHM` is a mapped buffer, which only a router that read
/// wz's descriptor and wrote it again can have produced; `RAW` is a router that
/// copied the bytes onwards.
// wz-proves: transport-shm wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: zenohd + z_queryable_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_router_relays_a_wz_getters_query_value_to_a_queryable_through_shared_memory() {
    let Some(run) = wz_getter_through_router().await else {
        return;
    };
    assert!(
        run.negotiated,
        "wz and the router did not negotiate SHM, so this leg measured nothing about shared \
         memory:\n{}",
        run.router_log
    );
    assert!(
        !run.replies.is_empty(),
        "the queryable answered no query:\n--- z_queryable_shm ---\n{}\n--- zenohd ---\n{}",
        run.queryable_log,
        run.router_log
    );
    assert!(
        run.queryable_log
            .contains(&format!("'{WZ_QUERY_VALUE}') [SHM]")),
        "the queryable did not print the getter's value as a shared-memory buffer:\n--- \
         z_queryable_shm ---\n{}\n--- zenohd ---\n{}",
        run.queryable_log,
        run.router_log
    );
}
