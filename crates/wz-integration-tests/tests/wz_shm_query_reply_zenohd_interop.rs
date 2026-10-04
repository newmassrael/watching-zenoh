// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport-shm` on the QUERY plane -- the value a query carries and the payload a
//! reply carries, against upstream's own SHM queryable and getter.
//!
//! ## What was unmeasured
//!
//! `wz_shm_payload_zenohd_interop` puts a PUSH through shared memory in both
//! directions. Upstream does not stop at a push: its receive path maps the shared
//! memory buffers of every network message that carries a payload, the Put of a
//! push, the value of a query and the payload of a reply and of an error reply
//! (`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn map_zmsg_to_shmbuf(`).
//! wz un-swapped a push and nothing else: its reply path held no resolver and said
//! so in a comment, so a reply whose slice names a segment was dropped. This file
//! asks what that costs against a real upstream peer, with the two programs
//! upstream ships for the purpose, `z_queryable_shm` and `z_get_shm`. It answered
//! twice. The reply was the one wz could close, and the reply leg below is the
//! witness that it is closed. The query's value is not: it ends the wz session on a
//! frame wz's generated codec cannot read, and the pin below records that and its
//! cause.
//!
//! ## The legs
//!
//! ```text
//!   [ wz getter ] <--reply, SHM-- zenoh z_queryable_shm --connect--> [ wz acceptor ]
//!   zenoh z_get_shm --connect--> [ zenohd, shared memory ] <--connect-- [ wz queryable ]
//! ```
//!
//! The getter leg is direct, because a getter needs no declaration to send a
//! query. The queryable leg has a ROUTER between the two, because a zenoh peer
//! routes a query only to queryables it has learned of, and a peer-to-peer
//! `z_get_shm` that has not learned wz's declaration sends to nobody and exits
//! (MEASURED: four attempts, each ending in a clean close with no query seen).
//! That is also how a queryable is reached in a deployment, and it puts the
//! router's own shared-memory relay on the path.
//!
//! Each leg asserts what a node that follows upstream does: the payload arrives, and
//! it arrives THROUGH shared memory, which the counting resolver shows. The getter
//! leg asks past the end of the queryable's pool, which holds ten chunks and hands
//! one to every reply, so it also shows that each chunk was given back: a getter
//! that reads a reply and never releases it gets the first eight or nine answered
//! and then finds the queryable parked in its allocator (MEASURED, before wz read a
//! reply at all).
//!
//! Requires `ZENOHD_SHM=1 scripts/build-zenohd.sh`, which builds the examples
//! beside the shared-memory `zenohd`. SKIPs where the oracle is absent: hosted CI
//! does not provision a source build for it.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;
use wz_integration_tests::common::{
    read_captured, wait_for_substring, zenoh_shm_example_binary, zenohd_shm_binary, ChildGuard,
    PortReservation, ZENOHD_LISTENER_LINE,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, QueryableOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, IterationEvent, WhatAmI};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_shm, connect_and_open_session, connect_and_open_session_with_shm,
    DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::shm_provider::PosixShmResolver;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::extshm::{ShmDescriptor, ShmResolver};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// What `z_queryable_shm` replies with by default, at the front of a 1024-byte
/// shared-memory buffer whose remainder is zeros.
const QUERYABLE_PAYLOAD: &str = "Queryable from Rust SHM!";

/// What `z_get_shm` sends as the value of its query by default, at the front of a
/// 1024-byte shared-memory buffer whose remainder is zeros.
const GET_PAYLOAD: &str = "Get from Rust SHM!";

/// How many replies past the first the getter leg asks for. The queryable's
/// provider holds ten chunks, so eleven more makes twelve in all, which a getter
/// that never gives a chunk back cannot reach.
const POOL_TURNOVER: usize = 11;

/// Send one query for the queryable's key and wait up to `within` for its first
/// reply, returning that reply's payload. `None` is no reply in time.
async fn ask(session: &TokioSession, within: Duration) -> Option<Vec<u8>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    session
        .query(
            "demo/example/zenoh-rs-queryable",
            QueryOptions::default(),
            move |reply| {
                let _ = tx.send(reply.payload().to_vec());
            },
            |_| {},
        )
        .unwrap_or_else(|e| panic!("the wz getter could not send its query: {e:?}"));
    tokio::time::timeout(within, rx.recv()).await.ok().flatten()
}

/// A resolver that counts what it was asked to resolve, so a leg can tell a payload
/// that crossed as shared memory from one that merely arrived.
struct CountingResolver {
    inner: PosixShmResolver,
    resolved: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
}

impl ShmResolver for CountingResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let bytes = self.inner.resolve(descriptor);
        let counter = if bytes.is_some() {
            &self.resolved
        } else {
            &self.refused
        };
        counter.fetch_add(1, Ordering::SeqCst);
        bytes
    }
}

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

/// What one run of a wz getter against `z_queryable_shm` saw.
struct GetterRun {
    /// Whether the wz session negotiated SHM with the queryable.
    negotiated: bool,
    /// The payload of every reply the wz getter was handed.
    replies: Vec<Vec<u8>>,
    /// Descriptors the resolver turned into bytes.
    resolved: usize,
    /// Descriptors the resolver refused.
    refused: usize,
    /// The last frames the wz drive loop polled, oldest first.
    trace: Vec<String>,
    /// Everything the queryable printed.
    zenoh_log: String,
}

/// Run `z_queryable_shm` against a wz acceptor, and have wz ask it until a reply
/// arrived and then twelve in all. The queryable answers with a shared-memory
/// buffer, so a wz that cannot read one hands the getter nothing.
async fn wz_getter_against_shm_queryable() -> Option<GetterRun> {
    let Some(z_queryable) = zenoh_shm_example_binary("z_queryable_shm") else {
        eprintln!(
            "SKIP: no z_queryable_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let (_guard, mut zenoh_log) = spawn_zenoh(
        &z_queryable,
        "z_queryable_shm",
        &[
            "-m".into(),
            "peer".into(),
            "-e".into(),
            format!("tcp/127.0.0.1:{port}"),
        ],
    );

    // A deadline, because a queryable that never dials (it died, or was built
    // without the feature) must fail this leg rather than park the job.
    let (stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "z_queryable_shm never dialled the wz acceptor:\n{}",
                read_captured(&mut zenoh_log)
            )
        })
        .expect("accept");
    let params = zenoh_interop_session_init_params(WhatAmI::Peer, vec![0x0d, 0x0a, 0x10, 0x02]);
    let mut opened = accept_and_open_session_with_shm(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "the wz acceptor did not reach Established: {e:?}\n{}",
            read_captured(&mut zenoh_log)
        )
    });
    let negotiated = opened.actions.is_shm();

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

    let timeouts = SessionTimeouts::spec_defaults();
    // The last few frames the drive loop polled, kept so that a getter that is
    // handed nothing can say what did arrive.
    let trace: Arc<StdMutex<Vec<String>>> = Arc::default();
    let tracing = trace.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| {
            if let IterationEvent::Poll(outcome) = &event {
                let mut line = format!("{outcome:?}");
                line.truncate(500);
                let mut last = tracing.lock().expect("trace");
                last.push(line);
                if last.len() > 6 {
                    last.remove(0);
                }
            }
            session.dispatch_iteration_event(event)
        },
    );

    let replies: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let scenario = async {
        // The queryable is declared a moment after the session opens, and a get
        // sent before the declaration is routed answers nothing, so ask again
        // until the first reply arrives.
        let mut first = None;
        for _ in 0..80 {
            if let Some(payload) = ask(&session, Duration::from_millis(500)).await {
                first = Some(payload);
                break;
            }
            // A query the peer ends with no reply (no queryable is declared yet)
            // closes its channel at once, so the pause is what spaces the asks out
            // instead of letting all of them land before the queryable exists.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let Some(first) = first else {
            return;
        };
        replies.lock().expect("replies").push(first);
        // Then ask past the end of the queryable's pool. Its provider holds ten
        // 1 KiB chunks and every reply takes one, which stays taken until the
        // RECEIVER gives it back, so a getter that reads a reply and never
        // releases or acknowledges it gets the first eight or nine answered and
        // then finds the queryable parked in its allocator (MEASURED: eight
        // "Responding" lines and then silence, with zenoh warning that no final
        // reply came). Twelve in a row is the witness that wz gives each back.
        for _ in 0..POOL_TURNOVER {
            match ask(&session, Duration::from_secs(5)).await {
                Some(payload) => replies.lock().expect("replies").push(payload),
                None => break,
            }
        }
    };
    let mut drive_log = zenoh_log.try_clone().expect("dup");
    tokio::select! {
        _ = drive => panic!(
            "the wz drive loop ended before the scenario did:\n{}",
            read_captured(&mut drive_log)
        ),
        () = scenario => {},
    }

    let replies = replies.lock().expect("replies").clone();
    let trace = trace.lock().expect("trace").clone();
    Some(GetterRun {
        negotiated,
        replies,
        resolved: resolved.load(Ordering::SeqCst),
        refused: refused.load(Ordering::SeqCst),
        trace,
        zenoh_log: read_captured(&mut zenoh_log),
    })
}

/// A TCP relay between wz and the router that keeps every byte the router sends
/// toward wz. A session that ends on a frame it cannot parse reports only a codec
/// error, and the cause of this file's pin is in the bytes: see
/// [`shm_value_extension_overruns_its_frame`].
async fn tap(router_port: u16) -> (u16, Arc<StdMutex<Vec<u8>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("tap bind");
    let port = listener.local_addr().expect("tap addr").port();
    let seen: Arc<StdMutex<Vec<u8>>> = Arc::default();
    let keep = seen.clone();
    tokio::spawn(async move {
        // A deadline, because the one that dials this relay is the wz session the
        // test opens next, and a test that fails before it dials must end the relay
        // and not leave it parked on an accept with the test's own task.
        let (wz, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("the wz session never dialled the tap relay within 30s"))
            .expect("tap accept");
        let router = tokio::net::TcpStream::connect(("127.0.0.1", router_port))
            .await
            .expect("tap connect");
        let (mut wz_r, mut wz_w) = wz.into_split();
        let (mut rt_r, mut rt_w) = router.into_split();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            while let Ok(n) = wz_r.read(&mut buf).await {
                if n == 0 || rt_w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut buf = [0u8; 8192];
        while let Ok(n) = rt_r.read(&mut buf).await {
            if n == 0 {
                break;
            }
            keep.lock().expect("tap").extend_from_slice(&buf[..n]);
            if wz_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        up.abort();
    });
    (port, seen)
}

/// Whether the LAST frame in `stream`, a record of what a streamed link carried (a
/// two-byte little-endian length before each frame), holds the shared-memory marker
/// extension (`0x84`: a unit extension with id 4 and more to follow) and then a ZBuf
/// extension (`0x43`: id 3) whose DECLARED length is longer than the bytes the frame
/// has left. That is how upstream writes the value of a query it sends through shared
/// memory: the length it declares is `w_len(encoding) + w_len(sliced payload)` and
/// `Zenoh080Sliced::w_len` adds `1 + x.len()` per slice where `x.len()` is the
/// LOGICAL length of the buffer, 1024, and not the seven bytes of descriptor it
/// writes (`commons/zenoh-codec/src/core/zbuf.rs` @ `message.zslices().fold(0, |acc, x| acc + 1 + x.len())`).
/// Upstream's own reader treats the declared length as a lower bound when the
/// marker is there: it requires the length to cover the encoding and then reads
/// the slices by their own structure (`commons/zenoh-codec/src/zenoh/mod.rs` @
/// `if ext_shm.is_some() {`).
fn shm_value_extension_overruns_its_frame(stream: &[u8]) -> bool {
    let mut at = 0;
    let mut last: Option<&[u8]> = None;
    while at + 2 <= stream.len() {
        let n = usize::from(u16::from_le_bytes([stream[at], stream[at + 1]]));
        if at + 2 + n > stream.len() {
            break;
        }
        last = Some(&stream[at + 2..at + 2 + n]);
        at += 2 + n;
    }
    let Some(frame) = last else {
        return false;
    };
    let Some(marker) = frame.windows(2).position(|w| w == [0x84, 0x43]) else {
        return false;
    };
    let mut declared: usize = 0;
    let mut shift = 0;
    let mut i = marker + 2;
    loop {
        let Some(&byte) = frame.get(i) else {
            return false;
        };
        declared |= usize::from(byte & 0x7f) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    declared > frame.len() - i
}

/// What one run of `z_get_shm` through a router to a wz queryable saw.
struct QueryableRun {
    /// Whether the wz session negotiated SHM with the router.
    negotiated: bool,
    /// Why the wz drive loop ended, when it ended before the scenario did.
    drive_ended: Option<String>,
    /// The last frames the wz drive loop polled, oldest first.
    trace: Vec<String>,
    /// Whether the last frame the router sent wz carried a shared-memory value
    /// extension whose declared length overruns the frame: see
    /// [`shm_value_extension_overruns_its_frame`].
    value_extension_overruns: bool,
    /// How many queries reached the wz queryable's callback, whatever they carried.
    queries_seen: usize,
    /// The value of every query that carried one.
    values: Vec<Vec<u8>>,
    /// Descriptors the resolver turned into bytes.
    resolved: usize,
    /// Descriptors the resolver refused.
    refused: usize,
    /// Everything the last getter printed.
    getter_log: String,
    /// Everything the router printed.
    router_log: String,
}

/// Run a shared-memory `zenohd`, connect a wz queryable to it, and run `z_get_shm`
/// as a client of it. The getter sends its query once, right after its session
/// opens, so the wz queryable is declared and given a moment to reach the router
/// BEFORE the getter starts, and a getter that still saw no queryable is run again,
/// up to four times, against the same router and the same wz session.
async fn shm_get_to_wz_queryable(offer_shm: bool) -> Option<QueryableRun> {
    let (Some(zenohd), Some(z_get)) = (zenohd_shm_binary(), zenoh_shm_example_binary("z_get_shm"))
    else {
        eprintln!(
            "SKIP: no shared-memory zenohd or z_get_shm at target/zenohd-shm \
             (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let port = PortReservation::pick();
    let listen_port = port.port();
    let router_log = tempfile::tempfile().expect("capture");
    let mut router_log_read = router_log.try_clone().expect("dup");
    let _router = ChildGuard::wrap(
        "zenohd (shared-memory oracle)".to_string(),
        Command::new(&zenohd)
            .args(["-l", &format!("tcp/127.0.0.1:{listen_port}")])
            .args(["--no-multicast-scouting", "--rest-http-port", "none"])
            // The readiness needle below is a `debug!`; see `ZENOHD_LISTENER_LINE`.
            .env("RUST_LOG", "z=debug")
            .stdout(Stdio::from(router_log.try_clone().expect("dup")))
            .stderr(Stdio::from(router_log))
            .spawn()
            .expect("spawn shm zenohd"),
    );
    if let Err(c) = wait_for_substring(
        &mut router_log_read,
        ZENOHD_LISTENER_LINE,
        Duration::from_secs(20),
    ) {
        panic!("the shm zenohd never announced its listener within 20s\n--- zenohd ---\n{c}");
    }
    drop(port);

    let (tap_port, tapped) = tap(listen_port).await;
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{tap_port}")).expect("locator");
    let params = zenoh_interop_session_init_params(WhatAmI::Peer, vec![0x0b, 0x0a, 0x10, 0x03]);
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
    let mut opened = opened.unwrap_or_else(|e| {
        panic!(
            "the wz dialer did not reach Established (offering SHM: {offer_shm}): {e:?}\n{}",
            read_captured(&mut router_log_read)
        )
    });
    let negotiated = opened.actions.is_shm();

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
    let queries_seen = Arc::new(AtomicUsize::new(0));
    let values: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let (seen, sink) = (queries_seen.clone(), values.clone());
    let _queryable = session
        .declare_queryable(
            "demo/example/**",
            QueryableOptions::default(),
            move |query, _reply| {
                seen.fetch_add(1, Ordering::SeqCst);
                if let Some(value) = query.payload() {
                    sink.lock().expect("values").push(value.to_vec());
                }
            },
        )
        .expect("declare the queryable");

    let timeouts = SessionTimeouts::spec_defaults();
    // The last few frames the drive loop polled, kept so that a session that ends
    // under the scenario can say what it was doing when it did.
    let trace: Arc<StdMutex<Vec<String>>> = Arc::default();
    let tracing = trace.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| {
            if let IterationEvent::Poll(outcome) = &event {
                let mut line = format!("{outcome:?}");
                line.truncate(400);
                let mut last = tracing.lock().expect("trace");
                last.push(line);
                if last.len() > 12 {
                    last.remove(0);
                }
            }
            session.dispatch_iteration_event(event)
        },
    );
    let getter_log: Arc<StdMutex<String>> = Arc::default();
    let probe = queries_seen.clone();
    let log_out = getter_log.clone();
    let scenario = async {
        for _attempt in 0..4 {
            // Let the declaration reach the router before the getter asks.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (_getter, mut log) = spawn_zenoh(
                &z_get,
                "z_get_shm",
                &[
                    "-m".into(),
                    "client".into(),
                    "-e".into(),
                    format!("tcp/127.0.0.1:{listen_port}"),
                ],
            );
            for _ in 0..60 {
                if probe.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Let the rest of the exchange settle: the value is read and
            // acknowledged as the callback is reached, not after.
            tokio::time::sleep(Duration::from_millis(300)).await;
            *log_out.lock().expect("log") = read_captured(&mut log);
            if probe.load(Ordering::SeqCst) > 0 {
                return;
            }
        }
    };
    // A session that ends under the scenario is a RESULT, not a harness fault: it is
    // what the query-value pin below exists to record, and the run says why.
    let drive_ended = tokio::select! {
        outcome = drive => Some(format!("{outcome:?}")),
        () = scenario => None,
    };
    let getter_log = getter_log.lock().expect("log").clone();
    let values = values.lock().expect("values").clone();
    let trace = trace.lock().expect("trace").clone();
    let value_extension_overruns =
        shm_value_extension_overruns_its_frame(&tapped.lock().expect("tap"));
    Some(QueryableRun {
        negotiated,
        drive_ended,
        trace,
        value_extension_overruns,
        queries_seen: queries_seen.load(Ordering::SeqCst),
        values,
        resolved: resolved.load(Ordering::SeqCst),
        refused: refused.load(Ordering::SeqCst),
        getter_log,
        router_log: read_captured(&mut router_log_read),
    })
}

/// A node that follows upstream reads the shared-memory payload of a REPLY: the
/// queryable answers with a buffer in its own provider, and the getter is handed
/// the bytes and, through the counting resolver, shown to have read them out of
/// shared memory. It is handed twelve of them in a row, which the queryable's
/// ten-chunk pool can only supply if each was given back.
// wz-proves: transport-shm zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_queryable_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_queryable_reply_reaches_a_wz_getter_through_shared_memory() {
    let Some(run) = wz_getter_against_shm_queryable().await else {
        return;
    };
    assert!(
        run.negotiated,
        "wz and the queryable must have negotiated SHM, or this leg proves nothing:\n{}",
        run.zenoh_log
    );
    let wanted = 1 + POOL_TURNOVER;
    assert!(
        run.replies
            .iter()
            .all(|p| p.starts_with(QUERYABLE_PAYLOAD.as_bytes())),
        "a reply handed to the wz getter did not carry the queryable's payload {QUERYABLE_PAYLOAD:?}; \
         first bytes {:?}",
        run.replies
            .iter()
            .find(|p| !p.starts_with(QUERYABLE_PAYLOAD.as_bytes()))
            .map(|p| p.iter().take(32).copied().collect::<Vec<u8>>()),
    );
    assert_eq!(
        run.replies.len(),
        wanted,
        "the wz getter was handed {} replies where the queryable's ten-chunk pool needs {wanted} \
         in a row to prove each chunk was given back; resolver resolved {} and refused {}; the \
         last frames wz polled:\n{}\n--- queryable ---\n{}",
        run.replies.len(),
        run.resolved,
        run.refused,
        run.trace.join("\n"),
        run.zenoh_log
    );
    assert!(
        run.resolved >= wanted,
        "the replies arrived but the resolver was asked for only {} of them, so they did not \
         all cross as shared memory:\n{}",
        run.resolved,
        run.zenoh_log
    );
}

/// Control for the query-value leg -- the same getter, the same router and the same
/// wz queryable, against a wz session that does NOT offer shared memory. The router
/// then relays the value as plain bytes, so the query must arrive and carry the text
/// without the resolver being asked anything. If this arm fails, the next leg's
/// failure is the topology or the harness and says nothing about shared memory.
// wz-proves: none -- the raw control for the query-value leg: wz offers no shared memory, so a delivery proves the topology and not the layout
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_get_shm); Layer Z runs via --ignored"]
async fn zenohd_get_value_reaches_a_wz_queryable_raw_when_shm_is_not_offered() {
    let Some(run) = shm_get_to_wz_queryable(false).await else {
        return;
    };
    assert!(
        !run.negotiated,
        "this control must run WITHOUT shared memory negotiated:\n{}",
        run.router_log
    );
    assert!(
        run.queries_seen > 0,
        "no query reached the wz queryable even raw, so the topology is wrong and the SHM \
         pin means nothing; drive ended: {:?}; trace:\n{}\n--- getter ---\n{}\n--- router ---\n{}",
        run.drive_ended,
        run.trace.join("\n"),
        run.getter_log,
        run.router_log
    );
    assert!(
        run.values
            .iter()
            .any(|v| v.starts_with(GET_PAYLOAD.as_bytes())),
        "a raw query reached the wz queryable but its value was not the getter's \
         {GET_PAYLOAD:?}; values: {:?}",
        run.values
            .iter()
            .map(|v| v.iter().take(32).copied().collect::<Vec<u8>>())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        run.resolved + run.refused,
        0,
        "no shared-memory descriptor should have reached the resolver in the raw control"
    );
}

/// A node that follows upstream reads the shared-memory VALUE of a QUERY: the
/// getter puts its value in a buffer of its own provider, the router relays the
/// query to wz with the value as a list of slices after the shared-memory marker,
/// and the wz queryable is handed the bytes and, through the counting resolver,
/// shown to have read them out of shared memory.
///
/// The extension that carries the value declares a length that is not the length
/// it has (see [`shm_value_extension_overruns_its_frame`]), and this leg asserts
/// that it still does, because that is the premise: a fixture that stopped sending
/// it would pass without reading anything. R3045 made the query's chain read the
/// value as upstream does, by its structure and not by the length in front of it.
/// Until then the generated chain trusted the length, read past the frame and
/// reported `NeedMoreBytes`, and the session ended: the drive loop's last polls
/// were the router's OAM frame, then `ParseError(Codec(NeedMoreBytes))`, then
/// `LinkLost(PeerClosed)`. The raw control above, the same getter and router and
/// queryable with wz not offering shared memory, delivered the value throughout.
// wz-proves: transport-shm zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_get_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_get_value_reaches_a_wz_queryable_through_shared_memory() {
    let Some(run) = shm_get_to_wz_queryable(true).await else {
        return;
    };
    assert!(
        run.negotiated,
        "wz and the router must have negotiated SHM, or this leg proves nothing:\n{}",
        run.router_log
    );
    assert!(
        run.value_extension_overruns,
        "the last frame the router sent wz no longer carries a shared-memory value extension \
         whose declared length overruns the frame, so this leg no longer exercises the shape \
         it is for; drive ended: {:?}; trace:\n{}\n--- getter ---\n{}\n--- router ---\n{}",
        run.drive_ended,
        run.trace.join("\n"),
        run.getter_log,
        run.router_log
    );
    assert_eq!(
        run.drive_ended, None,
        "the wz session ended under the scenario; trace:\n{}\n--- getter ---\n{}\n--- router ---\n{}",
        run.trace.join("\n"),
        run.getter_log,
        run.router_log
    );
    assert!(
        run.queries_seen > 0,
        "no query reached the wz queryable; trace:\n{}\n--- getter ---\n{}\n--- router ---\n{}",
        run.trace.join("\n"),
        run.getter_log,
        run.router_log
    );
    assert!(
        run.values
            .iter()
            .any(|v| v.starts_with(GET_PAYLOAD.as_bytes())),
        "a query reached the wz queryable but its value was not the getter's {GET_PAYLOAD:?}; \
         values: {:?}",
        run.values
            .iter()
            .map(|v| v.iter().take(32).copied().collect::<Vec<u8>>())
            .collect::<Vec<_>>()
    );
    assert!(
        run.resolved >= 1,
        "the value arrived but the resolver was never asked for it, so it did not cross as \
         shared memory:\n{}",
        run.router_log
    );
    assert_eq!(
        run.refused, 0,
        "the resolver refused a descriptor the router sent:\n{}",
        run.router_log
    );
}
