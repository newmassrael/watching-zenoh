// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 900 — ONE `wz-ap-demo` process started from a `--sessions`
//! document holding a client session to a stock zenohd and a peer session in a
//! UDP multicast group.
//!
//! `wz_client_and_multicast_peer_sessions_in_one_process_zenohd` showed the
//! library can hold the two side by side. This is the INPUT a lab authors: the
//! same two sessions from a file, in the demo binary, each observable on its
//! own stderr lines.
//!
//! ## What it asserts
//!
//! 1. Both sessions print READY: the client once Established against zenohd,
//!    the group session once joined; and a group member that beacons is seen
//!    by the group session (`peer arrived`).
//! 2. NOTHING CROSSES BETWEEN THEM. A Put a group member sends never reaches a
//!    subscriber on zenohd's side, while the same subscriber does receive a Put
//!    published to zenohd (the control, so the zero is a measurement). The
//!    two are separate sessions, as two upstream sessions in one program are;
//!    no bridge between them is claimed or built.
//! 3. A FAULT IN ONE DOES NOT STALL THE OTHER. zenohd is killed: the client
//!    session ends, and the group session then still admits a member that
//!    arrives after.
//! 4. A per-session close on SIGTERM: the group session closes, the ended
//!    client does not close a second time, and the process exits 0.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): it needs zenohd, a host that delivers
//! multicast on loopback, and the demo built with `transport-multicast` (Layer
//! M's `router-multicast-faces` build pulls it). The test NAME carries
//! `zenohd` because Layer E's skip filter is a name substring.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket};

use wz_integration_tests::bounded::BoundedStatus as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, spawn_zenohd_on_ephemeral_tcp, wz_ap_demo_binary,
};
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session, multicast_put_literal, MulticastDriveConfig, MulticastTxProducer,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    initiate_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::UdpDriver;
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::WhatAmI;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
/// A group port no other multicast leg in this tree binds.
const PORT: u16 = 7468;
const GROUP_KEY: &str = "demo/sessions/group";
const CONTROL_KEY: &str = "demo/sessions/control";
const SUBSCRIBED: &str = "demo/sessions/**";
const DEADLINE: Duration = Duration::from_secs(20);

/// The demo's stderr, read on a thread and polled without blocking the
/// runtime the in-process sessions run on.
struct DemoLines {
    rx: Receiver<String>,
    seen: Vec<String>,
}

impl DemoLines {
    async fn expect(&mut self, needle: &str) -> String {
        if let Some(line) = self.seen.iter().find(|l| l.contains(needle)) {
            return line.clone();
        }
        let until = Instant::now() + DEADLINE;
        loop {
            match self.rx.try_recv() {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(TryRecvError::Empty) => {
                    assert!(
                        Instant::now() < until,
                        "the demo never printed {needle:?}\n--- demo stderr ---\n{}",
                        self.seen.join("\n")
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(TryRecvError::Disconnected) => panic!(
                    "the demo exited before {needle:?}\n--- demo stderr ---\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    fn drain(&mut self) -> String {
        while let Ok(line) = self.rx.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}

/// A TX-only group member: it beacons JOINs (so the demo's group session
/// admits it) and sends what its producer is given. In-process for the reason
/// the library leg gives: its socket needs no membership of its own.
fn group_member(zid_byte: u8) -> (impl std::future::Future<Output = ()>, MulticastTxProducer) {
    let producer = MulticastTxProducer::new();
    let tx = producer.clone();
    let run = async move {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("bind a member's ephemeral socket");
        let mut driver = UdpDriver::from_socket(sock, SocketAddr::from((GROUP, PORT)));
        let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
        let params = MulticastParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: vec![zid_byte; 4],
            lease_ms: 5_000,
            join_interval_ms: 50,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        };
        let clock = TokioTime::new();
        let outcome = drive_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params,
                tick_ms: 10,
                max_iters: None,
            },
            &mut driver,
            &clock,
            |_| {},
            &producer,
        )
        .await;
        panic!("a group member's loop ended: {outcome:?}");
    };
    (run, tx)
}

/// A client session of the test's own to zenohd.
async fn client_to(port: u16, zid_byte: u8) -> OpenedSession {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("dial zenohd");
    initiate_and_open_session(
        DialedLink::Tcp(stream),
        zenoh_interop_session_init_params(WhatAmI::Client, vec![zid_byte; 4]),
        TokioTime::new(),
        None,
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("a test client reaches Established against zenohd")
}

// The subject is the demo's own input and its two sessions, not a behaviour
// graded against zenohd: zenohd is the client session's counterparty.
// wz-proves: none -- one demo process from a sessions file; zenohd only answers its client session
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo with transport-multicast) + multicast on loopback; set WZ_ZENOHD_BIN, run via Layer M / --ignored"]
async fn a_sessions_file_runs_a_zenohd_client_and_a_group_peer_in_one_demo() {
    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);

    let dir = tempfile::tempdir().expect("a directory for the document");
    let doc = dir.path().join("two.json5");
    std::fs::write(
        &doc,
        format!(
            r#"{{
                sessions: [
                    {{ name: "to_router", mode: "client", transport: "unicast", zid: "a1a1",
                       connect: {{ endpoints: ["tcp/127.0.0.1:{zenohd_port}"] }} }},
                    {{ name: "group", mode: "peer", transport: "multicast", zid: "b2b2",
                       group: {{ endpoint: "udp/{GROUP}:{PORT}", join_interval_ms: 100,
                                 lease_ms: 2000 }} }},
                ],
            }}"#
        ),
    )
    .expect("the document is written");

    let mut child = Command::new(&demo)
        .arg("--sessions")
        .arg(&doc)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the demo runs");
    let stderr = child.stderr.take().expect("stderr was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut lines = DemoLines {
        rx,
        seen: Vec::new(),
    };

    // (1) Each session READY on its own line.
    lines
        .expect("wz-ap-demo session to_router: READY client unicast connected to")
        .await;
    lines
        .expect("wz-ap-demo session group: READY peer multicast joined")
        .await;

    // The test's own subscriber (X) and publisher (Y) on zenohd's side.
    let mut x = client_to(zenohd_port, 0x0c).await;
    let mut y = client_to(zenohd_port, 0x0d).await;
    let x_session = TokioSession::new(
        x.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(x.clock),
    );
    let y_session = TokioSession::new(
        y.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(y.clock),
    );
    let control_seen = Arc::new(AtomicUsize::new(0));
    let group_seen = Arc::new(AtomicUsize::new(0));
    let _subscriber = {
        let control_seen = control_seen.clone();
        let group_seen = group_seen.clone();
        x_session.declare_subscriber(SUBSCRIBED, SubscribeOptions::default(), move |sample| {
            match sample.keyexpr() {
                CONTROL_KEY => control_seen.fetch_add(1, Ordering::SeqCst),
                GROUP_KEY => group_seen.fetch_add(1, Ordering::SeqCst),
                other => panic!("an unexpected key on zenohd's side: {other}"),
            };
        })
    };
    let timeouts = SessionTimeouts::spec_defaults();
    let drive_x = drive_session_until_terminal(
        &mut x.inbound,
        &x.actions,
        &mut x.engine,
        None,
        &x.clock,
        &timeouts,
        |event| x_session.dispatch_iteration_event(event),
    );
    let drive_y = drive_session_until_terminal(
        &mut y.inbound,
        &y.actions,
        &mut y.engine,
        None,
        &y.clock,
        &timeouts,
        |event| y_session.dispatch_iteration_event(event),
    );
    let (member_c, producer_c) = group_member(0xcc);

    let scenario = async {
        lines
            .expect("wz-ap-demo session group: peer arrived cccccccc")
            .await;
        // (2) The control: a Put published to zenohd reaches X, so X's
        // subscription is routed (republished until the route installs).
        let until = Instant::now() + DEADLINE;
        while control_seen.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < until, "the control Put never reached X");
            y_session
                .publish(CONTROL_KEY, b"control", PublishOptions::put())
                .expect("Y publishes");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The subject: a group member's Puts, on a key X subscribes to.
        for _ in 0..10 {
            producer_c
                .push(multicast_put_literal(GROUP_KEY, b"in-the-group").expect("put item"))
                .expect("member C's loop has attached its pipeline");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };

    let mut drive_x = Box::pin(drive_x);
    let mut drive_y = Box::pin(drive_y);
    let mut member_c = Box::pin(member_c);
    tokio::select! {
        outcome = &mut drive_x => panic!("X's loop ended: {outcome:?}"),
        outcome = &mut drive_y => panic!("Y's loop ended: {outcome:?}"),
        () = &mut member_c => unreachable!(),
        () = scenario => {}
    }
    assert!(control_seen.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        group_seen.load(Ordering::SeqCst),
        0,
        "a Put sent in the group reached a subscriber on zenohd's side: the two \
         sessions were bridged"
    );

    // (3) The fault is the client session's alone.
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let (member_d, _producer_d) = group_member(0xdd);
    let after = async {
        lines.expect("wz-ap-demo session to_router: ended").await;
        // Member D starts only now, so its admission is work the group session
        // did after its sibling ended.
        tokio::pin!(member_d);
        tokio::select! {
            () = &mut member_d => unreachable!(),
            _ = lines.expect("wz-ap-demo session group: peer arrived dddddddd") => {}
        }
    };
    tokio::select! {
        () = &mut member_c => unreachable!(),
        () = after => {}
    }
    drop(drive_x);
    drop(drive_y);

    // (4) A per-session close.
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status_bounded()
        .expect("kill runs");
    assert!(status.success());
    let until = Instant::now() + DEADLINE;
    let exit = loop {
        if let Some(exit) = child.try_wait().expect("wait") {
            break exit;
        }
        assert!(Instant::now() < until, "the demo did not exit on SIGTERM");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let transcript = lines.drain();
    assert!(exit.success(), "exit {exit:?}\n{transcript}");
    assert!(
        transcript.contains("wz-ap-demo session group: closed"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("wz-ap-demo session to_router: closed"),
        "{transcript}"
    );
    assert!(
        transcript.contains("wz-ap-demo sessions: all 2 session(s) ended"),
        "{transcript}"
    );
}
