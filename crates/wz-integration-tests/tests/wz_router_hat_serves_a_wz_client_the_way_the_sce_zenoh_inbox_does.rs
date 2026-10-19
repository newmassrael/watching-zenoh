// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A wz CLIENT doing, against a wz `--router-hat` router, what SCE Mesh's Zenoh binding asks of a
//! client session (`SCE_MESH.md` section 20, the `zenoh_inbox` transport), so that the client of
//! that binding can be this tree's and not upstream's.
//!
//! ## What the binding asks of a client
//!
//! One session to a router, and on it, per machine `R`:
//!
//! 1. a liveliness token on `sce-mesh/1/up/R`, which is how the others learn `R` is up;
//! 2. a subscriber on `sce-mesh/1/to/R/*`, which is `R`'s inbox;
//! 3. a liveliness subscriber on `sce-mesh/1/up/*` WITH HISTORY, so a machine that opens after
//!    another still learns it is up;
//! 4. a put on `sce-mesh/1/to/<peer>/R`, which is how an envelope reaches a peer.
//!
//! and it learns a machine is gone from that machine's token ending.
//!
//! ## What this holds
//!
//! The demo in its `--sessions` mode is a wz client: each entry is a session with roles, and the
//! roles `liveliness_token`, `subscribe`, `liveliness_subscribe` and `put` are exactly the four
//! operations above. Three arms, each read from what a client printed and not from the router's
//! own log:
//!
//! - **a put reaches the inbox, and a token appearing is seen**: a hub is up with all three of its
//!   declarations; a second machine comes up after it, and the hub sees its token appear and
//!   receives what the machine puts under the hub's inbox, with the sender's name as the key's
//!   last chunk (section 20.1).
//! - **history, with its control**: a token that existed before a subscriber's session did is
//!   replayed to a subscriber that asked for history, and is NOT shown to one that did not. Without
//!   the second half the first could be a router that pushes every token to everyone.
//! - **a machine that goes is reported**: the process holding a machine's token is killed, and the
//!   hub's liveliness subscriber prints the token as ended.
//!
//! A fourth test does the same four things with no demo process as the client: it opens the
//! sessions with the library calls the demo's own sessions mode makes (`dial_endpoint`,
//! `initiate_and_open_session`, `TokioSession`, `drive_session_until_terminal`) and puts with
//! `Block`, which no `--sessions` role can ask for. That is what an adapter linked into an app
//! would be doing, and it reads the congestion control the router forwarded off the received
//! sample, so a put that dropped the option would fail it.
//!
//! Four more tests run `wz-mesh-client`, the crate that is that adapter, through the kit SCE
//! publishes for the clients of its Zenoh binding (`sce_rust_mesh::conformance`): two machines
//! meeting through a router and one reaching the other's engine, a machine that goes away being
//! told as lost, the offline catch-up of a shared list, and the first of those across two
//! federated routers. They are the same functions upstream's client is run through in the SCE
//! repository, so that this client does what that one does is a test and not a claim. Each runs
//! on a router of its own, because the kit's machines carry fixed names.
//!
//! ## What it does not hold
//!
//! A reconnecting client, or a mobile build: `wz-mesh-client` ends with its session, and nothing
//! here builds it for Android or iOS.
//!
//! Opt-in (`#[ignore]`): it needs the demo built with `preset-ap-client`, `router-hat-router` and
//! `routing-token-tables`:
//!
//! ```text
//! cargo build -p wz-ap-demo --no-default-features \
//!     --features preset-ap-client,router-hat-router,routing-token-tables
//! cargo test -p wz-integration-tests --test wz_router_hat_serves_a_wz_client_the_way_the_sce_zenoh_inbox_does \
//!     -- --ignored --nocapture
//! ```
//!
//! Every test fn name carries `wz_router_hat_`, because Layer E's default sweep skips by the TEST
//! name (`--skip wz_router`) and not by the file's, and this file needs a demo built as a router
//! that Layer E's does not build; Layer E7m runs it. No claim here is a timing claim: every wait
//! has a generous bound and the assertions are on what was printed.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sce_rust_mesh::conformance::{self, Harness};
use sce_rust_mesh::inbox::ZenohClient;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, project_root, ChildGuard,
};
use wz_mesh_client::WzClient;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriberOptions, PublishOptions, SubscribeOptions, TokioSession,
};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, WhatAmI};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::qos::CongestionControl;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::SampleView;

/// How long to wait for something that must happen.
const WITHIN: Duration = Duration::from_secs(30);
/// How long to wait to see that something does NOT happen. It is a window and not a proof, and the
/// arm that uses it says so.
const QUIET: Duration = Duration::from_secs(4);

fn demo_binary() -> PathBuf {
    let demo = std::env::var_os("WZ_AP_DEMO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| project_root().join("crates/target/debug/wz-ap-demo"));
    assert!(
        demo.is_file(),
        "{} not found; build it as the header of this file says, or name it in WZ_AP_DEMO_BIN",
        demo.display()
    );
    demo
}

/// The lines a process has written to its stderr, kept as they arrive.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl Lines {
    fn push(&self, line: String) {
        self.0.lock().expect("the lines lock").push(line);
    }

    fn contains(&self, needle: &str) -> bool {
        self.0
            .lock()
            .expect("the lines lock")
            .iter()
            .any(|line| line.contains(needle))
    }

    fn all(&self) -> Vec<String> {
        self.0.lock().expect("the lines lock").clone()
    }

    /// Whether a line holding every one of `needles` has been written, within `within`.
    fn wait_for(&self, needles: &[&str], within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self
                .0
                .lock()
                .expect("the lines lock")
                .iter()
                .any(|line| needles.iter().all(|n| line.contains(n)))
            {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn holds(&self, needles: &[&str]) -> bool {
        self.0
            .lock()
            .expect("the lines lock")
            .iter()
            .any(|line| needles.iter().all(|n| line.contains(n)))
    }
}

/// A process of the demo with its stderr read into `lines`.
struct Node {
    guard: ChildGuard,
    lines: Lines,
}

impl Node {
    /// End the process without letting it say goodbye: its links close the way a crashed device's do.
    fn kill(&mut self) {
        let child = self.guard.child_mut();
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Freeze the process where it stands (SIGSTOP): its sockets stay open and it reads nothing
    /// more, which is a peer that has stopped taking what it is sent, not one that has gone.
    fn freeze(&mut self) {
        // SAFETY: a signal sent to a child this struct owns, whose pid is still ours until waited.
        unsafe { libc::kill(self.guard.child_mut().id() as libc::pid_t, libc::SIGSTOP) };
    }

    /// Let a frozen process run again (SIGCONT).
    fn thaw(&mut self) {
        // SAFETY: as in `freeze`.
        unsafe { libc::kill(self.guard.child_mut().id() as libc::pid_t, libc::SIGCONT) };
    }
}

fn spawn(demo: &Path, label: &str, args: &[&str]) -> Node {
    let mut child = Command::new(demo)
        .args(args)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{label} starts: {e}"));
    let stderr = child.stderr.take().expect("stderr is piped");
    let lines = Lines::default();
    {
        let lines = lines.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                lines.push(line);
            }
        });
    }
    Node {
        guard: ChildGuard::wrap(label.to_string(), child),
        lines,
    }
}

fn listening_port(line: &str) -> Option<u16> {
    let rest = line.split("listening on 127.0.0.1:").nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn start_router(demo: &Path) -> (Node, u16) {
    start_router_federated(demo, None)
}

/// A router, joined to the router listening on `connect_to` when one is named.
fn start_router_federated(demo: &Path, connect_to: Option<u16>) -> (Node, u16) {
    let connect = connect_to.map(|port| format!("127.0.0.1:{port}"));
    let mut args = vec!["--router-hat", "127.0.0.1:0"];
    if let Some(connect) = &connect {
        args.extend(["--connect", connect.as_str()]);
    }
    let node = spawn(demo, "wz-ap-demo router-hat", &args);
    let deadline = Instant::now() + WITHIN;
    let mut banner = String::new();
    loop {
        for line in node.lines.all() {
            if line.contains("BUILD FEATURES =") {
                banner = line.clone();
            }
            if let Some(port) = listening_port(&line) {
                for needed in ["router-hat-router", "routing-token-tables"] {
                    assert!(
                        banner.contains(needed),
                        "the demo was not built with `{needed}`: {banner}"
                    );
                }
                return (node, port);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the router did not say which port it listens on"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// A `--sessions` file for one machine: one wz client session with `driver` as its roles.
fn machine_document(name: &str, zid: u32, port: u16, driver: &str) -> String {
    format!(
        "{{ sessions: [ {{ name: \"{name}\", mode: \"client\", transport: \"unicast\", zid: \"{zid:x}\",\n\
         \x20 connect: {{ endpoints: [\"tcp/127.0.0.1:{port}\"] }},\n\
         \x20 driver: [ {driver} ] }} ] }}\n"
    )
}

/// Start the machine `name` on the router at `port`, with the files kept under `dir`.
fn start_machine(demo: &Path, dir: &Path, name: &str, zid: u32, port: u16, driver: &str) -> Node {
    let file = dir.join(format!("{name}.json5"));
    let mut out = fs::File::create(&file).expect("the sessions file is written");
    out.write_all(machine_document(name, zid, port, driver).as_bytes())
        .expect("the sessions file is written");
    spawn(
        demo,
        &format!("wz-ap-demo machine {name}"),
        &["--sessions", file.to_str().expect("a UTF-8 path")],
    )
}

/// The roles that declare a machine the way the binding does: its presence token and its inbox.
fn presence_and_inbox(name: &str) -> String {
    format!(
        "{{ role: \"liveliness_token\", key: \"sce-mesh/1/up/{name}\" }}, \
         {{ role: \"subscribe\", key: \"sce-mesh/1/to/{name}/*\" }}"
    )
}

/// What a machine that learns of the others declares: every presence, with history.
const SEES_EVERYONE_WITH_HISTORY: &str =
    "{ role: \"liveliness_subscribe\", key: \"sce-mesh/1/up/*\", history: true }";

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wz-sce-inbox-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_delivers_a_put_to_the_inbox_and_shows_a_token_appearing() {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let dir = scratch("put");
    let (_router, port) = start_router(&demo);

    let hub = start_machine(
        &demo,
        &dir,
        "hub",
        0x1000,
        port,
        &format!(
            "{}, {SEES_EVERYONE_WITH_HISTORY}",
            presence_and_inbox("hub")
        ),
    );
    assert!(
        hub.lines.wait_for(&["DRIVER subscribe declared"], WITHIN),
        "the hub declared its inbox: {:#?}",
        hub.lines.all()
    );

    // alice comes up after the hub, declares herself, and puts under the hub's inbox with her own
    // name as the last chunk. The put waits for her session so that it is not sent into nothing.
    let _alice = start_machine(
        &demo,
        &dir,
        "alice",
        0x2000,
        port,
        &format!(
            "{}, {{ role: \"put\", key: \"sce-mesh/1/to/hub/alice\", payload: \"note-1\", after_ms: 1500 }}",
            presence_and_inbox("alice")
        ),
    );

    assert!(
        hub.lines
            .wait_for(&["sample key=sce-mesh/1/up/alice", "kind=Put"], WITHIN),
        "the hub saw alice's token appear: {:#?}",
        hub.lines.all()
    );
    assert!(
        hub.lines
            .wait_for(&["sample key=sce-mesh/1/to/hub/alice", "bytes=6"], WITHIN),
        "the hub received alice's put in its inbox: {:#?}",
        hub.lines.all()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_replays_a_token_that_was_there_first_only_to_a_subscriber_that_asked() {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let dir = scratch("history");
    let (_router, port) = start_router(&demo);

    // bob is up, and has been, before either subscriber's session exists.
    let bob = start_machine(
        &demo,
        &dir,
        "bob",
        0x3000,
        port,
        "{ role: \"liveliness_token\", key: \"sce-mesh/1/up/bob\" }",
    );
    assert!(
        bob.lines
            .wait_for(&["DRIVER liveliness_token declared"], WITHIN),
        "bob declared his token: {:#?}",
        bob.lines.all()
    );
    // Let the router take the token in before anyone asks about it.
    thread::sleep(Duration::from_secs(1));

    let without = start_machine(
        &demo,
        &dir,
        "without",
        0x4000,
        port,
        "{ role: \"liveliness_subscribe\", key: \"sce-mesh/1/up/*\" }",
    );
    let with = start_machine(
        &demo,
        &dir,
        "with",
        0x5000,
        port,
        SEES_EVERYONE_WITH_HISTORY,
    );

    assert!(
        with.lines
            .wait_for(&["sample key=sce-mesh/1/up/bob", "kind=Put"], WITHIN),
        "the subscriber that asked for history was shown the token that was there first: {:#?}",
        with.lines.all()
    );

    // The control. It is a window and not a proof of absence, and the half that makes the first
    // half mean something: a router that told every subscriber about every token would pass the
    // assertion above too.
    thread::sleep(QUIET);
    assert!(
        !without
            .lines
            .holds(&["sample key=sce-mesh/1/up/bob", "kind=Put"]),
        "the subscriber that did not ask for history was shown a token that was there before it: {:#?}",
        without.lines.all()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_reports_a_machine_that_goes_by_its_token_ending() {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let dir = scratch("gone");
    let (_router, port) = start_router(&demo);

    let hub = start_machine(&demo, &dir, "hub", 0x6000, port, SEES_EVERYONE_WITH_HISTORY);
    assert!(
        hub.lines.wait_for(&["DRIVER liveliness_subscribe"], WITHIN),
        "the hub's presence subscriber is up: {:#?}",
        hub.lines.all()
    );
    let mut carol = start_machine(
        &demo,
        &dir,
        "carol",
        0x7000,
        port,
        "{ role: \"liveliness_token\", key: \"sce-mesh/1/up/carol\" }",
    );
    assert!(
        hub.lines
            .wait_for(&["sample key=sce-mesh/1/up/carol", "kind=Put"], WITHIN),
        "the hub saw carol's token appear: {:#?}",
        hub.lines.all()
    );
    assert!(
        !hub.lines
            .contains("sample key=sce-mesh/1/up/carol kind=Del"),
        "the token had not ended yet"
    );

    // carol's process ends without a goodbye, as a crashed device's does.
    carol.kill();
    assert!(
        hub.lines
            .wait_for(&["sample key=sce-mesh/1/up/carol", "kind=Del"], WITHIN),
        "the hub was told carol's token ended: {:#?}",
        hub.lines.all()
    );
    let _ = fs::remove_dir_all(&dir);
}

/// What a machine's session printed, as `kind key` lines: the library has no stderr to read, so the
/// callbacks write here.
type Seen = Arc<Mutex<Vec<String>>>;

fn seen_has(seen: &Seen, needle: &str) -> bool {
    seen.lock()
        .expect("the seen lock")
        .iter()
        .any(|line| line.contains(needle))
}

async fn seen_within(seen: &Seen, needle: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if seen_has(seen, needle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// A client session opened with the calls the demo's sessions mode makes, and driven on this
/// `LocalSet` until the returned handle is aborted. Aborting drops the connection, which is how a
/// machine that goes away looks to the router.
async fn open_as_a_library(port: u16, zid_byte: u8) -> (TokioSession, tokio::task::JoinHandle<()>) {
    let link = dial_endpoint(&format!("tcp/127.0.0.1:{port}"), &DialConfig::default())
        .await
        .expect("the router is dialled");
    let params = zenoh_interop_session_init_params(WhatAmI::Client, vec![0x5c, 0xe0, zid_byte]);
    let mut opened =
        initiate_and_open_session(link, params, TokioTime::new(), None, DEFAULT_OPEN_TICK_MS)
            .await
            .expect("the session opens");
    let observer = Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
        ApplicationLayerObserver::new(),
    ));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let driven = session.clone();
    let drive = tokio::task::spawn_local(async move {
        let timeouts = SessionTimeouts::spec_defaults();
        let _ = drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            |event| driven.dispatch_iteration_event(event),
        )
        .await;
    });
    (session, drive)
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_serves_a_wz_session_driven_as_a_library_the_way_the_binding_does() {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (_router, port) = start_router(&demo);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        // The hub declares itself the way the binding does: its inbox first, then its presence, then
        // the subscriber that learns of the others, with history.
        let (hub, _hub_drive) = open_as_a_library(port, 1).await;
        let hub_seen: Seen = Seen::default();
        let inbox_seen = Arc::clone(&hub_seen);
        let _inbox = hub
            .declare_subscriber(
                "sce-mesh/1/to/hub/*",
                SubscribeOptions::default(),
                move |sample: &dyn SampleView| {
                    let congestion = sample
                        .qos()
                        .map(|qos| format!("{:?}", qos.congestion()))
                        .unwrap_or_else(|| "none".to_string());
                    inbox_seen.lock().expect("the seen lock").push(format!(
                        "inbox {} bytes={} congestion={congestion}",
                        sample.keyexpr(),
                        sample.payload().len()
                    ));
                },
            )
            .expect("the inbox is declared");
        let _hub_token = hub
            .declare_token("sce-mesh/1/up/hub", LivelinessOptions::default())
            .expect("the hub's presence is declared");
        let presence_seen = Arc::clone(&hub_seen);
        let _presence = hub
            .declare_liveliness_subscriber(
                "sce-mesh/1/up/*",
                LivelinessSubscriberOptions::default().with_history(true),
                move |sample| {
                    presence_seen
                        .lock()
                        .expect("the seen lock")
                        .push(format!("presence {} {:?}", sample.keyexpr, sample.kind));
                },
            )
            .expect("the presence subscriber is declared");

        // alice comes up after the hub, declares herself, and waits until the hub's presence is
        // there before she puts, as the binding's readiness edge makes a machine do.
        let (alice, alice_drive) = open_as_a_library(port, 2).await;
        let alice_seen: Seen = Seen::default();
        let alice_presence = Arc::clone(&alice_seen);
        let _alice_token = alice
            .declare_token("sce-mesh/1/up/alice", LivelinessOptions::default())
            .expect("alice's presence is declared");
        let _alice_learns = alice
            .declare_liveliness_subscriber(
                "sce-mesh/1/up/*",
                LivelinessSubscriberOptions::default().with_history(true),
                move |sample| {
                    alice_presence
                        .lock()
                        .expect("the seen lock")
                        .push(format!("presence {} {:?}", sample.keyexpr, sample.kind));
                },
            )
            .expect("alice's presence subscriber is declared");

        assert!(
            seen_within(&alice_seen, "presence sce-mesh/1/up/hub Put", WITHIN).await,
            "alice learned the hub is up, by history: {:#?}",
            alice_seen.lock().expect("the seen lock")
        );
        assert!(
            seen_within(&hub_seen, "presence sce-mesh/1/up/alice Put", WITHIN).await,
            "the hub learned alice is up: {:#?}",
            hub_seen.lock().expect("the seen lock")
        );

        // The put the binding makes: Block, so a router's congestion is waited out and the core is
        // not left waiting for an envelope the network dropped (SCE_MESH section 20.2).
        alice
            .publish(
                "sce-mesh/1/to/hub/alice",
                b"note-1",
                PublishOptions::put().with_congestion_control(CongestionControl::Block),
            )
            .expect("the put is sent");
        assert!(
            seen_within(
                &hub_seen,
                "inbox sce-mesh/1/to/hub/alice bytes=6 congestion=Block",
                WITHIN
            )
            .await,
            "the hub received the put with the congestion control it was sent with: {:#?}",
            hub_seen.lock().expect("the seen lock")
        );

        // alice's connection drops, and the hub is told her presence ended.
        alice_drive.abort();
        drop(_alice_learns);
        drop(_alice_token);
        drop(alice);
        assert!(
            seen_within(&hub_seen, "presence sce-mesh/1/up/alice Delete", WITHIN).await,
            "the hub was told alice's presence ended: {:#?}",
            hub_seen.lock().expect("the seen lock")
        );
    });
}

/// The kit's harness for the wz client: each machine opens a session of its own to the router at
/// `port`.
struct WzHarness {
    port: u16,
}

impl Harness for WzHarness {
    type Client = WzClient;

    fn connect(&self) -> WzClient {
        WzClient::connect(&[&format!("tcp/127.0.0.1:{}", self.port)])
            .expect("the wz client connects to the router")
    }
}

/// A router, and the demo it came from, checked once for the build the kit needs.
fn a_router() -> (Node, u16) {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    start_router(&demo)
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_lets_two_wz_clients_meet_and_reach_each_others_engine() {
    let (_router, port) = a_router();
    conformance::two_machines_meet(&WzHarness { port });
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_reports_a_wz_client_that_went_away_as_lost() {
    let (_router, port) = a_router();
    conformance::a_machine_that_goes_away_is_told_as_lost(&WzHarness { port });
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_catches_a_wz_client_device_up_from_a_hub_that_stayed_up() {
    let (_router, port) = a_router();
    conformance::a_device_that_was_away_catches_up_from_a_hub_that_stayed_up(&WzHarness { port });
}

/// What the kit cannot see: the congestion control a put LEAVES with. A machine receives only the
/// bytes and the key, so a client that put with the default (drop) would pass every function of the
/// kit; the binding asks for Block (SCE_MESH.md section 20.2), and the one place it shows is the
/// QoS the router forwards with the sample. So the receiver here is a raw wz session, which can read
/// it, and the sender is `WzClient` through the trait.
#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_forwards_a_wz_client_put_with_block_congestion_control() {
    let (_router, port) = a_router();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let (receiver, _drive) = open_as_a_library(port, 9).await;
        let seen: Seen = Seen::default();
        let sink = Arc::clone(&seen);
        let _inbox = receiver
            .declare_subscriber(
                "sce-mesh/1/to/hub/*",
                SubscribeOptions::default(),
                move |sample: &dyn SampleView| {
                    let congestion = sample
                        .qos()
                        .map(|qos| format!("{:?}", qos.congestion()))
                        .unwrap_or_else(|| "none".to_string());
                    sink.lock().expect("the seen lock").push(format!(
                        "inbox {} congestion={congestion}",
                        sample.keyexpr()
                    ));
                },
            )
            .expect("the inbox is declared");

        // The client blocks its caller, so it lives on a blocking thread and this runtime keeps
        // driving the receiver. The route has to reach the router before a put can be delivered,
        // so the put is repeated until one arrives; every one carries the same options.
        let mut client = tokio::task::spawn_blocking(move || {
            WzClient::connect(&[&format!("tcp/127.0.0.1:{port}")])
                .expect("the wz client connects to the router")
        })
        .await
        .expect("the connect task ends");
        let deadline = Instant::now() + WITHIN;
        let mut arrived = false;
        while Instant::now() < deadline && !arrived {
            let (back, put) = tokio::task::spawn_blocking(move || {
                let put = client.put("sce-mesh/1/to/hub/alice", b"note-1");
                (client, put)
            })
            .await
            .expect("the put task ends");
            client = back;
            put.expect("the put is accepted");
            arrived = seen_within(
                &seen,
                "inbox sce-mesh/1/to/hub/alice congestion=Block",
                Duration::from_millis(500),
            )
            .await;
        }
        assert!(
            arrived,
            "the put left with Block congestion control: {:#?}",
            seen.lock().expect("the seen lock")
        );
        drop(client);
    });
}

/// What a put does when the peer has stopped taking what it is sent. The binding puts with `Block`,
/// which waits for room instead of dropping, and a wz session waits at most `wait_before_close`
/// (5 seconds by upstream's default) before it gives the peer up as unresponsive and closes the
/// session. `WzClient` runs the session and its callers' puts on one thread, so three things are
/// held here, each of which a client could get wrong:
///
/// - the wait ENDS, and is not reported as success: the put that waited its whole room answers
///   with a retryable error that says there was no room (a wz publish answers `Ok` there, as
///   upstream's does, and the client turns that into the refusal the binding asks for, section
///   20.2 of SCE_MESH.md: an envelope that was not placed is not reported as sent);
/// - the session closing is not starved by callers: no later put waits its room again, so at most
///   one put waits the full time, whatever the callers send next;
/// - dropping the client returns.
///
/// The writer that drains the queue lives on wz's own transmit runtime and not on the session's
/// thread, which is what makes the wait a wait and not a deadlock.
///
/// A router that is frozen after the client has connected is the peer. The payloads are large
/// enough to fill the kernel's socket buffers and then the session's queue. Before the client
/// judged a put by its wait, this test saw puts #40 to #42 answer `Ok` after exactly 5 seconds each
/// and the session end only on the fourth, and in another run no end within a minute.
#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_that_stops_reading_makes_a_wz_client_put_end_in_an_error_and_not_hang() {
    let (mut router, port) = a_router();
    let mut client = WzClient::connect(&[&format!("tcp/127.0.0.1:{port}")])
        .expect("the wz client connects to the router");
    // The route is not needed: a put to a key nobody subscribes still goes to the router, which
    // is what has to take it.
    let payload = vec![0xA5u8; 64 * 1024];
    router.freeze();

    // Fill the buffers and the queue. The bound on the whole loop is the point: a put that blocks
    // for good would never leave it.
    let started = Instant::now();
    let mut first_error = None;
    let mut accepted = 0usize;
    while first_error.is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "a put to a peer that stopped reading did not end within a minute after {accepted} puts"
        );
        let put_started = Instant::now();
        match client.put("sce-mesh/1/to/hub/alice", &payload) {
            Ok(()) => {
                assert!(
                    put_started.elapsed() < Duration::from_secs(5),
                    "put #{} waited {:?} for room and was reported as sent",
                    accepted + 1,
                    put_started.elapsed()
                );
                accepted += 1;
            }
            Err(error) => first_error = Some((error, put_started.elapsed())),
        }
    }
    let (error, waited) = first_error.expect("the loop ends on an error");
    eprintln!(
        "{accepted} puts of 64 KiB were taken, then one was refused after {waited:?}: {:?}",
        error.message
    );
    assert!(accepted > 0, "not even the first put was taken: {error}");
    assert!(
        error.retryable && error.message.contains("no room"),
        "the refusal says there was no room, and that sending again may work: {error:?}"
    );
    assert!(
        waited >= Duration::from_secs(5),
        "it was refused after {waited:?}, before the whole room was waited for"
    );

    // The session is closing, so a later put does not wait its room again: it is refused within the
    // time a close takes, which is the router's silence being given up on, not another 5 seconds
    // per put.
    let again_started = Instant::now();
    let again = client
        .put("sce-mesh/1/to/hub/alice", &payload)
        .expect_err("a put on a closing session is refused");
    assert!(
        again_started.elapsed() < Duration::from_secs(10),
        "a put after the room was given up waited {:?}: {again}",
        again_started.elapsed()
    );

    // Dropping the client joins its thread, and that returns.
    let dropped = Instant::now();
    drop(client);
    assert!(
        dropped.elapsed() < Duration::from_secs(30),
        "dropping the client took {:?}",
        dropped.elapsed()
    );
    router.thaw();
}

#[test]
#[ignore = "opt-in: needs wz-ap-demo built with preset-ap-client, router-hat-router and routing-token-tables"]
fn wz_router_hat_meets_wz_clients_across_two_federated_routers() {
    let demo = demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (_first, first_port) = start_router(&demo);
    let (_second, second_port) = start_router_federated(&demo, Some(first_port));
    conformance::two_machines_meet_across(
        &WzHarness { port: first_port },
        &WzHarness { port: second_port },
    );
}
