// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A lifecycle command SEALED by its commander's key (decision D17 of
//! `docs/session-lifecycle-intent.md`, the format `docs/command-seal.md`), carried end to end
//! through a stock zenohd whose own key no grant names, to the hosts both profiles ship.
//!
//! The router dials the node over mutual TLS with a key of its own, so the link proves the router
//! and no grant names it: a verb the router forwards with no attachment is the router's, and is
//! refused. The commander is a wz client of the router, since stock zenoh's `z_get` sends no
//! attachment: it opens a session in this process, seals each command with `wz_command_seal::seal`
//! and a `RingSigner` over a P-256 key the test makes, and sends it as the attachment of the
//! lifecycle GET. The node verifies the object, holds it to the request its key names and to the
//! commander's counter, and judges the commander the object's key proves.
//!
//! The fixed profile's node is `slot-commander` (`deploy/nodes/slot-commander.toml`) built as a
//! consumer builds one (`wz_package.py --node-file`), granting `status` and `close` to the
//! commander's zid and provisioned with an identity the test makes, so its zid outlives a restart.
//! Its record of decisions is read off its console (`HOST-WZ-DECISION`). The legs:
//!
//! - a listed commander's sealed `status` and `close` are permitted, after the echo a node that has
//!   just started asks of a commander it holds no counter for, and the record names the subject
//!   `sealed:<zid>`, beside the router's own query, refused as `verified:<router>`;
//! - the same object sent again is refused as a replay, with the commander's last counter;
//! - an object sealed by a key no list names verifies and is refused by the lists, and takes no
//!   counter: sent again it is refused by the lists again, not as a replay;
//! - after the node restarts, a command sealed before is refused with a new echo, a command
//!   carrying the echo of the last start is refused the same way, and the repeat carrying the new
//!   echo is permitted.
//!
//! The heap profile's node is `wz-ap-demo --peer`, hosting the lifecycle queries with the grants of
//! a node declaration that names the commander, dialled by the same router over mutual TLS: the
//! first three legs again, the record read off the process's log
//! (`lifecycle monitor: permit Status by sealed:<zid>`).
//!
//! Requires python3, cargo (the fixed node is built when its first leg runs), the reference zenohd
//! (`scripts/build-zenohd.sh`) and, for the heap legs, `wz-ap-demo` built with
//! `routing-peer,session-close-ingress,tls`. The fixed node's locators are fixed, so the legs run
//! one at a time (`--test-threads=1`). Runs on the `--ignored` lane; the file's `zenohd` token
//! keeps Layer E's sweep off it.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use wz_command_seal::{
    seal, zid_of_point, Echo, Es256Signer, Object, RingSigner, Verb, Zid, ECHO_LEN, MAX_SEALED_LEN,
};
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured, wait_for_substring,
    wait_for_tcp_accept, wz_ap_demo_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, WhatAmI};
use wz_runtime_tokio::session_open::{connect_and_open_session, DialConfig, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio_test_support::{key_named_identity, zenoh_interop_session_init_params};
use wz_session_core::credential_identity::zid_from_spki_der;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

use super::wz_declared_commander_zenohd_interop::{
    config_id, dialling_router, package, repo_root, Node, Party, BUDGET, CLOSE_ZID, DECLARATION,
    LISTENER, LISTENING, STATUS_REFUSED, STATUS_ZID, VERIFIED,
};

/// The peer every command names. Neither node holds it, so a permitted `status` reads no link and
/// a permitted `close` finds nothing to close.
const PEER: &str = "d4";
/// What a node answers a sealed command with when it holds no counter for its commander and the
/// command carries no echo of this start (`wz_session_core::sealed_command::SealRefused`).
const ECHO_REQUIRED: &str = "the sealed command must carry this node's echo";
/// What a node answers a sealed command whose counter it took before.
const REPLAY: &str = "the counter of the sealed command is not above its commander's last";
/// How long the commander waits for the replies to one query.
const QUERY_WAIT: Duration = Duration::from_secs(10);
/// How many inbound polls the commander's open may take.
const OPEN_ITERATIONS: usize = 4096;

/// A zid as a lifecycle key spells it.
fn zid_text(zid: &Zid) -> String {
    config_id(zid)
}

/// The zid a lifecycle key spells as `text`.
fn zid_of(text: &str) -> Zid {
    u128::from_str_radix(text, 16)
        .unwrap_or_else(|_| panic!("{text} is not a zid"))
        .to_le_bytes()
}

/// The DER a PKCS#8 PEM holds.
fn pkcs8_of_pem(pem: &str) -> Vec<u8> {
    let body = pem
        .split_once("-----BEGIN PRIVATE KEY-----")
        .and_then(|(_, after)| after.split_once("-----END PRIVATE KEY-----"))
        .map(|(body, _)| body.split_whitespace().collect::<String>())
        .expect("a PKCS#8 PEM");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("the PEM body is base64")
}

/// A commander: a P-256 key the test makes, the signer over it and the zid it names.
struct Commander {
    signer: RingSigner,
    zid: String,
}

impl Commander {
    /// A new key, held to the rule that the zid a sealed command proves is the zid the same key
    /// proves on a link (decision D1).
    fn new() -> Self {
        let made = key_named_identity();
        let signer =
            RingSigner::from_pkcs8(&pkcs8_of_pem(&made.key_pem)).expect("a P-256 PKCS#8 key");
        let zid = zid_text(&zid_from_spki_der(&made.spki_der));
        assert_eq!(
            zid,
            zid_text(&zid_of_point(&signer.point())),
            "the zid of the object's key is not the zid the same key proves on a link"
        );
        Self { signer, zid }
    }

    /// `verb` of [`PEER`] at the node `node`, under `counter`, carrying `echo`, sealed.
    fn seal(&self, verb: Verb, node: &str, counter: u64, echo: Option<Echo>) -> Vec<u8> {
        let command = wz_command_seal::Command {
            verb,
            node: zid_of(node),
            object: Object {
                peer: zid_of(PEER),
                generation: None,
            },
            counter,
            echo,
        };
        let mut out = [0u8; MAX_SEALED_LEN];
        let len = seal(&command, &self.signer, &mut out).expect("the command seals");
        out.get(..len).expect("the sealed length").to_vec()
    }
}

/// The echo a refusal hands out (`"echo":"<32 hex digits>"`), when it hands one out.
fn echo_in(reply: &str) -> Option<Echo> {
    let (_, rest) = reply.split_once("\"echo\":\"")?;
    let hex = rest.get(..ECHO_LEN * 2)?;
    let mut echo = [0u8; ECHO_LEN];
    for (at, byte) in echo.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * at..2 * at + 2)?, 16).ok()?;
    }
    Some(echo)
}

/// The zid each session of the commander claims: one per session, so the router never holds two
/// sessions that claim one zid.
static CLIENT_SESSIONS: AtomicU8 = AtomicU8::new(0);

/// The way to a node through the router: the port the router takes clients on, and the node's
/// zid and role as its lifecycle keys spell them.
struct Way {
    port: u16,
    node: String,
    whatami: &'static str,
}

impl Way {
    /// The key the node answers `verb` about [`PEER`] under.
    fn key(&self, verb: &str) -> String {
        format!("@/{}/{}/session/{verb}/{PEER}", self.node, self.whatami)
    }

    /// Every reply to `verb`, asked by a wz client of the router carrying `attachment`.
    async fn replies(&self, verb: &str, attachment: Option<&[u8]>) -> Vec<String> {
        ask_through(self.port, &self.key(verb), attachment).await
    }

    /// The one reply to `verb` carrying `attachment`, or a panic that says what came instead.
    async fn ask(&self, verb: &str, attachment: Option<&[u8]>) -> String {
        let replies = self.replies(verb, attachment).await;
        match replies.as_slice() {
            [one] => one.clone(),
            _ => panic!("{verb}: expected one reply, got {replies:?}"),
        }
    }

    /// Ask the router's own `status` until the node's queryable is routed to: the reply, which is
    /// the router's, since the query carries no sealed command.
    async fn routed(&self) -> String {
        let deadline = Instant::now() + BUDGET;
        loop {
            if let [one] = self.replies("status", None).await.as_slice() {
                return one.clone();
            }
            assert!(
                Instant::now() < deadline,
                "the router routed no lifecycle query to the node within {BUDGET:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// `commander`'s `verb` under `counter` with no echo, which a node that holds no counter for it
    /// refuses with the echo of its start, and then under `counter + 1` carrying that echo: the
    /// reply to the repeat, the bytes it was, and the echo.
    async fn after_the_echo(
        &self,
        commander: &Commander,
        verb: Verb,
        counter: u64,
    ) -> (String, Vec<u8>, Echo) {
        let word = verb.word();
        let first = self
            .ask(word, Some(&commander.seal(verb, &self.node, counter, None)))
            .await;
        assert!(
            first.contains(ECHO_REQUIRED),
            "a commander the node holds no counter for was not asked for the echo: {first}"
        );
        let echo =
            echo_in(&first).unwrap_or_else(|| panic!("the challenge carries no echo: {first}"));
        let repeat = commander.seal(verb, &self.node, counter + 1, Some(echo));
        let reply = self.ask(word, Some(&repeat)).await;
        (reply, repeat, echo)
    }
}

/// Ask `key` of the router listening on `port` from a wz client session opened for the one query,
/// carrying `attachment`, and hand back the payload of every reply, as text.
async fn ask_through(port: u16, key: &str, attachment: Option<&[u8]>) -> Vec<String> {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("a locator");
    let nth = CLIENT_SESSIONS.fetch_add(1, Ordering::SeqCst);
    let params = zenoh_interop_session_init_params(WhatAmI::Client, [0x5e, 0xa1, 0xed, nth | 0x80]);
    let mut opened = connect_and_open_session(
        locator,
        params,
        &DialConfig::default(),
        TokioTime::new(),
        Some(OPEN_ITERATIONS),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .unwrap_or_else(|e| panic!("the commander's session with zenohd did not open: {e:?}"));
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
            ApplicationLayerObserver::new(),
        )),
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
    let (replied, mut replies) = tokio::sync::mpsc::unbounded_channel();
    let (ended, mut finals) = tokio::sync::mpsc::unbounded_channel();
    let mut options = QueryOptions::get();
    if let Some(bytes) = attachment {
        options = options.with_attachment(bytes.to_vec());
    }
    let asked = async {
        session
            .query(
                key,
                options,
                move |reply: &dyn wz_session_core::reply_sink::ReplyView| {
                    let _ = replied.send(String::from_utf8_lossy(reply.payload()).into_owned());
                },
                move |_| {
                    let _ = ended.send(());
                },
            )
            .unwrap_or_else(|e| panic!("the commander could not send its query: {e:?}"));
        let _ = tokio::time::timeout(QUERY_WAIT, finals.recv()).await;
    };
    tokio::select! {
        outcome = drive => panic!("the commander's session ended before its query did: {outcome:?}"),
        () = asked => {}
    }
    let mut out = Vec::new();
    while let Ok(reply) = replies.try_recv() {
        out.push(reply);
    }
    out
}

/// Whether `console` says `needle` within [`BUDGET`].
fn says(mut console: impl FnMut() -> String, needle: &str) -> bool {
    let deadline = Instant::now() + BUDGET;
    loop {
        if console().contains(needle) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---- the fixed profile: the declared node ----

/// The declared node, built once, and the keys of the commanders it is asked by.
struct Sealed {
    /// The packaged node.
    node: PathBuf,
    /// The zid the node's provisioned key names.
    zid: String,
    /// Granted `status` and `close`.
    commander: Commander,
    /// Granted nothing.
    stranger: Commander,
    /// Where the declaration, the identity and the package are, removed when the process ends.
    _dir: tempfile::TempDir,
}

/// Make the node's identity and the commander's key, write the declaration that grants the
/// commander `status` and `close` and names the identity, and build the node from it.
fn sealed_node() -> &'static Sealed {
    static BUILT: OnceLock<Sealed> = OnceLock::new();
    BUILT.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a directory for the node");
        let identity = key_named_identity();
        let (cert, key) = (dir.path().join("node.crt"), dir.path().join("node.key"));
        std::fs::write(&cert, &identity.cert_pem).expect("write the node's certificate");
        std::fs::write(&key, &identity.key_pem).expect("write the node's key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .expect("make the key its owner's alone");
        let (commander, stranger) = (Commander::new(), Commander::new());
        let text =
            std::fs::read_to_string(repo_root().join(DECLARATION)).expect("read the declaration");
        assert_eq!(
            text.matches(STATUS_ZID).count(),
            1,
            "{DECLARATION} grants `status` once"
        );
        assert_eq!(
            text.matches(CLOSE_ZID).count(),
            1,
            "{DECLARATION} grants `close` once"
        );
        let granted = format!("zid = \"{}\"", commander.zid);
        let text = text
            .replace(STATUS_ZID, &granted)
            .replace(CLOSE_ZID, &granted)
            + &format!(
                "\n[identity]\ncertificate = {:?}\nprivate_key = {:?}\n",
                cert.display().to_string(),
                key.display().to_string()
            );
        let node = package(dir.path(), "slot-commander", &text);
        Sealed {
            node,
            zid: zid_text(&zid_from_spki_der(&identity.spki_der)),
            commander,
            stranger,
            _dir: dir,
        }
    })
}

/// The node running, and the router that dials it with a key no grant names.
struct FixedRun {
    /// The router, stopped first.
    router: ChildGuard,
    router_out: File,
    node: Node,
    way: Way,
    _files: tempfile::TempDir,
}

impl FixedRun {
    /// Start the node, then a stock zenohd that dials its listener over mutual TLS with
    /// `router`'s key and pins the certificate the node printed, and wait until the node holds a
    /// session whose key named the router.
    fn start(router: &Party) -> Self {
        let built = sealed_node();
        let mut node = Node::run(&built.node, "slot-commander (sealed commands)", LISTENING);
        assert_eq!(
            node.zid, built.zid,
            "the node proves a zid other than its provisioned key names"
        );
        let files = tempfile::tempdir().expect("a directory for the router");
        let pinned = std::fs::read_to_string(&node.certificate).expect("the node's certificate");
        let (router_child, mut router_out, port) =
            dialling_router(files.path(), LISTENER, router, &pinned);
        if !says(|| node.console(), VERIFIED) {
            panic!(
                "the router's session with the node did not come up verified\n--- node ---\n{}\n\
                 --- zenohd ---\n{}",
                node.console(),
                read_captured(&mut router_out)
            );
        }
        let way = Way {
            port,
            node: node.zid.clone(),
            whatami: "client",
        };
        Self {
            router: router_child,
            router_out,
            node,
            way,
            _files: files,
        }
    }

    /// Whether the node's record says `line`: a decision, as `HOST-WZ-DECISION` says it.
    fn decided(&mut self, line: &str) -> bool {
        says(|| self.node.console(), line)
    }

    /// What the node and the router have said, for a failure.
    fn logs(&mut self) -> String {
        format!(
            "--- node ---\n{}\n--- zenohd ---\n{}",
            self.node.console(),
            read_captured(&mut self.router_out)
        )
    }
}

impl Drop for FixedRun {
    fn drop(&mut self) {
        graceful_terminate(self.router.child_mut(), Duration::from_secs(5));
    }
}

/// The record's line for `verb` decided for `subject` as `verdict`.
fn decision(subject: &str, verb: &str, verdict: &str) -> String {
    format!("subject={subject} verb={verb} decision={verdict}")
}

// wz-proves: none -- a sealed command is decision D17 on the fixed-memory profile's in-band verbs, which no catalog atom names
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd); runs via --ignored"]
async fn zenohd_lane_fixed_a_listed_commanders_sealed_status_and_close_are_permitted_through_an_unlisted_router(
) {
    let built = sealed_node();
    let router = Party::new();
    let mut run = FixedRun::start(&router);

    // CONTROL: the router's own query is the router's, and no grant names it.
    let own = run.way.routed().await;
    assert!(
        own.contains(STATUS_REFUSED),
        "the router's own status was not refused: {own}\n{}",
        run.logs()
    );

    let (status, _, _) = run
        .way
        .after_the_echo(&built.commander, Verb::Status, 1)
        .await;
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the listed commander's sealed status was not answered: {status}\n{}",
        run.logs()
    );
    // The node holds the commander's counter now, so its next command needs no echo.
    let close = run
        .way
        .ask(
            "close",
            Some(&built.commander.seal(Verb::Close, &run.way.node, 3, None)),
        )
        .await;
    assert_eq!(
        close, "{\"verdict\":\"not_found\"}",
        "the listed commander's sealed close was not decided (the node holds no such peer)"
    );

    let sealed = format!("sealed:{}", built.commander.zid);
    for line in [
        decision(
            &format!("verified:{}", router.zid),
            "Status",
            "Deny(NotListed)",
        ),
        decision(&sealed, "Status", "Permit(Granted)"),
        decision(&sealed, "Close", "Permit(Granted)"),
    ] {
        assert!(
            run.decided(&line),
            "the node's record does not say {line:?}\n{}",
            run.logs()
        );
    }
}

// wz-proves: none -- the same node and decision as the leg above: the replay window of a sealed command on the fixed-memory profile
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd); runs via --ignored"]
async fn zenohd_lane_fixed_a_sealed_command_sent_again_is_refused_as_a_replay() {
    let built = sealed_node();
    let mut run = FixedRun::start(&Party::new());
    run.way.routed().await;

    let (status, repeat, _) = run
        .way
        .after_the_echo(&built.commander, Verb::Status, 1)
        .await;
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the listed commander's sealed status was not answered: {status}\n{}",
        run.logs()
    );
    let again = run.way.ask("status", Some(&repeat)).await;
    assert!(
        again.contains(REPLAY) && again.contains("\"last\":2"),
        "the same sealed object sent again was not refused as a replay of counter 2: {again}\n{}",
        run.logs()
    );
}

// wz-proves: none -- the same node and decision as the legs above: a sealed command whose key no list names
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd); runs via --ignored"]
async fn zenohd_lane_fixed_a_sealed_command_of_an_unlisted_key_is_refused_by_the_lists() {
    let built = sealed_node();
    let mut run = FixedRun::start(&Party::new());
    run.way.routed().await;

    // The object verifies, and is fresh once it carries the echo: the lists refuse it.
    let (refused, repeat, _) = run
        .way
        .after_the_echo(&built.stranger, Verb::Status, 1)
        .await;
    assert!(
        refused.contains(STATUS_REFUSED),
        "a sealed status of a key no list names was not refused by the lists: {refused}\n{}",
        run.logs()
    );
    // A refused commander takes no counter: the same object is refused by the lists again, and
    // not as a replay.
    let again = run.way.ask("status", Some(&repeat)).await;
    assert!(
        again.contains(STATUS_REFUSED) && !again.contains(REPLAY),
        "a refused sealed command took a counter: {again}"
    );
    let line = decision(
        &format!("sealed:{}", built.stranger.zid),
        "Status",
        "Deny(NotListed)",
    );
    assert!(
        run.decided(&line),
        "the node's record does not say {line:?}\n{}",
        run.logs()
    );
}

// wz-proves: none -- the echo a fixed-memory node draws when it starts (decision D17): a restart of the declared node
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd); runs via --ignored"]
async fn zenohd_lane_fixed_after_a_restart_a_sealed_command_is_taken_only_with_the_new_echo() {
    let built = sealed_node();
    let router = Party::new();
    let mut run = FixedRun::start(&router);
    run.way.routed().await;
    let (status, _, before) = run
        .way
        .after_the_echo(&built.commander, Verb::Status, 1)
        .await;
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the listed commander's sealed status was not answered: {status}\n{}",
        run.logs()
    );
    // Sealed before the node stops, under a counter above every one it took, and never sent.
    let sealed_before = built.commander.seal(Verb::Status, &run.way.node, 3, None);
    drop(run);

    let mut run = FixedRun::start(&router);
    run.way.routed().await;
    let first = run.way.ask("status", Some(&sealed_before)).await;
    let after = echo_in(&first).unwrap_or_else(|| {
        panic!(
            "a command sealed before the restart was not refused for the echo: {first}\n{}",
            run.logs()
        )
    });
    assert_ne!(
        after, before,
        "the node drew the echo of its last start again"
    );
    let stale = run
        .way
        .ask(
            "status",
            Some(
                &built
                    .commander
                    .seal(Verb::Status, &run.way.node, 4, Some(before)),
            ),
        )
        .await;
    assert_eq!(
        echo_in(&stale),
        Some(after),
        "a command carrying the echo of the last start was not refused with this start's: {stale}"
    );
    let repeat = run
        .way
        .ask(
            "status",
            Some(
                &built
                    .commander
                    .seal(Verb::Status, &run.way.node, 5, Some(after)),
            ),
        )
        .await;
    assert!(
        repeat.starts_with("{\"verdict\":\"status\""),
        "the repeat carrying this start's echo was not answered: {repeat}\n{}",
        run.logs()
    );
    let line = decision(
        &format!("sealed:{}", built.commander.zid),
        "Status",
        "Permit(Granted)",
    );
    assert!(
        run.decided(&line),
        "the restarted node's record does not say {line:?}\n{}",
        run.logs()
    );
}

// ---- the heap profile: the demo's peer ----

/// The demo's peer hosting the lifecycle queries with a declaration that grants `commander`
/// `status` and `close`, and a stock zenohd that dials its TLS listener with a key no grant
/// names.
struct HeapRun {
    router: ChildGuard,
    router_out: File,
    node: ChildGuard,
    log: File,
    way: Way,
    _files: tempfile::TempDir,
}

impl HeapRun {
    fn start(commander: &Commander, router: &Party) -> Self {
        let demo = wz_ap_demo_binary();
        assert_demo_binary_newer_than_sources(&demo);
        let files = tempfile::tempdir().expect("a directory for the node and the router");
        let identity = key_named_identity();
        let zid = zid_text(&zid_from_spki_der(&identity.spki_der));
        let write = |name: &str, text: &str| -> PathBuf {
            let path = files.path().join(name);
            std::fs::write(&path, text).expect("write a file of the node");
            path
        };
        let cert = write("node.pem", &identity.cert_pem);
        let key = write("node.key", &identity.key_pem);
        // The router's certificate is self-signed, so it is its own root: the node verifies the
        // router's key against it, and no grant names that key.
        let roots = write("router.pem", &router.cert_pem);
        let declared = write(
            "node.toml",
            &format!(
                "schema = 1\n\n[node]\nid = \"a\"\n\n[[endpoint]]\nrole = \"commander\"\n\
                 zid = \"{}\"\nverbs = \"close, status\"\n",
                commander.zid
            ),
        );
        let ports = PortReservation::pick();
        let tls = format!("tls/127.0.0.1:{}", ports.next_port());
        let tcp = format!("127.0.0.1:{}", ports.port());
        let mut log = tempfile::tempfile().expect("a capture for the node");
        let node = ChildGuard::wrap(
            "wz-ap-demo peer (--session-lifecycle, sealed commands)",
            Command::new(&demo)
                .arg("--peer")
                .arg(format!("{tcp},{tls}"))
                .arg("--zid")
                .arg(&zid)
                .arg("--tls-cert")
                .arg(&cert)
                .arg("--tls-key")
                .arg(&key)
                .arg("--tls-mtls")
                .arg("--tls-ca")
                .arg(&roots)
                .arg("--session-lifecycle")
                .arg("--node-declaration")
                .arg(&declared)
                // The decision record of a heap node is its log, a permit as a debug note.
                .env("RUST_LOG", "info,wz_session_core::lifecycle_monitor=debug")
                .stdout(Stdio::null())
                .stderr(Stdio::from(log.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn wz-ap-demo"),
        );
        let verbs_key = format!("@/{zid}/peer/session/verbs");
        if let Err(said) = wait_for_substring(
            &mut log,
            &format!("session lifecycle query at {verbs_key}"),
            Duration::from_secs(10),
        ) {
            panic!(
                "the peer did not host the lifecycle queries (is the demo built with \
                 --features routing-peer,session-close-ingress,tls?)\n{said}"
            );
        }
        drop(ports);
        let (router_child, router_out, port) =
            dialling_router(files.path(), &tls, router, &identity.cert_pem);
        // The commander dials the router's tcp listener, which a router started a moment ago may
        // not hold yet: a refused dial is the router's start, not the node's answer.
        assert!(
            wait_for_tcp_accept(port, Duration::from_secs(20)),
            "zenohd never listened on 127.0.0.1:{port}"
        );
        let way = Way {
            port,
            node: zid,
            whatami: "peer",
        };
        Self {
            router: router_child,
            router_out,
            node,
            log,
            way,
            _files: files,
        }
    }

    /// Whether the node's log says `needle`.
    fn logged(&mut self, needle: &str) -> bool {
        says(|| read_captured(&mut self.log), needle)
    }

    /// What the node and the router have said, for a failure.
    fn logs(&mut self) -> String {
        format!(
            "--- wz-ap-demo ---\n{}\n--- zenohd ---\n{}",
            read_captured(&mut self.log),
            read_captured(&mut self.router_out)
        )
    }
}

impl Drop for HeapRun {
    fn drop(&mut self) {
        for child in [&mut self.router, &mut self.node] {
            graceful_terminate(child.child_mut(), Duration::from_secs(5));
        }
    }
}

/// What the heap node logs for a decision of `verb` for `subject`: `permit` or `deny`.
fn monitor_line(verdict: &str, verb: &str, subject: &str) -> String {
    format!("lifecycle monitor: {verdict} {verb} by {subject}")
}

// wz-proves: none -- a sealed command on the heap profile's hosted lifecycle queries (decision D17), carried by zenohd, which no catalog atom names
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls, + zenohd); runs via --ignored"]
async fn zenohd_lane_heap_a_listed_commanders_sealed_status_and_close_are_permitted_through_an_unlisted_router(
) {
    let (commander, router) = (Commander::new(), Party::new());
    let mut run = HeapRun::start(&commander, &router);
    let own = run.way.routed().await;
    assert!(
        own.contains(STATUS_REFUSED),
        "the router's own status was not refused: {own}\n{}",
        run.logs()
    );

    let (status, _, _) = run.way.after_the_echo(&commander, Verb::Status, 1).await;
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the listed commander's sealed status was not answered: {status}\n{}",
        run.logs()
    );
    let close = run
        .way
        .ask(
            "close",
            Some(&commander.seal(Verb::Close, &run.way.node, 3, None)),
        )
        .await;
    assert!(
        close.contains("\"verdict\":\"not_found\""),
        "the listed commander's sealed close was not decided (the node holds no such peer): \
         {close}\n{}",
        run.logs()
    );

    let sealed = format!("sealed:{}", commander.zid);
    for line in [
        monitor_line("deny", "Status", &format!("verified:{}", router.zid)),
        monitor_line("permit", "Status", &sealed),
        monitor_line("permit", "Close", &sealed),
    ] {
        assert!(
            run.logged(&line),
            "the node's log does not say {line:?}\n{}",
            run.logs()
        );
    }
}

// wz-proves: none -- the replay window of a sealed command on the heap profile, which no catalog atom names
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls, + zenohd); runs via --ignored"]
async fn zenohd_lane_heap_a_sealed_command_sent_again_is_refused_as_a_replay() {
    let commander = Commander::new();
    let mut run = HeapRun::start(&commander, &Party::new());
    run.way.routed().await;

    let (status, repeat, _) = run.way.after_the_echo(&commander, Verb::Status, 1).await;
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the listed commander's sealed status was not answered: {status}\n{}",
        run.logs()
    );
    let again = run.way.ask("status", Some(&repeat)).await;
    assert!(
        again.contains(REPLAY) && again.contains("\"last\":2"),
        "the same sealed object sent again was not refused as a replay of counter 2: {again}\n{}",
        run.logs()
    );
}

// wz-proves: none -- a sealed command of a key no grant names on the heap profile, which no catalog atom names
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls, + zenohd); runs via --ignored"]
async fn zenohd_lane_heap_a_sealed_command_of_an_unlisted_key_is_refused_by_the_grants() {
    let (commander, stranger) = (Commander::new(), Commander::new());
    let mut run = HeapRun::start(&commander, &Party::new());
    run.way.routed().await;

    let (refused, repeat, _) = run.way.after_the_echo(&stranger, Verb::Status, 1).await;
    assert!(
        refused.contains(STATUS_REFUSED),
        "a sealed status of a key no grant names was not refused: {refused}\n{}",
        run.logs()
    );
    let again = run.way.ask("status", Some(&repeat)).await;
    assert!(
        again.contains(STATUS_REFUSED) && !again.contains(REPLAY),
        "a refused sealed command took a counter: {again}"
    );
    let line = monitor_line("deny", "Status", &format!("sealed:{}", stranger.zid));
    assert!(
        run.logged(&line),
        "the node's log does not say {line:?}\n{}",
        run.logs()
    );
}
