// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session lifecycle as a QUERY, over the wire between real nodes: a GET
//! closes the session with a peer and is answered with a verdict, a GET reads the
//! session's links before it, and a GET lists the verbs the node has.
//!
//! `wz-session-core`'s `lifecycle_query` and `wz-runtime-tokio`'s
//! `session_close_query` witness the answerer and the order it places on a session
//! bundle. What neither can say is that the verb is HOSTED: that a node started
//! with `--session-lifecycle` registers the queryables, that a query from another
//! process reaches them and that the verdict comes back over the session. This does.
//!
//! Topology (all `wz-ap-demo`, no foreign binary):
//!   * peer A, `--peer`, hosting the lifecycle queries, its grants read from a node
//!     declaration (`--node-declaration`, the `commander` rows a fixed node is built from);
//!   * peer D, `--peer --connect A` over TCP, zid pinned: the session the verbs name;
//!   * clients Q1, Q2, ... : one `--connect A --query <key>` each, whose reply log
//!     is the answer.
//!
//! A verb is judged by its commander (decision D16 of
//! `docs/session-lifecycle-intent.md`): the zid the key of the asking link proved.
//!
//! The FIRST test is the positive witness. A listens on TCP and on mutual TLS, and its
//! declaration grants `close` and `status` to the zid of a key the test makes. A client
//! that presents that key over TLS, claiming the zid it names, reads D's status and closes
//! D's session, and A's face for D goes DOWN. The CONTROL is a client that presents a key
//! on no row of the declaration over the same listener: its close is refused.
//!
//! The SECOND test grants the verbs to D's zid and asks them over plain TCP, which proves
//! no zid: whatever the client claims, it asks as nobody shown and is refused.
//!
//! The THIRD test hosts the queries with no grant and asks for a close: the answer
//! is `refused` with a reason, and no session is needed for that, because the
//! monitor decides before the directory is read.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard, PortReservation,
};
use wz_runtime_tokio_test_support::{key_named_identity, KeyNamedIdentity};
use wz_session_core::credential_identity::zid_from_spki_der;

const A_ZID: &str = "aa11aa11aa11aa11";
const D_ZID: &str = "dd22dd22dd22dd22";

/// The demo, checked to be newer than the sources it was built from: this test
/// needs the demo ALIVE and answering the queries, so a stale binary that predates
/// them would read as a node that never hosted them.
fn demo_binary() -> std::path::PathBuf {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    demo
}

/// A spawned `wz-ap-demo` whose stderr is captured to a file.
struct Node {
    guard: ChildGuard,
    log: File,
}

fn spawn(label: &str, args: &[&str]) -> Node {
    let stderr = tempfile::tempfile().expect("tempfile for stderr");
    let writer = stderr.try_clone().expect("dup stderr handle");
    let guard = ChildGuard::wrap(
        label,
        Command::new(demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    Node { guard, log: stderr }
}

impl Node {
    fn wait_for(&mut self, needle: &str, secs: u64) -> Result<String, String> {
        wait_for_substring(&mut self.log, needle, Duration::from_secs(secs))
    }

    fn stop(&mut self) -> String {
        let _ = self.guard.child_mut().kill();
        let _ = self.guard.child_mut().wait();
        read_captured(&mut self.log)
    }
}

/// Ask `node_addr` the query `key` from a fresh client started with `args` besides, and
/// return the client's reply log, or panic with both sides' logs if no reply came.
fn ask_with(node_addr: &str, args: &[&str], key: &str, node: &mut Node) -> String {
    let mut argv = vec!["--connect", node_addr];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--query", key, "--on-query-reply-log"]);
    let mut client = spawn(
        "wz-ap-demo client (--connect --query --on-query-reply-log)",
        &argv,
    );
    let reply = client.wait_for("REPLY RECEIVED", 10);
    let client_log = client.stop();
    match reply {
        Ok(captured) => captured,
        Err(_) => panic!(
            "no 'REPLY RECEIVED' for {key} within 10s\n--- client ---\n{client_log}\n--- node ---\n{}",
            read_captured(&mut node.log)
        ),
    }
}

/// Ask over a link that proves no zid.
fn ask(node_addr: &str, key: &str, node: &mut Node) -> String {
    ask_with(node_addr, &[], key, node)
}

/// The text of a path the demo takes as an argument.
fn path(p: &Path) -> &str {
    p.to_str().expect("a UTF-8 path")
}

/// One key the test makes, the self-signed certificate over it, and the zid it names (decision
/// D1: the first sixteen bytes of the SHA-256 of its SubjectPublicKeyInfo, spelled as a key
/// carries a zid).
struct Party {
    cert: PathBuf,
    key: PathBuf,
    zid: String,
}

impl Party {
    fn new(dir: &Path, name: &str) -> Self {
        let made: KeyNamedIdentity = key_named_identity();
        let (cert, key) = (
            dir.join(format!("{name}.pem")),
            dir.join(format!("{name}.key")),
        );
        std::fs::write(&cert, &made.cert_pem).expect("write the certificate");
        std::fs::write(&key, &made.key_pem).expect("write the key");
        let zid = format!(
            "{:x}",
            u128::from_le_bytes(zid_from_spki_der(&made.spki_der))
        );
        Self { cert, key, zid }
    }

    /// The arguments of a client that dials `node`'s TLS listener presenting this party's key
    /// and claiming the zid it names.
    fn client_args<'a>(&'a self, node: &'a Party) -> [&'a str; 8] {
        [
            "--zid",
            &self.zid,
            "--tls-ca",
            path(&node.cert),
            "--tls-connect-cert",
            path(&self.cert),
            "--tls-connect-key",
            path(&self.key),
        ]
    }
}

/// A node declaration that grants `verbs` to `zid`, in the shape a fixed node is built from
/// (`docs/target-build-contract.md`, section 5b), written into `dir`.
fn declaration(dir: &Path, zid: &str, verbs: &str) -> PathBuf {
    let file = dir.join("node.toml");
    std::fs::write(
        &file,
        format!(
            "schema = 1\n\n[node]\nid = \"a\"\n\n[[endpoint]]\nrole = \"commander\"\n\
             zid = \"{zid}\"\nverbs = \"{verbs}\"\n"
        ),
    )
    .expect("write the declaration");
    file
}

/// The face id the peer D holds on `node`, read off its `face N UP` line (the line
/// prints the peer's zid in wire order, so the match is on the role the line also
/// prints: the peer D is the only `Peer` this node accepts).
fn peer_face(log: &str) -> u64 {
    log.lines()
        .find(|l| l.contains(" UP (peer ") && l.contains("whatami Some(Peer)"))
        .and_then(|l| {
            l.split_once("face ")?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no 'face N UP' line for a Peer in:\n{log}"))
}

/// Wait for `node` to host the lifecycle queries under `zid`, or fail saying how the demo must
/// be built.
fn hosted(node: &mut Node, zid: &str) {
    let verbs_key = format!("@/{zid}/peer/session/verbs");
    if let Err(captured) = node.wait_for(&format!("session lifecycle query at {verbs_key}"), 5) {
        panic!(
            "peer A did not host the lifecycle queries (is the demo built with \
             --features routing-peer,session-close-ingress,tls?)\n--- A ---\n{captured}"
        );
    }
}

fn refused(reply: &str) -> bool {
    reply.contains(r#"\"verdict\":\"refused\""#) && reply.contains(r#"\"reason\":\""#)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls); Layer E6 runs via --ignored"]
fn wz_peer_session_lifecycle_close_by_a_declared_commander_over_mtls_closes_the_session() {
    let dir = tempfile::tempdir().expect("a directory for the keys and the declaration");
    let a_key = Party::new(dir.path(), "a");
    let commander = Party::new(dir.path(), "commander");
    let stranger = Party::new(dir.path(), "stranger");
    // Each client's certificate is self-signed, so it is its own root: A verifies its clients
    // against both, and only the declaration tells them apart.
    let clients = dir.path().join("clients.pem");
    let roots = [&commander, &stranger]
        .map(|party| std::fs::read_to_string(&party.cert).expect("read a certificate"))
        .concat();
    std::fs::write(&clients, roots).expect("write the client roots");
    let declared = declaration(dir.path(), &commander.zid, "close, status");

    let port_res = PortReservation::pick();
    let port_d = port_res.next_port();
    let port_tls = port_res.next_port();
    let addr_a = format!("127.0.0.1:{}", port_res.port());
    let tls_a = format!("tls/127.0.0.1:{port_tls}");
    let addr_d = format!("127.0.0.1:{port_d}");
    let a_zid = a_key.zid.as_str();
    let mut a = spawn(
        "wz-ap-demo peer A (--peer tcp and mutual tls, --node-declaration)",
        &[
            "--peer",
            &format!("{addr_a},{tls_a}"),
            "--zid",
            a_zid,
            "--tls-cert",
            path(&a_key.cert),
            "--tls-key",
            path(&a_key.key),
            "--tls-mtls",
            "--tls-ca",
            path(&clients),
            "--session-lifecycle",
            "--node-declaration",
            path(&declared),
        ],
    );
    hosted(&mut a, a_zid);
    drop(port_res);

    let mut d = spawn(
        "wz-ap-demo peer D (--peer --connect A)",
        &["--peer", &addr_d, "--zid", D_ZID, "--connect", &addr_a],
    );
    let a_up = a
        .wait_for(" UP (peer ", 10)
        .unwrap_or_else(|c| panic!("A never accepted peer D\n--- A ---\n{c}"));
    let face = peer_face(&a_up);
    let close_key = format!("@/{a_zid}/peer/session/close/{D_ZID}");

    // CONTROL: a key on no row of the declaration proves its zid over the same listener, and
    // its close is refused; the session with D is untouched.
    let denied = ask_with(&tls_a, &stranger.client_args(&a_key), &close_key, &mut a);
    assert!(
        refused(&denied),
        "a close asked by a zid the declaration does not name must answer refused:\n{denied}"
    );

    // STATUS (decision D6): the commander reads the session with D, one link and no close
    // ordered; a peer holds nobody by a machine, so no machine is listed.
    let status = ask_with(
        &tls_a,
        &commander.client_args(&a_key),
        &format!("@/{a_zid}/peer/session/status/{D_ZID}"),
        &mut a,
    );
    assert!(
        status.contains(r#"\"links\":{\"open\":1,\"closing\":0}"#)
            && status.contains(r#"\"machines\":[]"#),
        "the commander's status of a held session must read one open link:\n{status}"
    );

    // CLOSE: the verdict, then the effect.
    let closing = ask_with(&tls_a, &commander.client_args(&a_key), &close_key, &mut a);
    assert!(
        closing.contains(r#"\"verdict\":\"closing\""#) && closing.contains(r#"\"links\":1"#),
        "the commander's close of a held session must answer closing on 1 link:\n{closing}"
    );
    let down = a.wait_for(&format!("face {face} DOWN"), 10);
    let d_log = d.stop();
    let a_log = a.stop();
    down.unwrap_or_else(|_| {
        panic!(
            "the verdict said closing and A's face {face} never went DOWN\n--- A ---\n{a_log}\n--- D ---\n{d_log}"
        )
    });
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls); Layer E6 runs via --ignored"]
fn wz_peer_session_lifecycle_query_refuses_a_commander_no_link_proved() {
    let dir = tempfile::tempdir().expect("a directory for the declaration");
    let port_res = PortReservation::pick();
    let port_d = port_res.next_port();
    let addr_a = format!("127.0.0.1:{}", port_res.port());
    let addr_d = format!("127.0.0.1:{port_d}");

    // A's declaration grants the close and status verbs to D's zid. The querying clients reach
    // A over plain TCP, which proves no zid, so whatever they claim they ask as nobody shown.
    let declared = declaration(dir.path(), D_ZID, "close, status");
    let mut a = spawn(
        "wz-ap-demo peer A (--peer --session-lifecycle --node-declaration)",
        &[
            "--peer",
            &addr_a,
            "--zid",
            A_ZID,
            "--session-lifecycle",
            "--node-declaration",
            path(&declared),
        ],
    );
    hosted(&mut a, A_ZID);
    drop(port_res);

    let mut d = spawn(
        "wz-ap-demo peer D (--peer --connect A)",
        &["--peer", &addr_d, "--zid", D_ZID, "--connect", &addr_a],
    );
    a.wait_for(" UP (peer ", 10)
        .unwrap_or_else(|c| panic!("A never accepted peer D\n--- A ---\n{c}"));

    // CAPABILITY: the node says which verbs it has, whoever asks.
    let verbs = ask(&addr_a, &format!("@/{A_ZID}/peer/session/verbs"), &mut a);
    assert!(
        verbs.contains(r#"\"verbs\":[\"close\",\"reset\",\"status\"]"#),
        "the capability query did not list the close, reset and status verbs:\n{verbs}"
    );

    // STATUS and CLOSE (decision D16): granted verbs, asked by a commander no link proved, are
    // refused with a reason, before any session is read.
    for key in [
        format!("@/{A_ZID}/peer/session/status/{D_ZID}"),
        format!("@/{A_ZID}/peer/session/close/{D_ZID}"),
    ] {
        let answer = ask(&addr_a, &key, &mut a);
        assert!(
            refused(&answer),
            "a verb asked over a link that proved no zid must answer refused:\n{answer}"
        );
    }
    let _ = d.stop();
    let _ = a.stop();
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,session-close-ingress,tls); Layer E6 runs via --ignored"]
fn wz_peer_session_lifecycle_close_without_the_permit_is_refused_with_a_reason() {
    let port_res = PortReservation::pick();
    let addr_a = format!("127.0.0.1:{}", port_res.port());

    let mut a = spawn(
        "wz-ap-demo peer A (--peer --session-lifecycle, no declaration)",
        &["--peer", &addr_a, "--zid", A_ZID, "--session-lifecycle"],
    );
    hosted(&mut a, A_ZID);
    drop(port_res);

    // The node knows the verb whether or not it permits it...
    let verbs = ask(&addr_a, &format!("@/{A_ZID}/peer/session/verbs"), &mut a);
    assert!(
        verbs.contains(r#"\"verbs\":[\"close\",\"reset\",\"status\"]"#),
        "the capability query is about the node's verbs, not the permit:\n{verbs}"
    );
    // ...and refuses to run it, saying why, before it reads any session.
    let close_key = format!("@/{A_ZID}/peer/session/close/{D_ZID}");
    let answer = ask(&addr_a, &close_key, &mut a);
    assert!(
        refused(&answer),
        "an unpermitted close must answer refused with a reason:\n{answer}"
    );
    let _ = a.stop();
}
