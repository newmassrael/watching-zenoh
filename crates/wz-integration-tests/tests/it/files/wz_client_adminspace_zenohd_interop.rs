// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.23 `adminspace-core` — a CLIENT's admin space, asked through a router by
//! another client.
//!
//! Upstream declares `@/<zid>/<whatami>/**` as a routed queryable in every mode
//! (`zenoh/src/net/runtime/adminspace.rs` @ `pub async fn start(runtime: &Runtime)`),
//! so a zenohd started as a client answers `@/<zid>/client` to any node that
//! reaches it through its router: the answer arrives over the client's own link,
//! which is how a node that listens on nothing is seen to be up. The contract,
//! row by row, is in `docs/adminspace-client-mode.md`.
//!
//! Four legs, one predicate ([`assert_client_root_reply`]) over all of them:
//!
//! - the CONTROL: a zenohd router, a zenohd client A, and a wz client B asking.
//!   It measures upstream rather than restating it, and it is what makes the
//!   wz legs a comparison: the predicate is the shape the control answers with.
//! - a wz client A behind the same zenohd router: wz's declaration is one a
//!   stock router learns and routes.
//! - a wz client A behind a wz router: the whole path is wz's.
//! - a wz client A started with `--config` on a client file that has no
//!   `adminspace` block, behind a wz router: the daemon form hosts the admin
//!   space as zenohd does over the same file, with no flag typed.
//!
//! B is a fresh process per attempt and asks until it is answered, because
//! nothing on the router's side says when it has learned A's queryable; an
//! attempt that meets only the Final is a race, not a verdict, and the last one
//! is what a failure prints.

use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, demo_log_filter, read_captured, spawn_on_ephemeral_port,
    spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary, zenohd_binary,
    ChildGuard,
};

/// Client A's id in the control. No leading zero nibble, so upstream's
/// rendering of the id is the text given here.
const ZENOHD_CLIENT_ID: &str = "a1b2c3d4e5f60718";

/// The `metadata` both kinds of client A are started with, and what each serves.
const METADATA_ARG: &str = "{ name: 'client-a' }";
const METADATA_SERVED: &str = r#"{\"name\":\"client-a\"}"#;

/// The top-level fields of upstream's `local_data`
/// (`zenoh/src/net/runtime/adminspace.rs` @ `"plugins": plugins,`).
const ROOT_FIELDS: [&str; 6] = [
    "locators", "metadata", "plugins", "sessions", "version", "zid",
];

/// The line a wz client logs once its admin space is declared.
const HOSTED_MARKER: &str = "adminspace hosted at ";

const HOST_BUDGET: Duration = Duration::from_secs(10);
const ASK_BUDGET: Duration = Duration::from_secs(10);
const ASK_ATTEMPTS: usize = 10;

fn probe_stderr() -> File {
    tempfile::tempfile().expect("tempfile for the zenohd readiness probe")
}

/// zenohd as a CLIENT of the router at `port`. zenohd turns the admin space on
/// whatever the mode (`zenohd/src/main.rs` @ `config.adminspace.set_enabled(true)`),
/// and `--cfg mode` is applied after its router default, so this is upstream's
/// client with the admin space enabled.
fn spawn_zenohd_client(port: u16) -> ChildGuard {
    ChildGuard::wrap(
        "zenohd (client A, the upstream control)",
        Command::new(zenohd_binary())
            .arg("--cfg")
            .arg("mode:\"client\"")
            .arg("--cfg")
            .arg(format!("metadata:{METADATA_ARG}"))
            .arg("--id")
            .arg(ZENOHD_CLIENT_ID)
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd as a client"),
    )
}

/// A wz client A of the router at `port`, hosting its admin space. Returns its
/// guard, its log, and the admin root it logged (`@/<zid>/client`).
fn spawn_wz_client(port: u16) -> (ChildGuard, File, String) {
    spawn_hosting_client(
        "wz-ap-demo (client A, --config-queryable)",
        &[
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--config-queryable",
            "--metadata",
            METADATA_ARG,
        ],
    )
}

/// A stock client config naming the router at `port` and the metadata, with no
/// `adminspace` block: zenohd turns the admin space on over such a file
/// (`zenohd/src/main.rs` @ `config.adminspace.set_enabled(true).unwrap();`),
/// so a `wz-ap-demo --config` started on it must host one too.
fn client_config_without_an_adminspace_block(port: u16) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    write!(
        file,
        "{{ mode: \"client\", connect: {{ endpoints: [\"tcp/127.0.0.1:{port}\"] }}, \
         metadata: {METADATA_ARG} }}"
    )
    .expect("write config");
    file.flush().expect("flush config");
    file
}

/// A wz client A started on `args`, which must make it host its admin space.
/// Returns its guard, its log, and the admin root it logged (`@/<zid>/client`).
fn spawn_hosting_client(label: &'static str, args: &[&str]) -> (ChildGuard, File, String) {
    let stderr = tempfile::tempfile().expect("tempfile for client A's stderr");
    let writer = stderr.try_clone().expect("dup client A's stderr handle");
    let mut log = stderr;
    let mut guard = ChildGuard::wrap(
        label,
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo client A"),
    );
    let captured = match wait_for_substring(&mut log, HOSTED_MARKER, HOST_BUDGET) {
        Ok(c) => c,
        Err(c) => {
            let _ = guard.child_mut().kill();
            let _ = guard.child_mut().wait();
            panic!("client A never hosted its admin space\n{c}");
        }
    };
    let root = captured
        .lines()
        .find_map(|l| l.split_once(HOSTED_MARKER))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|k| k.strip_suffix("/**"))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("client A's log names no admin root\n{captured}"));
    assert!(
        root.ends_with("/client"),
        "a client's admin space is rooted at its own role: {root}"
    );
    (guard, log, root)
}

/// The zid of an admin root `@/<zid>/client`.
fn zid_of(root: &str) -> String {
    root.strip_prefix("@/")
        .and_then(|r| r.strip_suffix("/client"))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("not a client admin root: {root}"))
}

/// Ask `key` through the router at `port` from a fresh wz client B until a
/// reply arrives: `Ok` with the log of the attempt that got one, `Err` with the
/// log of the last attempt.
fn ask(port: u16, key: &str) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..ASK_ATTEMPTS {
        let stderr = tempfile::tempfile().expect("tempfile for client B's stderr");
        let writer = stderr.try_clone().expect("dup client B's stderr handle");
        let mut log = stderr;
        let mut asker = ChildGuard::wrap(
            "wz-ap-demo (client B, the asker)",
            Command::new(wz_ap_demo_binary())
                .arg("--connect")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--query")
                .arg(key)
                .arg("--on-query-reply-log")
                .arg("--on-query-final-log")
                .env("RUST_LOG", demo_log_filter())
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .expect("spawn wz-ap-demo client B"),
        );
        let captured = match wait_for_substring(&mut log, "FINAL RECEIVED", ASK_BUDGET) {
            Ok(c) | Err(c) => c,
        };
        let _ = asker.child_mut().kill();
        let _ = asker.child_mut().wait();
        if captured.contains("REPLY RECEIVED") {
            return Ok(captured);
        }
        last = captured;
        std::thread::sleep(Duration::from_millis(300));
    }
    Err(last)
}

/// The reply B received for `@/<zid>/client`, judged by what upstream's client
/// answers: under the client's own root, upstream's six top-level fields, the
/// client's own zid, the metadata it was started with, and the router it is
/// connected to listed as a session.
fn assert_client_root_reply(log: &str, zid: &str) {
    let key = format!("@/{zid}/client");
    let reply = log
        .lines()
        .find(|l| l.contains("REPLY RECEIVED") && l.contains(&format!("keyexpr='{key}'")))
        .unwrap_or_else(|| panic!("no reply under {key}\n{log}"));
    for field in ROOT_FIELDS {
        assert!(
            reply.contains(&format!("\\\"{field}\\\":")),
            "the document carries `{field}`, as upstream's does: {reply}"
        );
    }
    assert!(
        reply.contains(&format!("\\\"zid\\\":\\\"{zid}\\\"")),
        "the document names the client that answered: {reply}"
    );
    assert!(
        reply.contains(&format!("\\\"metadata\\\":{METADATA_SERVED}")),
        "the document serves the client's metadata: {reply}"
    );
    assert!(
        reply.contains("\\\"whatami\\\":\\\"router\\\""),
        "the client's session to its router is listed: {reply}"
    );
}

// wz-proves: none -- the upstream control: a zenohd client answers and wz only asks
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo; Layer Z runs via --ignored"]
fn a_zenohd_client_answers_its_client_key_through_a_zenohd_router() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut router, port) = spawn_zenohd_on_ephemeral_tcp(probe_stderr);
    let mut client_a = spawn_zenohd_client(port);
    let asked = ask(port, &format!("@/{ZENOHD_CLIENT_ID}/client"));
    let _ = client_a.child_mut().kill();
    let _ = client_a.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let log = asked.unwrap_or_else(|last| {
        panic!("no client B was answered by the zenohd client\n--- B ---\n{last}")
    });
    assert_client_root_reply(&log, ZENOHD_CLIENT_ID);
}

// wz-proves: adminspace-core wz->zenohd partial
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features adminspace-core); Layer Z runs via --ignored"]
fn a_wz_client_answers_its_client_key_through_a_zenohd_router() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut router, port) = spawn_zenohd_on_ephemeral_tcp(probe_stderr);
    let (mut client_a, mut a_log, root) = spawn_wz_client(port);
    let asked = ask(port, &root);
    let a_captured = read_captured(&mut a_log);
    let _ = client_a.child_mut().kill();
    let _ = client_a.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let log = asked.unwrap_or_else(|last| {
        panic!(
            "no client B was answered by wz client A\n--- B ---\n{last}\n--- A ---\n{a_captured}"
        )
    });
    assert_client_root_reply(&log, &zid_of(&root));
}

// wz-proves: none -- the shape of the zenohd client control above, reached from a file
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-core,zenoh-config); Layer Z runs via --ignored"]
fn a_wz_client_started_from_a_config_file_answers_its_client_key_through_a_wz_router() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut router, _router_log, port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &["--router-hat", "127.0.0.1:0"],
        "router-hat: listening on 127.0.0.1:",
        "wz-ap-demo (router)",
        tempfile::tempfile().expect("tempfile for the router's stderr"),
    );
    let config = client_config_without_an_adminspace_block(port);
    let config_path = config.path().to_str().expect("a UTF-8 tempfile path");
    let (mut client_a, mut a_log, root) = spawn_hosting_client(
        "wz-ap-demo (client A, --config alone)",
        &["--config", config_path],
    );
    let asked = ask(port, &root);
    let a_captured = read_captured(&mut a_log);
    let _ = client_a.child_mut().kill();
    let _ = client_a.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let log = asked.unwrap_or_else(|last| {
        panic!(
            "no client B was answered by wz client A\n--- B ---\n{last}\n--- A ---\n{a_captured}"
        )
    });
    assert_client_root_reply(&log, &zid_of(&root));
}

// wz-proves: none -- every process is wz's; the zenohd legs above adjudicate
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-core); Layer Z runs via --ignored"]
fn a_wz_client_answers_its_client_key_through_a_wz_router() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut router, _router_log, port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &["--router-hat", "127.0.0.1:0"],
        "router-hat: listening on 127.0.0.1:",
        "wz-ap-demo (router)",
        tempfile::tempfile().expect("tempfile for the router's stderr"),
    );
    let (mut client_a, mut a_log, root) = spawn_wz_client(port);
    let asked = ask(port, &root);
    let a_captured = read_captured(&mut a_log);
    let _ = client_a.child_mut().kill();
    let _ = client_a.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let log = asked.unwrap_or_else(|last| {
        panic!(
            "no client B was answered by wz client A\n--- B ---\n{last}\n--- A ---\n{a_captured}"
        )
    });
    assert_client_root_reply(&log, &zid_of(&root));
}
