// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One link per row: the wz demo dials a stock `zenohd` over a link the host
//! serves, and reaches Established.
//!
//! What a host owes the router interop is not the whole corpus but the part of it
//! whose subject depends on the host, and the host-dependent surface of a transport
//! is its links. So the rows here are the pure link handshakes of the corpus's router
//! file (`wz_client_reaches_established_against_zenohd_over_{ws,udp,tls,quic,unixsock}`),
//! one assertion each, and the body is one function with the link as data, because
//! the corpus tests differ only in the router's listener, the locator the demo dials
//! and, for the two certificate links, the CA flag. The TCP row is
//! `zenohd_handshake.rs`, which discovers its port instead of reserving a pair.
//!
//! The tests stay separate functions and not one loop over the table. Promotion from
//! observation to gate is per test and per host, after two consecutive green hosted
//! runs, and a loop would hide which link a red belongs to.
//!
//! A Unix socket is served on macOS and not on Windows, so its row and its test are
//! `cfg(unix)`. Not here, with the reason: `unixpipe` and `vsock` need a router built
//! with a transport feature the default build omits.
//!
//! Opt-in (`#[ignore]`) and binary-dependent: the router is named with `WZ_ZENOHD_BIN`
//! and the demo is the one `cargo build -p wz-ap-demo` produced with the link features
//! (`ws,tls,quic`, and `unixsock` on a host that serves it).

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(unix)]
use wz_integration_tests::common::spawn_zenohd_tcp_unixsock;
use wz_integration_tests::common::{
    read_captured, spawn_zenohd_tcp_quic, spawn_zenohd_tcp_tls, spawn_zenohd_tcp_udp,
    spawn_zenohd_tcp_ws, wait_for_substring, wz_ap_demo_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// What a row needs to start a router and to dial it: the TCP port is the router's
/// readiness gate, the link port is the one under test, and the two certificate links
/// read the PEM pair the caller wrote.
struct Ctx {
    tcp_port: u16,
    link_port: u16,
    cert: String,
    key: String,
}

struct Link {
    /// The transport name the demo logs once it has dialed, which is what the test
    /// reads to know the link it asked for is the one it got.
    transport: &'static str,
    /// The demo's flag naming the CA to trust, for the links that carry a
    /// certificate. `None` for a link with no certificate.
    ca_flag: Option<&'static str>,
    /// Start a stock router listening on this link.
    spawn: fn(&Ctx) -> ChildGuard,
    /// The locator the demo is told to dial.
    connect: fn(&Ctx) -> String,
}

fn probe_stderr() -> File {
    tempfile::tempfile().expect("tempfile for readiness probe stderr")
}

fn router_over_ws(c: &Ctx) -> ChildGuard {
    spawn_zenohd_tcp_ws(c.tcp_port, c.link_port, probe_stderr)
}

fn router_over_udp(c: &Ctx) -> ChildGuard {
    spawn_zenohd_tcp_udp(c.tcp_port, c.link_port, probe_stderr)
}

fn router_over_tls(c: &Ctx) -> ChildGuard {
    spawn_zenohd_tcp_tls(c.tcp_port, c.link_port, &c.cert, &c.key, probe_stderr)
}

fn router_over_quic(c: &Ctx) -> ChildGuard {
    spawn_zenohd_tcp_quic(c.tcp_port, c.link_port, &c.cert, &c.key, probe_stderr)
}

fn dial_ws(c: &Ctx) -> String {
    format!("ws/127.0.0.1:{}", c.link_port)
}

fn dial_udp(c: &Ctx) -> String {
    format!("udp/127.0.0.1:{}", c.link_port)
}

fn dial_tls(c: &Ctx) -> String {
    format!("tls/127.0.0.1:{}", c.link_port)
}

fn dial_quic(c: &Ctx) -> String {
    format!("quic/127.0.0.1:{}", c.link_port)
}

/// The socket a Unix-socket row listens on, keyed on the reserved TCP port so
/// concurrent tests cannot collide. Short on purpose: `sun_path` holds about a hundred
/// bytes on macOS, and its temp directory is already fifty of them.
#[cfg(unix)]
fn unixsock_path(tcp_port: u16) -> PathBuf {
    std::env::temp_dir().join(format!("wzhi-us-{tcp_port}.sock"))
}

#[cfg(unix)]
fn router_over_unixsock(c: &Ctx) -> ChildGuard {
    let sock = unixsock_path(c.tcp_port);
    spawn_zenohd_tcp_unixsock(c.tcp_port, &sock.to_string_lossy(), probe_stderr)
}

/// The locator has a double slash after the scheme when the path is absolute, the
/// shape zenoh's unixsock link expects.
#[cfg(unix)]
fn dial_unixsock(c: &Ctx) -> String {
    format!("unixsock-stream/{}", unixsock_path(c.tcp_port).display())
}

/// The Unix socket a test may leave, and its lock. A host without Unix sockets has
/// none, so the list is empty there and the call site has no `cfg`.
#[cfg(unix)]
fn socket_leftovers(tcp_port: u16) -> Vec<PathBuf> {
    let sock = unixsock_path(tcp_port);
    vec![PathBuf::from(format!("{}.lock", sock.display())), sock]
}

#[cfg(not(unix))]
fn socket_leftovers(_tcp_port: u16) -> Vec<PathBuf> {
    Vec::new()
}

const WS: Link = Link {
    transport: "ws",
    ca_flag: None,
    spawn: router_over_ws,
    connect: dial_ws,
};
const UDP: Link = Link {
    transport: "udp",
    ca_flag: None,
    spawn: router_over_udp,
    connect: dial_udp,
};
const TLS: Link = Link {
    transport: "tls",
    ca_flag: Some("--tls-ca"),
    spawn: router_over_tls,
    connect: dial_tls,
};
const QUIC: Link = Link {
    transport: "quic",
    ca_flag: Some("--quic-ca"),
    spawn: router_over_quic,
    connect: dial_quic,
};
#[cfg(unix)]
const UNIXSOCK: Link = Link {
    transport: "unixsock",
    ca_flag: None,
    spawn: router_over_unixsock,
    connect: dial_unixsock,
};

/// What a test leaves on disk, removed when it ends however it ends: the certificate
/// and key of a certificate link, the router config written beside the certificate,
/// the Unix socket and its lock. The corpus removes them on the straight path only.
struct TestFiles(Vec<PathBuf>);

impl Drop for TestFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn handshake_over(link: &Link) {
    let demo = wz_ap_demo_binary();
    let (tcp_res, link_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();

    // Named for every link and written only by the two that carry a certificate; the
    // guard removes whatever exists, which for a link with no files is nothing.
    let dir = std::env::temp_dir();
    let transport = link.transport;
    let cert_path = dir.join(format!("wz-host-interop-{transport}-{tcp_port}.cert.pem"));
    let key_path = dir.join(format!("wz-host-interop-{transport}-{tcp_port}.key.pem"));
    let mut leftovers = vec![
        cert_path.clone(),
        key_path.clone(),
        PathBuf::from(format!("{}.zenohd.json5", cert_path.display())),
    ];
    leftovers.extend(socket_leftovers(tcp_port));
    let _files = TestFiles(leftovers);
    if link.ca_flag.is_some() {
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        std::fs::write(&cert_path, cert_pem).expect("write cert pem");
        std::fs::write(&key_path, key_pem).expect("write key pem");
    }
    let ctx = Ctx {
        tcp_port,
        link_port,
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
    };

    let mut zenohd = (link.spawn)(&ctx);
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut command = Command::new(&demo);
    command.arg("--connect").arg((link.connect)(&ctx));
    if let Some(flag) = link.ca_flag {
        command.arg(flag).arg(&ctx.cert);
    }
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect <link>/zenohd --publish)",
        command
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg(format!("{transport}-handshake-probe"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect <link>/zenohd"),
    );

    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s over {transport}: the \
             wz<->zenohd handshake did not interoperate on this host.\n\
             --- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    // Witness the link. The router's listener for this link is on a port or a path of
    // its own and the TCP port is a separate one, so a TCP dial could not reach
    // Established here; but that is an inference, and the demo logs the transport it
    // dialed.
    let witness = format!("over {transport} transport");
    assert!(
        demo_captured.contains(&witness),
        "reached Established but the demo did not log '{witness}'.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, ws); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_ws_on_this_host() {
    handshake_over(&WS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, udp); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_udp_on_this_host() {
    handshake_over(&UDP);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, tls); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_tls_on_this_host() {
    handshake_over(&TLS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, quic); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_quic_on_this_host() {
    handshake_over(&QUIC);
}

#[cfg(unix)]
#[test]
#[ignore = "binary-dep e2e (zenohd router, unixsock); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_unixsock_on_this_host() {
    handshake_over(&UNIXSOCK);
}
