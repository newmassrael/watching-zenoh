// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One link per row: the wz demo dials a stock `zenohd` over a link the host
//! serves, and reaches Established.
//!
//! What a host owes the router interop is not the whole corpus but the part of it
//! whose subject depends on the host, and the host-dependent surface of a transport
//! is its links. So the rows here are the pure link handshakes of the corpus's router
//! file (`wz_client_reaches_established_against_zenohd_over_{ws,udp,tls,quic}`), one
//! assertion each, and the body is one function with the link as data, because the
//! four corpus tests differ only in the router's listener, the demo's connect
//! scheme and, for the two certificate links, the CA flag. The TCP row is
//! `zenohd_handshake.rs`, which discovers its port instead of reserving a pair.
//!
//! The tests stay separate functions and not one loop over the table. Promotion from
//! observation to gate is per test and per host, after two consecutive green hosted
//! runs, and a loop would hide which link a red belongs to.
//!
//! Not here, with the reason: `unixsock` is served on macOS and not on Windows, so it
//! is a row of its own that macOS owes; `unixpipe` and `vsock` need a router built with
//! a transport feature the default build omits.
//!
//! Opt-in (`#[ignore]`) and binary-dependent: the router is named with `WZ_ZENOHD_BIN`
//! and the demo is the one `cargo build -p wz-ap-demo --features ws,tls,quic` produced.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_tcp_quic, spawn_zenohd_tcp_tls, spawn_zenohd_tcp_udp,
    spawn_zenohd_tcp_ws, wait_for_substring, wz_ap_demo_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// How a stock router is told to listen on a link: the TCP port is its readiness
/// gate, the link port is the one under test, and the two certificate links read
/// the PEM pair the caller wrote.
type SpawnRouter = fn(tcp_port: u16, link_port: u16, cert: &str, key: &str) -> ChildGuard;

struct Link {
    /// The locator scheme the demo dials, and the transport name it logs.
    scheme: &'static str,
    /// The demo's flag naming the CA to trust, for the links that carry a
    /// certificate. `None` for a link with no certificate.
    ca_flag: Option<&'static str>,
    spawn: SpawnRouter,
}

fn probe_stderr() -> File {
    tempfile::tempfile().expect("tempfile for readiness probe stderr")
}

fn router_over_ws(tcp: u16, link: u16, _cert: &str, _key: &str) -> ChildGuard {
    spawn_zenohd_tcp_ws(tcp, link, probe_stderr)
}

fn router_over_udp(tcp: u16, link: u16, _cert: &str, _key: &str) -> ChildGuard {
    spawn_zenohd_tcp_udp(tcp, link, probe_stderr)
}

fn router_over_tls(tcp: u16, link: u16, cert: &str, key: &str) -> ChildGuard {
    spawn_zenohd_tcp_tls(tcp, link, cert, key, probe_stderr)
}

fn router_over_quic(tcp: u16, link: u16, cert: &str, key: &str) -> ChildGuard {
    spawn_zenohd_tcp_quic(tcp, link, cert, key, probe_stderr)
}

const WS: Link = Link {
    scheme: "ws",
    ca_flag: None,
    spawn: router_over_ws,
};
const UDP: Link = Link {
    scheme: "udp",
    ca_flag: None,
    spawn: router_over_udp,
};
const TLS: Link = Link {
    scheme: "tls",
    ca_flag: Some("--tls-ca"),
    spawn: router_over_tls,
};
const QUIC: Link = Link {
    scheme: "quic",
    ca_flag: Some("--quic-ca"),
    spawn: router_over_quic,
};

/// The certificate, key and router config a certificate link writes, removed when
/// the test ends however it ends. The corpus removes them on the straight path only.
struct CertFiles {
    cert: PathBuf,
    key: PathBuf,
}

impl Drop for CertFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cert);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_file(format!("{}.zenohd.json5", self.cert.display()));
    }
}

fn handshake_over(link: &Link) {
    let demo = wz_ap_demo_binary();
    let (tcp_res, link_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();

    // Written for every link and read only by the two that carry a certificate: a
    // link without one never touches the files, and the guard removes whatever exists.
    let dir = std::env::temp_dir();
    let files = CertFiles {
        cert: dir.join(format!(
            "wz-host-interop-{}-{tcp_port}.cert.pem",
            link.scheme
        )),
        key: dir.join(format!(
            "wz-host-interop-{}-{tcp_port}.key.pem",
            link.scheme
        )),
    };
    if link.ca_flag.is_some() {
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        std::fs::write(&files.cert, cert_pem).expect("write cert pem");
        std::fs::write(&files.key, key_pem).expect("write key pem");
    }
    let cert = files.cert.to_string_lossy().into_owned();
    let key = files.key.to_string_lossy().into_owned();

    let mut zenohd = (link.spawn)(tcp_port, link_port, &cert, &key);
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut command = Command::new(&demo);
    command
        .arg("--connect")
        .arg(format!("{}/127.0.0.1:{link_port}", link.scheme));
    if let Some(flag) = link.ca_flag {
        command.arg(flag).arg(&cert);
    }
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect <link>/zenohd --publish)",
        command
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg(format!("{}-handshake-probe", link.scheme))
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
            "wz-ap-demo did not log 'session Established' within 10s over {}: the \
             wz<->zenohd handshake did not interoperate on this host.\n\
             --- captured wz-ap-demo stderr ---\n{c}",
            link.scheme
        );
    }
    // Witness the link. The router's listener for this link is on a port of its own
    // and the TCP port is a separate one, so a TCP dial could not reach Established
    // here; but that is an inference, and the demo logs the transport it dialed.
    let witness = format!("over {} transport", link.scheme);
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
