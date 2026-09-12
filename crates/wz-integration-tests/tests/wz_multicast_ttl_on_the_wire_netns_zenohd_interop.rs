// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2587 — the multicast `ttl` locator key, adjudicated by a FOREIGN
//! implementation on the WIRE: zenohd and a wz router, each told
//! `--listen`/`--multicast-locator udp/<group>:<port>#iface=<veth>;ttl=<n>`, must
//! put the same value in the IP TTL field of what they send, and it must differ
//! from what each puts there without the key.
//!
//! # Why this does not need a routed hop
//!
//! Every earlier note on this key said a foreign `ttl` witness needs a router
//! between sender and receiver, including `scripts/lib/netns-topology.sh`'s own
//! header, because a veth pair delivered TTL 1 and TTL 8 alike. That measures
//! REACH, and reach is the kernel forwarding a datagram. What the key controls
//! is narrower: the value the IMPLEMENTATION writes into the header
//! (`IP_MULTICAST_TTL` on its sending socket). A receiver on the far side of one
//! link reads that value unchanged, because nothing between them decrements it.
//! Measured before this file was written, with zenohd and a raw `IP_RECVTTL`
//! reader in the namespace: `ttl=5` arrived as 5, and no key arrived as 1.
//!
//! So the observable is the header field, the reader is independent of both
//! implementations (plain libc, `common::read_multicast_ttl_v4`), and zenohd is the
//! adjudicator. Whether TTL 5 then crosses five routers is kernel behaviour and
//! nobody's implementation; this file does not claim it.
//!
//! # Why the reader runs in a namespace
//!
//! The sender's egress is pinned to the host end of the veth, so the only place
//! its datagram arrives from outside is the peer end. A reader on the host would
//! see the sender's own multicast loopback, whose TTL the kernel may present
//! differently from what went on the wire.
//!
//! # The reader is this test binary, re-executed
//!
//! It runs inside the namespace, so it must be a process started there. Rather
//! than a second binary, the witness re-runs ITSELF with `--exact
//! multicast_ttl_reader_entry`, carrying the request in [`READER_ENV`]
//! (`layer3_keyexpr_canon.rs`'s harness shape). `sudo` resets the environment,
//! so the variable travels as an `env` argument inside the namespace. Without
//! the variable, that entry is the reader's own CALIBRATION: on `lo` it must
//! read back two DIFFERENT values it set itself, so a reader that always
//! answers one number cannot pass the witness.

use std::io::Write as _;
use std::net::{Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, read_multicast_ttl_v4, wz_ap_demo_binary,
    zenohd_binary, ChildGuard, NetnsPair,
};

const READER_ENV: &str = "WZ_MULTICAST_TTL_READER";
const READER_ENTRY: &str = "multicast_ttl_reader_entry";
const READER_MARKER: &str = "<<<WZ-TTL-READER>>>";

const HOST_CIDR: &str = "10.251.10.1/30";
const PEER_CIDR: &str = "10.251.10.2/30";
const PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 251, 10, 2);
/// The hop limit the key asks for. Not 1, which is the OS default, so the arm
/// with the key and the arm without it can only agree if the key did nothing.
const REQUESTED_TTL: u8 = 5;
const DEFAULT_TTL: u8 = 1;
/// Longer than zenoh's multicast `join_interval` (2500 ms, the value zenohd
/// printed in its initial config) plus its startup, so a sender that is sending
/// is observed.
const READ_BUDGET: Duration = Duration::from_secs(12);

/// Run the reader INSIDE the namespace. The caller starts the sender only after
/// this, so the child has joined before the first beacon.
///
/// Not wrapped in `ChildGuard`: the reader ends on its own within
/// [`READ_BUDGET`], and a process started through `sudo` is not reachable by
/// killing the child anyway. `NetnsPair`'s drop kills whatever is left in the
/// namespace.
fn spawn_reader(netns: &NetnsPair, group: Ipv4Addr, port: u16) -> std::process::Child {
    let exe = std::env::current_exe().expect("the test binary's path");
    let request = format!("{group} {port} {PEER_ADDR} {}", READ_BUDGET.as_millis());
    netns
        .command(std::path::Path::new("env"))
        .arg(format!("{READER_ENV}={request}"))
        .arg(exe)
        .args(["--exact", READER_ENTRY, "--ignored", "--nocapture"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the TTL reader inside the namespace")
}

/// The reader's verdict: `Some(ttl)` read, `None` nothing arrived in budget.
fn reader_result(reader: std::process::Child) -> Option<u8> {
    let out = reader.wait_with_output().expect("wait for the TTL reader");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload = stdout
        .split_once(READER_MARKER)
        .map(|(_, tail)| tail.trim().to_string())
        .unwrap_or_else(|| {
            panic!(
                "the TTL reader printed no verdict (status {:?})\n--- stdout ---\n{stdout}\n\
                 --- stderr ---\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        });
    match payload.as_str() {
        "none" => None,
        n => Some(n.parse().expect("the reader prints a TTL or `none`")),
    }
}

/// One arm: start a reader for `group:port`, start `sender`, and return the TTL
/// read together with everything the sender wrote. An arm that reads nothing is
/// diagnosed from the sender's OWN log. R2587's first run read `None` from a
/// demo whose log said `#iface=` was ignored, and with its output discarded
/// that line was invisible.
fn ttl_on_the_wire(
    netns: &NetnsPair,
    group: Ipv4Addr,
    port: u16,
    mut sender: Command,
    label: &str,
) -> (Option<u8>, String) {
    let reader = spawn_reader(netns, group, port);
    // Give the child time to join before the first beacon.
    std::thread::sleep(Duration::from_millis(800));
    let capture = tempfile::tempfile().expect("tempfile for the sender's output");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let sender = ChildGuard::wrap(
        label.to_string(),
        sender
            .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
            .stderr(Stdio::from(capture))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let ttl = reader_result(reader);
    drop(sender);
    (ttl, read_captured(&mut log))
}

fn endpoint(group: Ipv4Addr, port: u16, iface: &str, ttl: Option<u8>) -> String {
    match ttl {
        Some(t) => format!("udp/{group}:{port}#iface={iface};ttl={t}"),
        None => format!("udp/{group}:{port}#iface={iface}"),
    }
}

// wz-proves: none -- harness entry; calibrates `read_multicast_ttl_v4` on two
// different TTLs so the witness that uses it is not vacuous, and serves as the
// re-exec target that reads the wire inside the namespace. It witnesses no atom.
#[test]
#[ignore = "real multicast on lo plus the re-exec half of the namespace TTL witness; \
            Layer M runs via --ignored"]
fn multicast_ttl_reader_entry() {
    if let Ok(request) = std::env::var(READER_ENV) {
        let parts: Vec<&str> = request.split_whitespace().collect();
        let [group, port, iface, budget_ms] = parts[..] else {
            panic!("reader request `{request}` is not `<group> <port> <iface> <ms>`");
        };
        let ttl = read_multicast_ttl_v4(
            group.parse().expect("group"),
            port.parse().expect("port"),
            iface.parse().expect("iface address"),
            Duration::from_millis(budget_ms.parse().expect("budget")),
        );
        print!(
            "{READER_MARKER}{}",
            ttl.map_or_else(|| "none".to_string(), |t| t.to_string())
        );
        std::io::stdout().flush().ok();
        std::process::exit(0);
    }

    // CALIBRATION: two different values the reader must tell apart, set by a
    // plain std socket and looped back on `lo`.
    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 30);
    for (port, ttl) in [(7480u16, 3u32), (7481, 7)] {
        let reader = std::thread::spawn(move || {
            read_multicast_ttl_v4(GROUP, port, Ipv4Addr::LOCALHOST, Duration::from_secs(3))
        });
        std::thread::sleep(Duration::from_millis(300));
        let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a sender on lo");
        tx.set_multicast_ttl_v4(ttl).expect("set the TTL");
        tx.set_multicast_loop_v4(true).expect("loop back");
        for _ in 0..5 {
            tx.send_to(b"calibration", (GROUP, port)).expect("send");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            reader.join().expect("reader thread"),
            Some(ttl as u8),
            "the reader must report the TTL the sender set, or the witness reads a constant"
        );
    }
}

// wz-proves: transport-link-udp zenohd->wz partial
#[test]
#[ignore = "binary-dep multicast e2e (zenohd + wz-ap-demo router-multicast-faces) inside a \
            network namespace (sudo); Layer M runs via --ignored"]
fn multicast_ttl_key_reaches_the_wire_as_zenohd_puts_it() {
    let zenohd = zenohd_binary();
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let netns = NetnsPair::up("ttl", HOST_CIDR, PEER_CIDR);
    let iface = netns.host_iface();

    let zenohd_arm = |group: Ipv4Addr, port: u16, ttl: Option<u8>| {
        let mut cmd = Command::new(&zenohd);
        cmd.args([
            "--no-multicast-scouting",
            "-l",
            &endpoint(group, port, &iface, ttl),
        ]);
        ttl_on_the_wire(&netns, group, port, cmd, "zenohd multicast listener")
    };
    let wz_arm = |group: Ipv4Addr, port: u16, ttl: Option<u8>| {
        let mut cmd = Command::new(&demo);
        cmd.args([
            "--router-hat",
            "127.0.0.1:0",
            "--multicast-locator",
            &endpoint(group, port, &iface, ttl),
        ]);
        ttl_on_the_wire(
            &netns,
            group,
            port,
            cmd,
            "wz-ap-demo router-hat multicast face",
        )
    };

    // A distinct group AND port per arm: a stale sender from one arm must never
    // be what the next arm's reader hears.
    let (zenohd_with, zw_log) =
        zenohd_arm(Ipv4Addr::new(239, 255, 73, 31), 7482, Some(REQUESTED_TTL));
    let (zenohd_without, zo_log) = zenohd_arm(Ipv4Addr::new(239, 255, 73, 32), 7483, None);
    let (wz_with, ww_log) = wz_arm(Ipv4Addr::new(239, 255, 73, 33), 7484, Some(REQUESTED_TTL));
    let (wz_without, wo_log) = wz_arm(Ipv4Addr::new(239, 255, 73, 34), 7485, None);

    // The adjudicator first: if zenohd does not show the difference, this
    // substrate cannot show it and the wz half would prove nothing.
    assert_eq!(
        (zenohd_with, zenohd_without),
        (Some(REQUESTED_TTL), Some(DEFAULT_TTL)),
        "zenohd must put ttl={REQUESTED_TTL} on the wire with the key and {DEFAULT_TTL} \
         without it\n--- zenohd with the key ---\n{zw_log}\n--- zenohd without ---\n{zo_log}"
    );
    assert_eq!(
        (wz_with, wz_without),
        (zenohd_with, zenohd_without),
        "wz must put the same TTL on the wire as zenohd, with the key and without it\n\
         --- wz with the key ---\n{ww_log}\n--- wz without ---\n{wo_log}"
    );
}
