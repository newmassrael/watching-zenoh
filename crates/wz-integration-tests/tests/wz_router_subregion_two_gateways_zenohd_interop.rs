// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 751 — a ROUTER placed in two routers' south subregion, on the
//! wire: two gateways, and exactly one of them carries each Put across the
//! boundary, against two stock zenohds doing the same.
//!
//! ## Topology
//!
//! ```text
//!        pico z_sub/z_pub (client) ── N  (zenohd, auto)
//!                                   /   \
//!                                 W1     W2     both partitioned: Z is south
//!                                   \   /
//!        pico z_pub/z_sub (client) ── Z  (zenohd, auto)
//! ```
//!
//! W1 and W2 run `gateway/south` = one subregion holding Z by zid, so each puts
//! Z in its subregion's ROUTER region, announces SOUTH to Z on the Open, and Z
//! places each in its own north with the remote as its gateway
//! (`zenoh/src/net/runtime/region.rs` @ `(None, Some(Bound::South)) => Ok((Region::North, Bound::South)),`).
//! N is a plain router north of both.
//!
//! ## Why a count of one is the claim
//!
//! Z holds a subscription from each gateway, since each carries N's subscriber
//! south, so Z sends a Put to BOTH. What keeps N's subscriber from receiving it
//! twice is the inter-region filter alone: of the gateways the forwarder links
//! to, only the largest carries a message across the boundary
//! (`zenoh/src/net/routing/dispatcher/tables.rs` @ `pub(crate) struct InterRegionFilter<'a> {`).
//! A gateway that does not know the other one is a gateway (its south net not a
//! full link-state mesh) or that does not filter, delivers twice. Down from N
//! the same holds per egress neighbour: both gateways receive the Put and only
//! one carries it to Z.
//!
//! A count of one is also what an unpartitioned mesh delivers, so the leg first
//! proves the partition is in force: Z's own logged decision for each gateway is
//! `Ok((North, South))`, which only an announced SOUTH bound produces.
//!
//! ## Legs
//!
//! The calibration runs W1 and W2 as zenohds with the same `gateway.south`, so
//! "exactly one copy" is the reference's behaviour and not an assumption. The
//! claim runs them as wz `--router-hat` nodes given the same text through
//! `--gateway-south`.
//!
//! ## Environment (`#[ignore]`, Layer Z)
//!
//! Needs zenohd, the zenoh-pico CLI and a `wz-ap-demo` built with
//! `router-hat-router,zenoh-config`.

use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_subscribed_zsub, wait_for_tcp_accept_alive, wz_ap_demo_binary,
    zenoh_pico_cli_binary, zenohd_binary, ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};

/// The zids, as zenoh spells them. W1 < W2 in every order a zid is compared by.
const N_ZID: &str = "a1b2c3d4";
const Z_ZID: &str = "c1b2c3d4";
const W1_ZID: &str = "e1";
const W2_ZID: &str = "e2";

/// The partition both gateways run: one subregion, holding Z by zid.
const SOUTH: &str = r#"[ { filters: [ { zids: ["c1b2c3d4"] } ] } ]"#;

const KEY_UP: &str = "demo/subregion/up";
const KEY_DOWN: &str = "demo/subregion/down";
const VALUE_UP: &str = "FROM-Z-TO-N";
const VALUE_DOWN: &str = "FROM-N-TO-Z";
/// Puts per direction. pico's z_pub sends one a second.
const PUTS: usize = 6;
/// Time for the four routers to exchange link state and declarations before a
/// subscriber is declared, and for a subscriber to reach the far side.
const CONVERGE: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Gateways {
    Zenohd,
    Wz,
}

fn tempfile() -> File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// A zenohd router config.
fn zenohd_config(zid: &str, listen: u16, connect: &[u16], south: &str) -> tempfile::NamedTempFile {
    let mut config = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("zenohd config file");
    let connect: Vec<String> = connect
        .iter()
        .map(|p| format!("\"tcp/127.0.0.1:{p}\""))
        .collect();
    write!(
        config,
        "{{ mode: \"router\", id: \"{zid}\", \
         listen: {{ endpoints: [\"tcp/127.0.0.1:{listen}\"] }}, \
         connect: {{ endpoints: [{}] }}, \
         scouting: {{ multicast: {{ enabled: false }} }}, \
         gateway: {{ south: {south} }} }}",
        connect.join(", ")
    )
    .expect("write zenohd config");
    config
}

/// A running zenohd and the file its log goes to.
struct Zenohd {
    guard: ChildGuard,
    log: File,
    _config: tempfile::NamedTempFile,
}

fn spawn_zenohd(label: &str, zid: &str, listen: u16, connect: &[u16], south: &str) -> Zenohd {
    let config = zenohd_config(zid, listen, connect, south);
    let log = tempfile();
    let reader = log.try_clone().expect("dup log handle");
    let mut guard = ChildGuard::wrap(
        label,
        Command::new(zenohd_binary())
            .arg("-c")
            .arg(config.path())
            .args(["--rest-http-port", "none"])
            .env("RUST_LOG", "zenoh=debug")
            .stdout(Stdio::from(log.try_clone().expect("dup log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), listen, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("{label}: {e}");
    }
    Zenohd {
        guard,
        log: reader,
        _config: config,
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for n in chars.by_ref() {
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// zenohd's logged `compute_region_of` answer for the remote `zid`.
fn region_decision(log: &str, zid: &str) -> Option<String> {
    log.lines().map(strip_ansi).find_map(|line| {
        (line.contains(&format!("peer.zid={zid} ")) && line.contains("compute_region_of"))
            .then(|| {
                line.split_once("return=")
                    .map(|(_, r)| r.trim().to_string())
            })
            .flatten()
    })
}

/// How many times each Put index `0..PUTS` of `value` reached a pico z_sub.
fn copies_per_put(captured: &str, value: &str) -> Vec<usize> {
    let mut copies = vec![0; PUTS];
    for line in captured.lines() {
        if !line.contains("Received") || !line.contains(value) {
            continue;
        }
        // The payload is `[   n] value`, after the `': '` that follows the key
        // (the line's first bracket is pico's own `[Subscriber]` tag).
        let index = line
            .split_once("': '[")
            .and_then(|(_, rest)| rest.split_once(']'))
            .and_then(|(n, _)| n.trim().parse::<usize>().ok());
        if let Some(i) = index.filter(|i| *i < PUTS) {
            copies[i] += 1;
        }
    }
    copies
}

/// A pico z_pub client sending `PUTS` Puts of `value` on `key` through
/// `endpoint`, run to completion; returns what it printed.
fn publish(key: &str, value: &str, endpoint: &str) -> String {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let out = tempfile();
    let mut reader = out.try_clone().expect("dup z_pub stdout");
    let err = out.try_clone().expect("dup z_pub stderr");
    let mut child = ChildGuard::wrap(
        "z_pub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args(["-k", key, "-v", value, "-e", endpoint, "-m", "client"])
            .args(["-n", &PUTS.to_string()])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn z_pub"),
    );
    let deadline = Instant::now() + Duration::from_secs(PUTS as u64 + 20);
    loop {
        if let Ok(Some(_)) = child.child_mut().try_wait() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    read_captured(&mut reader)
}

/// What one run measured.
struct Outcome {
    /// Z's region decision for W1 and for W2.
    z_places: [Option<String>; 2],
    /// Copies of each Put published at Z that N's subscriber received.
    up: Vec<usize>,
    /// Copies of each Put published at N that Z's subscriber received.
    down: Vec<usize>,
    diagnostics: String,
}

fn run(gateways: Gateways) -> Outcome {
    // One reservation at a time, held only until its child has bound the port.
    let spawn_reserved = |label: &str, zid: &str, connect: &[u16], south: &str| {
        let reservation = PortReservation::pick();
        let port = reservation.port();
        let node = spawn_zenohd(label, zid, port, connect, south);
        drop(reservation);
        (node, port)
    };
    let (mut n, n_port) = spawn_reserved("zenohd N", N_ZID, &[], r#""auto""#);
    let (mut z, z_port) = spawn_reserved("zenohd Z", Z_ZID, &[], r#""auto""#);
    let n_endpoint = format!("tcp/127.0.0.1:{n_port}");
    let z_endpoint = format!("tcp/127.0.0.1:{z_port}");

    // ── W1 and W2, each dialling N and Z. ──
    let mut gateway_logs: Vec<(String, File)> = Vec::new();
    let mut gateway_guards: Vec<ChildGuard> = Vec::new();
    let mut zenohd_gateways: Vec<Zenohd> = Vec::new();
    for zid in [W1_ZID, W2_ZID] {
        match gateways {
            Gateways::Zenohd => {
                let (w, _) = spawn_reserved("zenohd gateway", zid, &[n_port, z_port], SOUTH);
                zenohd_gateways.push(w);
            }
            Gateways::Wz => {
                let demo = wz_ap_demo_binary();
                assert_demo_binary_newer_than_sources(&demo);
                let connect = format!("127.0.0.1:{n_port},127.0.0.1:{z_port}");
                let (guard, reader, _port) = spawn_on_ephemeral_port(
                    &demo,
                    &[
                        "--router-hat",
                        "127.0.0.1:0",
                        "--zid",
                        zid,
                        "--connect",
                        &connect,
                        "--gateway-south",
                        SOUTH,
                    ],
                    "router-hat: listening on 127.0.0.1:",
                    "wz gateway",
                    tempfile(),
                );
                gateway_guards.push(guard);
                gateway_logs.push((zid.to_string(), reader));
            }
        }
    }
    std::thread::sleep(CONVERGE);

    // ── Up: subscribe at N, publish at Z. ──
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (n_sub, mut n_sub_out) =
        spawn_subscribed_zsub(&z_sub, KEY_UP, &n_endpoint, "router N", tempfile);
    std::thread::sleep(CONVERGE);
    let up_pub = publish(KEY_UP, VALUE_UP, &z_endpoint);
    std::thread::sleep(Duration::from_secs(2));
    let n_sub_text = read_captured(&mut n_sub_out);
    drop(n_sub);

    // ── Down: subscribe at Z, publish at N. ──
    let (z_sub_guard, mut z_sub_out) =
        spawn_subscribed_zsub(&z_sub, KEY_DOWN, &z_endpoint, "router Z", tempfile);
    std::thread::sleep(CONVERGE);
    let down_pub = publish(KEY_DOWN, VALUE_DOWN, &n_endpoint);
    std::thread::sleep(Duration::from_secs(2));
    let z_sub_text = read_captured(&mut z_sub_out);
    drop(z_sub_guard);

    let z_log = strip_ansi(&read_captured(&mut z.log));
    let z_places = [
        region_decision(&z_log, W1_ZID),
        region_decision(&z_log, W2_ZID),
    ];

    let mut diagnostics = format!(
        "--- N's subscriber ---\n{n_sub_text}\n--- Z's publisher ---\n{up_pub}\n\
         --- Z's subscriber ---\n{z_sub_text}\n--- N's publisher ---\n{down_pub}\n"
    );
    for (zid, mut log) in gateway_logs {
        diagnostics.push_str(&format!(
            "--- wz gateway {zid} ---\n{}\n",
            read_captured(&mut log)
        ));
    }
    for mut guard in gateway_guards {
        graceful_terminate(guard.child_mut(), Duration::from_secs(5));
    }
    for mut w in zenohd_gateways {
        let _ = w.guard.child_mut().kill();
        let _ = w.guard.child_mut().wait();
    }
    let _ = n.guard.child_mut().kill();
    let _ = n.guard.child_mut().wait();
    let _ = z.guard.child_mut().kill();
    let _ = z.guard.child_mut().wait();

    Outcome {
        z_places,
        up: copies_per_put(&n_sub_text, VALUE_UP),
        down: copies_per_put(&z_sub_text, VALUE_DOWN),
        diagnostics,
    }
}

fn assert_one_copy_each_way(who: &str, o: &Outcome) {
    for (i, place) in o.z_places.iter().enumerate() {
        assert_eq!(
            place.as_deref(),
            Some("Ok((North, South))"),
            "{who}: Z did not place gateway W{} as its gateway, so the partition is \
             not in force and a count of one would prove nothing\n{}",
            i + 1,
            o.diagnostics
        );
    }
    for (direction, copies) in [("up (Z to N)", &o.up), ("down (N to Z)", &o.down)] {
        assert!(
            copies.iter().any(|c| *c > 0),
            "{who}: no Put crossed {direction}; the boundary routed nothing\n{}",
            o.diagnostics
        );
        assert!(
            copies.iter().all(|c| *c <= 1),
            "{who}: a Put crossed {direction} more than once (copies per Put {copies:?}); \
             both gateways carried it\n{}",
            o.diagnostics
        );
    }
}

/// THE CALIBRATION: two stock gateways deliver each Put once in each direction.
// wz-proves: none -- harness entry; calibrates the leg below against two zenohds,
// which adjudicate what a pair of gateways does with a Put across a router
// subregion.
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico); Layer Z runs via --ignored"]
fn zenohd_gateways_carry_each_put_across_a_router_subregion_once() {
    let outcome = run(Gateways::Zenohd);
    assert_one_copy_each_way("zenohd gateways", &outcome);
}

/// THE CLAIM: two wz gateways do the same.
// wz-proves: none -- the gateway/south key is still unhonoured (the demo flag is
// the only way to run a partition), so no atom claims the partition yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico + wz-ap-demo --features router-hat-router,zenoh-config); Layer Z runs via --ignored"]
fn wz_gateways_carry_each_put_across_a_router_subregion_once_like_zenohd() {
    let outcome = run(Gateways::Wz);
    assert_one_copy_each_way("wz gateways", &outcome);
}
