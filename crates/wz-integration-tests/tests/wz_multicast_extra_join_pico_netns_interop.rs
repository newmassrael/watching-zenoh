// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2586 — the `#join=` multicast locator key, witnessed by a FOREIGN sender:
//! a zenoh-pico `z_pub -m peer` in its own network namespace publishes to a
//! group that is NOT the wz socket's own, and wz receives it only because
//! `#join=` installed that membership on the interface `#iface=` names.
//!
//! # Why every earlier witness of `join` was wz-only
//!
//! The atom's own reason recorded it: "no foreign witness exercises ttl or join".
//! On one host that is not an omission but a collapse. A foreign peer that
//! sends to a group has JOINED it, and with `IP_MULTICAST_ALL` (Linux default 1,
//! which neither wz nor zenoh's UDP link clears) a wildcard-bound wz socket on
//! the same device receives any group joined anywhere on that device. So wz
//! would receive the peer's group whether or not `#join=` did anything.
//!
//! A network namespace puts the peer's membership on ITS OWN device. Measured
//! before this file was written, with the same pico binary and the same veth
//! pair: a host socket bound to the port received nothing in 6s without the
//! membership, and pico's 25-byte datagram with it.
//!
//! # The arms, and what each one rules out
//!
//! Every arm binds wz for [`OWN_GROUP`] on one port while pico sends only to
//! [`EXTRA_GROUP`]. The two SILENT arms run first, so that no membership for the
//! extra group exists on the veth before the positive arm installs one:
//!
//! 1. NO `#join=`, `#iface=` pinned to the veth — must receive NOTHING. Without
//!    this arm a delivery would say nothing about `join`.
//! 2. `#join=` present, `#iface=` ABSENT — must receive NOTHING. An unpinned
//!    membership is installed on the kernel's default multicast device, which is
//!    not the veth, so this arm shows the interface the join is installed on is
//!    load-bearing. zenoh passes the resolved interface to every join in its
//!    loop, and so does wz.
//! 3. `#join=` present AND `#iface=` pinned — must decode pico's Push and admit
//!    its JOIN.
//!
//! A silent arm can also be silent because pico never started. Arm 3 runs
//! against the SAME pico process, started once before arm 1, so a pico that
//! failed to publish reds arm 3 instead of greening arms 1 and 2.
//!
//! # What this does not witness
//!
//! `ttl`. A veth pair is one link, and a TTL of 1 and of 8 both arrive
//! (`scripts/lib/netns-topology.sh`'s header records that measurement).

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, zenoh_pico_cli_binary, ChildGuard, NetnsPair, PICO_BATCH_MULTICAST_SIZE,
    PICO_PROTO_VERSION, PICO_SN_RESOLUTION,
};
use wz_runtime_tokio::multicast_glue::{drive_multicast_session, MulticastDriveConfig};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::WhatAmI;

/// The wz socket's OWN group, which pico never sends to.
const OWN_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 10);
/// The group pico sends to, reachable by wz only through `#join=`. Both groups
/// sit in the organization-local 239.0.0.0/8 scope, which no other test, lane or
/// zenoh default uses, so no stray membership can deliver them.
const EXTRA_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 11);
/// A port no other multicast lane binds.
const PORT: u16 = 7474;
const KEY: &str = "demo/mc/extrajoin";
const VALUE: &str = "WZ-MCAST-EXTRA-JOIN-R2586";
const HOST_CIDR: &str = "10.251.8.1/30";
const PEER_CIDR: &str = "10.251.8.2/30";

/// Long enough for three of pico's JOIN beacons (`Z_JOIN_INTERVAL` 2500 ms in
/// `vendor/zenoh-pico/include/zenoh-pico/config.h.in`) and eight of its once-a-second
/// Puts, so a silent arm is silent across several chances, not one.
const SILENT_BUDGET: Duration = Duration::from_secs(8);
const DELIVERY_BUDGET: Duration = Duration::from_secs(15);

fn wz_mc_params() -> MulticastParams {
    MulticastParams {
        version: PICO_PROTO_VERSION,
        whatami: WhatAmI::Peer,
        zid: vec![0x7a; 4],
        lease_ms: 5_000,
        join_interval_ms: 50,
        seq_num_res: PICO_SN_RESOLUTION,
        req_id_res: PICO_SN_RESOLUTION,
        batch_size: PICO_BATCH_MULTICAST_SIZE,
        is_qos: false,
    }
}

/// Bind wz for [`OWN_GROUP`] with `cfg`, drive the multicast session for up to
/// `budget`, and report `(pushes decoded, peers admitted)`.
async fn receive(cfg: McastSocketConfig<'_>, budget: Duration) -> (usize, usize) {
    let mut driver = UdpDriver::bind_multicast(OWN_GROUP, PORT, cfg)
        .await
        .expect("bind the wz multicast socket");
    let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params = wz_mc_params();
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        observer.subscribers.register(KEY, move |sample| {
            assert!(
                String::from_utf8_lossy(sample.payload()).ends_with(VALUE),
                "a decoded Push carries pico's value"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }
    let (_hold, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let clock = TokioTime::new();
    let drive = drive_multicast_session(
        &mut dispatcher,
        MulticastDriveConfig {
            params: &params,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver,
        &clock,
        |event| observer.dispatch_event(event),
        &mut rx,
    );
    let fired_probe = fired.clone();
    let wait = async move {
        let deadline = tokio::time::Instant::now() + budget;
        while tokio::time::Instant::now() < deadline {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::select! {
        _ = drive => panic!("the wz multicast drive loop ended unexpectedly"),
        _ = wait => {}
    }
    (fired.load(Ordering::SeqCst), dispatcher.active_peers())
}

// wz-proves: transport-link-udp pico->wz partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep multicast e2e (zenoh-pico CLI z_pub) inside a network namespace \
            (sudo); Layer M runs via --ignored"]
async fn multicast_extra_join_is_what_delivers_a_foreign_group_across_a_namespace() {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    // Declared BEFORE the pico child, so it drops AFTER it: its drop kills
    // whatever the child left in the namespace, then deletes the namespace.
    let netns = NetnsPair::up("xjoin", HOST_CIDR, PEER_CIDR);
    let host_iface = netns.host_iface();
    let locator = format!("udp/{EXTRA_GROUP}:{PORT}#iface={}", netns.peer_iface());

    let capture = tempfile::tempfile().expect("tempfile for the z_pub capture");
    let mut reader = capture.try_clone().expect("dup the capture handle");
    let _z_pub = ChildGuard::wrap(
        "z_pub multicast peer (zenoh-pico) in a namespace",
        netns
            .command(std::path::Path::new("stdbuf"))
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args([
                "-k", KEY, "-v", VALUE, "-l", &locator, "-m", "peer", "-n", "60",
            ])
            .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
            .stderr(Stdio::from(capture))
            .spawn()
            .expect("spawn z_pub inside the namespace"),
    );

    let extra = [EXTRA_GROUP.to_string()];

    let (unjoined, _) = receive(
        McastSocketConfig {
            iface: Some(&host_iface),
            ..Default::default()
        },
        SILENT_BUDGET,
    )
    .await;
    assert_eq!(
        unjoined, 0,
        "a wz socket with NO #join= decoded pico's Push for {EXTRA_GROUP}; something \
         other than the join delivers that group, so the positive arm proves nothing"
    );

    let (unpinned, _) = receive(
        McastSocketConfig {
            extra_joins: &extra,
            ..Default::default()
        },
        SILENT_BUDGET,
    )
    .await;
    assert_eq!(
        unpinned, 0,
        "#join= WITHOUT #iface= still delivered pico's group from the veth; the join's \
         interface is then not what decides delivery, and the positive arm cannot say \
         the pin took effect"
    );

    let (joined, admitted) = receive(
        McastSocketConfig {
            iface: Some(&host_iface),
            extra_joins: &extra,
            ..Default::default()
        },
        DELIVERY_BUDGET,
    )
    .await;
    assert!(
        joined >= 1,
        "wz given #join={EXTRA_GROUP} and #iface={host_iface} decoded no pico Push in \
         {DELIVERY_BUDGET:?} on {locator}\n--- captured z_pub ---\n{}",
        read_captured(&mut reader)
    );
    assert_eq!(
        admitted, 1,
        "the foreign peer reached wz's dispatcher through the extra group's JOIN"
    );
}
