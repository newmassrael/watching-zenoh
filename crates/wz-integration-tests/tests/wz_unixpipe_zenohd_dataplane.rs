// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y393 — wz <-> zenohd cross-impl DATA-PLANE interop over a UNIXPIPE
//! (named-FIFO) link.
//!
//! `wz_unixpipe_zenohd_interop.rs` proves only the HANDSHAKE reaches Established
//! (both dial directions). This file proves the next thing: a real `Put` SAMPLE
//! traverses the unixpipe link and is delivered to a subscriber, in BOTH data
//! directions AND across both the DIALED and the ACCEPTED unixpipe link — the
//! named-FIFO member of the `wz_to_zenohd_router::wz_publish_routes_through_
//! zenohd_to_pico_zsub_over_<X>` family (tcp/ws/tls/quic/unixsock) plus the
//! acceptor-direction proof modelled on `wz_ws_acceptor_zenohd_interop`.
//!
//! zenoh-pico has NO unixpipe link (it is a zenoh-full-only transport), so the
//! unixpipe hop is always wz <-> zenohd and a real zenoh-pico client attaches to
//! zenohd over TCP — a STAR through zenohd that makes an INDEPENDENT impl the
//! data-plane source/sink:
//!
//!   Leg 1 (forward, wz dials):  wz `--connect unixpipe/<b> --publish`  --unixpipe-->
//!       zenohd  --tcp-->  pico `z_sub`. A wz Put crosses the DIALED unixpipe link
//!       and pico prints it; the pico sink prints the VALUE, so payload integrity
//!       is asserted end-to-end.
//!   Leg 2 (reverse, wz dials):  pico `z_pub`  --tcp-->  zenohd  --unixpipe-->
//!       wz `--connect unixpipe/<b> --key` (routed subscriber). A pico Put crosses
//!       the DIALED unixpipe link in the OTHER direction into wz's subscriber.
//!   Leg 3 (reverse, wz ACCEPTS):  pico `z_pub`  --tcp-->  zenohd  --unixpipe(zenohd
//!       DIALS wz's multi-client acceptor)-->  wz `--listen unixpipe/<b> --key`.
//!       Proves the accepted unixpipe link produced by the R311y392 multi-client
//!       acceptor carries the data plane, not just the handshake (ONE concurrent
//!       client here — multi-client concurrency itself is a y392 handshake-level
//!       proof) — the acceptor twin of the ws/tls acceptor cross-impl legs.
//!
//! `#[ignore]` (binary-dep e2e): needs a UNIXPIPE-ENABLED zenohd at
//! `target/zenohd-unixpipe/zenohd` (stock zenohd omits `transport_unixpipe`; build
//! with `ZENOHD_UNIXPIPE=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh`), a
//! `wz-ap-demo` compiled with `transport-link-unixpipe`, AND the zenoh-pico CLI
//! (`z_sub` / `z_pub`). All run as the SAME uid (wz `mkfifo`s the request node
//! 0o600; run-ci Layer Z provisions everything). Linux-only (the unixpipe backend's
//! `read_write` open-rendezvous).

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_publishing_zpub, spawn_subscribed_zsub, spawn_zenohd_unixpipe_dialer,
    spawn_zenohd_unixpipe_tcp, wait_for_substring, wait_for_unixpipe_request_fifo,
    wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// A per-process-unique unixpipe base path under the temp dir; the request FIFO is
/// `<base>_uplink`. Distinct suffix per leg so parallel test binaries never share
/// nodes. A dedicated `dp-` prefix keeps it disjoint from `wz_unixpipe_zenohd_
/// interop`'s `wz-uxp-zenohd-` bases.
fn unixpipe_base(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("wz-uxp-dp-{tag}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Best-effort cleanup of a base's request FIFO AND every dedicated per-connection
/// sub-pipe node (`{base}_uplink`/`{base}_downlink` plus their decimal-suffixed
/// `..._uplink<N>`/`..._downlink<N>` twins). The dedicated read-ends normally
/// auto-unlink on Drop, but the tests SIGKILL their children (`kill()`), so Drop
/// never runs; this globs the whole `{base}_uplink*`/`{base}_downlink*` family so no
/// 0-byte FIFO inode accumulates across runs. A stale node is harmless regardless —
/// `base` embeds the pid, so a fresh run never collides — this is temp-dir hygiene.
fn cleanup(base: &str) {
    let path = std::path::Path::new(base);
    let (dir, name) = match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => (dir.to_path_buf(), name.to_string_lossy().into_owned()),
        _ => return,
    };
    let up = format!("{name}_uplink");
    let down = format!("{name}_downlink");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if fname.starts_with(&up) || fname.starts_with(&down) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

const SUB_FILTER: &str = "demo/unixpipe/**";

/// Leg 1 — the FORWARD data plane over the DIALED unixpipe link: a wz `--connect
/// unixpipe/..` publisher's Put routes through zenohd (`unixpipe` in, `tcp` out)
/// to a real zenoh-pico `z_sub`. The pico sink prints the received value, so this
/// asserts the keyexpr AND the payload survived the unixpipe crossing; the
/// `over unixpipe transport` wz witness rules out a silent non-unixpipe path.
// wz-proves: codec-frame wz->zenohd (over unixpipe)
// wz-proves: codec-push wz->zenohd (over unixpipe)
// wz-proves: pubsub-sample wz->pico (across unixpipe)
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe] + zenoh-pico z_sub"]
fn wz_put_over_unixpipe_routes_through_zenohd_to_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let base = unixpipe_base("fwd");
    cleanup(&base);
    let tcp_res = PortReservation::pick();
    let tcp_port = tcp_res.port();
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/unixpipe/dp-fwd";
    let publish_value = "hello-from-wz-over-unixpipe";

    // zenohd LISTENS on unixpipe (for wz) + tcp (for pico); ready = tcp accept +
    // handshake probe + the request FIFO present.
    let mut zenohd = spawn_zenohd_unixpipe_tcp(&base, tcp_port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // pico z_sub over TCP — returns once it logs "Declaring Subscriber on", i.e.
    // the route is installed on zenohd, so the wz Put lands on a present route.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, SUB_FILTER, &tcp_endpoint, "zenohd-unixpipe", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // wz DIALS zenohd over UNIXPIPE and publishes its burst.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect unixpipe --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("unixpipe/{base}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe --publish"),
    );

    let received = wait_for_substring(
        &mut z_sub_reader,
        ">> [Subscriber] Received",
        Duration::from_secs(15),
    );
    // The non-fallback witness: wz really dialed over the unixpipe transport (a
    // silent fallback to another link would make the pico receipt prove the wrong
    // link). This line is emitted at connect, before the burst.
    let dialed = wait_for_substring(
        &mut demo_reader,
        "over unixpipe transport",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    cleanup(&base);

    let sub_captured = read_captured(&mut z_sub_reader);
    let demo_captured = read_captured(&mut demo_reader);
    eprintln!("--- pico z_sub stdout ---\n{sub_captured}");
    eprintln!("--- wz-ap-demo stderr ---\n{demo_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '>> [Subscriber] Received' within 15s — the wz Put did not \
             route across the unixpipe link through zenohd to the pico subscriber.\n\
             --- z_sub stdout ---\n{c}"
        )
    });
    dialed.unwrap_or_else(|c| {
        panic!(
            "wz-ap-demo never logged 'over unixpipe transport' within 10s — the publisher did not \
             dial zenohd over the unixpipe link, so the pico receipt would prove the wrong \
             transport.\n--- wz stderr ---\n{c}"
        )
    });
    assert!(
        received_text.contains(publish_key),
        "pico received a sample but not on the published keyexpr '{publish_key}'.\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "pico received '{publish_key}' but not the published value '{publish_value}' — the payload \
         was truncated or replaced crossing the unixpipe link.\n{received_text}"
    );
}

/// Leg 2 — the REVERSE data plane over the DIALED unixpipe link: a pico `z_pub`'s
/// Put routes through zenohd (`tcp` in, `unixpipe` out) into a wz `--connect
/// unixpipe/.. --key` routed subscriber. wz declares the subscriber (route installed
/// on zenohd) BEFORE pico publishes, so the ordering is deterministic, not a sleep.
/// The wz fire log carries `payload_len`, not the value, and pico `z_pub` formats
/// its payload, so — like `wz_routed_subscribe_from_zenohd` — the discriminator is
/// the UNIQUE keyexpr on the fired sample.
// wz-proves: declare-subscriber wz->zenohd (over unixpipe)
// wz-proves: codec-frame zenohd->wz (over unixpipe)
// wz-proves: pubsub-sample pico->wz (across unixpipe)
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe] + zenoh-pico z_pub"]
fn pico_put_routes_through_zenohd_over_unixpipe_to_wz_subscriber() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let base = unixpipe_base("rev");
    cleanup(&base);
    let tcp_res = PortReservation::pick();
    let tcp_port = tcp_res.port();
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/unixpipe/dp-rev";
    let publish_value = "hello-routed-to-wz-over-unixpipe";

    let mut zenohd = spawn_zenohd_unixpipe_tcp(&base, tcp_port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // wz DIALS zenohd over UNIXPIPE and declares a ROUTED subscriber.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect unixpipe --key)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("unixpipe/{base}"))
            .arg("--key")
            .arg(SUB_FILTER)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe --key"),
    );

    let dialed = wait_for_substring(
        &mut demo_reader,
        "over unixpipe transport",
        Duration::from_secs(10),
    );
    let declared = wait_for_substring(
        &mut demo_reader,
        "DECLARED ROUTED SUBSCRIBER",
        Duration::from_secs(10),
    );

    // pico z_pub over TCP — spawned only after wz's subscription propagated to
    // zenohd, so the route already exists; the 30x burst tolerates any residual
    // propagation lag (no-flaky).
    let z_pub_child = (dialed.is_ok() && declared.is_ok()).then(|| {
        spawn_publishing_zpub(
            &z_pub,
            publish_key,
            publish_value,
            &tcp_endpoint,
            "zenohd-unixpipe",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });

    let fired = wait_for_substring(
        &mut demo_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(15),
    );

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    cleanup(&base);

    let demo_captured = read_captured(&mut demo_reader);
    eprintln!("--- wz-ap-demo stderr ---\n{demo_captured}");

    dialed.unwrap_or_else(|c| {
        panic!(
            "wz-ap-demo never logged 'over unixpipe transport' within 10s — it did not dial \
             zenohd over the unixpipe link.\n--- wz stderr ---\n{c}"
        )
    });
    declared.unwrap_or_else(|c| {
        panic!(
            "wz-ap-demo never logged 'DECLARED ROUTED SUBSCRIBER' within 10s — the routed \
             subscriber declare (R311ou) regressed.\n--- wz stderr ---\n{c}"
        )
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the unixpipe link into wz's routed subscriber.\n\
             --- wz stderr ---\n{c}"
        )
    });
    assert!(
        fired_text.contains(publish_key),
        "wz fired but not on the routed keyexpr '{publish_key}'.\n{fired_text}"
    );
}

/// Leg 3 — the ACCEPTOR data plane: a pico `z_pub`'s Put routes through zenohd and
/// ACROSS a unixpipe link that ZENOHD DIALED INTO wz's MULTI-CLIENT ACCEPTOR
/// (R311y392), landing on wz's `--listen unixpipe/.. --key` subscriber. The
/// handshake legs prove the acceptor reaches Established; this proves the accepted
/// unixpipe link carries the DATA plane too — the named-FIFO twin of
/// `wz_ws_acceptor_zenohd_interop` / `wz_tls_acceptor_zenohd_interop`. The pico
/// publisher never speaks unixpipe and never knows wz's base, so the wz subscriber
/// firing is a definitive witness that data crossed the accepted unixpipe link.
// wz-proves: transport-link-unixpipe zenohd->wz (acceptor)
// wz-proves: codec-frame zenohd->wz (over accepted unixpipe)
// wz-proves: pubsub-sample pico->wz (across accepted unixpipe)
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe] + zenoh-pico z_pub"]
fn pico_put_routes_through_zenohd_to_wz_unixpipe_acceptor_subscriber() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let base = unixpipe_base("acc");
    cleanup(&base);
    let tcp_res = PortReservation::pick();
    let tcp_port = tcp_res.port();
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/unixpipe/dp-acc";
    let publish_value = "hello-to-wz-unixpipe-acceptor";

    // wz is the multi-client ACCEPTOR (`--listen unixpipe/..`) + a routed subscriber.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let wz_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_reader = wz_stderr;
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--listen unixpipe --key)",
        Command::new(&demo)
            .arg("--listen")
            .arg(format!("unixpipe/{base}"))
            .arg("--key")
            .arg(SUB_FILTER)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen unixpipe --key"),
    );

    // The wz acceptor must be BOUND (its request FIFO present) before zenohd dials,
    // so the UnicastPipeClient invitation lands. Unlike the DIALER legs, an ACCEPTOR
    // declares its routed subscriber only AFTER the session Establishes (the runner
    // installs session handles on entering steady state), so the
    // DECLARED-ROUTED-SUBSCRIBER wait comes after the dial (below), not here.
    let listening = wait_for_substring(&mut wz_reader, "(unixpipe)", Duration::from_secs(10));
    let bound = listening.is_ok() && wait_for_unixpipe_request_fifo(&base, Duration::from_secs(5));

    // zenohd DIALS wz's unixpipe acceptor (`-e unixpipe/<base>`) + listens on tcp
    // for pico. Spawned only after wz is bound so the UnicastPipeClient invitation
    // finds the request FIFO.
    let mut zenohd = if bound {
        Some(spawn_zenohd_unixpipe_dialer(&base, tcp_port))
    } else {
        None
    };
    drop(tcp_res);

    // wz accepts the zenohd unixpipe dial + completes the handshake, then (on
    // Established) declares its routed subscriber onto the accepted session,
    // installing the route on zenohd.
    let established = zenohd.as_ref().map(|_| {
        wait_for_substring(
            &mut wz_reader,
            "session Established",
            Duration::from_secs(10),
        )
    });
    let declared = matches!(&established, Some(Ok(_))).then(|| {
        wait_for_substring(
            &mut wz_reader,
            "DECLARED ROUTED SUBSCRIBER",
            Duration::from_secs(10),
        )
    });

    // pico z_pub over TCP — after wz's routed subscriber declaration reached zenohd
    // (route installed); the 30x burst covers residual propagation lag (no-flaky).
    let z_pub_child = matches!(&declared, Some(Ok(_))).then(|| {
        spawn_publishing_zpub(
            &z_pub,
            publish_key,
            publish_value,
            &tcp_endpoint,
            "zenohd-unixpipe",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });

    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    if let Some(z) = zenohd.as_mut() {
        let _ = z.child_mut().kill();
        let _ = z.child_mut().wait();
    }
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    cleanup(&base);

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz unixpipe acceptor stderr ---\n{wz_captured}");

    assert!(
        bound,
        "wz-ap-demo did not bind the unixpipe acceptor (its '(unixpipe)' listen line + \
         '{base}_uplink' request FIFO) within 10s.\n--- wz stderr ---\n{wz_captured}"
    );
    established
        .expect("zenohd dialer was spawned once wz was bound")
        .unwrap_or_else(|c| {
            panic!(
                "wz acceptor never logged 'session Established' within 10s — zenohd's unixpipe \
                 dial did not complete the handshake with wz's multi-client acceptor.\n\
                 --- wz stderr ---\n{c}"
            )
        });
    declared
        .expect("the DECLARED-ROUTED-SUBSCRIBER wait runs once the session Established")
        .unwrap_or_else(|c| {
            panic!(
                "wz-ap-demo never logged 'DECLARED ROUTED SUBSCRIBER' within 10s of Established — \
                 the acceptor-side routed subscriber declare regressed.\n--- wz stderr ---\n{c}"
            )
        });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the ACCEPTED unixpipe link into wz's subscriber.\n\
             --- wz stderr ---\n{c}"
        )
    });
    assert!(
        fired_text.contains(publish_key),
        "wz fired but not on the routed keyexpr '{publish_key}'.\n{fired_text}"
    );
}
