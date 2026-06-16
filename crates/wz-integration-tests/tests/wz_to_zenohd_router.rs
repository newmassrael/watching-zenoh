// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311or — first cross-impl interop against the zenoh-full REFERENCE router.
//!
//! Every other interop test pairs wz with zenoh-PICO (the embedded C impl).
//! This pairs wz with `zenohd` v1.5.0 — the canonical Rust router — exercised
//! through the SAME binary + harness SSOT as the pico interop suite: the wz
//! side is the production `wz-ap-demo` binary (which already announces the
//! zenoh protocol `version = 0x09` and `whatami = Client` on its `--connect`
//! initiator path — `args.rs`), zenohd is spawned as the foreign router, and
//! `ChildGuard` / `wait_for_substring` / the binary locators are the shared
//! `common` harness. No in-process dial, no per-test harness fork, no
//! version override — wz speaks the reference protocol out of the box.
//!
//! Four legs:
//!   1. `wz_client_reaches_established_against_zenohd` — wz dials zenohd and
//!      completes InitSyn/InitAck/OpenSyn/OpenAck to Established (transport
//!      wire-parity with the canonical implementation). Deterministic: the
//!      handshake does not depend on any other peer.
//!   2. `wz_publish_routes_through_zenohd_to_pico_zsub` — wz's `Put` is routed
//!      by zenohd to a zenoh-pico `z_sub` (data-plane cross-impl through the
//!      reference router). wz emits a Put burst (wz-ap-demo's publisher_task)
//!      so a Put lands after z_sub's subscription has propagated to zenohd.
//!   3. `wz_routed_subscribe_from_zenohd` — the REVERSE data plane: wz declares
//!      a ROUTED subscriber (`wz-ap-demo --key`, which since R311ou emits a
//!      `Declare(DeclSubscriber)` so zenohd routes matching Pushes back), a
//!      zenoh-pico `z_pub` publishes, and zenohd routes the Put to wz's
//!      subscriber callback. This is the regression guard for R311ou — it
//!      pins, end-to-end, that wz-as-routed-subscriber works against the
//!      reference router (the prior R311or "router-mode subscriber out of
//!      scope" finding was empirically falsified).
//!   4. `wz_queryable_replies_via_zenohd_to_pico_zget` — the query/reply round
//!      trip: wz declares a ROUTED queryable (`wz-ap-demo --queryable --reply`,
//!      which since R311ow emits a `Declare(DeclQueryable)` so zenohd routes
//!      matching `Query` requests to wz), a zenoh-pico `z_get` queries, zenohd
//!      routes the query to wz's queryable, wz replies, and zenohd routes the
//!      reply back to z_get. The regression guard for R311ow — it pins, end to
//!      end, that wz-as-routed-queryable answers queries through the reference
//!      router (the declare_queryable sibling of leg 3's declare_subscriber).
//!   5. `wz_liveliness_token_visible_via_zenohd_to_pico_zget_liveliness` — the
//!      liveliness path: wz declares a liveliness TOKEN (`wz-ap-demo
//!      --declare-token`, the high-level `Session::declare_token` that emits a
//!      `Declare(DeclToken)`), zenohd tracks it in its liveliness subsystem, and
//!      a zenoh-pico `z_get_liveliness` query routed through zenohd observes the
//!      token as Alive. Pins, end to end, that wz's liveliness token declaration
//!      is liveliness-routable by the reference router.
//!   6. `wz_query_routed_to_pico_queryable_via_zenohd` — wz AS THE REQUESTER:
//!      wz sends a `Query` (`wz-ap-demo --query`), zenohd routes it to a
//!      zenoh-pico `z_queryable`, which replies, and zenohd routes the reply
//!      back to wz (logged `REPLY RECEIVED`). The symmetric counterpart of leg
//!      4 (which had pico query wz's queryable): here wz is the client/requester
//!      and pico is the responder, so this pins wz's outbound z_get + inbound
//!      reply-consume path against the reference router.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z) AND binary-dep: zenohd is an external
//! 1.5.0 build (`scripts/build-zenohd.sh`), not a wz artifact, so it never
//! gates the default sweep.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wait_for_tcp_accept, wz_ap_demo_binary,
    zenoh_pico_cli_binary, zenohd_binary, ChildGuard, PortReservation,
};

/// Spawn a TCP-only zenohd router on the reserved `port` and block until its
/// listener accepts (a probe `TcpStream::connect`). `--no-multicast-scouting` +
/// `--rest-http-port none` keep it to a single unicast TCP listener.
///
/// Readiness is a TCP-accept probe, NOT a stderr-log wait: zenohd block-buffers
/// its startup logs to a non-TTY fd, so a captured-stderr `wait_for_substring`
/// races the flush and times out with an empty capture (verified). A successful
/// connect proves the listener is up — the signal the clients actually need.
fn spawn_zenohd(port: u16) -> ChildGuard {
    let guard = ChildGuard::wrap(
        "zenohd (reference router)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd"),
    );
    assert!(
        wait_for_tcp_accept(port, Duration::from_secs(10)),
        "zenohd did not start accepting on tcp/127.0.0.1:{port} within 10s"
    );
    guard
}

/// Spawn a zenoh-pico `z_sub` against zenohd and return it once its session is
/// OPEN and the subscriber DECLARED (stdout line "Declaring Subscriber on ...").
/// pico's `z_sub` is a one-shot that prints "Unable to open session!" and exits
/// if its session open transiently fails — and it does NOT self-retry. Under
/// full-run-ci load that open occasionally fails, so the orchestrator retries
/// the spawn here. This is robustness for a FOREIGN one-shot binary, not a wz
/// workaround: the wz side is deterministic (the handshake test + 20x standalone
/// pass), and a transiently-failed `z_sub` open is not a wz defect — retrying it
/// keeps the data-plane assertion zero-flake. Returns the subscribed child + its
/// stdout reader for the `Received` wait.
fn spawn_subscribed_zsub(z_sub: &Path, sub_key: &str, endpoint: &str) -> (ChildGuard, File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_sub stdout");
        let out_writer = out.try_clone().expect("dup z_sub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_sub client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_sub)
                .args(["-k", sub_key, "-e", endpoint, "-m", "client"])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_sub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Declaring Subscriber on") {
                return (child, out_reader); // session open + subscriber declared
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_sub open attempt {attempt}/{ATTEMPTS} did not subscribe; retrying");
    }
    panic!("pico z_sub failed to open a session to zenohd after {ATTEMPTS} attempts");
}

/// wz dials zenohd as a client and reaches Established — the handshake
/// interoperates with the reference router. Deterministic (no peer-timing race).
#[test]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd"),
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
            "wz-ap-demo did not log 'session Established' within 10s — the wz<->zenohd \
             handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// wz's Put routes through zenohd to a zenoh-pico `z_sub` — the data-plane
/// cross-impl through the reference router.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-via-zenohd";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── pico z_sub: a client of zenohd, subscribed and ready (retried past any
    //    transient one-shot open failure). Its declared subscription is the
    //    route zenohd uses to forward wz's Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint);

    // ── wz-ap-demo: a client of zenohd that emits a Put burst. The burst
    //    (publisher_task) covers the window for z_sub's subscription to reach
    //    zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd"),
    );

    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's Put did not route \
             through zenohd to z_sub.\n--- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-ap-demo stderr ---\n{demo_captured}"
        ),
    };
    assert!(
        received_text.contains(publish_key),
        "z_sub received but the publish keyexpr '{publish_key}' is missing.\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub received but the publish value '{publish_value}' is missing.\n{received_text}"
    );
}

/// Spawn a zenoh-pico `z_pub` against zenohd and return it once it has opened a
/// session, declared its publisher, and begun putting (stdout "Putting Data").
/// Like [`spawn_subscribed_zsub`], the pico one-shot occasionally fails its
/// session open under full-run-ci load and does NOT self-retry, so the
/// orchestrator retries the spawn — robustness for a FOREIGN binary, not a wz
/// workaround (the wz routed-subscriber side is deterministic: the
/// `Declare(DeclSubscriber)` is emitted synchronously pre-drive). `z_pub`
/// `z_sleep_s(1)` before each Put and publishes `-n` times, so the burst spans
/// ~n seconds; the caller spawns this only AFTER wz logs DECLARED ROUTED
/// SUBSCRIBER, so the subscription is already on zenohd when the Puts arrive.
fn spawn_publishing_zpub(z_pub: &Path, key: &str, value: &str, endpoint: &str) -> ChildGuard {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_pub stdout");
        let out_writer = out.try_clone().expect("dup z_pub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_pub client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_pub)
                .args([
                    "-k", key, "-v", value, "-e", endpoint, "-m", "client", "-n", "30",
                ])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_pub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Putting Data") {
                return child; // session open + publisher declared + publishing
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_pub open attempt {attempt}/{ATTEMPTS} did not start publishing; retrying");
    }
    panic!("pico z_pub failed to open a session to zenohd after {ATTEMPTS} attempts");
}

/// The REVERSE data plane: a zenoh-pico `z_pub`'s Put routes through zenohd to
/// wz's ROUTED subscriber. wz declares the subscriber (`--key`, which emits a
/// `Declare(DeclSubscriber)` since R311ou); zenohd, seeing wz's declared
/// subscription, forwards the matching Put back to wz, whose callback fires.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_routed_subscribe_from_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let publish_key = "demo/zenohd";
    let sub_filter = "demo/**";
    let publish_value = "hello-routed-to-wz";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── wz-ap-demo: a CLIENT of zenohd that declares a ROUTED subscriber.
    //    `--key` now emits `Declare(DeclSubscriber)` (R311ou), so wait until
    //    that declaration has been announced before publishing — the route must
    //    exist on zenohd when the Puts arrive (deterministic ordering, not a
    //    sleep).
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --key)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--key")
            .arg(sub_filter)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --key"),
    );

    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED ROUTED SUBSCRIBER",
        Duration::from_secs(10),
    );

    // ── pico z_pub: publishes on demo/zenohd through zenohd (retried past any
    //    transient one-shot open). Spawned only after wz's subscription
    //    propagated, so zenohd already has the route.
    let z_pub_child = declared
        .is_ok()
        .then(|| spawn_publishing_zpub(&z_pub, publish_key, publish_value, &endpoint));

    let received = wait_for_substring(
        &mut demo_stderr_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(12),
    );

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &declared {
        panic!(
            "wz-ap-demo did not log 'DECLARED ROUTED SUBSCRIBER' within 10s — the routed \
             subscriber declare (R311ou) regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");

    let fired_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "wz did not log 'SUBSCRIBER FIRED' within 12s — zenohd did not route the z_pub Put \
             to wz's routed subscriber.\n--- captured wz-ap-demo stderr at deadline ---\n{c}"
        ),
    };
    assert!(
        fired_text.contains(publish_key),
        "wz fired but the routed keyexpr '{publish_key}' is missing from the SUBSCRIBER FIRED \
         line.\n{fired_text}"
    );
}

/// The query/reply round trip: a zenoh-pico `z_get`'s query routes through
/// zenohd to wz's ROUTED queryable, wz replies, and zenohd routes the reply back
/// to z_get. wz declares the queryable (`--queryable`, which emits a
/// `Declare(DeclQueryable)` since R311ow); zenohd, seeing wz's declared
/// queryable, forwards the matching `Query` to wz, whose handler replies, and
/// the reply routes back to z_get. The declare_queryable sibling of leg 3.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_get); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_queryable_replies_via_zenohd_to_pico_zget() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let queryable_key = "demo/zenohd";
    let reply_value = "reply-from-wz-queryable";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── wz-ap-demo: a CLIENT of zenohd that declares a ROUTED queryable.
    //    `--queryable` now emits `Declare(DeclQueryable)` (R311ow), so wait until
    //    that declaration has been announced before querying — the route must
    //    exist on zenohd when the query arrives (deterministic ordering, not a
    //    sleep). The demo holds the queryable handle across its drive loop, so it
    //    keeps answering queries until killed.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --queryable --reply)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--queryable")
            .arg(queryable_key)
            .arg("--reply")
            .arg(reply_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --queryable --reply"),
    );

    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED ROUTED QUERYABLE",
        Duration::from_secs(10),
    );

    // ── pico z_get: queries demo/zenohd through zenohd. z_get is a one-shot that
    //    blocks until the query's final notification, so a SINGLE query arriving
    //    before wz's DeclQueryable has propagated to zenohd returns final-only
    //    (no reply) and exits. Unlike leg 3's z_pub (which repeats Puts for ~30s),
    //    a query fires once — so retry the whole one-shot until a reply lands.
    //    Robustness for the foreign one-shot + the declaration-propagation window,
    //    NOT a wz workaround: the wz reply side is deterministic once the query
    //    reaches it (the queryable handler drains + replies + emits the Final on
    //    the drive iteration that dispatches the Query).
    let mut zget_captured = String::new();
    let mut zget_received = false;
    if declared.is_ok() {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = tempfile::tempfile().expect("tempfile for z_get stdout");
            let out_writer = out.try_clone().expect("dup z_get stdout handle");
            let mut out_reader = out;
            let mut zget = ChildGuard::wrap(
                "z_get client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_get)
                    .args(["-k", queryable_key, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_get via stdbuf"),
            );
            // z_get prints ">> Received <kind> ('<keyexpr>': '<value>')" per reply.
            let received =
                wait_for_substring(&mut out_reader, ">> Received", Duration::from_secs(8));
            let _ = zget.child_mut().kill();
            let _ = zget.child_mut().wait();
            zget_captured = read_captured(&mut out_reader);
            if received.is_ok() {
                zget_received = true;
                break;
            }
            eprintln!(
                "z_get attempt {attempt}/{ATTEMPTS} got no reply (route not yet propagated / \
                 transient open); retrying"
            );
        }
    }

    // Confirm wz's queryable actually fired — proves the query reached wz through
    // zenohd (already buffered by the time a reply landed, so a short wait).
    let fired = wait_for_substring(
        &mut demo_stderr_reader,
        "QUERYABLE FIRED",
        Duration::from_secs(5),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &declared {
        panic!(
            "wz-ap-demo did not log 'DECLARED ROUTED QUERYABLE' within 10s — the routed \
             queryable declare (R311ow) regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_get stdout ---\n{zget_captured}");

    assert!(
        fired.is_ok(),
        "wz did not log 'QUERYABLE FIRED' — zenohd did not route the z_get query to wz's routed \
         queryable.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        zget_received,
        "pico z_get did not receive a reply within the retry budget — wz's queryable reply did \
         not route back through zenohd.\n--- captured z_get stdout ---\n{zget_captured}"
    );
    assert!(
        zget_captured.contains(reply_value),
        "z_get received a reply but the wz reply value '{reply_value}' is missing.\n{zget_captured}"
    );
    assert!(
        zget_captured.contains(queryable_key),
        "z_get received a reply but the queryable keyexpr '{queryable_key}' is missing.\n\
         {zget_captured}"
    );
}

/// The liveliness path: wz declares a liveliness TOKEN, a zenoh-pico
/// `z_get_liveliness` queries the liveliness state through zenohd, and zenohd —
/// tracking wz's token in its liveliness subsystem — answers the pico query so
/// the token shows up as Alive. wz declares the token via `--declare-token` (the
/// high-level `Session::declare_token`, which emits a `Declare(DeclToken)` and
/// holds the RAII `LivelinessToken` for the demo's lifetime).
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_get_liveliness); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_liveliness_token_visible_via_zenohd_to_pico_zget_liveliness() {
    let demo = wz_ap_demo_binary();
    let z_get_liveliness = zenoh_pico_cli_binary("z_get_liveliness");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let token_keyexpr = "group1/zenohd";
    let query_pattern = "group1/**";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── wz-ap-demo: a CLIENT of zenohd that declares a liveliness TOKEN.
    //    `--declare-token` emits a `Declare(DeclToken)` and holds the RAII
    //    `LivelinessToken` across the drive loop, so the token stays alive on
    //    zenohd until the demo is killed. Wait for the declare to be announced
    //    before querying (deterministic ordering, not a sleep).
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --declare-token)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--declare-token")
            .arg(token_keyexpr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --declare-token"),
    );

    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED TOKEN",
        Duration::from_secs(10),
    );

    // ── pico z_get_liveliness: a one-shot liveliness query (like leg 4's z_get,
    //    it blocks until the query final). A single query arriving before wz's
    //    DeclToken has propagated to zenohd's liveliness subsystem returns no
    //    Alive token, so retry the whole one-shot until the token is observed —
    //    robustness for the foreign one-shot + the declaration-propagation
    //    window. The wz side is deterministic once the token is tracked.
    let mut zgl_captured = String::new();
    let mut zgl_alive = false;
    if declared.is_ok() {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = tempfile::tempfile().expect("tempfile for z_get_liveliness stdout");
            let out_writer = out.try_clone().expect("dup z_get_liveliness stdout handle");
            let mut out_reader = out;
            let mut zgl = ChildGuard::wrap(
                "z_get_liveliness client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_get_liveliness)
                    .args(["-k", query_pattern, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_get_liveliness via stdbuf"),
            );
            // z_get_liveliness prints ">> Alive token ('<keyexpr>')" per live token.
            let alive =
                wait_for_substring(&mut out_reader, ">> Alive token", Duration::from_secs(8));
            let _ = zgl.child_mut().kill();
            let _ = zgl.child_mut().wait();
            zgl_captured = read_captured(&mut out_reader);
            if alive.is_ok() {
                zgl_alive = true;
                break;
            }
            eprintln!(
                "z_get_liveliness attempt {attempt}/{ATTEMPTS} saw no Alive token (token not \
                 yet propagated / transient open); retrying"
            );
        }
    }

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &declared {
        panic!(
            "wz-ap-demo did not log 'DECLARED TOKEN' within 10s — the liveliness token \
             declare regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_get_liveliness stdout ---\n{zgl_captured}");

    assert!(
        zgl_alive,
        "pico z_get_liveliness saw no Alive token within the retry budget — wz's liveliness \
         token was not tracked / routed by zenohd.\n--- captured z_get_liveliness stdout ---\n\
         {zgl_captured}"
    );
    assert!(
        zgl_captured.contains(token_keyexpr),
        "z_get_liveliness saw an Alive token but the wz token keyexpr '{token_keyexpr}' is \
         missing.\n{zgl_captured}"
    );
}

/// Spawn a zenoh-pico `z_queryable` against zenohd and return it once it has
/// opened a session and created its queryable (stdout "Creating Queryable").
/// Like [`spawn_publishing_zpub`], the pico one-shot occasionally fails its
/// session open under full-run-ci load and does NOT self-retry, so the
/// orchestrator retries the spawn. The queryable then PERSISTS (it loops
/// answering inbound queries with the `-v` payload), so once it has propagated
/// to zenohd, wz's Query reaches it.
fn spawn_ready_z_queryable(
    z_queryable: &Path,
    key: &str,
    value: &str,
    endpoint: &str,
) -> ChildGuard {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_queryable stdout");
        let out_writer = out.try_clone().expect("dup z_queryable stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_queryable client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_queryable)
                .args(["-k", key, "-v", value, "-e", endpoint, "-m", "client"])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_queryable via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Creating Queryable") {
                return child; // session open + queryable declared
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!(
            "z_queryable open attempt {attempt}/{ATTEMPTS} did not create queryable; retrying"
        );
    }
    panic!("pico z_queryable failed to open a session to zenohd after {ATTEMPTS} attempts");
}

/// wz AS THE REQUESTER: wz sends a `Query`, zenohd routes it to a zenoh-pico
/// `z_queryable`, the queryable replies, and zenohd routes the reply back to wz.
/// The symmetric counterpart of leg 4 (pico queried wz's queryable); here wz is
/// the client/requester (`wz-ap-demo --query` emits the outbound `Query` and
/// `--on-query-reply-log` consumes + logs the inbound reply) and pico is the
/// responder.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_queryable); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_query_routed_to_pico_queryable_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let query_key = "demo/zenohd";
    let reply_value = "pico-reply-to-wz";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── pico z_queryable: a queryable on demo/zenohd, ready (declared on zenohd)
    //    before wz queries, and PERSISTING across wz attempts (it loops).
    let mut z_queryable_child =
        spawn_ready_z_queryable(&z_queryable, query_key, reply_value, &endpoint);

    // ── wz-ap-demo --query: a one-shot Query emitted once at Established. A
    //    single Query arriving before the pico queryable has propagated to
    //    zenohd returns final-only (no reply), so retry the whole demo until the
    //    reply lands — robustness for the propagation window (the wz outbound
    //    Query + inbound reply-consume side is deterministic once a reply routes
    //    back). The pico queryable persists across these wz restarts.
    let mut wz_captured = String::new();
    let mut wz_got_reply = false;
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
        let demo_stderr_writer = demo_stderr
            .try_clone()
            .expect("dup wz-ap-demo stderr handle");
        let mut demo_stderr_reader = demo_stderr;
        let mut demo_child = ChildGuard::wrap(
            "wz-ap-demo (--connect zenohd --query --on-query-reply-log)",
            Command::new(&demo)
                .arg("--connect")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--query")
                .arg(query_key)
                .arg("--on-query-reply-log")
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(demo_stderr_writer))
                .spawn()
                .expect("spawn wz-ap-demo --connect zenohd --query"),
        );
        // wz logs "REPLY RECEIVED rid=.. keyexpr=.. body=Put payload=\"<value>\"".
        let received = wait_for_substring(
            &mut demo_stderr_reader,
            "REPLY RECEIVED",
            Duration::from_secs(8),
        );
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        wz_captured = read_captured(&mut demo_stderr_reader);
        if received.is_ok() && wz_captured.contains(reply_value) {
            wz_got_reply = true;
            break;
        }
        eprintln!(
            "wz --query attempt {attempt}/{ATTEMPTS} got no reply carrying '{reply_value}' \
             (queryable not yet propagated / transient); retrying"
        );
    }

    let _ = z_queryable_child.child_mut().kill();
    let _ = z_queryable_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    eprintln!("--- captured wz-ap-demo stderr ---\n{wz_captured}");

    assert!(
        wz_got_reply,
        "wz did not log 'REPLY RECEIVED' carrying the pico reply value '{reply_value}' within \
         the retry budget — zenohd did not route wz's Query to the pico z_queryable, or the \
         reply did not route back.\n--- captured wz-ap-demo stderr ---\n{wz_captured}"
    );
    assert!(
        wz_captured.contains(query_key),
        "wz received a reply but the query keyexpr '{query_key}' is missing.\n{wz_captured}"
    );
}
