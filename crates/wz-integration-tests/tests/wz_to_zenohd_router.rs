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
//! Nine legs (1-7 TCP; 8-9 WebSocket transport, R311pk):
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
//!   7. `pico_liveliness_token_visible_via_zenohd_to_wz_subscriber` — the INVERSE
//!      of leg 5: a zenoh-pico `z_liveliness` declares a liveliness TOKEN, zenohd
//!      tracks it, and wz — connected as a CLIENT with `--liveliness-subscribe` —
//!      observes the routed token as a `LIVELINESS SAMPLE PUT`. leg 5 had wz
//!      produce while pico observed (one-shot z_get_liveliness); this has pico
//!      produce while wz observes (continuous subscriber), completing the
//!      bidirectional liveliness plane through the reference router. The
//!      zenohd-ROUTED counterpart of the direct Layer E2 test
//!      `wz_e2e_liveliness_round_trip_against_zenoh_pico_z_liveliness`.
//!   8. `wz_client_reaches_established_against_zenohd_over_ws` — wz reaches
//!      Established against zenohd over a WebSocket link (the WS-transport
//!      counterpart of leg 1). Deterministic, pico-free: pins that wz's WS
//!      transport (`ws_pipeline`, RFC6455, datagram-flow) completes the zenoh
//!      4-way handshake against the reference router's `ws/` listener. wz dials
//!      `--connect ws/...` (the `wz-ap-demo` binary built with the `connect-ws`
//!      feature); `spawn_zenohd_tcp_ws` dual-listens tcp+ws on one router.
//!   9. `wz_publish_routes_through_zenohd_to_pico_zsub_over_ws` — wz's Put over a
//!      WebSocket link routes through zenohd to a zenoh-pico `z_sub` on TCP (the
//!      WS-transport counterpart of leg 2). zenoh-pico has NO native WS
//!      (emscripten-only), so wz publishes over WS, the reference router decodes
//!      it off its `ws/` listener and forwards to the pico TCP subscriber —
//!      pinning wz's WS DATA PLANE against the reference zenoh WS link (not
//!      pico's WS, which cannot exist natively).
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

/// Spawn a zenohd router on the given `-l` listener locators and block until it
/// is HANDSHAKE-ready. The spawn + two-stage readiness SSOT both zenohd spawn
/// variants delegate to (R311pn — was copy-pasted across [`spawn_zenohd`] and
/// [`spawn_zenohd_tcp_ws`]). `--no-multicast-scouting` + `--rest-http-port none`
/// keep it to the configured unicast listeners.
///
/// Two-stage readiness (R311pi — session-review structural fix). First a
/// TCP-accept probe on `accept_port` (`TcpStream::connect`): a captured-stderr
/// log-wait would race zenohd's block-buffered startup flush, so the connect is
/// the listener-up signal. But TCP-accept proves only that the KERNEL accepted
/// the SYN — not that zenohd's transport/routing tasks are scheduled and can
/// complete a zenoh handshake. Under load there is a cold-start window between
/// "listener up" and "handshake-ready" that a bare TCP-accept gate leaves open.
/// So the second stage drives a real wz client to `Established` against
/// `handshake_probe` ([`wait_for_zenohd_handshake_ready`]) before returning —
/// the test's foreign one-shot clients then connect to a router that has already
/// proven it can finish a handshake.
fn spawn_zenohd_listeners(
    listeners: &[String],
    accept_port: u16,
    handshake_probe: &str,
) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    for locator in listeners {
        command.arg("-l").arg(locator);
    }
    command
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let guard = ChildGuard::wrap(
        "zenohd (reference router)",
        command.spawn().expect("spawn zenohd"),
    );
    assert!(
        wait_for_tcp_accept(accept_port, Duration::from_secs(10)),
        "zenohd did not start accepting on 127.0.0.1:{accept_port} within 10s"
    );
    // R311pi — close the TCP-accept-vs-handshake-ready gap with a real wz session.
    wait_for_zenohd_handshake_ready(handshake_probe);
    guard
}

/// Spawn a TCP-only zenohd router on the reserved `port` and block until it is
/// HANDSHAKE-ready. A single unicast TCP listener; both readiness gates target
/// the one port. See [`spawn_zenohd_listeners`] for the readiness rationale.
fn spawn_zenohd(port: u16) -> ChildGuard {
    spawn_zenohd_listeners(
        &[format!("tcp/127.0.0.1:{port}")],
        port,
        &format!("127.0.0.1:{port}"),
    )
}

/// Spawn a zenohd router listening on BOTH `tcp/` (for pico TCP clients) and
/// `ws/` (for the wz WebSocket client) on the reserved ports, and block until it
/// is HANDSHAKE-ready. R311pk — the dual-transport variant of [`spawn_zenohd`]
/// for the WS legs: zenoh-pico has NO native WS link (emscripten-only — its
/// `CMakeLists.txt` hard-errors a non-emscripten WS build), so pico dials TCP
/// while wz dials WS, and zenohd routes between its two listeners. This pins
/// wz's WS transport against the REFERENCE zenoh `ws/` link, not against pico's
/// (which cannot exist natively).
///
/// R311pn — readiness gives BOTH listeners a POSITIVE probe (was: tcp-accept on
/// `tcp_port` + a tcp handshake, with the `ws_port` only INFERRED from the
/// co-bound router being ready — the session-review ② finding). The TCP-accept
/// gate targets `tcp_port` (pico dials it), and the handshake-ready probe drives
/// a real wz client to `Established` over `ws/127.0.0.1:{ws_port}` — a genuine
/// RFC6455 upgrade + zenoh handshake that exercises the WS listener directly.
///
/// This is SAFE where R311pk's removed raw-TCP poke was not: that poke was a
/// bare `TcpStream::connect`-then-close with NO upgrade, so zenoh's serial
/// single-worker `zenoh-link-ws` accept task hit a tungstenite EOF, returned
/// `Err`, and self-deleted — wedging every later `ws/` dial. A REAL WS client
/// completes the upgrade, so the accept task stays alive (the legs then dial WS
/// 20/20). A completed handshake is exactly the positive WS-readiness signal the
/// raw poke could never be.
fn spawn_zenohd_tcp_ws(tcp_port: u16, ws_port: u16) -> ChildGuard {
    spawn_zenohd_listeners(
        &[
            format!("tcp/127.0.0.1:{tcp_port}"),
            format!("ws/127.0.0.1:{ws_port}"),
        ],
        tcp_port,
        &format!("ws/127.0.0.1:{ws_port}"),
    )
}

/// R311pi — confirm zenohd can complete a zenoh handshake by driving a throwaway
/// wz client to `Established` against the `connect` locator, then dropping the
/// client. The wz open is deterministic (in-process, no fork — the
/// `wz_client_reaches_established` path), so this probe is reliable even when the
/// foreign one-shot clients' opens occasionally need a retry under load. This is
/// the readiness signal [`spawn_zenohd_listeners`] returns on (replacing the bare
/// TCP-accept gate). The probe publishes to a dedicated keyexpr no test
/// subscribes to, and is killed before the spawn returns, so it leaves no routing
/// state behind.
///
/// R311pn — `connect` is a full `--connect` locator (not a bare port), so the
/// probe can target a `ws/...` listener with a REAL WS handshake (the TCP-only
/// variant passes `127.0.0.1:{port}`, the dual variant `ws/127.0.0.1:{ws_port}`).
/// A `ws/...` probe needs the `connect-ws` feature in the demo binary (the Layer
/// Z build enables it); without it the demo surfaces a typed `Unsupported` and
/// this probe fails loudly rather than passing on a TCP fallback.
fn wait_for_zenohd_handshake_ready(connect: &str) {
    let demo = wz_ap_demo_binary();
    let probe_stderr = tempfile::tempfile().expect("tempfile for readiness probe stderr");
    let probe_writer = probe_stderr
        .try_clone()
        .expect("dup readiness probe stderr handle");
    let mut probe_reader = probe_stderr;
    let mut probe = ChildGuard::wrap(
        "wz-ap-demo (zenohd handshake readiness probe)",
        Command::new(&demo)
            .arg("--connect")
            .arg(connect)
            .arg("--publish")
            .arg("wz/zenohd/readiness-probe")
            .arg("--value")
            .arg("ready")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(probe_writer))
            .spawn()
            .expect("spawn zenohd readiness probe"),
    );
    let ready = wait_for_substring(
        &mut probe_reader,
        "session Established",
        Duration::from_secs(10),
    );
    let _ = probe.child_mut().kill();
    let _ = probe.child_mut().wait();
    if ready.is_err() {
        let cap = read_captured(&mut probe_reader);
        panic!(
            "zenohd readiness probe (wz client) did not reach Established within 10s \
             over {connect:?} — zenohd is up but not handshake-ready.\n\
             --- probe stderr ---\n{cap}"
        );
    }
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
///
/// R311pf/R311pi — why the retry, honestly. The pico open occasionally fails
/// under full-run-ci load and was NOT reproduced synthetically (~200+ opens under
/// up to 5x CPU oversubscription, including 3 zenohd starting under load, produced
/// zero failures), so the exact mechanism is a HYPOTHESIS, not a verified fact:
/// scheduler starvation of the handshake window under the specific full-run-ci
/// profile (concurrent rustc memory/IO + multiple zenohd) is the most likely
/// candidate, but a zenohd handshake STALL is not excludable — the symptom is
/// reported on the pico side (`z_open() < 0`), where a clean zenohd log plus a
/// pico-side client timeout would look identical. R311pi closes the most
/// actionable part STRUCTURALLY: `spawn_zenohd` now drives a real wz handshake to
/// `Established` before returning, so the zenohd cold-start window is gated out,
/// and this retry is left as the client-side-starvation safety net for a foreign
/// one-shot that cannot self-retry. `spawn_publishing_zpub` shares this exact
/// open-transient retry. (The `z_get` / `z_get_liveliness` / `wz --query` retries
/// below are a DIFFERENT, well-understood concern — the route/declaration
/// propagation window — NOT this open transient; they are not the same phenomenon
/// and do not share this root-cause story.)
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
            // z_get prints ">> Received <kind> ('<keyexpr>': '<value>')" per reply
            // AND ">> Received query final notification" on the terminating final.
            // Both contain the bare ">> Received" substring, and the final ALWAYS
            // lands (even on a zero-reply query that missed the route), so the
            // break MUST also require the actual reply value — otherwise the
            // retry budget is dead (it would always break on attempt 1's final
            // and fall through to the reply-value assert). R311pb — mirror leg 6's
            // `received.is_ok() && contains(reply_value)` so the retry actually
            // covers the route-propagation window.
            let received =
                wait_for_substring(&mut out_reader, ">> Received", Duration::from_secs(8));
            let _ = zget.child_mut().kill();
            let _ = zget.child_mut().wait();
            zget_captured = read_captured(&mut out_reader);
            if received.is_ok() && zget_captured.contains(reply_value) {
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

/// Spawn a zenoh-pico `z_liveliness` (long-lived liveliness-token declarer)
/// against zenohd, retrying the open like [`spawn_subscribed_zsub`] /
/// [`spawn_publishing_zpub`] until the token is declared (stdout
/// "Declaring liveliness token"). z_liveliness does the same non-self-retrying
/// `z_open` as z_sub / z_pub (R311pf open-transient class), so the same
/// foreign-one-shot open-retry applies — leg 7's prior single unguarded spawn
/// was inconsistent with every other pico-spawning leg in this file. Returns the
/// declaring child (its token is held for the child's lifetime) + its stdout
/// reader.
fn spawn_declaring_z_liveliness(
    z_liveliness: &Path,
    token_keyexpr: &str,
    endpoint: &str,
) -> (ChildGuard, File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
        let out_writer = out.try_clone().expect("dup z_liveliness stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_liveliness client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_liveliness)
                .args(["-k", token_keyexpr, "-e", endpoint, "-m", "client"])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_liveliness via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Declaring liveliness token") {
                return (child, out_reader); // session open + token declared
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_liveliness open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
    }
    panic!("pico z_liveliness failed to open a session to zenohd after {ATTEMPTS} attempts");
}

/// leg 7 (R311pd) — the INVERSE of leg 5
/// (`wz_liveliness_token_visible_via_zenohd_to_pico_zget_liveliness`): here a
/// zenoh-pico `z_liveliness` declares a liveliness TOKEN, zenohd tracks it in
/// its liveliness subsystem, and wz — connected to zenohd as a CLIENT with
/// `--liveliness-subscribe` — observes the routed token as a
/// `LIVELINESS SAMPLE PUT`. leg 5 had wz produce + pico observe (via the
/// one-shot `z_get_liveliness`); this leg has pico produce + wz observe (via the
/// continuous liveliness subscriber), so together they pin the liveliness plane
/// in BOTH directions through the reference router.
///
/// The zenohd-ROUTED counterpart of the direct wz<->pico
/// `wz_e2e_liveliness_round_trip_against_zenoh_pico_z_liveliness` (Layer E2):
/// there pico dials wz directly and wz is the listener; here both are clients of
/// zenohd and zenohd routes the liveliness state between them. Production code
/// is unchanged — this pins, end to end, that wz's existing
/// `--liveliness-subscribe` (the high-level `Session::declare_liveliness_subscriber`,
/// R280) consumes a liveliness token routed by the reference router.
///
/// Determinism (R311ph — session-review fix): the wz subscriber is declared
/// with `--liveliness-subscribe-history` (`history = true`), so zenohd replays
/// the CURRENT alive token on subscription as well as routing future declares.
/// That removes the ordering race a `history = false` subscriber had — if pico's
/// token Declare reached zenohd before wz's Interest registered, a future-only
/// subscriber would miss it; with history the observer is order-independent of
/// which side won the race. `z_liveliness`'s open is retried like every other
/// foreign one-shot in this file (`spawn_declaring_z_liveliness`, the R311pf
/// open-transient robustness) since it does the same non-self-retrying `z_open`
/// as z_sub / z_pub. The witness is on the WZ side (its single-writer env_logger
/// stderr), so this leg is immune to the foreign-stdout block-buffering that
/// `spawn_zenohd` works around for the foreign CLIs.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_liveliness); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn pico_liveliness_token_visible_via_zenohd_to_wz_subscriber() {
    let demo = wz_ap_demo_binary();
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let token_keyexpr = "group1/zenoh-pico";
    let subscribe_pattern = "group1/**";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── wz-ap-demo: a CLIENT of zenohd that declares a liveliness SUBSCRIBER via
    //    `--liveliness-subscribe` + `--liveliness-subscribe-history` (history =
    //    true). On Established it emits an Interest and logs 'LIVELINESS SAMPLE
    //    PUT/DELETE' on every matching token sample zenohd routes to it. History
    //    makes the observer ORDER-INDEPENDENT: zenohd replays the current alive
    //    token on subscription, so even if pico's token Declare reached zenohd
    //    before wz's Interest registered (the race a future-only subscriber would
    //    lose), wz still observes the token. Wait for Established before declaring
    //    the token so the witness order is stable.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --liveliness-subscribe --history)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--liveliness-subscribe")
            .arg(subscribe_pattern)
            .arg("--liveliness-subscribe-history")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --liveliness-subscribe"),
    );

    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // ── pico z_liveliness: declares a liveliness TOKEN and HOLDS it (long-lived,
    //    unlike leg 5's one-shot). The open is retried until the token is declared
    //    (foreign one-shot open-transient robustness, like every other pico leg).
    //    zenohd tracks the token and routes the PUT sample to wz's history
    //    subscriber.
    let (mut z_child, mut z_stdout_reader) =
        spawn_declaring_z_liveliness(&z_liveliness, token_keyexpr, &endpoint);

    // Witness on the WZ side: its liveliness-subscriber callback logs
    // 'LIVELINESS SAMPLE PUT ...' once z_liveliness's Declare(Token), routed by
    // zenohd, reaches the subscriber registry through the production poll loop.
    let put = wait_for_substring(
        &mut demo_stderr_reader,
        "LIVELINESS SAMPLE PUT",
        Duration::from_secs(10),
    );

    let _ = z_child.child_mut().kill();
    let _ = z_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_captured = read_captured(&mut z_stdout_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s — the wz client \
             did not reach Established against zenohd.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_liveliness stdout ---\n{z_captured}");

    let put_text = match put {
        Ok(c) => c,
        Err(c) => panic!(
            "wz did not log 'LIVELINESS SAMPLE PUT' within 10s — pico's liveliness token \
             was not tracked / routed by zenohd to the wz subscriber.\n\
             --- captured wz-ap-demo stderr at deadline ---\n{c}\n\
             --- captured z_liveliness stdout ---\n{z_captured}"
        ),
    };
    // The PUT sample line carries the resolved token keyexpr literal + the
    // configured subscribe filter (runner.rs LIVELINESS SAMPLE format). Assert
    // both so a regression on inbound Declare(Token) decode or the peer-keyexpr
    // resolution localises here.
    assert!(
        put_text.contains(&format!("keyexpr='{token_keyexpr}'")),
        "wz logged 'LIVELINESS SAMPLE PUT' but the token keyexpr '{token_keyexpr}' is \
         missing — the subscriber fired but the routed literal drifted.\n{put_text}"
    );
    assert!(
        put_text.contains(&format!("filter='{subscribe_pattern}'")),
        "wz logged 'LIVELINESS SAMPLE PUT' but the subscribe filter '{subscribe_pattern}' \
         is missing.\n{put_text}"
    );
}

/// leg 8 (R311pk) — wz reaches Established against zenohd over a WebSocket link:
/// the WS-transport counterpart of leg 1 (handshake wire-parity). Deterministic
/// (no peer-timing race, pico-free) — pins that wz's WS transport
/// (`ws_pipeline`, RFC6455, datagram-flow) completes the zenoh 4-way handshake
/// against the reference router's `ws/` listener. wz dials with
/// `--connect ws/127.0.0.1:{ws_port}` (the `wz-ap-demo` binary built with the
/// `connect-ws` feature, R311pk); zenohd also listens on `tcp/` for its
/// handshake-readiness probe. Mirrors
/// [`wz_client_reaches_established_against_zenohd`] one transport over.
#[test]
#[ignore = "binary-dep e2e (zenohd router, WS); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd_over_ws() {
    let demo = wz_ap_demo_binary();
    let (tcp_res, ws_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let mut zenohd = spawn_zenohd_tcp_ws(tcp_port, ws_port);
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect ws/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("ws/127.0.0.1:{ws_port}"))
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("ws-handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect ws/zenohd"),
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
            "wz-ap-demo did not log 'session Established' within 10s over WS — the \
             wz<->zenohd WebSocket handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// leg 9 (R311pk) — wz's Put over a WebSocket link routes through zenohd to a
/// zenoh-pico `z_sub` on TCP: the WS-transport counterpart of leg 2 (data-plane
/// cross-impl). wz dials zenohd with `--connect ws/127.0.0.1:{ws_port}` (its
/// WebSocket transport), pico subscribes over `tcp/`, and zenohd routes wz's Put
/// ACROSS the two link types. zenoh-pico has no native WS (emscripten-only), so
/// this pins wz's WS data plane against the REFERENCE zenoh `ws/` link — wz
/// publishes over WS, the reference router decodes it off its `ws/` listener and
/// forwards to the pico TCP subscriber. The same Put-burst + retried-zsub shape
/// as [`wz_publish_routes_through_zenohd_to_pico_zsub`], one transport over.
#[test]
#[ignore = "binary-dep e2e (zenohd router WS + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub_over_ws() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (tcp_res, ws_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-over-ws";

    let mut zenohd = spawn_zenohd_tcp_ws(tcp_port, ws_port);
    drop(tcp_res);

    // ── pico z_sub: a TCP client of zenohd, subscribed and ready (retried past
    //    any transient one-shot open). Its declared subscription is the route
    //    zenohd uses to forward wz's WS Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint);

    // ── wz-ap-demo: a WEBSOCKET client of zenohd that emits a Put burst. The
    //    burst (publisher_task) covers the window for z_sub's subscription to
    //    reach zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect ws/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("ws/127.0.0.1:{ws_port}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect ws/zenohd --publish"),
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
            "z_sub did not log '{received_substr}' within 10s — wz's WS Put did not route \
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
