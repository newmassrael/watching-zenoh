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
//!      `--connect ws/...` (the `wz-ap-demo` binary built with the `ws`
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
    read_captured, spawn_publishing_zpub, spawn_subscribed_zsub, spawn_zenohd,
    spawn_zenohd_tcp_quic, spawn_zenohd_tcp_tls, spawn_zenohd_tcp_unixsock, spawn_zenohd_tcp_ws,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// The absolute filesystem path for a leg's zenohd `unixsock-stream/` listener,
/// keyed on the test's reserved (unique) `tcp_port` so concurrent-file legs never
/// collide. Short enough for the `AF_UNIX` `sun_path` limit (~108 bytes). The
/// emitted locator prepends `unixsock-stream/`, so an absolute path yields the
/// double-slash `unixsock-stream//tmp/...` shape zenoh's unixsock link expects.
fn zenohd_unixsock_path(tcp_port: u16) -> String {
    std::env::temp_dir()
        .join(format!("wz-zenohd-uxs-{tcp_port}.sock"))
        .to_string_lossy()
        .into_owned()
}

/// The `(cert_pem_path, key_pem_path)` for a TLS leg's zenohd server material,
/// keyed on the reserved (unique) `tcp_port` so concurrent-file legs never
/// collide. The test writes a fresh rcgen `localhost` cert/key here and hands
/// the cert to BOTH zenohd (listen_certificate) and the wz demo (`--tls-ca`, the
/// root to verify against — the self-signed leaf is its own CA).
fn zenohd_tls_cert_paths(tcp_port: u16) -> (String, String) {
    let dir = std::env::temp_dir();
    let cert = dir
        .join(format!("wz-zenohd-tls-{tcp_port}.cert.pem"))
        .to_string_lossy()
        .into_owned();
    let key = dir
        .join(format!("wz-zenohd-tls-{tcp_port}.key.pem"))
        .to_string_lossy()
        .into_owned();
    (cert, key)
}

/// wz dials zenohd as a client and reaches Established — the handshake
/// interoperates with the reference router. Deterministic (no peer-timing race).
// wz-proves: session-unicast-open wz->zenohd
// wz-proves: codec-init-body wz->zenohd
// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-open-body wz->zenohd
// wz-proves: codec-open-body zenohd->wz
// wz-proves: transport-link-tcp wz->zenohd
// wz-proves: transport-unicast wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: pubsub-put wz->zenohd
// wz-proves: pubsub-put wz->pico
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(port_res);

    // ── pico z_sub: a client of zenohd, subscribed and ready (retried past any
    //    transient one-shot open failure). Its declared subscription is the
    //    route zenohd uses to forward wz's Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

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

/// The REVERSE data plane: a zenoh-pico `z_pub`'s Put routes through zenohd to
/// wz's ROUTED subscriber. wz declares the subscriber (`--key`, which emits a
/// `Declare(DeclSubscriber)` since R311ou); zenohd, seeing wz's declared
/// subscription, forwards the matching Put back to wz, whose callback fires.
// wz-proves: declare-subscriber wz->zenohd
// wz-proves: codec-declare wz->zenohd
// wz-proves: codec-frame zenohd->wz
// wz-proves: codec-push zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
    let z_pub_child = declared.is_ok().then(|| {
        spawn_publishing_zpub(
            &z_pub,
            publish_key,
            publish_value,
            &endpoint,
            "zenohd",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });

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
// wz-proves: declare-queryable wz->zenohd
// wz-proves: codec-declare wz->zenohd
// wz-proves: codec-request zenohd->wz
// wz-proves: query-queryable wz->zenohd
// wz-proves: query-reply wz->zenohd
// wz-proves: query-reply wz->pico
// wz-proves: codec-response wz->zenohd
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
// wz-proves: declare-token wz->zenohd
// wz-proves: codec-declare wz->zenohd
// wz-proves: liveliness-token wz->zenohd
// wz-proves: liveliness-token wz->pico
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
// wz-proves: query-get wz->zenohd
// wz-proves: codec-request wz->zenohd
// wz-proves: query-reply zenohd->wz
// wz-proves: codec-response zenohd->wz
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
/// against zenohd, retrying the open like `spawn_subscribed_zsub` /
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
// wz-proves: declare-interest wz->zenohd partial
// wz-proves: codec-declare zenohd->wz
// wz-proves: liveliness-subscriber zenohd->wz
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

    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
/// `ws` feature, R311pk); zenohd also listens on `tcp/` for its
/// handshake-readiness probe. Mirrors
/// [`wz_client_reaches_established_against_zenohd`] one transport over.
// wz-proves: transport-link-ws wz->zenohd
// wz-proves: session-unicast-open wz->zenohd
// wz-proves: codec-init-body wz->zenohd
// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-open-body wz->zenohd
// wz-proves: codec-open-body zenohd->wz
// wz-proves: transport-unicast wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router, WS); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd_over_ws() {
    let demo = wz_ap_demo_binary();
    let (tcp_res, ws_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let mut zenohd = spawn_zenohd_tcp_ws(tcp_port, ws_port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
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
    // R311po — WITNESS the WS transport. The reserved `ws_port` is a ws-only
    // listener and `tcp_port` is a separate port, so a TCP dial here could not
    // reach Established (structurally — no TCP fallback to silently take); but
    // that is an INFERENCE. wz-ap-demo logs the dialed transport name, so this
    // asserts the leg really opened a WebSocket link. A regression that quietly
    // dialed TCP would drop "over ws transport" and fail here.
    assert!(
        demo_captured.contains("over ws transport"),
        "leg 8 reached Established but did not witness a WS-transport dial in \
         wz-ap-demo stderr (expected 'over ws transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
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
// wz-proves: transport-link-ws wz->zenohd
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: pubsub-put wz->zenohd
// wz-proves: pubsub-put wz->pico
// wz-proves: routing-client wz->zenohd
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

    let mut zenohd = spawn_zenohd_tcp_ws(tcp_port, ws_port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // ── pico z_sub: a TCP client of zenohd, subscribed and ready (retried past
    //    any transient one-shot open). Its declared subscription is the route
    //    zenohd uses to forward wz's WS Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

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
    // R311po — WITNESS the WS transport. z_sub receiving proves the data plane
    // routed, but not that wz's leg of it was WebSocket (vs a silent TCP dial);
    // wz-ap-demo logs the dialed transport name, so assert it dialed `ws`.
    assert!(
        demo_captured.contains("over ws transport"),
        "leg 9 routed wz->zenohd->pico but did not witness a WS-transport dial \
         in wz-ap-demo stderr (expected 'over ws transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
}

/// leg 10 (R311y364) — wz reaches Established against zenohd over a
/// `unixsock-stream` (Unix domain socket) link: the unixsock-transport
/// counterpart of leg 8 (ws) / leg 1 (tcp, handshake wire-parity). Deterministic
/// (no peer-timing race, pico-free) — pins that wz's unixsock transport
/// (`unixsock_pipeline`, a tokio `UnixStream` carrying the same zenoh
/// StreamEnvelope length-prefix as tcp/tls) completes the zenoh 4-way handshake
/// against the reference router's `unixsock-stream/` listener. wz dials with
/// `--connect unixsock-stream/{sock}` (the `wz-ap-demo` binary built with the
/// `unixsock` feature, R311y364); zenohd also listens on `tcp/` for its
/// TCP-accept readiness gate (pico has no `unixsock-stream` link). Mirrors
/// [`wz_client_reaches_established_against_zenohd_over_ws`] one transport over.
// wz-proves: transport-link-unixsock wz->zenohd
// wz-proves: session-unicast-open wz->zenohd
// wz-proves: codec-init-body wz->zenohd
// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-open-body wz->zenohd
// wz-proves: codec-open-body zenohd->wz
// wz-proves: transport-unicast wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router, unixsock); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd_over_unixsock() {
    let demo = wz_ap_demo_binary();
    let tcp_res = PortReservation::pick();
    let tcp_port = tcp_res.port();
    let sock = zenohd_unixsock_path(tcp_port);
    let mut zenohd = spawn_zenohd_tcp_unixsock(tcp_port, &sock, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect unixsock/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("unixsock-stream/{sock}"))
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("unixsock-handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixsock/zenohd"),
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
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(format!("{sock}.lock"));

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s over unixsock — the \
             wz<->zenohd Unix-domain-socket handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    // WITNESS the unixsock transport. The `unixsock-stream/{sock}` locator has no
    // TCP fallback (the socket path is a unixsock-only listener), so a broken
    // unixsock dial could not reach Established — but that is an INFERENCE.
    // wz-ap-demo logs the dialed transport name, so this asserts the leg really
    // opened a Unix-domain-socket link. A regression that quietly dialed TCP would
    // drop "over unixsock transport" and fail here.
    assert!(
        demo_captured.contains("over unixsock transport"),
        "leg 10 reached Established but did not witness a unixsock-transport dial in \
         wz-ap-demo stderr (expected 'over unixsock transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// leg 11 (R311y364) — wz's Put over a `unixsock-stream` link routes through
/// zenohd to a zenoh-pico `z_sub` on TCP: the unixsock-transport counterpart of
/// leg 9 (ws) / leg 2 (tcp, data-plane cross-impl). wz dials zenohd with
/// `--connect unixsock-stream/{sock}` (its Unix-domain-socket transport), pico
/// subscribes over `tcp/`, and zenohd routes wz's Put ACROSS the two link types.
/// zenoh-pico has no `unixsock-stream` link, so this pins wz's unixsock data
/// plane against the REFERENCE zenoh `unixsock-stream/` link — wz publishes over
/// the Unix socket, the reference router decodes it off its `unixsock-stream/`
/// listener and forwards to the pico TCP subscriber. The same Put-burst +
/// retried-zsub shape as [`wz_publish_routes_through_zenohd_to_pico_zsub`], one
/// transport over.
// wz-proves: transport-link-unixsock wz->zenohd
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: pubsub-put wz->zenohd
// wz-proves: pubsub-put wz->pico
// wz-proves: routing-client wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router unixsock + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub_over_unixsock() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let tcp_res = PortReservation::pick();
    let tcp_port = tcp_res.port();
    let sock = zenohd_unixsock_path(tcp_port);
    let endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-over-unixsock";

    let mut zenohd = spawn_zenohd_tcp_unixsock(tcp_port, &sock, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // ── pico z_sub: a TCP client of zenohd, subscribed and ready (retried past
    //    any transient one-shot open). Its declared subscription is the route
    //    zenohd uses to forward wz's unixsock Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // ── wz-ap-demo: a UNIX-SOCKET client of zenohd that emits a Put burst. The
    //    burst (publisher_task) covers the window for z_sub's subscription to
    //    reach zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect unixsock/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("unixsock-stream/{sock}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixsock/zenohd --publish"),
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
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(format!("{sock}.lock"));

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's unixsock Put did not \
             route through zenohd to z_sub.\n--- captured z_sub stdout at deadline ---\n{c}\n\
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
    // WITNESS the unixsock transport. z_sub receiving proves the data plane
    // routed, but not that wz's leg of it was a Unix socket (vs a silent TCP
    // dial); wz-ap-demo logs the dialed transport name, so assert it dialed
    // `unixsock`.
    assert!(
        demo_captured.contains("over unixsock transport"),
        "leg 11 routed wz->zenohd->pico but did not witness a unixsock-transport dial \
         in wz-ap-demo stderr (expected 'over unixsock transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
}

/// Remove a cert-transport (tls/quic) leg's on-disk material: the cert, the key,
/// and the zenohd config `spawn_zenohd_tcp_tls` / `spawn_zenohd_tcp_quic` wrote
/// beside the cert (`<cert>.zenohd.json5`). Called after the children are reaped
/// so /tmp does not accrue leftover PEM/config.
fn cleanup_cert_files(cert_path: &str, key_path: &str) {
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(format!("{cert_path}.zenohd.json5"));
}

/// leg 12 (R311y365) — wz reaches Established against zenohd over a `tls/`
/// (TLS-over-TCP) link: the TLS-transport counterpart of leg 8 (ws) / leg 10
/// (unixsock) / leg 1 (tcp, handshake wire-parity). Deterministic (no
/// peer-timing race, pico-free) — pins that wz's TLS transport (`tls_pipeline`,
/// a rustls `ClientStream` carrying the same StreamEnvelope length-prefix as
/// tcp) completes the rustls handshake AND the zenoh 4-way handshake against the
/// reference router's `tls/` listener. wz dials with
/// `--connect tls/127.0.0.1:{tls_port} --tls-ca {cert}` (the `wz-ap-demo` binary
/// built with the `tls` feature, R311y365): the connect ADDRESS is numeric but
/// the cert is verified against server name `localhost` (`from_ca_pem`), so one
/// rcgen self-signed `localhost` cert serves both zenohd (listen_certificate)
/// and wz (root_ca), with NO IP SAN. zenohd also listens on `tcp/` for its
/// readiness gate (pico has no usable `tls/` link here). Mirrors
/// [`wz_client_reaches_established_against_zenohd_over_ws`] one transport over.
// wz-proves: transport-link-tls wz->zenohd
// wz-proves: session-unicast-open wz->zenohd
// wz-proves: codec-init-body wz->zenohd
// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-open-body wz->zenohd
// wz-proves: codec-open-body zenohd->wz
// wz-proves: transport-unicast wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router, tls); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd_over_tls() {
    let demo = wz_ap_demo_binary();
    let (tcp_res, tls_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let (cert_path, key_path) = zenohd_tls_cert_paths(tcp_port);
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    std::fs::write(&cert_path, &cert_pem).expect("write tls cert pem");
    std::fs::write(&key_path, &key_pem).expect("write tls key pem");

    let mut zenohd = spawn_zenohd_tcp_tls(tcp_port, tls_port, &cert_path, &key_path, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect tls/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("tls/127.0.0.1:{tls_port}"))
            .arg("--tls-ca")
            .arg(&cert_path)
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("tls-handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect tls/zenohd"),
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
    cleanup_cert_files(&cert_path, &key_path);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s over tls — the \
             wz<->zenohd TLS handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    // WITNESS the tls transport. The reserved `tls_port` is a tls-only listener
    // and `tcp_port` is a separate port, so a TCP dial could not reach Established
    // here (structurally — no TCP fallback); but that is an INFERENCE. wz-ap-demo
    // logs the dialed transport name, so this asserts the leg really opened a TLS
    // link. A regression that quietly dialed TCP would drop "over tls transport".
    assert!(
        demo_captured.contains("over tls transport"),
        "leg 12 reached Established but did not witness a TLS-transport dial in \
         wz-ap-demo stderr (expected 'over tls transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// leg 13 (R311y365) — wz's Put over a `tls/` link routes through zenohd to a
/// zenoh-pico `z_sub` on TCP: the TLS-transport counterpart of leg 9 (ws) / leg
/// 11 (unixsock) / leg 2 (tcp, data-plane cross-impl). wz dials zenohd with
/// `--connect tls/127.0.0.1:{tls_port} --tls-ca {cert}` (its TLS transport), pico
/// subscribes over `tcp/`, and zenohd routes wz's Put ACROSS the two link types.
/// This pins wz's TLS data plane against the REFERENCE zenoh `tls/` link — wz
/// publishes over the encrypted stream, the reference router decodes it off its
/// `tls/` listener and forwards to the pico TCP subscriber. The same Put-burst +
/// retried-zsub shape as [`wz_publish_routes_through_zenohd_to_pico_zsub`], one
/// transport over.
// wz-proves: transport-link-tls wz->zenohd
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: pubsub-put wz->zenohd
// wz-proves: pubsub-put wz->pico
// wz-proves: routing-client wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router tls + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub_over_tls() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (tcp_res, tls_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let (cert_path, key_path) = zenohd_tls_cert_paths(tcp_port);
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-over-tls";

    let (cert_pem, key_pem) = localhost_cert_key_pem();
    std::fs::write(&cert_path, &cert_pem).expect("write tls cert pem");
    std::fs::write(&key_path, &key_pem).expect("write tls key pem");

    let mut zenohd = spawn_zenohd_tcp_tls(tcp_port, tls_port, &cert_path, &key_path, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // ── pico z_sub: a TCP client of zenohd, subscribed and ready (retried past
    //    any transient one-shot open). Its declared subscription is the route
    //    zenohd uses to forward wz's TLS Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // ── wz-ap-demo: a TLS client of zenohd that emits a Put burst. The burst
    //    (publisher_task) covers the window for z_sub's subscription to reach
    //    zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect tls/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("tls/127.0.0.1:{tls_port}"))
            .arg("--tls-ca")
            .arg(&cert_path)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect tls/zenohd --publish"),
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
    cleanup_cert_files(&cert_path, &key_path);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's TLS Put did not route \
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
    // WITNESS the tls transport. z_sub receiving proves the data plane routed, but
    // not that wz's leg of it was TLS (vs a silent TCP dial); wz-ap-demo logs the
    // dialed transport name, so assert it dialed `tls`.
    assert!(
        demo_captured.contains("over tls transport"),
        "leg 13 routed wz->zenohd->pico but did not witness a TLS-transport dial \
         in wz-ap-demo stderr (expected 'over tls transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
}

/// The `(cert_pem_path, key_pem_path)` for a QUIC leg's zenohd server material,
/// keyed on the reserved (unique) `tcp_port` so concurrent-file legs never
/// collide — the QUIC sibling of [`zenohd_tls_cert_paths`] with a `quic`-distinct
/// filename prefix (a `quic/` leg and a `tls/` leg picking the same `tcp_port`
/// would otherwise share a path). QUIC reads its cert from the SAME
/// `transport/link/tls` config block as TLS (spawn_zenohd_tcp_quic), so the cert
/// material itself is identical; only the on-disk path differs.
fn zenohd_quic_cert_paths(tcp_port: u16) -> (String, String) {
    let dir = std::env::temp_dir();
    let cert = dir
        .join(format!("wz-zenohd-quic-{tcp_port}.cert.pem"))
        .to_string_lossy()
        .into_owned();
    let key = dir
        .join(format!("wz-zenohd-quic-{tcp_port}.key.pem"))
        .to_string_lossy()
        .into_owned();
    (cert, key)
}

/// leg 14 (R311y366) — wz reaches Established against zenohd over a `quic/` (QUIC,
/// TLS-1.3 + ALPN `hq-29`) link: the QUIC-transport counterpart of leg 12 (tls) /
/// leg 8 (ws) / leg 1 (tcp, handshake wire-parity). Deterministic (no peer-timing
/// race, pico-free) — pins that wz's QUIC transport (`quic_pipeline`, a quinn
/// `Endpoint::connect` + single bidirectional stream carrying the same
/// StreamEnvelope length-prefix as tcp) completes the QUIC + TLS-1.3 handshake AND
/// the zenoh 4-way handshake against the reference router's `quic/` listener. wz
/// dials with `--connect quic/127.0.0.1:{quic_port} --quic-ca {cert}` (the
/// `wz-ap-demo` binary built with the `quic` feature, R311y366): the connect
/// ADDRESS is numeric but the cert is verified against server name `localhost`
/// (`QuicDialConfig::from_ca_pem`), so one rcgen self-signed `localhost` cert
/// serves both zenohd (listen_certificate, via the tls config block) and wz
/// (root_ca), with NO IP SAN. zenohd also listens on `tcp/` for its readiness gate
/// (pico has no usable `quic/` link here). Mirrors
/// [`wz_client_reaches_established_against_zenohd_over_tls`] one transport over.
// wz-proves: transport-link-quic wz->zenohd
// wz-proves: session-unicast-open wz->zenohd
// wz-proves: codec-init-body wz->zenohd
// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-open-body wz->zenohd
// wz-proves: codec-open-body zenohd->wz
// wz-proves: transport-unicast wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router, quic); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd_over_quic() {
    let demo = wz_ap_demo_binary();
    let (tcp_res, quic_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let (cert_path, key_path) = zenohd_quic_cert_paths(tcp_port);
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    std::fs::write(&cert_path, &cert_pem).expect("write quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write quic key pem");

    let mut zenohd = spawn_zenohd_tcp_quic(tcp_port, quic_port, &cert_path, &key_path, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect quic/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("quic/127.0.0.1:{quic_port}"))
            .arg("--quic-ca")
            .arg(&cert_path)
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("quic-handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect quic/zenohd"),
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
    cleanup_cert_files(&cert_path, &key_path);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s over quic — the \
             wz<->zenohd QUIC handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    // WITNESS the quic transport. The reserved `quic_port` is a quic-only listener
    // and `tcp_port` is a separate port, so a TCP dial could not reach Established
    // here (structurally — no TCP fallback); but that is an INFERENCE. wz-ap-demo
    // logs the dialed transport name, so this asserts the leg really opened a QUIC
    // link. A regression that quietly dialed TCP would drop "over quic transport".
    assert!(
        demo_captured.contains("over quic transport"),
        "leg 14 reached Established but did not witness a QUIC-transport dial in \
         wz-ap-demo stderr (expected 'over quic transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// leg 15 (R311y366) — wz's Put over a `quic/` link routes through zenohd to a
/// zenoh-pico `z_sub` on TCP: the QUIC-transport counterpart of leg 13 (tls) / leg
/// 9 (ws) / leg 2 (tcp, data-plane cross-impl). wz dials zenohd with
/// `--connect quic/127.0.0.1:{quic_port} --quic-ca {cert}` (its QUIC transport),
/// pico subscribes over `tcp/`, and zenohd routes wz's Put ACROSS the two link
/// types. This pins wz's QUIC data plane against the REFERENCE zenoh `quic/` link —
/// wz publishes over the QUIC stream, the reference router decodes it off its
/// `quic/` listener and forwards to the pico TCP subscriber. The same Put-burst +
/// retried-zsub shape as [`wz_publish_routes_through_zenohd_to_pico_zsub_over_tls`],
/// one transport over.
// wz-proves: transport-link-quic wz->zenohd
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: pubsub-put wz->zenohd
// wz-proves: pubsub-put wz->pico
// wz-proves: routing-client wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router quic + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub_over_quic() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (tcp_res, quic_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let (cert_path, key_path) = zenohd_quic_cert_paths(tcp_port);
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-over-quic";

    let (cert_pem, key_pem) = localhost_cert_key_pem();
    std::fs::write(&cert_path, &cert_pem).expect("write quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write quic key pem");

    let mut zenohd = spawn_zenohd_tcp_quic(tcp_port, quic_port, &cert_path, &key_path, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(tcp_res);

    // ── pico z_sub: a TCP client of zenohd, subscribed and ready (retried past
    //    any transient one-shot open). Its declared subscription is the route
    //    zenohd uses to forward wz's QUIC Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // ── wz-ap-demo: a QUIC client of zenohd that emits a Put burst. The burst
    //    (publisher_task) covers the window for z_sub's subscription to reach
    //    zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect quic/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("quic/127.0.0.1:{quic_port}"))
            .arg("--quic-ca")
            .arg(&cert_path)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect quic/zenohd --publish"),
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
    cleanup_cert_files(&cert_path, &key_path);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's QUIC Put did not route \
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
    // WITNESS the quic transport. z_sub receiving proves the data plane routed, but
    // not that wz's leg of it was QUIC (vs a silent TCP dial); wz-ap-demo logs the
    // dialed transport name, so assert it dialed `quic`.
    assert!(
        demo_captured.contains("over quic transport"),
        "leg 15 routed wz->zenohd->pico but did not witness a QUIC-transport dial \
         in wz-ap-demo stderr (expected 'over quic transport').\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
}
