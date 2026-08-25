// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 `router-connect-reconcile` — the runtime-reconciled federation face
//! CARRIES DATA between two real zenoh-pico clients, on the `preset-ap-full` build.
//!
//! ## The two gaps this closes, and why neither was visible before
//!
//! GAP 1 — `wz_router_hat_connect_reconcile.rs` proves the reconcile FOUR ways, and
//! every one of them asserts a LINK-STATE COUNT: `routers-net converged (2 node(s))`,
//! `peak routers-net 2 node(s)`, `dialed 1,`, a re-dial fire line. None of them asks
//! whether a single byte of application data crosses the face the reconcile just
//! dialed. A federation link that establishes, floods link-state, and then forwards
//! NOTHING passes all four. That file also records the reason it stopped there:
//!
//!     "Cross-impl is NOT needed for this atom: the reconcile introduces no new wire
//!      format -- the runtime dial reuses the already-cross-impl-proven session-open
//!      handshake -- so a wz<->wz loopback exercises the whole new control path."
//!
//! That is an EXEMPTION, and an exemption is a claim. It is right about the wire
//! FORMAT and silent about the DATA PATH: what the reconcile newly creates is a face
//! that the router tier must then choose as a forwarding next-hop, which is a routing
//! decision, not a codec one. This file tests the part the exemption did not cover.
//!
//! GAP 2 — `wz_router_hat_pico_interop.rs` states in its own header that the router
//! tier has no foreign witness at all ("NO cross-impl test yet puts a foreign impl on
//! THAT wire") and lists "multi-router federation to pico" among the legs it does not
//! exercise. The topology below is that leg.
//!
//! ## Topology, and why it is a DISCRIMINATOR rather than a demonstration
//!
//!     pico z_pub -m client ──► R1 ──(dialed at t+600ms by --connect-after)──► R2 ◄── pico z_sub -m client
//!
//! R1 is spawned with NO static `--connect`. The ONLY route from R1 to R2 is the one
//! the runtime reconcile creates, so a sample that reaches the foreign subscriber has
//! necessarily traversed it. Both endpoints are foreign: nothing in the exchange is wz
//! agreeing with its own twin.
//!
//! The `preset-ap-full` binary compiles `router-multicast-faces`, so the routers also
//! share a UDP multicast group — and a first run of this topology showed both routers
//! logging mcast-ingress federation activity, which would have made "the sample
//! crossed" prove nothing about the reconcile. Leg 2 is the calibration that kills
//! that confound: with `--connect-after` removed and NOTHING else changed, the same
//! AP-full binary (multicast compiled in, group live) forwards `0 data push(es)` and
//! the payload never arrives. The claim in leg 1 therefore binds to the reconcile.
//!
//! Both legs pin `--multicast-locator` to a group of their own. The default group is
//! machine-wide, and a router-hat belonging to some other lane joining it would make
//! leg 2 an absence-assertion over a shared resource — the shape a flaky test has.
//!
//! ## Honest scope
//!
//! The claim is `partial`. `router-connect-reconcile` carries TWO mechanisms — the
//! add-only runtime connect-list reconcile (slice 1) and the dropped-peer auto-redial
//! (slice 2) — and only the first is witnessed here by a foreign peer. Slice 2 keeps
//! its wz<->wz proof in `wz_router_hat_connect_reconcile.rs`.

use std::fs::File;
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    ChildGuard,
};

/// Generous: the lane runs under full-run-ci process pressure and every wait returns
/// the instant its marker lands, so a wide ceiling costs a green run nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(25);

/// A group of this file's own, so neither leg shares the machine-wide default with a
/// router-hat from another lane. Leg 2 asserts an ABSENCE; an absence over a shared
/// multicast group is not a test, it is a race.
const MCAST: &str = "udp/224.0.0.231:7499";

/// `--connect-after` fires this long after startup. Long enough that R1 is provably
/// isolated first, short enough not to pad the lane.
const RECONCILE_AFTER_MS: u64 = 600;

fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for router-hat stderr");
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    )
}

/// The binary under test is resolved through a SHARED path (`target/debug/wz-ap-demo`)
/// that other lanes rebuild with other feature sets. A run against the wrong build is
/// not a red test, it is a test that measured something else — this asserts the build
/// out of the binary's own startup banner before anything is concluded from it.
fn assert_is_apfull_build(captured: &str, whose: &str) {
    let banner = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES ="))
        .unwrap_or_else(|| {
            panic!("{whose} never printed its BUILD FEATURES banner\n--- {whose} ---\n{captured}")
        });
    for required in [
        "preset-ap-full",
        "router-connect-reconcile",
        "router-hat-router",
    ] {
        assert!(
            banner.contains(required),
            "{whose} was not the AP-full build this file tests: its banner lacks \
             `{required}`. The shared target/debug/wz-ap-demo was rebuilt by another \
             lane, so this run measured a different binary.\n--- banner ---\n{banner}"
        );
    }
}

/// LEG 1 — a foreign pico publisher's sample reaches a foreign pico subscriber across
/// a federation face that did not exist at startup.
///
/// R1 holds no static connect list, so `deliver_to_client_subscribers` on R1 cannot
/// reach R2's client: the sample must be bridged across the router tier over the face
/// `--connect-after` dialed at runtime. The reconcile fire line is asserted too, so a
/// green run cannot be explained by a startup dial that never happened.
// wz-proves: router-connect-reconcile wz->pico partial
// wz-proves: router-hat-router wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E15 runs via --ignored"]
fn apfull_reconcile_federation_carries_data_between_two_real_picos() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let sub_key = "demo/**";
    let pub_key = "demo/reconcile/xmesh";
    let payload = "APFULL-RECONCILE-XMESH-BETWEEN-TWO-PICOS";

    // R2 binds first: the reconcile needs a live target. It hosts no connect list of
    // its own, so its router tier can only rise because R1 dialed IN.
    let (mut r2_guard, mut r2_reader, p_r2) = spawn_router_hat(
        "router-hat-2 (AP-full)",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--zid",
            "22222222",
            "--multicast-locator",
            MCAST,
        ],
    );
    let addr_r2 = format!("127.0.0.1:{p_r2}");

    // R1: no `--connect`, only the runtime affordance.
    let connect_after = format!("{RECONCILE_AFTER_MS}:{addr_r2}");
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1 (AP-full)",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--zid",
            "11111111",
            "--multicast-locator",
            MCAST,
            "--connect-after",
            &connect_after,
        ],
    );
    let ep_r1 = format!("tcp/127.0.0.1:{p_r1}");
    let ep_r2 = format!("tcp/127.0.0.1:{p_r2}");

    // ORDER the federation before any pico attaches — the fixture owns this rather
    // than sleeping on it. Both markers, because convergence alone would not say the
    // reconcile is what produced it.
    let fired = wait_for_substring(
        &mut r1_reader,
        "--connect-after fired; reconciling connect-list",
        EXCHANGE_TIMEOUT,
    );
    let converged = wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        EXCHANGE_TIMEOUT,
    );

    // Foreign subscriber on R2. The helper returns only once pico has opened the
    // session AND declared.
    let (mut sub_child, mut sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &ep_r2, "the AP-full router-hat-2", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });
    // R2's own readiness witness: the pico subscription is installed in `client_subs`
    // before the first Put, so a lost first sample cannot be mistaken for a lost route.
    let learned = wait_for_substring(&mut r2_reader, "learned a client sub", EXCHANGE_TIMEOUT);

    // Foreign publisher on R1, bursting: an interest still propagating across the
    // freshly-reconciled face costs a dropped sample, not a failed test.
    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        pub_key,
        payload,
        &ep_r1,
        "the AP-full router-hat-1",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    let received =
        wait_for_substring(&mut sub_reader, payload, EXCHANGE_TIMEOUT).map(|c| c.to_string());

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = sub_child.child_mut().kill();
    let _ = sub_child.child_mut().wait();
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    assert_is_apfull_build(&r1_captured, "router-hat-1");
    assert_is_apfull_build(&r2_captured, "router-hat-2");

    fired.unwrap_or_else(|c| {
        panic!("router-hat-1 never fired the --connect-after reconcile\n--- r1 ---\n{c}")
    });
    converged.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never converged its router tier to 2 — the runtime reconcile \
             did not establish the federation face\n--- r1 ---\n{c}"
        )
    });
    learned.unwrap_or_else(|c| {
        panic!(
            "router-hat-2 never learned the foreign pico client subscription\n--- r2 \
             ---\n{c}"
        )
    });

    let sub_out = received.unwrap_or_else(|c| {
        panic!(
            "the real zenoh-pico z_sub on R2 never received '{payload}' published by \
             the real zenoh-pico z_pub on R1. R1 has no static --connect, so the only \
             path is the face --connect-after dialed at runtime: the reconcile \
             established a federation that link-state converged over but that carries \
             no data.\n--- pico z_sub stdout ---\n{c}\n--- router-hat-1 ---\n\
             {r1_captured}\n--- router-hat-2 ---\n{r2_captured}"
        )
    });
    assert!(
        sub_out.contains(pub_key),
        "the payload arrived but not on {pub_key} — the bridged sample carried the \
         wrong keyexpr\n--- pico z_sub stdout ---\n{sub_out}"
    );
    // The routers must have ACTUALLY forwarded. Latched at shutdown, so it cannot
    // race the app tick.
    assert!(
        !r1_captured.contains("0 data push(es) forwarded"),
        "the pico subscriber got the sample but router-hat-1's latched shutdown \
         summary reports zero forwarded pushes — the sample did not travel through \
         R1's forwarder\n--- router-hat-1 ---\n{r1_captured}"
    );
}

/// LEG 2 — the CALIBRATION that makes leg 1's claim bind to the reconcile.
///
/// Identical topology and the identical binary, with `--connect-after` removed and
/// nothing else changed. `preset-ap-full` compiles `router-multicast-faces` and the
/// group is live in both legs, so if multicast were carrying the exchange this leg
/// would pass — and leg 1 would be proving the multicast plane while naming the
/// reconcile. The assertions are the LATCHED shutdown counters (deterministic), with
/// the payload absence as the corroborating observation rather than the load-bearing
/// one.
// wz-proves: none -- negative control: with the reconcile removed the AP-full routers
// share only their multicast group, and the exchange fails; this is what binds leg 1's
// router-connect-reconcile claim to the reconcile-dialed face rather than to multicast
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E15 runs via --ignored"]
fn apfull_without_the_reconcile_the_two_picos_cannot_reach_each_other() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let sub_key = "demo/**";
    let pub_key = "demo/reconcile/xmesh";
    let payload = "APFULL-NO-RECONCILE-MUST-NOT-CROSS";

    let (mut r2_guard, mut r2_reader, p_r2) = spawn_router_hat(
        "router-hat-2 (AP-full, no reconcile)",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--zid",
            "22222222",
            "--multicast-locator",
            MCAST,
        ],
    );
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1 (AP-full, no reconcile)",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--zid",
            "11111111",
            "--multicast-locator",
            MCAST,
        ],
    );
    let ep_r1 = format!("tcp/127.0.0.1:{p_r1}");
    let ep_r2 = format!("tcp/127.0.0.1:{p_r2}");

    let (mut sub_child, mut sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &ep_r2, "the AP-full router-hat-2", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });
    wait_for_substring(&mut r2_reader, "learned a client sub", EXCHANGE_TIMEOUT).unwrap_or_else(
        |c| panic!("router-hat-2 never learned the foreign pico client sub\n--- r2 ---\n{c}"),
    );

    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        pub_key,
        payload,
        &ep_r1,
        "the AP-full router-hat-1",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    // Bounded window: long enough that a working path would have delivered many times
    // over (leg 1 delivers well inside it), and the structural assertions below do the
    // load-bearing work regardless.
    let crossed = wait_for_substring(&mut sub_reader, payload, EXCHANGE_TIMEOUT);

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = sub_child.child_mut().kill();
    let _ = sub_child.child_mut().wait();
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    assert_is_apfull_build(&r1_captured, "router-hat-1");
    assert_is_apfull_build(&r2_captured, "router-hat-2");

    // Structural, latched, deterministic: R1 never dialed and never federated.
    assert!(
        r1_captured.contains("dialed 0,"),
        "router-hat-1 dialed something without a --connect or --connect-after — the \
         calibration is not isolating the reconcile\n--- r1 ---\n{r1_captured}"
    );
    assert!(
        r1_captured.contains("peak routers-net 1 node(s)"),
        "router-hat-1's router tier rose above itself without any reconcile — the two \
         AP-full routers federated through some path other than --connect-after, which \
         would make leg 1's claim bind to that path instead\n--- r1 ---\n{r1_captured}"
    );
    assert!(
        r1_captured.contains("0 data push(es) forwarded"),
        "router-hat-1 forwarded data with no federation face — leg 1's claim would not \
         be isolating the reconcile\n--- r1 ---\n{r1_captured}"
    );
    assert!(
        !r1_captured.contains("--connect-after fired"),
        "a run without --connect-after must not fire a reconcile\n--- r1 ---\n{r1_captured}"
    );
    if let Ok(c) = crossed {
        panic!(
            "the payload reached the foreign subscriber on R2 with NO reconcile \
             between the routers. Leg 1 would then be proving whatever path this is — \
             the multicast group is the prime suspect — while naming \
             router-connect-reconcile.\n--- pico z_sub stdout ---\n{c}\n--- r1 ---\n\
             {r1_captured}\n--- r2 ---\n{r2_captured}"
        );
    }
}
