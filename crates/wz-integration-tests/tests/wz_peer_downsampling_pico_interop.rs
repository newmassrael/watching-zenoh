// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y452 — FOREIGN-INTEROP DOWNSAMPLING (§5.16 `access-downsampling`): a real
//! zenoh-pico `z_pub` CLI publishes a BURST of Puts on one keyexpr, and a
//! watching-zenoh peer's downsampling interceptor admits EXACTLY THE FIRST of
//! them — the rest arrive inside the rule's minimum interval and are dropped
//! (zenoh `net/routing/interceptor/downsampling.rs:242`, `now - latest >=
//! threshold`).
//!
//! ## Why the count is the discriminator
//!
//! "The subscriber received fewer messages" is a weak witness on its own. Here
//! the admitted count separates all three outcomes in ONE number, because the
//! burst size is known:
//!
//! - **0 admitted** → the session, the route or the pico build is broken.
//! - **[`PICO_PUB_COUNT`] admitted** → the peer works and nothing throttled.
//! - **exactly 1 admitted** → the downsampler ran and its rule timer held.
//!
//! A separate positive control on an UNGOVERNED keyexpr runs first in the SAME
//! leg, so the first outcome is excluded before the burst is even sent.
//!
//! ## Why this leg could not exist before R311y452
//!
//! The rate is derived from pico's own publish cadence rather than picked: `z_pub`
//! sleeps [`PICO_PUB_PERIOD_SECS`] between iterations
//! (`vendor/zenoh-pico/examples/unix/c11/z_pub.c:96-99`), so the burst spans
//! [`BURST_SPAN_SECS`] and the rule must be SLOWER than that for the drop to be
//! attributable to the rate limit. The pre-y452 `--downsample` was hardcoded to
//! 500 ms — FASTER than pico's 1 Hz cadence — so the old code admitted every put
//! in this burst and no configuration of it could have produced this leg. The
//! discriminating input is the interval itself, which is why the leg is driven
//! through `--downsample-freq`, in zenoh's own Hertz unit, and therefore also
//! binds the `interval_from_freq` mapping: an inverted mapping yields 30 ms
//! instead of 30 s and every put is admitted.
//!
//! pico is the ENCODER on the wire: its C stack opens the session, declares the
//! publisher and emits the Put burst; the wz peer's §5.16 downsampler is the
//! adjudicator. Requires the binary built with `--features routing-peer` (which
//! pulls `access-downsampling`); Layer E6 builds `routing-peer,adminspace-write`.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// How many Puts pico's `z_pub` emits — its `-n` flag
/// (`vendor/zenoh-pico/examples/unix/c11/z_pub.c:135-137`).
const PICO_PUB_COUNT: u32 = 3;

/// pico's inter-Put sleep: `z_sleep_s(1)` at the top of the publish loop
/// (`z_pub.c:96-99`). The cadence is upstream's, not ours to choose.
const PICO_PUB_PERIOD_SECS: u32 = 1;

/// How long the whole burst takes on the wire, worst case.
const BURST_SPAN_SECS: u32 = PICO_PUB_COUNT * PICO_PUB_PERIOD_SECS;

/// The peer's downsampling rate, as zenoh's maximum frequency in Hertz — slow
/// enough that the rule's interval covers the WHOLE burst with an order of
/// magnitude to spare, so exactly the first Put is due. Derived from pico's
/// cadence above rather than hardcoded, so an upstream change to the example's
/// sleep cannot silently turn the drop into a timing accident.
const DOWNSAMPLE_FREQ_HZ: f64 = 1.0 / (10.0 * BURST_SPAN_SECS as f64);

/// The keyexpr the downsampling rule governs — what pico bursts on.
const GOVERNED_KEY: &str = "demo/rate";

/// An UNGOVERNED keyexpr (it does not intersect [`GOVERNED_KEY`]) — the positive
/// control, so a later non-arrival is the rate limit and not a dead session.
const CONTROL_KEY: &str = "demo/ctl";

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Mirrors the sibling low-pass leg's
/// `spawn_peer`. Returns the guard, its stderr reader, and the port.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
             --features routing-peer?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Drive one of pico's publisher CLIs at the wz peer's tcp listener and block
/// until it exits. `extra` carries the per-CLI flags (`z_pub` needs `-n` so it
/// publishes a bounded burst instead of forever).
fn pico_publish(cli: &str, key: &str, value: &str, addr: &str, extra: &[&str]) {
    let bin = zenoh_pico_cli_binary(cli);
    let endpoint = format!("tcp/{addr}");
    let mut args = vec!["-k", key, "-v", value, "-e", &endpoint, "-m", "client"];
    args.extend_from_slice(extra);
    let mut child = ChildGuard::wrap(
        format!("{cli} client (zenoh-pico) {key}"),
        Command::new(&bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {cli}: {e}")),
    );
    let _ = child.child_mut().wait();
}

/// leg (R311y452) — a real zenoh-pico Put BURST on a governed keyexpr is admitted
/// exactly once by the wz peer's §5.16 downsampler, while an ungoverned Put in
/// the same leg is admitted normally. pico is the encoder; the wz peer's
/// interceptor is the adjudicator.
// wz-proves: access-downsampling pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_put/z_pub CLIs); Layer E6 runs via --ignored"]
fn wz_peer_downsamples_a_pico_put_burst_to_the_rule_interval() {
    let freq = DOWNSAMPLE_FREQ_HZ.to_string();
    let burst = PICO_PUB_COUNT.to_string();
    let (mut peer_guard, mut peer_reader, port) = spawn_peer(
        "downsample-peer",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "**",
            "--downsample",
            GOVERNED_KEY,
            "--downsample-freq",
            &freq,
        ],
    );
    let addr = format!("127.0.0.1:{port}");

    // Positive control FIRST: a Put on an ungoverned keyexpr must be ADMITTED, so
    // the burst's later non-arrivals are the rate limit and not a dead session.
    pico_publish("z_put", CONTROL_KEY, "ctl", &addr, &[]);
    let admitted = wait_for_substring(
        &mut peer_reader,
        "received mesh data (1 push(es))",
        Duration::from_secs(15),
    );

    // The atom: a burst of PICO_PUB_COUNT Puts on the governed keyexpr, one per
    // second. The rule's interval spans the whole burst, so only the FIRST is due.
    pico_publish("z_pub", GOVERNED_KEY, "burst", &addr, &["-n", &burst]);
    let dropped = wait_for_substring(
        &mut peer_reader,
        "interceptor dropped (2 message(s))",
        Duration::from_secs(30),
    );

    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut peer_reader);
    eprintln!("--- downsample-peer stderr ---\n{captured}");

    if let Err(c) = &admitted {
        panic!(
            "wz peer never admitted the ungoverned control put within 15s — the \
             peer/session/route is broken, not the downsampler.\n\
             --- downsample-peer stderr at deadline ---\n{c}"
        );
    }
    if let Err(c) = &dropped {
        panic!(
            "wz peer never dropped the {} later puts of the pico burst within 30s. \
             At {DOWNSAMPLE_FREQ_HZ} Hz the rule's interval covers the whole \
             {BURST_SPAN_SECS}s burst, so only the FIRST put is due — every one \
             admitted means the §5.16 downsampler did not run, or its interval was \
             not the configured one.\n--- downsample-peer stderr at deadline ---\n{c}",
            PICO_PUB_COUNT - 1
        );
    }
    // Exactly the burst's 2nd and 3rd puts were dropped ...
    assert!(
        captured.contains("interceptor dropped (2 message(s))"),
        "expected the downsampler to drop exactly {} messages (the burst minus its \
         first put).\n--- downsample-peer stderr ---\n{captured}",
        PICO_PUB_COUNT - 1
    );
    assert!(
        !captured.contains("interceptor dropped (3 message(s))"),
        "the downsampler dropped MORE than the burst's later puts — the control put \
         or a control-plane message was throttled too.\n\
         --- downsample-peer stderr ---\n{captured}"
    );
    // ... so exactly two pushes were admitted: the control, and the burst's first.
    assert!(
        captured.contains("2 data push(es) received"),
        "expected exactly 2 admitted data pushes (the ungoverned control, plus the \
         one due put of the burst).\n--- downsample-peer stderr ---\n{captured}"
    );
    // ... and the burst did NOT slip past unthrottled, which is what the pre-y452
    // 500ms-hardcoded interval produced against pico's 1 Hz cadence.
    assert!(
        !captured.contains("4 data push(es) received"),
        "the whole pico burst leaked past the §5.16 downsampler — at pico's \
         {PICO_PUB_PERIOD_SECS}s cadence that is exactly what an interval shorter \
         than the burst span does.\n--- downsample-peer stderr ---\n{captured}"
    );
}
