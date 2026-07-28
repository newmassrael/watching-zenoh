// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenohd COMPOSED lowlatency x compression cross-impl interop (R311y435).
//!
//! R311y434 fixed a real interop defect — wz wrapped lz4 compression OUTSIDE the
//! lowlatency lean encode, producing a wire no zenoh peer can read — and then
//! stated plainly what it could not prove:
//!
//! > NOT CLAIMED: a cross-impl witness for the COMPOSED session. No leg dials
//! > zenohd with both modes, because the demo cannot stage both offers. What is
//! > proven is narrower and stated as such: the composed session now emits
//! > exactly the lean wire (wz<->wz byte assertion) and the lean wire
//! > interoperates with zenohd (R311y372). The composition of those two is an
//! > argument, not a measurement.
//!
//! This file is that measurement. It exists because R311y435 widened
//! `session_open` to take an offer SET
//! (`initiate_and_open_session_with_offer`), which is exactly what R311y434
//! named as the blocker: with one entrypoint per MODE, no caller — demo or
//! deployment — could stage both offers at once.
//!
//! ## Why zenohd is a competent oracle for the PAIR
//!
//! Upstream's two flags are set independently and neither gates the other:
//! `is_lowlatency` lands on the transport config and `is_compression` on the
//! link `BatchConfig` (`zenoh-transport-1.5.0`
//! `unicast/establishment/open.rs:689` and `:701`), and the exclusivity check at
//! `unicast/manager.rs:264` names QOS, not compression. So a zenohd configured
//! for both is a configuration upstream supports, not a contrivance.
//!
//! What that router will NOT do is decompress a lean link: its lean rx reads only
//! `config.batch.mtu` (`unicast/lowlatency/link.rs:161`) and its lean tx
//! serializes straight to the link behind a 4-byte length prefix, never touching
//! `WBatch` or `BatchHeader` (`:33-73`). Upstream the negotiated wrap is simply
//! INERT on a lean link. That asymmetry is what makes this leg a proof: a peer
//! that wraps anyway is unreadable, and unreadable is observable here as
//! non-delivery through a real foreign router.
//!
//! ## Why the `active` witness and not just `negotiated`
//!
//! The pre-y434 build and the fixed build BOTH log `compression negotiated =
//! true` on this dial — the handshake is byte-identical, which was the whole
//! point of fixing the data path rather than the negotiation. So the negotiation
//! line cannot discriminate them. R311y435 adds the second demo witness,
//! `batch compression active = <compresses_batches()>`, which is the R311y434
//! split made observable from outside the process: NEGOTIATED versus APPLIED.
//!
//! ## The two legs — an option-atom PAIR differing in ONE offer
//!
//!   1. the PROOF. wz dials `--lowlatency --compression`. Both exts negotiate
//!      (`&=` true means zenohd mirrored each), the wrap is nonetheless reported
//!      INACTIVE, and a compressible Put routes lean through the composed zenohd
//!      to a pico `z_sub` byte-exact.
//!   2. the TWIN. The SAME dial against the SAME router configuration, minus
//!      `--lowlatency` alone. Compression negotiates identically, the wrap is now
//!      ACTIVE, and the same value routes wrapped. This is what makes leg 1's
//!      `active = false` attributable to the lowlatency offer rather than to
//!      compression having silently stopped working in this build.
//!
//! Binding to the atom's OWN code: drop the `!is_lowlatency()` conjunct from
//! `SessionLinkActions::compresses_batches` — the R311y434 fix — and leg 1 fails
//! (wz wraps the lean wire; the composed zenohd cannot read it, so nothing
//! reaches z_sub) while leg 2 stays green, since its session was never lean. That
//! RED is the first FOREIGN witness for that fix; until this round it had only a
//! wz<->wz byte assertion behind it.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd + the pico z_sub CLI are external
//! binaries. Serialized with the other zenohd legs (`--test-threads=1`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_subscribed_zsub, spawn_zenohd_lowlatency_compression_on_ephemeral_tcp,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// A value lz4 shrinks by more than an order of magnitude, so on the TWIN's
/// non-lean session `compress_batch` provably keeps the compressed form and the
/// COMPRESSION bit goes out SET. Both legs publish the same shape so the pair
/// differs in the offer alone; sized as in `wz_compression_zenohd_interop` to
/// stay well inside the fixture's routable range.
fn compressible_value(tag: &str) -> String {
    format!("{tag}-{}", "COMPOSED-LEAN-BATCH-".repeat(28))
}

/// Drive `wz-ap-demo --connect <port> --compression [--lowlatency] --publish
/// <key>` and return (demo stderr capture, the z_sub stdout capture at the
/// deadline or on success).
///
/// Shared by both legs so the ONLY difference between them is the
/// `offer_lowlatency` bool — the pair is a pair by construction, not by parallel
/// maintenance of two copies.
fn publish_through(
    port: u16,
    offer_lowlatency: bool,
    publish_key: &str,
    publish_value: &str,
) -> (String, Result<String, String>) {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // pico z_sub: a UNIVERSAL client of zenohd, subscribed and ready. zenoh-pico
    // has NEITHER the lean transport NOR compression, so its own link is plain
    // whatever wz negotiated — which is the point: zenohd must terminate wz's
    // transport and re-encode to route the sample here at all.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut command = Command::new(&demo);
    command.arg("--connect").arg(format!("127.0.0.1:{port}"));
    if offer_lowlatency {
        command.arg("--lowlatency");
    }
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd [--lowlatency] --compression --publish)",
        command
            .arg("--compression")
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --compression"),
    );

    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        ">> [Subscriber] Received",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    match &received {
        Ok(c) | Err(c) => eprintln!("--- captured z_sub stdout ---\n{c}"),
    }
    (demo_captured, received)
}

// wz-proves: transport-lowlatency wz->zenohd
// wz-proves: session-extcompression wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router lowlatency+compression + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_suppresses_the_lz4_wrap_on_a_lean_session_and_zenohd_routes_it() {
    let publish_key = "demo/zenohd-composed-lean";
    let publish_value = compressible_value("hello-composed-via-zenohd");

    let (mut zenohd, port) = spawn_zenohd_lowlatency_compression_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });

    let (demo_captured, received) = publish_through(port, true, publish_key, &publish_value);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // Assertion 1 — BOTH exts negotiated cross-impl. This is the configuration
    // upstream permits and pre-y434 wz mis-served: two independent flags, both
    // true, neither gating the other.
    assert!(
        demo_captured.contains("lowlatency negotiated = true"),
        "wz did not negotiate the lean transport with the composed zenohd \
         (expected 'lowlatency negotiated = true').\n--- captured wz-ap-demo \
         stderr ---\n{demo_captured}"
    );
    assert!(
        demo_captured.contains("compression negotiated = true"),
        "wz did not negotiate compression with the composed zenohd (expected \
         'compression negotiated = true'). Both exts must negotiate, or this leg \
         is not testing the COMPOSED case at all.\n--- captured wz-ap-demo \
         stderr ---\n{demo_captured}"
    );

    // Assertion 2 — NEGOTIATED but NOT APPLIED: the R311y434 split, witnessed
    // from outside the process. The handshake is byte-identical to a build that
    // would go on to wrap; only this line separates them.
    assert!(
        demo_captured.contains("batch compression active = false"),
        "wz reports the lz4 batch wrap ACTIVE on a lean session. Upstream's lean \
         tx never touches WBatch/BatchHeader and its lean rx never decompresses \
         (unicast/lowlatency/link.rs:33-73, :161), so a wrapped lean wire is \
         unreadable to every zenoh peer. This is the R311y434 defect \
         reappearing.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // Assertion 3 — the FOREIGN consequence. A composed zenohd routes the lean,
    // un-wrapped Put through to a pico subscriber. Wrap it and this is where the
    // failure surfaces: the router cannot decode the batch, so nothing arrives.
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '>> [Subscriber] Received' within 10s — wz's \
             composed (lean + compression-negotiated) Put did not route through \
             the composed zenohd to z_sub.\n--- captured z_sub stdout at deadline \
             ---\n{c}\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key),
        "z_sub received but the publish keyexpr '{publish_key}' is missing.\n{received_text}"
    );
    assert!(
        received_text.contains(&publish_value),
        "z_sub received but the {}-byte value did not arrive intact over the \
         composed session.\n{received_text}",
        publish_value.len()
    );
}

// wz-proves: session-extcompression wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router lowlatency+compression + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn the_same_dial_without_the_lowlatency_offer_applies_the_wrap_through_zenohd() {
    let publish_key = "demo/zenohd-composed-wrapped";
    let publish_value = compressible_value("hello-wrapped-via-zenohd");

    // The SAME router configuration as the leg above — lowlatency AND compression
    // both enabled. Only the wz-side offer differs, which is what attributes the
    // delta to that offer rather than to the router.
    let (mut zenohd, port) = spawn_zenohd_lowlatency_compression_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });

    let (demo_captured, received) = publish_through(port, false, publish_key, &publish_value);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // The router still offers lowlatency; wz simply does not ask, so the session
    // is universal. A `true` here would mean the offer is not consulted at all.
    assert!(
        !demo_captured.contains("lowlatency negotiated = true"),
        "wz negotiated the lean transport WITHOUT offering it — the ext must \
         follow the wz-side offer, not the router's willingness.\n--- captured \
         wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        demo_captured.contains("compression negotiated = true"),
        "wz did not negotiate compression against the same router that the \
         composed leg negotiated it with — the twin's premise is broken.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // THE DELTA. Same ext, same router, same payload: the wrap is ACTIVE here and
    // suppressed in the composed leg, and the ONE input that differs is the
    // lowlatency offer. Without this assertion, leg 1's `active = false` could be
    // read as compression being broken in this build.
    assert!(
        demo_captured.contains("batch compression active = true"),
        "the negotiated wrap is not APPLIED on a universal session, so the \
         composed leg's `active = false` is not attributable to the lowlatency \
         offer — the suppression is over-broad.\n--- captured wz-ap-demo stderr \
         ---\n{demo_captured}"
    );

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '>> [Subscriber] Received' within 10s — the \
             lz4-wrapped Put did not route through zenohd, so the composed leg's \
             delivery assertion has no baseline.\n--- captured z_sub stdout at \
             deadline ---\n{c}\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key) && received_text.contains(&publish_value),
        "z_sub received but the twin's keyexpr / value did not arrive \
         intact.\n{received_text}"
    );
}
