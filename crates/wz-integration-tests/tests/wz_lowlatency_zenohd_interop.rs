// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenohd LOWLATENCY transport cross-impl interop (R311y372).
//!
//! `transport-lowlatency` is zenoh's runtime-negotiated LEAN transport: both
//! peers OFFER the Z_EXT_LOWLATENCY unit ext (id 0x05) on InitSyn / InitAck, the
//! `&=` merge agrees, and the established session drops the Frame(sn) wrapper +
//! fragmentation, serializing the bare NetworkMessage directly (zenoh
//! `TransportUnicastLowlatency`). zenoh-pico has NO lowlatency transport at all
//! (no such ext, no lean framing), so the ONLY foreign witness is zenohd — the
//! canonical zenoh-full router — whose `transport/unicast/lowlatency` config
//! (mutually exclusive with `qos`, DEFAULT_CONFIG.json5:541) makes it negotiate
//! and speak the lean wire.
//!
//! The single leg is a DISCRIMINATOR, not a bare liveness check — it asserts two
//! independently load-bearing facts:
//!
//!   1. cross-impl NEGOTIATION of the 0x05 ext. The wz demo, dialed with
//!      `--lowlatency`, logs `lowlatency negotiated = true`. That value is
//!      `set_lowlatency_offer(true) &= peer_offered`, so it is `true` ONLY if
//!      zenohd offered Z_EXT_LOWLATENCY back on its InitAck. A zenohd without the
//!      lowlatency config, or a wz whose ext offer was neutered, yields `false`.
//!
//!   2. cross-impl LEAN-FRAMING interop. A wz `Put` routes through zenohd to a
//!      pico `z_sub`. wz's tx seam is `if is_lowlatency() { lean; return }`, so a
//!      `true` flag FORCES the bare-NetworkMessage wire; zenohd, in lowlatency
//!      transport mode for this link, parses that lean wire and routes the sample
//!      to the (universal-transport) pico subscriber. A Frame on this link — the
//!      pre-lowlatency wire — would not decode as a lowlatency message and the
//!      Put would never arrive.
//!
//! Together they bind to transport-lowlatency's OWN code: neuter the ext offer
//! (`extlowlatency::encode_lowlatency_ext`) and (1) fails; corrupt the lean tx
//! seam so a Frame goes out under a true flag and (2) fails. Both REDs leave the
//! non-lowlatency control (`wz_publish_routes_through_zenohd_to_pico_zsub`,
//! universal) GREEN, so neither is a codec-join-style shared-path false bind.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd + the pico z_sub CLI are external
//! binaries. Serialized with the other zenohd legs (`--test-threads=1`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_subscribed_zsub, spawn_zenohd, spawn_zenohd_lowlatency,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// R2224 (open-debt item 572) — the dial both legs make, so the pair differs in
/// WHICH ZENOHD IT RAN AGAINST and in nothing else.
///
/// Extracted when the calibration twin below was added: two copies of this
/// setup would be two places for the `--lowlatency` flag, the keyexpr and the
/// wait to drift, and a twin whose demo invocation differs from its sibling's
/// is not a control. The compression leg one file over already had the shape.
fn publish_with_lowlatency_through(
    port: u16,
    publish_key: &str,
    publish_value: &str,
) -> (String, Result<String, String>) {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // pico z_sub: a UNIVERSAL client of zenohd, subscribed and ready (retried
    // past any transient one-shot open failure). Its declared subscription is
    // the route zenohd uses to forward wz's Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --lowlatency --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--lowlatency")
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --lowlatency"),
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
#[test]
#[ignore = "binary-dep e2e (zenohd router lowlatency + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_lowlatency_negotiates_and_publishes_through_zenohd_to_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let publish_key = "demo/zenohd-lowlatency";
    let sub_key = "demo/**";
    let publish_value = "hello-lowlatency-via-zenohd";

    // zenohd with the lowlatency unicast transport (+ qos disabled, its
    // prerequisite). wz negotiates the lean wire against it; pico + the readiness
    // probe fall back to universal on their own links.
    let mut zenohd = spawn_zenohd_lowlatency(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(port_res);

    // pico z_sub: a UNIVERSAL client of zenohd, subscribed and ready (retried
    // past any transient one-shot open failure). Its declared subscription is the
    // route zenohd uses to forward wz's Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // wz-ap-demo: a LOWLATENCY client of zenohd that emits a Put burst over the
    // lean (Frame-less) data path once the lowlatency transport is negotiated.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --lowlatency --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--lowlatency")
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd --lowlatency"),
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

    // Assertion 1 — cross-impl NEGOTIATION: `&=` true means zenohd mirrored the
    // Z_EXT_LOWLATENCY ext on its InitAck. Without the router's lowlatency config
    // (or with the ext offer neutered) this reads `false`.
    assert!(
        demo_captured.contains("lowlatency negotiated = true"),
        "wz did not negotiate the lowlatency transport with zenohd (expected \
         'lowlatency negotiated = true' in the demo log). A zenohd without \
         transport/unicast/lowlatency, or a broken ext offer, yields `false`.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        !demo_captured.contains("lowlatency negotiated = false"),
        "wz logged lowlatency negotiated = false — the ext was not mirrored by \
         zenohd.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // Assertion 2 — cross-impl LEAN-FRAMING interop: the lean (bare
    // NetworkMessage) Put routed through the lowlatency-mode zenohd to z_sub.
    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's lean-transport \
             Put did not route through the lowlatency-mode zenohd to z_sub.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
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

// wz-proves: none -- the CALIBRATION twin of the leg above.
//
// R2224 (open-debt item 572). The leg above has asserted `negotiated = true`
// since R311y372 with nothing standing opposite it, so a wz that reported its
// own offer back — never consulting zenohd's InitAck — passed it. The
// compression leg one file over has had its twin since R311y433; this axis had
// the same shape and not the same control, which is the asymmetry the item's
// re-measurement turned up.
//
// A negotiation that correctly does NOT happen proves no atom's cross-impl
// behaviour, which is why this leg claims none.
#[test]
#[ignore = "binary-dep e2e (stock zenohd + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_lowlatency_offer_is_not_negotiated_by_a_stock_zenohd() {
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let publish_key = "demo/zenohd-lowlatency-twin";
    let publish_value = "hello-universal-via-zenohd";

    // A STOCK zenohd: `transport/unicast/lowlatency` is left at its false
    // default (`DEFAULT_CONFIG.json5:545`), so it never offers the 0x05 ext
    // back. wz's dial is byte-identical to the sibling's.
    let mut zenohd = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    drop(port_res);

    let (demo_captured, received) =
        publish_with_lowlatency_through(port, publish_key, publish_value);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // The `&=` merge collapses to false against a peer that did not offer.
    assert!(
        demo_captured.contains("lowlatency negotiated = false"),
        "wz did not report lowlatency negotiated = false against a STOCK \
         zenohd. Either the router now offers the 0x05 ext by default (which \
         would make the sibling leg's assertion untestable) or the `&=` merge \
         no longer consults the peer offer.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        !demo_captured.contains("lowlatency negotiated = true"),
        "wz negotiated the lean transport against a zenohd that was never \
         configured for it.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // And the session is not merely un-negotiated but WORKING: the universal
    // (Frame-wrapped) fallback still delivers, so the sibling's delivery
    // assertion is attributable to the lean path rather than to "wz can publish
    // through zenohd at all".
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '>> [Subscriber] Received' within 10s — the \
             universal fallback failed to route, so the sibling leg's delivery \
             assertion has no baseline.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-ap-demo stderr ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key) && received_text.contains(publish_value),
        "z_sub received but the twin's keyexpr / value did not arrive \
         intact.\n{received_text}"
    );
}
