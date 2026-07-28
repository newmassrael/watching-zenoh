// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenohd per-batch lz4 COMPRESSION cross-impl interop (R311y433).
//!
//! `transport-compression` + `session-extcompression` are zenoh's runtime-
//! negotiated batch compression: both peers OFFER the Z_EXT_COMPRESSION unit ext
//! (id 0x6) on InitSyn / InitAck, the `&=` merge agrees, and from then on every
//! post-establishment batch is a 1-byte `BatchHeader` followed by an lz4 block —
//! kept compressed only when that is SMALLER than the original, so incompressible
//! data ships raw with the bit clear and never grows (zenoh
//! `zenoh-transport-1.5.0` `common/batch.rs:324-352` compress,
//! `:465-500` decompress).
//!
//! zenoh-pico has NO compression at all (no such ext, no batch header), so the
//! ONLY foreign witness is zenohd — the canonical zenoh-full router — whose
//! `transport/unicast/compression/enabled` config makes it negotiate and speak
//! the wrapped wire. It needs no special build: `transport_compression` rides
//! zenoh's DEFAULT cargo feature set (`zenoh-1.5.0/Cargo.toml`), unlike the
//! unixpipe / vsock oracles which needed variant zenohd binaries.
//!
//! Until this round the byte-compatibility claim was PROSE:
//! `wz-session-core/src/compression.rs:27-30` said "the lz4 codec is the SAME
//! crate zenoh uses … so a future wz<->zenohd cross-impl session that negotiates
//! compression is byte-compatible". Layer A4 counted both atoms UNPROVEN, and
//! the behavioural lane C1ae is wz<->wz only. These legs are that claim's first
//! foreign witness.
//!
//! ## What the payload size is doing here
//!
//! The publish value is a long REPETITIVE string, and that is load-bearing
//! rather than cosmetic. `compress_batch` keeps the compressed form only when
//! `n < payload.len()`, so a SHORT value ships with the COMPRESSION bit CLEAR:
//! the batch then witnesses the 1-byte header framing and nothing about lz4.
//! Measured during authoring: a 20-byte value routes through a compression-
//! enabled zenohd exactly as a raw batch would, which is precisely the case that
//! would let a broken compressor pass. The ~536-byte repetitive value here
//! compresses by more than an order of magnitude, so `compress_batch` provably
//! sets the bit (the unit twin
//! `compression::tests::compressible_payload_round_trips_with_the_bit_set` pins
//! that property), and delivery therefore requires zenohd's lz4 DECOMPRESS path.
//!
//! It is also deliberately far below the fixture's large-payload ceiling. A
//! 4121-byte value does NOT reach the pico subscriber through this
//! wz -> zenohd -> pico chain — but the control run (same value, same zenohd, no
//! `--compression`) does not reach it either, so that ceiling is independent of
//! compression and is NOT this slice's subject. Sizing the value at ~536 bytes
//! keeps the leg inside the routable range with margin, so a future failure here
//! reads as a compression regression rather than as that unrelated limit.
//!
//! ## The two legs
//!
//!   1. the PROOF. wz dials with `--compression`, logs `compression negotiated =
//!      true` (that value is `set_compression_offer(true) &= peer_offered`, so it
//!      is `true` only because zenohd mirrored the 0x6 ext on its InitAck), and a
//!      compressible `Put` routes through zenohd to a pico `z_sub` byte-exact.
//!   2. the TWIN. The SAME wz dial against a STOCK zenohd (compression not
//!      configured; the knob defaults to false, `zenoh-config-1.5.0`
//!      `src/defaults.rs:241-245`) logs `compression negotiated = false` and the
//!      Put still arrives over the un-wrapped wire. This is what makes leg 1's
//!      negotiation assertion a discriminator instead of a tautology: the flag
//!      tracks the ROUTER's config, so it cannot be a hardcoded `true`.
//!
//! Together they bind to compression's OWN code: neuter the ext offer
//! (`extcompression::encode_compression_ext`) and leg 1's assertion 1 fails while
//! the twin stays green; corrupt `compress_batch`'s wire (wrong header bit, wrong
//! lz4 framing) and leg 1's assertion 2 fails while the twin — which never
//! reaches `compress_batch`, the `is_compression()` gate being false — stays
//! green. Neither RED touches the non-compression control
//! (`wz_publish_routes_through_zenohd_to_pico_zsub`).
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd + the pico z_sub CLI are external
//! binaries. Serialized with the other zenohd legs (`--test-threads=1`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_subscribed_zsub, spawn_zenohd_compression_on_ephemeral_tcp,
    spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    ChildGuard,
};

/// A value lz4 shrinks by more than an order of magnitude, so `compress_batch`
/// keeps the compressed form and the COMPRESSION bit goes out SET. Long enough to
/// compress, short enough to stay well inside the fixture's routable range (see
/// the module docs).
fn compressible_value(tag: &str) -> String {
    format!("{tag}-{}", "COMPRESSIBLE-BATCH-".repeat(28))
}

/// Drive `wz-ap-demo --connect <port> --compression --publish <key>` and return
/// (demo stderr capture, the z_sub stdout capture at the deadline or on success).
/// Shared by both legs so the ONLY difference between them is which zenohd the
/// port belongs to — the twin is a twin by construction, not by parallel
/// maintenance of two copies.
fn publish_with_compression_through(
    port: u16,
    publish_key: &str,
    publish_value: &str,
) -> (String, Result<String, String>) {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // pico z_sub: a client of zenohd, subscribed and ready (retried past any
    // transient one-shot open failure). pico speaks NO compression, so its own
    // link is un-wrapped whatever zenohd negotiated with wz — which is the point:
    // zenohd must decompress wz's batch to route it here at all.
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
        "wz-ap-demo (--connect zenohd --compression --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
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

// wz-proves: transport-compression wz->zenohd
// wz-proves: session-extcompression wz->zenohd
#[test]
#[ignore = "binary-dep e2e (zenohd router compression + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_compression_negotiates_and_publishes_lz4_batches_through_zenohd_to_pico_zsub() {
    let publish_key = "demo/zenohd-compression";
    let publish_value = compressible_value("hello-lz4-via-zenohd");

    // zenohd with `transport/unicast/compression/enabled:true`. wz negotiates the
    // wrapped wire against it; pico and the readiness probe never offer the ext,
    // so their own links stay un-wrapped.
    let (mut zenohd, port) = spawn_zenohd_compression_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });

    let (demo_captured, received) =
        publish_with_compression_through(port, publish_key, &publish_value);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // Assertion 1 — cross-impl NEGOTIATION: `&=` true means zenohd mirrored the
    // Z_EXT_COMPRESSION ext on its InitAck. The twin leg below runs the identical
    // dial against a stock zenohd and reads `false`, which is what forbids reading
    // this as a hardcoded constant.
    assert!(
        demo_captured.contains("compression negotiated = true"),
        "wz did not negotiate compression with zenohd (expected 'compression \
         negotiated = true' in the demo log). A zenohd without \
         transport/unicast/compression/enabled, or a broken ext offer, yields \
         `false`.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        !demo_captured.contains("compression negotiated = false"),
        "wz logged compression negotiated = false — the 0x6 ext was not mirrored \
         by zenohd.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // Assertion 2 — cross-impl lz4 BATCH interop: with the flag true, wz's tx seam
    // (`emit_on_link` -> `compress_batch`) wraps every batch, and this payload is
    // compressible enough that the COMPRESSION bit is set rather than cleared. So
    // the sample reaching a pico subscriber on the far side of zenohd means zenohd
    // ran its own lz4 decompress over wz-produced bytes.
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '>> [Subscriber] Received' within 10s — wz's \
             lz4-wrapped Put did not route through the compression-mode zenohd to \
             z_sub.\n--- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-ap-demo stderr ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key),
        "z_sub received but the publish keyexpr '{publish_key}' is missing.\n{received_text}"
    );
    // Byte-exactness through the lz4 round trip: the WHOLE value, not a prefix, so
    // a truncating decompress bound would fail here rather than pass.
    assert!(
        received_text.contains(&publish_value),
        "z_sub received but the {}-byte compressible value did not arrive intact \
         through the lz4 round trip.\n{received_text}",
        publish_value.len()
    );
}

// wz-proves: none -- the CALIBRATION twin of the leg above. It witnesses that wz's
// compression offer is NOT negotiated by a router that does not offer it back, which
// is what makes the sibling's `negotiated = true` a discriminator; a negotiation
// that correctly does not happen proves no atom's cross-impl behaviour.
#[test]
#[ignore = "binary-dep e2e (stock zenohd + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_compression_offer_is_not_negotiated_by_a_stock_zenohd() {
    let publish_key = "demo/zenohd-compression-twin";
    let publish_value = compressible_value("hello-uncompressed-via-zenohd");

    // A STOCK zenohd: `transport/unicast/compression/enabled` is left at its false
    // default, so it drops the non-mandatory 0x6 ext and never offers it back.
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });

    let (demo_captured, received) =
        publish_with_compression_through(port, publish_key, &publish_value);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // The `&=` merge collapses to false against a peer that did not offer.
    assert!(
        demo_captured.contains("compression negotiated = false"),
        "wz did not report compression negotiated = false against a STOCK zenohd. \
         Either the router now offers the 0x6 ext by default (which would make the \
         sibling leg's assertion untestable) or the `&=` merge no longer consults \
         the peer offer.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    assert!(
        !demo_captured.contains("compression negotiated = true"),
        "wz negotiated compression against a zenohd that was never configured for \
         it.\n--- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // And the session is not merely un-negotiated but WORKING: the un-wrapped
    // fallback still delivers, so leg 1's delivery assertion is attributable to
    // compression rather than to "wz can publish through zenohd at all".
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '>> [Subscriber] Received' within 10s — the \
             un-negotiated (raw) fallback failed to route, so the sibling leg's \
             delivery assertion has no baseline.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-ap-demo stderr ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key) && received_text.contains(&publish_value),
        "z_sub received but the twin's keyexpr / value did not arrive \
         intact.\n{received_text}"
    );
}
