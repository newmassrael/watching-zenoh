// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y451 — FOREIGN-INTEROP LOW-PASS ATTACHMENT ACCOUNTING (§5.16
//! `access-quota`): a real zenoh-pico `z_pub_attachment` CLI publishes a Put
//! whose PAYLOAD ALONE fits a watching-zenoh peer's `--max-payload` budget, and
//! the peer's low-pass interceptor drops it anyway — because zenoh budgets
//! `payload + attachment` (`net/routing/interceptor/low_pass.rs:358-361`) and
//! the attachment pushes it over.
//!
//! ## Why this fixture and not a bigger payload
//!
//! A Put that is simply too large proves nothing this atom did not already have:
//! the pre-R311y451 code sized the payload and dropped it. The gap was the
//! ATTACHMENT half, so the discriminating message is one the OLD code admits and
//! the NEW code drops. The budget is therefore calibrated to the payload
//! EXACTLY: [`LIMIT`] is the byte length of what pico's publisher emits, so
//!
//! - payload-only accounting  → `14 <= 14`      → ADMIT (the pre-y451 verdict)
//! - payload+attachment       → `14 + A > 14`   → DROP  (the zenoh verdict)
//!
//! and the leg holds for ANY attachment size `A >= 1`. That is deliberate: the
//! exact serialized size of pico's `ze_serializer` kv attachment is not asserted
//! anywhere, so the proof does not rest on a number that an upstream example
//! tweak could shift. It rests on the attachment being non-empty, which
//! `z_pub_attachment` guarantees by construction.
//!
//! ## Why a positive control is in the SAME leg
//!
//! "The subscriber received nothing" is satisfiable by a dead session, a wrong
//! port, or a pico build without the publisher feature. So one leg drives BOTH
//! against the SAME peer instance: a plain `z_put` under the budget is ADMITTED
//! (the session, the route and the interceptor's admit path all work), and the
//! attachment Put is DROPPED. The witness is the wz peer's own counters
//! (`received mesh data` / `interceptor dropped`) plus the graceful-shutdown
//! summary, the same instrumentation `wz_peer_acl_pico_interop` uses.
//!
//! RED (the proof binds to the low-pass code, not to routing): with the size
//! budget counting the payload alone — the shape this round replaced — the
//! attachment Put is admitted as a SECOND data push, so the `interceptor
//! dropped` barrier times out and the exact-count assertions fail.
//!
//! pico is the ENCODER on the wire: its C stack builds the Put, the `0x03`
//! push-body attachment ext and the kv serialization; wz decodes the ext chain
//! and adjudicates. Requires the binary built with `--features routing-peer`
//! (which pulls `access-quota`); Layer E6 builds `routing-peer,adminspace-write`.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// The value pico's `z_pub_attachment` is driven with.
const ATT_VALUE: &str = "att-put";

/// What `z_pub_attachment` prepends to that value: `sprintf(buf, "[%4d] %s",
/// idx, value)` at `vendor/zenoh-pico/examples/unix/c11/z_pub_attachment.c:99`,
/// with `idx == 0` on the single `-n 1` iteration. Seven bytes.
const PICO_PUB_PREFIX: &str = "[   0] ";

/// The peer's `--max-payload` budget, calibrated to EXACTLY the payload pico
/// emits. See the module note: this is what makes the leg discriminate the
/// attachment accounting rather than mere payload size.
const LIMIT: usize = PICO_PUB_PREFIX.len() + ATT_VALUE.len();

/// A control payload comfortably inside the budget.
const CONTROL_VALUE: &str = "ctl";

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Mirrors `wz_peer_acl_pico_interop`'s
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

/// Drive one of pico's one-shot publisher CLIs at the wz peer's tcp listener and
/// block until it exits. `extra` carries the per-CLI flags (`z_pub_attachment`
/// needs `-n 1` so it publishes exactly once instead of forever).
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

/// leg (R311y451) — a pico Put whose payload FITS the wz peer's low-pass budget
/// is still dropped once its ATTACHMENT is counted, while a plain Put under the
/// budget is admitted. pico is the encoder; the wz peer's §5.16 low-pass
/// interceptor is the adjudicator.
// wz-proves: access-quota pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_put/z_pub_attachment CLIs); Layer E6 runs via --ignored"]
fn wz_peer_low_pass_counts_a_pico_attachment_toward_the_budget() {
    let limit = LIMIT.to_string();
    let (mut peer_guard, mut peer_reader, port) = spawn_peer(
        "low-pass-peer",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "**",
            "--max-payload",
            &limit,
        ],
    );
    let addr = format!("127.0.0.1:{port}");

    // Positive control: a plain Put well inside the budget must be ADMITTED, so a
    // later NON-arrival is the size budget and not a dead session.
    pico_publish("z_put", "demo/ctl", CONTROL_VALUE, &addr, &[]);
    let admitted = wait_for_substring(
        &mut peer_reader,
        "received mesh data",
        Duration::from_secs(15),
    );

    // The atom: a Put whose PAYLOAD alone exactly fills the budget, plus a
    // non-empty attachment. Payload-only accounting admits it; zenoh's
    // payload+attachment accounting drops it.
    pico_publish(
        "z_pub_attachment",
        "demo/att",
        ATT_VALUE,
        &addr,
        &["-n", "1"],
    );
    let dropped = wait_for_substring(
        &mut peer_reader,
        "interceptor dropped",
        Duration::from_secs(15),
    );

    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut peer_reader);
    eprintln!("--- low-pass-peer stderr ---\n{captured}");

    if let Err(c) = &admitted {
        panic!(
            "wz peer never admitted the under-budget control put within 15s — the \
             peer/session/route is broken, not the low-pass filter.\n\
             --- low-pass-peer stderr at deadline ---\n{c}"
        );
    }
    if let Err(c) = &dropped {
        panic!(
            "wz peer never logged 'interceptor dropped' for the pico attachment put \
             within 15s. Its payload is exactly {LIMIT}B — the budget — so it is \
             admitted by payload-only accounting; the §5.16 low-pass did not count \
             the attachment bytes.\n--- low-pass-peer stderr at deadline ---\n{c}"
        );
    }
    // Exactly the one attachment Put was dropped ...
    assert!(
        captured.contains("interceptor dropped (1 message(s))"),
        "expected the low-pass to drop exactly 1 message (the attachment put).\n\
         --- low-pass-peer stderr ---\n{captured}"
    );
    // ... exactly the one control Put was admitted ...
    assert!(
        captured.contains("1 data push(es) received"),
        "expected exactly 1 admitted data push (the under-budget control put).\n\
         --- low-pass-peer stderr ---\n{captured}"
    );
    // ... and the attachment Put did NOT slip past to become a 2nd admitted push,
    // which is exactly what payload-only accounting produced.
    assert!(
        !captured.contains("2 data push(es) received"),
        "the pico attachment put leaked past the §5.16 low-pass and was admitted as \
         a 2nd data push — its attachment bytes were not counted toward the {LIMIT}B \
         budget.\n--- low-pass-peer stderr ---\n{captured}"
    );
}
