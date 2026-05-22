// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121g — DECLARE-aliased publisher round-trip integration test.
//!
//! Drives the wz-ap-demo binary in `--publish ... --declare-id N`
//! mode against an external zenoh-pico `z_sub` CLI peer. Exercises
//! the bandwidth-efficient repeated-keyexpr publisher shape:
//!
//!   1. wz emits a `Frame[Declare(DeclKexpr(N, "demo/test"))]` once
//!      after Established.
//!   2. zenoh-pico's `_z_handle_network_message` registers the
//!      mapping `N -> "demo/test"` in its peer-side keyexpr table.
//!   3. wz emits five `Frame[Push(WireexprLocal { id: N, suffix:
//!      None }, MsgPut("hi-r121g"))]`. Each Push carries only the
//!      mapping id on the wire — no per-Push suffix bytes.
//!   4. zenoh-pico's Push receive path resolves the mapping id
//!      via the table populated in step 2, matches the resolved
//!      keyexpr against the subscriber's `demo/**` pattern, and
//!      fires the subscriber callback.
//!   5. The test harness greps z_sub's stdout for the
//!      `>> [Subscriber] Received` witness with the resolved
//!      keyexpr substring.
//!
//! Diff from `wz_publisher_to_zsub.rs` (R121e): the demo is
//! launched with `--declare-id 7`, which routes the publisher
//! through `send_declare_keyexpr` + `send_push_aliased` instead of
//! `send_push_literal`. Both tests subscribe with the same
//! `demo/**` wildcard so the matcher path is shared; the only
//! variable is which wire shape carried the resolved keyexpr.
//!
//! Why this matters: zenoh-pico's DeclKexpr wire shape (header
//! flag layout, wireexpr suffix gating) is a known wz-codec
//! interop hazard surfaced during R121g authoring — the
//! generated codegen's B5-ν derived bit (`0x40` for WireexprLocal)
//! must be suppressed via the `WireexprNonlocal` arm, and the
//! `_Z_DECL_KEXPR_FLAG_N (0x20)` must be author-set since the
//! codec does not auto-derive it from suffix presence. The unit
//! test `build_declare_kexpr_emits_zenoh_pico_compatible_wire_bytes`
//! pins the wire bytes against zenoh-pico's reference; this
//! integration test pins the full round-trip behaviour so a
//! regression on either the codec emit OR the subscriber-side
//! mapping table population surfaces here.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn wz_publisher_aliased_round_trip_against_zenoh_pico_z_sub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // Publisher emits on "demo/test"; the DECLARE registers mapping
    // id 7 to that literal. z_sub subscribes to "demo/**" so the
    // resolved keyexpr satisfies the wildcard matcher.
    let publish_key = "demo/test";
    let sub_pattern = "demo/**";
    let publish_value = "hi-r121g-aliased";
    let mapping_id = "7";

    // ── wz-ap-demo (acceptor + DECLARE-aliased publisher) ───
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = Command::new(&demo)
        .arg("--listen")
        .arg(&listen_addr)
        .arg("--publish")
        .arg(publish_key)
        .arg("--value")
        .arg(publish_value)
        .arg("--declare-id")
        .arg(mapping_id)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(demo_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --listen + --declare-id");

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.kill();
        let _ = demo_child.wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }
    // R216 — bind confirmed, release the port-alloc mutex.
    drop(port_res);

    // ── z_sub (client + subscriber) ──────────────────────────
    // `stdbuf -oL` line-buffers stdout so the "Received" witness
    // surfaces in near-real-time. printf-to-pipe is block-buffered
    // by default on glibc; see `wz_publisher_to_zsub.rs` for the
    // same gotcha.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_sub)
        .args(["-k", sub_pattern, "-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(z_sub_stdout_writer))
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn z_sub via stdbuf");

    let session_opening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Opening session",
        Duration::from_secs(5),
    );
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = z_sub_child.kill();
    let _ = z_sub_child.wait();
    let _ = demo_child.kill();
    let _ = demo_child.wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    if let Err(c) = &session_opening {
        panic!(
            "z_sub did not log 'Opening session' within 5s — z_sub binary failed to \
             initialize. Captured z_sub stdout:\n{c}\n\
             --- captured demo stderr ---\n{demo_captured}"
        );
    }

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz-ap-demo aliased Push did not \
             reach z_sub's subscriber callback. Likely causes: (1) DeclKexpr wire-shape \
             regression (z_sub's `_z_register_resource` didn't populate the table); \
             (2) aliased Push N-flag regression (z_sub treats the suffix bytes as the \
             next message header); (3) keyexpr table id miss (publisher sent id != \
             {mapping_id}).\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured demo stderr at deadline ---\n{demo_captured}"
        ),
    };

    // Belt-and-suspenders: the resolved keyexpr in z_sub's
    // "Received" line must be the literal "demo/test" (NOT the
    // mapping id token "7" or an empty string), proving the
    // mapping table populated correctly AND the aliased Push
    // resolved via that table.
    assert!(
        received_text.contains(publish_key),
        "z_sub captured 'Received' but the resolved keyexpr '{publish_key}' is missing — \
         table population or aliased-Push resolution regressed.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub captured 'Received' but the publish value '{publish_value}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    // Also assert the wz-ap-demo emit log line shows the DECLARE
    // fired (proves the `--declare-id` opt-in landed; without it
    // the test would silently fall back to the literal-keyexpr
    // path and still pass the substring gates above).
    assert!(
        demo_captured.contains("PUBLISHER DECLARED"),
        "wz-ap-demo did not log 'PUBLISHER DECLARED' — `--declare-id` opt-in regressed.\n\
         --- captured demo stderr ---\n{demo_captured}"
    );
    // R247 — R235 wz-ap-demo Session API migration restructured the
    // PUBLISHER EMITTED log line into a key=value form that names the
    // dispatch mode explicitly (`mode=aliased` vs `mode=literal`).
    // The prior `PUBLISHER EMITTED ALIASED` token assertion was a
    // pre-R235 literal that R235-hotfix masked with `#[ignore]`
    // rather than fixed; this round retires the stale token in
    // favour of the structured `mode=aliased` form which still pins
    // the aliased-dispatch invariant (a regression into the literal
    // mode would emit `mode=literal` and visibly fail this check).
    assert!(
        demo_captured.contains("mode=aliased"),
        "wz-ap-demo did not log 'mode=aliased' on PUBLISHER EMITTED — aliased Push \
         burst regressed or fell back to literal mode.\n\
         --- captured demo stderr ---\n{demo_captured}"
    );
}
