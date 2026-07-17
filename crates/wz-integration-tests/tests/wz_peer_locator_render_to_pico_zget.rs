// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y348 — `locator-tcp`, witnessed by a real zenoh-pico peer.
//!
//! ## The design fork this test ANSWERS, by measurement
//!
//! R311y345 raised, and did not answer, whether the 8 `locator-*` atoms belong in
//! the cross-impl denominator at all, on the premise that "a locator string is
//! LOCAL configuration a foreign peer never sees". R311y348 nearly excluded all
//! eight on that premise, with an argument built on their own reasons ("the parse
//! is always-on; the toggle is the vehicle") and on the cargo shape they share
//! with `link-batching`, which IS excluded as a category-(2) alias.
//!
//! The premise is FALSE, and one run of this fixture is what showed it. wz PUTS
//! its locators on the wire — `@/<zid>/peer` renders
//! `{"locators":["tcp/127.0.0.1:<port>"], ...}` — and a real pico `z_get` decodes
//! them. So the 8 are foreign-OBSERVABLE, they stay in the denominator, and the
//! exclusion would have been wrong. Reading the reasons could not have settled
//! that; the reasons are what made the wrong answer look sound.
//!
//! ## What makes pico the witness, and what the bare `--peer` argv buys
//!
//! The demo is handed a locator with NO scheme (`127.0.0.1:<port>`), and what pico
//! reads back carries one (`tcp/127.0.0.1:<port>`). So the `tcp/` cannot have been
//! echoed out of argv — wz's locator layer PARSED the bare form, canonicalised it,
//! and rendered it into the admin payload that crossed the wire. That round trip
//! is the atom, and pico decoding the JSON is the foreign half of it.
//!
//! Measured both ways before this test was written: argv `127.0.0.1:P` -> pico sees
//! `tcp/127.0.0.1:P`; argv `tcp/127.0.0.1:P` -> pico sees the same canonical form.
//! The bare arm is the one asserted here precisely because it is the arm where an
//! echo is impossible.
//!
//! ## Why this claims `locator-tcp` and not the adminspace
//!
//! The admin handler is the CARRIER; `tcp/…` is the cargo. Flip the carrier off and
//! nothing renders — but the string's SHAPE is not the handler's: the handler
//! serialises whatever the locator layer hands it, and the scheme+canonical form
//! is `locator.rs`'s. The honest boundary is that this test proves the RENDER half
//! of the atom (wz emits a canonical `tcp/` locator a foreign peer accepts as such)
//! and not the DIAL half; the dial half belongs to `transport-link-tcp`, which the
//! pico interop corpus already exercises.
//!
//! `locator-tcp` is `reserved` + FOUNDATIONAL with cfg=0 — the parse is always
//! compiled — so there is no cfg site for the claim to be contained in, and A4's
//! containment invariant applies to `active` atoms only. That is not a licence:
//! it means the binding here is by ARTIFACT (the rendered string) rather than by
//! gate, and the assertion is written on the artifact for that reason.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
    Z_SUB_INIT_TIMEOUT,
};

// The `wz_peer_` prefix on BOTH the file and the fn is load-bearing, not cosmetic:
// Layer E's sweep filters by test NAME (`--skip wz_peer`), and it builds wz-ap-demo
// with DEFAULT features -- which reject `--peer`. Named anything else, this test is
// swept into Layer E, run against a demo that cannot serve it, and fails there.
// R311y350 learned that from the pre-push gate.
//
// This block sits ABOVE `#[test]` and not between it and `#[ignore]`, which is where
// R311y350 first put it: Layer C0 requires the two attributes be ADJACENT, and an
// insertion that reads harmlessly is exactly how an attribute gets stranded.
//
// wz-proves: locator-tcp wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-introspection-handlers + zenoh-pico z_get CLI); Layer E6b runs via --ignored"]
fn wz_peer_locator_render_decoded_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    // NO scheme. This is the whole anti-echo argument: whatever `tcp/` pico reads
    // back was put there by wz's locator layer, not copied from this string.
    let bare_addr = format!("127.0.0.1:{port}");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo peer (--peer <bare addr> --config-queryable)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&bare_addr)
            .arg("--config-queryable")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let ready = wait_for_substring(
        &mut demo_stderr_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    if let Err(captured) = &ready {
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        panic!(
            "wz-ap-demo never registered its admin host within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }
    drop(port_res);

    let z_get_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let z_get_stdout_writer = z_get_stdout.try_clone().expect("dup z_get stdout handle");
    let mut z_get_stdout_reader = z_get_stdout;

    let mut z_get_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args([
                "-k",
                "@/**",
                "-e",
                &format!("tcp/{bare_addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(z_get_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    // The assertion is the CANONICAL string, port and all: a substring like "tcp/"
    // would pass on the `-e tcp/...` endpoint echo in z_get's own banner, and a bare
    // "locators" would pass on an empty list. This form can only come from wz having
    // parsed the bare addr and rendered it back.
    let rendered = format!("\"locators\":[\"tcp/127.0.0.1:{port}\"]");
    if let Err(captured) =
        wait_for_substring(&mut z_get_stdout_reader, &rendered, Z_SUB_INIT_TIMEOUT)
    {
        let _ = demo_child.child_mut().kill();
        let _ = z_get_child.child_mut().kill();
        panic!(
            "pico's z_get never decoded wz's canonical tcp locator. Expected \
             {rendered} in the @/<zid>/peer payload -- wz was given the BARE \
             '{bare_addr}', so the scheme must come from its locator layer.\n\
             --- captured z_get stdout ---\n{captured}"
        );
    }

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
}
