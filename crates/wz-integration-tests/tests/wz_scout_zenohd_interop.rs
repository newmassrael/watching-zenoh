// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenohd ACTIVE MULTICAST SCOUTING cross-impl interop (R311y428).
//!
//! `scouting-active` is the DISCOVERY MODE: emit a Scout on the zenoh scouting
//! group and open a session against whatever a peer's Hello advertises, instead
//! of being told an endpoint. `scouting-multicast` is the transport underneath
//! it (the `224.0.0.224:7446` group join, FOUNDATIONAL — "always-on under
//! scouting-active"). Both were unproven cross-impl until this leg, and NOT for
//! want of a foreign counterparty: zenohd answers scouts in its default config.
//! The demo simply had no way to be told to scout (R311y423 measured it:
//! `grep -rn scout crates/wz-ap-demo/src/args.rs` returned one prose comment and
//! no flag), so the mode could not be driven end to end. `--scout` is that
//! entrypoint and this is its witness.
//!
//! WHY THE ASSERTION IS THE PORT. zenohd binds `tcp/127.0.0.1:0` — the KERNEL
//! picks the port, and this test learns it by reading zenohd's own announcement.
//! The wz demo is never told it: its argv carries `--scout` and no locator at
//! all. So a demo log line naming that exact port can only have come from
//! decoding the Hello zenohd sent back, which makes the equality a DISCRIMINATOR
//! rather than a liveness check — a `--scout` that parsed its flag, or that
//! defaulted to some built-in endpoint, cannot produce a number it was never
//! given. That is the shape R311y423 records as missing when it built
//! `gossip_dialed`: a flag is not a witness.
//!
//! Three assertions, each load-bearing:
//!
//!   1. `scouted peer locator tcp/127.0.0.1:<zenohd port>` — wz DECODED zenohd's
//!      Hello (the `zenohd->wz` direction). The line is printed only from
//!      `ScoutOutcome::Discovered`, whose sole producer is
//!      `record_hello_and_emit` extracting a locator from a decoded Hello.
//!   2. `record_hello=1` in that same line — the FSM's own action dispatch
//!      counter, so the claim binds to `scouting.scxml`'s actions and not merely
//!      to a string the runner could have assembled some other way.
//!   3. `session Established` on the discovered locator — zenohd decoded wz's
//!      Scout (the `wz->zenohd` direction; it answers only after
//!      `what.matches(self.whatami())`, zenoh orchestrator.rs:1155) AND the
//!      locator it advertised is real enough to complete a zenoh handshake on.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): zenohd is an external binary and the
//! scouting group is a real multicast socket. Layer M is the lane for exactly
//! that pair, and it has been hosted with a measured IGMP join since R311y421.
//! Needs the demo built `--features scouting-active` (that lane builds it).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_multicast_scouting_on_ephemeral_tcp, wait_for_substring,
    wz_ap_demo_binary, ChildGuard,
};

// wz-proves: scouting-active wz->zenohd
// wz-proves: scouting-active zenohd->wz
// wz-proves: scouting-multicast wz->zenohd
// wz-proves: scouting-multicast zenohd->wz
//
// BOTH directions are claimed because both are asserted, on the one Scout/Hello
// exchange the group carries: zenohd consumed wz's Scout (it replies only to a
// Scout it decoded whose `what` matches its whatami) and wz consumed zenohd's
// Hello (the port equality below is that decode's output). Neither claim rests
// on the other's leg.
#[test]
#[ignore = "binary-dep + multicast e2e (zenohd multicast-scouting router); run via Layer M / --ignored"]
fn wz_scout_discovers_zenohd_over_multicast_and_opens_the_advertised_locator() {
    let demo = wz_ap_demo_binary();

    // A zenohd with its DEFAULT multicast scouting responder. The returned port
    // is the one the kernel gave it, read back from zenohd's own announcement;
    // the spawn also gates on zenohd's scout-listener line, so the group socket
    // is bound and joined before wz emits anything (zenoh binds unicast
    // listeners first — a scout into that window would be lost, and nothing
    // retransmits a Scout).
    let (mut zenohd, zenohd_port) =
        spawn_zenohd_multicast_scouting_on_ephemeral_tcp("zenohd (multicast-scouting router)");
    let expected_locator = format!("tcp/127.0.0.1:{zenohd_port}");

    // wz-ap-demo in `--scout` mode. NOTE what is absent: no --connect, no
    // address of any kind. The only endpoint this process can reach is one a
    // peer tells it about.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--scout)",
        Command::new(&demo)
            .arg("--scout")
            .arg("--publish")
            .arg("demo/scouted")
            .arg("--value")
            .arg("hello-from-a-scouted-session")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --scout"),
    );

    // The Established line is the LAST of the three witnesses to appear, so
    // waiting on it also bounds the two before it. The budget covers the demo's
    // own 10s scouting budget plus the handshake.
    let established_substr = "session Established";
    let established = wait_for_substring(
        &mut demo_stderr_reader,
        established_substr,
        Duration::from_secs(20),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");

    // Assertion 1 — wz decoded zenohd's Hello and pulled THIS locator out of it.
    // The port was chosen by the kernel and never passed to the demo, so no
    // build that merely parsed `--scout` can print it.
    let scouted_line = demo_captured
        .lines()
        .find(|l| l.contains("scouted peer locator"))
        .unwrap_or_else(|| {
            panic!(
                "wz-ap-demo logged no 'scouted peer locator' line — the Scout got no \
                 Hello back from the multicast-scouting zenohd on 224.0.0.224:7446.\n\
                 --- captured wz-ap-demo stderr ---\n{demo_captured}"
            )
        });
    assert!(
        scouted_line.contains(&expected_locator),
        "wz scouted a locator that is not zenohd's announced listener.\n\
         expected: {expected_locator}\n\
         line:     {scouted_line}\n\
         A mismatch here means the Hello was decoded into the wrong endpoint (or \
         another zenoh peer on this host answered first).\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );

    // Assertion 2 — the FSM's own dispatch counter. Binds the claim to
    // `record_hello_and_emit` (scouting.scxml's hello.received action), not just
    // to the presence of a locator string.
    assert!(
        scouted_line.contains("record_hello=1"),
        "the scouted line does not report exactly one recorded Hello, so the \
         locator did not come from one decoded Hello dispatch.\nline: {scouted_line}"
    );

    // Assertion 3 — the discovered locator carried a real session. This is also
    // the `wz->zenohd` leg: zenohd answers a Scout only after decoding it and
    // matching its `what` mask, and it then accepted the handshake on the
    // endpoint it had advertised.
    established.unwrap_or_else(|c| {
        panic!(
            "wz-ap-demo did not log '{established_substr}' within 20s — the SCOUTED \
             locator {expected_locator} did not carry a session to zenohd.\n\
             --- captured wz-ap-demo stderr at deadline ---\n{c}"
        )
    });
    assert!(
        demo_captured.contains(&format!("connected to {expected_locator}")),
        "wz established, but not against the scouted locator {expected_locator}.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
}
