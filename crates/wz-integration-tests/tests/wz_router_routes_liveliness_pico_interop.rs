// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y803 — the `routing-routes` STAR router carrying liveliness between two
//! real zenoh-pico processes, and retracting a token whose holder it watched die.
//!
//! ## Why this file exists next to the router-hat one
//!
//! `wz_router_hat_liveliness_history_pico_interop.rs` witnesses the SAME
//! observable on a different substrate: `--router-hat` builds a
//! `RouterForwarder` whose token plane is the `routing-token-tables` atom.
//! `--router` builds a `RoutingForwarder` over `RouteTable`
//! (`wz-session-core/src/routing.rs`), which until this round recorded no token
//! at all — `record_declare` matched only the keyexpr and subscriber arms, and a
//! `DeclToken` fell through to `_ => false`. So a liveliness subscriber behind a
//! wz `--router` read an EMPTY world however many holders shared that router,
//! and a holder that dropped left its token alive forever.
//!
//! Two atoms named that hole and both are graded here: `liveliness-subscriber`
//! ("the RouteTable does not route the token plane at all ... a dropped face
//! leaves its tokens permanently alive, where zenoh's close_face drains and
//! undeclares them") and `routing-routes` ("no liveliness-token routing").
//! Reading each substrate's own code rather than the shared clause is what
//! separated them: the router-hat plane was already built.
//!
//! ## Why the token plane belongs here at all, when the QUERY plane does not
//!
//! R311y802 retired a residual that read as this one's twin — "RouteTable can
//! DUMP only subscribers" — because `observe` dispatches `Declare`, `Push` and
//! `Interest` and NOTHING else (`routing.rs:397-405`), so a queryable advertised
//! from there would invite a `Request` no arm could answer. The liveliness plane
//! survives that same test rather than escaping it: a `DeclareToken` IS the
//! delivery, an `UndeclareToken` IS the retraction, and a TOKENS `Interest` is
//! the ask — all three are message kinds this table already dispatches.
//!
//! ## The three arms, and what each one alone would fail to say
//!
//! - [`wz_router_carries_a_pico_token_and_retracts_it_when_the_holder_dies`] —
//!   the subscriber joins FIRST (`-h` omitted, so FUTURE-only), then the token
//!   appears, then its holder is KILLED. The rise proves propagation; the fall
//!   proves the retraction the ROUTER synthesises. R311y802 measured why the
//!   fall needs its own assertion: a witness that asserts only the rise is
//!   satisfied by any implementation that LATCHES.
//! - [`wz_router_replays_a_pre_existing_pico_token_to_a_history_subscriber`] —
//!   the reverse ordering with `-h` ON, which is the CURRENT dump instead. The
//!   sibling file `wz_router_terminates_a_pico_liveliness_get.rs` deliberately
//!   holds NO token so that its claim is about the terminator; this is the arm
//!   it declines to be.
//! - [`wz_router_without_history_replays_nothing`] — the same fixture with `-h`
//!   removed, which is what binds the arm above to the CURRENT bit rather than
//!   to the token merely existing.
//!
//! ## Why the kill, specifically
//!
//! `z_liveliness` undeclares its own token on SIGINT (it prints "Undeclaring
//! liveliness token..." and sends the retraction itself), so terminating it
//! gracefully would witness the PEER's retraction — an arm the propagation test
//! already covers. SIGKILL makes pico say nothing at all, so the only thing that
//! can produce the `Dropped token` line is wz's own face-down path
//! (`RouteTable::remove_face`), which is the arm under test.
//!
//! ## Build variant — this lane must OWN it
//!
//! Requires `--features routing-router,routing-routes`. `--router` alone
//! installs `NoOpForwarder` and holds faces without forwarding anything, so a
//! run against that binary would look identical and prove nothing.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, listen_port, read_captured,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The literal the holder declares, and the exact string every assertion below
/// requires. The subscriber's filter is a WILDCARD, so a line naming THIS token
/// is a real intersect against a real declaration and never an echo of the ask.
const PICO_TOKEN: &str = "group1/pico-token";
const SUB_FILTER: &str = "group1/**";

/// How long a positive arm waits for its line.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the negative twin waits before concluding nothing came. Anchored to
/// the positive bound rather than picked: the twin must not pass merely by being
/// asked sooner than its sibling was.
const NO_SAMPLE_WINDOW: Duration = Duration::from_secs(8);

/// Spawn `wz-ap-demo --router` on an ephemeral port and read the bound port back
/// out of its own banner.
fn spawn_star_router() -> (ChildGuard, File, u16) {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let writer = stderr.try_clone().expect("dup router stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        "routing-routes star router".to_string(),
        Command::new(&demo)
            .args(["--router", "127.0.0.1:0"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo --router"),
    );
    let captured = wait_for_substring(
        &mut reader,
        "router: listening on 127.0.0.1:",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "wz-ap-demo did not bind a router listener within 10s (is the binary \
             built with --features routing-router,routing-routes?)\n\
             --- router stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Spawn the pico token holder and return only once the token EXISTS — gated on
/// the banner `z_liveliness` prints after `z_liveliness_declare_token` returns
/// (`examples/unix/c11/z_liveliness.c:65`), never on a sleep. Without that gate
/// "the token was late" and "the router carried nothing" are the same picture.
fn spawn_pico_token(endpoint: &str) -> (ChildGuard, File) {
    let stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let writer = stdout.try_clone().expect("dup z_liveliness handle");
    let mut reader = stdout;
    let mut guard = ChildGuard::wrap(
        "z_liveliness token holder (zenoh-pico)".to_string(),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_pico_cli_binary("z_liveliness"))
            .args(["-k", PICO_TOKEN, "-t", "60", "-e", endpoint, "-m", "client"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );
    if let Err(captured) = wait_for_substring(
        &mut reader,
        "Press CTRL-C to undeclare liveliness token",
        Duration::from_secs(10),
    ) {
        let _ = guard.child_mut().kill();
        panic!(
            "z_liveliness never declared '{PICO_TOKEN}' within 10s, so nothing in \
             this fixture is about the router.\n--- z_liveliness stdout ---\n{captured}"
        );
    }
    (guard, reader)
}

/// Spawn the pico liveliness subscriber. `history` is the ONE flag that differs
/// between the CURRENT and FUTURE arms — `-h` sets `history`, which is the
/// CURRENT bit on the outbound TOKENS Interest and nothing else
/// (`vendor/zenoh-pico/src/net/liveliness.c:202-205`).
fn spawn_pico_subscriber(endpoint: &str, history: bool) -> (ChildGuard, File) {
    let stdout = tempfile::tempfile().expect("tempfile for z_sub_liveliness stdout");
    let writer = stdout.try_clone().expect("dup z_sub_liveliness handle");
    let mut reader = stdout;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary("z_sub_liveliness"))
        .args(["-k", SUB_FILTER, "-e", endpoint, "-m", "client"]);
    if history {
        cmd.arg("-h");
    }
    let mut guard = ChildGuard::wrap(
        "z_sub_liveliness subscriber (zenoh-pico)".to_string(),
        cmd.stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub_liveliness via stdbuf"),
    );
    // The subscriber's INTEREST must be on the wire before the ordering this
    // fixture depends on means anything; pico prints this line after
    // `z_liveliness_declare_subscriber` returns.
    if let Err(captured) =
        wait_for_substring(&mut reader, "Press CTRL-C to quit", Duration::from_secs(10))
    {
        let _ = guard.child_mut().kill();
        panic!(
            "z_sub_liveliness never declared its subscriber within 10s.\n\
             --- z_sub_liveliness stdout ---\n{captured}"
        );
    }
    (guard, reader)
}

/// THE HEADLINE, both edges. A liveliness token declared by one pico reaches
/// another pico through a wz star router, and is RETRACTED when the holder dies
/// without saying anything.
// wz-proves: liveliness-subscriber pico->wz partial
// wz-proves: routing-routes pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router,routing-routes + zenoh-pico z_liveliness / z_sub_liveliness); Layer E3 runs via --ignored"]
fn wz_router_carries_a_pico_token_and_retracts_it_when_the_holder_dies() {
    let (mut router, mut router_reader, port) = spawn_star_router();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // The SUBSCRIBER joins first, with no history: the only thing that can
    // deliver the token is the FUTURE advertisement the router makes when the
    // declaration arrives later.
    let (mut sub, mut sub_reader) = spawn_pico_subscriber(&endpoint, /*history=*/ false);
    let (mut holder, mut holder_reader) = spawn_pico_token(&endpoint);

    let rise = format!("New alive token ('{PICO_TOKEN}')");
    let rise_seen = wait_for_substring(&mut sub_reader, &rise, SAMPLE_TIMEOUT);
    if let Err(captured) = &rise_seen {
        let _ = sub.child_mut().kill();
        let _ = holder.child_mut().kill();
        let _ = router.child_mut().kill();
        panic!(
            "the token never reached the subscriber. Expected {rise:?}. Both picos \
             are clients of the SAME wz --router, so the only thing between them \
             is RouteTable -- which before R311y803 dropped every DeclToken on the \
             floor.\n--- z_sub_liveliness stdout ---\n{captured}\n\
             --- router stderr ---\n{}",
            read_captured(&mut router_reader)
        );
    }

    // KILL, not terminate. On SIGINT `z_liveliness` undeclares its own token and
    // the retraction would be the PEER's; SIGKILL makes pico say nothing, so a
    // `Dropped token` line can only come from wz's own face-down path.
    let _ = holder.child_mut().kill();
    let _ = holder.child_mut().wait();

    let fall = format!("Dropped token ('{PICO_TOKEN}')");
    let fall_seen = wait_for_substring(&mut sub_reader, &fall, SAMPLE_TIMEOUT);

    let sub_captured = read_captured(&mut sub_reader);
    let holder_captured = read_captured(&mut holder_reader);
    let _ = sub.child_mut().kill();
    let _ = sub.child_mut().wait();
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    assert!(
        !holder_captured.contains("Undeclaring liveliness token"),
        "the holder undeclared its OWN token, so the retraction below is the \
         PEER's and not the router's -- the kill did not land.\n\
         --- z_liveliness stdout ---\n{holder_captured}"
    );
    if let Err(captured) = fall_seen {
        panic!(
            "the holder was KILLED and the subscriber was never told. Expected \
             {fall:?}. A liveliness token means its holder is alive, so silence \
             here is a dead peer that stays alive in every observer forever -- \
             zenoh drains the face's tokens in close_face \
             (hat/router/mod.rs:541-544).\n\
             --- z_sub_liveliness stdout ---\n{captured}{sub_captured}\n\
             --- router stderr ---\n{router_captured}"
        );
    }
}

/// The CURRENT half, with the ordering reversed: the token exists BEFORE the
/// subscriber's session does, so nothing but the dump can deliver it.
// wz-proves: routing-routes pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router,routing-routes + zenoh-pico z_liveliness / z_sub_liveliness); Layer E3 runs via --ignored"]
fn wz_router_replays_a_pre_existing_pico_token_to_a_history_subscriber() {
    let captured = run_history_arm(true);
    let expected = format!("New alive token ('{PICO_TOKEN}')");
    assert!(
        captured.contains(&expected),
        "a token that existed before the subscriber joined was not replayed to a \
         history subscriber. Expected {expected:?} -- the holder's own banner \
         gated its spawn, so neither the token nor the session can explain \
         this.\n--- z_sub_liveliness stdout ---\n{captured}"
    );
}

/// The twin that makes the arm above the DUMP's claim rather than the token's.
/// Identical fixture, one pico flag removed.
///
/// `none` is honest rather than an omission: alone this arm witnesses no atom —
/// it witnesses that its sibling's sample is caused by the CURRENT bit.
// wz-proves: none -- anti-vacuity twin for the history arm above; it shows the
// replay is caused by the CURRENT bit `-h` sets and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router,routing-routes + zenoh-pico z_liveliness / z_sub_liveliness); Layer E3 runs via --ignored"]
fn wz_router_without_history_replays_nothing() {
    let captured = run_history_arm(false);
    assert!(
        !captured.contains("New alive token"),
        "history=false is FUTURE-ONLY, yet a token declared BEFORE the subscriber \
         arrived anyway. Either `-h` no longer gates the CURRENT bit, or the \
         sibling's green is not evidence of the dump at all.\n\
         --- z_sub_liveliness stdout ---\n{captured}"
    );
}

/// The shared body of the two history arms: holder FIRST (gated on its banner),
/// subscriber second, one flag apart.
fn run_history_arm(history: bool) -> String {
    let (mut router, mut router_reader, port) = spawn_star_router();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let (mut holder, mut holder_reader) = spawn_pico_token(&endpoint);
    let (mut sub, mut sub_reader) = spawn_pico_subscriber(&endpoint, history);

    let expected = format!("New alive token ('{PICO_TOKEN}')");
    let outcome = if history {
        wait_for_substring(&mut sub_reader, &expected, SAMPLE_TIMEOUT)
    } else {
        // The twin cannot "wait for nothing": it sleeps its bound, then reads
        // whatever landed. Anything present is a real replay and a real failure.
        std::thread::sleep(NO_SAMPLE_WINDOW);
        Ok(String::new())
    };

    let mut sub_captured = read_captured(&mut sub_reader);
    if let Ok(seen) = &outcome {
        sub_captured = format!("{seen}{sub_captured}");
    }
    let holder_captured = read_captured(&mut holder_reader);
    let _ = sub.child_mut().kill();
    let _ = sub.child_mut().wait();
    let _ = holder.child_mut().kill();
    let _ = holder.child_mut().wait();
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    if history && outcome.is_err() {
        panic!(
            "history=true and the pre-existing token was NOT replayed. Expected \
             {expected:?}.\n--- z_sub_liveliness stdout ---\n{sub_captured}\n\
             --- z_liveliness stdout ---\n{holder_captured}\n\
             --- router stderr ---\n{router_captured}"
        );
    }
    sub_captured
}
