// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y798 — the `AllComplete` matching semantic, witnessed by a real
//! zenoh-pico queryable.
//!
//! ## What R311y797 built and could not prove
//!
//! R311y797 gave `Querier::get_matching_status` a completeness-aware verdict:
//! a querier whose target is `AllComplete` matches only a COMPLETE queryable
//! whose keyexpr INCLUDES the querier's, where an ordinary target matches any
//! INTERSECTING one. Both arms were transcribed from upstream by direct read —
//! zenoh `matching_status_local` (`api/session.rs:1887-1894`) and pico
//! (`net/filtering.c:146-152` local, `:206-207` remote) — and pinned only
//! against wz's own registries. Its own ledger entry recorded the gap: no
//! foreign witness for the AllComplete axis.
//!
//! This file is that witness, and the bit under test is one a foreign process
//! puts on the wire.
//!
//! ## pico is the CAUSE, and its default is the whole fixture
//!
//! `z_queryable_options_default` sets `complete = false`
//! (`vendor/zenoh-pico/include/zenoh-pico/session/queryable.h:42`), and pico's
//! encoder OMITS the `QueryableInfo` ext entirely at that value —
//! `has_info_ext = complete || distance != 0` with
//! `_Z_QUERYABLE_DISTANCE_DEFAULT 0`
//! (`vendor/zenoh-pico/src/protocol/codec/declarations.c:107-112`). So stock
//! `z_queryable` declares an INCOMPLETE queryable by sending no ext at all, and
//! what this test binds is wz's reading of that ABSENCE: R311y797 decided an
//! absent ext reads as `false` because that is upstream's omit-on-DEFAULT
//! encoding, not because it is a safe guess. A wz that treated "no ext" as
//! unknown-therefore-complete would fail here against a real encoder.
//!
//! ## The two queriers differ in exactly one thing
//!
//! `--querier-matching-all-complete` is a BARE companion of
//! `--querier-matching-log`: it declares a second querier on the very same
//! keyexpr, with `QueryTarget::AllComplete` and nothing else changed. One
//! session, one inbound declaration, one instant, two verdicts. Two demo
//! processes could not make this claim — they would be watching two different
//! declarations.
//!
//! ## Why this cannot pass vacuously, in three parts
//!
//! 1. **The listeners exist.** Both `DECLARED QUERIER ...` lines are asserted
//!    before anything else. With `session-matching` off, `declare_matching_listener`
//!    returns a typed reject and the demo logs a WARN, so a run that proves
//!    nothing is distinguishable from a run whose transition has not happened.
//! 2. **The declaration arrived.** The ordinary querier reports `matching=true`
//!    on pico's queryable. Without this leg, "AllComplete stayed silent" would
//!    be satisfied by pico never connecting at all.
//! 3. **The AllComplete listener CAN speak.** The second test in this file
//!    gives the same demo a session-LOCAL queryable declared
//!    `--queryable-complete`, and the AllComplete listener reports `true`. An
//!    AllComplete watch that was simply inert would pass leg 1 and leg 2 and
//!    fail here.
//!
//! Legs 1-3 together attribute the silence: the listener is installed, it can
//! fire, the declaration reached the session — and it still refuses, because
//! the only remaining difference is the completeness bit pico did not set.
//!
//! ## Keyexprs are chosen so INCLUSION is not the thing being tested
//!
//! pico declares `demo/**`, which INCLUDES the querier's literal
//! `demo/matching/allcomplete`. Under `AllComplete` the keyexpr test is
//! inclusion, and this pair satisfies it — so the refusal in the first test
//! cannot be blamed on the keyexprs, only on `complete`. The inclusion-vs-
//! intersection distinction has its own unit witnesses at both registry tiers
//! (R311y797); this file holds the completeness conjunct fixed against a
//! foreign encoder instead.
//!
//! ## What a failure here means
//!
//! Making `declared_answers`' `AllComplete` arm ignore `candidate.complete`
//! turns the first test red (the AllComplete line appears) and leaves the
//! second green, which localises the defect to the completeness conjunct rather
//! than to the matching machinery.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation, Z_SUB_INIT_TIMEOUT,
};

/// wz's querier keyexpr — a literal on both queriers.
const QUERIER_KEY: &str = "demo/matching/allcomplete";
/// pico's queryable pattern: a wildcard that INCLUDES the querier's literal, so
/// the keyexpr half of the AllComplete predicate is satisfied and only the
/// completeness bit can refuse.
const PICO_QUERYABLE_KEY: &str = "demo/**";
/// The keyexpr the SESSION-OPENER `z_sub` subscribes on in the two local-half
/// tests. Deliberately outside `demo/**` so that even the subscriber plane
/// shares nothing with the queryable under test — the opener's only job is to
/// get the demo to the scope where it installs its listeners.
const SESSION_OPENER_KEY: &str = "opener/**";

/// How long to let the AllComplete listener stay silent AFTER the ordinary one
/// has already spoken. Not a race budget: the ordinary querier's `true` is the
/// synchronisation point, and both listeners are fed by the SAME dispatch of
/// the SAME inbound declaration through the same deferred-fire drain. This is
/// slack for that one drain, not for the network.
const SETTLE_AFTER_CONTROL: Duration = Duration::from_secs(2);

// wz-proves: session-matching pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn a_pico_incomplete_queryable_is_refused_by_an_all_complete_wz_querier() {
    // Both flags this file drives (`--querier-matching-all-complete`,
    // `--queryable-complete`) landed WITH it, so a stale binary would ignore
    // them silently — and the two silence legs would then pass for the wrong
    // reason. Layer C0's binary-freshness gate is what surfaced that: this
    // fixture was in its "spawns the demo without the guard" count.
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--listen --querier-matching-log --querier-matching-all-complete)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--querier-matching-log")
            .arg(QUERIER_KEY)
            .arg("--querier-matching-all-complete")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    drop(port_res);

    // pico's queryable: stock options, so `complete = false` and the ext is
    // omitted. `stdbuf -oL` for the same glibc block-buffering reason the
    // sibling fixtures carry.
    let mut z_queryable_child = ChildGuard::wrap(
        "z_queryable client (zenoh-pico, stock complete=false)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args([
                "-k",
                PICO_QUERYABLE_KEY,
                "-e",
                &endpoint,
                "-m",
                "client",
                "-v",
                "pico-incomplete",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_queryable via stdbuf"),
    );

    // Anti-vacuity part 1, asserted after the spawn for the reason the sibling
    // fixture records: the demo installs its listeners at run_demo scope, which
    // it reaches only once a peer has connected.
    for line in [
        "DECLARED QUERIER MATCHING LISTENER",
        "DECLARED QUERIER ALLCOMPLETE MATCHING LISTENER",
    ] {
        if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, line, Z_SUB_INIT_TIMEOUT)
        {
            let _ = demo_child.child_mut().kill();
            let _ = z_queryable_child.child_mut().kill();
            panic!(
                "wz-ap-demo never logged '{line}', so this test proves NOTHING \
                 about the AllComplete semantic (session-matching off => typed \
                 reject + a WARN line)\n--- captured demo stderr ---\n{captured}"
            );
        }
    }

    // Anti-vacuity part 2 AND the synchronisation point: the ordinary querier
    // sees pico's declaration. This is what makes the silence below meaningful.
    let control = format!("QUERIER MATCHING STATUS keyexpr='{QUERIER_KEY}' matching=true");
    if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, &control, Z_SUB_INIT_TIMEOUT)
    {
        let _ = demo_child.child_mut().kill();
        let _ = z_queryable_child.child_mut().kill();
        panic!(
            "pico declared a queryable on '{PICO_QUERYABLE_KEY}', which intersects \
             '{QUERIER_KEY}', but wz's ORDINARY querier never reported \
             matching=true. Nothing else could have raised it — wz declares no \
             local queryable in this run.\n--- captured demo stderr ---\n{captured}"
        );
    }

    // Both listeners are fed by the same dispatch of the same declaration, so
    // by the time the control has spoken the AllComplete one has had its turn.
    // The sleep is slack for one deferred-fire drain, not for the network.
    std::thread::sleep(SETTLE_AFTER_CONTROL);

    let captured = read_captured(&mut demo_stderr_reader);
    let all_complete_line = format!("QUERIER ALLCOMPLETE MATCHING STATUS keyexpr='{QUERIER_KEY}'");
    let spoke = captured.contains(&all_complete_line);

    let _ = z_queryable_child.child_mut().kill();
    let _ = z_queryable_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();

    assert!(
        !spoke,
        "an AllComplete querier must NOT match pico's queryable: pico declares \
         it with the stock `complete = false`, at which value pico omits the \
         QueryableInfo ext entirely. wz reported a transition anyway, which \
         means it read the absent ext as something other than incomplete, or \
         dropped the completeness conjunct.\n--- captured demo stderr ---\n{captured}"
    );
}

// wz-proves: session-matching pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn a_complete_session_local_queryable_does_satisfy_the_all_complete_querier() {
    // Anti-vacuity part 3, and the reason it is a SEPARATE test rather than a
    // later leg of the one above: the demo declares `--queryable` BEFORE the
    // matching listeners, so a complete local queryable makes the AllComplete
    // listener fire at REGISTRATION (R311y797's seed). Folding it into the run
    // above would have made the AllComplete listener speak before pico's
    // declaration ever arrived, and the silence there would prove nothing.
    //
    // It is also the only leg that exercises the session-LOCAL half of the
    // AllComplete verdict end-to-end through a real process.
    // Both flags this file drives (`--querier-matching-all-complete`,
    // `--queryable-complete`) landed WITH it, so a stale binary would ignore
    // them silently — and the two silence legs would then pass for the wrong
    // reason. Layer C0's binary-freshness gate is what surfaced that: this
    // fixture was in its "spawns the demo without the guard" count.
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--queryable-complete + --querier-matching-all-complete)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            // A LOCAL queryable whose pattern INCLUDES the querier's literal and
            // which declares itself COMPLETE — the two conjuncts the AllComplete
            // verdict needs, and the only source of them in this run.
            .arg("--queryable")
            .arg(PICO_QUERYABLE_KEY)
            .arg("--reply")
            .arg("wz-local-complete")
            .arg("--queryable-complete")
            .arg("--querier-matching-log")
            .arg(QUERIER_KEY)
            .arg("--querier-matching-all-complete")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    drop(port_res);

    // pico is here ONLY to open the session, which is what gets the demo to the
    // scope where it installs its listeners. It is a `z_sub` and not a
    // `z_queryable` deliberately, and the choice is load-bearing: a subscriber
    // declaration cannot reach `RemoteQueryableRegistry` at all, so the ONLY
    // queryable anywhere in this run is wz's own local one. A first draft used
    // `z_queryable` here and a falsify probe caught it — dropping the REMOTE
    // arm's completeness conjunct reddened this leg too, because pico's own
    // incomplete queryable was in scope to satisfy the broken predicate. The
    // leg proved "something refuses" rather than "the local half refuses".
    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (session opener; NOT a queryable, on purpose)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", SESSION_OPENER_KEY, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    let rise = format!("QUERIER ALLCOMPLETE MATCHING STATUS keyexpr='{QUERIER_KEY}' matching=true");
    let got = wait_for_substring(&mut demo_stderr_reader, &rise, Z_SUB_INIT_TIMEOUT);

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();

    if let Err(captured) = got {
        panic!(
            "a session-local queryable on '{PICO_QUERYABLE_KEY}' declared COMPLETE \
             includes '{QUERIER_KEY}', so the AllComplete querier must match it — \
             and this is the leg that proves the AllComplete listener is not \
             simply inert.\n--- captured demo stderr ---\n{captured}"
        );
    }
}

// wz-proves: session-matching pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn an_incomplete_session_local_queryable_does_not_satisfy_the_all_complete_querier() {
    // The LOCAL-half twin of the first test, and the leg that binds the local
    // completeness conjunct. Without it, the test above would still pass if
    // `has_local_matching` dropped its `require_complete` filter entirely: a
    // COMPLETE queryable satisfies both the correct predicate and the broken
    // one. This run differs from that one by a SINGLE argv token —
    // `--queryable-complete` is absent — so the flag is the only variable.
    //
    // The ordinary querier is the control here, exactly as pico's declaration
    // was in the first test: it must report `true` off the very same local
    // queryable, which proves the queryable exists and intersects, leaving
    // completeness as the only thing the AllComplete verdict can be refusing on.
    // Both flags this file drives (`--querier-matching-all-complete`,
    // `--queryable-complete`) landed WITH it, so a stale binary would ignore
    // them silently — and the two silence legs would then pass for the wrong
    // reason. Layer C0's binary-freshness gate is what surfaced that: this
    // fixture was in its "spawns the demo without the guard" count.
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--queryable WITHOUT --queryable-complete)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--queryable")
            .arg(PICO_QUERYABLE_KEY)
            .arg("--reply")
            .arg("wz-local-incomplete")
            .arg("--querier-matching-log")
            .arg(QUERIER_KEY)
            .arg("--querier-matching-all-complete")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    drop(port_res);

    // A `z_sub`, not a `z_queryable`, for the reason spelled out in the test
    // above: the only queryable in this run must be wz's own, or this leg
    // cannot attribute the refusal to the LOCAL completeness filter.
    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (session opener; NOT a queryable, on purpose)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", SESSION_OPENER_KEY, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // The AllComplete listener must EXIST before its silence can mean anything.
    // This leg needs the assertion more than the first one does: its control is
    // the ORDINARY querier's line, which a build (or a binary) that never
    // installed the AllComplete twin would still print — so without this the
    // silence below would be satisfied by the listener's absence.
    if let Err(captured) = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED QUERIER ALLCOMPLETE MATCHING LISTENER",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never installed the AllComplete matching listener, so \
             this test proves NOTHING about the local completeness conjunct\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    let control = format!("QUERIER MATCHING STATUS keyexpr='{QUERIER_KEY}' matching=true");
    if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, &control, Z_SUB_INIT_TIMEOUT)
    {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "the ORDINARY querier must match the session-local queryable on \
             '{PICO_QUERYABLE_KEY}' regardless of completeness, so its silence \
             means the fixture never got as far as the question it asks.\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    std::thread::sleep(SETTLE_AFTER_CONTROL);

    let captured = read_captured(&mut demo_stderr_reader);
    let all_complete_line = format!("QUERIER ALLCOMPLETE MATCHING STATUS keyexpr='{QUERIER_KEY}'");
    let spoke = captured.contains(&all_complete_line);

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();

    assert!(
        !spoke,
        "an AllComplete querier must NOT be satisfied by an INCOMPLETE \
         session-local queryable, however well the keyexprs line up. The only \
         difference between this run and the one that legitimately reports \
         `true` is the `--queryable-complete` token.\n\
         --- captured demo stderr ---\n{captured}"
    );
}
