// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "routing-peer",
    feature = "transport-lowlatency",
))]

//! R2096 (open-debt item 516) — every capability an aggregating mesh peer is
//! configured with is ACCEPTED at the command line, on `--max-links > 1` exactly
//! as on `--max-links 1`.
//!
//! ## This file used to assert the opposite, and that is the point
//!
//! R2095 wired `peer_loop`'s SINGLE-link dial to a whole `SessionOffer`, which
//! is what item 513 asked for. The AGGREGATING dial was a different entrypoint
//! — `initiate_and_open_session_with_multilink`, which took `(pref, qos, band)`
//! and stages no offer — so after that wiring the same flag reached the wire on
//! one path and nothing on the other. R2095 refused the combination rather than
//! dropping it (R311y506's treatment of `--qos-band`) and filed the residual as
//! item 516.
//!
//! R2096 paid it: both `_with_multilink` entrypoints take the `SessionOffer`
//! now, `FaceSources.qos` is gone, and the refusal became a false statement
//! about this binary. Deleting the guard without moving its witness would have
//! left the tree with no answer to "is the combination accepted", so the witness
//! was INVERTED instead. That is the cheap half of open-debt item 47 — a rule
//! outliving the limitation it described — caught in the round that invalidated
//! it rather than by a later audit.
//!
//! ## Why a process test
//!
//! The rule is `argv -> exit status`. A unit test over the offer builder would
//! pass whether or not `main` consults it — open-debt item 479's class, which
//! R2072 paid for once already. What is under judgement here is the BINARY.
//!
//! ## An accepted flag is proved by where the run DIES, not by silence
//!
//! Every arm still fails: a `--peer` that binds successfully runs until a
//! signal. So "no refusal" is not the assertion — REACHING THE BIND is (R2077:
//! an absent message and a run that never got there look identical). Each arm
//! asserts the bind error, which can only be reported by a run that got past
//! argv parsing with the flag accepted.
//!
//! The `--max-links 1` arm is the CONTROL and it is in this same test: it is
//! the configuration R2095 already made work, so an arm that fails there is
//! failing for a reason that has nothing to do with aggregation.
//!
//! ## Why `tcp/192.0.2.1:9` is the listen address
//!
//! `192.0.2.1` is RFC 5737 TEST-NET-1: assigned to no interface anywhere, so
//! `bind` returns immediately and does so on every machine. A port number would
//! not give that — an ephemeral port succeeds and a privileged one depends on
//! who is running the test.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    cmd.args(args);
    cmd.output().expect("the demo binary runs")
}

/// RFC 5737 TEST-NET-1 — assigned to no interface, so a bind here fails fast
/// and identically everywhere. See the module doc.
const UNBINDABLE: &str = "tcp/192.0.2.1:9";

/// The R2095 refusal, which must no longer be produced by anything.
///
/// Kept as a literal rather than deleted with the guard: the assertion "this
/// binary does not say that any more" needs the sentence to compare against,
/// and a round that reinstates the refusal reds here instead of silently
/// narrowing what an aggregating peer accepts.
const DROPPED: &str = "cannot be offered with --max-links > 1";

/// What an arm that got PAST argv parsing says: the bind of [`UNBINDABLE`]
/// failing. Asserting it is what separates "the flag was accepted" from "the
/// run stopped earlier for some other reason" — two states an absent refusal
/// reports identically.
const REACHED_THE_BIND: &str = "Cannot assign requested address";

/// Every capability an operator can put on a mesh peer, paired with the
/// `--max-links` values the two dial paths sit behind.
///
/// `1` is `dial_face` (R2095's wiring) and `2` is `dial_face_multilink`
/// (R2096's). Both are asked of every flag from ONE table, which is what makes
/// "the wire form depends on --max-links" a shape this test can see: an
/// entrypoint that drops a capability again fails the `2` row of that flag and
/// leaves its `1` row green.
const ARMS: &[(&str, &[&str])] = &[
    ("--lowlatency", &["1", "2"]),
    ("--compression", &["1", "2"]),
    ("--shm", &["1", "2"]),
    // `--qos` was never in the refused set — it is the one capability the
    // aggregation path already carried, by its own `FaceSources.qos` route.
    // R2096 deleted that route and moved it into the offer with the other
    // three, so it is asked here on the same terms: a regression that broke it
    // would otherwise be invisible.
    ("--qos", &["1", "2"]),
];

#[test]
fn an_aggregating_peer_accepts_every_capability_a_single_link_peer_accepts() {
    // Collected, not asserted where it is read (the discipline item 513 asked
    // for): an arm that dies where it is measured leaves every later arm
    // UNMEASURED, and unmeasured must not be reported as passed.
    let mut failures: Vec<String> = Vec::new();

    for (flag, link_counts) in ARMS {
        for links in *link_counts {
            let out = run(&["--peer", UNBINDABLE, "--max-links", links, flag]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains(DROPPED) {
                failures.push(format!(
                    "--max-links {links} {flag}: refused as un-offerable, but \
                     R2096 wired the aggregating open path to the whole \
                     SessionOffer.\n--- stderr ---\n{stderr}"
                ));
            }
            if !stderr.contains(REACHED_THE_BIND) {
                failures.push(format!(
                    "--max-links {links} {flag}: the run never reached the BIND, \
                     so nothing here says the flag was accepted — it stopped \
                     earlier.\n--- stderr ---\n{stderr}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the {} argv arms this test runs did not reach the bind with the \
         flag accepted:\n  {}",
        failures.len(),
        ARMS.iter().map(|(_, c)| c.len()).sum::<usize>(),
        failures.join("\n  ")
    );
}
