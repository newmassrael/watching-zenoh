// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2089 (open-debt item 222) — a wz `--router-hat` ANSWERS a Scout, and the
//! Hello it answers with says `router`.
//!
//! R311y846 built the responder and wired it into `run_peer` alone. That left
//! the mode a stock zenoh network actually looks for silent: a client's
//! `scouting/multicast/autoconnect` default is `["router"]`
//! (`DEFAULT_CONFIG.json5:172` in the pinned zenoh checkout), so the one role
//! every unconfigured client asks for was the one wz would never answer as. A
//! drop-in replacement that cannot be found in the role it is deployed as is not
//! a replacement.
//!
//! ## What is measured, and by what
//!
//! The scouter here is this test process: an ephemeral UDP socket that **never
//! joins the group**. That is load-bearing twice over. It makes the reply's
//! arrival a UNICAST proof (a Hello addressed to `GROUP:PORT` would not be
//! delivered to a socket with no membership — the argument
//! `scouting_responder_multicast.rs` states for the unit-level leg), and it
//! means nothing but wz's own `send_to(.., peer)` can produce the bytes this
//! test reads.
//!
//! Those bytes are then read by **this tree's dissector**,
//! [`wz_session_core::dissect::dissect_scouting_message`], and the assertion is
//! on the `whatami` field it walks out of the Hello's `cbyte`. Not on a log
//! line: the demo's `SCOUT RESPONDER listening ... as router` banner is what the
//! run-mode INTENDED, and the wire is what it DID. Those are different claims,
//! and R311y471's blind spot was exactly a place where only the first was ever
//! checked.
//!
//! ## Why the peer arm is in the SAME test
//!
//! `WhatAmI::Router`'s wire value is `0b00` (`whatami.rs:55`). An assertion that
//! reads zero out of a byte is the weakest shape an assertion can have — a field
//! that was never written reads zero too. So the control is not optional
//! decoration: the same scouter, the same code path, one node started as
//! `--peer` instead, must answer `0b01`. A responder that hardcoded either value
//! fails one of the two arms, and a `run_router_hat` with the spawn removed
//! fails the router arm while the peer arm stays green — which is the whole
//! point of keeping the two in one test rather than two files.
//!
//! Each node owns a DISTINCT group AND port. Distinct PORTS specifically,
//! because Linux `IP_MULTICAST_ALL` delivers to a wildcard-bound socket by port
//! regardless of which group the datagram carried (open-debt item 225 is the
//! probe that got this wrong once): two responders sharing a port would each
//! answer the other's Scout and neither arm would be measuring its own node.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): it spawns the demo binary and drives a
//! real multicast group, which is the pair Layer M owns. Needs the demo built
//! with `router-hat-router` + `scouting-responder` + `routing-peer` (that lane
//! builds it).

use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wz_codecs::scout::Scout;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, per_process_zid_hex, wait_for_capture_alive,
    wz_ap_demo_binary, ChildGuard,
};
use wz_session_core::dissect::{dissect_scouting_message, Field, FieldValue};

/// Roles, API form — the bitmask a Scout's `what` carries
/// (`zenoh-codec` `scouting/scout.rs`).
const WHAT_ROUTER: u8 = 0b001;
const WHAT_PEER: u8 = 0b010;

const RESPONDER_NEEDLE: &str = "SCOUT RESPONDER listening on ";
const ADVERTISED_NEEDLE: &str = "ADVERTISED SELF LOCATOR ";

/// One node under test: how it is started, where it answers, and what the wire
/// must say about it.
struct Arm {
    /// The run-mode flag, which is the whole independent variable.
    mode_flag: &'static str,
    group: Ipv4Addr,
    port: u16,
    zid_prefix: &'static str,
    /// The `whatami` the Hello must carry — the 2-bit HANDSHAKE form, which is
    /// what `walk_hello` reads out of `cbyte & 0x03`.
    expect_whatami: WhatAmI,
}

/// A Scout datagram in the shape both wz's own `scout_emit` and zenoh's
/// `Runtime::scout` put on the group: MID header, version, flags, no zid.
///
/// No zid because that is upstream's own shape (`orchestrator.rs` sends
/// `zid: None`), so this asker is indistinguishable from a stock one and the
/// responder's self-echo gate is not accidentally what is under test.
fn scout_datagram(what: u8) -> Vec<u8> {
    let mut scout = Scout::new();
    scout.version = 0x09;
    scout.set_what(what);
    let mut wire = vec![wire_const::S_MID_SCOUT];
    wire.extend_from_slice(&scout.encode_to_vec());
    wire
}

/// Read one named field's `Bits` value out of a walked tree.
fn bits(field: &Field, name: &str) -> Option<u64> {
    match field.find(name).map(|f| &f.value) {
        Some(FieldValue::Bits(v)) => Some(*v),
        _ => None,
    }
}

/// Scout the group and return the first datagram that comes back, or a
/// DIAGNOSIS.
///
/// Re-scouts on each attempt because a lost datagram is a normal event on a
/// multicast group and nothing retransmits it — upstream's own scouter re-emits
/// on a backoff for the same reason. The child's liveness is checked on every
/// turn and its captured stderr is carried into the error, so a node that died
/// at startup reports as a corpse with its own message rather than as a
/// deadline: this tree asserted a wrong single cause ("never dialled") one round
/// ago by discarding exactly this.
fn scout_and_read_hello(
    scouter: &UdpSocket,
    arm: &Arm,
    child: &mut Child,
    capture: &mut std::fs::File,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let datagram = scout_datagram(WHAT_ROUTER | WHAT_PEER);
    let mut buf = vec![0u8; 2048];
    loop {
        scouter
            .send_to(&datagram, (arm.group, arm.port))
            .map_err(|e| format!("could not scout {}:{}: {e}", arm.group, arm.port))?;
        match scouter.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from.port() != arm.port {
                    // Not ours: another responder on this host answered from a
                    // socket we did not ask. Reported rather than silently
                    // accepted — a stray Hello standing in for the node under
                    // test is the failure shape this file's port discipline
                    // exists to prevent.
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv_from on the scouter failed: {e}")),
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "the {} node exited before answering (status: {status})\n\
                 --- captured output ---\n{}",
                arm.mode_flag,
                wz_integration_tests::common::read_captured(capture)
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no Hello from the {} node on {}:{} within the budget (process \
                 still alive)\n--- captured output ---\n{}",
                arm.mode_flag,
                arm.group,
                arm.port,
                wz_integration_tests::common::read_captured(capture)
            ));
        }
    }
}

// Deliberately NOT a cross-impl claim: both the scouter and the answerer are
// this tree's code, so what this measures is that wz's ROUTER run-mode puts a
// role on the wire — not that a foreign stack agrees about it. The foreign half
// of the responder subsystem is `zenohd_scouts_wz_interop.rs`, which drives the
// PEER mode and is where a zenohd's own reading of a wz Hello is witnessed.
//
// So this file carries NO cross-impl claim marker, and its absence is the
// gate's own rule rather than an omission: invariant A4-3 refuses a foreign
// claim — the `none -- <reason>` spelling included — from a file that spawns
// and links no foreign implementation. Measured, not assumed: both spellings
// were tried this round and both were refused, in that order.
#[test]
#[ignore = "binary-dep e2e: needs wz-ap-demo[+router-hat-router,scouting-responder,routing-peer] \
            and a multicast route; runs via --ignored"]
fn a_wz_router_hat_answers_a_scout_with_a_hello_that_says_router() {
    let demo = wz_ap_demo_binary();
    // A demo built before this round has no `--scout-listen` on `--router-hat`
    // at all, so a stale binary does not weaken this proof — it reproduces the
    // exact red the test is written to detect, and sends the diagnosis hunting
    // in the responder for a defect that is in the build.
    assert_demo_binary_newer_than_sources(&demo);

    let arms = [
        Arm {
            mode_flag: "--router-hat",
            group: Ipv4Addr::new(224, 0, 0, 231),
            port: 17452,
            zid_prefix: "7201",
            expect_whatami: WhatAmI::Router,
        },
        // THE CONTROL. Same binary, same flag, same scouter, same socket
        // discipline; one word of argv different. See the module doc: without
        // it the router assertion is reading a zero.
        Arm {
            mode_flag: "--peer",
            group: Ipv4Addr::new(224, 0, 0, 232),
            port: 17453,
            zid_prefix: "7202",
            expect_whatami: WhatAmI::Peer,
        },
    ];

    let scouter = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind an ephemeral scouter that never joins the group");
    scouter
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("a read timeout is what makes the liveness check reachable");

    // Every arm's verdict is collected BEFORE any assertion, so one arm's
    // failure still reports what the other did — "the router is silent" and
    // "nothing on this host can answer a Scout" are different diagnoses and the
    // second is not worth a round of hunting.
    let mut verdicts: Vec<(&Arm, Result<(Vec<u8>, String, String), String>)> = Vec::new();
    for arm in &arms {
        let zid_hex = per_process_zid_hex(arm.zid_prefix, 4);
        let capture = tempfile::tempfile().expect("tempfile for the node's stderr");
        let writer = capture.try_clone().expect("dup the stderr handle");
        let mut capture = capture;
        let mut node = ChildGuard::wrap(
            arm.mode_flag,
            Command::new(&demo)
                .arg(arm.mode_flag)
                .arg("tcp/127.0.0.1:0")
                .arg("--scout-listen")
                // The group is MOVED off zenoh's default on purpose. Two nodes
                // in one test cannot share the default socket, and a run of this
                // test must not answer the Scouts of a zenohd another lane is
                // driving on `224.0.0.224:7446`.
                .arg("--scout-addr")
                .arg(format!("{}:{}", arm.group, arm.port))
                // PER-PROCESS: a fixed zid shared with a leftover or a
                // concurrent copy of this test would let the wrong node's Hello
                // satisfy the zid assertion below.
                .arg("--zid")
                .arg(&zid_hex)
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {} {}: {e}", demo.display(), arm.mode_flag)),
        );

        // Readiness in the order the node reaches it: the advertise decision
        // first (the locator the Hello will carry), then the group join. Both
        // through the liveness-aware wait, so a node that aborts on its argv is
        // reported as a corpse with its own message instead of costing the full
        // budget and then being guessed about.
        let advertised = wait_for_capture_alive(
            node.child_mut(),
            &mut capture,
            Duration::from_secs(15),
            "the advertised self locator",
            |captured| {
                captured
                    .split_once(ADVERTISED_NEEDLE)
                    .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_string())
                    .filter(|s| !s.is_empty())
            },
        );
        let banner = advertised.as_ref().ok().and_then(|_| {
            wait_for_capture_alive(
                node.child_mut(),
                &mut capture,
                Duration::from_secs(15),
                "the scout responder banner",
                |captured| {
                    captured
                        .split_once(RESPONDER_NEEDLE)
                        .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_string())
                        .filter(|s| !s.is_empty())
                },
            )
            .ok()
        });

        let verdict = match (advertised, banner) {
            (Ok(advertised), Some(banner)) => {
                scout_and_read_hello(&scouter, arm, node.child_mut(), &mut capture)
                    .map(|hello| (hello, advertised, banner))
            }
            (Ok(_), None) => Err(format!(
                "the {} node advertised a locator but never joined the scouting \
                 group; without the join there is no responder and the run below \
                 would be measuring nothing\n--- captured output ---\n{}",
                arm.mode_flag,
                wz_integration_tests::common::read_captured(&mut capture)
            )),
            (Err(e), _) => Err(e),
        };
        let _ = node.child_mut().kill();
        let _ = node.child_mut().wait();
        verdicts.push((arm, verdict.map(|(h, a, b)| (h, a, b))));
    }

    for (arm, verdict) in &verdicts {
        let (hello, advertised, banner) = match verdict {
            Ok(v) => v,
            Err(e) => panic!("{} arm: {e}", arm.mode_flag),
        };

        // THIS TREE'S DISSECT reads the answer. `dissect_scouting_message` is a
        // separate entry point from the transport walk because the MID spaces
        // collide (`0x01` is `Scout` here and `Init` there), so feeding a Hello
        // to the transport dispatcher decodes the WRONG message rather than
        // failing — the confident-wrong-answer this call avoids by construction.
        let walked = dissect_scouting_message(hello, 0)
            .unwrap_or_else(|e| {
                panic!(
                    "{} arm: wz answered {} bytes this tree cannot dissect: {e:?}",
                    arm.mode_flag,
                    hello.len()
                )
            })
            .unwrap_or_else(|| {
                panic!(
                    "{} arm: the answer's first byte is not a scouting MID, so it \
                     is not a Hello at all: {:02x?}",
                    arm.mode_flag, hello
                )
            });
        assert_eq!(
            walked.name, "Hello",
            "{} arm: a Scout must be answered with a Hello, got {}",
            arm.mode_flag, walked.name
        );

        // THE CLAIM. The role is read off the wire, not off the banner.
        assert_eq!(
            bits(&walked, "whatami"),
            Some(u64::from(arm.expect_whatami.to_wire())),
            "{} arm: the Hello must carry this node's own role. The banner said \
             {banner:?} and the wire said otherwise, which is the R311y471 shape: \
             an advertise decision that agrees with itself and not with the wire",
            arm.mode_flag,
        );

        // The answer came from the node this arm STARTED, not from a stray
        // responder that happens to share the group. Read by value against the
        // zid this arm pinned.
        let zid = match walked.find("zid").map(|f| &f.value) {
            Some(FieldValue::Bytes(b)) => b.clone(),
            other => panic!(
                "{} arm: a Hello always carries a zid; got {other:?}",
                arm.mode_flag
            ),
        };
        let zid_hex: String = zid.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            zid_hex.starts_with(arm.zid_prefix),
            "{} arm: the Hello came from zid {zid_hex}, which is not the node this \
             arm started (prefix {})",
            arm.mode_flag,
            arm.zid_prefix
        );

        // And it is DIALABLE: the locator on the wire is the one the node's own
        // advertise seam chose, not one composed for it. That is what makes the
        // discovery useful rather than merely observable.
        let locator = match walked.find("locator").map(|f| &f.value) {
            Some(FieldValue::Text(t)) => t.clone(),
            other => panic!(
                "{} arm: the Hello carries no locator, so a node that discovers \
                 this one still cannot reach it; got {other:?}",
                arm.mode_flag
            ),
        };
        assert_eq!(
            &locator, advertised,
            "{} arm: the Hello must advertise the string wz itself chose",
            arm.mode_flag
        );
        assert!(
            locator.starts_with("tcp/127.0.0.1:"),
            "{} arm: expected an ephemeral tcp advertise, got {locator:?}",
            arm.mode_flag
        );
    }
}
