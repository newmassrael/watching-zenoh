// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2307 (open-debt item 515) — a stock zenohd SCOUTING FOR ROUTERS discovers a
//! wz node whose run-mode came from a CONFIG FILE, and dials the locator that
//! node's own Hello advertised.
//!
//! ## What this adds to `zenohd_scouts_wz_router_interop.rs`
//!
//! That leg is the same claim on the same wire, with ONE difference: its arms
//! select the run-mode by ARGV (`--router-hat` / `--peer`). The invocation a
//! replacement actually receives is `wz-ap-demo --config their.json5`, and the
//! only witness for THAT spelling was `wz_router_hat_answers_a_scout.rs`, whose
//! scouter and whose dissector are both this tree's code — so A4-3 refuses it a
//! cross-impl marker, correctly. Open-debt item 515 is the record that the
//! spelling operators type had never been read by anything foreign.
//!
//! Nothing here is a defect probe. R2094 measured the behaviour and found it
//! GREEN; what was missing is the leg that says so, and a behaviour with no
//! witness is one nobody will notice losing.
//!
//! ## Why its OWN file, on the R2089 build
//!
//! Item 515 named the tension and left it to be decided: fold a third arm into
//! the R2094 leg, or stand a file beside it. Folding was refused, and the reason
//! is the very argument that gives every leg here its own build — prove a claim
//! in the MINIMAL feature set that carries it. A config arm needs
//! `zenoh-config`, so the R2094 build would have to grow it, and that leg's
//! `router-hat-router` / `scouting-responder` claims would stop being proven
//! minimally. Standing here instead costs the lane NO new build: the claim under
//! test is "the role a FILE selected is findable", whose minimal feature set
//! contains `zenoh-config` by construction, and that set is exactly the one
//! `wz_router_hat_answers_a_scout` already builds.
//!
//! ## What makes the dial ROLE-DEPENDENT, and what the control is for
//!
//! Unchanged from the sibling leg, because the wire is the same: zenohd runs
//! `mode: "peer"` with its `scouting/multicast/autoconnect` NARROWED to the
//! CLIENT default `["router"]` from the same line of the same upstream file
//! (`zenoh/DEFAULT_CONFIG.json5`). Upstream reads that list twice from one value
//! — it is the `what` of the Scout it emits and the matcher it applies to every
//! Hello — so a wz Hello claiming `peer` fails the second gate in foreign code.
//!
//! The control is therefore the SAME config document with ONE word changed:
//! `mode: "peer"`. Under a router-only scouter that node must not be dialled. If
//! the narrowing were inert, zenohd's own peer default would dial it and the
//! control reds; if multicast were dead on the host, the router arm reds first.
//!
//! NOTHING here names wz to zenohd: no `-e`, no `--connect`, no endpoint, no
//! zid. The config asks for `tcp/127.0.0.1:0`, so the KERNEL picks the port and
//! the only path from that port to zenohd's dialer runs through the Hello.
//!
//! ## The two documents are identical apart from the role
//!
//! Deliberately, and it is what makes each arm the other's control. They also
//! name zenoh's DEFAULT scouting socket rather than moving off it as the R2089
//! fixture does: an unconfigured zenohd looks there and nowhere else, so a
//! responder that joined a private group would be perfectly healthy and
//! completely undiscoverable. The arms run in sequence and pin PER-PROCESS zids,
//! which is what lets them share that socket safely.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): zenohd is an external binary and the
//! scouting group is a real multicast socket.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, configured_zid_value, face_zid_value,
    per_process_zid_hex, read_captured, spawn_zenohd_multicast_scouting_with_args,
    wait_for_capture_alive, wz_ap_demo_binary, ChildGuard,
};

const RESPONDER_NEEDLE: &str = "SCOUT RESPONDER listening on ";
const ADVERTISED_NEEDLE: &str = "ADVERTISED SELF LOCATOR ";
/// The group an unconfigured zenoh node looks on. Spelled out because a
/// responder that joined somewhere else is healthy and undiscoverable.
const DEFAULT_SCOUT_SOCKET: &str = "224.0.0.224:7446";

/// How long the ROUTER arm may take to be found. zenohd re-scouts on a 1s->8s
/// backoff, so this is several asks, not one.
const DIAL_BUDGET: Duration = Duration::from_secs(30);
/// How long the PEER arm is watched for a dial that must not arrive. Shorter
/// than the positive budget on purpose — it is spent in full on every run.
const NO_DIAL_BUDGET: Duration = Duration::from_secs(20);

/// One node under test. Every field but `mode` is shared by both arms, which is
/// what makes the pair a control rather than two experiments.
struct Arm {
    /// The value of `mode` in the staged document — the whole independent
    /// variable between the arms.
    mode: &'static str,
    name: &'static str,
    /// PER-PROCESS zid prefixes. zenoh dedupes scouted peers by zid, so a FIXED
    /// zid shared with a leftover or a concurrent copy of this test makes zenohd
    /// skip the dial — a failure with a healthy responder and a real Hello.
    wz_zid_prefix: &'static str,
    zenohd_zid_prefix: &'static str,
    /// The role this arm's document must produce in the node's OWN responder
    /// banner. A PRECONDITION, never the claim: it is what the file asked for,
    /// and asserting it is what stops an arm from silently becoming the other.
    banner_role: &'static str,
    /// Whether a foreign scouter asking only for ROUTERS must reach this node.
    expect_dial: bool,
}

impl Arm {
    /// Stage this arm's config document and return the argv that starts the
    /// demo with it and nothing else.
    ///
    /// ONE stock zenoh document, in upstream's own keys. The endpoint is
    /// `tcp/127.0.0.1:0` so the kernel picks the port; the scouting block names
    /// zenoh's default group, which is where the zenohd below will look.
    fn argv(&self, zid_hex: &str, dir: &std::path::Path) -> Vec<String> {
        let path = dir.join(format!("{}.json5", self.wz_zid_prefix));
        std::fs::write(
            &path,
            format!(
                r#"{{
  // The two documents differ in exactly this word.
  mode: "{}",
  id: "{zid_hex}",
  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
  scouting: {{ multicast: {{ enabled: true, listen: true,
                           address: "{DEFAULT_SCOUT_SOCKET}" }} }},
}}
"#,
                self.mode
            ),
        )
        .unwrap_or_else(|e| panic!("{}: staging the config file: {e}", self.name));
        vec![String::from("--config"), path.display().to_string()]
    }
}

/// What one arm's run produced: what wz said about itself, and the face line
/// from the pinned zenohd if one ever came up.
struct Outcome {
    advertised: String,
    banner: String,
    face: Result<String, String>,
    wz_alive_at_end: bool,
    zenohd_alive_at_end: bool,
}

// wz-proves: scouting-responder zenohd->wz
// wz-proves: scouting-multicast zenohd->wz
// wz-proves: router-hat-router zenohd->wz
//
// The SAME three atoms the argv sibling claims, and that is the point rather
// than a duplication: an atom's proof is a claim about a REACHABLE path, and
// until this file the only path a foreign adjudicator had walked to them was
// wz's own command line. The spelling an operator uses is a different path to
// the same behaviour, and item 515 exists because nothing had walked it.
//
// No atom is claimed for the config READER itself: `zenoh-config` is not in the
// inventory, so naming one would be inventing vocabulary. That is the same
// registration gap `config_verdict_zenohd_interop.rs` records for itself.
//
// ONE direction, for the reason the sibling states: the Scout is zenohd's and
// the Hello is wz's, so zenohd's consumption of a wz Hello is witnessed (it
// dials a port it was told only there) while wz's decode of zenohd's Scout
// proves nothing about zenohd's ENCODER.
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + \
            wz-ap-demo[+router-hat-router,routing-peer,scouting-responder,zenoh-config] \
            and a multicast route; runs via --ignored"]
fn a_stock_zenohd_scouting_for_routers_dials_a_wz_router_selected_by_a_config_file() {
    let demo = wz_ap_demo_binary();
    // A demo built before the config path existed reproduces the exact red this
    // test detects and sends the diagnosis hunting in the responder for a defect
    // that is in the build.
    assert_demo_binary_newer_than_sources(&demo);

    let staging = tempfile::tempdir().expect("a directory for the two config documents");

    let arms = [
        Arm {
            mode: "router",
            name: "--config <mode: router>",
            wz_zid_prefix: "7307",
            zenohd_zid_prefix: "2e10",
            banner_role: "as router",
            expect_dial: true,
        },
        // THE CONTROL. See the module doc: it is what makes the router-only
        // narrowing observable instead of assumed.
        Arm {
            mode: "peer",
            name: "--config <mode: peer>",
            wz_zid_prefix: "7308",
            zenohd_zid_prefix: "2e11",
            banner_role: "as peer",
            expect_dial: false,
        },
    ];

    // Every arm's outcome is collected BEFORE any assertion, so one arm's
    // failure still reports what the other did — "the router was not found" and
    // "nothing on this host can scout at all" are different diagnoses.
    let mut outcomes: Vec<(&Arm, Outcome)> = Vec::new();
    for arm in &arms {
        // EIGHT bytes, matching the sibling leg: a wz-encoded zid length no
        // foreign decoder in this tree had been handed before that round.
        let wz_zid_hex = per_process_zid_hex(arm.wz_zid_prefix, 8);
        let argv = arm.argv(&wz_zid_hex, staging.path());
        let capture = tempfile::tempfile().expect("tempfile for the wz node's stderr");
        let writer = capture.try_clone().expect("dup the wz stderr handle");
        let mut capture = capture;
        let mut wz = ChildGuard::wrap(
            arm.name,
            Command::new(&demo)
                .args(&argv)
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {} {argv:?}: {e}", demo.display())),
        );

        // Readiness in the order the node reaches it: the advertise decision
        // first (the locator the Hello will carry), then the group join. Both
        // through the LIVENESS-AWARE wait, so a node that aborts on its config
        // is reported as a corpse carrying its own message.
        //
        // Waiting for the join BEFORE zenohd starts is not politeness: zenohd's
        // first Scout leaves within milliseconds of startup and nothing
        // retransmits that datagram.
        let advertised = wait_for_capture_alive(
            wz.child_mut(),
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
                wz.child_mut(),
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

        let (advertised, banner) = match (advertised, banner) {
            (Ok(a), Some(b)) => (a, b),
            (Ok(_), None) => {
                let captured = read_captured(&mut capture);
                let _ = wz.child_mut().kill();
                let _ = wz.child_mut().wait();
                panic!(
                    "{} arm: the node advertised a locator but never joined the \
                     scouting group; without the join there is no responder and \
                     the run below would be measuring zenohd alone\n\
                     --- captured output ---\n{captured}",
                    arm.name
                );
            }
            (Err(e), _) => {
                let _ = wz.child_mut().kill();
                let _ = wz.child_mut().wait();
                panic!("{} arm: {e}", arm.name);
            }
        };

        // A real zenohd, configured exactly as the sibling leg configures it —
        // `--cfg` because zenohd has no `--mode` flag, PEER because a router's
        // multicast autoconnect default is the EMPTY list, and the ONE narrowed
        // key that puts a client's question on a process that behaves like a
        // peer.
        let zenohd_zid_hex = per_process_zid_hex(arm.zenohd_zid_prefix, 4);
        let zenohd_zid = configured_zid_value(&zenohd_zid_hex);
        let zenohd_id_cfg = format!("id:\"{zenohd_zid_hex}\"");
        let (mut zenohd, _zenohd_port) = spawn_zenohd_multicast_scouting_with_args(
            "zenohd (peer, scouts for ROUTERS and autoconnects)",
            &[
                "--cfg",
                r#"mode:"peer""#,
                // THE NARROWING. One key, to the value upstream itself gives a
                // client on the same line of the same file.
                "--cfg",
                r#"scouting/multicast/autoconnect:{"peer":["router"]}"#,
                "--cfg",
                &zenohd_id_cfg,
            ],
        );

        // The face this arm is about: an INBOUND accept whose remote is the
        // zenohd THIS arm pinned. Read by VALUE rather than by shape — a stray
        // wz or zenohd on the host's default group could otherwise stand in for
        // the foreign witness, or forge the negative's failure.
        let budget = if arm.expect_dial {
            DIAL_BUDGET
        } else {
            NO_DIAL_BUDGET
        };
        let face = wait_for_capture_alive(
            wz.child_mut(),
            &mut capture,
            budget,
            "an inbound face from the pinned zenohd",
            |captured| {
                captured
                    .lines()
                    .find(|l| l.contains(" UP (peer ") && face_zid_value(l) == Some(zenohd_zid))
                    .map(str::to_string)
            },
        );

        // Liveness at the END, and it is what makes the NEGATIVE arm an
        // observation rather than an absence.
        let wz_alive_at_end = matches!(wz.child_mut().try_wait(), Ok(None));
        let zenohd_alive_at_end = matches!(zenohd.child_mut().try_wait(), Ok(None));

        let _ = zenohd.child_mut().kill();
        let _ = zenohd.child_mut().wait();
        let _ = wz.child_mut().kill();
        let _ = wz.child_mut().wait();

        outcomes.push((
            arm,
            Outcome {
                advertised,
                banner,
                face,
                wz_alive_at_end,
                zenohd_alive_at_end,
            },
        ));
    }

    for (arm, outcome) in &outcomes {
        let Outcome {
            advertised,
            banner,
            face,
            wz_alive_at_end,
            zenohd_alive_at_end,
        } = outcome;

        assert!(
            advertised.starts_with("tcp/127.0.0.1:"),
            "{} arm: expected an ephemeral tcp advertise, got {advertised:?}",
            arm.name
        );
        assert!(
            banner.contains(DEFAULT_SCOUT_SOCKET),
            "{} arm: the responder must join zenoh's default scouting socket, \
             which is the only place an unconfigured zenohd looks; banner: {banner}",
            arm.name
        );
        // The banner is what the DOCUMENT asked for — a precondition, never the
        // claim; see `Arm::banner_role`. It is doing more work here than in the
        // argv sibling: there a wrong role would mean a wrong flag, here it
        // would mean the file's `mode` was not read at all, which is exactly the
        // failure this leg exists to be able to see.
        assert!(
            banner.contains(arm.banner_role),
            "{} arm: the node came up in the wrong role, so the config document's \
             `mode` did not select it and this arm is not the arm it is named; \
             banner: {banner}",
            arm.name
        );
        assert!(
            *zenohd_alive_at_end,
            "{} arm: the zenohd died during the window, so nothing here is a \
             statement about what it read",
            arm.name
        );
        assert!(
            *wz_alive_at_end,
            "{} arm: the wz node died during the window, so nothing here is a \
             statement about what it advertised",
            arm.name
        );

        match (arm.expect_dial, face) {
            // THE CLAIM. A stock zenoh node asking only for ROUTERS found a wz
            // node whose role came out of a FILE, and connected to the port that
            // node's own Hello advertised.
            (true, Ok(line)) => {
                assert!(
                    line.contains("(peer 127.0.0.1:"),
                    "{} arm: the face must be an inbound accept on loopback, \
                     which is the only address the document asked for: {line}",
                    arm.name
                );
                assert!(
                    line.contains("whatami Some(Peer)"),
                    "{} arm: the connecting node must present itself as the peer \
                     its autoconnect default came from: {line}",
                    arm.name
                );
            }
            (true, Err(e)) => panic!(
                "{} arm: a stock zenohd scouting for ROUTERS did not dial a wz \
                 router selected by a config file. wz advertised {advertised} and \
                 joined {DEFAULT_SCOUT_SOCKET}, and the spawn helper does not \
                 return until zenohd has announced its own scout listener — so \
                 the failure is downstream of the ask: what the Hello said, or \
                 the accept: {e}",
                arm.name
            ),
            // THE CONTROL. Its Err is the outcome, and the liveness assertions
            // above are what stop it from being satisfied by a dead run.
            (false, Err(_)) => {}
            (false, Ok(line)) => panic!(
                "{} arm: a scouter asking ONLY for routers dialled a wz node whose \
                 document said `mode: \"peer\"`. Either the narrowed \
                 `scouting/multicast/autoconnect` never applied — in which case \
                 the router arm proves only that zenohd dials whatever it finds — \
                 or the document's role never reached the Hello: {line}",
                arm.name
            ),
        }
    }
}
