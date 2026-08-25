// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2094 (open-debt item 510) — a stock zenohd SCOUTING FOR ROUTERS discovers a
//! wz `--router-hat` and dials the locator that router's own Hello advertised.
//!
//! ## Why this file exists beside `zenohd_scouts_wz_interop.rs`
//!
//! R2089 (item 222) made wz's ROUTER run-mode answer a Scout, and R2091 (item
//! 508) made a stock config file able to select that run-mode. Both were proven
//! by `wz_router_hat_answers_a_scout.rs`, whose scouter AND whose dissector are
//! this tree's own code — so what they establish is that wz understands wz.
//! That is not a replacement claim, and A4-3 refuses that file a cross-impl
//! marker for exactly this reason.
//!
//! The foreign half of the responder subsystem was the PEER mode only: the
//! sibling leg builds the demo `--features scouting-responder,routing-peer`, a
//! binary that has no `--router-hat` in it at all. So the role a stock zenoh
//! network actually looks for — a client's `scouting/multicast/autoconnect`
//! default is `["router"]`, `DEFAULT_CONFIG.json5:149` in the pinned checkout —
//! had never had its Hello read by anything but wz.
//!
//! ## What makes the dial ROLE-DEPENDENT rather than merely a dial
//!
//! zenohd runs `mode: "peer"`, whose `scouting/multicast/autoconnect` default is
//! `["router", "peer"]` — a list that dials a wz node whichever role its Hello
//! claims. That would witness "zenohd found wz", not "zenohd read `router` off
//! wz's Hello". So this leg NARROWS that one key to the CLIENT default from the
//! same line of the same upstream file, `["router"]`, and nothing else about
//! zenohd is touched. Upstream reads that list twice from one value
//! (`AutoConnect::multicast`, `zenoh/src/net/common.rs:16-26`): it is the `what`
//! of the Scout zenohd emits, and it is the matcher
//! `should_autoconnect(hello.zid, hello.whatami)` applies to every Hello that
//! comes back (`orchestrator.rs:1103`). A wz Hello that said `peer` therefore
//! fails the second gate in foreign code, and no face comes up.
//!
//! NOTHING here names wz: no `-e`, no `--connect`, no endpoint, no zid of wz's.
//! The port wz is reachable on is chosen by the KERNEL (`tcp/127.0.0.1:0`), so
//! the only path from that port to zenohd's dialer runs through the Hello.
//!
//! ## Why the PEER arm is in the SAME test
//!
//! The narrowing above is the whole strength of the router arm, and a narrowing
//! that silently failed to apply would leave a green test measuring the weaker
//! claim. So the control is the same binary, the same scouting group, the same
//! zenohd argv, with ONE word of the wz argv changed: `--peer`. Under a
//! router-only scouter that node must NOT be dialled. If the `--cfg` were inert,
//! zenohd's peer default would dial it and this arm reds; if multicast were dead
//! on the host, the router arm reds first. Neither arm can be green for a reason
//! the other one shares.
//!
//! Measured 2026-08-24 on this tree, before the leg was written: the router arm
//! answers three Scouts and takes a face; the peer arm answers NONE, because
//! zenohd's Scout carries `what = router` and wz's own responder gate refuses
//! it. The negative is therefore doubly caused — refused at wz's gate, and
//! unmatched at zenohd's — and the assertion below reads the half that is
//! foreign-decided: no face from THIS zenohd's pinned zid.
//!
//! ## The zid width
//!
//! wz's zid here is EIGHT bytes, and that is a third value for
//! `SCOUTING_E2E_ZID_WIDTHS`, not decoration. A Hello's zid length rides in a
//! nibble; the suite's two existing foreign witnesses pin 16 (zenohd's, read by
//! wz) and 4 (wz's, read by zenohd). Eight is a wz-encoded length no foreign
//! decoder in this tree had ever been handed.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): zenohd is an external binary and the
//! scouting group is a real multicast socket. Needs the demo built with
//! `router-hat-router` + `scouting-responder` (that lane builds it;
//! `router-hat-router` pulls `routing-peer` transitively, which is what compiles
//! the `--peer` control arm into the same binary).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, configured_zid_value, face_zid_value,
    per_process_zid_hex, read_captured, spawn_zenohd_multicast_scouting_with_args,
    wait_for_capture_alive, wz_ap_demo_binary, ChildGuard,
};

const RESPONDER_NEEDLE: &str = "SCOUT RESPONDER listening on ";
const ADVERTISED_NEEDLE: &str = "ADVERTISED SELF LOCATOR ";
/// The group an unconfigured zenoh node looks on (`DEFAULT_CONFIG.json5:140`).
/// Spelled out because a responder that joined somewhere else is perfectly
/// healthy and completely undiscoverable.
const DEFAULT_SCOUT_SOCKET: &str = "224.0.0.224:7446";

/// How long the ROUTER arm may take to be found. zenohd re-scouts on a 1s->8s
/// backoff (`SCOUT_INITIAL_PERIOD`, `orchestrator.rs:46`), so this is several
/// asks, not one.
const DIAL_BUDGET: Duration = Duration::from_secs(30);
/// How long the PEER arm is watched for a dial that must not arrive. Shorter
/// than the positive budget on purpose — it is spent in full on every run.
const NO_DIAL_BUDGET: Duration = Duration::from_secs(20);

/// One node under test: the run-mode it is started in, the identities the two
/// processes pin, and whether the foreign scouter is supposed to dial it.
struct Arm {
    /// The run-mode flag — the whole independent variable between the arms.
    flag: &'static str,
    name: &'static str,
    /// PER-PROCESS zid prefixes. zenoh dedupes scouted peers by zid
    /// (`connect_peer` returns early on "Already connected scouted peer",
    /// `orchestrator.rs:1029-1054`), so a FIXED zid shared with a leftover or a
    /// concurrent copy of this test makes zenohd skip the dial — a failure with
    /// a healthy responder and a real Hello, which is the least diagnosable
    /// shape this suite has recorded.
    wz_zid_prefix: &'static str,
    zenohd_zid_prefix: &'static str,
    /// The role this arm's run-mode must announce in its OWN responder banner.
    /// A PRECONDITION, never the claim: it is what the node intended, and
    /// R311y471's blind spot was a place where only the intent was checked.
    /// Asserting it here is what stops an arm from silently becoming the other
    /// arm — which is the one way this pair could agree by accident.
    banner_role: &'static str,
    /// Whether a foreign scouter asking only for ROUTERS must reach this node.
    expect_dial: bool,
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
// ONE direction, for the reason the sibling leg states: the Scout is zenohd's
// and the Hello is wz's, so zenohd's consumption of a wz Hello is witnessed (it
// dials a port it was told only there) while wz's decode of zenohd's Scout
// proves nothing about zenohd's ENCODER — wz reading it is the wz->wz half of
// the same parse.
//
// `router-hat-router` is claimed here and not in the R2089 wz<->wz file because
// this is the atom's first foreign witness on the DISCOVERY plane: its existing
// zenohd adjudicators all dial or are dialled at an endpoint the test hands
// over, and none of them establish that the run-mode is FINDABLE.
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + \
            wz-ap-demo[+router-hat-router,scouting-responder] and a multicast \
            route; runs via --ignored"]
fn a_stock_zenohd_scouting_for_routers_dials_the_wz_router_hat_and_not_the_wz_peer() {
    let demo = wz_ap_demo_binary();
    // A demo built before R2089 has no `--scout-listen` on `--router-hat` at
    // all, so a stale binary does not weaken this proof — it reproduces the
    // exact red the test is written to detect, and sends the diagnosis hunting
    // in the responder for a defect that is in the build.
    assert_demo_binary_newer_than_sources(&demo);

    let arms = [
        Arm {
            flag: "--router-hat",
            name: "--router-hat",
            wz_zid_prefix: "7207",
            zenohd_zid_prefix: "2e0e",
            banner_role: "as router",
            expect_dial: true,
        },
        // THE CONTROL. See the module doc: it is what makes the router-only
        // narrowing observable instead of assumed.
        Arm {
            flag: "--peer",
            name: "--peer",
            wz_zid_prefix: "7208",
            zenohd_zid_prefix: "2e0f",
            banner_role: "as peer",
            expect_dial: false,
        },
    ];

    // Every arm's outcome is collected BEFORE any assertion, so one arm's
    // failure still reports what the other did — "the router was not found" and
    // "nothing on this host can scout at all" are different diagnoses and only
    // the first is worth a round of hunting.
    let mut outcomes: Vec<(&Arm, Outcome)> = Vec::new();
    for arm in &arms {
        // EIGHT bytes — see the module doc. The value is per-process for the
        // dedupe reason `Arm::wz_zid_prefix` records.
        let wz_zid_hex = per_process_zid_hex(arm.wz_zid_prefix, 8);
        let capture = tempfile::tempfile().expect("tempfile for the wz node's stderr");
        let writer = capture.try_clone().expect("dup the wz stderr handle");
        let mut capture = capture;
        let mut wz = ChildGuard::wrap(
            arm.name,
            Command::new(&demo)
                .arg(arm.flag)
                // The KERNEL picks the port. That is what makes zenohd reaching
                // it evidence rather than coincidence: the number exists in no
                // config, no argv and no compiled-in constant, only in the
                // Hello wz answers with.
                .arg("tcp/127.0.0.1:0")
                .arg("--scout-listen")
                .arg("--zid")
                .arg(&wz_zid_hex)
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {} {}: {e}", demo.display(), arm.flag)),
        );

        // Readiness in the order the node reaches it: the advertise decision
        // first (the locator the Hello will carry), then the group join. Both
        // through the LIVENESS-AWARE wait, so a node that aborts on its argv is
        // reported as a corpse carrying its own message instead of costing the
        // full budget and then being guessed about.
        //
        // Waiting for the join BEFORE zenohd starts is not politeness: zenohd's
        // first Scout leaves within milliseconds of startup and nothing
        // retransmits that datagram, so a missed first beacon would spend budget
        // rather than fail, which is a flake and not a verdict.
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

        // A real zenohd. `--cfg` and not a `--mode` flag because zenohd has
        // none: the mode is a config key and the CLI exposes it only through
        // generic `KEY:JSON5-VALUE` pairs, so the quotes around `peer` are part
        // of the VALUE (a bare `peer` is not a JSON5 string and zenohd rejects
        // the pair).
        //
        // PEER and not ROUTER because a router's multicast autoconnect default
        // is the EMPTY list (`DEFAULT_CONFIG.json5:149`): a default zenohd
        // answers scouts and never dials one. PEER and not CLIENT — whose
        // `["router"]` this arm borrows — because `start_client` never calls
        // `start_scout` (`orchestrator.rs:130-171`), so a client neither
        // announces the scout listener this spawn helper gates on nor keeps
        // re-asking; the narrowed key below is how the client's QUESTION is put
        // on a process that behaves like a peer.
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
        // the foreign witness in the positive arm, or forge the negative's
        // failure in the control arm.
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
        // observation rather than an absence: a control whose wz node or whose
        // zenohd had died would report "no dial" for a reason that has nothing
        // to do with the role on the wire.
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
             which is where an unconfigured zenohd looks; banner: {banner}",
            arm.name
        );
        // The banner is what the run-mode INTENDED — a precondition, never the
        // claim; see `Arm::banner_role`.
        assert!(
            banner.contains(arm.banner_role),
            "{} arm: the node under test came up in the wrong role, so this arm \
             is not the arm it is named; banner: {banner}",
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
            // router it was told nothing about and connected to the port that
            // router's own Hello advertised.
            (true, Ok(line)) => {
                assert!(
                    line.contains("(peer 127.0.0.1:"),
                    "{} arm: the face must be an inbound accept on loopback, \
                     which is the only address wz advertised: {line}",
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
                "{} arm: a stock zenohd scouting for ROUTERS did not dial this \
                 wz router. wz advertised {advertised} and joined \
                 {DEFAULT_SCOUT_SOCKET}, and the spawn helper does not return \
                 until zenohd has announced its own scout listener — so the \
                 failure is downstream of the ask: what the Hello said, or the \
                 accept: {e}",
                arm.name
            ),
            // THE CONTROL. Its Err is the outcome, and the liveness assertions
            // above are what stop it from being satisfied by a dead run.
            (false, Err(_)) => {}
            (false, Ok(line)) => panic!(
                "{} arm: a scouter asking ONLY for routers dialled a wz PEER. \
                 Either the narrowed `scouting/multicast/autoconnect` never \
                 applied — in which case the router arm above proves only that \
                 zenohd dials whatever it finds — or wz's peer Hello claims a \
                 role it does not have: {line}",
                arm.name
            ),
        }
    }
}
