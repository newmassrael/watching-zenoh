// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y700 — the replay binary, driven with a real capture.
//!
//! The engine's own tests build `Samples` by hand, which proves the schedule
//! and the mutations and proves nothing about whether a CAPTURE yields any. A
//! library nobody runs hides its own lies (R311y664), and the lie available
//! here is the extraction: a plan of zero emissions is what both a broken
//! walker and an empty capture produce.

use std::path::PathBuf;
use std::process::Command;

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("wz-replay-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).expect("a fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// R311y700 ([REDACTED-REQ]) — A REAL CAPTURE YIELDS A REAL PLAN, at the command line.
///
/// ## What this proves that the engine's tests cannot
///
/// The engine is driven by `Samples` a test built. This drives the EXTRACTION:
/// a pcapng holding a zenoh reply is read, its keyexpr and payload are
/// recovered by the same walk the field layer uses, and the plan names both.
/// A walker that recovered nothing produces a plan of zero emissions, which is
/// also what an empty capture produces — so the assertion is on the CONTENT.
#[test]
fn a_capture_yields_a_plan_naming_its_keyexpr_and_its_payload_length() {
    let scratch = Scratch::new("plan");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("`demo/a` 5 byte(s)"),
        "the sample's keyexpr and its payload length come out of the capture: {text}"
    );
    assert!(text.contains("1 emission(s)"), "{text}");
    assert!(
        text.contains("0 mutated"),
        "and nothing was mutated without --fuzz: {text}"
    );
}

/// R311y716 ([REDACTED-REQ]) — the ALERT reaches the command line, with its reasons.
///
/// The delivery half of the requirement. What this proves that the module's own
/// tests cannot: the verdict an operator gets is computed from a real capture
/// read by the real binary, not from an `Outcome` a test built -- so a reason
/// that stops reaching the verdict, or a flag nothing acts on, fails here.
#[test]
fn an_incomplete_capture_raises_an_alert_naming_why() {
    let scratch = Scratch::new("alert");
    // A record referencing a keyexpr id this capture never saw declared: read,
    // attributed to nothing, and therefore a row total that is short.
    let capture = scratch.write("aliased.pcapng", &fixture::aliased_capture(false));

    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--alert")
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("unresolved_records"),
        "the alert names the leg that is short: {text}"
    );
    assert!(text.contains("wz/alert"), "and the default key: {text}");
    assert!(
        text.contains("NOT SENT"),
        "an alert with nowhere to go must say it did not go: {text}"
    );

    // The operator's own key reaches it.
    let keyed = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--alert")
        .arg("--alert-key")
        .arg("site/health")
        .output()
        .expect("runs");
    let keyed = String::from_utf8_lossy(&keyed.stdout).into_owned();
    assert!(keyed.contains("site/health"), "{keyed}");
    assert!(
        !keyed.contains("wz/alert"),
        "and REPLACES the default: {keyed}"
    );
}

/// R311y716 ([REDACTED-REQ]) — an alert REFUSES the options that shape a replay.
///
/// The rule this workspace settled after measuring the alternative: an option a
/// tool reads and nothing acts on is worse than one it rejects, because the
/// operator who typed it believes it took effect. `--fuzz` has nothing to
/// mutate when the payload is a verdict this run just computed.
#[test]
fn an_alert_refuses_the_options_that_would_shape_a_replay() {
    let scratch = Scratch::new("alert-refuse");
    let capture = scratch.write("aliased.pcapng", &fixture::aliased_capture(false));

    let refused = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--alert")
        .arg("--fuzz")
        .arg("flip:0")
        .output()
        .expect("runs");
    assert_eq!(refused.status.code(), Some(2), "it must not run");
    let why = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        why.contains("--fuzz"),
        "and it must name what it refused: {why}"
    );
    assert!(
        String::from_utf8_lossy(&refused.stdout).is_empty(),
        "nothing may be printed as though it had run"
    );

    // And the mirror: a key with no alert to send is equally a mistake.
    let orphan_key = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--alert-key")
        .arg("site/health")
        .output()
        .expect("runs");
    assert_eq!(orphan_key.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&orphan_key.stderr).contains("--alert"));
}

/// R311y700 ([REDACTED-REQ]) — the SPEED reaches the plan from the command line.
///
/// The engine proves the arithmetic; this proves the flag is wired to it. A
/// flag the parser reads and nothing acts on is the defect R311y669 shipped and
/// R311y670 had to close.
#[test]
fn the_speed_and_gap_options_reach_the_plan() {
    let scratch = Scratch::new("speed");
    let capture = scratch.write("reply.pcapng", &fixture::two_sample_capture());

    let run = |args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
                .arg(&capture)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    let normal = run(&["--gap", "200"]);
    assert!(normal.contains("1: +200 ms"), "{normal}");
    let fast = run(&["--gap", "200", "--speed", "4"]);
    assert!(
        fast.contains("1: +50 ms"),
        "four times as fast is a quarter of the gap: {fast}"
    );
    // AND THE TOTAL follows, which is the number an operator checks before
    // starting a replay.
    assert!(normal.contains("200 ms total"), "{normal}");
    assert!(fast.contains("50 ms total"), "{fast}");
}

/// R311y700 ([REDACTED-REQ]) — `--fuzz` reaches the payload, and the plan says which
/// emissions it changed.
#[test]
fn the_fuzz_option_mutates_the_payload_and_the_plan_says_so() {
    let scratch = Scratch::new("fuzz");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());

    let out = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&capture)
            .arg("--fuzz")
            .arg("truncate:2")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        out.contains("`demo/a` 2 byte(s) MUTATED (was 5)"),
        "the row carries the mutated length and the captured one: {out}"
    );
    assert!(out.contains("1 mutated"), "{out}");

    // A --fuzz spec this build cannot read is a usage error rather than a run
    // that quietly sends the captured bytes.
    let bad = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--fuzz")
        .arg("rotate:3")
        .output()
        .expect("runs");
    assert_eq!(bad.status.code(), Some(2));
}

/// R311y700 ([REDACTED-REQ]) — a speed that cannot be played is refused at the command
/// line, before anything is read.
#[test]
fn a_speed_of_zero_is_refused_at_the_command_line() {
    let scratch = Scratch::new("speed-zero");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--speed")
        .arg("0")
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("greater than zero"));
}

/// R311y701 (RP2) — A DATAGRAM CAPTURE YIELDS SAMPLES, and before this round it
/// yielded NONE.
///
/// ## The defect, measured
///
/// `wz_analyze::samples` walked `dissection.flows()`, which is the TCP half of a
/// capture. A multicast or UDP-unicast capture therefore produced an empty plan
/// — and an empty plan is exactly what a capture holding no application traffic
/// produces, so the tool reported "nothing to replay" about a file full of it.
///
/// ## Why the assertion is on the CONTENT
///
/// `1 emission(s)` alone would pass on a walker that invented one. The keyexpr
/// is `demo/dgram`, which appears nowhere but inside the UDP payload of this
/// fixture, and the byte count is the payload's.
#[test]
fn a_datagram_capture_yields_its_samples() {
    let scratch = Scratch::new("datagram");
    let capture = scratch.write("dgram.pcapng", &fixture::datagram_capture());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("1 emission(s)"),
        "the datagram half of a capture contributes samples: {text}"
    );
    assert!(
        text.contains("`demo/dgram` 5 byte(s)"),
        "and they are THESE samples, read out of the UDP payload rather than \
         invented: {text}"
    );
    assert!(
        !text.contains("could not be reached"),
        "with nothing out of reach on a capture this reader parses twice \
         consistently: {text}"
    );
}

/// R311y701 (RP3) — `--side` narrows the plan to ONE HALF of the conversation,
/// and the plan says what it left out.
///
/// ## Why the field needed a consumer
///
/// `Sample::direction` was recorded in R311y700 and read by nobody. Replaying
/// both halves of a captured conversation re-publishes the peer's answers as
/// though this node had said them, which is not a replay of a client — so the
/// axis existed in the data and could not be acted on.
///
/// ## Why the exclusion count is asserted
///
/// A plan of zero emissions is the same page whether the capture was empty or
/// the selector took nothing, and those send a reader to opposite places.
#[test]
fn the_side_selector_takes_one_half_of_the_conversation_and_says_what_it_left() {
    let scratch = Scratch::new("side");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());

    let run = |args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
                .arg(&capture)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    // The fixture's one sample travels from the high endpoint to the low one,
    // which the field listing prints as B.
    let kept = run(&["--side", "B"]);
    assert!(
        kept.contains("1 emission(s)") && kept.contains("`demo/a`"),
        "the half that carried it is taken: {kept}"
    );
    assert!(
        !kept.contains("did not take them"),
        "and nothing was excluded: {kept}"
    );

    let dropped = run(&["--side", "A"]);
    assert!(
        dropped.contains("0 emission(s)"),
        "the other half takes nothing: {dropped}"
    );
    assert!(
        dropped.contains("1 sample(s) the capture held are not in this plan"),
        "and the plan SAYS the capture held a sample the selection refused -- \
         without it this page is indistinguishable from an empty capture: \
         {dropped}"
    );

    // A side letter this tool does not know is a usage error, not a silent
    // both-halves run: a reader who typed `--side client` and got everything
    // replayed would believe they had narrowed it.
    let bad = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--side")
        .arg("client")
        .output()
        .expect("runs");
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("--side needs A or B"));
}

/// R311y702 ([REDACTED-REQ]) — `--connect` BEHAVES DIFFERENTLY IN THE TWO BUILDS, and
/// this one test says how in both.
///
/// ## Why one test rather than two
///
/// The refusal only exists where `live` is off and the dial only exists where
/// it is on, so a test of either alone is a test that does not run in the other
/// build — the "population of zero is green" shape this workspace has measured
/// more than once. Written as a difference, the `--no-default-features` lane
/// checks the refusal and the default lane checks the dial, from one name.
///
/// ## Why port 1
///
/// Nothing listens there, so the DIAL fails fast and deterministically. The
/// claim is not about a successful session -- `tests/live.rs` makes that one
/// against a real peer -- it is that the flag reaches a dial at all rather than
/// being parsed and dropped, which is the defect R311y669 shipped and R311y670
/// had to close.
#[test]
fn the_connect_flag_dials_where_live_is_on_and_is_refused_where_it_is_off() {
    let scratch = Scratch::new("connect");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--connect")
        .arg("tcp/127.0.0.1:1")
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    // Both builds refuse to exit zero, and both print the plan first: an
    // operator sees what WOULD go out before being told it did not.
    assert_eq!(out.status.code(), Some(2), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 emission(s)"), "{stdout}");

    if cfg!(feature = "live") {
        assert!(
            stderr.contains("did not open a session"),
            "the flag must reach a real dial, and the failure must be the \
             PEER's rather than this tool's parsing: {stderr}"
        );
    } else {
        assert!(
            stderr.contains("needs the `live` feature"),
            "a build that cannot send must SAY so rather than printing a plan \
             and exiting zero: {stderr}"
        );
        assert!(
            stderr.contains("Nothing was sent"),
            "and say it in the words an operator acts on: {stderr}"
        );
    }
}

/// R311y703 (RP4) — `--timing capture` REPLAYS THE PACE THE CAPTURE RECORDED,
/// driven through the binary against a real two-packet capture.
///
/// ## What the engine's own tests cannot reach
///
/// They build `Sample`s with capture times by hand, which proves the
/// arithmetic. This proves the EXTRACTION: that a real pcapng's per-packet
/// clock reaches a stream sample at all. Two rounds said it could not --
/// R311y700 in a doc and R311y702 in a carry -- on the argument that a stream
/// message's anchor is a byte offset. `FlowDissection::packet_for` maps that
/// offset to the packet that carried it, and this is the run that says so.
///
/// ## Anti-vacuity
///
/// The same capture is replayed under the DECLARED schedule, which must print
/// the flat gap. Without that control, `350` would be a number this test
/// asserts about a build that reads no timestamps at all -- it would only have
/// to print the default 100 for both, and 350 would never appear.
#[test]
fn the_timing_option_replays_the_pace_the_capture_recorded() {
    let scratch = Scratch::new("timing");
    let capture = scratch.write("two-packets.pcapng", &fixture::two_packet_capture());

    let run = |args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
                .arg(&capture)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    let declared = run(&[]);
    assert!(
        declared.contains("2 emission(s)"),
        "the fixture must yield both samples, or the pacing claim is about an \
         empty plan: {declared}"
    );
    assert!(
        declared.contains("1: +100 ms") && !declared.contains("(capture)"),
        "ANTI-VACUITY: the default is still the declared gap, unnamed: {declared}"
    );

    let measured = run(&["--timing", "capture"]);
    assert!(
        measured.contains("1: +350 ms"),
        "the two packets are 1_000_000 and 1_350_000 microseconds apart, and \
         that interval is what the replay reproduces: {measured}"
    );
    assert!(
        measured.contains("(capture)"),
        "and the row SAYS which clock it used, because a plan that mixed the \
         two silently would report a timing it did not reproduce: {measured}"
    );
    assert!(
        measured.contains("350 ms total"),
        "the total an operator checks follows the same clock: {measured}"
    );

    // SPEED scales the measured gap, which is what makes it a schedule rather
    // than a recording.
    let fast = run(&["--timing", "capture", "--speed", "2"]);
    assert!(fast.contains("1: +175 ms"), "{fast}");

    // A mode this tool does not know is a usage error, not a silent fallback to
    // the declared gaps -- the rule `--side` and `--payload-format` settled.
    let bad = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--timing")
        .arg("real")
        .output()
        .expect("runs");
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("`declared` or `capture`"));
}

/// R311y704 — `--max-total` REFUSES a plan that would run too long, at the
/// command line, after printing it.
///
/// The engine proves the arithmetic and the message; this proves the flag is
/// wired to a real exit code, and that the plan is still PRINTED — an operator
/// who hits the ceiling must be able to see what was too long, or the refusal
/// leaves them with a number and nothing to narrow.
#[test]
fn the_max_total_option_refuses_a_plan_that_would_run_too_long() {
    let scratch = Scratch::new("max-total");
    let capture = scratch.write("two.pcapng", &fixture::two_sample_capture());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--gap")
        .arg("500")
        .arg("--max-total")
        .arg("100")
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_eq!(out.status.code(), Some(2), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("2 emission(s)") && stdout.contains("500 ms total"),
        "the plan is PRINTED before it is refused: {stdout}"
    );
    assert!(
        stderr.contains("over the --max-total of 100 ms"),
        "and the refusal names both numbers: {stderr}"
    );

    // THE CONTROL. The same capture and gap without the ceiling exits clean, so
    // the refusal is the ceiling rather than anything else about this run.
    let ok = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--gap")
        .arg("500")
        .output()
        .expect("runs");
    assert_eq!(ok.status.code(), Some(0));
}

/// R311y704 (PF2 follow-up) — THE REPLAYABLE FRACTION OF A CAPTURE, measured.
///
/// R311y701 taught the extraction to resolve a keyexpr named by numeric id, and
/// its own carry recorded that this moves an unknown number of messages out of
/// `Samples::unresolved` and into the plan — with no witness to how many. A
/// capability whose effect nobody measures is one a later round can silently
/// undo.
///
/// So: the SAME capture, with and without the declaration its aliases resolve
/// through. Without it the message is honestly refused and counted; with it,
/// it is in the plan under the name the declaration bound.
#[test]
fn a_declaration_moves_a_message_out_of_the_floor_and_into_the_plan() {
    let scratch = Scratch::new("floor");

    let undeclared = scratch.write("undeclared.pcapng", &fixture::aliased_capture(false));
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&undeclared)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        text.contains("0 emission(s)"),
        "an id this capture never bound is not replayable under any name: {text}"
    );
    assert!(
        text.contains("1 message(s) carried a payload whose keyexpr is a numeric id"),
        "and the plan states that floor rather than being silently short: {text}"
    );

    let declared = scratch.write("declared.pcapng", &fixture::aliased_capture(true));
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&declared)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        text.contains("1 emission(s)") && text.contains("`demo/sensor`"),
        "with the declaration the capture carried, the same message replays \
         under the name that declaration bound: {text}"
    );
    assert!(
        !text.contains("numeric id"),
        "and the floor it was in is gone: {text}"
    );
}

/// R311y888 (open-debt item 363) — THE SHARED FIXTURES BUILD HEALTHY CAPTURES,
/// on both checksum axes, across every capture this module ships.
///
/// # Why every fixture and not one
///
/// `fixture/mod.rs` has two packet builders and six captures assembled from
/// them, and the captures differ in which builder and how many packets. A
/// witness over one of them would hold the builders and not the assembly —
/// `datagram_capture` reaches the UDP path, where a zero checksum is a sender
/// DECLINING rather than a mistake, and only a test that reads every capture
/// separates "declined" from "wrong" across the set.
///
/// # Why this file needed a witness at all
///
/// These builders already compute both sums. What they lacked is anything that
/// would notice if they stopped: every assertion in this file is about the
/// PLAN a capture yields, and a corrupt checksum moves none of it. That is the
/// state open-debt item 357 was found in — correct code with no witness, two
/// crates over — and it stood for months.
#[test]
fn every_fixture_capture_is_checksum_clean() {
    for (name, bytes) in [
        ("clean", fixture::clean_capture()),
        ("reply", fixture::reply_capture()),
        ("two_sample", fixture::two_sample_capture()),
        ("aliased", fixture::aliased_capture(true)),
        ("two_packet", fixture::two_packet_capture()),
        ("datagram", fixture::datagram_capture()),
    ] {
        let d = wz_capture::Dissection::from_pcapng(&bytes)
            .unwrap_or_else(|e| panic!("{name} must parse: {e:?}"));
        let h = d.health();
        assert_eq!(
            (h.ip_checksum_invalid, h.transport_checksum_invalid),
            (0, 0),
            "{name}: a fixture that ships a wrong checksum makes every capture \
             it builds read as corrupt"
        );
        assert!(
            h.ip_checksum_valid > 0,
            "{name}: the IPv4 axis must have VERIFIED something, or the zeros \
             above say only that nothing was checked"
        );
        // The transport axis is NOT asserted non-zero for every capture: the
        // datagram one is UDP, where a zero checksum is RFC 768's declining
        // form and reads as ABSENT. Demanding a verified sum there would be
        // demanding the fixture stop expressing that case.
        assert!(
            h.transport_checksum_valid > 0 || h.transport_checksum_absent > 0,
            "{name}: the transport axis must have reached a verdict at all"
        );
    }
}

mod fixture;
