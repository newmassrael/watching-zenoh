// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y481 — the `preset-ap-full` QUERY PLANE, driven against real zenoh-pico.
//!
//! ## The gap this closes, stated as the audit measures it
//!
//! Three atoms in `preset-ap-full` carried a `codec-parity partial` claim and
//! NOTHING else, which means they had never faced a live foreign process at all:
//!
//! | atom | its only prior claim |
//! |---|---|
//! | `query-selector-parameters` | `layer3_request_parameters_byte_equivalent` |
//! | `query-attachment` | `layer3_request_attachment_byte_equivalent` |
//! | `query-reply-err` | `layer3_response_err_byte_equivalent` (+ `_with_encoding`) |
//!
//! A `codec-parity` claim compares wz's encoder against pico's own
//! `_z_request_encode` / `_z_response_encode` over the SAME buffer, in-process
//! via the live FFI. That pins the BYTES and nothing else: it cannot see whether
//! the bytes ever reach a socket, whether a real pico process decodes them, or
//! whether the emit path stages the record at all. This file supplies the missing
//! half for all three — a real pico process printing the decoded value.
//!
//! R311y480 named this bundle as its own next step: the AP-full binary composes
//! all three atoms but `wz-ap-demo` had **no argv that reached them**, so no
//! foreign leg was possible. The CLI surface (`--query-params`,
//! `--query-attachment`, `--reply-err`, `--query-after-ms`) landed with this round
//! for exactly that reason.
//!
//! ## Why the AP-FULL binary and not an in-process wz querier
//!
//! All three atoms are `preset-ap-full`-ONLY — absent from `preset-ap-client`,
//! which is what the default `wz-ap-demo` and most of this crate's own harnesses
//! build. So these legs must drive the composed binary, and that also buys the
//! composition axis R311y480 opened: the atoms are witnessed WITH the other 130+
//! members compiled in, which no narrow lane can express.
//!
//! That is not a theoretical distinction. While standing this file up, the
//! reply-err leg was first run against a `target/debug/wz-ap-demo` that a later
//! `cargo build -p wz-ap-demo` (default features) had overwritten. The ERR reply
//! was ABSENT from the wire — 6 bytes carrying only the `ResponseFinal`, against
//! 41 bytes carrying `Response(Err)` + `ResponseFinal` on the correct binary — and
//! it read exactly like a wz defect. It was the ap-client build behaving correctly
//! with the atom compiled out. Layer E9 therefore builds the preset FIRST and the
//! legs assert a build-discriminating marker (below).
//!
//! ## What pins the build, per leg
//!
//! A leg that passes on the wrong binary certifies nothing, so each names a
//! marker that the ap-client build cannot produce:
//!
//! * The two QUERIER legs gate on wz's own `QUERY EMITTED … params=Some(…)` /
//!   `attachment_pairs=2` line before believing the foreign witness. `--query-params`
//!   and `--query-attachment` are rejected outright by a binary lacking the demo
//!   keys, so a wrong build exits 2 at spawn and `spawn_on_ephemeral_port`'s
//!   liveness check names the exit status.
//! * The QUERYABLE leg gates on `>> Received an error:` and asserts the OK-form
//!   `>> Received PUT` is ABSENT. `ReplyOut::reply_err` is signature-stable, so an
//!   atom-off build does NOT fail to compile — it silently emits nothing. Both
//!   halves are needed: the presence assertion catches "no reply at all", the
//!   absence assertion catches a hypothetical degradation to an OK reply.
//!
//! ## Ordering, and why `--query-after-ms` exists
//!
//! The demo's Query is ONE-SHOT with no retry, unlike the `z_pub -n 30` bursts the
//! publish-side legs lean on. A foreign queryable that has not finished declaring
//! when the Query lands never sees it. A hand run with NO hold passed — and passed
//! only because pico happened to print `Creating Queryable on` first. Relying on
//! that is the flake this knob removes, so both querier legs set a hold and assert
//! wz's `hold elapsed` bracket, making the ordering owned rather than raced.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_answering_zqueryable, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// How long the foreign exchange gets. Generous for the reason the sibling
/// AP-full file states: the lane runs under full-run-ci process pressure and
/// `wait_for_substring` returns the instant the marker appears, so a wide ceiling
/// costs a green run nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// The `--query-after-ms` hold. Comfortably past pico's declare (which follows
/// its session open immediately, i.e. within milliseconds of the Established the
/// hold is measured from) while staying well inside [`EXCHANGE_TIMEOUT`].
const QUERY_HOLD_MS: &str = "3000";

/// The queryable pattern the pico oracles declare on, and the concrete keyexpr
/// wz queries. Distinct so the printed line proves the MATCH, not an echo.
const QABL_PATTERN: &str = "demo/**";
const QUERY_KEYEXPR: &str = "demo/apfull/query";

/// Leg 1 — `query-selector-parameters`: wz's Query carries URL-style selector
/// parameters and a real pico `z_queryable` prints them.
///
/// ## Why the witness is the CONCATENATED string
///
/// pico's stock handler prints keyexpr and parameters with no separator of its
/// own — `printf(" >> [Queryable handler] Received Query '%.*s%.*s'", keystr,
/// params)` reading `z_query_parameters` (`z_queryable.c:38-39`). So a Query whose
/// `Q_P` flag or params slice was dropped prints the BARE keyexpr, and the same
/// line shape either way. Asserting the full `demo/apfull/query?p=42&kind=apfull`
/// is what separates the two; asserting only `Received Query` would pass with the
/// atom's contribution entirely absent.
///
/// The parameters carry TWO `&`-separated entries deliberately. A single
/// parameter would witness the slice arriving but not its INTERNAL structure; two
/// mean the separator has to survive as well, which is the dialect a real zenoh
/// selector parser splits on.
// wz-proves: query-selector-parameters wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_query_selector_parameters_decoded_by_a_real_pico_queryable() {
    let demo = wz_ap_demo_binary();
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let params = "?p=42&kind=apfull";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full querier stderr");
    let (mut demo_guard, mut demo_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "127.0.0.1:0",
            "--query",
            QUERY_KEYEXPR,
            "--query-params",
            params,
            "--query-after-ms",
            QUERY_HOLD_MS,
        ],
        "listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --query --query-params)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // The precondition, OWNED: the helper returns only once pico has opened the
    // session AND printed `Creating Queryable on`, so the declare is in place
    // before the held Query fires.
    let (mut qabl_child, mut qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        QABL_PATTERN,
        "apfull-qabl-answer",
        &endpoint,
        "the AP-full querier",
        || tempfile::tempfile().expect("tempfile for z_queryable stdout"),
    );

    // BUILD DISCRIMINATOR + ordering proof, asserted BEFORE the foreign witness so
    // a failure names which half broke. `params=Some(...)` can only be logged by a
    // binary that parsed the flag; `hold elapsed` proves the Query was not racing
    // the declare.
    let emitted = wait_for_substring(&mut demo_reader, "QUERY EMITTED", EXCHANGE_TIMEOUT)
        .map(|c| c.to_string());

    let witness = format!("Received Query '{QUERY_KEYEXPR}{params}'");
    let received =
        wait_for_substring(&mut qabl_reader, &witness, EXCHANGE_TIMEOUT).map(|c| c.to_string());

    let _ = qabl_child.child_mut().kill();
    let _ = qabl_child.child_mut().wait();
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));
    let demo_log = read_captured(&mut demo_reader);

    let emitted = match emitted {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full querier never logged 'QUERY EMITTED'. It did not reach the \
             emit at all, so nothing below can be attributed to the atom.\n\
             --- wz-ap-demo stderr ---\n{c}"
        ),
    };
    assert!(
        emitted.contains("hold elapsed"),
        "'QUERY EMITTED' appeared without the '--query-after-ms' hold bracket — the \
         Query raced pico's declare, so a green run here would be luck rather than \
         ordering\n--- wz-ap-demo stderr ---\n{emitted}"
    );
    assert!(
        emitted.contains(&format!("params=Some(\"{params}\")")),
        "the demo emitted a Query but did not report carrying params={params:?} — \
         the binary under test is not the preset-ap-full one this leg claims (an \
         ap-client build has no --query-params key at all)\n\
         --- wz-ap-demo stderr ---\n{emitted}"
    );
    if let Err(c) = received {
        panic!(
            "the real zenoh-pico z_queryable never printed {witness:?}. wz emitted \
             the Query, so the selector parameters did not survive to a foreign \
             decoder -- a dropped Q_P flag or params slice prints the BARE keyexpr \
             on the same line.\n--- pico z_queryable stdout ---\n{c}\
             \n--- wz-ap-demo stderr ---\n{demo_log}"
        );
    }
}

/// Leg 2 — `query-attachment`: wz's Query carries a `ze_serializer` kv-pair
/// attachment and a real pico `z_queryable_attachment` deserializes and prints
/// every pair.
///
/// ## Why this oracle, and why it had none before
///
/// `z_queryable_attachment` is the ONLY stock pico CLI that reads an INBOUND
/// Query's attachment: the plain `z_queryable` never calls `z_query_attachment`,
/// and `z_get_attachment` is the opposite direction (it attaches to an outbound
/// get and reads the REPLY). It is new to `build-zenoh-pico-cli.sh` this round for
/// that reason.
///
/// Its handler is not opaque — it runs
/// `ze_deserializer_deserialize_sequence_length` then a per-element string pair
/// (`z_queryable_attachment.c:71-87`), so wz must emit pico's kv-sequence form and
/// a bare byte blob would print NOTHING. That is why the demo routes through
/// `serialize_kv_attachment`, the same SSOT the push-side `z_sub_attachment`
/// witness uses.
///
/// ## TWO pairs, and both asserted
///
/// The blob's leading VLE is the sequence COUNT, and pico reads it first. A
/// single-pair fixture would pass on a count of 1 whatever the rest held; with two
/// pairs, asserting BOTH printed lines proves the count decoded AND that the
/// second element's length prefixes framed correctly. This is the
/// `feedback_count_not_match_for_chains` rule applied to a sequence: for a CHAIN,
/// "at least one arrived" passes a truncated frame.
// wz-proves: query-attachment wz->pico
// wz-proves: attachment-bytes wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI z_queryable_attachment); Layer E9 runs via --ignored"]
fn apfull_query_attachment_decoded_by_a_real_pico_queryable() {
    let demo = wz_ap_demo_binary();
    let z_queryable_attachment = zenoh_pico_cli_binary("z_queryable_attachment");

    let stderr = tempfile::tempfile().expect("tempfile for AP-full querier stderr");
    let (mut demo_guard, mut demo_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "127.0.0.1:0",
            "--query",
            QUERY_KEYEXPR,
            "--query-attachment",
            "wz-k1=wz-v1,wz-k2=wz-v2",
            "--query-after-ms",
            QUERY_HOLD_MS,
        ],
        "listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --query --query-attachment)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let (mut qabl_child, mut qabl_reader) = spawn_answering_zqueryable(
        &z_queryable_attachment,
        QABL_PATTERN,
        "apfull-qabl-answer",
        &endpoint,
        "the AP-full querier",
        || tempfile::tempfile().expect("tempfile for z_queryable_attachment stdout"),
    );

    let emitted = wait_for_substring(&mut demo_reader, "QUERY EMITTED", EXCHANGE_TIMEOUT)
        .map(|c| c.to_string());

    // Wait on the SECOND pair: pico prints them in sequence order, so the second
    // line appearing means the first already did and the count covered both.
    let second_pair = "1: wz-k2, wz-v2";
    let received =
        wait_for_substring(&mut qabl_reader, second_pair, EXCHANGE_TIMEOUT).map(|c| c.to_string());

    let _ = qabl_child.child_mut().kill();
    let _ = qabl_child.child_mut().wait();
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));
    let demo_log = read_captured(&mut demo_reader);

    let emitted = match emitted {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full querier never logged 'QUERY EMITTED'. It did not reach the \
             emit at all, so nothing below can be attributed to the atom.\n\
             --- wz-ap-demo stderr ---\n{c}"
        ),
    };
    assert!(
        emitted.contains("hold elapsed"),
        "'QUERY EMITTED' appeared without the '--query-after-ms' hold bracket — the \
         Query raced pico's declare, so a green run here would be luck rather than \
         ordering\n--- wz-ap-demo stderr ---\n{emitted}"
    );
    assert!(
        emitted.contains("attachment_pairs=2"),
        "the demo emitted a Query but did not report carrying 2 attachment pairs — \
         either the binary under test is not the preset-ap-full one (an ap-client \
         build has no --query-attachment key) or the pairs were dropped before the \
         encode\n--- wz-ap-demo stderr ---\n{emitted}"
    );
    let qabl_out = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "the real zenoh-pico z_queryable_attachment never printed {second_pair:?}. \
             wz emitted the Query with 2 pairs, so the kv sequence did not survive to \
             a foreign deserializer — a wrong leading count or a mis-framed length \
             prefix makes pico's deserialize fail and print NOTHING.\n\
             --- pico z_queryable_attachment stdout ---\n{c}\
             \n--- wz-ap-demo stderr ---\n{demo_log}"
        ),
    };
    assert!(
        qabl_out.contains("0: wz-k1, wz-v1"),
        "pico printed the second pair but not the first — the sequence decoded past \
         a corrupted head, which no single-pair assertion would have caught\n\
         --- pico z_queryable_attachment stdout ---\n{qabl_out}"
    );
    assert!(
        qabl_out.contains("with attachment:"),
        "the pairs printed without pico's 'with attachment:' header — the fixture is \
         matching something other than the attachment block\n\
         --- pico z_queryable_attachment stdout ---\n{qabl_out}"
    );
}

/// Leg 3 — `query-reply-err`: wz's queryable answers an ERR-form Reply and a real
/// pico `z_get` decodes it as an error rather than a sample.
///
/// ## Why BOTH a presence and an absence assertion
///
/// `ReplyOut::reply_err` is signature-STABLE — ungated on the trait — and only its
/// emit is gated: `query.rs`'s impl calls `send_err` under
/// `#[cfg(feature = "query-reply-err")]` and drops the call otherwise. So an
/// atom-off build compiles fine and answers NOTHING. The presence assertion on
/// `>> Received an error: <payload>` catches that. The absence assertion on
/// `>> Received PUT` catches the other failure shape — a path that degraded to an
/// OK reply would satisfy "pico printed something" while binding the claim to the
/// wrong wire arm.
///
/// pico's own reply handler is the discriminator: `z_reply_is_ok` picks the sample
/// branch, and only the else branch reads `z_reply_err_payload` and prints
/// `>> Received an error: %.*s` (`z_get.c:37-54`). It fires immediately with no
/// consolidation on this path — `_z_trigger_query_reply_err` calls the callback
/// straight through (`query.c:201-220`) — so a missing line is a missing frame,
/// not a buffered one.
///
/// ## Measured, and it is what made the round's honest scope clear
///
/// The absent-frame shape was captured on the wire: against an atom-off build wz
/// sends 6 bytes (`ResponseFinal` alone) where the atom-on build sends 41
/// (`Response(Err)` + `ResponseFinal`). That is the RED this leg detects.
// wz-proves: query-reply-err wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI z_get); Layer E9 runs via --ignored"]
fn apfull_query_reply_err_decoded_by_a_real_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let err_payload = "wz-apfull-reply-err";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full queryable stderr");
    let (mut demo_guard, mut demo_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "127.0.0.1:0",
            "--queryable",
            QABL_PATTERN,
            "--reply-err",
            err_payload,
        ],
        "listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --queryable --reply-err)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // NO ordering hold is arranged here, and the reason is a correction worth
    // keeping: the queryable is declared PRE-DRIVE only in the sense of "before the
    // steady-state loop" — `install_session_handles` runs AFTER the accept, so the
    // `DECLARED ROUTED QUERYABLE` banner cannot appear until a peer has connected.
    // A first version of this leg gated on that banner BEFORE spawning pico and
    // deadlocked by construction: the precondition it waited for was unreachable
    // until the thing it was gating had already run
    // (`feedback_verdict_assertion_must_be_reachable`). pico is therefore spawned
    // first, and the banner is asserted afterwards, where it is reachable and still
    // separates "the queryable was never there" from "it was there and did not
    // answer".
    //
    // The ordering is safe without a hold for a reason the querier legs cannot
    // borrow: the declare happens on the SAME accept that the inbound Query rides,
    // and it is synchronous with respect to the drive loop that dispatches that
    // Query — so there is no window for the Query to arrive first.
    //
    // pico's one-shot `z_get` does not self-retry its open, so absorb the transient
    // the sibling helpers absorb (6 attempts) rather than reading a lost race as a
    // wz failure.
    const OPEN_ATTEMPTS: usize = 6;
    let mut attached: Option<(ChildGuard, std::fs::File)> = None;
    for attempt in 1..=OPEN_ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_get stdout");
        let out_writer = out.try_clone().expect("dup z_get stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_get client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&z_get)
                .args(["-k", QUERY_KEYEXPR, "-e", &endpoint, "-m", "client"])
                .stderr(Stdio::from(
                    out_writer.try_clone().expect("dup stderr handle"),
                ))
                .stdout(Stdio::from(out_writer))
                .spawn()
                .expect("spawn z_get via stdbuf"),
        );
        match wait_for_substring(&mut out_reader, "Sending Query", Duration::from_secs(8)) {
            Ok(_) => {
                attached = Some((child, out_reader));
                break;
            }
            Err(_) => {
                let _ = child.child_mut().kill();
                let _ = child.child_mut().wait();
                eprintln!(
                    "z_get open attempt {attempt}/{OPEN_ATTEMPTS} did not send its Query; retrying"
                );
            }
        }
    }
    let (mut get_child, mut get_reader) = match attached {
        Some(pair) => pair,
        None => {
            graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));
            panic!(
                "pico z_get failed to open a session to the AP-full queryable after \
                 {OPEN_ATTEMPTS} attempts"
            );
        }
    };

    let witness = format!("Received an error: {err_payload}");
    let received =
        wait_for_substring(&mut get_reader, &witness, EXCHANGE_TIMEOUT).map(|c| c.to_string());
    let fired = wait_for_substring(&mut demo_reader, "QUERYABLE FIRED", EXCHANGE_TIMEOUT)
        .map(|c| c.to_string());

    let _ = get_child.child_mut().kill();
    let _ = get_child.child_mut().wait();
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));
    let demo_log = read_captured(&mut demo_reader);

    let fired = match fired {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full queryable never fired for pico's Query, so nothing below \
             can be attributed to the ERR arm\n--- wz-ap-demo stderr ---\n{c}"
        ),
    };
    assert!(
        fired.contains("DECLARED ROUTED QUERYABLE"),
        "the queryable callback fired without the routed-declare banner — the \
         registration path this leg claims to exercise is not the one that ran\n\
         --- wz-ap-demo stderr ---\n{fired}"
    );
    assert!(
        fired.contains(&format!("reply-err='{err_payload}'")),
        "the queryable fired but did not report taking the ERR arm — the binary \
         under test may be answering with the OK arm instead\n\
         --- wz-ap-demo stderr ---\n{fired}"
    );
    let get_out = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "the real zenoh-pico z_get never printed {witness:?}. wz's queryable took \
             the ERR arm, so the Response(Err) did not reach a foreign decoder — an \
             atom-off build puts the ResponseFinal on the wire and no Err frame at \
             all, which is exactly this shape.\n--- pico z_get stdout ---\n{c}\
             \n--- wz-ap-demo stderr ---\n{demo_log}"
        ),
    };
    assert!(
        !get_out.contains("Received PUT"),
        "pico decoded an ERR reply AND an OK sample for the same query — the ERR arm \
         did not replace the OK one, so this leg would pass on a build that emits \
         both and the claim would not bind to the ERR wire arm\n\
         --- pico z_get stdout ---\n{get_out}"
    );
}
