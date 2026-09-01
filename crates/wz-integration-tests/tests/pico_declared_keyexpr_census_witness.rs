// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2248 (no register item) — the `census.keyexprs` id-to-path mapping, against
//! a `Declare` a real zenoh-pico put on the wire.
//!
//! Closes item 595 of the unregistered register, which lives outside this
//! repository -- the same position `armed_oracle_census.py` records for 562 and
//! `armed_skip_guard.py` for 598. The item is named in full here, which is what
//! a reader grepping for it will find.
//!
//! ## The gap this fills, and it is NOT a missing capability
//!
//! `wz-capture` resolves an aliased keyexpr already: `DeclKexpr` binds an id to
//! a suffix in the SENDER's space (`agg.rs`), `KeyexprRow::keyexpr` is the
//! literal "after alias resolution", and `UnresolvedAlias` reports an id nobody
//! bound. `agg.rs`'s own unit tests drive all of it from hand-built frames.
//!
//! What nothing did was hold that resolution against a FOREIGN declaration.
//! Measured before this file existed: of the 15 tests under this directory that
//! reach `wz_capture`, ZERO carried an assertion mentioning `unresolved`,
//! `unknown_id`, `declared_id` or `resolve`. So the emitter was covered and the
//! claim -- "the path this row reports is the path the other implementation
//! actually declared" -- was not.
//!
//! ⚠ The distinction is the whole item: this file builds a WITNESS, not an
//! emitter. Nothing in `wz-capture` changes.
//!
//! ## Why `z_put` is the genuine article here
//!
//! zenoh-pico's own `examples/unix/c11/z_put.c` calls `z_declare_keyexpr`
//! explicitly, publishes through the returned alias, and `z_undeclare_keyexpr`s
//! it. So one run of the stock binary puts a complete declare / reference /
//! undeclare cycle on the wire, with the path chosen by `-k` -- which makes the
//! comparison in this file a comparison against a string a foreign encoder
//! serialised, not against one this test also wrote.
//!
//! `z_pub` would not do: it publishes on the literal keyexpr and declares no id,
//! so the row would resolve trivially and the test would assert nothing.
//!
//! ## The three conditions, and the controls that make each falsifiable
//!
//! 1. THE CAPTURE REALLY CONTAINS A DECLARATION. An empty or declaration-free
//!    capture satisfies "no unresolved aliases" perfectly, so `declarations()`
//!    is asserted BEFORE any comparison. This is the same anti-vacuity floor the
//!    sibling witnesses put first.
//! 2. THE RESOLVED PATH IS THE DECLARED ONE. The row keyed by the `-k` string
//!    must exist and must carry the put.
//! 3. A WRONG BINDING IS REJECTED. Two controls, because "wrong" has two shapes
//!    here and they fail differently:
//!    * the SUFFIX control rewrites the declared path on the wire (one byte of
//!      the ASCII the pico process serialised) and requires the row to follow
//!      the wire rather than the expectation. If the row still read the original
//!      string, this file would be asserting against its own `-k` argument.
//!    * the BINDING control drops the segment carrying the declaration and
//!      requires the id to surface in `unresolved`. If the reference resolved
//!      anyway, the mapping would not be coming from the declaration at all.

use std::process::Command;
use std::time::Duration;

use wz_capture::agg::aggregate;
use wz_capture::Dissection;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Side};

/// The synthesised endpoint ports, chosen for the reason the sibling witness
/// states: `FlowKey` orders endpoints by `(addr, port)` and both addresses are
/// loopback, so the lower port is `Direction::A`. wz listens, pico dials.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// The path pico is told to declare. Under `demo/**` so wz-ap-demo's subscriber
/// matches it, and long enough that the ASCII occurs exactly once in the
/// recording -- which the suffix control asserts rather than assumes.
const DECLARED: &str = "demo/census/declared-by-pico";

/// The single byte the suffix control rewrites, and what it becomes. Inside the
/// last segment of the path so it cannot collide with the `demo/**` match that
/// makes wz-ap-demo deliver the sample.
const MUTANT: &str = "demo/census/declared-by-picX";

/// Record one stock `z_put` through the tap: declare, put, undeclare.
fn record_a_declaring_put() -> Vec<(Side, Vec<u8>)> {
    let demo = wz_ap_demo_binary();
    // A stale demo here does not weaken the proof, it MISDIAGNOSES it: the
    // failure would be "wz-ap-demo never delivered the relayed sample", which
    // sends a reader into the census for a defect that is in the build.
    assert_demo_binary_newer_than_sources(&demo);
    let z_put = zenoh_pico_cli_binary("z_put");

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let (mut demo_guard, mut demo_reader, wz_port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (--listen, behind the tap proxy)",
        demo_stderr,
    );

    let (proxy_port, recording) = tap_proxy(wz_port);

    let mut capture = tempfile::tempfile().expect("zenoh-pico z_put capture");
    let put = Command::new(&z_put)
        .args([
            "-e",
            &format!("tcp/127.0.0.1:{proxy_port}"),
            "-k",
            DECLARED,
            "-v",
            "declared-alias-payload",
        ])
        .stdout(capture.try_clone().expect("clone capture"))
        .stderr(capture.try_clone().expect("clone capture"))
        .status()
        .expect("spawn zenoh-pico z_put");
    assert!(
        put.success(),
        "the stock zenoh-pico z_put exited {put:?} against the tapped acceptor -- \
         no session means no foreign declaration to grade. Its output was:\n{}",
        read_captured(&mut capture)
    );

    let delivered = wait_for_substring(
        &mut demo_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    );
    delivered.expect(
        "wz-ap-demo never delivered the relayed sample, so the recording would be \
         a partial handshake rather than a declare/put cycle",
    );
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));

    // Let the relay threads see EOF before the log is read.
    std::thread::sleep(Duration::from_millis(200));
    let segments = recording.lock().expect("recording lock").clone();
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- the proxy was bypassed or never accepted, \
         and an empty capture satisfies every assertion below"
    );
    segments
}

/// Index of the segment carrying `needle`, and how many segments carry it.
fn locate(segments: &[(Side, Vec<u8>)], needle: &[u8]) -> (Option<usize>, usize) {
    let mut first = None;
    let mut count = 0;
    for (i, (_, bytes)) in segments.iter().enumerate() {
        if bytes.windows(needle.len()).any(|w| w == needle) {
            count += 1;
            if first.is_none() {
                first = Some(i);
            }
        }
    }
    (first, count)
}

/// THE WITNESS: the census resolves an id to the path zenoh-pico declared.
///
/// The name carries `analyzer` for the reason Layer C0's skip-token gate gives:
/// `libtest --skip` matches the FUNCTION name, so a witness whose `#[ignore]`
/// reason names Layer Ewire is still run by Layer E's default sweep unless the
/// fn name says which family it belongs to. The sibling
/// `pico_wire_dissection.rs` is covered by the same token, and this is the same
/// family: an analyzer witness over a foreign capture.
// wz-proves: declare-keyexpr pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer Ewire runs via --ignored"]
fn the_analyzer_census_resolves_an_id_to_the_path_a_real_zenoh_pico_declared() {
    let segments = record_a_declaring_put();

    // ── WHERE THE DECLARATION SITS, established before it is relied on ────
    // Both controls below need this, and a needle that matched twice (or zero
    // times) would make each of them mean something different from what its
    // name says.
    let (declaring_segment, occurrences) = locate(&segments, DECLARED.as_bytes());
    assert_eq!(
        occurrences, 1,
        "the declared path occurs in {occurrences} recorded segment(s); the \
         controls below rewrite and drop THE declaration, and neither is that \
         if the path is spread across several segments or absent entirely"
    );
    let declaring_segment = declaring_segment.expect("one occurrence implies an index");

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let table = aggregate(&dissection);

    // ── ① ANTI-VACUITY: there IS a declaration to grade ───────────────────
    let (declared, undeclared) = table.declarations();
    assert!(
        declared >= 1,
        "the capture carries {declared} declaration(s), so 'the id resolved' \
         below would be true of a capture with no ids in it at all"
    );

    // ── ② THE RESOLVED PATH IS THE DECLARED ONE ───────────────────────────
    let row = table.row(DECLARED).unwrap_or_else(|| {
        panic!(
            "no census row for the path zenoh-pico declared ({DECLARED}); rows \
             present: {:?}, unresolved aliases: {:?}",
            table.rows().iter().map(|r| &r.keyexpr).collect::<Vec<_>>(),
            table
                .unresolved()
                .iter()
                .map(|a| (a.id, a.references))
                .collect::<Vec<_>>()
        )
    });
    let puts: usize = row.per_direction.iter().map(|c| c.puts).sum();
    assert_eq!(
        puts, 1,
        "the row resolved but carries {puts} put(s); the put pico sent through \
         the alias is what binds this row to the declaration rather than to the \
         declaration's own message"
    );
    assert!(
        table.unresolved().is_empty(),
        "every id in this capture was declared, so nothing should be \
         unresolved; got {:?}",
        table
            .unresolved()
            .iter()
            .map(|a| (a.id, a.references))
            .collect::<Vec<_>>()
    );
    assert!(
        undeclared >= 1,
        "z_put undeclares the alias before it exits, so the capture should \
         carry at least one undeclaration; got {undeclared}"
    );

    // ── ③a CONTROL, SUFFIX: the row must follow the WIRE, not the argument ─
    // One byte of the ASCII the pico process serialised is rewritten. If the
    // row still read DECLARED, this test would be comparing its own `-k`
    // argument against itself.
    let mut mutated = segments.clone();
    rewrite(&mut mutated[declaring_segment].1, DECLARED, MUTANT);
    let mutant_pcap = synthesise_pcap(&mutated, DIALER_PORT, LISTENER_PORT);
    let mutant =
        aggregate(&Dissection::from_pcap(&mutant_pcap).expect("the mutated pcap still parses"));
    assert!(
        mutant.row(DECLARED).is_none(),
        "the declared path was rewritten on the wire and the census still \
         reports the ORIGINAL string, so the row is not coming from the \
         declaration"
    );
    assert!(
        mutant.row(MUTANT).is_some(),
        "the rewritten path is not reported either; rows: {:?}",
        mutant.rows().iter().map(|r| &r.keyexpr).collect::<Vec<_>>()
    );

    // ── ③b CONTROL, BINDING: without the declaration the id is UNRESOLVED ──
    // The declaring segment is dropped. The put that referenced the id is
    // still there, so a census that resolved it anyway would not be reading
    // the binding at all.
    let mut without: Vec<(Side, Vec<u8>)> = segments.clone();
    without.remove(declaring_segment);
    let without_pcap = synthesise_pcap(&without, DIALER_PORT, LISTENER_PORT);
    let without_table =
        aggregate(&Dissection::from_pcap(&without_pcap).expect("the truncated pcap still parses"));
    assert!(
        without_table.row(DECLARED).is_none(),
        "the declaration was removed from the capture and the census still \
         resolves the id to {DECLARED}"
    );
    assert!(
        !without_table.unresolved().is_empty(),
        "the declaration was removed and no alias is reported unresolved, so \
         the reference is being dropped silently rather than reported"
    );
}

/// Replace the single occurrence of `from` with `to` in place. Same length by
/// construction, so no stream offset moves and the control varies ONE thing.
fn rewrite(bytes: &mut [u8], from: &str, to: &str) {
    assert_eq!(
        from.len(),
        to.len(),
        "the suffix control must not change the length of the wire"
    );
    let at = bytes
        .windows(from.len())
        .position(|w| w == from.as_bytes())
        .expect("the caller located this segment by the same needle");
    bytes[at..at + from.len()].copy_from_slice(to.as_bytes());
}
