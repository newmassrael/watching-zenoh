// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a row of the since-document costs with its field trees and without
//! them, and what the CBOR form of the treeless document costs on top.
//!
//! # The question this answers
//!
//! A consumer that lists the rows of a live capture asks for the rows after its
//! cursor at every step, and reported that at 20,000 small messages a second
//! the document could not keep up: about 3.7 KB a row, and about 17 us a row to
//! write. Its list reads what a row says about the message and none of the
//! trees. This measures, on a capture of small pushes like that one, how much
//! of a row's bytes and of the call are the trees ([`Trees::Written`] against
//! [`Trees::Left`]), and what writing the treeless document again as CBOR
//! ([`cbor_of_json`]) adds.
//!
//! The documents are written by the remembering since-door, the one a live
//! handle's doors call, from cursor 0 over the whole capture and then step by
//! step as the capture grows, which is how the consumer reads them.
//!
//! # What this does NOT do
//!
//! It fails on no threshold, for `decode_cost`'s reason. It asserts that it
//! measured what it names: both documents hold every row, the treeless one has
//! no `fields` key on any row, and its CBOR form is one data item.
//!
//! # Usage
//!
//! ```text
//! cargo bench -p wz-capture --features fixtures,dissect --bench row_facts_cost
//! cargo bench -p wz-capture --features fixtures,dissect --bench row_facts_cost -- --quick
//! ```

use std::time::Instant;

use wz_capture::cbor_of_json::cbor_of_json;
use wz_capture::fields_json::{
    fields_json_since_remembering_progress, FieldsMemory, RowCoordinates, Since, Trees,
};
use wz_capture::fixtures::{push_run_capture_of, RunTransport};
use wz_capture::Dissection;

const KEY: &str = "bench/rows";

/// The payload size the reporting consumer's load generator sends.
const PAYLOAD: usize = 64;

/// How many steps the capture is read in, as a list that follows it reads it.
const STEPS: usize = 10;

/// Each measurement is the fastest of this many runs.
const RUNS: usize = 3;

/// One list, numbered from 1 in the order it produced its messages: the
/// numbering a live handle gives a capture of one session.
struct OneList;

impl RowCoordinates for OneList {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64 + 1)
    }
    fn scouting_list_id(&self, _flow: &wz_capture::link::FlowKey) -> Option<u64> {
        None
    }
    fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }
}

/// The capture's first `bytes`, read; the dissection of a capture that has
/// grown to there.
fn dissection_of(file: &[u8]) -> Dissection {
    Dissection::from_capture(file).expect("the capture reads")
}

/// The fastest of [`RUNS`] runs of `work`, in microseconds, and its last result.
fn fastest<T>(mut work: impl FnMut() -> T) -> (u128, T) {
    let mut best = u128::MAX;
    let mut out = None;
    for _ in 0..RUNS {
        let start = Instant::now();
        let got = work();
        best = best.min(start.elapsed().as_micros());
        out = Some(got);
    }
    (best, out.expect("RUNS is not zero"))
}

/// One whole document from cursor 0, with a fresh memory of `trees`' shape.
fn whole(d: &Dissection, file: &[u8], rows: u64, trees: Trees) -> String {
    let mut memory = FieldsMemory::with_trees(trees);
    fields_json_since_remembering_progress(
        d,
        file,
        None,
        "",
        &OneList,
        Since {
            after_seq: 0,
            through_seq: rows,
        },
        &mut memory,
        None,
    )
    .expect("nothing stops the call")
}

/// The capture read in [`STEPS`] steps, each from the cursor the last one gave,
/// with one memory of `trees`' shape: the microseconds the doors took in all and
/// the bytes they wrote. The dissections are made before the clock starts.
fn stepped(prefixes: &[(Dissection, Vec<u8>, u64)], trees: Trees) -> (u128, usize) {
    let mut memory = FieldsMemory::with_trees(trees);
    let mut cursor = 0;
    let mut bytes = 0;
    let start = Instant::now();
    for (d, file, rows) in prefixes {
        let doc = fields_json_since_remembering_progress(
            d,
            file,
            None,
            "",
            &OneList,
            Since {
                after_seq: cursor,
                through_seq: *rows,
            },
            &mut memory,
            None,
        )
        .expect("nothing stops the call");
        bytes += doc.len();
        cursor = *rows;
    }
    (start.elapsed().as_micros(), bytes)
}

fn measure(pushes: usize) {
    let payload = |i: usize| {
        let mut p = vec![0u8; PAYLOAD];
        p[..8].copy_from_slice(&(i as u64).to_le_bytes());
        p
    };
    let file = push_run_capture_of(KEY, pushes, RunTransport::Stream, &payload);
    let d = dissection_of(&file);
    let handshake_rows = {
        let doc = whole(&d, &file, u64::MAX, Trees::Left);
        doc.matches("\"seq\":").count() - pushes
    };
    let rows = (pushes + handshake_rows) as u64;

    let (trees_us, with_trees) = fastest(|| whole(&d, &file, rows, Trees::Written));
    let (facts_us, facts) = fastest(|| whole(&d, &file, rows, Trees::Left));
    let (cbor_us, cbor) = fastest(|| cbor_of_json(&facts).expect("the document is JSON"));

    assert_eq!(with_trees.matches("\"seq\":").count() as u64, rows);
    assert_eq!(facts.matches("\"seq\":").count() as u64, rows);
    assert!(with_trees.contains(",\"fields\":{"), "the rows carry trees");
    assert!(!facts.contains(",\"fields\":{"), "no row carries a tree");
    assert!(
        facts.starts_with("{\"document\":{\"name\":\"row_facts\""),
        "the document names its shape"
    );

    // The capture read as it grew, in steps: each step's dissection is of the
    // prefix the step ends at, as a live handle's would be after its pushes.
    let prefixes: Vec<(Dissection, Vec<u8>, u64)> = (1..=STEPS)
        .map(|step| {
            let upto = pushes * step / STEPS;
            let part = push_run_capture_of(KEY, upto, RunTransport::Stream, &payload);
            let d = dissection_of(&part);
            (d, part, (upto + handshake_rows) as u64)
        })
        .collect();
    let (step_trees_us, step_trees_bytes) = stepped(&prefixes, Trees::Written);
    let (step_facts_us, step_facts_bytes) = stepped(&prefixes, Trees::Left);

    let per_row = |v: f64| v / rows as f64;
    println!(
        "pushes {pushes} ({PAYLOAD} B), rows {rows}, capture {} B",
        file.len()
    );
    println!(
        "  whole, with trees     {trees_us:>9} us {:>7.2} us/row  {:>10} B {:>8.1} B/row",
        per_row(trees_us as f64),
        with_trees.len(),
        per_row(with_trees.len() as f64)
    );
    println!(
        "  whole, without trees  {facts_us:>9} us {:>7.2} us/row  {:>10} B {:>8.1} B/row",
        per_row(facts_us as f64),
        facts.len(),
        per_row(facts.len() as f64)
    );
    println!(
        "  CBOR of the treeless  {cbor_us:>9} us {:>7.2} us/row  {:>10} B {:>8.1} B/row",
        per_row(cbor_us as f64),
        cbor.len(),
        per_row(cbor.len() as f64)
    );
    println!(
        "  {STEPS} steps, with trees     {step_trees_us:>9} us {:>7.2} us/row  {:>10} B",
        per_row(step_trees_us as f64),
        step_trees_bytes
    );
    println!(
        "  {STEPS} steps, without trees  {step_facts_us:>9} us {:>7.2} us/row  {:>10} B",
        per_row(step_facts_us as f64),
        step_facts_bytes
    );
    println!(
        "  trees: {:.1}% of the bytes, {:.1}% of the whole call; CBOR is {:.1}% of the treeless text",
        100.0 * (with_trees.len() - facts.len()) as f64 / with_trees.len() as f64,
        100.0 * (trees_us as f64 - facts_us as f64) / trees_us as f64,
        100.0 * cbor.len() as f64 / facts.len() as f64
    );
    // The last row as written, so what a treeless row still holds is read and
    // not inferred.
    // A row opens with its direction and the space its anchor is in; a conduit
    // object has a direction too, and no `offset_space` after it.
    let opened = facts
        .rfind(",\"offset_space\":")
        .and_then(|space| facts[..space].rfind("{\"direction\":"));
    if let Some(at) = opened {
        let end = facts[at..]
            .find("],\"shown\":")
            .map_or(facts.len(), |e| at + e);
        println!("  last treeless row: {}", &facts[at..end]);
    }
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let sizes: &[usize] = if quick { &[500] } else { &[2_000, 20_000] };
    for &pushes in sizes {
        measure(pushes);
    }
}
