// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one row of the field document costs, against the typed values a
//! consumer that plots a few field paths keeps from it.
//!
//! # The question this answers
//!
//! A consumer drawing one field over time reads `payload_decode.fields[]` of
//! every row and keeps one or two `typed_value`s. Whether that is enough, or
//! whether a door that writes only the chosen paths' values is warranted,
//! turns on two numbers this measures rather than argues:
//!
//! * how much of a row is the values kept, in BYTES: the document's bytes per
//!   row against the bytes a narrow door could not write less than (a sequence
//!   number, a path and a value per kept field);
//! * how much of a call is the WALK, which a narrow door pays as well (every
//!   message is still decoded and its payload read), and how much is the
//!   writing of the rows, which it would not.
//!
//! The capture is one session of `N` pushes, each a `pkg.Pose` the protobuf
//! writer built, read three ways: the walk alone, the field document with the
//! schema declared (`typed`), and the same with a bare `protobuf` rule (the
//! wire walk), so the cost the typed reading adds is measured too.
//!
//! # What this does NOT do
//!
//! It fails on no threshold, for `decode_cost`'s reason: a wall-clock number
//! that reds a lane on a shared runner is a flake generator. It asserts that it
//! measured: every row it counts was decoded by the schema.
//!
//! # Usage
//!
//! ```text
//! cargo bench -p wz-capture --features fixtures,dissect --bench fields_row_cost
//! cargo bench -p wz-capture --features fixtures,dissect --bench fields_row_cost -- --quick
//! ```

use std::time::Instant;

use wz_capture::fields_json::fields_json;
use wz_capture::fixtures::{push_run_capture_of, RunTransport};
use wz_capture::payload::formats::FormatMap;
use wz_capture::payload_decode::Declarations;
use wz_capture::proto_schema::ProtoFile;
use wz_capture::Dissection;

const SCHEMA: &str = r#"syntax = "proto3";
package pkg;
enum Gear { GEAR_UNSPECIFIED = 0; GEAR_PARK = 1; GEAR_DRIVE = 2; }
message Inner { double ratio = 1; }
message Pose {
  sint32 x = 1;
  double heading = 2;
  Gear gear = 3;
  Inner inner = 4;
  repeated int32 samples = 5;
  string label = 6;
}
"#;

const KEY: &str = "demo/pose";

/// The paths a plotting consumer keeps: `x` and `heading`.
const KEPT: &[&str] = &["1", "2"];

/// Each measurement is the fastest of this many runs.
const RUNS: usize = 3;

/// The `i`-th message. No kept field is ever at its default: proto3 does not
/// write a field at its default, and a row without the field has no value to
/// keep.
fn pose(i: usize) -> Vec<u8> {
    let values = format!(
        r#"{{"x": {x}, "heading": {h}, "gear": "GEAR_DRIVE", "inner": {{"ratio": 0.25}},
            "samples": [{i}, 2, 300], "label": "lap"}}"#,
        x = -(i as i64) - 1,
        h = i as f64 * 0.5 + 0.25,
    );
    wz_capture::proto_encode::encode_message(
        "pkg.Pose",
        &[ProtoFile {
            name: "pose.proto",
            text: SCHEMA.as_bytes(),
        }],
        0,
        &values,
    )
    .expect("the writer builds the message")
}

fn typed_declarations() -> String {
    let mut line = String::from("#@pose.proto=");
    wz_session_core::json::escape_into(SCHEMA, &mut line);
    format!("{line}\n{KEY}=protobuf@pkg.Pose\n")
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

/// The bytes a narrow door writes for one kept value at the least: the row's
/// sequence number, the path and the value, as `{"seq":S,"path":"P","value":V}`.
fn narrow_bytes(seq: usize, path: &str, value: &str) -> usize {
    format!("{{\"seq\":{seq},\"path\":\"{path}\",\"value\":{value}}}").len()
}

/// The `typed_value` of the entry at `path` in one row's text, the first one.
fn typed_value<'d>(row: &'d str, path: &str) -> Option<&'d str> {
    let at = row.find(&format!("{{\"path\":\"{path}\","))?;
    let rest = &row[at..];
    let v = rest.find("\"typed_value\":")? + "\"typed_value\":".len();
    let end = rest[v..].find(",\"enum_number\"")?;
    Some(&rest[v..v + end])
}

fn measure(pushes: usize) {
    let file = push_run_capture_of(KEY, pushes, RunTransport::Stream, &pose);
    let (walk_us, dissection) =
        fastest(|| Dissection::from_capture(&file).expect("the capture reads"));

    let typed_text = typed_declarations();
    let mut typed_map = FormatMap::new();
    typed_map
        .declare_all(&typed_text)
        .expect("the declarations install");
    let mut wire_map = FormatMap::new();
    wire_map
        .declare_all(&format!("{KEY}=protobuf\n"))
        .expect("the declarations install");

    let (bare_us, bare) = fastest(|| fields_json(&dissection, &file, None, None));
    let (typed_us, typed) = fastest(|| {
        let run = Declarations::new(&typed_map);
        fields_json(&dissection, &file, None, Some(&run))
    });
    let (wire_us, wire) = fastest(|| {
        let run = Declarations::new(&wire_map);
        fields_json(&dissection, &file, None, Some(&run))
    });

    // One decoded block per push, each read by the schema: the population the
    // per-row figures are over.
    let rows: Vec<&str> = typed
        .split("\"payload_decode\":{\"state\":\"decoded\"")
        .skip(1)
        .collect();
    assert_eq!(rows.len(), pushes, "every push decodes");
    assert!(
        rows.iter()
            .all(|r| r.starts_with(",\"keyexpr\":\"demo/pose\"")
                && r.contains("\"typed\":true,\"schema\":\"pkg.Pose\"")),
        "every push is read by the schema"
    );
    let mut narrow = 0usize;
    for (seq, row) in rows.iter().enumerate() {
        for path in KEPT {
            let value = typed_value(row, path).expect("the kept path is in the row");
            narrow += narrow_bytes(seq, path, value);
        }
    }

    let per = |bytes: usize| bytes as f64 / pushes as f64;
    println!("pushes {pushes}, capture {} B", file.len());
    println!("  walk (Dissection::from_capture)      {walk_us:>9} us");
    println!(
        "  document, no declarations            {bare_us:>9} us  {:>10} B  {:>8.1} B/push",
        bare.len(),
        per(bare.len())
    );
    println!(
        "  document, bare protobuf (wire walk)  {wire_us:>9} us  {:>10} B  {:>8.1} B/push",
        wire.len(),
        per(wire.len())
    );
    println!(
        "  document, protobuf@pkg.Pose (typed)  {typed_us:>9} us  {:>10} B  {:>8.1} B/push",
        typed.len(),
        per(typed.len())
    );
    println!(
        "  kept values ({} paths), narrowest form          {:>10} B  {:>8.1} B/push",
        KEPT.len(),
        narrow,
        per(narrow)
    );
    println!(
        "  document / kept values: {:.1}x; walk share of the typed call: {:.1}%",
        typed.len() as f64 / narrow as f64,
        100.0 * walk_us as f64 / (walk_us + typed_us) as f64
    );
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let sizes: &[usize] = if quick { &[200] } else { &[1_000, 10_000] };
    for &pushes in sizes {
        measure(pushes);
    }
}
