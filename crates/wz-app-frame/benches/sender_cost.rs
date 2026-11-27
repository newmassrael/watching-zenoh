// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the two senders of this crate cost per frame: the end-to-end stream
//! sender per protected frame, and the segment sender per message it splits.
//!
//! # Why it exists
//!
//! Logic moved from hand Rust into SCE documents must keep the cost it had
//! (owner, 2026-11-27). Both senders number what they send by a rollover rule
//! that every frame passes (census rows S11 3 and S10 8, W12 of
//! `docs/zenoh-logic-as-sce-kinds.md`), and the two hand-written rules are to
//! become one SCE algorithm. Nothing measured the send path, so the move could
//! be neither shown to keep its cost nor shown to lose it. This is that
//! instrument: the same program built against the tree before the move and
//! after it, on one machine, gives the two figures to compare.
//!
//! # What it measures
//!
//! * `e2e-*`: the nanoseconds of one `StreamSender::protect_into` of an
//!   eight-byte payload into a buffer made before the clock starts, the
//!   streams taking turns, with the CRC cache off and on. `4B-refuse` is a
//!   four-byte counter that never reaches its largest value in the run;
//!   `1B-wrap` is a one-byte counter that wraps every 256 frames of a stream,
//!   so the rollover branch is taken in the measured loop.
//! * `segment-*`: the nanoseconds of one `SegmentSender::split` of a
//!   48-byte message into three pieces handed to an emitter that keeps
//!   nothing. `4B-refuse` is a four-byte transfer number that never reaches
//!   its largest value; `1B-restart` is a one-byte one made with 1, which goes
//!   back to 1 every 255 messages.
//!
//! Each figure is the median of nine runs of the whole loop, after one run
//! that is not measured.
//!
//! # What it does not do
//!
//! It fails on no threshold: a wall-clock figure on a shared machine is not a
//! verdict by itself. A comparison runs the before and after programs
//! alternately on one idle machine and reads the medians.

use std::hint::black_box;
use std::time::Instant;

use wz_app_frame::e2e_frame::Values;
use wz_app_frame::e2e_profile::Profile;
use wz_app_frame::e2e_stream_sender::{Rollover as StreamRollover, SenderOptions, StreamSender};
use wz_app_frame::segment_sender::{Rollover as SegmentRollover, SegmentSender};

/// The end-to-end profile of the receiver's bench, its counter's width left
/// to fill in: a 64-bit CRC, the counter, a length and a plain identifier,
/// and a sender part derived from the address.
const E2E_PROFILE: &str = r#"{
  "name": "bench",
  "fields": [
    {"name": "crc", "bytes": 8},
    {"name": "counter", "bytes": COUNTER_BYTES},
    {"name": "length", "bytes": 4},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "sender", "lsb": 8, "width": 24,
                "derive": {"from": "address", "mask": "0x00FFFF00", "xor": "0x123400"}},
               {"name": "kind", "lsb": 0, "width": 4}]},
    {"name": "ident", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 64, "poly": "0x1B", "init": "0xFFFFFFFFFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFFFFFFFFFF",
          "cover": ["counter", "@payload", "length", "cell", "ident"]},
  "length": {"field": "length", "counts": "frame_minus", "fields": ["crc"]},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100},
  "judge": {"ident": "ident"},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"#;

/// The segment profile of the crate's synthetic one, its transfer number's
/// width left to fill in.
const SEGMENT_PROFILE: &str = concat!(
    r#"{"name":"bench-split","segments":{"fields":["#,
    r#"{"name":"mark","bytes":2,"equals":"0xA5C3"},"#,
    r#"{"name":"origin","bytes":2,"order":"little"},"#,
    r#"{"name":"number","bytes":NUMBER_BYTES},"#,
    r#"{"name":"size","bytes":3,"order":"little"},"#,
    r#"{"name":"at","bytes":3,"order":"little"},"#,
    r#"{"name":"check","bytes":2}],"#,
    r#""crc":{"field":"check","width":16,"poly":"0x8005","init":"0x0000","#,
    r#""refin":true,"refout":true,"xorout":"0x0000","#,
    r#""cover":["mark","origin","number","size","at","@chunk"]},"#,
    r#""stream":["origin"],"transfer":"number","total":"size","offset":"at","#,
    r#""total_max":4096}}"#
);
const SEGMENT_VALUES: &str = r#"{"origin":"0x0102"}"#;

const ADDRESS: u64 = 0x0A1B_2C3D;
const PAYLOAD: &[u8] = b"payload!";
const MESSAGE_BYTES: usize = 48;
const CHUNK_BYTES: usize = 16;
const ROUNDS: u64 = 4_000;
const RUNS: usize = 9;

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    xs[xs.len() / 2]
}

/// One unmeasured run, then the median of `RUNS` measured ones, of `run`,
/// which does `items` of what is measured.
fn per_item(items: u64, mut run: impl FnMut()) -> f64 {
    run();
    let mut ns = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        run();
        ns.push(start.elapsed().as_nanos() as f64 / items as f64);
    }
    median(ns)
}

fn protect(counter_bytes: u8, rollover: StreamRollover, crc_cache: bool, streams: usize) -> f64 {
    let text = E2E_PROFILE.replace("COUNTER_BYTES", &counter_bytes.to_string());
    let profile = Profile::parse(&text).expect("the profile is valid");
    let values = Values::new()
        .whole("ident", 0x7E57)
        .parts("cell", &[("kind", 9)])
        .address(ADDRESS);
    let options = SenderOptions {
        streams,
        first_counter: 0,
        rollover,
        crc_cache,
    };
    let mut tx = StreamSender::new(profile, values, options).expect("made");
    let mut out = vec![0u8; tx.frame_bytes(PAYLOAD.len())];
    let frames = ROUNDS * streams as u64;
    per_item(frames, || {
        for i in 0..frames {
            let stream = (i % streams as u64) as usize;
            let written = tx.protect_into(black_box(stream), black_box(PAYLOAD), &mut out);
            black_box(written.expect("protected"));
        }
    })
}

fn split(number_bytes: u8, rollover: SegmentRollover, first: u64) -> f64 {
    let text = SEGMENT_PROFILE.replace("NUMBER_BYTES", &number_bytes.to_string());
    let mut tx = SegmentSender::new(&text, SEGMENT_VALUES, first, rollover).expect("made");
    let message: Vec<u8> = (0..MESSAGE_BYTES).map(|i| (i * 7 + 3) as u8).collect();
    per_item(ROUNDS, || {
        for _ in 0..ROUNDS {
            let done = tx.split::<()>(black_box(&message), CHUNK_BYTES, |piece| {
                black_box(piece);
                Ok(())
            });
            black_box(done.expect("split"));
        }
    })
}

fn main() {
    println!("case\tstreams\tns");
    let e2e = [
        ("e2e-4B-refuse", 4, StreamRollover::Refuse),
        ("e2e-1B-wrap", 1, StreamRollover::Wrap),
    ];
    for (name, counter_bytes, rollover) in e2e {
        for crc_cache in [false, true] {
            let cache = if crc_cache { "-cache" } else { "" };
            for streams in [1usize, 4] {
                let ns = protect(counter_bytes, rollover, crc_cache, streams);
                println!("{name}{cache}\t{streams}\t{ns:.1}");
            }
        }
    }
    let segment = [
        ("segment-4B-refuse", 4, SegmentRollover::Refuse, 0),
        ("segment-1B-restart", 1, SegmentRollover::Restart, 1),
    ];
    for (name, number_bytes, rollover, first) in segment {
        println!("{name}\t1\t{:.1}", split(number_bytes, rollover, first));
    }
}
