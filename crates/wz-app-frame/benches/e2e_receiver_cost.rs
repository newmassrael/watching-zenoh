// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the end-to-end receiver costs per frame under sender keying, and what
//! naming the sender of a slot costs, at several counts of senders.
//!
//! # Why it exists
//!
//! Logic moved from hand Rust into SCE documents must keep the cost it had
//! (owner, 2026-11-27). The receiver's table of senders moved (census row S11
//! 2): the slot of a frame's sender was a scan of the streams, and is now a
//! look-up in the map the SCE algorithms write. Nothing measured the receive
//! path, so the move could be neither shown to keep its cost nor shown to lose
//! it. This is that instrument: the same program built against the tree before
//! the move and after it, on one machine, gives the two figures to compare.
//!
//! # What it measures
//!
//! For 1, 2, 4, 8 and 16 senders, each holding a slot: the nanoseconds of one
//! `Receiver::receive` of an intact frame, the senders taking turns, each
//! frame one counter step after its sender's last (the path every frame of a
//! healthy stream takes), and the nanoseconds of one `Receiver::slot_sender`.
//! Each figure is the median of nine runs of the whole loop. The frames are
//! built before the clock starts.
//!
//! # What it does not do
//!
//! It fails on no threshold: a wall-clock figure on a shared machine is not a
//! verdict by itself. A comparison runs the before and after programs
//! alternately on one idle machine and reads the medians.

use std::hint::black_box;
use std::time::Instant;

use wz_app_frame::e2e_frame::{build, Values};
use wz_app_frame::e2e_profile::Profile;
use wz_app_frame::e2e_receiver::{Keying, Receiver};

/// A profile with a sender part derived from the address, as the model tests'
/// right-hand layout: a 64-bit CRC, a four-byte counter, a length and a plain
/// identifier.
const PROFILE: &str = r#"{
  "name": "bench",
  "fields": [
    {"name": "crc", "bytes": 8},
    {"name": "counter", "bytes": 4},
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

const BASE_ADDRESS: u64 = 0x0A1B_2C3D;
const ROUNDS: u64 = 4_000;
const RUNS: usize = 9;

fn values(address: u64) -> Values {
    Values::new()
        .whole("ident", 0x7E57)
        .parts("cell", &[("kind", 9)])
        .address(address)
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    xs[xs.len() / 2]
}

fn main() {
    let profile = Profile::parse(PROFILE).expect("the profile is valid");
    let expected = values(BASE_ADDRESS);
    println!("senders\treceive_ns\tslot_sender_ns");
    for senders in [1u64, 2, 4, 8, 16] {
        // Senders differ in the bits the profile's mask keeps (8 to 23).
        let addresses: Vec<u64> = (0..senders).map(|i| BASE_ADDRESS ^ (i << 8)).collect();
        // Every frame of every run, built before any clock starts: run r, round k, sender s
        // carries the counter r * ROUNDS + k + 1, one step after the frame before it.
        let frames: Vec<Vec<Vec<u8>>> = (0..RUNS as u64 + 1)
            .map(|run| {
                (0..ROUNDS * senders)
                    .map(|i| {
                        let counter = run * ROUNDS + i / senders + 1;
                        let address = addresses[(i % senders) as usize];
                        build(
                            &profile,
                            &values(address).whole("counter", counter),
                            b"payload",
                        )
                        .expect("the frame builds")
                        .bytes
                    })
                    .collect()
            })
            .collect();
        let mut rx = Receiver::new(
            profile.clone(),
            &expected,
            Keying::Senders {
                slots: senders as usize,
                bound: None,
            },
            None,
            64,
        )
        .expect("made");
        // Run 0 gives every sender its slot and its baseline, unmeasured.
        let mut now = 0u64;
        for frame in &frames[0] {
            now += 1;
            black_box(rx.receive(0, frame, now).expect("judged"));
        }
        let mut receive = Vec::with_capacity(RUNS);
        let mut naming = Vec::with_capacity(RUNS);
        for run in &frames[1..] {
            let start = Instant::now();
            for frame in run {
                now += 1;
                black_box(rx.receive(0, black_box(frame), now).expect("judged"));
            }
            receive.push(start.elapsed().as_nanos() as f64 / run.len() as f64);
            let start = Instant::now();
            for _ in 0..ROUNDS {
                for slot in 0..senders as usize {
                    black_box(rx.slot_sender(black_box(slot)));
                }
            }
            naming.push(start.elapsed().as_nanos() as f64 / (ROUNDS * senders) as f64);
        }
        println!("{senders}\t{:.1}\t{:.1}", median(receive), median(naming));
    }
}
