// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2107 (open-debt item 527) — what one decoded byte costs, separated from
//! what one decoded PACKET costs.
//!
//! # The debt this closes is "we do not know", not "it is slow"
//!
//! A downstream consumer measured `Dissection::push_packet` at ~963 ns/packet
//! and described the shape as roughly a fixed cost plus a few ns per byte,
//! with the byte-proportional part an order of magnitude above a plain memcpy
//! — which would mean several copies on the reassembly path. That number is
//! theirs. Measured 2026-08-25, this tree had NO `[[bench]]` target and no
//! `benches/` directory anywhere, so it could neither reproduce the figure nor
//! produce evidence against it. That is the actual defect: not a cost, but the
//! absence of any instrument that could settle a claim about one.
//!
//! The report also said the question was not urgent "while the boundary
//! dominates". R2102 replaced that boundary — the C ABI's live door hands back
//! fixed-layout binary records instead of a JSON document per batch — so the
//! condition that deferred this has expired.
//!
//! # Why a fit rather than a benchmark number
//!
//! "963 ns/packet" is not a fact about the decoder; it is a fact about the
//! decoder AND the packet size that was used. The claim worth grading is the
//! SHAPE: a fixed per-packet cost plus a per-byte slope. So this measures the
//! same work at several payload sizes and least-squares fits
//! `ns = fixed + slope * bytes`. The intercept is what a zero-length packet
//! would cost and the slope is what one additional byte costs, and only the
//! second is comparable against a copy.
//!
//! The memcpy baseline is measured HERE, in the same process, on the same
//! sizes, through the same clock — not quoted from a table. A ratio against a
//! number from someone else's machine would be arithmetic, not evidence.
//!
//! # What this does NOT do
//!
//! It does not fail on a threshold. A wall-clock number that reds a CI lane on
//! a shared runner is a flake generator, and an arbitrary ceiling is this
//! workspace's "population zero wearing a threshold". What the lane asserts is
//! that the instrument WORKED: `--selftest` recovers known coefficients from
//! synthetic data and refuses a degenerate fit, and a measurement run reports
//! every size in its sweep with a non-zero elapsed time. Reading the numbers,
//! and deciding whether the slope justifies hunting copies, is a person's job
//! — and now a possible one.
//!
//! # Usage
//!
//! ```text
//! cargo bench -p wz-capture --bench decode_cost              # measure
//! cargo bench -p wz-capture --bench decode_cost -- --selftest
//! cargo bench -p wz-capture --bench decode_cost -- --quick   # CI sweep
//! ```

use std::time::Instant;

use wz_capture::link::LINKTYPE_ETHERNET;
use wz_capture::{Dissection, DissectionLimits};
use wz_packet_fixtures::{fill_ipv4_checksum, fill_tcp_checksum};

/// TCP payload sizes the sweep measures, in bytes.
///
/// Spread rather than clustered, because the whole output is a SLOPE: points
/// bunched at one end give a fit whose intercept and slope trade against each
/// other freely, and the two numbers this exists to separate would come back
/// entangled. The top is near an Ethernet MTU, which is where a real capture's
/// bulk packets sit.
const SIZES: &[usize] = &[0, 64, 256, 512, 1024, 1400];

/// Packets pushed per size in a measurement run, and in `--quick`.
///
/// The pair exists because CI and a workstation want different things from the
/// same instrument: a lane needs to know it RAN, a person reading the slope
/// needs the noise down. Neither number is a threshold — they set how long the
/// clock is open, not what it is allowed to say.
const ITERS: usize = 2_000;
const ITERS_QUICK: usize = 50;

/// Wire bytes per KeepAlive: `len_lo, len_hi, T_MID_KEEP_ALIVE`.
///
/// Named because the population floor is DERIVED from it — `iters * size /
/// UNIT_LEN` messages must come out of the sweep — so it is one fact rather
/// than a `3` in the payload builder and another `3` in the check.
const UNIT_LEN: usize = 3;

/// `payload_len` bytes of REAL zenoh session traffic: back-to-back
/// length-prefixed KeepAlives, truncated to length.
///
/// The first version of this filled the payload with `0x5a`, and the numbers
/// it produced were a trap. Junk bytes do not decode, so the message layer
/// never ran and the sweep measured link + IP + TCP reassembly with the
/// message decoder sitting idle — the wrong function, timed accurately, which
/// is what the checksum note below warns about one layer down. `produced()` is
/// what turned that from an opinion into a number: with junk it stays ZERO.
///
/// Three bytes each (`len_lo, len_hi, T_MID_KEEP_ALIVE`), so a 1400-byte
/// payload carries ~466 messages and the byte-proportional term includes the
/// per-message decode a live tap actually pays.
fn zenoh_payload(payload_len: usize) -> Vec<u8> {
    let unit = [1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    debug_assert_eq!(unit.len(), UNIT_LEN);
    let mut out = Vec::with_capacity(payload_len);
    while out.len() < payload_len {
        let take = unit.len().min(payload_len - out.len());
        out.extend_from_slice(&unit[..take]);
    }
    out
}

/// One Ethernet/IPv4/TCP frame carrying `payload_len` bytes.
///
/// Checksums are filled by `wz-packet-fixtures` rather than left zero: over
/// IPv4 a zero TCP checksum is present-and-wrong, and a decoder that files
/// every packet into the corruption bucket would be measured on the error path
/// instead of the reassembly path — the wrong function, timed accurately.
fn tcp_frame(seq: u32, payload_len: usize) -> Vec<u8> {
    let payload = zenoh_payload(payload_len);
    let mut tcp = Vec::with_capacity(20 + payload_len);
    tcp.extend_from_slice(&1111u16.to_be_bytes());
    tcp.extend_from_slice(&7447u16.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(0x10);
    tcp.extend_from_slice(&64u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&payload);
    fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut tcp);

    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    fill_ipv4_checksum(&mut ip);
    ip.extend_from_slice(&tcp);

    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

/// Least squares over `(x, y)`, returning `(intercept, slope)`.
///
/// `None` when every `x` is the same value. That is not defensive padding: a
/// degenerate sweep has no slope to report, and the arithmetic would divide by
/// zero and hand back a NaN or an infinity that prints like a measurement. A
/// fit that cannot separate the two coefficients must say so rather than
/// produce one.
fn fit(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / n;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / n;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for (x, y) in points {
        sxx += (x - mean_x) * (x - mean_x);
        sxy += (x - mean_x) * (y - mean_y);
    }
    if sxx == 0.0 {
        return None;
    }
    let slope = sxy / sxx;
    Some((mean_y - slope * mean_x, slope))
}

/// Nanoseconds per `push_packet`, at one payload size.
///
/// The dissection is BOUNDED (`for_live_tap`) and reused across the batch,
/// which is the regime the item is about: an unbounded one accumulates a
/// growing reassembly buffer for the single 5-tuple this loop feeds, so the
/// later iterations would measure that growth rather than steady-state decode
/// and the slope would come back a function of ITERS.
/// Which ceiling the sweep runs under.
///
/// This is a CONTROL, not an option. The bounded run is the live-tap regime the
/// item is about; the unbounded one is the same decode with no trimming. Two
/// numbers that differ by orders of magnitude attribute the cost to the trim
/// rather than to the decode, and neither number alone can say that.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ceiling {
    LiveTap,
    None,
}

fn decode_ns_per_packet(payload_len: usize, iters: usize, ceiling: Ceiling) -> (f64, u64) {
    // EVERY PACKET CARRIES NEW STREAM BYTES, and this is the correction that
    // makes the whole instrument mean anything. The first version pushed one
    // frame with a fixed `seq` `iters` times; TCP reassembly correctly saw
    // 19 999 retransmissions of data it already held, so only the FIRST
    // packet's bytes were ever decoded and the sweep timed the duplicate-
    // detection path while reporting decode. `produced()` said so — 466
    // messages for 20 000 packets — which is why the population is checked
    // against `iters` below rather than against zero.
    //
    // Built OUTSIDE the clock: the checksum arithmetic is real work and belongs
    // to the fixture, not to the decoder.
    let mut frames = Vec::with_capacity(iters + 64);
    let mut seq: u32 = 1000;
    for _ in 0..iters + 64 {
        frames.push(tcp_frame(seq, payload_len));
        seq = seq.wrapping_add(payload_len as u32);
    }

    let mut d = match ceiling {
        Ceiling::LiveTap => Dissection::with_limits(DissectionLimits::for_live_tap()),
        Ceiling::None => Dissection::new(),
    };
    // Warm the flow table and the allocator so the first push's one-off cost
    // is not spread across the batch.
    for (i, frame) in frames[..64].iter().enumerate() {
        d.push_packet(LINKTYPE_ETHERNET, i, frame);
    }
    let start = Instant::now();
    for (i, frame) in frames[64..].iter().enumerate() {
        d.push_packet(LINKTYPE_ETHERNET, i, frame);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_nanos() > 0,
        "the clock did not move over {iters} packet(s) of {payload_len} byte(s); \
         this measured nothing"
    );
    // `produced()` and not the live list length: `for_live_tap` TRIMS, so the
    // list holds a ceiling's worth while the counter holds everything the
    // decoder ever emitted. This is the population.
    let produced: u64 = d
        .message_lists_with_origin()
        .map(|(_, _, _, list)| list.produced())
        .sum();
    (elapsed.as_nanos() as f64 / iters as f64, produced)
}

/// Nanoseconds to copy the same frame, at one payload size.
///
/// `extend_from_slice` into a reused buffer: the cheapest honest thing that
/// touches every byte once, which is the floor the decoder's per-byte slope is
/// worth comparing against.
fn copy_ns_per_packet(payload_len: usize, iters: usize) -> f64 {
    let frame = tcp_frame(1000, payload_len);
    let mut sink: Vec<u8> = Vec::with_capacity(frame.len());
    for _ in 0..64 {
        sink.clear();
        sink.extend_from_slice(&frame);
    }
    let start = Instant::now();
    for _ in 0..iters {
        sink.clear();
        sink.extend_from_slice(&frame);
    }
    let elapsed = start.elapsed();
    // Keep the compiler from deleting the loop it was asked to time.
    std::hint::black_box(&sink);
    elapsed.as_nanos() as f64 / iters as f64
}

/// Drive the fitter against data whose answer is known.
///
/// The measurement arms cannot grade themselves — a wall clock has no expected
/// value — so what is gradable is the arithmetic between the clock and the
/// report. These arms are deterministic and run everywhere the lane runs.
fn selftest() -> i32 {
    let mut failures = 0;

    // Exact line: the fit must return the coefficients that generated it.
    let pts: Vec<(f64, f64)> = SIZES
        .iter()
        .map(|&b| (b as f64, 900.0 + 3.5 * b as f64))
        .collect();
    match fit(&pts) {
        Some((a, b)) if (a - 900.0).abs() < 1e-6 && (b - 3.5).abs() < 1e-9 => {}
        other => {
            failures += 1;
            println!("  FAIL exact line: fit returned {other:?}, expected (900, 3.5)");
        }
    }

    // A FLAT line has slope zero and an intercept, which is the shape a decoder
    // whose cost did not depend on size would produce. The fitter must report
    // that rather than refuse it: "no per-byte cost" is an answer.
    let flat: Vec<(f64, f64)> = SIZES.iter().map(|&b| (b as f64, 500.0)).collect();
    match fit(&flat) {
        Some((a, b)) if (a - 500.0).abs() < 1e-6 && b.abs() < 1e-9 => {}
        other => {
            failures += 1;
            println!("  FAIL flat line: fit returned {other:?}, expected (500, 0)");
        }
    }

    // Every x identical: no slope exists. A number here would be a division by
    // zero wearing a unit.
    let degenerate: Vec<(f64, f64)> = (0..5).map(|i| (128.0, 100.0 + i as f64)).collect();
    if let Some(bad) = fit(&degenerate) {
        failures += 1;
        println!("  FAIL degenerate sweep: fit returned {bad:?}, expected a refusal");
    }

    // One point cannot carry two coefficients.
    if let Some(bad) = fit(&[(64.0, 1.0)]) {
        failures += 1;
        println!("  FAIL single point: fit returned {bad:?}, expected a refusal");
    }

    // The frame builder must actually grow with the payload, or the sweep the
    // fit runs on would be the degenerate case above wearing real timings.
    let small = tcp_frame(1, 64).len();
    let large = tcp_frame(1, 1400).len();
    if large - small != 1400 - 64 {
        failures += 1;
        println!("  FAIL frame builder: 64 -> {small} bytes, 1400 -> {large}; the sweep is flat");
    }

    let total = 5;
    println!(
        "decode-cost selftest: {}/{total} arm(s) pass",
        total - failures
    );
    i32::from(failures > 0)
}

fn measure(iters: usize) -> i32 {
    let mut decode = Vec::new();
    let mut unbounded = Vec::new();
    let mut copy = Vec::new();
    let mut starved = Vec::new();
    println!("  payload   bounded ns/pkt   unbounded ns/pkt   memcpy ns/pkt   messages");
    for &size in SIZES {
        let (d, produced) = decode_ns_per_packet(size, iters, Ceiling::LiveTap);
        let (u, _) = decode_ns_per_packet(size, iters, Ceiling::None);
        let c = copy_ns_per_packet(size, iters);
        println!("  {size:>7}   {d:>14.1}   {u:>16.1}   {c:>13.1}   {produced:>8}");
        unbounded.push((size as f64, u));
        // THE FLOOR IS DERIVED FROM THE PAYLOAD, not picked. Every byte pushed
        // belongs to a 3-byte KeepAlive, so `iters * size / 3` messages must
        // come out; the slack is one per packet, for the unit straddling a
        // packet boundary that only completes with the next one.
        //
        // `produced > 0` was the first form of this and it was too weak: the
        // retransmission bug delivered ONE packet's 466 messages, which cleared
        // zero easily and even cleared `iters` at the larger sizes. A floor that
        // does not scale with the sweep is a floor the sweep can walk under.
        let expected = (iters * size / UNIT_LEN) as u64;
        if expected > 0 && produced + (iters as u64) < expected {
            starved.push((size, produced, expected));
        }
        decode.push((size as f64, d));
        copy.push((size as f64, c));
    }
    if !starved.is_empty() {
        println!(
            "decode-cost FAIL: (size, decoded, expected) {starved:?}. Every \
             byte pushed belongs to a {UNIT_LEN}-byte message, so the sweep \
             timed something other than decode -- duplicate detection, a \
             rejected checksum, or a flow that never opened."
        );
        return 1;
    }

    let (Some((d_fixed, d_slope)), Some((u_fixed, u_slope)), Some((_, c_slope))) =
        (fit(&decode), fit(&unbounded), fit(&copy))
    else {
        println!("decode-cost FAIL: the sweep did not admit a fit");
        return 1;
    };

    println!(
        "decode-cost: {} size(s) x {iters} packet(s)\n  \
         bounded (live tap): fixed {d_fixed:.0} ns/packet, {d_slope:.2} ns/byte, \
         {:.0}x memcpy\n  \
         unbounded:          fixed {u_fixed:.0} ns/packet, {u_slope:.2} ns/byte, \
         {:.0}x memcpy\n  \
         memcpy floor:       {c_slope:.3} ns/byte",
        SIZES.len(),
        d_slope / c_slope,
        u_slope / c_slope,
    );
    println!(
        "  the bounded/unbounded ratio is {:.0}x -- a gap here attributes the \
         per-byte cost to the CEILING's trim rather than to the decode itself.",
        d_slope / u_slope,
    );
    println!(
        "  (no threshold is asserted -- see this file's module doc for why; \
         the numbers are the output, the selftest is the gate)"
    );
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `cargo bench` passes its own harness flags through to a `harness = false`
    // target, so an unknown argument is IGNORED rather than refused here. That
    // is the opposite of the rule item 523 established for a program that
    // WRITES, and the difference is the point: this one only reads a clock.
    if args.iter().any(|a| a == "--selftest") {
        std::process::exit(selftest());
    }
    let iters = if args.iter().any(|a| a == "--quick") {
        ITERS_QUICK
    } else {
        ITERS
    };
    std::process::exit(measure(iters));
}
