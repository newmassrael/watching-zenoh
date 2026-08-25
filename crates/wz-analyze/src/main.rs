// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y664 (§1.2a) — the binary. Everything except file IO is in the library
//! beside it, which is what lets the behaviour be tested without writing
//! anything to disk.

use std::process::ExitCode;

use wz_analyze::{analyze_request, parse, Request, USAGE};

/// What a live read produced: the dissection, and the sentence that says how it
/// ended.
struct LiveRead {
    dissection: wz_capture::Dissection,
    line: String,
}

/// Round 1999 (item 470) — read a live tap for `bound_ms` and dissect what
/// arrives.
///
/// The loop is here rather than in the library for the reason the module doc
/// gives: this is the file that is allowed to touch the outside world. What it
/// must not do is decide the bound, which is why `bound_ms` is a parameter the
/// parser refuses to default.
///
/// ⚠ THE DROP COUNT IS READ ONCE, AT THE END, AND THAT IS DELIBERATE.
/// `PACKET_STATISTICS` is read-and-clear (see `LiveTap::take_stats`), so a
/// caller polling it inside the loop would consume the number for the caller
/// that reports it. One reader, one read.
fn live_read(interface: &str, bound_ms: u64) -> std::io::Result<LiveRead> {
    use std::time::{Duration, Instant};
    use wz_packet_socket::live_capture::{pump, LiveTap};

    let bound = Duration::from_millis(bound_ms);
    // The read timeout is what makes the bound observable at all: `pump`
    // returns on an idle source, so a quiet wire hands control back rather
    // than blocking past the deadline. Capped at the bound so a short read is
    // not rounded up by one timeout.
    let timeout = bound.min(Duration::from_millis(200));
    let mut tap = LiveTap::open_with_timeout(interface, timeout)?;
    // Clear whatever the kernel counted before this read began; those drops
    // belong to nobody's report.
    let _ = tap.take_stats()?;

    let mut dissection = wz_capture::Dissection::new();
    let started = Instant::now();
    let mut read = 0usize;
    while started.elapsed() < bound {
        // A generous per-call budget rather than one packet at a time: the
        // deadline is checked between batches, and a batch that fills is a busy
        // wire the loop should keep draining.
        read += pump(&mut tap, &mut dissection, 4096)?;
    }
    let elapsed = started.elapsed();
    let stats = tap.take_stats()?;
    dissection.finish();

    let line = format!(
        "wz-analyze: live tap on {interface}: read {read} packet(s) in {:.1}s, \
         stopped by --for; kernel received {} dropped {}{}",
        elapsed.as_secs_f64(),
        stats.received,
        stats.dropped,
        if stats.lossy() {
            " -- THE HOLES BELOW ARE PARTLY THIS MACHINE'S, not the network's"
        } else {
            ""
        }
    );
    Ok(LiveRead { dissection, line })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(&argv) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("wz-analyze: {err}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // Round 1999 (item 470) — a live tap is the OTHER source, and the parser
    // has already refused every combination where both or neither is named.
    let live = match options.interface.as_deref() {
        Some(name) => match live_read(name, options.live_ms.expect("parser requires --for")) {
            Ok(read) => Some(read),
            Err(err) => {
                eprintln!("wz-analyze: {name}: {err}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let capture = match &live {
        // The tap keeps no capture blob. `analyze_dissection`'s doc says which
        // one thing still reads this, and the parser refuses that flag here.
        Some(_) => Vec::new(),
        None => match std::fs::read(&options.capture) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("wz-analyze: {}: {err}", options.capture);
                return ExitCode::from(2);
            }
        },
    };
    // R311y708 (Y4) — every `--keylog` the command line named, joined.
    //
    // The join is where the multiplicity belongs: a command line has N files and
    // the analysis wants one key log text, and NSS key logs are line-oriented,
    // so appending them IS the merge. The `\n` between them is not cosmetic --
    // a file that does not end in a newline would otherwise glue its last line
    // onto the next file's first, producing two keys where there were three and
    // no error to say so.
    let mut keylog: Option<Vec<u8>> = None;
    for path in &options.keylogs {
        match std::fs::read(path) {
            Ok(bytes) => {
                let merged = keylog.get_or_insert_with(Vec::new);
                if !merged.is_empty() && !merged.ends_with(b"\n") {
                    merged.push(b'\n');
                }
                merged.extend_from_slice(&bytes);
            }
            Err(err) => {
                // A key log named and not readable is a HARD failure, not a
                // fallback to analysing without it: the caller asked for those
                // keys, and a report saying the capture could not be decrypted
                // would be the wrong answer to the question they asked.
                eprintln!("wz-analyze: {path}: {err}");
                return ExitCode::from(2);
            }
        }
    }

    // R311y670 — every option the command line accepts reaches the analysis.
    // The two added this round had to, or they would have been flags the parser
    // read and nothing acted on.
    // R311y673 — and the request is now DESCRIBED rather than enumerated, so a
    // new option is a named field here instead of a positional slot that
    // type-checks in the wrong place.
    let request = Request {
        capture: &capture,
        keylog: keylog.as_deref(),
        format: options.format,
        per_flow: options.per_flow,
        per_message: options.per_message,
        messages_per_flow: options.max_messages,
        quic_ports: &options.quic_ports,
        quic_cid_len: options.quic_cid_len,
        payload_rules: &options.payload_formats,
        payload_field_names: &options.payload_field_names,
        serial_linktypes: &options.serial_linktypes,
        census: options.census,
        per_field: options.per_field,
        bounded: options.bounded,
        health: options.health,
        select: options.select.as_ref(),
        csv: options.csv,
    };
    let analysed = match live {
        Some(read) => {
            // THE BOUND IS NAMED, and so is the kernel's drop count. Printed
            // BEFORE the report rather than after: a reader who learns the tap
            // dropped 60 000 packets only below the totals has already read the
            // totals as a fact about the network.
            eprintln!("{}", read.line);
            wz_analyze::analyze_dissection(read.dissection, &request)
        }
        None => analyze_request(&request),
    };
    let (rendered, outcome) = match analysed {
        Ok(out) => out,
        Err(err) => {
            eprintln!("wz-analyze: {}: {err:?}", options.capture);
            return ExitCode::from(2);
        }
    };
    println!("{rendered}");
    if outcome.foreign_secrets_blocks > 0 {
        eprintln!(
            "wz-analyze: {} decryption secrets block(s) carry another protocol's secrets",
            outcome.foreign_secrets_blocks
        );
    }
    // 0 = this reader saw the whole capture. 1 = it did not, which covers an
    // undecrypted flow, a gap, a dropped packet. Distinct from 2, which is this
    // tool failing rather than the capture being incomplete.
    if outcome.complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
