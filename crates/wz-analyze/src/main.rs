// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y664 (§1.2a) — the binary. Everything except file IO is in the library
//! beside it, which is what lets the behaviour be tested without writing
//! anything to disk.

use std::process::ExitCode;

use wz_analyze::{analyze_request, parse, Request, USAGE};

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
    let capture = match std::fs::read(&options.capture) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("wz-analyze: {}: {err}", options.capture);
            return ExitCode::from(2);
        }
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
    let (rendered, outcome) = match analyze_request(&Request {
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
        health: options.health,
        select: options.select.as_ref(),
    }) {
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
