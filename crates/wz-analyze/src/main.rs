// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y664 (§1.2a) — the binary. Everything except file IO is in the library
//! beside it, which is what lets the behaviour be tested without writing
//! anything to disk.

use std::process::ExitCode;

use wz_analyze::{analyze_with, parse, USAGE};

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
    let keylog = match options.keylog.as_deref().map(std::fs::read) {
        None => None,
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(err)) => {
            // A key log named and not readable is a HARD failure, not a
            // fallback to analysing without it: the caller asked for those keys,
            // and a report saying the capture could not be decrypted would be
            // the wrong answer to the question they asked.
            eprintln!(
                "wz-analyze: {}: {err}",
                options.keylog.as_deref().unwrap_or("<keylog>")
            );
            return ExitCode::from(2);
        }
    };

    let (rendered, outcome) = match analyze_with(
        &capture,
        keylog.as_deref(),
        options.format,
        options.per_flow,
        options.per_message,
    ) {
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
