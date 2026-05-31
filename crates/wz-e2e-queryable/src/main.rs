// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal queryable-only facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the queryable-only coherent facade subset (see this
//! crate's `Cargo.toml`) and answers a foreign zenoh-pico `z_get`'s
//! query: the acceptor registers ONE queryable whose callback emits a
//! single Put-form Reply; the queryable dispatch path (driven by the
//! shared harness's drive loop) emits the terminating ResponseFinal.
//!
//! Direction is wz = data SOURCE (the queryable answers). Deliberately
//! uses ONLY the queryable surface (`declare_queryable` + `ReplyEmitter`)
//! so the source compiles under the pinned subset with zero `#[cfg]`. The
//! acceptor scaffolding (bind / accept / open / drive / teardown) lives
//! in [`wz_e2e_harness`]; this binary is just its CLI + setup closure.

use std::process::ExitCode;

use wz::runtime_tokio::session::QueryableOptions;
use wz_e2e_harness::{run_acceptor_e2e, run_main};

const BINARY: &str = "wz-e2e-queryable";

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-queryable --listen <ADDR> --queryable <KEY> --reply <VALUE>");
        return ExitCode::FAILURE;
    };
    let CliArgs {
        listen,
        queryable_key,
        reply,
    } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Register one queryable. The callback emits a Put-form Reply;
            // the terminating ResponseFinal is scheduled by the queryable
            // dispatch path and flushed by the harness's drive loop. The
            // returned Queryable handle is held by the harness across the
            // loop (its Drop unregisters at teardown).
            let pattern_for_callback = queryable_key.clone();
            opened
                .session
                .declare_queryable(
                    queryable_key,
                    QueryableOptions::default(),
                    move |_event, responder| {
                        responder.reply(reply.as_bytes());
                        log::info!(
                            "{BINARY}: QUERYABLE FIRED pattern='{}' rid={} keyexpr='{}' reply='{}'",
                            pattern_for_callback,
                            responder.rid(),
                            responder.keyexpr_literal(),
                            reply,
                        );
                    },
                )
                .map_err(|e| std::io::Error::other(format!("declare_queryable failed: {e:?}")))
        }),
    )
}

/// Parsed `--listen / --queryable / --reply` triple. All three are
/// mandatory; this binary has exactly one mode.
struct CliArgs {
    listen: String,
    queryable_key: String,
    reply: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut queryable_key = None;
        let mut reply = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--queryable" => queryable_key = args.next(),
                "--reply" => reply = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            queryable_key: queryable_key?,
            reply: reply?,
        })
    }
}
