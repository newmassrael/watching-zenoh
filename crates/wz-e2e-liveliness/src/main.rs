// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal liveliness-subscriber-only facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the liveliness-subscriber-only coherent facade subset
//! (see this crate's `Cargo.toml`) and OBSERVES a foreign zenoh-pico
//! `z_liveliness` declarer's token: the acceptor registers ONE
//! liveliness subscriber whose callback logs each inbound liveliness
//! sample (PUT on declare, DELETE on undeclare).
//!
//! Direction is wz = SUBSCRIBER (sink), not declarer — wz's declarer
//! lacks nothing now (R283), but this binary's job is the subscriber
//! plane; its symmetric DECLARER sibling is wz-e2e-liveliness-token.
//! Deliberately uses ONLY the liveliness-subscriber surface
//! (`declare_liveliness_subscriber` + `LivelinessSample`) so the source
//! compiles under the pinned subset with zero `#[cfg]`. The acceptor
//! scaffolding lives in [`wz_e2e_harness`]; this binary is just its CLI
//! + setup closure.

use std::process::ExitCode;

use wz::runtime_tokio::declare::{LivelinessSample, LivelinessSampleKind};
use wz::runtime_tokio::session::LivelinessSubscriberOptions;
use wz_e2e_harness::{run_acceptor_e2e, run_main};

const BINARY: &str = "wz-e2e-liveliness";

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-liveliness --listen <ADDR> --subscribe <KEY>");
        return ExitCode::FAILURE;
    };
    let CliArgs {
        listen,
        subscribe_key,
    } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Register one liveliness subscriber. declare_liveliness_
            // subscriber also emits the outbound liveliness Interest so
            // the foreign declarer responds with its current tokens. The
            // returned handle is held by the harness across the loop.
            let filter_for_callback = subscribe_key.clone();
            opened
                .session
                .declare_liveliness_subscriber(
                    subscribe_key,
                    LivelinessSubscriberOptions::default(),
                    move |sample: LivelinessSample<'_>| {
                        let kind_str = match sample.kind {
                            LivelinessSampleKind::Put => "PUT",
                            LivelinessSampleKind::Delete => "DELETE",
                        };
                        log::info!(
                            "{BINARY}: LIVELINESS SAMPLE {kind_str} filter='{}' \
                             keyexpr='{}' token_id={}",
                            filter_for_callback,
                            sample.keyexpr,
                            sample.token_id,
                        );
                    },
                )
                .map_err(|e| {
                    std::io::Error::other(format!("declare_liveliness_subscriber failed: {e:?}"))
                })
        }),
    )
}

/// Parsed `--listen / --subscribe` pair. Both are mandatory; this binary
/// has exactly one mode.
struct CliArgs {
    listen: String,
    subscribe_key: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut subscribe_key = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--subscribe" => subscribe_key = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            subscribe_key: subscribe_key?,
        })
    }
}
