// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal liveliness-token-DECLARER facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the liveliness-token declarer subset (see this crate's
//! `Cargo.toml`) and proves the R283 inbound-Interest response
//! interoperates with a foreign zenoh-pico `z_get_liveliness` querier:
//! the acceptor declares ONE LivelinessToken, and when the querier's
//! non-final liveliness Interest arrives the observer's declarer-side
//! registry replies with an interest_id-tagged `Declare(DeclToken)` +
//! `Declare(DeclFinal)` (R283), satisfying the one-shot CURRENT query.
//!
//! Determinism: the shared harness runs the setup closure (the
//! `declare_token` below) BEFORE it enters the drive loop, so the token
//! is registered in the observer's `local_tokens` registry before ANY
//! inbound Interest is processed — exactly the ordering a one-shot
//! CURRENT querier (no future subscription) needs. (wz-ap-demo declares
//! in a background task gated on Established, which races the inbound
//! Interest; this binary's synchronous-before-loop declare is why it is
//! a dedicated declarer rather than a wz-ap-demo mode.)
//!
//! Symmetric sibling of `wz-e2e-liveliness` (the subscriber side).

use std::process::ExitCode;

use wz::runtime_tokio::session::LivelinessOptions;
use wz_e2e_harness::{run_acceptor_e2e, run_main};

const BINARY: &str = "wz-e2e-liveliness-token";

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-liveliness-token --listen <ADDR> --token <KEY>");
        return ExitCode::FAILURE;
    };
    let CliArgs { listen, token_key } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Declare the token. The harness runs this BEFORE the drive
            // loop, so the token is registered in observer.local_tokens
            // before any inbound Interest is processed — the deterministic
            // R283 ordering. declare_token both emits the proactive
            // Declare(DeclToken) and registers the token; the returned
            // handle is held by the harness across the loop, and its Drop
            // (UndeclToken) fires at teardown (the harness drops the hold
            // before closing the writer channel).
            let token = opened
                .session
                .declare_token(token_key.clone(), LivelinessOptions::default())
                .map_err(|e| std::io::Error::other(format!("declare_token failed: {e:?}")))?;
            log::info!("{BINARY}: DECLARED TOKEN keyexpr='{token_key}'");
            Ok(token)
        }),
    )
}

/// Parsed `--listen / --token` pair. Both are mandatory; this binary has
/// exactly one mode.
struct CliArgs {
    listen: String,
    token_key: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut token_key = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--token" => token_key = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            token_key: token_key?,
        })
    }
}
