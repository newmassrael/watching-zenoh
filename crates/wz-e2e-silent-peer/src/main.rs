// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A peer whose only job is to never answer.
//!
//! R311y338. Completes the session handshake, stays transport-alive, and
//! never answers an application Request. It is the fixture half of the
//! `--query-timeout-ms` e2e: the requester's timeout must be the ONLY thing
//! that terminates its query, so the peer must be silent by contract rather
//! than by accident. See this crate's `Cargo.toml` for why that distinction
//! is the whole point — R264's predecessor fixture borrowed its silence from
//! what turned out to be R311y337's defect, and inverted the day it was fixed.
//!
//! There is no setup closure, because there is nothing to register: this
//! binary pins no response plane, so a Reply and a ResponseFinal are types it
//! does not have. The harness still drives the session FSM, so keepalive and
//! lease behave exactly as a live peer's — the peer is UP, it simply never
//! answers. That is the shape of the thing a query timeout defends against.
//!
//! Deliberately NOT a wz-ap-demo variant: a flag like `--never-answer` would
//! put a be-broken switch in a reference binary, and a feature-stripped demo
//! would read as "the demo, crippled". This is its own crate so its name and
//! its manifest both say what it is.

use std::process::ExitCode;

use wz_e2e_harness::{run_main, run_silent_acceptor_e2e};

const BINARY: &str = "wz-e2e-silent-peer";

fn main() -> ExitCode {
    let Some(listen) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-silent-peer --listen <ADDR>");
        return ExitCode::FAILURE;
    };

    run_main(
        BINARY,
        // `run_silent_acceptor_e2e`, NOT `run_acceptor_e2e` with an empty
        // setup. The difference is load-bearing and was measured: an empty
        // setup still dispatches, so the double's silence would rest on which
        // response plane the BUILD GRAPH compiled in — and cargo unifies
        // features across packages built in one invocation, so a single
        // `cargo build -p wz-ap-demo -p wz-e2e-silent-peer` re-arms it and the
        // query-timeout e2e silently becomes a happy-path test. The silent
        // loop keeps the silence in code this binary owns, where unification
        // cannot reach it. The manifest's omission of the response plane is
        // defence in depth on top of that, not the guarantee itself.
        run_silent_acceptor_e2e(BINARY, listen),
    )
}

/// `--listen <ADDR>` and nothing else. There is no key, no reply payload and
/// no target: this peer answers nothing, so it needs to be told nothing.
struct CliArgs;

impl CliArgs {
    fn parse(args: impl Iterator<Item = String>) -> Option<String> {
        let rest: Vec<String> = args.collect();
        parse_pair(&rest, "--listen")
    }
}

/// Minimal `--flag <value>` lookup, mirroring the sibling e2e binaries'
/// hand-rolled parsing (no clap in the e2e binaries).
fn parse_pair(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
