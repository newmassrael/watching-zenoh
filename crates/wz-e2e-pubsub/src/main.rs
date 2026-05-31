// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal pubsub-only facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the pubsub-only coherent facade subset (see this crate's
//! `Cargo.toml`) and PUBLISHES a small burst of literal-keyexpr Put
//! Pushes that a foreign zenoh-pico `z_sub` client receives. Direction
//! is wz = data SOURCE.
//!
//! Deliberately uses ONLY the pub/sub surface (`Session::publish`) so the
//! source compiles under the pinned subset with zero `#[cfg]`. The
//! acceptor scaffolding (bind / accept / open / drive / teardown) lives
//! in [`wz_e2e_harness`]; this binary is its CLI + the publish-burst
//! setup closure (the one wz-e2e-* setup that EMITS rather than registers
//! a reactive handle — it returns an [`wz_e2e_harness::AbortOnDrop`] so
//! the harness stops the burst at teardown).

use std::process::ExitCode;

use wz::runtime_core::TimeSource;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::PublishOptions;
use wz::runtime_tokio::Reliability;
use wz_e2e_harness::{run_acceptor_e2e, run_main, AbortOnDrop};

const BINARY: &str = "wz-e2e-pubsub";

/// Number of Put Pushes emitted once Established. A short burst (rather
/// than a single Push) makes the round-trip robust against the foreign
/// subscriber's receive-task scheduling without depending on exact
/// timing.
const PUBLISH_BURST: usize = 8;
/// Spacing between burst Pushes; keeps the burst well inside the
/// integration test's receive window while not hammering the link.
const BURST_INTERVAL_MS: u64 = 150;

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-pubsub --listen <ADDR> --publish <KEY> --value <VALUE>");
        return ExitCode::FAILURE;
    };
    let CliArgs {
        listen,
        publish_key,
        value,
    } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Spawn the publish burst. A pure publisher registers no
            // reactive callback; the burst runs as a background task and
            // is returned wrapped in AbortOnDrop so the harness stops it
            // at teardown. The Session + clock are cloned/copied into the
            // task (the harness keeps its own clones alive across the
            // loop).
            let session = opened.session.clone();
            let clock = opened.clock;
            let publisher = tokio::spawn(async move {
                for idx in 0..PUBLISH_BURST {
                    let mut opts =
                        PublishOptions::default().with_reliability(Reliability::Reliable);
                    opts.kind = SampleKind::Put;
                    let fired = session.publish(&publish_key, value.as_bytes(), opts);
                    log::info!(
                        "{BINARY}: PUBLISHER EMITTED idx={idx} keyexpr='{publish_key}' \
                         payload_len={} loopback_fired={fired}",
                        value.len()
                    );
                    clock.sleep(BURST_INTERVAL_MS).await;
                }
                log::info!("{BINARY}: publisher burst complete");
            });
            Ok::<_, std::io::Error>(AbortOnDrop(publisher))
        }),
    )
}

/// Parsed `--listen / --publish / --value` triple. All three are
/// mandatory; this binary has exactly one mode.
struct CliArgs {
    listen: String,
    publish_key: String,
    value: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut publish_key = None;
        let mut value = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--publish" => publish_key = args.next(),
                "--value" => value = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            publish_key: publish_key?,
            value: value?,
        })
    }
}
