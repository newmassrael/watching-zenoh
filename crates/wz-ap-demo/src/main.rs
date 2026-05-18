// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — AP MVP demo binary entry point.
//
// R121a: skeleton round. Surfaces the binary entry point + CLI argv
// shape that the R121b functional round consumes. Intentionally
// minimal-but-real (the R63 retired wz-runtime-lwip NOP-stub was the
// anti-pattern precedent we avoid here): no faked session work, no
// stub callbacks pretending to be wired — just argv parse + a
// truthful "skeleton round, functional impl lands at R121b" message
// the integration harness can grep for to confirm it launched the
// right binary build.
//
// CLI shape (locked at R121a; consumed by R121b runtime + R121c
// integration test fixtures):
//
//   wz-ap-demo --listen <tcp_addr> --key <keyexpr>
//
//   --listen   server-side TCP bind address (e.g. 127.0.0.1:7447)
//              wz-runtime-tokio session FSM will bind + accept here.
//   --key      DECLARE subscriber keyexpr (e.g. demo/example/**)
//              registered with the pubsub registry on session-up.
//
// Round rollout:
//   - R121a (this round) — argv parse + skeleton ack; exits success
//     after printing the parsed arg set. Dependencies = 0.
//   - R121b — session FSM start + DECLARE subscriber + msg_put
//     inbound dispatch wiring driven by --listen + --key. Adds
//     wz-runtime-tokio + wz-codecs + tokio + log + env_logger.
//   - R121c — integration test launches this binary, drives external
//     zenoh-pico z_put against --listen, asserts the subscriber
//     callback fires on the chosen --key.

use std::env;
use std::process::ExitCode;

const ABOUT: &str = concat!(
    "wz-ap-demo ",
    env!("CARGO_PKG_VERSION"),
    " — AP MVP demo binary (R121a skeleton; functional impl lands at R121b)",
);

fn print_usage() {
    eprintln!("{ABOUT}");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    wz-ap-demo --listen <tcp_addr> --key <keyexpr>");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --listen <tcp_addr>   server-side TCP bind address (e.g. 127.0.0.1:7447)");
    eprintln!("    --key <keyexpr>       DECLARE subscriber keyexpr (e.g. demo/example/**)");
    eprintln!("    --help, -h            print this help and exit");
}

fn parse_pair(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let rest = &args[1..];

    if rest.is_empty() || rest.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    let listen = parse_pair(rest, "--listen");
    let key = parse_pair(rest, "--key");

    if listen.is_none() || key.is_none() {
        eprintln!("wz-ap-demo: --listen and --key are both required");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }

    eprintln!("{ABOUT}");
    eprintln!("listen = {}", listen.as_deref().unwrap());
    eprintln!("key    = {}", key.as_deref().unwrap());
    eprintln!("R121a skeleton — session FSM + DECLARE + msg_put inbound dispatch land at R121b.");
    ExitCode::SUCCESS
}
