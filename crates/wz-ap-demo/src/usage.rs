// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — CLI banner + `--help` text.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. The `ABOUT` constant doubles as the banner emitted ahead
// of role logging in `main`, and as the header line of the
// `--help` block; keeping both in one module keeps the version
// string single-sourced from `CARGO_PKG_VERSION`.

pub(crate) const ABOUT: &str = concat!(
    "wz-ap-demo ",
    env!("CARGO_PKG_VERSION"),
    " — AP MVP demo binary",
);

pub(crate) fn print_usage() {
    eprintln!("{ABOUT}");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    wz-ap-demo (--listen <addr> | --connect <addr> [--reconnect] | --scout)");
    eprintln!("               [--key <keyexpr>]");
    eprintln!("               [--publish <keyexpr> --value <text>]");
    eprintln!("               [--delete <keyexpr>]");
    eprintln!("               [--queryable <keyexpr> --reply <text>]");
    eprintln!("               [--query <keyexpr>]");
    eprintln!("               [--declare-token <keyexpr>]");
    eprintln!("               [--liveliness-subscribe <keyexpr>]");
    eprintln!("               [--on-remote-subscriber-log]");
    eprintln!("               [--on-remote-queryable-log]");
    eprintln!("               [--on-remote-liveliness-log]");
    eprintln!("               [--on-query-reply-log]");
    eprintln!("               [--on-query-final-log]");
    eprintln!("               [--query-timeout-ms <ms>]");
    eprintln!("               [--sweep-cadence-ms <ms>]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --listen <addr>          acceptor mode (e.g. 127.0.0.1:7447)");
    eprintln!("    --connect <addr>         initiator mode (HOST:PORT or tcp/|ws/HOST:PORT)");
    eprintln!("    --lowlatency             offer the lowlatency transport on --connect");
    eprintln!("    --scout                  initiator mode with a DISCOVERED locator: emit a");
    eprintln!("                             multicast Scout on 224.0.0.224:7446 and dial the");
    eprintln!("                             locator the first peer Hello advertises. Mutually");
    eprintln!("                             exclusive with --listen / --connect. Requires the");
    eprintln!("                             `scouting-active` build feature");
    eprintln!("    --scout-timeout-ms <ms>  total --scout discovery budget, spent across repeated");
    eprintln!("                             Scout cycles (default 10000; requires --scout)");
    eprintln!("    --router <addr>          multi-peer router mode: bind once, HOLD N concurrent");
    eprintln!(
        "                             peer faces (routing-router foundation, no forwarding)."
    );
    eprintln!("                             Requires the `routing-router` build feature.");
    eprintln!("    --reconnect              long-lived reconnect-supervised lifecycle for the");
    eprintln!("                             initiator (requires --connect): on link loss, re-dial");
    eprintln!("                             (re-resolving a hostname) + replay the declaration");
    eprintln!("                             cache instead of exiting. Default is round-trip-then-");
    eprintln!(
        "                             exit. pico Z_FEATURE_AUTO_RECONNECT parity (client-only)"
    );
    eprintln!("    --key <keyexpr>          DECLARE subscriber keyexpr (e.g. demo/example)");
    eprintln!("    --publish <keyexpr>      publisher keyexpr literal (e.g. demo/test)");
    eprintln!("    --value <text>           publisher payload text (required with --publish)");
    eprintln!("    --delete <keyexpr>       delete-keyexpr publisher (R219 MsgDel body)");
    eprintln!("                             mutually exclusive with --publish; no --value");
    eprintln!("    --queryable <keyexpr>    register a queryable for the given pattern;");
    eprintln!("                             each inbound Request(Query) whose keyexpr matches");
    eprintln!("                             fires a callback that emits one Reply via --reply");
    eprintln!("    --reply <text>           reply payload for the registered queryable");
    eprintln!("                             (required with --queryable)");
    eprintln!("    --query <keyexpr>        send a single Request(Query) on this keyexpr");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --declare-token <keyexpr>");
    eprintln!("                             send a single Declare(DeclToken) on this keyexpr");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --liveliness-subscribe <keyexpr>");
    eprintln!("                             declare a liveliness subscriber on <keyexpr> (R280);");
    eprintln!("                             emits one Interest(KE|TO|R|F) on Established and");
    eprintln!("                             logs 'LIVELINESS SAMPLE PUT/DELETE' on every matching");
    eprintln!("                             peer DeclToken / UndeclToken arrival");
    eprintln!("    --liveliness-subscribe-history");
    eprintln!("                             declare the liveliness subscriber with history=true");
    eprintln!("                             (replay CURRENT alive tokens on subscription, not");
    eprintln!("                             just future declares); order-independent observer");
    eprintln!("    --liveliness-get <keyexpr>");
    eprintln!("                             one-shot liveliness snapshot get on <keyexpr>;");
    eprintln!("                             emits one CURRENT Interest(KE|TO|R|C) on Established");
    eprintln!("    --liveliness-get-after-ms <ms>");
    eprintln!("                             hold that get <ms> after Established, so a foreign");
    eprintln!("                             token holder has time to declare first (a snapshot");
    eprintln!("                             only returns tokens that already exist)");
    eprintln!("                             and logs 'LIVELINESS GET REPLY' per alive token then");
    eprintln!("                             one 'LIVELINESS GET FINAL'");
    eprintln!("    --on-remote-subscriber-log");
    eprintln!("                             install a RemoteSubscriberRegistry callback that");
    eprintln!("                             logs 'REMOTE SUBSCRIBER DECLARED' on inbound");
    eprintln!("                             Declare(DeclSubscriber); paired with");
    eprintln!("                             'REMOTE SUBSCRIBER UNDECLARED' on UndeclSubscriber");
    eprintln!("    --on-remote-queryable-log");
    eprintln!("                             liveliness-equivalent for the queryable side");
    eprintln!("    --on-remote-liveliness-log");
    eprintln!("                             liveliness-equivalent for the DeclToken side");
    eprintln!("    --on-query-reply-log     install a ReplyRegistry callback that logs");
    eprintln!("                             'REPLY RECEIVED' on each inbound");
    eprintln!("                             Response(Reply|Err) for the --query rid");
    eprintln!("                             (requires --query)");
    eprintln!("    --on-query-final-log     install a ReplyRegistry on_final callback that");
    eprintln!("                             logs 'FINAL RECEIVED' when the matching");
    eprintln!("                             ResponseFinal terminates the reply chain");
    eprintln!("                             (requires --query)");
    eprintln!("    --query-timeout-ms <ms>  set a ReplyRegistry timeout for the outbound");
    eprintln!("                             Query's pending entry. When >0, the");
    eprintln!("                             on_final callback fires within");
    eprintln!("                             (timeout_ms + driver-loop-tick) of register");
    eprintln!("                             time if no peer Final arrives. 0 (default)");
    eprintln!("                             disables the timeout (requires --query)");
    eprintln!("    --sweep-cadence-ms <ms>  R264 sweep_task tick period in ms. Each tick");
    eprintln!("                             invokes ReplyRegistry::sweep_timed_out so");
    eprintln!("                             expired --query-timeout-ms entries fire their");
    eprintln!("                             on_final callback. Lower = tighter bound on");
    eprintln!("                             post-deadline wall-time at the cost of more");
    eprintln!("                             wake-ups. Must be > 0. Default 100");
    eprintln!("    --help, -h               print this help and exit");
    eprintln!();
    eprintln!("Exactly one of --listen / --connect / --scout is required.");
    eprintln!("At least one of --key / --publish / --delete / --queryable / --query / --declare-*");
    eprintln!("/ --on-remote-* must be supplied.");
}
