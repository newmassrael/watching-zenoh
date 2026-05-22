// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — AP MVP demo binary entry point.
//
// R121b: functional round. Wires the session FSM + DECLARE
// subscriber + msg_put inbound dispatch end-to-end against an
// external zenoh-pico peer over real TCP.
//
// R121e (this round): bidirectional pubsub. Adds publisher-side
// emission so the binary can drive zenoh-pico's `z_sub` (in
// addition to the R121b/c/d subscriber-side reception that
// already round-trips against `z_put`). The publisher path
// composes the existing wz-codecs `Push` + `Frame` envelopes via
// `wz_runtime_tokio::session_glue::{build_push_literal,
// encode_frame_with_push}` and dispatches through the same
// `OutboundWriteDriver` mpsc channel that the FSM script-actions
// use for the handshake outbound — no nested `block_on` (R121d
// constraint preserved).
//
// CLI shape (R121b base, R121e --publish/--value, R121f --connect):
//
//   wz-ap-demo (--listen <addr> | --connect <addr>)
//              [--key <keyexpr>]
//              [--publish <keyexpr> --value <text>]
//
//   --listen   server-side TCP bind address (acceptor mode;
//              e.g. 127.0.0.1:7447). Binds + accepts one peer,
//              then drives the session FSM with `InboundStart`.
//   --connect  remote TCP peer address (initiator mode;
//              e.g. 127.0.0.1:7447). Dials the peer, then drives
//              the session FSM with `OutboundStart` + `LinkOpened`
//              so wz emits the first `InitSyn` and walks the
//              4-way handshake from the dialing side.
//              Exactly one of --listen / --connect is required;
//              the two modes are mutually exclusive (a single
//              demo invocation acts as either acceptor OR
//              initiator, never both).
//   --key      DECLARE subscriber keyexpr (e.g. demo/example).
//              Each Push whose keyexpr matches this pattern fires
//              the demo callback (prints to stderr).
//              Optional — when omitted, no subscriber callback is
//              registered and inbound Pushes are silently dropped.
//   --publish  Publisher keyexpr literal (e.g. demo/test).
//              When present, the demo spawns a publisher task that
//              waits for the session FSM to reach Established
//              (role-agnostic `record_established_at` counter,
//              fires on both acceptor and initiator sides), then
//              emits N copies of the Push at a fixed cadence so a
//              z_sub peer can observe one (z_sub uses
//              `while(1) sleep(1)` so any single copy is enough;
//              the multi-copy emission absorbs tail-latency /
//              declare-subscriber timing variance).
//              Requires --value.
//   --value    Publisher payload text. Required when --publish is
//              present; ignored otherwise.
//
// At least one of {--key, --publish} must be supplied — running
// the demo with neither makes the session FSM advance but
// generates no observable AP-layer behaviour.
//
// Bidirectional TCP wiring (the architecturally non-trivial bit):
//
//   `drive_session_until_terminal` borrows the inbound driver as
//   `&mut LinkDriver` while `SessionLinkActions` holds the outbound
//   driver as `Arc<dyn BoxedLinkDriver>`. A single TcpStream cannot
//   satisfy both shapes simultaneously, so the demo splits the
//   accepted TcpStream into owned read + write halves (Tokio's
//   `TcpStream::into_split`) and threads them as two cooperating
//   drivers:
//
//     InboundReadDriver { reader: OwnedReadHalf }
//       impls `LinkDriver` — `poll_event` reads one Zenoh stream
//       envelope (u16 LE length prefix + payload), `send`/`open`/
//       `close` are no-ops (the inbound side never emits outbound
//       bytes).
//
//     OutboundWriteDriver { tx: mpsc::UnboundedSender<Vec<u8>> }
//       impls `BoxedLinkDriver` — `send_blocking` enqueues the
//       transport-message bytes onto an unbounded mpsc channel.
//       A dedicated async **writer task** (spawned in
//       `run_demo`) owns the `OwnedWriteHalf` and drains the
//       channel, writing the Zenoh stream envelope (u16 LE length
//       prefix + payload) for each enqueued frame. This avoids
//       the `Handle::block_on` reentrancy panic that would fire if
//       `send_blocking` blocked on async TCP writes from a future
//       being driven by the same runtime — `drive_session_until_
//       terminal` polls inbound asynchronously, then the FSM's
//       script-action handlers (e.g. `send_init_ack_with_cookie`)
//       fire synchronously on the same task; nested `block_on` is
//       not permitted. The channel is the textbook decoupling.
//       Channel-send is sync + non-blocking; the writer task
//       handles flush + ordering. Frame ordering is preserved
//       because there is exactly one writer task per outbound
//       channel.
//
//   Both halves wrap the same TcpStream so peer reads see what we
//   send and peer writes reach our poll_event. The split lets each
//   side own its half exclusively, satisfying both the `&mut
//   LinkDriver` and `Arc<dyn BoxedLinkDriver>` shape constraints.

use std::env;
use std::process::ExitCode;

mod args;
mod link_driver;
mod runner;
mod shutdown;
mod tasks;
mod teardown;
mod usage;

use crate::args::{
    parse_pair, DeclareEmitSpec, PushOperation, QueryRoleSpec, RemoteLogSpec, ReplyConsumerSpec,
    Role,
};
use crate::runner::run_demo;
use crate::usage::{print_usage, ABOUT};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let rest = &args[1..];

    if rest.is_empty() || rest.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    // R121f — exactly one of --listen / --connect must be supplied.
    // The demo's session FSM role-start is hard-coded to one or
    // the other (Acceptor calls InboundStart on listen; Initiator
    // calls OutboundStart + LinkOpened on connect) — there is no
    // self-loopback configuration that would justify both.
    let listen_opt = parse_pair(rest, "--listen");
    let connect_opt = parse_pair(rest, "--connect");
    let role: Role = match (listen_opt, connect_opt) {
        (Some(addr), None) => Role::Acceptor { listen: addr },
        (None, Some(addr)) => Role::Initiator { connect: addr },
        (Some(_), Some(_)) => {
            eprintln!("wz-ap-demo: --listen and --connect are mutually exclusive");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
        (None, None) => {
            eprintln!("wz-ap-demo: exactly one of --listen / --connect is required");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    };

    // R121e — the demo accepts subscriber-only, publisher-only,
    // OR both. The argument-validation matrix:
    //
    //   --key alone                       → subscriber mode (R121d).
    //   --publish + --value (no --key)    → publisher mode (R121e).
    //   --key + --publish + --value       → bidirectional mode
    //                                       (useful for loopback /
    //                                       echo scenarios).
    //   none of the above                 → reject (exit 2) — running
    //                                       the demo with no AP-layer
    //                                       behaviour does nothing
    //                                       observable.
    //   --publish without --value         → reject (exit 2) — the
    //                                       payload is mandatory once
    //                                       a publisher key is set.
    let key_opt = parse_pair(rest, "--key");
    let publish_opt = parse_pair(rest, "--publish");
    let value_opt = parse_pair(rest, "--value");
    // R219 — `--delete <keyexpr>` opts the demo into the
    // delete-keyexpr publisher mode: each burst tick emits a
    // `Frame[Push(MsgDel)]` instead of `Frame[Push(MsgPut(payload))]`.
    // Mutually exclusive with --publish (the two are distinct
    // application semantics; a publisher emits either Puts or
    // Deletes, not both, on a single run).
    let delete_opt = parse_pair(rest, "--delete");
    // R121g — `--declare-id <N>` opts the publisher into the
    // DECLARE-aliased path: send one `Declare(DeclKexpr(N, suffix))`
    // before the burst, then emit aliased Pushes carrying only
    // `id=N`. Defaults to None (literal-keyexpr path, R121e shape).
    // R219 — meaningful when EITHER --publish OR --delete is set.
    let declare_id_opt = parse_pair(rest, "--declare-id");
    // R121j-5c-e2e-demo — queryable / query CLI surface.
    // --queryable + --reply registers an inbound Request(Query) callback
    // that emits one Put-form Reply with the --reply payload. --query
    // emits a single outbound Request(Query) on the given keyexpr once
    // the session reaches Established (mirror of --publish timing
    // gate). Both are independent of --key / --publish; one demo
    // instance can act simultaneously as publisher + queryable + query
    // emitter if the corresponding argv combination is supplied.
    let queryable_opt = parse_pair(rest, "--queryable");
    let reply_opt = parse_pair(rest, "--reply");
    let query_opt = parse_pair(rest, "--query");
    // R121k-5 — declare emit + remote-declare callback CLI surface.
    let declare_subscriber_opt = parse_pair(rest, "--declare-subscriber");
    let declare_queryable_opt = parse_pair(rest, "--declare-queryable");
    let declare_token_opt = parse_pair(rest, "--declare-token");
    // R280 — optional `--liveliness-subscribe <keyexpr>` registers a
    // liveliness subscriber on the literal keyexpr pattern. Emits one
    // outbound Interest once Established and logs every matching peer
    // DeclToken / UndeclToken sample to stderr.
    let liveliness_subscribe_opt = parse_pair(rest, "--liveliness-subscribe");
    let on_remote_sub_log = rest.iter().any(|a| a == "--on-remote-subscriber-log");
    let on_remote_q_log = rest.iter().any(|a| a == "--on-remote-queryable-log");
    let on_remote_l_log = rest.iter().any(|a| a == "--on-remote-liveliness-log");
    // R121j-6-e2e — initiator-side ReplyRegistry log flags. Both
    // require --query (the rid is bound to the outbound Query the
    // demo emits; without that there is no z_get to consume replies
    // for). Reject explicitly so a mis-wired argv (`--on-query-reply-log`
    // on a queryable-side process) surfaces here rather than silently
    // installing an unreachable callback.
    let on_query_reply_log = rest.iter().any(|a| a == "--on-query-reply-log");
    let on_query_final_log = rest.iter().any(|a| a == "--on-query-final-log");
    // R263 — optional --query-timeout-ms <N> sets the ReplyRegistry
    // pending-entry deadline so a peer that never replies surfaces
    // the demo's on_final callback within N + driver-loop-tick wall
    // time. Default 0 = no timeout (pre-R263 behaviour preserved).
    let query_timeout_ms_opt = parse_pair(rest, "--query-timeout-ms");
    let query_timeout_ms: u32 = match query_timeout_ms_opt {
        Some(s) => match s.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("wz-ap-demo: --query-timeout-ms must be a u32 (got {s:?})",);
                return ExitCode::from(2);
            }
        },
        None => 0,
    };
    // R270 — optional --sweep-cadence-ms <N> sets the R264 sweep_task
    // tick period. Must be > 0 (0 would be a busy loop); default 100
    // matches the pre-R270 hardcoded constant. R264 carry closed here:
    // the cadence is now a CLI-tunable knob rather than a literal at
    // the sleep call site, so wall-time-bounded tests + topology-
    // specific tuning have a first-class entry point.
    let sweep_cadence_ms_opt = parse_pair(rest, "--sweep-cadence-ms");
    let sweep_cadence_ms: u32 = match sweep_cadence_ms_opt {
        Some(s) => match s.parse::<u32>() {
            Ok(0) => {
                eprintln!("wz-ap-demo: --sweep-cadence-ms must be > 0 (0 would busy-loop)",);
                return ExitCode::from(2);
            }
            Ok(n) => n,
            Err(_) => {
                eprintln!("wz-ap-demo: --sweep-cadence-ms must be a u32 (got {s:?})",);
                return ExitCode::from(2);
            }
        },
        None => 100,
    };
    if key_opt.is_none()
        && publish_opt.is_none()
        && delete_opt.is_none()
        && queryable_opt.is_none()
        && query_opt.is_none()
        && declare_subscriber_opt.is_none()
        && declare_queryable_opt.is_none()
        && declare_token_opt.is_none()
        && liveliness_subscribe_opt.is_none()
        && !on_remote_sub_log
        && !on_remote_q_log
        && !on_remote_l_log
    {
        eprintln!(
            "wz-ap-demo: at least one of --key / --publish / --delete / --queryable / --query / \
             --declare-* / --liveliness-subscribe / --on-remote-* must be supplied",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if publish_opt.is_some() && value_opt.is_none() {
        eprintln!("wz-ap-demo: --publish requires --value");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if publish_opt.is_none() && value_opt.is_some() {
        eprintln!("wz-ap-demo: --value is only meaningful with --publish (rejected to surface mis-wired argv)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    // R219 — --delete and --publish are distinct publisher modes; a
    // single run emits either Puts (Put payloads via --value) or
    // Deletes (no payload). Mixing both on one run does not match
    // any real-world application surface and would complicate
    // publisher_task's dispatch — reject explicitly here.
    if publish_opt.is_some() && delete_opt.is_some() {
        eprintln!("wz-ap-demo: --publish and --delete are mutually exclusive (pick one publisher mode per run)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if delete_opt.is_some() && value_opt.is_some() {
        eprintln!("wz-ap-demo: --delete does not accept --value (MsgDel carries no payload — rejected to surface mis-wired argv)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if declare_id_opt.is_some() && publish_opt.is_none() && delete_opt.is_none() {
        eprintln!("wz-ap-demo: --declare-id is only meaningful with --publish or --delete");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_some() && reply_opt.is_none() {
        eprintln!("wz-ap-demo: --queryable requires --reply");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_none() && reply_opt.is_some() {
        eprintln!(
            "wz-ap-demo: --reply is only meaningful with --queryable (rejected to surface mis-wired argv)",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if (on_query_reply_log || on_query_final_log) && query_opt.is_none() {
        eprintln!(
            "wz-ap-demo: --on-query-reply-log / --on-query-final-log require --query \
             (the ReplyRegistry binds to the rid of the outbound Query this demo emits)",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if query_timeout_ms > 0 && query_opt.is_none() {
        eprintln!(
            "wz-ap-demo: --query-timeout-ms requires --query (the timeout binds to \
             the pending entry the outbound Query registers)",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    let declare_id_parsed: Option<u64> = match declare_id_opt {
        Some(s) => {
            match s.parse::<u64>() {
                Ok(0) => {
                    eprintln!("wz-ap-demo: --declare-id must be non-zero (0 is the literal-keyexpr sentinel)");
                    return ExitCode::from(2);
                }
                Ok(n) => Some(n),
                Err(e) => {
                    eprintln!("wz-ap-demo: --declare-id must be a positive integer ({e})");
                    return ExitCode::from(2);
                }
            }
        }
        None => None,
    };
    // R219 — publisher_spec carries both Put and Delete modes through
    // a single channel into publisher_task. Put requires --value
    // (validated above); Delete carries no payload.
    let publisher_spec: Option<(String, PushOperation, Option<u64>)> =
        match (publish_opt, value_opt, delete_opt) {
            (Some(k), Some(v), None) => {
                Some((k, PushOperation::Put { value: v }, declare_id_parsed))
            }
            (None, None, Some(k)) => Some((k, PushOperation::Delete, declare_id_parsed)),
            _ => None,
        };
    let queryable_spec: Option<(String, String)> = match (queryable_opt, reply_opt) {
        (Some(p), Some(r)) => Some((p, r)),
        _ => None,
    };
    let query_spec: Option<String> = query_opt;

    // env_logger reads RUST_LOG (defaults to off). The integration
    // test fixture (R121c) sets RUST_LOG=info to surface subscriber-
    // dispatch / session-FSM transitions in the child stderr capture.
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();

    eprintln!("{ABOUT}");
    match &role {
        Role::Acceptor { listen } => log::info!("listen  = {listen}"),
        Role::Initiator { connect } => log::info!("connect = {connect}"),
    }
    if let Some(k) = &key_opt {
        log::info!("key     = {k}");
    }
    if let Some((k, op, id)) = &publisher_spec {
        match op {
            PushOperation::Put { value } => {
                log::info!("publish = {k}");
                log::info!("value   = {value}");
            }
            PushOperation::Delete => {
                log::info!("delete  = {k} (R219 Del-mode, no payload)");
            }
        }
        if let Some(n) = id {
            log::info!("declare-id = {n} (R121g DECLARE-aliased mode)");
        }
    }
    if let Some((p, r)) = &queryable_spec {
        log::info!("queryable = {p}");
        log::info!("reply     = {r}");
    }
    if let Some(q) = &query_spec {
        log::info!("query   = {q}");
    }
    if let Some(d) = &declare_subscriber_opt {
        log::info!("declare-subscriber = {d}");
    }
    if let Some(d) = &declare_queryable_opt {
        log::info!("declare-queryable = {d}");
    }
    if let Some(d) = &declare_token_opt {
        log::info!("declare-token = {d}");
    }
    if let Some(d) = &liveliness_subscribe_opt {
        log::info!("liveliness-subscribe = {d}");
    }
    if on_remote_sub_log {
        log::info!("on-remote-subscriber-log = true");
    }
    if on_remote_q_log {
        log::info!("on-remote-queryable-log = true");
    }
    if on_remote_l_log {
        log::info!("on-remote-liveliness-log = true");
    }
    if on_query_reply_log {
        log::info!("on-query-reply-log = true");
    }
    if on_query_final_log {
        log::info!("on-query-final-log = true");
    }

    // Build the multi-thread runtime explicitly — OutboundWriteDriver
    // (mirroring TokioLinkDriverAdapter's contract) requires this
    // flavor so block_on doesn't deadlock on the current-thread
    // worker.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };

    let declare_spec = DeclareEmitSpec {
        subscriber_keyexpr: declare_subscriber_opt,
        queryable_keyexpr: declare_queryable_opt,
        token_keyexpr: declare_token_opt,
        liveliness_subscriber_keyexpr: liveliness_subscribe_opt,
    };
    let remote_log_spec = RemoteLogSpec {
        on_remote_subscriber: on_remote_sub_log,
        on_remote_queryable: on_remote_q_log,
        on_remote_liveliness: on_remote_l_log,
    };
    let reply_log_spec = ReplyConsumerSpec {
        on_query_reply: on_query_reply_log,
        on_query_final: on_query_final_log,
        query_timeout_ms,
        sweep_cadence_ms,
    };
    let query_role_spec = QueryRoleSpec {
        queryable: queryable_spec,
        query: query_spec,
    };
    let outcome = runtime.block_on(async move {
        run_demo(
            role,
            key_opt,
            publisher_spec,
            query_role_spec,
            declare_spec,
            remote_log_spec,
            reply_log_spec,
        )
        .await
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}
