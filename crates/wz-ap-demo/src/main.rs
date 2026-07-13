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
// `wz::runtime_tokio::session_glue::{build_push_literal,
// encode_frame_with_push}` and dispatches through the same
// `TcpWriteDriver` mpsc channel that the FSM script-actions
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
//   --connect  remote peer locator (initiator mode). A bare
//              HOST:PORT (e.g. 127.0.0.1:7447) dials TCP; a
//              scheme'd tcp/HOST:PORT or ws/HOST:PORT dials that
//              transport (ws/ needs the `ws` build feature). Then
//              drives the session FSM with `OutboundStart` +
//              `LinkOpened` so wz emits the first `InitSyn` and
//              walks the 4-way handshake from the dialing side.
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
//   satisfy both shapes simultaneously, so the connection is split
//   into owned read + write halves (Tokio's `TcpStream::into_split`)
//   threaded as two cooperating drivers — a `TcpReadDriver`
//   (`LinkDriver`; codec-decodes one Zenoh stream envelope per
//   `poll_event`) and a `TcpWriteDriver` (`BoxedLinkDriver`;
//   `send_blocking` is a non-blocking enqueue onto an mpsc channel
//   drained by a dedicated writer task that frames each payload via
//   the `StreamEnvelope` codec). The channel decouples the sync
//   script-action / async-runtime boundary so no nested
//   `Handle::block_on` is needed (the reentrancy panic the R121d
//   constraint guards against).
//
//   R311ev — this split pipeline lives in the library as
//   `wz::runtime_tokio::link_pipeline::wire_tcp_stream` (lifted from
//   the demo's former local `link_driver` module at R311et). The demo
//   consumes it directly; see that module's doc for the full
//   read/write-split rationale.

use std::env;
use std::process::ExitCode;

use wz::runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe;

mod args;
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

    // R311qa — `--router <addr>` selects the multi-peer router mode (bind once,
    // HOLD N concurrent peer faces — the routing-router foundation), handled
    // before the single-session role parse below (which requires exactly one of
    // --listen / --connect). Opt-in behind the `routing-router` feature: a build
    // without it rejects the flag rather than silently no-op'ing, so the catalog
    // claim and the binary stay in lockstep.
    if let Some(router_addr) = parse_pair(rest, "--router") {
        #[cfg(feature = "routing-router")]
        return run_router_mode(router_addr);
        #[cfg(not(feature = "routing-router"))]
        {
            let _ = router_addr;
            eprintln!(
                "wz-ap-demo: --router requires the `routing-router` feature \
                 (build: cargo build -p wz-ap-demo --features routing-router)"
            );
            return ExitCode::from(2);
        }
    }

    // R311qg — `--peer <listen>` selects the peer-MESH mode (dial the configured
    // `--connect` peers AND accept inbound on `<listen>`, holding both — the
    // routing-peer foundation), handled before the single-session role parse.
    // The outbound dial targets come from `--connect` (comma-separated here,
    // where in single-session mode it is one initiator address). Opt-in behind
    // `routing-peer`: a build without it rejects the flag rather than silently
    // no-op'ing, so the catalog claim and the binary stay in lockstep.
    if let Some(peer_listen) = parse_pair(rest, "--peer") {
        #[cfg(feature = "routing-peer")]
        {
            let dial_targets: Vec<String> = parse_pair(rest, "--connect")
                .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                .unwrap_or_default();
            // R311ri (c3c e2e) — `--publish <key>` makes this peer ORIGINATE
            // data into the mesh (flooded along its spanning tree); absent, the
            // peer only forwards others' data.
            let publish_key = parse_pair(rest, "--publish");
            // R311rs (c3c-3 atom4-ii) — `--subscribe <key>` makes this peer
            // DECLARE interest in a keyexpr; the declaration floods across the
            // mesh so a `--publish` peer's subscription-filtered route reaches
            // it. Without a subscriber the data plane forwards nothing.
            let subscribe_key = parse_pair(rest, "--subscribe");
            // c3c-3 debt A1 — `--unsubscribe-after-data` makes a `--subscribe`
            // peer RETRACT its interest once it has confirmed the round-trip
            // (received data on the subscription): a self-coordinating lifecycle
            // that drives the UndeclareSubscriber propagation with no timing
            // window. Meaningful only alongside `--subscribe`.
            let unsubscribe_after_data = rest.iter().any(|a| a == "--unsubscribe-after-data");
            // Gossip-autoconnect opt-in: discover peers off the link-state flood
            // and DIAL the policy-admitted ones (a mesh that grows past the static
            // `--connect` set). Off by default — a peer dials only `--connect`.
            let autoconnect = rest.iter().any(|a| a == "--autoconnect");
            // R311tt (§5.16 access control) — `--acl-deny <keyexpr>` opts this
            // peer into ACL enforcement: an allow-default policy with one ingress
            // Put deny rule on the keyexpr (every peer subject). A Put a neighbour
            // floods on a denied keyexpr is dropped here, not relayed onward.
            // Off by default — without the flag the peer enforces nothing.
            let acl_deny = parse_pair(rest, "--acl-deny");
            // R311tw (§5.16 downsampling) — `--downsample <keyexpr>` rate-limits
            // egress data on the keyexpr to at most one per 500 ms, the QoS
            // sibling of the ACL on the same interceptor chain. Off by default.
            let downsample = parse_pair(rest, "--downsample");
            // R311tx (§5.16 access-quota) — `--max-payload <bytes>` caps every
            // keyexpr's Put payload size (zenoh low_pass); a larger Put is dropped
            // on egress. Off by default.
            let max_payload = parse_pair(rest, "--max-payload");
            // R311y45 (§5.23 Phase 2b) — `--config-queryable` opts this peer into
            // hosting its adminspace on the forwarder: a GET for
            // `@/<zid>/peer/config` is answered with the node's LIVE shared WzConfig
            // (the forwarder self-dispatch, R311y44). Off by default.
            let config_queryable = rest.iter().any(|a| a == "--config-queryable");
            // R311y48 (§5.23 Phase 3b) — `--config-writable` opts this peer into
            // hosting its config-WRITE subscriber on `@/<zid>/peer/config/**`: a
            // remote PUT to a config sub-key (`.../config/acl-deny <keyexpr>`)
            // reconfigures the LIVE forwarder (the R311y46 Push-plane self-dispatch
            // + the Phase-1 reconfigure drive). Off by default.
            let config_writable = rest.iter().any(|a| a == "--config-writable");
            // R311y51 (§5.23 adminspace-write) — `--config-write-permit` grants the
            // permissions.write gate (default-deny, zenoh PermissionsConf write:false).
            // Under `adminspace-write` a config-write PUT is APPLIED only with this
            // flag; without it the write is DENIED. Off by default. Orthogonal to
            // `--config-writable` (which HOSTS the write subscriber): host vs permit.
            let config_write_permit = rest.iter().any(|a| a == "--config-write-permit");
            // R311y276 (§5.23 adminspace-read) — `--no-admin-read` DENIES the
            // permissions.read GET gate on the `--config-queryable` host: under the
            // `adminspace-read` cfg the admin queryable then answers nothing (the
            // querier gets only the terminating Final). Default permissive (read:true,
            // zenoh PermissionsConf default). Off by default; inert without
            // `--config-queryable` (nothing hosts the admin GET) and, with the gate
            // compiled out, a no-op (admin_read_permit ignores the value).
            let no_admin_read = rest.iter().any(|a| a == "--no-admin-read");
            // R311y48 — `--put-key <keyexpr> --put-payload <text>`: originate a Put
            // carrying a SPECIFIC payload each app tick (vs `--publish`, which sends
            // a fixed marker). The wire driver a remote node uses to PUT another
            // peer's config-write key (`--put-key @/<A>/peer/config/acl-deny
            // --put-payload <denied-keyexpr>`). Both off by default; meaningful only
            // when both are set.
            let put_key = parse_pair(rest, "--put-key");
            let put_payload = parse_pair(rest, "--put-payload");
            // R311y213 (transport-multilink) — `--max-links <N>` sets the aggregated-
            // link budget (the unicast.max_links analogue): `> 1` aggregates N physical
            // links to a peer zid into ONE logical session (achieved by dialing the
            // same peer N times, e.g. `--connect a,a`, or a mutual connect). Non-numeric
            // or `0` warns and falls back to `1` (single-link), mirroring --max-payload's
            // graceful-degrade rather than aborting the run.
            #[cfg(feature = "transport-multilink")]
            let max_links: usize = parse_pair(rest, "--max-links")
                .map(|s| match s.trim().parse::<usize>() {
                    Ok(n) if n >= 1 => n,
                    Ok(_) => {
                        eprintln!("wz-ap-demo: --max-links must be >= 1; using 1 (single-link)");
                        1
                    }
                    Err(_) => {
                        eprintln!(
                            "wz-ap-demo: --max-links '{s}' is not a number; using 1 (single-link)"
                        );
                        1
                    }
                })
                .unwrap_or(1);
            // R311y218 (transport-qos) — `--qos` (presence bool) offers the QoS
            // transport on this peer's aggregated links (the WzConfig.qos knob).
            // TAKES EFFECT ONLY WITH `--max-links > 1`: qos is threaded through the
            // multilink open path (option-b), so a single-link peer (`--max-links 1`,
            // the default) takes the bare open arms and does NOT offer qos — `--qos`
            // is a runtime no-op there. Priority segregation across links is y219.
            #[cfg(feature = "transport-qos")]
            let qos = rest.iter().any(|a| a == "--qos");
            // R311y220 (transport-qos) — `--express-high` / `--low` select the QoS band
            // the `--publish` peer originates its data Puts at (mapped in `run_peer` to
            // `publish_qos`'s (priority, express) via `PublishBand`). Mutually exclusive;
            // `--express-high` wins with a warning if both are given (graceful-degrade,
            // like `--max-links`). Meaningful on an aggregated QoS multilink session
            // (`--max-links > 1 --qos`); otherwise a runtime no-op (the `is_qos()` clamp
            // forces DEFAULT). Off by default -> plain DEFAULT publish (LOW band).
            #[cfg(feature = "transport-qos")]
            let publish_band = {
                let express_high = rest.iter().any(|a| a == "--express-high");
                let low = rest.iter().any(|a| a == "--low");
                match (express_high, low) {
                    (true, true) => {
                        eprintln!(
                            "wz-ap-demo: --express-high and --low are mutually exclusive; \
                             using --express-high"
                        );
                        Some(crate::runner::PublishBand::ExpressHigh)
                    }
                    (true, false) => Some(crate::runner::PublishBand::ExpressHigh),
                    (false, true) => Some(crate::runner::PublishBand::Low),
                    (false, false) => None,
                }
            };
            return run_peer_mode(
                peer_listen,
                dial_targets,
                crate::runner::PeerOpts {
                    publish_key,
                    subscribe_key,
                    unsubscribe_after_data,
                    autoconnect,
                    config_queryable,
                    config_writable,
                    config_write_permit,
                    no_admin_read,
                    put_key,
                    put_payload,
                    #[cfg(feature = "transport-multilink")]
                    max_links,
                    #[cfg(feature = "transport-qos")]
                    qos,
                    #[cfg(feature = "transport-qos")]
                    publish_band,
                },
                InterceptorOpts {
                    acl_deny,
                    downsample,
                    max_payload,
                },
            );
        }
        #[cfg(not(feature = "routing-peer"))]
        {
            let _ = peer_listen;
            eprintln!(
                "wz-ap-demo: --peer requires the `routing-peer` feature \
                 (build: cargo build -p wz-ap-demo --features routing-peer)"
            );
            return ExitCode::from(2);
        }
    }

    // P4 §5.21 ACTIVATION — `--router-hat <listen>` selects the router-hat mode:
    // present a true wire WhatAmI::Router and drive the dual-mesh RouterForwarder
    // over real transport (bind `<listen>`, dial the `--connect` router set for
    // federation, hold both directions). Handled before the single-session role
    // parse. Opt-in behind `router-hat-router` (the active run-mode atom): a build
    // without it rejects the flag (the --router / --peer feature-gate discipline)
    // so the catalog claim and the binary stay in lockstep.
    if let Some(router_hat_listen) = parse_pair(rest, "--router-hat") {
        #[cfg(feature = "router-hat-router")]
        {
            let dial_targets: Vec<String> = parse_pair(rest, "--connect")
                .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                .unwrap_or_default();
            // `--connect-after <ms>:<addr>[,<addr>...]` (router-connect-reconcile):
            // schedule a runtime connect-list ADD `<ms>` after startup. Split on the
            // FIRST `:` so the `<addr>` `host:port` colon is preserved.
            #[cfg(feature = "router-connect-reconcile")]
            let connect_after: Option<(u64, Vec<String>)> = parse_pair(rest, "--connect-after")
                .and_then(|s| {
                    let (ms, addrs) = s.split_once(':')?;
                    let ms: u64 = ms.trim().parse().ok()?;
                    let addrs: Vec<String> =
                        addrs.split(',').map(|t| t.trim().to_string()).collect();
                    Some((ms, addrs))
                });
            #[cfg(not(feature = "router-connect-reconcile"))]
            let connect_after: Option<(u64, Vec<String>)> = {
                // Feature off: the flag is inert. Surface an explicit hint (keeping
                // the catalog claim and the binary in lockstep) rather than silently
                // ignoring it.
                if parse_pair(rest, "--connect-after").is_some() {
                    eprintln!(
                        "wz-ap-demo: --connect-after requires the \
                         `router-connect-reconcile` feature; ignoring"
                    );
                }
                None
            };
            // R311y232 (transport-qos ACTIVATION) — `--multicast-qos` (presence bool)
            // offers the per-priority QoS conduit on the router's data-plane
            // multicast group (the wz seam for zenoh `transport.multicast.qos.enabled`,
            // default false, DISTINCT from the unicast `--qos` / `transport.unicast.qos`
            // knob). Gated on `transport-qos` (no per-priority conduit compiles
            // otherwise); a build without the feature ignores the flag and offers the
            // pico-faithful 2-channel group.
            #[cfg(feature = "transport-qos")]
            let multicast_qos = rest.iter().any(|a| a == "--multicast-qos");
            #[cfg(not(feature = "transport-qos"))]
            let multicast_qos = {
                if rest.iter().any(|a| a == "--multicast-qos") {
                    eprintln!(
                        "wz-ap-demo: --multicast-qos requires the `transport-qos` \
                         feature; offering the non-QoS multicast group"
                    );
                }
                false
            };
            return run_router_hat_mode(
                router_hat_listen,
                dial_targets,
                connect_after,
                multicast_qos,
            );
        }
        #[cfg(not(feature = "router-hat-router"))]
        {
            let _ = router_hat_listen;
            eprintln!(
                "wz-ap-demo: --router-hat requires the `router-hat-router` feature \
                 (build: cargo build -p wz-ap-demo --features router-hat-router)"
            );
            return ExitCode::from(2);
        }
    }

    // R311y277 (§5.23 adminspace-config-hotreload ACTIVATION) — `--storage-host
    // <listen>` selects the storage-hosting mode: a bare-Session admin host that
    // live-spawns storages from a stock zenoh-pico client's config-writes and
    // reflects storage_manager Started in its plugins admin leg. Handled before the
    // single-session role parse. Opt-in behind `adminspace-config-hotreload`
    // (mirrors --router-hat): a build without it rejects the flag rather than
    // silently no-op'ing, so the catalog claim and the binary stay in lockstep.
    if let Some(storage_host_listen) = parse_pair(rest, "--storage-host") {
        #[cfg(feature = "adminspace-config-hotreload")]
        return run_storage_host_mode(storage_host_listen);
        #[cfg(not(feature = "adminspace-config-hotreload"))]
        {
            let _ = storage_host_listen;
            eprintln!(
                "wz-ap-demo: --storage-host requires the `adminspace-config-hotreload` feature \
                 (build: cargo build -p wz-ap-demo --features adminspace-config-hotreload)"
            );
            return ExitCode::from(2);
        }
    }

    // R121f — exactly one of --listen / --connect must be supplied.
    // The demo's session FSM role-start is hard-coded to one or
    // the other (Acceptor calls InboundStart on listen; Initiator
    // calls OutboundStart + LinkOpened on connect) — there is no
    // self-loopback configuration that would justify both.
    let listen_opt = parse_pair(rest, "--listen");
    let connect_opt = parse_pair(rest, "--connect");
    // R311pw — `--reconnect` is a presence flag (no value): it opts the
    // Initiator into the long-lived reconnect-supervised lifecycle. It is
    // meaningful ONLY with `--connect` (pico AUTO_RECONNECT is client-only);
    // pairing it with `--listen` is a usage error, rejected below.
    let reconnect = rest.iter().any(|a| a == "--reconnect");
    let role: Role = match (listen_opt, connect_opt) {
        (Some(_), None) if reconnect => {
            eprintln!(
                "wz-ap-demo: --reconnect requires --connect (an acceptor has no \
                 client reopen-task model; pico Z_FEATURE_AUTO_RECONNECT is client-only)"
            );
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
        (Some(addr), None) => Role::Acceptor { listen: addr },
        (None, Some(addr)) => Role::Initiator {
            connect: addr,
            reconnect,
        },
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
    // liveliness-get — optional `--liveliness-get <keyexpr>` issues one
    // CURRENT liveliness snapshot Interest once Established and logs each
    // reply + the terminating final. Reply-consuming "get" surface on the
    // declaration plane (sibling of --query on the Request plane).
    let liveliness_get_opt = parse_pair(rest, "--liveliness-get");
    // R121k-5 / R311oy — declare emit + remote-declare callback CLI surface.
    // The low-level `--declare-subscriber` / `--declare-queryable` raw-emit
    // hooks were retired: `--key` / `--queryable` now declare a ROUTED
    // subscriber / queryable through the real `Session::declare_{subscriber,
    // queryable}` path (R311ou / R311ow), which is the production declare path.
    // `--declare-token` stays — it IS the high-level `Session::declare_token`
    // (RAII liveliness token), not a low-level wire-emit hook.
    let declare_token_opt = parse_pair(rest, "--declare-token");
    // R280 — optional `--liveliness-subscribe <keyexpr>` registers a
    // liveliness subscriber on the literal keyexpr pattern. Emits one
    // outbound Interest once Established and logs every matching peer
    // DeclToken / UndeclToken sample to stderr.
    let liveliness_subscribe_opt = parse_pair(rest, "--liveliness-subscribe");
    // R311ph — `--liveliness-subscribe-history` declares the liveliness
    // subscriber with `history = true` (replay current alive tokens on
    // subscription), so an observer is order-independent of token declare time.
    let liveliness_subscribe_history = rest.iter().any(|a| a == "--liveliness-subscribe-history");
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
        && declare_token_opt.is_none()
        && liveliness_subscribe_opt.is_none()
        && liveliness_get_opt.is_none()
        && !on_remote_sub_log
        && !on_remote_q_log
        && !on_remote_l_log
    {
        eprintln!(
            "wz-ap-demo: at least one of --key / --publish / --delete / --queryable / --query / \
             --declare-token / --liveliness-subscribe / --liveliness-get / --on-remote-* must be supplied",
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
        Role::Initiator { connect, reconnect } => {
            log::info!("connect = {connect}");
            if *reconnect {
                log::info!("reconnect = on (long-lived supervised lifecycle)");
            }
        }
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

    // Build the multi-thread runtime explicitly so the spawned
    // writer task (link_pipeline) + the background publisher / query /
    // declare tasks run on worker threads alongside the drive_session
    // poll loop. The outbound `TcpWriteDriver` is a non-blocking channel
    // enqueue (no `block_on`), so this flavor is for task concurrency,
    // not a block_on-deadlock workaround.
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };

    // R300 — eager argv-level validation of the keyexprs that flow onto the
    // OUTBOUND wire. The same gate fires later at send-time (so library API
    // users are equally protected), but argv-level eager-fail gives the CLI
    // user a faster + more locatable error than waiting for the Established
    // gate to fire 5s later.
    //
    // R311ou — `--key` joined this list: it now declares a ROUTED subscriber
    // (`Session::declare_subscriber` emits `Declare(DeclSubscriber)` so a
    // router routes matching Pushes back), so its keyexpr reaches the outbound
    // wire and must pass the pico-safety gate.
    //
    // R311ow — `--queryable` likewise joined: `Session::declare_queryable` now
    // declares a ROUTED queryable (emits `Declare(DeclQueryable)` so a router
    // routes matching Query requests here), so its keyexpr also reaches the
    // outbound wire. The remaining receive-side keyexprs (--query,
    // --liveliness-subscribe) are still NOT gated: their patterns match INBOUND
    // peer keyexprs, never emitted by wz.
    for (flag, keyexpr_opt) in [
        ("--key", key_opt.as_deref()),
        (
            "--queryable",
            queryable_spec.as_ref().map(|(p, _)| p.as_str()),
        ),
        ("--declare-token", declare_token_opt.as_deref()),
    ] {
        if let Some(keyexpr) = keyexpr_opt {
            if let Err(e) = check_outbound_keyexpr_pico_safe(keyexpr) {
                eprintln!(
                    "wz-ap-demo: {flag}={keyexpr:?} rejected by R300 outbound \
                     DECLARE gate: {e}"
                );
                return ExitCode::from(2);
            }
        }
    }

    let declare_spec = DeclareEmitSpec {
        token_keyexpr: declare_token_opt,
        liveliness_subscriber_keyexpr: liveliness_subscribe_opt,
        liveliness_subscriber_history: liveliness_subscribe_history,
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
        liveliness_get: liveliness_get_opt,
    };
    // Optional `--zid <hex>`: override the single-session node's demo zid. The
    // mesh routing graph keys nodes by zid, so two session nodes behind routers
    // sharing the hardcoded 0x01020304 would collide; a distinct --zid per node
    // lets a query ISSUER + a QUERYABLE coexist in one router mesh (the P4 §5.21
    // query-plane E2E). No-op for the default direct wz<->wz tests.
    let zid_override: Option<Vec<u8>> = match parse_pair(rest, "--zid") {
        Some(h) => match parse_zid_hex(&h) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("wz-ap-demo: --zid {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
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
            zid_override,
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

/// Decode a `--zid <hex>` value into raw zid bytes — non-empty, even-length hex
/// (`"0a0b0c0d"` -> `[0x0a,0x0b,0x0c,0x0d]`). The demo zid override for a session
/// node that must carry a distinct identity inside a router mesh (the query-plane
/// E2E). Rejects odd-length / non-hex loudly so a mistyped flag fails fast.
fn parse_zid_hex(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim();
    if h.is_empty() || h.len() % 2 != 0 {
        return Err(format!("must be non-empty even-length hex (got {h:?})"));
    }
    // Reject any non-hex char up front — `u8::from_str_radix` otherwise accepts a
    // leading `+`/`-` inside a pair (e.g. "+a"), which is not valid hex here.
    if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid hex in {h:?}"));
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| format!("invalid hex in {h:?}")))
        .collect()
}

/// The demo's multi-thread tokio runtime (2 workers + io + time) — the SSOT for
/// both the single-session `run_demo` path and the `--router` multi-peer path.
/// Multi-thread so the spawned writer tasks (per session, and per face in the
/// router) run on workers alongside the drive loop.
fn build_demo_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
}

/// R311qa — drive the `--router` multi-peer mode: init logging, build the
/// runtime, and run the accept-and-hold loop ([`runner::run_router`]) to the
/// graceful-shutdown signal. Separate from the single-session `run_demo` entry
/// because a router has no per-face application behaviour — it only holds peers.
#[cfg(feature = "routing-router")]
fn run_router_mode(addr: String) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_router(&addr)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}

/// R311tw — the §5.16 interceptor opt-ins (`--acl-deny` / `--downsample`)
/// bundled into one parameter object, so the peer entry points stay under the
/// argument-count lint as the interceptor flag set grows — the same param-object
/// shape R311lw used for `run_session`. Each is `None` unless its flag was given.
#[cfg(feature = "routing-peer")]
pub(crate) struct InterceptorOpts {
    pub(crate) acl_deny: Option<String>,
    pub(crate) downsample: Option<String>,
    pub(crate) max_payload: Option<String>,
}

/// R311qg — peer-MESH mode entry: bind `listen`, dial each `dial_targets` peer,
/// and hold both directions' faces (the `routing-peer` foundation, hold-only).
/// Mirrors [`run_router_mode`] — a router has no per-face application behaviour,
/// and neither does a hold-only mesh peer.
#[cfg(feature = "routing-peer")]
fn run_peer_mode(
    listen: String,
    dial_targets: Vec<String>,
    opts: crate::runner::PeerOpts,
    interceptors: InterceptorOpts,
) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_peer(
        &listen,
        &dial_targets,
        &opts,
        &interceptors,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}

/// R311y277 (§5.23 adminspace-config-hotreload ACTIVATION) — storage-host mode
/// entry (`--storage-host <listen>`): init logging, build the runtime, and run the
/// multi-accept storage-hosting loop
/// ([`runner::run_storage_host`](crate::runner::run_storage_host)). Mirrors
/// [`run_router_hat_mode`] — a bare loop with no per-connection application I/O,
/// just the admin GET queryable + config-write subscriber + the storage lifecycle
/// apply (live-spawn / -despawn a `RuntimeStorageManager` storage).
#[cfg(feature = "adminspace-config-hotreload")]
fn run_storage_host_mode(listen: String) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_storage_host(&listen)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}

/// P4 §5.21 ACTIVATION — router-hat mode entry (`--router-hat <listen>`): present
/// a true wire WhatAmI::Router and drive the dual-mesh RouterForwarder over real
/// transport ([`runner::run_router_hat`](crate::runner::run_router_hat)). Mirrors
/// [`run_peer_mode`] — bind + dial the `--connect` router set + hold faces — but
/// the node announces Router and hosts no application I/O (a pure router).
#[cfg(feature = "router-hat-router")]
fn run_router_hat_mode(
    listen: String,
    dial_targets: Vec<String>,
    connect_after: Option<(u64, Vec<String>)>,
    multicast_qos: bool,
) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_router_hat(
        &listen,
        &dial_targets,
        connect_after,
        multicast_qos,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}
