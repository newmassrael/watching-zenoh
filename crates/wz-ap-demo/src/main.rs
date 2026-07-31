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

#[cfg(feature = "scouting-active")]
use crate::args::DEMO_ZID;
use crate::args::{
    parse_pair, AdvancedPublishSpec, DeclareEmitSpec, LivelinessGetSpec, PublisherSpec,
    PushOperation, QueryEmitSpec, QueryRoleSpec, QueryableReply, QueryableSpec, RemoteLogSpec,
    ReplyConsumerSpec, Role, DEFAULT_SCOUT_BUDGET_MS,
};
use crate::runner::run_demo;
use crate::usage::{print_usage, ABOUT};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let rest = &args[1..];

    // R311y482 — the BUILD FEATURES line, emitted HERE: ahead of the --help
    // return AND ahead of every mode branch below, so no invocation can omit it.
    // `eprintln!` rather than `log::info!` on purpose — the `--router` / `--peer`
    // / `--router-hat` / `--storage-host` modes each own their env_logger init
    // further down, so a logged line would be dropped by whichever path had not
    // initialised yet. See `usage::build_features` for why this line is
    // load-bearing rather than decorative.
    eprintln!("{}", crate::usage::build_features());

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
        // R311y405 — a `--router tls/...` / `--router quic/...` threads its server
        // cert via the same `--<scheme>-cert` / `--<scheme>-key` flags the one-shot
        // `--listen` acceptor uses, so mesh quic/tls works end-to-end (was rejected
        // at bind cert-absence). Cert-free schemes (tcp/ws/udp) leave them None.
        #[cfg(feature = "routing-router")]
        return run_router_mode(
            router_addr,
            parse_pair(rest, "--tls-cert"),
            parse_pair(rest, "--tls-key"),
            parse_pair(rest, "--quic-cert"),
            parse_pair(rest, "--quic-key"),
        );
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
            //
            // R311y431 — `--autoconnect-strategy <always|greater-zid>` picks the
            // tie-break, and the DEFAULT is `always` because that is zenoh's
            // default (`DEFAULT_CONFIG.json5` `autoconnect_strategy: { peer: {
            // to_router: "always", to_peer: "always" } }`). Before this the demo
            // hardcoded `greater-zid`, so no deploy could express zenoh's own
            // default. The strategy rides INSIDE the opt-in (`Option<_>`), so
            // "off, but with a strategy" cannot be constructed; a strategy given
            // without the opt-in is a hard error rather than a silent no-op.
            let autoconnect = if rest.iter().any(|a| a == "--autoconnect") {
                match parse_pair(rest, "--autoconnect-strategy").as_deref() {
                    None | Some("always") => Some(crate::runner::AutoConnectStrategy::Always),
                    Some("greater-zid") => Some(crate::runner::AutoConnectStrategy::GreaterZid),
                    Some(other) => {
                        eprintln!(
                            "wz-ap-demo: --autoconnect-strategy {other}: expected \
                             `always` or `greater-zid`"
                        );
                        return ExitCode::from(2);
                    }
                }
            } else if let Some(v) = parse_pair(rest, "--autoconnect-strategy") {
                eprintln!("wz-ap-demo: --autoconnect-strategy {v} requires --autoconnect");
                return ExitCode::from(2);
            } else {
                None
            };
            // R311y431 — `--peer-mode <linkstate|peer-to-peer>`: zenoh's
            // `routing.peer.mode`, which selects the whole routing hat
            // (`hat/mod.rs` -> `linkstate_peer` vs `p2p_peer`) and, per zenoh's
            // own config, "needs to be set to the same value in all peers and
            // routers of the subsystem".
            //
            // wz DEFAULTS TO `linkstate` even though zenoh defaults to
            // `peer_to_peer`, and the divergence is deliberate: wz's data plane
            // routes along the linkstate spanning tree, so `linkstate` is the
            // mode its whole stack implements. `peer-to-peer` here switches the
            // DISCOVERY plane (ingest + re-flood) so a wz peer can learn and
            // gossip-autoconnect inside a default-configured zenoh subsystem;
            // its data plane in that mode is NOT claimed.
            let full_linkstate = match parse_pair(rest, "--peer-mode").as_deref() {
                None | Some("linkstate") => true,
                Some("peer-to-peer") => false,
                Some(other) => {
                    eprintln!(
                        "wz-ap-demo: --peer-mode {other}: expected `linkstate` or \
                         `peer-to-peer`"
                    );
                    return ExitCode::from(2);
                }
            };
            // R311tt (§5.16 access control) — `--acl-deny <keyexpr>` opts this
            // peer into ACL enforcement: an allow-default policy with one ingress
            // Put deny rule on the keyexpr (every peer subject). A Put a neighbour
            // floods on a denied keyexpr is dropped here, not relayed onward.
            // Off by default — without the flag the peer enforces nothing.
            let acl_deny = parse_pair(rest, "--acl-deny");
            // R311tw (§5.16 downsampling) — `--downsample <keyexpr>` rate-limits
            // data on the keyexpr, the QoS sibling of the ACL on the same
            // interceptor chain. Off by default.
            let downsample = parse_pair(rest, "--downsample");
            // R311y452 — `--downsample-freq <hz>` sets that rate in zenoh's own
            // config unit, a maximum FREQUENCY in Hertz (`DownsamplingRuleConf.freq`),
            // rather than in an interval wz invented. Defaults to 2 Hz, which is the
            // 500 ms the flag alone has always meant. `0` is upstream's DROP-ALL
            // rule. Inert without `--downsample`.
            let downsample_freq = parse_pair(rest, "--downsample-freq");
            // R311y453 — the §5.16 SUBJECT axes on the downsampling rule.
            // `--downsample-link-protocol <name>` narrows it to faces speaking that
            // link protocol; `--downsample-interface <nic>` to faces whose link sits
            // on that NIC. Either absent leaves its axis unnarrowed, which is
            // zenoh's `None`. Both inert without `--downsample`.
            let downsample_link_protocol = parse_pair(rest, "--downsample-link-protocol");
            let downsample_interface = parse_pair(rest, "--downsample-interface");
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
            // `--zid <hex>` (optional): PIN this peer's routing zid instead of
            // deriving it from the ephemeral listen port. REQUIRED for a non-IP
            // listen (unixpipe / unixsock / vsock has no port to derive a distinct
            // mesh-graph zid from — R311y397); also gives a deterministic IP mesh id.
            // Mirrors the --router-hat parse.
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
            return run_peer_mode(
                peer_listen,
                dial_targets,
                crate::runner::PeerOpts {
                    publish_key,
                    subscribe_key,
                    unsubscribe_after_data,
                    autoconnect,
                    full_linkstate,
                    config_queryable,
                    config_writable,
                    config_write_permit,
                    no_admin_read,
                    put_key,
                    put_payload,
                    zid_override,
                    #[cfg(feature = "transport-multilink")]
                    max_links,
                    #[cfg(feature = "transport-qos")]
                    qos,
                    #[cfg(feature = "transport-qos")]
                    publish_band,
                    // R311y406 — a `--peer tls/...` / `--peer quic/...` threads its
                    // server cert via the same flags the `--listen`/`--router` paths
                    // use; cert-free schemes leave them None.
                    tls_cert: parse_pair(rest, "--tls-cert"),
                    tls_key: parse_pair(rest, "--tls-key"),
                    quic_cert: parse_pair(rest, "--quic-cert"),
                    quic_key: parse_pair(rest, "--quic-key"),
                },
                InterceptorOpts {
                    acl_deny,
                    downsample,
                    downsample_freq,
                    downsample_link_protocol,
                    downsample_interface,
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
            // `--zid <hex>` (optional): PIN this router's zid so the mesh master
            // election (HRW over shared_nodes) is deterministic — a federation e2e
            // needs a reproducible non-master. Without it the zid derives from the
            // ephemeral listen port and varies per run (the flaky root cause).
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
            return run_router_hat_mode(
                router_hat_listen,
                dial_targets,
                connect_after,
                multicast_qos,
                zid_override,
                // R311y406 — a `--router-hat tls/...` / `quic/...` threads its server
                // cert via the same flags the other listen paths use.
                crate::runner::AcceptCertPaths {
                    tls_cert: parse_pair(rest, "--tls-cert"),
                    tls_key: parse_pair(rest, "--tls-key"),
                    quic_cert: parse_pair(rest, "--quic-cert"),
                    quic_key: parse_pair(rest, "--quic-key"),
                },
                // R311y454 — `--multicast-locator udp/<group>:<port>[#iface=<name>]`:
                // the router's data-plane multicast group, spelled as a LOCATOR so the
                // `#iface=` tail is honoured by the same parser every unicast locator
                // uses. Absent => the historical hardcoded group, unnarrowed. Validated
                // in `run_router_hat_until` (which owns the group defaults) and a bad
                // value is a hard error there, not a silent default.
                parse_pair(rest, "--multicast-locator"),
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
        return run_storage_host_mode(storage_host_listen, parse_pair(rest, "--storage-host-dir"));
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
    // R311y428 — `--scout` is a THIRD way to reach the same Initiator role:
    // the connect locator is DISCOVERED by active multicast scouting instead of
    // given on argv. It is therefore resolved into `connect_opt` below, before
    // the role match, rather than modelled as another node kind — scouting is
    // pre-session locator resolution (docs/scouting-fsm.md), and everything
    // downstream of the resolved string is the ordinary one-shot Initiator.
    let scout_requested = rest.iter().any(|a| a == "--scout");
    let scout_budget_ms: Option<u64> = match parse_pair(rest, "--scout-timeout-ms") {
        Some(raw) => match raw.parse::<u64>() {
            Ok(0) => {
                eprintln!(
                    "wz-ap-demo: --scout-timeout-ms must be > 0 (it is the TOTAL \
                     discovery budget; 0 would emit no Scout at all)"
                );
                return ExitCode::from(2);
            }
            Ok(ms) => Some(ms),
            Err(e) => {
                eprintln!("wz-ap-demo: --scout-timeout-ms {raw:?} is not a u64: {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    if scout_budget_ms.is_some() && !scout_requested {
        eprintln!("wz-ap-demo: --scout-timeout-ms requires --scout");
        return ExitCode::from(2);
    }
    if scout_requested && (listen_opt.is_some() || connect_opt.is_some()) {
        eprintln!(
            "wz-ap-demo: --scout is mutually exclusive with --listen / --connect \
             (it DISCOVERS the locator --connect would have named; an acceptor \
              has nothing to discover)"
        );
        return ExitCode::from(2);
    }

    // env_logger reads RUST_LOG (defaults to off). The integration
    // test fixture (R121c) sets RUST_LOG=info to surface subscriber-
    // dispatch / session-FSM transitions in the child stderr capture.
    //
    // R311y428 — initialised HERE (was: after the whole argv parse, just before
    // the banner) because `--scout` LOGS ITS WITNESS — the locator a peer's
    // Hello advertised — and that happens before the role exists. Measured, not
    // reasoned: with the init still downstream, a real `--scout` run against
    // zenohd discovered and dialed the right locator while emitting NO scouting
    // line at all, so a test asserting on that line would have been asserting on
    // a line the binary could never print. Still exactly ONE init on this path:
    // the `--router` / `--peer` / `--router-hat` / `--storage-host` modes return
    // upstream of this point and keep their own (a second call panics).
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    eprintln!("{ABOUT}");

    // Optional `--zid <hex>`: override the single-session node's demo zid. The
    // mesh routing graph keys nodes by zid, so two session nodes behind routers
    // sharing the hardcoded 0x01020304 would collide; a distinct --zid per node
    // lets a query ISSUER + a QUERYABLE coexist in one router mesh (the P4 §5.21
    // query-plane E2E). No-op for the default direct wz<->wz tests.
    //
    // R311y428 — parsed HERE (was: just before the run_demo call) because
    // `--scout` puts this identity on the wire in its Scout frame, which is
    // emitted before the session role exists.
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

    // Build the multi-thread runtime explicitly so the spawned
    // writer task (link_pipeline) + the background publisher / query /
    // declare tasks run on worker threads alongside the drive_session
    // poll loop. The outbound `TcpWriteDriver` is a non-blocking channel
    // enqueue (no `block_on`), so this flavor is for task concurrency,
    // not a block_on-deadlock workaround.
    //
    // R311y428 — built HERE (was: after the argv parse, just before the
    // `run_demo` block_on) because `--scout` needs an async context BEFORE the
    // role exists — the locator it discovers IS the Initiator's connect target.
    // The same runtime drives `run_demo` below, so this is a move, not a second
    // runtime. The only observable reordering is that a runtime-build failure
    // now precedes the eager keyexpr validation; both are startup rejections
    // with distinct messages.
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };

    // R311y428 — `--scout` resolves the Initiator's locator by ACTIVE multicast
    // scouting; from here on the two paths are indistinguishable, which is the
    // point (a scouted locator is dialed by the same one-shot Initiator code as
    // an argv one).
    let connect_opt = if scout_requested {
        let budget_ms = scout_budget_ms.unwrap_or(DEFAULT_SCOUT_BUDGET_MS);
        match resolve_scouted_locator(&runtime, zid_override.clone(), budget_ms) {
            Ok(locator) => Some(locator),
            Err(code) => return code,
        }
    } else {
        connect_opt
    };
    // R311pw — `--reconnect` is a presence flag (no value): it opts the
    // Initiator into the long-lived reconnect-supervised lifecycle. It is
    // meaningful ONLY with `--connect` (pico AUTO_RECONNECT is client-only);
    // pairing it with `--listen` is a usage error, rejected below.
    let reconnect = rest.iter().any(|a| a == "--reconnect");
    // R311y372 / R311y433 — the two transport-MODE presence flags an Initiator
    // may offer on its InitSyn. R311y435 REMOVED the rejection of their
    // combination. The chain of reasons is worth keeping straight: y433 rejected
    // the pair as having "no coherent cross-impl wire meaning", which y434 showed
    // was true only of a wz defect (wz wrapped compression outside the lean
    // encode; zenoh's lean transport ignores the negotiated wrap). y434 fixed the
    // defect and kept the rejection for a NARROWER, purely local reason —
    // session_open had one entrypoint per MODE and none staged both offers — and
    // named widening it as the next slice. That slice is y435:
    // `initiate_and_open_session_with_offer` takes the SET, so both flags now
    // compose here exactly as they do upstream, and `runner::initiator_offer`
    // builds the offer.
    let lowlatency = rest.iter().any(|a| a == "--lowlatency");
    let compression = rest.iter().any(|a| a == "--compression");
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
        (Some(addr), None) => Role::Acceptor {
            listen: addr,
            // R311y375 — the cert-chain + private-key PEM paths a `tls/...` --listen
            // PRESENTS (the accept mirror of the Initiator's --tls-ca). Read here,
            // applied only on the one-shot accept path (establish_link /
            // build_accept_config); `None` for a non-tls listen.
            tls_cert: parse_pair(rest, "--tls-cert"),
            tls_key: parse_pair(rest, "--tls-key"),
            // R311y401 — the cert-chain + private-key PEM paths a `quic/...` --listen
            // PRESENTS (the QUIC twin of --tls-cert/--tls-key; SEPARATE flags since the
            // demo builds QUIC's own server config (TLS-1.3 + ALPN hq-29) from them,
            // the cert PEM itself being interchangeable). Applied only on the one-shot
            // accept path; `None` for a non-quic listen.
            quic_cert: parse_pair(rest, "--quic-cert"),
            quic_key: parse_pair(rest, "--quic-key"),
        },
        (None, Some(addr)) => Role::Initiator {
            connect: addr,
            reconnect,
            // R311y365 — the root-CA PEM path for a `tls/...` --connect (verified
            // against server name `localhost`). Read here, applied only on the
            // one-shot dial path (establish_link); `None` for a non-tls connect.
            tls_ca: parse_pair(rest, "--tls-ca"),
            // R311y366 — root-CA PEM path for a `quic/...` --connect (QUIC sibling
            // of --tls-ca; verified against server name `localhost`).
            quic_ca: parse_pair(rest, "--quic-ca"),
            // R311y369 — keyexpr namespace prefix for outbound publishes.
            namespace: parse_pair(rest, "--namespace"),
            // R311y372 — `--lowlatency` presence flag: offer the lowlatency
            // transport on the InitSyn (mirror of `--reconnect` presence parsing).
            lowlatency,
            // R311y433 — `--compression` presence flag: offer Z_EXT_COMPRESSION
            // (0x6) on the InitSyn, so a peer that also offers it negotiates the
            // per-batch lz4 wrap. Exclusive with `--lowlatency` (guard arm above).
            compression,
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
    // R311y481 — `--reply-err <text>` makes the queryable answer an ERR-form
    // Reply instead of `--reply`'s OK Put-form one. Mutually exclusive with
    // `--reply` (rejected below): a queryable answers one Query with one arm.
    let reply_err_opt = parse_pair(rest, "--reply-err");
    // R311y481 — `--query-params <params>` puts URL-style selector parameters on
    // the outbound Query body (`Q_P` flag + slice), and `--query-attachment
    // <k>=<v>[,…]` puts a kv-pair attachment on its ext 0x05. Both feature-uniform
    // (always parsed); see `QueryEmitSpec` for why the inertness is decided
    // downstream rather than here.
    let query_params_opt = parse_pair(rest, "--query-params");
    let query_attachment_opt = parse_pair(rest, "--query-attachment");
    // R311y481 — `--query-after-ms <ms>` holds the one-shot Query that long after
    // Established, so a foreign queryable has time to finish declaring. A
    // malformed value is a HARD error rather than a silent None, for the reason
    // `--liveliness-get-after-ms` rejects: an ordering knob that quietly does
    // nothing leaves the Query firing at t=0, which is the exact race it exists to
    // remove -- and the proof would then go green only when the timing happened to
    // work, i.e. flakily.
    let query_after_ms: Option<u64> = match parse_pair(rest, "--query-after-ms") {
        Some(s) => match s.trim().parse::<u64>() {
            Ok(ms) => Some(ms),
            Err(_) => {
                eprintln!("wz-ap-demo: --query-after-ms expects milliseconds, got '{s}'");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // liveliness-get — optional `--liveliness-get <keyexpr>` issues one
    // CURRENT liveliness snapshot Interest once Established and logs each
    // reply + the terminating final. Reply-consuming "get" surface on the
    // declaration plane (sibling of --query on the Request plane).
    let liveliness_get_opt = parse_pair(rest, "--liveliness-get");
    // R311y353 — `--liveliness-get-after-ms <ms>` holds the get that long after
    // Established, so a foreign token holder has time to declare. A malformed
    // value is a HARD error rather than a silent None, for the same reason
    // `--publish-after-ms` rejects: an ordering knob that quietly does nothing
    // leaves the get firing at t=0, which is the exact race it exists to remove
    // -- and the proof would go green on an empty snapshot only when the timing
    // happened to work, i.e. flakily.
    let liveliness_get_after_ms: Option<u64> = match parse_pair(rest, "--liveliness-get-after-ms") {
        Some(s) => match s.trim().parse::<u64>() {
            Ok(ms) => Some(ms),
            Err(_) => {
                eprintln!("wz-ap-demo: --liveliness-get-after-ms expects milliseconds, got '{s}'");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
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
    // R311y442 — `--advanced-subscribe <keyexpr>` declares an AdvancedSubscriber
    // whose STARTUP HISTORY GET asks every matching publisher's `@adv` cache for
    // the samples it published before this subscriber existed. `--history-max <N>`
    // caps that GET (`_max=N`). Feature-uniform parse (the `namespace` idiom): the
    // flags always parse, and `install_session_handles` reports the inert case on a
    // build without the `advanced` feature.
    let advanced_subscribe_opt = parse_pair(rest, "--advanced-subscribe");
    let advanced_history_max: Option<usize> = match parse_pair(rest, "--history-max") {
        Some(s) => match s.parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("wz-ap-demo: --history-max must be a usize (got {s:?})");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let advanced_history_max_age: Option<f64> = match parse_pair(rest, "--history-max-age") {
        Some(s) => match s.parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 => Some(n),
            _ => {
                eprintln!("wz-ap-demo: --history-max-age must be a positive f64 (got {s:?})");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // R311y443 — `--advanced-recovery` arms the SAMPLE-DRIVEN retransmission
    // trigger on that subscriber: a forward gap in a source's sequence numbers
    // is buffered and back-filled by an `_sn=last+1..` GET against that source's
    // `@adv` cache, instead of being reported as a Miss and delivered past.
    //
    // Sample-driven ONLY — no periodic re-ask, no heartbeat listener — and that
    // is what makes it a usable proof vehicle rather than just a feature switch.
    // wz has three recovery triggers and upstream's `z_advanced_pub` oracle emits
    // a 500 ms heartbeat beacon, so a subscriber with all three armed recovers a
    // gap without telling you WHICH trigger did it. With only the gap trigger
    // live, a recovered sample is attributable to the gap that preceded it.
    let advanced_recovery = rest.iter().any(|a| a == "--advanced-recovery");
    // R311y444 — the HEARTBEAT trigger, armed separately so the two triggers stay
    // distinguishable (they issue different selectors; see the field doc).
    let advanced_recovery_heartbeat = rest.iter().any(|a| a == "--advanced-recovery-heartbeat");
    if advanced_recovery_heartbeat && !advanced_recovery {
        eprintln!(
            "wz-ap-demo: --advanced-recovery-heartbeat requires --advanced-recovery \
             (the heartbeat trigger lives inside RecoveryConfig; without recovery it \
             would arm nothing)"
        );
        return ExitCode::from(2);
    }
    // The ceiling on `--advanced-recovery-periodic`, one hour. Far above any
    // plausible re-ask cadence and far below the u64::MAX that reads as armed
    // while never firing (R311y447-review).
    const PERIODIC_MAX_MS: u64 = 3_600_000;
    // R311y447 — the PERIODIC trigger, armed separately for the same reason as the
    // heartbeat one. It takes a PERIOD rather than being a bare switch because the
    // period is the observable: periodic emits the same OPEN `_sn=last+1..`
    // selector sample-driven does, so what distinguishes it is that it asks on a
    // cadence with no gap to explain the ask, and a fixture must know the cadence.
    let advanced_recovery_periodic_ms: Option<u64> =
        match parse_pair(rest, "--advanced-recovery-periodic") {
            Some(s) => match s.parse::<u64>() {
                Ok(0) => {
                    eprintln!(
                        "wz-ap-demo: --advanced-recovery-periodic must be > 0 \
                         (the runtime clamps a 0 ms period to 1 ms, i.e. a GET storm)"
                    );
                    return ExitCode::from(2);
                }
                // R311y447-review (REVIEWER 3) — the SYMMETRIC guard. The 0 case
                // is rejected because a degenerate period misrepresents the armed
                // state, and the top end does exactly the same thing from the
                // other side: `Duration::from_millis(u64::MAX)` survives the
                // runtime's `.max(1)` clamp (advanced_subscriber.rs:1516) as a
                // ~584-million-year sleep, so the declare marker reports the
                // trigger ARMED while its behaviour is identical to unarmed. The
                // ceiling is the run window a fixture could plausibly use; past
                // it, "armed" is a claim the process will never honour.
                Ok(n) if n > PERIODIC_MAX_MS => {
                    eprintln!(
                        "wz-ap-demo: --advanced-recovery-periodic {n} ms exceeds the \
                         {PERIODIC_MAX_MS} ms ceiling; a period no run will reach \
                         reports the trigger as armed while it never fires"
                    );
                    return ExitCode::from(2);
                }
                Ok(n) => Some(n),
                Err(_) => {
                    eprintln!(
                        "wz-ap-demo: --advanced-recovery-periodic must be a u64 \
                         millisecond period (got {s:?})"
                    );
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
    if advanced_recovery_periodic_ms.is_some() && !advanced_recovery {
        eprintln!(
            "wz-ap-demo: --advanced-recovery-periodic requires --advanced-recovery \
             (the periodic trigger lives inside RecoveryConfig; without recovery it \
             would arm nothing)"
        );
        return ExitCode::from(2);
    }
    // R311y442 — `--advanced-publish <keyexpr>` is the ANSWERING half: a wz
    // AdvancedPublisher whose `@adv` cache a FOREIGN advanced subscriber drains.
    // `--cache-max` sets the ring depth, `--advanced-publish-count` the burst size.
    let advanced_publish_opt = parse_pair(rest, "--advanced-publish");
    let advanced_cache_max: Option<usize> = match parse_pair(rest, "--cache-max") {
        Some(s) => match s.parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("wz-ap-demo: --cache-max must be a usize (got {s:?})");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // Cloned here because `value_opt` is MOVED into `publisher_spec` further down;
    // `--value` is shared between the plain and the advanced publisher.
    let advanced_publish_value = value_opt.clone();
    let advanced_publish_count: usize = match parse_pair(rest, "--advanced-publish-count") {
        Some(s) => match s.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("wz-ap-demo: --advanced-publish-count must be a usize (got {s:?})");
                return ExitCode::from(2);
            }
        },
        None => 5,
    };
    // R311y444 — `--advanced-publish-heartbeat <ms>` arms the publisher's last-sn
    // BEACON. Parsed as its own flag rather than folded into `--advanced-publish`
    // because its ABSENCE is load-bearing: the control twin of the beacon leg is
    // the same argv minus this flag, so a default that armed it would make the
    // two legs indistinguishable.
    let advanced_publish_heartbeat_ms: Option<u64> =
        match parse_pair(rest, "--advanced-publish-heartbeat") {
            Some(s) => match s.parse::<u64>() {
                Ok(0) => {
                    eprintln!(
                        "wz-ap-demo: --advanced-publish-heartbeat must be > 0 ms \
                         (0 would spin the beacon loop)"
                    );
                    return ExitCode::from(2);
                }
                Ok(n) => Some(n),
                Err(_) => {
                    eprintln!(
                        "wz-ap-demo: --advanced-publish-heartbeat must be a u64 \
                         millisecond period (got {s:?})"
                    );
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
    // R311y444-review (REVIEWER 3) — the sibling guard. `--advanced-publish-heartbeat`
    // arms a beacon ON the advanced publisher, so without `--advanced-publish` it
    // has nothing to arm. Rejected rather than ignored, matching this file's own
    // convention for `--value` without a publisher flag ("rejected to surface
    // mis-wired argv") and its twin `--advanced-recovery-heartbeat` above. The
    // first version of this round guarded one of the two new flags and not the
    // other, in a single commit.
    if advanced_publish_heartbeat_ms.is_some() && advanced_publish_opt.is_none() {
        eprintln!(
            "wz-ap-demo: --advanced-publish-heartbeat requires --advanced-publish \
             (the beacon rides the advanced publisher; without one it arms nothing)"
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    // R311y445 — `--group-join <group>`: join a zenoh-ext GROUP. The member id is
    // its own flag because it is the literal a FOREIGN peer prints in its view
    // listing, so a fixture must be able to pin it rather than grep for whatever
    // zid the demo happened to get.
    let group_join_opt = parse_pair(rest, "--group-join");
    let group_member_id_opt = parse_pair(rest, "--group-member-id");
    let group_lease_secs: Option<u64> = match parse_pair(rest, "--group-lease-secs") {
        Some(s) => match s.parse::<u64>() {
            Ok(0) => {
                eprintln!(
                    "wz-ap-demo: --group-lease-secs must be > 0 (a 0 lease expires instantly)"
                );
                return ExitCode::from(2);
            }
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("wz-ap-demo: --group-lease-secs must be a u64 (got {s:?})");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // The sibling guard, per R311y444-review: a flag that configures a mode is
    // rejected without that mode rather than silently ignored.
    for (flag, present) in [
        ("--group-member-id", group_member_id_opt.is_some()),
        ("--group-lease-secs", group_lease_secs.is_some()),
    ] {
        if present && group_join_opt.is_none() {
            eprintln!(
                "wz-ap-demo: {flag} requires --group-join (without a group there is \
                 no member to configure)"
            );
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    }
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
        // R311y442 — `--advanced-subscribe` is a standalone role like `--key`:
        // it declares a subscriber and drains the publishers' `@adv` caches, so
        // a demo carrying only this flag has real work to do.
        && advanced_subscribe_opt.is_none()
        && advanced_publish_opt.is_none()
        // R311y445 — `--group-join` is a standalone role too: joining a group
        // declares an event subscriber, a per-member queryable and a keep-alive
        // beacon, which is exactly the work a foreign group peer observes.
        && group_join_opt.is_none()
    {
        eprintln!(
            "wz-ap-demo: at least one of --key / --publish / --delete / --queryable / --query / \
             --declare-token / --liveliness-subscribe / --liveliness-get / \
             --advanced-subscribe / --advanced-publish / --group-join / \
             --on-remote-* must be supplied",
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
    // R311y442 — `--advanced-publish` carries a payload too, so it joins `--publish`
    // as a legitimate reason for `--value` to be present. The mis-wired-argv reject
    // stays for the case neither publisher flag is set.
    if advanced_publish_opt.is_some() && value_opt.is_none() {
        eprintln!("wz-ap-demo: --advanced-publish requires --value");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if publish_opt.is_none() && advanced_publish_opt.is_none() && value_opt.is_some() {
        eprintln!(
            "wz-ap-demo: --value is only meaningful with --publish / --advanced-publish \
             (rejected to surface mis-wired argv)"
        );
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
    // R311y481 — `--reply-err` joins `--reply` as a legitimate answer arm, so both
    // directions of this pair-check widen with it. The mutual EXCLUSION of the two
    // is checked here too rather than beside the spec construction below: this is
    // where the demo's argv pair-checks live, and a second validation site is a
    // second place for the rules to drift.
    if reply_opt.is_some() && reply_err_opt.is_some() {
        eprintln!(
            "wz-ap-demo: --reply and --reply-err are mutually exclusive; a queryable \
             answers a Query with an OK reply OR an ERR reply, not both",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_some() && reply_opt.is_none() && reply_err_opt.is_none() {
        eprintln!("wz-ap-demo: --queryable requires --reply <text> or --reply-err <text>");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_none() && (reply_opt.is_some() || reply_err_opt.is_some()) {
        eprintln!(
            "wz-ap-demo: --reply / --reply-err are only meaningful with --queryable (rejected to surface mis-wired argv)",
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
    // R311y345 — `--publish-after-ms <ms>` holds the burst that long after
    // Established, leaving the line idle. A malformed value is a hard error
    // rather than a silent None: an ordering knob that quietly does nothing
    // would turn the keepalive proof vacuous (the burst would fire at t=0 and
    // the lease window it exists to cross would never open).
    let publish_after_ms: Option<u64> = match parse_pair(rest, "--publish-after-ms") {
        Some(s) => match s.trim().parse::<u64>() {
            Ok(ms) => Some(ms),
            Err(_) => {
                eprintln!("wz-ap-demo: --publish-after-ms expects milliseconds, got '{s}'");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // R311y345 — `--batch` wraps the burst in a TX batching window. A bare flag
    // (no value), like `--reconnect` and `--delete`.
    let batch = rest.iter().any(|a| a == "--batch");
    // R311y347 — `--matching-log` installs a matching listener on the publish
    // keyexpr. A bare flag, same family as `--batch` / `--on-remote-*-log`.
    // Deliberately NOT cfg-gated: the `session-matching`-OFF build must reach the
    // same path and surface the typed reject, because that arm is the
    // anti-vacuity twin the proof rests on.
    let matching_log = rest.iter().any(|a| a == "--matching-log");
    let publisher_spec: Option<PublisherSpec> = match (publish_opt, value_opt, delete_opt) {
        (Some(k), Some(v), None) => Some(PublisherSpec {
            keyexpr: k,
            operation: PushOperation::Put { value: v },
            declare_id: declare_id_parsed,
            publish_after_ms,
            batch,
            matching_log,
        }),
        (None, None, Some(k)) => Some(PublisherSpec {
            keyexpr: k,
            operation: PushOperation::Delete,
            declare_id: declare_id_parsed,
            publish_after_ms,
            batch,
            matching_log,
        }),
        _ => None,
    };
    // A knob that silently does nothing is how a proof goes vacuous (R311y345's
    // rule for --publish-after-ms). `--matching-log` needs a publisher to hang
    // the listener on, so name the mistake rather than ignoring the flag.
    if matching_log && publisher_spec.is_none() {
        eprintln!(
            "wz-ap-demo: --matching-log needs a publisher; pass --publish <keyexpr> \
             --value <text> (or --delete <keyexpr>)"
        );
        return ExitCode::from(2);
    }
    // The three argv pair-checks this match relies on (`--reply` xor `--reply-err`;
    // each needs `--queryable`; `--queryable` needs one of them) all fired above,
    // at the demo's pair-check site. So every reachable combination here is
    // well-formed and the `_` arm is genuinely "no queryable requested".
    let queryable_spec: Option<QueryableSpec> = match (queryable_opt, reply_opt, reply_err_opt) {
        (Some(keyexpr), Some(text), None) => Some(QueryableSpec {
            keyexpr,
            reply: QueryableReply::Ok(text),
        }),
        (Some(keyexpr), None, Some(text)) => Some(QueryableSpec {
            keyexpr,
            reply: QueryableReply::Err(text),
        }),
        _ => None,
    };
    // R311y481 — `--query-params` / `--query-attachment` decorate `--query`, so a
    // run that passes one without it would emit nothing at all. Reject rather
    // than ignore, for the reason the `--reply` guard above states.
    if query_opt.is_none()
        && (query_params_opt.is_some()
            || query_attachment_opt.is_some()
            || query_after_ms.is_some())
    {
        eprintln!(
            "wz-ap-demo: --query-params / --query-attachment / --query-after-ms \
             decorate an outbound Query; pass --query <keyexpr>"
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    // `<k>=<v>[,<k>=<v>…]`. A malformed pair is a HARD error: an attachment that
    // silently drops a pair changes the sequence COUNT a foreign decoder reads,
    // so it would corrupt the very witness the flag exists to produce.
    let query_attachment_pairs: Option<Vec<(String, String)>> = match &query_attachment_opt {
        Some(spec) => {
            let mut pairs = Vec::new();
            for item in spec.split(',') {
                match item.split_once('=') {
                    Some((k, v)) if !k.is_empty() => pairs.push((k.to_string(), v.to_string())),
                    _ => {
                        eprintln!(
                            "wz-ap-demo: --query-attachment expects \
                             '<key>=<value>[,<key>=<value>…]' with a non-empty key, \
                             got {item:?}"
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            Some(pairs)
        }
        None => None,
    };
    let query_spec: Option<QueryEmitSpec> = query_opt.map(|keyexpr| QueryEmitSpec {
        keyexpr,
        parameters: query_params_opt,
        attachment: query_attachment_pairs,
        after_ms: query_after_ms,
    });

    // R311y428 — the env_logger init + the `{ABOUT}` banner that stood here
    // moved UP, ahead of the `--scout` locator resolution (see the comment at
    // that site). The role echo below is unchanged and still reports the
    // Initiator's `connect` — for a scouted run, that IS the discovered locator.
    match &role {
        Role::Acceptor {
            listen,
            tls_cert,
            tls_key,
            quic_cert,
            quic_key,
        } => {
            log::info!("listen  = {listen}");
            if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
                log::info!("tls-cert = {cert}");
                log::info!("tls-key  = {key}");
            }
            if let (Some(cert), Some(key)) = (quic_cert, quic_key) {
                log::info!("quic-cert = {cert}");
                log::info!("quic-key  = {key}");
            }
        }
        Role::Initiator {
            connect,
            reconnect,
            tls_ca,
            quic_ca,
            namespace,
            lowlatency,
            compression,
        } => {
            log::info!("connect = {connect}");
            if *reconnect {
                log::info!("reconnect = on (long-lived supervised lifecycle)");
            }
            if let Some(ca) = tls_ca {
                log::info!("tls-ca  = {ca} (tls/ dial verifies server name localhost)");
            }
            if let Some(ca) = quic_ca {
                log::info!("quic-ca = {ca} (quic/ dial verifies server name localhost)");
            }
            if let Some(ns) = namespace {
                log::info!("namespace = {ns} (outbound keyexprs prefixed {ns}/<key>)");
            }
            if *lowlatency {
                log::info!("lowlatency = on (offers Z_EXT_LOWLATENCY on the InitSyn)");
            }
            if *compression {
                log::info!("compression = on (offers Z_EXT_COMPRESSION on the InitSyn)");
            }
        }
    }
    if let Some(k) = &key_opt {
        log::info!("key     = {k}");
    }
    if let Some(PublisherSpec {
        keyexpr: k,
        operation: op,
        declare_id: id,
        publish_after_ms: after,
        batch: batch_on,
        matching_log: matching_on,
    }) = &publisher_spec
    {
        if *batch_on {
            log::info!("batch   = on (burst rides ONE frame; zp_start_batching parity)");
        }
        if *matching_on {
            log::info!(
                "matching = on (logs every matching-status transition a remote \
                 Decl/UndeclSubscriber drives)"
            );
        }
        if let Some(ms) = after {
            log::info!("publish-after = {ms}ms (burst held; session idle for this window)");
        }
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
    if let Some(QueryableSpec { keyexpr, reply }) = &queryable_spec {
        log::info!("queryable = {keyexpr}");
        match reply {
            QueryableReply::Ok(text) => log::info!("reply     = {text}"),
            QueryableReply::Err(text) => {
                log::info!("reply-err = {text} (ERR-form Reply, not a Put-form one)")
            }
        }
    }
    if let Some(QueryEmitSpec {
        keyexpr,
        parameters,
        attachment,
        after_ms,
    }) = &query_spec
    {
        log::info!("query   = {keyexpr}");
        if let Some(ms) = after_ms {
            log::info!("query-after = {ms}ms (one-shot Query held; line idle for this window)");
        }
        if let Some(params) = parameters {
            log::info!("query-params = {params} (Q_P flag + selector slice)");
        }
        if let Some(pairs) = attachment {
            log::info!(
                "query-attachment = {} pair(s) {:?} (ext 0x05, ze_serializer kv form)",
                pairs.len(),
                pairs,
            );
        }
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
            queryable_spec.as_ref().map(|q| q.keyexpr.as_str()),
        ),
        ("--declare-token", declare_token_opt.as_deref()),
        // R311y442 — `--advanced-subscribe` joined for the same reason as `--key`:
        // an AdvancedSubscriber declares a ROUTED subscriber on the keyexpr AND
        // derives its startup history GET (`<keyexpr>/@adv/**`) from it, so the
        // literal reaches the outbound wire on two paths, not one.
        ("--advanced-subscribe", advanced_subscribe_opt.as_deref()),
        // The advanced publisher emits Puts on this literal AND declares its cache
        // queryable + `@adv` liveliness token under it, so it is outbound twice over.
        ("--advanced-publish", advanced_publish_opt.as_deref()),
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
        advanced_subscriber_keyexpr: advanced_subscribe_opt,
        advanced_history_max,
        advanced_history_max_age,
        advanced_recovery,
        advanced_recovery_heartbeat,
        advanced_recovery_periodic_ms,
        group_join: group_join_opt.map(|group| crate::args::GroupJoinSpec {
            group,
            // Defaulted rather than required: the id only has to be STABLE for a
            // fixture to grep, and a literal default keeps the common case short.
            member_id: group_member_id_opt.unwrap_or_else(|| "wz-member".to_string()),
            lease_secs: group_lease_secs,
        }),
        advanced_publish: advanced_publish_opt.map(|keyexpr| AdvancedPublishSpec {
            keyexpr,
            // Guarded above: `--advanced-publish` without `--value` already exited.
            value: advanced_publish_value.unwrap_or_default(),
            count: advanced_publish_count,
            cache_max: advanced_cache_max,
            interval_ms: 200,
            heartbeat_ms: advanced_publish_heartbeat_ms,
            // Full path, not the `use` above: that import is `scouting-active`-gated
            // and this site is not.
            zid: zid_override
                .clone()
                .unwrap_or_else(|| crate::args::DEMO_ZID.to_vec()),
        }),
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
        liveliness_get: liveliness_get_opt.map(|keyexpr| LivelinessGetSpec {
            keyexpr,
            after_ms: liveliness_get_after_ms,
        }),
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
    let bytes: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| format!("invalid hex in {h:?}")))
        .collect::<Result<_, _>>()?;
    // R311y412 — enforce zenoh's zid VALIDITY at the CLI boundary, the same rule the
    // wire ctor `Zid::try_from` applies. Two gaps this closes:
    //   * all-zero (`--zid 00`) has no significant bytes, so it is not an identity at
    //     all; the node bound and then lost face after face forever.
    //   * over 16 bytes silently CORRUPTS the wire in release: `handshake_encode`'s
    //     `(zid_len - 1) & 0x0F` wraps, so a 17-byte zid encodes as length 1. The
    //     `debug_assert!` there catches it in debug builds only.
    if bytes.iter().all(|&b| b == 0) {
        return Err(format!(
            "must have at least one non-zero byte — zenoh identity is the VALUE, and \
             an all-zero zid ({h:?}) is empty"
        ));
    }
    if bytes.len() > 16 {
        return Err(format!(
            "must be at most 16 bytes (got {} in {h:?}) — zenoh's ZenohId MAX_SIZE",
            bytes.len()
        ));
    }
    Ok(bytes)
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

/// R311y428 — run one ACTIVE multicast scouting discovery and hand back the
/// locator a peer's Hello advertised, which the caller uses as the Initiator's
/// `--connect` target. `zid` is the `--zid <hex>` override when given; the Scout
/// otherwise announces [`DEMO_ZID`], the same identity the session will open
/// with.
///
/// Blocks on the demo runtime rather than being awaited inside `run_demo`
/// because the discovered locator is what CONSTRUCTS the role — there is no
/// Initiator to await it from yet.
#[cfg(feature = "scouting-active")]
fn resolve_scouted_locator(
    runtime: &tokio::runtime::Runtime,
    zid: Option<Vec<u8>>,
    budget_ms: u64,
) -> Result<String, ExitCode> {
    let zid = zid.unwrap_or_else(|| DEMO_ZID.to_vec());
    runtime
        .block_on(crate::runner::scout_for_peer_locator(zid, budget_ms))
        .map_err(|e| {
            eprintln!("{e}");
            ExitCode::from(1)
        })
}

/// The `scouting-active`-less build REJECTS `--scout` rather than silently
/// falling back to some other locator source — the same "the catalog claim and
/// the binary stay in lockstep" rule the `--router` / `--router-hat` /
/// `--storage-host` mode flags follow. Nothing about the flag's PARSE is gated;
/// only its execution is, so argv diagnostics are identical in both builds.
#[cfg(not(feature = "scouting-active"))]
fn resolve_scouted_locator(
    _runtime: &tokio::runtime::Runtime,
    _zid: Option<Vec<u8>>,
    _budget_ms: u64,
) -> Result<String, ExitCode> {
    eprintln!(
        "wz-ap-demo: --scout requires the `scouting-active` feature \
         (build: cargo build -p wz-ap-demo --features scouting-active)"
    );
    Err(ExitCode::from(2))
}

/// R311qa — drive the `--router` multi-peer mode: init logging, build the
/// runtime, and run the accept-and-hold loop ([`runner::run_router`]) to the
/// graceful-shutdown signal. Separate from the single-session `run_demo` entry
/// because a router has no per-face application behaviour — it only holds peers.
#[cfg(feature = "routing-router")]
fn run_router_mode(
    addr: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    quic_cert: Option<String>,
    quic_key: Option<String>,
) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_router(
        &addr, &tls_cert, &tls_key, &quic_cert, &quic_key,
    )) {
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
    /// R311y452 — the `--downsample` rate as zenoh's maximum frequency in Hertz;
    /// `None` keeps the 2 Hz (500 ms) the flag alone has always meant.
    pub(crate) downsample_freq: Option<String>,
    /// R311y453 — narrow the downsampling rule to one link PROTOCOL, or `None`
    /// to leave that subject axis unnarrowed (zenoh's `link_protocols: None`).
    pub(crate) downsample_link_protocol: Option<String>,
    /// R311y453 — narrow the downsampling rule to one NIC NAME, or `None` to
    /// leave that axis unnarrowed (zenoh's `interfaces: None`).
    pub(crate) downsample_interface: Option<String>,
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
fn run_storage_host_mode(listen: String, storage_dir: Option<String>) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();
    let runtime = match build_demo_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(crate::runner::run_storage_host(&listen, storage_dir)) {
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
    zid_override: Option<Vec<u8>>,
    cert_paths: crate::runner::AcceptCertPaths,
    // R311y454 — `--multicast-locator`, the router's data-plane group as a locator
    // so its `#iface=` tail reaches the multicast honor.
    multicast_locator: Option<String>,
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
        zid_override,
        &cert_paths,
        multicast_locator.as_deref(),
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}
