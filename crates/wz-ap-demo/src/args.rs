// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — CLI argument parsing + spec-type bundles.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds:
//
//   * `Role` — `--listen` vs `--connect` discriminator;
//   * `PushOperation` — publisher_task dispatch shape (Put vs Del);
//   * `parse_pair` — argv lookup helper used by `main`;
//   * `demo_session_init_params` — role-conditional zenoh-pico
//     interop parameter block (per-role `whatami`, version,
//     resolutions, etc.);
//   * Four spec bundles (`DeclareEmitSpec`, `RemoteLogSpec`,
//     `ReplyConsumerSpec`, `QueryRoleSpec`) that ferry argv-derived
//     state from `main` into `run_demo` without inflating the
//     latter's argument list past clippy::too_many_arguments.

use wz::runtime_tokio::session_glue::{SessionInitParams, SigningKey, WhatAmI};

/// R121f — session role select. `--listen` lands here as
/// `Acceptor`; `--connect` lands as `Initiator`. The two roles
/// drive different role-start FSM events (`InboundStart` vs
/// `OutboundStart` + `LinkOpened`) and different TCP setup
/// paths (bind+accept vs dial), but share the rest of the
/// session-FSM + outbound-publisher + inbound-subscriber wiring.
///
/// R311pw — `--reconnect` (application LIFECYCLE mode, distinct from the
/// compiled `session-reconnect` capability) rides on the `Initiator` variant
/// ONLY: zenoh-pico's `Z_FEATURE_AUTO_RECONNECT` is the CLIENT re-open path
/// (`_z_client_reopen_task_fn`), and an acceptor has no reopen-task model
/// (R311nv). Carrying the flag on the Initiator arm makes "an acceptor
/// reconnects" unrepresentable rather than a runtime guard. `reconnect = true`
/// runs the long-lived supervised lifecycle (re-dial + declaration replay on
/// link loss); `false` keeps the default round-trip-then-exit harness.
pub(crate) enum Role {
    Acceptor {
        listen: String,
        /// R311y375 — `--tls-cert <path>` / `--tls-key <path>`: the cert chain +
        /// private key PEM a `tls/...` --listen PRESENTS to a dialing peer (the
        /// accept mirror of the Initiator's `--tls-ca`, which the dialer verifies
        /// against). Feature-uniform (always parsed); `None` without the flags OR
        /// when built without the `tls` feature, in which case a `tls/...` listen
        /// surfaces the runtime's typed `Unsupported`. BOTH are required together
        /// for TLS. Read by `establish_link`'s Acceptor arm (`build_accept_config`,
        /// runner.rs); the reconnect/router paths are out of demo scope.
        tls_cert: Option<String>,
        tls_key: Option<String>,
        /// R311y401 — `--quic-cert <path>` / `--quic-key <path>`: the cert chain +
        /// private key PEM a `quic/...` --listen PRESENTS to a dialing peer (the
        /// QUIC twin of `tls_cert` / `tls_key`; SEPARATE flags because the demo builds
        /// QUIC's own server config (TLS-1.3 + ALPN hq-29) from them — the cert PEM
        /// itself is interchangeable, only the built ServerConfig differs).
        /// Feature-uniform (always parsed); `None` without the flags OR when built
        /// without the `quic` feature, in which case a `quic/...` listen surfaces the
        /// runtime's typed `Unsupported`. BOTH are required together for QUIC. Read
        /// by `establish_link`'s Acceptor arm (`build_accept_config`, runner.rs).
        quic_cert: Option<String>,
        quic_key: Option<String>,
    },
    /// R311y365 — `tls_ca` is the `--tls-ca <path>` root-CA PEM a `tls/...`
    /// --connect verifies zenoh's/the peer's server cert against (server name
    /// `localhost`). ALWAYS present (feature-uniform match sites); `None` when
    /// no `--tls-ca` was given OR the demo was built without the `tls` feature,
    /// so a `tls/...` dial then surfaces the runtime's typed `Unsupported`. Only
    /// the one-shot `establish_link` reads it (the reconnect path is out of demo
    /// scope, runner.rs).
    Initiator {
        connect: String,
        reconnect: bool,
        tls_ca: Option<String>,
        /// R311y366 — the `--quic-ca <path>` root-CA PEM a `quic/...` --connect
        /// verifies the peer's server cert against (server name `localhost`), the
        /// QUIC sibling of `tls_ca`. Feature-uniform (always present on the match
        /// sites); `None` when no `--quic-ca` was given OR the demo was built
        /// without the `quic` feature, so a `quic/...` dial then surfaces the
        /// runtime's typed `Unsupported`. Read only by the one-shot
        /// `establish_link` (runner.rs).
        quic_ca: Option<String>,
        /// R311y369 — the `--namespace <prefix>` keyexpr namespace an Initiator
        /// installs on its opened session (`set_namespace`), so outbound keyexprs
        /// are prefixed `<prefix>/<key>` on the wire. Feature-uniform (always
        /// parsed); `None` without `--namespace` OR when built without the
        /// `namespace` feature, in which case the flag is inert. Applied once, on
        /// the one-shot open (runner.rs; reconnect is out of demo scope).
        namespace: Option<String>,
        /// R311y372 — `--lowlatency` offers the Z_EXT_LOWLATENCY transport ext on
        /// the InitSyn, so a peer that also offers it negotiates the lean
        /// transport that drops the Frame(sn) wrapper on the data path.
        /// Feature-uniform (always parsed + banner-logged); `false` without
        /// `--lowlatency` OR when the demo was built without the
        /// `transport-lowlatency` feature, in which case the flag is inert.
        /// R311y435 moved WHERE that inertness is decided: the flag now feeds
        /// `runner::initiator_offer`, which drops an unbuildable capability from
        /// the `SessionOffer` before the library sees it, because the library
        /// seam (`SessionLinkActions::apply_offer`) deliberately ERRORS on one
        /// instead of downgrading. Initiator-only and one-shot-only, like
        /// `namespace`: the reconnect path is out of demo scope, and an
        /// acceptor's lowlatency offer is not exercised by the demo.
        lowlatency: bool,
        /// R311y433 — `--compression` offers the Z_EXT_COMPRESSION unit ext (id
        /// 0x6) on the InitSyn, so a peer that also offers it negotiates the
        /// per-batch lz4 wrap on every post-establishment batch. Feature-uniform
        /// and inert-when-unbuilt on the same `initiator_offer` seam as
        /// `lowlatency`; initiator-only and one-shot-only.
        ///
        /// COMBINABLE with `--lowlatency` since R311y435, and the history is
        /// worth keeping because the guard outlived its reason by a round.
        /// R311y433 rejected the pair as having no coherent cross-impl wire
        /// meaning; R311y434 showed that was true only of a wz defect (wz wrapped
        /// compression OUTSIDE the lean encode, while zenoh's lean transport
        /// serializes straight to the link behind a 4-byte length prefix and
        /// never touches `WBatch` / `BatchHeader` —
        /// `zenoh-transport-1.5.0` `unicast/lowlatency/link.rs:33-73`), fixed it,
        /// and kept the rejection for a narrower LOCAL reason: `session_open` had
        /// one entrypoint per MODE and none staged both offers. R311y435's
        /// `initiate_and_open_session_with_offer` takes the SET, so that reason
        /// is gone and the guard went with it. On a lean link the negotiated wrap
        /// is INERT in wz exactly as in zenoh.
        compression: bool,
    },
}

/// R219 — publisher-task operation kind. `Put` carries the
/// application payload (`--value <text>`); `Delete` is payload-
/// less (zenoh-pico's `z_delete` wire form: `MsgDel` body, no
/// `payload_len`/`payload` fields). The same publisher_task drives
/// both shapes — Established-gating, optional `DECLARE` preamble,
/// and the BURST_COUNT emission loop are invariant; only the
/// inner action call (`send_push_literal`/`_aliased` vs
/// `send_push_del_literal`/`_aliased`) differs at the dispatch
/// site.
#[derive(Clone, Debug)]
pub(crate) enum PushOperation {
    Put { value: String },
    Delete,
}

pub(crate) fn parse_pair(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

// R121d interop-tuned session params. Values aligned to
// zenoh-pico 1.5.0 defaults so the AP demo can complete a real
// session handshake against `z_put -m client`:
//
//   - `version = 0x09` matches `Z_PROTO_VERSION` in
//     zenoh-pico/include/zenoh-pico/config.h.in:190. The earlier
//     0x05 value (carried from the R121b MVP) was tolerated by
//     unicast but is one revision behind; matching the upstream
//     constant is the textbook interop default.
//   - `seq_num_res = 2` / `req_id_res = 2` match
//     `Z_SN_RESOLUTION` / `Z_REQ_RESOLUTION` (both 0x02) in the
//     same config header. The earlier `0` value resolved to an
//     8-bit SN window (`_z_sn_max(0) = 127`,
//     zenoh-pico/src/transport/utils.c:24-29), which would have
//     wrapped sequence numbers within a few frames.
//   - `batch_size = 65535` lets zenoh-pico cap to its own
//     `Z_BATCH_UNICAST_SIZE` (2048 in the bundled CLI build per
//     target/zenoh-pico-build/CMakeCache.txt). The earlier `0`
//     value crashed zenoh-pico inside `__unsafe_z_prepare_wbuf`
//     because the negotiation in
//     zenoh-pico/src/transport/unicast/transport.c:135-136
//     takes `min(own, peer)` and a zero-sized wbuf segfaults on
//     the first `_z_wbuf_put` (this was the R121d immediate
//     crash root cause).
//
// R121f — `whatami` is now role-conditional. zenoh-pico's
// production-tested handshake pattern is `Client → Peer/Router`
// (e.g. `z_put -m client` → wz-ap-demo --listen), AND `Peer →
// Peer-with-listen-locator` is fragile in zenoh-pico 1.5.0
// without prior multicast scouting (peer-peer over unicast TCP
// only is not the well-trodden path upstream). The R121f
// initiator path therefore announces `Client` (wire whatami =
// `(0x04 >> 1) & 0x03 = 0x02`) so a zenoh-pico
// `-m peer -l <locator>` listener accepts it via the same
// well-tested code path that R121c/d exercised in reverse
// (`z_put -m client` → wz acceptor).
//
// The acceptor side keeps `whatami = Peer (0x02)` from R121b/c/d
// — the existing R121c/e tests rely on this. Splitting the
// constant on role honours both directions.
//
// `lease = 10s`, `zid = 4-byte demo constant` carry from R121b
// unchanged. Production AP deployment will source these from
// deploy.yaml once the topology-schema migration (R123b-pre
// carry) lands.
/// The session-init `whatami`-determining node kind. Distinct from [`Role`] (the
/// single-session `--listen`/`--connect` discriminator) because R311qa's `--router`
/// is a THIRD node kind that is not an Acceptor: it picks the Peer `whatami` like
/// an acceptor but is modelled as its own kind rather than borrowing
/// `Role::Acceptor` (whose `listen` payload `demo_session_init_params` never
/// reads). [`Role::node_kind`] maps the single-session roles onto this.
pub(crate) enum NodeKind {
    Acceptor,
    Initiator,
    /// Only meaningful when the multi-peer router mode is compiled in.
    #[cfg(feature = "routing-router")]
    Router,
    /// Only meaningful when the peer-mesh mode is compiled in (R311qg). A peer
    /// both dials and accepts; like the router it announces the Peer `whatami`
    /// for now (a distinct WhatAmI refinement is a later atom).
    #[cfg(feature = "routing-peer")]
    Peer,
    /// P4 §5.21 ACTIVATION — the router-hat node (`--router-hat`): the ONE demo
    /// kind that announces a TRUE wire [`WhatAmI::Router`], driving the dual-mesh
    /// `RouterForwarder`. Distinct from [`NodeKind::Router`] (the star
    /// concentrator, which keeps the Peer stand-in wire value so the R121c/e
    /// accept tests and `run_router` are unchanged): the router-hat node needs
    /// the real Router role so connecting peers classify it into their linkstate
    /// graph as a router and this node partitions its two meshes by peer role.
    #[cfg(feature = "router-hat-router")]
    RouterHat,
    /// R311y277 (§5.23 `adminspace-config-hotreload` ACTIVATION) — the
    /// storage-hosting node (`--storage-host <listen>`): a bare-Session admin host
    /// that live-spawns storages from a stock zenoh-pico client's config-writes and
    /// reflects `storage_manager` `Started` in its plugins admin leg. Announces the
    /// Peer `whatami` (its admin key is `@/<zid>/peer/...`); distinct from the other
    /// kinds because it hosts a per-client Session with a `RuntimeStorageManager`
    /// rather than a forwarder (the y239 forward's reserved run-mode).
    #[cfg(feature = "adminspace-config-hotreload")]
    StorageHost,
}

impl Role {
    pub(crate) fn node_kind(&self) -> NodeKind {
        match self {
            Role::Acceptor { .. } => NodeKind::Acceptor,
            Role::Initiator { .. } => NodeKind::Initiator,
        }
    }
}

/// The zenoh protocol version byte this demo emits — `Z_PROTO_VERSION`
/// (zenoh-pico `include/zenoh-pico/config.h.in:190`), the value the interop
/// rationale above pins the session handshake to.
///
/// R311y428 — named rather than repeated: `--scout` emits it a SECOND time, in
/// the Scout frame's body byte 0 (`ScoutParams::version`), and a Scout that
/// announced a different version than the InitSyn that follows would be a wire
/// inconsistency with no single place to correct it.
pub(crate) const DEMO_PROTO_VERSION: u8 = 0x09;

/// The demo's default zenoh id, overridable with `--zid <hex>`.
///
/// R311y428 — named for the same reason as [`DEMO_PROTO_VERSION`]: `--scout`
/// puts it on the wire a second time (the Scout frame's `I`-flagged id, which
/// is how a responder identifies the scouter), and the Scout should announce
/// the identity the session that follows will open with.
pub(crate) const DEMO_ZID: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

/// `--scout-timeout-ms` default: the TOTAL active-scouting budget in ms, spent
/// across repeated Scout cycles until a peer's Hello arrives.
///
/// Feature-uniform (NOT cfg'd on `scouting-active`), for the reason
/// [`LivelinessGetSpec::after_ms`] states for its own knob: the argv surface
/// must parse identically in the OFF build, where `--scout` is rejected with a
/// feature message rather than a parse error.
pub(crate) const DEFAULT_SCOUT_BUDGET_MS: u64 = 10_000;

pub(crate) fn demo_session_init_params(kind: NodeKind) -> SessionInitParams {
    let whatami = match kind {
        NodeKind::Acceptor => WhatAmI::Peer, // R121b/c/d/e baseline
        // The router accepts via the same well-tested Client->Peer direction as
        // the acceptor (a true WhatAmI::Router wire value is a later refinement,
        // R311qa carry), so it also announces Peer.
        #[cfg(feature = "routing-router")]
        NodeKind::Router => WhatAmI::Peer,
        // A hold-only mesh peer announces Peer too (whatami refinement later).
        #[cfg(feature = "routing-peer")]
        NodeKind::Peer => WhatAmI::Peer,
        // P4 §5.21 ACTIVATION — the router-hat node announces the TRUE Router
        // wire value (0b00), so a connecting peer's linkstate graph tags it as a
        // router and this node's RouterForwarder partitions faces by role. This
        // is the first wz run-mode to present WhatAmI::Router on the wire.
        #[cfg(feature = "router-hat-router")]
        NodeKind::RouterHat => WhatAmI::Router,
        // R311y277 — the storage host announces Peer, so its admin key is
        // `@/<zid>/peer/...` (the surface a pico z_get / z_put addresses).
        #[cfg(feature = "adminspace-config-hotreload")]
        NodeKind::StorageHost => WhatAmI::Peer,
        NodeKind::Initiator => WhatAmI::Client, // R121f initiator path
    };
    SessionInitParams {
        version: DEMO_PROTO_VERSION,
        whatami,
        zid: DEMO_ZID.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        // Demo signing key — 32 bytes of 0xAB. Production deployment
        // MUST supply real per-process entropy via
        // `SigningKey::new_random()` once deploy.yaml carries the
        // cookie_signing_key source.
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte demo key satisfies >= 32 invariant"),
    }
}

/// R311y345 — the publisher's `--publish` bundle. Was a bare
/// `(String, PushOperation, Option<u64>)` tuple threaded through `run_demo` and
/// `spawn_tasks`; `--publish-after-ms` would have made it a second consecutive
/// `Option<u64>`, distinguishable only by position at every call site. Named
/// per the sibling idiom here ([`DeclareEmitSpec`], [`QueryRoleSpec`],
/// [`RemoteLogSpec`], [`ReplyConsumerSpec`]) instead.
pub(crate) struct PublisherSpec {
    /// `--publish <keyexpr>` — the literal the burst emits on.
    pub(crate) keyexpr: String,
    /// `--value <text>` (Put) or `--delete` (Del).
    pub(crate) operation: PushOperation,
    /// `--declare-id <id>` — when set, a DeclKexpr preamble maps `id -> keyexpr`
    /// and the burst emits aliased Pushes carrying only the id.
    pub(crate) declare_id: Option<u64>,
    /// `--publish-after-ms <ms>` — hold the burst this long AFTER Established,
    /// leaving the line idle. The ordering a foreign peer needs to witness
    /// `transport-keepalive`: past the adopted lease, a peer expires a silent
    /// line, so a Push that still lands proves the KeepAlive held it open.
    pub(crate) publish_after_ms: Option<u64>,
    /// `--batch` — wrap the burst in a TX batching window (`zp_start_batching` /
    /// `zp_batch_stop` parity), so every Push rides ONE frame as a message chain
    /// instead of one frame each. The shape a foreign peer needs to witness
    /// `transport-batching`: surfacing every Push proves it walked the chain to
    /// the end.
    pub(crate) batch: bool,
    /// `--matching-log` — declare a `Publisher` on `keyexpr` plus a
    /// `Publisher::declare_matching_listener`, and log every matching-status
    /// TRANSITION it reports.
    ///
    /// The ordering a FOREIGN peer needs to witness `session-matching`: the
    /// transitions are caused entirely by the remote's own
    /// `Declare(DeclSubscriber)` / `Declare(UndeclSubscriber)`, so a pico
    /// `z_sub` arriving and leaving drives both edges without wz touching the
    /// wire. Registration itself never fires (pico transition-only), which is
    /// why the listener is installed PRE-DRIVE, before any inbound Declare can
    /// be dispatched.
    ///
    /// Binds to the atom's OWN gated code: `Publisher::declare_matching_listener`
    /// is `#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]`
    /// and rejects typed with the feature off. Its sibling
    /// `Publisher::get_matching_status` is gated on `declare-subscriber` ALONE, so
    /// polling would NOT bind the claim to `session-matching`.
    pub(crate) matching_log: bool,
}

/// R121k-5 / R311oy — bundle of declare-emit keyexprs the demo emits once the
/// session reaches Established. Holds `--declare-token` (the high-level
/// [`wz::runtime_tokio::session::Session::declare_token`] RAII liveliness
/// token) and `--liveliness-subscribe`. The former `--declare-subscriber` /
/// `--declare-queryable` raw-emit fields were retired in R311oy: `--key` /
/// `--queryable` now declare a ROUTED subscriber / queryable through the real
/// `Session::declare_{subscriber, queryable}` path (R311ou / R311ow), handled
/// in `install_session_handles` rather than the raw `send_declare_*` emit here.
pub(crate) struct DeclareEmitSpec {
    pub(crate) token_keyexpr: Option<String>,
    /// R280 — optional `--liveliness-subscribe <keyexpr>` payload.
    /// When `Some`, the demo calls
    /// [`wz::runtime_tokio::session::Session::declare_liveliness_subscriber`]
    /// once before the drive_session loop starts; the returned RAII
    /// handle lives at `run_demo` scope so `Drop` emits
    /// `Interest(Final)` when the demo terminates. Separate from
    /// `token_keyexpr` (which declares a
    /// [`wz::runtime_tokio::session::LivelinessToken`] on the
    /// peer-facing side) because a single demo instance can act as
    /// token publisher + token subscriber simultaneously on a wz↔wz
    /// round-trip.
    pub(crate) liveliness_subscriber_keyexpr: Option<String>,
    /// R311ph — `--liveliness-subscribe-history`: declare the liveliness
    /// subscriber with `history = true` so the peer/router replays the CURRENT
    /// alive tokens on subscription (not just future declares). This makes an
    /// observer order-independent of when the token was declared — the fix for
    /// the leg-7 interop ordering race (a late-arriving `history = false`
    /// subscriber would miss an already-alive token).
    pub(crate) liveliness_subscriber_history: bool,
}

/// R121k-5 — bool flag bundle for the three Remote* registry log
/// callbacks. Each `true` installs a callback that prints a
/// stderr line on the matching inbound Declare arm so an integration
/// test fixture can grep for the expected line shape.
pub(crate) struct RemoteLogSpec {
    pub(crate) on_remote_subscriber: bool,
    pub(crate) on_remote_queryable: bool,
    pub(crate) on_remote_liveliness: bool,
}

/// R121j-6-e2e — bool flag bundle for the initiator-side
/// ReplyRegistry log callbacks. Both flags require --query (the rid
/// the registry binds to is the rid of the outbound Query this demo
/// emits); the validation in `main` rejects mis-wired argv before
/// this struct is constructed. Each `true` installs a callback that
/// prints a stderr line on the matching inbound record so an
/// integration test fixture can grep for the expected line shape.
pub(crate) struct ReplyConsumerSpec {
    pub(crate) on_query_reply: bool,
    pub(crate) on_query_final: bool,
    /// R263 — pending-entry deadline (ms) propagated to the
    /// observer.replies.register call below. Value 0 means "no
    /// timeout" (deadline_ms = None at register; pre-R263 behaviour
    /// preserved). Value > 0 means "compute deadline_ms =
    /// session_clock.now_monotonic_ms() + query_timeout_ms" so the
    /// R264 sweep_task surfaces on_final within that wall-clock
    /// budget when no Final arrives.
    pub(crate) query_timeout_ms: u32,
    /// R270 — sweep_task tick period (ms). Lower values tighten
    /// the bound on `on_final`'s post-deadline wall-time at the cost
    /// of more wake-ups. Must be > 0 (the main-side parser rejects
    /// 0 explicitly so this struct field can stay an unwrapped u32).
    /// The pre-R270 hardcoded value (100 ms) is the default the
    /// parser supplies when `--sweep-cadence-ms` is absent, so
    /// every existing wz-ap-demo invocation retains identical
    /// behaviour.
    pub(crate) sweep_cadence_ms: u32,
}

/// R121j-6-e2e — bundle of the Q/R role config. Carries the
/// queryable side (--queryable + --reply pair) and the z_get side
/// (--query) so a single demo can act as queryable, z_get, both, or
/// neither. Kept distinct from the publisher / subscriber / declare
/// configs because the wire-side dispatch tables (QueryableRegistry,
/// ReplyRegistry) live in a different module than the pubsub one.
/// R121j-5c-e2e-demo carried (--queryable, --reply, --query) on
/// separate run_demo parameters; R121j-6-e2e consolidates them so
/// run_demo's clippy::too_many_arguments threshold stays satisfied
/// with the new reply_log_spec.
pub(crate) struct QueryRoleSpec {
    pub(crate) queryable: Option<(String, String)>,
    pub(crate) query: Option<String>,
    /// liveliness-get — optional `--liveliness-get <keyexpr>` bundle.
    /// When `Some`, the demo spawns an Established-gated
    /// [`crate::tasks::liveliness_get_task`] that issues one
    /// [`wz::runtime_tokio::session::Session::liveliness_get`] snapshot
    /// query and logs each `LIVELINESS GET REPLY` + the terminating
    /// `LIVELINESS GET FINAL`. Grouped with the query role (both are
    /// reply-consuming "get" surfaces) though the wire is the
    /// declaration plane (a CURRENT liveliness Interest), not the
    /// Request/Query plane.
    pub(crate) liveliness_get: Option<LivelinessGetSpec>,
}

/// R311y353 — the `--liveliness-get` bundle. Was a bare `String` (the keyexpr)
/// threaded through `run_demo` and `spawn_background_tasks`; `--liveliness-get-
/// after-ms` makes it a two-field payload, so it is named per the sibling idiom
/// here ([`PublisherSpec`], [`DeclareEmitSpec`], [`QueryRoleSpec`],
/// [`RemoteLogSpec`], [`ReplyConsumerSpec`]) rather than grown into a tuple.
/// The atom's own surface has a further knob in reach for a later round
/// (`LivelinessGetOptions::timeout_ms`, which this task currently leaves at
/// `default()`), and a named struct is where that lands without touching a call
/// site.
pub(crate) struct LivelinessGetSpec {
    /// `--liveliness-get <keyexpr>` — the filter the CURRENT liveliness
    /// Interest carries.
    pub(crate) keyexpr: String,
    /// `--liveliness-get-after-ms <ms>` — hold the get this long AFTER
    /// Established.
    ///
    /// WHAT IT IS FOR, stated narrowly because R311y353 measured the wider claim
    /// and it was FALSE. The carried blocker for `liveliness-get` said the atom
    /// needed "an ordering the demo can't make" — wz asking before a foreign
    /// token holder had declared. That is NOT why the atom had no witness, and
    /// this knob is not what fixed it: a fixture can simply start the token
    /// holder first and gate on its declaration banner, and
    /// `wz_liveliness_get_zenohd_pico_interop.rs` passes with this hold set to
    /// nothing at all. The real blocker was zenoh-pico declining to answer any
    /// Interest on a unicast transport (`interest.c:533-535`), which no ordering
    /// could have touched.
    ///
    /// What survives is narrower and is a TIMING MARGIN, not a precondition: the
    /// get is ONE-SHOT and has no retry, so unlike the burst-driven tests here
    /// (whose 5x200ms burst is what "covers the window for the subscription to
    /// reach zenohd") it gets exactly one chance. The holder's banner proves it
    /// SENT its token, not that the router REGISTERED it. This hold covers that
    /// propagation window. It is a margin against a race not yet observed, kept
    /// because a one-shot proof has nothing else to absorb one — not evidence of
    /// a race that was.
    ///
    /// Deliberately NOT cfg-gated on `liveliness-get`, for the same reason
    /// `--publish-after-ms` is not gated on `transport-keepalive` and
    /// `--matching-log` is not gated on `session-matching`: it is a pure
    /// ordering delay, inert when the feature is off, and it must stay reachable
    /// in the OFF build. `Session::liveliness_get` is signature-stable and
    /// returns `LivelinessGetError::FeatureDisabled` when elided, so the OFF arm
    /// walks the identical path and logs no reply.
    pub(crate) after_ms: Option<u64>,
}
