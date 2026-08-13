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
        /// R311y505 — `--shm` on the ACCEPT side, and it is the arm that matters.
        ///
        /// zenoh sends its `Shm` challenge on the InitSyn unconditionally when the
        /// feature is built (`establishment/open.rs:152`), but on the InitAck only
        /// in REPLY to one it understood (`ext/shm.rs:455` returns `None` for an
        /// absent input). So a wz that only DIALS never receives a real zenoh
        /// `Shm` ext, and the question that matters — does wz's
        /// `peer_offered_shm` mistake zenoh's ZBuf@0x2 for its own UNIT@0x2 —
        /// stays untested. Only a wz ACCEPTOR that a zenohd dials gets that ext
        /// on the wire, and only one that OFFERS starts from `is_shm = true`, so
        /// a false positive is visible as `true` instead of `false`.
        shm: bool,
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
        /// R311y505 — `--shm` offers the SHM establishment capability on the
        /// InitSyn: a UNIT ext at id 0x2 (`extshm::SHM_ESTABLISHMENT_EXT_ID`),
        /// ANDed against whatever the peer reflects.
        ///
        /// It exists to put that offer in front of a FOREIGN peer, which nothing
        /// could do before: the library has carried
        /// `SessionOffer::with_shm` and `connect_and_open_session_with_shm` since
        /// R3b, but no spawnable binary ever set them, so the one extension wz
        /// places in zenoh's establishment ext space had never been on a wire a
        /// real zenohd read.
        ///
        /// Same `initiator_offer` seam as `lowlatency` / `compression`:
        /// feature-uniform, inert when `session-extshm` is unbuilt,
        /// initiator-only and one-shot-only. Combinable with both.
        shm: bool,
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

/// R311y497 — the `--storage-volume <path.so>` + `--storage-volume-config <text>`
/// pair, as ONE value.
///
/// A struct rather than two `Option<String>` parameters threaded side by side into
/// [`crate::runner::run_storage_host`]: two adjacent same-typed optionals are the
/// shape a caller silently transposes, and a transposed pair here would `dlopen`
/// the operator's config text and hand the volume its own path as a directory.
/// The config is `Option` INSIDE the struct because a volume may legitimately need
/// none, while a path is what makes the whole thing exist.
///
/// Deliberately singular where `--plugin` is plural: a host loads a SET of
/// plugins, but a dynamic volume is configured, and pairing an i-th config to an
/// i-th path by argv order is an operator interface that misfires silently. One
/// loaded volume is the honest MVP bound; N is a mechanical follow-up that needs a
/// pairing syntax, not a second `Vec`.
/// R311y503 — `--storage-gc-period-ms <ms>` / `--storage-gc-lifespan-ms <ms>`:
/// the per-storage garbage-collection policy every storage this host spawns is
/// created with.
///
/// In zenoh this is per-storage CONFIG FILE state
/// (`garbage_collection: { period_s, lifespan_s }`, `backend-traits/config.rs`),
/// read by the host when it spawns the storage — NOT something a remote client
/// writes. The demo has no config file, so its flags are that surface, and they
/// are deliberately host-side for the same reason: the `storage-add` wire intent
/// carries a name and a keyexpr, and letting a remote peer choose how long this
/// node retains metadata would be a policy decision on the wrong side of the
/// admin gate.
///
/// Absent flags mean zenoh's defaults (30 s period, 86400 s lifespan), which is
/// what [`GarbageCollectionConfig::default`] already supplies — so the struct
/// carries only the OVERRIDES and an un-flagged host is byte-identical to the
/// pre-R311y503 one.
#[cfg(feature = "adminspace-config-hotreload")]
#[derive(Default, Clone, Copy)]
pub(crate) struct StorageGcArgs {
    /// Sweep interval override, in milliseconds.
    pub(crate) period_ms: Option<u64>,
    /// Metadata-age cutoff override, in milliseconds. `0` collects every entry
    /// on the next sweep, which is how a test makes a 24-hour default observable
    /// without waiting a day.
    pub(crate) lifespan_ms: Option<u64>,
}

#[cfg(feature = "adminspace-config-hotreload")]
pub(crate) struct DynamicVolumeArgs {
    /// The `.so` to `dlopen`. The volume's registry id is NOT taken from here —
    /// it is what the `.so` itself declares, so two different libraries cannot be
    /// registered under one operator-chosen name.
    pub(crate) path: String,
    /// The volume's own configuration string, verbatim. Its meaning belongs to the
    /// volume; the bundled example volume reads it as a root directory.
    pub(crate) config: Option<String>,
}

/// Every `<flag> <value>` pair in `args`, in argv order.
///
/// R311y492 — `--plugin` is repeatable because a plugin HOST loads a set, not a
/// singleton, and `parse_pair` silently keeps only the first. A flag that
/// accepts one value while its concept is plural is the shape that makes an
/// operator's second `--plugin` disappear without a word.
#[cfg(feature = "adminspace-config-hotreload")]
pub(crate) fn parse_repeated(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
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

/// R311y506 (session-extqos) — parse `--qos-band START-END` and `--qos-rel 0|1`
/// into the `QoSLink` metadata this node declares.
///
/// The two spellings are deliberately zenoh's own endpoint-metadata VALUES
/// (`prio=1-4` -> `--qos-band 1-4`, `rel=1` -> `--qos-rel 1`), so an operator can
/// carry a band between a zenohd endpoint string and this demo without
/// re-deriving it. `PriorityRange::from_str` accepts `start-end` over the wire
/// bytes 0..=7 (`core/mod.rs:377`) and `Reliability::from_str` accepts the
/// integer discriminant (`:531`, BestEffort=0 / Reliable=1) — both mirrored here.
///
/// A malformed value ABORTS rather than degrading to "no band". A band silently
/// dropped would leave the node negotiating the presence-only UNIT ext, and the
/// resulting session would look perfectly healthy while proving nothing about the
/// band the operator asked for — the failure mode a proof harness cannot see.
#[cfg(feature = "session-extqos")]
pub(crate) fn parse_qos_link(args: &[String]) -> Option<wz::runtime_tokio::extqos::QosLinkState> {
    use wz::runtime_tokio::config::LinkPriorityRange;
    use wz::runtime_tokio::extqos::QosLinkState;
    use wz::runtime_tokio::qos::Priority;

    fn priority(s: &str, flag: &str) -> Priority {
        let byte: u8 = s.parse().unwrap_or_else(|e| {
            eprintln!("wz-ap-demo: {flag}: `{s}` is not a priority byte ({e}); expected 0..=7");
            std::process::exit(2);
        });
        if byte as usize >= Priority::NUM {
            eprintln!("wz-ap-demo: {flag}: priority {byte} is out of range; expected 0..=7");
            std::process::exit(2);
        }
        Priority::from_wire(byte)
    }

    let priorities = parse_pair(args, "--qos-band").map(|spec| {
        let (start, end) = spec.split_once('-').unwrap_or_else(|| {
            eprintln!(
                "wz-ap-demo: --qos-band: `{spec}` is not a range; expected START-END (e.g. 1-4)"
            );
            std::process::exit(2);
        });
        LinkPriorityRange::new(priority(start, "--qos-band"), priority(end, "--qos-band"))
    });
    let reliability = parse_pair(args, "--qos-rel").map(|spec| match spec.trim() {
        "0" => wz::runtime_tokio::Reliability::BestEffort,
        "1" => wz::runtime_tokio::Reliability::Reliable,
        other => {
            eprintln!(
                "wz-ap-demo: --qos-rel: `{other}` is not a reliability; expected 0 \
                     (best-effort) or 1 (reliable)"
            );
            std::process::exit(2);
        }
    });
    if priorities.is_none() && reliability.is_none() {
        return None;
    }
    Some(QosLinkState {
        priorities,
        reliability,
    })
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
    /// R311y775 — `--querier-matching-log <keyexpr>`: declare a
    /// [`wz::runtime_tokio::session::Querier`] on `keyexpr` plus a
    /// `Querier::declare_matching_listener`, and log every matching-status
    /// TRANSITION it reports.
    ///
    /// The QUERYABLE-plane twin of `--matching-log`, and a SEPARATE knob rather
    /// than a mode of it: the two watch different registries
    /// (`RemoteSubscriberRegistry` vs `RemoteQueryableRegistry`), are gated on
    /// different features (`declare-subscriber` vs `declare-queryable`), and are
    /// driven by different foreign processes (a pico `z_sub` vs a pico
    /// `z_queryable`). Folding them into one flag would make a run that proves
    /// one look like a run that proves both.
    ///
    /// Valued rather than bare because it does NOT ride the publisher: a querier
    /// carries its own keyexpr, so `--publish` is not a precondition here the way
    /// it is for `--matching-log`.
    ///
    /// Deliberately NOT cfg-gated, for the same reason as `--matching-log`: the
    /// `session-matching`-OFF build must reach the same path and surface the
    /// typed reject, because that arm is the anti-vacuity twin.
    pub(crate) querier_matching_log_keyexpr: Option<String>,
    /// R311ph — `--liveliness-subscribe-history`: declare the liveliness
    /// subscriber with `history = true` so the peer/router replays the CURRENT
    /// alive tokens on subscription (not just future declares). This makes an
    /// observer order-independent of when the token was declared — the fix for
    /// the leg-7 interop ordering race (a late-arriving `history = false`
    /// subscriber would miss an already-alive token).
    pub(crate) liveliness_subscriber_history: bool,
    /// R311y442 — `--advanced-subscribe <keyexpr>`: declare an
    /// [`wz::runtime_tokio::AdvancedSubscriber`] with a STARTUP HISTORY GET, so a
    /// subscriber that joins after a publisher has already published recovers the
    /// cached samples from that publisher's `@adv` cache. Feature-uniform (always
    /// parsed) on the same terms as `namespace` / `lowlatency`: `None` without the
    /// flag OR when built without the `advanced` feature, in which case the flag is
    /// inert and `install_session_handles` says so on stderr rather than declaring
    /// a plain subscriber that would silently look like a working history.
    pub(crate) advanced_subscriber_keyexpr: Option<String>,
    /// R311y442 — `--history-max <N>`: the `_max=N` cap on the startup history GET
    /// ([`HistoryConfig::max_samples`]). `None` leaves the GET uncapped, which is
    /// the zenoh default. Only read when `advanced_subscriber_keyexpr` is `Some`.
    pub(crate) advanced_history_max: Option<usize>,
    /// R311y442 — `--history-max-age <secs>`: the `_time=[now(-secs)..]` age bound
    /// on the startup history GET ([`HistoryConfig::max_age`]).
    ///
    /// It exists to make the LIST SEPARATOR observable from outside, which no
    /// other knob can do. `_anyke` is provable with a single-parameter selector,
    /// but `;`-vs-`&` only shows up once a selector carries TWO parameters: under
    /// the `&` spelling a real zenoh cache reads `_max=2&_time=[..]` as one
    /// parameter keyed `_max` whose value fails to parse, drops the cap, and
    /// replies with its WHOLE ring. So `--history-max 2 --history-max-age N`
    /// against a 5-sample foreign cache answers 2 when the dialect is right and 5
    /// when it is wrong — a foreign witness for the separator, not just a unit test.
    pub(crate) advanced_history_max_age: Option<f64>,
    /// R311y443 — `--advanced-recovery`: arm SAMPLE-DRIVEN retransmission on the
    /// advanced subscriber ([`RecoveryConfig::sample_driven`]). Off by default,
    /// which is zenoh's default too — `.recovery()` is opt-in there as well.
    ///
    /// The flag is what makes the recovery path's RED/GREEN twin a one-argument
    /// difference. With it, a forward gap is buffered and back-filled by an
    /// `_sn=last+1..` GET; without it the same gap reports a `Miss` and delivers
    /// past the hole. Two runs of one binary over one fixture therefore separate
    /// "the sample came back because it was recovered" from "the sample was never
    /// lost" — which no single run can.
    ///
    /// Sample-driven only: neither `periodic_queries` nor `heartbeat` is armed,
    /// so a recovered sample is attributable to the gap that triggered the GET
    /// rather than to a timer or to a foreign publisher's beacon.
    pub(crate) advanced_recovery: bool,
    /// R311y444 — `--advanced-recovery-heartbeat`: additionally arm the HEARTBEAT
    /// retransmission trigger ([`RecoveryConfig::with_heartbeat`]), which declares
    /// a second subscriber on `<ke>/@adv/pub/**` and issues a recovery GET when a
    /// publisher's beacon reports samples past `last_delivered`.
    ///
    /// Requires `--advanced-recovery` (the trigger lives inside `RecoveryConfig`,
    /// so without recovery there is nothing to add it to); the parser rejects the
    /// pair rather than silently arming nothing.
    ///
    /// Kept separate from `--advanced-recovery` deliberately. The two triggers
    /// issue DIFFERENT selectors — sample-driven sends an OPEN `_sn=last+1..`
    /// while heartbeat sends a BOUNDED `_sn=last+1..hb` — and that difference is
    /// the only thing that distinguishes them on the wire when both could have
    /// fired, so a flag that armed both at once would make the distinction
    /// unobservable.
    pub(crate) advanced_recovery_heartbeat: bool,
    /// R311y447 — `--advanced-recovery-periodic <ms>`: additionally arm the
    /// PERIODIC retransmission trigger ([`RecoveryConfig::with_periodic_queries`]),
    /// a background loop that re-asks every known source `_sn=last+1..` on a
    /// cadence. `None` (default) leaves it unarmed.
    ///
    /// Requires `--advanced-recovery`, and kept separate from it for the same
    /// reason as the heartbeat twin: the three triggers must stay individually
    /// attributable.
    ///
    /// It carries a PERIOD rather than being a bare switch because the period is
    /// the observable. The periodic trigger emits the same OPEN `_sn=last+1..`
    /// selector the sample-driven one does, so selector shape cannot separate
    /// them — what separates them is that `periodic_requests`
    /// (`advanced_subscriber.rs:685-702`) asks on EVERY tick for every known
    /// source with no GET in flight, consulting nothing, while sample-driven
    /// needs a non-empty reorder buffer (`:605`). On a stream with no loss the
    /// two therefore differ in PRESENCE, not in shape — and a fixture asserting
    /// that needs to know the cadence to expect.
    ///
    /// R311y447-review — an earlier version of this doc said sample-driven fires
    /// "out of `handle_live`'s gap branch" and that `periodic_requests` mirrors
    /// zenoh's `PeriodicQuery::run`. Both were overstated: the sample-driven
    /// request is issued after the match on `!pending_samples.is_empty()`, which
    /// history buffering can also satisfy, and wz's periodic carries an in-flight
    /// gate upstream does not. See `periodic_requests`' own doc for the second.
    pub(crate) advanced_recovery_periodic_ms: Option<u64>,
    /// R311y445 — `--group-join <group>`'s bundle: join a zenoh-ext GROUP as a
    /// member and hold the session open so a foreign group peer sees this member
    /// in its view. `None` without the flag.
    ///
    /// A separate surface from the advanced-pubsub flags rather than an extension
    /// of them: the group plane is self-contained (its own bincode wire on its own
    /// keyexpr namespace, independent of `@adv`).
    pub(crate) group_join: Option<GroupJoinSpec>,
    /// R311y442 — `--advanced-publish <keyexpr>`'s bundle. The ANSWERING half of
    /// the advanced-pubsub plane: a wz [`AdvancedPublisher`] with a sample cache,
    /// which a FOREIGN advanced subscriber then drains. `None` without the flag.
    pub(crate) advanced_publish: Option<AdvancedPublishSpec>,
}

/// R311y442 — the `--advanced-publish` parameter bundle. A struct rather than
/// five more `Option` fields on [`DeclareEmitSpec`] for the reason the rest of
/// this module already settled: the task takes one spec, not a positional list.
///
/// The `advanced`-OFF build reports every field it is ignoring, one by one. That
/// is not a lint workaround: an operator who passed `--cache-max 8` to a binary
/// built without the feature needs to see that the depth was dropped too, not
/// just that the keyexpr was.
pub(crate) struct AdvancedPublishSpec {
    /// `--advanced-publish <keyexpr>` — the literal the burst publishes on, and
    /// the base of the `<keyexpr>/@adv/pub/<zid>/<eid>/_` cache KE derived from it.
    pub(crate) keyexpr: String,
    /// `--value <text>` — the burst payload, emitted as `[{idx:4}] {value}` to
    /// mirror upstream's own `z_advanced_pub` sample shape.
    pub(crate) value: String,
    /// `--advanced-publish-count <N>` — how many samples the burst emits.
    pub(crate) count: usize,
    /// `--cache-max <N>` — the publisher's cache depth (`CacheConfig::max_samples`).
    /// `None` keeps the wz default.
    pub(crate) cache_max: Option<usize>,
    /// Milliseconds between burst samples. Fixed rather than a flag: its only job
    /// is to keep the samples distinguishable in time for the `_time` filter, and
    /// a knob nothing varies is a knob that rots.
    pub(crate) interval_ms: u64,
    /// R311y444 — `--advanced-publish-heartbeat <ms>`: arm the publisher's
    /// last-sn heartbeat BEACON at this period
    /// (`MissDetectionConfig::heartbeat`). `None` (default) = no beacon, which
    /// is what makes the control twin of the beacon leg possible.
    ///
    /// This is the ANSWERING half's counterpart to `--advanced-recovery`: the
    /// beacon is what tells a subscriber that a sample it never saw exists at
    /// all. It matters most for the LAST sample of a burst, which no later live
    /// sample can reveal a gap before — so with the beacon off, a lost last
    /// sample is unrecoverable BY CONSTRUCTION rather than by timing.
    pub(crate) heartbeat_ms: Option<u64>,
    /// The publisher's source identity, stamped into every sample's `SourceInfo`
    /// and rendered into the `@adv` KE. Taken from the demo's `--zid`, so a
    /// multi-publisher fixture gets distinct `@adv` namespaces the same way it
    /// gets distinct session zids.
    pub(crate) zid: Vec<u8>,
}

/// R311y445 — the `--group-join` parameter bundle.
///
/// The `advanced`-OFF build reports every field it is ignoring, one by one, for
/// the same reason [`AdvancedPublishSpec`] does: an operator who passed a member
/// id needs to see that it was dropped too, not just that the group was.
pub(crate) struct GroupJoinSpec {
    /// `--group-join <group>` — the group name. Must be non-wild; `Group::join`
    /// rejects a wildcard and the demo surfaces that rejection rather than
    /// silently joining nothing.
    pub(crate) group: String,
    /// `--group-member-id <id>` — this member's id, which is the literal a
    /// foreign peer prints in its view listing, so a fixture greps for it.
    pub(crate) member_id: String,
    /// `--group-lease-secs <n>` — the member lease. A fixture matches it to the
    /// oracle's own `Duration::from_secs(3)` so both sides expire on one scale;
    /// wz's default (zenoh-ext's 18s) otherwise.
    pub(crate) lease_secs: Option<u64>,
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
    pub(crate) queryable: Option<QueryableSpec>,
    pub(crate) query: Option<QueryEmitSpec>,
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

/// R311y481 — the `--queryable` bundle. Was a bare `(String, String)` tuple
/// (pattern, reply_text) threaded through [`QueryRoleSpec`]; `--reply-err` makes
/// the answer a two-armed CHOICE rather than a second string, so it is named per
/// the sibling idiom here ([`PublisherSpec`], [`DeclareEmitSpec`],
/// [`LivelinessGetSpec`]) instead of growing into a triple whose arms would be
/// distinguishable only by position.
pub(crate) struct QueryableSpec {
    /// `--queryable <keyexpr>` — the pattern the routed queryable declares on.
    pub(crate) keyexpr: String,
    /// How this queryable answers a matching inbound Query.
    pub(crate) reply: QueryableReply,
}

/// R311y481 — the queryable's answer form: an OK Put-form reply (`--reply`) or
/// an ERR reply (`--reply-err`).
///
/// An enum rather than two `Option<String>` fields because the two are mutually
/// exclusive on the wire — a queryable answers a given Query with one or the
/// other, never both — and the parser rejects the pair. Making the exclusion
/// unrepresentable is cheaper than a runtime guard
/// (`feedback_unrepresentable_over_test`).
pub(crate) enum QueryableReply {
    /// `--reply <text>` — a Put-form Reply carrying `text` as the payload. The
    /// R121j-5c-e2e shape, unchanged.
    Ok(String),
    /// `--reply-err <text>` — an ERR-form Reply carrying `text` as the error
    /// payload, via [`wz_session_core::query_sink::ReplyOut::reply_err`].
    ///
    /// `reply_err` is signature-STABLE (ungated on the trait) but its emit is
    /// gated: `query.rs`'s impl calls `send_err` only under
    /// `#[cfg(feature = "query-reply-err")]` and drops the call otherwise. So an
    /// OFF build answers a matching Query with NOTHING — not with a degraded OK
    /// reply that would read like a working error path. That is what binds a
    /// foreign witness of this flag to the atom's OWN gated code
    /// (`feedback_claim_binds_to_atom_code`).
    Err(String),
}

/// R311y481 — the `--query` bundle. Was a bare `String` (the keyexpr) threaded
/// through `run_demo` and `spawn_background_tasks`; `--query-params` and
/// `--query-attachment` make it a three-field payload, so it is named per the
/// sibling idiom rather than grown into a tuple of two consecutive `Option`s.
///
/// Both new fields are feature-UNIFORM (always parsed), on the same terms as
/// `--namespace` / `--lowlatency` / `--publish-after-ms`: the argv surface must
/// parse identically in the OFF build. Their inertness is decided downstream by
/// `build_request_query_with_meta`, which threads `meta.parameters` only under
/// `#[cfg(feature = "query-selector-parameters")]` and `meta.attachment` only
/// under `#[cfg(feature = "query-attachment")]` — the atoms' own gates. A
/// build without them emits the same Query bytes as a run without the flags,
/// which is exactly the RED arm a damage test needs.
pub(crate) struct QueryEmitSpec {
    /// `--query <keyexpr>` — the literal the outbound Query carries.
    pub(crate) keyexpr: String,
    /// `--query-params <params>` — the URL-style selector parameters that ride
    /// the Query body's `Q_P` flag + params slice (what a zenoh selector spells
    /// after `?`). `None` elides the flag entirely.
    ///
    /// Foreign-observable with no patch: pico's stock queryable handlers print
    /// the keyexpr and the parameters CONCATENATED —
    /// `Received Query '<keyexpr><params>'` via `z_query_parameters`
    /// (`z_queryable.c:38-39`) — so a dropped `Q_P` slice prints the bare
    /// keyexpr and a witness on the full string separates the two.
    pub(crate) parameters: Option<String>,
    /// `--query-attachment <k>=<v>[,<k>=<v>…]` — kv pairs serialized into the
    /// Query attachment ext (0x05) in pico's `ze_serializer` sequence form.
    ///
    /// Pairs rather than an opaque blob because the ORACLE is structured: pico's
    /// `z_queryable_attachment` runs
    /// `ze_deserializer_deserialize_sequence_length` and prints one
    /// `i: <key>, <value>` line per pair, and a bare byte blob fails that
    /// deserialize and prints NOTHING (`z_queryable_attachment.c:71-87`). The
    /// same constraint the push-side `z_sub_attachment` witness lives under, so
    /// the same SSOT encodes it (`serialize_kv_attachment`).
    pub(crate) attachment: Option<Vec<(String, String)>>,
    /// `--query-after-ms <ms>` — hold the Query this long AFTER Established.
    ///
    /// The `--liveliness-get-after-ms` precedent, and needed for the SAME narrow
    /// reason that doc states: this Query is ONE-SHOT with no retry, so unlike the
    /// burst-driven publisher fixtures (whose 5x200ms burst covers the window for
    /// a remote declaration to land) it gets exactly one chance. A foreign
    /// queryable that has not finished declaring when the Query arrives never sees
    /// it, and the demo has nothing to absorb that with.
    ///
    /// This was MEASURED, not assumed: a hand run with no hold passed, and passed
    /// only because pico happened to print `Creating Queryable on` before the
    /// Query landed. Relying on that is the flake this knob removes — a fixture
    /// gates on pico's readiness line and sets the hold past it, so the ordering
    /// is owned rather than raced (`feedback_no_flaky_ever`,
    /// `feedback_hand_composed_fixture_needs_twin`).
    ///
    /// Deliberately NOT cfg-gated on any query atom, for the reason
    /// `--publish-after-ms` is not gated on `transport-keepalive`: it is a pure
    /// ordering delay, inert when the atoms are off, and it must stay reachable in
    /// the OFF build so the RED arm walks the identical path.
    pub(crate) after_ms: Option<u64>,
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
