// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y39 — the typed wz runtime config SSOT (§5.23 config introspection).
//!
//! [`WzConfig`] is the TYPED union of wz runtime settings — the
//! beyond-zenoh answer to zenoh's stringly `serde_json::Value` config
//! blob (`zenoh/src/api/config.rs` @ `pub struct Config`). Illegal config
//! states are
//! unrepresentable by construction: a field is a real Rust type
//! (`WhatAmI`, `u16`, [`InterceptorConfig`]), not a JSON pointer into an
//! untyped tree.
//!
//! Two classes of setting, the distinction this first slice draws:
//!
//! * **read-at-open** — `whatami` / `batch_size` / `lease_ms` are
//!   negotiated and FIXED by the 4-way handshake
//!   ([`SessionInitParams`](wz_session_core::session_init_params::SessionInitParams));
//!   the config mirrors them for introspection (the admin surface reads
//!   them) but a post-open change cannot take effect without
//!   re-handshaking, so the config never re-applies them. These are
//!   populated once via [`WzConfig::from_init_params`].
//! * **live** — the interceptor / access-control config
//!   ([`InterceptorConfig`]: ACL, downsampling, low-pass) is the subset
//!   zenoh genuinely runtime-mutates (its config `Notifier` rebuilds the
//!   interceptor factories on a config diff). wz drives it the same way:
//!   [`WzConfig::reconfigure_interceptors`] mutates the typed config and,
//!   under `config-mutate-runtime`, re-installs the chain on the live
//!   forwarder via the [`InterceptorSink`](crate::interceptor::InterceptorSink)
//!   seam (the production impl is
//!   [`LinkstateForwarder`](crate::linkstate_forward::LinkstateForwarder)) so
//!   the change takes effect at runtime.
//!
//! `config-mutate-runtime` is the inert-vs-driven toggle: OFF, a config
//! mutation is stored but never re-applied (an inert mirror — the thing
//! the §5.23 design rejects); ON, the mutation re-drives the forwarder
//! (config-DRIVEN — never a hollow mirror). The toggle existing IS the
//! proof the config is load-bearing.
//!
//! Deferred §5.23 layers (this slice is the typed-config foundation, not
//! the whole admin-mutate stack): the JSON-pointer config tree + change
//! `Notifier` + list-key-by-id merge semantics (the full
//! `config-mutate-runtime` engine), and the universal (non-router)
//! read-at-open fields beyond the three mirrored here. (The admin
//! `PUT config/<key>` wire — `adminspace-write` — landed in R311y51, gated
//! by `permissions.write`; the config-GET read view is complete as of R311y54.)

#[cfg(feature = "routing-peer")]
use crate::interceptor::{InterceptorConfig, InterceptorSink};
use crate::retry_period::RetryPolicy;
#[cfg(feature = "routing-router-hat")]
use crate::router_forward::RouterLinkWeightSink;
use wz_codecs::whatami::WhatAmI;
#[cfg(feature = "routing-router-hat")]
use wz_routing_graph::{link_weights_from_config, DuplicateLinkWeight, TransportWeight};
use wz_session_core::session_init_params::SessionInitParams;

/// How a runtime config change reaches the code that uses the value.
///
/// This is a real distinction and not a style note — it is the reason one of
/// the slices below deliberately has no sink. Recording it as DATA rather than
/// as prose is what lets a gate check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationDiscipline {
    /// The consumer holds state COMPILED from the value — an interceptor chain,
    /// a `zid -> weight` map — so a change must be pushed into it through a
    /// sink. Storing the new value is not applying it, and the gap between the
    /// two is exactly what `reconfigure_*` closes.
    Push,
    /// The consumer re-reads the value on every use, so STORING it IS applying
    /// it and there is no inert mirror to keep in step. Upstream forces this
    /// shape where it takes the config lock inside a handler.
    Pull,
}

/// One upstream config key that this node can change at RUNTIME, and the typed
/// slice of [`WzConfig`] it lands in.
///
/// ## Why this table exists
///
/// wz carries TWO config surfaces and, until this table, nothing stated the
/// relationship between them: the keys honoured when a config document is READ
/// at startup (`zenoh_config::HONOURED_CONFIG_KEYS`) and the keys that can be
/// mutated while the node runs. They are not nested in either direction —
/// `interceptors` is mutable at runtime while all seven of its keys sit in
/// `UNHONOURED_UPSTREAM_CONFIG_KEYS`, so a stock zenoh document naming
/// `access_control/enabled` starts wz with the ACL off even though an admin PUT
/// could turn it on afterwards.
///
/// ⚠ The count of these slices was being kept as an ENGLISH ORDINAL in each
/// field's own doc — "the SECOND runtime-mutable typed slice", "the THIRD" —
/// and in an atom reason that still says there are two. A number spelled in
/// prose at four sites is a number nobody derives: it went stale the moment the
/// third slice landed, and the only thing that would have caught it was a
/// reader who happened to compare. This table is the single declaration, and
/// `scripts/lib/runtime_mutable_surface_gate.py` derives the slice set from the
/// `set_*` / `reconfigure_*` methods and refuses a table that does not match it.
///
/// ⛔ Do not add a row for a key wz merely READS at startup. The subject here is
/// mutation after `WzConfig` is built; a build-time `with_*` builder consumes
/// `self` and is not a runtime mutation, which is why the four `with_*`-only
/// fields (`max_links`, `qos`, `qos_link`, `connect_retry`) are absent.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeMutableKey {
    /// The upstream config key, spelled as `zenoh_config`'s key lists spell it.
    pub key: &'static str,
    /// The private [`WzConfig`] field this key lands in.
    pub slice: &'static str,
    /// Push or pull — see [`MutationDiscipline`].
    pub discipline: MutationDiscipline,
    /// The cargo feature gating the FIELD, carried as data rather than as a
    /// `#[cfg]` on the row. A conditional member would strand the table's own
    /// scaffolding on the builds that elide it, and a table that shrinks by
    /// build cannot state the surface; the gate checks this against the real
    /// `#[cfg]` instead.
    pub feature: &'static str,
}

/// Every config key this node can change at runtime — see [`RuntimeMutableKey`].
///
/// MEASURED, not asserted: each key is spelled as it appears in
/// `zenoh_config`'s own key lists, and each slice is a private field carrying a
/// `set_*` or `reconfigure_*` method.
pub const RUNTIME_MUTABLE_CONFIG_KEYS: &[RuntimeMutableKey] = &[
    // The ACL / downsampling / low-pass chain, all three compiled into one
    // interceptor stack, so every key here is PUSH through `InterceptorSink`.
    RuntimeMutableKey {
        key: "access_control/default_permission",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "access_control/enabled",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "access_control/policies",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "access_control/rules",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "access_control/subjects",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "downsampling",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    RuntimeMutableKey {
        key: "low_pass_filter",
        slice: "interceptors",
        discipline: MutationDiscipline::Push,
        feature: "routing-peer",
    },
    // PULL: both admin gates take the value off the live config per request, so
    // storing it is applying it and there is no sink to install.
    RuntimeMutableKey {
        key: "adminspace/permissions/read",
        slice: "admin_permissions",
        discipline: MutationDiscipline::Pull,
        feature: "adminspace-core",
    },
    RuntimeMutableKey {
        key: "adminspace/permissions/write",
        slice: "admin_permissions",
        discipline: MutationDiscipline::Pull,
        feature: "adminspace-core",
    },
    // PUSH: the forwarder holds a `zid -> weight` map built from these rows.
    RuntimeMutableKey {
        key: "routing/router/linkstate/transport_weights",
        slice: "router_link_weights",
        discipline: MutationDiscipline::Push,
        feature: "routing-router-hat",
    },
];

/// Why a runtime key write was refused — see [`WzConfig::set_by_key`].
///
/// Every arm NAMES the key. Upstream refuses an unknown config path at insert
/// and says which; a write that failed silently would be indistinguishable from
/// one that applied, which is the shape this whole seam exists to end.
#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
#[derive(Debug, Clone, PartialEq)]
pub enum SetByKeyError {
    /// A segment was empty or carried something outside `[A-Za-z0-9_]`. Refused
    /// before the document is built, because the key is spliced INTO it.
    MalformedKey { key: String },
    /// The value is not JSON5. Refused before the document is built, for the
    /// same reason.
    MalformedValue { key: String },
    /// The reader's own verdict on the one-key document: a key wz does not know
    /// at all, a wrong type, or a value the acceptance boundary refuses.
    Document(crate::zenoh_config::ConfigIngestError),
    /// wz KNOWS this key and deliberately does not honour it, so the reader
    /// accepted the document and reported the key as ignored. Kept distinct
    /// from both neighbours: `Document` would claim wz has never heard of it,
    /// and `NotRuntimeMutable` would claim wz acts on it at startup.
    NotHonoured { key: String },
    /// wz READS this key but holds no live slice for it in this build, so
    /// storing it would change nothing a consumer can see. Distinct from
    /// `Document` on purpose: that one means "wz does not know this key", this
    /// one means "wz knows it and cannot change it while running".
    NotRuntimeMutable { key: String },
    /// The key IS runtime-mutable, but its consumer holds state compiled from
    /// the value, so it can only be changed through the sink-taking
    /// `reconfigure_*` seam. Refused rather than stored: storing would report a
    /// success the consumer never saw, and would also skip the validation
    /// `reconfigure_*` performs before it commits.
    NeedsSink { key: String },
}

/// The typed wz runtime config SSOT — see the module doc. The read-at-open
/// fields are `pub` (introspection-readable); the live `interceptors`
/// field is private so every mutation routes through
/// [`Self::reconfigure_interceptors`] (the re-apply seam), never a bare
/// field write that would silently desync the config from the forwarder.
///
/// The private slices that can change while the node runs are declared once in
/// [`RUNTIME_MUTABLE_CONFIG_KEYS`]; do not count them in prose.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WzConfig {
    /// This node's role, read-at-open from the handshake. Mirrored for
    /// introspection; never re-applied (a role change needs a new session).
    pub whatami: WhatAmI,
    /// The EFFECTIVE per-link batch budget (bytes), read-at-open. Mirrors
    /// `SessionInitParams::effective_batch_size` (the `0`-unset sentinel is
    /// already resolved); handshake-fixed, never re-applied.
    pub batch_size: u16,
    /// Session lease (milliseconds), read-at-open from the handshake;
    /// handshake-fixed, never re-applied.
    pub lease_ms: u64,
    /// The LIVE interceptor / access-control config. Private: mutate via
    /// [`Self::reconfigure_interceptors`] so the forwarder stays in sync.
    #[cfg(feature = "routing-peer")]
    interceptors: InterceptorConfig,
    /// The LIVE adminspace permissions (zenoh `adminspace.permissions`, the
    /// `PermissionsConf` read/write pair). A runtime-mutable typed slice, declared
    /// in [`RUNTIME_MUTABLE_CONFIG_KEYS`] — R2642 removed the ORDINAL this doc
    /// used to carry ("the SECOND"), because an ordinal spelled at each field is
    /// a count nobody derives and it was already stale. It is here because zenoh
    /// re-reads `conf.adminspace.permissions()` from the LIVE config on EVERY admin
    /// request — the GET gate at `net/runtime/adminspace.rs:456-457` and the
    /// config-WRITE gate at `:394-396` both take the config lock inside the handler,
    /// so a runtime config change (which upstream's own admin PUT can perform) flips
    /// the gate for the very next request. A permit captured by value at host-setup
    /// time cannot do that, which is why the two gates read this field per request
    /// rather than a captured bool.
    ///
    /// Private, like `interceptors`: mutate via [`Self::set_admin_permissions`] so
    /// the "one live config instance, read per request" invariant is structural.
    /// Default = zenoh's `PermissionsConf::default` (read `true`, write `false`).
    #[cfg(feature = "adminspace-core")]
    admin_permissions: wz_session_core::adminspace::AdminSpacePermissions,
    /// R2634 (`router-hat-router`) — the LIVE configured router link weights,
    /// zenoh's `routing.router.linkstate.transport_weights`. A runtime-mutable
    /// typed slice, declared in [`RUNTIME_MUTABLE_CONFIG_KEYS`] — R2642 removed
    /// the ORDINAL here too. It is here for upstream's own reason:
    /// the router hat RE-READS this key off the live config
    /// (`zenoh/src/net/routing/hat/router/mod.rs` @ `fn update_from_config`),
    /// which is the only thing that makes the key reloadable without a restart.
    /// Rows handed to a forwarder from a startup-only local can be applied once
    /// and re-read by nobody, so the capability is not "unwired" without this
    /// field — it is unexpressible.
    ///
    /// Private, like the two slices before it: mutate via
    /// [`Self::reconfigure_router_link_weights`] so "one live config, applied
    /// through one seam" is structural rather than a convention.
    ///
    /// Held as ROWS and not as the `zid -> weight` map the graph takes, because
    /// rows are what the config document carries and what upstream stores; the
    /// map — and the one refusal a well-formed row list can still earn, two rows
    /// naming one destination — is built at APPLY time, which is where upstream
    /// builds it.
    #[cfg(feature = "routing-router-hat")]
    router_link_weights: Vec<TransportWeight>,
    /// R311y205 (transport-multilink) — the EMBEDDER-facing max number of physical
    /// links this node aggregates into ONE logical unicast session (zenoh
    /// `TransportManager` `unicast.max_links`). Default `1` = single-link,
    /// byte-identical to today. `active <=> cfg-toggle`: the field only exists
    /// under `transport-multilink`, and even then stays INERT unless set `> 1`
    /// (`1` = the single-link degenerate path).
    ///
    /// This is a faithful structural mirror of zenoh, not a divergence. zenoh splits
    /// `max_links` across two layers: the CONFIG surface `unicast.max_links`
    /// (`commons/zenoh-config`, `TransportUnicastConf`) is UNCONDITIONAL and defaults
    /// to `1`, while the COMPILE-TIME gate lives in the transport-manager's INTERNAL
    /// field (`io/zenoh-transport/src/unicast/manager.rs`, under `#[cfg(feature =
    /// "transport_multilink")]`), which is populated from the config value inside a
    /// `#[cfg]` block and activates the multilink establishment at `> 1`
    /// (`MultiLink::make(.., max_links > 1)`). wz collapses those two layers into this
    /// ONE `WzConfig` field and gates IT — faithful to zenoh's manager-layer gate,
    /// defaulting to `1` like the config surface.
    ///
    /// R311y213 — the `WzConfig.max_links -> FaceSources.max_links` mapping is now
    /// live in the reference peer runner (`wz-ap-demo`'s `run_peer`), which sets this
    /// field via [`Self::with_max_links`] from `--max-links` and hands the SAME
    /// `WzConfig` instance to both the aggregation loop and the `--config-queryable`
    /// admin handler, so there is ONE budget source, not a second (a structural
    /// no-desync). R311y473 made it GET-OBSERVABLE too: `to_admin_json` renders
    /// `max_links`, so the budget is readable over the wire and not only off a
    /// startup log line. `peer_loop` reads the activation
    /// knob off [`FaceSources::max_links`](crate::accept_loop::FaceSources) (the
    /// zid-registry join at `Step::Opened`); the runner bridges the two. (Until
    /// R311y213 this note claimed no such runner could exist because a
    /// `transport-multilink` × `session-reconnect` `compile_error!` XOR blocked the
    /// default reconnect runners; that XOR was removed in R311y211, making the
    /// mapping runner reachable.)
    #[cfg(feature = "transport-multilink")]
    pub max_links: usize,
    /// R311y216 (transport-qos) — the EMBEDDER-facing "this deploy offers the QoS
    /// transport toward its peers" knob (zenoh `unicast.is_qos`,
    /// `commons/zenoh-config` `TransportUnicastConf`, read into the establishment
    /// state at `manager.config.unicast.is_qos`). Default `false` = single-conduit,
    /// byte-identical to a pre-QoS session. `active <=> cfg-toggle`: the field only
    /// exists under `transport-qos`, and even then a session negotiates QoS only
    /// when BOTH this offer AND the peer's `ext_qos` offer are set (the symmetric
    /// `&=` AND at [`crate::session_open`] / `SessionLinkActions::set_qos_offer`).
    ///
    /// This is a faithful mirror of zenoh's config surface, not a divergence.
    /// zenoh reads `unicast.is_qos` per-manager (uniform across a manager's
    /// sessions); wz stages it per-session via the `*_with_qos` open entrypoints,
    /// a superset (one qos session + one non-qos session under one node), while
    /// each individual session still negotiates faithfully. Like `max_links`, this
    /// field is the config surface: the single-link `*_with_qos` entrypoints take
    /// the offer directly, while the reference peer runner bridges `WzConfig.qos ->
    /// FaceSources.qos -> the `*_with_multilink` entrypoints` (R311y218 delivered
    /// the demo `--qos` reader over the multilink path; per-face priority-band
    /// segregation is R311y219). R311y473 — `to_admin_json` renders it (as with
    /// `max_links`), as the node's OFFER rather than the negotiated outcome.
    #[cfg(feature = "transport-qos")]
    pub qos: bool,
    /// session-extqos (R311y506) — the QoS METADATA this node declares for its
    /// links: the priority band it serves and/or the reliability class, zenoh's
    /// endpoint `prio=` / `rel=` metadata (`Metadata::PRIORITIES` /
    /// `Metadata::RELIABILITY`, `core/endpoint.rs:196-197`) read into
    /// `State::QoS { .. }` by `StateOpen::new` / `StateAccept::new`.
    ///
    /// `None` (the default) keeps the presence-only UNIT `QoS` ext on the wire —
    /// byte-identical to a `transport-qos`-only node. `Some` switches the emit to
    /// the z64 `QoSLink` and arms the DIRECTIONAL containment, which can REFUSE a
    /// peer: an acceptor demands the initiator's band be a subset of its own, an
    /// initiator demands the acceptor's be a superset of its own. That refusal is
    /// zenoh's, not a wz addition, and it is what makes the band an interop
    /// contract rather than a hint.
    ///
    /// Meaningful only alongside [`Self::qos`] — zenoh reaches the endpoint
    /// metadata only inside the `is_qos` arm of `State::new`, and the wz emit seam
    /// applies the same guard, so metadata on a non-QoS node is inert.
    #[cfg(feature = "session-extqos")]
    pub qos_link: Option<wz_session_core::extqos::QosLinkState>,
    /// R311y786 — the connection-retry period for OUTBOUND dials this node
    /// re-attempts: zenoh's `connect.retry` block (`period_init_ms` /
    /// `period_max_ms` / `period_increase_factor`,
    /// `zenoh-config/src/connection_retry.rs:31-37`), read by
    /// `peer_connector_retry` and by the `closed_session` re-dial of a dropped
    /// configured peer.
    ///
    /// UNGATED, unlike `Self::max_links` and `Self::qos` (code spans, not
    /// intra-doc links: those two fields are feature-gated and therefore absent
    /// from the default-feature rustdoc run Layer C1bz measures — naming a
    /// cfg'd-out item is exactly what an unresolved link IS), because upstream's is
    /// too: `connect.retry` sits in the base config, not behind a feature, and both
    /// substrates that consume it (`router-connect-reconcile` peer auto-reconnect,
    /// `transport-multilink` per-link re-add) are separate features that would each
    /// have to appear in the gate. Three numbers with no dependencies; a build with
    /// neither substrate simply never reads them.
    ///
    /// Defaults to [`RetryPolicy::ZENOH_DEFAULT`] (1 s -> 2 s -> 4 s, capped) — the
    /// values a stock zenoh resolves when a config omits the section. Until
    /// R311y786 the re-dial was a hardcoded fixed 1 s with no ceiling and no
    /// growth, so a configured peer that was simply switched off was re-dialed at
    /// 1 Hz for as long as it stayed down. Note the CLIENT reconnect supervisor
    /// keeps a CONSTANT default instead
    /// ([`ReconnectPolicy`](crate::reconnect::ReconnectPolicy)): its parity source
    /// is pico's reopen task, not zenoh's orchestrator. Same schedule, different
    /// default, because they mirror different upstreams.
    pub connect_retry: RetryPolicy,
}

impl Default for WzConfig {
    /// The base config — `whatami = Peer`, `batch_size = 0`, `lease_ms = 0`, no
    /// interceptors, admin permissions at zenoh's `PermissionsConf` default
    /// (read `true`, write `false`), `max_links = 1`, `qos = false`. A hand-written impl (not
    /// derived) so the `transport-multilink` `max_links` defaults to `1` (the
    /// single-link degenerate path), not the `usize` `Default` of `0`; every other
    /// field keeps its type `Default` (`qos` = `false`, byte-identical to a pre-QoS
    /// session), so the derived and hand-written impls agree on the pre-multilink
    /// fields.
    fn default() -> Self {
        Self {
            whatami: WhatAmI::default(),
            batch_size: 0,
            lease_ms: 0,
            #[cfg(feature = "routing-peer")]
            interceptors: InterceptorConfig::default(),
            #[cfg(feature = "adminspace-core")]
            admin_permissions: wz_session_core::adminspace::AdminSpacePermissions::default(),
            // R2634 — no configured weight is upstream's default too: the config
            // row list is a `Vec` with no `Option` around it, so an absent key and
            // an empty array are the same document to a stock zenohd, and both
            // leave every link unweighted.
            #[cfg(feature = "routing-router-hat")]
            router_link_weights: Vec::new(),
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-qos")]
            qos: false,
            #[cfg(feature = "session-extqos")]
            qos_link: None,
            connect_retry: RetryPolicy::ZENOH_DEFAULT,
        }
    }
}

/// R311y205 (transport-multilink) — the per-link reliability preference the
/// dial / accept path attaches to a physical link so the aggregation core
/// segregates traffic classes across the aggregated links (the wz analogue of
/// zenoh's per-channel `select`): the reliable channel prefers the `Reliable`
/// link, the best-effort channel the `BestEffort` link, `Any` (default) the
/// failover pool.
///
/// IMPL-2b — re-exported from the no_std session kernel, where
/// [`LinkState`](wz_session_core::session_actions::LinkState) actually stores it
/// (the reliability-routed `select_link` reads it), so the AP config surface and
/// the kernel agree by construction (ONE type, no conversion at the
/// `set_link_reliability_pref` seam).
#[cfg(feature = "transport-multilink")]
pub use wz_session_core::session_actions::LinkReliabilityPref;

/// R311y217 (transport-multilink + transport-qos) — the per-link QoS-priority band
/// the dial / accept path attaches to a physical link so the aggregation core pins
/// each `(priority, reliability)` conduit to ONE link (the priority tier of
/// zenoh's per-channel `select`). Re-exported from the no_std session kernel where
/// [`LinkState`](wz_session_core::session_actions::LinkState) stores it, so the AP
/// config surface and the kernel agree by construction (ONE type, no conversion at
/// the `set_link_priority_range` seam).
///
/// R311y506 — the gate WIDENED to `transport-qos` alone, following the kernel
/// type it re-exports. The band has a SECOND consumer now: it is also the body of
/// the `init::ext::QoSLink` establishment ext (`session-extqos`), which needs no
/// multilink. Upstream uses one `PriorityRange` for both, and so does wz.
#[cfg(feature = "transport-qos")]
pub use wz_session_core::session_actions::LinkPriorityRange;

impl WzConfig {
    /// A config with default (empty) settings — `whatami = Peer`,
    /// `batch_size = 0`, `lease_ms = 0`, no interceptors. The
    /// feature-independent base constructor (signature-stable: the live
    /// interceptor field defaults in, never a constructor parameter).
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the read-at-open mirror from the handshake params — the
    /// "the session reads the config at open" leg. The live interceptor
    /// config is left at its current value (it is not a handshake param).
    pub fn from_init_params(params: &SessionInitParams) -> Self {
        Self {
            whatami: params.whatami,
            batch_size: params.effective_batch_size(),
            lease_ms: params.lease_ms,
            ..Self::default()
        }
    }

    /// R311y40 — the admin-GET JSON view of the config (the
    /// `@/<zid>/<whatami>/config` reply). BEYOND-ZENOH (R311y42 correction):
    /// zenoh's `@/<zid>/<whatami>/config/**` is a write-only subscriber (PUT ->
    /// `insert_json5`); zenoh has NO admin config-READ, so this typed read is a wz
    /// superset, not a mirror. Alphabetical keys, matching the serde_json-BTreeMap
    /// order the other §5.23 emitters (`AdminLocalData`) use.
    ///
    /// R311y49/y50 — the LIVE ACL is now in this view: under `routing-peer` +
    /// `access-acl`, `acl_default` (the policy's base verdict `"allow"`/`"deny"`)
    /// and `acl_deny` (the denied-keyexpr summary array) carry the access-control
    /// state. This makes a runtime config-write reconfigure GET-OBSERVABLE (the
    /// read-path counterpart to the data-plane drop): after a `config/acl-deny` PUT
    /// the admin GET shows the new deny list, closing the R311y45 read-at-open
    /// caveat on the read path too. `acl_default` is REQUIRED for faithfulness — a
    /// bare `acl_deny:[]` on a DEFAULT-DENY policy would read as "open" (the exact
    /// opposite of the truth); the pair disambiguates. `batch_size` / `lease_ms` /
    /// `whatami` remain the handshake-fixed read-at-open mirror.
    ///
    /// R311y53 — the interceptor view is complete on the rate/size axes:
    /// `downsampling` (under `access-downsampling`) and `low_pass` (under
    /// `access-quota`) emit the LIVE rule arrays (`{key_exprs, min_interval_ms}` /
    /// `{key_exprs, max_payload_size}`). These are startup-config introspection
    /// (only `acl-deny` is runtime-reconfigurable via config-write so far).
    ///
    /// R311y54 — the ACL view is now complete too: `acl_rules` is the FULL per-rule
    /// dump (each `{flow, key_exprs, messages, permission, subject}`), the detail
    /// complement to the `acl_deny` summary (which stays the quick-glance denied-
    /// keyexpr list). The §5.23 config-GET view now mirrors the entire live
    /// interceptor config; no introspection axis remains deferred.
    ///
    /// R311y50 — built from an ordered (alphabetical) (key, value-json) list rather
    /// than a hand-spliced `format!`, so a new field is "push a pair where it
    /// sorts" with no per-field comma bookkeeping (the prior trailing-comma-prepend
    /// only worked for one leading optional key and broke for the deferred
    /// `downsampling`/`sessions` fields, which sort mid-object). String values go
    /// through the shared [`wz_session_core::json::escape_into`] SSOT escaper.
    pub fn to_admin_json(&self) -> String {
        // (key, value-json) pairs, present-only; sorted alphabetically below, so the
        // order they are assembled in does not matter.
        //
        // R311y474 — the UNCONDITIONAL fields seed the vector rather than
        // being pushed after the cfg-gated ones. Same output (the sort follows), but
        // it is now the type that says which fields every build carries, and it
        // retires a REAL clippy::vec_init_then_push failure that Layer C1bb was
        // already red on: with `Vec::new()` first, a feature combo in which several
        // gated pushes expand back-to-back (transport-multilink + transport-qos was
        // enough) leaves clippy looking at a plain push chain it wants folded into
        // `vec![..]` — a suggestion the code CANNOT take, because under another combo
        // those very pushes are absent. Seeding the vector removes the cause instead
        // of silencing the lint.
        let mut whatami = String::new();
        wz_session_core::json::escape_into(self.whatami.to_str(), &mut whatami);
        // R311y786 — the re-dial cadence, GET-observable for the same reason
        // `max_links` is (R311y473): an operator diagnosing "why is this peer only
        // retried every 4 s" must be able to read the schedule off the wire rather
        // than off a startup log line. Inner keys ALPHABETICAL, like acl_rules.
        //
        // A non-finite factor renders `null`: `{:?}` on a NaN yields the bare token
        // `NaN`, which would make this whole document invalid JSON and take the
        // config GET down with it. `null` is valid and honest — the value is not a
        // number — and the schedule treats it as no growth either way.
        let factor = self.connect_retry.period_increase_factor;
        let connect_retry = format!(
            "{{\"period_increase_factor\":{},\"period_init_ms\":{},\"period_max_ms\":{}}}",
            if factor.is_finite() {
                format!("{factor:?}")
            } else {
                "null".to_string()
            },
            self.connect_retry.period_init_ms,
            self.connect_retry.period_max_ms,
        );
        // R2330 (unregistered open-debt item 14) — the LIVE adminspace permit,
        // GET-observable for the same reason `max_links` (R311y473) and
        // `connect_retry` (R311y786) are: an operator must be able to read the
        // gate's CURRENT state off the wire rather than off the startup config.
        //
        // It is what makes the RUNTIME FLIP itself witnessable. `set_admin_permissions`
        // changes this value while the node runs and every admin GET re-reads it, so
        // before this field a foreign client could observe the flip's EFFECT (replies
        // stop) but never the CAUSE. Two observations of this key across a flip are
        // the difference between "the node went quiet" and "read was revoked".
        //
        // SHAPE mirrors the INBOUND config path rather than inventing a flat key:
        // `zenoh_config.rs` already honours `adminspace/permissions/read` and
        // `adminspace/permissions/write`, so an operator diffs this against the same
        // JSON5 they wrote. Inner keys ALPHABETICAL, like `connect_retry` and
        // `acl_rules`.
        //
        // GATED on `adminspace-core`, which is the feature that owns the VALUE —
        // exactly the precedent this field follows: `acl_deny` is gated on
        // `access-acl` and `max_links` on `transport-multilink`, each behind the
        // feature owning what it reports. Without `adminspace-core` there is no
        // `admin_permissions` field on this struct and no adminspace to permit, so
        // reporting a permit would be inventing one.
        let mut fields: Vec<(&str, String)> = vec![
            ("batch_size", self.batch_size.to_string()),
            ("connect_retry", connect_retry),
            ("lease_ms", self.lease_ms.to_string()),
            ("whatami", whatami),
        ];

        #[cfg(feature = "adminspace-core")]
        {
            let permits = self.admin_permissions;
            fields.push((
                "adminspace",
                format!(
                    "{{\"permissions\":{{\"read\":{},\"write\":{}}}}}",
                    permits.read, permits.write
                ),
            ));
        }

        // acl_default / acl_deny — the LIVE ACL view, present only on a build that
        // can carry an interceptor ACL. With no ACL the node admits all, so the
        // base verdict is "allow" and the deny list is empty.
        #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
        {
            use wz_access_control::{Permission, SubjectSelector};
            use wz_session_core::zid_hex::zid_to_zenoh_hex;
            let default_perm = self
                .interceptors
                .acl
                .as_ref()
                .map(|a| a.default_permission())
                .unwrap_or(Permission::Allow);
            // R311y54 — via the Permission::as_str SSOT (shared with acl_rules).
            let mut v = String::new();
            wz_session_core::json::escape_into(default_perm.as_str(), &mut v);
            fields.push(("acl_default", v));

            // R311y60 — the denied-keyexpr summary via the json::push_str_array
            // SSOT (the array bracket/comma bookkeeping lives in one place beside
            // escape_into); empty when no ACL.
            let deny_keys = self
                .interceptors
                .acl
                .as_ref()
                .map(|a| a.deny_key_exprs())
                .unwrap_or_default();
            let mut deny = String::new();
            wz_session_core::json::push_str_array(deny_keys, &mut deny);
            fields.push(("acl_deny", deny));

            // R311y54 — acl_rules: the FULL per-rule dump (the detail complement to
            // the acl_deny summary), one object per rule with keys ALPHABETICAL
            // (flow, key_exprs, messages, permission, subject). subject is "any" or
            // the peer's zid hex; enums via the wz-access-control as_str SSOTs; the
            // key_exprs / messages string arrays via the json::push_str_array SSOT.
            let mut rules_json = String::from("[");
            if let Some(acl) = &self.interceptors.acl {
                for (i, rule) in acl.rules().iter().enumerate() {
                    if i > 0 {
                        rules_json.push(',');
                    }
                    rules_json.push_str("{\"flow\":");
                    wz_session_core::json::escape_into(rule.flow.as_str(), &mut rules_json);
                    rules_json.push_str(",\"key_exprs\":");
                    wz_session_core::json::push_str_array(&rule.key_exprs, &mut rules_json);
                    rules_json.push_str(",\"messages\":");
                    wz_session_core::json::push_str_array(
                        rule.messages.iter().map(|m| m.as_str()),
                        &mut rules_json,
                    );
                    rules_json.push_str(",\"permission\":");
                    wz_session_core::json::escape_into(rule.permission.as_str(), &mut rules_json);
                    rules_json.push_str(",\"subject\":");
                    let subject = match &rule.subject {
                        SubjectSelector::Any => String::from("any"),
                        SubjectSelector::Zid(z) => zid_to_zenoh_hex(z.as_slice()),
                    };
                    wz_session_core::json::escape_into(&subject, &mut rules_json);
                    rules_json.push('}');
                }
            }
            rules_json.push(']');
            fields.push(("acl_rules", rules_json));
        }

        // downsampling — the LIVE rate-limit rules (each `{key_exprs, min_interval_ms}`),
        // the §5.23 introspection of the access-downsampling interceptor slice. Present
        // only under access-downsampling; an empty array means no rule is installed.
        #[cfg(all(feature = "routing-peer", feature = "access-downsampling"))]
        {
            let mut ds = String::from("[");
            for (i, rule) in self.interceptors.downsampling.iter().enumerate() {
                if i > 0 {
                    ds.push(',');
                }
                ds.push_str("{\"key_exprs\":");
                wz_session_core::json::push_str_array(&rule.key_exprs, &mut ds);
                ds.push_str(",\"min_interval_ms\":");
                ds.push_str(&rule.min_interval.as_millis().to_string());
                ds.push('}');
            }
            ds.push(']');
            fields.push(("downsampling", ds));
        }

        // low_pass — the LIVE per-key payload-size caps (each `{key_exprs,
        // max_payload_size}`), the introspection of the access-quota interceptor
        // slice. Present only under access-quota; an empty array means no rule.
        #[cfg(all(feature = "routing-peer", feature = "access-quota"))]
        {
            let mut lp = String::from("[");
            for (i, rule) in self.interceptors.low_pass.iter().enumerate() {
                if i > 0 {
                    lp.push(',');
                }
                lp.push_str("{\"key_exprs\":");
                wz_session_core::json::push_str_array(&rule.key_exprs, &mut lp);
                lp.push_str(",\"max_payload_size\":");
                lp.push_str(&rule.max_payload_size.to_string());
                lp.push('}');
            }
            lp.push(']');
            fields.push(("low_pass", lp));
        }

        // R311y473 — max_links: the EFFECTIVE aggregation budget, closing the
        // "structural no-desync but not GET-observable" caveat R311y213 left on
        // this field. It is the config half of transport-multilink's S5 residual:
        // the runtime half is the per-link `sessions[].links` array the admin
        // `local_data` now renders. An operator could previously only read the
        // budget off a startup LOG LINE, which is not a wire surface.
        #[cfg(feature = "transport-multilink")]
        fields.push(("max_links", self.max_links.to_string()));

        // R311y473 — qos: the same treatment for the transport-qos offer, whose
        // doc-comment carried the identical "to_admin_json does not render it (as
        // with max_links)" caveat. This is the OFFER this node makes, not the
        // negotiated outcome (QoS engages only if the peer offers too).
        #[cfg(feature = "transport-qos")]
        fields.push(("qos", self.qos.to_string()));

        // session-extqos (R311y506) — the declared QoS link metadata, rendered as
        // zenoh's own endpoint-metadata spelling (`prio=start-end`, `rel=0|1`) so
        // an operator reading the adminspace sees the SAME string they would put
        // on a zenoh endpoint. Absent when nothing is declared, which is the
        // UNIT-ext-on-the-wire case.
        #[cfg(feature = "session-extqos")]
        let qos_link_rendered = self.qos_link.map(|s| {
            let mut parts: Vec<String> = Vec::new();
            if let Some(p) = s.priorities {
                parts.push(format!(
                    "prio={}-{}",
                    p.start().wire_byte(),
                    p.end().wire_byte()
                ));
            }
            if let Some(r) = s.reliability {
                parts.push(format!("rel={}", r as u8));
            }
            format!("\"{}\"", parts.join(";"))
        });
        #[cfg(feature = "session-extqos")]
        if let Some(rendered) = qos_link_rendered.as_deref() {
            fields.push(("qos_link", rendered.to_string()));
        }

        // serde_json-BTreeMap alphabetical key order. R311y53 — an explicit sort (vs
        // the prior push-in-order assumption) so a new field is just "push it" with no
        // position bookkeeping (downsampling/low_pass sort MID-object, between
        // batch_size and lease_ms / lease_ms and whatami).
        fields.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = String::from("{");
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(key);
            out.push_str("\":");
            out.push_str(value);
        }
        out.push('}');
        out
    }

    /// Builder-style initial interceptor config (consumed at setup).
    #[cfg(feature = "routing-peer")]
    pub fn with_interceptors(mut self, interceptors: InterceptorConfig) -> Self {
        self.interceptors = interceptors;
        self
    }

    /// R311y213 (transport-multilink) — set the aggregated-link budget (the
    /// `unicast.max_links` analogue), consumed at setup. The builder twin of the
    /// `pub max_links` field, mirroring [`Self::with_interceptors`]: the reference
    /// peer runner chains it onto `from_init_params(..).with_interceptors(..)` so the
    /// ONE `WzConfig` it hands to both the aggregation loop and the admin surface
    /// carries the effective budget (no post-construction field poke that could
    /// desync a shared config). `1` = single-link (the `Default`).
    #[cfg(feature = "transport-multilink")]
    pub fn with_max_links(mut self, max_links: usize) -> Self {
        self.max_links = max_links;
        self
    }

    /// R311y216 (transport-qos) — offer the QoS transport toward this node's
    /// peers (zenoh `unicast.is_qos`), consumed at setup. The builder twin of the
    /// `pub qos` field, mirroring [`Self::with_max_links`]: a caller reads this to
    /// select the `*_with_qos` open entrypoint. `false` = single-conduit (the
    /// `Default`, byte-identical to a pre-QoS session). QoS engages only when the
    /// peer also offers `ext_qos` (the symmetric `&=` AND at open).
    #[cfg(feature = "transport-qos")]
    pub fn with_qos(mut self, qos: bool) -> Self {
        self.qos = qos;
        self
    }

    /// session-extqos (R311y506) — declare this node's QoS link metadata (the
    /// priority band / reliability class it serves), the builder twin of the
    /// `pub qos_link` field. Also turns [`Self::qos`] ON, because the metadata is
    /// meaningless without the offer that carries it: zenoh reads the endpoint
    /// metadata only inside the `is_qos` arm of `State::new`, so a band declared
    /// on a NoQoS node would be silently dropped rather than negotiated. Making
    /// the implication structural here means a caller cannot express that
    /// no-op combination by accident.
    #[cfg(feature = "session-extqos")]
    pub fn with_qos_link(mut self, qos_link: wz_session_core::extqos::QosLinkState) -> Self {
        self.qos_link = Some(qos_link);
        self.qos = true;
        self
    }

    /// R311y786 — set the outbound connection-retry period (zenoh's
    /// `connect.retry`), the builder twin of the `pub connect_retry` field. The
    /// router host chains it so the ONE `WzConfig` it hands to both the face loop
    /// and the admin GET carries the effective schedule — the same
    /// no-desync-by-construction discipline as `Self::with_max_links` (a code
    /// span for the same reason as the `connect_retry` field doc: that builder
    /// is feature-gated and absent from the default-feature rustdoc run).
    pub fn with_connect_retry(mut self, connect_retry: RetryPolicy) -> Self {
        self.connect_retry = connect_retry;
        self
    }

    /// R311y48 (§5.23 Phase 3b) — read the live interceptor config. The
    /// read accessor symmetric with the private `interceptors` field's write
    /// path ([`Self::reconfigure_interceptors`]): a partial config-write (e.g.
    /// `config/acl-deny`, which sets only the ACL slice) clones THIS to preserve
    /// the unrelated interceptors (downsampling, low-pass), mutates the one slice,
    /// and re-applies the merged whole — so a write to one config key never
    /// silently drops the others. Borrowing, not cloning: the caller clones only
    /// when it intends to mutate-and-reapply.
    #[cfg(feature = "routing-peer")]
    pub fn interceptors(&self) -> &InterceptorConfig {
        &self.interceptors
    }

    /// The config-DRIVEN initial install: drive `sink` from this config's
    /// interceptor settings. Called once at routing setup — the same
    /// [`InterceptorSink::set_interceptors`] seam the live reconfigure re-uses,
    /// so setup and runtime go through ONE code path. `sink` is the abstract
    /// interceptor target (the production impl is the `LinkstateForwarder`); the
    /// trait seam is what lets the §5.23 combined node compose the config-drive
    /// surface without depending on the concrete forwarder type.
    #[cfg(feature = "routing-peer")]
    pub fn install_interceptors(&self, sink: &dyn InterceptorSink) {
        sink.set_interceptors(self.interceptors.clone());
    }

    /// Runtime reconfigure of the live interceptor config: store the new
    /// typed value and, under `config-mutate-runtime`, RE-INSTALL it on the
    /// live `sink` so the change takes effect immediately (the forwarder's
    /// admit/deny verdict flips on the next message). This is the
    /// config-DRIVEN leg the §5.23 design demands.
    ///
    /// `config-mutate-runtime` OFF: the new value is stored (the typed
    /// config stays the introspection SSOT) but NOT re-applied — an inert
    /// mirror, the build that opts out of runtime reconfiguration. The
    /// signature is feature-stable either way.
    #[cfg(feature = "routing-peer")]
    pub fn reconfigure_interceptors(
        &mut self,
        interceptors: InterceptorConfig,
        sink: &dyn InterceptorSink,
    ) {
        self.interceptors = interceptors;
        #[cfg(feature = "config-mutate-runtime")]
        sink.set_interceptors(self.interceptors.clone());
        #[cfg(not(feature = "config-mutate-runtime"))]
        let _ = sink;
    }

    /// Builder-style initial adminspace permissions (consumed at setup) — the
    /// admin twin of [`Self::with_interceptors`]. A host builds ONE `WzConfig`
    /// carrying its startup permits and hands it to both the admin GET host and
    /// the config-WRITE host, so there is one permit source, not two.
    #[cfg(feature = "adminspace-core")]
    pub fn with_admin_permissions(
        mut self,
        permissions: wz_session_core::adminspace::AdminSpacePermissions,
    ) -> Self {
        self.admin_permissions = permissions;
        self
    }

    /// Read the LIVE adminspace permissions — the accessor an admin host calls
    /// INSIDE its per-request handler, which is the whole point of the field.
    /// Returns by value (the type is two `bool`s and `Copy`), so a handler holding
    /// a shared cell borrows it for the read alone and never across a reply.
    ///
    /// Feed the result to [`admin_read_permit`](crate::admin_read_permit) /
    /// [`admin_write_permit`](crate::admin_write_permit) — the cfg resolvers that
    /// turn the value into the effective permit — rather than reading the fields
    /// directly, so a build with the gate compiled out stays permissive at exactly
    /// one place.
    #[cfg(feature = "adminspace-core")]
    pub fn admin_permissions(&self) -> wz_session_core::adminspace::AdminSpacePermissions {
        self.admin_permissions
    }

    /// Runtime reconfigure of the live adminspace permissions — the admin-permit
    /// twin of [`Self::reconfigure_interceptors`], and the mutation that makes the
    /// gate genuinely live: the next admin request re-reads this value.
    ///
    /// Unlike the interceptor slice this needs NO sink and no
    /// `config-mutate-runtime` arm. The distinction is real rather than an
    /// omission: an interceptor change must be PUSHED into a forwarder that
    /// compiled its chain, whereas the permits are PULLED by each gate on every
    /// request (zenoh does the same — it takes the config lock inside the handler,
    /// `net/runtime/adminspace.rs:394` and `:456`), so storing the new value IS
    /// applying it. There is consequently no inert-mirror arm to opt out of.
    #[cfg(feature = "adminspace-core")]
    pub fn set_admin_permissions(
        &mut self,
        permissions: wz_session_core::adminspace::AdminSpacePermissions,
    ) {
        self.admin_permissions = permissions;
    }

    /// Apply a parsed config document's runtime-mutable keys to this config,
    /// returning the keys it applied, in [`RUNTIME_MUTABLE_CONFIG_KEYS`] order.
    ///
    /// ## Why this exists
    ///
    /// Until R2643 there was no declared mapping from a config DOCUMENT to the
    /// live config at all. The document was parsed, its values were poured into
    /// builder calls by hand at each host — `wz-ap-demo`'s runner spells
    /// `.with_interceptors(..)` and `.with_admin_permissions(..)` one key at a
    /// time — and then the document was DISCARDED. That is why so few keys are
    /// runtime-mutable: with no document to write into, every mutable key costs
    /// a bespoke setter plus a host edit, so the cost is per key.
    ///
    /// Upstream's `Config` IS the document, with typed accessors over it, which
    /// is what makes `insert_json5(key, value)` reach any path. This function is
    /// the half of that join wz can have without giving up its typed fields: one
    /// place that says which document key lands in which live slice, driven by
    /// the registry rather than by a second hand-written list.
    ///
    /// ## Two rules it obeys, both of them measured rather than chosen
    ///
    /// ⚠ IT READS `named`, NOT THE MERGED VALUES. `ZenohConfigIngest::named` is
    /// the set of keys the document actually STATED, and its own doc says why
    /// the distinction is load-bearing: a merged value resolves to a default for
    /// a key nobody wrote, so a caller acting on it "would carry a decision the
    /// operator never made".
    ///
    /// ⛔ IT APPLIES PER KEY, NEVER PER SLICE. Two keys share the
    /// `admin_permissions` slice, and the parser fills the absent one with
    /// `unwrap_or` — so applying the whole slice from a document that named only
    /// `read` would silently reset `write` to its default. The control test for
    /// this is `a_document_naming_one_permission_leaves_its_sibling_alone`;
    /// collapsing these arms back into one slice assignment reddens it.
    ///
    /// ## What it deliberately does NOT do
    ///
    /// It stores; it does not push. For a [`MutationDiscipline::Push`] slice the
    /// consumer holds compiled state, and reaching it is `reconfigure_*`'s job
    /// through a sink. This is the STARTUP half of the join, before any sink
    /// exists; calling it on a running node would store a value no consumer has
    /// seen.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn apply_zenoh_config(
        &mut self,
        ingest: &crate::zenoh_config::ZenohConfigIngest,
    ) -> Vec<&'static str> {
        let mut applied = Vec::new();
        for row in RUNTIME_MUTABLE_CONFIG_KEYS {
            if !ingest.named.contains(&row.key) {
                continue;
            }
            if self.apply_one_key(row.key, ingest) {
                applied.push(row.key);
            }
        }
        applied
    }

    /// Write ONE config key at runtime, the way upstream's admin PUT does.
    ///
    /// `key` is the upstream spelling (`adminspace/permissions/read`) and
    /// `value` is its JSON5 text (`true`, `[{...}]`). The key is built into a
    /// NESTED one-key document and handed to the ordinary reader, so the
    /// acceptance boundary, the type check and the unknown-key refusal are the
    /// reader's rather than a second implementation of them.
    ///
    /// ⛔ THE DOCUMENT IS BUILT, NEVER CONCATENATED FROM UNTRUSTED TEXT. Both
    /// halves arrive from the wire, so both are injection vectors into the
    /// document this assembles:
    ///
    /// * the KEY is refused unless every segment is `[A-Za-z0-9_]+`, so a
    ///   segment cannot carry a quote and close the object early;
    /// * the VALUE is PARSED as a standalone JSON5 value before it is embedded,
    ///   so text like `true, "write": false` is refused — a single value cannot
    ///   carry a trailing member. Embedded raw, that text would have produced a
    ///   well-formed document setting a key nobody asked for.
    ///
    /// ⚠ THE PARSE IS THE GUARD, NOT THE RE-EMIT, and this sentence is here
    /// because R2644's first control proved it the other way round. Damaging
    /// only the re-emit — splicing the raw text while still parsing it — left
    /// every test GREEN, because the parse had already refused the value. A
    /// control that comes back green is a finding: the re-emit is belt and
    /// braces (it normalises what is embedded), and removing the PARSE is what
    /// lets the smuggled key land.
    ///
    /// ⚠ `get` splits on `/`, so the document must be NESTED — the flat
    /// spelling a wire PUT carries would resolve to nothing and the write would
    /// silently do nothing.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn set_by_key(&mut self, key: &str, value: &str) -> Result<(), SetByKeyError> {
        let segments: Vec<&str> = key.split('/').collect();
        if segments.is_empty()
            || segments
                .iter()
                .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err(SetByKeyError::MalformedKey {
                key: String::from(key),
            });
        }

        let parsed =
            wz_session_core::json5::parse(value).map_err(|_| SetByKeyError::MalformedValue {
                key: String::from(key),
            })?;
        let canonical = parsed.to_json5_text();

        let mut document = String::new();
        for segment in &segments {
            document.push('{');
            document.push('"');
            document.push_str(segment);
            document.push_str("\":");
        }
        document.push_str(&canonical);
        for _ in &segments {
            document.push('}');
        }

        let ingest = crate::zenoh_config::ZenohNodeConfig::from_json5(&document)
            .map_err(SetByKeyError::Document)?;
        // The reader ACCEPTS a key wz knows and does not honour — a stock zenoh
        // document carries many, and refusing the whole document over one would
        // be wrong. It reports them separately instead, and a write naming one
        // must not be answered the same way as a write naming a key wz reads:
        // R2644's first draft collapsed the two and a test said so.
        if ingest.ignored.iter().any(|ignored| ignored == key) {
            return Err(SetByKeyError::NotHonoured {
                key: String::from(key),
            });
        }
        // ⛔ A PUSH-discipline key cannot be written through this path. Two
        // independent reasons, both measured:
        //
        //  * the consumer holds state COMPILED from the value, and this path only
        //    STORES — so the write would look applied while the forwarder kept its
        //    old map. `apply_zenoh_config`'s own doc says it stores and does not
        //    push; this function is the running-node caller that doc warns about.
        //  * `reconfigure_*` builds the map BEFORE it commits the rows
        //    (`link_weights_from_config(&rows)?` and only then the assignment), so
        //    a refused document never becomes live. Storing here skips that, and a
        //    row set `reconfigure_*` would REJECT — two rows naming one
        //    destination — could be installed.
        //
        // ⚠ ORDERED AFTER THE IGNORED CHECK, and a test said so: `downsampling` is
        // a push-discipline row that wz does NOT honour, and refusing it for
        // wanting a sink would claim wz acts on a key it ignores entirely. Only a
        // key wz actually reads can meaningfully need one.
        //
        // The startup path is unaffected and deliberately so: there `install_*` is
        // the gate, validating before the value first reaches a consumer.
        if let Some(row) = RUNTIME_MUTABLE_CONFIG_KEYS
            .iter()
            .find(|row| row.key == key)
        {
            if row.discipline == MutationDiscipline::Push {
                return Err(SetByKeyError::NeedsSink {
                    key: String::from(key),
                });
            }
        }
        if self.apply_zenoh_config(&ingest).is_empty() {
            return Err(SetByKeyError::NotRuntimeMutable {
                key: String::from(key),
            });
        }
        Ok(())
    }

    /// One key of [`Self::apply_zenoh_config`]; `true` when the value landed.
    ///
    /// The catch-all is NOT a silent pass: a registry key with no arm here
    /// returns `false`, so it never appears in the applied list, and
    /// `runtime_mutable_surface_gate.py` refuses a HONOURED registry row this
    /// function does not name.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn apply_one_key(
        &mut self,
        key: &str,
        ingest: &crate::zenoh_config::ZenohConfigIngest,
    ) -> bool {
        match key {
            #[cfg(feature = "adminspace-core")]
            "adminspace/permissions/read" => match ingest.config.adminspace {
                Some(admin) => {
                    self.admin_permissions.read = admin.read;
                    true
                }
                None => false,
            },
            #[cfg(feature = "adminspace-core")]
            "adminspace/permissions/write" => match ingest.config.adminspace {
                Some(admin) => {
                    self.admin_permissions.write = admin.write;
                    true
                }
                None => false,
            },
            #[cfg(feature = "routing-router-hat")]
            "routing/router/linkstate/transport_weights" => {
                self.router_link_weights = ingest.config.router_transport_weights.clone();
                true
            }
            _ => false,
        }
    }

    /// Builder-style initial router link weights (consumed at setup) — the
    /// weights twin of [`Self::with_admin_permissions`]. A router host builds ONE
    /// `WzConfig` carrying its startup rows and hands it to both the forwarder
    /// install and its admin host, so there is one weight source, not two: the
    /// same structural no-desync `with_max_links` and `with_connect_retry` are
    /// there for.
    #[cfg(feature = "routing-router-hat")]
    pub fn with_router_link_weights(mut self, rows: Vec<TransportWeight>) -> Self {
        self.router_link_weights = rows;
        self
    }

    /// Read the LIVE configured router link weights — the read accessor
    /// symmetric with [`Self::reconfigure_router_link_weights`]. Borrowing, not
    /// cloning: a caller clones only when it intends to mutate-and-reapply.
    #[cfg(feature = "routing-router-hat")]
    pub fn router_link_weights(&self) -> &[TransportWeight] {
        &self.router_link_weights
    }

    /// The config-DRIVEN initial install: drive `sink` from this config's
    /// configured router link weights. Called once at routing setup — the same
    /// [`RouterLinkWeightSink::set_router_link_weights`] seam the live
    /// reconfigure re-uses, so setup and runtime go through ONE code path, as
    /// [`Self::install_interceptors`] does for the interceptor slice. It is also
    /// upstream's own ordering: its router hat builds the network WITH the
    /// weights at `init` (`zenoh/src/net/routing/hat/router/mod.rs` @
    /// `link_weights_from_config(router_link_weights`) and re-applies the same
    /// map-building step on a config update.
    ///
    /// Returns whether a live link moved — `false` for the ordinary setup call,
    /// where no face has registered yet and the weights are simply what the
    /// first flood carries.
    ///
    /// `Err` is the one refusal a well-formed row list can still earn: two rows
    /// naming the same destination. It is raised HERE and not at the config
    /// parse because that is where upstream raises it — a stock zenohd RESOLVES
    /// such a document and then dies building the network — and because wz's
    /// config ingest also validates documents destined for OTHER nodes, so it
    /// must accept what the parser accepts.
    #[cfg(feature = "routing-router-hat")]
    pub fn install_router_link_weights(
        &self,
        sink: &dyn RouterLinkWeightSink,
    ) -> Result<bool, DuplicateLinkWeight> {
        Ok(sink.set_router_link_weights(link_weights_from_config(&self.router_link_weights)?))
    }

    /// Runtime reconfigure of the live router link weights — the weights twin of
    /// [`Self::reconfigure_interceptors`], and the mutation that makes zenoh's
    /// `update_from_config` (`zenoh/src/net/routing/hat/router/mod.rs` @
    /// `fn update_from_config`) expressible here at all: store the new rows and,
    /// under `config-mutate-runtime`, RE-APPLY them to the live `sink` so the
    /// routers tier re-floods and re-computes without a restart.
    ///
    /// `config-mutate-runtime` OFF: the new rows are stored (the typed config
    /// stays the introspection SSOT) but NOT re-applied — the inert mirror, the
    /// same opt-out arm the interceptor slice offers, and the return is then
    /// `Ok(false)` because no link moved.
    ///
    /// The map is built BEFORE the rows are stored, so a refused document never
    /// becomes the live value. That is stricter than upstream, which stores the
    /// rows and fails at every apply, and it is deliberate: the two agree on what
    /// the NETWORK does (the old weights stand) and wz additionally cannot end up
    /// reporting a live config it would refuse to apply.
    #[cfg(feature = "routing-router-hat")]
    pub fn reconfigure_router_link_weights(
        &mut self,
        rows: Vec<TransportWeight>,
        sink: &dyn RouterLinkWeightSink,
    ) -> Result<bool, DuplicateLinkWeight> {
        let weights = link_weights_from_config(&rows)?;
        self.router_link_weights = rows;
        #[cfg(feature = "config-mutate-runtime")]
        {
            Ok(sink.set_router_link_weights(weights))
        }
        #[cfg(not(feature = "config-mutate-runtime"))]
        {
            let _ = (sink, weights);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2643 — ⭐ THE CONTROL for `apply_zenoh_config`'s per-key rule, and the
    /// reason that rule exists rather than a per-slice assignment.
    ///
    /// Two keys share the `admin_permissions` slice and the parser fills the one
    /// the document did not name with `unwrap_or` — `read` defaults `true`,
    /// `write` defaults `false`. So a per-SLICE apply driven by a document that
    /// named only `read` would write the parsed struct wholesale and silently
    /// reset `write` to `false`. This fixture makes the live value the OPPOSITE
    /// of that default in both positions, so the wrong shape cannot pass by
    /// coincidence: collapsing the two arms into one slice assignment turns the
    /// second assertion red.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn a_document_naming_one_permission_leaves_its_sibling_alone() {
        use crate::zenoh_config::ZenohNodeConfig;

        let mut cfg = WzConfig::new();
        cfg.set_admin_permissions(wz_session_core::adminspace::AdminSpacePermissions {
            read: false,
            write: true,
        });

        let ingest =
            ZenohNodeConfig::from_json5(r#"{ "adminspace": { "permissions": { "read": true } } }"#)
                .expect("a one-key document parses");
        assert_eq!(
            ingest.named,
            vec!["adminspace/permissions/read"],
            "the document stated exactly one key"
        );

        let applied = cfg.apply_zenoh_config(&ingest);
        assert_eq!(applied, vec!["adminspace/permissions/read"]);
        assert!(cfg.admin_permissions.read, "the named key is applied");
        assert!(
            cfg.admin_permissions.write,
            "the SIBLING the document never named keeps its LIVE value; the parser \
             resolved it to `false` as a default, and applying that would carry a \
             decision the operator never made"
        );
    }

    /// R2643 — a document that states nothing applies nothing. The anti-vacuity
    /// half of the test above: without it, an `apply_zenoh_config` that simply
    /// did nothing at all would pass that one.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    #[test]
    fn a_document_that_names_nothing_applies_nothing() {
        use crate::zenoh_config::ZenohNodeConfig;

        let ingest = ZenohNodeConfig::from_json5("{}").expect("an empty document parses");
        assert!(ingest.named.is_empty(), "nothing was stated");
        let mut cfg = WzConfig::new();
        assert!(
            cfg.apply_zenoh_config(&ingest).is_empty(),
            "a silent document is not an instruction"
        );
    }

    /// R2644 — a runtime key write reaches the live value, by the upstream
    /// spelling of the key.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn a_runtime_key_write_reaches_the_live_value() {
        let mut cfg = WzConfig::new();
        cfg.set_admin_permissions(wz_session_core::adminspace::AdminSpacePermissions {
            read: false,
            write: true,
        });
        cfg.set_by_key("adminspace/permissions/read", "true")
            .expect("a honoured, runtime-mutable key is written");
        assert!(cfg.admin_permissions.read);
        assert!(cfg.admin_permissions.write, "its sibling is untouched");
    }

    /// R2644 — ⭐ THE INJECTION CONTROL for the VALUE, and the reason
    /// `set_by_key` parses the value and re-emits it instead of splicing the
    /// text it was handed.
    ///
    /// Both halves of a runtime write arrive from the wire. Spliced raw, the
    /// value below would have produced
    /// `{"adminspace":{"permissions":{"read":true, "write": false}}}` — a
    /// perfectly well-formed document that parses cleanly and sets a key the
    /// caller never named. Parsing the value first refuses it as a value,
    /// because a single JSON5 value cannot carry a trailing member.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn a_value_that_smuggles_a_second_key_is_refused() {
        let mut cfg = WzConfig::new();
        cfg.set_admin_permissions(wz_session_core::adminspace::AdminSpacePermissions {
            read: false,
            write: true,
        });
        let err = cfg
            .set_by_key("adminspace/permissions/read", r#"true, "write": false"#)
            .expect_err("a value carrying a second member is not a value");
        assert_eq!(
            err,
            SetByKeyError::MalformedValue {
                key: String::from("adminspace/permissions/read")
            }
        );
        assert!(!cfg.admin_permissions.read, "nothing was applied");
        assert!(cfg.admin_permissions.write, "the smuggled key did NOT land");
    }

    /// R2644 — the injection control for the KEY. A segment carrying a quote
    /// would close the object the document builder is opening.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn a_key_segment_outside_the_alphabet_is_refused() {
        let mut cfg = WzConfig::new();
        for bad in [
            r#"adminspace/permissions/read", "mode": "client"#,
            "",
            "a//b",
        ] {
            assert!(
                matches!(
                    cfg.set_by_key(bad, "true"),
                    Err(SetByKeyError::MalformedKey { .. })
                ),
                "refused before the document is built: {bad:?}"
            );
        }
    }

    /// R2644 — THREE refusals wz must keep distinct, and the first draft of
    /// this test proved the code was collapsing two of them.
    ///
    /// A key wz has never heard of, a key it knows and deliberately ignores,
    /// and a key it reads at startup but cannot change while running are three
    /// different answers to an operator. Returning one answer for the last two
    /// would tell someone writing `downsampling` that wz reads the key, which
    /// it does not.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn the_three_refusals_are_kept_distinct() {
        let mut cfg = WzConfig::new();

        // Never heard of it: the reader's acceptance boundary refuses.
        assert!(matches!(
            cfg.set_by_key("no_such_key", "true"),
            Err(SetByKeyError::Document(_))
        ));

        // Known and deliberately NOT honoured: the reader accepts the document
        // — a stock zenoh file carries many such keys — and reports it ignored.
        assert_eq!(
            cfg.set_by_key("downsampling", "[]"),
            Err(SetByKeyError::NotHonoured {
                key: String::from("downsampling")
            })
        );

        // Honoured at startup, not runtime-mutable: accepted, read, unapplied.
        assert_eq!(
            cfg.set_by_key("mode", r#""router""#),
            Err(SetByKeyError::NotRuntimeMutable {
                key: String::from("mode")
            })
        );
    }

    /// R2644 — ⭐ THE CONTROL for the Push-discipline refusal, and the defect it
    /// closes: `set_by_key` used to return `Ok(())` for this key while STORING
    /// rows no consumer would ever see, and while skipping the map build
    /// `reconfigure_*` does before it commits.
    ///
    /// The fixture writes a row set that `reconfigure_*` would REJECT — two rows
    /// naming one destination — so the assertion covers both halves at once: the
    /// refusal is named, and the invalid rows did not become live. Deleting the
    /// discipline check turns this red on the stored rows, not merely on the
    /// error kind.
    #[cfg(all(feature = "zenoh-config", feature = "routing-router-hat"))]
    #[test]
    fn a_push_discipline_key_is_refused_rather_than_stored() {
        let mut cfg = WzConfig::new();
        let before = cfg.router_link_weights.len();

        let err = cfg
            .set_by_key(
                "routing/router/linkstate/transport_weights",
                r#"[ { "dst_zid": "b1b2c3d4", "weight": 10 },
                     { "dst_zid": "b1b2c3d4", "weight": 20 } ]"#,
            )
            .expect_err("a push-discipline key cannot be written without a sink");
        assert_eq!(
            err,
            SetByKeyError::NeedsSink {
                key: String::from("routing/router/linkstate/transport_weights")
            }
        );
        assert_eq!(
            cfg.router_link_weights.len(),
            before,
            "nothing was stored — including a row set reconfigure_* would refuse"
        );
    }

    /// R2643 — the weights row reaches the live slice, and the applied list
    /// names the key that moved.
    #[cfg(all(feature = "zenoh-config", feature = "routing-router-hat"))]
    #[test]
    fn a_named_weight_row_reaches_the_live_slice() {
        use crate::zenoh_config::ZenohNodeConfig;

        let ingest = ZenohNodeConfig::from_json5(
            r#"{ "routing": { "router": { "linkstate": { "transport_weights":
                 [ { "dst_zid": "b1b2c3d4", "weight": 10 } ] } } } }"#,
        )
        .expect("one weight row loads");

        let mut cfg = WzConfig::new();
        assert!(cfg.router_link_weights.is_empty(), "nothing configured yet");
        let applied = cfg.apply_zenoh_config(&ingest);
        assert_eq!(applied, vec!["routing/router/linkstate/transport_weights"]);
        assert_eq!(cfg.router_link_weights.len(), 1);
        assert_eq!(cfg.router_link_weights[0].weight.get(), 10);
    }

    // R311y40/y49/y50/y53 — the config GET reply shape: TYPED fields, serde_json-
    // BTreeMap alphabetical key order, whatami as the zenoh role string. The emitted
    // key set depends on the access-* features, so the byte-exact assertion is split
    // per feature combo (each gated to EXACTLY the build that emits that shape, so no
    // never-run branch and no wrong assertion under an un-CI'd partial combo). The
    // empty-config shape: acl => acl_default:"allow"/acl_deny:[]; downsampling/low_pass
    // => empty arrays; always batch_size/lease_ms/whatami — sorted alphabetically.
    fn router_config() -> WzConfig {
        WzConfig {
            whatami: WhatAmI::Router,
            batch_size: 65535,
            lease_ms: 10_000,
            ..WzConfig::new()
        }
    }

    // R311y473 — the seven exact-string tests below pin the ACCESS axis, and each
    // is gated to exactly the build emitting its shape. They now also exclude the
    // two TRANSPORT-axis keys (`max_links` / `qos`), which are orthogonal to
    // access and would otherwise multiply seven assertions by four. The combo that
    // carries all of them — the preset-ap-full shape — gets its own exact pin in
    // `to_admin_json_ap_full_shape_alphabetical`, so no shipped combo is left
    // without one.
    #[cfg(all(
        not(any(
            feature = "access-acl",
            feature = "access-downsampling",
            feature = "access-quota"
        )),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_base_alphabetical() {
        // No access interceptor feature: just the 3 read-at-open keys.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        not(feature = "access-downsampling"),
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_acl_only_alphabetical() {
        // access-acl only: acl_default/acl_deny/acl_rules lead (all sort before
        // batch_size). Empty policy -> empty deny + empty rules arrays.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"lease_ms":10000,"whatami":"router"}"#
        );
    }

    // R311y453 — the FOUR combinations of {acl, downsampling, quota} that had NO
    // assertion at all. The comment above claims the split covers every build
    // that emits a shape, but 4 of the 8 subsets fell through every gate:
    // downsampling-only, quota-only, acl+downsampling and acl+quota. The visible
    // symptom was a `router_config is never used` dead-code error under a single
    // access knob with `--all-targets` (recorded as a pre-existing defect in the
    // R311y452 carry, uncovered by any lane because C1y clippies each knob
    // LIB-only); the actual defect is the coverage hole the dead helper was
    // pointing at. Closing the hole is what removes the warning — an `#[allow]`
    // would have silenced the messenger.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-downsampling",
        not(feature = "access-acl"),
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_downsampling_only_alphabetical() {
        // downsampling sorts between batch_size and lease_ms.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"downsampling":[],"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-quota",
        not(feature = "access-acl"),
        not(feature = "access-downsampling"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_quota_only_alphabetical() {
        // low_pass sorts between lease_ms and whatami.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_acl_and_downsampling_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"downsampling":[],"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-quota",
        not(feature = "access-downsampling"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_acl_and_quota_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        feature = "access-quota",
        not(feature = "transport-multilink"),
        not(feature = "transport-qos"),
        // R2330 — `adminspace-core` adds the `adminspace` permit object, which
        // sorts between `acl_rules` and `batch_size`. These tests pin the exact
        // byte sequence, so each must exclude every field-adding feature.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_full_access_alphabetical() {
        // The full routing-peer access set (the wz-ap-demo build): acl_rules sorts
        // after acl_deny; downsampling between batch_size and lease_ms; low_pass
        // between lease_ms and whatami.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"downsampling":[],"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    /// R311y473 — the preset-ap-full config shape: the full access set PLUS the two
    /// transport-axis keys. This combo previously had NO exact-string pin (the seven
    /// access-axis tests all exclude it now that `max_links` / `qos` land), and it
    /// is the shape wz-ap-demo actually ships, so it gets one here.
    ///
    /// `max_links` sorts between `lease_ms` and `qos`, `qos` between `max_links` and
    /// `whatami` — both mid-object, which is exactly the position bookkeeping the
    /// R311y50 sorted-pairs rewrite exists to make free.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        feature = "access-quota",
        feature = "transport-multilink",
        feature = "transport-qos",
        // R2330 — see the sibling pins: `adminspace-core` adds a field, and this
        // one pins the exact bytes too.
        not(feature = "adminspace-core")
    ))]
    #[test]
    fn to_admin_json_ap_full_shape_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"connect_retry":{"period_increase_factor":2.0,"period_init_ms":1000,"period_max_ms":4000},"downsampling":[],"lease_ms":10000,"low_pass":[],"max_links":1,"qos":false,"whatami":"router"}"#
        );
    }

    /// R311y473 — `max_links` in the admin body tracks the BUILDER, not a constant.
    ///
    /// A presence assertion alone would pass against a hard-coded `1`, which is also
    /// the default — so the load-bearing leg is that `with_max_links(2)` moves it.
    /// This is the config half of closing transport-multilink's S5 residual: before
    /// it, the aggregation budget was readable only off a startup log line, and
    /// R311y213's "ONE budget source" was a structural claim with no wire surface to
    /// check it against.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn to_admin_json_max_links_tracks_the_builder() {
        let base = router_config().to_admin_json();
        assert!(
            base.contains(r#""max_links":1"#),
            "the default budget is the single-link 1, rendered: {base}"
        );
        let aggregating = router_config().with_max_links(2).to_admin_json();
        assert!(
            aggregating.contains(r#""max_links":2"#),
            "with_max_links(2) must be GET-observable, not just structurally held: {aggregating}"
        );
    }

    /// R2330 (unregistered open-debt item 14) — the adminspace permit is
    /// GET-observable, and it tracks the RUNTIME setter and not only the builder.
    ///
    /// That second half is the item's whole point and the reason this asserts
    /// through `set_admin_permissions` rather than through the constructor: the
    /// permit is re-read from the live config on EVERY admin GET, so a flip is a
    /// thing that happens to a RUNNING node. Before this field a foreign client
    /// could observe the flip's EFFECT (replies stop arriving) but never its
    /// CAUSE; two reads of this key across the flip now distinguish "the node went
    /// quiet" from "read was revoked", which is what makes the flip witnessable
    /// from outside at all.
    ///
    /// Gated on `adminspace-core` because `set_admin_permissions` is: the FIELD is
    /// unconditional (so the base assertion below holds on every build), but the
    /// runtime setter that makes the second half meaningful is not.
    #[cfg(feature = "adminspace-core")]
    #[test]
    fn to_admin_json_adminspace_permit_tracks_the_runtime_flip() {
        let base = router_config().to_admin_json();
        assert!(
            base.contains(r#""adminspace":{"permissions":{"read":true,"write":false}}"#),
            "zenoh's PermissionsConf default is permissive GET, default-deny \
             config-WRITE, and the admin view must render exactly that: {base}"
        );

        let mut flipped = router_config();
        flipped.set_admin_permissions(wz_session_core::adminspace::AdminSpacePermissions {
            read: false,
            write: true,
        });
        let after = flipped.to_admin_json();
        assert!(
            after.contains(r#""adminspace":{"permissions":{"read":false,"write":true}}"#),
            "a RUNTIME flip must move the rendered value — the admin GET re-reads \
             the live config, so a view that showed only the startup permit would \
             report a state the node has left: {after}"
        );
        assert_ne!(
            base, after,
            "the two documents must DIFFER, which is the property a foreign witness \
             actually depends on: it compares two GETs across the flip"
        );
    }

    /// R311y473 — the `qos` twin of
    /// [`to_admin_json_max_links_tracks_the_builder`]: the rendered value follows
    /// `with_qos`, and it is this node's OFFER (a session negotiates QoS only when
    /// the peer offers too, so the admin body must not be read as the outcome).
    #[cfg(feature = "transport-qos")]
    #[test]
    fn to_admin_json_qos_tracks_the_builder() {
        assert!(
            router_config().to_admin_json().contains(r#""qos":false"#),
            "the default offer is false (byte-identical to a pre-QoS session)"
        );
        let offered = router_config().with_qos(true).to_admin_json();
        assert!(
            offered.contains(r#""qos":true"#),
            "with_qos(true) must be GET-observable: {offered}"
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-downsampling",
        feature = "access-quota"
    ))]
    #[test]
    fn to_admin_json_renders_downsampling_and_low_pass_rules() {
        use crate::interceptor::InterceptorFlow;
        use crate::linkstate_forward::{
            DownsamplingMessage, DownsamplingRule, LowPassMessage, LowPassRule,
        };
        use std::time::Duration;
        let mut c = router_config();
        c.interceptors.downsampling = vec![DownsamplingRule {
            key_exprs: vec!["mesh/data".to_string()],
            min_interval: Duration::from_millis(250),
            messages: DownsamplingMessage::ALL.to_vec(),
            flows: InterceptorFlow::ALL.to_vec(),
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }];
        c.interceptors.low_pass = vec![LowPassRule {
            key_exprs: vec!["mesh/bulk".to_string()],
            max_payload_size: 1024,
            messages: LowPassMessage::ALL.to_vec(),
            flows: InterceptorFlow::ALL.to_vec(),
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }];
        let json = c.to_admin_json();
        assert!(
            json.contains(r#""downsampling":[{"key_exprs":["mesh/data"],"min_interval_ms":250}]"#),
            "downsampling rule not rendered: {json}"
        );
        assert!(
            json.contains(r#""low_pass":[{"key_exprs":["mesh/bulk"],"max_payload_size":1024}]"#),
            "low_pass rule not rendered: {json}"
        );
    }

    #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
    #[test]
    fn to_admin_json_renders_full_acl_rules() {
        // R311y54 — the full per-rule dump: subject/flow/messages/permission +
        // key_exprs, keys alphabetical within each rule object. The acl_deny summary
        // still reflects the deny keyexpr (the two views coexist: detail + summary).
        use wz_access_control::{
            AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
        };
        let mut c = router_config();
        c.interceptors.acl = Some(AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec!["mesh/data".to_string()],
                messages: vec![AclMessage::Put, AclMessage::Delete],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
                link_protocols: Vec::new(),
                interfaces: Vec::new(),
                usernames: Vec::new(),
            }],
        }));
        let json = c.to_admin_json();
        assert!(
            json.contains(
                r#""acl_rules":[{"flow":"ingress","key_exprs":["mesh/data"],"messages":["put","delete"],"permission":"deny","subject":"any"}]"#
            ),
            "acl_rules not rendered: {json}"
        );
        assert!(
            json.contains(r#""acl_deny":["mesh/data"]"#),
            "acl_deny summary not rendered: {json}"
        );
    }

    /// The adminspace permits are a LIVE slice of the config, like the interceptors
    /// — a `set` is visible to the very next read, and the read is what an admin
    /// host does per request. This pins the config half of the live gate; the
    /// behavioural half (a revoke denying the next GET on an already-declared
    /// queryable) is `declare_adminspace_live_permit_source_flips_the_gate_at_runtime`.
    ///
    /// The assertions go through `admin_read_permit` / `admin_write_permit` rather
    /// than the struct fields, because those resolvers are where "the gate compiled
    /// out" is decided: with the gate off the permit is `true` regardless of the
    /// stored value, and asserting the field would claim a denial the build does not
    /// perform.
    #[cfg(feature = "adminspace-core")]
    #[test]
    fn admin_permissions_are_a_live_config_slice() {
        use wz_session_core::adminspace::AdminSpacePermissions;

        // Default = zenoh's PermissionsConf (read true, write false).
        let mut cfg = WzConfig::new();
        assert_eq!(cfg.admin_permissions(), AdminSpacePermissions::default());

        // Setup-time builder.
        cfg = cfg.with_admin_permissions(AdminSpacePermissions {
            read: false,
            write: true,
        });
        assert!(!cfg.admin_permissions().read);
        assert!(cfg.admin_permissions().write);

        // Runtime mutation — the seam a config-write / operator control drives.
        cfg.set_admin_permissions(AdminSpacePermissions {
            read: true,
            write: false,
        });
        assert!(cfg.admin_permissions().read);
        assert!(!cfg.admin_permissions().write);

        // Resolved through the cfg sites both gates use, in BOTH directions.
        #[cfg(feature = "adminspace-read")]
        {
            assert!(crate::admin_read_permit(&cfg.admin_permissions()));
            cfg.set_admin_permissions(AdminSpacePermissions {
                read: false,
                write: false,
            });
            assert!(!crate::admin_read_permit(&cfg.admin_permissions()));
        }
        #[cfg(feature = "adminspace-write")]
        {
            assert!(!crate::admin_write_permit(&cfg.admin_permissions()));
            cfg.set_admin_permissions(AdminSpacePermissions {
                read: false,
                write: true,
            });
            assert!(crate::admin_write_permit(&cfg.admin_permissions()));
        }
    }

    /// R2634 — the configured-router-link-weight slice: the third live slice, and
    /// the one zenoh re-reads per `update_from_config`. Driven against a
    /// RECORDING sink rather than the forwarder, so what is graded here is the
    /// config seam's own contract (what it hands on, when, and what it refuses)
    /// and not the graph's — `router_forward.rs` grades the graph.
    #[cfg(feature = "routing-router-hat")]
    mod router_link_weights {
        use super::*;
        use core::num::NonZeroU16;
        use std::cell::RefCell;
        use wz_routing_graph::{LinkEdgeWeight, Zid};

        /// Records every map handed to it, and reports the `bool` it is told to.
        struct RecordingSink {
            installs: RefCell<Vec<std::collections::HashMap<Zid, LinkEdgeWeight>>>,
            moved: bool,
        }

        impl RecordingSink {
            fn new(moved: bool) -> Self {
                Self {
                    installs: RefCell::new(Vec::new()),
                    moved,
                }
            }
            fn calls(&self) -> usize {
                self.installs.borrow().len()
            }
            fn last(&self) -> std::collections::HashMap<Zid, LinkEdgeWeight> {
                self.installs
                    .borrow()
                    .last()
                    .cloned()
                    .expect("the sink was driven")
            }
        }

        impl RouterLinkWeightSink for RecordingSink {
            fn set_router_link_weights(
                &self,
                weights: std::collections::HashMap<Zid, LinkEdgeWeight>,
            ) -> bool {
                self.installs.borrow_mut().push(weights);
                self.moved
            }
        }

        fn zid(b: u8) -> Zid {
            Zid::from_slice(&[b])
        }

        fn row(b: u8, w: u16) -> TransportWeight {
            TransportWeight {
                dst_zid: zid(b),
                weight: NonZeroU16::new(w).expect("test weight is non-zero"),
            }
        }

        /// Setup drives the sink from the LIVE rows, and the map it hands on is
        /// the rows resolved by destination — the same translation the runtime
        /// reconfigure uses, which is the whole reason the seam exists.
        #[test]
        fn setup_installs_the_live_rows_as_a_map() {
            let cfg = WzConfig::new().with_router_link_weights(vec![row(0xAA, 250), row(0xBB, 10)]);
            let sink = RecordingSink::new(false);
            assert_eq!(cfg.install_router_link_weights(&sink), Ok(false));
            assert_eq!(sink.calls(), 1);
            let map = sink.last();
            assert_eq!(map.len(), 2);
            assert_eq!(map[&zid(0xAA)], LinkEdgeWeight::from_raw(250));
            assert_eq!(map[&zid(0xBB)], LinkEdgeWeight::from_raw(10));
            // The rows stay readable afterwards: an install is not a hand-off.
            assert_eq!(cfg.router_link_weights().len(), 2);
        }

        /// An empty list is a legal document (upstream's field is a bare `Vec`),
        /// so the seam still runs and hands on an empty map rather than skipping
        /// the sink — which is what makes "clear the weights" expressible.
        #[test]
        fn an_empty_row_list_still_drives_the_sink() {
            let cfg = WzConfig::new();
            let sink = RecordingSink::new(false);
            assert_eq!(cfg.install_router_link_weights(&sink), Ok(false));
            assert_eq!(sink.calls(), 1);
            assert!(sink.last().is_empty());
        }

        /// The one refusal a well-formed row list can earn, at BOTH entry
        /// points, and on the runtime one it happens BEFORE the store: a refused
        /// document never becomes the live value and never reaches the sink.
        #[test]
        fn a_repeated_destination_is_refused_before_anything_is_stored_or_applied() {
            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new().with_router_link_weights(vec![row(0xAA, 250)]);
            assert_eq!(
                cfg.reconfigure_router_link_weights(vec![row(0xBB, 5), row(0xBB, 6)], &sink),
                Err(wz_routing_graph::DuplicateLinkWeight { dst_zid: zid(0xBB) })
            );
            assert_eq!(sink.calls(), 0, "the sink is never driven by a refusal");
            assert_eq!(
                cfg.router_link_weights(),
                &[row(0xAA, 250)],
                "the live rows are the ones that were accepted"
            );

            // Setup refuses the same document, through the same builder.
            let bad = WzConfig::new().with_router_link_weights(vec![row(0xCC, 1), row(0xCC, 2)]);
            assert_eq!(
                bad.install_router_link_weights(&sink),
                Err(wz_routing_graph::DuplicateLinkWeight { dst_zid: zid(0xCC) })
            );
            assert_eq!(sink.calls(), 0);
        }

        /// The runtime leg: new rows become the live value, and under
        /// `config-mutate-runtime` they are re-applied to the sink — the
        /// `update_from_config` half. Without that feature the rows are stored
        /// and NOT applied (the inert mirror the interceptor slice also offers),
        /// so the returned "a link moved" is `false`.
        #[test]
        fn a_runtime_reconfigure_stores_and_reapplies() {
            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new().with_router_link_weights(vec![row(0xAA, 250)]);
            let moved = cfg
                .reconfigure_router_link_weights(vec![row(0xAA, 300), row(0xBB, 7)], &sink)
                .expect("distinct destinations");
            assert_eq!(
                cfg.router_link_weights(),
                &[row(0xAA, 300), row(0xBB, 7)],
                "the live rows are the new ones"
            );
            #[cfg(feature = "config-mutate-runtime")]
            {
                assert!(moved, "the sink reported a moved link");
                assert_eq!(sink.calls(), 1);
                let map = sink.last();
                assert_eq!(map[&zid(0xAA)], LinkEdgeWeight::from_raw(300));
                assert_eq!(map[&zid(0xBB)], LinkEdgeWeight::from_raw(7));
            }
            #[cfg(not(feature = "config-mutate-runtime"))]
            {
                assert!(!moved, "an inert mirror moves nothing");
                assert_eq!(sink.calls(), 0);
            }
        }
    }
}
