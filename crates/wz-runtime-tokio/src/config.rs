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

/// Why a runtime key write was refused — see [`WzConfig::set_by_key`] and
/// [`WzConfig::remove_by_key`].
///
/// Every arm NAMES the key. Upstream refuses an unknown config path at insert
/// and says which; a write that failed silently would be indistinguishable from
/// one that applied, which is the shape this whole seam exists to end.
///
/// R2646 renamed this from `SetByKeyError`, and the rename is the change: the
/// delete half now returns it too, and upstream's write gate is ONE gate that
/// matches on the body (`zenoh/src/net/runtime/adminspace.rs`
/// @ `match &msg.payload {`) after ONE permission check. A name saying "set"
/// would have
/// made the shared refusals read as the set half's, which is how two halves of
/// one gate start justifying separate rules. `MalformedValue` is the one arm
/// only the set half can raise — a delete carries no value to malform — and
/// that asymmetry is real rather than a naming accident.
#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigKeyWriteError {
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
    ///
    /// ⚠ R2654 — THIS IS NOW "THE CALLER BROUGHT NO SINK", not "no sink can
    /// exist". [`WzConfig::set_by_key_with`] takes the live consumers and
    /// writes a push-discipline key through them; `set_by_key` is that function
    /// with an EMPTY [`ConfigSinks`], so this arm is what an empty one answers.
    /// The distinction matters to an operator: the key is writable, on a host
    /// that has the consumer it names.
    NeedsSink { key: String },
    /// The value parsed, and the CONSUMER refused it — two link-weight rows
    /// naming one destination is the only such refusal today.
    ///
    /// Distinct from [`Self::Document`] because it is raised somewhere else and
    /// means something else: the reader ACCEPTS such a document, deliberately,
    /// because upstream's parser accepts it too and a wz node validates
    /// documents destined for other nodes. Upstream then RESOLVES it and dies
    /// building its network; wz refuses the write instead, at the same seam and
    /// without the node going down.
    ConsumerRefused { key: String },
    /// The key belongs to a SUBTREE that is compiled as a unit, and the subtree
    /// this write would produce does not compile — a policy naming a rule id no
    /// rule defines is the shape.
    ///
    /// ⚠ NAMED SEPARATELY FROM [`Self::NotRuntimeMutable`], which is what this
    /// used to answer and which sends an operator the wrong way entirely: the
    /// key IS runtime-mutable and the value IS well formed. What is wrong is the
    /// subtree AROUND it, which for `access_control` means the write order
    /// matters — rules and subjects before the policy that names them, exactly
    /// as upstream's own `init` demands of a whole document.
    SubtreeRefused { key: String },
}

/// R2654 — the `access_control/*` document inputs as they stood before a write.
///
/// ⚠ THE FIELD IS CONDITIONAL AND THE TYPE IS NOT, which is the same choice
/// [`RuntimeMutableKey`] makes about its `feature` column: a `#[cfg]` on a
/// PARAMETER strands the signature of everything that takes it, so the
/// condition lives on the field and every build can name the type. On a build
/// with no ACL this is a zero-sized value that records the one true thing there
/// is to record — that there were no inputs to put back.
#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
#[derive(Clone, Default)]
struct AclSnapshot {
    #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
    inputs: crate::zenoh_config::AclConfigInputs,
}

/// R2654 — the live consumers a runtime config write may have to reach.
///
/// # Why a write takes these at all
///
/// Eight of the ten rows in [`RUNTIME_MUTABLE_CONFIG_KEYS`] are
/// [`MutationDiscipline::Push`]: their consumer holds state COMPILED from the
/// value, so storing the value is not applying it. Until this type,
/// [`WzConfig::set_by_key`] refused all eight by name, which left the wire-
/// facing write surface exactly TWO BOOLEANS wide against upstream's whole
/// config document — the residual the `adminspace-write` atom is graded on.
///
/// The refusal was never about the key. It was about the CALL SITE: a write
/// entry point that cannot reach the consumers of what it writes has nothing
/// honest to do with a push key. So the consumers come in with the value.
///
/// # Why builders rather than a struct literal
///
/// Which fields exist depends on the enabled routing features, so
/// `ConfigSinks { interceptors, ..Default::default() }` is correct under the
/// full set and a `clippy::needless_update` error under one of them. That is
/// the same trap [`InterceptorConfig`] documents, and the same answer: a
/// caller chains only the sinks its build has, and a new slice adds a builder
/// without touching any existing call site.
///
/// ⚠ AN ABSENT SINK IS A REFUSAL, NEVER A SILENT STORE. A host that owns a
/// consumer and forgets to name it here gets [`ConfigKeyWriteError::NeedsSink`]
/// for that key — the same answer it got before this type existed, which is why
/// adding it changes no behaviour until a caller supplies something.
#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
#[derive(Default)]
pub struct ConfigSinks<'a> {
    /// The interceptor stack, which every `access_control/*`, `downsampling`
    /// and `low_pass_filter` write has to reach.
    #[cfg(feature = "routing-peer")]
    interceptors: Option<&'a dyn InterceptorSink>,
    /// The router's configured link weights.
    #[cfg(feature = "routing-router-hat")]
    router_link_weights: Option<&'a dyn RouterLinkWeightSink>,
    /// Holds `'a` on a build that compiles NEITHER sink field, where the
    /// lifetime would otherwise be unused and the type would not compile. Such
    /// a build has no push-discipline slice to reach, so the type is still
    /// meaningful there: it is the empty set of consumers, which is what
    /// `set_by_key` hands in.
    _lifetime: core::marker::PhantomData<&'a ()>,
}

#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
impl<'a> ConfigSinks<'a> {
    /// No consumers — every push-discipline key answers `NeedsSink`.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Name the live interceptor stack.
    #[cfg(feature = "routing-peer")]
    #[must_use]
    pub fn with_interceptors(mut self, sink: &'a dyn InterceptorSink) -> Self {
        self.interceptors = Some(sink);
        self
    }

    /// Name the live router link-weight consumer.
    #[cfg(feature = "routing-router-hat")]
    #[must_use]
    pub fn with_router_link_weights(mut self, sink: &'a dyn RouterLinkWeightSink) -> Self {
        self.router_link_weights = Some(sink);
        self
    }
}

#[cfg(all(
    feature = "zenoh-config",
    any(feature = "adminspace-core", feature = "routing-router-hat")
))]
impl core::fmt::Debug for ConfigSinks<'_> {
    /// Says WHICH consumers are present, never what they are: a sink is a live
    /// forwarder and its `Debug` would print a routing table into a log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut named: Vec<&'static str> = Vec::new();
        #[cfg(feature = "routing-peer")]
        if self.interceptors.is_some() {
            named.push("interceptors");
        }
        #[cfg(feature = "routing-router-hat")]
        if self.router_link_weights.is_some() {
            named.push("router_link_weights");
        }
        write!(f, "ConfigSinks{named:?}")
    }
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
    /// R2652 — the `access_control/*` document inputs the live policy above was
    /// COMPILED from, kept because that compilation cannot be inverted.
    ///
    /// # Why this exists rather than merging into the compiled form
    ///
    /// [`InterceptorConfig::acl`] holds a policy whose rules are the expansion of
    /// upstream's `rules x subjects x policies`. Given an expanded rule there is
    /// no way back to the three entries that produced it, so a write to any one
    /// of those keys cannot be merged — it must be RE-EXPANDED against the
    /// current other two, which is what these inputs are for.
    ///
    /// # Why it carries no `set_`/`reconfigure_` method, deliberately
    ///
    /// `runtime_mutable_surface_gate` derives its slice population as exactly
    /// "private fields having such a method", and the five ACL keys already name
    /// `interceptors` as their slice. Giving this one a method would make it a
    /// DECLARED slice demanding registry rows of its own, and the resulting
    /// mismatch would read as a registry error when the registry is correct.
    /// Updates happen inside the existing `apply_one_key` arms, which re-derive
    /// the compiled policy from here — so these inputs are the SSOT and the
    /// compiled form is a pure function of them, which is what stops the two
    /// from drifting into the inert mirror this tree keeps paying for.
    ///
    /// # Why the `#[cfg]` is this long rather than the field's own two features
    ///
    /// It names exactly the builds where the field is READ, which is the ACL
    /// arms of `apply_one_key`: that function needs `zenoh-config` and one of
    /// the two admin hats, its ACL arms need `routing-peer` for the live slice
    /// and `access-acl` for the engine. A shorter `#[cfg]` would compile the
    /// field into builds that never touch it, and this crate denies dead code,
    /// so the conjunction is not tidiness — it is the condition under which a
    /// document-driven ACL apply exists at all.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    acl_inputs: crate::zenoh_config::AclConfigInputs,
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
            #[cfg(all(
                feature = "routing-peer",
                feature = "access-acl",
                feature = "zenoh-config",
                any(feature = "adminspace-core", feature = "routing-router-hat")
            ))]
            acl_inputs: crate::zenoh_config::AclConfigInputs::default(),
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
        self.apply_document(ingest).0
    }

    /// [`Self::apply_zenoh_config`] plus the one thing its `Vec` cannot say:
    /// whether the ACL subtree was REFUSED.
    ///
    /// The public function drops a refused subtree's keys from the applied list,
    /// which is the right answer for a caller asking "what landed" — and the
    /// wrong one for a caller asking "why did this ONE key not land", because
    /// `NotRuntimeMutable` and "the subtree does not compile" send an operator
    /// in opposite directions. The keyed write asks the second question, so it
    /// gets the second answer, without a second copy of the loop.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn apply_document(
        &mut self,
        ingest: &crate::zenoh_config::ZenohConfigIngest,
    ) -> (Vec<&'static str>, bool) {
        let acl_before = self.acl_snapshot();
        let mut applied = Vec::new();
        for row in RUNTIME_MUTABLE_CONFIG_KEYS {
            if !ingest.named.contains(&row.key) {
                continue;
            }
            if self.apply_one_key(row.key, Some(ingest)) {
                applied.push(row.key);
            }
        }
        let settled = self.settle_acl_subtree(&mut applied, &acl_before);
        (applied, settled)
    }

    /// The ACL document inputs as they stand, for a caller that is about to
    /// change them and may have to put them back.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn acl_snapshot(&self) -> AclSnapshot {
        AclSnapshot {
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            inputs: self.acl_inputs.clone(),
        }
    }

    /// R2654 — the ACL subtree's compile, lifted out of
    /// [`Self::apply_zenoh_config`] so the DELETE half reaches it too.
    ///
    /// # Why it had to move
    ///
    /// R2652 put this step at the end of the document apply, which was the only
    /// caller that could reach an `access_control/*` arm: a delete refused every
    /// push-discipline key before it got there. R2654 gave the delete half
    /// sinks, so it can now reach those arms — and reaching them without this
    /// step would store new inputs beside a policy compiled from the old ones,
    /// which is precisely the inert-mirror state `acl_inputs`' own doc exists to
    /// prevent. One function, both callers, no second implementation.
    ///
    /// `applied` is edited in place: a subtree that does not compile leaves its
    /// keys out of the applied list, because they did not land. `false` says
    /// that happened, which is the one thing the list itself cannot distinguish
    /// from a key nobody wrote.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn settle_acl_subtree(
        &mut self,
        applied: &mut Vec<&'static str>,
        before: &AclSnapshot,
    ) -> bool {
        // R2652 — THE ONE SUBTREE STEP. The five `access_control/*` arms store
        // without compiling (their own comment says why), so the compile happens
        // here, once, against the whole subtree — the same place upstream does
        // it, which is after the config has been read rather than per key.
        //
        // ⚠ The `starts_with` is the SUBTREE, not a prefix trick: upstream's
        // `AclConfig` IS the `access_control` subtree, so "did this document
        // touch the ACL" and "did it name a key under that prefix" are the same
        // question. The keys come from `RUNTIME_MUTABLE_CONFIG_KEYS` by way of
        // `applied`, so there is no second list of them here.
        //
        // ⛔ GUARDED, and not merely as a saving: an unconditional recompile
        // would overwrite a policy a host had built PROGRAMMATICALLY (through
        // `with_interceptors`) every time any unrelated key was applied, because
        // the retained inputs of such a host are empty and compile to no ACL.
        #[cfg(all(
            feature = "routing-peer",
            feature = "access-acl",
            any(feature = "adminspace-core", feature = "routing-router-hat")
        ))]
        if applied.iter().any(|key| key.starts_with("access_control/"))
            && !self.recompile_acl(&before.inputs)
        {
            applied.retain(|key| !key.starts_with("access_control/"));
            return false;
        }
        // Consumed by the `#[cfg]`-elided arm above on a build with no ACL.
        let _ = (&applied, before);
        true
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
    pub fn set_by_key(&mut self, key: &str, value: &str) -> Result<(), ConfigKeyWriteError> {
        self.set_by_key_with(key, value, &ConfigSinks::none())
    }

    /// R2654 — write ONE config key at runtime, THROUGH the consumers that hold
    /// state compiled from it.
    ///
    /// [`Self::set_by_key`] is this function with an empty [`ConfigSinks`], so
    /// there is one implementation of the write gate rather than two that must
    /// agree. That matters more than it looks: the delete half already shares
    /// `apply_one_key`'s table with the set half for exactly this reason, and a
    /// second sink-aware write path would have re-opened the split at the level
    /// above.
    ///
    /// # What a push-discipline key does here that it could not do before
    ///
    /// Eight of ten registry rows are [`MutationDiscipline::Push`] and were
    /// refused by name, which left this seam two booleans wide. A push key now
    /// goes to the `reconfigure_*` seam for the SLICE it names, which is the one
    /// call that validates and commits together — so the two reasons the old
    /// refusal gave are both answered rather than avoided:
    ///
    ///  * the consumer sees the change, because the sink is driven in the same
    ///    call that stores it;
    ///  * a value the consumer refuses never becomes live, because
    ///    `reconfigure_router_link_weights` builds the map BEFORE it commits the
    ///    rows and its `Err` is returned here as
    ///    [`ConfigKeyWriteError::ConsumerRefused`].
    ///
    /// ⚠ THE REFUSAL ORDER IS THE OLD ONE AND A TEST SAYS WHY. `downsampling`
    /// used to be a push row wz did not honour, and refusing it for wanting a
    /// sink would have claimed wz acts on a key it ignores entirely. The
    /// unhonoured check therefore still comes first, inside `ingest_for_key`.
    ///
    /// ⚠ DISPATCH IS BY SLICE, NOT BY KEY, and that is what makes the registry's
    /// `slice` field load-bearing rather than decorative: seven keys share the
    /// interceptor slice and one push is what all seven need, so a per-key arm
    /// here would be seven copies of one sentence.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn set_by_key_with(
        &mut self,
        key: &str,
        value: &str,
        sinks: &ConfigSinks<'_>,
    ) -> Result<(), ConfigKeyWriteError> {
        let ingest = Self::ingest_for_key(key, value)?;
        let row = RUNTIME_MUTABLE_CONFIG_KEYS
            .iter()
            .find(|row| row.key == key);
        // ⛔ THE SINK IS RESOLVED BEFORE ANYTHING IS STORED. A missing one must
        // not leave the value stored-but-unpushed, which is the state the old
        // refusal existed to prevent; resolving first means a `NeedsSink` write
        // changes nothing at all, exactly as it did before.
        let pushes = matches!(row, Some(r) if r.discipline == MutationDiscipline::Push);
        if pushes {
            let slice = row.expect("`pushes` is false without a row").slice;
            Self::push_slice_would_reach(slice, sinks).ok_or_else(|| {
                ConfigKeyWriteError::NeedsSink {
                    key: String::from(key),
                }
            })?;
        }
        // ⛔ ATOMIC ACROSS THE STORE AND THE PUSH, and the snapshot is what makes
        // it so. `reconfigure_*` validates before IT commits, but by then the
        // value is already in this struct -- so a consumer refusal has to undo
        // the store or the write is half applied: stored, unpushed, and reported
        // as an error. Snapshotting the whole config covers every slice with one
        // rule, including the ones this registry has not grown yet, where a
        // per-slice undo would be a second table to keep in step.
        //
        // Taken only for a PUSH key: a pull key's store IS its application, so
        // there is nothing to undo and nothing to pay for the clone with.
        let restore = if pushes { Some(self.clone()) } else { None };
        // The STORE is the startup half's own function, per key, with the ACL
        // subtree's atomic compile inside it -- not a second implementation of
        // either.
        let (applied, settled) = self.apply_document(&ingest);
        if applied.is_empty() {
            if let Some(previous) = restore {
                *self = previous;
            }
            return Err(if settled {
                ConfigKeyWriteError::NotRuntimeMutable {
                    key: String::from(key),
                }
            } else {
                ConfigKeyWriteError::SubtreeRefused {
                    key: String::from(key),
                }
            });
        }
        if pushes {
            let slice = row.expect("`pushes` is false without a row").slice;
            if let Err(err) = self.push_slice(slice, sinks, key) {
                if let Some(previous) = restore {
                    *self = previous;
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Whether `sinks` carries the consumer `slice` needs — asked BEFORE a value
    /// is stored, so a write with no sink leaves the config untouched.
    ///
    /// `None` means "no consumer for that slice here", which the caller turns
    /// into [`ConfigKeyWriteError::NeedsSink`]. It deliberately does not say
    /// WHICH consumer is missing: the key names its slice and the registry maps
    /// one to the other, so a second spelling of that here would be a table.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn push_slice_would_reach(slice: &str, sinks: &ConfigSinks<'_>) -> Option<()> {
        match slice {
            #[cfg(feature = "routing-peer")]
            "interceptors" => sinks.interceptors.map(|_| ()),
            #[cfg(feature = "routing-router-hat")]
            "router_link_weights" => sinks.router_link_weights.map(|_| ()),
            // A slice this build compiles no consumer for, or a registry row
            // naming a slice nobody pushes. Both are "the write cannot reach a
            // consumer", which is what the caller reports.
            _ => None,
        }
    }

    /// Drive the consumer of `slice` from the values this config now holds.
    ///
    /// Called only after the store, and only when
    /// [`Self::push_slice_would_reach`] has already said the sink is there — so
    /// the `else` arms below are unreachable rather than defensive, and they
    /// answer `NeedsSink` rather than panicking because a running node must not
    /// die on a mismatch between two functions in this file.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn push_slice(
        &mut self,
        slice: &str,
        sinks: &ConfigSinks<'_>,
        key: &str,
    ) -> Result<(), ConfigKeyWriteError> {
        match slice {
            #[cfg(feature = "routing-peer")]
            "interceptors" => {
                let Some(sink) = sinks.interceptors else {
                    return Err(ConfigKeyWriteError::NeedsSink {
                        key: String::from(key),
                    });
                };
                let live = self.interceptors.clone();
                self.reconfigure_interceptors(live, sink);
                Ok(())
            }
            #[cfg(feature = "routing-router-hat")]
            "router_link_weights" => {
                let Some(sink) = sinks.router_link_weights else {
                    return Err(ConfigKeyWriteError::NeedsSink {
                        key: String::from(key),
                    });
                };
                let rows = self.router_link_weights.clone();
                self.reconfigure_router_link_weights(rows, sink)
                    .map(|_| ())
                    .map_err(|_| ConfigKeyWriteError::ConsumerRefused {
                        key: String::from(key),
                    })
            }
            _ => Err(ConfigKeyWriteError::NeedsSink {
                key: String::from(key),
            }),
        }
    }

    /// R2648 — the PARSE-AND-ACCEPT front end that every runtime write shares,
    /// whatever its key's [`MutationDiscipline`] turns out to be.
    ///
    /// # Why this is a function and not the head of [`Self::set_by_key`]
    ///
    /// A PUSH-discipline key cannot be written through `set_by_key` (it refuses
    /// with [`ConfigKeyWriteError::NeedsSink`], for the two reasons stated
    /// there), so its host has to reach the same parsed value by some other
    /// route in order to hand it to the drain that owns the sink. The only
    /// other route is to repeat this: split the segments, splice the value into
    /// a one-key document, read it back, and ask whether wz honours the key.
    /// A SECOND copy of that is a second answer to "does wz honour this key?"
    /// and to "is this value acceptable?", and the two would drift — this tree
    /// has paid for that class often enough to name it. One front end, and the
    /// discipline decides only what happens to the result.
    ///
    /// Takes no `&self`: nothing here reads the live config. What comes back is
    /// the reader's verdict on a document carrying exactly this one key, which
    /// is a question about the KEY and the VALUE and not about this node.
    ///
    /// The `ignored` check is the last thing it does, and it stays last for the
    /// reason `set_by_key` records: the reader ACCEPTS a key wz knows and does
    /// not honour, so a write naming one must be told that specifically rather
    /// than be answered as if wz had never heard of it.
    ///
    /// Carries the gate of the callers it was lifted out of, spelled literally
    /// rather than inherited: `ConfigKeyWriteError` and the `zenoh_config`
    /// module it returns are themselves behind it, so an ungated copy does not
    /// fail to LINK on a narrower build — it fails to NAME its own types.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn ingest_for_key(
        key: &str,
        value: &str,
    ) -> Result<crate::zenoh_config::ZenohConfigIngest, ConfigKeyWriteError> {
        let segments = Self::key_segments(key)?;

        let parsed = wz_session_core::json5::parse(value).map_err(|_| {
            ConfigKeyWriteError::MalformedValue {
                key: String::from(key),
            }
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
            .map_err(ConfigKeyWriteError::Document)?;
        // The reader ACCEPTS a key wz knows and does not honour — a stock zenoh
        // document carries many, and refusing the whole document over one would
        // be wrong. It reports them separately instead, and a write naming one
        // must not be answered the same way as a write naming a key wz reads:
        // R2644's first draft collapsed the two and a test said so.
        // R2646 — `ignored` is now computed by `zenoh_config::honours_config_key`,
        // which is also what the DELETE half asks directly (it has no document to
        // partition). One definition, so the two halves of this gate cannot come
        // to disagree about which keys wz honours.
        if ingest.ignored.iter().any(|ignored| ignored == key) {
            return Err(ConfigKeyWriteError::NotHonoured {
                key: String::from(key),
            });
        }
        Ok(ingest)
    }

    /// The key-segment check both halves of the write gate apply, returning the
    /// split segments the set half then splices into its document.
    ///
    /// Shared rather than repeated because it is a SAFETY check on the set side
    /// (the segments are built INTO a JSON5 document, so a segment carrying a
    /// quote could close the object early) and the delete side takes the same
    /// key from the same wire. A delete builds no document, so the check is not
    /// load-bearing there in the same way — which is exactly why it would have
    /// been tempting to write a laxer one, and why there is only one.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn key_segments(key: &str) -> Result<Vec<&str>, ConfigKeyWriteError> {
        let segments: Vec<&str> = key.split('/').collect();
        if segments.is_empty()
            || segments
                .iter()
                .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err(ConfigKeyWriteError::MalformedKey {
                key: String::from(key),
            });
        }
        Ok(segments)
    }

    /// Delete ONE config key at runtime, the way upstream's admin DEL does —
    /// restoring it to the schema default.
    ///
    /// ⭐ WHY A RESTORE IS THE FAITHFUL READING OF A DELETE HERE, stated because
    /// R2644's note said the opposite and was right about a different subject.
    /// That note ("setting a key to its default is not removing it, so a delete
    /// needs the held document") is true when a config ROUND-TRIPS a document:
    /// there, removing a key and defaulting it differ observably, because the
    /// re-emitted document still shows the defaulted key. wz's live config is a
    /// struct of TYPED FIELDS with no absent state — there is no document to
    /// re-emit and no way to observe "present at the default" apart from "absent"
    /// — so in a typed config the entire observable content of a delete is that
    /// the key goes back to its default. Upstream agrees on what the NODE then
    /// does: its `config.remove(key)` drops the override so the default applies.
    ///
    /// ⚠ WHAT THIS DOES NOT COVER, named rather than left to be found: upstream
    /// tries `try_remove_json5_array_item(key)` FIRST and only then `remove`, so
    /// a key addressing ONE ELEMENT of an array is removable there and is not
    /// here — the same asymmetry the set half carries against
    /// `try_insert_json5_array_item`. Both halves are missing the array-item
    /// route, which makes it one gap in the array addressing of this seam rather
    /// than a property of the delete, and it is registered as such.
    ///
    /// The refusals are the set half's, in the set half's order, for the reason
    /// given at [`Self::set_by_key`]: an unhonoured key must not be answered as
    /// if wz acted on it, and a PUSH-discipline key must not be silently stored.
    /// `MalformedValue` alone cannot arise — a delete carries no value.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn remove_by_key(&mut self, key: &str) -> Result<(), ConfigKeyWriteError> {
        self.remove_by_key_with(key, &ConfigSinks::none())
    }

    /// R2654 — delete ONE config key at runtime, THROUGH the consumers that hold
    /// state compiled from it. The delete twin of [`Self::set_by_key_with`], and
    /// [`Self::remove_by_key`] is this function with an empty [`ConfigSinks`].
    ///
    /// The two halves stay one gate the way they already did: the same refusals
    /// in the same order, the same per-key table for the store, and now the same
    /// slice dispatch for the push. What differs is only the SOURCE of the value
    /// — `None`, meaning the schema default — which is the difference a delete
    /// IS.
    ///
    /// ⚠ IT SETTLES THE ACL SUBTREE, and R2654 had to lift that step out of the
    /// document apply to make it possible. Deleting `access_control/rules`
    /// stores an empty rule list; without the recompile the live policy would go
    /// on enforcing the rules that were just removed, which is a deletion that
    /// reports success and changes nothing an attacker would notice.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    pub fn remove_by_key_with(
        &mut self,
        key: &str,
        sinks: &ConfigSinks<'_>,
    ) -> Result<(), ConfigKeyWriteError> {
        let _ = Self::key_segments(key)?;
        if !crate::zenoh_config::honours_config_key(key) {
            return Err(ConfigKeyWriteError::NotHonoured {
                key: String::from(key),
            });
        }
        let row = RUNTIME_MUTABLE_CONFIG_KEYS
            .iter()
            .find(|row| row.key == key);
        let pushes = matches!(row, Some(r) if r.discipline == MutationDiscipline::Push);
        if pushes {
            let slice = row.expect("`pushes` is false without a row").slice;
            Self::push_slice_would_reach(slice, sinks).ok_or_else(|| {
                ConfigKeyWriteError::NeedsSink {
                    key: String::from(key),
                }
            })?;
        }
        let restore = if pushes { Some(self.clone()) } else { None };
        let acl_before = self.acl_snapshot();
        let mut applied: Vec<&'static str> = Vec::new();
        if let Some(row) = row {
            if self.apply_one_key(key, None) {
                applied.push(row.key);
            }
        }
        let settled = self.settle_acl_subtree(&mut applied, &acl_before);
        if applied.is_empty() {
            if let Some(previous) = restore {
                *self = previous;
            }
            return Err(if settled {
                ConfigKeyWriteError::NotRuntimeMutable {
                    key: String::from(key),
                }
            } else {
                ConfigKeyWriteError::SubtreeRefused {
                    key: String::from(key),
                }
            });
        }
        if pushes {
            let slice = row.expect("`pushes` is false without a row").slice;
            if let Err(err) = self.push_slice(slice, sinks, key) {
                if let Some(previous) = restore {
                    *self = previous;
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// One key of [`Self::apply_zenoh_config`]; `true` when the value landed.
    ///
    /// `source` is the document the value comes from. `None` means THE SCHEMA
    /// DEFAULT — the delete half, where upstream removes the override so the
    /// default applies again (`zenoh/src/net/runtime/adminspace.rs`
    /// @ `PushBody::Del(_) => {` reaching @ `config.remove(key)`).
    ///
    /// ⭐ THE TWO HALVES SHARE THIS ONE TABLE, and that is the design rather
    /// than a saving. R2646's first sketch was a second `reset_one_key` with
    /// the same key list, which is two tables that must agree about which keys
    /// exist — the shape this file already refuses for the runtime-mutable
    /// count. Sharing the arms means a new registry key gets its delete half
    /// from the same edit that gives it its set half, and it means
    /// `runtime_mutable_surface_gate.py`'s existing "every honoured row is
    /// named here" check covers BOTH halves without learning anything new.
    ///
    /// ⚠ The default is taken from [`Self::default`], not from a literal
    /// repeated here: that impl is where this crate states zenoh's defaults
    /// (its own doc names `PermissionsConf`'s read `true` / write `false`, and
    /// R2634 recorded that an empty weight list is upstream's default too). A
    /// literal here would be a third copy of a number nobody re-derives.
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
        source: Option<&crate::zenoh_config::ZenohConfigIngest>,
    ) -> bool {
        match key {
            #[cfg(feature = "adminspace-core")]
            "adminspace/permissions/read" => {
                self.admin_permissions.read = match source {
                    Some(ingest) => match ingest.config.adminspace {
                        Some(admin) => admin.read,
                        None => return false,
                    },
                    None => Self::default().admin_permissions.read,
                };
                true
            }
            #[cfg(feature = "adminspace-core")]
            "adminspace/permissions/write" => {
                self.admin_permissions.write = match source {
                    Some(ingest) => match ingest.config.adminspace {
                        Some(admin) => admin.write,
                        None => return false,
                    },
                    None => Self::default().admin_permissions.write,
                };
                true
            }
            #[cfg(feature = "routing-router-hat")]
            "routing/router/linkstate/transport_weights" => {
                self.router_link_weights = match source {
                    Some(ingest) => ingest.config.router_transport_weights.clone(),
                    None => Self::default().router_link_weights,
                };
                true
            }
            // R2650 — `low_pass_filter`, the first interceptor key with a reader.
            //
            // Gated on BOTH the module's feature and the rule type's, spelled
            // literally rather than inherited: `interceptor` is `routing-peer`
            // and `LowPassRule` is `access-quota`, and a build carrying one
            // without the other must not see this arm.
            //
            // This is where the document's spelling becomes the enforcement
            // type. It stays out of `ZenohNodeConfig` because that struct is
            // feature-INDEPENDENT -- the reader must read the same document to
            // the same values in every build -- and those two types are not.
            #[cfg(all(feature = "routing-peer", feature = "access-quota"))]
            "low_pass_filter" => {
                let confs = match source {
                    Some(ingest) => ingest.config.low_pass_filter.clone(),
                    // The schema default is NO filter, which is also what a real
                    // zenohd resolves a silent document to (it renders `[]`).
                    None => Vec::new(),
                };
                let mut rules = Vec::with_capacity(confs.len());
                for conf in &confs {
                    // Every literal was validated at PARSE, so none of these can
                    // be `None` here. Answering `false` rather than unwrapping
                    // keeps that an assertion about the reader instead of a
                    // panic in a running node if the two ever drift.
                    let (Some(messages), Some(flows), Some(links)) = (
                        conf.messages
                            .iter()
                            .map(|m| {
                                crate::interceptor::low_pass::LowPassMessage::from_upstream_str(m)
                            })
                            .collect::<Option<Vec<_>>>(),
                        conf.flows
                            .iter()
                            .map(|f| crate::interceptor::InterceptorFlow::from_upstream_str(f))
                            .collect::<Option<Vec<_>>>(),
                        conf.link_protocols
                            .iter()
                            .map(|l| wz_session_core::link::InterceptorLink::from_upstream_str(l))
                            .collect::<Option<Vec<_>>>(),
                    ) else {
                        return false;
                    };
                    rules.push(crate::interceptor::low_pass::LowPassRule {
                        key_exprs: conf.key_exprs.clone(),
                        max_payload_size: conf.size_limit as usize,
                        messages,
                        flows,
                        link_protocols: links,
                        interfaces: conf.interfaces.clone(),
                    });
                }
                self.interceptors.low_pass = rules;
                true
            }
            // R2651 — `downsampling`, the second interceptor key with a reader.
            //
            // The EXPANSION is what differs from its sibling: one document item
            // carries N rate rules and the axes they share, and each rule becomes
            // one wz rule with those axes copied onto it. Upstream's own shape —
            // the subject and kind selectors sit on the item, only the rate
            // varies per rule — so this is a re-spelling, not a reinterpretation.
            #[cfg(all(feature = "routing-peer", feature = "access-downsampling"))]
            "downsampling" => {
                let items = match source {
                    Some(ingest) => ingest.config.downsampling.clone(),
                    None => Vec::new(),
                };
                let mut rules = Vec::new();
                for item in &items {
                    let (Some(messages), Some(flows), Some(links)) = (
                        item.messages
                            .iter()
                            .map(|m| {
                                crate::interceptor::downsampling::DownsamplingMessage::from_upstream_str(m)
                            })
                            .collect::<Option<Vec<_>>>(),
                        item.flows
                            .iter()
                            .map(|f| crate::interceptor::InterceptorFlow::from_upstream_str(f))
                            .collect::<Option<Vec<_>>>(),
                        item.link_protocols
                            .iter()
                            .map(|l| {
                                wz_session_core::link::InterceptorLink::from_upstream_str(l)
                            })
                            .collect::<Option<Vec<_>>>(),
                    ) else {
                        return false;
                    };
                    for rule in &item.rules {
                        rules.push(crate::interceptor::downsampling::DownsamplingRule {
                            key_exprs: vec![rule.key_expr.clone()],
                            // `0.0` is DROP-ALL and a negative or non-finite rate
                            // is no throttle; both live in this one function, so
                            // the reader does not restate either edge.
                            min_interval: crate::interceptor::downsampling::interval_from_freq(
                                rule.freq,
                            ),
                            messages: messages.clone(),
                            flows: flows.clone(),
                            link_protocols: links.clone(),
                            interfaces: item.interfaces.clone(),
                        });
                    }
                }
                self.interceptors.downsampling = rules;
                true
            }
            // R2652 — the five `access_control/*` keys.
            //
            // ⭐ THESE ARMS STORE AND DO NOT COMPILE, which is the one thing
            // that separates them from their two interceptor siblings above.
            // The five are ONE document subtree that upstream compiles as a
            // unit, and this function is called once PER KEY, in the registry's
            // alphabetical order: `policies` lands before `rules` and
            // `subjects`, so a compile inside these arms would run three times
            // against a subtree naming ids that do not exist yet. The compile
            // is therefore one step at the end of `apply_zenoh_config`, where
            // the whole subtree has landed.
            //
            // ⚠ Each arm still writes only its OWN key's slice, for the reason
            // that function's doc gives: the parser fills an unnamed sibling
            // with a default, so assigning the whole `AclConfigInputs` from a
            // document that named one key would reset the other four.
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            "access_control/default_permission" => {
                self.acl_inputs.default_permission = match source {
                    Some(ingest) => ingest.config.access_control.default_permission.clone(),
                    None => Self::default().acl_inputs.default_permission,
                };
                true
            }
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            "access_control/enabled" => {
                self.acl_inputs.enabled = match source {
                    Some(ingest) => ingest.config.access_control.enabled,
                    // Upstream's `enabled` is a bare `bool` defaulting to FALSE,
                    // measured off a real zenohd rendering a document that never
                    // named the key.
                    None => false,
                };
                true
            }
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            "access_control/policies" => {
                self.acl_inputs.policies = match source {
                    Some(ingest) => ingest.config.access_control.policies.clone(),
                    None => Vec::new(),
                };
                true
            }
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            "access_control/rules" => {
                self.acl_inputs.rules = match source {
                    Some(ingest) => ingest.config.access_control.rules.clone(),
                    None => Vec::new(),
                };
                true
            }
            #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
            "access_control/subjects" => {
                self.acl_inputs.subjects = match source {
                    Some(ingest) => ingest.config.access_control.subjects.clone(),
                    None => Vec::new(),
                };
                true
            }
            _ => false,
        }
    }

    /// R2652 — recompile the live ACL slice from the retained document inputs,
    /// ATOMICALLY: on refusal the inputs go back to `restore` and nothing about
    /// the live policy moves.
    ///
    /// All-or-nothing because the subtree is all-or-nothing upstream: a
    /// `policy_information_point` that bails leaves `acl_interceptor_factories`
    /// bailing too, so no enforcer is built from a half-read subtree. Keeping
    /// the stored inputs in step with that means rolling them back, otherwise
    /// the retention would hold a document the live policy was never compiled
    /// from — the inert-mirror shape this field's own doc exists to prevent.
    ///
    /// `false` says the subtree was refused, which is how the caller knows not
    /// to report those keys as applied.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    fn recompile_acl(&mut self, restore: &crate::zenoh_config::AclConfigInputs) -> bool {
        match crate::zenoh_config::acl_config_from_inputs(&self.acl_inputs) {
            Ok(compiled) => {
                self.interceptors.acl = compiled.map(wz_access_control::AclPolicy::new);
                true
            }
            Err(_) => {
                self.acl_inputs = restore.clone();
                false
            }
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

    /// R2652 — a key wz KNOWS and deliberately does not honour, CHOSEN from the
    /// registry rather than spelled.
    ///
    /// Three tests wanted such a key and all three wrote `downsampling`. R2651
    /// honoured it; two of them went red and the third — which only asserts the
    /// two halves AGREE — went quietly vacuous, because both halves now answer
    /// `NeedsSink` and agreeing about the wrong thing still counts as agreeing.
    /// None of it surfaced, because the tests need `zenoh-config` plus an admin
    /// hat and no default lane compiles that.
    ///
    /// ⚠ The list is chained the way the acceptance boundary is, and the choice
    /// SKIPS any key that is runtime-mutable: `ingest_for_key` reports
    /// `NotHonoured` before it looks at discipline, so a push-discipline key
    /// would still answer `NotHonoured` here — and the DELETE half asks
    /// `honours_config_key` first and would too. Skipping them anyway keeps the
    /// fixture a key with ONE classification, which is what the caller's
    /// three-way distinction is about.
    ///
    /// ⚠ Gated as the UNION of its callers, not as its own dependencies. Both
    /// are `zenoh-config` plus `adminspace-core`, and gate 2h found the shorter
    /// `#[cfg]` by compiling a leg that has the first and not the second: this
    /// crate denies dead code, so a helper compiled where no caller is becomes
    /// a build error rather than a warning.
    ///
    /// ⛔ THE SCAN ITSELF LIVES IN `zenoh_config`, and that is not tidiness.
    /// `unhonoured_kind_evidence_gate.py` treats any file whose CODE names an
    /// `UNHONOURED_*` constant as an ENUMERATOR and drops it from the citation
    /// sweep — so reading the list here would have silently removed this file
    /// from a gate that reads it. The module that DEFINES the lists is already
    /// excluded, so the scan costs nothing there.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    fn a_known_but_unhonoured_key() -> &'static str {
        crate::zenoh_config::first_unhonoured_key_outside(
            &RUNTIME_MUTABLE_CONFIG_KEYS
                .iter()
                .map(|row| row.key)
                .collect::<Vec<_>>(),
        )
    }

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
            ConfigKeyWriteError::MalformedValue {
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
                    Err(ConfigKeyWriteError::MalformedKey { .. })
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
            Err(ConfigKeyWriteError::Document(_))
        ));

        // Known and deliberately NOT honoured: the reader accepts the document
        // — a stock zenoh file carries many such keys — and reports it ignored.
        //
        // ⛔ THE KEY IS DERIVED, NOT NAMED, and R2652 rewrote it that way after
        // paying for the literal. This line said `downsampling` from R2644
        // until R2651 HONOURED that key, at which point the case stopped being
        // "known and unhonoured" and started being "push-discipline", and this
        // assertion went red — on a feature combination no default lane
        // compiles, so nothing said so for a round. A literal here is a
        // CLASSIFICATION, and the next honouring round invalidates it again.
        let ignored = a_known_but_unhonoured_key();
        assert_eq!(
            cfg.set_by_key(ignored, "[]"),
            Err(ConfigKeyWriteError::NotHonoured {
                key: String::from(ignored)
            })
        );

        // Honoured at startup, not runtime-mutable: accepted, read, unapplied.
        assert_eq!(
            cfg.set_by_key("mode", r#""router""#),
            Err(ConfigKeyWriteError::NotRuntimeMutable {
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
            ConfigKeyWriteError::NeedsSink {
                key: String::from("routing/router/linkstate/transport_weights")
            }
        );
        assert_eq!(
            cfg.router_link_weights.len(),
            before,
            "nothing was stored — including a row set reconfigure_* would refuse"
        );
    }

    /// R2646 — the DELETE half restores the schema default, and it is measured
    /// as a RESTORE rather than as "the value we happened to write is gone".
    ///
    /// ⭐ The fixture moves the key AWAY from its default first, and the
    /// assertion is against [`WzConfig::default`] rather than against the
    /// literal `true`. A test asserting the literal would still pass if
    /// `apply_one_key`'s delete arm were rewired to any other source that
    /// happened to yield `true` — including the value already there, which is
    /// the one wrong behaviour a delete can have (doing nothing and reporting
    /// success). Reading the default through the same accessor the production
    /// arm reads it through is what makes this a property rather than a
    /// coincidence.
    ///
    /// The anti-vacuity half is the `assert_ne!`: if the write never moved the
    /// value off its default, the restore assertion would hold for a
    /// `remove_by_key` that did nothing at all.
    #[cfg(all(feature = "zenoh-config", feature = "adminspace-core"))]
    #[test]
    fn a_delete_restores_the_schema_default() {
        let mut cfg = WzConfig::new();
        let schema_default = WzConfig::default().admin_permissions().read;

        cfg.set_by_key("adminspace/permissions/read", "false")
            .expect("the read permission is runtime-mutable");
        assert_ne!(
            cfg.admin_permissions().read,
            schema_default,
            "the fixture must first move the key OFF its default, or the \
             restore below proves nothing"
        );

        cfg.remove_by_key("adminspace/permissions/read")
            .expect("a runtime-mutable honoured key can be deleted");
        assert_eq!(
            cfg.admin_permissions().read,
            schema_default,
            "a delete restores the key to the schema default — upstream drops \
             the override so the default applies again"
        );
    }

    /// R2646 — a PLUGIN config write is REFUSED, by both halves, rather than
    /// applied without a validator.
    ///
    /// ⭐ THIS TEST EXISTS TO PIN A REFUTATION, so that it is falsifiable code
    /// rather than a paragraph. `adminspace-write`'s reason has carried a
    /// residual since 1.5.0 saying "upstream routes every config write through
    /// the ConfigValidator seam before mutating and wz applies unvalidated".
    /// MEASURED at the pin, the first half is false: that seam is reachable
    /// ONLY through the plugins field — both of its call sites are inside
    /// `commons/zenoh-config/src/lib.rs` @ `impl PluginsConfig`, one in
    /// @ `pub fn remove(&mut self, key: &str) -> ZResult<()> {` and one in the
    /// `ValidatedMap` insert, each keyed by a plugin NAME and delegating to
    /// that started plugin's own `config_checker`. A write to
    /// `adminspace/permissions/read` passes no validator upstream either.
    ///
    /// So the comparison the residual draws has no subject here: wz does not
    /// honour `plugins` at all (it is in `UNHONOURED_UPSTREAM_CONFIG_KEYS`, with
    /// its own `PluginRegistry` cited as what wz has instead), and a write
    /// naming it is refused BY NAME. Refusing is not the same as applying
    /// unvalidated — it is strictly more conservative.
    ///
    /// ⚠ What this test does NOT claim: that wz could not one day want such a
    /// hook. The day `plugins` becomes honoured, this test reds — which is the
    /// point of pinning it here rather than writing it down.
    ///
    /// Gated exactly as its SUBJECT is: `set_by_key` / `remove_by_key` live
    /// behind this cfg, so a test naming them without it does not compile on a
    /// build that elides them. Gate 2h found this by running a leg that does.
    #[cfg(all(
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    #[test]
    fn a_plugin_config_write_is_refused_rather_than_applied_unvalidated() {
        let key = "plugins/rest/http_port";
        assert_eq!(
            WzConfig::new()
                .set_by_key(key, "8000")
                .expect_err("wz does not honour plugin config"),
            ConfigKeyWriteError::NotHonoured {
                key: String::from(key)
            },
            "a plugin config WRITE is refused by name, not applied unvalidated"
        );
        assert_eq!(
            WzConfig::new()
                .remove_by_key(key)
                .expect_err("nor can it be deleted"),
            ConfigKeyWriteError::NotHonoured {
                key: String::from(key)
            },
            "and so is the DELETE — upstream's validator covers its remove path \
             too, so a delete that slipped through would be the same gap"
        );
    }

    /// R2646 — the delete half refuses exactly what the set half refuses, and
    /// by the same names.
    ///
    /// This is the test that would catch the two halves drifting: it drives the
    /// SAME three keys through BOTH entry points and asserts the refusals match
    /// pairwise. A delete that quietly accepted an unhonoured key — or that
    /// stored a push-discipline key the set half refuses to store — would be a
    /// second, laxer write path into the same config, reachable from the same
    /// wire by changing one message kind.
    ///
    /// ⚠ R2652 CORRECTING R2646, which wrote here that "`downsampling` is
    /// push-discipline AND unhonoured, so it is the key that tells
    /// `NotHonoured` from `NeedsSink`". R2651 honoured that key, so the row
    /// became a SECOND push-discipline case and this loop stopped covering the
    /// unhonoured one at all — without failing, because a test that asserts two
    /// halves AGREE goes on passing when they agree about something else.
    /// That is the sharper half of the lesson: the vacuity was invisible where
    /// the set half's own red was merely unrun.
    ///
    /// The unhonoured row is DERIVED now — see [`a_known_but_unhonoured_key`] —
    /// and the loop asserts each row lands on the refusal it was chosen for, so
    /// a row drifting into another classification reds instead of going quiet.
    #[cfg(all(
        feature = "zenoh-config",
        feature = "adminspace-core",
        feature = "routing-router-hat"
    ))]
    #[test]
    fn the_delete_half_refuses_what_the_set_half_refuses() {
        let ignored = a_known_but_unhonoured_key();
        for (key, value, expected) in [
            // Malformed: a segment outside `[A-Za-z0-9_]`.
            (
                "adminspace/permissions/re-ad",
                "true",
                ConfigKeyWriteError::MalformedKey {
                    key: String::from("adminspace/permissions/re-ad"),
                },
            ),
            // Known, deliberately unhonoured.
            (
                ignored,
                "[]",
                ConfigKeyWriteError::NotHonoured {
                    key: String::from(ignored),
                },
            ),
            // Honoured and runtime-mutable, but PUSH discipline.
            (
                "routing/router/linkstate/transport_weights",
                "[]",
                ConfigKeyWriteError::NeedsSink {
                    key: String::from("routing/router/linkstate/transport_weights"),
                },
            ),
        ] {
            let set = WzConfig::new()
                .set_by_key(key, value)
                .expect_err("the set half refuses this key");
            let del = WzConfig::new()
                .remove_by_key(key)
                .expect_err("so must the delete half");
            assert_eq!(
                set, del,
                "the two halves of ONE write gate must refuse '{key}' identically"
            );
            assert_eq!(
                set, expected,
                "'{key}' is in this loop to cover ONE refusal and it is \
                 answering a different one — the row has drifted into another \
                 classification and the loop has stopped covering the first"
            );
        }
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

    /// R2654 — the INTERCEPTOR slice reached by a keyed write, which is the half
    /// of this round the weights slice cannot grade.
    ///
    /// Seven of the eight push-discipline keys land here and they share ONE
    /// consumer, so this is where "dispatch is by slice, not by key" is either
    /// true or a sentence. It is also the only slice with a SUBTREE: the five
    /// `access_control/*` keys compile as a unit, which a per-key write makes
    /// visible in a way a whole-document apply never did.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "zenoh-config",
        any(feature = "adminspace-core", feature = "routing-router-hat")
    ))]
    mod interceptor_slice_writes {
        use super::*;
        use std::cell::RefCell;

        /// Records every interceptor config handed to it.
        struct RecordingInterceptorSink {
            installs: RefCell<Vec<InterceptorConfig>>,
        }

        impl RecordingInterceptorSink {
            fn new() -> Self {
                Self {
                    installs: RefCell::new(Vec::new()),
                }
            }
            fn last_rule_count(&self) -> Option<usize> {
                self.installs
                    .borrow()
                    .last()
                    .map(|c| c.acl.as_ref().map_or(0, |p| p.rules().len()))
            }
        }

        impl InterceptorSink for RecordingInterceptorSink {
            fn set_interceptors(&self, config: InterceptorConfig) {
                self.installs.borrow_mut().push(config);
            }
        }

        /// Write the four keys a one-rule policy needs, in the order the subtree
        /// admits: the named entries before the policy that names them.
        fn install_a_one_rule_policy(
            cfg: &mut WzConfig,
            sinks: &ConfigSinks<'_>,
        ) -> Result<(), ConfigKeyWriteError> {
            cfg.set_by_key_with("access_control/enabled", "true", sinks)?;
            cfg.set_by_key_with(
                "access_control/rules",
                r#"[{ id: "r1", key_exprs: ["demo/**"], messages: ["put"],
                      permission: "deny" }]"#,
                sinks,
            )?;
            cfg.set_by_key_with("access_control/subjects", r#"[{ id: "s1" }]"#, sinks)?;
            cfg.set_by_key_with(
                "access_control/policies",
                r#"[{ rules: ["r1"], subjects: ["s1"] }]"#,
                sinks,
            )
        }

        /// R2654 — an ACL policy built over the wire, key by key, reaches the
        /// live interceptor stack.
        #[test]
        fn the_acl_subtree_is_writable_one_key_at_a_time() {
            let sink = RecordingInterceptorSink::new();
            let sinks = ConfigSinks::none().with_interceptors(&sink);
            let mut cfg = WzConfig::new();
            assert_eq!(install_a_one_rule_policy(&mut cfg, &sinks), Ok(()));
            // TWO, not one, and the fixture's own name says "one rule" about
            // the DOCUMENT rather than the compiled form: the rule leaves
            // `flows` absent, which upstream resolves to both directions, and an
            // `AclRule` carries a single flow. So one document rule times two
            // flows is two compiled rules. The first cut of this test asserted
            // 1 and the expansion was right.
            assert_eq!(
                cfg.interceptors().acl.as_ref().map(|p| p.rules().len()),
                Some(2),
                "the four writes compiled to the policy they describe"
            );
            #[cfg(feature = "config-mutate-runtime")]
            assert_eq!(
                sink.last_rule_count(),
                Some(2),
                "and the CONSUMER holds it -- the seven interceptor keys share \
                 one sink, so this is the slice dispatch working"
            );
        }

        /// ⭐ R2654 — THE HAZARD THE WIDENING CREATED, and the reason
        /// `settle_acl_subtree` had to be lifted out of the document apply.
        ///
        /// A delete stores new inputs through `apply_one_key`. Until this round
        /// the subtree compile lived in `apply_zenoh_config`, which a delete
        /// never reached — because a delete refused every push key before it got
        /// there. Give the delete half a sink without moving that step and this
        /// delete reports success while the live policy goes on enforcing the
        /// rules that were just removed.
        ///
        /// ⚠ IT DELETES THE POLICY, NOT THE RULE SET, and that is a measurement
        /// rather than a convenience. Deleting `access_control/rules` first
        /// leaves `policies` naming an id nothing defines, so the subtree does
        /// not compile and the write is refused as `SubtreeRefused` — which is
        /// upstream's answer to the same document and is asserted in its own
        /// test below. The JOIN is what this one grades, so it takes the delete
        /// that leaves a compilable subtree.
        #[test]
        fn deleting_a_policy_recompiles_the_live_rule_set() {
            let sink = RecordingInterceptorSink::new();
            let sinks = ConfigSinks::none().with_interceptors(&sink);
            let mut cfg = WzConfig::new();
            install_a_one_rule_policy(&mut cfg, &sinks).expect("the policy installs");

            assert_eq!(
                cfg.remove_by_key_with("access_control/policies", &sinks),
                Ok(())
            );
            assert_eq!(
                cfg.interceptors().acl.as_ref().map(|p| p.rules().len()),
                Some(0),
                "the deleted policy left the LIVE rule set, not only the stored \
                 inputs -- a delete that reported success and changed nothing an \
                 attacker would notice is the defect this asserts against"
            );
            #[cfg(feature = "config-mutate-runtime")]
            assert_eq!(
                sink.last_rule_count(),
                Some(0),
                "and the consumer was handed the emptied policy"
            );
        }

        /// R2654 — deleting one entry of the subtree while another still names
        /// it is refused, and refused as a SUBTREE.
        ///
        /// The pair with the test above: same seam, same sink, and the delete
        /// that cannot leave a compilable subtree is the one that is refused. A
        /// delete allowed here would install a policy whose rule ids resolve to
        /// nothing, which is the document upstream's `init` bails on.
        #[test]
        fn deleting_a_rule_set_a_policy_still_names_is_refused() {
            let sink = RecordingInterceptorSink::new();
            let sinks = ConfigSinks::none().with_interceptors(&sink);
            let mut cfg = WzConfig::new();
            install_a_one_rule_policy(&mut cfg, &sinks).expect("the policy installs");

            assert_eq!(
                cfg.remove_by_key_with("access_control/rules", &sinks),
                Err(ConfigKeyWriteError::SubtreeRefused {
                    key: String::from("access_control/rules")
                })
            );
            assert_eq!(
                cfg.interceptors().acl.as_ref().map(|p| p.rules().len()),
                Some(2),
                "and the refused delete left the live policy exactly as it was"
            );
        }

        /// R2654 — a write that is well formed, runtime-mutable and STILL
        /// refused, because the subtree it lands in does not compile.
        ///
        /// It answers by its own name. `NotRuntimeMutable` is what this used to
        /// say, and it is false twice over: the key is runtime-mutable and the
        /// value is fine. What an operator has to be told is the ORDER -- the
        /// named entries before the policy naming them, which is upstream's own
        /// demand of a whole document.
        #[test]
        fn a_policy_naming_nothing_yet_is_refused_as_a_subtree_not_as_a_key() {
            let sink = RecordingInterceptorSink::new();
            let sinks = ConfigSinks::none().with_interceptors(&sink);
            let mut cfg = WzConfig::new();
            cfg.set_by_key_with("access_control/enabled", "true", &sinks)
                .expect("the switch goes first and stands alone");
            assert_eq!(
                cfg.set_by_key_with(
                    "access_control/policies",
                    r#"[{ rules: ["r1"], subjects: ["s1"] }]"#,
                    &sinks,
                ),
                Err(ConfigKeyWriteError::SubtreeRefused {
                    key: String::from("access_control/policies")
                })
            );
            // ⚠ `acl` is SOME here and that is right: `enabled: true` with no
            // rules is a real policy -- it imposes `default_permission` on every
            // message -- so the switch landing is not the same as the policy
            // landing. What the refused write must not have done is add a rule.
            assert_eq!(
                cfg.interceptors().acl.as_ref().map(|p| p.rules().len()),
                Some(0),
                "the refused write installed no rule; the enabled-and-empty \
                 policy is what the switch alone already meant"
            );
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

        /// R2648 — THE JOIN a runtime config-key write adds, and the one thing
        /// neither end's tests can see.
        ///
        /// Both ends were already covered: [`WzConfig::ingest_for_key`] is the
        /// reader's own acceptance path, and `reconfigure_router_link_weights`
        /// has the two tests above. What nothing asserted is that the rows a
        /// WIRE VALUE names are the rows the sink is handed — and this tree has
        /// paid repeatedly for assuming a join because both of its ends hold.
        ///
        /// Anti-vacuity is the point of comparing the rows to literals rather
        /// than to `is_empty()`: the parse yielding NOTHING would satisfy a
        /// weaker assertion while proving the opposite of this one, because an
        /// empty list is a legitimate value here ("weight nothing").
        #[cfg(all(
            feature = "zenoh-config",
            any(feature = "adminspace-core", feature = "routing-router-hat")
        ))]
        #[test]
        fn a_wire_value_for_the_weights_key_reaches_the_sink_through_the_front_end() {
            let ingest = WzConfig::ingest_for_key(
                "routing/router/linkstate/transport_weights",
                r#"[{ dst_zid: "aa", weight: 250 }, { dst_zid: "bb", weight: 7 }]"#,
            )
            .expect("the reader honours this key");
            let rows = ingest.config.router_transport_weights;
            assert_eq!(
                rows,
                vec![row(0xAA, 250), row(0xBB, 7)],
                "the rows carry the values the wire named, in the order it named them"
            );

            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new();
            let moved = cfg.reconfigure_router_link_weights(rows, &sink);
            // ⚠ R2652 — THE SINK HALF IS FEATURE-SPLIT, and this test asserted
            // only the `config-mutate-runtime` arm while its own `#[cfg]` did
            // not require that feature: without it `reconfigure_*` stores the
            // rows and drives NOTHING, by design, so the assertion was red on
            // every build that compiled the test and lacked the feature.
            // Invisible because no default lane compiles this pair.
            //
            // ⛔ Both arms are spelled LITERALLY rather than folded into one
            // expression keyed off the feature. A conditional expectation reads
            // as the same assertion in both builds while asserting whatever the
            // code does, which is the shape that let this sit red.
            #[cfg(feature = "config-mutate-runtime")]
            {
                assert_eq!(moved, Ok(true), "the sink reports the link moved");
                assert_eq!(sink.calls(), 1, "the sink is driven exactly once");
            }
            #[cfg(not(feature = "config-mutate-runtime"))]
            {
                assert_eq!(
                    moved,
                    Ok(false),
                    "without the runtime-mutate feature there is no live \
                     re-apply, so nothing moved"
                );
                assert_eq!(sink.calls(), 0, "and the sink is not driven at all");
            }
            // Unconditional: the rows are STORED either way, which is the half
            // of the join this test is named for.
            assert_eq!(
                cfg.router_link_weights(),
                &[row(0xAA, 250), row(0xBB, 7)],
                "and the live rows are what the wire asked for"
            );
        }

        /// R2654 — THE RESIDUAL THIS ATOM IS GRADED ON, in one test: a
        /// push-discipline key written over the wire lands AND reaches its
        /// consumer, because the write was given one.
        ///
        /// Before this round `set_by_key` answered `NeedsSink` for eight of the
        /// ten registry rows, which left the admin write surface two booleans
        /// wide against upstream's whole document. The arms below are the two
        /// halves of that: the same key, the same value, once with a consumer
        /// and once without.
        #[cfg(all(
            feature = "zenoh-config",
            any(feature = "adminspace-core", feature = "routing-router-hat")
        ))]
        #[test]
        fn a_push_key_is_writable_when_the_write_is_given_its_consumer() {
            const KEY: &str = "routing/router/linkstate/transport_weights";
            const VALUE: &str = r#"[{ dst_zid: "aa", weight: 250 }]"#;

            // WITH the consumer: stored and driven.
            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new();
            let sinks = ConfigSinks::none().with_router_link_weights(&sink);
            assert_eq!(cfg.set_by_key_with(KEY, VALUE, &sinks), Ok(()));
            assert_eq!(
                cfg.router_link_weights(),
                &[row(0xAA, 250)],
                "the wire's rows are the live rows"
            );
            #[cfg(feature = "config-mutate-runtime")]
            assert_eq!(sink.calls(), 1, "and the consumer was driven, exactly once");
            #[cfg(not(feature = "config-mutate-runtime"))]
            assert_eq!(
                sink.calls(),
                0,
                "without the runtime-mutate feature the store is the whole of it"
            );

            // WITHOUT it: refused by name, and NOTHING stored. The second half
            // is the one that matters -- a refusal that had already written the
            // value would be the half-applied state the old blanket refusal
            // existed to prevent.
            let mut bare = WzConfig::new();
            assert_eq!(
                bare.set_by_key(KEY, VALUE),
                Err(ConfigKeyWriteError::NeedsSink {
                    key: String::from(KEY)
                })
            );
            assert!(
                bare.router_link_weights().is_empty(),
                "a NeedsSink refusal leaves the config exactly as it was"
            );
        }

        /// R2654 — a value the CONSUMER refuses is refused by name and leaves
        /// nothing behind.
        ///
        /// Two rows naming one destination is the one such value today. The
        /// reader ACCEPTS the document on purpose -- upstream's parser does too,
        /// and a wz node validates documents destined for other nodes -- so this
        /// is the seam where it is caught, exactly where upstream catches it
        /// while building its network.
        ///
        /// ⚠ THE SECOND ASSERTION IS THE POINT. `reconfigure_*` validates before
        /// IT commits, but the value is already stored by the time the push
        /// runs, so without the snapshot this refusal would leave the duplicate
        /// rows live and report an error about them.
        #[cfg(all(
            feature = "zenoh-config",
            any(feature = "adminspace-core", feature = "routing-router-hat")
        ))]
        #[test]
        fn a_value_the_consumer_refuses_is_named_and_rolled_back() {
            const KEY: &str = "routing/router/linkstate/transport_weights";
            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new().with_router_link_weights(vec![row(0xAA, 250)]);
            let sinks = ConfigSinks::none().with_router_link_weights(&sink);
            assert_eq!(
                cfg.set_by_key_with(
                    KEY,
                    r#"[{ dst_zid: "cc", weight: 1 }, { dst_zid: "cc", weight: 2 }]"#,
                    &sinks,
                ),
                Err(ConfigKeyWriteError::ConsumerRefused {
                    key: String::from(KEY)
                })
            );
            assert_eq!(
                cfg.router_link_weights(),
                &[row(0xAA, 250)],
                "the refused rows did not become live, and the previous ones \
                 are still there"
            );
        }

        /// R2654 — the DELETE half reaches its consumer too, and restores the
        /// schema default.
        ///
        /// It is here rather than beside the set half because the two are one
        /// gate and this is what says so: the same key, the same sink, the same
        /// slice dispatch, and the only difference is that the value comes from
        /// `WzConfig::default` instead of from the wire.
        #[cfg(all(
            feature = "zenoh-config",
            any(feature = "adminspace-core", feature = "routing-router-hat")
        ))]
        #[test]
        fn the_delete_half_reaches_the_consumer_as_the_set_half_does() {
            const KEY: &str = "routing/router/linkstate/transport_weights";
            let sink = RecordingSink::new(true);
            let mut cfg = WzConfig::new().with_router_link_weights(vec![row(0xAA, 250)]);
            let sinks = ConfigSinks::none().with_router_link_weights(&sink);
            assert_eq!(cfg.remove_by_key_with(KEY, &sinks), Ok(()));
            assert!(
                cfg.router_link_weights().is_empty(),
                "the schema default for this key is no weights at all"
            );
            #[cfg(feature = "config-mutate-runtime")]
            assert_eq!(
                sink.last().len(),
                0,
                "and the consumer was handed the EMPTY map, not left holding \
                 the deleted row"
            );
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
