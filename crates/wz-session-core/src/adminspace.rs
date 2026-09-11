// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Admin space `local_data` — the `@/<zid>/<whatami>` introspection view the
//! built-in admin queryable replies with. The wz mirror of zenoh
//! `zenoh/src/net/runtime/adminspace.rs` @ `fn local_data` + the
//! `@/<zid>/<whatami>/**` queryable keyexpr (`AdminSpace::start`,
//! `adminspace.rs:159,341`).
//!
//! Scope (`adminspace-core`, §5.23): the built-in queryable keyexpr helpers +
//! the `local_data` JSON body. The per-entity handlers
//! (subscriber/publisher/queryable/queriers, `adminspace.rs:741+`), the
//! `metrics` OpenMetrics export (`:706`), the `permissions.read` GET gate
//! (`:457`), the `config/**` write path (`:392`), and the router
//! `linkstate` / `route/successor` handlers are SEPARATE catalog atoms
//! (`adminspace-read` / `-write` / `-introspection-handlers` / `-metrics`)
//! layered ON this core — NOT part of it.
//!
//! zenoh's `AdminSpace` is owned by the `Runtime` (which holds the transport
//! manager, the listening locators, and every transport), so `local_data` is a
//! runtime-wide view. wz is session-centric: the node context (`version`,
//! listening `locators`) is owned by the runtime / embedder that opens the
//! session — exactly as zenoh's `Runtime` passes `version` into
//! `AdminSpace::start` (`adminspace.rs:155`) — and is supplied here rather than
//! read off the `Session`. The `sessions` array is the connected peer(s) the
//! session knows (`SessionLinkActions::peer_zid`), the session-centric mirror of
//! zenoh's `get_transports_unicast()` enumeration (`adminspace.rs:664`).
//!
//! The serializer is manual (no `serde_json`) so the builder stays `alloc`-only
//! and no_std-feasible (R311xu scoped adminspace-core's data paths as
//! no_std-feasible) while emitting the same key set a zenoh admin client expects.

use alloc::string::String;
use alloc::vec::Vec;

/// One link of a connected transport — the `{src,dst}` pair zenoh's
/// `link_to_json` emits (`adminspace.rs:608-613`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminLink {
    /// Local link endpoint (`Link::src`).
    pub src: String,
    /// Remote link endpoint (`Link::dst`).
    pub dst: String,
}

/// One connected peer — a `sessions[]` entry, the session-centric mirror of
/// zenoh's `transport_unicast_to_json` (`adminspace.rs:607-637`). `whatami` is
/// `None` when the peer's role is not known (rendered as zenoh's `"unknown"`
/// fallback, `:630`). The `weight` zenoh carries (`:632`) is a router-linkstate
/// value, always `null` at this core (a router-mode follow-up atom).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminSession {
    /// The peer's zid in zenoh `ZenohId` Display form
    /// (`crate::zid_hex::zid_to_zenoh_hex`).
    pub peer_zid_hex: String,
    /// The peer's role string (`WhatAmI::to_str`), or `None` → `"unknown"`.
    pub whatami: Option<String>,
    /// The transport's links.
    pub links: Vec<AdminLink>,
    /// R2415 (open-debt items 675/678) — whether this transport negotiated SHM,
    /// the pin's `shm` field (`transport.is_shm()` at `transport_unicast_to_json`).
    ///
    /// UNGATED, and for the reason [`AdminAnswerCtx::stats`] records: a
    /// `#[cfg]`-gated pub struct field forces a matching `#[cfg]` at every
    /// construction site, and this tree has already been bitten by that when one
    /// of those sites was a demo crate with no such feature of its own. Upstream
    /// makes the same call from the other direction — it computes `shm` under
    /// `shared-memory` and binds `false` without it, so the FIELD is
    /// unconditional there too and only the VALUE is gated. A build without
    /// `transport-shm` reports `false`, which is what it means.
    pub shm: bool,
}

/// wz-native plugin state — the compile-time analogue of zenoh's `PluginState`
/// (`zenoh-plugin-trait/src/plugin.rs:35-40`). wz has NO dynamic loading, so a
/// subsystem's presence IS its compiled-in-ness: a compiled subsystem is at least
/// [`Loaded`](Self::Loaded), and [`Started`](Self::Started) once the node
/// activates it at runtime. [`Declared`](Self::Declared) — zenoh's
/// config-named-but-unloaded state — has no wz analogue (presence == compiled;
/// there is no "named but absent"), but the variant is retained for wire fidelity
/// with zenoh's serde enum so an admin client parses the same `state` strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPluginState {
    /// Config-named but not loaded (zenoh). wz never emits this (kept for parity).
    Declared,
    /// Compiled into the binary but not activated at runtime.
    Loaded,
    /// Compiled into the binary AND activated at runtime.
    Started,
}

impl AdminPluginState {
    /// The zenoh serde variant name (capitalized — `serde` serializes the variant
    /// name verbatim, `plugin.rs:35-40`): `"Declared"` / `"Loaded"` / `"Started"`.
    /// Consumed only by [`AdminPlugin::to_status_json`] (gated the same way).
    #[cfg(feature = "adminspace-plugins-handlers")]
    fn as_str(self) -> &'static str {
        match self {
            AdminPluginState::Declared => "Declared",
            AdminPluginState::Loaded => "Loaded",
            AdminPluginState::Started => "Started",
        }
    }
}

/// The wz-native `"__static__"` plugin path marker — the honest superset over
/// zenoh's dylib path (`PluginStatus::path`, `plugin.rs:83`). zenoh reports a
/// loaded plugin's `.so` filesystem path (or `"__not_loaded__"` when unloaded,
/// `manager/dynamic_plugin.rs:149-155`); wz subsystems are STATICALLY linked
/// (composed at build time, no dlopen — cf. `wz-rest`'s "compile-time-composed
/// superset of zenoh's zenoh-plugin-rest"), so there is no dylib path. The marker
/// mirrors the form of zenoh's `"__not_loaded__"` sentinel.
pub const WZ_STATIC_PLUGIN_PATH: &str = "__static__";

/// One leaf of a plugin's OWN admin sub-tree, below
/// `@/<zid>/<whatami>/status/plugins/<id>` — the wz analogue of a single
/// `Response` a zenoh plugin returns from `PluginControl::adminspace_getter`,
/// which the adminspace dispatches at
/// `zenoh/src/net/runtime/adminspace.rs` @ `adminspace_getter` and replies
/// as `serde_json::to_vec(&response.value)` with `APPLICATION_JSON` (`:992-996`).
///
/// The wz shape is a SNAPSHOT rather than a callback because wz's plugins are
/// compiled-in subsystems, not `dyn PluginControl` objects: the host already
/// rebuilds its `&[AdminPlugin]` slice inside the admin handler, once per GET, so
/// a snapshot taken there is exactly as live as upstream's pull and cannot be
/// served from a moment other than the one the rest of the reply came from. What
/// upstream gets from the getter's `key_expr` argument — serving only the leaves
/// the GET asks for — wz gets from the same per-leaf intersection test every
/// other admin leg uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPluginStatusLeaf {
    /// The key suffix BELOW the plugin's status root, with no leading `/`
    /// (e.g. `"version"`, `"volumes/mem"`, `"storages/s1"`). The full reply key is
    /// `@/<zid>/<whatami>/status/plugins/<id>/<suffix>`.
    pub suffix: String,
    /// The already-serialized JSON body, replied verbatim as `APPLICATION_JSON`.
    /// Pre-rendered rather than a typed value because the leaf bodies are
    /// subsystem-specific (a volume's capability, a storage's config) and this
    /// core has no business knowing their shapes — the subsystem that owns the
    /// state owns its rendering.
    pub json_body: String,
}

impl AdminPluginStatusLeaf {
    /// A leaf at `suffix` carrying `json_body`.
    pub fn new(suffix: impl Into<String>, json_body: impl Into<String>) -> Self {
        Self {
            suffix: suffix.into(),
            json_body: json_body.into(),
        }
    }
}

/// One entry in the wz-native plugin registry — the compile-time analogue of a
/// zenoh `PluginStatusRec` (`zenoh-plugin-trait/src/plugin.rs:92-102`). A wz
/// "plugin" is a COMPILED-IN composable subsystem with a zenoh-plugin analogue
/// (`storage_manager` = zenoh-plugin-storage-manager; `rest` = zenoh-plugin-rest),
/// NOT a dlopen shared library — the wz "superset via composition": the same admin
/// wire shape, sourced from the cargo-feature/subsystem registry instead of a
/// `PluginsManager`. ALWAYS compiled (like [`AdminSession`]) so
/// [`answer_admin_query`]'s slice parameter is signature-stable across the
/// `adminspace-plugins-handlers` toggle; only the reply BLOCKS that consume it are
/// `#[cfg]`-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPlugin {
    /// The plugin id (zenoh `PluginStatus::id`) — the registry key + reply-key leaf.
    pub id: String,
    /// The human plugin name (zenoh `PluginStatus::name`); wz uses the same string.
    pub name: String,
    /// The plugin version (zenoh `PluginStatus::version`, `Option`) — the node's
    /// build version for a static wz subsystem. `None` → the `version` key is
    /// OMITTED from the status body (zenoh's `skip_serializing_if`).
    pub version: Option<String>,
    /// The plugin path — [`WZ_STATIC_PLUGIN_PATH`] for a static wz subsystem.
    pub path: String,
    /// Compiled-in / activated state.
    pub state: AdminPluginState,
    /// This plugin's OWN admin sub-tree (surface C below `__path__`) — the wz
    /// analogue of what zenoh's `adminspace_getter` returns for this plugin. Empty
    /// for a subsystem that publishes no state of its own, which is the honest
    /// default: a plugin the node cannot introspect must answer nothing rather
    /// than an empty object that a client would read as "introspected, and empty".
    /// Served only when the plugin is [`Started`](AdminPluginState::Started), the
    /// same gate `__path__` is behind.
    pub status_leaves: Vec<AdminPluginStatusLeaf>,
}

impl AdminPlugin {
    /// Build a static wz-subsystem plugin entry: [`path`](Self::path) =
    /// [`WZ_STATIC_PLUGIN_PATH`]. `version` is the node build version (or `None`).
    /// No status sub-tree — add one with
    /// [`with_status_leaves`](Self::with_status_leaves).
    pub fn wz_static(id: &str, name: &str, version: Option<&str>, state: AdminPluginState) -> Self {
        Self {
            id: String::from(id),
            name: String::from(name),
            version: version.map(String::from),
            path: String::from(WZ_STATIC_PLUGIN_PATH),
            state,
            status_leaves: Vec::new(),
        }
    }

    /// Attach this plugin's admin sub-tree (surface C). Builder-form rather than a
    /// setter so a host composes the record in one expression at the point it
    /// takes the snapshot, which is the only point where the leaves are known to
    /// match the state the rest of the record reports.
    pub fn with_status_leaves(mut self, leaves: Vec<AdminPluginStatusLeaf>) -> Self {
        self.status_leaves = leaves;
        self
    }
}

// The status-body + local_data-object serializers are consumed ONLY by the
// `adminspace-plugins-handlers` reply blocks; gated so a build without the feature
// (where `AdminPlugin` still compiles inside the always-present `answer_admin_query`
// signature) does not carry them as dead code — the same rationale as
// `AdminSources::to_json`.
#[cfg(feature = "adminspace-plugins-handlers")]
impl AdminPlugin {
    /// The zenoh `PluginStatusRec` JSON body (handler B, `@/<zid>/<whatami>/
    /// plugins/<id>`). `serde` serializes the derived struct in FIELD-DECLARATION
    /// order (NOT alphabetical — this is `serde_json::to_vec(&rec)`, not the `json!`
    /// macro): `name, id, version?, long_version, path, state, report`
    /// (`plugin.rs:92-102`). `version` is OMITTED when `None`
    /// (`skip_serializing_if`), while `long_version` is emitted as `null`
    /// (asymmetric — only `version` is skipped); wz has no long_version, so it is
    /// always `null`. `report` is the default `{"level":"Info"}` (zenoh
    /// `PluginReport::default`; `messages` skipped when empty) — wz subsystems
    /// surface no health report (an extension point).
    fn to_status_json(&self) -> String {
        let mut out = String::from("{\"name\":");
        crate::json::escape_into(&self.name, &mut out);
        out.push_str(",\"id\":");
        crate::json::escape_into(&self.id, &mut out);
        if let Some(v) = &self.version {
            out.push_str(",\"version\":");
            crate::json::escape_into(v, &mut out);
        }
        out.push_str(",\"long_version\":null,\"path\":");
        crate::json::escape_into(&self.path, &mut out);
        out.push_str(",\"state\":");
        crate::json::escape_into(self.state.as_str(), &mut out);
        out.push_str(",\"report\":{\"level\":\"Info\"}}");
        out
    }
}

/// The `local_data` `plugins` field object (surface A) — zenoh builds it from
/// `started_plugins_iter()` (`adminspace.rs:588-593`) as a JSON object keyed by
/// plugin id, each value `{"name":..,"path":..}`. Only STARTED plugins appear (a
/// `Loaded` subsystem is in handler B but not here — faithful to zenoh). The
/// object keys are id-SORTED (zenoh's `serde_json` `Map` is a `BTreeMap`, no
/// `preserve_order`), and each value's `name`/`path` keys are alphabetical (the
/// `json!` macro form). Emits `{}` when no plugin is started.
#[cfg(feature = "adminspace-plugins-handlers")]
fn push_plugins_object(plugins: &[AdminPlugin], out: &mut String) {
    let mut started: Vec<&AdminPlugin> = plugins
        .iter()
        .filter(|p| p.state == AdminPluginState::Started)
        .collect();
    started.sort_by(|a, b| a.id.cmp(&b.id));
    out.push('{');
    for (i, p) in started.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // The object KEY is the plugin id as a quoted JSON string.
        crate::json::escape_into(&p.id, out);
        out.push_str(":{\"name\":");
        crate::json::escape_into(&p.name, out);
        out.push_str(",\"path\":");
        crate::json::escape_into(&p.path, out);
        out.push('}');
    }
    out.push('}');
}

/// The `@/<zid>/<whatami>` `local_data` view — zenoh `local_data`'s JSON object
/// (`adminspace.rs:678-685`): `{zid, version, metadata, locators, sessions,
/// plugins}`. `metadata` is `null` at this core (wz has no config-metadata
/// surface). `plugins` is `null` WITHOUT `adminspace-plugins-handlers` (the
/// original byte-behavior) and, WITH the feature, the started-plugins object
/// [`push_plugins_object`] builds from [`Self::plugins`] (surface A); the key set
/// is preserved so a zenoh admin client parses the same shape either way.
///
/// NOT-THIS-KEY: metadata
///
/// R2155 (open-debt item 541) — the word `metadata` is everywhere in this tree
/// as wz's own vocabulary, and this view is the one place upstream's CONFIG key
/// of that name would land. It lands as the hardcoded null above, so this type
/// is not what honours it. The disclaimer sits here rather than in the config
/// reader's doc because a claim about a mechanism belongs beside the mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminLocalData {
    /// This node's zid in zenoh `ZenohId` Display form.
    pub zid_hex: String,
    /// The embedder-supplied version string (zenoh `AdminContext::version`).
    pub version: String,
    /// The node's listening locators (embedder-supplied; zenoh
    /// `transport_mgr.get_locators()`, `adminspace.rs:599-603`).
    pub locators: Vec<String>,
    /// The connected peer(s).
    pub sessions: Vec<AdminSession>,
    /// The node's compiled-in plugin registry (surface A, the `plugins` field).
    /// Only STARTED entries appear in the emitted object; ignored (and the field
    /// emits `null`) without `adminspace-plugins-handlers`. Always present so the
    /// struct + [`answer_admin_query`] stay signature-stable across the toggle.
    pub plugins: Vec<AdminPlugin>,
}

/// Admin-space access permissions — the embedder-supplied gate values for the
/// `@/<zid>/<whatami>` admin queryable + config-WRITE subscriber, the wz mirror
/// of zenoh's `config.adminspace.permissions` (`zenoh-config` `PermissionsConf`).
/// Both fields are always present so the declare signatures stay
/// feature-toggle-independent; the GATES that consult them are separate atoms
/// (`adminspace-read` for `read`, `adminspace-write` for `write`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSpacePermissions {
    /// Allow admin GETs. zenoh `permissions.read` (`adminspace.rs:457`),
    /// default `true` (`zenoh-config` `PermissionsConf::default`, lib.rs:892).
    /// When `false` the admin queryable answers nothing — the querier receives
    /// only the terminating Final (zenoh replies a bare `ResponseFinal`,
    /// `adminspace.rs:462-467`).
    pub read: bool,
    /// Allow admin config WRITEs (a PUT under `@/<zid>/<whatami>/config/**`).
    /// zenoh `permissions.write`, checked at the top of the admin `send_push`
    /// handler (`if !permissions().write { error!; return }`, `adminspace.rs:396`),
    /// default `false` (`PermissionsConf::default`, lib.rs:893) — the asymmetry:
    /// GET is permissive, config-WRITE is denied unless explicitly granted. The
    /// gate that consults this value is the `adminspace-write` atom (a separate
    /// cfg); [`parse_admin_config_write`] is where the check lives.
    pub write: bool,
}

impl Default for AdminSpacePermissions {
    /// zenoh's `PermissionsConf` default is `read: true, write: false` (lib.rs:892-893)
    /// — permissive GET, default-deny config-WRITE.
    fn default() -> Self {
        Self {
            read: true,
            write: false,
        }
    }
}

/// The outcome of an admin-query answer — whether the `read` gate served the GET
/// or denied it.
///
/// This exists because the gate's DIAGNOSTIC and the gate's DECISION live in
/// different layers here. zenoh logs inside the gate itself
/// (`tracing::error!("Received GET on '{}' but adminspace.permissions.read=false
/// in configuration")`,
/// `zenoh/src/net/runtime/adminspace.rs` @ `permissions().read`) because its
/// adminspace
/// is a std, `tracing`-linked component. [`answer_admin_query`] is `no_std` +
/// `alloc` and links no logger, so it REPORTS the deny to its caller and the host —
/// which owns the log facade — emits the diagnostic. One gate, one decision, and
/// the report is a value rather than a side effect, so a test can assert the deny
/// without capturing log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a DeniedRead outcome is the host's cue to emit the deny diagnostic"]
pub enum AdminAnswerOutcome {
    /// `read` was permitted: every intersecting handler ran (which may still be
    /// none, when the GET keyexpr intersects no admin key).
    Served,
    /// `read = false`: nothing was replied. The querier receives only the
    /// terminating Final (zenoh's bare `ResponseFinal`, `adminspace.rs:462-467`).
    DeniedRead,
}

/// The deny diagnostic itself, worded ONCE.
///
/// R2329 (unregistered open-debt item 13). The `#[must_use]` above forces a
/// host to CONSUME the outcome; it cannot force the host to say the right
/// thing, and until this round every host said it by hand. MEASURED: the same
/// sentence was written out at FIVE sites — four in `wz-ap-demo/src/runner.rs`
/// and one in `wz-runtime-tokio/src/session/mod.rs` — with no shared source.
///
/// That is the copies-of-one-needle hazard this workspace has already paid for
/// once (R2230: one predicate inlined four times, two of them fixed, leaving a
/// finder that found and a counter that counted zero). It is worse here than a
/// wording drift, because the sentence is also what any future witness would
/// have to grep for: five spellings mean a witness can match some hosts and
/// silently miss others. One of the five already wraps across a line
/// continuation, so a literal grep for the whole sentence does not even find it
/// today.
///
/// The wording is zenoh's, deliberately — same severity, same cause, same text
/// — so an operator moving between the two implementations reads one sentence.
/// [`AdminAnswerOutcome`]'s own doc above carries the upstream citation; this
/// one deliberately does not repeat it, because a second copy of a citation is
/// a second thing to keep resolving.
///
/// It returns a `String` rather than being a `const` format string because
/// `log::error!` requires a literal at the macro site; hosts call
/// `log::error!("{}", denied_read_diagnostic(k))`, which keeps the wording here
/// and the log facade there. That split is the same one the enum's own doc
/// describes: this crate is `no_std` + `alloc` and links no logger.
#[must_use]
pub fn denied_read_diagnostic(keyexpr: &str) -> alloc::string::String {
    alloc::format!(
        "Received GET on '{keyexpr}' but adminspace.permissions.read=false in configuration"
    )
}

impl AdminLocalData {
    /// Serialize to the zenoh `local_data` JSON object. zenoh builds it with the
    /// `json!` macro then `serde_json::to_vec`, and pins `serde_json` WITHOUT
    /// `preserve_order` — so its `Map` is a `BTreeMap` and the emitted object keys
    /// are ALPHABETICALLY sorted, NOT `json!` source order. Key ORDER here is that
    /// order: top-level `locators, metadata, plugins, sessions, version, zid`; each
    /// `sessions` entry `links, peer, shm, weight, whatami`; each link `dst, src`.
    /// Manual emit (no `serde_json`) keeps the builder `alloc`-only and
    /// no_std-feasible.
    ///
    /// # R2415: this doc used to claim "matches those bytes exactly", and re-measured
    /// # against the PIN (zenoh 1.10.0) that claim was FALSE
    ///
    /// It was written against zenoh 1.5.0 and never re-checked, which is open-debt
    /// item 678 and the shape item 675 exists to close: a stale grade does not merely
    /// age, it asserts something a later reader has no reason to doubt. At the pin a
    /// session entry carries `links, peer, region, shm, weight, whatami`, and the
    /// four fields divide into four DIFFERENT situations rather than one gap:
    ///
    /// * `shm` — CLOSED by this round. wz negotiates it already
    ///   (`SessionActions::is_shm` under `transport-shm`); it simply was not
    ///   reported. The field is now emitted, in its alphabetical position.
    /// * `region` — upstream's own recent addition, still carrying a `FIXME(regions)`
    ///   and recomputed per query there. wz has no analogue, so this is an honest
    ///   ABSENCE, not a defect, and must not be written up as parity.
    /// * `weight` — router-tier: upstream reads a `links_info` lookup, wz emits
    ///   `null`. Named as a router-mode follow-up long before this round.
    /// * `metadata` (top level) — upstream serves `config.metadata()`; wz's config
    ///   has no such field at all, so this is a config-surface question.
    ///
    /// So the honest statement is the one above — the key ORDER is upstream's, and
    /// the field SET diverges by the three named residuals. `admin_unspoken_fields`
    /// is where a consumer learns which of them arrive as `null`.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        // R311y60 — the locators string array via the json::push_str_array SSOT.
        out.push_str("{\"locators\":");
        crate::json::push_str_array(&self.locators, &mut out);
        // `metadata` is null at this core; `plugins` is the started-plugins object
        // under `adminspace-plugins-handlers`, else `null` (the original behavior).
        out.push_str(",\"metadata\":null,\"plugins\":");
        #[cfg(feature = "adminspace-plugins-handlers")]
        push_plugins_object(&self.plugins, &mut out);
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        out.push_str("null");
        out.push_str(",\"sessions\":[");
        for (i, session) in self.sessions.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"links\":[");
            for (j, link) in session.links.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                out.push_str("{\"dst\":");
                push_json_str(&link.dst, &mut out);
                out.push_str(",\"src\":");
                push_json_str(&link.src, &mut out);
                out.push('}');
            }
            out.push_str("],\"peer\":");
            push_json_str(&session.peer_zid_hex, &mut out);
            // R2415 — `shm` sits between `peer` and `weight` because upstream's
            // serde_json Map is a BTreeMap and emits keys ALPHABETICALLY; inserting
            // it anywhere else would be a different byte stream for the same facts.
            out.push_str(if session.shm {
                ",\"shm\":true,\"weight\":null,\"whatami\":"
            } else {
                ",\"shm\":false,\"weight\":null,\"whatami\":"
            });
            match &session.whatami {
                Some(w) => push_json_str(w, &mut out),
                None => push_json_str("unknown", &mut out),
            }
            out.push('}');
        }
        out.push_str("],\"version\":");
        push_json_str(&self.version, &mut out);
        out.push_str(",\"zid\":");
        push_json_str(&self.zid_hex, &mut out);
        out.push('}');
        out
    }
}

/// The admin root keyexpr `@/<zid>/<whatami>` — the key `local_data` replies
/// under (zenoh `reply_key`, `adminspace.rs:562-567`) and the literal the
/// built-in queryable answers a GET against.
pub fn admin_root_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = String::with_capacity(2 + zid_hex.len() + 1 + whatami.len());
    s.push_str("@/");
    s.push_str(zid_hex);
    s.push('/');
    s.push_str(whatami);
    s
}

/// The built-in admin queryable keyexpr `@/<zid>/<whatami>/**` — zenoh declares
/// its admin queryable on `[root_key, "/**"].concat()` (`adminspace.rs:341`), so
/// any admin GET under the node prefix routes to it.
pub fn admin_queryable_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/**");
    s
}

/// The admin metrics keyexpr `@/<zid>/<whatami>/metrics` — zenoh's `metrics`
/// handler key (`adminspace.rs:164`).
#[cfg(feature = "adminspace-metrics")]
pub fn admin_metrics_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/metrics");
    s
}

/// R311y40 — the admin config keyexpr `@/<zid>/<whatami>/config`, the typed
/// config READ view. BEYOND-ZENOH (R311y42 correction): zenoh declares
/// `@/<zid>/<whatami>/config/**` ONLY as a write-only `DeclareSubscriber` (the
/// PUT path -> `insert_json5`, adminspace.rs:350-353) and has NO admin
/// config-READ GET at all; wz ADDS this typed read surface (a superset, not a
/// mirror of a zenoh read path). Ungated (part of adminspace-core): a config GET
/// is core admin introspection, not a metrics-gated handler.
pub fn admin_config_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/config");
    s
}

/// R2414 (open-debt items 675/677) — the metrics leg's encoding, the pin's own
/// constant (`zenoh/src/net/runtime/adminspace.rs` @ `METRICS_ENCODING`).
///
/// ONE literal for both the reply and the manifest row, so the document and the
/// wire cannot drift: `encoding_from_mime` splits it on the FIRST `;` exactly as
/// upstream's `From<&str>` does, giving predefined id 15
/// (`application/openmetrics-text`, agreed by zenoh, zenoh-pico and this crate's
/// own table) plus the remainder as schema.
#[cfg(feature = "adminspace-metrics")]
pub const METRICS_ENCODING: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// R2413 (open-debt item 676) — the admin SURFACE keyexpr
/// `@/<zid>/<whatami>/wz/surface`: the key under which this node describes its own
/// adminspace.
///
/// BEYOND-ZENOH, and named so rather than presented as parity: the pin (zenoh
/// 1.10.0 `zenoh/src/net/runtime/adminspace.rs` @ `macro_rules! add_handler`)
/// registers no handler of this kind, so a
/// consumer that finds this key has learned it is talking to wz. The `wz/` chunk
/// exists for exactly that reason — every other admin key this module answers
/// carries a name upstream also uses, so a wz-native leg needs a namespace of its
/// own or it becomes a name upstream can later collide with.
pub fn admin_surface_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/wz/surface");
    s
}

/// How many replies one admin leg produces for a GET that intersects it.
///
/// R2413 — the axis a key list alone cannot carry. `config` answers once; the
/// per-entity introspection leg answers ONE reply per declared subscriber or
/// queryable, so its manifest row is a PATTERN and a consumer must not read a
/// single reply as the whole leg. Without this, "the key is in the list and I got
/// one reply" and "the key is in the list and I got all of it" are the same
/// observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminLegCardinality {
    /// Exactly one reply, under the literal key in the row.
    Single,
    /// Zero or more replies under keys matching the row's pattern — one per live
    /// item (a declared entity, a compiled-in plugin, a routing successor).
    PerItem,
}

impl AdminLegCardinality {
    /// The manifest word. `per-item` rather than `many` because zero is a normal
    /// count for these legs and "many" reads as a promise of more than one.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::PerItem => "per-item",
        }
    }
}

/// One row of the adminspace surface manifest: a key this BUILD answers, the
/// encoding it answers in, and how many replies it produces.
///
/// R2413 — the row is built from the same `#[cfg]` that gates the reply leg, so
/// the manifest and the answerer move together by construction. What keeps that
/// true is not the co-location, though — it is
/// `the_manifest_describes_exactly_the_legs_this_build_answers`, which derives the
/// population by RUNNING [`answer_admin_query`] against a wildcard and comparing
/// what it actually replied with what this table declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLeg {
    /// The concrete key (`Single`) or the key pattern (`PerItem`), with this
    /// node's zid and role already substituted — usable in a GET verbatim.
    pub key: String,
    /// The encoding this leg replies in, as the wire media type
    /// (`application/json`, `text/plain`, …) — an OWNED string because it is
    /// derived from the encoding SSOT rather than chosen from a fixed set, and a
    /// schema-carrying encoding renders as `mime;schema`.
    pub encoding: String,
    /// How many replies a GET intersecting this leg produces.
    pub cardinality: AdminLegCardinality,
}

/// The media type string for an [`EncodingHint`](crate::sample::EncodingHint) this
/// module replies with — DERIVED from the encoding SSOT, never enumerated here.
///
/// # R2414: this used to be a two-arm `if/else` whose `else` returned JSON
///
/// The first draft answered `text/plain` for the text/plain hint and
/// `application/json` for *everything else*. That was accidentally right while
/// this module replied exactly two encodings, and it was a trap for the moment it
/// replied a third: the manifest gate builds BOTH the declared name and the
/// observed name through this function, so a new encoding would have been given
/// the same wrong name on both sides and the gate would have agreed with itself.
/// A check whose predicate is supplied by its own definition cannot fail — the
/// failure this repository keeps paying for, here planted inside the very gate
/// built to prevent it.
///
/// [`encoding_to_mime`](crate::encoding::encoding_to_mime) already IS the
/// id↔MIME SSOT (it knows all 53 predefined ids, `application/openmetrics-text`
/// among them, and re-joins a schema with `;`), so deriving from it means a leg
/// that changes encoding cannot change what the document says about it without
/// the two disagreeing.
fn leg_encoding_name(hint: &crate::sample::EncodingHint) -> String {
    crate::encoding::encoding_to_mime(hint)
}

/// R2413 (open-debt item 676) — every admin leg THIS BUILD answers, in reply
/// order.
///
/// # The question this exists to answer
///
/// A consumer asked (2026-09-07) how to tell, from the wire alone, which admin
/// keys a node answers — because the answer is a property of the node's BUILD and
/// six `#[cfg]`s move it. Measured at the time, live, on a wildcard GET: an
/// `adminspace-core`-only build replies 2 keys, and one with metrics +
/// introspection + plugins replies 3 (the extra being `metrics`; the other two
/// legs fan out per item and a node with no declarations and no plugins produces
/// none). Nothing on the wire said the difference was the build rather than the
/// node's state, and nothing said what the missing keys would have been.
///
/// # Router legs
///
/// The `linkstate` / `route` legs live in [`answer_router_admin_query`], a
/// different function with a different host. They are declared here anyway,
/// predicated on `whatami == "router"`, because the router hat calls BOTH
/// answerers for one GET (see the router-hat adminspace integration test) and a
/// consumer sees one surface, not two. A peer never serves them, which is what the
/// role predicate encodes.
pub fn admin_legs(zid_hex: &str, whatami: &str) -> Vec<AdminLeg> {
    use crate::sample::EncodingHint;
    let mut legs = Vec::new();
    // Closures, not values: each row owns its rendered name, and the rendering
    // stays a call into the encoding SSOT rather than a constant captured once.
    let json = || leg_encoding_name(&EncodingHint::APPLICATION_JSON);
    let text = || leg_encoding_name(&EncodingHint::TEXT_PLAIN);

    // `local_data` — ungated, the one leg every adminspace build answers.
    legs.push(AdminLeg {
        key: admin_root_key(zid_hex, whatami),
        encoding: json(),
        cardinality: AdminLegCardinality::Single,
    });
    #[cfg(feature = "adminspace-metrics")]
    legs.push(AdminLeg {
        key: admin_metrics_key(zid_hex, whatami),
        // Derived from the SAME constant the reply uses, through the same SSOT.
        encoding: leg_encoding_name(&crate::encoding::encoding_from_mime(METRICS_ENCODING)),
        cardinality: AdminLegCardinality::Single,
    });
    legs.push(AdminLeg {
        key: admin_config_key(zid_hex, whatami),
        encoding: json(),
        cardinality: AdminLegCardinality::Single,
    });
    #[cfg(feature = "adminspace-introspection-handlers")]
    for kind in [AdminEntityKind::Subscriber, AdminEntityKind::Queryable] {
        legs.push(AdminLeg {
            key: admin_entity_key(zid_hex, whatami, kind.as_str(), "**"),
            encoding: json(),
            cardinality: AdminLegCardinality::PerItem,
        });
    }
    #[cfg(feature = "adminspace-plugins-handlers")]
    {
        legs.push(AdminLeg {
            key: admin_plugin_key(zid_hex, whatami, "*"),
            encoding: json(),
            cardinality: AdminLegCardinality::PerItem,
        });
        legs.push(AdminLeg {
            key: admin_plugin_status_path_key(zid_hex, whatami, "*"),
            encoding: text(),
            cardinality: AdminLegCardinality::PerItem,
        });
        let mut leaves = admin_plugin_status_root_key(zid_hex, whatami, "*");
        leaves.push_str("/**");
        legs.push(AdminLeg {
            key: leaves,
            encoding: json(),
            cardinality: AdminLegCardinality::PerItem,
        });
    }
    // The surface document itself. Listed because a leg a consumer can GET and
    // cannot find in the manifest is exactly the ambiguity this document exists to
    // remove — including when that leg is this one.
    legs.push(AdminLeg {
        key: admin_surface_key(zid_hex, whatami),
        encoding: json(),
        cardinality: AdminLegCardinality::Single,
    });
    #[cfg(feature = "adminspace-router-linkstate")]
    if whatami == "router" {
        legs.push(AdminLeg {
            key: admin_linkstate_routers_key(zid_hex, whatami),
            encoding: text(),
            cardinality: AdminLegCardinality::Single,
        });
        legs.push(AdminLeg {
            key: admin_linkstate_peers_key(zid_hex, whatami),
            encoding: text(),
            cardinality: AdminLegCardinality::Single,
        });
        let mut successors = admin_route_successor_prefix(zid_hex, whatami);
        successors.push_str("/**");
        legs.push(AdminLeg {
            key: successors,
            encoding: json(),
            cardinality: AdminLegCardinality::PerItem,
        });
    }
    // Silence the unused binding in a build that compiles no text/plain leg.
    let _ = text;
    legs
}

/// R2413 (open-debt item 676) — the root document fields this build emits as
/// `null` BECAUSE IT DOES NOT SPEAK THEM, as dotted paths (`[]` = "every element
/// of this array").
///
/// # The third question, and why the other two cannot answer it
///
/// The consumer's sharpest ask: seeing `"plugins":null` in `local_data`, is that
/// "this node has no plugins" or "this build does not report plugins"? Measured
/// live on 2026-09-07: an `adminspace-core`-only build emits `"plugins":null`, and
/// one with `adminspace-plugins-handlers` and no started plugin emits
/// `"plugins":{}`. So the bytes DO discriminate today — and nothing declared it,
/// nothing gated it, and a consumer could only learn it by reading this tree.
/// [`admin_legs`] cannot say it either: `plugins` is a FIELD of a leg that is in
/// the list both ways.
///
/// This is the same hole `wz-capture`'s `doc_revision::planes` fills for the
/// census document (R2180, open-debt item 554), and it is filled the same way — by
/// DECLARING, in the document, which `null`s are the library's silence.
///
/// # Two of these are permanent, one is a build fact
///
/// `metadata` and `sessions[].weight` are `null` in every wz build; the pin fills
/// both (`config.metadata()` at `local_data`, and a `links_info` lookup for
/// `weight`). They are listed because a consumer cannot tell a permanent silence
/// from a build-conditional one either, and both mean "do not wait for this".
pub fn admin_unspoken_fields() -> Vec<&'static str> {
    let mut fields = alloc::vec!["metadata"];
    #[cfg(not(feature = "adminspace-plugins-handlers"))]
    fields.push("plugins");
    fields.push("sessions[].weight");
    fields
}

/// R2413 (open-debt item 676) — the adminspace surface document: the body this
/// node replies under [`admin_surface_key`].
///
/// ```json
/// {"revision":1,
///  "legs":[{"key":"@/<zid>/peer","encoding":"application/json","cardinality":"single"}, …],
///  "unspoken":["metadata","plugins","sessions[].weight"]}
/// ```
///
/// `revision` is the document's own contract number, the convention
/// `wz-capture`'s `doc_revision` established for the dissect-side self-reports: it
/// moves when a consumer that parsed the previous shape would misread this one,
/// and NOT when a leg appears or disappears — that is what the document is FOR,
/// and a revision that moved with the feature flags would tell a consumer to
/// re-audit on every build.
///
/// # Resolving a key that two rows match — the MOST LITERAL row wins
///
/// Two rows can match one key, and exactly one pair does so today: the reserved
/// `status/plugins/<id>/__path__` leaf is `text/plain` while the plugin's own
/// status leaves beside it are JSON, so the rows are
/// `…/status/plugins/*/__path__` and `…/status/plugins/*/**`. A keyexpr cannot
/// say "every leaf EXCEPT `__path__`", so the overlap is not removable by naming
/// — it is resolved by a stated rule instead: **the matching row with the most
/// non-wildcard chunks describes the reply.** That is the discipline a keyexpr
/// consumer already applies to overlapping subscriptions, and
/// `the_manifest_describes_exactly_the_legs_this_build_answers` enforces both
/// halves of it — that the rule picks a row, and that no two rows tie.
///
/// Merging the two into one row was the alternative and it loses the encoding
/// axis, which is question two of the three this document exists to answer.
pub fn admin_surface_json(zid_hex: &str, whatami: &str) -> String {
    let mut out = String::from("{\"revision\":1,\"legs\":[");
    for (i, leg) in admin_legs(zid_hex, whatami).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"key\":");
        push_json_str(&leg.key, &mut out);
        out.push_str(",\"encoding\":");
        push_json_str(&leg.encoding, &mut out);
        out.push_str(",\"cardinality\":");
        push_json_str(leg.cardinality.as_str(), &mut out);
        out.push('}');
    }
    out.push_str("],\"unspoken\":");
    crate::json::push_str_array(admin_unspoken_fields(), &mut out);
    out.push('}');
    out
}

/// The declaring-node buckets for an admin introspection entry — the wz analogue of
/// zenoh's `hat::Sources`
/// (`zenoh/src/net/routing/hat/mod.rs` @ `struct Sources`), which is the JSON
/// body BOTH
/// the `subscribers_data` and `queryables_data` handlers serialize
/// (`serde_json::to_string(&sub.1)`, zenoh `adminspace.rs:793,843`). zids are in
/// zenoh `ZenohId` Display (hex) form. Serialized field order matches zenoh's serde
/// derive: `routers`, `peers`, `clients`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminSources {
    /// Router nodes that declared the entity (empty for a plain peer's peer-tier
    /// interest table).
    pub routers: Vec<String>,
    /// Peer nodes that declared the entity (self + mesh peers, for a peer-tier table).
    pub peers: Vec<String>,
    /// Client nodes that declared the entity.
    pub clients: Vec<String>,
}

// Only the introspection reply block consumes `to_json`; gated so a build without the
// feature (where `AdminSources` still compiles inside the always-present
// `AdminDeclaration`) does not carry it as dead code.
#[cfg(feature = "adminspace-introspection-handlers")]
impl AdminSources {
    /// Zenoh's `Sources` JSON: `{"routers":[..],"peers":[..],"clients":[..]}` (serde
    /// field order), each bucket a JSON array of hex-zid strings. Built via the same
    /// `json::push_str_array` SSOT [`AdminLocalData::to_json`] uses (quote + escape).
    fn to_json(&self) -> String {
        let mut out = String::from("{\"routers\":");
        crate::json::push_str_array(&self.routers, &mut out);
        out.push_str(",\"peers\":");
        crate::json::push_str_array(&self.peers, &mut out);
        out.push_str(",\"clients\":");
        crate::json::push_str_array(&self.clients, &mut out);
        out.push('}');
        out
    }
}

/// The kind of a per-entity admin introspection [`AdminDeclaration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminEntityKind {
    /// `@/<zid>/<whatami>/subscriber/<keyexpr>`.
    Subscriber,
    /// `@/<zid>/<whatami>/queryable/<keyexpr>`.
    Queryable,
}

// `as_str` is consumed only by the introspection reply block (same rationale as
// `AdminSources::to_json` above).
#[cfg(feature = "adminspace-introspection-handlers")]
impl AdminEntityKind {
    fn as_str(self) -> &'static str {
        match self {
            AdminEntityKind::Subscriber => "subscriber",
            AdminEntityKind::Queryable => "queryable",
        }
    }
}

/// One declared entity the per-entity admin introspection handlers reply for
/// (§5.23 `adminspace-introspection-handlers`) — the wz analogue of a
/// `subscribers_data` / `queryables_data` loop item (zenoh
/// `zenoh/src/net/runtime/adminspace.rs` @ `fn subscribers_data` and
/// @ `fn queryables_data`). Keyed `@/<zid>/<whatami>/<kind>/<keyexpr>`,
/// body the entity's [`AdminSources`] (`{routers,peers,clients}`) — the SAME
/// `Sources` body zenoh serializes for both kinds. ALWAYS compiled (like
/// [`AdminSession`]) so [`answer_admin_query`]'s slice parameter is signature-stable
/// across the feature toggle; only the reply BLOCK that consumes it is `#[cfg]`-gated.
///
/// PUBLISHER / QUERIER are deliberately ABSENT: wz maintains no publisher or querier
/// table (`declare_publisher` / `declare_querier` return pure send/get handles with
/// no wire record — `session/mod.rs:2196`), and zenoh's `publishers_data` /
/// `queriers_data` loop over an empty table emits NOTHING, so omitting these is
/// byte-identical to zenoh running with no declared publishers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDeclaration {
    /// Whether this is a subscriber or a queryable entry.
    pub kind: AdminEntityKind,
    /// The entity's declared keyexpr (may itself contain wildcards, e.g. `demo/**`).
    pub keyexpr: String,
    /// The nodes that declared this keyexpr (`{routers,peers,clients}`), the reply body.
    pub sources: AdminSources,
}

/// The per-entity admin introspection key `@/<zid>/<whatami>/<kind>/<pattern>`
/// (`kind` = `subscriber` / `queryable`), zenoh `adminspace.rs:786`. `pattern` is
/// the entity's declared (canonical) keyexpr; it may itself contain wildcards (a
/// subscriber on `demo/**` → `@/<zid>/<whatami>/subscriber/demo/**`), which the
/// intersection matcher handles symmetrically. A grammar-invalid pattern yields an
/// ill-formed target that [`keyexpr_match::keyexpr_intersects_target`] treats as
/// no-match (silently skipped) — wz's no-panic posture, NOT zenoh's
/// `.try_into().unwrap()`.
#[cfg(feature = "adminspace-introspection-handlers")]
fn admin_entity_key(zid_hex: &str, whatami: &str, kind: &str, pattern: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push('/');
    s.push_str(kind);
    s.push('/');
    s.push_str(pattern);
    s
}

/// R311y48 (§5.23 Phase 3b) — the admin config-WRITE keyexpr PATTERN
/// `@/<zid>/<whatami>/config/**`. The PATTERN is faithful to zenoh, which declares
/// its write-only config `DeclareSubscriber` on exactly this key
/// (`adminspace.rs:350-353`); a routing peer registers a LOCAL subscriber on it so
/// a remote PUT self-dispatches to its config-write handler (the R311y46 Push-plane
/// twin of the y44 self-query dispatch the config GET uses).
///
/// FIDELITY CAVEAT (R311y50) — only the KEY PATTERN matches zenoh; the SUB-KEY +
/// PAYLOAD shape does NOT (yet). zenoh strips the `@/<zid>/<whatami>/config/`
/// prefix and feeds the remaining JSON-POINTER path + a JSON5 body to
/// `insert_json5` (its ACL lives under `config/access_control`). wz's current
/// handler instead recognizes a single bespoke sub-key `acl-deny` with a BARE
/// keyexpr payload — a deliberate MVP affordance, NOT a json-pointer subset, so it
/// is NOT subsumed by the eventual full json5/json-pointer engine (that engine
/// would parse `config/access_control` + json5, and `acl-deny` would retire or
/// become an explicit non-zenoh alias). The read sibling [`admin_config_key`]
/// (`@/<zid>/<whatami>/config`, single key) is itself beyond-zenoh (zenoh has no
/// config READ).
pub fn admin_config_write_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_config_write_prefix(zid_hex, whatami);
    s.push_str("**");
    s
}

/// R2393 — the STRIP prefix `@/<zid>/<whatami>/config/` that
/// [`parse_admin_config_write`] takes, the companion of the SUBSCRIPTION pattern
/// [`admin_config_write_key`] returns.
///
/// # Why this is a function, and why the pattern above is now derived from it
///
/// The pattern and the prefix are one fact wearing two shapes, and nothing in the
/// types relates them: the pattern ends `/**`, the prefix ends `/`, so passing the
/// pattern where the prefix belongs type-checks, compiles, and yields a
/// `strip_prefix` that can never match. Every PUT then decodes
/// [`AdminConfigWriteOutcome::NotAWrite`], whose handler arm is correctly silent —
/// so a host wired that way registers its subscriber, logs that it is hosting it,
/// receives the samples, and applies nothing.
///
/// That is not hypothetical. Three shipping hosts need this prefix; two built it by
/// hand from [`admin_config_key`] and the third built it from the PATTERN, and the
/// mismatch survived its own round's unit tests because those tests pass the prefix
/// as a LITERAL — the demo wiring was the only caller that had to derive it, and a
/// demo is what no unit test drives. Deriving the pattern from the prefix gives the
/// pair one origin, and `write_prefix_and_write_pattern_agree_on_the_subkey` pins
/// that origin, so an edit to either shape has to keep the other true.
pub fn admin_config_write_prefix(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_config_key(zid_hex, whatami);
    s.push('/');
    s
}

/// R311y237 (§5.23 `adminspace-plugins-handlers`) — the per-plugin admin key
/// `@/<zid>/<whatami>/plugins/<id>` (surface B). zenoh's `plugins_data` handler
/// replies each `PluginStatusRec` under `root_key.join(status.id())`
/// (`adminspace.rs:934`); the `id` here is the wz subsystem id (`storage_manager`,
/// `rest`).
#[cfg(feature = "adminspace-plugins-handlers")]
fn admin_plugin_key(zid_hex: &str, whatami: &str, id: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/plugins/");
    s.push_str(id);
    s
}

/// R311y237 (§5.23 `adminspace-plugins-handlers`) — the per-plugin status-path
/// key `@/<zid>/<whatami>/status/plugins/<id>/__path__` (surface C). zenoh's
/// `plugins_status` handler replies each STARTED plugin's `path()` under this
/// `__path__` leaf as `text/plain` (`adminspace.rs:963-969`).
#[cfg(feature = "adminspace-plugins-handlers")]
fn admin_plugin_status_path_key(zid_hex: &str, whatami: &str, id: &str) -> String {
    let mut s = admin_plugin_status_root_key(zid_hex, whatami, id);
    s.push_str("/__path__");
    s
}

/// R311y828 (§5.23 `adminspace-plugins-handlers`) — the per-plugin STATUS ROOT
/// `@/<zid>/<whatami>/status/plugins/<id>`, which is both the parent of the
/// `__path__` leg and the prefix every [`AdminPluginStatusLeaf`] hangs off. zenoh
/// builds the same string once as `plugin_key` and passes it to the plugin's
/// `adminspace_getter` as `plugin_status_key` (`adminspace.rs:961, 987`), which is
/// why the getter's own keys are relative to it.
#[cfg(feature = "adminspace-plugins-handlers")]
fn admin_plugin_status_root_key(zid_hex: &str, whatami: &str, id: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/status/plugins/");
    s.push_str(id);
    s
}

/// R311y45 (§5.23 Phase 2b) — the node-identity + version + locators + GET
/// permission an [`answer_admin_query`] call needs. The caller (a Session, or a
/// routing peer's forwarder-hosted admin) supplies these; `sessions[]` and
/// `config_json` are passed separately because each host reads them differently
/// (a Session from its one peer + its read-at-open snapshot; a routing peer from
/// its faces + its LIVE shared `WzConfig`).
pub struct AdminAnswerCtx<'a> {
    /// This node's zid in zenoh hex form.
    pub zid_hex: &'a str,
    /// This node's role string (`WhatAmI::to_str`).
    pub whatami: &'a str,
    /// The embedder-supplied version string.
    pub version: &'a str,
    /// The node's listening locators.
    pub locators: &'a [String],
    /// The admin GET permission (zenoh `permissions.read`, `adminspace.rs:457`):
    /// the caller passes `permissions.read` under `adminspace-read`, else `true`,
    /// so the answerer stays feature-toggle-independent (the gate is the value,
    /// not a cfg).
    pub read: bool,
    /// R311y810 (`transport-stats`) — this node's live counter snapshot, or
    /// `None` when it has none to report.
    ///
    /// The metrics leg appends its OpenMetrics rendering after the `zenoh_build`
    /// gauge, which is where zenoh appends
    /// `manager().get_stats().report().openmetrics_text()` under its own `stats`
    /// feature (`zenoh/src/net/runtime/adminspace.rs` @ `.stats()`). Carried on
    /// the CONTEXT
    /// rather than read inside the answerer because the answerer is
    /// session-independent by contract: a Session passes its own report, while a
    /// mesh host has no equivalent to upstream's transport-MANAGER aggregate and
    /// passes `None` — a residual named at the call site, not hidden by one.
    ///
    /// UNGATED, and deliberately: a `#[cfg]` here would be a cfg-gated pub
    /// struct field, so every one of the five construction sites would need a
    /// matching `#[cfg]` — including `wz-ap-demo`, which has no `transport-stats`
    /// feature of its own and would therefore break the moment feature
    /// unification turned the flag on in `wz-session-core`. The field costs one
    /// `Option` in a build that never fills it.
    pub stats: Option<crate::stats::TransportStatsReport>,
}

/// R311y45 (§5.23 Phase 2b) — the Session-INDEPENDENT admin-query answerer: the
/// match+reply SSOT BOTH the Session-level adminspace queryable AND the
/// forwarder-hosted routing-peer admin call, so both emit byte-identical replies.
/// Fires every admin handler whose key INTERSECTS the GET keyexpr (zenoh's
/// `for (key, handler) in handlers { if key_expr.intersects(key) { .. } }`,
/// `adminspace.rs:499-503`): root `local_data`, `metrics` (under
/// `adminspace-metrics`), `config`, the per-entity `subscriber`/`queryable`
/// introspection (under `adminspace-introspection-handlers`), and the
/// `plugins`/`status/plugins` legs (under `adminspace-plugins-handlers`).
/// `read=false` answers NOTHING (the dispatch SSOT still emits the terminating
/// Final — zenoh's bare ResponseFinal on deny, `:462-467`) and RETURNS
/// [`AdminAnswerOutcome::DeniedRead`], which is the host's cue to emit the deny
/// diagnostic zenoh logs inside its own gate. The reply path is the same
/// `reply_keyed_encoded` the Session queryable uses.
///
/// `plugins` is the node's compiled-in subsystem registry (surface A/B/C); it is
/// consumed by [`AdminLocalData::plugins`] unconditionally (so the parameter is
/// always used) and by the `plugins/**` + `status/plugins/**` reply blocks under
/// the feature.
pub fn answer_admin_query(
    view: &dyn crate::query_sink::QueryView,
    out: &mut dyn crate::query_sink::ReplyOut,
    ctx: &AdminAnswerCtx,
    sessions: &[AdminSession],
    declarations: &[AdminDeclaration],
    plugins: &[AdminPlugin],
    config_json: &str,
) -> AdminAnswerOutcome {
    if !ctx.read {
        return AdminAnswerOutcome::DeniedRead;
    }
    // `declarations` is consumed ONLY by the `adminspace-introspection-handlers`
    // reply block below; keep the parameter unconditional (signature stability) and
    // consume it here when the feature is off.
    #[cfg(not(feature = "adminspace-introspection-handlers"))]
    let _ = declarations;
    let ke = view.keyexpr();

    // `local_data` (root key `@/<zid>/<whatami>`).
    let root_key = admin_root_key(ctx.zid_hex, ctx.whatami);
    let root_chunks: Vec<&str> = root_key.split('/').collect();
    if crate::keyexpr_match::keyexpr_intersects_target(ke, &root_chunks) {
        let data = AdminLocalData {
            zid_hex: String::from(ctx.zid_hex),
            version: String::from(ctx.version),
            locators: ctx.locators.to_vec(),
            sessions: sessions.to_vec(),
            // Surface A: the `plugins` field object (started-only) — always set so
            // `plugins` is a used parameter regardless of the feature; `to_json`
            // emits `null` when `adminspace-plugins-handlers` is off.
            plugins: plugins.to_vec(),
        };
        out.reply_keyed_encoded(
            &root_key,
            data.to_json().as_bytes(),
            Some(&crate::sample::EncodingHint::APPLICATION_JSON),
        );
    }

    // `metrics` (`@/<zid>/<whatami>/metrics`, OpenMetrics text) — under
    // adminspace-metrics. R2414 moved the encoding to the pin's own
    // `METRICS_ENCODING` and the document now closes with `# EOF`.
    #[cfg(feature = "adminspace-metrics")]
    {
        let metrics_key = admin_metrics_key(ctx.zid_hex, ctx.whatami);
        let metrics_chunks: Vec<&str> = metrics_key.split('/').collect();
        if crate::keyexpr_match::keyexpr_intersects_target(ke, &metrics_chunks) {
            let mut body = metrics_text(ctx.zid_hex, ctx.whatami, ctx.version);
            // R311y810 — the transport-stats composition, appended AFTER the
            // build-info block exactly as upstream appends its own stats block
            // (adminspace.rs:722-730). A node without counters (or a build
            // without the feature) emits the build-info block alone. No `#[cfg]`:
            // the gate is the VALUE being `None`, the same shape `ctx.read` uses.
            if let Some(stats) = ctx.stats {
                body.push_str(&stats.openmetrics_text());
            }
            // R2494 (open-debt item 677) — upstream's `descriptors` parameter,
            // the ONE of its six metrics parameters that is honourable against
            // this body. Upstream's own arm drops the `# HELP` / `# TYPE` lines
            // and keeps the samples:
            // `zenoh/src/net/runtime/adminspace.rs` @ `if query.parameters().get("descriptors") == Some("false") {`
            //
            // EQUALITY against `"false"`, not a presence test, and the
            // difference is load-bearing here for the first time:
            // [`crate::selector_params::param_value`] documents that a VALUELESS
            // key yields `Some("")` (zenoh's own `get` semantics), so a bare
            // `?descriptors` must leave the descriptors ON. Upstream's `==
            // Some("false")` says the same; `is_some()` would not.
            //
            // ⚠ THE TERMINATOR IS NOT A DESCRIPTOR. Upstream strips every `#`
            // line and re-appends `# EOF` with `.chain(["# EOF\n"])` because its
            // terminator sits INSIDE the filtered text. wz appends
            // `metrics_eof()` AFTER this filter's subject, so that re-append is
            // a step this assembly already gives for free -- copying it would be
            // cargo-culting upstream's workaround for a shape wz does not have.
            if crate::selector_params::param_value_bytes(view.parameters(), "descriptors")
                == Some("false")
            {
                let kept: alloc::string::String = body
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .map(|l| alloc::format!("{l}\n"))
                    .collect();
                body = kept;
            }
            // R2414 — and the terminator LAST, after any counters. OpenMetrics
            // ends at `# EOF`; emitting it inside `metrics_text` would bury the
            // stats block behind the end of the document.
            body.push_str(metrics_eof());
            out.reply_keyed_encoded(
                &metrics_key,
                body.as_bytes(),
                Some(&crate::encoding::encoding_from_mime(METRICS_ENCODING)),
            );
        }
    }

    // `config` (`@/<zid>/<whatami>/config`): the typed WzConfig read-at-open JSON
    // the caller supplies (a routing peer reads its LIVE shared instance per query).
    let config_key = admin_config_key(ctx.zid_hex, ctx.whatami);
    let config_chunks: Vec<&str> = config_key.split('/').collect();
    if crate::keyexpr_match::keyexpr_intersects_target(ke, &config_chunks) {
        out.reply_keyed_encoded(
            &config_key,
            config_json.as_bytes(),
            Some(&crate::sample::EncodingHint::APPLICATION_JSON),
        );
    }

    // `subscriber` / `queryable` per-entity introspection (`@/<zid>/<whatami>/
    // {subscriber,queryable}/<keyexpr>`) — under `adminspace-introspection-handlers`.
    // ONE reply per declared entity whose entity key INTERSECTS the GET (the wz
    // analogue of zenoh's `subscribers_data` / `queryables_data` per-item loop,
    // `adminspace.rs:781,831`). The entity key is built from the entity's canonical
    // declared keyexpr; an ill-formed key is silently skipped by the intersection
    // matcher's well-formed guard (wz never replicates zenoh's `.unwrap()` panic).
    #[cfg(feature = "adminspace-introspection-handlers")]
    for decl in declarations {
        let entity_key =
            admin_entity_key(ctx.zid_hex, ctx.whatami, decl.kind.as_str(), &decl.keyexpr);
        let entity_chunks: Vec<&str> = entity_key.split('/').collect();
        if crate::keyexpr_match::keyexpr_intersects_target(ke, &entity_chunks) {
            // Body = the entity's `Sources` (`{routers,peers,clients}`) — the SAME
            // struct zenoh serializes for BOTH subscriber and queryable admin replies.
            out.reply_keyed_encoded(
                &entity_key,
                decl.sources.to_json().as_bytes(),
                Some(&crate::sample::EncodingHint::APPLICATION_JSON),
            );
        }
    }

    // `plugins/**` (surface B) + `status/plugins/**` (surface C) — under
    // `adminspace-plugins-handlers`. The wz-native superset of zenoh's
    // PluginsManager admin handlers (adminspace.rs:922 `plugins_data` + :952
    // `plugins_status`): the plugin list is the compiled-in subsystem registry the
    // HOST supplies, NOT a dlopen enumeration.
    #[cfg(feature = "adminspace-plugins-handlers")]
    {
        // Surface B — `@/<zid>/<whatami>/plugins/<id>`: ONE reply per DECLARED
        // plugin (any state) whose entity key INTERSECTS the GET, body the zenoh
        // `PluginStatusRec` (zenoh replies every `plugins_status(names)` item,
        // adminspace.rs:930-934). The wz registry is the compiled-subsystem list,
        // so "declared" = "compiled in" (every entry the host passes).
        for p in plugins {
            let key = admin_plugin_key(ctx.zid_hex, ctx.whatami, &p.id);
            let chunks: Vec<&str> = key.split('/').collect();
            if crate::keyexpr_match::keyexpr_intersects_target(ke, &chunks) {
                out.reply_keyed_encoded(
                    &key,
                    p.to_status_json().as_bytes(),
                    Some(&crate::sample::EncodingHint::APPLICATION_JSON),
                );
            }
        }
        // Surface C — `@/<zid>/<whatami>/status/plugins/<id>/**`: for each STARTED
        // plugin, the `__path__` leg (text/plain, the plugin path) followed by the
        // plugin's OWN sub-tree. zenoh iterates `started_plugins_iter()`, replies
        // `__path__` as TEXT_PLAIN (adminspace.rs:960-969) and then delegates the
        // rest of the sub-tree to the plugin's `adminspace_getter` (:987), replying
        // each response as APPLICATION_JSON (:992-996). R311y828 closed that
        // delegation: the leaves arrive on the record the host already rebuilds per
        // GET ([`AdminPluginStatusLeaf`]), so the two halves of a reply describe the
        // same instant. Emission order matches upstream — `__path__` first, then the
        // getter's responses in the order the plugin produced them.
        for p in plugins {
            if p.state != AdminPluginState::Started {
                continue;
            }
            let key = admin_plugin_status_path_key(ctx.zid_hex, ctx.whatami, &p.id);
            let chunks: Vec<&str> = key.split('/').collect();
            if crate::keyexpr_match::keyexpr_intersects_target(ke, &chunks) {
                out.reply_keyed_encoded(
                    &key,
                    p.path.as_bytes(),
                    Some(&crate::sample::EncodingHint::TEXT_PLAIN),
                );
            }
            if p.status_leaves.is_empty() {
                continue;
            }
            let status_root = admin_plugin_status_root_key(ctx.zid_hex, ctx.whatami, &p.id);
            for leaf in &p.status_leaves {
                let mut leaf_key = status_root.clone();
                leaf_key.push('/');
                leaf_key.push_str(&leaf.suffix);
                let leaf_chunks: Vec<&str> = leaf_key.split('/').collect();
                if crate::keyexpr_match::keyexpr_intersects_target(ke, &leaf_chunks) {
                    out.reply_keyed_encoded(
                        &leaf_key,
                        leaf.json_body.as_bytes(),
                        Some(&crate::sample::EncodingHint::APPLICATION_JSON),
                    );
                }
            }
        }
    }

    // `wz/surface` (`@/<zid>/<whatami>/wz/surface`) — the node's description of
    // its OWN adminspace: which keys this build answers, in which encoding, and
    // which `local_data` nulls are silence rather than emptiness. R2413
    // (open-debt item 676). Ungated within `adminspace-core`, deliberately: a
    // build that has an adminspace but cannot say what is in it puts the consumer
    // straight back to guessing, which is the whole defect. Emitted LAST so it
    // does not displace an upstream-shaped reply from the position a consumer
    // reading upstream's fan-out expects.
    let surface_key = admin_surface_key(ctx.zid_hex, ctx.whatami);
    let surface_chunks: Vec<&str> = surface_key.split('/').collect();
    if crate::keyexpr_match::keyexpr_intersects_target(ke, &surface_chunks) {
        out.reply_keyed_encoded(
            &surface_key,
            admin_surface_json(ctx.zid_hex, ctx.whatami).as_bytes(),
            Some(&crate::sample::EncodingHint::APPLICATION_JSON),
        );
    }
    AdminAnswerOutcome::Served
}

/// The ROUTER-tier admin `linkstate/routers` key `@/<zid>/<whatami>/linkstate/routers`
/// (zenoh `zenoh/src/net/runtime/adminspace.rs` @ `fn linkstate_data`).
/// Router-only in zenoh; the wz router host
/// (whatami `"router"`) is the sole caller.
#[cfg(feature = "adminspace-router-linkstate")]
fn admin_linkstate_routers_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/linkstate/routers");
    s
}

/// The admin `linkstate/peers` key `@/<zid>/<whatami>/linkstate/peers` (zenoh
/// `adminspace.rs:181`). zenoh registers this for any non-Client linkstate node
/// (a Router AND a plain linkstate peer); the wz router serves it from its
/// peer-tier `linkstatepeers_net`. Peer-host serving is a NAMED deferral.
#[cfg(feature = "adminspace-router-linkstate")]
fn admin_linkstate_peers_key(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/linkstate/peers");
    s
}

/// The admin route-successor key PREFIX `@/<zid>/<whatami>/route/successor` — zenoh
/// declares the handler on `.../route/successor/**` (`adminspace.rs:213`) and each
/// reply hangs `/src/<src>/dst/<dst>` under this prefix (`:891,:909`). Router-only.
#[cfg(feature = "adminspace-router-linkstate")]
fn admin_route_successor_prefix(zid_hex: &str, whatami: &str) -> String {
    let mut s = admin_root_key(zid_hex, whatami);
    s.push_str("/route/successor");
    s
}

/// One route-successor entry key `<prefix>/src/<src>/dst/<dst>` — the key zenoh
/// replies each `SuccessorEntry` under (`adminspace.rs:909-913`). Both zids are
/// already in zenoh `ZenohId` Display (hex) form.
#[cfg(feature = "adminspace-router-linkstate")]
fn route_successor_entry_key(prefix: &str, src_hex: &str, dst_hex: &str) -> String {
    let mut s = String::with_capacity(prefix.len() + 10 + src_hex.len() + dst_hex.len());
    s.push_str(prefix);
    s.push_str("/src/");
    s.push_str(src_hex);
    s.push_str("/dst/");
    s.push_str(dst_hex);
    s
}

/// R311y204 (§5.23 `adminspace-router-linkstate`) — the pre-rendered ROUTER-tier
/// topology view an [`answer_router_admin_query`] call replies from. The router
/// host renders these at the wz-runtime-tokio layer (from its two
/// `LinkstateNetwork`s via `dot_with(zid_to_zenoh_hex)` / `route_successors()`)
/// and passes them IN — the SAME host-agnostic seam [`answer_admin_query`] uses
/// for `config_json`, keeping this data-view net-agnostic + no_std-feasible.
/// Every zid string is already zenoh `ZenohId` Display (hex) form.
pub struct AdminRouterCtx<'a> {
    /// This node's zid in zenoh hex form.
    pub zid_hex: &'a str,
    /// This node's role string — `"router"` for the router host.
    pub whatami: &'a str,
    /// The router-tier graph DOT (zenoh `info(Router)` = `routers_net.dot()`),
    /// `None` to omit the `linkstate/routers` leg.
    pub routers_dot: Option<&'a str>,
    /// The peer-tier graph DOT (zenoh `info(Peer)` = `linkstatepeers_net.dot()`),
    /// `None` to omit the `linkstate/peers` leg.
    pub peers_dot: Option<&'a str>,
    /// Every `(source, destination, successor)` triple (all zenoh-hex), the
    /// enumeration zenoh's `route_successors()` produces from `routers_net`.
    pub successors: &'a [(String, String, String)],
    /// The admin GET permission (zenoh `permissions.read`): `false` answers
    /// nothing, the same gate [`answer_admin_query`] applies.
    pub read: bool,
}

/// R311y204 (§5.23 `adminspace-router-linkstate`) — the Session-independent
/// ROUTER-tier admin answerer, the router-legs sibling of [`answer_admin_query`]:
/// fires every router leg whose key INTERSECTS the GET keyexpr (zenoh's
/// per-handler `if key_expr.intersects(key)` dispatch, `adminspace.rs:499-503`):
/// `linkstate/routers` + `linkstate/peers` (TEXT_PLAIN petgraph DOT, zenoh
/// `:754,:774`), and one `route/successor/src/<src>/dst/<dst>` reply per triple
/// whose entry key intersects the GET (APPLICATION_JSON, the successor zid as a
/// JSON string `"<hex>"`, zenoh `:884`). A narrowed `/src/X/dst/Y` GET intersects
/// only its one entry, so the enumerate+intersect path subsumes zenoh's `route_
/// successor(src,dst)` perf shortcut (`:896-904`) — same observable result, no
/// separate parse. `read=false` answers NOTHING (the dispatch SSOT still emits the
/// terminating Final). The reply path is the same `reply_keyed_encoded` the Session
/// queryable uses. The signature is feature-toggle-independent; the reply BODY is
/// `#[cfg]`-gated (the caller passes an empty/`None` ctx with the feature off).
pub fn answer_router_admin_query(
    view: &dyn crate::query_sink::QueryView,
    out: &mut dyn crate::query_sink::ReplyOut,
    ctx: &AdminRouterCtx,
) -> AdminAnswerOutcome {
    if !ctx.read {
        return AdminAnswerOutcome::DeniedRead;
    }
    // The reply legs are consumed ONLY under the feature; keep the signature
    // stable and consume the params here when the feature is off.
    #[cfg(not(feature = "adminspace-router-linkstate"))]
    let _ = (view, out);
    #[cfg(feature = "adminspace-router-linkstate")]
    {
        let ke = view.keyexpr();

        // `linkstate/routers` (`@/<zid>/router/linkstate/routers`, text/plain DOT).
        if let Some(dot) = ctx.routers_dot {
            let key = admin_linkstate_routers_key(ctx.zid_hex, ctx.whatami);
            let chunks: Vec<&str> = key.split('/').collect();
            if crate::keyexpr_match::keyexpr_intersects_target(ke, &chunks) {
                out.reply_keyed_encoded(
                    &key,
                    dot.as_bytes(),
                    Some(&crate::sample::EncodingHint::TEXT_PLAIN),
                );
            }
        }

        // `linkstate/peers` (`@/<zid>/router/linkstate/peers`, text/plain DOT).
        if let Some(dot) = ctx.peers_dot {
            let key = admin_linkstate_peers_key(ctx.zid_hex, ctx.whatami);
            let chunks: Vec<&str> = key.split('/').collect();
            if crate::keyexpr_match::keyexpr_intersects_target(ke, &chunks) {
                out.reply_keyed_encoded(
                    &key,
                    dot.as_bytes(),
                    Some(&crate::sample::EncodingHint::TEXT_PLAIN),
                );
            }
        }

        // `route/successor/**` — ONE reply per (src,dst) triple whose entry key
        // intersects the GET; body = the successor zid as a JSON string `"<hex>"`.
        let prefix = admin_route_successor_prefix(ctx.zid_hex, ctx.whatami);
        for (src_hex, dst_hex, successor_hex) in ctx.successors {
            let key = route_successor_entry_key(&prefix, src_hex, dst_hex);
            let chunks: Vec<&str> = key.split('/').collect();
            if crate::keyexpr_match::keyexpr_intersects_target(ke, &chunks) {
                let mut body = String::new();
                crate::json::escape_into(successor_hex, &mut body);
                out.reply_keyed_encoded(
                    &key,
                    body.as_bytes(),
                    Some(&crate::sample::EncodingHint::APPLICATION_JSON),
                );
            }
        }
    }
    AdminAnswerOutcome::Served
}

/// R311y51 (§5.23 `adminspace-write`) — the typed intent a recognized admin
/// config-WRITE PUT decodes to. MVP affordance (NOT zenoh's full json5/json-pointer
/// config engine — see the [`admin_config_write_key`] fidelity caveat): the bespoke
/// `acl-deny` sub-key (R311y51), and — under `adminspace-config-hotreload` (R311y239)
/// — the `storage-add` / `storage-del` sub-keys that live-spawn / -despawn a storage
/// via the compiled storage-manager subsystem (the wz-native superset of zenoh's
/// config-hotreload, which is dlopen plugin start/stop — no wz analogue). The
/// variants are ALWAYS compiled (signature stability); only the PARSE arms that
/// construct the storage ones are `#[cfg]`-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminConfigWrite {
    /// `.../config/acl-deny <keyexpr>` — deny the keyexpr carried in the payload.
    AclDeny(String),
    /// `.../config/storage-add <name>[@<volume_id>]:<keyexpr>` — live-spawn a
    /// storage `name` owning `key_expr`. The config-diff-driven subsystem
    /// activation the host applies via the runtime storage manager (R311y239).
    /// Split on the FIRST `:` only, so `key_expr` may itself contain `:`.
    AddStorage {
        /// The storage's unique name within the manager.
        name: String,
        /// The keyexpr the storage captures + answers on.
        key_expr: String,
        /// The volume the client NAMED, or `None` when it named none.
        ///
        /// R311y497 made this `Option`, and the distinction is the whole point:
        /// before it, the wire always said `"mem"` and the host unconditionally
        /// overrode it, so a client could not choose a volume and a host could not
        /// tell "the client wants mem" from "the client did not say". A
        /// `dlopen`ed volume (`storage-mgr-dynamic-volume-loading`) is
        /// unreachable from a foreign client without that distinction — which is
        /// what made this the follow-up R311y496 named and this round closed.
        ///
        /// `None` keeps the pre-y497 behaviour byte-for-byte:
        /// [`to_storage_config`](Self::to_storage_config) resolves it to `"mem"`,
        /// and a host that maps storages onto its own volume still may.
        volume_id: Option<String>,
        /// R2571 — the PER-STORAGE volume payload the client sent, the wire half
        /// of [`StorageConfig::volume_cfg`](crate::storage_config::StorageConfig::volume_cfg).
        /// EMPTY is upstream's `Value::Null`: the client named a bare volume id.
        ///
        /// Upstream's `volume` field is a string OR an object carrying a
        /// mandatory `id` plus arbitrary backend keys
        /// (`plugins/zenoh-backend-traits/src/config.rs` @ `Some(Value::Object(volume)) => {`).
        /// wz's wire had only the string
        /// form; `@<volume_id>?<k>=<v>&…` is the object form, and the mandatory
        /// `id` is structural here rather than checked — it is the `@` field
        /// itself, which was already refused when empty.
        volume_cfg: Vec<(String, String)>,
    },
    /// `.../config/storage-del <name>` — live-despawn the storage named `name`
    /// (RAII undeclare of its capture-sub + queryable). R311y239.
    RemoveStorage(String),
    /// R2374 (§5.23 `adminspace-read`) — `.../config/admin-read true|false`: set
    /// this node's `adminspace.permissions.read` on the LIVE config.
    ///
    /// # Why this key and not another bespoke one
    ///
    /// The three sub-keys above are wz-shaped affordances with no single upstream
    /// pointer behind them. This one is different: `adminspace/permissions/read`
    /// is a key upstream's own admin PUT can write, because upstream's config is a
    /// json5 document and its write path routes any pointer into the live
    /// `Config` -- the same admin handler this module's header already cites for
    /// the read gate. So a wz node that could not be told
    /// to change its own read permit over the wire was NARROWER than upstream on a
    /// key upstream carries -- which is a divergence, where inventing a fourth
    /// bespoke intent would have been a widening.
    ///
    /// It is what makes the read gate's LIVENESS observable from outside the
    /// process: before this, nothing on a wz node's wire could move its
    /// permissions, so "the permit is re-read per GET" could only be witnessed by
    /// a test that reached inside. See
    /// `wz_storage_host_adminspace_read_permit_flips_over_the_wire`.
    AdminReadPermit(bool),
    /// R2393 (`router-connect-reconcile`) — `.../config/connect-add <endpoint>[,…]`
    /// — dial these endpoints now, the wz analogue of upstream re-entering
    /// `update_peers` when a live node's connect list changes.
    ///
    /// # Why this key is admissible, on the test [`AdminReadPermit`](Self::AdminReadPermit) used
    ///
    /// The atom's last live residual said wz's runtime connect ADD is reachable only
    /// from a ONE-SHOT CLI argument (`--connect-after`), where upstream re-reads the
    /// list on a config change
    /// (`zenoh/src/net/runtime/orchestrator.rs` @ `connect_peers`). That
    /// is a DIVERGENCE on a capability upstream HAS, not a wz affordance nobody asked
    /// for — the same test that admitted the read permit and would have refused a
    /// bespoke fifth intent.
    ///
    /// Deliberately an ADD, mirroring the mechanism behind it: the reconcile seam is
    /// add-only because a close-removed teardown is a Client-only mesh-blackhole
    /// footgun the atom excludes on purpose, and an intent that could REMOVE would be
    /// wider than what it drives.
    ///
    /// The payload is one or more endpoints separated by `,`. An empty payload, or
    /// any empty element, is `Malformed` — never a partial dial, because a node told
    /// to join two peers and silently joining one is the shape an operator cannot
    /// see.
    ConnectAdd(alloc::vec::Vec<alloc::string::String>),
}

#[cfg(feature = "adminspace-config-hotreload")]
impl AdminConfigWrite {
    /// R311y239 — the intent → [`crate::storage_config::StorageConfig`] SSOT: an
    /// [`AddStorage`](Self::AddStorage) intent maps to a `StorageConfig` (zenoh-faithful
    /// defaults, [`StorageConfig::new`](crate::storage_config::StorageConfig::new)) the
    /// runtime storage manager spawns; any other
    /// intent yields `None`. Kept here (not at the runtime layer) because both the
    /// intent and `StorageConfig` are wz-session-core types — one mapping, no drift.
    pub fn to_storage_config(&self) -> Option<crate::storage_config::StorageConfig> {
        match self {
            AdminConfigWrite::AddStorage {
                name,
                key_expr,
                volume_id,
                volume_cfg,
            } => {
                let mut config = crate::storage_config::StorageConfig::new(
                    name,
                    key_expr,
                    // A client that named NO volume resolves to the in-memory one,
                    // which is exactly what the pre-R311y497 wire always encoded — so
                    // a legacy `<name>:<keyexpr>` payload produces the identical
                    // config it always did. A host is free to map an un-named storage
                    // onto its own volume afterwards; it must NOT do that to a storage
                    // whose volume the client named.
                    volume_id.as_deref().unwrap_or(DEFAULT_STORAGE_VOLUME_ID),
                );
                // R2571 — and the per-storage payload rides with it. This is the
                // ONE place the wire's object form reaches a `StorageConfig`, and
                // it is what keeps the field from being a knob nothing fills:
                // `Volume::create_storage` already takes `&StorageConfig`, so
                // every backend can read it with no trait change, exactly as
                // upstream hands `volume_cfg` to `create_storage` untouched.
                config.volume_cfg = volume_cfg.clone();
                Some(config)
            }
            _ => None,
        }
    }
}

/// R311y51 (§5.23 `adminspace-write`) — the outcome of gating + decoding an admin
/// config-WRITE PUT, so the caller logs each case as zenoh does (a permission
/// deny is an `error`, `adminspace.rs:397`; a malformed / unknown write is benign).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminConfigWriteOutcome {
    /// Permitted + recognized: the caller applies this intent.
    Apply(AdminConfigWrite),
    /// `permissions.write == false`: rejected before decode, the wz mirror of
    /// zenoh's `if !permissions().write { error!; return }` (`adminspace.rs:396`).
    Denied,
    /// The PUT key is not under the `@/<zid>/<whatami>/config/` write prefix
    /// (e.g. the bare `.../config` GET key the `/**` subscriber also matches) —
    /// silently ignored, not a write.
    NotAWrite,
    /// A recognized sub-key with an unusable payload (an empty `acl-deny`, or a
    /// `storage-add`/`storage-del` with an empty name / keyexpr / no `:`).
    Malformed,
    /// An unrecognized sub-key — `acl-deny` (always) + `storage-add`/`storage-del`
    /// (under `adminspace-config-hotreload`) are decoded; the full json5 engine is
    /// deferred. The caller logs + ignores an unknown sub-key.
    UnknownKey(String),
}

/// R311y51 (§5.23 `adminspace-write`) — the Session-independent config-WRITE
/// permission gate + decoder, the write-side SSOT mirror of [`answer_admin_query`]
/// (the read SSOT). Gates on `permissions_write` FIRST — the wz mirror of zenoh's
/// `if !conf.adminspace.permissions().write { return }` at the top of the admin
/// `send_push` handler (`adminspace.rs:396`) — and only then strips `write_prefix`
/// (the `@/<zid>/<whatami>/config/` prefix) and decodes the recognized sub-key.
///
/// The caller supplies `permissions_write`: under the `adminspace-write` cfg it is
/// [`AdminSpacePermissions::write`] (default `false`, the zenoh asymmetry), else
/// `true` (the gate compiled out — the pre-gate behavior), so this decoder stays
/// feature-toggle-independent (the gate is the value, not a cfg here). The payload
/// is decoded lossily then trimmed, byte-for-byte the demo's prior inline parse.
pub fn parse_admin_config_write(
    write_prefix: &str,
    keyexpr: &str,
    payload: &[u8],
    permissions_write: bool,
) -> AdminConfigWriteOutcome {
    if !permissions_write {
        return AdminConfigWriteOutcome::Denied;
    }
    let Some(subkey) = keyexpr.strip_prefix(write_prefix) else {
        return AdminConfigWriteOutcome::NotAWrite;
    };
    match subkey {
        "acl-deny" => {
            let deny = String::from_utf8_lossy(payload);
            let deny = deny.trim();
            if deny.is_empty() {
                AdminConfigWriteOutcome::Malformed
            } else {
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AclDeny(String::from(deny)))
            }
        }
        // R2393 (router-connect-reconcile) — `connect-add <ep>[,<ep>…]`: the live
        // config-change producer for the runtime connect list, beside the one-shot
        // `--connect-after` timer that was until now its ONLY producer. The dial
        // machinery is untouched; this decodes an intent and the host feeds the
        // `ReconcileSender` the accept loop already drains.
        //
        // ALL-OR-NOTHING on the split: a trailing or doubled `,` makes the WHOLE
        // payload Malformed rather than dialling the members that did parse. A
        // partially-applied connect list is the one outcome an operator cannot
        // observe from outside — the node comes up, joins some peers, reports
        // nothing — and it is the same reasoning the `admin-read` arm gives for
        // refusing anything but a strict `true`/`false`.
        //
        // Ungated for the reason the whole decoder is: the gate is the VALUE
        // `permissions_write`, not a `#[cfg]`. A host holding no reconcile sender
        // simply has nothing to apply it to, and says so.
        "connect-add" => {
            let raw = String::from_utf8_lossy(payload);
            let eps: alloc::vec::Vec<alloc::string::String> = raw
                .split(',')
                .map(|e| alloc::string::String::from(e.trim()))
                .collect();
            if eps.iter().any(|e| e.is_empty()) {
                AdminConfigWriteOutcome::Malformed
            } else {
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::ConnectAdd(eps))
            }
        }
        // R311y239 (adminspace-config-hotreload) — the config-diff-driven storage
        // lifecycle. `storage-add <name>:<keyexpr>` decodes to AddStorage (split on the
        // FIRST `:` only, so the keyexpr may contain `:`; volume is always the in-memory
        // one — the host live-spawns it via the runtime storage manager); an empty name
        // or keyexpr is Malformed. Gated so a build without the feature falls the
        // sub-key through to UnknownKey (signature-stable; the decoder is one SSOT).
        #[cfg(feature = "adminspace-config-hotreload")]
        "storage-add" => match parse_storage_add_payload(payload) {
            Some((name, key_expr, volume_id, volume_cfg)) => {
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name,
                    key_expr,
                    volume_id,
                    volume_cfg,
                })
            }
            None => AdminConfigWriteOutcome::Malformed,
        },
        // `storage-del <name>` — despawn the named storage; empty name is Malformed.
        #[cfg(feature = "adminspace-config-hotreload")]
        "storage-del" => {
            let name = String::from_utf8_lossy(payload);
            let name = name.trim();
            if name.is_empty() {
                AdminConfigWriteOutcome::Malformed
            } else {
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::RemoveStorage(String::from(name)))
            }
        }
        // R2374 (§5.23 adminspace-read) — `admin-read true|false`, the one sub-key
        // here that names a key UPSTREAM's config document also carries
        // (`adminspace/permissions/read`). Ungated for the reason this decoder is
        // ungated everywhere: the gate is the VALUE `permissions_write`, not a
        // `#[cfg]`, so a build with the read gate compiled out still decodes the
        // intent and its host is free to apply it to a permit nothing consults.
        //
        // Strict `true` / `false` after trimming, and anything else is Malformed
        // rather than falsy: a permission that reads "yes" as "deny" is the
        // failure this whole gate exists to prevent, and a typo must be reported
        // to the operator rather than silently locking or unlocking a node.
        "admin-read" => {
            let value = String::from_utf8_lossy(payload);
            match value.trim() {
                "true" => AdminConfigWriteOutcome::Apply(AdminConfigWrite::AdminReadPermit(true)),
                "false" => AdminConfigWriteOutcome::Apply(AdminConfigWrite::AdminReadPermit(false)),
                _ => AdminConfigWriteOutcome::Malformed,
            }
        }
        other => AdminConfigWriteOutcome::UnknownKey(String::from(other)),
    }
}

/// The volume an [`AddStorage`](AdminConfigWrite::AddStorage) that named none
/// resolves to — the in-memory volume every host registers.
///
/// Named rather than repeated because it is the value the wire encoded
/// unconditionally before R311y497, so it is what "unchanged for a legacy
/// payload" means, in one place.
#[cfg(feature = "adminspace-config-hotreload")]
pub const DEFAULT_STORAGE_VOLUME_ID: &str = "mem";

/// R311y239 (`adminspace-config-hotreload`) — decode a `storage-add` payload
/// `<name>[@<volume_id>]:<keyexpr>` into `(name, key_expr, volume_id)`.
///
/// The payload is split on the FIRST `:` only: the leading field is the storage's
/// IDENTITY and `key_expr` is the entire remainder — so a keyexpr that itself
/// contains `:` (a legal keyexpr byte per the zenoh grammar) is preserved
/// verbatim, not silently truncated. Returns `None`
/// (→ [`AdminConfigWriteOutcome::Malformed`]) if `name` or `key_expr` is empty, or
/// if there is no `:` at all.
///
/// R311y497 — the leading field may carry `@<volume_id>`, split on its LAST `@`.
/// Volume selection is what a `dlopen`ed volume
/// (`storage-mgr-dynamic-volume-loading`) needs to be reachable from a foreign
/// client at all: before this, the wire always encoded `"mem"` and the host
/// overrode it, so no client could ask for any other volume. R311y496 named this
/// as the deferred follow-up and recorded WHY it had been deferred — "it needs a
/// keyexpr-safe delimiter or a json5 body". The delimiter is keyexpr-safe by
/// CONSTRUCTION here, not by luck: it is applied only to the leading NAME field,
/// which is a manager-unique identifier and not a keyexpr, so the keyexpr's
/// grammar freedom (which `@` is part of — every adminspace key begins `@/`) is
/// untouched. Splitting on the LAST `@` keeps a name that itself contains one
/// addressable, and an empty volume (`demo@:ke`) is Malformed rather than a
/// storage on a volume called "".
#[cfg(feature = "adminspace-config-hotreload")]
#[allow(clippy::type_complexity)]
fn parse_storage_add_payload(
    payload: &[u8],
) -> Option<(String, String, Option<String>, Vec<(String, String)>)> {
    let text = String::from_utf8_lossy(payload);
    let (head, key_expr) = text.split_once(':')?;
    let head = head.trim();
    let key_expr = key_expr.trim();
    if key_expr.is_empty() {
        return None;
    }
    let mut volume_cfg: Vec<(String, String)> = Vec::new();
    let (name, volume_id) = match head.rsplit_once('@') {
        Some((n, v)) => {
            let (n, v) = (n.trim(), v.trim());
            // R2571 — the object form: `@<volume_id>?<k>=<v>&<k>=<v>`. Split on
            // the FIRST `?` so a `?` inside a value survives, the same polarity
            // the `:` split above uses for the keyexpr. The volume id is what is
            // left of it, so the mandatory-`id` rule upstream checks by hand
            // (`config.rs` @ `misses mandatory string-typed field`) is
            // structural here: an empty id is refused below either way.
            let (v, cfg_text) = match v.split_once('?') {
                Some((id, cfg)) => (id.trim(), Some(cfg)),
                None => (v, None),
            };
            if v.is_empty() {
                return None;
            }
            if let Some(cfg) = cfg_text {
                // A pair with no `=` is a client error, not a key with an empty
                // value: refusing it is what keeps `?k` from silently becoming
                // `k=""`. An empty KEY is refused for the same reason.
                for pair in cfg.split('&') {
                    let (key, value) = pair.split_once('=')?;
                    let key = key.trim();
                    if key.is_empty() {
                        return None;
                    }
                    volume_cfg.push((String::from(key), String::from(value.trim())));
                }
            }
            (n, Some(String::from(v)))
        }
        None => (head, None),
    };
    if name.is_empty() {
        return None;
    }
    Some((
        String::from(name),
        String::from(key_expr),
        volume_id,
        volume_cfg,
    ))
}

/// The OpenMetrics build-info block the admin `@/<zid>/<whatami>/metrics` GET
/// opens with. R2414 (open-debt items 675/677) re-measured this against the PIN
/// and rewrote it; the shape below is zenoh 1.10.0's
/// (`zenoh/src/net/runtime/adminspace.rs` @ `fn metrics`, its no-stats literal).
///
/// # What the re-measure found — the previous body was wrong on four counts
///
/// It was graded against zenoh 1.5.0 and had drifted on every axis at once: the
/// HELP string, the TYPE (`gauge`, where the pin declares `info`), the sample
/// name (`zenoh_build`, where the pin emits `zenoh_build_info`), and the label
/// set (`version` alone, where the pin also carries `local_id` and
/// `local_whatami`). An OpenMetrics `info` family named `zenoh_build` emits its
/// sample as `zenoh_build_info`, which is why the two names differ by design.
///
/// # `# EOF` is NOT emitted here, and that is the point
///
/// OpenMetrics requires `# EOF` to be the LAST line, and this node appends its
/// `transport-stats` block AFTER this block — so putting EOF here would place
/// counters after the terminator and produce an invalid document. The caller
/// closes the document instead. Upstream never has content after EOF either:
/// its `descriptors=false` path strips every `#` line and re-appends `# EOF\n`
/// at the end, which is what establishes EOF as terminal rather than positional.
///
/// ⚠ One deliberate divergence from the pin's literal, named rather than hidden:
/// upstream writes `"# EOF\n "` — a stray space AFTER the final newline. wz does
/// not copy it. It is a byte past the document terminator, it belongs to no line,
/// and a strict reader may reject trailing content; copying a typo into a wire
/// format is not fidelity. Everything before it is byte-for-byte the pin's.
#[cfg(feature = "adminspace-metrics")]
pub fn metrics_text(zid_hex: &str, whatami: &str, version: &str) -> String {
    let mut out = String::new();
    out.push_str("# HELP zenoh_build Zenoh build version.\n");
    out.push_str("# TYPE zenoh_build info\n");
    out.push_str("zenoh_build_info{local_id=\"");
    push_openmetrics_label(zid_hex, &mut out);
    out.push_str("\",local_whatami=\"");
    push_openmetrics_label(whatami, &mut out);
    out.push_str("\",version=\"");
    push_openmetrics_label(version, &mut out);
    out.push_str("\"} 1\n");
    out
}

/// The OpenMetrics document terminator. Its own function so the ONE rule that
/// governs it — last line, after everything — has one place to be stated and one
/// place to be changed.
#[cfg(feature = "adminspace-metrics")]
pub fn metrics_eof() -> &'static str {
    "# EOF\n"
}

/// Append `s` as an OpenMetrics label value (escape `\`, `"`, newline per the
/// OpenMetrics text format). A normal version contains none of these, so the
/// output is byte-identical to zenoh's unescaped `format!`; the escape only
/// guards a pathological version string.
#[cfg(feature = "adminspace-metrics")]
fn push_openmetrics_label(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

/// Append `s` to `out` as a quoted, escaped JSON string. R311y50 — delegates to
/// the [`crate::json::escape_into`] SSOT escaper (hoisted so it is not duplicated
/// by the `config`-side admin-JSON emitter); the thin local name is kept because
/// the `local_data` builder above calls it at ~8 sites.
fn push_json_str(s: &str, out: &mut String) {
    crate::json::escape_into(s, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString as _;
    use alloc::vec;

    #[test]
    fn root_and_queryable_keys_match_zenoh_form() {
        // zenoh root_key = `@/{zid}/{whatami}` (adminspace.rs:159); the queryable
        // is declared on `[root_key, "/**"].concat()` (:341).
        assert_eq!(admin_root_key("a1b2", "peer"), "@/a1b2/peer");
        assert_eq!(admin_queryable_key("a1b2", "peer"), "@/a1b2/peer/**");
        assert_eq!(admin_config_key("a1b2", "peer"), "@/a1b2/peer/config");
        // R311y48 — the config-WRITE pattern hangs `/**` under the config key
        // (zenoh's write-only config subscriber, adminspace.rs:350-353).
        assert_eq!(
            admin_config_write_key("a1b2", "peer"),
            "@/a1b2/peer/config/**"
        );
        assert_eq!(admin_root_key("0", "router"), "@/0/router");
    }

    /// R2393 — the SUBSCRIPTION pattern and the STRIP prefix agree, on the only
    /// thing they must agree about: a concrete key the pattern matches, stripped by
    /// the prefix, leaves exactly the sub-key [`parse_admin_config_write`] switches
    /// on.
    ///
    /// This exists because the two shapes are interchangeable to the COMPILER and
    /// not to `strip_prefix`. `82fd09b2` wired the router-hat's config-write handler
    /// with `admin_config_write_key(..) + "/"` — the PATTERN where the PREFIX
    /// belongs — which type-checks, registers, logs that it is hosting the
    /// subscriber, and then decodes every arriving PUT as `NotAWrite`, whose arm is
    /// silent by design. Every unit test of that round still passed: they pass the
    /// prefix as a `const` literal, so not one of them had to DERIVE it.
    ///
    /// Written as a ROUND TRIP through the decoder rather than as two string
    /// equalities, because an equality only re-states the constructors and would
    /// still hold if both drifted the same direction. The control arm feeds the
    /// decoder the PATTERN and requires `NotAWrite`, so this test discriminates
    /// rather than restates: if the control ever starts decoding, the test has
    /// stopped measuring anything.
    #[test]
    fn write_prefix_and_write_pattern_agree_on_the_subkey() {
        let pattern = admin_config_write_key("a1b2", "router");
        let prefix = admin_config_write_prefix("a1b2", "router");
        assert_eq!(prefix, "@/a1b2/router/config/");
        // One origin: the pattern IS the prefix with the `**` chunk appended, so an
        // edit to either shape cannot silently drift from the other.
        assert_eq!(pattern, format!("{prefix}**"));

        // A concrete key under that pattern round-trips: the prefix strips, the
        // remainder is the sub-key, and a real intent comes back.
        let key = format!("{prefix}connect-add");
        assert_eq!(
            parse_admin_config_write(&prefix, &key, b"tcp/127.0.0.1:7447", true),
            AdminConfigWriteOutcome::Apply(AdminConfigWrite::ConnectAdd(vec![String::from(
                "tcp/127.0.0.1:7447"
            )])),
            "a key under the write PATTERN must decode when stripped by the write \
             PREFIX; NotAWrite here means the two shapes have drifted apart"
        );

        // CONTROL — the defect itself, reproduced: the same key stripped by the
        // PATTERN plus a slash must NOT decode.
        assert_eq!(
            parse_admin_config_write(&format!("{pattern}/"), &key, b"tcp/127.0.0.1:7447", true),
            AdminConfigWriteOutcome::NotAWrite,
            "the PATTERN where the PREFIX belongs must not decode — if this arm ever \
             passes, this test no longer discriminates"
        );
    }

    #[test]
    fn admin_queryable_double_wildcard_routes_root_and_subpath_gets() {
        // The `@/<zid>/<whatami>/**` built-in queryable must INTERSECT both the
        // bare root admin GET and any sub-path GET (`.../metrics`, deeper) so a
        // remote peer's Query reaches the handler — the wire-path match
        // (`QueryableRegistry::has_matching` → `keyexpr_intersects_target`). The
        // trailing `**` is honored ONLY when `keyexpr-wildcard-double` is on;
        // `adminspace-core` pulls it, so a slim `--no-default-features`
        // adminspace build still routes remote admin GETs. The local loopback
        // GET does not exercise `**`, so THIS matcher assertion — not the e2e —
        // is what locks the dep: drop `keyexpr-wildcard-double` from
        // `adminspace-core` and the `**` degrades to a literal chunk, flipping
        // every positive assertion below to a non-match.
        use crate::keyexpr_match::keyexpr_intersects_target;
        use alloc::vec::Vec;
        let qk = admin_queryable_key("a1b2", "peer"); // "@/a1b2/peer/**"
        let root: Vec<&str> = "@/a1b2/peer".split('/').collect();
        let metrics: Vec<&str> = "@/a1b2/peer/metrics".split('/').collect();
        let deep: Vec<&str> = "@/a1b2/peer/subscriber/foo".split('/').collect();
        let foreign: Vec<&str> = "@/ffff/peer".split('/').collect();
        assert!(
            keyexpr_intersects_target(&qk, &root),
            "bare root admin GET reaches the /** queryable (trailing ** matches zero chunks)"
        );
        assert!(
            keyexpr_intersects_target(&qk, &metrics),
            "a /metrics sub-path GET reaches the /** queryable"
        );
        assert!(
            keyexpr_intersects_target(&qk, &deep),
            "a deep sub-path GET reaches the /** queryable"
        );
        assert!(
            !keyexpr_intersects_target(&qk, &foreign),
            "a foreign zid does NOT match (negative control)"
        );
    }

    #[test]
    fn empty_local_data_emits_the_full_key_set() {
        let data = AdminLocalData {
            zid_hex: "a1b2".to_string(),
            version: "0.1.0".to_string(),
            locators: vec![],
            sessions: vec![],
            plugins: vec![],
        };
        // The zenoh `local_data` key set with no peers / locators, in
        // serde_json's BTreeMap (alphabetical) key order:
        // locators/metadata/plugins/sessions/version/zid. `plugins` is `null`
        // without `adminspace-plugins-handlers` (the original byte-behavior) and
        // `{}` with it (an empty started-plugins object, faithful to zenoh's
        // `started_plugins_iter().collect()` on no started plugins).
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        let plugins_tok = "null";
        #[cfg(feature = "adminspace-plugins-handlers")]
        let plugins_tok = "{}";
        assert_eq!(
            data.to_json(),
            format!(
                r#"{{"locators":[],"metadata":null,"plugins":{plugins_tok},"sessions":[],"version":"0.1.0","zid":"a1b2"}}"#
            )
        );
    }

    #[test]
    fn populated_local_data_mirrors_transport_unicast_json() {
        let data = AdminLocalData {
            zid_hex: "a1b2".to_string(),
            version: "0.1.0".to_string(),
            locators: vec!["tcp/127.0.0.1:7447".to_string()],
            sessions: vec![AdminSession {
                peer_zid_hex: "c3d4".to_string(),
                whatami: Some("router".to_string()),
                links: vec![AdminLink {
                    src: "tcp/127.0.0.1:7447".to_string(),
                    dst: "tcp/127.0.0.1:51000".to_string(),
                }],
                // R2415 — a session that DID negotiate SHM, so this test pins the
                // `true` rendering and its alphabetical slot; the sibling below
                // pins `false`. A single fixture would leave one of the two
                // renderings unexercised.
                shm: true,
            }],
            plugins: vec![],
        };
        // serde_json BTreeMap (alphabetical) key order at every level:
        // top locators/metadata/plugins/sessions/version/zid; session
        // links/peer/shm/weight/whatami; link dst/src. `plugins` = `null` (feature
        // off) or `{}` (feature on, no STARTED plugin).
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        let plugins_tok = "null";
        #[cfg(feature = "adminspace-plugins-handlers")]
        let plugins_tok = "{}";
        assert_eq!(
            data.to_json(),
            format!(
                concat!(
                    r#"{{"locators":["tcp/127.0.0.1:7447"],"metadata":null,"plugins":{plugins_tok},"#,
                    r#""sessions":[{{"links":[{{"dst":"tcp/127.0.0.1:51000","src":"tcp/127.0.0.1:7447"}}],"#,
                    r#""peer":"c3d4","shm":true,"weight":null,"whatami":"router"}}],"#,
                    r#""version":"0.1.0","zid":"a1b2"}}"#
                ),
                plugins_tok = plugins_tok
            )
        );
    }

    #[test]
    fn unknown_peer_whatami_renders_as_zenoh_fallback() {
        // zenoh renders an unresolved peer role as the literal "unknown"
        // (`get_whatami().map_or_else(|_| "unknown", ..)`, adminspace.rs:630).
        let data = AdminLocalData {
            zid_hex: "a1b2".to_string(),
            version: "0.1.0".to_string(),
            locators: vec![],
            sessions: vec![AdminSession {
                peer_zid_hex: "c3d4".to_string(),
                whatami: None,
                links: vec![],
                shm: false,
            }],
            plugins: vec![],
        };
        assert!(data.to_json().contains(r#""whatami":"unknown""#));
        // R2415 — the `false` rendering and its alphabetical slot, the pair to the
        // `true` case pinned above. `shm` sits between `peer` and `weight`.
        assert!(
            data.to_json()
                .contains(r#""peer":"c3d4","shm":false,"weight":null"#),
            "{}",
            data.to_json()
        );
    }

    #[test]
    fn json_strings_are_escaped() {
        // A defensively-escaped emitter: a quote / backslash / control byte in a
        // string value must not break the JSON.
        let data = AdminLocalData {
            zid_hex: "a1b2".to_string(),
            version: "v\"1\\0\n".to_string(),
            locators: vec![],
            sessions: vec![],
            plugins: vec![],
        };
        assert!(data.to_json().contains(r#""version":"v\"1\\0\n""#));
    }

    #[test]
    fn permissions_default_matches_zenoh_read_true_write_false() {
        // zenoh PermissionsConf::default() = read:true, write:false (lib.rs:892-893)
        // — permissive GET, default-deny config-WRITE (the asymmetry).
        assert!(AdminSpacePermissions::default().read);
        assert!(!AdminSpacePermissions::default().write);
    }

    // R311y51 — the config-WRITE gate + decoder (the write-side SSOT). The prefix
    // a config sub-key hangs under: `admin_config_key` + the separating slash.
    const WRITE_PREFIX: &str = "@/a1b2/peer/config/";

    #[test]
    fn parse_config_write_acl_deny_when_permitted() {
        // permissions.write=true + a recognized acl-deny -> Apply, payload trimmed
        // (byte-for-byte the demo's prior from_utf8_lossy().trim() parse).
        let out = parse_admin_config_write(
            WRITE_PREFIX,
            "@/a1b2/peer/config/acl-deny",
            b"  mesh/data  ",
            true,
        );
        assert_eq!(
            out,
            AdminConfigWriteOutcome::Apply(AdminConfigWrite::AclDeny(String::from("mesh/data")))
        );
    }

    #[test]
    fn parse_config_write_denied_when_permission_off() {
        // permissions.write=false -> Denied, the adminspace-write gate (zenoh
        // `if !permissions().write { return }`, adminspace.rs:396).
        let out = parse_admin_config_write(
            WRITE_PREFIX,
            "@/a1b2/peer/config/acl-deny",
            b"mesh/data",
            false,
        );
        assert_eq!(out, AdminConfigWriteOutcome::Denied);
    }

    #[test]
    fn parse_config_write_gate_precedes_decode() {
        // The gate is checked BEFORE strip/decode (zenoh order): even a well-formed
        // acl-deny is Denied when the permission is off — the deny does not depend
        // on the payload being valid.
        let out = parse_admin_config_write(WRITE_PREFIX, "@/a1b2/peer/config/acl-deny", b"", false);
        assert_eq!(out, AdminConfigWriteOutcome::Denied);
    }

    // ── R2393 (router-connect-reconcile) — the live connect-list producer ──

    #[test]
    fn parse_config_write_connect_add_decodes_each_endpoint() {
        // The intent upstream reaches by re-entering `update_peers` on a config
        // change. Whitespace around each element is trimmed, as every other arm here
        // trims, so an operator's spaced list dials what a tight one does.
        let out = parse_admin_config_write(
            WRITE_PREFIX,
            "@/a1b2/peer/config/connect-add",
            b" tcp/127.0.0.1:7447 , tcp/127.0.0.1:7448 ",
            true,
        );
        assert_eq!(
            out,
            AdminConfigWriteOutcome::Apply(AdminConfigWrite::ConnectAdd(vec![
                String::from("tcp/127.0.0.1:7447"),
                String::from("tcp/127.0.0.1:7448"),
            ]))
        );
    }

    #[test]
    fn parse_config_write_connect_add_is_all_or_nothing() {
        // Four shapes, because they fail on DIFFERENT halves of the guard: a
        // trailing comma yields a trailing EMPTY element, an empty payload yields a
        // SINGLE empty one. A guard checking only `is_empty()` on the VECTOR would
        // pass both, since `"".split(',')` yields one element rather than none —
        // which is why the per-element check carries the weight.
        for payload in [
            &b"tcp/127.0.0.1:7447,"[..],
            &b"tcp/127.0.0.1:7447,,tcp/127.0.0.1:7448"[..],
            &b""[..],
            &b"   "[..],
        ] {
            assert_eq!(
                parse_admin_config_write(
                    WRITE_PREFIX,
                    "@/a1b2/peer/config/connect-add",
                    payload,
                    true,
                ),
                AdminConfigWriteOutcome::Malformed,
                "a partially-parsable connect list must not dial its parsable half"
            );
        }
    }

    #[test]
    fn parse_config_write_connect_add_obeys_the_write_gate() {
        // The gate precedes decode for this arm as for every other, so the new
        // intent cannot become a way around `permissions.write` — it is the one arm
        // that makes a node dial arbitrary endpoints from the wire.
        let out = parse_admin_config_write(
            WRITE_PREFIX,
            "@/a1b2/peer/config/connect-add",
            b"tcp/127.0.0.1:7447",
            false,
        );
        assert_eq!(out, AdminConfigWriteOutcome::Denied);
    }

    #[test]
    fn parse_config_write_empty_acl_deny_is_malformed() {
        let out =
            parse_admin_config_write(WRITE_PREFIX, "@/a1b2/peer/config/acl-deny", b"   ", true);
        assert_eq!(out, AdminConfigWriteOutcome::Malformed);
    }

    #[test]
    fn parse_config_write_unknown_subkey() {
        // Only acl-deny is decoded; the full json5 engine is deferred §5.23.
        let out =
            parse_admin_config_write(WRITE_PREFIX, "@/a1b2/peer/config/batch-size", b"100", true);
        assert_eq!(
            out,
            AdminConfigWriteOutcome::UnknownKey(String::from("batch-size"))
        );
    }

    #[test]
    fn parse_config_write_bare_config_key_is_not_a_write() {
        // The bare `.../config` GET key the `/**` write subscriber also matches has
        // no trailing sub-key -> NotAWrite (the demo's prior `else { return }`).
        let out = parse_admin_config_write(WRITE_PREFIX, "@/a1b2/peer/config", b"x", true);
        assert_eq!(out, AdminConfigWriteOutcome::NotAWrite);
    }

    /// R2374 (§5.23 adminspace-read) — `admin-read` decodes BOTH truth values, and
    /// the population is the two of them rather than the one a test would reach
    /// for. A decoder that recognised only `false` would pass a deny test and
    /// leave a node no way back.
    #[test]
    fn parse_config_write_admin_read_decodes_both_truth_values() {
        for (payload, want) in [(&b"true"[..], true), (&b"false"[..], false)] {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/admin-read",
                payload,
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AdminReadPermit(want)),
                "payload {:?}",
                core::str::from_utf8(payload)
            );
        }
        // Surrounding whitespace is trimmed, as it is for every other sub-key: a
        // shell that appends a newline must not lock a node out.
        assert_eq!(
            parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/admin-read",
                b" false\n",
                true
            ),
            AdminConfigWriteOutcome::Apply(AdminConfigWrite::AdminReadPermit(false))
        );
    }

    /// R2374 — anything that is not exactly `true` or `false` is MALFORMED, not
    /// falsy.
    ///
    /// This is the arm worth its own test: the tempting decode is
    /// `payload == b"true"`, which reads every typo as a DENY. A permission that
    /// turns a misspelling into a locked node is the failure the gate exists to
    /// prevent, and an operator gets told rather than obeyed.
    #[test]
    fn parse_config_write_admin_read_refuses_anything_but_the_two_words() {
        for payload in [&b""[..], b"1", b"0", b"yes", b"no", b"True", b"FALSE"] {
            assert_eq!(
                parse_admin_config_write(
                    WRITE_PREFIX,
                    "@/a1b2/peer/config/admin-read",
                    payload,
                    true
                ),
                AdminConfigWriteOutcome::Malformed,
                "payload {:?} must not be read as a permission",
                core::str::from_utf8(payload)
            );
        }
    }

    /// R2374 — the write GATE precedes this decode too, like every other sub-key.
    /// A node that honoured `admin-read` from an unpermitted writer would let
    /// anyone on the wire grant themselves the read permit, which is a strictly
    /// worse hole than the one the gate closes.
    #[test]
    fn parse_config_write_admin_read_is_refused_without_the_write_permit() {
        assert_eq!(
            parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/admin-read",
                b"true",
                false
            ),
            AdminConfigWriteOutcome::Denied
        );
    }

    // R311y239 — the config-hotreload storage-lifecycle decode (adminspace-config-hotreload).
    #[cfg(feature = "adminspace-config-hotreload")]
    mod config_hotreload {
        use super::*;

        #[test]
        fn storage_add_decodes_name_keyexpr_and_names_no_volume() {
            // `storage-add demo:demo/**` -> AddStorage naming NO volume. R311y497
            // made that distinct from naming "mem": a host may map an un-named
            // storage onto its own volume, and must not do that to a named one.
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo:demo/**",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name: String::from("demo"),
                    key_expr: String::from("demo/**"),
                    volume_id: None,
                    volume_cfg: Vec::new(),
                })
            );
        }

        /// R311y497 — a legacy payload's CONFIG is byte-identical to what it
        /// produced before the wire gained volume selection. This is the leg that
        /// makes `volume_id: None` a widening rather than a change.
        #[test]
        fn a_payload_naming_no_volume_still_resolves_to_the_in_memory_one() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo:demo/**",
                true,
            );
            let AdminConfigWriteOutcome::Apply(intent) = out else {
                panic!("storage-add must Apply");
            };
            let cfg = intent.to_storage_config().expect("AddStorage -> config");
            assert_eq!(cfg.volume_id, DEFAULT_STORAGE_VOLUME_ID);
            assert_eq!(cfg.volume_id, "mem");
        }

        /// R311y497 — the client SELECTS a volume, which is what makes a `dlopen`ed
        /// volume reachable from a foreign peer.
        #[test]
        fn storage_add_may_name_a_volume_after_the_name() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo@wzvol_example:demo/**",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name: String::from("demo"),
                    key_expr: String::from("demo/**"),
                    volume_id: Some(String::from("wzvol_example")),
                    volume_cfg: Vec::new(),
                })
            );
            let AdminConfigWriteOutcome::Apply(intent) = out else {
                unreachable!("asserted Apply above")
            };
            assert_eq!(
                intent
                    .to_storage_config()
                    .expect("AddStorage -> config")
                    .volume_id,
                "wzvol_example",
                "the NAMED volume reaches the config, not the default"
            );
        }

        /// The `@` delimiter must not narrow the keyexpr grammar, and this is the
        /// leg that holds it to that: `@` is legal in a keyexpr (every adminspace
        /// key starts `@/`), and the split is applied ONLY to the leading name
        /// field. A keyexpr carrying `@` therefore survives intact.
        #[test]
        fn the_volume_delimiter_does_not_touch_an_at_sign_in_the_keyexpr() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"mirror:@/a1b2/peer/**",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name: String::from("mirror"),
                    key_expr: String::from("@/a1b2/peer/**"),
                    volume_id: None,
                    volume_cfg: Vec::new(),
                })
            );
        }

        /// A name that itself contains `@` stays addressable: the split is on the
        /// LAST one, so the volume is unambiguous either way.
        #[test]
        fn a_name_containing_an_at_sign_splits_on_the_last_one() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"a@b@fsdyn:demo/**",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name: String::from("a@b"),
                    key_expr: String::from("demo/**"),
                    volume_id: Some(String::from("fsdyn")),
                    volume_cfg: Vec::new(),
                })
            );
        }

        /// R2571 — upstream's OBJECT form for `volume`, which wz's wire had no
        /// spelling for: `@<volume_id>?<k>=<v>&<k>=<v>` is
        /// `volume: {id: …, k: v}` (`plugins/zenoh-backend-traits/src/config.rs`
        /// @ `Some(Value::Object(volume)) => {`). The payload must reach the
        /// CONFIG, not merely parse — that is the difference between a knob and
        /// a knob nothing fills.
        #[test]
        fn storage_add_carries_a_per_storage_volume_payload() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo@fsdyn?dir=/tmp/wz&mode=rw:demo/**",
                true,
            );
            let AdminConfigWriteOutcome::Apply(intent) = out else {
                panic!("expected Apply, got {out:?}")
            };
            let config = intent.to_storage_config().expect("AddStorage -> config");
            assert_eq!(config.volume_id, "fsdyn");
            assert_eq!(
                config.volume_cfg,
                alloc::vec![
                    (String::from("dir"), String::from("/tmp/wz")),
                    (String::from("mode"), String::from("rw")),
                ],
                "the payload reaches the config in wire order"
            );
        }

        /// The string form still yields NO payload — upstream's `Value::Null`
        /// arm. This is the back-compat pin: every pre-R2571 payload must
        /// produce the config it always did.
        #[test]
        fn storage_add_without_a_payload_is_unchanged() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo@fsdyn:demo/**",
                true,
            );
            let AdminConfigWriteOutcome::Apply(intent) = out else {
                panic!("expected Apply, got {out:?}")
            };
            let config = intent.to_storage_config().expect("AddStorage -> config");
            assert_eq!(config.volume_id, "fsdyn");
            assert!(config.volume_cfg.is_empty(), "no `?` means upstream's Null");
        }

        /// A pair with no `=`, or with an empty key, is MALFORMED rather than a
        /// key with an empty value. Silently reading `?dir` as `dir=""` is how a
        /// storage comes up configured differently from what the operator wrote.
        #[test]
        fn storage_add_payload_without_a_value_is_malformed() {
            for payload in [
                &b"demo@fsdyn?dir:demo/**"[..],
                &b"demo@fsdyn?=rw:demo/**"[..],
            ] {
                assert_eq!(
                    parse_admin_config_write(
                        WRITE_PREFIX,
                        "@/a1b2/peer/config/storage-add",
                        payload,
                        true,
                    ),
                    AdminConfigWriteOutcome::Malformed,
                    "payload {:?} must not resolve",
                    core::str::from_utf8(payload).unwrap(),
                );
            }
        }

        /// The mandatory `id` upstream checks by hand is STRUCTURAL here — it is
        /// the `@` field, and an empty one was already refused. `@?k=v` has no
        /// id, so it is Malformed for the reason it always was.
        #[test]
        fn storage_add_payload_without_a_volume_id_is_malformed() {
            assert_eq!(
                parse_admin_config_write(
                    WRITE_PREFIX,
                    "@/a1b2/peer/config/storage-add",
                    b"demo@?dir=/tmp:demo/**",
                    true,
                ),
                AdminConfigWriteOutcome::Malformed,
            );
        }

        #[test]
        fn storage_add_keyexpr_may_contain_colon() {
            // Split on the FIRST `:` only: a keyexpr containing `:` (a legal keyexpr
            // byte) is preserved verbatim, NOT truncated.
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"  demo : foo:bar/**  ",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AddStorage {
                    name: String::from("demo"),
                    key_expr: String::from("foo:bar/**"),
                    volume_id: None,
                    volume_cfg: Vec::new(),
                })
            );
        }

        #[test]
        fn storage_add_empty_name_or_keyexpr_is_malformed() {
            // R311y497 adds the empty-VOLUME cases: `demo@:ke` must be Malformed
            // rather than a storage on a volume called "", which would resolve to
            // no registered volume and fail one layer later with a worse message.
            for payload in [
                &b":demo/**"[..],
                b"demo:",
                b"",
                b"  :  ",
                b"demo@:demo/**",
                b"demo@   :demo/**",
                b"@fsdyn:demo/**",
            ] {
                let out = parse_admin_config_write(
                    WRITE_PREFIX,
                    "@/a1b2/peer/config/storage-add",
                    payload,
                    true,
                );
                assert_eq!(
                    out,
                    AdminConfigWriteOutcome::Malformed,
                    "payload {payload:?}"
                );
            }
        }

        #[test]
        fn storage_del_decodes_name() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-del",
                b"  demo  ",
                true,
            );
            assert_eq!(
                out,
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::RemoveStorage(String::from(
                    "demo"
                )))
            );
        }

        #[test]
        fn storage_del_empty_is_malformed() {
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-del",
                b"  ",
                true,
            );
            assert_eq!(out, AdminConfigWriteOutcome::Malformed);
        }

        #[test]
        fn storage_write_gated_by_permission() {
            // permissions.write=false denies BEFORE decode (same gate as acl-deny).
            let out = parse_admin_config_write(
                WRITE_PREFIX,
                "@/a1b2/peer/config/storage-add",
                b"demo:demo/**",
                false,
            );
            assert_eq!(out, AdminConfigWriteOutcome::Denied);
        }
    }

    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_key_and_build_info_match_zenoh() {
        assert_eq!(admin_metrics_key("a1b2", "peer"), "@/a1b2/peer/metrics");
        // R2414 — byte-faithful to the PIN's build-info block (zenoh 1.10.0
        // `zenoh/src/net/runtime/adminspace.rs` @ `fn metrics`): HELP + TYPE `info`
        // + the `zenoh_build_info` sample carrying local_id, local_whatami and
        // version. Re-measured from 1.5.0, where this asserted a `gauge` named
        // `zenoh_build` with a version label alone — wrong on four counts.
        assert_eq!(
            metrics_text("a1b2", "peer", "0.1.0"),
            "# HELP zenoh_build Zenoh build version.\n\
             # TYPE zenoh_build info\n\
             zenoh_build_info{local_id=\"a1b2\",local_whatami=\"peer\",version=\"0.1.0\"} 1\n"
        );
        // The terminator is NOT part of this block — the caller appends it after
        // any counters, because OpenMetrics ends at `# EOF`.
        assert!(!metrics_text("a1b2", "peer", "0.1.0").contains("# EOF"));
        assert_eq!(metrics_eof(), "# EOF\n");
    }

    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_label_escapes_pathological_version() {
        assert!(metrics_text("a1b2", "peer", "v\"x").contains(r#"version="v\"x""#));
    }

    /// R311y810 — the metrics leg APPENDS the counter block after the build-info
    /// gauge, which is where upstream appends its own
    /// (`zenoh/src/net/runtime/adminspace.rs` @ `.stats()`). Pinned on the
    /// ANSWERER, not on the
    /// R2494 (open-debt item 677) — `descriptors=false` strips the `# HELP` and
    /// `# TYPE` lines, which is the ONE of upstream's six metrics parameters
    /// that is honourable against wz's body today. The other five quantify over
    /// structure wz does not emit (no per-transport / per-link / per-key
    /// breakdown, no disconnected reporting) or need a compressor this tree has
    /// no dependency for, so implementing them would be five no-ops and a
    /// manifest decision -- measured, not assumed.
    ///
    /// ⚠ THE TERMINATOR IS NOT A DESCRIPTOR. Upstream strips every `#` line and
    /// re-appends `# EOF` with `.chain(["# EOF\n"])` because its terminator sits
    /// INSIDE the filtered text; wz appends `metrics_eof()` after the filter's
    /// subject, so copying that re-append here would be cargo-culting a step
    /// wz's assembly already gives for free. The assertion below pins that.
    /// R2533 (open-debt item 677) — wz DOES NOT COMPRESS ITS METRICS, and this
    /// pins that the encoding it sends never claims otherwise.
    ///
    /// # The decision, and why it needs a guard rather than a comment
    ///
    /// Upstream gzips by DEFAULT — `zenoh/src/net/runtime/adminspace.rs` @ `if query.parameters().get("compression") != Some("false") {`
    /// wraps the body in a `GzEncoder` and then appends `;content-encoding=gzip`
    /// to the encoding string. The owner's decision (2026-09-10) is that wz does
    /// NOT take a compressor: this tree has no gzip dependency anywhere, and
    /// acquiring one would reach the no-alloc tier and the footprint lanes'
    /// absolute pins for a metrics nicety.
    ///
    /// That is a parity DIVERGENCE, and a declined feature is only safe while
    /// the wire stays honest about it. R2414 made wz send the pin's real
    /// `METRICS_ENCODING` instead of `text/plain`, so the encoding string is now
    /// load-bearing: a consumer reads it to decide whether to inflate. If a
    /// later round ever copies upstream's suffix without copying its compressor,
    /// every such consumer breaks on wz — and nothing else in this tree would
    /// notice, because the body would still be valid OpenMetrics text.
    ///
    /// # What it grades
    ///
    /// The encoding wz ACTUALLY PUT ON THE REPLY, read back off the recorder
    /// rather than re-derived from the constant — a test that compared
    /// `METRICS_ENCODING` with itself would pass on any tree. The anti-vacuity
    /// arm asserts the leg answered with the openmetrics encoding at all, so a
    /// build that replies with nothing (or drops the encoding) cannot satisfy
    /// the claim by emitting less.
    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_encoding_never_claims_a_content_encoding() {
        let mut out = RecordingReply::default();
        let view = admin_view("@/a1b2/peer/metrics");
        let _ = answer_admin_query(
            &view,
            &mut out,
            &admin_ctx_with_stats(crate::stats::TransportStatsReport::default()),
            &[],
            &[],
            &[],
            "{}",
        );
        let (_, encoding) = out
            .replies
            .iter()
            .zip(out.encodings.iter())
            .find(|((k, _), _)| k == "@/a1b2/peer/metrics")
            .expect("the metrics leg replied");
        let hint = encoding
            .as_ref()
            .expect("the metrics leg carries an encoding");
        let mime = crate::encoding::encoding_to_mime(hint);

        // ANTI-VACUITY FIRST: the leg really is answering as openmetrics, so a
        // build that dropped the encoding cannot pass the claim below.
        assert!(
            mime.starts_with("application/openmetrics-text"),
            "the metrics leg must answer as openmetrics; got {mime:?}"
        );
        assert!(
            !mime.contains("content-encoding") && !mime.contains("gzip"),
            "wz does not compress metrics, so its encoding must not claim a \
             content-encoding (owner decision, item 677); got {mime:?}"
        );
    }

    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_descriptors_false_strips_help_and_type_but_not_eof() {
        let mut out = RecordingReply::default();
        let view = admin_view_with_params("@/a1b2/peer/metrics", "descriptors=false");
        let mut stats = crate::stats::TransportStatsReport::default();
        stats.tx.bytes = 140;
        let _ = answer_admin_query(
            &view,
            &mut out,
            &admin_ctx_with_stats(stats),
            &[],
            &[],
            &[],
            "{}",
        );
        let body = out
            .replies
            .iter()
            .find(|(k, _)| k == "@/a1b2/peer/metrics")
            .map(|(_, p)| String::from_utf8_lossy(p).into_owned())
            .expect("the metrics leg replied");
        assert!(
            !body.contains("# HELP") && !body.contains("# TYPE"),
            "descriptors=false strips HELP/TYPE; got:\n{body}"
        );
        assert!(
            body.ends_with("# EOF\n"),
            "the terminator survives the descriptor strip; got:\n{body}"
        );
        assert!(
            body.contains("tx_bytes 140"),
            "the SAMPLES survive -- only their descriptors go; got:\n{body}"
        );
    }

    /// renderer: the renderer's own shape is pinned in `stats.rs`, and what this
    /// adds is that the composition happens at all and in that order.
    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_reply_appends_the_transport_stats_block() {
        let mut out = RecordingReply::default();
        let view = admin_view("@/a1b2/peer/metrics");
        let mut stats = crate::stats::TransportStatsReport::default();
        stats.tx.bytes = 140;
        stats.tx.t_msgs = 2;
        stats.rx.bytes = 12;
        stats.rx.t_msgs = 1;
        let _ = answer_admin_query(
            &view,
            &mut out,
            &admin_ctx_with_stats(stats),
            &[],
            &[],
            &[],
            "{}",
        );
        let body = out
            .replies
            .iter()
            .find(|(k, _)| k == "@/a1b2/peer/metrics")
            .map(|(_, p)| String::from_utf8_lossy(p).into_owned())
            .expect("the metrics leg replied");
        assert_eq!(
            body,
            metrics_text("a1b2", "peer", "0.1.0") + &stats.openmetrics_text() + metrics_eof(),
            "build-info, then the counter block, then the terminator — in that \
             order. R2414: the terminator moving above the counters would bury \
             them behind the end of the document."
        );
        // R2494 — the ANTI-VACUITY partner of the descriptors test below: with
        // no parameter given, the `#` descriptor lines MUST still be there. A
        // suppression test alone would pass against a build that never emitted
        // them.
        assert!(
            body.contains("# HELP") && body.contains("# TYPE"),
            "the default reply carries its descriptors; got:\n{body}"
        );
        // Stated separately from the equality above, because that equality would
        // still hold if BOTH sides put EOF in the wrong place.
        assert!(
            body.ends_with("# EOF\n"),
            "the document ends at its terminator:\n{body}"
        );
    }

    /// The same leg with NO report serves the build-info block ALONE — byte-
    /// identical to what it served before R311y810. This is the paired negative:
    /// without it, a composition that always appended (or that appended an empty
    /// block) would pass the test above and silently change every node that has
    /// no counters to report.
    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_reply_without_a_report_is_unchanged() {
        let mut out = RecordingReply::default();
        let view = admin_view("@/a1b2/peer/metrics");
        let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &[], "{}");
        let body = out
            .replies
            .iter()
            .find(|(k, _)| k == "@/a1b2/peer/metrics")
            .map(|(_, p)| String::from_utf8_lossy(p).into_owned())
            .expect("the metrics leg replied");
        assert_eq!(body, metrics_text("a1b2", "peer", "0.1.0") + metrics_eof());
    }

    /// R2413 (open-debt item 676) — the manifest declares EXACTLY the legs this
    /// build answers, with the encoding each one actually replied in.
    ///
    /// # Why the population is RUN rather than listed
    ///
    /// [`admin_legs`] is a table, and a test that re-read that table would pass on
    /// any table, including one that has drifted away from the answerer it claims
    /// to describe. So the population here is DERIVED: the fixture drives
    /// [`answer_admin_query`] with a `**` GET and a node state that exercises every
    /// per-item leg (one declaration of each entity kind, one STARTED plugin
    /// carrying a status leaf), and the set of keys it actually replied is the
    /// thing the manifest is compared against. A leg that stops firing, a leg that
    /// fires and is not declared, and a declared leg that fires with a different
    /// encoding are three distinct reds here.
    ///
    /// The fixture is what makes zero impossible: it declares items, so an
    /// answerer that replied nothing fails at the `is_empty` guard rather than
    /// reporting a vacuous agreement between two empty sets.
    #[test]
    fn the_manifest_describes_exactly_the_legs_this_build_answers() {
        let mut out = RecordingReply::default();
        let view = admin_view("@/a1b2/peer/**");
        let _ = answer_admin_query(
            &view,
            &mut out,
            &admin_ctx(true),
            &[],
            &fixture_declarations(),
            &fixture_plugins(),
            "{}",
        );
        assert!(
            !out.replies.is_empty(),
            "the wildcard GET fired no handler at all — the population this test \
             derives is empty, so every comparison below would hold vacuously"
        );

        // What the build DECLARES, as (pattern, encoding, cardinality).
        let declared = admin_legs("a1b2", "peer");
        assert!(
            !declared.is_empty(),
            "the manifest declares no leg; see the guard above for why an empty \
             population is a failure rather than an agreement"
        );

        // Every reply the answerer actually produced must be covered by exactly one
        // declared row, and the encodings must agree.
        for (i, (key, _)) in out.replies.iter().enumerate() {
            let observed = out.encodings[i]
                .as_ref()
                .map(leg_encoding_name)
                .expect("every admin leg replies with an explicit encoding");
            let matching: Vec<&AdminLeg> = declared
                .iter()
                .filter(|leg| pattern_covers(&leg.key, key))
                .collect();
            assert!(
                !matching.is_empty(),
                "the answerer replied `{key}` and no declared leg describes it — a \
                 reply the manifest cannot name sends the consumer straight back to \
                 the guessing item 676 reported"
            );
            // The stated resolution rule: most non-wildcard chunks wins, and the
            // winner must be unique. Asserting the tie is impossible is what keeps
            // the rule a rule rather than a preference.
            let best = matching
                .iter()
                .map(|leg| literal_chunks(&leg.key))
                .max()
                .expect("non-empty");
            let winners: Vec<&&AdminLeg> = matching
                .iter()
                .filter(|leg| literal_chunks(&leg.key) == best)
                .collect();
            assert_eq!(
                winners.len(),
                1,
                "`{key}` is matched by {} equally-literal rows ({:?}) — the \
                 most-literal rule cannot pick between them, so the manifest is \
                 ambiguous for this key",
                winners.len(),
                winners.iter().map(|l| &l.key).collect::<Vec<_>>()
            );
            assert_eq!(
                winners[0].encoding, observed,
                "leg `{}` is declared `{}` but replied `{observed}` for key `{key}`",
                winners[0].key, winners[0].encoding
            );
        }

        // And the other direction: every declared leg must have fired. The fixture
        // supplies an item for each per-item leg precisely so that "declared but
        // never observed" means the declaration is wrong, not that the fixture was
        // too thin.
        for leg in &declared {
            let fired = out
                .replies
                .iter()
                .any(|(key, _)| pattern_covers(&leg.key, key));
            assert!(
                fired,
                "the manifest declares `{}` but the answerer never replied under \
                 it — a key a consumer is told to GET and that answers nothing is \
                 worse than an absent row",
                leg.key
            );
        }
    }

    /// R2414 (items 675/677) — the document names the metrics leg's media type by
    /// its REAL name, not merely by a name it also uses on the other side.
    ///
    /// # Why the sibling gate cannot stand in for this
    ///
    /// `the_manifest_describes_exactly_the_legs_this_build_answers` compares the
    /// declared name against the observed one, and BOTH are rendered by
    /// [`leg_encoding_name`]. That catches a one-sided change and is blind to a
    /// two-sided one — which is precisely the change a correct implementer makes.
    /// Before R2414 that renderer answered `application/json` for anything that
    /// was not text/plain, so moving the metrics leg to OpenMetrics would have
    /// left both sides agreeing on `application/json`: green gate, lying document.
    ///
    /// This test is the outside check. It names the expected media type as a
    /// LITERAL rather than deriving it, deliberately: a derivation here would go
    /// through the same renderer and inherit whatever it says.
    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn the_document_names_the_metrics_media_type_literally() {
        let doc = admin_surface_json("a1b2", "peer");
        assert!(
            doc.contains(
                r#""key":"@/a1b2/peer/metrics","encoding":"application/openmetrics-text; version=1.0.0; charset=utf-8""#
            ),
            "the metrics row must carry the OpenMetrics media type verbatim — a \
             renderer that collapses unknown encodings to `application/json` \
             passes its own sibling gate and lies here:\n{doc}"
        );
    }

    /// R2413 — `unspoken` names exactly the root-document fields this build emits
    /// as `null`.
    ///
    /// Derived by PARSING the `local_data` body this build actually produced and
    /// collecting its nulls, so the declaration is checked against bytes rather
    /// than against the `#[cfg]`s that were used to write it. A field that becomes
    /// real without leaving the list, and a field that turns `null` without
    /// joining it, both fail here.
    #[test]
    fn unspoken_names_exactly_the_nulls_the_root_document_emits() {
        let data = AdminLocalData {
            zid_hex: String::from("a1b2"),
            version: String::from("0.1.0"),
            locators: alloc::vec![String::from("tcp/127.0.0.1:7447")],
            // One session, so the `sessions[]` paths have an element to be null in.
            sessions: alloc::vec![AdminSession {
                peer_zid_hex: String::from("c3d4"),
                whatami: Some(String::from("peer")),
                links: alloc::vec![],
                shm: false,
            }],
            plugins: fixture_plugins(),
        };
        let root: serde_json::Value =
            serde_json::from_str(&data.to_json()).expect("local_data is JSON");

        let mut observed: Vec<String> = Vec::new();
        for (k, v) in root.as_object().expect("a JSON object") {
            if v.is_null() {
                observed.push(k.clone());
            }
        }
        for (k, v) in root["sessions"][0]
            .as_object()
            .expect("the session entry is an object")
        {
            if v.is_null() {
                observed.push(alloc::format!("sessions[].{k}"));
            }
        }
        observed.sort();

        let mut declared: Vec<String> = admin_unspoken_fields()
            .iter()
            .map(|s| String::from(*s))
            .collect();
        declared.sort();
        assert_eq!(
            observed, declared,
            "`unspoken` must name exactly the nulls `local_data` emits: a null the \
             list omits is the ambiguity item 676 reported, and a name the document \
             no longer emits tells a consumer to expect silence that has ended"
        );
    }

    /// R2413 — the DISCRIMINATOR the consumer asked for, exercised in the one
    /// direction a single build can exercise it.
    ///
    /// Measured live on 2026-09-07: `plugins` is `null` without
    /// `adminspace-plugins-handlers` and `{}` with it and no started plugin. So the
    /// bytes already told the two apart and nothing said so, which is why the
    /// manifest declares it. Each arm asserts the pairing this build can see — the
    /// emitted shape AND the `unspoken` membership that explains it.
    #[test]
    fn the_plugins_null_and_the_manifest_agree_about_which_it_is() {
        let data = AdminLocalData {
            zid_hex: String::from("a1b2"),
            version: String::from("0.1.0"),
            locators: alloc::vec![],
            sessions: alloc::vec![],
            // Deliberately EMPTY: this is the case the consumer could not read.
            plugins: alloc::vec![],
        };
        let root: serde_json::Value =
            serde_json::from_str(&data.to_json()).expect("local_data is JSON");
        let unspoken = admin_unspoken_fields();

        #[cfg(feature = "adminspace-plugins-handlers")]
        {
            assert!(
                root["plugins"].is_object() && root["plugins"].as_object().unwrap().is_empty(),
                "a build that speaks plugins reports NONE as an empty object: {}",
                data.to_json()
            );
            assert!(
                !unspoken.contains(&"plugins"),
                "this build speaks plugins, so `plugins` must not be listed as silence"
            );
        }
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        {
            assert!(
                root["plugins"].is_null(),
                "a build without the feature emits `plugins: null`: {}",
                data.to_json()
            );
            assert!(
                unspoken.contains(&"plugins"),
                "the `null` this build emits is silence, and only `unspoken` can say so"
            );
        }
    }

    /// The specificity a manifest row carries under the document's stated
    /// resolution rule: how many of its chunks are literal rather than `*` / `**`.
    fn literal_chunks(pattern: &str) -> usize {
        pattern
            .split('/')
            .filter(|c| *c != "*" && *c != "**")
            .count()
    }

    /// Does a manifest row's pattern cover this concrete reply key? `*` matches one
    /// chunk, `**` matches zero or more — the keyexpr semantics the manifest
    /// promises a consumer.
    ///
    /// Implemented HERE rather than delegated to
    /// [`keyexpr_match::keyexpr_intersects_target`](crate::keyexpr_match) because
    /// that matcher honours `*` only under `keyexpr-wildcard-single`, and this
    /// build's own gate must not report agreement because a feature that reads
    /// wildcards was compiled out. The first draft did delegate, and a
    /// `--no-default-features` run failed on `@/a1b2/peer/plugins/storage_manager`
    /// with `*` degraded to a literal chunk — a gate that passes for the wrong
    /// reason in one direction fails for the wrong reason in the other.
    fn pattern_covers(pattern: &str, key: &str) -> bool {
        let p: Vec<&str> = pattern.split('/').collect();
        let k: Vec<&str> = key.split('/').collect();
        fn walk(p: &[&str], k: &[&str]) -> bool {
            match p.first() {
                None => k.is_empty(),
                Some(&"**") => (0..=k.len()).any(|skip| walk(&p[1..], &k[skip..])),
                Some(&"*") => !k.is_empty() && walk(&p[1..], &k[1..]),
                Some(lit) => !k.is_empty() && k[0] == *lit && walk(&p[1..], &k[1..]),
            }
        }
        walk(&p, &k)
    }

    /// The per-item fixture the manifest gate needs: one declared entity of EACH
    /// introspection kind. Empty when the build has no introspection leg, which is
    /// the same thing the manifest says.
    fn fixture_declarations() -> Vec<AdminDeclaration> {
        #[cfg(feature = "adminspace-introspection-handlers")]
        {
            alloc::vec![
                AdminDeclaration {
                    kind: AdminEntityKind::Subscriber,
                    keyexpr: String::from("demo/example"),
                    sources: AdminSources::default(),
                },
                AdminDeclaration {
                    kind: AdminEntityKind::Queryable,
                    keyexpr: String::from("demo/example"),
                    sources: AdminSources::default(),
                },
            ]
        }
        #[cfg(not(feature = "adminspace-introspection-handlers"))]
        Vec::new()
    }

    /// The per-item fixture for the plugins legs: one STARTED plugin carrying a
    /// status leaf, so surfaces B and C both fan out. A non-started plugin would
    /// exercise B alone and leave C's declaration unchecked.
    fn fixture_plugins() -> Vec<AdminPlugin> {
        #[cfg(feature = "adminspace-plugins-handlers")]
        {
            alloc::vec![AdminPlugin::wz_static(
                "storage_manager",
                "storage-manager",
                Some("0.1.0"),
                AdminPluginState::Started,
            )
            .with_status_leaves(alloc::vec![AdminPluginStatusLeaf::new("stores", "{}")])]
        }
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        Vec::new()
    }

    // R311y45 — a recording ReplyOut for the answer_admin_query unit tests:
    // captures each emitted (keyexpr, payload).
    #[derive(Default)]
    struct RecordingReply {
        replies: Vec<(String, Vec<u8>)>,
        /// R2413 — the ENCODING each keyed reply carried, recorded in step with
        /// `replies`. It used to be dropped on the floor (`_encoding`), which made
        /// the manifest's encoding column unverifiable from here: a test can only
        /// compare a declaration against a measurement it kept.
        encodings: Vec<Option<crate::sample::EncodingHint>>,
    }
    impl crate::query_sink::ReplyOut for RecordingReply {
        fn reply(&mut self, payload: &[u8]) {
            self.replies.push((String::new(), payload.to_vec()));
            self.encodings.push(None);
        }
        fn reply_keyed(&mut self, keyexpr: &str, payload: &[u8]) {
            self.replies.push((keyexpr.to_string(), payload.to_vec()));
            self.encodings.push(None);
        }
        fn reply_keyed_encoded(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&crate::sample::EncodingHint>,
        ) {
            self.replies.push((keyexpr.to_string(), payload.to_vec()));
            self.encodings.push(encoding.cloned());
        }
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _: Option<u32>, _: Option<&str>, _: &[u8]) {}
        fn with_responder(&mut self, _: &[u8], _: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn admin_ctx<'a>(read: bool) -> AdminAnswerCtx<'a> {
        AdminAnswerCtx {
            zid_hex: "a1b2",
            whatami: "peer",
            version: "0.1.0",
            locators: &[],
            read,
            stats: None,
        }
    }

    /// R311y810 — the same context carrying a counter snapshot, for the tests
    /// that pin the metrics composition. Separate from [`admin_ctx`] so every
    /// OTHER admin test keeps asserting the no-stats body unchanged.
    #[cfg(feature = "adminspace-metrics")]
    fn admin_ctx_with_stats<'a>(stats: crate::stats::TransportStatsReport) -> AdminAnswerCtx<'a> {
        AdminAnswerCtx {
            stats: Some(stats),
            ..admin_ctx(true)
        }
    }

    fn admin_view(keyexpr: &str) -> crate::query_sink::BorrowedQuery<'_> {
        crate::query_sink::BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 1,
            is_local: false,
        }
    }

    /// R2494 (open-debt item 677) — the same view WITH a selector parameter
    /// string, which `admin_view` above pins to `None`. Upstream reads six
    /// parameters on the metrics leg; wz read none, and the channel was already
    /// there (`QueryView::parameters`), so what was missing was a READ SITE and
    /// a test that could see one.
    ///
    /// ⚠ GATED AT THE DEFINITION because its only caller is, exactly as
    /// `admin_ctx_with_stats` above is. A feature subset that compiles the
    /// caller out leaves this helper with no user, and `-D warnings` turns
    /// `dead_code` into a compile error — which the default-feature lane
    /// (pre-push gate 3) cannot see, so seven `run-ci.sh` adminspace legs
    /// were what caught it.
    #[cfg(feature = "adminspace-metrics")]
    fn admin_view_with_params<'a>(
        keyexpr: &'a str,
        parameters: &'a str,
    ) -> crate::query_sink::BorrowedQuery<'a> {
        crate::query_sink::BorrowedQuery {
            parameters: Some(parameters.as_bytes()),
            ..admin_view(keyexpr)
        }
    }

    #[test]
    fn answer_admin_query_config_get_replies_only_the_config_json() {
        // A GET on `@/a1b2/peer/config` fires ONLY the config handler (root is 3
        // chunks, the query 4 — no intersect without a wildcard).
        let view = admin_view("@/a1b2/peer/config");
        let mut out = RecordingReply::default();
        let _ = answer_admin_query(
            &view,
            &mut out,
            &admin_ctx(true),
            &[],
            &[],
            &[],
            r#"{"batch_size":65535,"lease_ms":10000,"whatami":"peer"}"#,
        );
        assert_eq!(out.replies.len(), 1, "only the config handler fires");
        assert_eq!(out.replies[0].0, "@/a1b2/peer/config");
        assert_eq!(
            String::from_utf8(out.replies[0].1.clone()).unwrap(),
            r#"{"batch_size":65535,"lease_ms":10000,"whatami":"peer"}"#
        );
    }

    #[test]
    fn answer_admin_query_root_get_replies_local_data() {
        // A GET on the bare root fires ONLY local_data (config is 4 chunks).
        let view = admin_view("@/a1b2/peer");
        let mut out = RecordingReply::default();
        let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &[], "{}");
        assert_eq!(out.replies.len(), 1, "only local_data fires");
        assert_eq!(out.replies[0].0, "@/a1b2/peer");
        // No plugins passed: `plugins` is `null` without the feature, `{}` with it.
        #[cfg(not(feature = "adminspace-plugins-handlers"))]
        let plugins_tok = "null";
        #[cfg(feature = "adminspace-plugins-handlers")]
        let plugins_tok = "{}";
        assert_eq!(
            String::from_utf8(out.replies[0].1.clone()).unwrap(),
            format!(
                r#"{{"locators":[],"metadata":null,"plugins":{plugins_tok},"sessions":[],"version":"0.1.0","zid":"a1b2"}}"#
            )
        );
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    fn sub_decl(keyexpr: &str, peers: &[&str]) -> AdminDeclaration {
        AdminDeclaration {
            kind: AdminEntityKind::Subscriber,
            keyexpr: String::from(keyexpr),
            sources: AdminSources {
                routers: Vec::new(),
                peers: peers.iter().map(|p| String::from(*p)).collect(),
                clients: Vec::new(),
            },
        }
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    fn qabl_decl(keyexpr: &str, peers: &[&str]) -> AdminDeclaration {
        AdminDeclaration {
            kind: AdminEntityKind::Queryable,
            ..sub_decl(keyexpr, peers)
        }
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    #[test]
    fn answer_admin_query_subscriber_get_lists_each_with_sources_body() {
        // A wildcard GET on `@/a1b2/peer/subscriber/**` replies ONE entry per declared
        // subscriber, keyed by the sub's keyexpr, body the zenoh `Sources` struct
        // `{"routers":[],"peers":[<declarers>],"clients":[]}` — NOT `null`. Neither root
        // (3 chunks) nor config (4th chunk `config`) intersects a 5-chunk `subscriber/**`
        // GET, so only the subs fire.
        let view = admin_view("@/a1b2/peer/subscriber/**");
        let mut out = RecordingReply::default();
        let decls = [
            sub_decl("demo/**", &["a1b2"]),
            sub_decl("other/data", &["a1b2", "c3d4"]),
        ];
        let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, &[], "{}");
        assert_eq!(out.replies.len(), 2, "one reply per declared subscriber");
        assert!(out
            .replies
            .iter()
            .any(|(k, v)| k == "@/a1b2/peer/subscriber/demo/**"
                && v == br#"{"routers":[],"peers":["a1b2"],"clients":[]}"#));
        // A keyexpr declared by two peers aggregates both zids into `peers`.
        assert!(out
            .replies
            .iter()
            .any(|(k, v)| k == "@/a1b2/peer/subscriber/other/data"
                && v == br#"{"routers":[],"peers":["a1b2","c3d4"],"clients":[]}"#));
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    #[test]
    fn answer_admin_query_subscriber_get_intersect_filters_by_keyexpr() {
        // A NARROWED GET replies only the intersecting subscriber (zenoh's per-entity
        // `query.intersects(entity_key)` gate) — `other/data` is excluded.
        let view = admin_view("@/a1b2/peer/subscriber/demo/**");
        let mut out = RecordingReply::default();
        let decls = [
            sub_decl("demo/**", &["a1b2"]),
            sub_decl("other/data", &["a1b2"]),
        ];
        let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, &[], "{}");
        assert_eq!(out.replies.len(), 1, "only the intersecting subscriber");
        assert_eq!(out.replies[0].0, "@/a1b2/peer/subscriber/demo/**");
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    #[test]
    fn answer_admin_query_queryable_get_serializes_sources() {
        // A queryable entry ALSO replies the `Sources` body (zenoh serializes the same
        // struct for `queryables_data`), at `@/<zid>/<whatami>/queryable/<keyexpr>`.
        let view = admin_view("@/a1b2/peer/queryable/**");
        let mut out = RecordingReply::default();
        let decls = [qabl_decl("demo/q", &["a1b2"])];
        let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, &[], "{}");
        assert_eq!(out.replies.len(), 1);
        assert_eq!(out.replies[0].0, "@/a1b2/peer/queryable/demo/q");
        assert_eq!(
            String::from_utf8(out.replies[0].1.clone()).unwrap(),
            r#"{"routers":[],"peers":["a1b2"],"clients":[]}"#
        );
    }

    #[cfg(feature = "adminspace-introspection-handlers")]
    #[test]
    fn answer_admin_query_introspection_is_read_gated_and_kind_scoped() {
        // read=false gates ALL replies (including introspection).
        let mut out = RecordingReply::default();
        let subs = [sub_decl("demo/**", &["a1b2"])];
        let _ = answer_admin_query(
            &admin_view("@/a1b2/peer/subscriber/**"),
            &mut out,
            &admin_ctx(false),
            &[],
            &subs,
            &[],
            "{}",
        );
        assert!(out.replies.is_empty(), "read=false gates all replies");
        // A `subscriber/**` GET must NOT list a Queryable declaration (kind scoping):
        // the queryable's entity key is `.../queryable/...`, disjoint from the GET.
        let mut out2 = RecordingReply::default();
        let qabls = [qabl_decl("demo/q", &["a1b2"])];
        let _ = answer_admin_query(
            &admin_view("@/a1b2/peer/subscriber/**"),
            &mut out2,
            &admin_ctx(true),
            &[],
            &qabls,
            &[],
            "{}",
        );
        assert!(
            out2.replies.is_empty(),
            "a subscriber GET must not list a queryable"
        );
    }

    #[test]
    fn answer_admin_query_read_false_answers_nothing() {
        // read=false: a deny answers NOTHING (the dispatch SSOT emits the Final).
        let view = admin_view("@/a1b2/peer/config");
        let mut out = RecordingReply::default();
        let outcome = answer_admin_query(&view, &mut out, &admin_ctx(false), &[], &[], &[], "{}");
        // The deny is REPORTED, not merely silent: the host logs off this value
        // (zenoh logs inside its own gate, adminspace.rs:458-461).
        assert_eq!(outcome, AdminAnswerOutcome::DeniedRead);
        assert!(out.replies.is_empty(), "read=false yields no replies");
    }

    // R311y237 — the wz-native plugins surface (adminspace-plugins-handlers).
    #[cfg(feature = "adminspace-plugins-handlers")]
    mod plugins {
        use super::*;

        // A compiled-but-not-started subsystem (Loaded) + an activated one (Started).
        fn storage_loaded() -> AdminPlugin {
            AdminPlugin::wz_static(
                "storage_manager",
                "storage_manager",
                Some("0.1.0"),
                AdminPluginState::Loaded,
            )
        }
        fn rest_started() -> AdminPlugin {
            AdminPlugin::wz_static("rest", "rest", Some("0.1.0"), AdminPluginState::Started)
        }

        #[test]
        fn status_json_matches_zenoh_pluginstatusrec_field_order() {
            // serde field-declaration order: name,id,version,long_version,path,state,
            // report; version present (Some), long_version null, report default Info.
            assert_eq!(
                storage_loaded().to_status_json(),
                concat!(
                    r#"{"name":"storage_manager","id":"storage_manager","version":"0.1.0","#,
                    r#""long_version":null,"path":"__static__","state":"Loaded","#,
                    r#""report":{"level":"Info"}}"#
                )
            );
        }

        #[test]
        fn status_json_omits_version_when_none() {
            // zenoh's `version` has skip_serializing_if=Option::is_none, while
            // long_version is emitted as null (asymmetric).
            let p = AdminPlugin::wz_static("rest", "rest", None, AdminPluginState::Started);
            assert_eq!(
                p.to_status_json(),
                concat!(
                    r#"{"name":"rest","id":"rest","long_version":null,"path":"__static__","#,
                    r#""state":"Started","report":{"level":"Info"}}"#
                )
            );
        }

        #[test]
        fn local_data_plugins_field_lists_started_only_id_sorted() {
            // Surface A: the root local_data `plugins` object lists STARTED plugins
            // only (a Loaded subsystem appears in handler B, not here), keyed by id.
            let view = admin_view("@/a1b2/peer");
            let mut out = RecordingReply::default();
            let plugins = [rest_started(), storage_loaded()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert_eq!(out.replies.len(), 1, "only local_data fires on a root GET");
            let body = String::from_utf8(out.replies[0].1.clone()).unwrap();
            // Only `rest` (Started); `storage_manager` (Loaded) is absent. Each value
            // is `{"name","path"}` (alphabetical), the object keyed+id-sorted.
            assert!(
                body.contains(r#""plugins":{"rest":{"name":"rest","path":"__static__"}}"#),
                "local_data plugins field must list only the started rest: {body}"
            );
        }

        #[test]
        fn plugins_handler_lists_every_declared_plugin_full_status() {
            // Surface B: `plugins/**` replies ONE full PluginStatusRec per plugin
            // (any state — both Loaded and Started), keyed `@/<zid>/<whatami>/
            // plugins/<id>`.
            let view = admin_view("@/a1b2/peer/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [storage_loaded(), rest_started()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert_eq!(out.replies.len(), 2, "one reply per declared plugin");
            assert!(out
                .replies
                .iter()
                .any(|(k, v)| k == "@/a1b2/peer/plugins/storage_manager"
                    && v == storage_loaded().to_status_json().as_bytes()));
            assert!(out
                .replies
                .iter()
                .any(|(k, v)| k == "@/a1b2/peer/plugins/rest"
                    && v == rest_started().to_status_json().as_bytes()));
        }

        #[test]
        fn plugins_handler_narrowed_get_filters_by_id() {
            // A narrowed `plugins/storage_manager` GET replies only that plugin.
            let view = admin_view("@/a1b2/peer/plugins/storage_manager");
            let mut out = RecordingReply::default();
            let plugins = [storage_loaded(), rest_started()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert_eq!(out.replies.len(), 1, "only the intersecting plugin");
            assert_eq!(out.replies[0].0, "@/a1b2/peer/plugins/storage_manager");
        }

        #[test]
        fn status_plugins_handler_replies_path_for_started_only() {
            // Surface C: `status/plugins/**` replies the `__path__` leg (text/plain)
            // for STARTED plugins only (zenoh's started_plugins_iter). A Loaded
            // subsystem is absent from C.
            let view = admin_view("@/a1b2/peer/status/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [storage_loaded(), rest_started()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert_eq!(out.replies.len(), 1, "only the started rest __path__ leg");
            assert_eq!(out.replies[0].0, "@/a1b2/peer/status/plugins/rest/__path__");
            assert_eq!(out.replies[0].1, WZ_STATIC_PLUGIN_PATH.as_bytes());
        }

        // R311y828 — a plugin that publishes leaves. `storage_manager` is the one
        // subsystem wz claims to mirror, and it is exactly the upstream plugin whose
        // `adminspace_getter` publishes `/version`, `/volumes/**` and `/storages/**`
        // (plugins/zenoh-plugin-storage-manager/src/lib.rs:336-389).
        fn storage_started_with_leaves() -> AdminPlugin {
            AdminPlugin::wz_static(
                "storage_manager",
                "storage_manager",
                Some("0.1.0"),
                AdminPluginState::Started,
            )
            .with_status_leaves(vec![
                AdminPluginStatusLeaf::new("version", "\"0.1.0\""),
                AdminPluginStatusLeaf::new("volumes/mem/__path__", "\"__static__\""),
                AdminPluginStatusLeaf::new("volumes/mem", "{\"capability\":{}}"),
                AdminPluginStatusLeaf::new("storages/s1", "{\"key_expr\":\"demo/**\"}"),
            ])
        }

        #[test]
        fn a_plugin_publishing_no_leaves_serves_only_path() {
            // The CONTROL for the two tests below, and the state R311y828 measured
            // before changing anything: with no leaves the sub-tree GET yields the
            // `__path__` leg and NOTHING else. It is what makes a green
            // `status_subtree_serves_every_leaf` mean the leaves were served rather
            // than that the observation window was wrong.
            let view = admin_view("@/a1b2/peer/status/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [rest_started()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert_eq!(
                out.replies.len(),
                1,
                "a plugin with no sub-tree answers only __path__: {:?}",
                out.replies.iter().map(|(k, _)| k).collect::<Vec<_>>()
            );
        }

        #[test]
        fn status_subtree_serves_every_leaf_as_json_under_the_plugin_root() {
            // Surface C, the getter delegation: `__path__` FIRST (text/plain, zenoh's
            // order at adminspace.rs:963 before :987), then one JSON reply per leaf,
            // each keyed under the plugin's own status root.
            let view = admin_view("@/a1b2/peer/status/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [storage_started_with_leaves()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            let keys: Vec<&str> = out.replies.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                keys,
                vec![
                    "@/a1b2/peer/status/plugins/storage_manager/__path__",
                    "@/a1b2/peer/status/plugins/storage_manager/version",
                    "@/a1b2/peer/status/plugins/storage_manager/volumes/mem/__path__",
                    "@/a1b2/peer/status/plugins/storage_manager/volumes/mem",
                    "@/a1b2/peer/status/plugins/storage_manager/storages/s1",
                ],
                "__path__ first, then the leaves in the order the plugin produced them"
            );
            // The BODY travels verbatim: the core does not re-render what the
            // subsystem rendered.
            assert_eq!(
                out.replies[4].1, b"{\"key_expr\":\"demo/**\"}",
                "the leaf body is replied byte-for-byte"
            );
        }

        #[test]
        fn a_narrowed_subtree_get_serves_only_the_leaves_it_covers() {
            // The wz analogue of upstream passing the GET's `key_expr` INTO the
            // getter so it filters its own responses (lib.rs:345, 357, 361, 374): a
            // GET narrowed to `volumes/**` must not drag in `/version` or
            // `/storages/**`, and must not drag in `__path__` either — that leg is a
            // sibling of `volumes`, not a parent.
            let view = admin_view("@/a1b2/peer/status/plugins/storage_manager/volumes/**");
            let mut out = RecordingReply::default();
            let plugins = [storage_started_with_leaves()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            let keys: Vec<&str> = out.replies.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                keys,
                vec![
                    "@/a1b2/peer/status/plugins/storage_manager/volumes/mem/__path__",
                    "@/a1b2/peer/status/plugins/storage_manager/volumes/mem",
                ],
                "only the leaves the GET covers"
            );
        }

        #[test]
        fn a_loaded_plugins_leaves_are_not_served() {
            // The sub-tree is behind the SAME Started gate as `__path__` (zenoh's
            // `started_plugins_iter`, adminspace.rs:960): a subsystem that is
            // compiled in but not activated publishes no state, so a client cannot
            // read a stale sub-tree off a plugin that is not running.
            let mut loaded = storage_started_with_leaves();
            loaded.state = AdminPluginState::Loaded;
            let view = admin_view("@/a1b2/peer/status/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [loaded];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert!(
                out.replies.is_empty(),
                "a Loaded plugin serves neither __path__ nor its sub-tree: {:?}",
                out.replies.iter().map(|(k, _)| k).collect::<Vec<_>>()
            );
        }

        #[test]
        fn plugins_surfaces_are_read_gated() {
            // read=false gates the plugins legs too (the dispatch SSOT emits Final).
            let mut out = RecordingReply::default();
            let plugins = [rest_started()];
            let _ = answer_admin_query(
                &admin_view("@/a1b2/peer/plugins/**"),
                &mut out,
                &admin_ctx(false),
                &[],
                &[],
                &plugins,
                "{}",
            );
            assert!(
                out.replies.is_empty(),
                "read=false yields no plugin replies"
            );
        }

        #[test]
        fn plugins_handler_empty_registry_replies_nothing() {
            // Surface B with an EMPTY registry: a `plugins/**` GET yields 0 replies
            // (distinct from the read-gate path — read=true, but nothing compiled).
            let view = admin_view("@/a1b2/peer/plugins/**");
            let mut out = RecordingReply::default();
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &[], "{}");
            assert!(
                out.replies.is_empty(),
                "an empty plugin registry replies nothing to plugins/**"
            );
        }

        #[test]
        fn status_plugins_all_loaded_replies_nothing() {
            // Surface C started-only filter: with ONLY a Loaded plugin, a
            // `status/plugins/**` GET yields nothing (the __path__ leg is started-only,
            // zenoh's `started_plugins_iter`). This guards against inverting the
            // `state != Started` filter — an inversion would wrongly reply here.
            let view = admin_view("@/a1b2/peer/status/plugins/**");
            let mut out = RecordingReply::default();
            let plugins = [storage_loaded()];
            let _ = answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], &plugins, "{}");
            assert!(
                out.replies.is_empty(),
                "status/plugins/** replies nothing when no plugin is Started"
            );
        }
    }

    // R311y204 — the ROUTER-tier admin legs (adminspace-router-linkstate).
    #[cfg(feature = "adminspace-router-linkstate")]
    fn router_ctx<'a>(
        read: bool,
        routers_dot: Option<&'a str>,
        peers_dot: Option<&'a str>,
        successors: &'a [(String, String, String)],
    ) -> AdminRouterCtx<'a> {
        AdminRouterCtx {
            zid_hex: "a1b2",
            whatami: "router",
            routers_dot,
            peers_dot,
            successors,
            read,
        }
    }

    #[cfg(feature = "adminspace-router-linkstate")]
    #[test]
    fn router_admin_keys_match_zenoh_form() {
        // zenoh registers `.../linkstate/routers` (adminspace.rs:171),
        // `.../linkstate/peers` (:181), and each successor under
        // `.../route/successor/src/<src>/dst/<dst>` (:909-913).
        assert_eq!(
            admin_linkstate_routers_key("a1b2", "router"),
            "@/a1b2/router/linkstate/routers"
        );
        assert_eq!(
            admin_linkstate_peers_key("a1b2", "router"),
            "@/a1b2/router/linkstate/peers"
        );
        assert_eq!(
            admin_route_successor_prefix("a1b2", "router"),
            "@/a1b2/router/route/successor"
        );
        assert_eq!(
            route_successor_entry_key("@/a1b2/router/route/successor", "201", "c3d4"),
            "@/a1b2/router/route/successor/src/201/dst/c3d4"
        );
    }

    #[cfg(feature = "adminspace-router-linkstate")]
    #[test]
    fn router_admin_linkstate_get_replies_both_dots_text_plain() {
        // A `@/a1b2/router/linkstate/**` GET replies BOTH graphs as their DOT
        // bodies (passthrough — the answerer never re-renders; the host injected
        // the zenoh-hex labels).
        let view = admin_view("@/a1b2/router/linkstate/**");
        let mut out = RecordingReply::default();
        let _ = answer_router_admin_query(
            &view,
            &mut out,
            &router_ctx(true, Some("graph { R }"), Some("graph { P }"), &[]),
        );
        assert_eq!(out.replies.len(), 2, "routers + peers DOT");
        assert!(out
            .replies
            .iter()
            .any(|(k, v)| k == "@/a1b2/router/linkstate/routers" && v == b"graph { R }"));
        assert!(out
            .replies
            .iter()
            .any(|(k, v)| k == "@/a1b2/router/linkstate/peers" && v == b"graph { P }"));
    }

    #[cfg(feature = "adminspace-router-linkstate")]
    #[test]
    fn router_admin_linkstate_routers_get_scopes_to_one_leg() {
        // A narrowed GET on just `linkstate/routers` fires only that leg (the
        // peers key does not intersect a 5-chunk `.../linkstate/routers` GET).
        let view = admin_view("@/a1b2/router/linkstate/routers");
        let mut out = RecordingReply::default();
        let _ = answer_router_admin_query(
            &view,
            &mut out,
            &router_ctx(true, Some("graph { R }"), Some("graph { P }"), &[]),
        );
        assert_eq!(out.replies.len(), 1);
        assert_eq!(out.replies[0].0, "@/a1b2/router/linkstate/routers");
    }

    #[cfg(feature = "adminspace-router-linkstate")]
    #[test]
    fn router_admin_successor_get_enumerates_filters_and_json_string_body() {
        let succ = vec![
            ("201".to_string(), "c3d4".to_string(), "aaaa".to_string()),
            ("201".to_string(), "e5f6".to_string(), "bbbb".to_string()),
        ];
        // A wildcard GET replies EVERY successor entry, body = the successor zid
        // as a JSON string `"<hex>"` (zenoh `json!(successor)` serialize_str).
        let mut out = RecordingReply::default();
        let _ = answer_router_admin_query(
            &admin_view("@/a1b2/router/route/successor/**"),
            &mut out,
            &router_ctx(true, None, None, &succ),
        );
        assert_eq!(out.replies.len(), 2, "one reply per successor triple");
        assert!(out.replies.iter().any(|(k, v)| k
            == "@/a1b2/router/route/successor/src/201/dst/c3d4"
            && v == br#""aaaa""#));
        assert!(out.replies.iter().any(|(k, v)| k
            == "@/a1b2/router/route/successor/src/201/dst/e5f6"
            && v == br#""bbbb""#));
        // A narrowed `/src/201/dst/c3d4` GET hits ONLY that one entry — the
        // enumerate+intersect path subsumes zenoh's `route_successor(src,dst)`
        // perf shortcut (same observable result).
        let mut out2 = RecordingReply::default();
        let _ = answer_router_admin_query(
            &admin_view("@/a1b2/router/route/successor/src/201/dst/c3d4"),
            &mut out2,
            &router_ctx(true, None, None, &succ),
        );
        assert_eq!(out2.replies.len(), 1);
        assert_eq!(
            out2.replies[0].0,
            "@/a1b2/router/route/successor/src/201/dst/c3d4"
        );
        assert_eq!(
            String::from_utf8(out2.replies[0].1.clone()).unwrap(),
            r#""aaaa""#
        );
    }

    #[cfg(feature = "adminspace-router-linkstate")]
    #[test]
    fn router_admin_read_false_and_none_legs_answer_nothing() {
        // read=false gates ALL router legs (the deny still emits the Final at the
        // dispatch SSOT).
        let succ = vec![("201".to_string(), "c3d4".to_string(), "aaaa".to_string())];
        let mut out = RecordingReply::default();
        let outcome = answer_router_admin_query(
            &admin_view("@/a1b2/router/linkstate/**"),
            &mut out,
            &router_ctx(false, Some("graph { R }"), Some("graph { P }"), &succ),
        );
        assert!(out.replies.is_empty(), "read=false yields no replies");
        assert_eq!(outcome, AdminAnswerOutcome::DeniedRead);
        // A `None` DOT leg is omitted even on a matching GET (the leg absent, not
        // an empty body). The outcome distinguishes this from the deny above:
        // BOTH answer nothing, and only one of them is a permission denial the
        // host must report.
        let mut out2 = RecordingReply::default();
        let outcome2 = answer_router_admin_query(
            &admin_view("@/a1b2/router/linkstate/**"),
            &mut out2,
            &router_ctx(true, None, None, &[]),
        );
        assert!(
            out2.replies.is_empty(),
            "None routers_dot/peers_dot omit their legs"
        );
        assert_eq!(outcome2, AdminAnswerOutcome::Served);
    }
}
