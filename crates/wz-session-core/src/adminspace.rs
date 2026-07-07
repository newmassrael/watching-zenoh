// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Admin space `local_data` — the `@/<zid>/<whatami>` introspection view the
//! built-in admin queryable replies with. The wz mirror of zenoh
//! `net/runtime/adminspace.rs`: `local_data` (`adminspace.rs:561-704`) + the
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
}

/// The `@/<zid>/<whatami>` `local_data` view — zenoh `local_data`'s JSON object
/// (`adminspace.rs:678-685`): `{zid, version, metadata, locators, sessions,
/// plugins}`. `metadata` and `plugins` are `null` at this core (wz has no
/// config-metadata surface and no plugin framework — the plugin family is a
/// separate out-of-scope / foundational-inert atom cluster); the key set is
/// preserved so a zenoh admin client parses the same shape.
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

impl AdminLocalData {
    /// Serialize to the faithful zenoh `local_data` JSON object. zenoh builds
    /// it with the `json!` macro then `serde_json::to_vec`
    /// (`adminspace.rs:678-690`), and pins `serde_json` WITHOUT the
    /// `preserve_order` feature — so its `Map` is a `BTreeMap` and the emitted
    /// object keys are ALPHABETICALLY sorted, NOT `json!` source order. This
    /// emitter matches those bytes exactly: top-level
    /// `locators, metadata, plugins, sessions, version, zid`; each `sessions`
    /// entry `links, peer, weight, whatami` (`transport_unicast_to_json`,
    /// `:628-633`); each link `dst, src` (`link_to_json`, `:609-612`). Manual
    /// emit (no `serde_json`) keeps the builder `alloc`-only and no_std-feasible.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        // R311y60 — the locators string array via the json::push_str_array SSOT.
        out.push_str("{\"locators\":");
        crate::json::push_str_array(&self.locators, &mut out);
        out.push_str(",\"metadata\":null,\"plugins\":null,\"sessions\":[");
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
            out.push_str(",\"weight\":null,\"whatami\":");
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

/// The declaring-node buckets for an admin introspection entry — the wz analogue of
/// zenoh's `hat::Sources` (`net/routing/hat/mod.rs:59`), which is the JSON body BOTH
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
/// `net/runtime/adminspace.rs:781,831`). Keyed `@/<zid>/<whatami>/<kind>/<keyexpr>`,
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
    let mut s = admin_config_key(zid_hex, whatami);
    s.push_str("/**");
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
}

/// R311y45 (§5.23 Phase 2b) — the Session-INDEPENDENT admin-query answerer: the
/// match+reply SSOT BOTH the Session-level adminspace queryable AND the
/// forwarder-hosted routing-peer admin call, so both emit byte-identical replies.
/// Fires every admin handler whose key INTERSECTS the GET keyexpr (zenoh's
/// `for (key, handler) in handlers { if key_expr.intersects(key) { .. } }`,
/// `adminspace.rs:499-503`): root `local_data`, `metrics` (under
/// `adminspace-metrics`), and `config`. `read=false` answers NOTHING (the
/// dispatch SSOT still emits the terminating Final — zenoh's bare ResponseFinal
/// on deny, `:462-467`). The reply path is the same `reply_keyed_encoded` the
/// Session queryable uses.
pub fn answer_admin_query(
    view: &dyn crate::query_sink::QueryView,
    out: &mut dyn crate::query_sink::ReplyOut,
    ctx: &AdminAnswerCtx,
    sessions: &[AdminSession],
    declarations: &[AdminDeclaration],
    config_json: &str,
) {
    if !ctx.read {
        return;
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
        };
        out.reply_keyed_encoded(
            &root_key,
            data.to_json().as_bytes(),
            Some(&crate::sample::EncodingHint::APPLICATION_JSON),
        );
    }

    // `metrics` (`@/<zid>/<whatami>/metrics`, text/plain) — under adminspace-metrics.
    #[cfg(feature = "adminspace-metrics")]
    {
        let metrics_key = admin_metrics_key(ctx.zid_hex, ctx.whatami);
        let metrics_chunks: Vec<&str> = metrics_key.split('/').collect();
        if crate::keyexpr_match::keyexpr_intersects_target(ke, &metrics_chunks) {
            out.reply_keyed_encoded(
                &metrics_key,
                metrics_text(ctx.version).as_bytes(),
                Some(&crate::sample::EncodingHint::TEXT_PLAIN),
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
}

/// The ROUTER-tier admin `linkstate/routers` key `@/<zid>/<whatami>/linkstate/routers`
/// (zenoh `net/runtime/adminspace.rs:171`). Router-only in zenoh; the wz router host
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
) {
    if !ctx.read {
        return;
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
}

/// R311y51 (§5.23 `adminspace-write`) — the typed intent a recognized admin
/// config-WRITE PUT decodes to. MVP affordance (NOT zenoh — see the
/// [`admin_config_write_key`] fidelity caveat): only the bespoke `acl-deny`
/// sub-key; the full json5/json-pointer config engine is a deferred §5.23 layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminConfigWrite {
    /// `.../config/acl-deny <keyexpr>` — deny the keyexpr carried in the payload.
    AclDeny(String),
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
    /// A recognized sub-key with an unusable payload (an empty `acl-deny`).
    Malformed,
    /// An unrecognized sub-key — only `acl-deny` is decoded (the full json5
    /// engine is deferred); the caller logs + ignores it.
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
        other => AdminConfigWriteOutcome::UnknownKey(String::from(other)),
    }
}

/// The OpenMetrics body the admin `@/<zid>/<whatami>/metrics` GET replies with
/// (`text/plain`). Byte-faithful to zenoh's UNCONDITIONAL build-info block
/// (`adminspace.rs:714-720`): a `zenoh_build` gauge carrying the node version.
/// zenoh additionally appends `manager().get_stats().report().openmetrics_text()`
/// under its `stats` feature (`:722-730`); the wz transport-stats OpenMetrics
/// composition is a documented follow-up, so this v1 emits exactly the build-info
/// block a zenoh built without `stats` emits.
#[cfg(feature = "adminspace-metrics")]
pub fn metrics_text(version: &str) -> String {
    let mut out = String::new();
    out.push_str("# HELP zenoh_build Information about zenoh.\n");
    out.push_str("# TYPE zenoh_build gauge\n");
    out.push_str("zenoh_build{version=\"");
    push_openmetrics_label(version, &mut out);
    out.push_str("\"} 1\n");
    out
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
        };
        // The zenoh `local_data` key set with no peers / locators, in
        // serde_json's BTreeMap (alphabetical) key order:
        // locators/metadata/plugins/sessions/version/zid.
        assert_eq!(
            data.to_json(),
            r#"{"locators":[],"metadata":null,"plugins":null,"sessions":[],"version":"0.1.0","zid":"a1b2"}"#
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
            }],
        };
        // serde_json BTreeMap (alphabetical) key order at every level:
        // top locators/metadata/plugins/sessions/version/zid; session
        // links/peer/weight/whatami; link dst/src.
        assert_eq!(
            data.to_json(),
            concat!(
                r#"{"locators":["tcp/127.0.0.1:7447"],"metadata":null,"plugins":null,"#,
                r#""sessions":[{"links":[{"dst":"tcp/127.0.0.1:51000","src":"tcp/127.0.0.1:7447"}],"#,
                r#""peer":"c3d4","weight":null,"whatami":"router"}],"#,
                r#""version":"0.1.0","zid":"a1b2"}"#
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
            }],
        };
        assert!(data.to_json().contains(r#""whatami":"unknown""#));
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

    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_key_and_build_info_match_zenoh() {
        assert_eq!(admin_metrics_key("a1b2", "peer"), "@/a1b2/peer/metrics");
        // Byte-faithful to zenoh's unconditional build-info block
        // (adminspace.rs:714-720): HELP + TYPE gauge + the zenoh_build sample.
        assert_eq!(
            metrics_text("0.1.0"),
            "# HELP zenoh_build Information about zenoh.\n\
             # TYPE zenoh_build gauge\n\
             zenoh_build{version=\"0.1.0\"} 1\n"
        );
    }

    #[cfg(feature = "adminspace-metrics")]
    #[test]
    fn metrics_label_escapes_pathological_version() {
        assert!(metrics_text("v\"x").contains(r#"version="v\"x""#));
    }

    // R311y45 — a recording ReplyOut for the answer_admin_query unit tests:
    // captures each emitted (keyexpr, payload).
    #[derive(Default)]
    struct RecordingReply {
        replies: Vec<(String, Vec<u8>)>,
    }
    impl crate::query_sink::ReplyOut for RecordingReply {
        fn reply(&mut self, payload: &[u8]) {
            self.replies.push((String::new(), payload.to_vec()));
        }
        fn reply_keyed(&mut self, keyexpr: &str, payload: &[u8]) {
            self.replies.push((keyexpr.to_string(), payload.to_vec()));
        }
        fn reply_keyed_encoded(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            _encoding: Option<&crate::sample::EncodingHint>,
        ) {
            self.replies.push((keyexpr.to_string(), payload.to_vec()));
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
        }
    }

    fn admin_view(keyexpr: &str) -> crate::query_sink::BorrowedQuery<'_> {
        crate::query_sink::BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment: None,
            source_info: None,
            rid: 1,
            is_local: false,
        }
    }

    #[test]
    fn answer_admin_query_config_get_replies_only_the_config_json() {
        // A GET on `@/a1b2/peer/config` fires ONLY the config handler (root is 3
        // chunks, the query 4 — no intersect without a wildcard).
        let view = admin_view("@/a1b2/peer/config");
        let mut out = RecordingReply::default();
        answer_admin_query(
            &view,
            &mut out,
            &admin_ctx(true),
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
        answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &[], "{}");
        assert_eq!(out.replies.len(), 1, "only local_data fires");
        assert_eq!(out.replies[0].0, "@/a1b2/peer");
        assert_eq!(
            String::from_utf8(out.replies[0].1.clone()).unwrap(),
            r#"{"locators":[],"metadata":null,"plugins":null,"sessions":[],"version":"0.1.0","zid":"a1b2"}"#
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
        answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, "{}");
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
        answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, "{}");
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
        answer_admin_query(&view, &mut out, &admin_ctx(true), &[], &decls, "{}");
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
        answer_admin_query(
            &admin_view("@/a1b2/peer/subscriber/**"),
            &mut out,
            &admin_ctx(false),
            &[],
            &subs,
            "{}",
        );
        assert!(out.replies.is_empty(), "read=false gates all replies");
        // A `subscriber/**` GET must NOT list a Queryable declaration (kind scoping):
        // the queryable's entity key is `.../queryable/...`, disjoint from the GET.
        let mut out2 = RecordingReply::default();
        let qabls = [qabl_decl("demo/q", &["a1b2"])];
        answer_admin_query(
            &admin_view("@/a1b2/peer/subscriber/**"),
            &mut out2,
            &admin_ctx(true),
            &[],
            &qabls,
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
        answer_admin_query(&view, &mut out, &admin_ctx(false), &[], &[], "{}");
        assert!(out.replies.is_empty(), "read=false yields no replies");
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
        answer_router_admin_query(
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
        answer_router_admin_query(
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
        answer_router_admin_query(
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
        answer_router_admin_query(
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
        answer_router_admin_query(
            &admin_view("@/a1b2/router/linkstate/**"),
            &mut out,
            &router_ctx(false, Some("graph { R }"), Some("graph { P }"), &succ),
        );
        assert!(out.replies.is_empty(), "read=false yields no replies");
        // A `None` DOT leg is omitted even on a matching GET (the leg absent, not
        // an empty body).
        let mut out2 = RecordingReply::default();
        answer_router_admin_query(
            &admin_view("@/a1b2/router/linkstate/**"),
            &mut out2,
            &router_ctx(true, None, None, &[]),
        );
        assert!(
            out2.replies.is_empty(),
            "None routers_dot/peers_dot omit their legs"
        );
    }
}
