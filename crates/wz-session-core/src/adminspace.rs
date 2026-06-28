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
/// `@/<zid>/<whatami>` admin queryable, the wz mirror of zenoh's
/// `config.adminspace.permissions` (`zenoh-config` `PermissionsConf`, read by
/// `send_request`, `adminspace.rs:457`). The `read` field is always present so
/// `Session::declare_adminspace`'s signature is feature-toggle-independent; the
/// GET gate that consults it is the `adminspace-read` atom (a separate cfg).
/// (zenoh's `PermissionsConf` also carries `write` — that joins this struct when
/// the `adminspace-write` atom lands, the gate that would consult it.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSpacePermissions {
    /// Allow admin GETs. zenoh `permissions.read` (`adminspace.rs:457`),
    /// default `true` (`zenoh-config` `PermissionsConf::default`, lib.rs:889).
    /// When `false` the admin queryable answers nothing — the querier receives
    /// only the terminating Final (zenoh replies a bare `ResponseFinal`,
    /// `adminspace.rs:462-467`).
    pub read: bool,
}

impl Default for AdminSpacePermissions {
    /// zenoh's `PermissionsConf` default is `read: true` (permissive GET).
    fn default() -> Self {
        Self { read: true }
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
        out.push_str("{\"locators\":[");
        for (i, loc) in self.locators.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_json_str(loc, &mut out);
        }
        out.push_str("],\"metadata\":null,\"plugins\":null,\"sessions\":[");
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
    config_json: &str,
) {
    if !ctx.read {
        return;
    }
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
    fn permissions_default_matches_zenoh_read_true() {
        // zenoh PermissionsConf::default() = read:true (lib.rs:889).
        assert!(AdminSpacePermissions::default().read);
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
        answer_admin_query(&view, &mut out, &admin_ctx(true), &[], "{}");
        assert_eq!(out.replies.len(), 1, "only local_data fires");
        assert_eq!(out.replies[0].0, "@/a1b2/peer");
        assert_eq!(
            String::from_utf8(out.replies[0].1.clone()).unwrap(),
            r#"{"locators":[],"metadata":null,"plugins":null,"sessions":[],"version":"0.1.0","zid":"a1b2"}"#
        );
    }

    #[test]
    fn answer_admin_query_read_false_answers_nothing() {
        // read=false: a deny answers NOTHING (the dispatch SSOT emits the Final).
        let view = admin_view("@/a1b2/peer/config");
        let mut out = RecordingReply::default();
        answer_admin_query(&view, &mut out, &admin_ctx(false), &[], "{}");
        assert!(out.replies.is_empty(), "read=false yields no replies");
    }
}
