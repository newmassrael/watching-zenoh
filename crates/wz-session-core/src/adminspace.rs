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

/// Append `s` to `out` as a quoted, escaped JSON string. Covers the RFC 8259
/// mandatory escapes (`"`, `\`, and the C0 control range); the admin payload's
/// strings (hex zids, socket-address locators, a version) do not contain them in
/// practice, but the escape keeps the emitter a correct JSON string serializer
/// rather than a `format!` a stray byte could corrupt.
fn push_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
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
        assert_eq!(admin_root_key("0", "router"), "@/0/router");
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
}
