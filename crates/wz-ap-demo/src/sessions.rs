// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 900 — `--sessions <file>`: the document that starts SEVERAL
//! local sessions in one demo process (a client session towards a router and a
//! peer session in a multicast group, for one).
//!
//! # The document
//!
//! A JSON5 object holding the `sessions:` list of a deploy machine
//! (`scripts/lib/deploy_sessions.py` documents every key) plus the machine's
//! default `zid`:
//!
//! ```text
//! {
//!   zid: "a1b2c3d4",                       // optional; every session inherits it
//!   sessions: [
//!     { name: "to_router", mode: "client", transport: "unicast",
//!       connect: { endpoints: ["tcp/192.0.2.10:7447"] } },
//!     { name: "group", mode: "peer", transport: "multicast",
//!       group: { endpoint: "udp/224.0.0.224:7446#iface=eth0",
//!                join_interval_ms: 2500, lease_ms: 10000 } },
//!   ],
//! }
//! ```
//!
//! # One rule set
//!
//! The rules are `deploy_sessions.py`'s, read in its AP column (an AP session's
//! link is its own endpoint, so `link` is optional and one session holds one
//! endpoint; per-session `limits` and `buffer_pools` are refused, because the AP
//! runtime has nothing per session to apply them to). This module MIRRORS them
//! rather than calling Python, and the two are held together by one case file,
//! `scripts/lib/deploy_sessions_ap_cases.json`: the validator's `--selftest` and
//! this module's `parity_tests` judge the same documents against the same refused key paths,
//! so a rule either side loses or gains reds one of them.
//!
//! What the validator cannot know is what THIS build can run: a multicast
//! session needs the `transport-multicast` feature, an `#iface=` tail needs
//! `locator-iface`, and an endpoint's scheme needs its link compiled in.
//! [`SessionsPlan::build_refusals`] answers that, after the rules, with the same
//! dotted key paths.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use wz::runtime_tokio::json5::{self, number_as_u64, Json5Value};

/// The keys a session may carry, `deploy_sessions.py`'s `SESSION_KEYS`.
const SESSION_KEYS: &[&str] = &[
    "name",
    "mode",
    "transport",
    "link",
    "zid",
    "connect",
    "listen",
    "accept",
    "group",
    "limits",
    "buffer_pools",
    "heap_budget_bytes",
];
const UNICAST_ONLY: &[&str] = &["connect", "listen", "accept"];
const MULTICAST_ONLY: &[&str] = &["group"];
const GROUP_KEYS: &[&str] = &["endpoint", "join_interval_ms", "lease_ms"];
/// The keys of the document itself. Everything else a deploy machine carries
/// (`platform`, `links`, `limits`, pools) describes hardware this process does
/// not have, so it is refused rather than read and ignored.
const DOCUMENT_KEYS: &[&str] = &["zid", "sessions"];

/// A group's JOIN interval when the document names none: upstream's
/// (`commons/zenoh-config/src/defaults.rs` @ `join_interval: Some(2500),`).
pub(crate) const DEFAULT_JOIN_INTERVAL_MS: u64 = 2_500;
/// A group's lease when the document names none: upstream's link lease, which
/// its multicast manager reads (`commons/zenoh-config/src/defaults.rs` @
/// `lease: 10_000,`).
pub(crate) const DEFAULT_GROUP_LEASE_MS: u64 = 10_000;

/// One refused key: its dotted path from the top of the document, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) path: String,
    pub(crate) why: String,
}

impl Refusal {
    fn new(path: impl Into<String>, why: impl Into<String>) -> Self {
        Refusal {
            path: path.into(),
            why: why.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.why)
    }
}

/// The role a session announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Client,
    Peer,
}

impl Mode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Client => "client",
            Mode::Peer => "peer",
        }
    }
}

/// The one link a session holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionLink {
    /// A unicast session that dials: the endpoints are tried in order and the
    /// first that opens is the session's link, as an upstream client connects.
    Connect { endpoints: Vec<String> },
    /// A unicast session that listens on one endpoint and holds up to
    /// `max_sessions` accepted sessions at once (`accept.max_sessions`, 1 when
    /// absent).
    Listen {
        endpoint: String,
        max_sessions: usize,
    },
    /// A multicast session joined to one group.
    Group {
        endpoint: String,
        join_interval_ms: u64,
        lease_ms: u64,
    },
}

impl SessionLink {
    pub(crate) fn transport(&self) -> &'static str {
        match self {
            SessionLink::Connect { .. } | SessionLink::Listen { .. } => "unicast",
            SessionLink::Group { .. } => "multicast",
        }
    }
}

/// One session the document starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionSpec {
    /// The session's position in the list, which every key path names.
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) mode: Mode,
    /// The session's own zid, else the document's, as written (zenoh's
    /// printed form). `None`: the session draws a random one at start.
    pub(crate) zid: Option<String>,
    pub(crate) link: SessionLink,
}

/// Every session of a document that passed the rules, in start order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionsPlan {
    pub(crate) sessions: Vec<SessionSpec>,
}

/// What this build of the demo can run, which the rules cannot know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildCapabilities {
    /// A multicast session (`transport-multicast`).
    pub(crate) multicast: bool,
    /// An `#iface=` tail on a group endpoint (`locator-iface`).
    pub(crate) iface: bool,
    /// The unicast link schemes compiled in.
    pub(crate) schemes: Vec<&'static str>,
}

impl BuildCapabilities {
    pub(crate) fn of_this_build() -> Self {
        BuildCapabilities {
            multicast: cfg!(feature = "transport-multicast"),
            iface: cfg!(feature = "locator-iface"),
            schemes: wz::runtime_tokio::compiled_in_link_schemes().to_vec(),
        }
    }
}

/// The `--sessions <file>` command line, or `None` when the flag is absent.
///
/// The document describes the WHOLE process, so the flag takes nothing beside
/// it: every other flag configures the one node a single-session run mode
/// starts, and none of them says which of several sessions it would mean.
/// Refusing the combination, rather than applying a flag to every session or to
/// none, is what keeps each existing flag meaning exactly what it meant.
pub(crate) fn sessions_flag(argv: &[String]) -> Option<Result<String, String>> {
    let at = argv.iter().position(|a| a == "--sessions")?;
    Some(match (argv.len(), argv.get(at + 1)) {
        (2, Some(path)) if at == 0 && !path.starts_with("--") => Ok(path.clone()),
        (_, None) => Err("--sessions needs a file".to_string()),
        (_, Some(path)) if path.starts_with("--") => Err("--sessions needs a file".to_string()),
        _ => {
            let others: Vec<&str> = argv
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != at && *i != at + 1)
                .map(|(_, a)| a.as_str())
                .collect();
            Err(format!(
                "--sessions describes every session of this process and takes no other \
                 argument (also given: {})",
                others.join(" ")
            ))
        }
    })
}

/// Read a `--sessions` document: its syntax, its own keys, then the shared
/// rules. Every refusal is returned, not the first, as the validator reports.
pub(crate) fn read_sessions_document(text: &str) -> Result<SessionsPlan, Vec<Refusal>> {
    let doc = json5::parse(text).map_err(|e| {
        vec![Refusal::new(
            "document",
            format!("not a JSON5 document: {e}"),
        )]
    })?;
    let Json5Value::Object(entries) = &doc else {
        return Err(vec![Refusal::new(
            "document",
            "must be an object with a `sessions` list",
        )]);
    };
    let mut refusals = Vec::new();
    for key in key_set(entries) {
        if !DOCUMENT_KEYS.contains(&key) {
            refusals.push(Refusal::new(
                key,
                "unknown key; the document holds `zid` and `sessions`",
            ));
        }
    }
    if field(entries, "sessions").is_none() {
        refusals.push(Refusal::new(
            "sessions",
            "required, a list of the sessions to start",
        ));
    }
    refusals.extend(rule_refusals(&doc));
    if refusals.is_empty() {
        Ok(plan_of(&doc))
    } else {
        Err(refusals)
    }
}

impl SessionsPlan {
    /// What `caps` cannot run, by key path. Empty when the build runs it all.
    pub(crate) fn build_refusals(&self, caps: &BuildCapabilities) -> Vec<Refusal> {
        let mut out = Vec::new();
        for s in &self.sessions {
            let path = format!("sessions[{}]", s.index);
            match &s.link {
                SessionLink::Group { endpoint, .. } => {
                    if !caps.multicast {
                        out.push(Refusal::new(
                            format!("{path}.transport"),
                            "a multicast session needs the `transport-multicast` build \
                             feature (build: cargo build -p wz-ap-demo --features \
                             transport-multicast)",
                        ));
                    }
                    if endpoint.contains('#') && !caps.iface {
                        out.push(Refusal::new(
                            format!("{path}.group.endpoint"),
                            "an `#iface=` tail needs the `locator-iface` build feature; \
                             without it the group would join on the default interface",
                        ));
                    }
                }
                SessionLink::Connect { endpoints } => {
                    for (i, ep) in endpoints.iter().enumerate() {
                        if let Some(why) = unicast_endpoint_problem(ep, caps) {
                            out.push(Refusal::new(format!("{path}.connect.endpoints[{i}]"), why));
                        }
                    }
                }
                SessionLink::Listen { endpoint, .. } => {
                    if let Some(why) = unicast_endpoint_problem(endpoint, caps) {
                        out.push(Refusal::new(format!("{path}.listen.endpoints[0]"), why));
                    }
                }
            }
        }
        out
    }
}

/// Why this build cannot open a unicast `endpoint`, or `None`.
fn unicast_endpoint_problem(endpoint: &str, caps: &BuildCapabilities) -> Option<String> {
    let scheme = endpoint.split('/').next().unwrap_or_default();
    if matches!(scheme, "tls" | "quic") {
        return Some(format!(
            "a `{scheme}/` endpoint needs certificate material, which a sessions \
             document does not carry"
        ));
    }
    if !caps.schemes.contains(&scheme) {
        return Some(format!(
            "`{scheme}` is not a link this build carries (it has: {})",
            caps.schemes.join(", ")
        ));
    }
    if endpoint.contains('#') {
        return Some(
            "a `#` tail on a unicast endpoint is not read by this dial; leave it out".to_string(),
        );
    }
    None
}

// ---------------------------------------------------------------------------
// The rules: `deploy_sessions.validate_machine` for a machine whose platform
// class is `ap` and which has no `links` table. Kept in the validator's order so
// the two read side by side.
// ---------------------------------------------------------------------------

/// Every rule refusal for a document; [] when it passes.
pub(crate) fn rule_refusals(doc: &Json5Value) -> Vec<Refusal> {
    let mut errors = Vec::new();
    let Json5Value::Object(machine) = doc else {
        return errors;
    };
    if let Some(zid) = field(machine, "zid") {
        if let Some(why) = zid_problem(zid) {
            errors.push(Refusal::new("zid", why));
        }
    }
    let Some(sessions) = field(machine, "sessions") else {
        return errors;
    };
    let sessions = match sessions {
        Json5Value::Array(items) if !items.is_empty() => items,
        _ => {
            errors.push(Refusal::new("sessions", "must be a non-empty list"));
            return errors;
        }
    };
    let machine_zid: Option<&str> = field(machine, "zid")
        .filter(|z| zid_problem(z).is_none())
        .and_then(as_str);

    let mut names: Vec<(String, usize)> = Vec::new();
    let mut zid_owner: Vec<((String, &'static str), String)> = Vec::new();
    let mut endpoint_owner: Vec<(String, String)> = Vec::new();

    for (i, s) in sessions.iter().enumerate() {
        let path = format!("sessions[{i}]");
        let Json5Value::Object(s) = s else {
            errors.push(Refusal::new(path, "must be a mapping"));
            continue;
        };
        for key in key_set(s) {
            if !SESSION_KEYS.contains(&key) {
                errors.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
            }
        }
        if has(s, "heap_budget_bytes") {
            errors.push(Refusal::new(
                format!("{path}.heap_budget_bytes"),
                "reserved and not implemented -- the heap profiles have no per-session \
                 heap budget; a session's budget is its static `buffer_pools`",
            ));
        }

        let mut label = path.clone();
        match field(s, "name").and_then(as_str) {
            Some(name) if name_ok(name) => {
                if let Some((_, first)) = names.iter().find(|(n, _)| n == name) {
                    errors.push(Refusal::new(
                        format!("{path}.name"),
                        format!("`{name}` is already the name of sessions[{first}]"),
                    ));
                } else {
                    names.push((name.to_string(), i));
                    label = format!("{path} (`{name}`)");
                }
            }
            _ => errors.push(Refusal::new(
                format!("{path}.name"),
                "required, `[a-z][a-z0-9_]*`",
            )),
        }

        let mode = field(s, "mode").and_then(as_str);
        if !matches!(mode, Some("client" | "peer")) {
            errors.push(Refusal::new(
                format!("{path}.mode"),
                "required, one of client, peer",
            ));
        }
        let transport: Option<&'static str> = match field(s, "transport").and_then(as_str) {
            Some("unicast") => Some("unicast"),
            Some("multicast") => Some("multicast"),
            _ => {
                errors.push(Refusal::new(
                    format!("{path}.transport"),
                    "required, one of unicast, multicast",
                ));
                None
            }
        };

        // AP: `link` is optional, and this document has no `links` table, so
        // a link that is named names nothing.
        if has(s, "link") {
            errors.push(Refusal::new(
                format!("{path}.link"),
                "required, a key of links; an AP session's link is its own endpoint \
                 and this document has no links table",
            ));
        }

        let mut own_zid = field(s, "zid");
        if let Some(z) = own_zid {
            if let Some(why) = zid_problem(z) {
                errors.push(Refusal::new(format!("{path}.zid"), why));
                own_zid = None;
            }
        }
        let zid = own_zid.and_then(as_str).or(machine_zid);
        if let (Some(zid), Some(transport)) = (zid, transport) {
            let key = (zid.to_string(), transport);
            if let Some((_, owner)) = zid_owner.iter().find(|(k, _)| *k == key) {
                errors.push(Refusal::new(
                    format!("{path}.zid"),
                    format!(
                        "{label} and {owner} are both {transport} sessions with zid {zid}; \
                         sessions of one transport need distinct ids (only a unicast and a \
                         multicast session may share one)"
                    ),
                ));
            } else {
                zid_owner.push((key, label.clone()));
            }
        }

        let mut claim = |errors: &mut Vec<Refusal>, at: String, endpoint: &Json5Value| {
            let Some(endpoint) = as_str(endpoint) else {
                return;
            };
            let locator = endpoint.split('#').next().unwrap_or_default();
            if let Some((_, owner)) = endpoint_owner.iter().find(|(l, _)| l == locator) {
                errors.push(Refusal::new(
                    at,
                    format!("`{locator}` is already the link of {owner}; one session per link"),
                ));
            } else {
                endpoint_owner.push((locator.to_string(), label.clone()));
            }
        };

        match transport {
            Some("unicast") => {
                for key in MULTICAST_ONLY {
                    if has(s, key) {
                        errors.push(Refusal::new(
                            format!("{path}.{key}"),
                            format!("a unicast session has no `{key}`"),
                        ));
                    }
                }
                for key in ["connect", "listen"] {
                    if let Some(block) = field(s, key) {
                        endpoints(&mut errors, &format!("{path}.{key}"), block);
                    }
                }
                if !has(s, "connect") && !has(s, "listen") {
                    errors.push(Refusal::new(
                        format!("{path}.connect"),
                        "a unicast session needs `connect.endpoints` or `listen.endpoints`",
                    ));
                }
                if has(s, "connect") && has(s, "listen") {
                    errors.push(Refusal::new(
                        format!("{path}.listen"),
                        "an AP session holds one link, so it dials or it listens; declare \
                         a second session for the other",
                    ));
                } else if let Some(Json5Value::Object(listen)) = field(s, "listen") {
                    if let Some(Json5Value::Array(eps)) = field(listen, "endpoints") {
                        if eps.len() > 1 {
                            errors.push(Refusal::new(
                                format!("{path}.listen.endpoints"),
                                "an AP session listens on one endpoint (one link per session)",
                            ));
                        } else if let Some(first) = eps.first() {
                            claim(&mut errors, format!("{path}.listen.endpoints[0]"), first);
                        }
                    }
                }
                if let Some(acc) = field(s, "accept") {
                    if !has(s, "listen") {
                        errors.push(Refusal::new(
                            format!("{path}.accept"),
                            "only a session that listens accepts",
                        ));
                    }
                    match acc {
                        Json5Value::Object(acc) => {
                            for key in key_set(acc) {
                                if key != "max_sessions" {
                                    errors.push(Refusal::new(
                                        format!("{path}.accept.{key}"),
                                        "unknown key",
                                    ));
                                }
                            }
                            if field(acc, "max_sessions").and_then(positive_int).is_none() {
                                errors.push(Refusal::new(
                                    format!("{path}.accept.max_sessions"),
                                    "a positive integer",
                                ));
                            }
                        }
                        _ => {
                            errors.push(Refusal::new(format!("{path}.accept"), "must be a mapping"))
                        }
                    }
                }
            }
            Some("multicast") => {
                for key in UNICAST_ONLY {
                    if has(s, key) {
                        errors.push(Refusal::new(
                            format!("{path}.{key}"),
                            format!("a multicast session has no `{key}`"),
                        ));
                    }
                }
                if mode == Some("client") {
                    errors.push(Refusal::new(
                        format!("{path}.mode"),
                        "a multicast session is a `peer`",
                    ));
                }
                match field(s, "group") {
                    Some(Json5Value::Object(group)) => {
                        for key in key_set(group) {
                            if !GROUP_KEYS.contains(&key) {
                                errors.push(Refusal::new(
                                    format!("{path}.group.{key}"),
                                    "unknown key",
                                ));
                            }
                        }
                        let endpoint = field(group, "endpoint");
                        if let Some(why) = group_endpoint_problem(endpoint) {
                            errors.push(Refusal::new(format!("{path}.group.endpoint"), why));
                        } else if let Some(endpoint) = endpoint {
                            claim(&mut errors, format!("{path}.group.endpoint"), endpoint);
                        }
                        for key in ["join_interval_ms", "lease_ms"] {
                            if let Some(v) = field(group, key) {
                                if positive_int(v).is_none() {
                                    errors.push(Refusal::new(
                                        format!("{path}.group.{key}"),
                                        "a positive integer",
                                    ));
                                }
                            }
                        }
                    }
                    _ => errors.push(Refusal::new(
                        format!("{path}.group"),
                        "required for a multicast session",
                    )),
                }
            }
            _ => {}
        }

        // AP: nothing per session to apply a limit or a pool to.
        if has(s, "limits") {
            errors.push(Refusal::new(
                format!("{path}.limits"),
                "the AP runtime has no per-session table bound to apply a limit to",
            ));
        }
        if has(s, "buffer_pools") {
            errors.push(Refusal::new(
                format!("{path}.buffer_pools"),
                "an AP session has no pools of its own; its link buffers are the \
                 process's shared link-RX arena",
            ));
        }
    }
    errors
}

/// `_endpoints`: a `{ endpoints: [<locator>, ...] }` block.
fn endpoints(errors: &mut Vec<Refusal>, path: &str, block: &Json5Value) {
    let Json5Value::Object(block) = block else {
        errors.push(Refusal::new(
            path,
            "must be a mapping with an `endpoints` list",
        ));
        return;
    };
    for key in key_set(block) {
        if key != "endpoints" {
            errors.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    let eps = match field(block, "endpoints") {
        Some(Json5Value::Array(eps)) if !eps.is_empty() => eps,
        _ => {
            errors.push(Refusal::new(
                format!("{path}.endpoints"),
                "must be a non-empty list of locators",
            ));
            return;
        }
    };
    for (i, ep) in eps.iter().enumerate() {
        let ok = as_str(ep).is_some_and(|ep| ep.contains('/') && !ep.starts_with('/'));
        if !ok {
            errors.push(Refusal::new(
                format!("{path}.endpoints[{i}]"),
                "not a locator (`<proto>/<address>`)",
            ));
        }
    }
}

/// `zid_problem`: why a value is not a zenoh id upstream would parse.
fn zid_problem(value: &Json5Value) -> Option<&'static str> {
    let Some(value) = as_str(value) else {
        return Some("must be a string of lowercase hex digits");
    };
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.chars().any(char::is_uppercase) {
        return Some("uppercase hexadecimal is not accepted, use lowercase");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Some("must be lowercase hex digits only");
    }
    if value.starts_with('0') {
        return Some("leading 0s are not valid");
    }
    if value.len() > 32 {
        return Some("is longer than 16 bytes (32 hex digits)");
    }
    None
}

/// `group_endpoint_problem` for an AP: why a value is not an admissible group
/// endpoint.
fn group_endpoint_problem(value: Option<&Json5Value>) -> Option<String> {
    let Some(text) = value.and_then(as_str) else {
        return Some("must be a locator string".to_string());
    };
    let (locator, meta) = match text.split_once('#') {
        Some((l, m)) => (l, Some(m)),
        None => (text, None),
    };
    let Some(addr) = locator.strip_prefix("udp/") else {
        return Some("a group endpoint is `udp/<group>:<port>`".to_string());
    };
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Some("needs a port between 1 and 65535".to_string());
    };
    let port_ok = !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| (1..65536).contains(&p));
    if !port_ok {
        return Some("needs a port between 1 and 65535".to_string());
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Some(format!("`{host}` is not an IP address"));
    };
    if !ip.is_multicast() {
        return Some(format!("`{host}` is not a multicast group address"));
    }
    let meta = meta?;
    for pair in meta.split(';') {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (pair, None),
        };
        if key != "iface" {
            return Some(format!(
                "`#{pair}`: only the `#iface=` tail is admitted on a group endpoint"
            ));
        }
        match value {
            None | Some("") => {
                return Some(
                    "`#iface=` needs a value; leave the tail out for the default interface"
                        .to_string(),
                )
            }
            Some("auto") => {
                return Some(
                    "`auto` is not a word on a locator; leave the tail out for the default \
                     interface"
                        .to_string(),
                )
            }
            Some(_) => {}
        }
    }
    None
}

/// The plan of a document [`rule_refusals`] passed. Every lookup below is one
/// the rules already proved present and well-formed.
fn plan_of(doc: &Json5Value) -> SessionsPlan {
    let Json5Value::Object(machine) = doc else {
        unreachable!("the rules passed an object");
    };
    let machine_zid = field(machine, "zid").and_then(as_str);
    let Some(Json5Value::Array(items)) = field(machine, "sessions") else {
        unreachable!("the rules passed a sessions list");
    };
    let sessions = items
        .iter()
        .enumerate()
        .map(|(index, s)| {
            let Json5Value::Object(s) = s else {
                unreachable!("the rules passed every session as a mapping");
            };
            let text = |key: &str| field(s, key).and_then(as_str).unwrap_or_default();
            let mode = if text("mode") == "client" {
                Mode::Client
            } else {
                Mode::Peer
            };
            let zid = field(s, "zid")
                .and_then(as_str)
                .or(machine_zid)
                .map(str::to_string);
            let first_endpoint = |block: &str| -> Vec<String> {
                match field(s, block).and_then(|b| match b {
                    Json5Value::Object(b) => field(b, "endpoints"),
                    _ => None,
                }) {
                    Some(Json5Value::Array(eps)) => {
                        eps.iter().filter_map(as_str).map(str::to_string).collect()
                    }
                    _ => Vec::new(),
                }
            };
            let link = if text("transport") == "multicast" {
                let Some(Json5Value::Object(group)) = field(s, "group") else {
                    unreachable!("the rules passed a group block");
                };
                let ms = |key: &str, default: u64| {
                    field(group, key).and_then(positive_int).unwrap_or(default)
                };
                SessionLink::Group {
                    endpoint: field(group, "endpoint")
                        .and_then(as_str)
                        .unwrap_or_default()
                        .to_string(),
                    join_interval_ms: ms("join_interval_ms", DEFAULT_JOIN_INTERVAL_MS),
                    lease_ms: ms("lease_ms", DEFAULT_GROUP_LEASE_MS),
                }
            } else if has(s, "listen") {
                let max_sessions = match field(s, "accept") {
                    Some(Json5Value::Object(acc)) => field(acc, "max_sessions")
                        .and_then(positive_int)
                        .and_then(|n| usize::try_from(n).ok())
                        .unwrap_or(1),
                    _ => 1,
                };
                SessionLink::Listen {
                    endpoint: first_endpoint("listen").remove(0),
                    max_sessions,
                }
            } else {
                SessionLink::Connect {
                    endpoints: first_endpoint("connect"),
                }
            };
            SessionSpec {
                index,
                name: text("name").to_string(),
                mode,
                zid,
                link,
            }
        })
        .collect();
    SessionsPlan { sessions }
}

// ---------------------------------------------------------------------------
// Small readers over a JSON5 object. A duplicate key resolves last-wins, as the
// validator's `json`/`yaml` loads do.
// ---------------------------------------------------------------------------

fn field<'a>(entries: &'a [(String, Json5Value)], key: &str) -> Option<&'a Json5Value> {
    entries.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn has(entries: &[(String, Json5Value)], key: &str) -> bool {
    entries.iter().any(|(k, _)| k == key)
}

fn key_set(entries: &[(String, Json5Value)]) -> BTreeSet<&str> {
    entries.iter().map(|(k, _)| k.as_str()).collect()
}

fn as_str(value: &Json5Value) -> Option<&str> {
    match value {
        Json5Value::String(s) => Some(s),
        _ => None,
    }
}

/// `_positive_int`: an integer above zero (never a bool or a string).
fn positive_int(value: &Json5Value) -> Option<u64> {
    match value {
        Json5Value::Number(text) => number_as_u64(text).filter(|n| *n > 0),
        _ => None,
    }
}

/// `NAME_RE`: `^[a-z][a-z0-9_]*$`.
fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The shared case file judges this reader against `deploy_sessions.py`.
#[cfg(test)]
mod parity_tests {
    use super::*;

    const CASES: &str = include_str!("../../../scripts/lib/deploy_sessions_ap_cases.json");

    fn paths(refusals: &[Refusal]) -> BTreeSet<String> {
        refusals.iter().map(|r| r.path.clone()).collect()
    }

    /// Every case refuses exactly the key paths the validator refuses: a missing
    /// path is a rule this reader lost, an extra one a rule the validator does
    /// not have.
    #[test]
    fn every_shared_case_refuses_the_paths_the_validator_refuses() {
        let doc = json5::parse(CASES).expect("the case file parses");
        let Some(Json5Value::Array(cases)) = doc.get("cases") else {
            panic!("the case file has a `cases` list");
        };
        // Anti-vacuity, as the validator's own: a file that lost its cases
        // would agree with everything.
        assert!(cases.len() >= 20, "only {} case(s)", cases.len());
        let mut failures = Vec::new();
        for case in cases {
            let label = case.get("label").and_then(as_str).expect("a label");
            let document = case.get("document").expect("a document");
            let Some(Json5Value::Array(want)) = case.get("refuses") else {
                panic!("{label}: a `refuses` list");
            };
            let want: BTreeSet<String> = want
                .iter()
                .map(|p| as_str(p).expect("a path").to_string())
                .collect();
            let got = paths(&rule_refusals(document));
            if got != want {
                failures.push(format!("{label}: got {got:?}, want {want:?}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    const TWO: &str = r#"{
        zid: "a1b2c3d4",
        sessions: [
            { name: "to_router", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448"] } },
            { name: "group", mode: "peer", transport: "multicast", zid: "b1",
              group: { endpoint: "udp/224.0.0.224:7446#iface=lo" } },
            { name: "inbound", mode: "peer", transport: "unicast", zid: "c1",
              listen: { endpoints: ["tcp/127.0.0.1:0"] }, accept: { max_sessions: 3 } },
        ],
    }"#;

    /// The plan carries each session's link, its zid (own, else the
    /// document's) and upstream's group defaults where the document is silent.
    #[test]
    fn a_document_reads_into_one_spec_per_session() {
        let plan = read_sessions_document(TWO).expect("the document passes");
        assert_eq!(
            plan.sessions,
            vec![
                SessionSpec {
                    index: 0,
                    name: "to_router".into(),
                    mode: Mode::Client,
                    zid: Some("a1b2c3d4".into()),
                    link: SessionLink::Connect {
                        endpoints: vec!["tcp/127.0.0.1:7447".into(), "tcp/127.0.0.1:7448".into()],
                    },
                },
                SessionSpec {
                    index: 1,
                    name: "group".into(),
                    mode: Mode::Peer,
                    zid: Some("b1".into()),
                    link: SessionLink::Group {
                        endpoint: "udp/224.0.0.224:7446#iface=lo".into(),
                        join_interval_ms: DEFAULT_JOIN_INTERVAL_MS,
                        lease_ms: DEFAULT_GROUP_LEASE_MS,
                    },
                },
                SessionSpec {
                    index: 2,
                    name: "inbound".into(),
                    mode: Mode::Peer,
                    zid: Some("c1".into()),
                    link: SessionLink::Listen {
                        endpoint: "tcp/127.0.0.1:0".into(),
                        max_sessions: 3,
                    },
                },
            ]
        );
    }

    /// No zid anywhere is no zid: the session draws one when it starts.
    #[test]
    fn a_session_with_no_zid_anywhere_draws_one() {
        let plan = read_sessions_document(
            r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
                 connect: { endpoints: ["tcp/127.0.0.1:7447"] } } ] }"#,
        )
        .expect("passes");
        assert_eq!(plan.sessions[0].zid, None);
    }

    fn refused(text: &str) -> Vec<String> {
        read_sessions_document(text)
            .expect_err("refused")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The document's own refusals, which the validator does not judge: its
    /// syntax, its shape, a key a machine has and this process does not, and a
    /// missing list.
    #[test]
    fn the_document_itself_is_refused_by_key() {
        assert!(refused("{ sessions: [ ")[0].starts_with("document: not a JSON5 document"));
        assert!(refused("[]")[0].starts_with("document: must be an object"));
        let r = refused(r#"{ zid: "a1" }"#);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with("sessions: required"), "{r:?}");
        let r = refused(
            r#"{ links: {}, sessions: [ { name: "a", mode: "client", transport: "unicast",
                 connect: { endpoints: ["tcp/127.0.0.1:7447"] } } ] }"#,
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with("links: unknown key"), "{r:?}");
    }

    /// A refusal prints as the dotted path, then why.
    #[test]
    fn a_refusal_names_the_key_as_a_dotted_path() {
        let r = refused(
            r#"{ sessions: [ { name: "g", mode: "peer", transport: "multicast",
                 group: { endpoint: "udp/224.0.0.224:7446#iface=auto" } } ] }"#,
        );
        assert_eq!(
            r,
            vec![
                "sessions[0].group.endpoint: `auto` is not a word on a locator; leave the \
                 tail out for the default interface"
                    .to_string()
            ]
        );
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    /// The flag stands alone: absent is `None`, alone is the path, and with
    /// anything beside it, or without a file, it is refused naming why.
    #[test]
    fn the_flag_takes_one_file_and_nothing_else() {
        assert_eq!(
            sessions_flag(&argv(&["--connect", "tcp/127.0.0.1:7447"])),
            None
        );
        assert_eq!(
            sessions_flag(&argv(&["--sessions", "two.json5"])),
            Some(Ok("two.json5".to_string()))
        );
        for bad in [
            &["--sessions"][..],
            &["--sessions", "--connect"][..],
            &["--sessions", "two.json5", "--connect", "tcp/127.0.0.1:7447"][..],
            &["--zid", "a1", "--sessions", "two.json5"][..],
        ] {
            let err = sessions_flag(&argv(bad))
                .expect("present")
                .expect_err("refused");
            assert!(err.starts_with("--sessions "), "{bad:?} -> {err}");
        }
        let err = sessions_flag(&argv(&["--sessions", "two.json5", "--zid", "a1"]))
            .expect("present")
            .expect_err("refused");
        assert!(err.ends_with("(also given: --zid a1)"), "{err}");
    }

    fn caps(multicast: bool, iface: bool) -> BuildCapabilities {
        BuildCapabilities {
            multicast,
            iface,
            schemes: vec!["tcp", "udp", "tls"],
        }
    }

    /// What a build cannot run is refused at the key that asks for it.
    #[test]
    fn a_build_refuses_what_it_cannot_run_by_key() {
        let plan = read_sessions_document(TWO).expect("passes");
        assert!(plan.build_refusals(&caps(true, true)).is_empty());
        let paths: Vec<String> = plan
            .build_refusals(&caps(false, false))
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(
            paths,
            vec!["sessions[1].transport", "sessions[1].group.endpoint"]
        );

        let plan = read_sessions_document(
            r#"{ sessions: [
                { name: "a", mode: "client", transport: "unicast",
                  connect: { endpoints: ["tls/127.0.0.1:7447", "ws/127.0.0.1:7448",
                                         "tcp/127.0.0.1:7449#iface=lo", "tcp/127.0.0.1:7450"] } },
                { name: "b", mode: "peer", transport: "unicast", zid: "b2",
                  listen: { endpoints: ["quic/127.0.0.1:7451"] } } ] }"#,
        )
        .expect("passes the rules");
        let paths: Vec<String> = plan
            .build_refusals(&caps(true, true))
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                "sessions[0].connect.endpoints[0]",
                "sessions[0].connect.endpoints[1]",
                "sessions[0].connect.endpoints[2]",
                "sessions[1].listen.endpoints[0]",
            ]
        );
    }
}
