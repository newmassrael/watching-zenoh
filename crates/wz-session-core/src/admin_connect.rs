// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2824 (§5.23 `adminspace-write`) — upstream's config-WRITE surface for
//! `connect/endpoints`, with no allocator, so an MCU can be told at runtime
//! which peers to hold a session with.
//!
//! ## The surface is upstream's, not a new one
//!
//! A host tells a zenoh node to change its connections by writing its config:
//! a PUT on `@/<zid>/<whatami>/config/connect/endpoints` replaces the list and
//! a DEL removes it. That is what `send_push` in upstream's admin space does
//! for every key under `config/**`, gated by `adminspace.permissions.write`
//! (`zenoh/src/net/runtime/adminspace.rs` @
//! `if !conf.adminspace.permissions().write {`), default `false`. A host that
//! drives a stock zenohd this way drives a wz MCU the same way, and no second
//! grammar exists for a third implementation to learn.
//!
//! `adminspace` has the AP half of the same surface, but it needs `alloc`
//! throughout (`String` keys, `Vec` intents). This module is the part an MCU
//! can hold: one key, a fixed number of endpoints, each a fixed-room string.
//!
//! ## What it decides, in upstream's order
//!
//! 1. The permit, before anything about the key or the value — upstream
//!    returns right after logging when `permissions().write` is false.
//! 2. The key must lie in THIS node's config space, by the same set-semantics
//!    membership the AP decoder uses (`admin_config_space`), so a wildcard
//!    address reaches this node here exactly when it does there.
//! 3. The sub-key. Only `connect/endpoints` is carried here; any other config
//!    key is reported as such rather than silently dropped.
//! 4. The value. A PUT's payload is the JSON5 upstream's `insert_json5`
//!    accepts for this key: an array of endpoint strings, or the per-mode
//!    object (`router` / `peer` / `client`, nothing else, as upstream's
//!    `ModeValues` is `deny_unknown_fields`). A DEL is upstream's
//!    `config.remove`, which leaves the key at its default, the empty list.
//!
//! ## The list is the caller's, not the verdict's
//!
//! Eight endpoints of 64 bytes are over half a kilobyte. Carried inside the
//! verdict, that is moved through every return on a stack an MCU sizes by
//! hand. So the caller lends the storage and the verdict stays a few bytes:
//! the list is written into it and is meaningful only when the verdict is
//! [`crate::admin_connect::ConnectWriteOutcome::Replace`] (a full path: a
//! module's inner doc resolves from the crate root). A caller keeps its live
//! list apart from
//! that storage and swaps on `Replace`, so a refused write never disturbs the
//! connections the node holds.
//!
//! ## What it does not decide
//!
//! Whether an endpoint names a transport this build can dial. Upstream parses
//! each string as an `EndPoint` at insertion; the full locator grammar needs
//! `alloc` here (`locator::parse_locator`), so this surface checks the shape
//! every endpoint shares (`<proto>/<address>`, both non-empty) and the dial
//! layer answers the rest. A write upstream would refuse for a malformed
//! address can therefore reach the dial layer here; it cannot be applied as a
//! connection, and the dial layer says so.

use crate::admin_config_space::{
    subkey_in_config_space, write_config_space_pattern, ConfigSpaceRefusal,
};
use crate::caps::{MAX_LOCATOR_LEN, MAX_STATIC_CONNECT};
use crate::json5_lex::{Json5Error, Lexer};

/// The config sub-key this surface carries, as upstream spells it.
pub const CONNECT_ENDPOINTS_SUBKEY: &str = "connect/endpoints";

/// One endpoint, copied out of the write. Owned, because the buffer the
/// write arrived in is reused before the connection is made.
///
/// `heapless` on EVERY backing, not the crate's `BoundedString`: that type's
/// capacity is advisory when `alloc` is on, so the same write would be
/// refused as too long on an MCU and accepted on an AP. A verdict on the wire
/// must not depend on which allocator the node was built with.
pub type EndpointText = heapless::String<MAX_LOCATOR_LEN>;

/// R2841 — how a group of locators is to be used: upstream's
/// `LocatorsStrategy`, spelled `allOf` / `oneOf` on the wire:
/// `commons/zenoh-protocol/src/core/endpoint.rs` @ `pub enum LocatorsStrategy {`
/// Upstream's runtime implements only `AllOf` (open links to all locators of
/// the group) and reserves `OneOf`; both are accepted, as upstream accepts
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocatorsStrategy {
    /// `allOf`.
    AllOf,
    /// `oneOf`.
    OneOf,
}

impl LocatorsStrategy {
    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            LocatorsStrategy::AllOf => "allOf",
            LocatorsStrategy::OneOf => "oneOf",
        }
    }
}

/// R2841 — the group an entry came from, when the list element was
/// upstream's object form `{ strategy, locators: [...] }` rather than a
/// string. `index` numbers the groups of one list from 0, so consecutive
/// entries with the same index are one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointGroup {
    /// Which group of the list.
    pub index: u8,
    /// How the group's locators are to be used.
    pub strategy: LocatorsStrategy,
}

/// R2841 — one element of the written list, flattened: an endpoint, and the
/// group it was written in, if any. An EMPTY group (`locators: []`, which
/// upstream accepts) is one entry with an empty endpoint, so the list reads
/// back as it was written; it names nothing to dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEntry {
    /// The endpoint text, `<proto>/<address>[?..][#..]`; empty only for an
    /// empty group.
    pub endpoint: EndpointText,
    /// The group this entry was written in; `None` for a bare string.
    pub group: Option<EndpointGroup>,
}

impl ConnectEntry {
    /// A bare endpoint, not in a group.
    pub fn single(endpoint: EndpointText) -> Self {
        Self {
            endpoint,
            group: None,
        }
    }

    /// The endpoint text.
    pub fn as_str(&self) -> &str {
        &self.endpoint
    }
}

/// The endpoint list a write carries, groups flattened into their entries.
/// `heapless` for the same reason as [`EndpointText`]: `BoundedVec::push`
/// never refuses under `alloc`. The capacity counts entries, so a group of
/// three takes three.
pub type ConnectEndpoints = heapless::Vec<ConnectEntry, MAX_STATIC_CONNECT>;

/// R2841 — how many entries of `list` belong to group `index`.
pub fn group_len(list: &[ConnectEntry], index: u8) -> usize {
    list.iter()
        .filter(|e| e.group.map(|g| g.index) == Some(index) && !e.endpoint.is_empty())
        .count()
}

/// A config write as it arrived: a PUT with its payload, or a DEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigWriteBody<'a> {
    /// A PUT, with its payload.
    Put(&'a [u8]),
    /// A DEL.
    Del,
}

/// The verdict on one arriving write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectWriteOutcome {
    /// The key is not in this node's config space. Upstream never sees it.
    NotThisSpace,
    /// A `**` in the zid or whatami slot: the sub-key is underdetermined, and
    /// the AP decoder refuses the same address for the same reason
    /// (`AdminConfigWriteSpace::subkey`).
    AmbiguousSpaceAddress,
    /// `adminspace.permissions.write` is false. Upstream logs an error and
    /// applies nothing.
    Denied,
    /// A key in this node's config space other than `connect/endpoints`.
    /// This surface does not carry it.
    OtherKey,
    /// The payload is not the JSON5 this key takes.
    Malformed(Json5Error),
    /// More endpoints than [`MAX_STATIC_CONNECT`].
    TooMany,
    /// One endpoint is longer than [`MAX_LOCATOR_LEN`] bytes.
    EndpointTooLong,
    /// An endpoint is not `<proto>/<address>`.
    NotAnEndpoint,
    /// Hold sessions with exactly the endpoints now in the caller's list.
    Replace,
    /// The key was removed: back to the default, no configured endpoints.
    Remove,
}

/// Room for `@/<zid>/<whatami>/config/**`: a zid is at most 16 bytes, so 32
/// hex digits, and the longest `whatami` is `router`.
const PATTERN_ROOM: usize = 64;

/// How deep a value this surface will skip inside the per-mode object. The
/// only members it skips are rejected ones, so this bounds work, not meaning.
const SKIP_DEPTH: usize = 4;

/// Decide one config write for the node `zid_hex` / `whatami`, with the
/// node's current `permissions.write` passed in by the caller (it is the
/// caller's live config, read per write as upstream reads it). The endpoint
/// list is written into `out`, which is cleared first; it is the new list
/// only when the verdict is [`ConnectWriteOutcome::Replace`].
///
/// The permit is checked first and the space second — the AP decoder's order,
/// `adminspace::parse_admin_config_write`, which is upstream's `send_push`
/// order. Membership is `admin_config_space`, the code that decoder uses, so a
/// wildcard address (`@/*/peer/config/connect/endpoints`) is this node's here
/// exactly when it is there.
pub fn parse_connect_endpoints_write(
    zid_hex: &str,
    whatami: &str,
    keyexpr: &str,
    body: ConfigWriteBody<'_>,
    permissions_write: bool,
    out: &mut ConnectEndpoints,
) -> ConnectWriteOutcome {
    out.clear();
    if !permissions_write {
        return ConnectWriteOutcome::Denied;
    }
    let mut pattern: heapless::String<PATTERN_ROOM> = heapless::String::new();
    if write_config_space_pattern(&mut pattern, zid_hex, whatami).is_err() {
        return ConnectWriteOutcome::NotThisSpace;
    }
    let subkey = match subkey_in_config_space(&pattern, keyexpr) {
        Ok(subkey) => subkey,
        Err(ConfigSpaceRefusal::NotInSpace) => return ConnectWriteOutcome::NotThisSpace,
        Err(ConfigSpaceRefusal::AmbiguousSpaceAddress) => {
            return ConnectWriteOutcome::AmbiguousSpaceAddress
        }
    };
    if subkey != CONNECT_ENDPOINTS_SUBKEY {
        return ConnectWriteOutcome::OtherKey;
    }
    match body {
        ConfigWriteBody::Del => ConnectWriteOutcome::Remove,
        ConfigWriteBody::Put(payload) => match decode_endpoints(payload, whatami, out) {
            Ok(()) => ConnectWriteOutcome::Replace,
            Err(refusal) => {
                out.clear();
                refusal.into()
            }
        },
    }
}

/// Every way a value can be refused. Small, so a `Result` carrying it costs
/// nothing to return.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    Malformed(Json5Error),
    TooMany,
    EndpointTooLong,
    NotAnEndpoint,
}

impl From<Json5Error> for Refusal {
    fn from(e: Json5Error) -> Self {
        Refusal::Malformed(e)
    }
}

impl From<Refusal> for ConnectWriteOutcome {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Malformed(e) => ConnectWriteOutcome::Malformed(e),
            Refusal::TooMany => ConnectWriteOutcome::TooMany,
            Refusal::EndpointTooLong => ConnectWriteOutcome::EndpointTooLong,
            Refusal::NotAnEndpoint => ConnectWriteOutcome::NotAnEndpoint,
        }
    }
}

fn decode_endpoints(
    payload: &[u8],
    whatami: &str,
    out: &mut ConnectEndpoints,
) -> Result<(), Refusal> {
    let text = core::str::from_utf8(payload).map_err(|e| Json5Error {
        offset: e.valid_up_to(),
        expected: "UTF-8",
    })?;
    let mut lex = Lexer::new(text);
    lex.skip_trivia()?;
    match lex.peek() {
        Some(b'[') => endpoint_array(&mut lex, Some(out))?,
        Some(b'{') => per_mode(&mut lex, whatami, out)?,
        _ => return Err(lex.err("an endpoint array or a per-mode object").into()),
    }
    lex.skip_trivia()?;
    if !lex.at_end() {
        return Err(lex.err("end of document").into());
    }
    Ok(())
}

/// `{ router: [...], peer: [...], client: [...] }`, every member optional,
/// no other member allowed, none twice. The member for `whatami` fills
/// `out`; the others are checked the same way and discarded, because
/// upstream deserializes the whole object and refuses a bad member whichever
/// mode it names. An absent member for `whatami` leaves `out` empty, the
/// default.
fn per_mode(lex: &mut Lexer<'_>, whatami: &str, out: &mut ConnectEndpoints) -> Result<(), Refusal> {
    lex.bump(); // '{'
    let mut seen = [false; 3];
    loop {
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b'}') => {
                lex.bump();
                return Ok(());
            }
            None => return Err(lex.err("} closing an object").into()),
            _ => {}
        }
        let name_at = lex.pos();
        let name = lex.member_name()?;
        let slot = ["router", "peer", "client"]
            .iter()
            .position(|m| name.eq_str(m))
            .ok_or(Json5Error {
                offset: name_at,
                expected: "one of router, peer, client",
            })?;
        if seen[slot] {
            return Err(Json5Error {
                offset: name_at,
                expected: "each mode at most once",
            }
            .into());
        }
        seen[slot] = true;
        lex.skip_trivia()?;
        lex.expect(b':', ": after a member name")?;
        lex.skip_trivia()?;
        if lex.peek() != Some(b'[') {
            let _ = lex.skip_value(SKIP_DEPTH);
            return Err(Json5Error {
                offset: name_at,
                expected: "an endpoint array for the mode",
            }
            .into());
        }
        let target = if name.eq_str(whatami) {
            Some(&mut *out)
        } else {
            None
        };
        endpoint_array(lex, target)?;
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b',') => lex.bump(),
            Some(b'}') => {}
            _ => return Err(lex.err(", or } after a member").into()),
        }
    }
}

/// `[ element, ... ]`, each element an endpoint string or, R2841, upstream's
/// group object `{ strategy, locators: [...] }` (its `EndPoints` is
/// `untagged`: a string is `Single`, a map is `Locators`). With `out`, the
/// entries are pushed there; without it they are checked against the same
/// limits and dropped.
fn endpoint_array(
    lex: &mut Lexer<'_>,
    mut out: Option<&mut ConnectEndpoints>,
) -> Result<(), Refusal> {
    lex.bump(); // '['
    let mut count = 0usize;
    let mut groups = 0usize;
    loop {
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b']') => {
                lex.bump();
                return Ok(());
            }
            None => return Err(lex.err("] closing an array").into()),
            Some(b'{') => {
                let index = u8::try_from(groups).map_err(|_| Refusal::TooMany)?;
                groups += 1;
                endpoint_group(lex, index, &mut count, out.as_deref_mut())?;
            }
            _ => {
                if !lex.at_string() {
                    return Err(lex.err("an endpoint string or a locators object").into());
                }
                let text = endpoint_string(lex)?;
                push_entry(ConnectEntry::single(text), &mut count, out.as_deref_mut())?;
            }
        }
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b',') => lex.bump(),
            Some(b']') => {}
            _ => return Err(lex.err(", or ] after an element").into()),
        }
    }
}

/// One endpoint string, decoded and shape-checked.
fn endpoint_string(lex: &mut Lexer<'_>) -> Result<EndpointText, Refusal> {
    let s = lex.string()?;
    let mut text = EndpointText::new();
    if s.decode_into(&mut text).is_err() {
        return Err(Refusal::EndpointTooLong);
    }
    if !endpoint_shape_ok(&text) {
        return Err(Refusal::NotAnEndpoint);
    }
    Ok(text)
}

fn push_entry(
    entry: ConnectEntry,
    count: &mut usize,
    out: Option<&mut ConnectEndpoints>,
) -> Result<(), Refusal> {
    *count += 1;
    if *count > MAX_STATIC_CONNECT {
        return Err(Refusal::TooMany);
    }
    if let Some(list) = out {
        // Cannot fail: `count` was checked against the same capacity.
        let _ = list.push(entry);
    }
    Ok(())
}

/// R2841 — `{ strategy: "allOf" | "oneOf", locators: [ "...", ... ] }`, the
/// way upstream's `EndPoints` visitor reads a map: both members required,
/// each at most once, and any OTHER member skipped, since its helper struct
/// does not deny unknown fields (read at
/// `commons/zenoh-protocol/src/core/endpoint.rs` @ `struct LocatorsHelper {`).
/// The locators are pushed as entries of group `index`; an empty group is one
/// entry with no endpoint, so it reads back as written.
fn endpoint_group(
    lex: &mut Lexer<'_>,
    index: u8,
    count: &mut usize,
    mut out: Option<&mut ConnectEndpoints>,
) -> Result<(), Refusal> {
    let open_at = lex.pos();
    lex.bump(); // '{'
    let mut strategy: Option<LocatorsStrategy> = None;
    // The locators are held until the strategy is known, as they may come
    // first. Room for the whole list: a group cannot be larger than it.
    let mut locators: heapless::Vec<EndpointText, MAX_STATIC_CONNECT> = heapless::Vec::new();
    let mut saw_locators = false;
    loop {
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b'}') => {
                lex.bump();
                break;
            }
            None => return Err(lex.err("} closing a locators object").into()),
            _ => {}
        }
        let name_at = lex.pos();
        let name = lex.member_name()?;
        lex.skip_trivia()?;
        lex.expect(b':', ": after a member name")?;
        lex.skip_trivia()?;
        if name.eq_str("strategy") {
            if strategy.is_some() {
                return Err(duplicate(name_at));
            }
            if !lex.at_string() {
                return Err(lex.err("\"allOf\" or \"oneOf\"").into());
            }
            let at = lex.pos();
            let s = lex.string()?;
            strategy = Some(if s.eq_str("allOf") {
                LocatorsStrategy::AllOf
            } else if s.eq_str("oneOf") {
                LocatorsStrategy::OneOf
            } else {
                return Err(Json5Error {
                    offset: at,
                    expected: "\"allOf\" or \"oneOf\"",
                }
                .into());
            });
        } else if name.eq_str("locators") {
            if saw_locators {
                return Err(duplicate(name_at));
            }
            saw_locators = true;
            lex.expect(b'[', "a locators array")?;
            loop {
                lex.skip_trivia()?;
                match lex.peek() {
                    Some(b']') => {
                        lex.bump();
                        break;
                    }
                    None => return Err(lex.err("] closing an array").into()),
                    _ => {}
                }
                if !lex.at_string() {
                    return Err(lex.err("an endpoint string").into());
                }
                let text = endpoint_string(lex)?;
                if locators.push(text).is_err() {
                    return Err(Refusal::TooMany);
                }
                lex.skip_trivia()?;
                match lex.peek() {
                    Some(b',') => lex.bump(),
                    Some(b']') => {}
                    _ => return Err(lex.err(", or ] after an element").into()),
                }
            }
        } else {
            lex.skip_value(SKIP_DEPTH)?;
        }
        lex.skip_trivia()?;
        match lex.peek() {
            Some(b',') => lex.bump(),
            Some(b'}') => {}
            _ => return Err(lex.err(", or } after a member").into()),
        }
    }
    let Some(strategy) = strategy else {
        return Err(Json5Error {
            offset: open_at,
            expected: "a strategy member",
        }
        .into());
    };
    if !saw_locators {
        return Err(Json5Error {
            offset: open_at,
            expected: "a locators member",
        }
        .into());
    }
    let group = Some(EndpointGroup { index, strategy });
    if locators.is_empty() {
        return push_entry(
            ConnectEntry {
                endpoint: EndpointText::new(),
                group,
            },
            count,
            out,
        );
    }
    for endpoint in locators {
        push_entry(ConnectEntry { endpoint, group }, count, out.as_deref_mut())?;
    }
    Ok(())
}

fn duplicate(at: usize) -> Refusal {
    Json5Error {
        offset: at,
        expected: "each member at most once",
    }
    .into()
}

/// The shape every endpoint shares: a protocol, a `/`, an address.
fn endpoint_shape_ok(text: &str) -> bool {
    match text.split_once('/') {
        Some((proto, rest)) => !proto.is_empty() && !rest.is_empty(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `std`, not `alloc`: this module builds without an allocator, and the
    // crate links `std` for tests only (lib.rs).
    use std::format;
    use std::vec::Vec;

    const ZID: &str = "a1b2";
    const KEY: &str = "@/a1b2/peer/config/connect/endpoints";

    fn write(
        key: &str,
        body: ConfigWriteBody<'_>,
        permit: bool,
    ) -> (ConnectWriteOutcome, Vec<ConnectEntry>) {
        let mut list = ConnectEndpoints::new();
        let _ = list.push(ConnectEntry::single(
            EndpointText::try_from("tcp/stale:1").unwrap(),
        ));
        let out = parse_connect_endpoints_write(ZID, "peer", key, body, permit, &mut list);
        (out, list.iter().cloned().collect())
    }

    fn put(payload: &str, permit: bool) -> (ConnectWriteOutcome, Vec<ConnectEntry>) {
        write(KEY, ConfigWriteBody::Put(payload.as_bytes()), permit)
    }

    fn texts(list: &[ConnectEntry]) -> Vec<&str> {
        list.iter().map(|e| e.as_str()).collect()
    }

    /// R2841 — upstream's object element, read as upstream's `EndPoints`
    /// visitor reads it: the locators flattened in order, each carrying its
    /// group's index and strategy, strings and groups mixed in one list.
    #[test]
    fn a_locators_object_is_a_group_of_entries() {
        let (out, list) = put(
            r#"["tcp/a:1", { strategy: "allOf", locators: ["tcp/b:1", "tcp/b:2"] },
               { locators: ["udp/c:1"], strategy: 'oneOf' }]"#,
            true,
        );
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert_eq!(texts(&list), ["tcp/a:1", "tcp/b:1", "tcp/b:2", "udp/c:1"]);
        assert_eq!(list[0].group, None);
        let all_of = Some(EndpointGroup {
            index: 0,
            strategy: LocatorsStrategy::AllOf,
        });
        assert_eq!((list[1].group, list[2].group), (all_of, all_of));
        assert_eq!(
            list[3].group,
            Some(EndpointGroup {
                index: 1,
                strategy: LocatorsStrategy::OneOf,
            })
        );
        assert_eq!(group_len(&list, 0), 2);
        assert_eq!(group_len(&list, 1), 1);
    }

    /// An empty group is kept, as one entry with no endpoint, so it reads
    /// back; it counts no locator. Unknown members are skipped, as upstream's
    /// helper struct skips them.
    #[test]
    fn an_empty_group_and_an_unknown_member_are_upstreams() {
        let (out, list) = put(
            r#"[{ strategy: "allOf", locators: [], note: {x: 1} }]"#,
            true,
        );
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert_eq!(list.len(), 1);
        assert!(list[0].endpoint.is_empty());
        assert_eq!(group_len(&list, 0), 0);
    }

    /// What upstream's visitor refuses: a missing or repeated member, a
    /// strategy it does not name, a locator that is not a string.
    #[test]
    fn a_locators_object_upstream_refuses_is_refused() {
        for doc in [
            r#"[{ locators: ["tcp/a:1"] }]"#,
            r#"[{ strategy: "allOf" }]"#,
            r#"[{ strategy: "allOf", strategy: "oneOf", locators: [] }]"#,
            r#"[{ strategy: "anyOf", locators: ["tcp/a:1"] }]"#,
            r#"[{ strategy: "allOf", locators: [1] }]"#,
            r#"[{ strategy: "allOf", locators: "tcp/a:1" }]"#,
        ] {
            assert!(
                matches!(put(doc, true).0, ConnectWriteOutcome::Malformed(_)),
                "{doc}"
            );
        }
        assert_eq!(
            put(r#"[{ strategy: "allOf", locators: ["tcp"] }]"#, true).0,
            ConnectWriteOutcome::NotAnEndpoint
        );
    }

    #[test]
    fn a_permitted_put_replaces_the_list_in_upstreams_json5() {
        let (out, list) = put(r#"["tcp/10.0.0.1:7447", 'udp/10.0.0.2:7447',]"#, true);
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert_eq!(texts(&list), ["tcp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        let (out, list) = put("[]", true);
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert!(list.is_empty(), "an empty list is a list");
    }

    #[test]
    fn a_del_removes_the_key() {
        let (out, list) = write(KEY, ConfigWriteBody::Del, true);
        assert_eq!(out, ConnectWriteOutcome::Remove);
        assert!(list.is_empty());
    }

    #[test]
    fn the_permit_is_checked_before_the_key_or_the_value() {
        // Upstream returns on a false permit before it looks at anything else,
        // so neither a malformed value nor another key changes the verdict.
        assert_eq!(put("not json", false).0, ConnectWriteOutcome::Denied);
        let other = write(
            "@/a1b2/peer/config/mode",
            ConfigWriteBody::Put(b"\"client\""),
            false,
        );
        assert_eq!(other.0, ConnectWriteOutcome::Denied);
        assert_eq!(
            write(KEY, ConfigWriteBody::Del, false).0,
            ConnectWriteOutcome::Denied
        );
    }

    #[test]
    fn a_refused_write_leaves_nothing_in_the_callers_list() {
        // The lent storage is cleared on every verdict but `Replace`, so a
        // caller that forgets to check cannot dial a half-decoded list.
        for (out, list) in [put("[\"tcp/a:1\", 7]", true), put("[]", false)] {
            assert_ne!(out, ConnectWriteOutcome::Replace);
            assert!(list.is_empty(), "{out:?} left {list:?}");
        }
    }

    #[test]
    fn only_this_nodes_config_space_is_this_surfaces_business() {
        for key in [
            "@/ffff/peer/config/connect/endpoints",
            "@/a1b2/router/config/connect/endpoints",
            "@/a1b2/peer/connect/endpoints",
            "@/a1b2/peer//config/connect/endpoints",
            "demo/connect/endpoints",
        ] {
            let out = write(key, ConfigWriteBody::Put(b"[]"), true).0;
            assert_eq!(out, ConnectWriteOutcome::NotThisSpace, "{key}");
        }
        // A wildcard address is this node's when upstream's set semantics say
        // so, and a `**` in a one-chunk slot is refused as the AP refuses it.
        for key in [
            "@/*/peer/config/connect/endpoints",
            "@/a1b2/*/config/connect/endpoints",
        ] {
            let out = write(key, ConfigWriteBody::Put(b"[]"), true).0;
            assert_eq!(out, ConnectWriteOutcome::Replace, "{key}");
        }
        let ambiguous = write(
            "@/**/config/connect/endpoints",
            ConfigWriteBody::Put(b"[]"),
            true,
        );
        assert_eq!(ambiguous.0, ConnectWriteOutcome::AmbiguousSpaceAddress);
        let other = write(
            "@/a1b2/peer/config/listen/endpoints",
            ConfigWriteBody::Put(b"[]"),
            true,
        );
        assert_eq!(other.0, ConnectWriteOutcome::OtherKey);
    }

    #[test]
    fn the_per_mode_object_selects_this_nodes_mode() {
        let doc = r#"{ router: ["tcp/r:1"], peer: ["tcp/p:1", "tcp/p:2"], /* c */ client: [] }"#;
        let (out, list) = put(doc, true);
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert_eq!(texts(&list), ["tcp/p:1", "tcp/p:2"]);
        // A mode the object does not name is the default, the empty list.
        let (out, list) = put(r#"{ router: ["tcp/r:1"] }"#, true);
        assert_eq!(out, ConnectWriteOutcome::Replace);
        assert!(list.is_empty());
    }

    #[test]
    fn the_per_mode_object_refuses_what_upstreams_modevalues_refuses() {
        for doc in [
            r#"{ peer: ["tcp/p:1"], gateway: ["tcp/g:1"] }"#,
            r#"{ peer: ["tcp/p:1"], peer: ["tcp/p:2"] }"#,
            r#"{ router: "tcp/r:1" }"#,
            r#"{ router: ["not-an-endpoint"], peer: ["tcp/p:1"] }"#,
        ] {
            assert_ne!(put(doc, true).0, ConnectWriteOutcome::Replace, "{doc}");
        }
    }

    #[test]
    fn a_value_that_is_not_an_endpoint_list_is_malformed() {
        for doc in [
            "",
            "\"tcp/a:1\"",
            "[1]",
            "[\"tcp/a:1\" \"tcp/b:1\"]",
            "[] []",
            "[\"tcp/a:1\"",
        ] {
            assert!(
                matches!(put(doc, true).0, ConnectWriteOutcome::Malformed(_)),
                "{doc:?}"
            );
        }
        let bad_utf8 = write(KEY, ConfigWriteBody::Put(&[b'[', 0xFF, b']']), true);
        assert!(matches!(bad_utf8.0, ConnectWriteOutcome::Malformed(_)));
    }

    #[test]
    fn the_fixed_room_is_a_verdict_not_a_truncation() {
        let nine = (0..=MAX_STATIC_CONNECT)
            .map(|i| format!("\"tcp/10.0.0.{i}:7447\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            put(&format!("[{nine}]"), true).0,
            ConnectWriteOutcome::TooMany
        );

        let long = format!("[\"tcp/{}:1\"]", "h".repeat(MAX_LOCATOR_LEN));
        assert_eq!(put(&long, true).0, ConnectWriteOutcome::EndpointTooLong);

        for doc in [r#"["tcp"]"#, r#"["/a:1"]"#, r#"["tcp/"]"#] {
            assert_eq!(
                put(doc, true).0,
                ConnectWriteOutcome::NotAnEndpoint,
                "{doc}"
            );
        }
    }
}
