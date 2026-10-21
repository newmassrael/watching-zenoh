// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The list of endpoints a node holds sessions with, with no allocator.
//!
//! These types were `admin_connect`'s, because the first thing that filled the list was upstream's
//! `connect/endpoints` config write. Nothing in them is the admin space's: a firmware that dials a
//! router named at build time holds the same list, and has no use for the write parser, the JSON5
//! lexer or the config-space addressing that `adminspace-write` brings. So they live here, behind
//! their own feature (`connect-endpoints`), and `admin_connect` re-exports them under the names it
//! always had.

use crate::caps::{MAX_LOCATOR_LEN, MAX_STATIC_CONNECT};

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
