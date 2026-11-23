// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-limit-bindings.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! Where each limit is bound, as the declaration states it: what the limit does to storage, the
//! scopes that each hold one value, the latest stage each storage profile decides it at, and what
//! a peer sees of it. The limit's value is the constant of the same name in `crate::caps`.

use crate::policy_binding::{Binding, Driven, LimitBinding, LimitKind, Scope, Storage, Wire};

/// Where [`super::MAX_KEYEXPR_BYTES`] is bound.
pub const MAX_KEYEXPR_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::KEY_ARENA_BYTES`] is bound.
pub const KEY_ARENA_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967291)),
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_SUBSCRIPTIONS`] is bound.
pub const MAX_SUBSCRIPTIONS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MATCH_MEMO_SLOTS`] is bound.
pub const MATCH_MEMO_SLOTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::MATCH_MEMO_FIXED_SLOTS`] is bound.
pub const MATCH_MEMO_FIXED_SLOTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Capacity,
    scope: &[Scope::Session],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MATCH_MEMO_KEY_BYTES`] is bound.
pub const MATCH_MEMO_KEY_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Capacity,
    scope: &[Scope::Session],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::DELIVERY_LANE_EVENTS`] is bound.
pub const DELIVERY_LANE_EVENTS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::DELIVERY_LANE_BYTES`] is bound.
pub const DELIVERY_LANE_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::DELIVERY_LANE_CALLBACKS`] is bound.
pub const DELIVERY_LANE_CALLBACKS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_QUERYABLES`] is bound.
pub const MAX_QUERYABLES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_PENDING_QUERIES`] is bound.
pub const MAX_PENDING_QUERIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::LINK_NOTED_REQUESTS`] is bound.
pub const LINK_NOTED_REQUESTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_DECL_OBSERVERS`] is bound.
pub const MAX_DECL_OBSERVERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_LIVELINESS_SUBSCRIPTIONS`] is bound.
pub const MAX_LIVELINESS_SUBSCRIPTIONS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_LOCAL_TOKENS`] is bound.
pub const MAX_LOCAL_TOKENS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_PUBLISHERS`] is bound.
pub const MAX_PUBLISHERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_QUERIERS`] is bound.
pub const MAX_QUERIERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_MATCHING_LISTENERS`] is bound.
pub const MAX_MATCHING_LISTENERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_DECLARED_KEYEXPRS`] is bound.
pub const MAX_DECLARED_KEYEXPRS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::HELD_SESSIONS`] is bound.
pub const HELD_SESSIONS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_SAMPLES`] is bound.
pub const HELD_SAMPLES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_REPLIES`] is bound.
pub const HELD_REPLIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_QUERIES`] is bound.
pub const HELD_QUERIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_PAYLOADS`] is bound.
pub const HELD_PAYLOADS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_CONFIGS`] is bound.
pub const HELD_CONFIGS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_HELLOS`] is bound.
pub const HELD_HELLOS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::HELD_PAYLOAD_BYTES`] is bound.
pub const HELD_PAYLOAD_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::CONFIG_ENTRIES`] is bound.
pub const CONFIG_ENTRIES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 255)),
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_SCOUT_HELLOS`] is bound.
pub const MAX_SCOUT_HELLOS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::SCOUT_HELLO_LOCATORS`] is bound.
pub const SCOUT_HELLO_LOCATORS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::CONFIG_DOCUMENT_DEPTH`] is bound.
pub const CONFIG_DOCUMENT_DEPTH: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((3, 64)),
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::CONFIG_TEXT_BYTES`] is bound.
pub const CONFIG_TEXT_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 1048576)),
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_PENDING_LIVELINESS_GETS`] is bound.
pub const MAX_PENDING_LIVELINESS_GETS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_PENDING_DECLARES`] is bound.
pub const MAX_PENDING_DECLARES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_INBOUND_SUB_INTERESTS`] is bound.
pub const MAX_INBOUND_SUB_INTERESTS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_PEER_KEYEXPR_ALIASES`] is bound.
pub const MAX_PEER_KEYEXPR_ALIASES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_SHARED_KEY_IDS`] is bound.
pub const MAX_SHARED_KEY_IDS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::MAX_REMOTE_DECLS`] is bound.
pub const MAX_REMOTE_DECLS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_PENDING_REPLIES`] is bound.
pub const MAX_PENDING_REPLIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_PENDING_FINALS`] is bound.
pub const MAX_PENDING_FINALS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_REPLY_PAYLOAD_BYTES`] is bound.
pub const MAX_REPLY_PAYLOAD_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_ADMIN_REPLY_BYTES`] is bound.
pub const MAX_ADMIN_REPLY_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_ADMIN_LOCATORS`] is bound.
pub const MAX_ADMIN_LOCATORS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_ADMIN_SESSION_LINKS`] is bound.
pub const MAX_ADMIN_SESSION_LINKS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Session],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_MULTICAST_REPLIES`] is bound.
pub const MAX_MULTICAST_REPLIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_TASKS`] is bound.
pub const MAX_TASKS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_TIMERS`] is bound.
pub const MAX_TIMERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_TICKERS`] is bound.
pub const MAX_TICKERS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Build),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_LOCATOR_LEN`] is bound.
pub const MAX_LOCATOR_LEN: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Runtime, Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_STATIC_CONNECT`] is bound.
pub const MAX_STATIC_CONNECT: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_PEER_NODES`] is bound.
pub const MAX_PEER_NODES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: None,
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MAX_FACES`] is bound.
pub const MAX_FACES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::MAX_ACCEPT_PENDING`] is bound.
pub const MAX_ACCEPT_PENDING: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::RX_POOL_BUFFERS`] is bound.
pub const RX_POOL_BUFFERS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::TX_POOL_SLOTS`] is bound.
pub const TX_POOL_SLOTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::SESSION_MAX_PEER_KEYEXPR_ALIASES`] is bound.
pub const SESSION_MAX_PEER_KEYEXPR_ALIASES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::SESSION_MAX_REMOTE_DECLS`] is bound.
pub const SESSION_MAX_REMOTE_DECLS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::SESSION_MAX_INBOUND_SUB_INTERESTS`] is bound.
pub const SESSION_MAX_INBOUND_SUB_INTERESTS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::QUERIER_MAX_PENDING_QUERIES`] is bound.
pub const QUERIER_MAX_PENDING_QUERIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Live),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::TX_NO_PROGRESS_WINDOW_US`] is bound.
pub const TX_NO_PROGRESS_WINDOW_US: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 5000000)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Timing,
};

/// Where [`super::TX_EXPIRY_CLOSE_AFTER`] is bound.
pub const TX_EXPIRY_CLOSE_AFTER: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: Some((0, 65535)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Timing,
};

/// Where [`super::DATAGRAM_FRAGMENT_BURST`] is bound.
pub const DATAGRAM_FRAGMENT_BURST: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Live),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::DATAGRAM_FRAGMENT_GAP_US`] is bound.
pub const DATAGRAM_FRAGMENT_GAP_US: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 1000000)),
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Live),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::QUERY_PARAMETERS_MAX_BYTES`] is bound.
pub const QUERY_PARAMETERS_MAX_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Live),
    wire: Wire::None,
};

/// Where [`super::QUERY_ATTACHMENT_MAX_BYTES`] is bound.
pub const QUERY_ATTACHMENT_MAX_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Live),
    wire: Wire::None,
};

/// Where [`super::HANDSHAKE_COOKIE_BYTES`] is bound.
pub const HANDSHAKE_COOKIE_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Capacity,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::PICO_TX_QUEUE_SIZE`] is bound.
pub const PICO_TX_QUEUE_SIZE: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 16)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::SNAPSHOT_PERIOD_MS`] is bound.
pub const SNAPSHOT_PERIOD_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 2147483)),
    storage: Storage::Quota,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Live),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::SNAPSHOT_HISTOGRAM_BUCKETS`] is bound.
pub const SNAPSHOT_HISTOGRAM_BUCKETS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 32)),
    storage: Storage::Both,
    scope: &[Scope::Runtime, Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::Visible,
};

/// Where [`super::SUPERVISION_CHECKPOINTS`] is bound.
pub const SUPERVISION_CHECKPOINTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 64)),
    storage: Storage::Both,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::E2E_SUPERVISED_STREAMS`] is bound.
pub const E2E_SUPERVISED_STREAMS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::APP_LINK_QUEUE_BYTES`] is bound.
pub const APP_LINK_QUEUE_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::EVENT_RING_SLOTS`] is bound.
pub const EVENT_RING_SLOTS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 1073741823)),
    storage: Storage::Both,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::EVENT_RECORD_ARGS`] is bound.
pub const EVENT_RECORD_ARGS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 255)),
    storage: Storage::Capacity,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Build),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::CLOCK_SOURCES`] is bound.
pub const CLOCK_SOURCES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::E2E_SENDER_SLOTS`] is bound.
pub const E2E_SENDER_SLOTS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::REPLAY_DEPTH_MAX`] is bound.
pub const REPLAY_DEPTH_MAX: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::MESSAGE_CATALOG_ENTRIES`] is bound.
pub const MESSAGE_CATALOG_ENTRIES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::INSTANCE_KEY_FIELDS`] is bound.
pub const INSTANCE_KEY_FIELDS: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::INSTANCES_PER_MESSAGE`] is bound.
pub const INSTANCES_PER_MESSAGE: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Local),
    range: None,
    storage: Storage::Both,
    scope: &[Scope::Entity],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Build),
    wire: Wire::None,
};

/// Where [`super::CLOCK_MAX_FORWARD_STEP_MS`] is bound.
pub const CLOCK_MAX_FORWARD_STEP_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Runtime],
    binding_heap: Some(Binding::Live),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::DECLARATION_SYNC_BURST_MESSAGES`] is bound.
pub const DECLARATION_SYNC_BURST_MESSAGES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Timing,
};

/// Where [`super::DECLARATION_SYNC_FINAL_TIMEOUT_MS`] is bound.
pub const DECLARATION_SYNC_FINAL_TIMEOUT_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Live),
    wire: Wire::None,
};

/// Where [`super::DECLARATION_SYNC_INTERVAL_MS`] is bound.
pub const DECLARATION_SYNC_INTERVAL_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Live),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Timing,
};

/// Where [`super::DECLARATION_SYNC_RX_NO_PROGRESS_MS`] is bound.
pub const DECLARATION_SYNC_RX_NO_PROGRESS_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::None,
};

/// Where [`super::DECLARATION_SYNC_RETRY_INTERVAL_MS`] is bound.
pub const DECLARATION_SYNC_RETRY_INTERVAL_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Timing,
};

/// Where [`super::DECLARATION_SYNC_TX_NO_PROGRESS_MS`] is bound.
pub const DECLARATION_SYNC_TX_NO_PROGRESS_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::PICO_UNICAST_BATCH_BYTES`] is bound.
pub const PICO_UNICAST_BATCH_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 65535)),
    storage: Storage::Both,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::Negotiated,
};

/// Where [`super::PICO_MULTICAST_BATCH_BYTES`] is bound.
pub const PICO_MULTICAST_BATCH_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 65535)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Visible,
};

/// Where [`super::PICO_LEASE_MS`] is bound.
pub const PICO_LEASE_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Negotiated,
};

/// Where [`super::PICO_SOCKET_TIMEOUT_MS`] is bound.
pub const PICO_SOCKET_TIMEOUT_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((0, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::PICO_CONNECT_TIMEOUT_MS`] is bound.
pub const PICO_CONNECT_TIMEOUT_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::PICO_FRAG_MAX_BYTES`] is bound.
pub const PICO_FRAG_MAX_BYTES: LimitBinding = LimitBinding {
    kind: LimitKind::Bound,
    driven: Some(Driven::Remote),
    range: None,
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: Some(Binding::Open),
    wire: Wire::None,
};

/// Where [`super::PICO_ACCEPT_TIMEOUT_MS`] is bound.
pub const PICO_ACCEPT_TIMEOUT_MS: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Link],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};

/// Where [`super::PICO_KEEPALIVES_PER_LEASE`] is bound.
pub const PICO_KEEPALIVES_PER_LEASE: LimitBinding = LimitBinding {
    kind: LimitKind::Parameter,
    driven: None,
    range: Some((1, 4294967295)),
    storage: Storage::Quota,
    scope: &[Scope::Session],
    binding_heap: Some(Binding::Open),
    binding_fixed: None,
    wire: Wire::Timing,
};
