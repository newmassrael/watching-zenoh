// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-limit-snapshots.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The limits a stage after the build may decide, as the code will read them: each is a field of
//! [`SessionLimits`] or of [`RuntimeLimits`], the snapshots a creator hands its machines. Their
//! build defaults are what the build runs with today ([`LimitSpec::DEFAULT`]), so a snapshot
//! that starts from them changes nothing; a test names another value with the field's
//! `select_*`.
//!
//! Each limit's type implements [`LimitSpec`]: its capacity in this build, the domain the build
//! allows (the build's value alone where `DEFAULTS_ONLY`), and the build's value, which the
//! domain must hold: a constant after each type evaluates its domain, so a build that states a
//! value outside it does not compile. A field holds no byte for a limit whose domain is one value.

use crate::caps;
use crate::limit_binding::{
    limit_defaults_only, LimitDomain, LimitEntry, LimitField, LimitSpec, Limited,
    OutsideLimitDomain, Quota,
};
use crate::policy_binding::Driven;

/// Whether a limit's domain keeps only the build's value: what `WZ_LIMIT_DOMAINS` states, else
/// whether the target has no operating system.
const DEFAULTS_ONLY: bool = limit_defaults_only(option_env!("WZ_LIMIT_DOMAINS"));

/// The capacity of a limit the fixed storage profile sizes storage by and the heap profile
/// does not: `value` where the build's tables are fixed in size, none where they grow.
const fn fixed_capacity(value: usize) -> Option<usize> {
    if crate::bounded::ENFORCES_CAPACITY {
        Some(value)
    } else {
        None
    }
}

/// `MAX_KEYEXPR_BYTES`: The longest key expression, in bytes, a session stores: a
/// subscription's pattern, or a key a peer declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxKeyexprBytes;

impl LimitSpec for MaxKeyexprBytes {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_KEYEXPR_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = Some(caps::MAX_KEYEXPR_BYTES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_KEYEXPR_BYTES);
}

const _: LimitDomain = MaxKeyexprBytes::DOMAIN;

/// How `MAX_KEYEXPR_BYTES` is held: in no byte when its domain is one value.
type MaxKeyexprBytesHeld = Limited<MaxKeyexprBytes, { MaxKeyexprBytes::HELD }>;

/// `MAX_SUBSCRIPTIONS`: The subscribers a session holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxSubscriptions;

impl LimitSpec for MaxSubscriptions {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_SUBSCRIPTIONS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_SUBSCRIPTIONS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxSubscriptions::DOMAIN;

/// How `MAX_SUBSCRIPTIONS` is held: in no byte when its domain is one value.
type MaxSubscriptionsHeld = Limited<MaxSubscriptions, { MaxSubscriptions::HELD }>;

/// `MATCH_MEMO_SLOTS`: How many distinct keys the receive match cache remembers at once:
/// the keys whose matching subscriptions it can answer without matching again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchMemoSlots;

impl LimitSpec for MatchMemoSlots {
    type Value = usize;
    const LIMIT: &'static str = "MATCH_MEMO_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::MATCH_MEMO_SLOTS;
}

const _: LimitDomain = MatchMemoSlots::DOMAIN;

/// How `MATCH_MEMO_SLOTS` is held: in no byte when its domain is one value.
type MatchMemoSlotsHeld = Limited<MatchMemoSlots, { MatchMemoSlots::HELD }>;

/// `DELIVERY_LANE_EVENTS`: How many samples the delivery lane of an offloaded subscriber
/// holds at once: the samples the receive path has copied in and its callback has not yet
/// run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneEvents;

impl LimitSpec for DeliveryLaneEvents {
    type Value = Quota;
    const LIMIT: &'static str = "DELIVERY_LANE_EVENTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = Some(caps::DELIVERY_LANE_EVENTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::DELIVERY_LANE_EVENTS);
}

const _: LimitDomain = DeliveryLaneEvents::DOMAIN;

/// How `DELIVERY_LANE_EVENTS` is held: in no byte when its domain is one value.
type DeliveryLaneEventsHeld = Limited<DeliveryLaneEvents, { DeliveryLaneEvents::HELD }>;

/// `DELIVERY_LANE_BYTES`: How many bytes of copied samples a delivery lane holds at once:
/// the key, the payload, the attachment and the encoding schema of each waiting sample, and
/// the end of the byte area a sample skipped to stay in one piece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneBytes;

impl LimitSpec for DeliveryLaneBytes {
    type Value = usize;
    const LIMIT: &'static str = "DELIVERY_LANE_BYTES";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DELIVERY_LANE_BYTES;
}

const _: LimitDomain = DeliveryLaneBytes::DOMAIN;

/// How `DELIVERY_LANE_BYTES` is held: in no byte when its domain is one value.
type DeliveryLaneBytesHeld = Limited<DeliveryLaneBytes, { DeliveryLaneBytes::HELD }>;

/// `DELIVERY_LANE_CALLBACKS`: How many callback invocations a delivery lane owes at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneCallbacks;

impl LimitSpec for DeliveryLaneCallbacks {
    type Value = Quota;
    const LIMIT: &'static str = "DELIVERY_LANE_CALLBACKS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::DELIVERY_LANE_CALLBACKS, false);
}

const _: LimitDomain = DeliveryLaneCallbacks::DOMAIN;

/// How `DELIVERY_LANE_CALLBACKS` is held: in no byte when its domain is one value.
type DeliveryLaneCallbacksHeld = Limited<DeliveryLaneCallbacks, { DeliveryLaneCallbacks::HELD }>;

/// `MAX_QUERYABLES`: The queryables a session holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxQueryables;

impl LimitSpec for MaxQueryables {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_QUERYABLES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_QUERYABLES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxQueryables::DOMAIN;

/// How `MAX_QUERYABLES` is held: in no byte when its domain is one value.
type MaxQueryablesHeld = Limited<MaxQueryables, { MaxQueryables::HELD }>;

/// `MAX_PENDING_QUERIES`: The queries (gets) a session has waiting for their replies at
/// once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingQueries;

impl LimitSpec for MaxPendingQueries {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_QUERIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_QUERIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingQueries::DOMAIN;

/// How `MAX_PENDING_QUERIES` is held: in no byte when its domain is one value.
type MaxPendingQueriesHeld = Limited<MaxPendingQueries, { MaxPendingQueries::HELD }>;

/// `LINK_NOTED_REQUESTS`: How many queries a peer sent over one link the node remembers the
/// key form of at once, so that its replies name the key as the query did, when the link
/// names keys by the shared key ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkNotedRequests;

impl LimitSpec for LinkNotedRequests {
    type Value = usize;
    const LIMIT: &'static str = "LINK_NOTED_REQUESTS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::LINK_NOTED_REQUESTS;
}

const _: LimitDomain = LinkNotedRequests::DOMAIN;

/// How `LINK_NOTED_REQUESTS` is held: in no byte when its domain is one value.
type LinkNotedRequestsHeld = Limited<LinkNotedRequests, { LinkNotedRequests::HELD }>;

/// `MAX_DECL_OBSERVERS`: The observers an application installs on the declarations of its
/// peers (subscribers, queryables and liveliness tokens appearing or leaving), per kind and
/// per direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxDeclObservers;

impl LimitSpec for MaxDeclObservers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_DECL_OBSERVERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_DECL_OBSERVERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxDeclObservers::DOMAIN;

/// How `MAX_DECL_OBSERVERS` is held: in no byte when its domain is one value.
type MaxDeclObserversHeld = Limited<MaxDeclObservers, { MaxDeclObservers::HELD }>;

/// `MAX_LIVELINESS_SUBSCRIPTIONS`: The liveliness subscribers a session holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLivelinessSubscriptions;

impl LimitSpec for MaxLivelinessSubscriptions {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LIVELINESS_SUBSCRIPTIONS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_LIVELINESS_SUBSCRIPTIONS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxLivelinessSubscriptions::DOMAIN;

/// How `MAX_LIVELINESS_SUBSCRIPTIONS` is held: in no byte when its domain is one value.
type MaxLivelinessSubscriptionsHeld =
    Limited<MaxLivelinessSubscriptions, { MaxLivelinessSubscriptions::HELD }>;

/// `MAX_LOCAL_TOKENS`: The liveliness tokens a session itself declares and holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLocalTokens;

impl LimitSpec for MaxLocalTokens {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LOCAL_TOKENS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_LOCAL_TOKENS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxLocalTokens::DOMAIN;

/// How `MAX_LOCAL_TOKENS` is held: in no byte when its domain is one value.
type MaxLocalTokensHeld = Limited<MaxLocalTokens, { MaxLocalTokens::HELD }>;

/// `MAX_PENDING_LIVELINESS_GETS`: The liveliness gets (snapshots of the tokens alive) a
/// session has waiting for their answer at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingLivelinessGets;

impl LimitSpec for MaxPendingLivelinessGets {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_LIVELINESS_GETS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_LIVELINESS_GETS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingLivelinessGets::DOMAIN;

/// How `MAX_PENDING_LIVELINESS_GETS` is held: in no byte when its domain is one value.
type MaxPendingLivelinessGetsHeld =
    Limited<MaxPendingLivelinessGets, { MaxPendingLivelinessGets::HELD }>;

/// `MAX_PENDING_DECLARES`: The declarations a session can have ready to send in answer to
/// its peers' interests between two sends: each answer is the session's matching
/// declarations and a final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingDeclares;

impl LimitSpec for MaxPendingDeclares {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_DECLARES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_DECLARES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingDeclares::DOMAIN;

/// How `MAX_PENDING_DECLARES` is held: in no byte when its domain is one value.
type MaxPendingDeclaresHeld = Limited<MaxPendingDeclares, { MaxPendingDeclares::HELD }>;

/// `MAX_INBOUND_SUB_INTERESTS`: The peers' interests in this session's subscribers that the
/// session remembers, so that a subscriber declared later is announced to them: one per
/// publisher a peer holds with a write filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxInboundSubInterests;

impl LimitSpec for MaxInboundSubInterests {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_INBOUND_SUB_INTERESTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_INBOUND_SUB_INTERESTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxInboundSubInterests::DOMAIN;

/// How `MAX_INBOUND_SUB_INTERESTS` is held: in no byte when its domain is one value.
type MaxInboundSubInterestsHeld = Limited<MaxInboundSubInterests, { MaxInboundSubInterests::HELD }>;

/// `MAX_PEER_KEYEXPR_ALIASES`: The key expressions one peer may have declared to this
/// session at a time, to name them by a short id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPeerKeyexprAliases;

impl LimitSpec for MaxPeerKeyexprAliases {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PEER_KEYEXPR_ALIASES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PEER_KEYEXPR_ALIASES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPeerKeyexprAliases::DOMAIN;

/// How `MAX_PEER_KEYEXPR_ALIASES` is held: in no byte when its domain is one value.
type MaxPeerKeyexprAliasesHeld = Limited<MaxPeerKeyexprAliases, { MaxPeerKeyexprAliases::HELD }>;

/// `MAX_SHARED_KEY_IDS`: The entries of the key-id dictionary every node of a deployment
/// shares (shared-key-ids) that one session may be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxSharedKeyIds;

impl LimitSpec for MaxSharedKeyIds {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_SHARED_KEY_IDS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::MAX_SHARED_KEY_IDS, false);
}

const _: LimitDomain = MaxSharedKeyIds::DOMAIN;

/// How `MAX_SHARED_KEY_IDS` is held: in no byte when its domain is one value.
type MaxSharedKeyIdsHeld = Limited<MaxSharedKeyIds, { MaxSharedKeyIds::HELD }>;

/// `MAX_REMOTE_DECLS`: The declarations of one kind (subscribers, queryables, liveliness
/// tokens) one peer may hold open to this session at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxRemoteDecls;

impl LimitSpec for MaxRemoteDecls {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_REMOTE_DECLS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_REMOTE_DECLS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxRemoteDecls::DOMAIN;

/// How `MAX_REMOTE_DECLS` is held: in no byte when its domain is one value.
type MaxRemoteDeclsHeld = Limited<MaxRemoteDecls, { MaxRemoteDecls::HELD }>;

/// `MAX_PENDING_REPLIES`: The replies a session's queryables may have ready to send between
/// two sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingReplies;

impl LimitSpec for MaxPendingReplies {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_REPLIES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_REPLIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingReplies::DOMAIN;

/// How `MAX_PENDING_REPLIES` is held: in no byte when its domain is one value.
type MaxPendingRepliesHeld = Limited<MaxPendingReplies, { MaxPendingReplies::HELD }>;

/// `MAX_PENDING_FINALS`: The queries a session may owe the end of an answer between two
/// sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingFinals;

impl LimitSpec for MaxPendingFinals {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_FINALS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_FINALS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingFinals::DOMAIN;

/// How `MAX_PENDING_FINALS` is held: in no byte when its domain is one value.
type MaxPendingFinalsHeld = Limited<MaxPendingFinals, { MaxPendingFinals::HELD }>;

/// `MAX_REPLY_PAYLOAD_BYTES`: The largest payload of one reply, in bytes, and the largest
/// attachment beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxReplyPayloadBytes;

impl LimitSpec for MaxReplyPayloadBytes {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_REPLY_PAYLOAD_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_REPLY_PAYLOAD_BYTES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxReplyPayloadBytes::DOMAIN;

/// How `MAX_REPLY_PAYLOAD_BYTES` is held: in no byte when its domain is one value.
type MaxReplyPayloadBytesHeld = Limited<MaxReplyPayloadBytes, { MaxReplyPayloadBytes::HELD }>;

/// `MAX_MULTICAST_REPLIES`: The replies a node holds for a multicast group before it sends
/// them, with or without an allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxMulticastReplies;

impl LimitSpec for MaxMulticastReplies {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_MULTICAST_REPLIES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_MULTICAST_REPLIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_MULTICAST_REPLIES);
}

const _: LimitDomain = MaxMulticastReplies::DOMAIN;

/// How `MAX_MULTICAST_REPLIES` is held: in no byte when its domain is one value.
type MaxMulticastRepliesHeld = Limited<MaxMulticastReplies, { MaxMulticastReplies::HELD }>;

/// `MAX_LOCATOR_LEN`: The longest locator, in bytes, a node stores: one it is told to
/// connect to, or one it listens on (for example udp/192.168.1.10:7447).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLocatorLen;

impl LimitSpec for MaxLocatorLen {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LOCATOR_LEN";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = Some(caps::MAX_LOCATOR_LEN);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_LOCATOR_LEN);
}

const _: LimitDomain = MaxLocatorLen::DOMAIN;

/// How `MAX_LOCATOR_LEN` is held: in no byte when its domain is one value.
type MaxLocatorLenHeld = Limited<MaxLocatorLen, { MaxLocatorLen::HELD }>;

/// `MAX_STATIC_CONNECT`: The locators a node is told to connect to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxStaticConnect;

impl LimitSpec for MaxStaticConnect {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_STATIC_CONNECT";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = Some(caps::MAX_STATIC_CONNECT);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_STATIC_CONNECT);
}

const _: LimitDomain = MaxStaticConnect::DOMAIN;

/// How `MAX_STATIC_CONNECT` is held: in no byte when its domain is one value.
type MaxStaticConnectHeld = Limited<MaxStaticConnect, { MaxStaticConnect::HELD }>;

/// `QUERIER_MAX_PENDING_QUERIES`: The queries one declared querier may have in flight at
/// once; one more is refused until a pending one ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerierMaxPendingQueries;

impl LimitSpec for QuerierMaxPendingQueries {
    type Value = Quota;
    const LIMIT: &'static str = "QUERIER_MAX_PENDING_QUERIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERIER_MAX_PENDING_QUERIES, true);
}

const _: LimitDomain = QuerierMaxPendingQueries::DOMAIN;

/// How `QUERIER_MAX_PENDING_QUERIES` is held: in no byte when its domain is one value.
type QuerierMaxPendingQueriesHeld =
    Limited<QuerierMaxPendingQueries, { QuerierMaxPendingQueries::HELD }>;

/// `TX_NO_PROGRESS_WINDOW_US`: How long, in microseconds, a blocking message may wait with
/// no progress when the tx-no-progress-deadline policy is on: no fragment of it going out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxNoProgressWindowUs;

impl LimitSpec for TxNoProgressWindowUs {
    type Value = usize;
    const LIMIT: &'static str = "TX_NO_PROGRESS_WINDOW_US";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 5000000, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::TX_NO_PROGRESS_WINDOW_US;
}

const _: LimitDomain = TxNoProgressWindowUs::DOMAIN;

/// How `TX_NO_PROGRESS_WINDOW_US` is held: in no byte when its domain is one value.
type TxNoProgressWindowUsHeld = Limited<TxNoProgressWindowUs, { TxNoProgressWindowUs::HELD }>;

/// `TX_EXPIRY_CLOSE_AFTER`: How many blocking messages in a row may find no room within
/// their deadline before the session is closed as unresponsive, when the tx-expiry-keeps-
/// session policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxExpiryCloseAfter;

impl LimitSpec for TxExpiryCloseAfter {
    type Value = Quota;
    const LIMIT: &'static str = "TX_EXPIRY_CLOSE_AFTER";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::TX_EXPIRY_CLOSE_AFTER, true);
}

const _: LimitDomain = TxExpiryCloseAfter::DOMAIN;

/// How `TX_EXPIRY_CLOSE_AFTER` is held: in no byte when its domain is one value.
type TxExpiryCloseAfterHeld = Limited<TxExpiryCloseAfter, { TxExpiryCloseAfter::HELD }>;

/// `DATAGRAM_FRAGMENT_BURST`: How many fragments of a message a UDP link's writer writes in
/// a row when the datagram-fragment-pacing policy is on, before the next one waits for
/// DATAGRAM_FRAGMENT_GAP_US.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramFragmentBurst;

impl LimitSpec for DatagramFragmentBurst {
    type Value = usize;
    const LIMIT: &'static str = "DATAGRAM_FRAGMENT_BURST";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DATAGRAM_FRAGMENT_BURST;
}

const _: LimitDomain = DatagramFragmentBurst::DOMAIN;

/// How `DATAGRAM_FRAGMENT_BURST` is held: in no byte when its domain is one value.
type DatagramFragmentBurstHeld = Limited<DatagramFragmentBurst, { DatagramFragmentBurst::HELD }>;

/// `DATAGRAM_FRAGMENT_GAP_US`: How long, in microseconds, must pass after the last fragment
/// was written before a UDP link's writer writes another one past the burst, when the
/// datagram-fragment-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramFragmentGapUs;

impl LimitSpec for DatagramFragmentGapUs {
    type Value = usize;
    const LIMIT: &'static str = "DATAGRAM_FRAGMENT_GAP_US";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 1000000, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DATAGRAM_FRAGMENT_GAP_US;
}

const _: LimitDomain = DatagramFragmentGapUs::DOMAIN;

/// How `DATAGRAM_FRAGMENT_GAP_US` is held: in no byte when its domain is one value.
type DatagramFragmentGapUsHeld = Limited<DatagramFragmentGapUs, { DatagramFragmentGapUs::HELD }>;

/// `QUERY_PARAMETERS_MAX_BYTES`: The most bytes of selector parameters a query from a peer
/// may carry for this node to run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryParametersMaxBytes;

impl LimitSpec for QueryParametersMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "QUERY_PARAMETERS_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERY_PARAMETERS_MAX_BYTES, true);
}

const _: LimitDomain = QueryParametersMaxBytes::DOMAIN;

/// How `QUERY_PARAMETERS_MAX_BYTES` is held: in no byte when its domain is one value.
type QueryParametersMaxBytesHeld =
    Limited<QueryParametersMaxBytes, { QueryParametersMaxBytes::HELD }>;

/// `QUERY_ATTACHMENT_MAX_BYTES`: The most bytes of attachment a query from a peer may carry
/// for this node to run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryAttachmentMaxBytes;

impl LimitSpec for QueryAttachmentMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "QUERY_ATTACHMENT_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERY_ATTACHMENT_MAX_BYTES, true);
}

const _: LimitDomain = QueryAttachmentMaxBytes::DOMAIN;

/// How `QUERY_ATTACHMENT_MAX_BYTES` is held: in no byte when its domain is one value.
type QueryAttachmentMaxBytesHeld =
    Limited<QueryAttachmentMaxBytes, { QueryAttachmentMaxBytes::HELD }>;

/// `PICO_TX_QUEUE_SIZE`: How many batches each priority's outbound queue holds for the pico
/// C ABI, in 1 to 16 (upstream's range for a queue size; a value outside it counts as the
/// nearest end).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoTxQueueSize;

impl LimitSpec for PicoTxQueueSize {
    type Value = usize;
    const LIMIT: &'static str = "PICO_TX_QUEUE_SIZE";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 16, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_TX_QUEUE_SIZE;
}

const _: LimitDomain = PicoTxQueueSize::DOMAIN;

/// How `PICO_TX_QUEUE_SIZE` is held: in no byte when its domain is one value.
type PicoTxQueueSizeHeld = Limited<PicoTxQueueSize, { PicoTxQueueSize::HELD }>;

/// `SNAPSHOT_PERIOD_MS`: How often, in milliseconds, the node takes a snapshot of itself:
/// what it spends and how its messages are spaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotPeriodMs;

impl LimitSpec for SnapshotPeriodMs {
    type Value = usize;
    const LIMIT: &'static str = "SNAPSHOT_PERIOD_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 2147483, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SNAPSHOT_PERIOD_MS;
}

const _: LimitDomain = SnapshotPeriodMs::DOMAIN;

/// How `SNAPSHOT_PERIOD_MS` is held: in no byte when its domain is one value.
type SnapshotPeriodMsHeld = Limited<SnapshotPeriodMs, { SnapshotPeriodMs::HELD }>;

/// `SNAPSHOT_HISTOGRAM_BUCKETS`: How many buckets the snapshot's message-interval histogram
/// has, each 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotHistogramBuckets;

impl LimitSpec for SnapshotHistogramBuckets {
    type Value = usize;
    const LIMIT: &'static str = "SNAPSHOT_HISTOGRAM_BUCKETS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = Some(caps::SNAPSHOT_HISTOGRAM_BUCKETS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 32, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SNAPSHOT_HISTOGRAM_BUCKETS;
}

const _: LimitDomain = SnapshotHistogramBuckets::DOMAIN;

/// How `SNAPSHOT_HISTOGRAM_BUCKETS` is held: in no byte when its domain is one value.
type SnapshotHistogramBucketsHeld =
    Limited<SnapshotHistogramBuckets, { SnapshotHistogramBuckets::HELD }>;

/// `SUPERVISION_CHECKPOINTS`: How many checkpoints the node's supervisor watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisionCheckpoints;

impl LimitSpec for SupervisionCheckpoints {
    type Value = usize;
    const LIMIT: &'static str = "SUPERVISION_CHECKPOINTS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = Some(caps::SUPERVISION_CHECKPOINTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 64, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SUPERVISION_CHECKPOINTS;
}

const _: LimitDomain = SupervisionCheckpoints::DOMAIN;

/// How `SUPERVISION_CHECKPOINTS` is held: in no byte when its domain is one value.
type SupervisionCheckpointsHeld = Limited<SupervisionCheckpoints, { SupervisionCheckpoints::HELD }>;

/// `E2E_SUPERVISED_STREAMS`: How many periodic streams one reception supervisor holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E2eSupervisedStreams;

impl LimitSpec for E2eSupervisedStreams {
    type Value = Quota;
    const LIMIT: &'static str = "E2E_SUPERVISED_STREAMS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::E2E_SUPERVISED_STREAMS, false);
}

const _: LimitDomain = E2eSupervisedStreams::DOMAIN;

/// How `E2E_SUPERVISED_STREAMS` is held: in no byte when its domain is one value.
type E2eSupervisedStreamsHeld = Limited<E2eSupervisedStreams, { E2eSupervisedStreams::HELD }>;

/// `APP_LINK_QUEUE_BYTES`: The most bytes one link of a transport the program supplies
/// queues in either direction: what the program handed in and the session has not read, and
/// what a session that cannot wait handed over and the program has not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppLinkQueueBytes;

impl LimitSpec for AppLinkQueueBytes {
    type Value = Quota;
    const LIMIT: &'static str = "APP_LINK_QUEUE_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::APP_LINK_QUEUE_BYTES, false);
}

const _: LimitDomain = AppLinkQueueBytes::DOMAIN;

/// How `APP_LINK_QUEUE_BYTES` is held: in no byte when its domain is one value.
type AppLinkQueueBytesHeld = Limited<AppLinkQueueBytes, { AppLinkQueueBytes::HELD }>;

/// `EVENT_RING_SLOTS`: How many event records the node's event ring holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRingSlots;

impl LimitSpec for EventRingSlots {
    type Value = usize;
    const LIMIT: &'static str = "EVENT_RING_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = Some(caps::EVENT_RING_SLOTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 1073741823, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::EVENT_RING_SLOTS;
}

const _: LimitDomain = EventRingSlots::DOMAIN;

/// How `EVENT_RING_SLOTS` is held: in no byte when its domain is one value.
type EventRingSlotsHeld = Limited<EventRingSlots, { EventRingSlots::HELD }>;

/// `CLOCK_SOURCES`: How many clock sources an application can register with the node at
/// once, when the clock-source capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSources;

impl LimitSpec for ClockSources {
    type Value = Quota;
    const LIMIT: &'static str = "CLOCK_SOURCES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::CLOCK_SOURCES, false);
}

const _: LimitDomain = ClockSources::DOMAIN;

/// How `CLOCK_SOURCES` is held: in no byte when its domain is one value.
type ClockSourcesHeld = Limited<ClockSources, { ClockSources::HELD }>;

/// `E2E_SENDER_SLOTS`: How many senders one receiving judge of end-to-end protected frames
/// keeps a counter for, when the e2e-sender-demux capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E2eSenderSlots;

impl LimitSpec for E2eSenderSlots {
    type Value = Quota;
    const LIMIT: &'static str = "E2E_SENDER_SLOTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = fixed_capacity(caps::E2E_SENDER_SLOTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::E2E_SENDER_SLOTS);
}

const _: LimitDomain = E2eSenderSlots::DOMAIN;

/// How `E2E_SENDER_SLOTS` is held: in no byte when its domain is one value.
type E2eSenderSlotsHeld = Limited<E2eSenderSlots, { E2eSenderSlots::HELD }>;

/// `REPLAY_DEPTH_MAX`: The deepest replay a message may keep: how many of the frames it
/// last sent, as they were sent, a publisher holds for a subscriber that arrives later and
/// asks for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayDepthMax;

impl LimitSpec for ReplayDepthMax {
    type Value = Quota;
    const LIMIT: &'static str = "REPLAY_DEPTH_MAX";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::REPLAY_DEPTH_MAX);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::REPLAY_DEPTH_MAX);
}

const _: LimitDomain = ReplayDepthMax::DOMAIN;

/// How `REPLAY_DEPTH_MAX` is held: in no byte when its domain is one value.
type ReplayDepthMaxHeld = Limited<ReplayDepthMax, { ReplayDepthMax::HELD }>;

/// `MESSAGE_CATALOG_ENTRIES`: How many messages one message catalog declares, when the
/// message-catalog capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageCatalogEntries;

impl LimitSpec for MessageCatalogEntries {
    type Value = Quota;
    const LIMIT: &'static str = "MESSAGE_CATALOG_ENTRIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::MESSAGE_CATALOG_ENTRIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MESSAGE_CATALOG_ENTRIES);
}

const _: LimitDomain = MessageCatalogEntries::DOMAIN;

/// How `MESSAGE_CATALOG_ENTRIES` is held: in no byte when its domain is one value.
type MessageCatalogEntriesHeld = Limited<MessageCatalogEntries, { MessageCatalogEntries::HELD }>;

/// `INSTANCE_KEY_FIELDS`: How many fields of a payload one message's instance key names,
/// when the instance-key capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceKeyFields;

impl LimitSpec for InstanceKeyFields {
    type Value = Quota;
    const LIMIT: &'static str = "INSTANCE_KEY_FIELDS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::INSTANCE_KEY_FIELDS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::INSTANCE_KEY_FIELDS);
}

const _: LimitDomain = InstanceKeyFields::DOMAIN;

/// How `INSTANCE_KEY_FIELDS` is held: in no byte when its domain is one value.
type InstanceKeyFieldsHeld = Limited<InstanceKeyFields, { InstanceKeyFields::HELD }>;

/// `INSTANCES_PER_MESSAGE`: How many instances one message's instance key may tell apart,
/// when the instance-key capability is on: the product of the lengths of the lists of
/// values its key fields may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstancesPerMessage;

impl LimitSpec for InstancesPerMessage {
    type Value = Quota;
    const LIMIT: &'static str = "INSTANCES_PER_MESSAGE";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const CAPACITY: Option<usize> = fixed_capacity(caps::INSTANCES_PER_MESSAGE);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::INSTANCES_PER_MESSAGE);
}

const _: LimitDomain = InstancesPerMessage::DOMAIN;

/// How `INSTANCES_PER_MESSAGE` is held: in no byte when its domain is one value.
type InstancesPerMessageHeld = Limited<InstancesPerMessage, { InstancesPerMessage::HELD }>;

/// `CLOCK_MAX_FORWARD_STEP_MS`: How far ahead of the node's clock, in milliseconds, a
/// timestamp from another node may be before the node's hybrid logical clock refuses it, as
/// zenoh's UHLC_MAX_DELTA_MS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockMaxForwardStepMs;

impl LimitSpec for ClockMaxForwardStepMs {
    type Value = usize;
    const LIMIT: &'static str = "CLOCK_MAX_FORWARD_STEP_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::CLOCK_MAX_FORWARD_STEP_MS;
}

const _: LimitDomain = ClockMaxForwardStepMs::DOMAIN;

/// How `CLOCK_MAX_FORWARD_STEP_MS` is held: in no byte when its domain is one value.
type ClockMaxForwardStepMsHeld = Limited<ClockMaxForwardStepMs, { ClockMaxForwardStepMs::HELD }>;

/// `DECLARATION_SYNC_BURST_MESSAGES`: How many declarations one turn of a paced declaration
/// replay sends, when the declaration-sync-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncBurstMessages;

impl LimitSpec for DeclarationSyncBurstMessages {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_BURST_MESSAGES";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_BURST_MESSAGES;
}

const _: LimitDomain = DeclarationSyncBurstMessages::DOMAIN;

/// How `DECLARATION_SYNC_BURST_MESSAGES` is held: in no byte when its domain is one value.
type DeclarationSyncBurstMessagesHeld =
    Limited<DeclarationSyncBurstMessages, { DeclarationSyncBurstMessages::HELD }>;

/// `DECLARATION_SYNC_FINAL_TIMEOUT_MS`: How long, in milliseconds, a node waits for the
/// peer's answer to an interest it sent before it counts the interest as unanswered and
/// goes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncFinalTimeoutMs;

impl LimitSpec for DeclarationSyncFinalTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_FINAL_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_FINAL_TIMEOUT_MS;
}

const _: LimitDomain = DeclarationSyncFinalTimeoutMs::DOMAIN;

/// How `DECLARATION_SYNC_FINAL_TIMEOUT_MS` is held: in no byte when its domain is one value.
type DeclarationSyncFinalTimeoutMsHeld =
    Limited<DeclarationSyncFinalTimeoutMs, { DeclarationSyncFinalTimeoutMs::HELD }>;

/// `DECLARATION_SYNC_INTERVAL_MS`: How long, in milliseconds, a paced declaration replay
/// waits between two of its turns, when the declaration-sync-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncIntervalMs;

impl LimitSpec for DeclarationSyncIntervalMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_INTERVAL_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_INTERVAL_MS;
}

const _: LimitDomain = DeclarationSyncIntervalMs::DOMAIN;

/// How `DECLARATION_SYNC_INTERVAL_MS` is held: in no byte when its domain is one value.
type DeclarationSyncIntervalMsHeld =
    Limited<DeclarationSyncIntervalMs, { DeclarationSyncIntervalMs::HELD }>;

/// `DECLARATION_SYNC_RX_NO_PROGRESS_MS`: How long, in milliseconds, a session waits for the
/// next of its peer's initial declarations before it takes the declaration sync as cut
/// short, when the reliable-gap-reconnect policy is not off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncRxNoProgressMs;

impl LimitSpec for DeclarationSyncRxNoProgressMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_RX_NO_PROGRESS_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_RX_NO_PROGRESS_MS;
}

const _: LimitDomain = DeclarationSyncRxNoProgressMs::DOMAIN;

/// How `DECLARATION_SYNC_RX_NO_PROGRESS_MS` is held: in no byte when its domain is one value.
type DeclarationSyncRxNoProgressMsHeld =
    Limited<DeclarationSyncRxNoProgressMs, { DeclarationSyncRxNoProgressMs::HELD }>;

/// `DECLARATION_SYNC_RETRY_INTERVAL_MS`: How long, in milliseconds, a paced declaration
/// replay waits before it tries again a turn the link did not take for want of room, when
/// the declaration-sync-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncRetryIntervalMs;

impl LimitSpec for DeclarationSyncRetryIntervalMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_RETRY_INTERVAL_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_RETRY_INTERVAL_MS;
}

const _: LimitDomain = DeclarationSyncRetryIntervalMs::DOMAIN;

/// How `DECLARATION_SYNC_RETRY_INTERVAL_MS` is held: in no byte when its domain is one value.
type DeclarationSyncRetryIntervalMsHeld =
    Limited<DeclarationSyncRetryIntervalMs, { DeclarationSyncRetryIntervalMs::HELD }>;

/// `DECLARATION_SYNC_TX_NO_PROGRESS_MS`: How long, in milliseconds, a paced declaration
/// replay that retries refused turns (DECLARATION_SYNC_RETRY_INTERVAL_MS not 0) goes on
/// with no declaration sent before it gives up, which ends the link as a refused turn does
/// without retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncTxNoProgressMs;

impl LimitSpec for DeclarationSyncTxNoProgressMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_TX_NO_PROGRESS_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS;
}

const _: LimitDomain = DeclarationSyncTxNoProgressMs::DOMAIN;

/// How `DECLARATION_SYNC_TX_NO_PROGRESS_MS` is held: in no byte when its domain is one value.
type DeclarationSyncTxNoProgressMsHeld =
    Limited<DeclarationSyncTxNoProgressMs, { DeclarationSyncTxNoProgressMs::HELD }>;

/// `PICO_UNICAST_BATCH_BYTES`: The batch size, in bytes, a session of the zenoh-pico
/// interface advertises when it opens a unicast session, as zenoh-pico's
/// BATCH_UNICAST_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoUnicastBatchBytes;

impl LimitSpec for PicoUnicastBatchBytes {
    type Value = usize;
    const LIMIT: &'static str = "PICO_UNICAST_BATCH_BYTES";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 65535, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_UNICAST_BATCH_BYTES;
}

const _: LimitDomain = PicoUnicastBatchBytes::DOMAIN;

/// How `PICO_UNICAST_BATCH_BYTES` is held: in no byte when its domain is one value.
type PicoUnicastBatchBytesHeld = Limited<PicoUnicastBatchBytes, { PicoUnicastBatchBytes::HELD }>;

/// `PICO_MULTICAST_BATCH_BYTES`: The batch size, in bytes, a session of the zenoh-pico
/// interface advertises in the Join of a multicast group, as zenoh-pico's
/// BATCH_MULTICAST_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoMulticastBatchBytes;

impl LimitSpec for PicoMulticastBatchBytes {
    type Value = usize;
    const LIMIT: &'static str = "PICO_MULTICAST_BATCH_BYTES";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 65535, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_MULTICAST_BATCH_BYTES;
}

const _: LimitDomain = PicoMulticastBatchBytes::DOMAIN;

/// How `PICO_MULTICAST_BATCH_BYTES` is held: in no byte when its domain is one value.
type PicoMulticastBatchBytesHeld =
    Limited<PicoMulticastBatchBytes, { PicoMulticastBatchBytes::HELD }>;

/// `PICO_LEASE_MS`: The lease, in milliseconds, a session of the zenoh-pico interface
/// advertises, unicast and in a multicast group's Join, as zenoh-pico's Z_TRANSPORT_LEASE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoLeaseMs;

impl LimitSpec for PicoLeaseMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_LEASE_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_LEASE_MS;
}

const _: LimitDomain = PicoLeaseMs::DOMAIN;

/// How `PICO_LEASE_MS` is held: in no byte when its domain is one value.
type PicoLeaseMsHeld = Limited<PicoLeaseMs, { PicoLeaseMs::HELD }>;

/// `PICO_SOCKET_TIMEOUT_MS`: How long, in milliseconds, one read step of the cooperative
/// zenoh-pico session waits on its link before it returns with nothing, as zenoh-pico's
/// Z_CONFIG_SOCKET_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoSocketTimeoutMs;

impl LimitSpec for PicoSocketTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_SOCKET_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_SOCKET_TIMEOUT_MS;
}

const _: LimitDomain = PicoSocketTimeoutMs::DOMAIN;

/// How `PICO_SOCKET_TIMEOUT_MS` is held: in no byte when its domain is one value.
type PicoSocketTimeoutMsHeld = Limited<PicoSocketTimeoutMs, { PicoSocketTimeoutMs::HELD }>;

/// `PICO_CONNECT_TIMEOUT_MS`: How long, in milliseconds, each open of an endpoint by a
/// zenoh-pico session waits for the dial and the handshake before it fails, on either
/// engine, as zenoh-pico's Z_TRANSPORT_CONNECT_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoConnectTimeoutMs;

impl LimitSpec for PicoConnectTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_CONNECT_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_CONNECT_TIMEOUT_MS;
}

const _: LimitDomain = PicoConnectTimeoutMs::DOMAIN;

/// How `PICO_CONNECT_TIMEOUT_MS` is held: in no byte when its domain is one value.
type PicoConnectTimeoutMsHeld = Limited<PicoConnectTimeoutMs, { PicoConnectTimeoutMs::HELD }>;

/// `PICO_FRAG_MAX_BYTES`: The largest message, in bytes, a session of the zenoh-pico
/// interface rejoins from fragments, unicast and in a multicast group, as zenoh-pico's
/// FRAG_MAX_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoFragMaxBytes;

impl LimitSpec for PicoFragMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "PICO_FRAG_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::PICO_FRAG_MAX_BYTES, false);
}

const _: LimitDomain = PicoFragMaxBytes::DOMAIN;

/// How `PICO_FRAG_MAX_BYTES` is held: in no byte when its domain is one value.
type PicoFragMaxBytesHeld = Limited<PicoFragMaxBytes, { PicoFragMaxBytes::HELD }>;

/// `PICO_ACCEPT_TIMEOUT_MS`: How long, in milliseconds, a listening session of the zenoh-
/// pico interface gives an inbound link to complete its whole handshake, link handshake
/// included, before it drops the link without a word, as zenoh-pico's
/// Z_TRANSPORT_ACCEPT_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoAcceptTimeoutMs;

impl LimitSpec for PicoAcceptTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_ACCEPT_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_ACCEPT_TIMEOUT_MS;
}

const _: LimitDomain = PicoAcceptTimeoutMs::DOMAIN;

/// How `PICO_ACCEPT_TIMEOUT_MS` is held: in no byte when its domain is one value.
type PicoAcceptTimeoutMsHeld = Limited<PicoAcceptTimeoutMs, { PicoAcceptTimeoutMs::HELD }>;

/// `PICO_KEEPALIVES_PER_LEASE`: How many keepalives a session of the zenoh-pico interface
/// sends in one lease, as zenoh-pico's Z_TRANSPORT_LEASE_EXPIRE_FACTOR: whenever the line
/// has been idle for the adopted lease divided by this, the session sends one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoKeepalivesPerLease;

impl LimitSpec for PicoKeepalivesPerLease {
    type Value = usize;
    const LIMIT: &'static str = "PICO_KEEPALIVES_PER_LEASE";
    const DRIVEN: Option<Driven> = None;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_KEEPALIVES_PER_LEASE;
}

const _: LimitDomain = PicoKeepalivesPerLease::DOMAIN;

/// How `PICO_KEEPALIVES_PER_LEASE` is held: in no byte when its domain is one value.
type PicoKeepalivesPerLeaseHeld = Limited<PicoKeepalivesPerLease, { PicoKeepalivesPerLease::HELD }>;

/// The value of every limit a session holds, as one snapshot: what a creator resolved and
/// hands the machines of its scope. A machine reads a limit through the accessor of its
/// field, never from the build. Each value lies inside the build's domain of its limit, and
/// a limit whose domain is one value reads as that value whatever was selected
/// ([`Limited::get`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionLimits {
    /// `MAX_KEYEXPR_BYTES`.
    max_keyexpr_bytes: MaxKeyexprBytesHeld,
    /// `MAX_SUBSCRIPTIONS`.
    max_subscriptions: MaxSubscriptionsHeld,
    /// `MATCH_MEMO_SLOTS`.
    match_memo_slots: MatchMemoSlotsHeld,
    /// `DELIVERY_LANE_EVENTS`.
    delivery_lane_events: DeliveryLaneEventsHeld,
    /// `DELIVERY_LANE_BYTES`.
    delivery_lane_bytes: DeliveryLaneBytesHeld,
    /// `DELIVERY_LANE_CALLBACKS`.
    delivery_lane_callbacks: DeliveryLaneCallbacksHeld,
    /// `MAX_QUERYABLES`.
    max_queryables: MaxQueryablesHeld,
    /// `MAX_PENDING_QUERIES`.
    max_pending_queries: MaxPendingQueriesHeld,
    /// `LINK_NOTED_REQUESTS`.
    link_noted_requests: LinkNotedRequestsHeld,
    /// `MAX_DECL_OBSERVERS`.
    max_decl_observers: MaxDeclObserversHeld,
    /// `MAX_LIVELINESS_SUBSCRIPTIONS`.
    max_liveliness_subscriptions: MaxLivelinessSubscriptionsHeld,
    /// `MAX_LOCAL_TOKENS`.
    max_local_tokens: MaxLocalTokensHeld,
    /// `MAX_PENDING_LIVELINESS_GETS`.
    max_pending_liveliness_gets: MaxPendingLivelinessGetsHeld,
    /// `MAX_PENDING_DECLARES`.
    max_pending_declares: MaxPendingDeclaresHeld,
    /// `MAX_INBOUND_SUB_INTERESTS`.
    max_inbound_sub_interests: MaxInboundSubInterestsHeld,
    /// `MAX_PEER_KEYEXPR_ALIASES`.
    max_peer_keyexpr_aliases: MaxPeerKeyexprAliasesHeld,
    /// `MAX_SHARED_KEY_IDS`.
    max_shared_key_ids: MaxSharedKeyIdsHeld,
    /// `MAX_REMOTE_DECLS`.
    max_remote_decls: MaxRemoteDeclsHeld,
    /// `MAX_PENDING_REPLIES`.
    max_pending_replies: MaxPendingRepliesHeld,
    /// `MAX_PENDING_FINALS`.
    max_pending_finals: MaxPendingFinalsHeld,
    /// `MAX_REPLY_PAYLOAD_BYTES`.
    max_reply_payload_bytes: MaxReplyPayloadBytesHeld,
    /// `MAX_MULTICAST_REPLIES`.
    max_multicast_replies: MaxMulticastRepliesHeld,
    /// `QUERIER_MAX_PENDING_QUERIES`.
    querier_max_pending_queries: QuerierMaxPendingQueriesHeld,
    /// `TX_NO_PROGRESS_WINDOW_US`.
    tx_no_progress_window_us: TxNoProgressWindowUsHeld,
    /// `TX_EXPIRY_CLOSE_AFTER`.
    tx_expiry_close_after: TxExpiryCloseAfterHeld,
    /// `DATAGRAM_FRAGMENT_BURST`.
    datagram_fragment_burst: DatagramFragmentBurstHeld,
    /// `DATAGRAM_FRAGMENT_GAP_US`.
    datagram_fragment_gap_us: DatagramFragmentGapUsHeld,
    /// `QUERY_PARAMETERS_MAX_BYTES`.
    query_parameters_max_bytes: QueryParametersMaxBytesHeld,
    /// `QUERY_ATTACHMENT_MAX_BYTES`.
    query_attachment_max_bytes: QueryAttachmentMaxBytesHeld,
    /// `PICO_TX_QUEUE_SIZE`.
    pico_tx_queue_size: PicoTxQueueSizeHeld,
    /// `APP_LINK_QUEUE_BYTES`.
    app_link_queue_bytes: AppLinkQueueBytesHeld,
    /// `E2E_SENDER_SLOTS`.
    e2e_sender_slots: E2eSenderSlotsHeld,
    /// `REPLAY_DEPTH_MAX`.
    replay_depth_max: ReplayDepthMaxHeld,
    /// `INSTANCE_KEY_FIELDS`.
    instance_key_fields: InstanceKeyFieldsHeld,
    /// `INSTANCES_PER_MESSAGE`.
    instances_per_message: InstancesPerMessageHeld,
    /// `DECLARATION_SYNC_BURST_MESSAGES`.
    declaration_sync_burst_messages: DeclarationSyncBurstMessagesHeld,
    /// `DECLARATION_SYNC_FINAL_TIMEOUT_MS`.
    declaration_sync_final_timeout_ms: DeclarationSyncFinalTimeoutMsHeld,
    /// `DECLARATION_SYNC_INTERVAL_MS`.
    declaration_sync_interval_ms: DeclarationSyncIntervalMsHeld,
    /// `DECLARATION_SYNC_RX_NO_PROGRESS_MS`.
    declaration_sync_rx_no_progress_ms: DeclarationSyncRxNoProgressMsHeld,
    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS`.
    declaration_sync_retry_interval_ms: DeclarationSyncRetryIntervalMsHeld,
    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS`.
    declaration_sync_tx_no_progress_ms: DeclarationSyncTxNoProgressMsHeld,
    /// `PICO_UNICAST_BATCH_BYTES`.
    pico_unicast_batch_bytes: PicoUnicastBatchBytesHeld,
    /// `PICO_MULTICAST_BATCH_BYTES`.
    pico_multicast_batch_bytes: PicoMulticastBatchBytesHeld,
    /// `PICO_LEASE_MS`.
    pico_lease_ms: PicoLeaseMsHeld,
    /// `PICO_SOCKET_TIMEOUT_MS`.
    pico_socket_timeout_ms: PicoSocketTimeoutMsHeld,
    /// `PICO_CONNECT_TIMEOUT_MS`.
    pico_connect_timeout_ms: PicoConnectTimeoutMsHeld,
    /// `PICO_FRAG_MAX_BYTES`.
    pico_frag_max_bytes: PicoFragMaxBytesHeld,
    /// `PICO_ACCEPT_TIMEOUT_MS`.
    pico_accept_timeout_ms: PicoAcceptTimeoutMsHeld,
    /// `PICO_KEEPALIVES_PER_LEASE`.
    pico_keepalives_per_lease: PicoKeepalivesPerLeaseHeld,
}

impl SessionLimits {
    /// The build defaults: each limit's value as the build states it ([`LimitSpec::DEFAULT`]).
    pub const fn from_build() -> Self {
        Self {
            max_keyexpr_bytes: Limited::build_default(),
            max_subscriptions: Limited::build_default(),
            match_memo_slots: Limited::build_default(),
            delivery_lane_events: Limited::build_default(),
            delivery_lane_bytes: Limited::build_default(),
            delivery_lane_callbacks: Limited::build_default(),
            max_queryables: Limited::build_default(),
            max_pending_queries: Limited::build_default(),
            link_noted_requests: Limited::build_default(),
            max_decl_observers: Limited::build_default(),
            max_liveliness_subscriptions: Limited::build_default(),
            max_local_tokens: Limited::build_default(),
            max_pending_liveliness_gets: Limited::build_default(),
            max_pending_declares: Limited::build_default(),
            max_inbound_sub_interests: Limited::build_default(),
            max_peer_keyexpr_aliases: Limited::build_default(),
            max_shared_key_ids: Limited::build_default(),
            max_remote_decls: Limited::build_default(),
            max_pending_replies: Limited::build_default(),
            max_pending_finals: Limited::build_default(),
            max_reply_payload_bytes: Limited::build_default(),
            max_multicast_replies: Limited::build_default(),
            querier_max_pending_queries: Limited::build_default(),
            tx_no_progress_window_us: Limited::build_default(),
            tx_expiry_close_after: Limited::build_default(),
            datagram_fragment_burst: Limited::build_default(),
            datagram_fragment_gap_us: Limited::build_default(),
            query_parameters_max_bytes: Limited::build_default(),
            query_attachment_max_bytes: Limited::build_default(),
            pico_tx_queue_size: Limited::build_default(),
            app_link_queue_bytes: Limited::build_default(),
            e2e_sender_slots: Limited::build_default(),
            replay_depth_max: Limited::build_default(),
            instance_key_fields: Limited::build_default(),
            instances_per_message: Limited::build_default(),
            declaration_sync_burst_messages: Limited::build_default(),
            declaration_sync_final_timeout_ms: Limited::build_default(),
            declaration_sync_interval_ms: Limited::build_default(),
            declaration_sync_rx_no_progress_ms: Limited::build_default(),
            declaration_sync_retry_interval_ms: Limited::build_default(),
            declaration_sync_tx_no_progress_ms: Limited::build_default(),
            pico_unicast_batch_bytes: Limited::build_default(),
            pico_multicast_batch_bytes: Limited::build_default(),
            pico_lease_ms: Limited::build_default(),
            pico_socket_timeout_ms: Limited::build_default(),
            pico_connect_timeout_ms: Limited::build_default(),
            pico_frag_max_bytes: Limited::build_default(),
            pico_accept_timeout_ms: Limited::build_default(),
            pico_keepalives_per_lease: Limited::build_default(),
        }
    }

    /// The build defaults ([`Self::from_build`]): the snapshot a creator starts from. A machine
    /// does not call it; it reads the snapshot its creator handed it.
    pub const fn defaults() -> Self {
        Self::from_build()
    }

    /// `MAX_KEYEXPR_BYTES` as this snapshot holds it.
    pub const fn max_keyexpr_bytes(&self) -> Quota {
        self.max_keyexpr_bytes.get()
    }

    /// Selects `MAX_KEYEXPR_BYTES`, when the build's domain holds `value`.
    pub fn select_max_keyexpr_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_keyexpr_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_SUBSCRIPTIONS` as this snapshot holds it.
    pub const fn max_subscriptions(&self) -> Quota {
        self.max_subscriptions.get()
    }

    /// Selects `MAX_SUBSCRIPTIONS`, when the build's domain holds `value`.
    pub fn select_max_subscriptions(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_subscriptions = Limited::select(value)?;
        Ok(())
    }

    /// `MATCH_MEMO_SLOTS` as this snapshot holds it.
    pub const fn match_memo_slots(&self) -> usize {
        self.match_memo_slots.get()
    }

    /// Selects `MATCH_MEMO_SLOTS`, when the build's domain holds `value`.
    pub fn select_match_memo_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.match_memo_slots = Limited::select(value)?;
        Ok(())
    }

    /// `DELIVERY_LANE_EVENTS` as this snapshot holds it.
    pub const fn delivery_lane_events(&self) -> Quota {
        self.delivery_lane_events.get()
    }

    /// Selects `DELIVERY_LANE_EVENTS`, when the build's domain holds `value`.
    pub fn select_delivery_lane_events(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.delivery_lane_events = Limited::select(value)?;
        Ok(())
    }

    /// `DELIVERY_LANE_BYTES` as this snapshot holds it.
    pub const fn delivery_lane_bytes(&self) -> usize {
        self.delivery_lane_bytes.get()
    }

    /// Selects `DELIVERY_LANE_BYTES`, when the build's domain holds `value`.
    pub fn select_delivery_lane_bytes(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.delivery_lane_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `DELIVERY_LANE_CALLBACKS` as this snapshot holds it.
    pub const fn delivery_lane_callbacks(&self) -> Quota {
        self.delivery_lane_callbacks.get()
    }

    /// Selects `DELIVERY_LANE_CALLBACKS`, when the build's domain holds `value`.
    pub fn select_delivery_lane_callbacks(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.delivery_lane_callbacks = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_QUERYABLES` as this snapshot holds it.
    pub const fn max_queryables(&self) -> Quota {
        self.max_queryables.get()
    }

    /// Selects `MAX_QUERYABLES`, when the build's domain holds `value`.
    pub fn select_max_queryables(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_queryables = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PENDING_QUERIES` as this snapshot holds it.
    pub const fn max_pending_queries(&self) -> Quota {
        self.max_pending_queries.get()
    }

    /// Selects `MAX_PENDING_QUERIES`, when the build's domain holds `value`.
    pub fn select_max_pending_queries(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_pending_queries = Limited::select(value)?;
        Ok(())
    }

    /// `LINK_NOTED_REQUESTS` as this snapshot holds it.
    pub const fn link_noted_requests(&self) -> usize {
        self.link_noted_requests.get()
    }

    /// Selects `LINK_NOTED_REQUESTS`, when the build's domain holds `value`.
    pub fn select_link_noted_requests(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.link_noted_requests = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_DECL_OBSERVERS` as this snapshot holds it.
    pub const fn max_decl_observers(&self) -> Quota {
        self.max_decl_observers.get()
    }

    /// Selects `MAX_DECL_OBSERVERS`, when the build's domain holds `value`.
    pub fn select_max_decl_observers(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_decl_observers = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_LIVELINESS_SUBSCRIPTIONS` as this snapshot holds it.
    pub const fn max_liveliness_subscriptions(&self) -> Quota {
        self.max_liveliness_subscriptions.get()
    }

    /// Selects `MAX_LIVELINESS_SUBSCRIPTIONS`, when the build's domain holds `value`.
    pub fn select_max_liveliness_subscriptions(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.max_liveliness_subscriptions = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_LOCAL_TOKENS` as this snapshot holds it.
    pub const fn max_local_tokens(&self) -> Quota {
        self.max_local_tokens.get()
    }

    /// Selects `MAX_LOCAL_TOKENS`, when the build's domain holds `value`.
    pub fn select_max_local_tokens(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_local_tokens = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PENDING_LIVELINESS_GETS` as this snapshot holds it.
    pub const fn max_pending_liveliness_gets(&self) -> Quota {
        self.max_pending_liveliness_gets.get()
    }

    /// Selects `MAX_PENDING_LIVELINESS_GETS`, when the build's domain holds `value`.
    pub fn select_max_pending_liveliness_gets(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.max_pending_liveliness_gets = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PENDING_DECLARES` as this snapshot holds it.
    pub const fn max_pending_declares(&self) -> Quota {
        self.max_pending_declares.get()
    }

    /// Selects `MAX_PENDING_DECLARES`, when the build's domain holds `value`.
    pub fn select_max_pending_declares(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_pending_declares = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_INBOUND_SUB_INTERESTS` as this snapshot holds it.
    pub const fn max_inbound_sub_interests(&self) -> Quota {
        self.max_inbound_sub_interests.get()
    }

    /// Selects `MAX_INBOUND_SUB_INTERESTS`, when the build's domain holds `value`.
    pub fn select_max_inbound_sub_interests(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.max_inbound_sub_interests = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PEER_KEYEXPR_ALIASES` as this snapshot holds it.
    pub const fn max_peer_keyexpr_aliases(&self) -> Quota {
        self.max_peer_keyexpr_aliases.get()
    }

    /// Selects `MAX_PEER_KEYEXPR_ALIASES`, when the build's domain holds `value`.
    pub fn select_max_peer_keyexpr_aliases(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.max_peer_keyexpr_aliases = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_SHARED_KEY_IDS` as this snapshot holds it.
    pub const fn max_shared_key_ids(&self) -> Quota {
        self.max_shared_key_ids.get()
    }

    /// Selects `MAX_SHARED_KEY_IDS`, when the build's domain holds `value`.
    pub fn select_max_shared_key_ids(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_shared_key_ids = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_REMOTE_DECLS` as this snapshot holds it.
    pub const fn max_remote_decls(&self) -> Quota {
        self.max_remote_decls.get()
    }

    /// Selects `MAX_REMOTE_DECLS`, when the build's domain holds `value`.
    pub fn select_max_remote_decls(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_remote_decls = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PENDING_REPLIES` as this snapshot holds it.
    pub const fn max_pending_replies(&self) -> Quota {
        self.max_pending_replies.get()
    }

    /// Selects `MAX_PENDING_REPLIES`, when the build's domain holds `value`.
    pub fn select_max_pending_replies(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_pending_replies = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_PENDING_FINALS` as this snapshot holds it.
    pub const fn max_pending_finals(&self) -> Quota {
        self.max_pending_finals.get()
    }

    /// Selects `MAX_PENDING_FINALS`, when the build's domain holds `value`.
    pub fn select_max_pending_finals(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_pending_finals = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_REPLY_PAYLOAD_BYTES` as this snapshot holds it.
    pub const fn max_reply_payload_bytes(&self) -> Quota {
        self.max_reply_payload_bytes.get()
    }

    /// Selects `MAX_REPLY_PAYLOAD_BYTES`, when the build's domain holds `value`.
    pub fn select_max_reply_payload_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.max_reply_payload_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_MULTICAST_REPLIES` as this snapshot holds it.
    pub const fn max_multicast_replies(&self) -> Quota {
        self.max_multicast_replies.get()
    }

    /// Selects `MAX_MULTICAST_REPLIES`, when the build's domain holds `value`.
    pub fn select_max_multicast_replies(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_multicast_replies = Limited::select(value)?;
        Ok(())
    }

    /// `QUERIER_MAX_PENDING_QUERIES` as this snapshot holds it.
    pub const fn querier_max_pending_queries(&self) -> Quota {
        self.querier_max_pending_queries.get()
    }

    /// Selects `QUERIER_MAX_PENDING_QUERIES`, when the build's domain holds `value`.
    pub fn select_querier_max_pending_queries(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.querier_max_pending_queries = Limited::select(value)?;
        Ok(())
    }

    /// `TX_NO_PROGRESS_WINDOW_US` as this snapshot holds it.
    pub const fn tx_no_progress_window_us(&self) -> usize {
        self.tx_no_progress_window_us.get()
    }

    /// Selects `TX_NO_PROGRESS_WINDOW_US`, when the build's domain holds `value`.
    pub fn select_tx_no_progress_window_us(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.tx_no_progress_window_us = Limited::select(value)?;
        Ok(())
    }

    /// `TX_EXPIRY_CLOSE_AFTER` as this snapshot holds it.
    pub const fn tx_expiry_close_after(&self) -> Quota {
        self.tx_expiry_close_after.get()
    }

    /// Selects `TX_EXPIRY_CLOSE_AFTER`, when the build's domain holds `value`.
    pub fn select_tx_expiry_close_after(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.tx_expiry_close_after = Limited::select(value)?;
        Ok(())
    }

    /// `DATAGRAM_FRAGMENT_BURST` as this snapshot holds it.
    pub const fn datagram_fragment_burst(&self) -> usize {
        self.datagram_fragment_burst.get()
    }

    /// Selects `DATAGRAM_FRAGMENT_BURST`, when the build's domain holds `value`.
    pub fn select_datagram_fragment_burst(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.datagram_fragment_burst = Limited::select(value)?;
        Ok(())
    }

    /// `DATAGRAM_FRAGMENT_GAP_US` as this snapshot holds it.
    pub const fn datagram_fragment_gap_us(&self) -> usize {
        self.datagram_fragment_gap_us.get()
    }

    /// Selects `DATAGRAM_FRAGMENT_GAP_US`, when the build's domain holds `value`.
    pub fn select_datagram_fragment_gap_us(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.datagram_fragment_gap_us = Limited::select(value)?;
        Ok(())
    }

    /// `QUERY_PARAMETERS_MAX_BYTES` as this snapshot holds it.
    pub const fn query_parameters_max_bytes(&self) -> Quota {
        self.query_parameters_max_bytes.get()
    }

    /// Selects `QUERY_PARAMETERS_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_query_parameters_max_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.query_parameters_max_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `QUERY_ATTACHMENT_MAX_BYTES` as this snapshot holds it.
    pub const fn query_attachment_max_bytes(&self) -> Quota {
        self.query_attachment_max_bytes.get()
    }

    /// Selects `QUERY_ATTACHMENT_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_query_attachment_max_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.query_attachment_max_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_TX_QUEUE_SIZE` as this snapshot holds it.
    pub const fn pico_tx_queue_size(&self) -> usize {
        self.pico_tx_queue_size.get()
    }

    /// Selects `PICO_TX_QUEUE_SIZE`, when the build's domain holds `value`.
    pub fn select_pico_tx_queue_size(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.pico_tx_queue_size = Limited::select(value)?;
        Ok(())
    }

    /// `APP_LINK_QUEUE_BYTES` as this snapshot holds it.
    pub const fn app_link_queue_bytes(&self) -> Quota {
        self.app_link_queue_bytes.get()
    }

    /// Selects `APP_LINK_QUEUE_BYTES`, when the build's domain holds `value`.
    pub fn select_app_link_queue_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.app_link_queue_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `E2E_SENDER_SLOTS` as this snapshot holds it.
    pub const fn e2e_sender_slots(&self) -> Quota {
        self.e2e_sender_slots.get()
    }

    /// Selects `E2E_SENDER_SLOTS`, when the build's domain holds `value`.
    pub fn select_e2e_sender_slots(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.e2e_sender_slots = Limited::select(value)?;
        Ok(())
    }

    /// `REPLAY_DEPTH_MAX` as this snapshot holds it.
    pub const fn replay_depth_max(&self) -> Quota {
        self.replay_depth_max.get()
    }

    /// Selects `REPLAY_DEPTH_MAX`, when the build's domain holds `value`.
    pub fn select_replay_depth_max(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.replay_depth_max = Limited::select(value)?;
        Ok(())
    }

    /// `INSTANCE_KEY_FIELDS` as this snapshot holds it.
    pub const fn instance_key_fields(&self) -> Quota {
        self.instance_key_fields.get()
    }

    /// Selects `INSTANCE_KEY_FIELDS`, when the build's domain holds `value`.
    pub fn select_instance_key_fields(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.instance_key_fields = Limited::select(value)?;
        Ok(())
    }

    /// `INSTANCES_PER_MESSAGE` as this snapshot holds it.
    pub const fn instances_per_message(&self) -> Quota {
        self.instances_per_message.get()
    }

    /// Selects `INSTANCES_PER_MESSAGE`, when the build's domain holds `value`.
    pub fn select_instances_per_message(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.instances_per_message = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_BURST_MESSAGES` as this snapshot holds it.
    pub const fn declaration_sync_burst_messages(&self) -> usize {
        self.declaration_sync_burst_messages.get()
    }

    /// Selects `DECLARATION_SYNC_BURST_MESSAGES`, when the build's domain holds `value`.
    pub fn select_declaration_sync_burst_messages(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_burst_messages = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_FINAL_TIMEOUT_MS` as this snapshot holds it.
    pub const fn declaration_sync_final_timeout_ms(&self) -> usize {
        self.declaration_sync_final_timeout_ms.get()
    }

    /// Selects `DECLARATION_SYNC_FINAL_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_final_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_final_timeout_ms = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_INTERVAL_MS` as this snapshot holds it.
    pub const fn declaration_sync_interval_ms(&self) -> usize {
        self.declaration_sync_interval_ms.get()
    }

    /// Selects `DECLARATION_SYNC_INTERVAL_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_interval_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_interval_ms = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_RX_NO_PROGRESS_MS` as this snapshot holds it.
    pub const fn declaration_sync_rx_no_progress_ms(&self) -> usize {
        self.declaration_sync_rx_no_progress_ms.get()
    }

    /// Selects `DECLARATION_SYNC_RX_NO_PROGRESS_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_rx_no_progress_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_rx_no_progress_ms = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` as this snapshot holds it.
    pub const fn declaration_sync_retry_interval_ms(&self) -> usize {
        self.declaration_sync_retry_interval_ms.get()
    }

    /// Selects `DECLARATION_SYNC_RETRY_INTERVAL_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_retry_interval_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_retry_interval_ms = Limited::select(value)?;
        Ok(())
    }

    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` as this snapshot holds it.
    pub const fn declaration_sync_tx_no_progress_ms(&self) -> usize {
        self.declaration_sync_tx_no_progress_ms.get()
    }

    /// Selects `DECLARATION_SYNC_TX_NO_PROGRESS_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_tx_no_progress_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.declaration_sync_tx_no_progress_ms = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_UNICAST_BATCH_BYTES` as this snapshot holds it.
    pub const fn pico_unicast_batch_bytes(&self) -> usize {
        self.pico_unicast_batch_bytes.get()
    }

    /// Selects `PICO_UNICAST_BATCH_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_unicast_batch_bytes(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_unicast_batch_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_MULTICAST_BATCH_BYTES` as this snapshot holds it.
    pub const fn pico_multicast_batch_bytes(&self) -> usize {
        self.pico_multicast_batch_bytes.get()
    }

    /// Selects `PICO_MULTICAST_BATCH_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_multicast_batch_bytes(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_multicast_batch_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_LEASE_MS` as this snapshot holds it.
    pub const fn pico_lease_ms(&self) -> usize {
        self.pico_lease_ms.get()
    }

    /// Selects `PICO_LEASE_MS`, when the build's domain holds `value`.
    pub fn select_pico_lease_ms(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.pico_lease_ms = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_SOCKET_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_socket_timeout_ms(&self) -> usize {
        self.pico_socket_timeout_ms.get()
    }

    /// Selects `PICO_SOCKET_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_socket_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_socket_timeout_ms = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_CONNECT_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_connect_timeout_ms(&self) -> usize {
        self.pico_connect_timeout_ms.get()
    }

    /// Selects `PICO_CONNECT_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_connect_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_connect_timeout_ms = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_FRAG_MAX_BYTES` as this snapshot holds it.
    pub const fn pico_frag_max_bytes(&self) -> Quota {
        self.pico_frag_max_bytes.get()
    }

    /// Selects `PICO_FRAG_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_frag_max_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.pico_frag_max_bytes = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_ACCEPT_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_accept_timeout_ms(&self) -> usize {
        self.pico_accept_timeout_ms.get()
    }

    /// Selects `PICO_ACCEPT_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_accept_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_accept_timeout_ms = Limited::select(value)?;
        Ok(())
    }

    /// `PICO_KEEPALIVES_PER_LEASE` as this snapshot holds it.
    pub const fn pico_keepalives_per_lease(&self) -> usize {
        self.pico_keepalives_per_lease.get()
    }

    /// Selects `PICO_KEEPALIVES_PER_LEASE`, when the build's domain holds `value`.
    pub fn select_pico_keepalives_per_lease(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.pico_keepalives_per_lease = Limited::select(value)?;
        Ok(())
    }
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self::from_build()
    }
}

impl LimitField<SessionLimits> for MaxKeyexprBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_keyexpr_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_keyexpr_bytes()
    }
}

impl LimitField<SessionLimits> for MaxSubscriptions {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_subscriptions(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_subscriptions()
    }
}

impl LimitField<SessionLimits> for MatchMemoSlots {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_match_memo_slots(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.match_memo_slots()
    }
}

impl LimitField<SessionLimits> for DeliveryLaneEvents {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_delivery_lane_events(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.delivery_lane_events()
    }
}

impl LimitField<SessionLimits> for DeliveryLaneBytes {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_delivery_lane_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.delivery_lane_bytes()
    }
}

impl LimitField<SessionLimits> for DeliveryLaneCallbacks {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_delivery_lane_callbacks(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.delivery_lane_callbacks()
    }
}

impl LimitField<SessionLimits> for MaxQueryables {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_queryables(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_queryables()
    }
}

impl LimitField<SessionLimits> for MaxPendingQueries {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_pending_queries(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_pending_queries()
    }
}

impl LimitField<SessionLimits> for LinkNotedRequests {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_link_noted_requests(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.link_noted_requests()
    }
}

impl LimitField<SessionLimits> for MaxDeclObservers {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_decl_observers(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_decl_observers()
    }
}

impl LimitField<SessionLimits> for MaxLivelinessSubscriptions {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_liveliness_subscriptions(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_liveliness_subscriptions()
    }
}

impl LimitField<SessionLimits> for MaxLocalTokens {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_local_tokens(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_local_tokens()
    }
}

impl LimitField<SessionLimits> for MaxPendingLivelinessGets {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_pending_liveliness_gets(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_pending_liveliness_gets()
    }
}

impl LimitField<SessionLimits> for MaxPendingDeclares {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_pending_declares(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_pending_declares()
    }
}

impl LimitField<SessionLimits> for MaxInboundSubInterests {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_inbound_sub_interests(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_inbound_sub_interests()
    }
}

impl LimitField<SessionLimits> for MaxPeerKeyexprAliases {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_peer_keyexpr_aliases(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_peer_keyexpr_aliases()
    }
}

impl LimitField<SessionLimits> for MaxSharedKeyIds {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_shared_key_ids(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_shared_key_ids()
    }
}

impl LimitField<SessionLimits> for MaxRemoteDecls {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_remote_decls(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_remote_decls()
    }
}

impl LimitField<SessionLimits> for MaxPendingReplies {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_pending_replies(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_pending_replies()
    }
}

impl LimitField<SessionLimits> for MaxPendingFinals {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_pending_finals(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_pending_finals()
    }
}

impl LimitField<SessionLimits> for MaxReplyPayloadBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_reply_payload_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_reply_payload_bytes()
    }
}

impl LimitField<SessionLimits> for MaxMulticastReplies {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_multicast_replies(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.max_multicast_replies()
    }
}

impl LimitField<SessionLimits> for QuerierMaxPendingQueries {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_querier_max_pending_queries(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.querier_max_pending_queries()
    }
}

impl LimitField<SessionLimits> for TxNoProgressWindowUs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_tx_no_progress_window_us(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.tx_no_progress_window_us()
    }
}

impl LimitField<SessionLimits> for TxExpiryCloseAfter {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_tx_expiry_close_after(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.tx_expiry_close_after()
    }
}

impl LimitField<SessionLimits> for DatagramFragmentBurst {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_datagram_fragment_burst(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.datagram_fragment_burst()
    }
}

impl LimitField<SessionLimits> for DatagramFragmentGapUs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_datagram_fragment_gap_us(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.datagram_fragment_gap_us()
    }
}

impl LimitField<SessionLimits> for QueryParametersMaxBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_query_parameters_max_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.query_parameters_max_bytes()
    }
}

impl LimitField<SessionLimits> for QueryAttachmentMaxBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_query_attachment_max_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.query_attachment_max_bytes()
    }
}

impl LimitField<SessionLimits> for PicoTxQueueSize {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_tx_queue_size(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_tx_queue_size()
    }
}

impl LimitField<SessionLimits> for AppLinkQueueBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_app_link_queue_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.app_link_queue_bytes()
    }
}

impl LimitField<SessionLimits> for E2eSenderSlots {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_e2e_sender_slots(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.e2e_sender_slots()
    }
}

impl LimitField<SessionLimits> for ReplayDepthMax {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_replay_depth_max(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.replay_depth_max()
    }
}

impl LimitField<SessionLimits> for InstanceKeyFields {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_instance_key_fields(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.instance_key_fields()
    }
}

impl LimitField<SessionLimits> for InstancesPerMessage {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_instances_per_message(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.instances_per_message()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncBurstMessages {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_burst_messages(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_burst_messages()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncFinalTimeoutMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_final_timeout_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_final_timeout_ms()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncIntervalMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_interval_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_interval_ms()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncRxNoProgressMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_rx_no_progress_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_rx_no_progress_ms()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncRetryIntervalMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_retry_interval_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_retry_interval_ms()
    }
}

impl LimitField<SessionLimits> for DeclarationSyncTxNoProgressMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_declaration_sync_tx_no_progress_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.declaration_sync_tx_no_progress_ms()
    }
}

impl LimitField<SessionLimits> for PicoUnicastBatchBytes {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_unicast_batch_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_unicast_batch_bytes()
    }
}

impl LimitField<SessionLimits> for PicoMulticastBatchBytes {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_multicast_batch_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_multicast_batch_bytes()
    }
}

impl LimitField<SessionLimits> for PicoLeaseMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_lease_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_lease_ms()
    }
}

impl LimitField<SessionLimits> for PicoSocketTimeoutMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_socket_timeout_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_socket_timeout_ms()
    }
}

impl LimitField<SessionLimits> for PicoConnectTimeoutMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_connect_timeout_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_connect_timeout_ms()
    }
}

impl LimitField<SessionLimits> for PicoFragMaxBytes {
    fn select_in(snapshot: &mut SessionLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_frag_max_bytes(value)
    }

    fn held_in(snapshot: &SessionLimits) -> Quota {
        snapshot.pico_frag_max_bytes()
    }
}

impl LimitField<SessionLimits> for PicoAcceptTimeoutMs {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_accept_timeout_ms(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_accept_timeout_ms()
    }
}

impl LimitField<SessionLimits> for PicoKeepalivesPerLease {
    fn select_in(snapshot: &mut SessionLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_pico_keepalives_per_lease(value)
    }

    fn held_in(snapshot: &SessionLimits) -> usize {
        snapshot.pico_keepalives_per_lease()
    }
}

/// How many limits [`SessionLimits`] holds: the length of [`SESSION_LIMITS`].
pub const SESSION_LIMIT_COUNT: usize = 49;

/// Every limit of [`SessionLimits`] as a reader that names it by its id sees it, in the order of
/// its fields.
pub static SESSION_LIMITS: [LimitEntry<SessionLimits>; SESSION_LIMIT_COUNT] = [
    LimitEntry::of::<MaxKeyexprBytes>(),
    LimitEntry::of::<MaxSubscriptions>(),
    LimitEntry::of::<MatchMemoSlots>(),
    LimitEntry::of::<DeliveryLaneEvents>(),
    LimitEntry::of::<DeliveryLaneBytes>(),
    LimitEntry::of::<DeliveryLaneCallbacks>(),
    LimitEntry::of::<MaxQueryables>(),
    LimitEntry::of::<MaxPendingQueries>(),
    LimitEntry::of::<LinkNotedRequests>(),
    LimitEntry::of::<MaxDeclObservers>(),
    LimitEntry::of::<MaxLivelinessSubscriptions>(),
    LimitEntry::of::<MaxLocalTokens>(),
    LimitEntry::of::<MaxPendingLivelinessGets>(),
    LimitEntry::of::<MaxPendingDeclares>(),
    LimitEntry::of::<MaxInboundSubInterests>(),
    LimitEntry::of::<MaxPeerKeyexprAliases>(),
    LimitEntry::of::<MaxSharedKeyIds>(),
    LimitEntry::of::<MaxRemoteDecls>(),
    LimitEntry::of::<MaxPendingReplies>(),
    LimitEntry::of::<MaxPendingFinals>(),
    LimitEntry::of::<MaxReplyPayloadBytes>(),
    LimitEntry::of::<MaxMulticastReplies>(),
    LimitEntry::of::<QuerierMaxPendingQueries>(),
    LimitEntry::of::<TxNoProgressWindowUs>(),
    LimitEntry::of::<TxExpiryCloseAfter>(),
    LimitEntry::of::<DatagramFragmentBurst>(),
    LimitEntry::of::<DatagramFragmentGapUs>(),
    LimitEntry::of::<QueryParametersMaxBytes>(),
    LimitEntry::of::<QueryAttachmentMaxBytes>(),
    LimitEntry::of::<PicoTxQueueSize>(),
    LimitEntry::of::<AppLinkQueueBytes>(),
    LimitEntry::of::<E2eSenderSlots>(),
    LimitEntry::of::<ReplayDepthMax>(),
    LimitEntry::of::<InstanceKeyFields>(),
    LimitEntry::of::<InstancesPerMessage>(),
    LimitEntry::of::<DeclarationSyncBurstMessages>(),
    LimitEntry::of::<DeclarationSyncFinalTimeoutMs>(),
    LimitEntry::of::<DeclarationSyncIntervalMs>(),
    LimitEntry::of::<DeclarationSyncRxNoProgressMs>(),
    LimitEntry::of::<DeclarationSyncRetryIntervalMs>(),
    LimitEntry::of::<DeclarationSyncTxNoProgressMs>(),
    LimitEntry::of::<PicoUnicastBatchBytes>(),
    LimitEntry::of::<PicoMulticastBatchBytes>(),
    LimitEntry::of::<PicoLeaseMs>(),
    LimitEntry::of::<PicoSocketTimeoutMs>(),
    LimitEntry::of::<PicoConnectTimeoutMs>(),
    LimitEntry::of::<PicoFragMaxBytes>(),
    LimitEntry::of::<PicoAcceptTimeoutMs>(),
    LimitEntry::of::<PicoKeepalivesPerLease>(),
];

/// The value of every limit a node or runtime holds, as one snapshot: what a creator
/// resolved and hands the machines of its scope. A machine reads a limit through the
/// accessor of its field, never from the build. Each value lies inside the build's domain
/// of its limit, and a limit whose domain is one value reads as that value whatever was
/// selected ([`Limited::get`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeLimits {
    /// `MAX_LOCATOR_LEN`.
    max_locator_len: MaxLocatorLenHeld,
    /// `MAX_STATIC_CONNECT`.
    max_static_connect: MaxStaticConnectHeld,
    /// `SNAPSHOT_PERIOD_MS`.
    snapshot_period_ms: SnapshotPeriodMsHeld,
    /// `SNAPSHOT_HISTOGRAM_BUCKETS`.
    snapshot_histogram_buckets: SnapshotHistogramBucketsHeld,
    /// `SUPERVISION_CHECKPOINTS`.
    supervision_checkpoints: SupervisionCheckpointsHeld,
    /// `E2E_SUPERVISED_STREAMS`.
    e2e_supervised_streams: E2eSupervisedStreamsHeld,
    /// `EVENT_RING_SLOTS`.
    event_ring_slots: EventRingSlotsHeld,
    /// `CLOCK_SOURCES`.
    clock_sources: ClockSourcesHeld,
    /// `MESSAGE_CATALOG_ENTRIES`.
    message_catalog_entries: MessageCatalogEntriesHeld,
    /// `CLOCK_MAX_FORWARD_STEP_MS`.
    clock_max_forward_step_ms: ClockMaxForwardStepMsHeld,
}

impl RuntimeLimits {
    /// The build defaults: each limit's value as the build states it ([`LimitSpec::DEFAULT`]).
    pub const fn from_build() -> Self {
        Self {
            max_locator_len: Limited::build_default(),
            max_static_connect: Limited::build_default(),
            snapshot_period_ms: Limited::build_default(),
            snapshot_histogram_buckets: Limited::build_default(),
            supervision_checkpoints: Limited::build_default(),
            e2e_supervised_streams: Limited::build_default(),
            event_ring_slots: Limited::build_default(),
            clock_sources: Limited::build_default(),
            message_catalog_entries: Limited::build_default(),
            clock_max_forward_step_ms: Limited::build_default(),
        }
    }

    /// The build defaults ([`Self::from_build`]): the snapshot a creator starts from. A machine
    /// does not call it; it reads the snapshot its creator handed it.
    pub const fn defaults() -> Self {
        Self::from_build()
    }

    /// `MAX_LOCATOR_LEN` as this snapshot holds it.
    pub const fn max_locator_len(&self) -> Quota {
        self.max_locator_len.get()
    }

    /// Selects `MAX_LOCATOR_LEN`, when the build's domain holds `value`.
    pub fn select_max_locator_len(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_locator_len = Limited::select(value)?;
        Ok(())
    }

    /// `MAX_STATIC_CONNECT` as this snapshot holds it.
    pub const fn max_static_connect(&self) -> Quota {
        self.max_static_connect.get()
    }

    /// Selects `MAX_STATIC_CONNECT`, when the build's domain holds `value`.
    pub fn select_max_static_connect(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.max_static_connect = Limited::select(value)?;
        Ok(())
    }

    /// `SNAPSHOT_PERIOD_MS` as this snapshot holds it.
    pub const fn snapshot_period_ms(&self) -> usize {
        self.snapshot_period_ms.get()
    }

    /// Selects `SNAPSHOT_PERIOD_MS`, when the build's domain holds `value`.
    pub fn select_snapshot_period_ms(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.snapshot_period_ms = Limited::select(value)?;
        Ok(())
    }

    /// `SNAPSHOT_HISTOGRAM_BUCKETS` as this snapshot holds it.
    pub const fn snapshot_histogram_buckets(&self) -> usize {
        self.snapshot_histogram_buckets.get()
    }

    /// Selects `SNAPSHOT_HISTOGRAM_BUCKETS`, when the build's domain holds `value`.
    pub fn select_snapshot_histogram_buckets(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.snapshot_histogram_buckets = Limited::select(value)?;
        Ok(())
    }

    /// `SUPERVISION_CHECKPOINTS` as this snapshot holds it.
    pub const fn supervision_checkpoints(&self) -> usize {
        self.supervision_checkpoints.get()
    }

    /// Selects `SUPERVISION_CHECKPOINTS`, when the build's domain holds `value`.
    pub fn select_supervision_checkpoints(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.supervision_checkpoints = Limited::select(value)?;
        Ok(())
    }

    /// `E2E_SUPERVISED_STREAMS` as this snapshot holds it.
    pub const fn e2e_supervised_streams(&self) -> Quota {
        self.e2e_supervised_streams.get()
    }

    /// Selects `E2E_SUPERVISED_STREAMS`, when the build's domain holds `value`.
    pub fn select_e2e_supervised_streams(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.e2e_supervised_streams = Limited::select(value)?;
        Ok(())
    }

    /// `EVENT_RING_SLOTS` as this snapshot holds it.
    pub const fn event_ring_slots(&self) -> usize {
        self.event_ring_slots.get()
    }

    /// Selects `EVENT_RING_SLOTS`, when the build's domain holds `value`.
    pub fn select_event_ring_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.event_ring_slots = Limited::select(value)?;
        Ok(())
    }

    /// `CLOCK_SOURCES` as this snapshot holds it.
    pub const fn clock_sources(&self) -> Quota {
        self.clock_sources.get()
    }

    /// Selects `CLOCK_SOURCES`, when the build's domain holds `value`.
    pub fn select_clock_sources(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.clock_sources = Limited::select(value)?;
        Ok(())
    }

    /// `MESSAGE_CATALOG_ENTRIES` as this snapshot holds it.
    pub const fn message_catalog_entries(&self) -> Quota {
        self.message_catalog_entries.get()
    }

    /// Selects `MESSAGE_CATALOG_ENTRIES`, when the build's domain holds `value`.
    pub fn select_message_catalog_entries(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.message_catalog_entries = Limited::select(value)?;
        Ok(())
    }

    /// `CLOCK_MAX_FORWARD_STEP_MS` as this snapshot holds it.
    pub const fn clock_max_forward_step_ms(&self) -> usize {
        self.clock_max_forward_step_ms.get()
    }

    /// Selects `CLOCK_MAX_FORWARD_STEP_MS`, when the build's domain holds `value`.
    pub fn select_clock_max_forward_step_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.clock_max_forward_step_ms = Limited::select(value)?;
        Ok(())
    }
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self::from_build()
    }
}

impl LimitField<RuntimeLimits> for MaxLocatorLen {
    fn select_in(snapshot: &mut RuntimeLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_locator_len(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> Quota {
        snapshot.max_locator_len()
    }
}

impl LimitField<RuntimeLimits> for MaxStaticConnect {
    fn select_in(snapshot: &mut RuntimeLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_max_static_connect(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> Quota {
        snapshot.max_static_connect()
    }
}

impl LimitField<RuntimeLimits> for SnapshotPeriodMs {
    fn select_in(snapshot: &mut RuntimeLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_snapshot_period_ms(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> usize {
        snapshot.snapshot_period_ms()
    }
}

impl LimitField<RuntimeLimits> for SnapshotHistogramBuckets {
    fn select_in(snapshot: &mut RuntimeLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_snapshot_histogram_buckets(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> usize {
        snapshot.snapshot_histogram_buckets()
    }
}

impl LimitField<RuntimeLimits> for SupervisionCheckpoints {
    fn select_in(snapshot: &mut RuntimeLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_supervision_checkpoints(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> usize {
        snapshot.supervision_checkpoints()
    }
}

impl LimitField<RuntimeLimits> for E2eSupervisedStreams {
    fn select_in(snapshot: &mut RuntimeLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_e2e_supervised_streams(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> Quota {
        snapshot.e2e_supervised_streams()
    }
}

impl LimitField<RuntimeLimits> for EventRingSlots {
    fn select_in(snapshot: &mut RuntimeLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_event_ring_slots(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> usize {
        snapshot.event_ring_slots()
    }
}

impl LimitField<RuntimeLimits> for ClockSources {
    fn select_in(snapshot: &mut RuntimeLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_clock_sources(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> Quota {
        snapshot.clock_sources()
    }
}

impl LimitField<RuntimeLimits> for MessageCatalogEntries {
    fn select_in(snapshot: &mut RuntimeLimits, value: Quota) -> Result<(), OutsideLimitDomain> {
        snapshot.select_message_catalog_entries(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> Quota {
        snapshot.message_catalog_entries()
    }
}

impl LimitField<RuntimeLimits> for ClockMaxForwardStepMs {
    fn select_in(snapshot: &mut RuntimeLimits, value: usize) -> Result<(), OutsideLimitDomain> {
        snapshot.select_clock_max_forward_step_ms(value)
    }

    fn held_in(snapshot: &RuntimeLimits) -> usize {
        snapshot.clock_max_forward_step_ms()
    }
}

/// How many limits [`RuntimeLimits`] holds: the length of [`RUNTIME_LIMITS`].
pub const RUNTIME_LIMIT_COUNT: usize = 10;

/// Every limit of [`RuntimeLimits`] as a reader that names it by its id sees it, in the order of
/// its fields.
pub static RUNTIME_LIMITS: [LimitEntry<RuntimeLimits>; RUNTIME_LIMIT_COUNT] = [
    LimitEntry::of::<MaxLocatorLen>(),
    LimitEntry::of::<MaxStaticConnect>(),
    LimitEntry::of::<SnapshotPeriodMs>(),
    LimitEntry::of::<SnapshotHistogramBuckets>(),
    LimitEntry::of::<SupervisionCheckpoints>(),
    LimitEntry::of::<E2eSupervisedStreams>(),
    LimitEntry::of::<EventRingSlots>(),
    LimitEntry::of::<ClockSources>(),
    LimitEntry::of::<MessageCatalogEntries>(),
    LimitEntry::of::<ClockMaxForwardStepMs>(),
];
