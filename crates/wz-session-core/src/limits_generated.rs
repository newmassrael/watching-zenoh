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
    limit_defaults_only, word_after, LimitDomain, LimitEntry, LimitField, LimitSpec, LimitValue,
    Limited, OutsideLimitDomain, Quota,
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

/// The capacity of a parameter whose bytes a session's arena lends when it opens, under the
/// build's value: `value` where the build's tables are fixed in size or its engine lends from
/// an arena (`limits-lent-at-open`), so a stage after the build only lowers it; none where the
/// heap sizes the bytes from the session's own value.
const fn lent_capacity(value: usize) -> Option<usize> {
    if crate::bounded::ENFORCES_CAPACITY || crate::limit_binding::LIMITS_LENT_AT_OPEN {
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = Some(caps::MAX_KEYEXPR_BYTES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_KEYEXPR_BYTES);
}

const _: LimitDomain = MaxKeyexprBytes::DOMAIN;

/// How `MAX_KEYEXPR_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxKeyexprBytesHeld = Limited<MaxKeyexprBytes, { MaxKeyexprBytes::HELD }>;

/// `KEY_ARENA_BYTES`: How many bytes of key text a session holds at once, in one arena
/// every keyed row keeps its key in: its declared key expressions, its entities with their
/// write filters, Interests and matching listeners, its pending gets and what each peer
/// declares to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyArenaBytes;

impl LimitSpec for KeyArenaBytes {
    type Value = usize;
    const LIMIT: &'static str = "KEY_ARENA_BYTES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::KEY_ARENA_BYTES);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967291, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::KEY_ARENA_BYTES;
}

const _: LimitDomain = KeyArenaBytes::DOMAIN;

/// How `KEY_ARENA_BYTES` is held: in no byte when its domain is one value.
pub type KeyArenaBytesHeld = Limited<KeyArenaBytes, { KeyArenaBytes::HELD }>;

/// `MAX_SUBSCRIPTIONS`: The subscribers a session holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxSubscriptions;

impl LimitSpec for MaxSubscriptions {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_SUBSCRIPTIONS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_SUBSCRIPTIONS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxSubscriptions::DOMAIN;

/// How `MAX_SUBSCRIPTIONS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxSubscriptionsHeld = Limited<MaxSubscriptions, { MaxSubscriptions::HELD }>;

/// `MATCH_MEMO_SLOTS`: How many distinct keys the receive match cache remembers at once:
/// the keys whose matching subscriptions it can answer without matching again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchMemoSlots;

impl LimitSpec for MatchMemoSlots {
    type Value = usize;
    const LIMIT: &'static str = "MATCH_MEMO_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::MATCH_MEMO_SLOTS;
}

const _: LimitDomain = MatchMemoSlots::DOMAIN;

/// How `MATCH_MEMO_SLOTS` is held: in no byte when its domain is one value.
pub type MatchMemoSlotsHeld = Limited<MatchMemoSlots, { MatchMemoSlots::HELD }>;

/// `DELIVERY_LANE_EVENTS`: How many samples the delivery lane of an offloaded subscriber
/// holds at once: the samples the receive path has copied in and its callback has not yet
/// run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneEvents;

impl LimitSpec for DeliveryLaneEvents {
    type Value = Quota;
    const LIMIT: &'static str = "DELIVERY_LANE_EVENTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = Some(caps::DELIVERY_LANE_EVENTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::DELIVERY_LANE_EVENTS);
}

const _: LimitDomain = DeliveryLaneEvents::DOMAIN;

/// How `DELIVERY_LANE_EVENTS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type DeliveryLaneEventsHeld = Limited<DeliveryLaneEvents, { DeliveryLaneEvents::HELD }>;

/// `DELIVERY_LANE_BYTES`: How many bytes of copied samples a delivery lane holds at once:
/// the key, the payload, the attachment and the encoding schema of each waiting sample, the
/// ids of the subscribers a sample written once for several of them is for, and the end of
/// the byte area a sample skipped to stay in one piece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneBytes;

impl LimitSpec for DeliveryLaneBytes {
    type Value = usize;
    const LIMIT: &'static str = "DELIVERY_LANE_BYTES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::DELIVERY_LANE_BYTES);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DELIVERY_LANE_BYTES;
}

const _: LimitDomain = DeliveryLaneBytes::DOMAIN;

/// How `DELIVERY_LANE_BYTES` is held: in no byte when its domain is one value.
pub type DeliveryLaneBytesHeld = Limited<DeliveryLaneBytes, { DeliveryLaneBytes::HELD }>;

/// `DELIVERY_LANE_CALLBACKS`: How many callback invocations a delivery lane owes at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLaneCallbacks;

impl LimitSpec for DeliveryLaneCallbacks {
    type Value = Quota;
    const LIMIT: &'static str = "DELIVERY_LANE_CALLBACKS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = Some(caps::DELIVERY_LANE_CALLBACKS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::DELIVERY_LANE_CALLBACKS);
}

const _: LimitDomain = DeliveryLaneCallbacks::DOMAIN;

/// How `DELIVERY_LANE_CALLBACKS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type DeliveryLaneCallbacksHeld =
    Limited<DeliveryLaneCallbacks, { DeliveryLaneCallbacks::HELD }>;

/// `MAX_QUERYABLES`: The queryables a session holds at once, a background one included
/// until the session closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxQueryables;

impl LimitSpec for MaxQueryables {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_QUERYABLES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_QUERYABLES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxQueryables::DOMAIN;

/// How `MAX_QUERYABLES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxQueryablesHeld = Limited<MaxQueryables, { MaxQueryables::HELD }>;

/// `MAX_PENDING_QUERIES`: The queries (gets) a session has waiting for their replies at
/// once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingQueries;

impl LimitSpec for MaxPendingQueries {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_QUERIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_QUERIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingQueries::DOMAIN;

/// How `MAX_PENDING_QUERIES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPendingQueriesHeld = Limited<MaxPendingQueries, { MaxPendingQueries::HELD }>;

/// `LINK_NOTED_REQUESTS`: How many queries a peer sent over one link the node remembers the
/// key form of at once, so that its replies name the key as the query did, when the link
/// names keys by the shared key ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkNotedRequests;

impl LimitSpec for LinkNotedRequests {
    type Value = usize;
    const LIMIT: &'static str = "LINK_NOTED_REQUESTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::LINK_NOTED_REQUESTS;
}

const _: LimitDomain = LinkNotedRequests::DOMAIN;

/// How `LINK_NOTED_REQUESTS` is held: in no byte when its domain is one value.
pub type LinkNotedRequestsHeld = Limited<LinkNotedRequests, { LinkNotedRequests::HELD }>;

/// `MAX_DECL_OBSERVERS`: The observers an application installs on the declarations of its
/// peers (subscribers, queryables and liveliness tokens appearing or leaving), per kind and
/// per direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxDeclObservers;

impl LimitSpec for MaxDeclObservers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_DECL_OBSERVERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_DECL_OBSERVERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxDeclObservers::DOMAIN;

/// How `MAX_DECL_OBSERVERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxDeclObserversHeld = Limited<MaxDeclObservers, { MaxDeclObservers::HELD }>;

/// `MAX_LIVELINESS_SUBSCRIPTIONS`: The liveliness subscribers a session holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLivelinessSubscriptions;

impl LimitSpec for MaxLivelinessSubscriptions {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LIVELINESS_SUBSCRIPTIONS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_LIVELINESS_SUBSCRIPTIONS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxLivelinessSubscriptions::DOMAIN;

/// How `MAX_LIVELINESS_SUBSCRIPTIONS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxLivelinessSubscriptionsHeld =
    Limited<MaxLivelinessSubscriptions, { MaxLivelinessSubscriptions::HELD }>;

/// `MAX_LOCAL_TOKENS`: The liveliness tokens a session itself declares and holds at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLocalTokens;

impl LimitSpec for MaxLocalTokens {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LOCAL_TOKENS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_LOCAL_TOKENS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxLocalTokens::DOMAIN;

/// How `MAX_LOCAL_TOKENS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxLocalTokensHeld = Limited<MaxLocalTokens, { MaxLocalTokens::HELD }>;

/// `MAX_PUBLISHERS`: The publishers a session holds at once, each with the write filter
/// that asks whether anything subscribes to its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPublishers;

impl LimitSpec for MaxPublishers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PUBLISHERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PUBLISHERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPublishers::DOMAIN;

/// How `MAX_PUBLISHERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPublishersHeld = Limited<MaxPublishers, { MaxPublishers::HELD }>;

/// `MAX_QUERIERS`: The queriers a session holds at once, each with the write filter that
/// asks whether anything answers on its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxQueriers;

impl LimitSpec for MaxQueriers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_QUERIERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_QUERIERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxQueriers::DOMAIN;

/// How `MAX_QUERIERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxQueriersHeld = Limited<MaxQueriers, { MaxQueriers::HELD }>;

/// `MAX_MATCHING_LISTENERS`: The matching listeners a session holds at once, over all its
/// publishers and queriers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxMatchingListeners;

impl LimitSpec for MaxMatchingListeners {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_MATCHING_LISTENERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_MATCHING_LISTENERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxMatchingListeners::DOMAIN;

/// How `MAX_MATCHING_LISTENERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxMatchingListenersHeld = Limited<MaxMatchingListeners, { MaxMatchingListeners::HELD }>;

/// `MAX_DECL_WATCHES`: The declaration watches a session holds at once (what its peers
/// declare and retract, told to the program), over every kind of entity watched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxDeclWatches;

impl LimitSpec for MaxDeclWatches {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_DECL_WATCHES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_DECL_WATCHES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxDeclWatches::DOMAIN;

/// How `MAX_DECL_WATCHES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxDeclWatchesHeld = Limited<MaxDeclWatches, { MaxDeclWatches::HELD }>;

/// `MAX_TRANSPORT_EVENTS_LISTENERS`: The transport events listeners a session holds at
/// once, each told when a transport to a peer opens or closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxTransportEventsListeners;

impl LimitSpec for MaxTransportEventsListeners {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_TRANSPORT_EVENTS_LISTENERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_TRANSPORT_EVENTS_LISTENERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxTransportEventsListeners::DOMAIN;

/// How `MAX_TRANSPORT_EVENTS_LISTENERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxTransportEventsListenersHeld =
    Limited<MaxTransportEventsListeners, { MaxTransportEventsListeners::HELD }>;

/// `MAX_LINK_EVENTS_LISTENERS`: The link events listeners a session holds at once, each
/// told when a link to a peer comes up or goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLinkEventsListeners;

impl LimitSpec for MaxLinkEventsListeners {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LINK_EVENTS_LISTENERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_LINK_EVENTS_LISTENERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxLinkEventsListeners::DOMAIN;

/// How `MAX_LINK_EVENTS_LISTENERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxLinkEventsListenersHeld =
    Limited<MaxLinkEventsListeners, { MaxLinkEventsListeners::HELD }>;

/// `MAX_DECLARED_KEYEXPRS`: The key expressions a session declares to its peers at once,
/// each held by the entities that name it and by the program's declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxDeclaredKeyexprs;

impl LimitSpec for MaxDeclaredKeyexprs {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_DECLARED_KEYEXPRS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_DECLARED_KEYEXPRS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxDeclaredKeyexprs::DOMAIN;

/// How `MAX_DECLARED_KEYEXPRS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxDeclaredKeyexprsHeld = Limited<MaxDeclaredKeyexprs, { MaxDeclaredKeyexprs::HELD }>;

/// `MAX_PENDING_LIVELINESS_GETS`: The liveliness gets (snapshots of the tokens alive) a
/// session has waiting for their answer at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingLivelinessGets;

impl LimitSpec for MaxPendingLivelinessGets {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_LIVELINESS_GETS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_LIVELINESS_GETS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingLivelinessGets::DOMAIN;

/// How `MAX_PENDING_LIVELINESS_GETS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPendingLivelinessGetsHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_DECLARES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingDeclares::DOMAIN;

/// How `MAX_PENDING_DECLARES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPendingDeclaresHeld = Limited<MaxPendingDeclares, { MaxPendingDeclares::HELD }>;

/// `MAX_INBOUND_SUB_INTERESTS`: The peers' interests in this session's subscribers that the
/// session remembers, so that a subscriber declared later is announced to them: one per
/// publisher a peer holds with a write filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxInboundSubInterests;

impl LimitSpec for MaxInboundSubInterests {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_INBOUND_SUB_INTERESTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_INBOUND_SUB_INTERESTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxInboundSubInterests::DOMAIN;

/// How `MAX_INBOUND_SUB_INTERESTS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxInboundSubInterestsHeld =
    Limited<MaxInboundSubInterests, { MaxInboundSubInterests::HELD }>;

/// `MAX_PEER_KEYEXPR_ALIASES`: The key expressions one peer may have declared to this
/// session at a time, to name them by a short id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPeerKeyexprAliases;

impl LimitSpec for MaxPeerKeyexprAliases {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PEER_KEYEXPR_ALIASES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PEER_KEYEXPR_ALIASES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPeerKeyexprAliases::DOMAIN;

/// How `MAX_PEER_KEYEXPR_ALIASES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPeerKeyexprAliasesHeld =
    Limited<MaxPeerKeyexprAliases, { MaxPeerKeyexprAliases::HELD }>;

/// `MAX_SHARED_KEY_IDS`: The entries of the key-id dictionary every node of a deployment
/// shares (shared-key-ids) that one session may be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxSharedKeyIds;

impl LimitSpec for MaxSharedKeyIds {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_SHARED_KEY_IDS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::MAX_SHARED_KEY_IDS, false);
}

const _: LimitDomain = MaxSharedKeyIds::DOMAIN;

/// How `MAX_SHARED_KEY_IDS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxSharedKeyIdsHeld = Limited<MaxSharedKeyIds, { MaxSharedKeyIds::HELD }>;

/// `MAX_REMOTE_DECLS`: The declarations of one kind (subscribers, queryables, liveliness
/// tokens) one peer may hold open to this session at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxRemoteDecls;

impl LimitSpec for MaxRemoteDecls {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_REMOTE_DECLS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_REMOTE_DECLS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxRemoteDecls::DOMAIN;

/// How `MAX_REMOTE_DECLS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxRemoteDeclsHeld = Limited<MaxRemoteDecls, { MaxRemoteDecls::HELD }>;

/// `MAX_PENDING_REPLIES`: The replies a session's queryables may have ready to send between
/// two sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingReplies;

impl LimitSpec for MaxPendingReplies {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_REPLIES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_REPLIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingReplies::DOMAIN;

/// How `MAX_PENDING_REPLIES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPendingRepliesHeld = Limited<MaxPendingReplies, { MaxPendingReplies::HELD }>;

/// `MAX_PENDING_FINALS`: The queries a session may owe the end of an answer between two
/// sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxPendingFinals;

impl LimitSpec for MaxPendingFinals {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_PENDING_FINALS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_PENDING_FINALS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxPendingFinals::DOMAIN;

/// How `MAX_PENDING_FINALS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxPendingFinalsHeld = Limited<MaxPendingFinals, { MaxPendingFinals::HELD }>;

/// `MAX_REPLY_PAYLOAD_BYTES`: The largest payload of one reply, in bytes, and the largest
/// attachment beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxReplyPayloadBytes;

impl LimitSpec for MaxReplyPayloadBytes {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_REPLY_PAYLOAD_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_REPLY_PAYLOAD_BYTES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxReplyPayloadBytes::DOMAIN;

/// How `MAX_REPLY_PAYLOAD_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxReplyPayloadBytesHeld = Limited<MaxReplyPayloadBytes, { MaxReplyPayloadBytes::HELD }>;

/// `MAX_MULTICAST_REPLIES`: The replies a node holds for a multicast group before it sends
/// them, with or without an allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxMulticastReplies;

impl LimitSpec for MaxMulticastReplies {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_MULTICAST_REPLIES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_MULTICAST_REPLIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_MULTICAST_REPLIES);
}

const _: LimitDomain = MaxMulticastReplies::DOMAIN;

/// How `MAX_MULTICAST_REPLIES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxMulticastRepliesHeld = Limited<MaxMulticastReplies, { MaxMulticastReplies::HELD }>;

/// `GROUP_READS_PER_MOVE`: How many datagrams of a multicast group in a row a read of the C
/// ABI's cooperative engine takes, a step each, before it moves the session's links, timers
/// and sweeps again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupReadsPerMove;

impl LimitSpec for GroupReadsPerMove {
    type Value = usize;
    const LIMIT: &'static str = "GROUP_READS_PER_MOVE";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 255, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::GROUP_READS_PER_MOVE;
}

const _: LimitDomain = GroupReadsPerMove::DOMAIN;

/// How `GROUP_READS_PER_MOVE` is held: in no byte when its domain is one value.
pub type GroupReadsPerMoveHeld = Limited<GroupReadsPerMove, { GroupReadsPerMove::HELD }>;

/// `MAX_ADVANCED_PUBLISHERS`: The advanced publishers a session holds at once, each the C
/// object over the publisher, its cache and its detection token, which are counted in their
/// own tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxAdvancedPublishers;

impl LimitSpec for MaxAdvancedPublishers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_ADVANCED_PUBLISHERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_ADVANCED_PUBLISHERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxAdvancedPublishers::DOMAIN;

/// How `MAX_ADVANCED_PUBLISHERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxAdvancedPublishersHeld =
    Limited<MaxAdvancedPublishers, { MaxAdvancedPublishers::HELD }>;

/// `MAX_ADVANCED_SUBSCRIBERS`: The advanced subscribers a session holds at once, owned or
/// background, each the C object over the subscriber, its history and recovery and its
/// detection token, which are counted in their own tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxAdvancedSubscribers;

impl LimitSpec for MaxAdvancedSubscribers {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_ADVANCED_SUBSCRIBERS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_ADVANCED_SUBSCRIBERS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxAdvancedSubscribers::DOMAIN;

/// How `MAX_ADVANCED_SUBSCRIBERS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxAdvancedSubscribersHeld =
    Limited<MaxAdvancedSubscribers, { MaxAdvancedSubscribers::HELD }>;

/// `MAX_LOCATOR_LEN`: The longest locator, in bytes, a node stores: one it is told to
/// connect to, or one it listens on (for example udp/192.168.1.10:7447).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxLocatorLen;

impl LimitSpec for MaxLocatorLen {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_LOCATOR_LEN";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = Some(caps::MAX_LOCATOR_LEN);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MAX_LOCATOR_LEN);
}

const _: LimitDomain = MaxLocatorLen::DOMAIN;

/// How `MAX_LOCATOR_LEN` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxLocatorLenHeld = Limited<MaxLocatorLen, { MaxLocatorLen::HELD }>;

/// `MAX_STATIC_CONNECT`: The locators a node is told to connect to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxStaticConnect;

impl LimitSpec for MaxStaticConnect {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_STATIC_CONNECT";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_STATIC_CONNECT);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxStaticConnect::DOMAIN;

/// How `MAX_STATIC_CONNECT` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxStaticConnectHeld = Limited<MaxStaticConnect, { MaxStaticConnect::HELD }>;

/// `MAX_FACES`: The faces a session that listens holds besides the one it dials: the links
/// it accepts, those still in their handshake among them, and those it attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxFaces;

impl LimitSpec for MaxFaces {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_FACES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_FACES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxFaces::DOMAIN;

/// How `MAX_FACES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxFacesHeld = Limited<MaxFaces, { MaxFaces::HELD }>;

/// `MAX_ACCEPT_PENDING`: The inbound links a session that listens holds in their handshake
/// at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxAcceptPending;

impl LimitSpec for MaxAcceptPending {
    type Value = Quota;
    const LIMIT: &'static str = "MAX_ACCEPT_PENDING";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_ACCEPT_PENDING);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = MaxAcceptPending::DOMAIN;

/// How `MAX_ACCEPT_PENDING` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MaxAcceptPendingHeld = Limited<MaxAcceptPending, { MaxAcceptPending::HELD }>;

/// `RX_POOL_BUFFERS`: How many receive buffers, each of the batch a session advertises, the
/// links of a session share when its engine lends their buffers from the session's memory
/// at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxPoolBuffers;

impl LimitSpec for RxPoolBuffers {
    type Value = usize;
    const LIMIT: &'static str = "RX_POOL_BUFFERS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::RX_POOL_BUFFERS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::RX_POOL_BUFFERS;
}

const _: LimitDomain = RxPoolBuffers::DOMAIN;

/// How `RX_POOL_BUFFERS` is held: in no byte when its domain is one value.
pub type RxPoolBuffersHeld = Limited<RxPoolBuffers, { RxPoolBuffers::HELD }>;

/// `TX_POOL_SLOTS`: How many outbound slots, each of the batch a session advertises, the
/// links of a session share when its engine lends their buffers from the session's memory
/// at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPoolSlots;

impl LimitSpec for TxPoolSlots {
    type Value = usize;
    const LIMIT: &'static str = "TX_POOL_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::TX_POOL_SLOTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::TX_POOL_SLOTS;
}

const _: LimitDomain = TxPoolSlots::DOMAIN;

/// How `TX_POOL_SLOTS` is held: in no byte when its domain is one value.
pub type TxPoolSlotsHeld = Limited<TxPoolSlots, { TxPoolSlots::HELD }>;

/// `SESSION_MAX_PEER_KEYEXPR_ALIASES`: The key expressions all the peers of a session may
/// have declared to it at a time, each peer also held to MAX_PEER_KEYEXPR_ALIASES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionMaxPeerKeyexprAliases;

impl LimitSpec for SessionMaxPeerKeyexprAliases {
    type Value = Quota;
    const LIMIT: &'static str = "SESSION_MAX_PEER_KEYEXPR_ALIASES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::SESSION_MAX_PEER_KEYEXPR_ALIASES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = SessionMaxPeerKeyexprAliases::DOMAIN;

/// How `SESSION_MAX_PEER_KEYEXPR_ALIASES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type SessionMaxPeerKeyexprAliasesHeld =
    Limited<SessionMaxPeerKeyexprAliases, { SessionMaxPeerKeyexprAliases::HELD }>;

/// `SESSION_MAX_REMOTE_DECLS`: The declarations of one kind (subscribers, queryables,
/// liveliness tokens) all the peers of a session may hold open to it at a time, each peer
/// also held to MAX_REMOTE_DECLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionMaxRemoteDecls;

impl LimitSpec for SessionMaxRemoteDecls {
    type Value = Quota;
    const LIMIT: &'static str = "SESSION_MAX_REMOTE_DECLS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::SESSION_MAX_REMOTE_DECLS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = SessionMaxRemoteDecls::DOMAIN;

/// How `SESSION_MAX_REMOTE_DECLS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type SessionMaxRemoteDeclsHeld =
    Limited<SessionMaxRemoteDecls, { SessionMaxRemoteDecls::HELD }>;

/// `SESSION_MAX_INBOUND_SUB_INTERESTS`: The interests in this session's subscribers that
/// all its peers may have it remember at a time, each peer also held to
/// MAX_INBOUND_SUB_INTERESTS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionMaxInboundSubInterests;

impl LimitSpec for SessionMaxInboundSubInterests {
    type Value = Quota;
    const LIMIT: &'static str = "SESSION_MAX_INBOUND_SUB_INTERESTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::SESSION_MAX_INBOUND_SUB_INTERESTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
}

const _: LimitDomain = SessionMaxInboundSubInterests::DOMAIN;

/// How `SESSION_MAX_INBOUND_SUB_INTERESTS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type SessionMaxInboundSubInterestsHeld =
    Limited<SessionMaxInboundSubInterests, { SessionMaxInboundSubInterests::HELD }>;

/// `QUERIER_MAX_PENDING_QUERIES`: The queries one declared querier may have in flight at
/// once; one more is refused until a pending one ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerierMaxPendingQueries;

impl LimitSpec for QuerierMaxPendingQueries {
    type Value = Quota;
    const LIMIT: &'static str = "QUERIER_MAX_PENDING_QUERIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERIER_MAX_PENDING_QUERIES, true);
}

const _: LimitDomain = QuerierMaxPendingQueries::DOMAIN;

/// How `QUERIER_MAX_PENDING_QUERIES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type QuerierMaxPendingQueriesHeld =
    Limited<QuerierMaxPendingQueries, { QuerierMaxPendingQueries::HELD }>;

/// `TX_NO_PROGRESS_WINDOW_US`: How long, in microseconds, a blocking message may wait with
/// no progress when the tx-no-progress-deadline policy is on: no fragment of it going out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxNoProgressWindowUs;

impl LimitSpec for TxNoProgressWindowUs {
    type Value = usize;
    const LIMIT: &'static str = "TX_NO_PROGRESS_WINDOW_US";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 5000000, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::TX_NO_PROGRESS_WINDOW_US;
}

const _: LimitDomain = TxNoProgressWindowUs::DOMAIN;

/// How `TX_NO_PROGRESS_WINDOW_US` is held: in no byte when its domain is one value.
pub type TxNoProgressWindowUsHeld = Limited<TxNoProgressWindowUs, { TxNoProgressWindowUs::HELD }>;

/// `TX_EXPIRY_CLOSE_AFTER`: How many blocking messages in a row may find no room within
/// their deadline before the session is closed as unresponsive, when the
/// tx-expiry-keeps-session policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxExpiryCloseAfter;

impl LimitSpec for TxExpiryCloseAfter {
    type Value = Quota;
    const LIMIT: &'static str = "TX_EXPIRY_CLOSE_AFTER";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_bound_within(Self::CAPACITY, 65535, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::TX_EXPIRY_CLOSE_AFTER, true);
}

const _: LimitDomain = TxExpiryCloseAfter::DOMAIN;

/// How `TX_EXPIRY_CLOSE_AFTER` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type TxExpiryCloseAfterHeld = Limited<TxExpiryCloseAfter, { TxExpiryCloseAfter::HELD }>;

/// `DATAGRAM_FRAGMENT_BURST`: How many fragments of a message a UDP link's writer writes in
/// a row when the datagram-fragment-pacing policy is on, before the next one waits for
/// DATAGRAM_FRAGMENT_GAP_US.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramFragmentBurst;

impl LimitSpec for DatagramFragmentBurst {
    type Value = usize;
    const LIMIT: &'static str = "DATAGRAM_FRAGMENT_BURST";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DATAGRAM_FRAGMENT_BURST;
}

const _: LimitDomain = DatagramFragmentBurst::DOMAIN;

/// How `DATAGRAM_FRAGMENT_BURST` is held: in no byte when its domain is one value.
pub type DatagramFragmentBurstHeld =
    Limited<DatagramFragmentBurst, { DatagramFragmentBurst::HELD }>;

/// `DATAGRAM_FRAGMENT_GAP_US`: How long, in microseconds, must pass after the last fragment
/// was written before a UDP link's writer writes another one past the burst, when the
/// datagram-fragment-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramFragmentGapUs;

impl LimitSpec for DatagramFragmentGapUs {
    type Value = usize;
    const LIMIT: &'static str = "DATAGRAM_FRAGMENT_GAP_US";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 1000000, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DATAGRAM_FRAGMENT_GAP_US;
}

const _: LimitDomain = DatagramFragmentGapUs::DOMAIN;

/// How `DATAGRAM_FRAGMENT_GAP_US` is held: in no byte when its domain is one value.
pub type DatagramFragmentGapUsHeld =
    Limited<DatagramFragmentGapUs, { DatagramFragmentGapUs::HELD }>;

/// `QUERY_PARAMETERS_MAX_BYTES`: The most bytes of selector parameters a query from a peer
/// may carry for this node to run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryParametersMaxBytes;

impl LimitSpec for QueryParametersMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "QUERY_PARAMETERS_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERY_PARAMETERS_MAX_BYTES, true);
}

const _: LimitDomain = QueryParametersMaxBytes::DOMAIN;

/// How `QUERY_PARAMETERS_MAX_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type QueryParametersMaxBytesHeld =
    Limited<QueryParametersMaxBytes, { QueryParametersMaxBytes::HELD }>;

/// `QUERY_ATTACHMENT_MAX_BYTES`: The most bytes of attachment a query from a peer may carry
/// for this node to run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryAttachmentMaxBytes;

impl LimitSpec for QueryAttachmentMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "QUERY_ATTACHMENT_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::QUERY_ATTACHMENT_MAX_BYTES, true);
}

const _: LimitDomain = QueryAttachmentMaxBytes::DOMAIN;

/// How `QUERY_ATTACHMENT_MAX_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type QueryAttachmentMaxBytesHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 16, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_TX_QUEUE_SIZE;
}

const _: LimitDomain = PicoTxQueueSize::DOMAIN;

/// How `PICO_TX_QUEUE_SIZE` is held: in no byte when its domain is one value.
pub type PicoTxQueueSizeHeld = Limited<PicoTxQueueSize, { PicoTxQueueSize::HELD }>;

/// `SNAPSHOT_PERIOD_MS`: How often, in milliseconds, the node takes a snapshot of itself:
/// what it spends and how its messages are spaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotPeriodMs;

impl LimitSpec for SnapshotPeriodMs {
    type Value = usize;
    const LIMIT: &'static str = "SNAPSHOT_PERIOD_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 2147483, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SNAPSHOT_PERIOD_MS;
}

const _: LimitDomain = SnapshotPeriodMs::DOMAIN;

/// How `SNAPSHOT_PERIOD_MS` is held: in no byte when its domain is one value.
pub type SnapshotPeriodMsHeld = Limited<SnapshotPeriodMs, { SnapshotPeriodMs::HELD }>;

/// `SNAPSHOT_HISTOGRAM_BUCKETS`: How many buckets the snapshot's message-interval histogram
/// has, each 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotHistogramBuckets;

impl LimitSpec for SnapshotHistogramBuckets {
    type Value = usize;
    const LIMIT: &'static str = "SNAPSHOT_HISTOGRAM_BUCKETS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = Some(caps::SNAPSHOT_HISTOGRAM_BUCKETS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 32, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SNAPSHOT_HISTOGRAM_BUCKETS;
}

const _: LimitDomain = SnapshotHistogramBuckets::DOMAIN;

/// How `SNAPSHOT_HISTOGRAM_BUCKETS` is held: in no byte when its domain is one value.
pub type SnapshotHistogramBucketsHeld =
    Limited<SnapshotHistogramBuckets, { SnapshotHistogramBuckets::HELD }>;

/// `SUPERVISION_CHECKPOINTS`: How many checkpoints the node's supervisor watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisionCheckpoints;

impl LimitSpec for SupervisionCheckpoints {
    type Value = usize;
    const LIMIT: &'static str = "SUPERVISION_CHECKPOINTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = Some(caps::SUPERVISION_CHECKPOINTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 64, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::SUPERVISION_CHECKPOINTS;
}

const _: LimitDomain = SupervisionCheckpoints::DOMAIN;

/// How `SUPERVISION_CHECKPOINTS` is held: in no byte when its domain is one value.
pub type SupervisionCheckpointsHeld =
    Limited<SupervisionCheckpoints, { SupervisionCheckpoints::HELD }>;

/// `E2E_SUPERVISED_STREAMS`: How many periodic streams one reception supervisor holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E2eSupervisedStreams;

impl LimitSpec for E2eSupervisedStreams {
    type Value = Quota;
    const LIMIT: &'static str = "E2E_SUPERVISED_STREAMS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::E2E_SUPERVISED_STREAMS, false);
}

const _: LimitDomain = E2eSupervisedStreams::DOMAIN;

/// How `E2E_SUPERVISED_STREAMS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type E2eSupervisedStreamsHeld = Limited<E2eSupervisedStreams, { E2eSupervisedStreams::HELD }>;

/// `APP_LINK_QUEUE_BYTES`: The most bytes one link of a transport the program supplies
/// queues in either direction: what the program handed in and the session has not read, and
/// what a session that cannot wait handed over and the program has not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppLinkQueueBytes;

impl LimitSpec for AppLinkQueueBytes {
    type Value = Quota;
    const LIMIT: &'static str = "APP_LINK_QUEUE_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::APP_LINK_QUEUE_BYTES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::APP_LINK_QUEUE_BYTES);
}

const _: LimitDomain = AppLinkQueueBytes::DOMAIN;

/// How `APP_LINK_QUEUE_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type AppLinkQueueBytesHeld = Limited<AppLinkQueueBytes, { AppLinkQueueBytes::HELD }>;

/// `EVENT_RING_SLOTS`: How many event records the node's event ring holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRingSlots;

impl LimitSpec for EventRingSlots {
    type Value = usize;
    const LIMIT: &'static str = "EVENT_RING_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = Some(caps::EVENT_RING_SLOTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 1073741823, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::EVENT_RING_SLOTS;
}

const _: LimitDomain = EventRingSlots::DOMAIN;

/// How `EVENT_RING_SLOTS` is held: in no byte when its domain is one value.
pub type EventRingSlotsHeld = Limited<EventRingSlots, { EventRingSlots::HELD }>;

/// `CLOCK_SOURCES`: How many clock sources an application can register with the node at
/// once, when the clock-source capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSources;

impl LimitSpec for ClockSources {
    type Value = Quota;
    const LIMIT: &'static str = "CLOCK_SOURCES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::CLOCK_SOURCES, false);
}

const _: LimitDomain = ClockSources::DOMAIN;

/// How `CLOCK_SOURCES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type ClockSourcesHeld = Limited<ClockSources, { ClockSources::HELD }>;

/// `E2E_SENDER_SLOTS`: How many senders one receiving judge of end-to-end protected frames
/// keeps a counter for, when the e2e-sender-demux capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E2eSenderSlots;

impl LimitSpec for E2eSenderSlots {
    type Value = Quota;
    const LIMIT: &'static str = "E2E_SENDER_SLOTS";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = fixed_capacity(caps::E2E_SENDER_SLOTS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::E2E_SENDER_SLOTS);
}

const _: LimitDomain = E2eSenderSlots::DOMAIN;

/// How `E2E_SENDER_SLOTS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type E2eSenderSlotsHeld = Limited<E2eSenderSlots, { E2eSenderSlots::HELD }>;

/// `REPLAY_DEPTH_MAX`: The deepest replay a message may keep: how many of the frames it
/// last sent, as they were sent, a publisher holds for a subscriber that arrives later and
/// asks for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayDepthMax;

impl LimitSpec for ReplayDepthMax {
    type Value = Quota;
    const LIMIT: &'static str = "REPLAY_DEPTH_MAX";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::REPLAY_DEPTH_MAX);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::REPLAY_DEPTH_MAX);
}

const _: LimitDomain = ReplayDepthMax::DOMAIN;

/// How `REPLAY_DEPTH_MAX` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type ReplayDepthMaxHeld = Limited<ReplayDepthMax, { ReplayDepthMax::HELD }>;

/// `MESSAGE_CATALOG_ENTRIES`: How many messages one message catalog declares, when the
/// message-catalog capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageCatalogEntries;

impl LimitSpec for MessageCatalogEntries {
    type Value = Quota;
    const LIMIT: &'static str = "MESSAGE_CATALOG_ENTRIES";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = fixed_capacity(caps::MESSAGE_CATALOG_ENTRIES);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::MESSAGE_CATALOG_ENTRIES);
}

const _: LimitDomain = MessageCatalogEntries::DOMAIN;

/// How `MESSAGE_CATALOG_ENTRIES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type MessageCatalogEntriesHeld =
    Limited<MessageCatalogEntries, { MessageCatalogEntries::HELD }>;

/// `INSTANCE_KEY_FIELDS`: How many fields of a payload one message's instance key names,
/// when the instance-key capability is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceKeyFields;

impl LimitSpec for InstanceKeyFields {
    type Value = Quota;
    const LIMIT: &'static str = "INSTANCE_KEY_FIELDS";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = fixed_capacity(caps::INSTANCE_KEY_FIELDS);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::INSTANCE_KEY_FIELDS);
}

const _: LimitDomain = InstanceKeyFields::DOMAIN;

/// How `INSTANCE_KEY_FIELDS` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type InstanceKeyFieldsHeld = Limited<InstanceKeyFields, { InstanceKeyFields::HELD }>;

/// `INSTANCES_PER_MESSAGE`: How many instances one message's instance key may tell apart,
/// when the instance-key capability is on: the product of the lengths of the lists of
/// values its key fields may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstancesPerMessage;

impl LimitSpec for InstancesPerMessage {
    type Value = Quota;
    const LIMIT: &'static str = "INSTANCES_PER_MESSAGE";
    const DRIVEN: Option<Driven> = Some(Driven::Local);
    const READ_FROM_SNAPSHOT: bool = false;
    const CAPACITY: Option<usize> = fixed_capacity(caps::INSTANCES_PER_MESSAGE);
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::at_most(caps::INSTANCES_PER_MESSAGE);
}

const _: LimitDomain = InstancesPerMessage::DOMAIN;

/// How `INSTANCES_PER_MESSAGE` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type InstancesPerMessageHeld = Limited<InstancesPerMessage, { InstancesPerMessage::HELD }>;

/// `CLOCK_MAX_FORWARD_STEP_MS`: How far ahead of the node's clock, in milliseconds, a
/// timestamp from another node may be before the node's hybrid logical clock refuses it, as
/// zenoh's UHLC_MAX_DELTA_MS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockMaxForwardStepMs;

impl LimitSpec for ClockMaxForwardStepMs {
    type Value = usize;
    const LIMIT: &'static str = "CLOCK_MAX_FORWARD_STEP_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::CLOCK_MAX_FORWARD_STEP_MS;
}

const _: LimitDomain = ClockMaxForwardStepMs::DOMAIN;

/// How `CLOCK_MAX_FORWARD_STEP_MS` is held: in no byte when its domain is one value.
pub type ClockMaxForwardStepMsHeld =
    Limited<ClockMaxForwardStepMs, { ClockMaxForwardStepMs::HELD }>;

/// `DECLARATION_SYNC_BURST_MESSAGES`: How many declarations one turn of a paced declaration
/// replay sends, when the declaration-sync-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncBurstMessages;

impl LimitSpec for DeclarationSyncBurstMessages {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_BURST_MESSAGES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_BURST_MESSAGES;
}

const _: LimitDomain = DeclarationSyncBurstMessages::DOMAIN;

/// How `DECLARATION_SYNC_BURST_MESSAGES` is held: in no byte when its domain is one value.
pub type DeclarationSyncBurstMessagesHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_FINAL_TIMEOUT_MS;
}

const _: LimitDomain = DeclarationSyncFinalTimeoutMs::DOMAIN;

/// How `DECLARATION_SYNC_FINAL_TIMEOUT_MS` is held: in no byte when its domain is one value.
pub type DeclarationSyncFinalTimeoutMsHeld =
    Limited<DeclarationSyncFinalTimeoutMs, { DeclarationSyncFinalTimeoutMs::HELD }>;

/// `DECLARATION_SYNC_INTERVAL_MS`: How long, in milliseconds, a paced declaration replay
/// waits between two of its turns, when the declaration-sync-pacing policy is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclarationSyncIntervalMs;

impl LimitSpec for DeclarationSyncIntervalMs {
    type Value = usize;
    const LIMIT: &'static str = "DECLARATION_SYNC_INTERVAL_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_INTERVAL_MS;
}

const _: LimitDomain = DeclarationSyncIntervalMs::DOMAIN;

/// How `DECLARATION_SYNC_INTERVAL_MS` is held: in no byte when its domain is one value.
pub type DeclarationSyncIntervalMsHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_RX_NO_PROGRESS_MS;
}

const _: LimitDomain = DeclarationSyncRxNoProgressMs::DOMAIN;

/// How `DECLARATION_SYNC_RX_NO_PROGRESS_MS` is held: in no byte when its domain is one value.
pub type DeclarationSyncRxNoProgressMsHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_RETRY_INTERVAL_MS;
}

const _: LimitDomain = DeclarationSyncRetryIntervalMs::DOMAIN;

/// How `DECLARATION_SYNC_RETRY_INTERVAL_MS` is held: in no byte when its domain is one value.
pub type DeclarationSyncRetryIntervalMsHeld =
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
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS;
}

const _: LimitDomain = DeclarationSyncTxNoProgressMs::DOMAIN;

/// How `DECLARATION_SYNC_TX_NO_PROGRESS_MS` is held: in no byte when its domain is one value.
pub type DeclarationSyncTxNoProgressMsHeld =
    Limited<DeclarationSyncTxNoProgressMs, { DeclarationSyncTxNoProgressMs::HELD }>;

/// `HANDED_LEG_BYTES`: How many bytes a session holds of the droppable publishes it owes
/// its other faces when a publish finds the session held by a send that waits on one face:
/// the publish is dropped on that face and kept, in room the session took at open, until
/// whoever holds the session next sends it to the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandedLegBytes;

impl LimitSpec for HandedLegBytes {
    type Value = usize;
    const LIMIT: &'static str = "HANDED_LEG_BYTES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::HANDED_LEG_BYTES);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::HANDED_LEG_BYTES;
}

const _: LimitDomain = HandedLegBytes::DOMAIN;

/// How `HANDED_LEG_BYTES` is held: in no byte when its domain is one value.
pub type HandedLegBytesHeld = Limited<HandedLegBytes, { HandedLegBytes::HELD }>;

/// `UDP_PORT_SLOTS`: How many datagrams the udp ports a session listens on hold at once,
/// read off their sockets and waiting for the links of their peers to take them, in slots
/// of the batch the session advertises that it reserves when it opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPortSlots;

impl LimitSpec for UdpPortSlots {
    type Value = usize;
    const LIMIT: &'static str = "UDP_PORT_SLOTS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::UDP_PORT_SLOTS);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::UDP_PORT_SLOTS;
}

const _: LimitDomain = UdpPortSlots::DOMAIN;

/// How `UDP_PORT_SLOTS` is held: in no byte when its domain is one value.
pub type UdpPortSlotsHeld = Limited<UdpPortSlots, { UdpPortSlots::HELD }>;

/// `PICO_UNICAST_BATCH_BYTES`: The batch size, in bytes, a session of the zenoh-pico
/// interface advertises when it opens a unicast session, as zenoh-pico's
/// BATCH_UNICAST_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoUnicastBatchBytes;

impl LimitSpec for PicoUnicastBatchBytes {
    type Value = usize;
    const LIMIT: &'static str = "PICO_UNICAST_BATCH_BYTES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = lent_capacity(caps::PICO_UNICAST_BATCH_BYTES);
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 65535, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_UNICAST_BATCH_BYTES;
}

const _: LimitDomain = PicoUnicastBatchBytes::DOMAIN;

/// How `PICO_UNICAST_BATCH_BYTES` is held: in no byte when its domain is one value.
pub type PicoUnicastBatchBytesHeld =
    Limited<PicoUnicastBatchBytes, { PicoUnicastBatchBytes::HELD }>;

/// `PICO_MULTICAST_BATCH_BYTES`: The batch size, in bytes, a session of the zenoh-pico
/// interface advertises in the Join of a multicast group, as zenoh-pico's
/// BATCH_MULTICAST_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoMulticastBatchBytes;

impl LimitSpec for PicoMulticastBatchBytes {
    type Value = usize;
    const LIMIT: &'static str = "PICO_MULTICAST_BATCH_BYTES";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 65535, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_MULTICAST_BATCH_BYTES;
}

const _: LimitDomain = PicoMulticastBatchBytes::DOMAIN;

/// How `PICO_MULTICAST_BATCH_BYTES` is held: in no byte when its domain is one value.
pub type PicoMulticastBatchBytesHeld =
    Limited<PicoMulticastBatchBytes, { PicoMulticastBatchBytes::HELD }>;

/// `PICO_LEASE_MS`: The lease, in milliseconds, a session of the zenoh-pico interface
/// advertises, unicast and in a multicast group's Join, as zenoh-pico's Z_TRANSPORT_LEASE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoLeaseMs;

impl LimitSpec for PicoLeaseMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_LEASE_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_LEASE_MS;
}

const _: LimitDomain = PicoLeaseMs::DOMAIN;

/// How `PICO_LEASE_MS` is held: in no byte when its domain is one value.
pub type PicoLeaseMsHeld = Limited<PicoLeaseMs, { PicoLeaseMs::HELD }>;

/// `PICO_SOCKET_TIMEOUT_MS`: How long, in milliseconds, one read step of the cooperative
/// zenoh-pico session waits on its link before it returns with nothing, as zenoh-pico's
/// Z_CONFIG_SOCKET_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoSocketTimeoutMs;

impl LimitSpec for PicoSocketTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_SOCKET_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(0, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_SOCKET_TIMEOUT_MS;
}

const _: LimitDomain = PicoSocketTimeoutMs::DOMAIN;

/// How `PICO_SOCKET_TIMEOUT_MS` is held: in no byte when its domain is one value.
pub type PicoSocketTimeoutMsHeld = Limited<PicoSocketTimeoutMs, { PicoSocketTimeoutMs::HELD }>;

/// `PICO_CONNECT_TIMEOUT_MS`: How long, in milliseconds, each open of an endpoint by a
/// zenoh-pico session waits for the dial and the handshake before it fails, on either
/// engine, as zenoh-pico's Z_TRANSPORT_CONNECT_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoConnectTimeoutMs;

impl LimitSpec for PicoConnectTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_CONNECT_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_CONNECT_TIMEOUT_MS;
}

const _: LimitDomain = PicoConnectTimeoutMs::DOMAIN;

/// How `PICO_CONNECT_TIMEOUT_MS` is held: in no byte when its domain is one value.
pub type PicoConnectTimeoutMsHeld = Limited<PicoConnectTimeoutMs, { PicoConnectTimeoutMs::HELD }>;

/// `PICO_FRAG_MAX_BYTES`: The largest message, in bytes, a session of the zenoh-pico
/// interface rejoins from fragments, unicast and in a multicast group, as zenoh-pico's
/// FRAG_MAX_SIZE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoFragMaxBytes;

impl LimitSpec for PicoFragMaxBytes {
    type Value = Quota;
    const LIMIT: &'static str = "PICO_FRAG_MAX_BYTES";
    const DRIVEN: Option<Driven> = Some(Driven::Remote);
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain = LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: Quota = Quota::from_build(caps::PICO_FRAG_MAX_BYTES, false);
}

const _: LimitDomain = PicoFragMaxBytes::DOMAIN;

/// How `PICO_FRAG_MAX_BYTES` is held: in no byte when its domain is one value.
/// A table the bound limits keeps it so, and asks it [`Limited::admits`].
pub type PicoFragMaxBytesHeld = Limited<PicoFragMaxBytes, { PicoFragMaxBytes::HELD }>;

/// `PICO_ACCEPT_TIMEOUT_MS`: How long, in milliseconds, a listening session of the
/// zenoh-pico interface gives an inbound link to complete its whole handshake, link
/// handshake included, before it drops the link without a word, as zenoh-pico's
/// Z_TRANSPORT_ACCEPT_TIMEOUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoAcceptTimeoutMs;

impl LimitSpec for PicoAcceptTimeoutMs {
    type Value = usize;
    const LIMIT: &'static str = "PICO_ACCEPT_TIMEOUT_MS";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_ACCEPT_TIMEOUT_MS;
}

const _: LimitDomain = PicoAcceptTimeoutMs::DOMAIN;

/// How `PICO_ACCEPT_TIMEOUT_MS` is held: in no byte when its domain is one value.
pub type PicoAcceptTimeoutMsHeld = Limited<PicoAcceptTimeoutMs, { PicoAcceptTimeoutMs::HELD }>;

/// `PICO_KEEPALIVES_PER_LEASE`: How many keepalives a session of the zenoh-pico interface
/// sends in one lease, as zenoh-pico's Z_TRANSPORT_LEASE_EXPIRE_FACTOR: whenever the line
/// has been idle for the adopted lease divided by this, the session sends one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicoKeepalivesPerLease;

impl LimitSpec for PicoKeepalivesPerLease {
    type Value = usize;
    const LIMIT: &'static str = "PICO_KEEPALIVES_PER_LEASE";
    const DRIVEN: Option<Driven> = None;
    const READ_FROM_SNAPSHOT: bool = true;
    const CAPACITY: Option<usize> = None;
    const DOMAIN: LimitDomain =
        LimitDomain::of_parameter(1, 4294967295, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY);
    const DEFAULT: usize = caps::PICO_KEEPALIVES_PER_LEASE;
}

const _: LimitDomain = PicoKeepalivesPerLease::DOMAIN;

/// How `PICO_KEEPALIVES_PER_LEASE` is held: in no byte when its domain is one value.
pub type PicoKeepalivesPerLeaseHeld =
    Limited<PicoKeepalivesPerLease, { PicoKeepalivesPerLease::HELD }>;

/// The value of every limit a session holds, as one snapshot: what a creator resolved and
/// hands the machines of its scope. A machine reads a limit through the accessor of its
/// field, never from the build. Each value lies inside the build's domain of its limit, and
/// a limit whose domain is one value reads as that value whatever was selected
/// ([`Limited::get`]).
///
/// The values lie in one array of words, a word for each limit whose domain is more than
/// one value ([`LimitField::WORD`]) and none for the rest, so two snapshots compare as one
/// slice.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(transparent)]
pub struct SessionLimits {
    words: [usize; SESSION_LIMIT_WORDS],
}

/// How many words [`SessionLimits`] keeps its values in.
const SESSION_LIMIT_WORDS: usize = word_after::<PicoKeepalivesPerLease, SessionLimits>();

impl SessionLimits {
    /// The build defaults: each limit's value as the build states it ([`LimitSpec::DEFAULT`]).
    pub const fn from_build() -> Self {
        let mut limits = Self {
            words: [0; SESSION_LIMIT_WORDS],
        };
        limits.keep(&MaxKeyexprBytesHeld::build_default());
        limits.keep(&KeyArenaBytesHeld::build_default());
        limits.keep(&MaxSubscriptionsHeld::build_default());
        limits.keep(&MatchMemoSlotsHeld::build_default());
        limits.keep(&DeliveryLaneEventsHeld::build_default());
        limits.keep(&DeliveryLaneBytesHeld::build_default());
        limits.keep(&DeliveryLaneCallbacksHeld::build_default());
        limits.keep(&MaxQueryablesHeld::build_default());
        limits.keep(&MaxPendingQueriesHeld::build_default());
        limits.keep(&LinkNotedRequestsHeld::build_default());
        limits.keep(&MaxDeclObserversHeld::build_default());
        limits.keep(&MaxLivelinessSubscriptionsHeld::build_default());
        limits.keep(&MaxLocalTokensHeld::build_default());
        limits.keep(&MaxPublishersHeld::build_default());
        limits.keep(&MaxQueriersHeld::build_default());
        limits.keep(&MaxMatchingListenersHeld::build_default());
        limits.keep(&MaxDeclWatchesHeld::build_default());
        limits.keep(&MaxTransportEventsListenersHeld::build_default());
        limits.keep(&MaxLinkEventsListenersHeld::build_default());
        limits.keep(&MaxDeclaredKeyexprsHeld::build_default());
        limits.keep(&MaxPendingLivelinessGetsHeld::build_default());
        limits.keep(&MaxPendingDeclaresHeld::build_default());
        limits.keep(&MaxInboundSubInterestsHeld::build_default());
        limits.keep(&MaxPeerKeyexprAliasesHeld::build_default());
        limits.keep(&MaxSharedKeyIdsHeld::build_default());
        limits.keep(&MaxRemoteDeclsHeld::build_default());
        limits.keep(&MaxPendingRepliesHeld::build_default());
        limits.keep(&MaxPendingFinalsHeld::build_default());
        limits.keep(&MaxReplyPayloadBytesHeld::build_default());
        limits.keep(&MaxMulticastRepliesHeld::build_default());
        limits.keep(&GroupReadsPerMoveHeld::build_default());
        limits.keep(&MaxAdvancedPublishersHeld::build_default());
        limits.keep(&MaxAdvancedSubscribersHeld::build_default());
        limits.keep(&MaxFacesHeld::build_default());
        limits.keep(&MaxAcceptPendingHeld::build_default());
        limits.keep(&RxPoolBuffersHeld::build_default());
        limits.keep(&TxPoolSlotsHeld::build_default());
        limits.keep(&SessionMaxPeerKeyexprAliasesHeld::build_default());
        limits.keep(&SessionMaxRemoteDeclsHeld::build_default());
        limits.keep(&SessionMaxInboundSubInterestsHeld::build_default());
        limits.keep(&QuerierMaxPendingQueriesHeld::build_default());
        limits.keep(&TxNoProgressWindowUsHeld::build_default());
        limits.keep(&TxExpiryCloseAfterHeld::build_default());
        limits.keep(&DatagramFragmentBurstHeld::build_default());
        limits.keep(&DatagramFragmentGapUsHeld::build_default());
        limits.keep(&QueryParametersMaxBytesHeld::build_default());
        limits.keep(&QueryAttachmentMaxBytesHeld::build_default());
        limits.keep(&PicoTxQueueSizeHeld::build_default());
        limits.keep(&AppLinkQueueBytesHeld::build_default());
        limits.keep(&E2eSenderSlotsHeld::build_default());
        limits.keep(&ReplayDepthMaxHeld::build_default());
        limits.keep(&InstanceKeyFieldsHeld::build_default());
        limits.keep(&InstancesPerMessageHeld::build_default());
        limits.keep(&DeclarationSyncBurstMessagesHeld::build_default());
        limits.keep(&DeclarationSyncFinalTimeoutMsHeld::build_default());
        limits.keep(&DeclarationSyncIntervalMsHeld::build_default());
        limits.keep(&DeclarationSyncRxNoProgressMsHeld::build_default());
        limits.keep(&DeclarationSyncRetryIntervalMsHeld::build_default());
        limits.keep(&DeclarationSyncTxNoProgressMsHeld::build_default());
        limits.keep(&HandedLegBytesHeld::build_default());
        limits.keep(&UdpPortSlotsHeld::build_default());
        limits.keep(&PicoUnicastBatchBytesHeld::build_default());
        limits.keep(&PicoMulticastBatchBytesHeld::build_default());
        limits.keep(&PicoLeaseMsHeld::build_default());
        limits.keep(&PicoSocketTimeoutMsHeld::build_default());
        limits.keep(&PicoConnectTimeoutMsHeld::build_default());
        limits.keep(&PicoFragMaxBytesHeld::build_default());
        limits.keep(&PicoAcceptTimeoutMsHeld::build_default());
        limits.keep(&PicoKeepalivesPerLeaseHeld::build_default());
        limits
    }

    /// The build defaults, evaluated when the build is compiled: one value every creator
    /// copies, so no caller carries a store per field of its own.
    pub const BUILD: Self = Self::from_build();

    /// The build defaults ([`Self::BUILD`]): the snapshot a creator starts from. A machine
    /// does not call it; it reads the snapshot its creator handed it.
    pub const fn defaults() -> Self {
        Self::BUILD
    }

    /// The pico preset: each limit `[limit.pico_open]` states at its open value, each other
    /// limit `[limit.pico_preset]` states at the preset's value, where the build's domain holds
    /// it, and the rest at the build's. What an ABI that follows zenoh-pico opens a session
    /// under before its config states otherwise; laid out when the build is compiled, from the
    /// declaration and not from the build's environment.
    pub const PICO_PRESET: Self = {
        let mut limits = Self::BUILD;
        limits.keep(&KeyArenaBytesHeld::preset_or_build(
            4320,
            LimitValue::Integer(4320),
        ));
        limits.keep(&MaxSubscriptionsHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&DeliveryLaneBytesHeld::preset_or_build(
            4768,
            LimitValue::Integer(4768),
        ));
        limits.keep(&DeliveryLaneCallbacksHeld::preset_or_build(
            Quota::at_most(64),
            LimitValue::Integer(64),
        ));
        limits.keep(&MaxQueryablesHeld::preset_or_build(
            Quota::at_most(2),
            LimitValue::Integer(2),
        ));
        limits.keep(&MaxPendingQueriesHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxLivelinessSubscriptionsHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxLocalTokensHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxPublishersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxQueriersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxMatchingListenersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxTransportEventsListenersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxLinkEventsListenersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxDeclaredKeyexprsHeld::preset_or_build(
            Quota::at_most(2),
            LimitValue::Integer(2),
        ));
        limits.keep(&MaxPendingLivelinessGetsHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxPendingRepliesHeld::preset_or_build(
            Quota::at_most(2),
            LimitValue::Integer(2),
        ));
        limits.keep(&MaxPendingFinalsHeld::preset_or_build(
            Quota::at_most(2),
            LimitValue::Integer(2),
        ));
        limits.keep(&MaxAdvancedPublishersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxAdvancedSubscribersHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&MaxFacesHeld::preset_or_build(
            Quota::at_most(10),
            LimitValue::Integer(10),
        ));
        limits.keep(&MaxAcceptPendingHeld::preset_or_build(
            Quota::at_most(1),
            LimitValue::Integer(1),
        ));
        limits.keep(&RxPoolBuffersHeld::preset_or_build(
            2,
            LimitValue::Integer(2),
        ));
        limits.keep(&TxPoolSlotsHeld::preset_or_build(2, LimitValue::Integer(2)));
        limits.keep(&SessionMaxPeerKeyexprAliasesHeld::preset_or_build(
            Quota::at_most(32),
            LimitValue::Integer(32),
        ));
        limits.keep(&SessionMaxRemoteDeclsHeld::preset_or_build(
            Quota::at_most(32),
            LimitValue::Integer(32),
        ));
        limits.keep(&SessionMaxInboundSubInterestsHeld::preset_or_build(
            Quota::at_most(16),
            LimitValue::Integer(16),
        ));
        limits.keep(&AppLinkQueueBytesHeld::preset_or_build(
            Quota::at_most(2050),
            LimitValue::Integer(2050),
        ));
        limits.keep(&UdpPortSlotsHeld::preset_or_build(
            10,
            LimitValue::Integer(10),
        ));
        limits
    };

    /// The limit `L` as the snapshot's words keep it ([`LimitField::WORD`]).
    const fn limit<L: LimitField<Self>, const HELD: usize>(&self) -> Limited<L, HELD> {
        Limited::in_words(&self.words, L::WORD)
    }

    /// Keeps `held` in the snapshot's words, in the word of its limit.
    const fn keep<L: LimitField<Self>, const HELD: usize>(&mut self, held: &Limited<L, HELD>) {
        held.keep_in(&mut self.words, L::WORD);
    }

    /// `MAX_KEYEXPR_BYTES` as this snapshot holds it.
    pub const fn max_keyexpr_bytes(&self) -> Quota {
        self.max_keyexpr_bytes_held().get()
    }

    /// `MAX_KEYEXPR_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_keyexpr_bytes_held(&self) -> MaxKeyexprBytesHeld {
        self.limit()
    }

    /// Selects `MAX_KEYEXPR_BYTES`, when the build's domain holds `value`.
    pub fn select_max_keyexpr_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxKeyexprBytesHeld::select(value)?);
        Ok(())
    }

    /// `KEY_ARENA_BYTES` as this snapshot holds it.
    pub const fn key_arena_bytes(&self) -> usize {
        self.key_arena_bytes_held().get()
    }

    /// `KEY_ARENA_BYTES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn key_arena_bytes_held(&self) -> KeyArenaBytesHeld {
        self.limit()
    }

    /// Selects `KEY_ARENA_BYTES`, when the build's domain holds `value`.
    pub fn select_key_arena_bytes(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&KeyArenaBytesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_SUBSCRIPTIONS` as this snapshot holds it.
    pub const fn max_subscriptions(&self) -> Quota {
        self.max_subscriptions_held().get()
    }

    /// `MAX_SUBSCRIPTIONS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_subscriptions_held(&self) -> MaxSubscriptionsHeld {
        self.limit()
    }

    /// Selects `MAX_SUBSCRIPTIONS`, when the build's domain holds `value`.
    pub fn select_max_subscriptions(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxSubscriptionsHeld::select(value)?);
        Ok(())
    }

    /// `MATCH_MEMO_SLOTS` as this snapshot holds it.
    pub const fn match_memo_slots(&self) -> usize {
        self.match_memo_slots_held().get()
    }

    /// `MATCH_MEMO_SLOTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn match_memo_slots_held(&self) -> MatchMemoSlotsHeld {
        self.limit()
    }

    /// Selects `MATCH_MEMO_SLOTS`, when the build's domain holds `value`.
    pub fn select_match_memo_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&MatchMemoSlotsHeld::select(value)?);
        Ok(())
    }

    /// `DELIVERY_LANE_EVENTS` as this snapshot holds it.
    pub const fn delivery_lane_events(&self) -> Quota {
        self.delivery_lane_events_held().get()
    }

    /// `DELIVERY_LANE_EVENTS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn delivery_lane_events_held(&self) -> DeliveryLaneEventsHeld {
        self.limit()
    }

    /// Selects `DELIVERY_LANE_EVENTS`, when the build's domain holds `value`.
    pub fn select_delivery_lane_events(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeliveryLaneEventsHeld::select(value)?);
        Ok(())
    }

    /// `DELIVERY_LANE_BYTES` as this snapshot holds it.
    pub const fn delivery_lane_bytes(&self) -> usize {
        self.delivery_lane_bytes_held().get()
    }

    /// `DELIVERY_LANE_BYTES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn delivery_lane_bytes_held(&self) -> DeliveryLaneBytesHeld {
        self.limit()
    }

    /// Selects `DELIVERY_LANE_BYTES`, when the build's domain holds `value`.
    pub fn select_delivery_lane_bytes(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeliveryLaneBytesHeld::select(value)?);
        Ok(())
    }

    /// `DELIVERY_LANE_CALLBACKS` as this snapshot holds it.
    pub const fn delivery_lane_callbacks(&self) -> Quota {
        self.delivery_lane_callbacks_held().get()
    }

    /// `DELIVERY_LANE_CALLBACKS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn delivery_lane_callbacks_held(&self) -> DeliveryLaneCallbacksHeld {
        self.limit()
    }

    /// Selects `DELIVERY_LANE_CALLBACKS`, when the build's domain holds `value`.
    pub fn select_delivery_lane_callbacks(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeliveryLaneCallbacksHeld::select(value)?);
        Ok(())
    }

    /// `MAX_QUERYABLES` as this snapshot holds it.
    pub const fn max_queryables(&self) -> Quota {
        self.max_queryables_held().get()
    }

    /// `MAX_QUERYABLES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_queryables_held(&self) -> MaxQueryablesHeld {
        self.limit()
    }

    /// Selects `MAX_QUERYABLES`, when the build's domain holds `value`.
    pub fn select_max_queryables(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxQueryablesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PENDING_QUERIES` as this snapshot holds it.
    pub const fn max_pending_queries(&self) -> Quota {
        self.max_pending_queries_held().get()
    }

    /// `MAX_PENDING_QUERIES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_pending_queries_held(&self) -> MaxPendingQueriesHeld {
        self.limit()
    }

    /// Selects `MAX_PENDING_QUERIES`, when the build's domain holds `value`.
    pub fn select_max_pending_queries(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPendingQueriesHeld::select(value)?);
        Ok(())
    }

    /// `LINK_NOTED_REQUESTS` as this snapshot holds it.
    pub const fn link_noted_requests(&self) -> usize {
        self.link_noted_requests_held().get()
    }

    /// `LINK_NOTED_REQUESTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn link_noted_requests_held(&self) -> LinkNotedRequestsHeld {
        self.limit()
    }

    /// Selects `LINK_NOTED_REQUESTS`, when the build's domain holds `value`.
    pub fn select_link_noted_requests(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&LinkNotedRequestsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_DECL_OBSERVERS` as this snapshot holds it.
    pub const fn max_decl_observers(&self) -> Quota {
        self.max_decl_observers_held().get()
    }

    /// `MAX_DECL_OBSERVERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_decl_observers_held(&self) -> MaxDeclObserversHeld {
        self.limit()
    }

    /// Selects `MAX_DECL_OBSERVERS`, when the build's domain holds `value`.
    pub fn select_max_decl_observers(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxDeclObserversHeld::select(value)?);
        Ok(())
    }

    /// `MAX_LIVELINESS_SUBSCRIPTIONS` as this snapshot holds it.
    pub const fn max_liveliness_subscriptions(&self) -> Quota {
        self.max_liveliness_subscriptions_held().get()
    }

    /// `MAX_LIVELINESS_SUBSCRIPTIONS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_liveliness_subscriptions_held(&self) -> MaxLivelinessSubscriptionsHeld {
        self.limit()
    }

    /// Selects `MAX_LIVELINESS_SUBSCRIPTIONS`, when the build's domain holds `value`.
    pub fn select_max_liveliness_subscriptions(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxLivelinessSubscriptionsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_LOCAL_TOKENS` as this snapshot holds it.
    pub const fn max_local_tokens(&self) -> Quota {
        self.max_local_tokens_held().get()
    }

    /// `MAX_LOCAL_TOKENS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_local_tokens_held(&self) -> MaxLocalTokensHeld {
        self.limit()
    }

    /// Selects `MAX_LOCAL_TOKENS`, when the build's domain holds `value`.
    pub fn select_max_local_tokens(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxLocalTokensHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PUBLISHERS` as this snapshot holds it.
    pub const fn max_publishers(&self) -> Quota {
        self.max_publishers_held().get()
    }

    /// `MAX_PUBLISHERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_publishers_held(&self) -> MaxPublishersHeld {
        self.limit()
    }

    /// Selects `MAX_PUBLISHERS`, when the build's domain holds `value`.
    pub fn select_max_publishers(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPublishersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_QUERIERS` as this snapshot holds it.
    pub const fn max_queriers(&self) -> Quota {
        self.max_queriers_held().get()
    }

    /// `MAX_QUERIERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_queriers_held(&self) -> MaxQueriersHeld {
        self.limit()
    }

    /// Selects `MAX_QUERIERS`, when the build's domain holds `value`.
    pub fn select_max_queriers(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxQueriersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_MATCHING_LISTENERS` as this snapshot holds it.
    pub const fn max_matching_listeners(&self) -> Quota {
        self.max_matching_listeners_held().get()
    }

    /// `MAX_MATCHING_LISTENERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_matching_listeners_held(&self) -> MaxMatchingListenersHeld {
        self.limit()
    }

    /// Selects `MAX_MATCHING_LISTENERS`, when the build's domain holds `value`.
    pub fn select_max_matching_listeners(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxMatchingListenersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_DECL_WATCHES` as this snapshot holds it.
    pub const fn max_decl_watches(&self) -> Quota {
        self.max_decl_watches_held().get()
    }

    /// `MAX_DECL_WATCHES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_decl_watches_held(&self) -> MaxDeclWatchesHeld {
        self.limit()
    }

    /// Selects `MAX_DECL_WATCHES`, when the build's domain holds `value`.
    pub fn select_max_decl_watches(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxDeclWatchesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_TRANSPORT_EVENTS_LISTENERS` as this snapshot holds it.
    pub const fn max_transport_events_listeners(&self) -> Quota {
        self.max_transport_events_listeners_held().get()
    }

    /// `MAX_TRANSPORT_EVENTS_LISTENERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_transport_events_listeners_held(&self) -> MaxTransportEventsListenersHeld {
        self.limit()
    }

    /// Selects `MAX_TRANSPORT_EVENTS_LISTENERS`, when the build's domain holds `value`.
    pub fn select_max_transport_events_listeners(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxTransportEventsListenersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_LINK_EVENTS_LISTENERS` as this snapshot holds it.
    pub const fn max_link_events_listeners(&self) -> Quota {
        self.max_link_events_listeners_held().get()
    }

    /// `MAX_LINK_EVENTS_LISTENERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_link_events_listeners_held(&self) -> MaxLinkEventsListenersHeld {
        self.limit()
    }

    /// Selects `MAX_LINK_EVENTS_LISTENERS`, when the build's domain holds `value`.
    pub fn select_max_link_events_listeners(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxLinkEventsListenersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_DECLARED_KEYEXPRS` as this snapshot holds it.
    pub const fn max_declared_keyexprs(&self) -> Quota {
        self.max_declared_keyexprs_held().get()
    }

    /// `MAX_DECLARED_KEYEXPRS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_declared_keyexprs_held(&self) -> MaxDeclaredKeyexprsHeld {
        self.limit()
    }

    /// Selects `MAX_DECLARED_KEYEXPRS`, when the build's domain holds `value`.
    pub fn select_max_declared_keyexprs(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxDeclaredKeyexprsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PENDING_LIVELINESS_GETS` as this snapshot holds it.
    pub const fn max_pending_liveliness_gets(&self) -> Quota {
        self.max_pending_liveliness_gets_held().get()
    }

    /// `MAX_PENDING_LIVELINESS_GETS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_pending_liveliness_gets_held(&self) -> MaxPendingLivelinessGetsHeld {
        self.limit()
    }

    /// Selects `MAX_PENDING_LIVELINESS_GETS`, when the build's domain holds `value`.
    pub fn select_max_pending_liveliness_gets(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPendingLivelinessGetsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PENDING_DECLARES` as this snapshot holds it.
    pub const fn max_pending_declares(&self) -> Quota {
        self.max_pending_declares_held().get()
    }

    /// `MAX_PENDING_DECLARES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_pending_declares_held(&self) -> MaxPendingDeclaresHeld {
        self.limit()
    }

    /// Selects `MAX_PENDING_DECLARES`, when the build's domain holds `value`.
    pub fn select_max_pending_declares(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPendingDeclaresHeld::select(value)?);
        Ok(())
    }

    /// `MAX_INBOUND_SUB_INTERESTS` as this snapshot holds it.
    pub const fn max_inbound_sub_interests(&self) -> Quota {
        self.max_inbound_sub_interests_held().get()
    }

    /// `MAX_INBOUND_SUB_INTERESTS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_inbound_sub_interests_held(&self) -> MaxInboundSubInterestsHeld {
        self.limit()
    }

    /// Selects `MAX_INBOUND_SUB_INTERESTS`, when the build's domain holds `value`.
    pub fn select_max_inbound_sub_interests(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxInboundSubInterestsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PEER_KEYEXPR_ALIASES` as this snapshot holds it.
    pub const fn max_peer_keyexpr_aliases(&self) -> Quota {
        self.max_peer_keyexpr_aliases_held().get()
    }

    /// `MAX_PEER_KEYEXPR_ALIASES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_peer_keyexpr_aliases_held(&self) -> MaxPeerKeyexprAliasesHeld {
        self.limit()
    }

    /// Selects `MAX_PEER_KEYEXPR_ALIASES`, when the build's domain holds `value`.
    pub fn select_max_peer_keyexpr_aliases(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPeerKeyexprAliasesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_SHARED_KEY_IDS` as this snapshot holds it.
    pub const fn max_shared_key_ids(&self) -> Quota {
        self.max_shared_key_ids_held().get()
    }

    /// `MAX_SHARED_KEY_IDS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_shared_key_ids_held(&self) -> MaxSharedKeyIdsHeld {
        self.limit()
    }

    /// Selects `MAX_SHARED_KEY_IDS`, when the build's domain holds `value`.
    pub fn select_max_shared_key_ids(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxSharedKeyIdsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_REMOTE_DECLS` as this snapshot holds it.
    pub const fn max_remote_decls(&self) -> Quota {
        self.max_remote_decls_held().get()
    }

    /// `MAX_REMOTE_DECLS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_remote_decls_held(&self) -> MaxRemoteDeclsHeld {
        self.limit()
    }

    /// Selects `MAX_REMOTE_DECLS`, when the build's domain holds `value`.
    pub fn select_max_remote_decls(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxRemoteDeclsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PENDING_REPLIES` as this snapshot holds it.
    pub const fn max_pending_replies(&self) -> Quota {
        self.max_pending_replies_held().get()
    }

    /// `MAX_PENDING_REPLIES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_pending_replies_held(&self) -> MaxPendingRepliesHeld {
        self.limit()
    }

    /// Selects `MAX_PENDING_REPLIES`, when the build's domain holds `value`.
    pub fn select_max_pending_replies(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPendingRepliesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_PENDING_FINALS` as this snapshot holds it.
    pub const fn max_pending_finals(&self) -> Quota {
        self.max_pending_finals_held().get()
    }

    /// `MAX_PENDING_FINALS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_pending_finals_held(&self) -> MaxPendingFinalsHeld {
        self.limit()
    }

    /// Selects `MAX_PENDING_FINALS`, when the build's domain holds `value`.
    pub fn select_max_pending_finals(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxPendingFinalsHeld::select(value)?);
        Ok(())
    }

    /// `MAX_REPLY_PAYLOAD_BYTES` as this snapshot holds it.
    pub const fn max_reply_payload_bytes(&self) -> Quota {
        self.max_reply_payload_bytes_held().get()
    }

    /// `MAX_REPLY_PAYLOAD_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_reply_payload_bytes_held(&self) -> MaxReplyPayloadBytesHeld {
        self.limit()
    }

    /// Selects `MAX_REPLY_PAYLOAD_BYTES`, when the build's domain holds `value`.
    pub fn select_max_reply_payload_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxReplyPayloadBytesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_MULTICAST_REPLIES` as this snapshot holds it.
    pub const fn max_multicast_replies(&self) -> Quota {
        self.max_multicast_replies_held().get()
    }

    /// `MAX_MULTICAST_REPLIES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_multicast_replies_held(&self) -> MaxMulticastRepliesHeld {
        self.limit()
    }

    /// Selects `MAX_MULTICAST_REPLIES`, when the build's domain holds `value`.
    pub fn select_max_multicast_replies(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxMulticastRepliesHeld::select(value)?);
        Ok(())
    }

    /// `GROUP_READS_PER_MOVE` as this snapshot holds it.
    pub const fn group_reads_per_move(&self) -> usize {
        self.group_reads_per_move_held().get()
    }

    /// `GROUP_READS_PER_MOVE` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn group_reads_per_move_held(&self) -> GroupReadsPerMoveHeld {
        self.limit()
    }

    /// Selects `GROUP_READS_PER_MOVE`, when the build's domain holds `value`.
    pub fn select_group_reads_per_move(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&GroupReadsPerMoveHeld::select(value)?);
        Ok(())
    }

    /// `MAX_ADVANCED_PUBLISHERS` as this snapshot holds it.
    pub const fn max_advanced_publishers(&self) -> Quota {
        self.max_advanced_publishers_held().get()
    }

    /// `MAX_ADVANCED_PUBLISHERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_advanced_publishers_held(&self) -> MaxAdvancedPublishersHeld {
        self.limit()
    }

    /// Selects `MAX_ADVANCED_PUBLISHERS`, when the build's domain holds `value`.
    pub fn select_max_advanced_publishers(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxAdvancedPublishersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_ADVANCED_SUBSCRIBERS` as this snapshot holds it.
    pub const fn max_advanced_subscribers(&self) -> Quota {
        self.max_advanced_subscribers_held().get()
    }

    /// `MAX_ADVANCED_SUBSCRIBERS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_advanced_subscribers_held(&self) -> MaxAdvancedSubscribersHeld {
        self.limit()
    }

    /// Selects `MAX_ADVANCED_SUBSCRIBERS`, when the build's domain holds `value`.
    pub fn select_max_advanced_subscribers(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxAdvancedSubscribersHeld::select(value)?);
        Ok(())
    }

    /// `MAX_FACES` as this snapshot holds it.
    pub const fn max_faces(&self) -> Quota {
        self.max_faces_held().get()
    }

    /// `MAX_FACES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_faces_held(&self) -> MaxFacesHeld {
        self.limit()
    }

    /// Selects `MAX_FACES`, when the build's domain holds `value`.
    pub fn select_max_faces(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxFacesHeld::select(value)?);
        Ok(())
    }

    /// `MAX_ACCEPT_PENDING` as this snapshot holds it.
    pub const fn max_accept_pending(&self) -> Quota {
        self.max_accept_pending_held().get()
    }

    /// `MAX_ACCEPT_PENDING` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_accept_pending_held(&self) -> MaxAcceptPendingHeld {
        self.limit()
    }

    /// Selects `MAX_ACCEPT_PENDING`, when the build's domain holds `value`.
    pub fn select_max_accept_pending(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxAcceptPendingHeld::select(value)?);
        Ok(())
    }

    /// `RX_POOL_BUFFERS` as this snapshot holds it.
    pub const fn rx_pool_buffers(&self) -> usize {
        self.rx_pool_buffers_held().get()
    }

    /// `RX_POOL_BUFFERS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn rx_pool_buffers_held(&self) -> RxPoolBuffersHeld {
        self.limit()
    }

    /// Selects `RX_POOL_BUFFERS`, when the build's domain holds `value`.
    pub fn select_rx_pool_buffers(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&RxPoolBuffersHeld::select(value)?);
        Ok(())
    }

    /// `TX_POOL_SLOTS` as this snapshot holds it.
    pub const fn tx_pool_slots(&self) -> usize {
        self.tx_pool_slots_held().get()
    }

    /// `TX_POOL_SLOTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn tx_pool_slots_held(&self) -> TxPoolSlotsHeld {
        self.limit()
    }

    /// Selects `TX_POOL_SLOTS`, when the build's domain holds `value`.
    pub fn select_tx_pool_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&TxPoolSlotsHeld::select(value)?);
        Ok(())
    }

    /// `SESSION_MAX_PEER_KEYEXPR_ALIASES` as this snapshot holds it.
    pub const fn session_max_peer_keyexpr_aliases(&self) -> Quota {
        self.session_max_peer_keyexpr_aliases_held().get()
    }

    /// `SESSION_MAX_PEER_KEYEXPR_ALIASES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn session_max_peer_keyexpr_aliases_held(&self) -> SessionMaxPeerKeyexprAliasesHeld {
        self.limit()
    }

    /// Selects `SESSION_MAX_PEER_KEYEXPR_ALIASES`, when the build's domain holds `value`.
    pub fn select_session_max_peer_keyexpr_aliases(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&SessionMaxPeerKeyexprAliasesHeld::select(value)?);
        Ok(())
    }

    /// `SESSION_MAX_REMOTE_DECLS` as this snapshot holds it.
    pub const fn session_max_remote_decls(&self) -> Quota {
        self.session_max_remote_decls_held().get()
    }

    /// `SESSION_MAX_REMOTE_DECLS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn session_max_remote_decls_held(&self) -> SessionMaxRemoteDeclsHeld {
        self.limit()
    }

    /// Selects `SESSION_MAX_REMOTE_DECLS`, when the build's domain holds `value`.
    pub fn select_session_max_remote_decls(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&SessionMaxRemoteDeclsHeld::select(value)?);
        Ok(())
    }

    /// `SESSION_MAX_INBOUND_SUB_INTERESTS` as this snapshot holds it.
    pub const fn session_max_inbound_sub_interests(&self) -> Quota {
        self.session_max_inbound_sub_interests_held().get()
    }

    /// `SESSION_MAX_INBOUND_SUB_INTERESTS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn session_max_inbound_sub_interests_held(
        &self,
    ) -> SessionMaxInboundSubInterestsHeld {
        self.limit()
    }

    /// Selects `SESSION_MAX_INBOUND_SUB_INTERESTS`, when the build's domain holds `value`.
    pub fn select_session_max_inbound_sub_interests(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&SessionMaxInboundSubInterestsHeld::select(value)?);
        Ok(())
    }

    /// `QUERIER_MAX_PENDING_QUERIES` as this snapshot holds it.
    pub const fn querier_max_pending_queries(&self) -> Quota {
        self.querier_max_pending_queries_held().get()
    }

    /// `QUERIER_MAX_PENDING_QUERIES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn querier_max_pending_queries_held(&self) -> QuerierMaxPendingQueriesHeld {
        self.limit()
    }

    /// Selects `QUERIER_MAX_PENDING_QUERIES`, when the build's domain holds `value`.
    pub fn select_querier_max_pending_queries(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&QuerierMaxPendingQueriesHeld::select(value)?);
        Ok(())
    }

    /// `TX_NO_PROGRESS_WINDOW_US` as this snapshot holds it.
    pub const fn tx_no_progress_window_us(&self) -> usize {
        self.tx_no_progress_window_us_held().get()
    }

    /// `TX_NO_PROGRESS_WINDOW_US` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn tx_no_progress_window_us_held(&self) -> TxNoProgressWindowUsHeld {
        self.limit()
    }

    /// Selects `TX_NO_PROGRESS_WINDOW_US`, when the build's domain holds `value`.
    pub fn select_tx_no_progress_window_us(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&TxNoProgressWindowUsHeld::select(value)?);
        Ok(())
    }

    /// `TX_EXPIRY_CLOSE_AFTER` as this snapshot holds it.
    pub const fn tx_expiry_close_after(&self) -> Quota {
        self.tx_expiry_close_after_held().get()
    }

    /// `TX_EXPIRY_CLOSE_AFTER` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn tx_expiry_close_after_held(&self) -> TxExpiryCloseAfterHeld {
        self.limit()
    }

    /// Selects `TX_EXPIRY_CLOSE_AFTER`, when the build's domain holds `value`.
    pub fn select_tx_expiry_close_after(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&TxExpiryCloseAfterHeld::select(value)?);
        Ok(())
    }

    /// `DATAGRAM_FRAGMENT_BURST` as this snapshot holds it.
    pub const fn datagram_fragment_burst(&self) -> usize {
        self.datagram_fragment_burst_held().get()
    }

    /// `DATAGRAM_FRAGMENT_BURST` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn datagram_fragment_burst_held(&self) -> DatagramFragmentBurstHeld {
        self.limit()
    }

    /// Selects `DATAGRAM_FRAGMENT_BURST`, when the build's domain holds `value`.
    pub fn select_datagram_fragment_burst(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DatagramFragmentBurstHeld::select(value)?);
        Ok(())
    }

    /// `DATAGRAM_FRAGMENT_GAP_US` as this snapshot holds it.
    pub const fn datagram_fragment_gap_us(&self) -> usize {
        self.datagram_fragment_gap_us_held().get()
    }

    /// `DATAGRAM_FRAGMENT_GAP_US` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn datagram_fragment_gap_us_held(&self) -> DatagramFragmentGapUsHeld {
        self.limit()
    }

    /// Selects `DATAGRAM_FRAGMENT_GAP_US`, when the build's domain holds `value`.
    pub fn select_datagram_fragment_gap_us(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DatagramFragmentGapUsHeld::select(value)?);
        Ok(())
    }

    /// `QUERY_PARAMETERS_MAX_BYTES` as this snapshot holds it.
    pub const fn query_parameters_max_bytes(&self) -> Quota {
        self.query_parameters_max_bytes_held().get()
    }

    /// `QUERY_PARAMETERS_MAX_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn query_parameters_max_bytes_held(&self) -> QueryParametersMaxBytesHeld {
        self.limit()
    }

    /// Selects `QUERY_PARAMETERS_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_query_parameters_max_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&QueryParametersMaxBytesHeld::select(value)?);
        Ok(())
    }

    /// `QUERY_ATTACHMENT_MAX_BYTES` as this snapshot holds it.
    pub const fn query_attachment_max_bytes(&self) -> Quota {
        self.query_attachment_max_bytes_held().get()
    }

    /// `QUERY_ATTACHMENT_MAX_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn query_attachment_max_bytes_held(&self) -> QueryAttachmentMaxBytesHeld {
        self.limit()
    }

    /// Selects `QUERY_ATTACHMENT_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_query_attachment_max_bytes(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&QueryAttachmentMaxBytesHeld::select(value)?);
        Ok(())
    }

    /// `PICO_TX_QUEUE_SIZE` as this snapshot holds it.
    pub const fn pico_tx_queue_size(&self) -> usize {
        self.pico_tx_queue_size_held().get()
    }

    /// `PICO_TX_QUEUE_SIZE` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_tx_queue_size_held(&self) -> PicoTxQueueSizeHeld {
        self.limit()
    }

    /// Selects `PICO_TX_QUEUE_SIZE`, when the build's domain holds `value`.
    pub fn select_pico_tx_queue_size(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoTxQueueSizeHeld::select(value)?);
        Ok(())
    }

    /// `APP_LINK_QUEUE_BYTES` as this snapshot holds it.
    pub const fn app_link_queue_bytes(&self) -> Quota {
        self.app_link_queue_bytes_held().get()
    }

    /// `APP_LINK_QUEUE_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn app_link_queue_bytes_held(&self) -> AppLinkQueueBytesHeld {
        self.limit()
    }

    /// Selects `APP_LINK_QUEUE_BYTES`, when the build's domain holds `value`.
    pub fn select_app_link_queue_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&AppLinkQueueBytesHeld::select(value)?);
        Ok(())
    }

    /// `E2E_SENDER_SLOTS` as this snapshot holds it.
    pub const fn e2e_sender_slots(&self) -> Quota {
        self.e2e_sender_slots_held().get()
    }

    /// `E2E_SENDER_SLOTS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn e2e_sender_slots_held(&self) -> E2eSenderSlotsHeld {
        self.limit()
    }

    /// Selects `E2E_SENDER_SLOTS`, when the build's domain holds `value`.
    pub fn select_e2e_sender_slots(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&E2eSenderSlotsHeld::select(value)?);
        Ok(())
    }

    /// `REPLAY_DEPTH_MAX` as this snapshot holds it.
    pub const fn replay_depth_max(&self) -> Quota {
        self.replay_depth_max_held().get()
    }

    /// `REPLAY_DEPTH_MAX` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn replay_depth_max_held(&self) -> ReplayDepthMaxHeld {
        self.limit()
    }

    /// Selects `REPLAY_DEPTH_MAX`, when the build's domain holds `value`.
    pub fn select_replay_depth_max(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&ReplayDepthMaxHeld::select(value)?);
        Ok(())
    }

    /// `INSTANCE_KEY_FIELDS` as this snapshot holds it.
    pub const fn instance_key_fields(&self) -> Quota {
        self.instance_key_fields_held().get()
    }

    /// `INSTANCE_KEY_FIELDS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn instance_key_fields_held(&self) -> InstanceKeyFieldsHeld {
        self.limit()
    }

    /// Selects `INSTANCE_KEY_FIELDS`, when the build's domain holds `value`.
    pub fn select_instance_key_fields(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&InstanceKeyFieldsHeld::select(value)?);
        Ok(())
    }

    /// `INSTANCES_PER_MESSAGE` as this snapshot holds it.
    pub const fn instances_per_message(&self) -> Quota {
        self.instances_per_message_held().get()
    }

    /// `INSTANCES_PER_MESSAGE` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn instances_per_message_held(&self) -> InstancesPerMessageHeld {
        self.limit()
    }

    /// Selects `INSTANCES_PER_MESSAGE`, when the build's domain holds `value`.
    pub fn select_instances_per_message(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&InstancesPerMessageHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_BURST_MESSAGES` as this snapshot holds it.
    pub const fn declaration_sync_burst_messages(&self) -> usize {
        self.declaration_sync_burst_messages_held().get()
    }

    /// `DECLARATION_SYNC_BURST_MESSAGES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_burst_messages_held(&self) -> DeclarationSyncBurstMessagesHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_BURST_MESSAGES`, when the build's domain holds `value`.
    pub fn select_declaration_sync_burst_messages(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncBurstMessagesHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_FINAL_TIMEOUT_MS` as this snapshot holds it.
    pub const fn declaration_sync_final_timeout_ms(&self) -> usize {
        self.declaration_sync_final_timeout_ms_held().get()
    }

    /// `DECLARATION_SYNC_FINAL_TIMEOUT_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_final_timeout_ms_held(
        &self,
    ) -> DeclarationSyncFinalTimeoutMsHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_FINAL_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_final_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncFinalTimeoutMsHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_INTERVAL_MS` as this snapshot holds it.
    pub const fn declaration_sync_interval_ms(&self) -> usize {
        self.declaration_sync_interval_ms_held().get()
    }

    /// `DECLARATION_SYNC_INTERVAL_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_interval_ms_held(&self) -> DeclarationSyncIntervalMsHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_INTERVAL_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_interval_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncIntervalMsHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_RX_NO_PROGRESS_MS` as this snapshot holds it.
    pub const fn declaration_sync_rx_no_progress_ms(&self) -> usize {
        self.declaration_sync_rx_no_progress_ms_held().get()
    }

    /// `DECLARATION_SYNC_RX_NO_PROGRESS_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_rx_no_progress_ms_held(
        &self,
    ) -> DeclarationSyncRxNoProgressMsHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_RX_NO_PROGRESS_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_rx_no_progress_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncRxNoProgressMsHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` as this snapshot holds it.
    pub const fn declaration_sync_retry_interval_ms(&self) -> usize {
        self.declaration_sync_retry_interval_ms_held().get()
    }

    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_retry_interval_ms_held(
        &self,
    ) -> DeclarationSyncRetryIntervalMsHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_RETRY_INTERVAL_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_retry_interval_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncRetryIntervalMsHeld::select(value)?);
        Ok(())
    }

    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` as this snapshot holds it.
    pub const fn declaration_sync_tx_no_progress_ms(&self) -> usize {
        self.declaration_sync_tx_no_progress_ms_held().get()
    }

    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn declaration_sync_tx_no_progress_ms_held(
        &self,
    ) -> DeclarationSyncTxNoProgressMsHeld {
        self.limit()
    }

    /// Selects `DECLARATION_SYNC_TX_NO_PROGRESS_MS`, when the build's domain holds `value`.
    pub fn select_declaration_sync_tx_no_progress_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&DeclarationSyncTxNoProgressMsHeld::select(value)?);
        Ok(())
    }

    /// `HANDED_LEG_BYTES` as this snapshot holds it.
    pub const fn handed_leg_bytes(&self) -> usize {
        self.handed_leg_bytes_held().get()
    }

    /// `HANDED_LEG_BYTES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn handed_leg_bytes_held(&self) -> HandedLegBytesHeld {
        self.limit()
    }

    /// Selects `HANDED_LEG_BYTES`, when the build's domain holds `value`.
    pub fn select_handed_leg_bytes(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&HandedLegBytesHeld::select(value)?);
        Ok(())
    }

    /// `UDP_PORT_SLOTS` as this snapshot holds it.
    pub const fn udp_port_slots(&self) -> usize {
        self.udp_port_slots_held().get()
    }

    /// `UDP_PORT_SLOTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn udp_port_slots_held(&self) -> UdpPortSlotsHeld {
        self.limit()
    }

    /// Selects `UDP_PORT_SLOTS`, when the build's domain holds `value`.
    pub fn select_udp_port_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&UdpPortSlotsHeld::select(value)?);
        Ok(())
    }

    /// `PICO_UNICAST_BATCH_BYTES` as this snapshot holds it.
    pub const fn pico_unicast_batch_bytes(&self) -> usize {
        self.pico_unicast_batch_bytes_held().get()
    }

    /// `PICO_UNICAST_BATCH_BYTES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_unicast_batch_bytes_held(&self) -> PicoUnicastBatchBytesHeld {
        self.limit()
    }

    /// Selects `PICO_UNICAST_BATCH_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_unicast_batch_bytes(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoUnicastBatchBytesHeld::select(value)?);
        Ok(())
    }

    /// `PICO_MULTICAST_BATCH_BYTES` as this snapshot holds it.
    pub const fn pico_multicast_batch_bytes(&self) -> usize {
        self.pico_multicast_batch_bytes_held().get()
    }

    /// `PICO_MULTICAST_BATCH_BYTES` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_multicast_batch_bytes_held(&self) -> PicoMulticastBatchBytesHeld {
        self.limit()
    }

    /// Selects `PICO_MULTICAST_BATCH_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_multicast_batch_bytes(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoMulticastBatchBytesHeld::select(value)?);
        Ok(())
    }

    /// `PICO_LEASE_MS` as this snapshot holds it.
    pub const fn pico_lease_ms(&self) -> usize {
        self.pico_lease_ms_held().get()
    }

    /// `PICO_LEASE_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_lease_ms_held(&self) -> PicoLeaseMsHeld {
        self.limit()
    }

    /// Selects `PICO_LEASE_MS`, when the build's domain holds `value`.
    pub fn select_pico_lease_ms(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoLeaseMsHeld::select(value)?);
        Ok(())
    }

    /// `PICO_SOCKET_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_socket_timeout_ms(&self) -> usize {
        self.pico_socket_timeout_ms_held().get()
    }

    /// `PICO_SOCKET_TIMEOUT_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_socket_timeout_ms_held(&self) -> PicoSocketTimeoutMsHeld {
        self.limit()
    }

    /// Selects `PICO_SOCKET_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_socket_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoSocketTimeoutMsHeld::select(value)?);
        Ok(())
    }

    /// `PICO_CONNECT_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_connect_timeout_ms(&self) -> usize {
        self.pico_connect_timeout_ms_held().get()
    }

    /// `PICO_CONNECT_TIMEOUT_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_connect_timeout_ms_held(&self) -> PicoConnectTimeoutMsHeld {
        self.limit()
    }

    /// Selects `PICO_CONNECT_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_connect_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoConnectTimeoutMsHeld::select(value)?);
        Ok(())
    }

    /// `PICO_FRAG_MAX_BYTES` as this snapshot holds it.
    pub const fn pico_frag_max_bytes(&self) -> Quota {
        self.pico_frag_max_bytes_held().get()
    }

    /// `PICO_FRAG_MAX_BYTES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn pico_frag_max_bytes_held(&self) -> PicoFragMaxBytesHeld {
        self.limit()
    }

    /// Selects `PICO_FRAG_MAX_BYTES`, when the build's domain holds `value`.
    pub fn select_pico_frag_max_bytes(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoFragMaxBytesHeld::select(value)?);
        Ok(())
    }

    /// `PICO_ACCEPT_TIMEOUT_MS` as this snapshot holds it.
    pub const fn pico_accept_timeout_ms(&self) -> usize {
        self.pico_accept_timeout_ms_held().get()
    }

    /// `PICO_ACCEPT_TIMEOUT_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_accept_timeout_ms_held(&self) -> PicoAcceptTimeoutMsHeld {
        self.limit()
    }

    /// Selects `PICO_ACCEPT_TIMEOUT_MS`, when the build's domain holds `value`.
    pub fn select_pico_accept_timeout_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoAcceptTimeoutMsHeld::select(value)?);
        Ok(())
    }

    /// `PICO_KEEPALIVES_PER_LEASE` as this snapshot holds it.
    pub const fn pico_keepalives_per_lease(&self) -> usize {
        self.pico_keepalives_per_lease_held().get()
    }

    /// `PICO_KEEPALIVES_PER_LEASE` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn pico_keepalives_per_lease_held(&self) -> PicoKeepalivesPerLeaseHeld {
        self.limit()
    }

    /// Selects `PICO_KEEPALIVES_PER_LEASE`, when the build's domain holds `value`.
    pub fn select_pico_keepalives_per_lease(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&PicoKeepalivesPerLeaseHeld::select(value)?);
        Ok(())
    }
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self::BUILD
    }
}

impl core::fmt::Debug for SessionLimits {
    /// Each limit by its id, with the value the snapshot holds.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        LimitEntry::fmt_snapshot(&SESSION_LIMITS, "SessionLimits", self, f)
    }
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxKeyexprBytes {
    const WORD: usize = 0;
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for KeyArenaBytes {
    const WORD: usize = word_after::<MaxKeyexprBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxSubscriptions {
    const WORD: usize = word_after::<KeyArenaBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MatchMemoSlots {
    const WORD: usize = word_after::<MaxSubscriptions, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeliveryLaneEvents {
    const WORD: usize = word_after::<MatchMemoSlots, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeliveryLaneBytes {
    const WORD: usize = word_after::<DeliveryLaneEvents, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeliveryLaneCallbacks {
    const WORD: usize = word_after::<DeliveryLaneBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxQueryables {
    const WORD: usize = word_after::<DeliveryLaneCallbacks, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPendingQueries {
    const WORD: usize = word_after::<MaxQueryables, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for LinkNotedRequests {
    const WORD: usize = word_after::<MaxPendingQueries, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxDeclObservers {
    const WORD: usize = word_after::<LinkNotedRequests, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxLivelinessSubscriptions {
    const WORD: usize = word_after::<MaxDeclObservers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxLocalTokens {
    const WORD: usize = word_after::<MaxLivelinessSubscriptions, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPublishers {
    const WORD: usize = word_after::<MaxLocalTokens, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxQueriers {
    const WORD: usize = word_after::<MaxPublishers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxMatchingListeners {
    const WORD: usize = word_after::<MaxQueriers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxDeclWatches {
    const WORD: usize = word_after::<MaxMatchingListeners, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxTransportEventsListeners {
    const WORD: usize = word_after::<MaxDeclWatches, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxLinkEventsListeners {
    const WORD: usize = word_after::<MaxTransportEventsListeners, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxDeclaredKeyexprs {
    const WORD: usize = word_after::<MaxLinkEventsListeners, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPendingLivelinessGets {
    const WORD: usize = word_after::<MaxDeclaredKeyexprs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPendingDeclares {
    const WORD: usize = word_after::<MaxPendingLivelinessGets, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxInboundSubInterests {
    const WORD: usize = word_after::<MaxPendingDeclares, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPeerKeyexprAliases {
    const WORD: usize = word_after::<MaxInboundSubInterests, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxSharedKeyIds {
    const WORD: usize = word_after::<MaxPeerKeyexprAliases, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxRemoteDecls {
    const WORD: usize = word_after::<MaxSharedKeyIds, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPendingReplies {
    const WORD: usize = word_after::<MaxRemoteDecls, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxPendingFinals {
    const WORD: usize = word_after::<MaxPendingReplies, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxReplyPayloadBytes {
    const WORD: usize = word_after::<MaxPendingFinals, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxMulticastReplies {
    const WORD: usize = word_after::<MaxReplyPayloadBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for GroupReadsPerMove {
    const WORD: usize = word_after::<MaxMulticastReplies, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxAdvancedPublishers {
    const WORD: usize = word_after::<GroupReadsPerMove, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxAdvancedSubscribers {
    const WORD: usize = word_after::<MaxAdvancedPublishers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxFaces {
    const WORD: usize = word_after::<MaxAdvancedSubscribers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for MaxAcceptPending {
    const WORD: usize = word_after::<MaxFaces, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for RxPoolBuffers {
    const WORD: usize = word_after::<MaxAcceptPending, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for TxPoolSlots {
    const WORD: usize = word_after::<RxPoolBuffers, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for SessionMaxPeerKeyexprAliases {
    const WORD: usize = word_after::<TxPoolSlots, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for SessionMaxRemoteDecls {
    const WORD: usize = word_after::<SessionMaxPeerKeyexprAliases, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for SessionMaxInboundSubInterests {
    const WORD: usize = word_after::<SessionMaxRemoteDecls, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for QuerierMaxPendingQueries {
    const WORD: usize = word_after::<SessionMaxInboundSubInterests, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for TxNoProgressWindowUs {
    const WORD: usize = word_after::<QuerierMaxPendingQueries, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for TxExpiryCloseAfter {
    const WORD: usize = word_after::<TxNoProgressWindowUs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DatagramFragmentBurst {
    const WORD: usize = word_after::<TxExpiryCloseAfter, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DatagramFragmentGapUs {
    const WORD: usize = word_after::<DatagramFragmentBurst, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for QueryParametersMaxBytes {
    const WORD: usize = word_after::<DatagramFragmentGapUs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for QueryAttachmentMaxBytes {
    const WORD: usize = word_after::<QueryParametersMaxBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoTxQueueSize {
    const WORD: usize = word_after::<QueryAttachmentMaxBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for AppLinkQueueBytes {
    const WORD: usize = word_after::<PicoTxQueueSize, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for E2eSenderSlots {
    const WORD: usize = word_after::<AppLinkQueueBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for ReplayDepthMax {
    const WORD: usize = word_after::<E2eSenderSlots, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for InstanceKeyFields {
    const WORD: usize = word_after::<ReplayDepthMax, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for InstancesPerMessage {
    const WORD: usize = word_after::<InstanceKeyFields, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncBurstMessages {
    const WORD: usize = word_after::<InstancesPerMessage, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncFinalTimeoutMs {
    const WORD: usize = word_after::<DeclarationSyncBurstMessages, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncIntervalMs {
    const WORD: usize = word_after::<DeclarationSyncFinalTimeoutMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncRxNoProgressMs {
    const WORD: usize = word_after::<DeclarationSyncIntervalMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncRetryIntervalMs {
    const WORD: usize = word_after::<DeclarationSyncRxNoProgressMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for DeclarationSyncTxNoProgressMs {
    const WORD: usize = word_after::<DeclarationSyncRetryIntervalMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for HandedLegBytes {
    const WORD: usize = word_after::<DeclarationSyncTxNoProgressMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for UdpPortSlots {
    const WORD: usize = word_after::<HandedLegBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoUnicastBatchBytes {
    const WORD: usize = word_after::<UdpPortSlots, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoMulticastBatchBytes {
    const WORD: usize = word_after::<PicoUnicastBatchBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoLeaseMs {
    const WORD: usize = word_after::<PicoMulticastBatchBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoSocketTimeoutMs {
    const WORD: usize = word_after::<PicoLeaseMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoConnectTimeoutMs {
    const WORD: usize = word_after::<PicoSocketTimeoutMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoFragMaxBytes {
    const WORD: usize = word_after::<PicoConnectTimeoutMs, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoAcceptTimeoutMs {
    const WORD: usize = word_after::<PicoFragMaxBytes, SessionLimits>();
}

// SAFETY: `SessionLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `SESSION_LIMIT_WORDS`.
unsafe impl LimitField<SessionLimits> for PicoKeepalivesPerLease {
    const WORD: usize = word_after::<PicoAcceptTimeoutMs, SessionLimits>();
}

/// How many limits [`SessionLimits`] holds: the length of [`SESSION_LIMITS`].
pub const SESSION_LIMIT_COUNT: usize = 69;

/// Every limit of [`SessionLimits`] as a reader that names it by its id sees it, in the order of
/// its words.
pub static SESSION_LIMITS: [LimitEntry<SessionLimits>; SESSION_LIMIT_COUNT] = [
    LimitEntry::of::<MaxKeyexprBytes>(),
    LimitEntry::of::<KeyArenaBytes>(),
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
    LimitEntry::of::<MaxPublishers>(),
    LimitEntry::of::<MaxQueriers>(),
    LimitEntry::of::<MaxMatchingListeners>(),
    LimitEntry::of::<MaxDeclWatches>(),
    LimitEntry::of::<MaxTransportEventsListeners>(),
    LimitEntry::of::<MaxLinkEventsListeners>(),
    LimitEntry::of::<MaxDeclaredKeyexprs>(),
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
    LimitEntry::of::<GroupReadsPerMove>(),
    LimitEntry::of::<MaxAdvancedPublishers>(),
    LimitEntry::of::<MaxAdvancedSubscribers>(),
    LimitEntry::of::<MaxFaces>(),
    LimitEntry::of::<MaxAcceptPending>(),
    LimitEntry::of::<RxPoolBuffers>(),
    LimitEntry::of::<TxPoolSlots>(),
    LimitEntry::of::<SessionMaxPeerKeyexprAliases>(),
    LimitEntry::of::<SessionMaxRemoteDecls>(),
    LimitEntry::of::<SessionMaxInboundSubInterests>(),
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
    LimitEntry::of::<HandedLegBytes>(),
    LimitEntry::of::<UdpPortSlots>(),
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
///
/// The values lie in one array of words, a word for each limit whose domain is more than
/// one value ([`LimitField::WORD`]) and none for the rest, so two snapshots compare as one
/// slice.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(transparent)]
pub struct RuntimeLimits {
    words: [usize; RUNTIME_LIMIT_WORDS],
}

/// How many words [`RuntimeLimits`] keeps its values in.
const RUNTIME_LIMIT_WORDS: usize = word_after::<ClockMaxForwardStepMs, RuntimeLimits>();

impl RuntimeLimits {
    /// The build defaults: each limit's value as the build states it ([`LimitSpec::DEFAULT`]).
    pub const fn from_build() -> Self {
        let mut limits = Self {
            words: [0; RUNTIME_LIMIT_WORDS],
        };
        limits.keep(&MaxLocatorLenHeld::build_default());
        limits.keep(&MaxStaticConnectHeld::build_default());
        limits.keep(&SnapshotPeriodMsHeld::build_default());
        limits.keep(&SnapshotHistogramBucketsHeld::build_default());
        limits.keep(&SupervisionCheckpointsHeld::build_default());
        limits.keep(&E2eSupervisedStreamsHeld::build_default());
        limits.keep(&EventRingSlotsHeld::build_default());
        limits.keep(&ClockSourcesHeld::build_default());
        limits.keep(&MessageCatalogEntriesHeld::build_default());
        limits.keep(&ClockMaxForwardStepMsHeld::build_default());
        limits
    }

    /// The build defaults, evaluated when the build is compiled: one value every creator
    /// copies, so no caller carries a store per field of its own.
    pub const BUILD: Self = Self::from_build();

    /// The build defaults ([`Self::BUILD`]): the snapshot a creator starts from. A machine
    /// does not call it; it reads the snapshot its creator handed it.
    pub const fn defaults() -> Self {
        Self::BUILD
    }

    /// The limit `L` as the snapshot's words keep it ([`LimitField::WORD`]).
    const fn limit<L: LimitField<Self>, const HELD: usize>(&self) -> Limited<L, HELD> {
        Limited::in_words(&self.words, L::WORD)
    }

    /// Keeps `held` in the snapshot's words, in the word of its limit.
    const fn keep<L: LimitField<Self>, const HELD: usize>(&mut self, held: &Limited<L, HELD>) {
        held.keep_in(&mut self.words, L::WORD);
    }

    /// `MAX_LOCATOR_LEN` as this snapshot holds it.
    pub const fn max_locator_len(&self) -> Quota {
        self.max_locator_len_held().get()
    }

    /// `MAX_LOCATOR_LEN` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_locator_len_held(&self) -> MaxLocatorLenHeld {
        self.limit()
    }

    /// Selects `MAX_LOCATOR_LEN`, when the build's domain holds `value`.
    pub fn select_max_locator_len(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxLocatorLenHeld::select(value)?);
        Ok(())
    }

    /// `MAX_STATIC_CONNECT` as this snapshot holds it.
    pub const fn max_static_connect(&self) -> Quota {
        self.max_static_connect_held().get()
    }

    /// `MAX_STATIC_CONNECT` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn max_static_connect_held(&self) -> MaxStaticConnectHeld {
        self.limit()
    }

    /// Selects `MAX_STATIC_CONNECT`, when the build's domain holds `value`.
    pub fn select_max_static_connect(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&MaxStaticConnectHeld::select(value)?);
        Ok(())
    }

    /// `SNAPSHOT_PERIOD_MS` as this snapshot holds it.
    pub const fn snapshot_period_ms(&self) -> usize {
        self.snapshot_period_ms_held().get()
    }

    /// `SNAPSHOT_PERIOD_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn snapshot_period_ms_held(&self) -> SnapshotPeriodMsHeld {
        self.limit()
    }

    /// Selects `SNAPSHOT_PERIOD_MS`, when the build's domain holds `value`.
    pub fn select_snapshot_period_ms(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&SnapshotPeriodMsHeld::select(value)?);
        Ok(())
    }

    /// `SNAPSHOT_HISTOGRAM_BUCKETS` as this snapshot holds it.
    pub const fn snapshot_histogram_buckets(&self) -> usize {
        self.snapshot_histogram_buckets_held().get()
    }

    /// `SNAPSHOT_HISTOGRAM_BUCKETS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn snapshot_histogram_buckets_held(&self) -> SnapshotHistogramBucketsHeld {
        self.limit()
    }

    /// Selects `SNAPSHOT_HISTOGRAM_BUCKETS`, when the build's domain holds `value`.
    pub fn select_snapshot_histogram_buckets(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&SnapshotHistogramBucketsHeld::select(value)?);
        Ok(())
    }

    /// `SUPERVISION_CHECKPOINTS` as this snapshot holds it.
    pub const fn supervision_checkpoints(&self) -> usize {
        self.supervision_checkpoints_held().get()
    }

    /// `SUPERVISION_CHECKPOINTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn supervision_checkpoints_held(&self) -> SupervisionCheckpointsHeld {
        self.limit()
    }

    /// Selects `SUPERVISION_CHECKPOINTS`, when the build's domain holds `value`.
    pub fn select_supervision_checkpoints(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&SupervisionCheckpointsHeld::select(value)?);
        Ok(())
    }

    /// `E2E_SUPERVISED_STREAMS` as this snapshot holds it.
    pub const fn e2e_supervised_streams(&self) -> Quota {
        self.e2e_supervised_streams_held().get()
    }

    /// `E2E_SUPERVISED_STREAMS` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn e2e_supervised_streams_held(&self) -> E2eSupervisedStreamsHeld {
        self.limit()
    }

    /// Selects `E2E_SUPERVISED_STREAMS`, when the build's domain holds `value`.
    pub fn select_e2e_supervised_streams(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&E2eSupervisedStreamsHeld::select(value)?);
        Ok(())
    }

    /// `EVENT_RING_SLOTS` as this snapshot holds it.
    pub const fn event_ring_slots(&self) -> usize {
        self.event_ring_slots_held().get()
    }

    /// `EVENT_RING_SLOTS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn event_ring_slots_held(&self) -> EventRingSlotsHeld {
        self.limit()
    }

    /// Selects `EVENT_RING_SLOTS`, when the build's domain holds `value`.
    pub fn select_event_ring_slots(&mut self, value: usize) -> Result<(), OutsideLimitDomain> {
        self.keep(&EventRingSlotsHeld::select(value)?);
        Ok(())
    }

    /// `CLOCK_SOURCES` as this snapshot holds it.
    pub const fn clock_sources(&self) -> Quota {
        self.clock_sources_held().get()
    }

    /// `CLOCK_SOURCES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn clock_sources_held(&self) -> ClockSourcesHeld {
        self.limit()
    }

    /// Selects `CLOCK_SOURCES`, when the build's domain holds `value`.
    pub fn select_clock_sources(&mut self, value: Quota) -> Result<(), OutsideLimitDomain> {
        self.keep(&ClockSourcesHeld::select(value)?);
        Ok(())
    }

    /// `MESSAGE_CATALOG_ENTRIES` as this snapshot holds it.
    pub const fn message_catalog_entries(&self) -> Quota {
        self.message_catalog_entries_held().get()
    }

    /// `MESSAGE_CATALOG_ENTRIES` as the snapshot keeps it, for the table the bound limits to keep
    /// and ask ([`Limited::admits`]): in no byte where the build allows one value.
    pub const fn message_catalog_entries_held(&self) -> MessageCatalogEntriesHeld {
        self.limit()
    }

    /// Selects `MESSAGE_CATALOG_ENTRIES`, when the build's domain holds `value`.
    pub fn select_message_catalog_entries(
        &mut self,
        value: Quota,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&MessageCatalogEntriesHeld::select(value)?);
        Ok(())
    }

    /// `CLOCK_MAX_FORWARD_STEP_MS` as this snapshot holds it.
    pub const fn clock_max_forward_step_ms(&self) -> usize {
        self.clock_max_forward_step_ms_held().get()
    }

    /// `CLOCK_MAX_FORWARD_STEP_MS` as the snapshot keeps it, for a machine that keeps the value beside
    /// its own state: in no byte where the build allows one value.
    pub const fn clock_max_forward_step_ms_held(&self) -> ClockMaxForwardStepMsHeld {
        self.limit()
    }

    /// Selects `CLOCK_MAX_FORWARD_STEP_MS`, when the build's domain holds `value`.
    pub fn select_clock_max_forward_step_ms(
        &mut self,
        value: usize,
    ) -> Result<(), OutsideLimitDomain> {
        self.keep(&ClockMaxForwardStepMsHeld::select(value)?);
        Ok(())
    }
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self::BUILD
    }
}

impl core::fmt::Debug for RuntimeLimits {
    /// Each limit by its id, with the value the snapshot holds.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        LimitEntry::fmt_snapshot(&RUNTIME_LIMITS, "RuntimeLimits", self, f)
    }
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for MaxLocatorLen {
    const WORD: usize = 0;
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for MaxStaticConnect {
    const WORD: usize = word_after::<MaxLocatorLen, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for SnapshotPeriodMs {
    const WORD: usize = word_after::<MaxStaticConnect, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for SnapshotHistogramBuckets {
    const WORD: usize = word_after::<SnapshotPeriodMs, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for SupervisionCheckpoints {
    const WORD: usize = word_after::<SnapshotHistogramBuckets, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for E2eSupervisedStreams {
    const WORD: usize = word_after::<SupervisionCheckpoints, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for EventRingSlots {
    const WORD: usize = word_after::<E2eSupervisedStreams, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for ClockSources {
    const WORD: usize = word_after::<EventRingSlots, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for MessageCatalogEntries {
    const WORD: usize = word_after::<ClockSources, RuntimeLimits>();
}

// SAFETY: `RuntimeLimits` is transparent over its words, and this limit's word follows
// those of the limit before it, inside `RUNTIME_LIMIT_WORDS`.
unsafe impl LimitField<RuntimeLimits> for ClockMaxForwardStepMs {
    const WORD: usize = word_after::<MessageCatalogEntries, RuntimeLimits>();
}

/// How many limits [`RuntimeLimits`] holds: the length of [`RUNTIME_LIMITS`].
pub const RUNTIME_LIMIT_COUNT: usize = 10;

/// Every limit of [`RuntimeLimits`] as a reader that names it by its id sees it, in the order of
/// its words.
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

/// Every limit that is a capacity alone, by its id: the build sizes storage by it and no later
/// stage decides it, so neither snapshot holds it and a document that states it is refused by
/// name.
pub static CAPACITY_LIMITS: [&str; 42] = [
    "MATCH_MEMO_FIXED_SLOTS",
    "MATCH_MEMO_KEY_BYTES",
    "HELD_SESSIONS",
    "CALLBACK_THREADS",
    "ENGINE_ROWS",
    "HELD_SAMPLES",
    "HELD_REPLIES",
    "HELD_QUERIES",
    "HELD_CONFIGS",
    "HELD_HELLOS",
    "PAYLOAD_SMALL_BLOCK_BYTES",
    "PAYLOAD_MEDIUM_BLOCK_BYTES",
    "HELD_SMALL_PAYLOAD_BLOCKS",
    "HELD_MEDIUM_PAYLOAD_BLOCKS",
    "HELD_LARGE_PAYLOAD_BLOCKS",
    "HELD_ENCODINGS",
    "MAX_ENCODING_SCHEMA_BYTES",
    "CONFIG_ENTRIES",
    "MAX_SCOUT_HELLOS",
    "SCOUT_HELLO_LOCATORS",
    "CONFIG_DOCUMENT_DEPTH",
    "CONFIG_TEXT_BYTES",
    "MAX_ADMIN_REPLY_BYTES",
    "MAX_ADMIN_LOCATORS",
    "MAX_ADMIN_SESSION_LINKS",
    "MAX_TASKS",
    "MAX_TIMERS",
    "MAX_TICKERS",
    "ADVANCED_CACHE_BYTES",
    "MAX_SAMPLE_MISS_LISTENERS",
    "MAX_ADVANCED_SOURCES",
    "ADVANCED_SUBSCRIBER_PENDING_BYTES",
    "MAX_GROUP_ENDPOINT_LEN",
    "MAX_RAWETH_ENDPOINT_LEN",
    "MAX_GROUP_MEMBERS",
    "MAX_MEMBER_KEYEXPRS",
    "MAX_CONNECTIVITY_REPLAY_EVENTS",
    "MAX_FACE_WATCH_ROWS",
    "MAX_CONNECTIVITY_TOLD_ROWS",
    "MAX_PEER_NODES",
    "HANDSHAKE_COOKIE_BYTES",
    "EVENT_RECORD_ARGS",
];
