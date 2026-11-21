// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Every table a PEER writes, or that is owed to ONE peer, for one session
//! (fixed-memory step S9a, decision Q7: per session).
//!
//! The application-layer observer holds what the APPLICATION registers
//! (subscribers, queryables, local tokens, the switchboard); one registration
//! serves every session, and the process holds it once. This holds the rest:
//!
//! - what the peer's wire ids NAME: its keyexpr aliases
//!   ([`crate::pubsub::SubscriberPeer`], bound by `MAX_PEER_KEYEXPR_ALIASES`) and
//!   the subscribers, queryables and tokens it declared to us
//!   ([`crate::declare::subscriber::RemoteSubscriberPeer`],
//!   [`crate::declare::queryable::RemoteQueryablePeer`],
//!   [`crate::declare::liveliness_subscriber::PeerTokens`], each
//!   bound by `MAX_REMOTE_DECLS`), each held to the value the creator of the
//!   session states ([`crate::peer_tables::PeerTables::limit_to`]);
//! - what it ASKED to be told, and what is staged back to it: its subscriber
//!   interests ([`crate::caps::MAX_INBOUND_SUB_INTERESTS`]) and the staged
//!   answers ([`crate::caps::MAX_PENDING_DECLARES`]), the interest answers of the
//!   liveliness plane (`PeerTables::pending_declares`);
//! - what its queries make us OWE it: the replies staged and the `Final`s that
//!   follow ([`crate::reply_stage::ReplyStage`],
//!   [`crate::caps::MAX_PENDING_REPLIES`]; [`crate::reply_stage::FinalStage`],
//!   [`crate::caps::MAX_PENDING_FINALS`]).
//!
//! # Why per session
//!
//! A wire id is scoped by the transport session it arrived on: two peers both
//! number their aliases, declarations and requests from 1, so one table keyed by
//! the bare id conflates two peers (the isolation tests of
//! `tests/bounded_heapless_backing.rs` drive the same id from two sessions).
//! And a table one peer can fill is a table every session shares the exhaustion
//! of; one table per session makes a flood the flooded session's own, which is
//! what the same tests prove. Each session's memory is then its slot's size, which
//! is what the deploy file's `limits` keys state.
//!
//! # What is not here
//!
//! The requester-side pending queries (`ReplyRegistry`) are written by the
//! APPLICATION (`z_get`) and only completed by a peer, so they are not a table a
//! peer fills; but the request ids they are keyed by are minted per session, so
//! two sessions' ids collide in one registry. That table moves when its sink type
//! does (the registry is generic over the application's reply sink); it is
//! bounded already ([`crate::caps::MAX_PENDING_QUERIES`]).

use crate::bounded::{Profile, Static, Storage};
use crate::declare::liveliness_subscriber::PeerTokens;
use crate::declare::queryable::RemoteQueryablePeer;
use crate::declare::subscriber::RemoteSubscriberPeer;
use crate::pubsub::SubscriberPeer;
use crate::reply_stage::{FinalStage, ReplyStage};

#[cfg(feature = "liveliness-token")]
use crate::bounded::BoundedVec;
#[cfg(feature = "liveliness-token")]
use crate::caps;
#[cfg(feature = "liveliness-token")]
use crate::declare::local_token::DeclResponseItem;

/// The tables of one session's peer. See the module documentation.
///
/// The storage policy `P` is one choice for every table of the peer: the build's
/// [`Profile`] unless a caller names another, so `PeerTables` alone is the build's
/// tables and `PeerTables<Static>` / `PeerTables<Heap>` are the two policies side by
/// side in one build.
pub struct PeerTables<P: Storage = Profile> {
    /// The peer's keyexpr aliases, its subscriber interests and what is staged
    /// back to it.
    pub subscribers: SubscriberPeer<P>,
    /// The subscribers the peer declared to us.
    pub remote_subscribers: RemoteSubscriberPeer<P>,
    /// The queryables the peer declared to us.
    pub remote_queryables: RemoteQueryablePeer<P>,
    /// The liveliness tokens the peer declared to us.
    pub tokens: PeerTokens<P>,
    /// The replies a queryable staged for the peer's queries.
    pub replies: ReplyStage<P>,
    /// The `Final`s owed to the peer's queries.
    pub finals: FinalStage<P>,
    /// The answers to the peer's liveliness interests, staged until the next
    /// drain: [`caps::MAX_PENDING_DECLARES`] items, whole chains or none.
    #[cfg(feature = "liveliness-token")]
    pub pending_declares: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }, P>,
    /// The liveliness interests whose answer chain `pending_declares` could not
    /// take whole, and which were therefore staged not at all.
    #[cfg(feature = "liveliness-token")]
    pub token_interest_chains_refused: u32,
}

impl<P: Storage> Default for PeerTables<P> {
    fn default() -> Self {
        Self {
            subscribers: SubscriberPeer::default(),
            remote_subscribers: RemoteSubscriberPeer::default(),
            remote_queryables: RemoteQueryablePeer::default(),
            tokens: PeerTokens::default(),
            replies: ReplyStage::default(),
            finals: FinalStage::default(),
            #[cfg(feature = "liveliness-token")]
            pending_declares: BoundedVec::default(),
            #[cfg(feature = "liveliness-token")]
            token_interest_chains_refused: 0,
        }
    }
}

impl PeerTables<Static> {
    /// Empty tables of the static policy, for a peer that has said nothing yet.
    /// `const`, so a session slot that holds them can be a `static`.
    pub const fn new_static() -> Self {
        Self {
            subscribers: SubscriberPeer::new_static(),
            remote_subscribers: RemoteSubscriberPeer::new_static(),
            remote_queryables: RemoteQueryablePeer::new_static(),
            tokens: PeerTokens::new_static(),
            replies: ReplyStage::new_static(),
            finals: FinalStage::new_static(),
            #[cfg(feature = "liveliness-token")]
            pending_declares: BoundedVec::new_static(),
            #[cfg(feature = "liveliness-token")]
            token_interest_chains_refused: 0,
        }
    }
}

impl PeerTables<Profile> {
    /// Empty tables, for a peer that has said nothing yet. `const` on the fixed
    /// backing, so a session slot that holds them can be a `static`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self::new_static()
    }

    /// Empty tables, for a peer that has said nothing yet.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes one session's peer tables take where the table is placed, for
    /// the build's limits: what the deploy file's `limits` keys add up to, read off
    /// the types and not estimated.
    pub const fn bytes() -> usize {
        core::mem::size_of::<Self>()
    }
}

impl<P: Storage> PeerTables<P> {
    /// Hold the tables to the limits `limits` states: what the creator of the session resolved
    /// for it. In place, as a slot's tables are placed before a session is opened in them; what
    /// each table holds is kept, and what it is asked for next is held to the new quota.
    /// [`Self::forget_peer`] keeps the quotas; a session opened in the slot next states its own
    /// here.
    pub fn limit_to(&mut self, limits: &crate::limits::SessionLimits) {
        self.replies
            .limit_to(crate::reply_stage::ReplyBounds::of(limits));
        self.finals.limit_to(limits.max_pending_finals_held());
        self.subscribers
            .limit_aliases_to(limits.max_peer_keyexpr_aliases_held());
        let remote_decls = limits.max_remote_decls_held();
        self.remote_subscribers.limit_to(remote_decls);
        self.remote_queryables.limit_to(remote_decls);
        self.tokens.limit_to(remote_decls);
        let keys = limits.max_keyexpr_bytes_held();
        self.subscribers.limit_keys_to(keys);
        self.remote_subscribers.limit_keys_to(keys);
        self.remote_queryables.limit_keys_to(keys);
        self.tokens.limit_keys_to(keys);
    }

    /// Forget everything the peer said and everything owed to it, in place: the
    /// session ended, or its slot is being handed to the next one. What the session
    /// itself installed (its own id space and zid) goes too, because the next
    /// session's are its own. The counted refusals are kept by each table: they
    /// say what was asked of the table over its life and are what a report reads.
    ///
    /// In place, because the tables are large and a fresh value built on the stack
    /// to be moved in would cost the stack its whole size.
    pub fn forget_peer(&mut self) {
        self.subscribers.forget_peer();
        #[cfg(feature = "alloc")]
        self.subscribers.clear_own_mapping_space();
        self.subscribers.clear_own_zid();
        self.remote_subscribers.forget();
        self.remote_queryables.forget();
        self.tokens.forget();
        self.replies.clear();
        self.finals.clear();
        #[cfg(feature = "liveliness-token")]
        self.pending_declares.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;

    /// The tables are what the limits say, and they are not zero: a size of zero
    /// would be a table that holds nothing.
    #[test]
    fn the_tables_take_what_the_limits_say() {
        // The keyexpr rows dominate: the aliases and each of the three
        // declaration tables hold `MAX_KEYEXPR_BYTES` of text per row on the fixed
        // backing, and the interest table holds one more.
        let rows = caps::MAX_PEER_KEYEXPR_ALIASES + 3 * caps::MAX_REMOTE_DECLS;
        let floor = rows * caps::MAX_KEYEXPR_BYTES;
        if crate::bounded::ENFORCES_CAPACITY {
            assert!(
                PeerTables::bytes() >= floor,
                "{} bytes cannot hold {rows} rows of {} text bytes",
                PeerTables::bytes(),
                caps::MAX_KEYEXPR_BYTES
            );
        }
        assert!(PeerTables::bytes() > 0);
    }

    /// The tables take the bounds their creator states: held to two, a peer's third alias and
    /// third subscriber are refused and counted, and the quotas outlive a forgotten peer, as the
    /// session's limits outlive one link.
    #[cfg(all(feature = "alloc", feature = "codec-declare"))]
    #[test]
    fn the_tables_take_the_bounds_their_creator_states() {
        use crate::limit_binding::{LimitSpec, Quota};
        use crate::limits::{MaxPeerKeyexprAliases, MaxRemoteDecls, SessionLimits};
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        let mut limits = SessionLimits::defaults();
        let aliases = limits.select_max_peer_keyexpr_aliases(Quota::at_most(2));
        let decls = limits.select_max_remote_decls(Quota::at_most(2));
        if MaxPeerKeyexprAliases::DOMAIN.is_singleton() || MaxRemoteDecls::DOMAIN.is_singleton() {
            assert!(
                aliases.is_err() || decls.is_err(),
                "a build of one value refuses two"
            );
            return;
        }
        aliases.expect("two is inside the domain");
        decls.expect("two is inside the domain");
        let mut tables = PeerTables::new();
        tables.limit_to(&limits);
        let two = Quota::at_most(2);
        assert_eq!(
            (
                tables.subscribers.alias_quota().get(),
                tables.remote_subscribers.quota().get(),
                tables.remote_queryables.quota().get(),
                tables.tokens.quota().get(),
            ),
            (two, two, two, two),
            "every table the peer fills is handed its quota"
        );
        let mut subscribers = crate::declare::subscriber::RemoteSubscriberTable::<
            crate::decl_sink::BoxedDeclSink,
            crate::decl_sink::BoxedUndeclSink,
        >::default();
        let none: hashbrown::HashMap<u64, std::string::String> = hashbrown::HashMap::new();
        for round in 0..2 {
            for id in 1..=3u64 {
                let key = std::format!("bound/{id}");
                tables
                    .subscribers
                    .absorb_declare(&DeclareOwnedVariant::CodecZenohDeclKexpr(fx::decl_kexpr(
                        id, &key,
                    )));
                subscribers.dispatch_declare(
                    &mut tables.remote_subscribers,
                    &DeclareOwnedVariant::CodecZenohDeclSubscriber(fx::decl_subscriber(
                        id,
                        0,
                        Some(&key),
                    )),
                    &none,
                );
            }
            assert_eq!(
                (
                    tables.subscribers.alias_count(),
                    tables.subscribers.alias_refusals(),
                    tables.remote_subscribers.declared_count(),
                    tables.remote_subscribers.refusals(),
                ),
                (2, round + 1, 2, round + 1),
                "round {round}: two held and the third refused, the counts kept across a forget"
            );
            tables.forget_peer();
        }
    }

    /// The tables take the key bound their creator states: held to two bytes, a peer's alias
    /// and declared subscriber on a key of three are refused (the subscriber counted, as a row
    /// that cannot hold its key is), what fits is taken, and the bound outlives a forgotten peer.
    #[cfg(all(feature = "alloc", feature = "codec-declare"))]
    #[test]
    fn the_tables_take_the_key_bound_their_creator_states() {
        use crate::limit_binding::{LimitSpec, Quota};
        use crate::limits::{MaxKeyexprBytes, SessionLimits};
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        let mut limits = SessionLimits::defaults();
        let stated = limits.select_max_keyexpr_bytes(Quota::at_most(2));
        if MaxKeyexprBytes::DOMAIN.is_singleton() {
            assert!(stated.is_err(), "a build of one value refuses two");
            return;
        }
        stated.expect("two is inside the domain");
        let mut tables = PeerTables::new();
        tables.limit_to(&limits);
        let two = Quota::at_most(2);
        assert_eq!(
            (
                tables.subscribers.key_quota().get(),
                tables.remote_subscribers.key_quota().get(),
                tables.remote_queryables.key_quota().get(),
                tables.tokens.key_quota().get(),
            ),
            (two, two, two, two),
            "every table the peer fills is handed the key bound"
        );
        let mut subscribers = crate::declare::subscriber::RemoteSubscriberTable::<
            crate::decl_sink::BoxedDeclSink,
            crate::decl_sink::BoxedUndeclSink,
        >::default();
        let none: hashbrown::HashMap<u64, std::string::String> = hashbrown::HashMap::new();
        for round in 0..2u32 {
            for (id, key) in [(1u64, "abc"), (2, "ab")] {
                tables
                    .subscribers
                    .absorb_declare(&DeclareOwnedVariant::CodecZenohDeclKexpr(fx::decl_kexpr(
                        id, key,
                    )));
                subscribers.dispatch_declare(
                    &mut tables.remote_subscribers,
                    &DeclareOwnedVariant::CodecZenohDeclSubscriber(fx::decl_subscriber(
                        id,
                        0,
                        Some(key),
                    )),
                    &none,
                );
            }
            assert_eq!(
                (
                    tables.subscribers.alias_count(),
                    tables.remote_subscribers.declared_count(),
                    tables.remote_subscribers.refusals(),
                ),
                (1, 1, round + 1),
                "round {round}: the key of two is held and the key of three refused"
            );
            tables.forget_peer();
        }
    }

    /// A forgotten peer is an empty one, and its counts survive.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_forgotten_peer_holds_nothing_and_keeps_its_counts() {
        let mut tables = PeerTables::new();
        tables.forget_peer();
        assert_eq!(tables.subscribers.alias_count(), 0);
        assert_eq!(tables.remote_subscribers.declared_count(), 0);
        assert_eq!(tables.remote_queryables.declared_count(), 0);
        assert_eq!(tables.tokens.count(), 0);
    }
}
