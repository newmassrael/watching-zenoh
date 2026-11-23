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

use crate::bounded::{Arena, LendRefused, Lent, Profile, Static, Storage};
use crate::declare::liveliness_subscriber::PeerTokens;
use crate::declare::queryable::RemoteQueryablePeer;
use crate::declare::subscriber::RemoteSubscriberPeer;
use crate::key_arena::{KeySpace, LentKeys};
use crate::pubsub::SubscriberPeer;
use crate::reply_stage::{FinalStage, ReplyStage};
use core::mem::MaybeUninit;
use core::ptr::{self, addr_of_mut};

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
        let mut place = MaybeUninit::uninit();
        Self::init_in(&mut place);
        // SAFETY: `init_in` wrote every field of the tables into `place`.
        unsafe { place.assume_init() }
    }
}

impl<P: Storage> PeerTables<P> {
    /// Empty tables, for a peer that has said nothing yet, written field by field into `place`,
    /// which is overwritten without dropping what it held: the single list of fields, which
    /// [`Default`] shares. Of the lent policy the tables have no rows until
    /// [`PeerTables::lend_rows`] lends them some where they lie.
    ///
    /// The tables keyed by the peer's ids are inline at the build's capacity, kilobytes each, so a
    /// set built as a value and moved into the place that keeps it passes through the frame of every
    /// function it is moved by. Not inlined: the largest value its own frame holds is one table.
    #[inline(never)]
    pub fn init_in(place: &mut MaybeUninit<Self>) -> &mut Self {
        let at = place.as_mut_ptr();
        // Each gated statement opens with the path `ptr::write(`, not with the `addr_of_mut!`
        // macro, as `SlotObserverOf::init_in_place` says why.
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it; `every_field_is_written` names every field, so the tables are whole when
        // they are lent.
        unsafe {
            ptr::write(addr_of_mut!((*at).subscribers), SubscriberPeer::default());
            ptr::write(
                addr_of_mut!((*at).remote_subscribers),
                RemoteSubscriberPeer::default(),
            );
            ptr::write(
                addr_of_mut!((*at).remote_queryables),
                RemoteQueryablePeer::default(),
            );
            ptr::write(addr_of_mut!((*at).tokens), PeerTokens::default());
            ptr::write(addr_of_mut!((*at).replies), ReplyStage::default());
            ptr::write(addr_of_mut!((*at).finals), FinalStage::default());
            #[cfg(feature = "liveliness-token")]
            ptr::write(addr_of_mut!((*at).pending_declares), BoundedVec::default());
            #[cfg(feature = "liveliness-token")]
            ptr::write(addr_of_mut!((*at).token_interest_chains_refused), 0);
            &mut *at
        }
    }

    /// A field added to [`PeerTables`] and not written by [`Self::init_in`] would be read
    /// uninitialised. This destructures the tables with no `..`, so adding a field without naming
    /// it here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(tables: Self) {
        let Self {
            subscribers: _,
            remote_subscribers: _,
            remote_queryables: _,
            tokens: _,
            replies: _,
            finals: _,
            #[cfg(feature = "liveliness-token")]
                pending_declares: _,
            #[cfg(feature = "liveliness-token")]
                token_interest_chains_refused: _,
        } = tables;
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

/// How many rows each table of [`PeerTables`] of the lent policy is lent ([`PeerTables::lent`]):
/// the values of their limits the session's open resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerRows {
    /// The peer's subscriber interests (`MAX_INBOUND_SUB_INTERESTS`); lent none in a build without
    /// `declare-subscriber`.
    pub sub_interests: usize,
    /// The answers staged back to the peer's interests (`MAX_PENDING_DECLARES`): the subscriber
    /// plane's staging and, with `liveliness-token`, the liveliness plane's, each this many.
    pub pending_declares: usize,
    /// The replies staged for the peer's queries (`MAX_PENDING_REPLIES`).
    pub replies: usize,
    /// The bytes the staged replies' keys and payloads lie in (`ReplyStage::area_bytes` of the
    /// replies, their payload bound and their key bound).
    pub reply_bytes: usize,
    /// The `Final`s owed to the peer's queries (`MAX_PENDING_FINALS`).
    pub finals: usize,
}

impl PeerTables<Lent> {
    /// Empty tables, for a peer that has said nothing yet, the rows of each table `rows` states
    /// lent from `arena` and the keys of every row kept in `keys`, the session's key arena, held
    /// to `limits` as [`PeerTables::limit_to`] holds them. Refused when a table is over the
    /// build's capacity or the arena has not the room, the rows lent so far going back with the
    /// arena. The tables keyed by the peer's ids are the policy's inline ones, each row a key's
    /// place.
    pub fn lent(
        arena: &mut Arena,
        keys: KeySpace,
        rows: PeerRows,
        limits: &crate::limits::SessionLimits,
    ) -> Result<Self, LendRefused> {
        let mut tables = Self::default();
        tables.lend_rows(arena, keys, rows, limits)?;
        Ok(tables)
    }

    /// Lend tables of no rows ([`PeerTables::init_in`]) the rows `rows` states from `arena`,
    /// where they lie, hand them `keys` to keep their rows' keys in, and hold them to `limits`:
    /// what [`Self::lent`] makes, without the tables being a value of their own. Each table is
    /// lent in the order `lent` lends them, so the arena is laid out as its plan
    /// ([`Self::arena_bytes`]) counts it. Refused as `lent` is; the tables stay whole, those lent
    /// before the refusal holding their rows, which go back with the arena.
    pub fn lend_rows(
        &mut self,
        arena: &mut Arena,
        keys: KeySpace,
        rows: PeerRows,
        limits: &crate::limits::SessionLimits,
    ) -> Result<(), LendRefused> {
        self.keep_keys_in(LentKeys::from(keys));
        self.subscribers
            .lend_rows(arena, rows.sub_interests, rows.pending_declares)?;
        self.replies = ReplyStage::lent(arena, rows.replies, rows.reply_bytes)?;
        self.finals = FinalStage::lent(arena, rows.finals)?;
        #[cfg(feature = "liveliness-token")]
        {
            self.pending_declares = arena.lend(rows.pending_declares)?;
        }
        self.limit_to(limits);
        Ok(())
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows`: each table's spans. `None` past the
    /// address space.
    pub const fn arena_bytes(rows: PeerRows) -> Option<usize> {
        // A build without `liveliness-token` stages no answer of the liveliness plane.
        #[cfg(feature = "liveliness-token")]
        let tokens = Arena::table_bytes::<DeclResponseItem>(rows.pending_declares);
        #[cfg(not(feature = "liveliness-token"))]
        let tokens = Some(0);
        let spans = [
            SubscriberPeer::<Lent>::arena_bytes(rows.sub_interests, rows.pending_declares),
            ReplyStage::<Lent>::arena_bytes(rows.replies, rows.reply_bytes),
            FinalStage::<Lent>::arena_bytes(rows.finals),
            tokens,
        ];
        let mut sum = 0usize;
        let mut at = 0;
        while at < spans.len() {
            sum = match spans[at] {
                Some(span) => match sum.checked_add(span) {
                    Some(sum) => sum,
                    None => return None,
                },
                None => return None,
            };
            at += 1;
        }
        Some(sum)
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

    /// Keep the keys of every row the peer writes from here on in `keys` ([`Storage::Keys`]):
    /// the session's key arena, on the lent policy. A table of no key arena keeps no key, so what
    /// the peer declares is dropped and counted until it is handed one.
    pub fn keep_keys_in(&mut self, keys: P::Keys) {
        self.subscribers.keep_keys_in(keys.clone());
        self.remote_subscribers.keep_keys_in(keys.clone());
        self.remote_queryables.keep_keys_in(keys.clone());
        self.tokens.keep_keys_in(keys);
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

#[cfg(test)]
mod lent_tests {
    //! The tables of a peer lent from a session's arena: the rows lent are what bound them, what
    //! they are lent is what their plan states, and a drain leaves them the rows it found.
    use super::*;
    use crate::bounded::ARENA_ALIGN;
    use crate::caps;
    use crate::limits::SessionLimits;
    use crate::query_sink::ReplyError;
    use crate::reply_stage::{
        FinalStaging, PartsBody, PartsKind, ReplyParts, ReplyStaging, TimestampParts,
    };
    use crate::sample::QosLevel;
    use core::ptr::NonNull;

    /// One block of an arena's memory, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block([u8; ARENA_ALIGN]);

    /// An arena over `bytes` bytes the test process leaks, so it outlives every table lent from it.
    fn arena(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every lent table.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// `each` rows of every table, and room for `each` replies of 8 bytes on keys of 8.
    fn rows(each: usize) -> PeerRows {
        PeerRows {
            sub_interests: each,
            pending_declares: each,
            replies: each,
            reply_bytes: ReplyStage::<Lent>::area_bytes(each, 8, 8).expect("a small area"),
            finals: each,
        }
    }

    /// A key arena of `bytes` bytes of blocks, lent from an arena of its own, so the arena the
    /// tables' rows are lent from is laid out by their plan alone.
    fn keys(bytes: usize) -> KeySpace {
        arena(KeySpace::span_bytes(bytes).expect("a small key arena"))
            .lend_keys(bytes)
            .expect("the arena is the key arena's span")
    }

    fn lent(rows: PeerRows) -> PeerTables<Lent> {
        PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys(1024),
            rows,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows")
    }

    /// A one-byte Put on `"k"` for request `rid`, stamped by `responder` and `timestamp`.
    fn reply<'a>(
        rid: crate::wire_id::RequestId,
        responder: Option<(&'a [u8], u32)>,
        timestamp: Option<TimestampParts<'a>>,
    ) -> ReplyParts<'a> {
        ReplyParts {
            rid,
            keyexpr: "k",
            responder,
            qos: QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(b"v"),
                encoding: None,
                timestamp,
                attachment: None,
                source_info: None,
            },
        }
    }

    /// What lending a peer's tables takes from an arena is what their plan states, to the byte.
    #[test]
    fn lent_peer_tables_take_the_bytes_their_plan_states() {
        let rows = rows(2);
        let mut memory = arena(1 << 16);
        let tables =
            PeerTables::<Lent>::lent(&mut memory, keys(64), rows, &SessionLimits::defaults())
                .expect("the arena has the rows");
        let planned = PeerTables::<Lent>::arena_bytes(rows).expect("within the address space");
        assert_eq!(memory.high_water(), planned);
        assert!(planned > 0, "a plan of two rows each lends something");
        drop(tables);
    }

    /// Tables written where they lie and lent their rows there are the tables `lent` makes by
    /// value: the same bytes of the arena, one row of each table that bounds them, the quotas.
    #[test]
    fn peer_tables_lent_in_place_are_the_tables_lent_by_value() {
        let rows = rows(1);
        let limits = SessionLimits::defaults();
        let mut by_value_memory = arena(1 << 16);
        let mut by_value = PeerTables::<Lent>::lent(&mut by_value_memory, keys(64), rows, &limits)
            .expect("the rows");
        let mut memory = arena(1 << 16);
        let mut place = MaybeUninit::<PeerTables<Lent>>::uninit();
        let in_place = PeerTables::init_in(&mut place);
        assert!(
            !in_place.finals.has_room(),
            "CONTROL: tables of no rows refuse a Final"
        );
        in_place
            .lend_rows(&mut memory, keys(64), rows, &limits)
            .expect("the arena has the rows");
        assert_eq!(
            memory.high_water(),
            by_value_memory.high_water(),
            "the same tables lent in the same order take the same bytes"
        );
        for tables in [&mut by_value, &mut *in_place] {
            assert_eq!(tables.replies.stage_parts(reply(1, None, None)), Ok(()));
            assert_eq!(
                tables.replies.stage_parts(reply(2, None, None)),
                Err(ReplyError::StagingFull)
            );
            tables.finals.owe(1, QosLevel::DEFAULT);
            assert!(!tables.finals.has_room(), "one row of Finals");
            #[cfg(feature = "liveliness-token")]
            {
                assert!(tables
                    .pending_declares
                    .push(DeclResponseItem::Final { interest_id: 1 })
                    .is_ok());
                assert!(tables
                    .pending_declares
                    .push(DeclResponseItem::Final { interest_id: 2 })
                    .is_err());
            }
        }
        // SAFETY: `init_in` wrote the whole tables into `place`, and they are dropped once.
        unsafe { place.assume_init_drop() };
    }

    /// A refusal of the rows leaves the tables written in place whole: they are dropped as tables,
    /// with what was lent before the refusal.
    #[test]
    fn peer_tables_refused_their_rows_in_place_stay_whole() {
        let rows = rows(1);
        let planned = PeerTables::<Lent>::arena_bytes(rows).expect("within the address space");
        let mut place = MaybeUninit::<PeerTables<Lent>>::uninit();
        let refused = PeerTables::init_in(&mut place).lend_rows(
            &mut arena(planned - 1),
            keys(64),
            rows,
            &SessionLimits::defaults(),
        );
        assert!(matches!(refused, Err(LendRefused::Exhausted { .. })));
        // SAFETY: `init_in` wrote the whole tables into `place`, a refused lend leaves them whole,
        // and they are dropped once.
        unsafe { place.assume_init_drop() };
    }

    /// An arena one byte short of the plan refuses the tables as exhausted.
    #[test]
    fn lent_peer_tables_the_arena_cannot_hold_are_refused() {
        let rows = rows(1);
        let planned = PeerTables::<Lent>::arena_bytes(rows).expect("within the address space");
        let refused = PeerTables::<Lent>::lent(
            &mut arena(planned - 1),
            keys(64),
            rows,
            &SessionLimits::defaults(),
        );
        assert!(matches!(refused, Err(LendRefused::Exhausted { .. })));
    }

    /// A table asked for more rows than the build's capacity is refused, not lent its ceiling.
    #[test]
    fn lent_peer_tables_over_the_build_are_refused() {
        let over = PeerRows {
            finals: caps::MAX_PENDING_FINALS + 1,
            ..rows(1)
        };
        let refused = PeerTables::<Lent>::lent(
            &mut arena(1 << 20),
            keys(64),
            over,
            &SessionLimits::defaults(),
        );
        assert!(matches!(
            refused,
            Err(LendRefused::OverCeiling { rows: asked, ceiling })
                if asked == caps::MAX_PENDING_FINALS + 1 && ceiling == caps::MAX_PENDING_FINALS
        ));
    }

    /// One reply and one `Final` lent: the second of each is refused and counted, and a drain
    /// leaves the rows it found, so the next of each is taken.
    #[test]
    fn a_lent_peer_refuses_past_its_rows_and_keeps_them_across_a_drain() {
        let mut tables = lent(rows(1));
        assert_eq!(tables.replies.stage_parts(reply(1, None, None)), Ok(()));
        assert_eq!(
            tables.replies.stage_parts(reply(2, None, None)),
            Err(ReplyError::StagingFull)
        );
        assert_eq!(tables.replies.refusals().staging_full, 1);
        let mut drained = 0;
        tables.replies.drain_parts(|_| drained += 1);
        assert_eq!(drained, 1);
        assert_eq!(
            tables.replies.stage_parts(reply(3, None, None)),
            Ok(()),
            "the drain kept the row the arena lent"
        );

        assert!(tables.finals.has_room());
        tables.finals.owe(1, QosLevel::DEFAULT);
        assert!(!tables.finals.has_room(), "the one row holds a Final");
        let owed = tables.finals.take_owed();
        assert_eq!(owed.len(), 1);
        assert!(
            tables.finals.has_room(),
            "taking what is owed keeps the row the arena lent"
        );
        tables.finals.owe(2, QosLevel::DEFAULT);
        assert_eq!(tables.finals.owed(), 1);
    }

    /// The identities a staged reply carries are inline in its row, not tables of their own: a
    /// lent stage holds the responder's zid and, in a build that keeps a reply's timestamp, the
    /// timestamp's.
    #[test]
    fn a_lent_stage_holds_a_replys_identities() {
        let mut tables = lent(rows(1));
        let stamp = TimestampParts {
            time: 42,
            zid: &[4, 5],
        };
        assert_eq!(
            tables
                .replies
                .stage_parts(reply(1, Some((&[1, 2, 3], 7)), Some(stamp))),
            Ok(())
        );
        let parts = tables.replies.parts(0).expect("one reply staged");
        assert_eq!(parts.responder, Some((&[1u8, 2, 3][..], 7)));
        let PartsKind::Reply {
            body: PartsBody::Put(_),
            timestamp,
            ..
        } = parts.kind
        else {
            panic!("a Put was staged");
        };
        assert_eq!(
            timestamp.map(|ts| (ts.time, ts.zid)),
            cfg!(feature = "pubsub-timestamp").then_some((42, &[4u8, 5][..]))
        );
    }

    /// The answers staged to a peer's interest are taken out for the drain and the staging keeps
    /// its rows: the next interest's answer is staged in them.
    #[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
    #[test]
    fn a_lent_peer_side_stages_again_after_a_take() {
        use crate::pubsub::{SubInterestReply, SubscriberTable};
        use crate::sink::BoxedSink;

        let mut tables = lent(rows(2));
        let mut table = SubscriberTable::<BoxedSink>::default();
        for interest in [7u64, 8] {
            table.respond_to_subscriber_interest_borrowed(
                &mut tables.subscribers,
                interest,
                Some("demo/**"),
                false,
                true,
                false,
            );
            let staged = tables.subscribers.take_staged_sub_interest_replies();
            assert!(
                staged.iter().any(|item| matches!(
                    item,
                    SubInterestReply::Final { interest_id } if *interest_id == interest
                )),
                "interest {interest}: its chain was staged in the side's rows"
            );
        }
    }

    /// The liveliness plane's staging is lent too: an answer is held in its row.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn a_lent_peer_holds_a_liveliness_answer() {
        let mut tables = lent(rows(1));
        assert!(tables
            .pending_declares
            .push(DeclResponseItem::Final { interest_id: 1 })
            .is_ok());
        assert!(tables
            .pending_declares
            .push(DeclResponseItem::Final { interest_id: 2 })
            .is_err());
    }

    /// An interest the peer asks keeps its key in the key arena the tables were handed, though
    /// the interest side's rows are lent after the arena is handed (`PeerTables::lend_rows`): the
    /// row is held with its key, and the answer is more than a `Final` alone.
    #[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
    #[test]
    fn a_lent_peers_interest_keeps_its_key_in_the_key_arena() {
        use crate::key_arena::block_bytes;
        use crate::pubsub::SubscriberTable;
        use crate::sink::BoxedSink;

        let keys = keys(256);
        let mut tables = PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys,
            rows(1),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let mut table = SubscriberTable::<BoxedSink>::default();
        table.respond_to_subscriber_interest_borrowed(
            &mut tables.subscribers,
            7,
            Some("demo/**"),
            false,
            true,
            false,
        );
        assert_eq!(
            keys.counts().used,
            block_bytes("demo/**".len()).expect("a short key"),
            "the interest's row keeps its key in the arena"
        );
    }

    /// The table a peer's subscriber declarations are dispatched through.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    type RemoteSubscribers = crate::declare::subscriber::RemoteSubscriberTable<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >;

    /// The peer declares a subscriber `id` on `key` into `tables`.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    fn declare_subscriber(
        table: &mut RemoteSubscribers,
        tables: &mut PeerTables<Lent>,
        id: u64,
        key: &str,
    ) {
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        let none: hashbrown::HashMap<u64, std::string::String> = hashbrown::HashMap::new();
        table.dispatch_declare(
            &mut tables.remote_subscribers,
            &DeclareOwnedVariant::CodecZenohDeclSubscriber(fx::decl_subscriber(id, 0, Some(key))),
            &none,
        );
    }

    /// The peer aliases `key` under `id` in `tables`.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    fn declare_alias(tables: &mut PeerTables<Lent>, id: u64, key: &str) {
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        tables
            .subscribers
            .absorb_declare(&DeclareOwnedVariant::CodecZenohDeclKexpr(fx::decl_kexpr(
                id, key,
            )));
    }

    /// What a peer declares is kept in the session's key arena, a block of each key's length,
    /// and reads back as it was declared: an alias resolves to its literal and a subscriber
    /// matches its key. Forgetting the peer gives every block back, and the next peer's key of
    /// the same length takes the same bytes, the arena's peak unmoved.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    #[test]
    fn a_lent_peers_keys_lie_in_the_key_arena_and_read_back_as_declared() {
        use crate::key_arena::block_bytes;

        let keys = keys(256);
        let mut tables = PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys,
            rows(1),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let mut table = RemoteSubscribers::default();
        declare_alias(&mut tables, 3, "demo/alias");
        declare_subscriber(&mut table, &mut tables, 1, "demo/sub/**");
        assert_eq!(
            tables.subscribers.resolve_inbound_mapping(3).as_deref(),
            Some("demo/alias")
        );
        assert!(tables.remote_subscribers.has_matching("demo/sub/x"));
        assert!(!tables.remote_subscribers.has_matching("demo/other"));
        let blocks = block_bytes("demo/alias".len()).expect("short")
            + block_bytes("demo/sub/**".len()).expect("short");
        assert_eq!(keys.counts().used, blocks, "a block of each key's length");
        let peak = keys.counts().peak;
        tables.forget_peer();
        assert_eq!(
            keys.counts().used,
            0,
            "a forgotten peer gives every block back"
        );
        declare_alias(&mut tables, 4, "demo/again");
        assert_eq!(
            tables.subscribers.resolve_inbound_mapping(4).as_deref(),
            Some("demo/again")
        );
        assert_eq!(
            keys.counts().peak,
            peak,
            "the blocks given back are taken again"
        );
    }

    /// A peer's declaration whose key finds no room in the session's key arena is dropped and
    /// counted with its table's refusals, as one its table has no room for is, and the arena
    /// counts the key it refused; the room a withdrawal gives back takes the next declaration.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    #[test]
    fn a_peers_declaration_the_key_arena_cannot_hold_is_dropped_and_counted() {
        use crate::key_arena::block_bytes;
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        if caps::MAX_REMOTE_DECLS < 2 {
            // A table of one row refuses the second declaration by itself.
            return;
        }
        let keys = keys(block_bytes("demo/k/1".len()).expect("short"));
        let mut tables = PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys,
            rows(1),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let mut table = RemoteSubscribers::default();
        declare_subscriber(&mut table, &mut tables, 1, "demo/k/1");
        declare_subscriber(&mut table, &mut tables, 2, "demo/k/2");
        assert_eq!(
            (
                tables.remote_subscribers.declared_count(),
                tables.remote_subscribers.refusals(),
                keys.counts().refused,
            ),
            (1, 1, 1),
            "(declarations held, refused by the table, keys the arena refused)"
        );
        assert!(!tables.remote_subscribers.has_matching("demo/k/2"));
        declare_alias(&mut tables, 5, "demo/k/5");
        assert_eq!(
            (
                tables.subscribers.alias_count(),
                tables.subscribers.alias_refusals()
            ),
            (0, 1),
            "an alias with no room for its key is dropped and counted too"
        );
        let none: hashbrown::HashMap<u64, std::string::String> = hashbrown::HashMap::new();
        table.dispatch_declare(
            &mut tables.remote_subscribers,
            &DeclareOwnedVariant::CodecZenohUndeclSubscriber(fx::undecl_subscriber(1)),
            &none,
        );
        declare_subscriber(&mut table, &mut tables, 2, "demo/k/2");
        assert_eq!(tables.remote_subscribers.declared_count(), 1);
        assert!(
            tables.remote_subscribers.has_matching("demo/k/2"),
            "the block the withdrawal gave back holds the next key"
        );
    }

    /// Tables of the lent policy that were handed no key arena keep no key: what the peer
    /// declares is dropped and counted, never held under a key of nowhere.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber"
    ))]
    #[test]
    fn lent_tables_handed_no_key_arena_drop_and_count_what_the_peer_declares() {
        let mut tables = PeerTables::<Lent>::default();
        let mut table = RemoteSubscribers::default();
        declare_subscriber(&mut table, &mut tables, 1, "demo/k/1");
        assert_eq!(
            (
                tables.remote_subscribers.declared_count(),
                tables.remote_subscribers.refusals()
            ),
            (0, 1)
        );
    }
}
