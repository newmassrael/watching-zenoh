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
#[cfg(feature = "peer-row-pools")]
use crate::row_pool::{Keyed, OwnSpans, RowLender, RowSource, RowSpace};
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
/// the values of their limits the session's open resolved. What the peer writes by its own
/// choice (its aliases, its declarations, its interests) is not lent to each face: its rows lie in
/// the session's pools ([`PeerPools`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerRows {
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
    /// lent from `arena`, the keys of every row kept in `keys`, the session's key arena, and the
    /// rows the peer writes by its own choice in `pools`, the session's, held to `limits` as
    /// [`PeerTables::limit_to`] holds them. Refused when a table is over the build's capacity or
    /// the arena has not the room, the rows lent so far going back with the arena.
    pub fn lent(
        arena: &mut Arena,
        keys: KeySpace,
        rows: PeerRows,
        pools: &mut PeerPools,
        limits: &crate::limits::SessionLimits,
    ) -> Result<Self, LendRefused> {
        let mut tables = Self::default();
        tables.lend_rows(arena, keys, rows, pools, limits)?;
        Ok(tables)
    }

    /// Lend tables of no rows ([`PeerTables::init_in`]) the rows `rows` states from `arena`,
    /// where they lie, hand them `keys` to keep their rows' keys in and `pools` to keep what the
    /// peer writes in, and hold them to `limits`: what [`Self::lent`] makes, without the tables
    /// being a value of their own. Each table is lent in the order `lent` lends them, so the
    /// arena is laid out as its plan ([`Self::arena_bytes`]) counts it. Refused as `lent` is;
    /// the tables stay whole, those lent before the refusal holding their rows, which go back with
    /// the arena.
    pub fn lend_rows(
        &mut self,
        arena: &mut Arena,
        keys: KeySpace,
        rows: PeerRows,
        pools: &mut PeerPools,
        limits: &crate::limits::SessionLimits,
    ) -> Result<(), LendRefused> {
        self.keep_keys_in(LentKeys::from(keys));
        self.keep_rows_in(pools);
        self.subscribers.lend_rows(arena, rows.pending_declares)?;
        self.replies = ReplyStage::lent(arena, rows.replies, rows.reply_bytes)?;
        self.finals = FinalStage::lent(arena, rows.finals)?;
        #[cfg(feature = "liveliness-token")]
        {
            self.pending_declares = arena.lend(rows.pending_declares)?;
        }
        self.limit_to(limits);
        Ok(())
    }

    /// Keep what the peer writes by its own choice from here on in rows `pools` hands out, the
    /// session's: its aliases, its subscribers, queryables and tokens and the repeats of them, and
    /// its interests. Rows of a shared pool are handed to every face's tables; one face's own spans
    /// to the first tables that ask alone, so tables handed nothing keep what they had. What the
    /// tables held in other rows is forgotten first.
    #[cfg(feature = "peer-row-pools")]
    pub fn keep_rows_in(&mut self, pools: &mut PeerPools) {
        if let Some(space) = pools.aliases.hand_out() {
            self.subscribers.keep_alias_rows_in(space);
        }
        #[cfg(feature = "declare-subscriber")]
        self.subscribers.keep_interest_rows_in(&mut pools.interests);
        if let Some(space) = pools.subscribers.hand_out() {
            self.remote_subscribers.keep_rows_in(space);
        }
        if let Some(space) = pools.queryables.hand_out() {
            self.remote_queryables.keep_rows_in(space);
        }
        #[cfg(feature = "alloc")]
        {
            if let Some(space) = pools.sub_repeats.hand_out() {
                self.remote_subscribers.keep_repeat_rows_in(space);
            }
            if let Some(space) = pools.queryable_repeats.hand_out() {
                self.remote_queryables.keep_repeat_rows_in(space);
            }
        }
        if let Some(space) = pools.tokens.hand_out() {
            self.tokens.keep_rows_in(space);
        }
    }

    /// Nothing to keep: a build without `peer-row-pools` keeps what the peer writes inline.
    #[cfg(not(feature = "peer-row-pools"))]
    pub fn keep_rows_in(&mut self, pools: &mut PeerPools) {
        let _ = pools;
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
            SubscriberPeer::<Lent>::arena_bytes(rows.pending_declares),
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

/// Whether this build's lent tables keep what a peer writes in pools a session's faces share
/// (`peer-row-pools`): an engine that lends no pool where it is off reads this as a constant, so
/// the code that sizes and lends them is not in its text.
pub const SHARES_ROWS: bool = cfg!(feature = "peer-row-pools");

/// How many rows each kind of what the peers of one session write by their own choice is lent
/// ([`PeerPools::lent`]), and whether the session's faces share them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerPoolRows {
    /// The peers' keyexpr aliases (`SESSION_MAX_PEER_KEYEXPR_ALIASES`).
    pub aliases: usize,
    /// The peers' declarations of one kind (`SESSION_MAX_REMOTE_DECLS`): the subscribers, the
    /// queryables and the tokens each this many, and with `alloc` the repeats of the subscribers
    /// and of the queryables each this many, as a repeat is an id its kind's table holds.
    pub remote_decls: usize,
    /// The peers' subscriber interests (`SESSION_MAX_INBOUND_SUB_INTERESTS`); none in a build
    /// without `declare-subscriber`.
    pub interests: usize,
    /// Whether the faces of the session share the rows, a pool of each kind for a session of many
    /// faces, or one face has them, a span of each of its tables' own for a session of one.
    pub shared: bool,
}

/// The kind of row of a table keyed by a peer's ids whose value is a key's place.
#[cfg(feature = "peer-row-pools")]
type KeyKind = Keyed<crate::key_arena::KeyRef>;

/// The kind of row of the peer's queryables.
#[cfg(feature = "peer-row-pools")]
type QueryableKind = Keyed<crate::id_map::DeclaredQueryable<Lent>>;

/// The kind of row of the repeats of the peer's subscribers or queryables.
#[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
type RepeatKind = crate::row_pool::Seq<(u64, u64)>;

impl PeerPoolRows {
    /// The bytes the aliases' rows take in an arena: none without `peer-row-pools`, whose tables
    /// keep their rows inline. `None` past the most rows a pool or a span names, or the address
    /// space.
    pub const fn alias_bytes(&self) -> Option<usize> {
        #[cfg(feature = "peer-row-pools")]
        {
            if self.shared {
                RowSpace::<KeyKind>::pool_bytes(self.aliases)
            } else {
                span_of(RowSpace::<KeyKind>::own_bytes(self.aliases))
            }
        }
        #[cfg(not(feature = "peer-row-pools"))]
        {
            Some(0)
        }
    }

    /// The bytes the declarations' rows take in an arena: the subscribers', the queryables', the
    /// tokens' and, with `alloc`, the repeats'. In a session of one face they are one span, each
    /// table's rows from where the one before ends, aligned for its rows (`decl_end`). `None`
    /// past the most rows a pool or a span names, or the address space. No bytes without
    /// `peer-row-pools`.
    pub const fn decl_bytes(&self) -> Option<usize> {
        #[cfg(feature = "peer-row-pools")]
        {
            let rows = self.remote_decls;
            if !self.shared {
                return span_of(decl_end(rows));
            }
            #[cfg(feature = "alloc")]
            let repeats = match RowSpace::<RepeatKind>::pool_bytes(rows) {
                Some(each) => each.checked_mul(2),
                None => None,
            };
            #[cfg(not(feature = "alloc"))]
            let repeats = Some(0);
            sum_spans(&[
                RowSpace::<KeyKind>::pool_bytes(rows),
                RowSpace::<QueryableKind>::pool_bytes(rows),
                RowSpace::<KeyKind>::pool_bytes(rows),
                repeats,
            ])
        }
        #[cfg(not(feature = "peer-row-pools"))]
        {
            Some(0)
        }
    }

    /// The bytes the interests' rows take in an arena: none without `declare-subscriber` or
    /// `peer-row-pools`. `None` past the most rows a pool or a span names, or the address space.
    pub const fn interest_bytes(&self) -> Option<usize> {
        #[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
        {
            if self.shared {
                crate::pubsub::InterestRows::pool_bytes(self.interests)
            } else {
                span_of(crate::pubsub::InterestRows::own_bytes(self.interests))
            }
        }
        #[cfg(not(all(feature = "declare-subscriber", feature = "peer-row-pools")))]
        {
            Some(0)
        }
    }

    /// The bytes an arena [`PeerPools::lent`] takes for these rows. `None` past the most rows a
    /// pool or a span names, or the address space.
    pub const fn arena_bytes(&self) -> Option<usize> {
        sum_spans(&[self.alias_bytes(), self.decl_bytes(), self.interest_bytes()])
    }
}

/// `bytes` rounded up to an arena's span.
#[cfg(feature = "peer-row-pools")]
const fn span_of(bytes: Option<usize>) -> Option<usize> {
    match bytes {
        Some(bytes) => Arena::span(bytes),
        None => None,
    }
}

/// Where the rows of a face's own declaration tables of `rows` rows each end in the one span they
/// share, laid out as [`PeerPools::lent`] carves them: the subscribers', the queryables', the
/// tokens' and, with `alloc`, the subscribers' repeats' and the queryables' repeats', each from
/// where the one before ends, aligned for its rows. `None` past the most rows a span names or
/// the address space.
#[cfg(feature = "peer-row-pools")]
const fn decl_end(rows: usize) -> Option<usize> {
    let tokens = OwnSpans::after::<KeyKind>(
        OwnSpans::after::<QueryableKind>(OwnSpans::after::<KeyKind>(Some(0), rows), rows),
        rows,
    );
    #[cfg(feature = "alloc")]
    {
        OwnSpans::after::<RepeatKind>(OwnSpans::after::<RepeatKind>(tokens, rows), rows)
    }
    #[cfg(not(feature = "alloc"))]
    {
        tokens
    }
}

/// Where the tables of the faces of a session keep what their peers write by their own choice:
/// lent from the session's arena once, at its open (`crate::row_pool`), and handed to each face's
/// tables as they are made ([`PeerTables::keep_rows_in`]).
///
/// For a session of many faces, one pool of each row kind the faces share, each face's table a
/// list of the rows its peer holds: a face's tables keep the bound of each peer, and a pool bounds
/// what the faces hold together, so a session reserves what its faces may hold at once and not its
/// faces times what each may hold. A row a full pool cannot take is refused and counted by the
/// table that asked, as a declaration past that table's bound is. Every face's tables are handed
/// rows of the same pools.
///
/// For a session of one face, a span of each table's own of that face's bound, laid out as the
/// inline tables lay their rows out, with no link and no pool state. Each span is handed to the
/// first tables that ask and to no others, so no two tables lay rows over each other: this is not
/// copied, and tables made after the first are handed nothing and refuse what their peer writes.
///
/// Without `peer-row-pools` (a build of one face) the tables keep those rows inline and there is
/// nothing to lend: this holds nothing and hands nothing out.
#[derive(Debug)]
pub struct PeerPools {
    #[cfg(feature = "peer-row-pools")]
    aliases: RowSource<KeyKind>,
    #[cfg(feature = "peer-row-pools")]
    subscribers: RowSource<KeyKind>,
    #[cfg(feature = "peer-row-pools")]
    queryables: RowSource<QueryableKind>,
    #[cfg(feature = "peer-row-pools")]
    tokens: RowSource<KeyKind>,
    #[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
    sub_repeats: RowSource<RepeatKind>,
    #[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
    queryable_repeats: RowSource<RepeatKind>,
    #[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
    interests: crate::pubsub::InterestRows,
}

/// What each pool of a session's shared [`PeerPools`] holds now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerPoolCounts {
    /// The peers' aliases.
    pub aliases: crate::row_pool::RowCounts,
    /// The peers' subscribers.
    pub subscribers: crate::row_pool::RowCounts,
    /// The peers' queryables.
    pub queryables: crate::row_pool::RowCounts,
    /// The peers' tokens.
    pub tokens: crate::row_pool::RowCounts,
    /// The repeats of the peers' subscribers; nothing without `alloc`.
    pub sub_repeats: crate::row_pool::RowCounts,
    /// The repeats of the peers' queryables; nothing without `alloc`.
    pub queryable_repeats: crate::row_pool::RowCounts,
    /// The peers' subscriber interests; nothing without `declare-subscriber`.
    pub interests: crate::row_pool::RowCounts,
}

impl PeerPools {
    /// Nothing to lend: a build without `peer-row-pools` keeps what the peers write inline in each
    /// face's tables.
    #[cfg(not(feature = "peer-row-pools"))]
    pub fn lent(arena: &mut Arena, rows: PeerPoolRows) -> Result<Self, LendRefused> {
        let _ = (arena, rows);
        Ok(Self {})
    }

    /// The rows `rows` states, lent from `arena` in the order [`PeerPoolRows::arena_bytes`]
    /// counts them: the aliases', the declarations' and the interests'. For a session of one face
    /// each of those is one span, the declaration tables' carved in the order `decl_end` lays
    /// them out. Refused, what was lent so far going back with the arena, when the arena has not
    /// the room or a count is past what a pool or a span names.
    #[cfg(feature = "peer-row-pools")]
    pub fn lent(arena: &mut Arena, rows: PeerPoolRows) -> Result<Self, LendRefused> {
        let decls = rows.remote_decls;
        let mut lend = RowLender::new(arena, rows.shared);
        lend.group(RowSpace::<KeyKind>::own_bytes(rows.aliases));
        let aliases = lend.next(rows.aliases);
        lend.group(decl_end(decls));
        let pools = Self {
            aliases,
            subscribers: lend.next(decls),
            queryables: lend.next(decls),
            tokens: lend.next(decls),
            #[cfg(feature = "alloc")]
            sub_repeats: lend.next(decls),
            #[cfg(feature = "alloc")]
            queryable_repeats: lend.next(decls),
            #[cfg(feature = "declare-subscriber")]
            interests: crate::pubsub::InterestRows::lent(&mut lend, rows.interests),
        };
        lend.finish()?;
        Ok(pools)
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows`. `None` past the most rows a pool
    /// or a span names, or the address space.
    pub const fn arena_bytes(rows: PeerPoolRows) -> Option<usize> {
        rows.arena_bytes()
    }

    /// Whether the faces share these rows; one face's own spans are handed to that face's tables
    /// alone.
    pub fn is_shared(&self) -> bool {
        #[cfg(feature = "peer-row-pools")]
        {
            self.aliases.is_shared()
        }
        #[cfg(not(feature = "peer-row-pools"))]
        {
            false
        }
    }

    /// What each shared pool holds now; `None` for one face's own spans, whose tables say what they
    /// hold.
    #[cfg(not(feature = "peer-row-pools"))]
    pub fn counts(&self) -> Option<PeerPoolCounts> {
        None
    }

    /// What each shared pool holds now; `None` for one face's own spans.
    #[cfg(feature = "peer-row-pools")]
    pub fn counts(&self) -> Option<PeerPoolCounts> {
        Some(PeerPoolCounts {
            aliases: self.aliases.counts()?,
            subscribers: self.subscribers.counts()?,
            queryables: self.queryables.counts()?,
            tokens: self.tokens.counts()?,
            #[cfg(feature = "alloc")]
            sub_repeats: self.sub_repeats.counts()?,
            #[cfg(not(feature = "alloc"))]
            sub_repeats: crate::row_pool::RowCounts::default(),
            #[cfg(feature = "alloc")]
            queryable_repeats: self.queryable_repeats.counts()?,
            #[cfg(not(feature = "alloc"))]
            queryable_repeats: crate::row_pool::RowCounts::default(),
            #[cfg(feature = "declare-subscriber")]
            interests: self.interests.counts()?,
            #[cfg(not(feature = "declare-subscriber"))]
            interests: crate::row_pool::RowCounts::default(),
        })
    }
}

/// The sum of `spans`, or `None` when one is `None` or the sum is past the address space.
const fn sum_spans(spans: &[Option<usize>]) -> Option<usize> {
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
        #[cfg(feature = "declare-subscriber")]
        self.subscribers
            .limit_interests_to(limits.max_inbound_sub_interests_held());
        #[cfg(feature = "declare-subscriber")]
        self.subscribers
            .limit_interest_replies_to(limits.max_pending_declares_held());
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
            .lend_keys(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
            .expect("the arena is the key arena's span")
    }

    /// Pools the faces share of `each` rows of every kind, lent from an arena of their own, so the
    /// arena a peer's tables are lent from is laid out by their plan alone.
    fn pools(each: usize) -> PeerPools {
        rows_of(each, true)
    }

    /// One face's own spans of `each` rows of every kind, lent from an arena of their own.
    #[cfg(feature = "peer-row-pools")]
    fn own_rows(each: usize) -> PeerPools {
        rows_of(each, false)
    }

    fn rows_of(each: usize, shared: bool) -> PeerPools {
        let rows = PeerPoolRows {
            aliases: each,
            remote_decls: each,
            interests: each,
            shared,
        };
        PeerPools::lent(
            &mut arena(PeerPools::arena_bytes(rows).expect("small pools")),
            rows,
        )
        .expect("the arena is the pools' span")
    }

    fn lent(rows: PeerRows) -> PeerTables<Lent> {
        PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys(1024),
            rows,
            &mut pools(16),
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
        let tables = PeerTables::<Lent>::lent(
            &mut memory,
            keys(64),
            rows,
            &mut pools(1),
            &SessionLimits::defaults(),
        )
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
        let mut by_value =
            PeerTables::<Lent>::lent(&mut by_value_memory, keys(64), rows, &mut pools(1), &limits)
                .expect("the rows");
        let mut memory = arena(1 << 16);
        let mut place = MaybeUninit::<PeerTables<Lent>>::uninit();
        let in_place = PeerTables::init_in(&mut place);
        assert!(
            !in_place.finals.has_room(),
            "CONTROL: tables of no rows refuse a Final"
        );
        in_place
            .lend_rows(&mut memory, keys(64), rows, &mut pools(1), &limits)
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
            &mut pools(1),
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
            &mut pools(1),
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
            &mut pools(1),
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
            &mut pools(4),
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
            &mut pools(4),
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
            &mut pools(4),
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

    /// One face's own spans are lent as their plan counts and go to the first tables that ask
    /// alone: every source is spent once they took it, so tables made after them are handed nothing
    /// and no two tables lay rows over each other. A session's shared pools are handed to every
    /// table that asks.
    #[cfg(feature = "peer-row-pools")]
    #[test]
    fn one_faces_own_spans_go_to_the_first_tables_alone() {
        let limits = SessionLimits::defaults();
        let mut own = own_rows(2);
        assert!(!own.is_shared() && own.counts().is_none());
        let _first =
            PeerTables::<Lent>::lent(&mut arena(1 << 16), keys(64), rows(1), &mut own, &limits)
                .expect("the arena has the rows");
        assert!(
            own.aliases.hand_out().is_none()
                && own.subscribers.hand_out().is_none()
                && own.queryables.hand_out().is_none()
                && own.tokens.hand_out().is_none(),
            "the first tables took every span"
        );
        let mut shared = pools(2);
        let _first =
            PeerTables::<Lent>::lent(&mut arena(1 << 16), keys(64), rows(1), &mut shared, &limits)
                .expect("the arena has the rows");
        assert!(
            shared.aliases.hand_out().is_some() && shared.tokens.hand_out().is_some(),
            "a pool goes to every table that asks"
        );
        assert!(shared.is_shared() && shared.counts().is_some());
    }

    /// Faces' tables, each lent its own rows and all keeping what their peers declare in one set of
    /// pools and one key arena.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber",
        feature = "peer-row-pools"
    ))]
    fn faces_sharing(
        count: usize,
        pools: &mut PeerPools,
        keys: KeySpace,
    ) -> std::vec::Vec<PeerTables<Lent>> {
        (0..count)
            .map(|_| {
                PeerTables::<Lent>::lent(
                    &mut arena(1 << 16),
                    keys,
                    rows(1),
                    pools,
                    &SessionLimits::defaults(),
                )
                .expect("the arena has the rows")
            })
            .collect()
    }

    /// Eight faces whose peers each declare two subscribers fit a pool of sixteen rows, where
    /// their bounds add up to eight times `MAX_REMOTE_DECLS`: every one is held and matched, the
    /// ids of one peer apart from another's. The next declaration, on any face, finds the pool full:
    /// it alone is refused, counted by its face's table and by the pool, and every face keeps what
    /// it held; a row another face's peer withdraws takes it.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber",
        feature = "peer-row-pools"
    ))]
    #[test]
    fn many_faces_declaring_a_few_fit_a_pool_far_smaller_than_their_bounds() {
        use crate::transport_profile::owned::DeclareOwnedVariant;
        use wz_session_core_test_support as fx;

        const FACES: usize = 8;
        if caps::MAX_REMOTE_DECLS < 3 {
            // A table of fewer rows refuses the third declaration by itself.
            return;
        }
        let mut shared = pools(FACES * 2);
        let mut faces = faces_sharing(FACES, &mut shared, keys(4096));
        let mut table = RemoteSubscribers::default();
        for (n, tables) in faces.iter_mut().enumerate() {
            for id in 1..=2u64 {
                declare_subscriber(&mut table, tables, id, &std::format!("demo/{n}/{id}"));
            }
        }
        assert_eq!(
            shared.counts().expect("shared pools").subscribers.used,
            FACES * 2
        );
        for (n, tables) in faces.iter().enumerate() {
            assert_eq!(
                (
                    tables.remote_subscribers.declared_count(),
                    tables.remote_subscribers.refusals()
                ),
                (2, 0),
                "face {n} holds both of its peer's subscribers"
            );
            assert!(tables
                .remote_subscribers
                .has_matching(&std::format!("demo/{n}/2")));
            assert!(!tables
                .remote_subscribers
                .has_matching(&std::format!("demo/{}/1", n + 1)));
        }
        declare_subscriber(&mut table, &mut faces[3], 3, "demo/3/3");
        assert_eq!(
            (
                faces[3].remote_subscribers.declared_count(),
                faces[3].remote_subscribers.refusals(),
                shared.counts().expect("shared pools").subscribers.refused,
            ),
            (2, 1, 1),
            "(held, refused by the face's table, refused by the pool)"
        );
        assert!(!faces[3].remote_subscribers.has_matching("demo/3/3"));
        for (n, tables) in faces.iter().enumerate() {
            assert_eq!(
                tables.remote_subscribers.declared_count(),
                2,
                "face {n} kept its rows"
            );
        }
        let none: hashbrown::HashMap<u64, std::string::String> = hashbrown::HashMap::new();
        table.dispatch_declare(
            &mut faces[6].remote_subscribers,
            &DeclareOwnedVariant::CodecZenohUndeclSubscriber(fx::undecl_subscriber(1)),
            &none,
        );
        declare_subscriber(&mut table, &mut faces[3], 3, "demo/3/3");
        assert!(
            faces[3].remote_subscribers.has_matching("demo/3/3"),
            "the row face 6's peer withdrew holds face 3's next subscriber"
        );
        assert_eq!(
            shared.counts().expect("shared pools").subscribers.used,
            FACES * 2
        );
    }

    /// A peer forgotten gives back exactly the rows it held in the session's pools, its aliases',
    /// subscribers' and interests', and the other face's peer keeps every row it held; the rows
    /// given back take the next peer's declarations.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber",
        feature = "peer-row-pools"
    ))]
    #[test]
    fn a_forgotten_peer_gives_back_exactly_its_rows() {
        use crate::pubsub::SubscriberTable;
        use crate::sink::BoxedSink;

        if caps::MAX_REMOTE_DECLS < 3 {
            // A table of fewer rows refuses the third declaration by itself.
            return;
        }
        let mut shared = pools(4);
        let mut faces = faces_sharing(2, &mut shared, keys(4096));
        let mut table = RemoteSubscribers::default();
        let mut interests = SubscriberTable::<BoxedSink>::default();
        declare_alias(&mut faces[0], 1, "demo/a/alias");
        declare_subscriber(&mut table, &mut faces[0], 1, "demo/a/1");
        declare_subscriber(&mut table, &mut faces[0], 2, "demo/a/2");
        interests.respond_to_subscriber_interest_borrowed(
            &mut faces[0].subscribers,
            7,
            Some("demo/a/**"),
            false,
            true,
            true,
        );
        declare_alias(&mut faces[1], 1, "demo/b/alias");
        declare_subscriber(&mut table, &mut faces[1], 1, "demo/b/1");
        let held = shared.counts().expect("shared pools");
        assert_eq!(
            (
                held.aliases.used,
                held.subscribers.used,
                held.interests.used
            ),
            (2, 3, 1),
            "CONTROL: (aliases, subscribers, interests) both peers hold"
        );
        faces[0].forget_peer();
        let left = shared.counts().expect("shared pools");
        assert_eq!(
            (
                left.aliases.used,
                left.subscribers.used,
                left.interests.used
            ),
            (1, 1, 0),
            "the forgotten peer's rows went back, and only those"
        );
        assert!(faces[1].remote_subscribers.has_matching("demo/b/1"));
        assert_eq!(
            faces[1].subscribers.resolve_inbound_mapping(1).as_deref(),
            Some("demo/b/alias")
        );
        for id in 1..=3u64 {
            declare_subscriber(&mut table, &mut faces[0], id, &std::format!("demo/c/{id}"));
        }
        assert_eq!(faces[0].remote_subscribers.declared_count(), 3);
        assert_eq!(
            shared.counts().expect("shared pools").subscribers.refused,
            0,
            "the rows given back took them"
        );
    }

    /// One face's own spans hold what its peer writes to their rows and refuse past them: two
    /// subscribers, an alias and an interest are held, the third subscriber is refused and counted
    /// by its table, and a forgotten peer leaves the rows to the next declarations. They are no
    /// pool: nothing of them is counted as one.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-declare",
        feature = "declare-subscriber",
        feature = "peer-row-pools"
    ))]
    #[test]
    fn a_faces_own_spans_hold_its_peers_rows_and_refuse_past_them() {
        use crate::pubsub::SubscriberTable;
        use crate::sink::BoxedSink;

        if caps::MAX_REMOTE_DECLS < 3 {
            // A table of fewer rows refuses the third declaration by itself.
            return;
        }
        let mut own = own_rows(2);
        assert!(!own.is_shared() && own.counts().is_none());
        let mut tables = PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys(1024),
            rows(1),
            &mut own,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let mut table = RemoteSubscribers::default();
        declare_alias(&mut tables, 9, "demo/own/alias");
        for id in 1..=3u64 {
            declare_subscriber(&mut table, &mut tables, id, &std::format!("demo/own/{id}"));
        }
        assert_eq!(
            (
                tables.remote_subscribers.declared_count(),
                tables.remote_subscribers.refusals()
            ),
            (2, 1),
            "the span's two rows held, the third refused and counted"
        );
        assert_eq!(
            tables.subscribers.resolve_inbound_mapping(9).as_deref(),
            Some("demo/own/alias")
        );
        SubscriberTable::<BoxedSink>::default().respond_to_subscriber_interest_borrowed(
            &mut tables.subscribers,
            7,
            Some("demo/**"),
            false,
            true,
            true,
        );
        assert_eq!(tables.subscribers.interest_count(), 1);
        tables.forget_peer();
        declare_subscriber(&mut table, &mut tables, 3, "demo/own/3");
        assert!(
            tables.remote_subscribers.has_matching("demo/own/3"),
            "the rows a forgotten peer left take the next declaration"
        );
        let mut second = PeerTables::<Lent>::lent(
            &mut arena(1 << 16),
            keys(1024),
            rows(1),
            &mut own,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        declare_subscriber(&mut table, &mut second, 1, "demo/second/1");
        assert_eq!(
            (
                second.remote_subscribers.declared_count(),
                second.remote_subscribers.refusals()
            ),
            (0, 1),
            "tables made after the first are handed none of the face's spans"
        );
        assert!(tables.remote_subscribers.has_matching("demo/own/3"));
    }

    /// One face's own spans and the heads of its tables take no more than the inline tables of the
    /// same bounds did: each table's rows are the inline table's, and the head that points at them
    /// fits in the room the inline table's length, count and padding took. What the spans add is
    /// their rounding to an arena's spans, under one span's alignment for each of the three.
    #[cfg(all(
        feature = "alloc",
        feature = "declare-subscriber",
        feature = "peer-row-pools",
        not(feature = "pool-monitor")
    ))]
    #[test]
    fn one_faces_own_spans_take_no_more_than_the_inline_tables() {
        use crate::id_map::{DeclaredQueryable, FixedIdMap, PooledIdMap};
        use crate::key_arena::KeyRef;
        use crate::row_pool::{PooledRows, Seq};
        use core::mem::size_of;
        const A: usize = caps::MAX_PEER_KEYEXPR_ALIASES;
        const D: usize = caps::MAX_REMOTE_DECLS;
        const I: usize = caps::MAX_INBOUND_SUB_INTERESTS;
        let rows = PeerPoolRows {
            aliases: A,
            remote_decls: D,
            interests: I,
            shared: false,
        };
        let interest_rows = crate::pubsub::InterestRows::own_bytes(I).expect("fits");
        let heads = size_of::<PooledIdMap<KeyRef, A>>()
            + 2 * size_of::<PooledIdMap<KeyRef, D>>()
            + size_of::<PooledIdMap<DeclaredQueryable<Lent>, D>>()
            + 2 * size_of::<PooledRows<Seq<(u64, u64)>, D>>()
            + size_of::<PooledRows<Seq<u64>, I>>();
        let laid = RowSpace::<KeyKind>::own_bytes(A).expect("fits")
            + decl_end(D).expect("fits")
            + interest_rows;
        let inline = size_of::<FixedIdMap<KeyRef, A>>()
            + 2 * size_of::<FixedIdMap<KeyRef, D>>()
            + size_of::<FixedIdMap<DeclaredQueryable<Lent>, D>>()
            + 2 * size_of::<crate::bounded::BoundedVec<(u64, u64), D, Static>>()
            + size_of::<crate::bounded::BoundedVec<u8, 1, Lent>>()
            + span_of(Some(interest_rows)).expect("fits");
        assert!(
            heads + laid <= inline,
            "heads {heads} and rows {laid} against the inline tables' {inline}"
        );
        let rounding = rows.arena_bytes().expect("fits") - laid;
        assert!(rounding < 3 * ARENA_ALIGN, "{rounding} bytes of rounding");
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
