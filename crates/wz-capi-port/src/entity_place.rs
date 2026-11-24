// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The places an engine lends an ABI for its objects of a session's entities: an engine whose
//! session reserves its memory at its open lays a place out for each entity its limits admit, so the
//! ABI's object for an entity lies in that session's memory and no other's ([`PlaceLender`]).

use core::ptr::NonNull;

/// How many kinds of entity an ABI may hold places of its own for ([`EntityKind`]).
pub const ENTITY_KINDS: usize = 6;

/// A kind of the session's own entities whose rows an ABI may hold a place of its own beside, one
/// for each the session's limit of the kind admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityKind {
    /// A publisher (`MAX_PUBLISHERS`).
    Publisher,
    /// A subscriber (`MAX_SUBSCRIPTIONS`).
    Subscriber,
    /// A queryable (`MAX_QUERYABLES`).
    Queryable,
    /// A liveliness token (`MAX_LOCAL_TOKENS`).
    Token,
    /// A liveliness subscriber (`MAX_LIVELINESS_SUBSCRIPTIONS`).
    LivelinessSubscriber,
    /// A querier (`MAX_QUERIERS`).
    Querier,
}

impl EntityKind {
    /// Every kind, in the order an engine lays their places out.
    pub const ALL: [Self; ENTITY_KINDS] = [
        Self::Publisher,
        Self::Subscriber,
        Self::Queryable,
        Self::Token,
        Self::LivelinessSubscriber,
        Self::Querier,
    ];
}

/// One place a session lent the ABI for an entity of a kind ([`PlaceLender::claim_place`]), held by
/// the ABI's object of the entity: its first byte, aligned as the session's memory lays a place
/// out and holding the layout the open was given for the kind, and the kind. Neither copied nor
/// cloned, so a place is given back once, and only to the session and the kind that lent it, as
/// giving it back consumes it ([`PlaceLender::give_back_place`]).
#[derive(Debug, PartialEq, Eq)]
pub struct EntityPlace {
    base: NonNull<u8>,
    kind: EntityKind,
}

// SAFETY: a place is an address in a session's memory and its kind; the lender touches its bytes
// never and its flag only under the session's lock, so handing the place to another thread shares
// nothing.
unsafe impl Send for EntityPlace {}
// SAFETY: as for `Send`: a shared place is read only as an address.
unsafe impl Sync for EntityPlace {}

impl EntityPlace {
    /// The place at `base` a lender lent for an entity of `kind`.
    ///
    /// # Safety
    /// `base` is the first byte of a place the lender lent for `kind` now, and no other
    /// `EntityPlace` names it: the one token of the claim.
    pub unsafe fn lent(base: NonNull<u8>, kind: EntityKind) -> Self {
        Self { base, kind }
    }

    /// Where the place starts.
    pub fn as_ptr(&self) -> NonNull<u8> {
        self.base
    }

    /// The kind it was lent for.
    pub fn kind(&self) -> EntityKind {
        self.kind
    }
}

/// An engine that lends an ABI places for its objects of the session's entities, from memory the
/// session reserved at its open ([`crate::SessionEngine::place_lender`]).
pub trait PlaceLender {
    /// A place for one of the session's entities of `kind`, closed or not: `None` when every one
    /// is lent, or when the open laid out none of the kind. A closed session's declaration is
    /// refused by the declaration itself, which answers it as it would with a place to spare.
    fn claim_place(&self, kind: EntityKind) -> Option<EntityPlace>;

    /// Give back `place`, closed or not, or hand it back untouched when it is no place this
    /// session lent. What the ABI kept at the place it lets go of first.
    fn give_back_place(&self, place: EntityPlace) -> Result<(), EntityPlace>;
}

/// An engine that lends an ABI rows for the samples its advanced publishers' caches keep, from
/// memory the session reserved at its open: as many as `ADVANCED_CACHE_ROWS` admits, each of the
/// layout the open was given for them, so a cache's put copies its sample into the session's memory
/// and takes none of its own ([`crate::SessionEngine::cache_row_lender`]).
pub trait CacheRowLender {
    /// A free row, closed or not: `None` when every one is lent, or when the open laid out none.
    fn claim_cache_row(&self) -> Option<NonNull<u8>>;

    /// Give back `row`, closed or not: `false`, and the row stays lent, when it is no row this
    /// session lent.
    ///
    /// # Safety
    /// `row` is a row a session lent the ABI and the ABI has not given back, and nothing lies there
    /// any more.
    unsafe fn give_back_cache_row(&self, row: NonNull<u8>) -> bool;
}
