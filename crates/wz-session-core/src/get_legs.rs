// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The legs of the gets pending on one face: for each, the id the face's peer answers it under
//! and the get it is a leg of, a row of the session's tables; and how a Response of that peer is
//! read ([`ReplyReceive`]).
//!
//! What a get is (the key its replies must intersect, its consolidation, its deadline, its
//! callback, how many of its legs still owe a Final) is its row's. A face holds only what it alone
//! can say: which of its peer's answers names which get, and how many Finals the face still owes
//! each leg: one for a link or the session's own queryables, one for each member a group holds
//! when the get is asked. A leg is ended by its last Final or by the loss of its face, and handed
//! back for the caller to end on the get's row, which counts legs and not Finals; a get its row
//! retires before that is forgotten here.
//!
//! The table is bounded by the gets it names: a get has at most one leg on a face, so a face never
//! holds more legs than the session holds gets, and the table states no quota of its own.

use crate::bounded::{Arena, BoundedVec, LendRefused, Lent, Profile, Storage};
use crate::caps;
use crate::reply::ReplyReceive;
use crate::reply_sink::ReplyView;
use crate::wire_id::{request_row, RequestId};

/// One leg: the id its query carries to the face's peer, the get it is a leg of, and the Finals
/// the face still owes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GetLeg<H> {
    id: RequestId,
    get: H,
    finals: u32,
}

/// The legs of the gets pending on one face, and the read of its peer's Responses. See the module.
pub struct GetLegs<H, P: Storage = Profile> {
    legs: BoundedVec<GetLeg<H>, { caps::MAX_PENDING_QUERIES }, P>,
    receive: ReplyReceive,
}

impl<H, P: Storage> Default for GetLegs<H, P> {
    fn default() -> Self {
        Self {
            legs: BoundedVec::default(),
            receive: ReplyReceive::default(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<H> GetLegs<H, crate::bounded::OnUse> {
    /// An empty table of at most `rows` legs, under `MAX_PENDING_QUERIES`, taken at its first
    /// leg: the gets a session holds pending on one face, at its open. Nothing is taken, so
    /// nothing is refused here: a leg past the count, or one the allocator has no room for, is
    /// refused when it is held.
    pub fn counted(rows: usize) -> Self {
        Self {
            legs: BoundedVec::counted(rows),
            receive: ReplyReceive::default(),
        }
    }
}

/// The rows of a [`GetLegs`] of the region policy, which a region lays out beside it: its legs',
/// at the build's bound.
pub struct GetLegsRows<H> {
    legs: [core::mem::MaybeUninit<GetLeg<H>>; caps::MAX_PENDING_QUERIES],
}

// SAFETY: the rows are `MaybeUninit`, valid as any bytes, holding no value until placed.
unsafe impl<H> crate::bounded::ZeroEmpty for GetLegsRows<H> {}

/// The lines a region's description holds for one [`GetLegs`] of the region policy: its legs'
/// rows. A leg keeps no key, so the table holds no handle to the region's key arena.
pub const GET_LEGS_LINES: usize = 1;

impl<H> GetLegs<H, crate::bounded::Region> {
    /// The description of a table of the region policy at `at` in a region and its
    /// [`GetLegsRows`] at `rows`: the line of its legs' rows. The table is written as
    /// [`Default`] makes one before the region is placed, since the receive's key gate is not
    /// zero bytes. The table states no quota of its own (see the module), so nothing holds it to
    /// the session's limits after.
    pub const fn places(at: usize, rows: usize) -> crate::bounded::RegionLines<GET_LEGS_LINES> {
        crate::bounded::RegionLines::EMPTY.seq(crate::bounded::SeqPlace::of_room::<
            GetLeg<H>,
            { caps::MAX_PENDING_QUERIES },
        >(
            at.wrapping_add(core::mem::offset_of!(Self, legs)),
            rows.wrapping_add(core::mem::offset_of!(GetLegsRows<H>, legs)),
        ))
    }
}

impl<H> GetLegs<H, Lent> {
    /// An empty table whose legs are `rows` rows lent from `arena`, at most
    /// `MAX_PENDING_QUERIES`: the gets the session holds pending on one face, at its open.
    /// Refused, taking nothing, past that ceiling or past what the arena has left.
    pub fn lent(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        Ok(Self {
            legs: arena.lend(rows)?,
            receive: ReplyReceive::default(),
        })
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows` rows. `None` past the address space.
    pub const fn arena_bytes(rows: usize) -> Option<usize> {
        Arena::table_bytes::<GetLeg<H>>(rows)
    }
}

impl<H: Copy + Eq, P: Storage> GetLegs<H, P> {
    /// How a Response of the face's peer is read: its key gate and shared memory.
    pub fn receive(&self) -> &ReplyReceive {
        &self.receive
    }

    /// See [`Self::receive`].
    pub fn receive_mut(&mut self) -> &mut ReplyReceive {
        &mut self.receive
    }

    /// Whether one more leg may be held: a row its storage has free.
    pub fn has_room(&self) -> bool {
        self.legs.free_slots() > 0
    }

    /// The row the next leg is held in: what an id that names its leg's row carries
    /// ([`crate::wire_id::request_id_at`]).
    pub fn next_row(&self) -> usize {
        self.legs.len()
    }

    /// Hold a leg of `get` whose query carries `id`, owing the face's one Final: whether it was
    /// held. A table with no row free holds none, and the caller's get has one leg fewer.
    pub fn hold(&mut self, id: RequestId, get: H) -> bool {
        self.hold_owing(id, get, 1)
    }

    /// Hold a leg of `get` whose query carries `id` to every peer the face reaches, owing a Final
    /// of each of `finals` of them (a group's members when the get is asked): whether it was held.
    /// A leg owing none is not held, as it would never end; a table with no row free holds none.
    pub fn hold_owing(&mut self, id: RequestId, get: H, finals: u32) -> bool {
        finals > 0 && self.legs.push(GetLeg { id, get, finals }).is_ok()
    }

    /// The row of the leg `id` names: the row the id carries when the leg is still in it, else
    /// the first leg of the id (one an earlier end moved toward the front).
    fn row_of(&self, id: RequestId) -> Option<usize> {
        let carried = request_row(id);
        if self.legs.get(carried).is_some_and(|leg| leg.id == id) {
            return Some(carried);
        }
        self.legs.iter().position(|leg| leg.id == id)
    }

    /// The get the answer carrying `id` is for, `None` for an id no leg holds.
    pub fn get_of(&self, id: RequestId) -> Option<H> {
        self.row_of(id)
            .and_then(|at| self.legs.get(at))
            .map(|leg| leg.get)
    }

    /// The get a reply of the face's peer is handed to: `None` for a reply on a key the face's key
    /// gate drops (counted there) and for one whose id no leg holds. The get's row says whether it
    /// takes the reply.
    pub fn reply_to(&mut self, reply: &dyn ReplyView) -> Option<H> {
        if !self.receive.admits_key(reply) {
            return None;
        }
        self.get_of(reply.rid())
    }

    /// A Final of the leg `id` names came: the leg ends at the last it owes, and its get is handed
    /// back for the caller to end the leg on its row. `None` for a Final the leg owes more after,
    /// and for an id no leg holds, a Final past the last among them.
    pub fn end_leg(&mut self, id: RequestId) -> Option<H> {
        let at = self.row_of(id)?;
        let leg = self.legs.get_mut(at)?;
        leg.finals = leg.finals.saturating_sub(1);
        if leg.finals > 0 {
            return None;
        }
        Some(self.legs.remove(at).get)
    }

    /// Let go of every leg of `get`, which its row retired: how many there were. No Final it is
    /// still owed is waited on.
    pub fn forget(&mut self, get: H) -> usize {
        let before = self.legs.len();
        self.legs.retain(|leg| leg.get != get);
        before.saturating_sub(self.legs.len())
    }

    /// The face is lost and its peer sends no Final now: every leg is ended, each get handed to
    /// `ended` for the caller to end the leg on its row. The rows stay the table's.
    pub fn end_every_leg(&mut self, mut ended: impl FnMut(H)) {
        for leg in self.legs.iter() {
            ended(leg.get);
        }
        self.legs.clear();
    }

    /// How many legs are held.
    pub fn len(&self) -> usize {
        self.legs.len()
    }

    /// Whether no leg is held.
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }
}

#[cfg(test)]
mod tests;
