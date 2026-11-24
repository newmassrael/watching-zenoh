// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The legs of a session's gets still pending on its faces: for each, the face it was asked of, the
//! id its callback is held under, the entry of the face's table of pending gets it was registered
//! under ([`GetKind`]) and the key of the fan that cancels it, when a token can.
//!
//! A leg's row ends when its entry is dropped from its face's table ([`PendingGet::unregister`]):
//! the entry's sink says the leg's end. The rows are lent from the session's arena, one for each
//! entry the faces' tables can hold, so a leg the tables admitted always finds a row.

use crate::bounded::{BoundedVec, CapacityFull, Storage};
#[cfg(feature = "storage-profile")]
use crate::reply_sink::ReplySink;
#[cfg(feature = "storage-profile")]
use crate::slot_observer::{NoRequesters, Requesters};
use crate::wire_id::RequestId;

/// Which of a face's tables of pending gets a leg's entry is in, and the id it is registered under
/// there: each kind's id is its own type, so one cannot be looked up as the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetKind {
    /// A query: its entry is under its request id, and its peer owes a Final.
    Query(RequestId),
    /// A liveliness snapshot: its entry is under its Interest id, and its peer owes a DeclFinal.
    #[cfg(feature = "liveliness-get")]
    Liveliness(u64),
}

/// A leg the session has pending, `F` the key of the fan that cancels it.
#[derive(Debug)]
pub struct PendingGet<F> {
    /// The face the leg was asked of.
    pub face: u64,
    /// The id the leg's callback is held under.
    pub leg: u64,
    /// The entry of the face's tables the leg is registered under.
    pub kind: GetKind,
    /// The key of the fan that cancels the leg, when a token can.
    pub fan: Option<F>,
}

impl<F> PendingGet<F> {
    /// Drop this leg's entry from its face's pending gets, which ends the leg (its sink's guard
    /// says so). A face the session no longer holds took its entries with it.
    pub fn unregister(&self, faces: &mut (impl SessionFaces + ?Sized)) {
        faces.end_leg(self.face, self.kind);
    }
}

/// The rows a session holds its pending legs in: a table its arena lent, or `()` for a session
/// that asks no get and holds none.
pub trait PendingLegs {
    /// The key of the fan that cancels a leg.
    type Fan;

    /// Hold `leg`, or hand it back when every row is taken.
    fn note(&mut self, leg: PendingGet<Self::Fan>) -> Result<(), PendingGet<Self::Fan>>;

    /// Take out every leg asked of `face`, each handed to `gone`, the rest kept in their order.
    fn drop_face(&mut self, face: u64, gone: impl FnMut(PendingGet<Self::Fan>));
}

impl<F, const N: usize, P: Storage> PendingLegs for BoundedVec<PendingGet<F>, N, P> {
    type Fan = F;

    fn note(&mut self, leg: PendingGet<F>) -> Result<(), PendingGet<F>> {
        self.push(leg).map_err(|CapacityFull(leg)| leg)
    }

    fn drop_face(&mut self, face: u64, mut gone: impl FnMut(PendingGet<F>)) {
        let mut at = 0;
        while at < self.len() {
            if self[at].face == face {
                gone(self.remove(at));
            } else {
                at += 1;
            }
        }
    }
}

impl PendingLegs for () {
    type Fan = core::convert::Infallible;

    fn note(&mut self, leg: PendingGet<Self::Fan>) -> Result<(), PendingGet<Self::Fan>> {
        Err(leg)
    }

    fn drop_face(&mut self, _face: u64, _gone: impl FnMut(PendingGet<Self::Fan>)) {}
}

/// The faces of a session as its state reaches them: what each face's peer declared and the
/// session's gets pending on it, which the engine's registry keeps.
pub trait SessionFaces {
    /// The entry `kind` names is no longer pending on face `face`; a face the session no longer
    /// holds took its entries with it.
    fn end_leg(&mut self, face: u64, kind: GetKind);

    /// What the peer of face `face` declared goes with its link: its subscribers and queryables,
    /// and its tokens, retracted as the round of deliveries takes each.
    fn lose_face(&mut self, face: u64);

    /// When the earliest get pending on any face is due.
    fn next_get_deadline_ms(&self) -> Option<u64>;
}

/// A face's tables of pending gets, as a leg's entry is ended in them and their earliest deadline
/// read.
pub trait LegTables {
    /// The entry `kind` names is no longer pending here.
    fn end_leg(&mut self, kind: GetKind);

    /// When the earliest entry here is due: a query's or a liveliness snapshot's.
    fn next_deadline_ms(&self) -> Option<u64>;
}

#[cfg(feature = "storage-profile")]
impl<R: ReplySink, G: ReplySink, P: Storage> LegTables for Requesters<R, G, P> {
    fn end_leg(&mut self, kind: GetKind) {
        match kind {
            GetKind::Query(rid) => {
                self.replies.unregister(rid);
            }
            #[cfg(feature = "liveliness-get")]
            GetKind::Liveliness(interest_id) => {
                self.liveliness_gets.unregister(interest_id);
            }
        }
    }

    fn next_deadline_ms(&self) -> Option<u64> {
        let queries = self.replies.next_deadline_ms();
        #[cfg(feature = "liveliness-get")]
        let snapshots = self.liveliness_gets.next_deadline_ms();
        #[cfg(not(feature = "liveliness-get"))]
        let snapshots = None;
        queries.into_iter().chain(snapshots).min()
    }
}

#[cfg(feature = "storage-profile")]
impl LegTables for NoRequesters {
    fn end_leg(&mut self, _kind: GetKind) {}

    fn next_deadline_ms(&self) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Static;
    use std::vec::Vec;

    fn leg(face: u64, leg: u64) -> PendingGet<u8> {
        PendingGet {
            face,
            leg,
            kind: GetKind::Query(leg as RequestId),
            fan: None,
        }
    }

    /// A table holds legs to its rows and hands back the one past them.
    #[test]
    fn a_full_table_hands_the_leg_back() {
        let mut legs = BoundedVec::<PendingGet<u8>, 2, Static>::new();
        assert!(legs.note(leg(1, 1)).is_ok());
        assert!(legs.note(leg(1, 2)).is_ok());
        let refused = legs.note(leg(2, 3)).unwrap_err();
        assert_eq!((refused.face, refused.leg), (2, 3));
        assert_eq!(legs.len(), 2);
    }

    /// The legs of a lost face are taken out, each once, and the others keep their order.
    #[test]
    fn the_legs_of_a_lost_face_go_and_the_rest_keep_their_order() {
        let mut legs = BoundedVec::<PendingGet<u8>, 8, Static>::new();
        for (face, id) in [(1, 1), (2, 2), (1, 3), (3, 4), (1, 5)] {
            legs.note(leg(face, id)).unwrap();
        }
        let mut gone = Vec::new();
        legs.drop_face(1, |leg| gone.push(leg.leg));
        assert_eq!(gone, [1, 3, 5]);
        let kept: Vec<u64> = legs.iter().map(|leg| leg.leg).collect();
        assert_eq!(kept, [2, 4]);
        legs.drop_face(9, |_| panic!("no leg was asked of face 9"));
        assert_eq!(legs.len(), 2);
    }

    /// A session that holds no legs refuses each and has none to drop.
    #[test]
    fn no_rows_hold_no_leg() {
        let refused = PendingLegs::note(
            &mut (),
            PendingGet {
                face: 1,
                leg: 1,
                kind: GetKind::Query(1),
                fan: None,
            },
        )
        .unwrap_err();
        assert_eq!(refused.leg, 1);
        PendingLegs::drop_face(&mut (), 1, |_| unreachable!());
    }

    /// A leg's entry is ended in the tables of the face it was asked of, under its kind.
    #[test]
    fn a_leg_is_unregistered_from_its_face_under_its_kind() {
        struct Ends(Vec<(u64, GetKind)>);
        impl SessionFaces for Ends {
            fn end_leg(&mut self, face: u64, kind: GetKind) {
                self.0.push((face, kind));
            }

            fn lose_face(&mut self, _face: u64) {}

            fn next_get_deadline_ms(&self) -> Option<u64> {
                None
            }
        }
        let mut ends = Ends(Vec::new());
        leg(4, 7).unregister(&mut ends);
        assert_eq!(ends.0, [(4, GetKind::Query(7))]);
    }
}
