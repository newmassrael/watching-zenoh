// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The legs of a session's gets still pending on its faces: for each, the face it was asked of, the
//! id its callback is held under, the entry of the face's table of pending gets it was registered
//! under ([`GetKind`]) and the key of the fan that cancels it, when a token can.
//!
//! A leg's row ends when its entry is dropped from its face's table ([`PendingGet::unregister`]):
//! the entry's sink says the leg's end. The rows are lent from the session's arena, one for each
//! entry the faces' tables can hold, so a leg the tables admitted always finds a row.
//!
//! [`GetKind`]: crate::pending_get::GetKind
//! [`PendingGet::unregister`]: crate::pending_get::PendingGet::unregister

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
        while let Some(leg) = self.get(at) {
            if leg.face == face {
                gone(self.remove(at));
            } else {
                at = at.saturating_add(1);
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

    /// When the earliest get pending on any face is due. To write: the faces may keep a bound of
    /// it that an end of a get was not told to, which the read brings up to date ([`DueIndex`]).
    fn next_get_deadline_ms(&mut self) -> Option<u64>;

    /// Retract the tokens the peers of lost links declared, a token at a time while `room` says
    /// the round of deliveries takes its `Delete` now: whether none is owed any more. Faces that
    /// keep no token owe none and ask no room.
    fn retract_owed(&mut self, _room: &mut dyn FnMut() -> bool) -> bool {
        true
    }
}

/// A face's tables of pending gets, as a leg's entry is ended in them and their earliest deadline
/// read.
pub trait LegTables {
    /// The entry `kind` names is no longer pending here.
    fn end_leg(&mut self, kind: GetKind);

    /// When the earliest entry here is due: a query's or a liveliness snapshot's, as each table
    /// keeps it, with no walk of the entries.
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
        let due_ms = self.replies.due_ms();
        #[cfg(feature = "liveliness-get")]
        let due_ms = due_ms.min(self.liveliness_gets.due_ms());
        (due_ms != u64::MAX).then_some(due_ms)
    }
}

#[cfg(feature = "storage-profile")]
impl LegTables for NoRequesters {
    fn end_leg(&mut self, _kind: GetKind) {}

    fn next_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// A row of a session's index of the earliest deadline of its gets ([`DueIndex`]), one for each
/// table of pending gets the session keeps: the key of that table's leaf, and the leaf that wins
/// the node of the index's tree the row keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DueRow {
    /// Never later than the earliest deadline the row's table holds, `u64::MAX` for never.
    key: u64,
    /// The leaf that wins the row's node.
    winner: usize,
}

impl DueRow {
    /// The row of a table that holds no deadline, its node not yet played ([`DueIndex::reset`]).
    pub const NEVER: Self = Self {
        key: u64::MAX,
        winner: 0,
    };
}

/// A session's index of the earliest deadline of its gets: a tree of winners over its tables of
/// pending gets (Knuth, TAOCP vol. 3, 5.4.1), a leaf for each table and a node for each leaf but
/// one, whose root names the table with the earliest key. The membership is fixed at the open, so
/// a key that moves replays the path from its leaf alone, and the root is read with no walk.
///
/// A leaf's key is never later than its table's earliest deadline. A write that may add a deadline
/// lowers it at once ([`Self::lower`]); an end, which only moves a table's earliest deadline later,
/// is not told: the key stays a bound until the leaf comes to the root, where [`Self::earliest`]
/// reads the table and raises it. A root whose key is its table's is then the earliest of all,
/// since no other key is later than its own table's.
///
/// The holder of the tables keeps the rows ([`Self::row`]): leaf `n` keys row `n`, and node `n`
/// (from 1, below [`Self::leaves`]) is kept by row `n - 1`.
pub trait DueIndex {
    /// How many tables the index keeps a leaf for: one at least.
    fn leaves(&self) -> usize;

    /// Row `at`, `None` past the rows.
    fn row(&self, at: usize) -> Option<&DueRow>;

    /// Row `at` to write, `None` past the rows.
    fn row_mut(&mut self, at: usize) -> Option<&mut DueRow>;

    /// The earliest deadline table `leaf` holds now, `u64::MAX` with none, read with no walk of
    /// its entries ([`LegTables::next_deadline_ms`]).
    fn due(&self, leaf: usize) -> u64;

    /// Every leaf's key never and every node played from its children: the index of tables that
    /// hold no deadline, which is how an open finds them.
    fn reset(&mut self) {
        let leaves = self.leaves();
        for at in 0..leaves {
            if let Some(row) = self.row_mut(at) {
                *row = DueRow::NEVER;
            }
        }
        // From the last node up, so each is played after both its children.
        for node in (1..leaves).rev() {
            play(self, node);
        }
    }

    /// Bring leaf `leaf`'s key down to the earliest deadline its table holds now, never up: what a
    /// write that may have added a deadline to the table owes the index.
    fn lower(&mut self, leaf: usize) {
        let due = self.due(leaf);
        let Some(row) = self.row_mut(leaf).filter(|row| due < row.key) else {
            return;
        };
        row.key = due;
        replay(self, leaf);
    }

    /// The earliest deadline any table holds, `None` when none holds one. The root's table is read
    /// and, while its key is earlier than the table's deadline (an end the index was not told of),
    /// the key is raised to it and its path replayed; each leaf is raised once at most, as a key
    /// raised is its table's.
    fn earliest(&mut self) -> Option<u64> {
        loop {
            let leaf = champion(self, 1);
            let key = key_of(self, leaf);
            if key == u64::MAX {
                return None;
            }
            let due = self.due(leaf);
            if due == key {
                return Some(key);
            }
            let row = self.row_mut(leaf)?;
            row.key = due;
            replay(self, leaf);
        }
    }

    /// The leaf of a table that holds a deadline at or before `now_ms`, `None` when none does: the
    /// table a sweep at `now_ms` ends a get in, after which its leaf is not named again for it.
    fn due_by(&mut self, now_ms: u64) -> Option<usize> {
        let earliest = self.earliest()?;
        (earliest <= now_ms).then(|| champion(self, 1))
    }
}

/// The key of leaf `leaf`, never for a leaf past the rows.
fn key_of<I: DueIndex + ?Sized>(index: &I, leaf: usize) -> u64 {
    index.row(leaf).map_or(u64::MAX, |row| row.key)
}

/// The leaf that wins position `at` of the tree: positions from `leaves` on are the leaves, in
/// their order, and those below it the nodes, the root at 1 and the children of `n` at `2n` and
/// `2n + 1`.
fn champion<I: DueIndex + ?Sized>(index: &I, at: usize) -> usize {
    let leaves = index.leaves();
    if at >= leaves {
        at.wrapping_sub(leaves)
    } else {
        index.row(at.wrapping_sub(1)).map_or(0, |row| row.winner)
    }
}

/// Play node `node` again from its children: the earlier key wins, the left child on a tie.
fn play<I: DueIndex + ?Sized>(index: &mut I, node: usize) {
    let left = champion(index, node << 1);
    let right = champion(index, (node << 1) | 1);
    let winner = if key_of(index, right) < key_of(index, left) {
        right
    } else {
        left
    };
    if let Some(row) = index.row_mut(node.wrapping_sub(1)) {
        row.winner = winner;
    }
}

/// Play every node on the path from leaf `leaf` to the root again, after its key moved.
fn replay<I: DueIndex + ?Sized>(index: &mut I, leaf: usize) {
    let mut node = leaf.wrapping_add(index.leaves()) >> 1;
    while node != 0 {
        play(index, node);
        node >>= 1;
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
        let mut legs = BoundedVec::<PendingGet<u8>, 2, Static>::new_static();
        assert!(legs.note(leg(1, 1)).is_ok());
        assert!(legs.note(leg(1, 2)).is_ok());
        let refused = legs.note(leg(2, 3)).unwrap_err();
        assert_eq!((refused.face, refused.leg), (2, 3));
        assert_eq!(legs.len(), 2);
    }

    /// The legs of a lost face are taken out, each once, and the others keep their order.
    #[test]
    fn the_legs_of_a_lost_face_go_and_the_rest_keep_their_order() {
        let mut legs = BoundedVec::<PendingGet<u8>, 8, Static>::new_static();
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

            fn next_get_deadline_ms(&mut self) -> Option<u64> {
                None
            }
        }
        let mut ends = Ends(Vec::new());
        leg(4, 7).unregister(&mut ends);
        assert_eq!(ends.0, [(4, GetKind::Query(7))]);
    }

    /// Faces that keep no token owe no retraction and ask the round for no room.
    #[test]
    fn faces_that_keep_no_token_owe_no_retraction() {
        struct Tokenless;
        impl SessionFaces for Tokenless {
            fn end_leg(&mut self, _face: u64, _kind: GetKind) {}

            fn lose_face(&mut self, _face: u64) {}

            fn next_get_deadline_ms(&mut self) -> Option<u64> {
                None
            }
        }
        let mut asked = false;
        assert!(Tokenless.retract_owed(&mut || {
            asked = true;
            false
        }));
        assert!(!asked, "no room asked");
    }

    /// Tables of pending gets as a test states their earliest deadlines, and their index's rows.
    struct Tables {
        dues: Vec<u64>,
        rows: Vec<DueRow>,
    }

    impl Tables {
        /// `leaves` tables that hold no deadline, indexed as an open finds them.
        fn none(leaves: usize) -> Self {
            let mut tables = Self {
                dues: (0..leaves).map(|_| u64::MAX).collect(),
                rows: (0..leaves).map(|_| DueRow::NEVER).collect(),
            };
            tables.reset();
            tables
        }

        /// Table `leaf` takes a get due at `due_ms`, and the index is told.
        fn hold(&mut self, leaf: usize, due_ms: u64) {
            self.dues[leaf] = self.dues[leaf].min(due_ms);
            self.lower(leaf);
        }

        /// What a walk of the tables reads.
        fn walked(&self) -> Option<u64> {
            self.dues
                .iter()
                .copied()
                .min()
                .filter(|due| *due != u64::MAX)
        }
    }

    impl DueIndex for Tables {
        fn leaves(&self) -> usize {
            self.rows.len()
        }

        fn row(&self, at: usize) -> Option<&DueRow> {
            self.rows.get(at)
        }

        fn row_mut(&mut self, at: usize) -> Option<&mut DueRow> {
            self.rows.get_mut(at)
        }

        fn due(&self, leaf: usize) -> u64 {
            self.dues.get(leaf).copied().unwrap_or(u64::MAX)
        }
    }

    /// Tables that hold no deadline answer none, and name no table due at any time. Turned red by
    /// a reset that leaves a key below never.
    #[test]
    fn an_index_of_tables_with_no_deadline_answers_none() {
        let mut tables = Tables::none(5);
        assert_eq!(tables.earliest(), None);
        assert_eq!(tables.due_by(u64::MAX), None);
    }

    /// A deadline held lowers the index at once, and an end the index is not told of is read when
    /// it is asked: the earliest left, and none once every table is empty. Turned red by a hold
    /// that does not lower its leaf, or by a root whose key is answered without its table read.
    #[test]
    fn a_held_deadline_lowers_the_index_and_an_untold_end_is_read_at_the_root() {
        let mut tables = Tables::none(5);
        tables.hold(3, 300);
        tables.hold(1, 100);
        assert_eq!(tables.earliest(), Some(100));
        tables.dues[1] = u64::MAX;
        assert_eq!(tables.earliest(), Some(300), "the ended get's deadline");
        tables.dues[3] = 500;
        assert_eq!(tables.earliest(), Some(500), "the table's later get");
        tables.hold(0, 50);
        assert_eq!(tables.earliest(), Some(50));
        tables.dues[0] = u64::MAX;
        tables.dues[3] = u64::MAX;
        assert_eq!(tables.earliest(), None, "every get ended");
    }

    /// A lowering never raises a key: a table whose deadline moved later keeps its bound until
    /// the root reads it. Turned red by a lowering that writes a later deadline.
    #[test]
    fn a_lowering_never_raises_a_key() {
        let mut tables = Tables::none(3);
        tables.hold(2, 100);
        tables.dues[2] = 400;
        tables.lower(2);
        assert_eq!(tables.rows[2].key, 100, "lowered to a later deadline");
        assert_eq!(tables.earliest(), Some(400));
        assert_eq!(tables.rows[2].key, 400, "the root's read raised it");
    }

    /// The table a sweep is due in is named once its deadline comes and not before, and once its
    /// gets are swept the next one is. Turned red by a due leaf read off a stale key.
    #[test]
    fn due_by_names_the_table_whose_deadline_came() {
        let mut tables = Tables::none(4);
        tables.hold(0, 400);
        tables.hold(2, 200);
        assert_eq!(tables.due_by(199), None, "CONTROL: nothing is due yet");
        assert_eq!(tables.due_by(200), Some(2));
        tables.dues[2] = u64::MAX;
        assert_eq!(tables.due_by(200), None, "the swept table is named again");
        assert_eq!(tables.due_by(400), Some(0));
    }

    /// One table needs no node: its leaf is the root.
    #[test]
    fn an_index_of_one_table_is_its_leaf() {
        let mut tables = Tables::none(1);
        assert_eq!(tables.earliest(), None);
        tables.hold(0, 70);
        assert_eq!(tables.earliest(), Some(70));
        assert_eq!(tables.due_by(70), Some(0));
        tables.dues[0] = u64::MAX;
        assert_eq!(tables.earliest(), None);
    }

    /// For every count of tables up to nine, a run of holds and of ends the index is not told of
    /// answers at each step what a walk of the tables reads. Turned red by a node played from the
    /// wrong children, a path replayed short of the root, or a tie that loses a table.
    #[test]
    fn the_index_answers_what_a_walk_of_the_tables_reads() {
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for leaves in 1..=9u64 {
            let mut tables = Tables::none(leaves as usize);
            for _ in 0..400 {
                let leaf = (next() % leaves) as usize;
                if next() % 3 == 0 {
                    let current = tables.dues[leaf];
                    tables.dues[leaf] = if next() % 2 == 0 {
                        u64::MAX
                    } else {
                        current.max(next() % 1_000)
                    };
                } else {
                    tables.hold(leaf, next() % 1_000);
                }
                assert_eq!(tables.earliest(), tables.walked(), "{leaves} tables");
            }
        }
    }

    /// A face's tables answer the earliest deadline still pending in either of them, as each
    /// keeps it: a query's Final hands the earliest to the snapshot's, and none is left once each
    /// table's legs ended. Turned red by a table that keeps the deadline of an entry gone, or by
    /// a read of the queries' table alone.
    #[cfg(all(feature = "storage-profile", feature = "alloc"))]
    #[test]
    fn a_faces_tables_answer_the_earliest_deadline_left_in_either() {
        use crate::reply_acceptance::ReplyAcceptance;
        use crate::reply_sink::BoxedReplySink;
        fn sink() -> BoxedReplySink {
            BoxedReplySink::new(|_| {}, |_| {})
        }
        let mut tables = Requesters::<BoxedReplySink, BoxedReplySink>::new();
        assert_eq!(tables.next_deadline_ms(), None, "CONTROL: nothing pending");
        tables
            .replies
            .register_sink(1, 1, Some(100), ReplyAcceptance::Any, sink())
            .expect("a row is free");
        tables
            .replies
            .register_sink(2, 1, Some(400), ReplyAcceptance::Any, sink())
            .expect("a row is free");
        #[cfg(feature = "liveliness-get")]
        tables
            .liveliness_gets
            .register(7, Some(250), sink())
            .expect("a row is free");
        assert_eq!(tables.next_deadline_ms(), Some(100));
        tables.replies.deliver_local_final(1);
        #[cfg(feature = "liveliness-get")]
        {
            assert_eq!(
                tables.next_deadline_ms(),
                Some(250),
                "the snapshot's is the earliest left"
            );
            tables.end_leg(GetKind::Liveliness(7));
        }
        assert_eq!(tables.next_deadline_ms(), Some(400));
        tables.end_leg(GetKind::Query(2));
        assert_eq!(tables.next_deadline_ms(), None, "every leg ended");
    }
}
