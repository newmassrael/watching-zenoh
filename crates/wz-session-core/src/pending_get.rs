// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's faces as its state reaches them, each face's tables of pending gets as their
//! earliest deadline is read, and the index of the earliest deadline over those tables.
//!
//! A leg of a get is its entry in the table of the face it was asked of, and nothing besides: the
//! entry's sink says the leg's end when the entry is dropped (its Final, its deadline, its
//! cancellation, the loss of its face), so no other record of the leg is kept to end it.

#[cfg(feature = "storage-profile")]
use crate::bounded::Storage;
#[cfg(feature = "storage-profile")]
use crate::reply_sink::ReplySink;
#[cfg(feature = "storage-profile")]
use crate::slot_observer::{NoRequesters, Requesters};

/// The faces of a session as its state reaches them: what each face's peer declared and the
/// session's gets pending on it, which the engine's registry keeps.
pub trait SessionFaces {
    /// What the peer of face `face` declared goes with its link: its subscribers and queryables,
    /// and its tokens, retracted as the round of deliveries takes each. Every get asked of it ends
    /// too, as its peer can send no Final now: each entry of its tables of pending gets is
    /// dropped, which says that leg's end.
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

/// A face's tables of pending gets, as their earliest deadline is read.
pub trait LegTables {
    /// When the earliest entry here is due: a query's or a liveliness snapshot's, as each table
    /// keeps it, with no walk of the entries.
    fn next_deadline_ms(&self) -> Option<u64>;
}

#[cfg(feature = "storage-profile")]
impl<R: ReplySink, G: ReplySink, P: Storage> LegTables for Requesters<R, G, P> {
    fn next_deadline_ms(&self) -> Option<u64> {
        let due_ms = self.replies.due_ms();
        #[cfg(feature = "liveliness-get")]
        let due_ms = due_ms.min(self.liveliness_gets.due_ms());
        (due_ms != u64::MAX).then_some(due_ms)
    }
}

#[cfg(feature = "storage-profile")]
impl LegTables for NoRequesters {
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
/// one, whose root names the table with the earliest key. A key that moves replays the path from
/// its leaf alone, and the root is read with no walk; a table that joins the index is told by one
/// rebuild ([`Self::rebuild`]), the tree laid over the leaves it has then.
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

    /// Every leaf keyed by the earliest deadline its table holds now and every node played from its
    /// children: what the index owes when a table joined it, the tree's shape being its count of
    /// leaves. A key a table holds is kept, as a lowering from never brings each to it.
    fn rebuild(&mut self) {
        self.reset();
        for leaf in 0..self.leaves() {
            self.lower(leaf);
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
    use std::vec::Vec;

    /// Faces that keep no token owe no retraction and ask the round for no room.
    #[test]
    fn faces_that_keep_no_token_owe_no_retraction() {
        struct Tokenless;
        impl SessionFaces for Tokenless {
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

    /// Tables that join an index holding deadlines are told by a rebuild, after which the index
    /// answers what a walk of every table reads, the deadlines held before among them, at each
    /// count of tables up to nine. Turned red by a rebuild that keys no leaf by its table.
    #[test]
    fn a_rebuild_after_tables_join_keeps_every_deadline_held() {
        let mut tables = Tables::none(1);
        tables.hold(0, 300);
        for joined in 1..9u64 {
            let due = if joined % 2 == 0 {
                u64::MAX
            } else {
                500 - joined * 10
            };
            tables.dues.push(due);
            tables.rows.push(DueRow::NEVER);
            tables.rebuild();
            assert_eq!(tables.earliest(), tables.walked(), "{} tables", joined + 1);
        }
        assert_eq!(
            tables.earliest(),
            Some(300),
            "the first table's deadline came first"
        );
        tables.dues[0] = u64::MAX;
        assert_eq!(
            tables.earliest(),
            Some(430),
            "then the earliest of those that joined"
        );
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
            assert!(tables.liveliness_gets.unregister(7));
        }
        assert_eq!(tables.next_deadline_ms(), Some(400));
        assert!(tables.replies.unregister(2));
        assert_eq!(tables.next_deadline_ms(), None, "every leg ended");
    }
}
