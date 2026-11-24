// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The queries an engine keeps on the heap past their handlers, each named by the id the port
//! names a kept query with ([`HeldQueryId`]).
//!
//! The cooperative engine keeps a query in the row of its Final and names it by the link it came
//! in on. An engine whose runtime holds a kept query as a value of its own (the tokio registry's
//! face sessions, a router node's forwarder) keeps that value here: one row per keep, the id being
//! the row's. A row's turn moves each time it is let go of, so the id of a keep released already
//! names nothing, whatever keep has taken the row since.

use alloc::sync::Arc;
use alloc::vec::Vec;

use wz_session_core::wire_id::RequestId;

use crate::sync::Lock;
use crate::{HeldQueryId, Refusal};

/// The values an engine keeps for the queries a program keeps past their handlers, each under the
/// [`HeldQueryId`] its keep answers ([`Self::keep`]) and given back once ([`Self::release`]).
///
/// A value is shared: a reply made with it ([`Self::get`]) holds it while the reply runs, so a
/// release from another thread meanwhile drops it once that reply ends. Nothing is dropped while
/// the slab's lock is held: dropping a value may let go of what the engine holds for its query.
pub struct HeldSlab<T> {
    rows: Lock<Rows<T>>,
}

struct Rows<T> {
    rows: Vec<Row<T>>,
    /// The rows let go of, which the next keeps take before a row is added.
    free: Vec<u32>,
}

struct Row<T> {
    turn: u32,
    kept: Option<(RequestId, Arc<T>)>,
}

impl<T> HeldSlab<T> {
    /// A slab that keeps nothing.
    pub const fn new() -> Self {
        Self {
            rows: Lock::new(Rows {
                rows: Vec::new(),
                free: Vec::new(),
            }),
        }
    }

    /// Keep `value` for the query `rid`: one keep, under an id of its own. Refused with
    /// [`Refusal::TableFull`] once every row an id can name is taken, and `value` is then dropped
    /// after the slab's lock is let go of.
    pub fn keep(&self, rid: RequestId, value: T) -> Result<HeldQueryId, Refusal> {
        let held = Arc::new(value);
        self.rows
            .with(|rows| rows.take_row(rid, held))
            .map_err(|_unkept| Refusal::TableFull)
    }

    /// The value kept under `id`, shared: `None` for an id released already or never answered.
    pub fn get(&self, id: HeldQueryId) -> Option<Arc<T>> {
        self.rows.with(|rows| rows.kept(id).map(Arc::clone))
    }

    /// Let go of the keep `id`, its value dropped once no reply holds it. Whether `id` was kept:
    /// an id released already, or never answered, lets go of nothing.
    pub fn release(&self, id: HeldQueryId) -> bool {
        let released = self.rows.with(|rows| rows.release(id));
        released.is_some()
    }

    /// How many keeps the slab holds.
    pub fn kept(&self) -> usize {
        self.rows
            .with(|rows| rows.rows.iter().filter(|row| row.kept.is_some()).count())
    }
}

impl<T> Default for HeldSlab<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Rows<T> {
    /// Put `held` in a free row, or in a row added; `held` back when no id can name one more.
    fn take_row(&mut self, rid: RequestId, held: Arc<T>) -> Result<HeldQueryId, Arc<T>> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let Ok(index) = u32::try_from(self.rows.len()) else {
                    return Err(held);
                };
                self.rows.push(Row {
                    turn: 0,
                    kept: None,
                });
                index
            }
        };
        let Some(row) = at(index).and_then(|at| self.rows.get_mut(at)) else {
            return Err(held);
        };
        row.kept = Some((rid, held));
        Ok(id_of(index, row.turn, rid))
    }

    fn kept(&self, id: HeldQueryId) -> Option<&Arc<T>> {
        let (index, turn) = place_of(id);
        let row = self.rows.get(at(index)?)?;
        match &row.kept {
            Some((rid, held)) if row.turn == turn && *rid == id.rid => Some(held),
            _ => None,
        }
    }

    fn release(&mut self, id: HeldQueryId) -> Option<Arc<T>> {
        self.kept(id)?;
        let (index, _) = place_of(id);
        let row = self.rows.get_mut(at(index)?)?;
        let (_, held) = row.kept.take()?;
        row.turn = row.turn.wrapping_add(1);
        self.free.push(index);
        Some(held)
    }
}

/// The row `index` as a place in the rows.
fn at(index: u32) -> Option<usize> {
    usize::try_from(index).ok()
}

/// The id of the keep of query `rid` in row `index` at `turn`: the turn in the high half of
/// the engine's key, the row in the low.
fn id_of(index: u32, turn: u32, rid: RequestId) -> HeldQueryId {
    HeldQueryId {
        generation: u64::from(turn).wrapping_shl(32) | u64::from(index),
        rid,
    }
}

/// The row and the turn an id names, as [`id_of`] made them.
fn place_of(id: HeldQueryId) -> (u32, u32) {
    let low = u32::try_from(id.generation & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    let high = u32::try_from(id.generation.wrapping_shr(32)).unwrap_or(u32::MAX);
    (low, high)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// A value that counts its drops.
    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A keep answers its value until it is released, once: a second release, and a read after
    /// the first, find nothing, and the value is dropped by the release.
    #[test]
    fn a_keep_is_read_until_its_one_release_drops_it() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slab = HeldSlab::new();
        let id = slab.keep(7, Counted(Arc::clone(&drops))).expect("room");
        assert_eq!(id.rid, 7);
        assert!(slab.get(id).is_some());
        assert_eq!(slab.kept(), 1);
        assert!(slab.release(id));
        assert_eq!(drops.load(Ordering::SeqCst), 1, "the release dropped it");
        assert!(slab.get(id).is_none());
        assert!(!slab.release(id), "a keep is released once");
        assert_eq!(slab.kept(), 0);
    }

    /// A row let go of is taken by the next keep under another id, and the id of the keep released
    /// names nothing of the new one.
    #[test]
    fn a_row_taken_again_is_not_named_by_the_id_released() {
        let slab = HeldSlab::new();
        let first = slab.keep(1, "first").expect("room");
        assert!(slab.release(first));
        let second = slab.keep(1, "second").expect("room");
        assert_ne!(first, second, "the row's turn moved");
        assert!(slab.get(first).is_none());
        assert!(!slab.release(first), "the stale id lets go of nothing");
        assert_eq!(slab.get(second).as_deref(), Some(&"second"));
        assert_eq!(slab.kept(), 1);
    }

    /// Two keeps of one query are two ids, each released on its own.
    #[test]
    fn two_keeps_of_one_query_are_released_apart() {
        let slab = HeldSlab::new();
        let one = slab.keep(3, 1_u8).expect("room");
        let two = slab.keep(3, 2_u8).expect("room");
        assert_ne!(one, two);
        assert!(slab.release(one));
        assert_eq!(slab.get(two).as_deref(), Some(&2));
        assert!(slab.release(two));
        assert_eq!(slab.kept(), 0);
    }

    /// An id whose request id is not the keep's names nothing.
    #[test]
    fn an_id_of_another_request_names_nothing() {
        let slab = HeldSlab::new();
        let id = slab.keep(5, ()).expect("room");
        let other = HeldQueryId { rid: 6, ..id };
        assert!(slab.get(other).is_none());
        assert!(!slab.release(other));
        assert!(slab.release(id));
    }

    /// A value a reply still holds outlives the release of its keep, and is dropped with the
    /// reply's hold.
    #[test]
    fn a_value_a_reply_holds_outlives_its_release() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slab = HeldSlab::new();
        let id = slab.keep(9, Counted(Arc::clone(&drops))).expect("room");
        let replying = slab.get(id).expect("kept");
        assert!(slab.release(id));
        assert_eq!(drops.load(Ordering::SeqCst), 0, "the reply holds it");
        drop(replying);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    /// The id names the row in its low half and the turn in its high half.
    #[test]
    fn an_id_names_its_row_and_turn() {
        let id = id_of(0xABCD, 3, 1);
        assert_eq!(id.generation, (3_u64 << 32) | 0xABCD);
        assert_eq!(place_of(id), (0xABCD, 3));
    }
}
