// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A reach of a session's engine that keeps nothing of it standing ([`ReachEngine`]): what a
//! holder that must not keep the session open holds (a key expression the program keeps, a query
//! kept past its callback, a cancellation token, the engine's own reach of itself).
//!
//! An engine is put in a row of one table of the process ([`caps::ENGINE_ROWS`] rows) when its
//! session opens, and taken out when it closes. A reach names the row and the generation the row
//! was at when the engine was put in it; the close moves the generation on, so a reach kept past
//! the close finds another generation, or the row vacant, and reaches nothing, whatever the row
//! holds since. Reaching takes a count of the engine under the row's lock, the lock the close
//! takes the engine out under, so an engine is never reached past its close nor once its last
//! holder has let go. The table takes no memory of the heap, and a reach is two words.

use core::ops::Deref;
use core::ptr::NonNull;

use wz_session_core::caps;

use crate::sync::Lock;

/// An engine a [`ReachEngine`] reaches: what takes a count of it for the length of a use.
///
/// # Safety
/// [`Self::retain_live`] takes a count that keeps the engine standing until [`Self::release`]
/// gives it back, and takes none once the engine's last holder has let go; and the engine stands
/// for as long as the row it was put in holds it: it is taken out ([`ReachEngine::clear`]) before
/// its memory goes.
pub unsafe trait Reachable: Send + Sync {
    /// Take a count of the engine while one of its holders is left, and say whether it was taken.
    fn retain_live(&self) -> bool;

    /// Give back a count [`Self::retain_live`] took.
    ///
    /// # Safety
    /// The count is one [`Self::retain_live`] took, given back once; nothing is read through the
    /// engine after it by the one that gives it back.
    unsafe fn release(&self);
}

/// One row of the table: the generation it is at, and the engine it holds while that engine's
/// session is open.
struct Row {
    generation: u32,
    engine: Option<NonNull<dyn Reachable>>,
}

// SAFETY: the engine a row holds is `Send + Sync` (`Reachable`), and is reached only under the
// row's lock or through a count taken under it.
unsafe impl Send for Row {}

/// The rows, one for each session of the process open at once.
static ROWS: [Lock<Row>; caps::ENGINE_ROWS] = [const {
    Lock::new(Row {
        generation: 0,
        engine: None,
    })
}; caps::ENGINE_ROWS];

/// A reach of an engine through its row: a row and a generation, copied freely, keeping nothing
/// of the engine standing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReachEngine {
    row: usize,
    generation: u32,
}

impl ReachEngine {
    /// Put `engine` in a vacant row and answer the reach of it there; `None` when every row holds
    /// an engine, which refuses the open of one more session.
    ///
    /// # Safety
    /// `engine` stands until [`Self::clear`] is called on the reach answered.
    pub unsafe fn put(engine: NonNull<dyn Reachable>) -> Option<Self> {
        ROWS.iter().enumerate().find_map(|(row, lock)| {
            lock.with(|held| {
                if held.engine.is_some() {
                    return None;
                }
                held.engine = Some(engine);
                Some(Self {
                    row,
                    generation: held.generation,
                })
            })
        })
    }

    /// Take the engine out of its row, at its session's close: no reach of it reaches it from
    /// then on, and the row is vacant for the next. A count taken before is kept until it is
    /// given back. A reach whose row moved on already takes nothing out.
    pub fn clear(&self) {
        if let Some(lock) = ROWS.get(self.row) {
            lock.with(|held| {
                if held.generation == self.generation && held.engine.is_some() {
                    held.engine = None;
                    held.generation = held.generation.wrapping_add(1);
                }
            });
        }
    }

    /// The engine, with a count of it kept for as long as the answer is held; `None` once its
    /// session closed, or its last holder let go.
    pub fn reach(&self) -> Option<Reached> {
        let lock = ROWS.get(self.row)?;
        let engine = lock.with(|held| {
            if held.generation != self.generation {
                return None;
            }
            let engine = held.engine?;
            // SAFETY: an engine stands while its row holds it (`Reachable`).
            unsafe { engine.as_ref() }.retain_live().then_some(engine)
        })?;
        Some(Reached { engine })
    }
}

/// An engine reached ([`ReachEngine::reach`]), and the count taken of it, given back when this
/// is dropped.
pub struct Reached {
    engine: NonNull<dyn Reachable>,
}

// SAFETY: the engine is `Send + Sync` (`Reachable`), and this holds a count of it.
unsafe impl Send for Reached {}
// SAFETY: as `Send`.
unsafe impl Sync for Reached {}

impl Reached {
    /// The engine, and the count of it, given up to the caller: a holder of the engine's own type
    /// takes the count over and gives it back as that type does.
    pub fn into_raw(self) -> NonNull<dyn Reachable> {
        let engine = self.engine;
        core::mem::forget(self);
        engine
    }
}

impl Deref for Reached {
    type Target = dyn Reachable;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the count this holds keeps the engine standing.
        unsafe { self.engine.as_ref() }
    }
}

impl Drop for Reached {
    fn drop(&mut self) {
        // SAFETY: the count this holds, given back once; nothing is read through it after.
        unsafe { self.engine.as_ref().release() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// The tests share the process's one table: one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// An engine counted by its holders, as the cooperative engine's is.
    struct Counted {
        holders: AtomicUsize,
    }

    impl Counted {
        fn held() -> Self {
            Self {
                holders: AtomicUsize::new(1),
            }
        }

        fn holders(&self) -> usize {
            self.holders.load(Ordering::SeqCst)
        }
    }

    // SAFETY: a count is taken only while one is held, and each test keeps its engine standing
    // past its clear.
    unsafe impl Reachable for Counted {
        fn retain_live(&self) -> bool {
            self.holders
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                    if held > 0 {
                        Some(held + 1)
                    } else {
                        None
                    }
                })
                .is_ok()
        }

        unsafe fn release(&self) {
            self.holders.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn put(engine: &Counted) -> Option<ReachEngine> {
        let engine: &(dyn Reachable + 'static) = engine;
        // SAFETY: every test clears what it put before its engine goes.
        unsafe { ReachEngine::put(NonNull::from(engine)) }
    }

    /// An open engine is reached with a count taken for the length of the use, given back when the
    /// reach is let go. Turned red by a reach that takes no count, or one never given back.
    #[test]
    fn an_open_engine_is_reached_with_a_count_for_the_use() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = Counted::held();
        let reach = put(&engine).expect("a vacant row");
        let reached = reach.reach().expect("the engine is open");
        assert_eq!(engine.holders(), 2, "the reach holds a count");
        drop(reached);
        assert_eq!(engine.holders(), 1, "given back with the reach");
        reach.clear();
    }

    /// A reach kept past the close reaches nothing, even once its row holds another engine; the
    /// new engine's reach reaches it, and a second clear of the old reach takes nothing out.
    /// Turned red by a close that leaves the generation where it was, or a clear that empties a
    /// row another engine holds.
    #[test]
    fn a_reach_kept_past_the_close_reaches_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let first = Counted::held();
        let old = put(&first).expect("a vacant row");
        old.clear();
        assert!(old.reach().is_none(), "closed, it is not reached");
        let second = Counted::held();
        let new = put(&second).expect("a vacant row");
        assert!(
            old.reach().is_none(),
            "the row's new engine is not the old reach's"
        );
        old.clear();
        assert!(new.reach().is_some(), "an old clear takes nothing out");
        assert_eq!(first.holders(), 1, "nothing was taken of the closed engine");
        new.clear();
    }

    /// An engine whose last holder let go is not reached, though its row still holds it.
    /// Turned red by a reach that takes a count of an engine with no holder left.
    #[test]
    fn an_engine_no_holder_keeps_is_not_reached() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = Counted::held();
        let reach = put(&engine).expect("a vacant row");
        // SAFETY: the engine's one holder lets go.
        unsafe { engine.release() };
        assert!(reach.reach().is_none());
        assert_eq!(engine.holders(), 0, "no count was taken");
        reach.clear();
    }

    /// With every row holding an engine, one more is refused; a row cleared takes the next.
    /// Turned red by a put past the table, or a cleared row that stays held.
    #[test]
    fn a_full_table_refuses_one_more_engine() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engines: std::vec::Vec<Counted> =
            (0..caps::ENGINE_ROWS).map(|_| Counted::held()).collect();
        let reaches: std::vec::Vec<ReachEngine> = engines.iter().map_while(put).collect();
        assert_eq!(reaches.len(), caps::ENGINE_ROWS, "every row takes one");
        let one_more = Counted::held();
        assert!(put(&one_more).is_none(), "one past the rows is refused");
        let (first, rest) = reaches.split_first().expect("a row at least");
        first.clear();
        let next = put(&one_more).expect("the cleared row takes it");
        assert!(next.reach().is_some());
        next.clear();
        for reach in rest {
            reach.clear();
        }
    }
}
