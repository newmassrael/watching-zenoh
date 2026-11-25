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
//! holder has let go. Whether the session is still open is read from the row's mark alone, with
//! no lock and no count ([`ReachEngine::is_current`]): a reply asks it of every answer. The table
//! takes no memory of the heap, and a reach is two words.

use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use wz_session_core::caps;

use crate::cancellation::FanCanceller;
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

    /// What ends the legs of a get's fan this engine issued, reached through its row
    /// ([`crate::cancellation::Canceller::Engine`]): `None`, the provided answer, for an engine
    /// that issues no get a token can cancel.
    fn canceller(&self) -> Option<&dyn FanCanceller> {
        None
    }
}

/// One row of the table: the engine it holds while that engine's session is open. Its mark lies
/// beside it, in [`MARKS`] at the same place.
struct Row {
    engine: Option<NonNull<dyn Reachable>>,
}

/// The bit of a row's mark that says an open has taken the row for the engine it is making.
const CLAIMED: u32 = 1;

/// The bit of a row's mark that says the session of the engine it holds ended on its own, its
/// engine still in the row: reached as before, but no longer current ([`ReachEngine::end`]).
const ENDED: u32 = 2;

/// What a row's mark moves on by at a close: one generation, in the bits above [`CLAIMED`] and
/// [`ENDED`].
const GENERATION_STEP: u32 = 4;

/// The generation a row's mark is at.
const fn generation(mark: u32) -> u32 {
    mark & !(CLAIMED | ENDED)
}

/// The mark of each row: the generation it is at, whether an open has taken it for the engine it
/// is making ([`CLAIMED`]), and whether that engine's session ended ([`ENDED`]). Written only
/// under the table's lock; read under it, and without it by [`ReachEngine::is_current`], which a
/// lock-free load answers because every change of a mark is one store.
static MARKS: [AtomicU32; caps::ENGINE_ROWS] = [const { AtomicU32::new(0) }; caps::ENGINE_ROWS];

/// The mark of the row at `row`, read under the table's lock.
fn mark_of(row: usize) -> u32 {
    MARKS
        .get(row)
        .map_or(0, |mark| mark.load(Ordering::Relaxed))
}

/// Set the mark of the row at `row`, under the table's lock: published to a lock-free reader of
/// it with what was written before.
fn set_mark(row: usize, value: u32) {
    if let Some(mark) = MARKS.get(row) {
        mark.store(value, Ordering::Release);
    }
}

// SAFETY: the engine a row holds is `Send + Sync` (`Reachable`), and is reached only under the
// table's lock or through a count taken under it.
unsafe impl Send for Row {}

/// The rows, one for each session of the process open at once, under one lock: what each takes it
/// for (a claim, a fill, a clear, a reach) is a few words read and written, so one lock for the
/// table costs no wait a lock for each row would spare, and the rows hold no lock of their own.
static ROWS: Lock<[Row; caps::ENGINE_ROWS]> =
    Lock::new([const { Row { engine: None } }; caps::ENGINE_ROWS]);

/// A reach of an engine through its row: a row and a generation, copied freely, keeping nothing
/// of the engine standing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReachEngine {
    row: usize,
    generation: u32,
}

impl ReachEngine {
    /// A reach of no engine: it reaches nothing and clears nothing, as a reach kept past its
    /// engine's close does. What a holder made with no session holds.
    pub const fn vacant() -> Self {
        Self {
            row: usize::MAX,
            generation: 0,
        }
    }

    /// Take a vacant row for an engine an open is about to make, before it reserves anything for
    /// it; `None` when every row holds an engine or is taken, which refuses the open of one more
    /// session. The row is vacant again when the claim is let go of unfilled.
    pub fn claim() -> Option<RowClaim> {
        ROWS.with(|rows| {
            let (row, _) = rows
                .iter()
                .enumerate()
                .find(|(row, held)| held.engine.is_none() && mark_of(*row) & CLAIMED == 0)?;
            set_mark(row, mark_of(row) | CLAIMED);
            Some(RowClaim { row })
        })
    }

    /// Put `engine` in a vacant row and answer the reach of it there; `None` when every row holds
    /// an engine ([`Self::claim`]).
    ///
    /// # Safety
    /// `engine` stands until [`Self::clear`] is called on the reach answered.
    pub unsafe fn put(engine: NonNull<dyn Reachable>) -> Option<Self> {
        let claim = Self::claim()?;
        // SAFETY: the caller's.
        Some(unsafe { claim.fill(engine) })
    }

    /// Take the engine out of its row, at its session's close: no reach of it reaches it from
    /// then on, and the row is vacant for the next. A count taken before is kept until it is
    /// given back. A reach whose row moved on already takes nothing out.
    pub fn clear(&self) {
        ROWS.with(|rows| {
            let mark = mark_of(self.row);
            let named = rows
                .get_mut(self.row)
                .filter(|held| generation(mark) == self.generation && held.engine.is_some());
            if let Some(held) = named {
                held.engine = None;
                set_mark(self.row, generation(mark).wrapping_add(GENERATION_STEP));
            }
        });
    }

    /// Mark the engine's session as ended on its own, its engine kept in its row: what a session
    /// a step ended says (its dial role's link lost, with no redial), so that a reach of it is no
    /// longer current ([`Self::is_current`]) though it still reaches the engine. A reach whose row
    /// moved on marks nothing; the close that follows clears the mark with the row.
    pub fn end(&self) {
        ROWS.with(|rows| {
            let mark = mark_of(self.row);
            let named = rows
                .get(self.row)
                .is_some_and(|held| generation(mark) == self.generation && held.engine.is_some());
            if named {
                set_mark(self.row, mark | ENDED);
            }
        });
    }

    /// Whether the engine is in its row and its session has not ended: what a reply asks before
    /// anything else, answered by one load of the row's mark, with no lock and no count of the
    /// engine. A close moves the generation on, and a step that ends the session marks it before
    /// it says the session closed, so a reach that is not current reaches a closed session or
    /// none. A vacant reach is never current.
    pub fn is_current(&self) -> bool {
        MARKS
            .get(self.row)
            .is_some_and(|mark| mark.load(Ordering::Acquire) == self.generation)
    }

    /// The engine, with a count of it kept for as long as the answer is held; `None` once its
    /// session closed, or its last holder let go.
    pub fn reach(&self) -> Option<Reached> {
        let engine = ROWS.with(|rows| {
            let held = rows.get(self.row)?;
            if generation(mark_of(self.row)) != self.generation {
                return None;
            }
            let engine = held.engine?;
            // SAFETY: an engine stands while its row holds it (`Reachable`).
            unsafe { engine.as_ref() }.retain_live().then_some(engine)
        })?;
        Some(Reached { engine })
    }
}

/// A row taken for an engine an open is making ([`ReachEngine::claim`]): no other open takes
/// it, and no reach reaches anything through it, until it is filled; let go of unfilled, it is
/// vacant again.
pub struct RowClaim {
    row: usize,
}

impl RowClaim {
    /// Put `engine` in the row and answer the reach of it there.
    ///
    /// # Safety
    /// `engine` stands until [`ReachEngine::clear`] is called on the reach answered.
    pub unsafe fn fill(self, engine: NonNull<dyn Reachable>) -> ReachEngine {
        let row = self.row;
        core::mem::forget(self);
        ROWS.with(|rows| {
            rows.get_mut(row).map_or_else(ReachEngine::vacant, |held| {
                let mark = mark_of(row) & !CLAIMED;
                set_mark(row, mark);
                held.engine = Some(engine);
                ReachEngine {
                    row,
                    generation: generation(mark),
                }
            })
        })
    }
}

impl Drop for RowClaim {
    fn drop(&mut self) {
        ROWS.with(|_| set_mark(self.row, mark_of(self.row) & !CLAIMED));
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

    /// A row claimed for an engine being made is taken by no other open and reaches nothing until
    /// it is filled; let go of unfilled, it is vacant again. Turned red by a claim another claim
    /// can take, or one that leaves its row taken when it is let go of.
    #[test]
    fn a_claimed_row_is_taken_until_filled_or_let_go_of() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let claims: std::vec::Vec<RowClaim> = core::iter::from_fn(ReachEngine::claim)
            .take(caps::ENGINE_ROWS + 1)
            .collect();
        assert_eq!(claims.len(), caps::ENGINE_ROWS, "every row is claimed once");
        let engine = Counted::held();
        assert!(put(&engine).is_none(), "no row is left");
        drop(claims);
        let reach = put(&engine).expect("the claims were let go of");
        assert!(reach.reach().is_some());
        reach.clear();
        let claim = ReachEngine::claim().expect("a vacant row");
        let reachable: &(dyn Reachable + 'static) = &engine;
        // SAFETY: the engine is cleared out of its row before it goes, below.
        let filled = unsafe { claim.fill(NonNull::from(reachable)) };
        assert!(
            filled.reach().is_some(),
            "the filled row reaches its engine"
        );
        filled.clear();
    }

    /// A reach of no engine reaches nothing, and its clear takes no engine out of any row.
    /// Turned red by a vacant reach that names a row of the table.
    #[test]
    fn a_vacant_reach_reaches_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = Counted::held();
        let reach = put(&engine).expect("a vacant row");
        let vacant = ReachEngine::vacant();
        assert!(vacant.reach().is_none());
        vacant.clear();
        assert!(reach.reach().is_some(), "the vacant clear took nothing out");
        assert_eq!(engine.holders(), 1);
        reach.clear();
    }

    /// An engine that ends the legs of the fans it issued, counted by its holders.
    struct Cancels {
        counted: Counted,
        cancelled: AtomicUsize,
    }

    impl crate::cancellation::FanCanceller for Cancels {
        fn cancel_fan(&self, _key: crate::cancellation::FanKey) {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }

    // SAFETY: as `Counted`'s, whose count this one is.
    unsafe impl Reachable for Cancels {
        fn retain_live(&self) -> bool {
            self.counted.retain_live()
        }

        unsafe fn release(&self) {
            // SAFETY: the caller's.
            unsafe { self.counted.release() }
        }

        fn canceller(&self) -> Option<&dyn FanCanceller> {
            Some(self)
        }
    }

    /// A fan whose engine was attached by its row is cancelled through the engine while the
    /// engine is open, the count taken for the cancel given back after it; once the engine
    /// closed, the cancel reaches nothing. Turned red by an engine canceller that ends no leg,
    /// keeps the count it took, or reaches an engine past its close.
    #[test]
    fn a_fan_attached_by_its_engines_row_is_cancelled_only_while_the_engine_is_open() {
        use crate::cancellation::{CancellableFan, Canceller};
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = Cancels {
            counted: Counted::held(),
            cancelled: AtomicUsize::new(0),
        };
        let reachable: &(dyn Reachable + 'static) = &engine;
        // SAFETY: the engine is cleared out of its row before it goes, below.
        let reach = unsafe { ReachEngine::put(NonNull::from(reachable)) }.expect("a vacant row");
        let open = CancellableFan::new();
        assert!(open.attach(Canceller::Engine(reach)));
        open.cancel();
        assert_eq!(
            engine.cancelled.load(Ordering::SeqCst),
            1,
            "the engine ended its legs"
        );
        assert_eq!(
            engine.counted.holders(),
            1,
            "the cancel's count was given back"
        );
        let closed = CancellableFan::new();
        assert!(closed.attach(Canceller::Engine(reach)));
        reach.clear();
        closed.cancel();
        assert_eq!(
            engine.cancelled.load(Ordering::SeqCst),
            1,
            "a closed engine is not reached"
        );
    }

    /// A row is the engine's two words, its mark one word of 32 bits beside it: the generation,
    /// the claim and the end share that word, and the table's one lock is in neither. Turned red
    /// by a row that holds its mark, or a lock, of its own, or a mark wider than 32 bits.
    #[test]
    fn a_row_is_the_engines_two_words_and_its_mark_one_word_of_32_bits() {
        assert_eq!(
            core::mem::size_of::<Row>(),
            2 * core::mem::size_of::<usize>()
        );
        assert_eq!(core::mem::size_of_val(&MARKS), caps::ENGINE_ROWS * 4);
    }

    /// An open engine's reach is current. Once its session ends on its own the reach is no longer
    /// current, though it still reaches the engine; the close clears the end with the row, so the
    /// row's next engine is current, and an old reach's end marks nothing of it. A vacant reach is
    /// never current. Turned red by an end that marks nothing, an ended engine no longer reached, a
    /// clear that leaves the end on the row for its next engine, or an old reach that ends it.
    #[test]
    fn an_ended_session_is_reached_but_not_current_until_its_row_is_cleared() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let first = Counted::held();
        let old = put(&first).expect("a vacant row");
        assert!(old.is_current(), "an open engine's reach is current");
        old.end();
        assert!(!old.is_current(), "ended, it is not current");
        drop(old.reach().expect("an ended engine is still reached"));
        old.clear();
        assert!(!old.is_current(), "closed, it is not current");
        let second = Counted::held();
        let new = put(&second).expect("a vacant row");
        assert_eq!(new.row, old.row, "the cleared row takes the next engine");
        assert!(new.is_current(), "the end went with the clear");
        old.end();
        assert!(
            new.is_current(),
            "an old reach ends nothing of the next engine"
        );
        assert!(!ReachEngine::vacant().is_current());
        new.clear();
        assert_eq!(first.holders(), 1, "nothing was kept of the ended engine");
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
