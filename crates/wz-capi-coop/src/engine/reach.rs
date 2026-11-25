// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A reach of a session's engine that keeps nothing of it standing ([`ReachEngine`]): what a
//! holder that must not keep the session open holds (a key expression the program keeps, a query
//! kept past its callback, a cancellation token, the engine's own reach), as a weak count of a
//! heap's would, with no heap.
//!
//! An engine is put in a row of one table of the process ([`caps::ENGINE_ROWS`] rows) when its
//! session opens, and taken out when it closes. A reach names the row and the generation the row
//! was at when the engine was put in it; the close moves the generation on, so a reach kept past
//! the close finds another generation, or the row vacant, and reaches nothing, whatever the row
//! holds since. Reaching takes a count of the engine under the row's lock, the lock the close
//! takes the engine out under, so an engine is never reached past its close nor once its last
//! holder has let go. Whether the session is still open is read from the row's mark alone, with
//! no lock and no count ([`ReachEngine::is_current`]): a reply asks it of every answer. The table
//! takes no memory of the heap, a row is one word and a reach two.
//!
//! The table is this engine's: a reach is of the type the engine was put in as, and reaching it
//! is a count of that type's `Shared` taken where it lies, so no table of operations stands
//! between a reach and its engine.

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use wz_capi_port::cancellation::EngineAt;
#[cfg(feature = "query")]
use wz_capi_port::cancellation::{Canceller, FanCanceller, FanEnd};
use wz_capi_port::sync::Lock;
use wz_runtime_coop::kept::Shared;
use wz_session_core::caps;

/// One row of the table: where the engine it holds lies while that engine's session is open, of
/// the type its reach names. Its mark lies beside it, in [`MARKS`] at the same place.
struct Row {
    engine: Option<NonNull<()>>,
}

// SAFETY: the engine a row names is `Send + Sync` (`RowClaim::fill`), and is reached only under
// the table's lock or through a count taken under it.
unsafe impl Send for Row {}

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

/// The rows, one for each session of the process open at once, under one lock: what each takes it
/// for (a claim, a fill, a clear, a reach) is a few words read and written, so one lock for the
/// table costs no wait a lock for each row would spare, and the rows hold no lock of their own.
static ROWS: Lock<[Row; caps::ENGINE_ROWS]> =
    Lock::new([const { Row { engine: None } }; caps::ENGINE_ROWS]);

/// A reach of an engine of type `E` through its row: a row and a generation, copied freely,
/// keeping nothing of the engine standing.
pub(crate) struct ReachEngine<E> {
    at: EngineAt,
    engine: PhantomData<fn() -> E>,
}

impl<E> Clone for ReachEngine<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for ReachEngine<E> {}

impl<E> PartialEq for ReachEngine<E> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl<E> ReachEngine<E> {
    /// A reach of no engine: it reaches nothing and clears nothing, as a reach kept past its
    /// engine's close does. What a holder made with no session holds.
    pub(crate) const fn vacant() -> Self {
        Self::named(EngineAt {
            row: usize::MAX,
            generation: 0,
        })
    }

    const fn named(at: EngineAt) -> Self {
        Self {
            at,
            engine: PhantomData,
        }
    }

    /// Take the engine out of its row, at its session's close: no reach of it reaches it from
    /// then on, and the row is vacant for the next. A count taken before is kept until it is
    /// given back. A reach whose row moved on already takes nothing out.
    pub(crate) fn clear(&self) {
        let EngineAt {
            row,
            generation: at,
        } = self.at;
        ROWS.with(|rows| {
            let mark = mark_of(row);
            let named = rows
                .get_mut(row)
                .filter(|held| generation(mark) == at && held.engine.is_some());
            if let Some(held) = named {
                held.engine = None;
                set_mark(row, generation(mark).wrapping_add(GENERATION_STEP));
            }
        });
    }

    /// Mark the engine's session as ended on its own, its engine kept in its row: what a session
    /// a step ended says (its dial role's link lost, with no redial), so that a reach of it is no
    /// longer current ([`Self::is_current`]) though it still reaches the engine. A reach whose row
    /// moved on marks nothing; the close that follows clears the mark with the row.
    pub(crate) fn end(&self) {
        let EngineAt {
            row,
            generation: at,
        } = self.at;
        ROWS.with(|rows| {
            let mark = mark_of(row);
            let named = rows
                .get(row)
                .is_some_and(|held| generation(mark) == at && held.engine.is_some());
            if named {
                set_mark(row, mark | ENDED);
            }
        });
    }

    /// Whether the engine is in its row and its session has not ended: what a reply asks before
    /// anything else, answered by one load of the row's mark, with no lock and no count of the
    /// engine. A close moves the generation on, and a step that ends the session marks it before
    /// it says the session closed, so a reach that is not current reaches a closed session or
    /// none. A vacant reach is never current.
    pub(crate) fn is_current(&self) -> bool {
        MARKS
            .get(self.at.row)
            .is_some_and(|mark| mark.load(Ordering::Acquire) == self.at.generation)
    }

    /// A holder of the engine, with a count of it taken for as long as the answer is held; `None`
    /// once its session closed, or its last holder let go.
    pub(crate) fn reach(&self) -> Option<Shared<E>> {
        let EngineAt {
            row,
            generation: at,
        } = self.at;
        ROWS.with(|rows| {
            let engine = rows.get(row)?.engine?;
            if generation(mark_of(row)) != at {
                return None;
            }
            // SAFETY: the row holds, at the generation this reach names, the engine the fill that
            // made the reach put there, an `E` that is the value of a `Shared<E>` whose place
            // stands while the row holds it (`RowClaim::fill`); the count is taken under the lock
            // the clear takes it out under.
            unsafe { Shared::retain_live(engine.cast::<E>()) }
        })
    }
}

#[cfg(feature = "query")]
impl<E: FanCanceller> ReachEngine<E> {
    /// What ends the legs of a get's fan this engine issued, reached through its row: nothing of
    /// the engine is kept standing, and a fan that ends past the session's close reaches nothing.
    pub(crate) fn canceller(self) -> Canceller {
        Canceller::Engine {
            at: self.at,
            ends: Self::fan_ended,
        }
    }

    /// Tell the engine `at` names `end` while it can be reached, under a count of it taken for
    /// the call: what [`Self::canceller`] names, of the reach's own type.
    fn fan_ended(at: EngineAt, end: FanEnd) {
        if let Some(engine) = Self::named(at).reach() {
            end.tell(&*engine);
        }
    }
}

/// A row taken for an engine an open is making ([`Self::take`]): no other open takes it, and no
/// reach reaches anything through it, until it is filled; let go of unfilled, it is vacant again.
pub struct RowClaim {
    row: usize,
}

impl RowClaim {
    /// Take a vacant row for an engine an open is about to make, before it reserves anything for
    /// it; `None` when every row holds an engine or is taken, which refuses the open of one more
    /// session.
    pub fn take() -> Option<Self> {
        ROWS.with(|rows| {
            let (row, _) = rows
                .iter()
                .enumerate()
                .find(|(row, held)| held.engine.is_none() && mark_of(*row) & CLAIMED == 0)?;
            set_mark(row, mark_of(row) | CLAIMED);
            Some(Self { row })
        })
    }

    /// Put `engine` in the row and answer the reach of it there.
    ///
    /// # Safety
    /// `engine` is what `Shared::as_ptr` answers of a holder of a `Shared<E>`, and its place
    /// stands until [`ReachEngine::clear`] is called on the reach answered.
    pub(crate) unsafe fn fill<E: Send + Sync>(self, engine: NonNull<E>) -> ReachEngine<E> {
        let row = self.row;
        core::mem::forget(self);
        ROWS.with(|rows| {
            rows.get_mut(row).map_or_else(ReachEngine::vacant, |held| {
                let mark = mark_of(row) & !CLAIMED;
                set_mark(row, mark);
                held.engine = Some(engine.cast::<()>());
                ReachEngine::named(EngineAt {
                    row,
                    generation: generation(mark),
                })
            })
        })
    }
}

impl Drop for RowClaim {
    fn drop(&mut self) {
        ROWS.with(|_| set_mark(self.row, mark_of(self.row) & !CLAIMED));
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The tests share the process's one table, with one another and with the engines the crate's
    /// other tests open: one at a time, and none fills the table, which `tests/engine_rows.rs`
    /// does in a binary of its own.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// An engine counted by its holders, as the cooperative engine is.
    fn engine() -> Shared<u32> {
        Shared::boxed(0)
    }

    fn put(engine: &Shared<u32>) -> Option<ReachEngine<u32>> {
        let claim = RowClaim::take()?;
        // SAFETY: every test clears what it put before its engine goes.
        Some(unsafe { claim.fill(Shared::as_ptr(engine)) })
    }

    /// An open engine is reached with a count taken for the length of the use, given back when the
    /// reach is let go. Turned red by a reach that takes no count, or one never given back.
    #[test]
    fn an_open_engine_is_reached_with_a_count_for_the_use() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = engine();
        let reach = put(&engine).expect("a vacant row");
        let reached = reach.reach().expect("the engine is open");
        assert!(
            Shared::ptr_eq(&reached, &engine),
            "the engine put in the row"
        );
        assert_eq!(Shared::holders(&engine), 2, "the reach holds a count");
        drop(reached);
        assert_eq!(Shared::holders(&engine), 1, "given back with the reach");
        reach.clear();
    }

    /// A reach kept past the close reaches nothing, even once its row holds another engine; the
    /// new engine's reach reaches it, and a second clear of the old reach takes nothing out.
    /// Turned red by a close that leaves the generation where it was, or a clear that empties a
    /// row another engine holds.
    #[test]
    fn a_reach_kept_past_the_close_reaches_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let first = engine();
        let old = put(&first).expect("a vacant row");
        old.clear();
        assert!(old.reach().is_none(), "closed, it is not reached");
        let second = engine();
        let new = put(&second).expect("a vacant row");
        assert!(
            old.reach().is_none(),
            "the row's new engine is not the old reach's"
        );
        old.clear();
        assert!(new.reach().is_some(), "an old clear takes nothing out");
        assert_eq!(
            Shared::holders(&first),
            1,
            "nothing was taken of the closed engine"
        );
        new.clear();
    }

    /// A reach of no engine reaches nothing, and its clear takes no engine out of any row.
    /// Turned red by a vacant reach that names a row of the table.
    #[test]
    fn a_vacant_reach_reaches_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = engine();
        let reach = put(&engine).expect("a vacant row");
        let vacant = ReachEngine::<u32>::vacant();
        assert!(vacant.reach().is_none());
        vacant.clear();
        assert!(reach.reach().is_some(), "the vacant clear took nothing out");
        assert_eq!(Shared::holders(&engine), 1);
        reach.clear();
    }

    /// A row is one word, the place of its engine, its mark one word of 32 bits beside it: the
    /// generation, the claim and the end share that word, and the table's one lock is in neither;
    /// a reach is the row and the generation. Turned red by a row that holds a table of
    /// operations, its mark or a lock of its own, or a mark wider than 32 bits.
    #[test]
    fn a_row_is_one_word_and_its_mark_one_word_of_32_bits() {
        assert_eq!(core::mem::size_of::<Row>(), core::mem::size_of::<usize>());
        assert_eq!(core::mem::size_of_val(&MARKS), caps::ENGINE_ROWS * 4);
        assert_eq!(
            core::mem::size_of::<ReachEngine<u32>>(),
            core::mem::size_of::<EngineAt>()
        );
    }

    /// An open engine's reach is current. Once its session ends on its own the reach is no longer
    /// current, though it still reaches the engine; the close clears the end with the row, and an
    /// old reach's end marks nothing of the row after. A vacant reach is never current. Turned red
    /// by an end that marks nothing, an ended engine no longer reached, a clear that leaves the end
    /// on the row for its next engine, or an old reach that ends it.
    #[test]
    fn an_ended_session_is_reached_but_not_current_until_its_row_is_cleared() {
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let first = engine();
        let old = put(&first).expect("a vacant row");
        assert!(old.is_current(), "an open engine's reach is current");
        old.end();
        assert!(!old.is_current(), "ended, it is not current");
        drop(old.reach().expect("an ended engine is still reached"));
        old.clear();
        assert!(!old.is_current(), "closed, it is not current");
        // The row may be taken by an open of another test from here on, which claims and fills
        // it but ends nothing.
        assert_eq!(
            mark_of(old.at.row) & ENDED,
            0,
            "the end went with the clear"
        );
        old.end();
        assert_eq!(
            mark_of(old.at.row) & ENDED,
            0,
            "an old reach ends nothing of the row's next engine"
        );
        assert!(!ReachEngine::<u32>::vacant().is_current());
        assert_eq!(
            Shared::holders(&first),
            1,
            "nothing was kept of the ended engine"
        );
    }

    /// An engine that ends the legs of the fans it issued.
    #[cfg(feature = "query")]
    #[derive(Default)]
    struct Cancels {
        cancelled: std::sync::atomic::AtomicUsize,
        over: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "query")]
    impl FanCanceller for Cancels {
        fn cancel_fan(&self, _key: wz_capi_port::cancellation::FanKey) {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }

        fn fan_over(&self, _key: wz_capi_port::cancellation::FanKey) {
            self.over.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A fan whose engine was attached by its row is cancelled through the engine while the
    /// engine is open, the count taken for the cancel given back after it, and a fan dropped
    /// uncancelled is told over the same way; once the engine closed, the cancel reaches nothing.
    /// Turned red by an engine canceller that ends no leg, tells the wrong end, keeps the count it
    /// took, or reaches an engine past its close.
    #[cfg(feature = "query")]
    #[test]
    fn a_fan_attached_by_its_engines_row_is_cancelled_only_while_the_engine_is_open() {
        use wz_capi_port::cancellation::CancellableFan;
        let _serial = SERIAL.lock().unwrap_or_else(|held| held.into_inner());
        let engine = Shared::boxed(Cancels::default());
        let claim = RowClaim::take().expect("a vacant row");
        // SAFETY: the engine is cleared out of its row before it goes, below.
        let reach = unsafe { claim.fill(Shared::as_ptr(&engine)) };
        let open = CancellableFan::new();
        assert!(open.attach(reach.canceller()));
        open.cancel();
        assert_eq!(
            engine.cancelled.load(Ordering::SeqCst),
            1,
            "the engine ended its legs"
        );
        assert_eq!(
            Shared::holders(&engine),
            1,
            "the cancel's count was given back"
        );
        let dropped = CancellableFan::new();
        assert!(dropped.attach(reach.canceller()));
        drop(dropped);
        assert_eq!(
            engine.over.load(Ordering::SeqCst),
            1,
            "the dropped fan is over"
        );
        let closed = CancellableFan::new();
        assert!(closed.attach(reach.canceller()));
        reach.clear();
        closed.cancel();
        assert_eq!(
            engine.cancelled.load(Ordering::SeqCst),
            1,
            "a closed engine is not reached"
        );
    }
}
