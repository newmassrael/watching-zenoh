// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The control block of a session's engine, one row of the process's table of engines, and a reach
//! of the engine through it that keeps nothing of it standing ([`ReachEngine`]): what a holder that
//! must not keep the session open holds (a key expression the program keeps, a query kept past its
//! callback, a cancellation token, the engine's own reach), as a weak count of a heap's would.
//!
//! An open claims a row before it reserves anything, puts its engine in it once the engine is made,
//! and its close takes the engine out and moves the row's generation on. A reach names the row and
//! the generation the row was at when the engine was put in it, so a reach kept past the close finds
//! another generation, or the row vacant, and reaches nothing, whatever the row holds since.
//! Reaching takes a count of the engine under the rows' lock, the lock the close takes the engine
//! out under, so an engine is never reached past its close nor once its last holder has let go.
//! Whether the session is still open is read from the row's mark alone, with no lock and no count
//! ([`ReachEngine::is_current`]): a reply asks it of every answer.
//!
//! Where the rows come from is the build's storage policy, one decision for the whole table
//! ([`RowSource`] of `wz_session_core::bounded::Profile`). On the fixed policy the rows lie in
//! static memory, the build's `ENGINE_ROWS` of them, and that count is the one bound of the sessions
//! open at once. On the heap policy no row lies in static memory: an open takes a row of the heap
//! when the table holds no vacant one, and the table keeps it, generation and all, for the next
//! open, so the sessions open at once have no bound but the heap's, as zenoh-pico allocates each
//! session it opens. Where a session lays its own tables (lent from its arena at the open, or in a
//! region the build laid out) is another axis and decides nothing here. No row is ever given back
//! on either policy, so a reach names its row by where it lies, and the row stands for as long as
//! the process.
//!
//! The sessions a program states through an ABI's doors that reserve its pools are a count of
//! this table's ([`RowClaim::hold_to`]): the table is held to that many rows, those past them
//! withheld from the opens and, on the heap policy, none taken of the heap past them, so the open
//! of one more session is refused by its claim, until the count is let go of with the pools. The
//! count is no second table: a session takes its row and nothing else.
//!
//! The table is this engine's: a reach is of the type the engine was put in as, and reaching it is
//! a count of that type's `Shared` taken where it lies, so no table of operations stands between a
//! reach and its engine. What takes the rows' lock and is asked of more than one place (a claim, a
//! claim let go of unfilled, a close) is one body out of line, so the lock is laid out once for it.

use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use wz_capi_port::cancellation::EngineAt;
#[cfg(feature = "query")]
use wz_capi_port::cancellation::{Canceller, FanCanceller, FanEnd};
use wz_capi_port::sync::Lock;
use wz_runtime_coop::kept::Shared;
use wz_session_core::bounded::{Heap, Profile, Static};
use wz_session_core::caps;

/// The bit of a row's mark that says an open has taken the row for the engine it is making.
const CLAIMED: u32 = 1;

/// The bit of a row's mark that says the session of the engine it holds ended on its own, its
/// engine still in the row: reached as before, but no longer current ([`ReachEngine::end`]).
const ENDED: u32 = 2;

/// The bit of a row's mark that says no open takes the row: the table is held to a count of
/// sessions that leaves the row out ([`RowClaim::hold_to`]), until the count is let go of.
const WITHHELD: u32 = 4;

/// What a row's mark moves on by at a close: one generation, in the bits above [`CLAIMED`],
/// [`ENDED`] and [`WITHHELD`].
const GENERATION_STEP: u32 = 8;

/// The generation a row's mark is at.
const fn generation(mark: u32) -> u32 {
    mark & !(CLAIMED | ENDED | WITHHELD)
}

/// What the rows' lock lends while it is held, and nothing else makes: the one way to a word that
/// is read and written only under that lock ([`UnderLock`]).
struct Locked;

/// The one lock of every row and every table of rows: what each takes it for (a claim, a fill, a
/// clear, a reach) is a few words read and written, so one lock costs no wait a lock for each row
/// would spare, and the rows hold no lock of their own.
static ROWS_LOCK: Lock<Locked> = Lock::new(Locked);

/// A word read and written only with the rows' lock held, through what the lock lends.
struct UnderLock<T>(UnsafeCell<T>);

// SAFETY: the word is reached only through `get` and `set`, which take what the rows' one lock
// lends while it is held, so no two threads reach it at once; the words kept so are the place of an
// engine that is `Send + Sync` (`RowClaim::fill`), rows of the heap, which are `Sync`, and a flag.
unsafe impl<T: Copy> Sync for UnderLock<T> {}

impl<T: Copy> UnderLock<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The word, read with the rows' lock held.
    fn get(&self, _locked: &Locked) -> T {
        // SAFETY: the rows' lock is held, as only it lends a `Locked`, so nothing writes the word
        // meanwhile.
        unsafe { *self.0.get() }
    }

    /// Write the word, with the rows' lock held.
    fn set(&self, _locked: &Locked, value: T) {
        // SAFETY: as `get`: nothing else reads or writes the word while the lock is held.
        unsafe { *self.0.get() = value }
    }
}

/// One row: the control block of one session's engine. Its mark (the generation it is at, whether
/// an open claimed it, whether its session ended, whether a count of sessions withholds it) is one
/// word a reach reads with no lock; where the engine it holds lies is a word under the rows' lock.
struct Row {
    /// Written only under the rows' lock, each change one store; read under it, and without it by
    /// [`ReachEngine::is_current`].
    mark: AtomicU32,
    engine: UnderLock<Option<NonNull<()>>>,
}

impl Row {
    /// A row marked `mark` that holds no engine.
    const fn marked(mark: u32) -> Self {
        Self {
            mark: AtomicU32::new(mark),
            engine: UnderLock::new(None),
        }
    }

    /// The row's mark, read under the rows' lock.
    fn mark(&self) -> u32 {
        self.mark.load(Ordering::Relaxed)
    }

    /// Set the row's mark, under the rows' lock: published to a lock-free reader of it with what
    /// was written before.
    fn set_mark(&self, value: u32) {
        self.mark.store(value, Ordering::Release);
    }

    /// Whether an open may take the row: it holds no engine, no open has claimed it and no count of
    /// sessions withholds it.
    fn is_vacant(&self, locked: &Locked) -> bool {
        self.engine.get(locked).is_none() && self.mark() & (CLAIMED | WITHHELD) == 0
    }

    /// Whether a session holds the row: its engine is in it, or an open claimed it for the engine
    /// it is making.
    fn is_open(&self, locked: &Locked) -> bool {
        self.engine.get(locked).is_some() || self.mark() & CLAIMED != 0
    }

    /// Where the row lies: what a reach names it by.
    fn at(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }
}

/// A row the heap policy took from the heap, and the row the table took before it. Never given
/// back, so a reach of it is a reach of a row for as long as the process.
struct GrownRow {
    row: Row,
    next: UnderLock<Option<&'static GrownRow>>,
}

#[cfg(all(test, feature = "std"))]
std::thread_local! {
    /// The rows of the heap the claims of this thread took (`RowClaim::rows_taken_here`).
    static ROWS_TAKEN_HERE: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

impl GrownRow {
    /// `count` vacant rows of the heap at their first generation, in one block, each linked before
    /// the next and the last before `next`: the first of them, or `None`, nothing taken, when the
    /// heap has no room for the block. Never given back, as a row taken for an open is not.
    fn vacant_block(count: usize, next: Option<&'static GrownRow>) -> Option<&'static Self> {
        let layout = Layout::array::<Self>(count).ok()?;
        if layout.size() == 0 {
            return None;
        }
        // SAFETY: the layout is not of zero bytes.
        let place = NonNull::new(unsafe { alloc::alloc::alloc(layout) })?.cast::<Self>();
        let mut first = next;
        for at in (0..count).rev() {
            // SAFETY: the heap gave `place` for `count` rows, each aligned for a `GrownRow`, and
            // `at` is one of them; each is written once here and never given back, so the row it
            // lends stands for as long as the process.
            let row = unsafe {
                let row = place.as_ptr().add(at);
                row.write(Self {
                    row: Row::marked(0),
                    next: UnderLock::new(first),
                });
                &*row
            };
            first = Some(row);
        }
        first
    }

    /// A row of the heap claimed for the open that asked for it, at its first generation, linked
    /// before `next`; `None` when the heap has no room for it.
    fn claimed(next: Option<&'static GrownRow>) -> Option<&'static Self> {
        // SAFETY: a grown row is not of zero bytes.
        let place = NonNull::new(unsafe { alloc::alloc::alloc(Layout::new::<Self>()) })?;
        #[cfg(all(test, feature = "std"))]
        ROWS_TAKEN_HERE.with(|taken| taken.set(taken.get().saturating_add(1)));
        let place = place.cast::<Self>();
        // SAFETY: the heap gave `place` for a `GrownRow`, aligned for it; it is written once here
        // and never given back, so the row it lends stands for as long as the process.
        unsafe {
            place.as_ptr().write(Self {
                row: Row::marked(CLAIMED),
                next: UnderLock::new(next),
            });
            Some(place.as_ref())
        }
    }
}

/// A table of rows of the storage policy its parameters name: `FIXED` rows in static memory, and
/// where `GROWS` holds the rows it took from the heap, newest first, each kept for the next open
/// once its session closed. The two policies are two instances of it ([`RowSource`]); how a row
/// is claimed, filled, cleared and reached is written once.
struct EngineRows<const FIXED: usize, const GROWS: bool> {
    fixed: [Row; FIXED],
    grown: UnderLock<Option<&'static GrownRow>>,
    /// The table is held to a count of sessions ([`RowClaim::hold_to`]): on the heap policy it
    /// takes no row of the heap until the count is let go of.
    held: UnderLock<bool>,
}

impl<const FIXED: usize, const GROWS: bool> EngineRows<FIXED, GROWS> {
    /// A table that holds no engine and is held to no count.
    const fn new() -> Self {
        Self {
            fixed: [const { Row::marked(0) }; FIXED],
            grown: UnderLock::new(None),
            held: UnderLock::new(false),
        }
    }

    /// Every row of the table: its static rows, then those it took of the heap, newest first.
    fn rows<'a>(&'static self, locked: &'a Locked) -> impl Iterator<Item = &'static Row> + 'a {
        let first = if GROWS { self.grown.get(locked) } else { None };
        let grown = core::iter::successors(first, move |kept| kept.next.get(locked));
        self.fixed.iter().chain(grown.map(|kept| &kept.row))
    }

    /// Take a vacant row for an engine an open is about to make: a row of the table that holds no
    /// engine, that no open took and that no count withholds, and past them on the heap policy one
    /// more row of the heap, kept by the table from then on. `None` when every row of a fixed table
    /// is held, taken or withheld, when the table is held to a count every row of which is open, or
    /// when the heap has no room for one more row. The one body every open calls, out of line.
    #[inline(never)]
    fn claim(&'static self) -> Option<RowClaim> {
        ROWS_LOCK.with(|locked| {
            let locked: &Locked = locked;
            if let Some(row) = self.rows(locked).find(|row| row.is_vacant(locked)) {
                row.set_mark(row.mark() | CLAIMED);
                return Some(RowClaim { row });
            }
            if !GROWS || self.held.get(locked) {
                return None;
            }
            // Taken of the heap with the lock held: the allocator takes no lock of the rows, and a
            // claim is one taking of the lock, whichever row it finds.
            let grown = GrownRow::claimed(self.grown.get(locked))?;
            self.grown.set(locked, Some(grown));
            Some(RowClaim { row: &grown.row })
        })
    }

    /// Hold the table to `sessions` rows ([`RowClaim::hold_to`]): on the heap policy the rows it
    /// lacks are taken of the heap now, in one block, and the table takes none after; the rows past
    /// the count are withheld from the opens. Refused while a session holds a row, and when the
    /// heap has no room for the block; either way the table is as it was.
    fn hold_to(&'static self, sessions: usize) -> Result<(), RowsRefused> {
        ROWS_LOCK.with(|locked| {
            let locked: &Locked = locked;
            if self.rows(locked).any(|row| row.is_open(locked)) {
                return Err(RowsRefused::Open);
            }
            if GROWS {
                let rows = self.rows(locked).count();
                if let Some(lacking) = sessions.checked_sub(rows).filter(|&lacking| lacking > 0) {
                    let first = GrownRow::vacant_block(lacking, self.grown.get(locked))
                        .ok_or(RowsRefused::NoMemory)?;
                    self.grown.set(locked, Some(first));
                }
                self.held.set(locked, true);
            }
            for (at, row) in self.rows(locked).enumerate() {
                let mark = row.mark() & !WITHHELD;
                row.set_mark(if at < sessions { mark } else { mark | WITHHELD });
            }
            Ok(())
        })
    }

    /// Let go of the count the table is held to: every row may be taken again and, on the heap
    /// policy, the table takes rows of the heap again. `false`, the count kept, while a session
    /// holds a row.
    fn let_go_of_count(&'static self) -> bool {
        ROWS_LOCK.with(|locked| {
            let locked: &Locked = locked;
            if self.rows(locked).any(|row| row.is_open(locked)) {
                return false;
            }
            for row in self.rows(locked) {
                row.set_mark(row.mark() & !WITHHELD);
            }
            self.held.set(locked, false);
            true
        })
    }
}

/// Where the process's table of engines takes its rows from, by a storage policy of the session
/// core (`wz_session_core::bounded`): the build's policy (`Profile`) names the table the process
/// opens its sessions in ([`ENGINES`]).
trait RowSource {
    /// The table of rows of the policy.
    type Rows: Sync + 'static;
}

/// The heap policy: no row in static memory, a row of the heap for an open that finds none vacant,
/// kept for the next open, and no bound but the heap's.
impl RowSource for Heap {
    type Rows = EngineRows<0, true>;
}

/// The fixed policy: the build's `ENGINE_ROWS` rows in static memory, the one bound of the
/// sessions open at once, and nothing of the heap.
impl RowSource for Static {
    type Rows = EngineRows<{ caps::ENGINE_ROWS }, false>;
}

/// The process's table of engines, of the build's storage policy.
static ENGINES: <Profile as RowSource>::Rows = EngineRows::new();

/// A reach of an engine of type `E` through its row: where the row lies and the generation it was
/// at, copied freely, keeping nothing of the engine standing.
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
            row: 0,
            generation: 0,
        })
    }

    const fn named(at: EngineAt) -> Self {
        Self {
            at,
            engine: PhantomData,
        }
    }

    /// The row the reach names; `None` for a vacant reach.
    fn row(&self) -> Option<&'static Row> {
        // SAFETY: a reach names no row (zero) or where a row lies that `RowClaim::fill` put an
        // engine in: a row of a table in a static, or a row of the heap that no table gives back,
        // either of which stands for as long as the process.
        unsafe { (self.at.row as *const Row).as_ref() }
    }

    /// Take the engine out of its row, at its session's close: no reach of it reaches it from
    /// then on, and the row is vacant for the next open. A count taken before is kept until it is
    /// given back. A reach whose row moved on already takes nothing out.
    pub(crate) fn clear(&self) {
        clear_row(self.row(), self.at.generation);
    }

    /// Mark the engine's session as ended on its own, its engine kept in its row: what a session
    /// a step ended says (its dial role's link lost, with no redial), so that a reach of it is no
    /// longer current ([`Self::is_current`]) though it still reaches the engine. A reach whose row
    /// moved on marks nothing; the close that follows clears the mark with the row.
    pub(crate) fn end(&self) {
        let Some(row) = self.row() else {
            return;
        };
        ROWS_LOCK.with(|locked| {
            let mark = row.mark();
            if generation(mark) == self.at.generation && row.engine.get(locked).is_some() {
                row.set_mark(mark | ENDED);
            }
        });
    }

    /// Whether the engine is in its row and its session has not ended: what a reply asks before
    /// anything else, answered by one load of the row's mark, with no lock and no count of the
    /// engine. A close moves the generation on, and a step that ends the session marks it before
    /// it says the session closed, so a reach that is not current reaches a closed session or
    /// none. A vacant reach is never current.
    pub(crate) fn is_current(&self) -> bool {
        self.row()
            .is_some_and(|row| row.mark.load(Ordering::Acquire) == self.at.generation)
    }

    /// A holder of the engine, with a count of it taken for as long as the answer is held; `None`
    /// once its session closed, or its last holder let go.
    pub(crate) fn reach(&self) -> Option<Shared<E>> {
        let row = self.row()?;
        ROWS_LOCK.with(|locked| {
            if generation(row.mark()) != self.at.generation {
                return None;
            }
            let engine = row.engine.get(locked)?;
            // SAFETY: the row holds, at the generation this reach names, the engine the fill that
            // made the reach put there, an `E` that is the value of a `Shared<E>` whose place
            // stands while the row holds it (`RowClaim::fill`); the count is taken under the lock
            // the clear takes it out under.
            unsafe { Shared::retain_live(engine.cast::<E>()) }
        })
    }
}

/// Take the engine out of `row`, the row of a reach that names the generation `named`, unless the
/// row moved on from it or holds no engine: [`ReachEngine::clear`], of no engine's type, so the
/// session's close and its engine's last drop call one body.
#[inline(never)]
fn clear_row(row: Option<&'static Row>, named: u32) {
    let Some(row) = row else {
        return;
    };
    ROWS_LOCK.with(|locked| {
        let mark = row.mark();
        if generation(mark) == named && row.engine.get(locked).is_some() {
            row.engine.set(locked, None);
            row.set_mark(generation(mark).wrapping_add(GENERATION_STEP));
        }
    });
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

/// Why the process's table of engines was not held to a count of sessions
/// ([`RowClaim::hold_to`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowsRefused {
    /// A session holds a row of the table, or an open has claimed one: the count would leave it
    /// out while it is open.
    Open,
    /// The heap had no room for the rows the count asks.
    NoMemory,
}

/// A row taken for an engine an open is making ([`Self::take`]): no other open takes it, and no
/// reach reaches anything through it, until it is filled; let go of unfilled, it is vacant again.
pub struct RowClaim {
    row: &'static Row,
}

impl RowClaim {
    /// Take a row of the process's table for an engine an open is about to make, before it
    /// reserves anything for it, where the build's storage policy says: a vacant row of the
    /// table, or on the heap policy one more row of the heap. `None` when a fixed table has every
    /// row held or taken, when the table is held to a count of sessions all open
    /// ([`Self::hold_to`]), or when the heap has no room for a row, which refuses the open of one
    /// more session.
    pub fn take() -> Option<Self> {
        ENGINES.claim()
    }

    /// Hold the process's table to `sessions` rows: the count of sessions open at once a program
    /// states through the doors that reserve an ABI's pools. An open past them is refused by its
    /// claim ([`Self::take`]) until the count is let go of ([`Self::let_go_of_count`]). On the heap
    /// policy the table takes the rows it lacks of the heap now, and none after; on the fixed
    /// policy a count past the table's rows is held to them. Refused while a session holds a row
    /// or an open has claimed one ([`RowsRefused::Open`]), and when the heap has no room for the
    /// rows ([`RowsRefused::NoMemory`]): either way the table, and the heap, are as they were.
    pub fn hold_to(sessions: usize) -> Result<(), RowsRefused> {
        ENGINES.hold_to(sessions)
    }

    /// Let go of the count of sessions the process's table is held to ([`Self::hold_to`]), so the
    /// opens take rows as the storage policy says again: what the doors that give an ABI's pools
    /// up ask. `false`, and the count kept, while a session holds a row or an open has claimed one;
    /// `true` too when the table is held to no count.
    pub fn let_go_of_count() -> bool {
        ENGINES.let_go_of_count()
    }

    /// How many rows of the heap the claims of the calling thread took. The process's table takes
    /// one only for a claim that finds none it kept vacant, which the opens of every thread decide,
    /// so a test that counts the allocations of an open on its own thread sets the row apart.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn rows_taken_here() -> u64 {
        ROWS_TAKEN_HERE.with(core::cell::Cell::get)
    }

    /// Put `engine` in the row and answer the reach of it there.
    ///
    /// # Safety
    /// `engine` is what `Shared::as_ptr` answers of a holder of a `Shared<E>`, and its place
    /// stands until [`ReachEngine::clear`] is called on the reach answered.
    pub(crate) unsafe fn fill<E: Send + Sync>(self, engine: NonNull<E>) -> ReachEngine<E> {
        let row = self.row;
        core::mem::forget(self);
        ROWS_LOCK.with(|locked| {
            let mark = row.mark() & !CLAIMED;
            row.set_mark(mark);
            row.engine.set(locked, Some(engine.cast::<()>()));
            ReachEngine::named(EngineAt {
                row: row.at(),
                generation: generation(mark),
            })
        })
    }
}

impl Drop for RowClaim {
    fn drop(&mut self) {
        let_go_unfilled(self.row);
    }
}

/// Let go of `row`, claimed and never filled, so the next open may take it: the drop of a
/// [`RowClaim`], one body for every way an open fails after its claim.
#[inline(never)]
fn let_go_unfilled(row: &'static Row) {
    ROWS_LOCK.with(|_| row.set_mark(row.mark() & !CLAIMED));
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// An engine counted by its holders, as the cooperative engine is.
    fn engine() -> Shared<u32> {
        Shared::try_boxed(0).expect("the heap has room for the engine")
    }

    /// The engine `held` put in a row `table` lends, as an open puts its engine.
    fn put<const FIXED: usize, const GROWS: bool>(
        table: &'static EngineRows<FIXED, GROWS>,
        held: &Shared<u32>,
    ) -> Option<ReachEngine<u32>> {
        let claim = table.claim()?;
        // SAFETY: every test clears what it put before its engine goes.
        Some(unsafe { claim.fill(Shared::as_ptr(held)) })
    }

    /// How many rows `table` took of the heap.
    fn grown<const FIXED: usize, const GROWS: bool>(
        table: &'static EngineRows<FIXED, GROWS>,
    ) -> usize {
        ROWS_LOCK.with(|locked| {
            let locked: &Locked = locked;
            core::iter::successors(table.grown.get(locked), |kept| kept.next.get(locked)).count()
        })
    }

    /// An open engine is reached with a count taken for the length of the use, given back when the
    /// reach is let go. Turned red by a reach that takes no count, or one never given back.
    #[test]
    fn an_open_engine_is_reached_with_a_count_for_the_use() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        let held = engine();
        let reach = put(&TABLE, &held).expect("a row of the heap");
        let reached = reach.reach().expect("the engine is open");
        assert!(Shared::ptr_eq(&reached, &held), "the engine put in the row");
        assert_eq!(Shared::holders(&held), 2, "the reach holds a count");
        drop(reached);
        assert_eq!(Shared::holders(&held), 1, "given back with the reach");
        reach.clear();
    }

    /// On the fixed policy the table's rows are the one bound: with every row holding an open
    /// session, the claim of one more open is refused and nothing is taken of the heap; the close of
    /// one vacates its row, which the next open takes at the next generation, and the table is full
    /// again. Turned red by a fixed table that grows past its rows (`if !GROWS` in `claim`), or a
    /// close that leaves the row held or its generation where it was.
    #[test]
    fn a_fixed_table_refuses_the_open_past_its_rows_until_a_close_vacates_one() {
        static TABLE: EngineRows<3, false> = EngineRows::new();
        let engines: Vec<Shared<u32>> = (0..3).map(|_| engine()).collect();
        let reaches: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&TABLE, held).expect("a vacant row"))
            .collect();
        assert!(TABLE.claim().is_none(), "the fourth open is refused");
        assert_eq!(grown(&TABLE), 0, "a fixed table takes nothing of the heap");

        let closed = reaches[1];
        closed.clear();
        let next = engine();
        let reopened = put(&TABLE, &next).expect("the row the close vacated");
        assert_eq!(
            reopened.at.row, closed.at.row,
            "the vacated row is the one taken"
        );
        assert_eq!(
            reopened.at.generation,
            closed.at.generation.wrapping_add(GENERATION_STEP),
            "its generation moved on"
        );
        assert!(TABLE.claim().is_none(), "the table is full again");
        for reach in reaches.iter().chain([&reopened]) {
            reach.clear();
        }
    }

    /// On the heap policy the sessions open at once have no bound of the table: eleven open at
    /// once, each on a row of the heap; the close of one leaves its row to the table, and the next
    /// open takes that row at the next generation and takes nothing more of the heap. Turned red by
    /// a heap table that refuses past a count, takes a row of the heap while one it kept is vacant
    /// (`first` in `claim`), or reuses a row at its old generation.
    #[test]
    fn a_heap_table_opens_eleven_at_once_and_lends_a_closed_ones_row_to_the_next_open() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        let engines: Vec<Shared<u32>> = (0..11).map(|_| engine()).collect();
        let reaches: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&TABLE, held).expect("a row of the heap"))
            .collect();
        assert_eq!(
            grown(&TABLE),
            11,
            "a row of the heap for each session open at once"
        );
        assert!(
            reaches.iter().all(|reach| reach.reach().is_some()),
            "every open session is reached"
        );

        let closed = reaches[4];
        closed.clear();
        let next = engine();
        let reopened = put(&TABLE, &next).expect("the row the close vacated");
        assert_eq!(
            reopened.at.row, closed.at.row,
            "the table kept the row for the next open"
        );
        assert_eq!(
            reopened.at.generation,
            closed.at.generation.wrapping_add(GENERATION_STEP),
            "its generation moved on"
        );
        assert_eq!(grown(&TABLE), 11, "nothing more is taken of the heap");
        for reach in reaches.iter().chain([&reopened]) {
            reach.clear();
        }
        assert!(
            engines.iter().all(|held| Shared::holders(held) == 1),
            "the table holds no count of an engine"
        );
    }

    /// A reach kept past the close reaches nothing and is not current, even once its row holds
    /// the engine of the next open; that engine's reach reaches it, and the old reach's clear and
    /// end touch nothing of it. The same on either policy, the table holding one row so the next
    /// open takes the closed one's. Turned red by a close that leaves the generation where it
    /// was, a reach that reads the engine before the generation, or a clear that empties a row
    /// another engine holds.
    fn a_reach_kept_past_its_close_reaches_nothing_in<const FIXED: usize, const GROWS: bool>(
        table: &'static EngineRows<FIXED, GROWS>,
    ) {
        let first = engine();
        let old = put(table, &first).expect("a vacant row");
        old.clear();
        assert!(old.reach().is_none(), "closed, it is not reached");
        assert!(!old.is_current(), "closed, it is not current");
        let second = engine();
        let new = put(table, &second).expect("the vacated row");
        assert_eq!(new.at.row, old.at.row, "the next open is in the same row");
        assert!(
            old.reach().is_none(),
            "the row's new engine is not the old reach's"
        );
        assert!(!old.is_current(), "nor is the old reach current");
        old.clear();
        old.end();
        assert!(new.reach().is_some(), "an old clear takes nothing out");
        assert!(new.is_current(), "an old end ends nothing");
        assert_eq!(
            Shared::holders(&first),
            1,
            "nothing was taken of the closed engine"
        );
        new.clear();
    }

    #[test]
    fn a_reach_kept_past_its_close_reaches_nothing_on_the_fixed_policy() {
        static TABLE: EngineRows<1, false> = EngineRows::new();
        a_reach_kept_past_its_close_reaches_nothing_in(&TABLE);
    }

    #[test]
    fn a_reach_kept_past_its_close_reaches_nothing_on_the_heap_policy() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        a_reach_kept_past_its_close_reaches_nothing_in(&TABLE);
        assert_eq!(grown(&TABLE), 1, "the second open took the first one's row");
    }

    /// A reach of no engine reaches nothing, and its clear takes no engine out of any row.
    /// Turned red by a vacant reach that names a row.
    #[test]
    fn a_vacant_reach_reaches_nothing() {
        static TABLE: EngineRows<1, false> = EngineRows::new();
        let held = engine();
        let reach = put(&TABLE, &held).expect("a vacant row");
        let vacant = ReachEngine::<u32>::vacant();
        assert!(vacant.reach().is_none());
        assert!(!vacant.is_current());
        vacant.clear();
        assert!(reach.reach().is_some(), "the vacant clear took nothing out");
        assert_eq!(Shared::holders(&held), 1);
        reach.clear();
    }

    /// A claim let go of unfilled leaves its row vacant for the next open, on either policy, and a
    /// heap table takes no other row for it. Turned red by a claim whose drop leaves the row taken.
    #[test]
    fn a_claim_let_go_of_unfilled_leaves_its_row_vacant() {
        static FIXED: EngineRows<1, false> = EngineRows::new();
        static GROWN: EngineRows<0, true> = EngineRows::new();
        drop(FIXED.claim().expect("a vacant row"));
        assert!(FIXED.claim().is_some(), "the row let go of is vacant again");
        drop(GROWN.claim().expect("a row of the heap"));
        drop(GROWN.claim().expect("the row let go of"));
        assert_eq!(grown(&GROWN), 1, "the row let go of was taken again");
    }

    /// A row is the place of its engine and a mark of 32 bits beside it, under no lock of its own;
    /// a reach is where the row lies and its generation. The heap policy's table holds no row in
    /// static memory, only the word that keeps its rows of the heap and the flag of its count, and
    /// the fixed policy's holds the build's rows beside the same; the process's table is the
    /// build's policy's. Turned red by a row that holds a lock or a table of operations, or a
    /// policy that names the other's table.
    #[test]
    fn a_policy_names_its_table_and_a_row_is_its_engine_and_its_mark() {
        let word = core::mem::size_of::<usize>();
        assert!(core::mem::size_of::<Row>() <= 2 * word);
        assert_eq!(
            core::mem::size_of::<ReachEngine<u32>>(),
            core::mem::size_of::<EngineAt>()
        );
        let heap = core::mem::size_of::<<Heap as RowSource>::Rows>();
        assert!(heap <= 2 * word, "no row of the heap policy's is static");
        let fixed = core::mem::size_of::<<Static as RowSource>::Rows>();
        assert_eq!(
            fixed,
            caps::ENGINE_ROWS * core::mem::size_of::<Row>() + heap
        );
        let built = if wz_session_core::bounded::ENFORCES_CAPACITY {
            fixed
        } else {
            heap
        };
        assert_eq!(core::mem::size_of_val(&ENGINES), built);
    }

    /// Whether the next open of `table` is refused, the claim it took, if any, let go of at once.
    fn refuses<const FIXED: usize, const GROWS: bool>(
        table: &'static EngineRows<FIXED, GROWS>,
    ) -> bool {
        table.claim().is_none()
    }

    /// A fixed table held to two of its three rows lets two sessions open and refuses the third,
    /// keeps the count while a session holds a row, and once the count is let go of every row is
    /// taken again; a reach kept past its close reaches nothing throughout. Turned red by a claim
    /// that takes a withheld row (`WITHHELD` in `is_vacant`), a count that withholds nothing past
    /// it, or a count let go of while a session is open (`is_open` in `let_go_of_count`).
    #[test]
    fn a_fixed_table_held_to_a_count_refuses_the_open_past_it_until_the_count_is_let_go_of() {
        static TABLE: EngineRows<3, false> = EngineRows::new();
        assert_eq!(TABLE.hold_to(2), Ok(()));
        let engines: Vec<Shared<u32>> = (0..3).map(|_| engine()).collect();
        let first = put(&TABLE, &engines[0]).expect("a row within the count");
        let second = put(&TABLE, &engines[1]).expect("a row within the count");
        assert!(refuses(&TABLE), "the open past the count is refused");
        assert!(!TABLE.let_go_of_count(), "kept while a session holds a row");
        assert!(refuses(&TABLE), "and still held to it");
        first.clear();
        let third = put(&TABLE, &engines[2]).expect("the row the close vacated");
        assert!(refuses(&TABLE), "the count is two sessions open at once");
        second.clear();
        third.clear();
        assert!(TABLE.let_go_of_count(), "let go of with no session open");
        let reaches: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&TABLE, held).expect("every row is taken again"))
            .collect();
        assert!(refuses(&TABLE), "the table's own rows still bound it");
        assert!(first.reach().is_none() && !first.is_current());
        for reach in &reaches {
            reach.clear();
        }
    }

    /// A heap table held to a count takes the rows it lacks of the heap at once, lets that many
    /// sessions open, refuses the next without taking a row of the heap for it, and once the count
    /// is let go of takes rows of the heap for the opens again. Turned red by a claim that grows a
    /// held table (`self.held` in `claim`), or a count that takes no row of the heap.
    #[test]
    fn a_heap_table_held_to_a_count_takes_its_rows_at_once_and_none_past_them() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        assert_eq!(TABLE.hold_to(2), Ok(()));
        assert_eq!(grown(&TABLE), 2, "the count's rows, taken before any open");
        let engines: Vec<Shared<u32>> = (0..3).map(|_| engine()).collect();
        let reaches: Vec<ReachEngine<u32>> = engines[..2]
            .iter()
            .map(|held| put(&TABLE, held).expect("a row of the count"))
            .collect();
        assert!(refuses(&TABLE), "the open past the count is refused");
        assert_eq!(grown(&TABLE), 2, "and took no row of the heap");
        assert!(!TABLE.let_go_of_count(), "kept while a session holds a row");
        for reach in &reaches {
            reach.clear();
        }
        assert!(TABLE.let_go_of_count());
        let more: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&TABLE, held).expect("the heap gives a row again"))
            .collect();
        assert_eq!(grown(&TABLE), 3, "one more row of the heap for the third");
        for reach in &more {
            reach.clear();
        }
    }

    /// A heap table that kept more rows from earlier opens than the count it is held to withholds
    /// those past the count: one session opens, the second is refused though a kept row is vacant.
    /// Turned red by a count that withholds only rows it took itself.
    #[test]
    fn a_count_withholds_the_kept_rows_past_it() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        let engines: Vec<Shared<u32>> = (0..3).map(|_| engine()).collect();
        let earlier: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&TABLE, held).expect("a row of the heap"))
            .collect();
        for reach in &earlier {
            reach.clear();
        }
        assert_eq!(TABLE.hold_to(1), Ok(()));
        assert_eq!(grown(&TABLE), 3, "no row is given back");
        let open = put(&TABLE, &engines[0]).expect("the one row of the count");
        assert!(refuses(&TABLE), "a kept row past the count is withheld");
        assert!(
            earlier.iter().all(|reach| reach.reach().is_none()),
            "a reach kept past its close reaches nothing"
        );
        open.clear();
        assert!(TABLE.let_go_of_count());
    }

    /// A count the heap cannot give rows for is refused and leaves the table as it was: held to no
    /// count, it takes a row of the heap for the next open. Turned red by a refused count that
    /// holds the table all the same (`held` set before the block is taken).
    #[test]
    fn a_count_the_heap_cannot_give_rows_for_is_refused_and_holds_nothing() {
        static TABLE: EngineRows<0, true> = EngineRows::new();
        assert_eq!(TABLE.hold_to(usize::MAX), Err(RowsRefused::NoMemory));
        assert_eq!(grown(&TABLE), 0, "nothing was taken of the heap");
        assert!(!refuses(&TABLE), "the table is held to no count");
    }

    /// A count asked while a session holds a row, or while an open has claimed one, is refused,
    /// and nothing is withheld: the next open is taken as before. Turned red by a count that
    /// withholds an open session's row (`is_open` in `hold_to`).
    #[test]
    fn a_count_asked_while_a_session_is_open_is_refused_and_withholds_nothing() {
        static TABLE: EngineRows<2, false> = EngineRows::new();
        let held = engine();
        let claim = TABLE.claim().expect("a vacant row");
        assert_eq!(
            TABLE.hold_to(0),
            Err(RowsRefused::Open),
            "an open claimed a row"
        );
        // SAFETY: the engine is cleared out of its row before it goes, below.
        let reach = unsafe { claim.fill(Shared::as_ptr(&held)) };
        assert_eq!(
            TABLE.hold_to(0),
            Err(RowsRefused::Open),
            "a session holds one"
        );
        let other = engine();
        let next = put(&TABLE, &other).expect("nothing was withheld");
        reach.clear();
        next.clear();
    }

    /// A count past a fixed table's rows is held to them, and a count of none refuses every open
    /// on either policy, the heap taking nothing for it; let go of, the opens are taken again.
    /// Turned red by a fixed table that grows past its rows for a count, or a count of none that
    /// lets an open take a row.
    #[test]
    fn a_count_past_a_fixed_tables_rows_is_held_to_them_and_a_count_of_none_refuses_every_open() {
        static FIXED: EngineRows<2, false> = EngineRows::new();
        static GROWN: EngineRows<0, true> = EngineRows::new();
        assert_eq!(FIXED.hold_to(5), Ok(()));
        let engines: Vec<Shared<u32>> = (0..2).map(|_| engine()).collect();
        let reaches: Vec<ReachEngine<u32>> = engines
            .iter()
            .map(|held| put(&FIXED, held).expect("a row of the table"))
            .collect();
        assert!(
            refuses(&FIXED),
            "the table's two rows bound the count of five"
        );
        assert_eq!(grown(&FIXED), 0);
        for reach in &reaches {
            reach.clear();
        }
        assert!(FIXED.let_go_of_count());

        assert_eq!(FIXED.hold_to(0), Ok(()));
        assert_eq!(GROWN.hold_to(0), Ok(()));
        assert!(refuses(&FIXED) && refuses(&GROWN), "no session opens");
        assert_eq!(grown(&GROWN), 0, "nothing was taken of the heap");
        assert!(FIXED.let_go_of_count() && GROWN.let_go_of_count());
        assert!(
            !refuses(&FIXED) && !refuses(&GROWN),
            "the opens are taken again"
        );
    }

    /// An open engine's reach is current. Once its session ends on its own the reach is no longer
    /// current, though it still reaches the engine; the close clears the end with the row, and an
    /// old reach's end marks nothing of the row after. Turned red by an end that marks nothing, an
    /// ended engine no longer reached, a clear that leaves the end on the row for its next engine,
    /// or an old reach that ends it.
    #[test]
    fn an_ended_session_is_reached_but_not_current_until_its_row_is_cleared() {
        static TABLE: EngineRows<1, false> = EngineRows::new();
        let first = engine();
        let old = put(&TABLE, &first).expect("a vacant row");
        assert!(old.is_current(), "an open engine's reach is current");
        old.end();
        assert!(!old.is_current(), "ended, it is not current");
        drop(old.reach().expect("an ended engine is still reached"));
        old.clear();
        assert!(!old.is_current(), "closed, it is not current");
        let row = old.row().expect("the reach names a row");
        assert_eq!(row.mark() & ENDED, 0, "the end went with the clear");
        let second = engine();
        let new = put(&TABLE, &second).expect("the vacated row");
        old.end();
        assert_eq!(
            row.mark() & ENDED,
            0,
            "an old reach ends nothing of the row's next engine"
        );
        assert!(new.is_current());
        assert_eq!(
            Shared::holders(&first),
            1,
            "nothing was kept of the ended engine"
        );
        new.clear();
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
        static TABLE: EngineRows<0, true> = EngineRows::new();
        let Ok(engine) = Shared::try_boxed(Cancels::default()) else {
            panic!("the heap has room for the engine");
        };
        let claim = TABLE.claim().expect("a row of the heap");
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
