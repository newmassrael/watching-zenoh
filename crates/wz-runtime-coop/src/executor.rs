// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative task pool: one executor for every profile of this runtime.
//!
//! A task is a CELL of a table ([`TaskCell`]): its future is written into the cell's bytes in
//! place, its wake and cancel flags are the cell's own, its result is written into the same bytes
//! after it, and when the task and its handle are both done the cell is free for the next. A
//! spawn allocates nothing, and a table that cannot take a task refuses it, COUNTED
//! ([`ExecutorState::refusals`]).
//!
//! ## Where the table lies
//!
//! - In a `static` the image declares (`TaskTable`, `session-slot`), which the runtime's cell
//!   starts (`RuntimeCell`): no heap at all.
//! - Reserved once, when the runtime is made (`CoopRuntime::reserved`, the heap profile):
//!   `tasks` cells and their `task_bytes` each, in one block. What an engine that owes no
//!   allocation after its open asks for: the table is the open's, and a spawn past it is refused.
//! - Grown when every cell is taken (`CoopRuntime::new`, the heap profile), by a chunk of bare
//!   cells that never moves; a cell keeps the bytes a spawn gave it for the next task that fits
//!   them, so a program that spawns the same tasks again allocates nothing after the first. A
//!   table reserved while its open lasts (`CoopRuntime::opening`) holds such cells beside the ones
//!   it reserved. What these do is reached only through the table that has them, so a runtime
//!   whose table is reserved links none of it.
//!
//! The first two refuse a task too large for their cells, or with an alignment past
//! [`CELL_ALIGN`], as [`SpawnRefusal::TooLarge`] with the future handed back; the third gives
//! the cell the bytes the task needs.
//!
//! ## Wakers and handles
//!
//! A waker is a reference to its task's cell, and waking it raises the cell's flag: no waker
//! allocates. A stale waker (a task that ended, a cell that was reused) raises the flag of the
//! cell's next task, which polls once for nothing: a spurious wake is allowed. The tables the
//! runtime owns (reserved, grown) are kept by a count: the runtime, every waker and every join
//! handle hold one, so a waker kept past the runtime (a socket's readiness, say) still points at
//! a cell, and the tasks themselves are dropped when the runtime is, as a heap of boxed futures
//! dropped them.
//!
//! ## The contract this makes with the profile
//!
//! The table is `Sync` by the profile's own rule and not by anything a compiler can check: tasks
//! are polled by ONE executor at a time (one core, or the engine's lock), and the only thing an
//! interrupt or another thread may do to a cell is raise its wake flag. Every other field is
//! touched only inside a critical section.

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::cell::RefCell;
use core::cell::{Cell, UnsafeCell};
use core::future::Future;
use core::marker::PhantomData;
#[cfg(feature = "session-slot")]
use core::mem::MaybeUninit;
use core::mem::{align_of, size_of, ManuallyDrop};
use core::pin::Pin;
use core::ptr;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::ptr::NonNull;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::alloc::Layout;
use critical_section::{CriticalSection, Mutex};
use wz_runtime_core::RuntimeError;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::atomic::Arc;
use crate::atomic::{AtomicBool, Ordering};

pub use crate::yield_now::{yield_now, YieldNow};

/// The alignment every cell's bytes have: the most a task's future or its output may ask for of a
/// fixed table.
pub const CELL_ALIGN: usize = 16;

/// The cells a grown table adds first, and the least it adds when it grows again.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
const FIRST_CHUNK: usize = 4;

/// How far a cell has come.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Nobody holds it; the next spawn may take it.
    Free,
    /// Taken by a spawn that is writing its future in.
    Spawning,
    /// Holds a future that is between polls.
    Live,
    /// The executor is polling, sweeping or finishing it.
    Polling,
    /// The task is over. Its output (or its cancellation) waits for the handle.
    Done,
}

/// How a cell's future is driven and dropped, written when the future is: the
/// three functions that know its type.
#[derive(Clone, Copy)]
struct Ops {
    /// Poll the future at the buffer; on `Ready` drop it there and write its
    /// output at the offset.
    poll: unsafe fn(*mut u8, usize, &mut Context<'_>) -> Poll<()>,
    /// Drop the future at the buffer (a task that is swept before it ends).
    drop_future: DropFn,
    /// Drop the output at the buffer (a result no handle took); `None` for an output with
    /// nothing to drop, whose cell is then freed in the section that ends its task.
    drop_output: Option<DropFn>,
}

/// Drop the value at the buffer, of a type erased with the task that wrote it.
type DropFn = unsafe fn(*mut u8);

/// What a cell's bookkeeping holds; touched only inside a critical section.
struct Meta {
    state: State,
    /// The local set (`CoopLocalSet`) the task was spawned on, 0 for none: a set counts its own
    /// tasks, and the heap profile's drops them when the set is gone.
    set: u32,
    /// A handle still points at this cell: it is not freed until the handle is
    /// consumed or dropped, so a handle never reads the next task's result.
    handle: bool,
    /// The handle aborted the task before it ended: it reads `JoinCancelled`.
    aborted: bool,
    /// The task's output is in the buffer at `out_off`.
    has_output: bool,
    out_off: usize,
    join_waker: Option<Waker>,
    ops: Option<Ops>,
    /// The cell's bytes and their length: set once for a fixed table, and for a grown one each
    /// time a task needs more than the cell has.
    buf: *mut u8,
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    cap: usize,
    /// The alignment the bytes of a grown table's cell were allocated with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    buf_align: usize,
}

impl Meta {
    const fn new() -> Self {
        Self {
            state: State::Free,
            set: 0,
            handle: false,
            aborted: false,
            has_output: false,
            out_off: 0,
            join_waker: None,
            ops: None,
            buf: ptr::null_mut(),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            cap: 0,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            buf_align: CELL_ALIGN,
        }
    }
}

/// One task's cell: two flags an interrupt may touch and the bookkeeping that only
/// a critical section may.
pub struct TaskCell {
    wake: AtomicBool,
    cancel: AtomicBool,
    /// Reached only inside a critical section (`Self::with_meta`).
    meta: UnsafeCell<Meta>,
    /// The store that owns the cell, whose count a waker and a handle hold; null for a cell of a
    /// `static` table, which is never freed. Written when the cell is made and never after.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    owner: *const TaskStore,
}

// SAFETY: see the module's contract. The flags are atomics; `meta` is reached only inside a
// critical section, by closures that run no code but this module's; the cell's bytes are written
// only by the one claimant of the cell (state `Spawning`) and the one poller (state `Polling`),
// which the state word makes exclusive; `owner` is only read once the cell is handed out.
unsafe impl Sync for TaskCell {}

impl TaskCell {
    #[cfg(feature = "session-slot")]
    const fn new() -> Self {
        Self {
            wake: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            meta: UnsafeCell::new(Meta::new()),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            owner: ptr::null(),
        }
    }

    /// A free cell over `cap` bytes at `buf` (none for a bare one), whose store is named once the
    /// store is made (`TaskStore::new`).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn owned(buf: *mut u8, cap: usize) -> Self {
        let mut meta = Meta::new();
        meta.buf = buf;
        meta.cap = cap;
        Self {
            wake: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            meta: UnsafeCell::new(meta),
            owner: ptr::null(),
        }
    }

    /// Run `f` on the cell's bookkeeping, inside a critical section.
    ///
    /// The section is what keeps another context off the bookkeeping: a join handle is `Send`, so
    /// one may be polled or dropped on another thread than the executor's. `f` reads and writes
    /// fields and runs no other code: a waker it takes out is woken or dropped by the caller after,
    /// and one it stores was cloned before, so no code of another crate runs while the
    /// bookkeeping is borrowed and none can borrow it again on the same thread.
    fn with_meta<R>(&self, f: impl FnOnce(&mut Meta) -> R) -> R {
        crate::cs::with(|cs| self.meta_in(cs, f))
    }

    /// Run `f` on the cell's bookkeeping inside the section `cs` the caller holds: what lets one
    /// section look at several cells in turn, a pass settling one cell and looking at the next.
    /// The rule is [`Self::with_meta`]'s, and the borrow ends with `f`, so no two are alive.
    fn meta_in<R>(&self, _cs: CriticalSection<'_>, f: impl FnOnce(&mut Meta) -> R) -> R {
        // SAFETY: the caller holds a critical section, so one context reaches the bookkeeping;
        // nothing `f` runs reaches this cell's bookkeeping again.
        f(unsafe { &mut *self.meta.get() })
    }
}

/// Free the cell whose bookkeeping this is. Its bytes stay with it, for the next task.
///
/// The cell is freed only once no handle holds it, and a handle that lets go takes its waker with
/// it ([`TaskJoin`]), so there is no waker to drop here, which no section could do.
fn free(meta: &mut Meta) {
    debug_assert!(
        meta.join_waker.is_none(),
        "a cell no handle holds keeps no handle's waker"
    );
    meta.ops = None;
    meta.has_output = false;
    meta.aborted = false;
    meta.handle = false;
    meta.set = 0;
    meta.state = State::Free;
}

/// Take a count on the store that owns `cell`, for a waker or a handle that will point at it.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn retain(cell: &TaskCell) {
    if !cell.owner.is_null() {
        // SAFETY: the caller reached the cell through the executor or through a waker or handle
        // that holds a count, so the store is alive.
        unsafe { Arc::increment_strong_count(cell.owner) }
    }
}

/// A cell of a `static` table needs no count: it is never freed.
#[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
fn retain(_cell: &TaskCell) {}

/// Give back a count `retain` took on `owner`. The store may be freed by it, with the cell the
/// count was taken for: nothing reads the cell after.
///
/// # Safety
/// `owner` is a cell's `owner`, and the caller holds a count on it that it gives back here.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe fn release_owner(owner: *const TaskStore) {
    if !owner.is_null() {
        // SAFETY: the caller's contract.
        unsafe { Arc::decrement_strong_count(owner) }
    }
}

/// The bytes of one cell of a `static` table.
#[cfg(feature = "session-slot")]
#[repr(C, align(16))]
struct TaskBytes<const BYTES: usize>(UnsafeCell<MaybeUninit<[u8; BYTES]>>);

#[cfg(feature = "session-slot")]
const _: () = assert!(align_of::<TaskBytes<1>>() == CELL_ALIGN);

/// The task table an image declares: `TASKS` cells of `BYTES` bytes each, in a
/// `static`, which the runtime's cell (`RuntimeCell`) holds.
#[cfg(feature = "session-slot")]
pub struct TaskTable<const TASKS: usize, const BYTES: usize> {
    cells: [TaskCell; TASKS],
    bytes: [TaskBytes<BYTES>; TASKS],
}

// SAFETY: see the module's contract; the bytes are reached only through a cell's
// own state word.
#[cfg(feature = "session-slot")]
unsafe impl<const TASKS: usize, const BYTES: usize> Sync for TaskTable<TASKS, BYTES> {}

#[cfg(feature = "session-slot")]
impl<const TASKS: usize, const BYTES: usize> TaskTable<TASKS, BYTES> {
    /// A table of free cells.
    pub const fn new() -> Self {
        Self {
            cells: [const { TaskCell::new() }; TASKS],
            bytes: [const { TaskBytes(UnsafeCell::new(MaybeUninit::uninit())) }; TASKS],
        }
    }

    /// Give each cell its bytes. Once, when the runtime that owns the table
    /// starts: the table is a `static` and a `const fn` cannot point a field at
    /// another of the same value.
    pub(crate) fn link(&'static self) -> ExecutorState {
        for (cell, bytes) in self.cells.iter().zip(self.bytes.iter()) {
            cell.with_meta(|meta| meta.buf = bytes.0.get().cast::<u8>());
        }
        ExecutorState::over(Cells::Table(&self.cells), Some(BYTES))
    }
}

#[cfg(feature = "session-slot")]
impl<const TASKS: usize, const BYTES: usize> Default for TaskTable<TASKS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

/// The cells of a table the runtime owns, and the bytes of the cells it reserved, in one block.
///
/// Held by a count: the executor, every waker and every join handle of its cells. Its cells lie
/// where `new` wrote them until the store goes, so a reference to one is good for as long as a
/// count is held. A table that takes memory after it is made holds stores of bare cells besides
/// (`Taking`), which a spawn gives the bytes a task needs (`fit_cell`); only such a store gives
/// those bytes back when it goes.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub(crate) struct TaskStore {
    /// The cells, at the front of the block: written by `new`, dropped by the store's drop.
    cells: *const [TaskCell],
    /// The block, null when the store has no bytes at all, and its layout.
    block: *mut u8,
    layout: Layout,
    /// The bytes each cell has of the block; `None` for bare cells, and for a store whose bytes
    /// would lie past the address space, whose cells have none and take no task.
    cell_bytes: Option<usize>,
    /// Gives back the bytes a spawn gave bare cells; `None` for a store whose cells' bytes are the
    /// block's, so a runtime that reserves its table links none of it.
    unfit: Option<fn(&[TaskCell])>,
}

// SAFETY: the cells are `Sync` by the module's contract, and the block is reached only through
// them.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe impl Send for TaskStore {}
// SAFETY: as above.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe impl Sync for TaskStore {}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TaskStore {
    /// `count` free cells in one block: each with `bytes` of the block behind the cells, at steps
    /// of the cells' alignment, when `bytes` is given; bare otherwise, with `unfit` to give back
    /// what spawns give them. Bytes past the address space are not reserved: the cells are made
    /// with none and a spawn is refused at the call, counted. A count past it makes no cells.
    fn new(count: usize, bytes: Option<usize>, unfit: Option<fn(&[TaskCell])>) -> Arc<Self> {
        let (count, cells_layout) = match Layout::array::<TaskCell>(count) {
            Ok(layout) => (count, layout),
            Err(_) => (0, Layout::new::<[TaskCell; 0]>()),
        };
        // Where each cell's bytes start in the block and how far apart they are, with the layout of
        // the block that holds them behind the cells.
        let reserved = bytes.and_then(|bytes| {
            let stride = round_up(bytes.max(1), CELL_ALIGN);
            let tail = Layout::from_size_align(stride.checked_mul(count)?, CELL_ALIGN).ok()?;
            let (layout, offset) = cells_layout.extend(tail).ok()?;
            Some((layout, offset, stride, bytes))
        });
        let layout = reserved
            .map_or(cells_layout, |(layout, ..)| layout)
            .pad_to_align();
        let block = if layout.size() == 0 {
            ptr::null_mut()
        } else {
            // SAFETY: the layout's size is not zero.
            let block = unsafe { alloc::alloc::alloc(layout) };
            if block.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            block
        };
        let first: *mut TaskCell = if block.is_null() {
            NonNull::dangling().as_ptr()
        } else {
            block.cast()
        };
        for at in 0..count {
            let (buf, cap) = match reserved {
                // `wrapping_add` and not `add`: no cell's bytes are reached until a spawn takes the
                // cell, and each offset lies inside the block.
                Some((_, offset, stride, bytes)) => (
                    block
                        .wrapping_add(offset)
                        .wrapping_add(at.saturating_mul(stride)),
                    bytes,
                ),
                None => (ptr::null_mut(), 0),
            };
            // SAFETY: `at` is below `count`, so the place is one of the block's cells, aligned for
            // one, written once here and read by nothing before.
            unsafe { first.add(at).write(TaskCell::owned(buf, cap)) };
        }
        let store = Arc::new(Self {
            cells: ptr::slice_from_raw_parts(first.cast_const(), count),
            block,
            layout,
            cell_bytes: reserved.map(|(.., bytes)| bytes),
            unfit,
        });
        let owner = Arc::as_ptr(&store);
        for at in 0..count {
            // SAFETY: the cells were written above and nothing else points at them yet; each write
            // is through the raw pointer, in bounds, and makes no reference.
            unsafe { (*first.add(at)).owner = owner };
        }
        store
    }

    /// The store's cells.
    fn cells(&self) -> &'static [TaskCell] {
        // SAFETY: the cells lie where `new` wrote them until the store is dropped, and every holder
        // of a cell past the executor's own call holds a count on the store (`retain`), so the
        // reference does not outlive them.
        unsafe { &*self.cells }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Drop for TaskStore {
    fn drop(&mut self) {
        // The last count is gone, so nothing else reaches the store: its cells are read without a
        // section.
        if let Some(unfit) = self.unfit {
            unfit(self.cells());
        }
        // SAFETY: `new` wrote every cell, and they are dropped once, here, before their block goes.
        unsafe { ptr::drop_in_place(self.cells.cast_mut()) };
        if !self.block.is_null() {
            // SAFETY: the block was allocated with this layout by `new`.
            unsafe { alloc::alloc::dealloc(self.block, self.layout) }
        }
    }
}

/// Give back the bytes spawns gave each of a store's bare cells (`fit_cell`).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn give_back_fitted(cells: &[TaskCell]) {
    for cell in cells {
        // SAFETY: the store is going, so nothing else reaches its cells.
        let meta = unsafe { &*cell.meta.get() };
        if !meta.buf.is_null() {
            // SAFETY: a bare cell's bytes were allocated by `fit_cell` with this size and
            // alignment, and no task is in them: the executor that dropped its tasks is gone, and a
            // done task's output went with its handle.
            unsafe {
                alloc::alloc::dealloc(
                    meta.buf,
                    Layout::from_size_align_unchecked(meta.cap, meta.buf_align),
                )
            }
        }
    }
}

/// The cells of a table that takes memory after it is made, beside the cells it reserved: what
/// only such a table does, behind `TakesMemory`, which only `ExecutorState::growing` and
/// `ExecutorState::opening` make, so a runtime whose table is reserved links none of it.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
trait TakesMemory: Send + Sync {
    /// The cell at `index` among these cells.
    fn cell_at(&self, index: usize) -> Option<&'static TaskCell>;

    /// How many of these cells there are.
    fn count(&self) -> usize;

    /// Take a free cell among these for a task of `need` bytes at `align`, given the bytes it
    /// needs, or say why none was: none free (`Ok`), or bytes no allocation can have.
    fn take(&self, set: u32, need: usize, align: usize) -> Result<Taken, SpawnRefusal>;

    /// The open is over: a cell with no bytes is given none from now on.
    fn seal(&self);
}

/// How a spawn went among the cells of a `TakesMemory`.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
enum Taken {
    /// A cell taken for the spawn (`Spawning`), and the bytes its task is written into.
    Cell(&'static TaskCell, *mut u8),
    /// None free: whether there is any of these cells, and whether one has bytes the task fits.
    Full { any: bool, room: bool },
}

/// Stores of bare cells, which a spawn gives the bytes its task needs: the one an opening table
/// adds for what its open spawns, or the chunks a grown table adds when every cell is taken.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct Taking {
    chunks: Mutex<RefCell<Vec<Arc<TaskStore>>>>,
    /// A chunk is added when every cell is taken, and a free cell too small for a task is given
    /// new bytes: what a grown table does.
    grows: bool,
    /// The open is over (`ExecutorState::seal`).
    sealed: AtomicBool,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Taking {
    fn over(chunks: Vec<Arc<TaskStore>>, grows: bool) -> Self {
        Self {
            chunks: Mutex::new(RefCell::new(chunks)),
            grows,
            sealed: AtomicBool::new(false),
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TakesMemory for Taking {
    fn cell_at(&self, index: usize) -> Option<&'static TaskCell> {
        crate::cs::with(|cs| {
            let mut left = index;
            for chunk in self.chunks.borrow(cs).borrow().iter() {
                let cells = chunk.cells();
                if let Some(cell) = cells.get(left) {
                    return Some(cell);
                }
                left = left.checked_sub(cells.len())?;
            }
            None
        })
    }

    fn count(&self) -> usize {
        crate::cs::with(|cs| {
            self.chunks
                .borrow(cs)
                .borrow()
                .iter()
                .map(|chunk| chunk.cells().len())
                .sum()
        })
    }

    fn take(&self, set: u32, need: usize, align: usize) -> Result<Taken, SpawnRefusal> {
        // A grown table gives any free cell the bytes a task needs; one whose open lasts gives
        // them to a free cell that has none yet; either takes a free cell whose bytes the task fits.
        let refits = self.grows;
        let fills = !self.sealed.load(Ordering::Acquire);
        let mut any = false;
        let mut room = false;
        // The search is one section: it takes the first free cell it finds, which no other context
        // may take between its look and its claim.
        let found = crate::cs::with(|cs| {
            self.chunks
                .borrow(cs)
                .borrow()
                .iter()
                .flat_map(|chunk| chunk.cells().iter())
                .find_map(|cell| {
                    any = true;
                    cell.meta_in(cs, |meta| {
                        let fits = meta.cap >= need && meta.buf_align >= align;
                        room |= fits;
                        let empty = meta.buf.is_null();
                        if meta.state == State::Free && (refits || fits || (fills && empty)) {
                            meta.state = State::Spawning;
                            meta.set = set;
                            Some((cell, meta.buf))
                        } else {
                            None
                        }
                    })
                })
        });
        let (cell, buf) = match found {
            Some(taken) => taken,
            None if self.grows => {
                let chunk =
                    TaskStore::new(self.count().max(FIRST_CHUNK), None, Some(give_back_fitted));
                let Some(first) = chunk.cells().first() else {
                    return Ok(Taken::Full { any, room });
                };
                // Taken before the chunk is the table's, so no other spawn finds it free.
                first.with_meta(|meta| {
                    meta.state = State::Spawning;
                    meta.set = set;
                });
                crate::cs::with(|cs| self.chunks.borrow(cs).borrow_mut().push(chunk));
                (first, ptr::null_mut())
            }
            None => return Ok(Taken::Full { any, room }),
        };
        if !refits && !buf.is_null() {
            return Ok(Taken::Cell(cell, buf));
        }
        match fit_cell(cell, need, align) {
            Some(buf) => Ok(Taken::Cell(cell, buf)),
            None => {
                ExecutorState::release(cell);
                Err(SpawnRefusal::TooLarge)
            }
        }
    }

    fn seal(&self) {
        self.sealed.store(true, Ordering::Release);
    }
}

/// Why a spawn was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpawnRefusal {
    /// Every cell is taken.
    NoTaskCell,
    /// The future and its output do not fit a cell, or ask for more alignment than
    /// a cell has.
    TooLarge,
}

/// How a pass left a cell it took (`Polling`).
#[derive(Clone, Copy)]
enum Left {
    /// The task answered `Pending`: it waits for its next wake.
    Pending,
    /// The task answered and wrote its output.
    Answered,
    /// The task was swept: its future is dropped and it has no output.
    Swept,
}

/// What a pass does with a cell, decided in the section that looks at it.
#[derive(Clone, Copy)]
enum Act {
    Nothing,
    Sweep(Ops, *mut u8),
    Poll(Ops, *mut u8, usize),
}

/// What settling a cell leaves for after the section: a waker's code and an output's drop are
/// their owners' code, which no section runs.
#[derive(Default)]
struct Settled {
    /// The waker of the handle that waits for the task.
    wake: Option<Waker>,
    /// The output of a task no handle waits for, which needs dropping: the cell, the drop and
    /// where the output lies.
    unread: Option<(&'static TaskCell, DropFn, *mut u8)>,
}

impl Settled {
    /// Wake the handle, or drop the output no handle will read and free its cell. Answers whether
    /// a handle's waker was woken.
    fn carry_out(self) -> bool {
        let woke = self.wake.is_some();
        if let Some(waker) = self.wake {
            waker.wake();
        }
        if let Some((cell, drop_output, at)) = self.unread {
            // SAFETY: the task answered and left its output at `at`, no handle will read it, and
            // the cell stays the pass's (`Polling`) until it is freed here: it is dropped once.
            unsafe { drop_output(at) };
            cell.with_meta(free);
        }
        woke
    }
}

/// A cell taken for a task: the cell, where its future lies and where its output will.
struct Claimed {
    cell: &'static TaskCell,
    buf: *mut u8,
    out_off: usize,
}

/// A refused spawn, which hands the future back: the caller decides what the
/// refusal means (a session that cannot be hosted gives its slot back).
pub struct SpawnRefused<F> {
    /// The future that was offered.
    pub future: F,
    /// Why it was refused.
    pub why: SpawnRefusal,
}

impl<F> core::fmt::Debug for SpawnRefused<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpawnRefused")
            .field("why", &self.why)
            .finish()
    }
}

/// The refusals an executor has made, by reason.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Refusals {
    /// Spawns refused for want of a free cell.
    pub no_task_cell: u32,
    /// Spawns refused because the future and its output do not fit a cell.
    pub too_large: u32,
}

/// Where an executor's cells are.
enum Cells {
    /// A `static` table the image declares.
    #[cfg(feature = "session-slot")]
    Table(&'static [TaskCell]),
    /// A table the runtime owns: the cells it reserved (none for a grown one).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Store(Arc<TaskStore>),
}

/// The task pool of a runtime: a view of its table that spawns into it and polls it.
pub struct ExecutorState {
    cells: Cells,
    /// The bytes every cell of `cells` has; `None` for cells that have none (a grown table's,
    /// or a reserved one's whose bytes would lie past the address space), which take no task.
    cell_bytes: Option<usize>,
    /// The cells of a table that takes memory after it is made, beside `cells`: `None` for a
    /// table that does not (a `static` one, or one reserved), which then links none of them.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    taking: Option<Box<dyn TakesMemory>>,
    /// The number the next local set's tasks are marked with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    next_set: Mutex<Cell<u32>>,
    refused: Mutex<Cell<Refusals>>,
    /// The most cells the table has held at once: zero-sized unless the build keeps the mark
    /// (`pool-monitor`), so the state is the size it was.
    #[cfg(feature = "session-slot")]
    high: Mutex<Cell<wz_session_core::pool_gauge::HighWater>>,
}

/// The bytes of a task cell that holds a future of type `F` and its output: what a spawn of it
/// checks a cell against, for a future whose type can be named.
pub const fn cell_bytes_for<F: Future>() -> usize {
    round_up(size_of::<F>(), align_of::<F::Output>()).saturating_add(size_of::<F::Output>())
}

/// `value` rounded up to a multiple of `align`, or `usize::MAX` where there is none: a size no
/// cell holds, so a task of it is refused as too large.
const fn round_up(value: usize, align: usize) -> usize {
    match value.checked_next_multiple_of(align) {
        Some(rounded) => rounded,
        None => usize::MAX,
    }
}

/// The bytes of a task cell that holds the future `make` returns and that future's output: what a
/// spawn of it checks a cell against, as a constant. `make` is only the way to NAME the future,
/// which an `async` block or an `impl Future` return has no other way to be named: pass the
/// function that returns it, with its type arguments, and it is not called.
pub const fn cell_bytes_of<A, B, R: Future>(_make: fn(A, B) -> R) -> usize {
    round_up(size_of::<R>(), align_of::<R::Output>()).saturating_add(size_of::<R::Output>())
}

/// Poll the future at `buf`; when it is ready, drop it in place and write its
/// output at `out_off`.
///
/// # Safety
/// `buf` holds a live `F` at offset 0, pinned there since it was written, with room
/// for an `F::Output` at `out_off`; it is not polled again after it answers `Ready`.
unsafe fn poll_erased<F: Future>(buf: *mut u8, out_off: usize, cx: &mut Context<'_>) -> Poll<()> {
    // SAFETY: the caller's contract; the future has not moved since it was written.
    let fut = unsafe { Pin::new_unchecked(&mut *buf.cast::<F>()) };
    match fut.poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(output) => {
            // SAFETY: the future answered and is not polled again, so it is dropped
            // here, once; `out_off` is aligned for the output and in bounds (the
            // spawn checked both), and the future's bytes are no longer in use.
            unsafe {
                ptr::drop_in_place(buf.cast::<F>());
                ptr::write(buf.add(out_off).cast::<F::Output>(), output);
            }
            Poll::Ready(())
        }
    }
}

/// Drop the `T` at `ptr`.
///
/// # Safety
/// `ptr` holds a live, aligned `T` that nothing uses afterwards.
unsafe fn drop_erased<T>(ptr: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe { ptr::drop_in_place(ptr.cast::<T>()) }
}

/// Give a bare `cell` (a cell of a `Taking`), which the caller has taken (`Spawning`), bytes for
/// a task of `need` bytes at `align`: the ones it has when they are enough, which is what lets a
/// grown table spawn again without allocating, or new ones in their place. `None` for a size and
/// alignment no allocation can have, the cell's bytes as they were.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn fit_cell(cell: &TaskCell, need: usize, align: usize) -> Option<*mut u8> {
    let align = align.max(CELL_ALIGN);
    let (held, cap, held_align) = cell.with_meta(|meta| (meta.buf, meta.cap, meta.buf_align));
    if !held.is_null() && cap >= need && held_align >= align {
        return Some(held);
    }
    let size = need.max(1);
    let layout = Layout::from_size_align(size, align).ok()?;
    // SAFETY: the layout's size is not zero.
    let fresh = unsafe { alloc::alloc::alloc(layout) };
    if fresh.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    if !held.is_null() {
        // SAFETY: the bytes were allocated with the cell's recorded size and alignment, and the
        // cell is taken by this spawn alone with no task in it.
        unsafe { alloc::alloc::dealloc(held, Layout::from_size_align_unchecked(cap, held_align)) }
    }
    cell.with_meta(|meta| {
        meta.buf = fresh;
        meta.cap = size;
        meta.buf_align = align;
    });
    Some(fresh)
}

impl ExecutorState {
    fn over(cells: Cells, cell_bytes: Option<usize>) -> Self {
        Self {
            cells,
            cell_bytes,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            taking: None,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            next_set: Mutex::new(Cell::new(1)),
            refused: Mutex::new(Cell::new(Refusals::default())),
            #[cfg(feature = "session-slot")]
            high: Mutex::new(Cell::new(wz_session_core::pool_gauge::HighWater::new())),
        }
    }

    /// A table that grows when every cell is taken.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn growing() -> Self {
        let mut state = Self::over(Cells::Store(TaskStore::new(0, None, None)), None);
        state.taking = Some(Box::new(Taking::over(Vec::new(), true)));
        state
    }

    /// `tasks` cells of `task_bytes` each, reserved now in one block, and `added` bare cells beside
    /// them: while the open lasts, a task no free cell fits takes one of those and the bytes it
    /// needs, kept for the next task it fits. Once [`Self::seal`] is called the table is fixed, and
    /// a spawn that finds no free cell it fits is refused, counted; so is one that finds every
    /// added cell taken. The table never holds more cells than it was made with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn opening(tasks: usize, task_bytes: usize, added: usize) -> Self {
        let store = TaskStore::new(tasks, Some(task_bytes), None);
        let cell_bytes = store.cell_bytes;
        let mut state = Self::over(Cells::Store(store), cell_bytes);
        let mut chunks = Vec::new();
        if added > 0 {
            chunks.push(TaskStore::new(added, None, Some(give_back_fitted)));
        }
        state.taking = Some(Box::new(Taking::over(chunks, false)));
        state
    }

    /// The open is over: the table takes no more memory, and a spawn that finds no free cell it
    /// fits is refused, counted. Nothing for a table that takes no memory after it is made.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn seal(&self) {
        if let Some(taking) = self.taking.as_deref() {
            taking.seal();
        }
    }

    /// `tasks` cells of `task_bytes` each, reserved now in one block: a spawn past them is
    /// refused, counted, and none allocates.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn reserved(tasks: usize, task_bytes: usize) -> Self {
        let store = TaskStore::new(tasks, Some(task_bytes), None);
        let cell_bytes = store.cell_bytes;
        Self::over(Cells::Store(store), cell_bytes)
    }

    /// A number for a new local set, which its tasks are marked with: never 0, which marks a task
    /// that is no set's.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn new_local_set(&self) -> u32 {
        crate::cs::with(|cs| {
            let next = self.next_set.borrow(cs);
            let set = next.get();
            next.set(set.wrapping_add(1).max(1));
            set
        })
    }

    /// Every cell of the table, in its order: the cells it reserved, then those it took memory for.
    fn each_cell(&self) -> impl Iterator<Item = &'static TaskCell> + '_ {
        let taken = (0..usize::MAX).map_while(move |index| self.taken_at(index));
        self.fixed_cells().iter().chain(taken)
    }

    /// The cells the table was made with.
    fn fixed_cells(&self) -> &'static [TaskCell] {
        match self.cells {
            #[cfg(feature = "session-slot")]
            Cells::Table(cells) => cells,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Cells::Store(ref store) => store.cells(),
        }
    }

    /// The cell at `index` among those the table took memory for.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn taken_at(&self, index: usize) -> Option<&'static TaskCell> {
        self.taking.as_deref()?.cell_at(index)
    }

    /// A `static` table takes no memory.
    #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
    fn taken_at(&self, _index: usize) -> Option<&'static TaskCell> {
        None
    }

    /// How many cells the table took memory for.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn taken_count(&self) -> usize {
        self.taking.as_deref().map_or(0, |taking| taking.count())
    }

    /// A `static` table takes no memory.
    #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
    fn taken_count(&self) -> usize {
        0
    }

    /// Refusals made so far.
    pub fn refusals(&self) -> Refusals {
        crate::cs::with(|cs| self.refused.borrow(cs).get())
    }

    fn refuse(&self, why: SpawnRefusal) {
        crate::cs::with(|cs| {
            let counts = self.refused.borrow(cs);
            let mut now = counts.get();
            match why {
                SpawnRefusal::NoTaskCell => now.no_task_cell = now.no_task_cell.saturating_add(1),
                SpawnRefusal::TooLarge => now.too_large = now.too_large.saturating_add(1),
            }
            counts.set(now);
        });
    }

    /// The cell count of the table: for a grown one, the cells it has grown to so far.
    pub fn capacity(&self) -> usize {
        self.fixed_cells().len().saturating_add(self.taken_count())
    }

    /// Write `fut` into a free cell and mark it ready, or refuse it, counted, and
    /// hand it back. `set`: the local set the task is spawned on, 0 for none.
    ///
    /// The future is a value passed through here and handed back in the refusal, so a future of
    /// some size is copied through this frame and the caller's result: a large one is made in
    /// the cell by [`Self::spawn_with`] instead.
    pub(crate) fn spawn<F: Future + 'static>(
        &self,
        fut: F,
        set: u32,
    ) -> Result<&'static TaskCell, SpawnRefused<F>> {
        match self.claim::<F>(set) {
            Ok(claimed) => Ok(Self::start(claimed, fut)),
            Err(why) => Err(SpawnRefused { future: fut, why }),
        }
    }

    /// Make the future of a task IN a free cell and mark it ready, or refuse it, counted.
    ///
    /// `make` runs only once a cell is taken, and what it builds is written where the task will
    /// poll it, so no frame of this call holds the future: a spawn that takes a future by value
    /// and hands it back on a refusal puts it on the stack four times over (a session's task is
    /// 4.7 KB, which was a 19 KB frame). A refusal drops `make` with what it captured.
    pub(crate) fn spawn_with<F: Future + 'static>(
        &self,
        make: impl FnOnce() -> F,
        set: u32,
    ) -> Result<&'static TaskCell, SpawnRefusal> {
        let claimed = self.claim::<F>(set)?;
        Ok(Self::start(claimed, make()))
    }

    /// Take a free cell for a future of type `F`, or refuse, counted: the cell is `Spawning`,
    /// held by this caller alone, and the offset its output will lie at comes with it. Only the
    /// sizes are `F`'s; the search is [`Self::claim_bytes`], one body for every task type.
    #[inline(always)]
    fn claim<F: Future + 'static>(&self, set: u32) -> Result<Claimed, SpawnRefusal> {
        let out_off = round_up(size_of::<F>(), align_of::<F::Output>());
        let need = out_off.saturating_add(size_of::<F::Output>());
        let align = if align_of::<F>() > align_of::<F::Output>() {
            align_of::<F>()
        } else {
            align_of::<F::Output>()
        };
        let (cell, buf) = self.claim_bytes(set, need, align)?;
        Ok(Claimed { cell, buf, out_off })
    }

    /// Take a free cell for a task of `need` bytes at `align`, or refuse, counted.
    #[inline(never)]
    fn claim_bytes(
        &self,
        set: u32,
        need: usize,
        align: usize,
    ) -> Result<(&'static TaskCell, *mut u8), SpawnRefusal> {
        let fixed = self.fixed_cells();
        // Every cell the table was made with has its bytes, so a task fits all of them or none.
        let fits = self.cell_bytes.is_some_and(|cap| need <= cap) && align <= CELL_ALIGN;
        // The search is one section: it takes the first free cell it finds, which no other context
        // may take between its look and its claim.
        let found = if fits {
            crate::cs::with(|cs| {
                fixed.iter().find_map(|cell| {
                    cell.meta_in(cs, |meta| {
                        if meta.state == State::Free {
                            meta.state = State::Spawning;
                            meta.set = set;
                            Some((cell, meta.buf))
                        } else {
                            None
                        }
                    })
                })
            })
        } else {
            None
        };
        if let Some(taken) = found {
            #[cfg(all(feature = "pool-monitor", feature = "session-slot"))]
            self.note_high_water();
            return Ok(taken);
        }
        // A table that takes memory after it is made looks among the cells it took memory for. A
        // task a taken cell fits waits for one to come free; one no cell fits never will, which is
        // the cause named.
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        if let Some(taking) = self.taking.as_deref() {
            let why = match taking.take(set, need, align) {
                Ok(Taken::Cell(cell, buf)) => return Ok((cell, buf)),
                Ok(Taken::Full { any, room }) => {
                    let room = room || (fits && !fixed.is_empty());
                    let any = any || !fixed.is_empty();
                    if room || !any {
                        SpawnRefusal::NoTaskCell
                    } else {
                        SpawnRefusal::TooLarge
                    }
                }
                Err(why) => why,
            };
            self.refuse(why);
            return Err(why);
        }
        let why = if fits {
            SpawnRefusal::NoTaskCell
        } else {
            SpawnRefusal::TooLarge
        };
        self.refuse(why);
        Err(why)
    }

    /// The cell is taken: the mark is what the table holds now, if that is the most so far.
    #[cfg(all(feature = "pool-monitor", feature = "session-slot"))]
    fn note_high_water(&self) {
        let held = self.live_task_count();
        crate::cs::with(|cs| {
            let high = self.high.borrow(cs);
            let mut mark = high.get();
            mark.note(held);
            high.set(mark);
        });
    }

    /// Write `fut` into the cell `claimed` names and make the task live.
    #[inline(always)]
    fn start<F: Future + 'static>(claimed: Claimed, fut: F) -> &'static TaskCell {
        let Claimed { cell, buf, out_off } = claimed;
        // SAFETY: the cell is `Spawning`, which only the caller holds, and its bytes
        // are long enough and aligned for `F` and its output, which `claim` checked
        // (a fixed table) or gave the cell (a grown one).
        unsafe { ptr::write(buf.cast::<F>(), fut) };
        let drop_output: Option<DropFn> = if core::mem::needs_drop::<F::Output>() {
            Some(drop_erased::<F::Output>)
        } else {
            None
        };
        Self::go_live(
            cell,
            Ops {
                poll: poll_erased::<F>,
                drop_future: drop_erased::<F>,
                drop_output,
            },
            out_off,
        );
        cell
    }

    /// Make the task whose future `cell` now holds live, driven by `ops`, its output to lie at
    /// `out_off`: one body for every task type.
    #[inline(never)]
    fn go_live(cell: &'static TaskCell, ops: Ops, out_off: usize) {
        cell.cancel.store(false, Ordering::Release);
        cell.wake.store(true, Ordering::Release);
        cell.with_meta(|meta| {
            // A cell is freed with no waker of a handle (`free`).
            debug_assert!(meta.join_waker.is_none());
            meta.ops = Some(ops);
            meta.out_off = out_off;
            meta.has_output = false;
            meta.aborted = false;
            meta.handle = true;
            meta.state = State::Live;
        });
    }

    /// Give the cell back: a handle that read its task's result, or let go of a task that ended.
    fn release(cell: &'static TaskCell) {
        cell.with_meta(free);
    }

    /// Look at `cell` inside the section `cs`, the pass that holds it: a live task that was
    /// aborted is to be swept and one whose wake flag is raised polled, either taken by the pass
    /// (`Polling`); anything else is left as it is.
    fn classify(cell: &'static TaskCell, cs: CriticalSection<'_>) -> Act {
        cell.meta_in(cs, |meta| {
            if meta.state != State::Live {
                return Act::Nothing;
            }
            let Some(ops) = meta.ops else {
                return Act::Nothing;
            };
            if cell.cancel.load(Ordering::Acquire) {
                meta.state = State::Polling;
                Act::Sweep(ops, meta.buf)
            } else if cell.wake.swap(false, Ordering::AcqRel) {
                meta.state = State::Polling;
                Act::Poll(ops, meta.buf, meta.out_off)
            } else {
                Act::Nothing
            }
        })
    }

    /// Write how the pass left `cell` into its bookkeeping, inside the section `cs`: a task that
    /// waits is live again; a task that is over is `Done` for its handle, or, with no handle,
    /// free, once an output that needs dropping is dropped ([`Settled::carry_out`]).
    fn settle(cell: &'static TaskCell, left: Left, cs: CriticalSection<'_>) -> Settled {
        cell.meta_in(cs, |meta| {
            let mut settled = Settled::default();
            let completed = match left {
                Left::Pending => {
                    meta.state = State::Live;
                    return settled;
                }
                Left::Answered => true,
                Left::Swept => false,
            };
            meta.has_output = completed;
            if meta.handle {
                meta.state = State::Done;
                settled.wake = meta.join_waker.take();
                return settled;
            }
            let unread = meta.ops.and_then(|ops| ops.drop_output);
            match unread {
                // The cell stays the pass's (`Polling`) until its output is dropped.
                Some(drop_output) if completed => {
                    settled.unread = Some((cell, drop_output, meta.buf.wrapping_add(meta.out_off)));
                }
                _ => free(meta),
            }
            settled
        })
    }

    /// Poll every ready task at most once, and sweep every task whose handle
    /// aborted it. A task that answers `Pending` stays for the next pass; one that
    /// answers `Ready` leaves its output for its handle. A task spawned from inside
    /// a poll may be polled in this pass if its cell lies later in the table, or
    /// in the next.
    ///
    /// One critical section per cell: the section that looks at a cell also settles the cell
    /// polled before it, so a task the pass polls costs it no section of its own. The cell polled
    /// last is settled by the pass's closing section, so the table is settled when this returns.
    pub fn run_until_idle(&self) {
        // The cell the pass polled or swept last and how it left it, to be settled by the next
        // section.
        let mut owed: Option<(&'static TaskCell, Left)> = None;
        // Every cell in the table's order, then the end of the table, whose section settles the
        // cell polled last.
        for next in self.each_cell().map(Some).chain(core::iter::once(None)) {
            let (settled, mut act) = crate::cs::with(|cs| {
                let settled = match owed {
                    Some((cell, left)) => Self::settle(cell, left, cs),
                    None => Settled::default(),
                };
                let act = match next {
                    Some(cell) => Self::classify(cell, cs),
                    None => Act::Nothing,
                };
                (settled, act)
            });
            let woke = settled.carry_out();
            let Some(cell) = next else {
                return;
            };
            // The handle's waker woken just now may be the waker of this cell's task, which the
            // section looked at before it was woken: it is looked at again, so it is polled in
            // this pass, as it was when each cell was settled before the next was looked at.
            if woke && matches!(act, Act::Nothing) && cell.wake.load(Ordering::Acquire) {
                act = crate::cs::with(|cs| Self::classify(cell, cs));
            }
            owed = match act {
                Act::Nothing => None,
                Act::Sweep(ops, buf) => {
                    // SAFETY: the cell was `Live`, so it holds a future that has
                    // not answered; it is `Polling` now, which keeps every other
                    // user off it, and it is dropped once.
                    unsafe { (ops.drop_future)(buf) };
                    Some((cell, Left::Swept))
                }
                Act::Poll(ops, buf, out_off) => {
                    // The executor's own count keeps the cell while it polls: this waker holds
                    // none and gives none back, and a clone the task keeps takes its own.
                    let waker = borrowed_waker(cell);
                    let mut cx = Context::from_waker(&waker);
                    // SAFETY: the cell was `Live`, so it holds a pinned future that
                    // has not answered, and it is `Polling` now.
                    let left = match unsafe { (ops.poll)(buf, out_off, &mut cx) } {
                        Poll::Ready(()) => Left::Answered,
                        Poll::Pending => Left::Pending,
                    };
                    Some((cell, left))
                }
            };
        }
    }

    /// Diagnostic + test helper: cells that hold a task (or a result no handle has
    /// read yet).
    pub fn live_task_count(&self) -> usize {
        crate::cs::with(|cs| {
            self.each_cell()
                .filter(|cell| cell.meta_in(cs, |meta| meta.state != State::Free))
                .count()
        })
    }

    /// Diagnostic + test helper: tasks of a local set that have not ended (a result waiting for
    /// its handle is not one).
    pub(crate) fn running_local_count(&self) -> usize {
        crate::cs::with(|cs| {
            self.each_cell()
                .filter(|cell| {
                    cell.meta_in(cs, |meta| {
                        meta.set != 0
                            && matches!(meta.state, State::Spawning | State::Live | State::Polling)
                    })
                })
                .count()
        })
    }

    /// Diagnostic + test helper: true if a task that is waiting has its wake flag
    /// set.
    pub(crate) fn any_ready(&self) -> bool {
        crate::cs::with(|cs| {
            self.each_cell().any(|cell| {
                cell.meta_in(cs, |meta| meta.state == State::Live)
                    && cell.wake.load(Ordering::Acquire)
            })
        })
    }
}

/// The runtime is gone: every task it still holds is dropped where it lies, as a heap of boxed
/// futures was dropped with its runtime, and a handle that still waits reads `JoinCancelled`. A
/// result already waiting stays for its handle. The cells themselves stay until the last waker
/// and handle let go of the table.
impl Drop for ExecutorState {
    fn drop(&mut self) {
        self.drop_live(None);
    }
}

impl ExecutorState {
    /// Drop, where it lies, every task that has not ended and was spawned on local set `set` (on
    /// any set, and on none, for `None`); a handle that still waits for one reads
    /// `JoinCancelled`. A task being polled is not one of them.
    fn drop_live(&self, set: Option<u32>) {
        for cell in self.each_cell() {
            let live = cell.with_meta(|meta| {
                if meta.state != State::Live || set.is_some_and(|set| set != meta.set) {
                    return None;
                }
                let ops = meta.ops?;
                meta.state = State::Polling;
                meta.aborted = true;
                Some((ops, meta.buf))
            });
            if let Some((ops, buf)) = live {
                // SAFETY: the cell was `Live`, so it holds a future that has not answered, and
                // it is `Polling` now; it is dropped once.
                unsafe { (ops.drop_future)(buf) };
                crate::cs::with(|cs| Self::settle(cell, Left::Swept, cs)).carry_out();
            }
        }
    }

    /// The last handle of local set `set` is gone: its tasks go with it, as they did when a set
    /// kept its own list of them. A task that holds a handle of the runtime would otherwise keep
    /// itself, and the socket it reads, alive through the runtime's table.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn drop_tasks_of(&self, set: u32) {
        self.drop_live(Some(set));
    }
}

/// The task table says its state as a pool (`pool-monitor`): its cells, those that hold a task or
/// a result nobody has read, the most that held one at once where the build keeps the mark, and
/// the spawns refused for want of a free cell. A task too large for a cell is not a want of room,
/// so it is not counted here (`Refusals::too_large`).
#[cfg(feature = "session-slot")]
impl wz_session_core::pool_gauge::PoolGauge for ExecutorState {
    fn pool_stat(&self, name: &'static str) -> wz_session_core::pool_gauge::PoolStat {
        wz_session_core::pool_gauge::PoolStat {
            name,
            capacity: u32::try_from(self.capacity()).unwrap_or(u32::MAX),
            in_use: u32::try_from(self.live_task_count()).unwrap_or(u32::MAX),
            high_water: crate::cs::with(|cs| self.high.borrow(cs).get().get()),
            refused: u64::from(self.refusals().no_task_cell),
        }
    }
}

// The waker of a task is a reference to its cell: cloning it copies the reference and takes a
// count on the cell's store, waking it raises the cell's wake flag, dropping it gives the count
// back. A cell of a `static` table has no store, and its counts are nothing.
unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // SAFETY: `data` is a `TaskCell` reached through a waker, which keeps it.
    retain(unsafe { &*data.cast::<TaskCell>() });
    RawWaker::new(data, &VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    // SAFETY: `data` is a `TaskCell` this waker keeps; the waker is consumed, so its count goes.
    unsafe {
        waker_wake_by_ref(data);
        waker_drop(data);
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: `data` is a `TaskCell` reached through a waker, which keeps it.
    let cell = unsafe { &*data.cast::<TaskCell>() };
    cell.wake.store(true, Ordering::Release);
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe fn waker_drop(data: *const ()) {
    // SAFETY: `data` is a `TaskCell` whose store this waker holds a count on, given back here;
    // the cell is not read after.
    unsafe {
        let owner = (*data.cast::<TaskCell>()).owner;
        release_owner(owner);
    }
}

#[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
unsafe fn waker_drop(_data: *const ()) {}

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// The waker the executor polls `cell` with: one that holds no count and is never dropped, so it
/// gives none back. A task that keeps a clone takes a count of its own.
fn borrowed_waker(cell: &'static TaskCell) -> ManuallyDrop<Waker> {
    let raw = RawWaker::new(ptr::from_ref(cell).cast::<()>(), &VTABLE);
    // SAFETY: the vtable upholds the `RawWaker` contract: clone takes a count that keeps the
    // cell and drop gives it back; this waker itself is never dropped, matching the count it
    // never took.
    ManuallyDrop::new(unsafe { Waker::from_raw(raw) })
}

/// A waker that raises `flag`: what a synchronous driver waits on a handle with.
///
/// # Safety
/// `flag` outlives the waker and every clone of it: whatever is handed the waker gives it up
/// before `flag` is gone.
pub(crate) unsafe fn flag_waker(flag: &AtomicBool) -> Waker {
    static FLAG_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |data| RawWaker::new(data, &FLAG_VTABLE),
        |data| {
            // SAFETY: `data` is the flag, alive by the caller's contract.
            unsafe { &*data.cast::<AtomicBool>() }.store(true, Ordering::Release)
        },
        |data| {
            // SAFETY: as above.
            unsafe { &*data.cast::<AtomicBool>() }.store(true, Ordering::Release)
        },
        |_| {},
    );
    // SAFETY: the vtable's functions only store the flag, which the caller keeps alive.
    unsafe {
        Waker::from_raw(RawWaker::new(
            ptr::from_ref(flag).cast::<()>(),
            &FLAG_VTABLE,
        ))
    }
}

/// The handle of a task in a cell: the future that answers with its output, and
/// the means to abort it. What both [`crate::CoopJoinHandle`] and
/// [`crate::CoopLocalJoinHandle`] are made of. It holds a count on the cell's table.
pub(crate) struct TaskJoin<T> {
    /// `None` for a spawn that was refused: the handle answers `Shutdown`.
    cell: Option<&'static TaskCell>,
    /// The handle has answered: the cell is no longer its.
    taken: bool,
    output: PhantomData<fn() -> T>,
}

impl<T> TaskJoin<T> {
    /// The handle of the task in `cell`.
    pub(crate) fn attached(cell: &'static TaskCell) -> Self {
        retain(cell);
        Self {
            cell: Some(cell),
            taken: false,
            output: PhantomData,
        }
    }

    /// The handle of a spawn that was refused.
    pub(crate) fn refused() -> Self {
        Self {
            cell: None,
            taken: false,
            output: PhantomData,
        }
    }

    /// Abort the task: it is swept by the next pass, and this handle answers
    /// `JoinCancelled` from now on. A task that already ended keeps its result.
    pub(crate) fn abort(&self) {
        let Some(cell) = self.cell.filter(|_| !self.taken) else {
            return;
        };
        let waker = cell.with_meta(|meta| {
            if meta.state == State::Done || meta.state == State::Free {
                return None;
            }
            meta.aborted = true;
            cell.cancel.store(true, Ordering::Release);
            meta.join_waker.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// True once the task has produced a result, or was aborted, that no poll has
    /// taken yet.
    pub(crate) fn is_finished(&self) -> bool {
        match self.cell.filter(|_| !self.taken) {
            None => true,
            Some(cell) => cell.with_meta(|meta| meta.state == State::Done || meta.aborted),
        }
    }

    pub(crate) fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, RuntimeError>> {
        let Some(cell) = self.cell else {
            return Poll::Ready(Err(RuntimeError::Shutdown));
        };
        if self.taken {
            return Poll::Ready(Err(RuntimeError::JoinCancelled));
        }
        enum Seen {
            Pending,
            Cancelled,
            Lost,
            /// Where the output lies, how it is dropped, whether the task was aborted, and
            /// whether it left an output.
            Output(*mut u8, Ops, bool, bool),
        }
        // Cloned, and the waker it replaces dropped, outside the section: a waker's clone and drop
        // are its owner's code.
        let mut fresh = Some(cx.waker().clone());
        let (seen, gone) = cell.with_meta(|meta| match meta.state {
            State::Done => match meta.ops {
                Some(ops) => {
                    let at = Seen::Output(
                        // SAFETY of the offset: `out_off` was computed in bounds.
                        meta.buf.wrapping_add(meta.out_off),
                        ops,
                        meta.aborted,
                        meta.has_output,
                    );
                    (at, None)
                }
                // `go_live` gives a cell its operations before it can finish and only `free`
                // takes them, after which the cell is free: a done cell without them has no
                // output to read.
                None => (Seen::Lost, None),
            },
            _ if meta.aborted => {
                // Detach: the executor frees the cell when it finishes sweeping.
                meta.handle = false;
                (Seen::Cancelled, meta.join_waker.take())
            }
            _ => (
                Seen::Pending,
                core::mem::replace(&mut meta.join_waker, fresh.take()),
            ),
        });
        drop(gone);
        drop(fresh);
        match seen {
            Seen::Pending => Poll::Pending,
            Seen::Lost => {
                self.taken = true;
                ExecutorState::release(cell);
                Poll::Ready(Err(RuntimeError::JoinCancelled))
            }
            Seen::Cancelled => {
                self.taken = true;
                Poll::Ready(Err(RuntimeError::JoinCancelled))
            }
            Seen::Output(at, ops, aborted, has_output) => {
                self.taken = true;
                let answer = if aborted {
                    if let Some(drop_output) = ops.drop_output.filter(|_| has_output) {
                        // SAFETY: a done cell that holds an output holds it live;
                        // it is dropped once and the handle is over.
                        unsafe { drop_output(at) };
                    }
                    Err(RuntimeError::JoinCancelled)
                } else {
                    // SAFETY: a task that ended without an abort left one `T` here,
                    // which this read moves out; the cell is then freed without
                    // dropping it again.
                    Ok(unsafe { ptr::read(at.cast::<T>()) })
                };
                ExecutorState::release(cell);
                Poll::Ready(answer)
            }
        }
    }
}

impl<T> Drop for TaskJoin<T> {
    fn drop(&mut self) {
        let Some(cell) = self.cell else {
            return;
        };
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        let owner = cell.owner;
        if !self.taken {
            // A done task's output to drop, the cell freed once it is; a done task with nothing
            // to drop is freed in the section. A task not done runs on without its handle, and
            // the waker the handle left is dropped outside the section.
            let (unread, waker) = cell.with_meta(|meta| {
                if meta.state != State::Done {
                    meta.handle = false;
                    return (None, meta.join_waker.take());
                }
                let drop_output = meta.ops.and_then(|ops| ops.drop_output);
                match drop_output {
                    Some(drop_output) if meta.has_output => (
                        Some((drop_output, meta.buf.wrapping_add(meta.out_off))),
                        None,
                    ),
                    _ => {
                        free(meta);
                        (None, None)
                    }
                }
            });
            drop(waker);
            if let Some((drop_output, at)) = unread {
                // SAFETY: a done cell that holds an output holds it live and no
                // handle has read it; it is dropped once.
                unsafe { drop_output(at) };
                ExecutorState::release(cell);
            }
        }
        // SAFETY: `attached` took this count on the cell's store; the cell is not read after.
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        unsafe {
            release_owner(owner)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A size rounds up to the next multiple of its alignment; one with no multiple below
    /// `usize::MAX`, or an alignment of none, reads `usize::MAX`, which no cell holds.
    #[test]
    fn a_size_rounds_up_or_reads_as_more_than_any_cell() {
        assert_eq!(round_up(0, CELL_ALIGN), 0);
        assert_eq!(round_up(17, CELL_ALIGN), 32);
        assert_eq!(round_up(32, CELL_ALIGN), 32);
        assert_eq!(round_up(usize::MAX, CELL_ALIGN), usize::MAX);
        assert_eq!(round_up(5, 0), usize::MAX);
    }

    /// A cell asked for bytes no allocation can have is refused, and keeps what it held.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_cell_asked_for_more_than_an_allocation_can_have_is_refused() {
        let cell = TaskCell::owned(ptr::null_mut(), 0);
        assert_eq!(fit_cell(&cell, usize::MAX, CELL_ALIGN), None);
        assert!(cell.with_meta(|meta| meta.buf.is_null() && meta.cap == 0));
    }

    /// A store whose reserved block would be past the address space reserves none: its cells
    /// have no bytes, and a table of fixed cells refuses a task as too large.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_table_past_the_address_space_reserves_nothing_and_refuses_at_the_spawn() {
        let state = ExecutorState::reserved(2, usize::MAX / 2);
        assert_eq!(state.capacity(), 2);
        assert!(state
            .each_cell()
            .all(|cell| cell.with_meta(|meta| meta.buf.is_null() && meta.cap == 0)));
        assert_eq!(
            state
                .spawn(async { 1u8 }, 0)
                .map(|_| ())
                .map_err(|refused| refused.why),
            Err(SpawnRefusal::TooLarge)
        );
        assert_eq!(state.refusals().too_large, 1);
    }

    /// A done cell without its operations has no output to read: its join reads cancelled and
    /// the cell is free again.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_done_cell_without_its_operations_reads_cancelled_and_is_freed() {
        let cell: &'static TaskCell = Box::leak(Box::new(TaskCell::owned(ptr::null_mut(), 0)));
        cell.with_meta(|meta| {
            meta.state = State::Done;
            meta.handle = true;
        });
        let mut join = TaskJoin::<u8>::attached(cell);
        let flag = AtomicBool::new(false);
        // SAFETY: the waker is dropped with `cx` before `flag` goes.
        let waker = unsafe { flag_waker(&flag) };
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            join.poll_join(&mut cx),
            Poll::Ready(Err(RuntimeError::JoinCancelled))
        ));
        assert!(cell.with_meta(|meta| meta.state == State::Free));
    }

    /// A reserved table lays its cells and their bytes in one block: each cell's bytes lie behind
    /// the cells, aligned to the cells' alignment and a stride apart, and the table takes no memory
    /// after it is made.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_reserved_table_lays_its_cells_and_their_bytes_in_one_block() {
        let state = ExecutorState::reserved(3, 100);
        let Cells::Store(ref store) = state.cells;
        let block = store.block as usize;
        let block_end = block + store.layout.size();
        let cells_end = store.cells().as_ptr_range().end as usize;
        let bufs: Vec<usize> = state
            .each_cell()
            .map(|cell| cell.with_meta(|meta| meta.buf as usize))
            .collect();
        assert_eq!(bufs.len(), 3);
        for (at, buf) in bufs.iter().enumerate() {
            assert_eq!(buf % CELL_ALIGN, 0, "cell {at}'s bytes are aligned");
            assert_eq!(
                *buf,
                bufs[0] + at * 112,
                "cell {at}'s bytes are a stride on"
            );
            assert!(
                *buf >= cells_end && buf + 112 <= block_end,
                "cell {at}'s bytes are the block's"
            );
        }
        assert!(
            state.taking.is_none(),
            "a reserved table takes no memory after it is made"
        );
        assert_eq!(state.capacity(), 3);
    }

    /// A reserved table of no cells refuses a task its cells would fit for want of a cell, and one
    /// they would not, by size or by alignment, as too large.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_reserved_table_of_no_cells_names_the_cause_of_each_refusal() {
        let state = ExecutorState::reserved(0, 64);
        assert_eq!(
            state.claim_bytes(0, 8, 8).map(|_| ()),
            Err(SpawnRefusal::NoTaskCell)
        );
        assert_eq!(
            state.claim_bytes(0, 65, 8).map(|_| ()),
            Err(SpawnRefusal::TooLarge)
        );
        assert_eq!(
            state.claim_bytes(0, 8, 2 * CELL_ALIGN).map(|_| ()),
            Err(SpawnRefusal::TooLarge)
        );
        assert_eq!(
            state.refusals(),
            Refusals {
                no_task_cell: 1,
                too_large: 2,
            }
        );
    }

    /// An opening table places a task its reserved cells fit in one of them, and a larger one in a
    /// bare cell it gives the bytes: it holds as many bare cells as it was told, and no more.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn an_opening_table_takes_a_reserved_cell_first_and_fits_a_bare_one_after() {
        let state = ExecutorState::opening(1, 64, 1);
        assert_eq!(state.capacity(), 2);
        let reserved = state.fixed_cells().first().expect("one reserved cell");
        let (first, _) = state.claim_bytes(0, 32, 8).expect("the reserved cell");
        assert!(ptr::eq(first, reserved));
        let (second, buf) = state
            .claim_bytes(0, 200, 8)
            .expect("the bare cell, given bytes");
        assert!(!ptr::eq(second, reserved));
        assert!(!buf.is_null());
        assert!(second.with_meta(|meta| meta.cap >= 200 && meta.buf == buf));
        assert_eq!(
            state.claim_bytes(0, 8, 8).map(|_| ()),
            Err(SpawnRefusal::NoTaskCell),
            "both cells are taken and no third is added"
        );
        assert_eq!(state.capacity(), 2);
        ExecutorState::release(first);
        ExecutorState::release(second);
    }
}
