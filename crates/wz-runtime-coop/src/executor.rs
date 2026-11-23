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
//!   `tasks` cells of `task_bytes` each in one block. What an engine that owes no allocation
//!   after its open asks for: the table is the open's, and a spawn past it is refused.
//! - Grown when every cell is taken (`CoopRuntime::new`, the heap profile), by a chunk of cells
//!   that never moves; a cell keeps its bytes for the next task that fits them, so a program that
//!   spawns the same tasks again allocates nothing after the first.
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

#[cfg(feature = "session-slot")]
use core::cell::UnsafeCell;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::marker::PhantomData;
#[cfg(feature = "session-slot")]
use core::mem::MaybeUninit;
use core::mem::{align_of, size_of, ManuallyDrop};
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::alloc::Layout;
use critical_section::Mutex;
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
    drop_future: unsafe fn(*mut u8),
    /// Drop the output at the buffer (a result no handle took).
    drop_output: unsafe fn(*mut u8),
}

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
    meta: Mutex<RefCell<Meta>>,
    /// The store that owns the cell, whose count a waker and a handle hold; null for a cell of a
    /// `static` table, which is never freed. Written when the cell is made and never after.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    owner: *const TaskStore,
}

// SAFETY: see the module's contract. The flags are atomics; `meta` is behind a
// critical section; the cell's bytes are written only by the one claimant of the
// cell (state `Spawning`) and the one poller (state `Polling`), which the state
// word makes exclusive; `owner` is only read.
unsafe impl Sync for TaskCell {}

impl TaskCell {
    #[cfg(feature = "session-slot")]
    const fn new() -> Self {
        Self {
            wake: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            meta: Mutex::new(RefCell::new(Meta::new())),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            owner: ptr::null(),
        }
    }

    /// A free cell of `owner`'s, over `cap` bytes at `buf` (none yet for a grown table).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn owned(owner: *const TaskStore, buf: *mut u8, cap: usize) -> Self {
        let mut meta = Meta::new();
        meta.buf = buf;
        meta.cap = cap;
        Self {
            wake: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            meta: Mutex::new(RefCell::new(meta)),
            owner,
        }
    }

    fn with_meta<R>(&self, f: impl FnOnce(&mut Meta) -> R) -> R {
        crate::cs::with(|cs| f(&mut self.meta.borrow(cs).borrow_mut()))
    }
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
            cell.with_meta(|meta| {
                meta.buf = bytes.0.get().cast::<u8>();
                meta.cap = BYTES;
            });
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

/// The cells of a table the runtime owns, reserved or grown, and the bytes of a reserved one.
///
/// Held by a count: the executor, every waker and every join handle of its cells. The cells are
/// in chunks that never move once made and are let go only with the store, so a reference to a
/// cell is good for as long as a count is held.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub(crate) struct TaskStore {
    /// Each chunk a box given up to a raw pointer: the list moves when it grows, and a box moved
    /// with it would be asserted unique again over the cells other holders point at.
    chunks: Mutex<RefCell<Vec<*const [TaskCell]>>>,
    /// The block a reserved table's cells lie in, and its layout; null for a grown table, whose
    /// cells each keep bytes of their own.
    region: *mut u8,
    region_layout: Layout,
}

// SAFETY: the chunk list is behind a critical section; the cells are `Sync` by the module's
// contract; the region is reached only through the cells.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe impl Send for TaskStore {}
// SAFETY: as above.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
unsafe impl Sync for TaskStore {}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TaskStore {
    /// The cell at `index` in the order of the chunks, if the store has that many. Out of line:
    /// every pass over the table asks it, and its section and its walk are one body for all.
    #[inline(never)]
    fn cell_at(&self, index: usize) -> Option<&'static TaskCell> {
        let at = crate::cs::with(|cs| {
            let chunks = self.chunks.borrow(cs).borrow();
            let mut left = index;
            for &chunk in chunks.iter() {
                // SAFETY: a chunk the list holds is alive until the store is dropped.
                let chunk: &[TaskCell] = unsafe { &*chunk };
                if let Some(cell) = chunk.get(left) {
                    return Some(ptr::from_ref(cell));
                }
                left -= chunk.len();
            }
            None
        })?;
        // SAFETY: a chunk is a box the list owns, which never moves and is let go only when the
        // store is; every holder of a cell past the executor's own call holds a count on the store
        // (`retain`), so the reference does not outlive the cell.
        Some(unsafe { &*at })
    }

    /// The cells the store holds.
    #[inline(never)]
    fn len(&self) -> usize {
        crate::cs::with(|cs| {
            self.chunks
                .borrow(cs)
                .borrow()
                .iter()
                .map(|c| c.len())
                .sum()
        })
    }

    /// Add a chunk of `count` free cells (at least one), with its first cell already taken for a
    /// spawn (`Spawning`): the cell a growing table hands the spawn that found no other.
    fn grow(&self, set: u32, count: usize) -> &'static TaskCell {
        let cells = self.add_chunk(count.max(1), 0, 0);
        cells[0].with_meta(|meta| {
            meta.state = State::Spawning;
            meta.set = set;
        });
        &cells[0]
    }

    /// Add a chunk of `count` free cells: the first `reserved` over the store's region, `bytes`
    /// each at steps of `round_up(bytes, CELL_ALIGN)`, and the rest with no bytes yet, which a
    /// spawn gives them (`fit_cell`). The one maker of cells, for a reserved table and a grown
    /// one alike.
    #[inline(never)]
    fn add_chunk(&self, count: usize, reserved: usize, bytes: usize) -> &'static [TaskCell] {
        let owner: *const TaskStore = self;
        let stride = round_up(bytes.max(1), CELL_ALIGN);
        let region = self.region;
        let chunk: Box<[TaskCell]> = (0..count)
            .map(|at| {
                if at < reserved {
                    // `wrapping_add` and not `add`: no cell's bytes are reached until a spawn
                    // takes it, and each offset is inside the region.
                    TaskCell::owned(owner, region.wrapping_add(at * stride), bytes)
                } else {
                    TaskCell::owned(owner, ptr::null_mut(), 0)
                }
            })
            .collect();
        let raw: *const [TaskCell] = Box::into_raw(chunk).cast_const();
        crate::cs::with(|cs| self.chunks.borrow(cs).borrow_mut().push(raw));
        // SAFETY: as for `cell_at`: the chunk is a box the store owns now, which never moves and
        // is let go only with the store.
        unsafe { &*raw }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Drop for TaskStore {
    fn drop(&mut self) {
        // The last count is gone, so nothing else reaches the store: its cells are read without a
        // section.
        let chunks = core::mem::take(self.chunks.get_mut().get_mut());
        for raw in chunks {
            // SAFETY: each chunk is a box the store gave up to the list, taken back here once.
            let mut chunk = unsafe { Box::from_raw(raw.cast_mut()) };
            for cell in chunk.iter_mut() {
                let meta = cell.meta.get_mut().get_mut();
                let (buf, cap, align) = (meta.buf, meta.cap, meta.buf_align);
                // A reserved cell's bytes are the region's, given back below with it.
                let in_region = !self.region.is_null()
                    && (buf as usize) >= (self.region as usize)
                    && (buf as usize) < (self.region as usize) + self.region_layout.size();
                if !buf.is_null() && !in_region {
                    // SAFETY: a grown table's cell holds bytes `fit_cell` allocated with this
                    // size and alignment, and no task is in them: the executor that dropped its
                    // tasks is gone, and a done task's output went with its handle.
                    unsafe {
                        alloc::alloc::dealloc(buf, Layout::from_size_align_unchecked(cap, align))
                    }
                }
            }
        }
        if !self.region.is_null() {
            // SAFETY: the region was allocated with this layout by `ExecutorState::reserved`.
            unsafe { alloc::alloc::dealloc(self.region, self.region_layout) }
        }
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
    /// A table the runtime owns, reserved or grown.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Store(Arc<TaskStore>),
}

/// The task pool of a runtime: a view of its table that spawns into it and polls it.
pub struct ExecutorState {
    cells: Cells,
    /// The bytes of every cell of a fixed table (a `static` one or one reserved); `None` for a
    /// grown table, whose cells take the bytes each task needs.
    cell_bytes: Option<usize>,
    /// How the table grows; `None` for a fixed one.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    growth: Option<Growth>,
    /// The number the next local set's tasks are marked with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    next_set: Mutex<Cell<u32>>,
    /// A table that grows while its open lasts is fixed from now on (`Self::seal`).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    sealed: AtomicBool,
    refused: Mutex<Cell<Refusals>>,
    /// The most cells the table has held at once: zero-sized unless the build keeps the mark
    /// (`pool-monitor`), so the state is the size it was.
    #[cfg(feature = "session-slot")]
    high: Mutex<Cell<wz_session_core::pool_gauge::HighWater>>,
}

/// The bytes of a task cell that holds a future of type `F` and its output: what a spawn of it
/// checks a cell against, for a future whose type can be named.
pub const fn cell_bytes_for<F: Future>() -> usize {
    round_up(size_of::<F>(), align_of::<F::Output>()) + size_of::<F::Output>()
}

/// `value` rounded up to a multiple of `align`.
const fn round_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// The bytes of a task cell that holds the future `make` returns and that future's output: what a
/// spawn of it checks a cell against, as a constant. `make` is only the way to NAME the future,
/// which an `async` block or an `impl Future` return has no other way to be named: pass the
/// function that returns it, with its type arguments, and it is not called.
pub const fn cell_bytes_of<A, B, R: Future>(_make: fn(A, B) -> R) -> usize {
    round_up(size_of::<R>(), align_of::<R::Output>()) + size_of::<R::Output>()
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

/// The alignment `meta`'s cell's bytes have: what a grown cell was given, a fixed cell's
/// [`CELL_ALIGN`].
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn cell_align(meta: &Meta) -> usize {
    meta.buf_align
}

/// See the heap profile's form: every cell of a `static` table is aligned alike.
#[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
fn cell_align(_meta: &Meta) -> usize {
    CELL_ALIGN
}

/// Give a grown table's `cell`, which the caller has taken (`Spawning`), bytes for a task of
/// `need` bytes at `align`: the ones it has when they are enough, which is what lets a grown
/// table spawn again without allocating, or new ones in their place.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn fit_cell(cell: &TaskCell, need: usize, align: usize) -> *mut u8 {
    let align = align.max(CELL_ALIGN);
    let (held, cap, held_align) = cell.with_meta(|meta| (meta.buf, meta.cap, meta.buf_align));
    if !held.is_null() && cap >= need && held_align >= align {
        return held;
    }
    let size = need.max(1);
    let layout = Layout::from_size_align(size, align).expect("a task's size and alignment");
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
    fresh
}

/// The store of `tasks` cells of `task_bytes` each, in one block reserved now, and `empty` cells
/// beside them with no bytes yet.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn reserved_store(tasks: usize, task_bytes: usize, empty: usize) -> Arc<TaskStore> {
    let stride = round_up(task_bytes.max(1), CELL_ALIGN);
    let layout = stride
        .checked_mul(tasks)
        .and_then(|size| Layout::from_size_align(size, CELL_ALIGN).ok())
        .expect("a task table's size");
    let region = if layout.size() == 0 {
        ptr::null_mut()
    } else {
        // SAFETY: the layout's size is not zero.
        let region = unsafe { alloc::alloc::alloc(layout) };
        if region.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        region
    };
    let store = Arc::new(TaskStore {
        chunks: Mutex::new(RefCell::new(Vec::new())),
        region,
        region_layout: layout,
    });
    store.add_chunk(tasks.saturating_add(empty), tasks, task_bytes);
    store
}

/// What a table that takes memory after it is made does, reached only through such a table: a
/// program that makes none links none of it.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
#[derive(Clone, Copy)]
struct Growth {
    /// A grown table's (`CoopRuntime::new`): a cell of a new chunk of the count given, already
    /// taken for a spawn of the set given; its chunks double, and a free cell too small for a
    /// task is given new bytes. `None` for a table reserved while its open lasts
    /// (`CoopRuntime::opening`), whose cells are all made with it: only a cell with no bytes yet
    /// is given the bytes of the task that takes it, and none once it is sealed.
    grow: Option<fn(&TaskStore, u32, usize) -> &'static TaskCell>,
    /// Bytes for a task of the size and alignment given, in the cell given.
    fit: fn(&TaskCell, usize, usize) -> *mut u8,
}

impl ExecutorState {
    fn over(cells: Cells, cell_bytes: Option<usize>) -> Self {
        Self {
            cells,
            cell_bytes,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            growth: None,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            next_set: Mutex::new(Cell::new(1)),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            sealed: AtomicBool::new(false),
            refused: Mutex::new(Cell::new(Refusals::default())),
            #[cfg(feature = "session-slot")]
            high: Mutex::new(Cell::new(wz_session_core::pool_gauge::HighWater::new())),
        }
    }

    /// A table that grows when every cell is taken.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn growing() -> Self {
        let store = TaskStore {
            chunks: Mutex::new(RefCell::new(Vec::new())),
            region: ptr::null_mut(),
            region_layout: Layout::new::<u8>(),
        };
        let mut state = Self::over(Cells::Store(Arc::new(store)), None);
        state.growth = Some(Growth {
            grow: Some(TaskStore::grow),
            fit: fit_cell,
        });
        state
    }

    /// `tasks` cells of `task_bytes` each, reserved now in one block, and `added` cells beside
    /// them with no bytes yet: while the open lasts, a task no free cell fits takes one of those
    /// and the bytes it needs, kept for the next task it fits. Once [`Self::seal`] is called the
    /// table is fixed, and a spawn that finds no free cell it fits is refused, counted; so is one
    /// that finds every added cell taken. The table never holds more cells than it was made with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn opening(tasks: usize, task_bytes: usize, added: usize) -> Self {
        let mut state = Self::over(Cells::Store(reserved_store(tasks, task_bytes, added)), None);
        state.growth = Some(Growth {
            grow: None,
            fit: fit_cell,
        });
        state
    }

    /// The open is over: the table takes no more memory, and a spawn that finds no free cell it
    /// fits is refused, counted.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn seal(&self) {
        self.sealed.store(true, Ordering::Release);
    }

    /// `tasks` cells of `task_bytes` each, reserved now in one block: a spawn past them is
    /// refused, counted, and none allocates.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) fn reserved(tasks: usize, task_bytes: usize) -> Self {
        Self::over(
            Cells::Store(reserved_store(tasks, task_bytes, 0)),
            Some(task_bytes),
        )
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

    /// The cell at `index`, in the table's order.
    fn cell_at(&self, index: usize) -> Option<&'static TaskCell> {
        match self.cells {
            #[cfg(feature = "session-slot")]
            Cells::Table(cells) => cells.get(index),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Cells::Store(ref store) => store.cell_at(index),
        }
    }

    /// A cell made for a spawn that found every other taken: one of a grown table's new chunk.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn grow(&self, set: u32) -> Option<&'static TaskCell> {
        let grow = self.growth?.grow?;
        match self.cells {
            Cells::Store(ref store) => Some(grow(store, set, store.len().max(FIRST_CHUNK))),
        }
    }

    /// A fixed table does not grow.
    #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
    fn grow(&self, _set: u32) -> Option<&'static TaskCell> {
        None
    }

    /// Whether a free cell too small for a task is given new bytes: a grown table's are.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn refits(&self) -> bool {
        self.growth.is_some_and(|growth| growth.grow.is_some())
    }

    /// A fixed table's cells keep the bytes they have.
    #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
    fn refits(&self) -> bool {
        false
    }

    /// Whether a free cell with no bytes yet may be given them: one of a table reserved while its
    /// open lasts, until it is sealed.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn fills(&self) -> bool {
        self.growth.is_some() && !self.sealed.load(Ordering::Acquire)
    }

    /// A `static` table's cells all have their bytes.
    #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
    fn fills(&self) -> bool {
        false
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
        match self.cells {
            #[cfg(feature = "session-slot")]
            Cells::Table(cells) => cells.len(),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Cells::Store(ref store) => store.len(),
        }
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
        let need = out_off + size_of::<F::Output>();
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
        if let Some(cap) = self.cell_bytes {
            if align > CELL_ALIGN || need > cap {
                self.refuse(SpawnRefusal::TooLarge);
                return Err(SpawnRefusal::TooLarge);
            }
        }
        // A grown table gives any free cell the bytes a task needs, and a table whose open lasts
        // a free cell that has none yet; every table takes a free cell whose bytes the task fits.
        let refits = self.refits();
        let fills = self.fills();
        let mut index = 0;
        // A cell of the table, free or not, has bytes the task fits.
        let mut room = false;
        let found = loop {
            let Some(cell) = self.cell_at(index) else {
                break None;
            };
            index += 1;
            let taken = cell.with_meta(|meta| {
                let fits = meta.cap >= need && cell_align(meta) >= align;
                room |= fits;
                let empty = meta.buf.is_null();
                if meta.state == State::Free && (refits || fits || (fills && empty)) {
                    meta.state = State::Spawning;
                    meta.set = set;
                    Some(meta.buf)
                } else {
                    None
                }
            });
            if let Some(buf) = taken {
                break Some((cell, buf));
            }
        };
        let (cell, buf) = match found {
            Some(taken) => taken,
            None => match self.grow(set) {
                Some(cell) => (cell, ptr::null_mut()),
                None => {
                    // A task a taken cell fits waits for one to come free; one no cell fits never
                    // will, which is the cause named.
                    let why = if room || index == 0 {
                        SpawnRefusal::NoTaskCell
                    } else {
                        SpawnRefusal::TooLarge
                    };
                    self.refuse(why);
                    return Err(why);
                }
            },
        };
        // A cell with no bytes yet, or a grown table's cell, takes the bytes the task needs.
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        let buf = match self.growth {
            Some(growth) if refits || buf.is_null() => (growth.fit)(cell, need, align),
            _ => buf,
        };
        // The cell is taken: the mark is what the table holds now, if that is the most so far.
        #[cfg(all(feature = "pool-monitor", feature = "session-slot"))]
        {
            let held = self.live_task_count();
            crate::cs::with(|cs| {
                let high = self.high.borrow(cs);
                let mut mark = high.get();
                mark.note(held);
                high.set(mark);
            });
        }
        Ok((cell, buf))
    }

    /// Write `fut` into the cell `claimed` names and make the task live.
    #[inline(always)]
    fn start<F: Future + 'static>(claimed: Claimed, fut: F) -> &'static TaskCell {
        let Claimed { cell, buf, out_off } = claimed;
        // SAFETY: the cell is `Spawning`, which only the caller holds, and its bytes
        // are long enough and aligned for `F` and its output, which `claim` checked
        // (a fixed table) or gave the cell (a grown one).
        unsafe { ptr::write(buf.cast::<F>(), fut) };
        Self::go_live(
            cell,
            Ops {
                poll: poll_erased::<F>,
                drop_future: drop_erased::<F>,
                drop_output: drop_erased::<F::Output>,
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
            meta.ops = Some(ops);
            meta.out_off = out_off;
            meta.has_output = false;
            meta.aborted = false;
            meta.handle = true;
            meta.join_waker = None;
            meta.state = State::Live;
        });
    }

    /// The task at `cell` is over (`completed`: its future answered and left its
    /// output; otherwise it was swept and its future dropped). With a handle the
    /// cell stays, `Done`, until the handle has read it; without one it is freed.
    fn finish(cell: &'static TaskCell, completed: bool) {
        let (waker, free_output) = cell.with_meta(|meta| {
            meta.has_output = completed;
            if meta.handle {
                meta.state = State::Done;
                (meta.join_waker.take(), None)
            } else if completed {
                (
                    None,
                    meta.ops
                        .map(|ops| (ops.drop_output, meta.buf, meta.out_off)),
                )
            } else {
                (None, None)
            }
        });
        if let Some(waker) = waker {
            waker.wake();
            return;
        }
        if let Some((drop_output, buf, out_off)) = free_output {
            // SAFETY: `has_output` was set by a task that answered, and no handle
            // will read it.
            unsafe { drop_output(buf.add(out_off)) };
        }
        let detached = cell.with_meta(|meta| !meta.handle);
        if detached {
            Self::release(cell);
        }
    }

    /// Give the cell back. Its bytes stay with it, for the next task.
    fn release(cell: &'static TaskCell) {
        cell.with_meta(|meta| {
            meta.ops = None;
            meta.has_output = false;
            meta.aborted = false;
            meta.handle = false;
            meta.set = 0;
            meta.join_waker = None;
            meta.state = State::Free;
        });
    }

    /// Poll every ready task at most once, and sweep every task whose handle
    /// aborted it. A task that answers `Pending` stays for the next pass; one that
    /// answers `Ready` leaves its output for its handle. A task spawned from inside
    /// a poll may be polled in this pass if its cell lies later in the table, or
    /// in the next.
    pub fn run_until_idle(&self) {
        let mut index = 0;
        while let Some(cell) = self.cell_at(index) {
            index += 1;
            enum Act {
                Nothing,
                Sweep(Ops, *mut u8),
                Poll(Ops, *mut u8, usize),
            }
            let act = cell.with_meta(|meta| {
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
            });
            match act {
                Act::Nothing => {}
                Act::Sweep(ops, buf) => {
                    // SAFETY: the cell was `Live`, so it holds a future that has
                    // not answered; it is `Polling` now, which keeps every other
                    // user off it, and it is dropped once.
                    unsafe { (ops.drop_future)(buf) };
                    Self::finish(cell, false);
                }
                Act::Poll(ops, buf, out_off) => {
                    // The executor's own count keeps the cell while it polls: this waker holds
                    // none and gives none back, and a clone the task keeps takes its own.
                    let waker = borrowed_waker(cell);
                    let mut cx = Context::from_waker(&waker);
                    // SAFETY: the cell was `Live`, so it holds a pinned future that
                    // has not answered, and it is `Polling` now.
                    match unsafe { (ops.poll)(buf, out_off, &mut cx) } {
                        Poll::Ready(()) => Self::finish(cell, true),
                        Poll::Pending => cell.with_meta(|meta| meta.state = State::Live),
                    }
                }
            }
        }
    }

    /// Diagnostic + test helper: cells that hold a task (or a result no handle has
    /// read yet).
    pub fn live_task_count(&self) -> usize {
        let mut held = 0;
        let mut index = 0;
        while let Some(cell) = self.cell_at(index) {
            index += 1;
            if cell.with_meta(|meta| meta.state != State::Free) {
                held += 1;
            }
        }
        held
    }

    /// Diagnostic + test helper: tasks of a local set that have not ended (a result waiting for
    /// its handle is not one).
    pub(crate) fn running_local_count(&self) -> usize {
        let mut running = 0;
        let mut index = 0;
        while let Some(cell) = self.cell_at(index) {
            index += 1;
            let is = cell.with_meta(|meta| {
                meta.set != 0
                    && matches!(meta.state, State::Spawning | State::Live | State::Polling)
            });
            if is {
                running += 1;
            }
        }
        running
    }

    /// Diagnostic + test helper: true if a task that is waiting has its wake flag
    /// set.
    pub(crate) fn any_ready(&self) -> bool {
        let mut index = 0;
        while let Some(cell) = self.cell_at(index) {
            index += 1;
            if cell.with_meta(|meta| meta.state == State::Live) && cell.wake.load(Ordering::Acquire)
            {
                return true;
            }
        }
        false
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
        let mut index = 0;
        while let Some(cell) = self.cell_at(index) {
            index += 1;
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
                Self::finish(cell, false);
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
            Output(*mut u8, Ops, bool),
        }
        let seen = cell.with_meta(|meta| match meta.state {
            State::Done => {
                let ops = meta.ops.expect("a done cell holds its operations");
                Seen::Output(
                    // SAFETY of the offset: `out_off` was computed in bounds.
                    meta.buf.wrapping_add(meta.out_off),
                    ops,
                    meta.aborted,
                )
            }
            _ if meta.aborted => {
                // Detach: the executor frees the cell when it finishes sweeping.
                meta.handle = false;
                meta.join_waker = None;
                Seen::Cancelled
            }
            _ => {
                meta.join_waker = Some(cx.waker().clone());
                Seen::Pending
            }
        });
        match seen {
            Seen::Pending => Poll::Pending,
            Seen::Cancelled => {
                self.taken = true;
                Poll::Ready(Err(RuntimeError::JoinCancelled))
            }
            Seen::Output(at, ops, aborted) => {
                self.taken = true;
                let answer = if aborted {
                    if cell.with_meta(|meta| meta.has_output) {
                        // SAFETY: a done cell that holds an output holds it live;
                        // it is dropped once and the handle is over.
                        unsafe { (ops.drop_output)(at) };
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
            /// How to drop an output nobody read: the function and where it lies.
            type Unread = Option<(unsafe fn(*mut u8), *mut u8)>;
            enum Left {
                Detached,
                Done(Unread),
            }
            let left = cell.with_meta(|meta| {
                if meta.state == State::Done {
                    let ops = if meta.has_output { meta.ops } else { None };
                    let output =
                        ops.map(|ops| (ops.drop_output, meta.buf.wrapping_add(meta.out_off)));
                    Left::Done(output)
                } else {
                    meta.handle = false;
                    meta.join_waker = None;
                    Left::Detached
                }
            });
            if let Left::Done(output) = left {
                if let Some((drop_output, at)) = output {
                    // SAFETY: a done cell that holds an output holds it live and no
                    // handle has read it; it is dropped once.
                    unsafe { drop_output(at) };
                }
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
