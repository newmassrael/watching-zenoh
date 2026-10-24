// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative task pool on STATIC storage (`session-slot`, fixed-memory
//! step S6): the form of [`crate::executor`] the MCU session profile compiles in
//! its place, with the same surface and no heap.
//!
//! ## What the heap form was made of, and what this one is
//!
//! A spawned task was a `Pin<Box<dyn Future>>` in a `Vec<Option<TaskSlot>>` that
//! only ever grew, with two `Arc<AtomicBool>` (a wake flag and a cancel flag) per
//! task, a `Arc<Mutex<RefCell<JoinState<T>>>>` for its result and another box for
//! the wrapper future: five allocations for every task and a table that was never
//! given back. Here a task is a CELL of a table the image declares
//! ([`TaskTable`]): the future is written into the cell's bytes in place, its
//! wake and cancel flags are the cell's own, its result is written into the same
//! bytes after it, and when the task and its handle are both done the cell is free
//! for the next. Nothing is allocated, and a full table is a refusal that is
//! COUNTED ([`ExecutorState::refusals`]), never a fallback to the heap.
//!
//! ## What a task must fit
//!
//! A future and its output together must fit a cell (`TASK_BYTES` of the image's
//! table) with an alignment of at most [`CELL_ALIGN`]. A task that does not is
//! refused as [`SpawnRefusal::TooLarge`] with the future handed back; the image
//! sizes its cells from the tasks it runs (a session pump task is a reference to
//! its pump cell and an observer: a few dozen bytes).
//!
//! ## The contract this makes with the profile
//!
//! The table is `Sync` by the profile's own rule and not by anything a compiler
//! can check: tasks are polled by ONE executor on one core, and the only thing an
//! interrupt may do to a cell is raise its wake flag (a waker is a reference to the
//! cell and `wake` stores one flag). Every other field is touched only inside a
//! critical section, as the heap form's are.

use core::cell::{Cell, RefCell, UnsafeCell};
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{align_of, size_of, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use critical_section::Mutex;
use wz_runtime_core::RuntimeError;

use crate::atomic::{AtomicBool, Ordering};

pub use crate::yield_now::{yield_now, YieldNow};

/// The alignment every cell's bytes have: the most a task's future or its output
/// may ask for.
pub const CELL_ALIGN: usize = 16;

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
    /// The cell's bytes and their length, set once when the runtime starts.
    buf: *mut u8,
    cap: usize,
}

impl Meta {
    const fn new() -> Self {
        Self {
            state: State::Free,
            handle: false,
            aborted: false,
            has_output: false,
            out_off: 0,
            join_waker: None,
            ops: None,
            buf: ptr::null_mut(),
            cap: 0,
        }
    }
}

/// One task's cell: two flags an interrupt may touch and the bookkeeping that only
/// a critical section may.
pub struct TaskCell {
    wake: AtomicBool,
    cancel: AtomicBool,
    meta: Mutex<RefCell<Meta>>,
}

// SAFETY: see the module's contract. The flags are atomics; `meta` is behind a
// critical section; the cell's bytes are written only by the one claimant of the
// cell (state `Spawning`) and the one poller (state `Polling`), which the state
// word makes exclusive.
unsafe impl Sync for TaskCell {}

impl TaskCell {
    const fn new() -> Self {
        Self {
            wake: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            meta: Mutex::new(RefCell::new(Meta::new())),
        }
    }

    fn with_meta<R>(&self, f: impl FnOnce(&mut Meta) -> R) -> R {
        crate::cs::with(|cs| f(&mut self.meta.borrow(cs).borrow_mut()))
    }
}

/// The bytes of one cell.
#[repr(C, align(16))]
struct TaskBytes<const BYTES: usize>(UnsafeCell<MaybeUninit<[u8; BYTES]>>);

const _: () = assert!(align_of::<TaskBytes<1>>() == CELL_ALIGN);

/// The task table an image declares: `TASKS` cells of `BYTES` bytes each, in a
/// `static`, which the runtime's cell ([`crate::runtime_impl::RuntimeCell`])
/// holds.
pub struct TaskTable<const TASKS: usize, const BYTES: usize> {
    cells: [TaskCell; TASKS],
    bytes: [TaskBytes<BYTES>; TASKS],
}

// SAFETY: see the module's contract; the bytes are reached only through a cell's
// own state word.
unsafe impl<const TASKS: usize, const BYTES: usize> Sync for TaskTable<TASKS, BYTES> {}

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
        ExecutorState {
            cells: &self.cells,
            refused: Mutex::new(Cell::new(Refusals::default())),
        }
    }
}

impl<const TASKS: usize, const BYTES: usize> Default for TaskTable<TASKS, BYTES> {
    fn default() -> Self {
        Self::new()
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

/// The task pool of a runtime: a view of a [`TaskTable`] that spawns into it and
/// polls it.
pub struct ExecutorState {
    cells: &'static [TaskCell],
    refused: Mutex<Cell<Refusals>>,
}

/// `value` rounded up to a multiple of `align`.
const fn round_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
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

impl ExecutorState {
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

    /// The cell count of the table.
    pub fn capacity(&self) -> usize {
        self.cells.len()
    }

    /// Write `fut` into a free cell and mark it ready, or refuse it, counted, and
    /// hand it back.
    pub(crate) fn spawn<F: Future + 'static>(
        &self,
        fut: F,
    ) -> Result<&'static TaskCell, SpawnRefused<F>> {
        let out_off = round_up(size_of::<F>(), align_of::<F::Output>());
        let cap = self
            .cells
            .first()
            .map_or(0, |cell| cell.with_meta(|m| m.cap));
        if align_of::<F>() > CELL_ALIGN
            || align_of::<F::Output>() > CELL_ALIGN
            || out_off + size_of::<F::Output>() > cap
        {
            self.refuse(SpawnRefusal::TooLarge);
            return Err(SpawnRefused {
                future: fut,
                why: SpawnRefusal::TooLarge,
            });
        }
        let claimed = self.cells.iter().find_map(|cell| {
            cell.with_meta(|meta| {
                if meta.state == State::Free {
                    meta.state = State::Spawning;
                    Some(meta.buf)
                } else {
                    None
                }
            })
            .map(|buf| (cell, buf))
        });
        let Some((cell, buf)) = claimed else {
            self.refuse(SpawnRefusal::NoTaskCell);
            return Err(SpawnRefused {
                future: fut,
                why: SpawnRefusal::NoTaskCell,
            });
        };
        // SAFETY: the cell is `Spawning`, which only this call holds, and its bytes
        // are `cap` long and `CELL_ALIGN`-aligned, which the check above compared
        // against `F`'s size and alignment.
        unsafe { ptr::write(buf.cast::<F>(), fut) };
        cell.cancel.store(false, Ordering::Release);
        cell.wake.store(true, Ordering::Release);
        cell.with_meta(|meta| {
            meta.ops = Some(Ops {
                poll: poll_erased::<F>,
                drop_future: drop_erased::<F>,
                drop_output: drop_erased::<F::Output>,
            });
            meta.out_off = out_off;
            meta.has_output = false;
            meta.aborted = false;
            meta.handle = true;
            meta.join_waker = None;
            meta.state = State::Live;
        });
        Ok(cell)
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

    /// Give the cell back.
    fn release(cell: &'static TaskCell) {
        cell.with_meta(|meta| {
            meta.ops = None;
            meta.has_output = false;
            meta.aborted = false;
            meta.handle = false;
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
        for cell in self.cells {
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
                    let waker = cell_waker(cell);
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
        self.cells
            .iter()
            .filter(|cell| cell.with_meta(|meta| meta.state != State::Free))
            .count()
    }

    /// Diagnostic + test helper: true if a task that is waiting has its wake flag
    /// set.
    pub(crate) fn any_ready(&self) -> bool {
        self.cells.iter().any(|cell| {
            cell.with_meta(|meta| meta.state == State::Live) && cell.wake.load(Ordering::Acquire)
        })
    }
}

// The waker of a task is a reference to its cell: cloning it copies the
// reference, waking it raises the cell's wake flag, dropping it does nothing. A
// stale waker (a task that ended, a cell that was reused) raises the flag of the
// cell's next task, which polls once for nothing: a spurious wake is allowed.
unsafe fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    // SAFETY: `data` is a `&'static TaskCell` made by `cell_waker`.
    unsafe { waker_wake_by_ref(data) }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: `data` is a `&'static TaskCell` made by `cell_waker`.
    let cell = unsafe { &*data.cast::<TaskCell>() };
    cell.wake.store(true, Ordering::Release);
}

unsafe fn waker_drop(_data: *const ()) {}

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// The waker that raises `cell`'s wake flag.
pub(crate) fn cell_waker(cell: &'static TaskCell) -> Waker {
    let raw = RawWaker::new((cell as *const TaskCell).cast::<()>(), &VTABLE);
    // SAFETY: the vtable upholds the `RawWaker` contract: clone copies a reference
    // that is `'static`, wake and wake_by_ref store one atomic, drop releases
    // nothing.
    unsafe { Waker::from_raw(raw) }
}

/// The handle of a task in a cell: the future that answers with its output, and
/// the means to abort it. What both [`crate::CoopJoinHandle`] and
/// [`crate::CoopLocalJoinHandle`] are made of.
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
        let Some(cell) = self.cell.filter(|_| !self.taken) else {
            return;
        };
        /// How to drop an output nobody read: the function and where it lies.
        type Unread = Option<(unsafe fn(*mut u8), *mut u8)>;
        enum Left {
            Detached,
            Done(Unread),
        }
        let left = cell.with_meta(|meta| {
            if meta.state == State::Done {
                let ops = if meta.has_output { meta.ops } else { None };
                let output = ops.map(|ops| (ops.drop_output, meta.buf.wrapping_add(meta.out_off)));
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
}
