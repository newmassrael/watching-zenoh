// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The task table a heap-profile runtime owns, grown (`CoopRuntime::new`) or reserved
//! (`CoopRuntime::reserved`), against what it promises beside the static table's own tests
//! (`static_tests`): a grown table spawns the same tasks again without allocating; a reserved one
//! allocates nothing after it is made and refuses past its rows, counted; the tasks are dropped
//! with the runtime; a waker kept past the runtime still points at a cell; and the timer table,
//! reserved or grown, holds a sleep without allocating once it has the entry.
//!
//! The allocations are counted on the thread that runs the test, by the allocator below: a test
//! binary has one, and the other tests of the crate run through it uncounted.

extern crate std;

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::alloc::{GlobalAlloc, Layout, System};
use std::rc::Rc;

use wz_runtime_core::{Runtime, RuntimeError, TimeSource};

use crate::executor::{yield_now, Refusals, SpawnRefusal};
use crate::kept::Kept;
use crate::{
    ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeForm, RuntimePlace, RuntimeRows,
};
use core::ptr::NonNull;

/// The allocator of this test binary: the system's, counting on a thread that asked it to.
struct Counting;

std::thread_local! {
    /// The allocations this thread made since it began counting, while it counts.
    static COUNTED: Cell<Option<usize>> = const { Cell::new(None) };
    /// Whether every allocation this thread asks for is refused, as a heap that is full would.
    static REFUSING: Cell<bool> = const { Cell::new(false) };
}

/// `f`'s answer, every allocation this thread asks for while it runs refused: what a caller of
/// the heap does when the heap is full, with nothing taken from it.
pub(crate) fn refused<R>(f: impl FnOnce() -> R) -> R {
    REFUSING.with(|refusing| refusing.set(true));
    let answer = f();
    REFUSING.with(|refusing| refusing.set(false));
    answer
}

/// Whether this thread's allocations are refused now (`refused`).
fn refusing() -> bool {
    REFUSING.try_with(Cell::get).unwrap_or(false)
}

fn note() {
    let _ = COUNTED.try_with(|counted| {
        if let Some(n) = counted.get() {
            counted.set(Some(n + 1));
        }
    });
}

// SAFETY: every call is the system allocator's, with the arguments it was given, or a refusal
// (null), which hands out no memory.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        if refusing() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        if refusing() {
            return core::ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        if refusing() {
            return core::ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// `f`'s answer and the allocations this thread made running it.
pub(crate) fn allocations<R>(f: impl FnOnce() -> R) -> (R, usize) {
    COUNTED.with(|counted| counted.set(Some(0)));
    let answer = f();
    let made = COUNTED.with(|counted| counted.replace(None)).unwrap_or(0);
    (answer, made)
}

/// A clock that does not move.
struct Still;

impl ClockSource for Still {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A value that counts its own drops into a static of the test.
struct Counted(&'static AtomicU32);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A waker that does nothing.
fn noop_waker() -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: every function of the vtable ignores its data pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

/// Poll `handle` once with a waker that does nothing.
fn poll_once<F: Future + Unpin>(handle: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(handle).poll(&mut cx)
}

/// A task that never ends and yields every turn.
async fn forever() {
    loop {
        yield_now().await;
    }
}

#[test]
fn a_grown_table_spawns_the_same_task_again_without_allocating() {
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let round = |n: u32| {
        let handle = local.spawn_local(async move {
            yield_now().await;
            n + 1
        });
        local.block_on_local(handle).expect("not cancelled")
    };
    // The first task makes the table's first chunk and its cell's bytes.
    assert_eq!(round(1), 2);
    let (answers, made) = allocations(|| (round(2), round(3)));
    assert_eq!(answers, (3, 4));
    assert_eq!(
        made, 0,
        "a task that fits a free cell's bytes is written there: the spawn, the passes and the \
         read of its handle allocate nothing"
    );
    assert_eq!(runtime.task_refusals(), Refusals::default());
}

#[test]
fn a_grown_table_grows_past_its_first_chunk_and_never_refuses() {
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let handles: std::vec::Vec<_> = (0..10).map(|_| local.spawn_local(forever())).collect();
    assert_eq!(local.live_local_task_count(), 10);
    assert!(handles.iter().all(|handle| !handle.is_finished()));
    local.run_until_idle();
    assert_eq!(
        local.live_local_task_count(),
        10,
        "every task is still running"
    );
    assert_eq!(runtime.task_refusals(), Refusals::default());
    for handle in &handles {
        handle.abort();
    }
    local.run_until_idle();
    drop(handles);
    assert_eq!(local.live_local_task_count(), 0);
    assert_eq!(runtime.live_task_count(), 0, "every cell is free");
}

/// A task that spawns another while it is polled, on a table whose cells are all taken: the
/// table grows under the pass that polls it, and the new task runs.
#[test]
fn a_task_spawned_from_inside_a_poll_grows_the_table_under_the_pass() {
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    // Seven fill the first chunk (four cells) and all of the second (four) but the outer task's
    // cell, so the inner task finds none free.
    let fillers: std::vec::Vec<_> = (0..7).map(|_| local.spawn_local(forever())).collect();
    let inner_set = local.clone();
    let outer = local.spawn_local(async move {
        let inner = inner_set.spawn_local(async { 40u32 });
        inner.await.expect("the inner task ran") + 2
    });
    assert_eq!(local.block_on_local(outer).expect("ran"), 42);
    assert!(
        runtime.task_refusals() == Refusals::default() && local.live_local_task_count() == 7,
        "the inner task took a cell of a third chunk and is gone; the fillers run"
    );
    for filler in &fillers {
        filler.abort();
    }
    local.run_until_idle();
    drop(fillers);
    assert_eq!(runtime.live_task_count(), 0);
}

#[test]
fn a_reserved_table_takes_its_rows_and_refuses_one_more_counted() {
    let runtime = CoopRuntime::reserved(
        Still,
        RuntimeRows {
            tasks: 2,
            task_bytes: 128,
            timers: 1,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    let first = local.try_spawn_local(forever()).expect("a cell");
    let second = local.try_spawn_local(forever()).expect("a cell");
    let Err(refused) = local.try_spawn_local(async { 3u8 }) else {
        panic!("both cells are taken");
    };
    assert_eq!(refused.why, SpawnRefusal::NoTaskCell);
    assert_eq!(
        runtime.task_refusals().no_task_cell,
        1,
        "the refusal is counted"
    );

    // The form that cannot fail answers a handle that reads `Shutdown`, counted too.
    let mut shut = local.spawn_local(async { 4u8 });
    assert!(shut.is_finished());
    assert!(matches!(
        poll_once(&mut shut),
        Poll::Ready(Err(RuntimeError::Shutdown))
    ));
    assert_eq!(runtime.task_refusals().no_task_cell, 2);
    // As does the runtime contract's spawn.
    let mut contract = runtime.spawn(async { 5u8 });
    assert!(matches!(
        poll_once(&mut contract),
        Poll::Ready(Err(RuntimeError::Shutdown))
    ));
    assert_eq!(runtime.task_refusals().no_task_cell, 3);
    assert_eq!(runtime.task_refusals().too_large, 0);
    assert_eq!(runtime.live_task_count(), 2, "a refusal takes no cell");

    // A cell comes back when its task is aborted, swept and its handle is gone.
    first.abort();
    local.run_until_idle();
    drop(first);
    let again = local
        .try_spawn_local(async { 6u8 })
        .expect("the freed cell");
    assert_eq!(local.block_on_local(again).expect("ran"), 6);
    drop(second);
}

#[test]
fn a_reserved_table_refuses_a_task_one_byte_larger_than_its_cells() {
    // Written as a function returning a future because that is the form `cell_bytes_of` names.
    #[allow(clippy::manual_async_fn)]
    fn task(a: u64, b: [u8; 100]) -> impl Future<Output = u32> {
        async move {
            yield_now().await;
            (a as u32) + u32::from(b[0])
        }
    }
    const BYTES: usize = crate::executor::cell_bytes_of(task);
    let fits = CoopRuntime::reserved(
        Still,
        RuntimeRows {
            tasks: 1,
            task_bytes: BYTES,
            timers: 1,
        },
    );
    let local = CoopLocalSet::new(&fits);
    let handle = local
        .try_spawn_local(task(3, [4; 100]))
        .expect("a cell of exactly its bytes");
    assert_eq!(local.block_on_local(handle).expect("ran"), 7);

    let short = CoopRuntime::reserved(
        Still,
        RuntimeRows {
            tasks: 1,
            task_bytes: BYTES - 1,
            timers: 1,
        },
    );
    let local = CoopLocalSet::new(&short);
    assert!(matches!(
        local.try_spawn_local(task(3, [4; 100])),
        Err(refused) if refused.why == SpawnRefusal::TooLarge
    ));
    assert_eq!(short.task_refusals().too_large, 1);
    assert_eq!(short.task_refusals().no_task_cell, 0);
    assert_eq!(short.live_task_count(), 0, "a refusal takes no cell");
}

#[test]
fn a_reserved_runtime_allocates_when_it_is_made_and_never_after() {
    let (runtime, made) = allocations(|| {
        CoopRuntime::reserved(
            Still,
            RuntimeRows {
                tasks: 3,
                task_bytes: 256,
                timers: 1,
            },
        )
    });
    assert!(made > 0, "the table is reserved when the runtime is made");
    let local = CoopLocalSet::new(&runtime);
    let ((), made) = allocations(|| {
        for round in 0..3u32 {
            let answer = local
                .try_spawn_local(async move {
                    yield_now().await;
                    round
                })
                .expect("a cell");
            let spinner = local.try_spawn_local(forever()).expect("a cell");
            // Held to the round's end, so its cell is the runtime contract's until then.
            let _contract = runtime.spawn(async move { round });
            assert_eq!(local.block_on_local(answer).expect("ran"), round);
            spinner.abort();
            local.run_until_idle();
            drop(spinner);
        }
    });
    assert_eq!(made, 0, "spawns, passes, aborts and reads take no memory");
    assert_eq!(runtime.task_refusals(), Refusals::default());
}

#[test]
fn the_rows_say_the_bytes_a_reserved_table_takes() {
    let rows = RuntimeRows {
        tasks: 3,
        task_bytes: 100,
        timers: 2,
    };
    let cell = core::mem::size_of::<crate::executor::TaskCell>();
    let entry = core::mem::size_of::<crate::timer::TimerSlot>();
    assert_eq!(
        rows.reserved_bytes(),
        3 * (112 + cell) + 2 * entry,
        "each cell's bytes rounded to 16, its bookkeeping, and each timer entry"
    );
    let none = RuntimeRows {
        tasks: 0,
        task_bytes: 4096,
        timers: 0,
    };
    assert_eq!(none.reserved_bytes(), 0);
}

/// A clock a test moves by hand. One per test, so it is a static of the test.
struct Hand(&'static AtomicU64);

impl ClockSource for Hand {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A task of `local` that sleeps `ms` on `runtime`'s clock and answers `answer`.
fn sleeper(
    runtime: &CoopRuntime<Hand>,
    local: &CoopLocalSet<Hand>,
    ms: u64,
    answer: u32,
) -> crate::CoopLocalJoinHandle<u32> {
    let time = CoopTime::new(runtime);
    local.spawn_local(async move {
        time.sleep(ms).await;
        answer
    })
}

/// A clock a test moves by hand that counts how often it is read. One per test, so its two words
/// are statics of the test.
struct Counted(&'static AtomicU64, &'static AtomicUsize);

impl ClockSource for Counted {
    fn now_us(&self) -> u64 {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.load(Ordering::SeqCst)
    }
}

/// A pass over the ready tasks reads no clock and wakes no timer, though one is due; a pass given
/// a time wakes the timers due by it, so the sleep ends. CONTROL: a pass that looks at the timers
/// itself reads the clock once. Turned red by a ready pass that reads the clock or wakes the timers
/// by its own reading, or a pass given a time that does not wake what is due by it.
#[test]
fn a_pass_over_the_ready_tasks_reads_no_clock() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static READS: AtomicUsize = AtomicUsize::new(0);
    let runtime = CoopRuntime::new(Counted(&NOW, &READS));
    let local = CoopLocalSet::new(&runtime);
    let time = CoopTime::new(&runtime);
    let task = local.spawn_local(async move {
        time.sleep(5).await;
        3u32
    });
    local.run_until_idle();
    assert_eq!(
        runtime.timers().pending_count(),
        1,
        "the sleep took an entry"
    );
    NOW.store(10_000, Ordering::SeqCst);

    let before = READS.load(Ordering::SeqCst);
    local.run_ready(None);
    assert_eq!(
        READS.load(Ordering::SeqCst) - before,
        0,
        "a pass over the ready tasks reads no clock"
    );
    assert_eq!(
        runtime.timers().pending_count(),
        1,
        "and wakes no timer, though it is due"
    );
    assert!(!task.is_finished(), "the sleeper was not polled");

    local.run_ready(Some(10_000));
    assert_eq!(
        runtime.timers().pending_count(),
        0,
        "the pass at a time woke it"
    );
    assert!(task.is_finished(), "and its task ran in the same pass");

    let before = READS.load(Ordering::SeqCst);
    local.run_until_idle();
    assert_eq!(
        READS.load(Ordering::SeqCst) - before,
        1,
        "CONTROL: a pass that looks at the timers reads the clock once"
    );
}

#[test]
fn a_reserved_timer_table_refuses_counted_and_the_sleep_still_ends_by_polling() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let runtime = CoopRuntime::reserved(
        Hand(&NOW),
        RuntimeRows {
            tasks: 3,
            task_bytes: 256,
            timers: 1,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    assert_eq!(runtime.timers().capacity(), 1);
    let first = sleeper(&runtime, &local, 5, 1);
    let second = sleeper(&runtime, &local, 5, 2);
    local.run_until_idle();
    assert_eq!(runtime.timers().pending_count(), 1, "one entry, taken");
    assert!(
        runtime.timer_refusals() >= 1,
        "the second sleep was refused an entry and counted"
    );
    assert_eq!(
        runtime.timers().capacity(),
        1,
        "a reserved table does not grow"
    );
    NOW.store(10_000, Ordering::SeqCst);
    assert_eq!(local.block_on_local(first).expect("by its deadline"), 1);
    assert_eq!(
        local
            .block_on_local(second)
            .expect("by polling, then by its deadline"),
        2
    );
    assert_eq!(runtime.timers().pending_count(), 0);
}

#[test]
fn a_reserved_runtime_takes_no_memory_for_a_sleep() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let runtime = CoopRuntime::reserved(
        Hand(&NOW),
        RuntimeRows {
            tasks: 2,
            task_bytes: 256,
            timers: 2,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    let (answer, made) = allocations(|| {
        let handle = sleeper(&runtime, &local, 5, 9);
        local.run_until_idle();
        assert_eq!(runtime.timers().pending_count(), 1);
        NOW.store(10_000, Ordering::SeqCst);
        local.block_on_local(handle).expect("by its deadline")
    });
    assert_eq!(answer, 9);
    assert_eq!(made, 0, "the sleep's entry is one of the table's");
    assert_eq!(runtime.timer_refusals(), 0);
}

#[test]
fn a_timeout_holds_its_future_in_place_and_takes_no_memory() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let runtime = CoopRuntime::reserved(
        Hand(&NOW),
        RuntimeRows {
            tasks: 1,
            task_bytes: 256,
            timers: 1,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    let (elapsed, made) = allocations(|| {
        let time = CoopTime::new(&runtime);
        let handle = local.spawn_local(async move { time.timeout(2, forever()).await.is_err() });
        local.run_until_idle();
        NOW.store(5_000, Ordering::SeqCst);
        local.block_on_local(handle).expect("not cancelled")
    });
    assert!(elapsed, "the deadline passed before the inner future ended");
    assert_eq!(
        made, 0,
        "the inner future lies in the timeout, in the task's cell"
    );
}

#[test]
fn a_grown_timer_table_takes_every_sleep_and_reuses_its_entries() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let runtime = CoopRuntime::new(Hand(&NOW));
    let local = CoopLocalSet::new(&runtime);
    let round = |deadline_ms: u64| {
        let handles: std::vec::Vec<_> = (0..5u32)
            .map(|n| sleeper(&runtime, &local, deadline_ms, n))
            .collect();
        local.run_until_idle();
        assert_eq!(
            runtime.timers().pending_count(),
            5,
            "every sleep has an entry"
        );
        NOW.fetch_add(deadline_ms * 1000 + 1, Ordering::SeqCst);
        handles
            .into_iter()
            .map(|handle| local.block_on_local(handle).expect("by its deadline"))
            .sum::<u32>()
    };
    assert_eq!(round(5), 10);
    assert_eq!(runtime.timer_refusals(), 0, "a grown table refuses none");
    assert_eq!(runtime.timers().capacity(), 5);
    assert_eq!(runtime.timers().pending_count(), 0);
    // The same sleeps again find the entries and the cells free: the table does not grow, and
    // nothing but the list of handles this test keeps is allocated.
    let (sum, made) = allocations(|| round(10));
    assert_eq!(sum, 10);
    assert_eq!(runtime.timers().capacity(), 5);
    assert_eq!(
        made, 1,
        "the test's own list of five handles, and nothing of the runtime's"
    );
}

#[test]
fn dropping_the_runtime_drops_its_tasks_and_their_handles_read_cancelled() {
    static DROPS: AtomicU32 = AtomicU32::new(0);
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let guard = Counted(&DROPS);
    let mut handle = local.spawn_local(async move {
        let _guard = guard;
        forever().await;
    });
    local.run_until_idle();
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        0,
        "alive while the runtime is"
    );
    drop(local);
    drop(runtime);
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "the task went with the runtime"
    );
    assert!(handle.is_finished());
    assert!(matches!(
        poll_once(&mut handle),
        Poll::Ready(Err(RuntimeError::JoinCancelled))
    ));
}

/// A task too large for a cell the open did not size for: what an engine spawns while it opens
/// and cannot name beforehand.
#[allow(clippy::manual_async_fn)]
fn large(bytes: [u8; 256]) -> impl Future<Output = u8> {
    async move {
        yield_now().await;
        bytes[0]
    }
}

#[allow(clippy::manual_async_fn)]
fn larger(bytes: [u8; 1024]) -> impl Future<Output = u8> {
    async move {
        yield_now().await;
        bytes[0]
    }
}

#[test]
fn an_opening_runtime_places_what_its_open_spawns_and_nothing_once_sealed() {
    let runtime = CoopRuntime::opening(
        Still,
        RuntimeRows {
            tasks: 1,
            task_bytes: 64,
            timers: 0,
        },
        1,
    );
    let local = CoopLocalSet::new(&runtime);
    let small = local.try_spawn_local(forever()).expect("the reserved cell");
    let first = local
        .try_spawn_local(large([3; 256]))
        .expect("while the open lasts, a cell of its own size");
    assert_eq!(local.block_on_local(first).expect("ran"), 3);
    assert_eq!(runtime.task_refusals(), Refusals::default());
    runtime.seal();
    let (again, made) = allocations(|| {
        let handle = local
            .try_spawn_local(large([4; 256]))
            .expect("the cell added for it while the open lasted");
        local.block_on_local(handle).expect("ran")
    });
    assert_eq!((again, made), (4, 0), "a sealed runtime takes no memory");
    let held = local
        .try_spawn_local(large([5; 256]))
        .expect("the added cell, free again");
    let Err(full) = local.try_spawn_local(forever()) else {
        panic!("both cells are taken and the runtime is sealed");
    };
    assert_eq!(
        full.why,
        SpawnRefusal::NoTaskCell,
        "a task a cell fits waits"
    );
    let Err(too_large) = local.try_spawn_local(larger([6; 1024])) else {
        panic!("no cell fits it and the runtime is sealed");
    };
    assert_eq!(
        too_large.why,
        SpawnRefusal::TooLarge,
        "a task no cell fits never will"
    );
    assert_eq!(
        runtime.task_refusals(),
        Refusals {
            no_task_cell: 1,
            too_large: 1,
            heap_refused: 0,
        }
    );
    small.abort();
    held.abort();
    local.run_until_idle();
}

/// An open adds no more cells than it was told it may: a task that finds every cell taken while
/// the open lasts, the added ones too, is refused and counted as one past a reserved table's rows,
/// and the table holds what it held.
#[test]
fn an_opening_runtime_adds_no_cell_past_the_ones_it_may_add() {
    let runtime = CoopRuntime::opening(
        Still,
        RuntimeRows {
            tasks: 1,
            task_bytes: 64,
            timers: 0,
        },
        1,
    );
    let local = CoopLocalSet::new(&runtime);
    let small = local.try_spawn_local(forever()).expect("the reserved cell");
    let added = local
        .try_spawn_local(large([1; 256]))
        .expect("the one cell the open may add");
    assert_eq!(runtime.inner.executor.capacity(), 2);
    let Err(past) = local.try_spawn_local(large([2; 256])) else {
        panic!("the open added the one cell it may, and both are taken");
    };
    assert_eq!(
        past.why,
        SpawnRefusal::NoTaskCell,
        "a task a cell fits waits"
    );
    assert_eq!(
        runtime.inner.executor.capacity(),
        2,
        "no cell was added past the one"
    );
    assert_eq!(
        runtime.task_refusals(),
        Refusals {
            no_task_cell: 1,
            too_large: 0,
            heap_refused: 0,
        }
    );
    small.abort();
    added.abort();
    local.run_until_idle();
}

/// A clock that does not move and counts its drops into a static of the test: the runtime that
/// holds it is gone when it is.
struct Released(&'static AtomicU32);

impl ClockSource for Released {
    fn now_us(&self) -> u64 {
        0
    }
}

impl Drop for Released {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// The table keeps no task past its local set, whichever way the table was made: a task that holds
/// a handle of the runtime goes with its set, so the runtime, and its clock, go with the last
/// handle outside the table. Were the table to keep the task, the task's handle would keep the
/// runtime, and the runtime the task, for as long as the process.
#[test]
fn a_runtime_whose_task_holds_it_is_let_go_with_the_last_handle_outside_its_table() {
    static RELEASED: AtomicU32 = AtomicU32::new(0);
    const ROWS: RuntimeRows = RuntimeRows {
        tasks: 2,
        task_bytes: 256,
        timers: 1,
    };
    type Make = fn() -> CoopRuntime<Released>;
    let makers: [(&str, Make); 3] = [
        ("grown", || CoopRuntime::new(Released(&RELEASED))),
        ("reserved", || {
            CoopRuntime::reserved(Released(&RELEASED), ROWS)
        }),
        ("opened and sealed", || {
            let runtime = CoopRuntime::opening(Released(&RELEASED), ROWS, 0);
            runtime.seal();
            runtime
        }),
    ];
    for (kind, make) in makers {
        let before = RELEASED.load(Ordering::SeqCst);
        let runtime = make();
        let local = CoopLocalSet::new(&runtime);
        let held = runtime.clone();
        let task = local
            .try_spawn_local(async move {
                let _runtime = held;
                forever().await;
            })
            .expect("a cell");
        local.run_until_idle();
        drop(task);
        drop(runtime);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            before,
            "{kind}: the local set still holds the runtime"
        );
        drop(local);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            before + 1,
            "{kind}: the runtime went with the set its task was on, though the task held it"
        );
    }
}

/// A session's task holds a handle of the runtime, so the runtime's table alone would keep it, and
/// what it reads with, for good: its set's last handle takes it, and another set's tasks stay.
#[test]
fn dropping_a_local_set_drops_its_tasks_while_the_runtime_lives() {
    static DROPS: AtomicU32 = AtomicU32::new(0);
    let runtime = CoopRuntime::new(Still);
    let first = CoopLocalSet::new(&runtime);
    let second = CoopLocalSet::new(&runtime);
    let held = runtime.clone();
    let guard = Counted(&DROPS);
    let mut gone = first.spawn_local(async move {
        let _runtime = held;
        let _guard = guard;
        forever().await;
    });
    let stays = second.spawn_local(forever());
    second.run_until_idle();
    assert_eq!(DROPS.load(Ordering::SeqCst), 0, "alive while its set is");
    drop(first);
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "the set's task went with the set, though it held the runtime"
    );
    assert!(matches!(
        poll_once(&mut gone),
        Poll::Ready(Err(RuntimeError::JoinCancelled))
    ));
    assert!(!stays.is_finished(), "another set's task stays");
    assert_eq!(second.live_local_task_count(), 1);
    stays.abort();
    second.run_until_idle();
    drop(stays);
    assert_eq!(runtime.live_task_count(), 0);
}

#[test]
fn a_waker_kept_past_the_runtime_still_points_at_a_cell() {
    let kept: Rc<RefCell<Option<Waker>>> = Rc::new(RefCell::new(None));
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let stash = Rc::clone(&kept);
    let handle = local.spawn_local(core::future::poll_fn(move |cx| {
        *stash.borrow_mut() = Some(cx.waker().clone());
        Poll::<()>::Pending
    }));
    local.run_until_idle();
    drop(handle);
    drop(local);
    drop(runtime);
    let waker = kept.borrow_mut().take().expect("the task kept its waker");
    // The table is held by the waker's count: waking it raises a flag of a cell that is still
    // there, and the last count frees it.
    let twin = waker.clone();
    assert!(twin.will_wake(&waker));
    twin.wake();
    waker.wake_by_ref();
    drop(waker);
}

/// How many times the memory of a placed runtime's span was given back, in
/// `a_placed_runtime_takes_nothing_of_the_heap_and_keeps_its_memory_to_its_last_holder`.
static SPAN_GIVEN_BACK: AtomicU32 = AtomicU32::new(0);

/// What the last count of that span's memory does: it records that it ran.
unsafe fn span_given_back(_kept: NonNull<Kept>) {
    SPAN_GIVEN_BACK.fetch_add(1, Ordering::SeqCst);
}

/// A runtime placed in a span of counted memory makes its tables, spawns and polls with nothing of
/// the heap, and keeps the memory until its last holder lets go: a waker kept past the runtime and
/// past the memory's own holder keeps it, and the waker's drop gives it back. A span one byte
/// short of the layout places nothing. Turned red by a placed runtime that allocates, by one that
/// gives the memory back while a waker still points into it, or by one that never gives it back.
#[test]
fn a_placed_runtime_takes_nothing_of_the_heap_and_keeps_its_memory_to_its_last_holder() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let rows = RuntimeRows {
        tasks: 2,
        task_bytes: 256,
        timers: 1,
    };
    let form = RuntimeForm::Reserved;
    let layout = CoopRuntime::<Hand>::placed_layout(rows, form).expect("a span of these rows");
    // SAFETY: the layout is not of zero bytes: it holds the runtime's state.
    let span = NonNull::new(unsafe { std::alloc::alloc(layout) }).expect("the host has the memory");
    let memory = NonNull::from(std::boxed::Box::leak(std::boxed::Box::new(Kept::new(
        span_given_back,
    ))));
    // SAFETY: the span is the layout's bytes, used by nothing else; the memory's count is live.
    let short = unsafe { RuntimePlace::new(span, layout.size() - 1, memory) };
    assert!(
        CoopRuntime::placed(Hand(&NOW), rows, form, short).is_none(),
        "a span short of the layout places nothing"
    );
    let kept: Rc<RefCell<Option<Waker>>> = Rc::new(RefCell::new(None));
    let stash = Rc::clone(&kept);
    let ((), allocated) = allocations(|| {
        // SAFETY: as above; the span is freed only after its memory's count was given back.
        let place = unsafe { RuntimePlace::new(span, layout.size(), memory) };
        let (runtime, local) =
            CoopRuntime::placed(Hand(&NOW), rows, form, place).expect("the span fits");
        assert_eq!(runtime.timers().capacity(), 1, "the entries are the span's");
        let handle = local.spawn_local(core::future::poll_fn(move |cx| {
            *stash.borrow_mut() = Some(cx.waker().clone());
            Poll::<()>::Pending
        }));
        local.run_until_idle();
        drop(handle);
        drop(local);
        drop(runtime);
    });
    assert_eq!(allocated, 0, "nothing of the heap");
    // SAFETY: the memory's own holder lets go of its count, once.
    unsafe { Kept::release(memory) };
    assert_eq!(
        SPAN_GIVEN_BACK.load(Ordering::SeqCst),
        0,
        "a waker kept past the runtime keeps the memory"
    );
    let waker = kept.borrow_mut().take().expect("the task kept its waker");
    waker.wake_by_ref();
    drop(waker);
    assert_eq!(
        SPAN_GIVEN_BACK.load(Ordering::SeqCst),
        1,
        "the last holder gives the memory back"
    );
    // SAFETY: the memory's last count ran; the span and the count are freed once, here.
    unsafe {
        std::alloc::dealloc(span.as_ptr(), layout);
        drop(std::boxed::Box::from_raw(memory.as_ptr()));
    }
}

/// How many times the memory of a placed runtime's span was given back, in
/// `a_runtime_placed_for_an_open_that_adds_cells_is_refused_by_a_full_heap`.
static OPENING_GIVEN_BACK: AtomicU32 = AtomicU32::new(0);

/// What the last count of that span's memory does: it records that it ran.
unsafe fn opening_given_back(_kept: NonNull<Kept>) {
    OPENING_GIVEN_BACK.fetch_add(1, Ordering::SeqCst);
}

/// A runtime placed for an open that adds cells takes the table of the added cells of the heap: a
/// heap that refuses it places no runtime, ends nothing and keeps no count of the span, and the
/// same span with the heap's memory places one. Turned red by added cells whose refusal ends the
/// program, or by a refusal that keeps a count of the span.
#[test]
fn a_runtime_placed_for_an_open_that_adds_cells_is_refused_by_a_full_heap() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let rows = RuntimeRows {
        tasks: 1,
        task_bytes: 256,
        timers: 0,
    };
    let form = RuntimeForm::Opening { added: 1 };
    let layout = CoopRuntime::<Hand>::placed_layout(rows, form).expect("a span of these rows");
    // SAFETY: the layout is not of zero bytes: it holds the runtime's state.
    let span = NonNull::new(unsafe { std::alloc::alloc(layout) }).expect("the host has the memory");
    let memory = NonNull::from(std::boxed::Box::leak(std::boxed::Box::new(Kept::new(
        opening_given_back,
    ))));
    // SAFETY: the span is the layout's bytes, used by nothing else while a count of its memory is
    // held; the memory's count is live until it is given back below.
    let place = || unsafe { RuntimePlace::new(span, layout.size(), memory) };
    let placed_none = refused(|| CoopRuntime::placed(Hand(&NOW), rows, form, place()).is_none());
    assert!(placed_none, "a full heap places no runtime");
    let opened = CoopRuntime::placed(Hand(&NOW), rows, form, place());
    assert!(
        opened.is_some(),
        "CONTROL: with the heap's memory the same span places one"
    );
    drop(opened);
    // SAFETY: the memory's own holder lets go of its count, once.
    unsafe { Kept::release(memory) };
    assert_eq!(
        OPENING_GIVEN_BACK.load(Ordering::SeqCst),
        1,
        "neither the refusal nor the runtime keeps a count of the span"
    );
    // SAFETY: the memory's last count ran; the span and the count are freed once, here.
    unsafe {
        std::alloc::dealloc(span.as_ptr(), layout);
        drop(std::boxed::Box::from_raw(memory.as_ptr()));
    }
}

/// A spawn during an open whose added cell the heap refuses its bytes is refused as the heap's,
/// counted apart from a task too large, and ends nothing; the same spawn with the heap's memory
/// takes the cell. Turned red by a refusal that ends the program, or one named or counted as a
/// task too large.
#[test]
fn a_spawn_whose_cell_bytes_the_heap_refuses_is_refused_as_the_heaps() {
    let rows = RuntimeRows {
        tasks: 0,
        task_bytes: 0,
        timers: 0,
    };
    let runtime = CoopRuntime::opening(Still, rows, 1);
    let local = CoopLocalSet::new(&runtime);
    let spawned = refused(|| {
        local
            .try_spawn_local(async { 1u8 })
            .map(drop)
            .map_err(|refused| refused.why)
    });
    assert_eq!(spawned, Err(SpawnRefusal::HeapRefused));
    assert_eq!(
        runtime.task_refusals(),
        Refusals {
            no_task_cell: 0,
            too_large: 0,
            heap_refused: 1,
        }
    );
    assert!(
        local.try_spawn_local(async { 1u8 }).is_ok(),
        "CONTROL: with the heap's memory the cell takes the task"
    );
}

/// A value the heap refuses its memory is handed back, and the same value with the heap's memory
/// is held. Turned red by a try that ends the program, or drops the value it was refused.
#[test]
fn a_value_the_heap_refuses_is_handed_back() {
    let back = refused(|| crate::kept::Shared::try_boxed(7u32));
    assert!(matches!(back, Err(7)), "the value comes back");
    let held = crate::kept::Shared::try_boxed(7u32);
    assert!(held.is_ok_and(|held| *held == 7), "CONTROL: held");
}

/// A task no handle waits for is over in the pass that polls it: its cell is free when the pass
/// returns, whether its output had something to drop (dropped once, then freed) or nothing (freed
/// in the section that settles it).
#[test]
fn a_pass_frees_the_cells_of_tasks_no_handle_waits_for_and_drops_their_output_once() {
    static DROPS: AtomicU32 = AtomicU32::new(0);
    let runtime = CoopRuntime::reserved(
        Still,
        RuntimeRows {
            tasks: 2,
            task_bytes: 256,
            timers: 0,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    drop(local.spawn_local(async { Counted(&DROPS) }));
    drop(local.spawn_local(async { 7u32 }));
    assert_eq!(runtime.live_task_count(), 2);
    local.run_until_idle();
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "the output no handle reads is dropped, once"
    );
    assert_eq!(runtime.live_task_count(), 0, "both cells are free");
}

/// The cell of a task that ended with no handle is free before the pass polls the next cell: a
/// task there that spawns finds it, on a table with no other.
#[test]
fn a_cell_the_pass_freed_is_free_for_a_task_the_next_cell_spawns() {
    static DROPS: AtomicU32 = AtomicU32::new(0);
    let runtime = CoopRuntime::reserved(
        Still,
        RuntimeRows {
            tasks: 2,
            task_bytes: 256,
            timers: 0,
        },
    );
    let local = CoopLocalSet::new(&runtime);
    drop(local.spawn_local(async { Counted(&DROPS) }));
    let inner = local.clone();
    let spawner = local.spawn_local(async move { inner.try_spawn_local(async { 5u8 }).is_ok() });
    local.run_until_idle();
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert!(
        local.block_on_local(spawner).expect("not cancelled"),
        "the first task's cell was free when the second task spawned"
    );
    assert_eq!(runtime.task_refusals(), Refusals::default());
}

/// A task waiting on the handle of the task in the cell before it is woken by the section that
/// settles that task, after the section looked at its own cell: it is looked at again and polled
/// in the same pass, and reads the output.
#[test]
fn a_task_waiting_on_the_cell_before_it_reads_the_output_in_the_same_pass() {
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let go = Rc::new(Cell::new(false));
    let parked: Rc<RefCell<Option<Waker>>> = Rc::new(RefCell::new(None));
    let (gate, stash) = (Rc::clone(&go), Rc::clone(&parked));
    let first = local.spawn_local(core::future::poll_fn(move |cx| {
        if gate.get() {
            Poll::Ready(20u32)
        } else {
            *stash.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }));
    let waiter = local.spawn_local(async move { first.await.expect("not cancelled") + 1 });
    local.run_until_idle();
    assert!(!waiter.is_finished(), "the first task waits for its gate");
    go.set(true);
    parked
        .borrow_mut()
        .take()
        .expect("the first task parked its waker")
        .wake();
    local.run_until_idle();
    assert!(
        waiter.is_finished(),
        "the waiter was polled in the pass that ended the task it waits on"
    );
    assert_eq!(local.block_on_local(waiter).expect("not cancelled"), 21);
}

/// A handle let go after its task ended frees the cell: at once for an output with nothing to
/// drop, after dropping it once for one that has.
#[test]
fn a_handle_let_go_after_its_task_ended_frees_the_cell() {
    static DROPS: AtomicU32 = AtomicU32::new(0);
    let runtime = CoopRuntime::new(Still);
    let local = CoopLocalSet::new(&runtime);
    let plain = local.spawn_local(async { 3u32 });
    let owning = local.spawn_local(async { Counted(&DROPS) });
    local.run_until_idle();
    assert!(plain.is_finished() && owning.is_finished());
    assert_eq!(
        runtime.live_task_count(),
        2,
        "each result waits for its handle"
    );
    drop(plain);
    assert_eq!(runtime.live_task_count(), 1);
    drop(owning);
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.live_task_count(), 0);
}

/// A waker that writes its number into a shared list when it is woken.
struct Recorder {
    id: u32,
    woken: std::sync::Arc<std::sync::Mutex<std::vec::Vec<u32>>>,
}

impl std::task::Wake for Recorder {
    fn wake(self: std::sync::Arc<Self>) {
        self.woken.lock().expect("not poisoned").push(self.id);
    }
}

/// More entries due than one section takes: every one is woken, earliest first and ties in the
/// order they were registered, and an entry not yet due stays.
#[test]
fn every_due_timer_is_woken_earliest_first_past_one_batch() {
    let runtime = CoopRuntime::new(Still);
    let woken = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let entries = [
        (1u32, 50u64),
        (2, 10),
        (3, 30),
        (4, 10),
        (5, 20),
        (6, 40),
        (7, 500),
    ];
    for (id, deadline_us) in entries {
        let waker = Waker::from(std::sync::Arc::new(Recorder {
            id,
            woken: std::sync::Arc::clone(&woken),
        }));
        assert!(runtime.timers().register(deadline_us, waker));
    }
    runtime.timers().pop_expired(100);
    assert_eq!(
        *woken.lock().expect("not poisoned"),
        [2u32, 4, 5, 3, 6, 1],
        "every due entry, earliest first, ties in registration order"
    );
    assert_eq!(
        runtime.timers().pending_count(),
        1,
        "the entry not yet due stays"
    );
}

/// A waker that writes, when it is woken, how many entries its queue still holds.
struct Counter {
    queue: std::sync::Arc<crate::timer::TimerQueue>,
    seen: std::sync::Arc<std::sync::Mutex<std::vec::Vec<usize>>>,
}

impl std::task::Wake for Counter {
    fn wake(self: std::sync::Arc<Self>) {
        let left = self.queue.pending_count();
        self.seen.lock().expect("not poisoned").push(left);
    }
}

/// The due entries leave the table four to a section, and are woken after it: each waker of the
/// first four finds the other two due entries still in the table, and each of the last two finds
/// only the one not yet due. Turned red by a pass that takes one entry a section (each waker would
/// find one fewer than the last) or every due entry in one.
#[test]
fn due_timers_leave_the_table_four_to_a_section() {
    let queue = std::sync::Arc::new(crate::timer::TimerQueue::growing());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    for deadline_us in [10u64, 20, 30, 40, 50, 60, 500] {
        let waker = Waker::from(std::sync::Arc::new(Counter {
            queue: std::sync::Arc::clone(&queue),
            seen: std::sync::Arc::clone(&seen),
        }));
        assert!(queue.register(deadline_us, waker));
    }
    queue.pop_expired(100);
    assert_eq!(
        *seen.lock().expect("not poisoned"),
        [3usize, 3, 3, 3, 1, 1],
        "four taken in the first section, the other two in the next"
    );
    // The entry not yet due holds the queue in its waker: woken, it lets the queue go.
    queue.pop_expired(u64::MAX);
    assert_eq!(queue.pending_count(), 0);
}
