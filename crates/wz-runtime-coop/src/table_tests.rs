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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::alloc::{GlobalAlloc, Layout, System};
use std::rc::Rc;

use wz_runtime_core::{Runtime, RuntimeError, TimeSource};

use crate::executor::{yield_now, Refusals, SpawnRefusal};
use crate::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeRows};

/// The allocator of this test binary: the system's, counting on a thread that asked it to.
struct Counting;

std::thread_local! {
    /// The allocations this thread made since it began counting, while it counts.
    static COUNTED: Cell<Option<usize>> = const { Cell::new(None) };
}

fn note() {
    let _ = COUNTED.try_with(|counted| {
        if let Some(n) = counted.get() {
            counted.set(Some(n + 1));
        }
    });
}

// SAFETY: every call is the system allocator's, with the arguments it was given.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
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
fn allocations<R>(f: impl FnOnce() -> R) -> (R, usize) {
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
            let _ = runtime.spawn(async move { round });
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
