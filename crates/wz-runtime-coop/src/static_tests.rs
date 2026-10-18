// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The static task pool, timer table and runtime cell (`session-slot`, fixed-memory
//! step S6), against the contract the heap forms had and the one they could not:
//! a full table is a COUNTED refusal, a finished task's cell is reused, and what a
//! task held is dropped exactly once on every way out.
//!
//! Each test declares its own `static` runtime cell, since a cell starts one
//! runtime. Counting allocations is the lwIP crate's witness
//! (`session_pump_allocations`); what is read here is the table's own accounting.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use wz_runtime_core::{Runtime, RuntimeError, TimeSource};

use crate::executor::{yield_now, SpawnRefusal};
use crate::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};

/// A clock a test moves by hand. One per test, so it is a static of the test.
struct Hand(&'static AtomicU64);
impl ClockSource for Hand {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A value that counts its own drops into a static of the test.
struct Counted(&'static AtomicU32);
impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A waker that does nothing (`Waker::noop` is newer than this crate's MSRV).
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
fn a_runtime_cell_starts_one_runtime() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    assert!(CELL.start(Hand(&NOW)).is_some());
    assert!(
        CELL.start(Hand(&NOW)).is_none(),
        "a second start would share the tables"
    );
}

#[test]
fn the_runtime_may_cross_threads_as_the_trait_demands() {
    fn send_sync<T: Send + Sync>() {}
    fn sync<T: Sync>() {}
    send_sync::<CoopRuntime<Hand>>();
    send_sync::<crate::CoopJoinHandle<u32>>();
    // A static of the image, which only has to be shared.
    sync::<RuntimeCell<Hand, 2, 64, 2>>();
}

#[test]
fn a_spawned_task_is_polled_to_its_output_and_its_cell_is_reused() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    for round in 0..3u32 {
        let handle = local
            .spawn_local(async move { round + 40 })
            .expect("the one cell is free again");
        assert_eq!(local.live_local_task_count(), 1);
        assert_eq!(
            local.block_on_local(handle).expect("not cancelled"),
            round + 40
        );
        assert_eq!(local.live_local_task_count(), 0, "the cell is free again");
    }
    assert_eq!(runtime.task_refusals().no_task_cell, 0);
}

#[test]
fn a_full_task_table_refuses_counts_and_hands_the_future_back() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static DROPS: AtomicU32 = AtomicU32::new(0);
    static CELL: RuntimeCell<Hand, 2, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let first = local.spawn_local(forever()).expect("a cell");
    let second = local.spawn_local(forever()).expect("a cell");

    let guard = Counted(&DROPS);
    let Err(refused) = local.spawn_local(async move {
        let _guard = guard;
    }) else {
        panic!("both cells are taken");
    };
    assert_eq!(refused.why, SpawnRefusal::NoTaskCell);
    assert_eq!(
        runtime.task_refusals().no_task_cell,
        1,
        "the refusal is counted"
    );
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        0,
        "the future came back unspent"
    );
    drop(refused);
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "and is the caller's to drop"
    );

    // A cell comes back when its task is aborted, swept and its handle is gone.
    first.abort();
    local.run_until_idle();
    drop(first);
    let third = local.spawn_local(async { 3u8 }).expect("the freed cell");
    assert_eq!(local.block_on_local(third).expect("ran"), 3);
    drop(second);
}

/// Exhaustion of the task table, case R6 of the pool design: a table of `TASKS`
/// cells takes exactly `TASKS` tasks, and every spawn past that is a refusal that is
/// counted, hands the future back and takes no cell, however many are tried.
#[test]
fn a_task_table_fills_to_its_capacity_and_every_spawn_past_it_is_refused_and_counted() {
    const TASKS: usize = 4;
    static NOW: AtomicU64 = AtomicU64::new(0);
    static DROPS: AtomicU32 = AtomicU32::new(0);
    static CELL: RuntimeCell<Hand, TASKS, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);

    // Fill to N: every one of the N cells is a task, and nothing is refused yet.
    let mut held = [const { None }; TASKS];
    for (taken, slot) in held.iter_mut().enumerate() {
        assert_eq!(local.live_local_task_count(), taken);
        *slot = Some(local.spawn_local(forever()).expect("a free cell"));
    }
    assert_eq!(local.live_local_task_count(), TASKS, "every cell is a task");
    assert_eq!(runtime.task_refusals().no_task_cell, 0);

    // N+1, N+2, N+3: each is refused, counted once, and gives its future back
    // unspent; none takes a cell.
    for attempt in 1..=3u32 {
        let Err(refused) = local.spawn_local({
            let guard = Counted(&DROPS);
            async move {
                let _guard = guard;
            }
        }) else {
            panic!("all {TASKS} cells are taken");
        };
        assert_eq!(refused.why, SpawnRefusal::NoTaskCell);
        assert_eq!(runtime.task_refusals().no_task_cell, attempt);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            attempt - 1,
            "the refused future was not run or dropped by the table"
        );
        drop(refused);
        assert_eq!(DROPS.load(Ordering::SeqCst), attempt);
        assert_eq!(
            local.live_local_task_count(),
            TASKS,
            "a refusal takes no cell"
        );
    }
    assert_eq!(runtime.task_refusals().too_large, 0);

    // Each cell given back lets exactly one more task in, and the refusals so far
    // stay counted.
    for slot in &mut held {
        let handle = slot.take().expect("held");
        handle.abort();
        local.run_until_idle();
        drop(handle);
        let again = local.spawn_local(async { 1u8 }).expect("the freed cell");
        assert_eq!(local.block_on_local(again).expect("ran"), 1);
        assert_eq!(runtime.task_refusals().no_task_cell, 3);
    }
}

/// The refusal counters are the table's own accounting, and each refusal is
/// counted under its own cause, only ever upward: a cell coming free does not reset
/// them, a refusal of one cause does not move the other, and a future that is both
/// too large and meets a full table is counted as too large (the cause that does
/// not go away by waiting).
#[test]
fn the_task_refusal_counters_are_split_by_cause_and_only_rise() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let big = [1u8; 512];
    let too_big = |big: [u8; 512]| async move {
        yield_now().await;
        big[0]
    };
    let counts = || {
        let refusals = runtime.task_refusals();
        (refusals.no_task_cell, refusals.too_large)
    };
    assert_eq!(
        counts(),
        (0, 0),
        "nothing is refused before anything is tried"
    );

    assert!(local.spawn_local(too_big(big)).is_err());
    assert_eq!(counts(), (0, 1));

    let taken = local.spawn_local(forever()).expect("the one cell");
    assert!(local.spawn_local(forever()).is_err());
    assert_eq!(counts(), (1, 1), "a full table is the other cause");

    let Err(both) = local.spawn_local(too_big(big)) else {
        panic!("too large and the table is full");
    };
    assert_eq!(both.why, SpawnRefusal::TooLarge);
    assert_eq!(
        counts(),
        (1, 2),
        "the cause that does not wait out is named"
    );
    drop(both);

    taken.abort();
    local.run_until_idle();
    drop(taken);
    let ran = local.spawn_local(async { 5u8 }).expect("the freed cell");
    assert_eq!(local.block_on_local(ran).expect("ran"), 5);
    assert_eq!(counts(), (1, 2), "a cell coming free resets nothing");
}

#[test]
fn a_task_too_large_for_a_cell_is_refused_and_counted() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 2, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let big = [7u8; 512];
    let Err(refused) = local.spawn_local(async move {
        yield_now().await;
        big[3]
    }) else {
        panic!("512 bytes do not fit a 64-byte cell");
    };
    assert_eq!(refused.why, SpawnRefusal::TooLarge);
    assert_eq!(runtime.task_refusals().too_large, 1);
    assert_eq!(runtime.task_refusals().no_task_cell, 0);
    assert_eq!(local.live_local_task_count(), 0, "a refusal takes no cell");
}

#[test]
fn an_output_nobody_reads_is_dropped_once_with_the_handle() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static DROPS: AtomicU32 = AtomicU32::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);

    // The task ends first; the handle goes without reading its output.
    let handle = local
        .spawn_local(async { Counted(&DROPS) })
        .expect("a cell");
    local.run_until_idle();
    assert!(handle.is_finished());
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        0,
        "the output waits in the cell"
    );
    drop(handle);
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "dropped with the handle, once"
    );
    assert_eq!(local.live_local_task_count(), 0);

    // The handle goes first; the task's output is dropped when it ends.
    let handle = local
        .spawn_local(async { Counted(&DROPS) })
        .expect("a cell");
    drop(handle);
    local.run_until_idle();
    assert_eq!(DROPS.load(Ordering::SeqCst), 2);
    assert_eq!(local.live_local_task_count(), 0, "and the cell is free");
}

#[test]
fn an_aborted_task_is_swept_its_state_dropped_and_its_handle_cancelled() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static DROPS: AtomicU32 = AtomicU32::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let guard = Counted(&DROPS);
    let mut handle = local
        .spawn_local(async move {
            let _guard = guard;
            forever().await;
        })
        .expect("a cell");
    local.run_until_idle();
    assert_eq!(DROPS.load(Ordering::SeqCst), 0, "alive while it runs");
    handle.abort();
    assert!(handle.is_finished(), "the handle is answered at once");
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        0,
        "the body goes at the next pass"
    );
    local.run_until_idle();
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        1,
        "swept: what it held is dropped"
    );
    assert!(matches!(
        poll_once(&mut handle),
        Poll::Ready(Err(RuntimeError::JoinCancelled))
    ));
    assert_eq!(local.live_local_task_count(), 0, "the cell is free");
}

#[test]
fn an_abort_after_the_task_ended_keeps_its_result() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let handle = local.spawn_local(async { 17u32 }).expect("a cell");
    local.run_until_idle();
    handle.abort();
    assert_eq!(local.block_on_local(handle).expect("kept"), 17);
}

#[test]
fn a_spawn_through_the_runtime_contract_runs_and_a_refused_one_answers_shutdown() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let mut ran = runtime.spawn(async { 9u32 });
    let mut refused = runtime.spawn(async { 10u32 });
    assert_eq!(runtime.task_refusals().no_task_cell, 1);
    runtime.run_until_idle();
    assert!(matches!(poll_once(&mut ran), Poll::Ready(Ok(9))));
    assert!(matches!(
        poll_once(&mut refused),
        Poll::Ready(Err(RuntimeError::Shutdown))
    ));
}

#[test]
fn a_sleep_registers_in_the_table_and_wakes_at_its_deadline() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 2, 64, 2> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let time = CoopTime::new(&runtime);
    let handle = local
        .spawn_local(async move {
            time.sleep(5).await;
            7u32
        })
        .expect("a cell");
    local.run_until_idle();
    assert_eq!(runtime.timers().pending_count(), 1);
    assert_eq!(runtime.timers().next_deadline_us(), Some(5_000));
    NOW.store(10_000, Ordering::SeqCst);
    assert_eq!(local.block_on_local(handle).expect("woken"), 7);
    assert_eq!(runtime.timers().pending_count(), 0);
    assert_eq!(runtime.timer_refusals(), 0);
}

#[test]
fn a_full_timer_table_refuses_counts_and_the_sleep_still_ends_by_polling() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 3, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let sleeper = |ms: u64, answer: u32| {
        let time = CoopTime::new(&runtime);
        local
            .spawn_local(async move {
                time.sleep(ms).await;
                answer
            })
            .expect("a cell")
    };
    let first = sleeper(5, 1);
    let second = sleeper(5, 2);
    local.run_until_idle();
    assert_eq!(runtime.timers().pending_count(), 1, "one entry, taken");
    assert!(
        runtime.timer_refusals() >= 1,
        "the second sleep was refused an entry and counted"
    );
    NOW.store(10_000, Ordering::SeqCst);
    assert_eq!(local.block_on_local(first).expect("by its deadline"), 1);
    assert_eq!(
        local
            .block_on_local(second)
            .expect("by polling, then by its deadline"),
        2
    );
}

/// Exhaustion of the timer table, case R6: a table of `TIMERS` entries holds
/// `TIMERS` deadlines, a sleep past that is refused an entry and counted (it wakes
/// itself instead, so it still ends), the count rises with every pass the sleep
/// is still without an entry and never falls, and the sleep moves into the table
/// the moment an entry is free: the table is never grown and never lost a sleep.
#[test]
fn a_timer_table_fills_to_its_capacity_and_a_sleep_past_it_takes_an_entry_once_one_is_free() {
    const TIMERS: usize = 3;
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 6, 64, TIMERS> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    assert_eq!(runtime.timers().capacity(), TIMERS);
    let sleeper = |ms: u64, answer: u32| {
        let time = CoopTime::new(&runtime);
        local
            .spawn_local(async move {
                time.sleep(ms).await;
                answer
            })
            .expect("a task cell")
    };

    // Fill to M: the three earliest deadlines are the three entries.
    let first = sleeper(5, 1);
    let second = sleeper(6, 2);
    let third = sleeper(7, 3);
    local.run_until_idle();
    assert_eq!(
        runtime.timers().pending_count(),
        TIMERS,
        "the table is full"
    );
    assert_eq!(runtime.timer_refusals(), 0, "nothing was refused yet");

    // M+1 and M+2 are refused an entry; each is counted every time it tries, which
    // is every pass until an entry is free, and the count never falls.
    let fourth = sleeper(100, 4);
    let fifth = sleeper(100, 5);
    local.run_until_idle();
    let after_first_pass = runtime.timer_refusals();
    assert_eq!(after_first_pass, 2, "two sleeps were each refused once");
    local.run_until_idle();
    let after_second_pass = runtime.timer_refusals();
    assert!(
        after_second_pass > after_first_pass,
        "a sleep still without an entry tries again on the next pass, and is counted"
    );
    assert_eq!(
        runtime.timers().pending_count(),
        TIMERS,
        "a refusal takes no entry and grows nothing"
    );

    // The three registered deadlines pass: their sleeps end, and the two that were
    // waiting by polling take the freed entries on their next pass.
    NOW.store(10_000, Ordering::SeqCst);
    assert_eq!(local.block_on_local(first).expect("woken"), 1);
    assert_eq!(local.block_on_local(second).expect("woken"), 2);
    assert_eq!(local.block_on_local(third).expect("woken"), 3);
    local.run_until_idle();
    assert_eq!(
        runtime.timers().pending_count(),
        2,
        "both waiting sleeps now hold an entry"
    );
    let settled = runtime.timer_refusals();
    assert!(settled >= after_second_pass, "the counter only rises");
    local.run_until_idle();
    assert_eq!(
        runtime.timer_refusals(),
        settled,
        "a sleep with an entry is not refused again"
    );

    NOW.store(200_000, Ordering::SeqCst);
    assert_eq!(local.block_on_local(fourth).expect("woken"), 4);
    assert_eq!(local.block_on_local(fifth).expect("woken"), 5);
    assert_eq!(
        runtime.timers().pending_count(),
        0,
        "every entry is free again"
    );
}

#[test]
fn a_timeout_holds_its_future_inline_and_elapses_at_its_deadline() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 128, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let local = CoopLocalSet::new(&runtime);
    let time = CoopTime::new(&runtime);
    let handle = local
        .spawn_local(async move { time.timeout(2, forever()).await.is_err() })
        .expect("a cell");
    local.run_until_idle();
    NOW.store(5_000, Ordering::SeqCst);
    assert!(local.block_on_local(handle).expect("elapsed"));
}

#[test]
fn the_time_source_still_reads_milliseconds_from_the_cells_clock() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    static CELL: RuntimeCell<Hand, 1, 64, 1> = RuntimeCell::new();
    let runtime = CELL.start(Hand(&NOW)).expect("start");
    let time = CoopTime::new(&runtime);
    assert_eq!(time.now_monotonic_ms(), 0);
    NOW.store(2_500, Ordering::SeqCst);
    assert_eq!(time.now_monotonic_ms(), 2);
}
