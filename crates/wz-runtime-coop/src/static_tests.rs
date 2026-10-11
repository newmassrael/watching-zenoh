// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use core::task::{Context, Poll, Waker};

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

/// Poll `handle` once with a waker that does nothing.
fn poll_once<F: Future + Unpin>(handle: &mut F) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
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
