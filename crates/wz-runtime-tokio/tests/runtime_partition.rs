// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Subsystem runtime partitioning — the `runtime-tokio` atom's first residual.
//!
//! The registry clause this file measures, verbatim: "no subsystem runtime
//! partitioning. wz has one ambient tokio runtime for everything
//! (runtime_impl.rs:83-114), so a saturated RX path shares workers with TX;
//! zenoh isolates five separate runtimes -- Application, Acceptor, TX, RX, Net
//! -- each with independently tunable worker_threads and max_blocking_threads
//! (commons/zenoh-runtime/src/lib.rs:48-72, 103-127)."
//!
//! [`saturated_rx_starves_tx_on_one_shared_runtime`] is that clause, made
//! executable: it saturates every worker of one shared runtime from the RX
//! side and shows the TX side does not run. It was green before the partition
//! landed and stays green after — it is what the partition exists to avoid,
//! and it is the discriminator against a "partitioned" pool that quietly hands
//! every subsystem the same runtime.

use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wz_runtime_core::Runtime;
use wz_runtime_tokio::runtime_impl::TokioRuntime;
use wz_runtime_tokio::runtime_pool::{
    PartitionedRuntime, RuntimeConfigError, RuntimeParam, RuntimeParams, RuntimePool, WzRuntime,
};

/// BACKSTOP on how long a saturating task may hold its worker. It is not the
/// hold — the test RELEASES its holders (see [`Holders`]) — it is what stops a
/// panicking test from leaving workers occupied and hanging runtime shutdown.
///
/// R311y866 replaced a 2 000 ms hold with this. The old constant was the hold
/// itself, and its comment claimed it was "long enough that the observation
/// window below closes first". Measured, it was not: a holder's clock starts
/// when THAT holder reaches a worker, and `saturate` allows each of them
/// [`REACH_WORKER_MS`] to get there, so the relation that had to hold was
/// `hold > REACH_WORKER_MS + OBSERVE_MS` = 5 750 ms against 2 000 ms. A probe
/// that staggered the second holder by 1 500 ms — well inside the budget the
/// helper itself grants — printed `holder A on a worker at 48µs`, `holder B at
/// 1.500s`, and `at 2.250s the TX task had run = true` where the assertion
/// demands false. Raising the number to 6 000 would have made every run of this
/// file six seconds long and still been a guess about someone else's scheduler.
const HOLD_CEILING_MS: u64 = 30_000;
/// How often a holder checks whether the test has released it. The thread is
/// occupied either way — a sleeping thread is one tokio cannot poll on, which
/// is the whole property these tests need — so this only bounds how long a
/// release takes to be noticed.
const HOLD_POLL_MS: u64 = 5;
/// How long a test waits for the other subsystem to report progress.
const OBSERVE_MS: u64 = 750;
/// Ceiling on how long a saturating task may take to reach a worker. Exceeding
/// it is a failure with a name, not a hang.
const REACH_WORKER_MS: u64 = 5_000;

/// A one-shot "this ran" flag, observed from a thread that is not a worker.
fn progress_flag() -> (Arc<AtomicBool>, Arc<AtomicBool>) {
    let flag = Arc::new(AtomicBool::new(false));
    (Arc::clone(&flag), flag)
}

/// Occupy `count` workers with tasks that block the thread outright — the
/// shape a saturated RX path has, where decode work is CPU-bound and does not
/// yield. Returns once every task has been picked up by a worker, so the
/// saturation is a fact rather than a race.
///
/// The start signal travels over a std channel, not a tokio one: it is sent
/// from inside an async block, where tokio's own blocking senders refuse to
/// run, and received on a thread that holds no worker.
///
/// # One at a time, and why
///
/// This spawned all `count` tasks and only then waited for `count` signals,
/// which made the setup depend on something tokio does not promise: that
/// `count` tasks sitting in the injection queue are DISTRIBUTED across `count`
/// workers rather than stacked. A worker takes a BATCH off that queue, and the
/// first task it runs here blocks its thread outright, so any task batched
/// behind it is stranded on a queue nobody is draining — the wait then expires
/// and the file reads `Timeout` with no clue which holder never arrived.
///
/// Spawning one at a time replaces that assumption with a liveness one: holder
/// `k` is not created until `k-1` are confirmed ON workers, so there is a free
/// worker for it and tokio only has to poll a ready task. It is also the shape
/// [`holders_that_arrive_far_apart_still_hold_together`] has always used by
/// hand — the one saturating test in this file that has never gone red on
/// hosted CI, while this helper's three callers took Layer C1j red on runs
/// 32193989329, 32386238488 and 32418058280.
///
/// ⚠ NOT CLAIMED: that this is the mechanism behind those reds. It was not
/// reproduced locally — ~200 runs across four configurations (2 CPUs, 1 CPU,
/// six competing burners, eight concurrent processes) never once put two
/// holders on one worker. What this change does is remove an assumption that
/// is unguaranteed by contract, and make the remaining failure SAY something:
/// the panic below now names which holder of how many never arrived.
fn saturate(spawn: impl Fn(std::sync::mpsc::Sender<()>), count: usize) {
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    for arrived in 0..count {
        spawn(started_tx.clone());
        if let Err(e) = started_rx.recv_timeout(Duration::from_millis(REACH_WORKER_MS)) {
            panic!(
                "saturating task {} of {count} did not reach a worker within \
                 {REACH_WORKER_MS}ms ({e:?}); {arrived} of {count} had already \
                 arrived. Each task is spawned only after the previous one is \
                 ON a worker, so a free worker existed for this one and tokio \
                 had a ready task to poll",
                arrived + 1,
            );
        }
    }
    drop(started_tx);
}

/// A set of held workers, released when the test says so.
///
/// R311y866. The release is a HANDLE rather than a duration because the thing
/// being measured is "does the other subsystem get a worker WHILE these are
/// held", and a duration cannot express "while": it can only be a guess that
/// outlasts a wait whose own ceiling is five seconds. Holding until told keeps
/// the window a fact.
///
/// [`Self::release`] is called BEFORE the assertion in every test here, so a
/// failing assertion unwinds with the workers already free.
#[derive(Clone)]
struct Holders(Arc<AtomicBool>);

impl Holders {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn release(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Drop for Holders {
    /// The backstop for a test that panics before its own release — every clone
    /// shares the flag, so one drop frees them all.
    fn drop(&mut self) {
        self.release();
    }
}

/// The body of a saturating task: report the worker, then hold it until the
/// test releases it.
///
/// It holds by SLEEPING IN SLICES rather than by yielding: a `std::thread::sleep`
/// inside an async task occupies the worker outright, which is the shape a
/// saturated RX path has, and the slices only bound how quickly a release is
/// noticed. [`HOLD_CEILING_MS`] is the last-resort exit, not the design.
async fn hold_a_worker(started: std::sync::mpsc::Sender<()>, holders: Holders) {
    let _ = started.send(());
    let deadline = std::time::Instant::now() + Duration::from_millis(HOLD_CEILING_MS);
    while !holders.0.load(Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(HOLD_POLL_MS));
    }
}

/// Name of the thread a task ran on, recorded into a shared slot.
async fn record_thread_name(slot: Arc<std::sync::Mutex<Option<String>>>) {
    let name = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string();
    *slot.lock().expect("thread-name slot") = Some(name);
}

// ---------------------------------------------------------------------------
// The clause, executable
// ---------------------------------------------------------------------------

/// R311y866 — holders that reach their workers far apart still hold TOGETHER.
///
/// THE DEFECT THIS PINS, measured on the previous build as a probe that printed
/// rather than asserted. `saturate` grants each holder [`REACH_WORKER_MS`] =
/// 5 000 ms to reach a worker, and each holder's hold began when IT arrived, so
/// the relation the old 2 000 ms constant needed was
/// `hold > REACH_WORKER_MS + OBSERVE_MS` = 5 750 ms. Staggering the second
/// holder by 1 500 ms — well inside the budget the helper itself grants —
/// printed `holder A on a worker at 48µs`, `holder B at 1.500s`, and
/// `at 2.250s the TX task had run = true`, which is the negative assertion in
/// [`saturated_rx_starves_tx_on_one_shared_runtime`] failing. It is what took
/// Layer C1j red on hosted run 32193989329 with nothing in the tree to blame.
///
/// THE STAGGER IS THE TEST. A held-until-released holder makes this case
/// uninteresting by construction, which is exactly the claim: the window is a
/// fact about the test's control flow and not about how evenly a loaded runner
/// happened to schedule two spawns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn holders_that_arrive_far_apart_still_hold_together() {
    let rt = TokioRuntime;
    let holders = Holders::new();
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();

    rt.spawn(hold_a_worker(started_tx.clone(), holders.clone()));
    started_rx
        .recv_timeout(Duration::from_millis(REACH_WORKER_MS))
        .expect("the first holder reaches a worker");

    // Longer than the old hold's remaining life would have been, so a build
    // with a duration-based hold fails here rather than sometimes.
    std::thread::sleep(Duration::from_millis(1_500));
    rt.spawn(hold_a_worker(started_tx, holders.clone()));
    started_rx
        .recv_timeout(Duration::from_millis(REACH_WORKER_MS))
        .expect("the second holder reaches a worker");

    let (tx_ran, observer) = progress_flag();
    rt.spawn(async move {
        tx_ran.store(true, Ordering::SeqCst);
    });
    std::thread::sleep(Duration::from_millis(OBSERVE_MS));
    let ran = observer.load(Ordering::SeqCst);
    holders.release();
    assert!(
        !ran,
        "the first holder arrived 1.5s before the second, which is inside the \
         {REACH_WORKER_MS}ms budget `saturate` grants each of them. Both must \
         still be holding when the window closes — a hold that expires on its \
         own clock frees a worker mid-window and this reads TX progress that \
         the runtime was never supposed to allow"
    );
}

/// R311y866 — CONTROL. A released holder DOES free its worker.
///
/// Without this leg the fix above could be "hold forever", which passes every
/// negative assertion in this file and measures nothing. It also pins the
/// release path the other tests depend on for not hanging runtime shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_holder_gives_its_worker_back() {
    let rt = TokioRuntime;
    let holders = Holders::new();
    saturate(
        |started| {
            rt.spawn(hold_a_worker(started, holders.clone()));
        },
        2,
    );

    let (tx_ran, observer) = progress_flag();
    rt.spawn(async move {
        tx_ran.store(true, Ordering::SeqCst);
    });
    holders.release();

    // Generous against HOLD_POLL_MS, and far under HOLD_CEILING_MS — so a pass
    // here means the RELEASE freed the workers, not the backstop.
    std::thread::sleep(Duration::from_millis(OBSERVE_MS));
    assert!(
        observer.load(Ordering::SeqCst),
        "a holder that has been released must let a TX task onto its worker \
         within {OBSERVE_MS}ms; if it does not, the negative legs in this file \
         are passing because nothing ever runs"
    );
}

/// One shared runtime, both workers taken by the RX side, and the TX side gets
/// no worker within its window.
///
/// `block_on` drives this test body on the calling thread, not on a worker, so
/// the two workers are genuinely all there is to compete for, and the window is
/// observed with a plain sleep so no tokio timer is involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_rx_starves_tx_on_one_shared_runtime() {
    let rt = TokioRuntime;
    let holders = Holders::new();
    saturate(
        |started| {
            rt.spawn(hold_a_worker(started, holders.clone()));
        },
        2,
    );

    let (tx_ran, observer) = progress_flag();
    rt.spawn(async move {
        tx_ran.store(true, Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_millis(OBSERVE_MS));
    // READ, then RELEASE, then assert. Reading first is what makes the window
    // the held one; releasing before the assertion is what keeps a failure from
    // unwinding with two workers still occupied.
    let ran = observer.load(Ordering::SeqCst);
    holders.release();
    assert!(
        !ran,
        "sharing one runtime is what the clause says wz does: a TX task must \
         NOT get a worker while the RX side holds every one of them"
    );
}

/// The ambient runtime is what `TokioRuntime` hands every caller, so two
/// callers that mean different subsystems land in the same worker pool and are
/// named by it identically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambient_runtime_names_every_subsystem_alike() {
    let rt = TokioRuntime;
    let mut slots = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let slot = Arc::new(std::sync::Mutex::new(None));
        handles.push(rt.spawn(record_thread_name(Arc::clone(&slot))));
        slots.push(slot);
    }
    for h in handles {
        h.await.expect("spawned task joins");
    }

    let names: Vec<String> = slots
        .iter()
        .map(|s| s.lock().expect("slot").clone().expect("task ran"))
        .collect();
    assert_eq!(
        names[0], names[1],
        "one ambient pool means one thread-name prefix for every subsystem; got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// What the partition changes
// ---------------------------------------------------------------------------

/// The same saturation, against the partition: RX holds every one of its own
/// workers and TX still runs.
///
/// Deliberately a plain `#[test]` with no ambient runtime at all — the
/// partition owns its runtimes, so a synchronous caller reaches it without
/// standing one up first.
#[test]
fn saturated_rx_does_not_starve_tx_when_partitioned() {
    let pool = RuntimePool::new(RuntimeParams::defaults()).expect("defaults are a valid partition");
    let rx_workers = RuntimeParam::defaults_for(WzRuntime::Rx).worker_threads;

    let holders = Holders::new();
    saturate(
        |started| {
            pool.spawn(WzRuntime::Rx, hold_a_worker(started, holders.clone()));
        },
        rx_workers,
    );

    let (tx_ran, observer) = progress_flag();
    pool.spawn(WzRuntime::Tx, async move {
        tx_ran.store(true, Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_millis(OBSERVE_MS));
    // R311y866 — this leg had the MIRROR of the other one's flake and it was
    // the worse kind. A holder whose clock expired mid-window freed an RX worker,
    // and TX running then proved nothing about the partition; the test went
    // GREEN for the wrong reason. Holding until released is what makes "RX is
    // saturated" true for the whole window this reads.
    let ran = observer.load(Ordering::SeqCst);
    holders.release();
    assert!(
        ran,
        "TX has its own runtime, so RX saturating all {rx_workers} of its workers \
         must not delay it"
    );
}

/// Each subsystem runs on threads of its own, named for it.
#[test]
fn each_subsystem_runs_on_threads_named_for_it() {
    let pool = RuntimePool::new(RuntimeParams::defaults()).expect("defaults are a valid partition");

    for rt in WzRuntime::ALL {
        let slot = Arc::new(std::sync::Mutex::new(None));
        let handle = pool.spawn(rt, record_thread_name(Arc::clone(&slot)));
        pool.handle(rt)
            .block_on(handle)
            .expect("spawned task joins");
        let name = slot.lock().expect("slot").clone().expect("task ran");
        let expected = format!("wz-{}-", rt.as_str());
        assert!(
            name.starts_with(&expected),
            "{rt} must run on its own threads: expected a `{expected}` prefix, got `{name}`"
        );
    }
}

/// `PartitionedRuntime` is the `Runtime` trait bound to one subsystem, and it
/// routes there rather than to the ambient runtime — asserted from inside an
/// ambient runtime, which is the case that could hide the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partitioned_runtime_routes_to_its_named_subsystem() {
    let rx = PartitionedRuntime::new(WzRuntime::Rx);
    assert_eq!(rx.subsystem(), WzRuntime::Rx);

    let slot = Arc::new(std::sync::Mutex::new(None));
    rx.spawn(record_thread_name(Arc::clone(&slot)))
        .await
        .expect("spawned task joins");

    let name = slot.lock().expect("slot").clone().expect("task ran");
    assert!(
        name.starts_with("wz-rx-"),
        "a PartitionedRuntime bound to rx must spawn onto rx, not onto the ambient \
         runtime this test is running on; got `{name}`"
    );
}

/// Handover collapses two subsystems onto one runtime — the knob for a host
/// too small to want five.
#[test]
fn handover_puts_two_subsystems_on_one_runtime() {
    let mut params = RuntimeParams::defaults();
    params.get_mut(WzRuntime::Tx).handover = Some(WzRuntime::Rx);
    let pool = RuntimePool::new(params).expect("a single-hop handover is valid");

    assert_eq!(pool.resolve(WzRuntime::Tx), WzRuntime::Rx);

    let slot = Arc::new(std::sync::Mutex::new(None));
    let handle = pool.spawn(WzRuntime::Tx, record_thread_name(Arc::clone(&slot)));
    pool.handle(WzRuntime::Tx)
        .block_on(handle)
        .expect("spawned task joins");

    let name = slot.lock().expect("slot").clone().expect("task ran");
    assert!(
        name.starts_with("wz-rx-"),
        "work handed over to rx must run on rx's threads; got `{name}`"
    );
}

// ---------------------------------------------------------------------------
// Tuning
// ---------------------------------------------------------------------------

/// The defaults are upstream's: two workers for the receive path, one
/// everywhere else, 50 blocking threads throughout.
#[test]
fn defaults_match_upstream_worker_counts() {
    for rt in WzRuntime::ALL {
        let param = RuntimeParam::defaults_for(rt);
        let expected_workers = if rt == WzRuntime::Rx { 2 } else { 1 };
        assert_eq!(
            param.worker_threads, expected_workers,
            "{rt} default worker_threads"
        );
        assert_eq!(param.max_blocking_threads, 50, "{rt} max_blocking_threads");
        assert_eq!(param.handover, None, "{rt} hands over to nobody by default");
    }
}

/// A config changes exactly what it names and leaves the rest at its default.
#[test]
fn config_overrides_only_what_it_names() {
    let params = RuntimeParams::parse(
        "rx:worker_threads=4;tx:max_blocking_threads=8,worker_threads=3;acc:handover=app",
    )
    .expect("a well-formed config is accepted");

    assert_eq!(params.get(WzRuntime::Rx).worker_threads, 4);
    assert_eq!(
        params.get(WzRuntime::Rx).max_blocking_threads,
        50,
        "an unnamed key keeps its default"
    );
    assert_eq!(params.get(WzRuntime::Tx).max_blocking_threads, 8);
    assert_eq!(params.get(WzRuntime::Tx).worker_threads, 3);
    assert_eq!(
        params.get(WzRuntime::Acceptor).handover,
        Some(WzRuntime::Application)
    );
    assert_eq!(
        params.get(WzRuntime::Net),
        &RuntimeParam::defaults_for(WzRuntime::Net),
        "an unnamed runtime keeps every default"
    );
}

/// Every rejected shape is rejected by the token that was wrong, so the
/// operator is told which one — and nothing is degraded to a default.
#[test]
fn malformed_config_is_refused_by_token() {
    assert_eq!(
        RuntimeParams::parse("rx"),
        Err(RuntimeConfigError::MalformedGroup("rx".to_string()))
    );
    assert_eq!(
        RuntimeParams::parse("rx:worker_threads"),
        Err(RuntimeConfigError::MalformedField(
            "worker_threads".to_string()
        ))
    );
    assert_eq!(
        RuntimeParams::parse("decoder:worker_threads=2"),
        Err(RuntimeConfigError::UnknownRuntime("decoder".to_string()))
    );
    assert_eq!(
        RuntimeParams::parse("rx:threads=2"),
        Err(RuntimeConfigError::UnknownKey("threads".to_string()))
    );
    assert_eq!(
        RuntimeParams::parse("rx:worker_threads=0"),
        Err(RuntimeConfigError::NotAThreadCount {
            key: "worker_threads".to_string(),
            value: "0".to_string()
        }),
        "a runtime with no workers runs nothing; it is not a tuning"
    );
    assert_eq!(
        RuntimeParams::parse("rx:worker_threads=many"),
        Err(RuntimeConfigError::NotAThreadCount {
            key: "worker_threads".to_string(),
            value: "many".to_string()
        })
    );
    assert_eq!(
        RuntimeParams::parse("rx:handover=nowhere"),
        Err(RuntimeConfigError::UnknownRuntime("nowhere".to_string()))
    );
}

/// Handover resolves in one hop, matching upstream. A chain is therefore
/// refused rather than silently truncated at the first hop.
#[test]
fn handover_chain_is_refused() {
    assert_eq!(
        RuntimeParams::parse("tx:handover=rx;rx:handover=app"),
        Err(RuntimeConfigError::HandoverChain {
            from: WzRuntime::Tx,
            via: WzRuntime::Rx,
            to: WzRuntime::Application,
        })
    );

    let mut params = RuntimeParams::defaults();
    params.get_mut(WzRuntime::Tx).handover = Some(WzRuntime::Rx);
    params.get_mut(WzRuntime::Rx).handover = Some(WzRuntime::Application);
    assert!(
        RuntimePool::new(params).is_err(),
        "the pool refuses the same chain a config string would have been refused for"
    );
}

/// Whitespace and empty groups are tolerated, so a config can be written
/// across lines in a unit file without becoming a parse error.
#[test]
fn config_tolerates_whitespace_and_empty_groups() {
    let params = RuntimeParams::parse(" rx : worker_threads = 4 ; ; tx : worker_threads = 2 ; ")
        .expect("whitespace is not a syntax error");
    assert_eq!(params.get(WzRuntime::Rx).worker_threads, 4);
    assert_eq!(params.get(WzRuntime::Tx).worker_threads, 2);
}

/// An empty value means "no overrides", not "an error".
#[test]
fn empty_config_is_the_defaults() {
    assert_eq!(
        RuntimeParams::parse("").expect("empty is valid"),
        RuntimeParams::defaults()
    );
}

// ---------------------------------------------------------------------------
// The blocking bridge's guards
// ---------------------------------------------------------------------------

/// The current-thread scheduler has no second worker to make progress while
/// this one blocks, so the bridge names the misuse instead of deadlocking.
/// `#[tokio::test]` without a flavor IS the current-thread scheduler, which is
/// exactly the consumer this guards.
#[tokio::test]
#[should_panic(expected = "current-thread scheduler")]
async fn block_in_place_refuses_the_current_thread_scheduler() {
    WzRuntime::Tx.block_in_place(async {});
}

/// On a multi-thread scheduler the bridge does its job: the value comes back
/// to the synchronous caller, and the future is polled inside the named
/// subsystem's context.
///
/// The context, not the thread, is what is asserted, and the distinction is
/// the whole mechanism: `Handle::block_on` polls the future on the CALLING
/// thread while entering the target runtime, so work the future spawns is what
/// lands on that subsystem's workers. An earlier version of this test asserted
/// the calling thread was renamed and was wrong about the bridge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_in_place_drives_the_future_in_its_subsystem_context() {
    let slot = Arc::new(std::sync::Mutex::new(None));
    let inner = Arc::clone(&slot);

    let answer = WzRuntime::Net.block_in_place(async move {
        tokio::spawn(record_thread_name(inner))
            .await
            .expect("spawned task joins");
        7u32
    });

    assert_eq!(answer, 7, "the bridged future's value reaches the caller");
    let name = slot.lock().expect("slot").clone().expect("task ran");
    assert!(
        name.starts_with("wz-net-"),
        "work spawned from the bridged future belongs to the subsystem it was \
         bridged onto, not to the ambient runtime; got `{name}`"
    );
}
