// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The pico C ABI under load: worker threads put, get and declare while sessions are closed and
//! opened again under them, over a transport the program supplies that blocks, splits, loses and
//! cuts what it is handed. Bounded in time and driven by a seed, and run by Layer S, never by a
//! default `cargo test` (every test is `#[ignore]`d).
//!
//! What a run must show, besides finishing:
//!
//! * no thread stops: a watchdog reads a heartbeat of every thread the test runs and, when one
//!   has made no progress for the stall bound, writes what each was doing, the library's loops
//!   (`liveness::loops_now`) and every thread's kernel state (`liveness::threads_now`) to the
//!   process's stderr and aborts, so a deadlock is a failed run with a report and never a hung
//!   lane;
//! * no lock is taken in two orders: the runtime's lock-order checker is on in this debug build
//!   and stops the thread that closes a cycle; every panic of every thread, the library's own
//!   included, is counted, and the run fails on any;
//! * every closure the library was handed is dropped once: each callback context is counted when
//!   it is made and when its drop runs, and the counts must meet once the sessions are gone (a get
//!   still pending when its session closed included);
//! * nothing grows: this process counts the allocations it holds (its own `#[global_allocator]`,
//!   which is why the file is an executable of its own), and the count after the run is held to
//!   the count before it;
//! * the sessions recover: with the faults off, a put and a get cross between the sessions the
//!   storm left.
//!
//! The seed fixes the mix of operations and of faults, not the interleaving of the threads; a red
//! run prints the seed, and `WZ_STABILITY_SEED` runs the same mix again.
//!
//! Every locator is synthetic: no socket is opened, the transport is the in-memory pipe below.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_pico::app_transport::{
    wz_ext_config_transport, wz_ext_link_event_t, wz_ext_link_kind_t, wz_ext_link_result_t,
    wz_ext_link_t, wz_ext_loaned_transport_t, wz_ext_owned_transport_t, wz_ext_transport_accepted,
    wz_ext_transport_drop, wz_ext_transport_event, wz_ext_transport_loan, wz_ext_transport_move,
    wz_ext_transport_new, wz_ext_transport_received, wz_ext_transport_t, WZ_EXT_LINK_CLOSED,
    WZ_EXT_LINK_DATAGRAM, WZ_EXT_LINK_DATAGRAM_LISTEN, WZ_EXT_LINK_EVENT_CLOSED,
    WZ_EXT_LINK_EVENT_CONNECTED, WZ_EXT_LINK_EVENT_WRITABLE, WZ_EXT_LINK_OK,
    WZ_EXT_LINK_STREAM_DIAL, WZ_EXT_LINK_STREAM_LISTEN, WZ_EXT_LINK_WOULD_BLOCK,
};
use wz_capi_pico::liveliness::{
    z_liveliness_declare_token, z_liveliness_token_move, z_liveliness_undeclare_token,
    z_owned_liveliness_token_t,
};
use wz_capi_pico::result::WZ_EXT_ERR_LINK_FULL;
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_copy_from_str, z_bytes_move, z_bytes_to_slice, z_close,
    z_closure_query, z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable,
    z_declare_subscriber, z_get, z_get_options_default, z_get_options_t, z_loaned_bytes_t,
    z_loaned_query_t, z_loaned_reply_t, z_loaned_sample_t, z_open, z_owned_bytes_t,
    z_owned_config_t, z_owned_queryable_t, z_owned_session_t, z_owned_slice_t,
    z_owned_subscriber_t, z_put, z_query_keyexpr, z_query_reply, z_queryable_move,
    z_queryable_options_default, z_queryable_options_t, z_reply_is_ok, z_reply_ok,
    z_sample_payload, z_session_drop, z_session_loan, z_session_move, z_slice_data, z_slice_drop,
    z_slice_len, z_slice_loan, z_slice_move, z_subscriber_move, z_undeclare_queryable,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

// ---------------------------------------------------------------------------------------------
// The allocations this process holds.

/// Allocations made and not yet freed, by every thread of the process.
static LIVE_ALLOCATIONS: AtomicIsize = AtomicIsize::new(0);
/// The bytes they hold.
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the counters only observe
// what it returned.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The fewest allocations the process held while it settled: the lowest count seen, once no
/// lower one has been seen for `quiet`, or at `longest`. A thread that is ending (a runtime's
/// idle blocking thread is let go after ten seconds) frees what it held as it ends, so a single
/// reading taken at once would count it.
fn settled_allocations(quiet: Duration, longest: Duration) -> isize {
    let start = Instant::now();
    let mut lowest = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
    let mut lowest_at = start;
    while start.elapsed() < longest && lowest_at.elapsed() < quiet {
        std::thread::sleep(Duration::from_millis(50));
        let now = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
        if now < lowest {
            lowest = now;
            lowest_at = Instant::now();
        }
    }
    lowest
}

// ---------------------------------------------------------------------------------------------
// Every panic of every thread.

static PANICS: AtomicUsize = AtomicUsize::new(0);
static PANIC_TEXT: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Count every panic of the process, a library thread's included: the lock-order checker stops
/// the thread that closes a cycle with a panic, and a panic on a runtime's thread fails no test by
/// itself.
fn count_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut text) = PANIC_TEXT.lock() {
                text.push(info.to_string());
            }
            previous(info);
        }));
    });
}

fn panics_so_far() -> (usize, Vec<String>) {
    let text = PANIC_TEXT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (PANICS.load(Ordering::SeqCst), text)
}

// ---------------------------------------------------------------------------------------------
// The run's parameters.

/// The mix a run uses when the lane names none.
const DEFAULT_SEED: u64 = 0x5EED_5EED_5EED;

struct Run {
    seed: u64,
    /// How long the storm of each chaos test lasts at least; past it the storm runs on, up to
    /// `MIX_GRACE`, until it has made every call and injected every fault of its shape.
    seconds: u64,
    workers: usize,
    /// How many sessions the sequential test opens and closes.
    cycles: usize,
    /// Every wait of the test is this many times longer: a run under valgrind is that much slower.
    scale: u32,
    /// How long a thread may go without progress before the watchdog stops the run.
    stall: Duration,
}

/// A number from the environment, `default` when the variable is unset. A value that is not a
/// number stops the run: a mistyped bound would otherwise run some other bound.
fn env_number<T: std::str::FromStr>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(text) => text
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name}={text:?} is not a number")),
        Err(_) => default,
    }
}

impl Run {
    fn from_env() -> Self {
        let scale: u32 = env_number("WZ_STABILITY_TIME_SCALE", 1u32).max(1);
        let stall_seconds: u64 = env_number("WZ_STABILITY_STALL_SECONDS", 30u64);
        Self {
            seed: env_number("WZ_STABILITY_SEED", DEFAULT_SEED),
            seconds: env_number("WZ_STABILITY_SECONDS", 20u64).max(1),
            workers: env_number("WZ_STABILITY_WORKERS", 4usize).clamp(1, 64),
            cycles: env_number("WZ_STABILITY_CYCLES", 40usize).max(4),
            scale,
            stall: Duration::from_secs(stall_seconds.max(1)) * scale,
        }
    }

    fn scaled(&self, wait: Duration) -> Duration {
        wait * self.scale
    }
}

/// SplitMix64: one 64-bit state, a full period, and the same sequence for the same seed on every
/// platform, which is all a fault mix asks of it.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n`, 0 for an empty range.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The watchdog.

/// What a thread of the test was last doing.
#[derive(Clone, Copy, Debug)]
enum Op {
    Idle,
    Put,
    Get,
    Subscriber,
    Queryable,
    Token,
    Close,
    Release,
    Open,
    Cut,
    Wait,
    Join,
    Recover,
    Teardown,
}

impl Op {
    const ALL: [Op; 14] = [
        Op::Idle,
        Op::Put,
        Op::Get,
        Op::Subscriber,
        Op::Queryable,
        Op::Token,
        Op::Close,
        Op::Release,
        Op::Open,
        Op::Cut,
        Op::Wait,
        Op::Join,
        Op::Recover,
        Op::Teardown,
    ];

    fn from_index(index: usize) -> Op {
        Op::ALL.get(index).copied().unwrap_or(Op::Idle)
    }
}

/// One thread's heartbeat: when it last made progress and what it was doing then. A beat is
/// judged only while its thread runs: from its first mark until its thread rests it.
struct Beat {
    name: String,
    start: Instant,
    at_ms: AtomicU64,
    op: AtomicUsize,
    running: AtomicBool,
}

impl Beat {
    fn mark(&self, op: Op) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.at_ms.store(now, Ordering::SeqCst);
        self.op.store(op as usize, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
    }

    /// The thread has ended: no progress is owed any more.
    fn rest(&self) {
        self.mark(Op::Idle);
        self.running.store(false, Ordering::SeqCst);
    }

    fn stalled_for(&self, now_ms: u64, bound_ms: u64) -> bool {
        self.running.load(Ordering::SeqCst)
            && now_ms.saturating_sub(self.at_ms.load(Ordering::SeqCst)) > bound_ms
    }
}

struct Watch {
    start: Instant,
    stall: Duration,
    seed: u64,
    beats: Mutex<Vec<Arc<Beat>>>,
    stop: AtomicBool,
    /// The pipe of the phase under way, whose counters the report includes.
    pipe: Mutex<Option<Arc<Pipe>>>,
}

impl Watch {
    fn new(run: &Run) -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            stall: run.stall,
            seed: run.seed,
            beats: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            pipe: Mutex::new(None),
        })
    }

    fn beat(&self, name: &str) -> Arc<Beat> {
        let beat = Arc::new(Beat {
            name: name.to_owned(),
            start: self.start,
            at_ms: AtomicU64::new(0),
            op: AtomicUsize::new(Op::Idle as usize),
            running: AtomicBool::new(false),
        });
        self.beats.lock().unwrap().push(Arc::clone(&beat));
        beat
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn watch_pipe(&self, pipe: Option<Arc<Pipe>>) {
        *self.pipe.lock().unwrap() = pipe;
    }

    /// Write what every thread was doing to the process's stderr, past the test harness's
    /// capture, and abort: a stopped thread cannot be unwound, and a lane must not hang on it.
    fn report_and_abort(&self, stalled: &Beat, now_ms: u64) -> ! {
        let mut text = String::new();
        let stall_ms = self.stall.as_millis();
        let _ = writeln!(
            text,
            "\nstability watchdog: `{}` made no progress for {} ms (bound {stall_ms} ms); \
             seed {} (WZ_STABILITY_SEED={} runs this mix again)",
            stalled.name,
            now_ms.saturating_sub(stalled.at_ms.load(Ordering::SeqCst)),
            self.seed,
            self.seed,
        );
        if let Ok(beats) = self.beats.try_lock() {
            for beat in beats.iter() {
                let op = Op::from_index(beat.op.load(Ordering::SeqCst));
                let age = now_ms.saturating_sub(beat.at_ms.load(Ordering::SeqCst));
                let state = if beat.running.load(Ordering::SeqCst) {
                    "running"
                } else {
                    "ended"
                };
                let _ = writeln!(
                    text,
                    "  thread {} ({state}): {op:?}, {age} ms ago",
                    beat.name
                );
            }
        }
        if let Ok(pipe) = self.pipe.try_lock() {
            if let Some(pipe) = pipe.as_ref() {
                let _ = writeln!(text, "  pipe: {}", pipe.summary());
            }
        }
        for (name, step, since) in wz_runtime_tokio::liveness::loops_now() {
            let _ = writeln!(text, "  loop {name}: {step}, turned {since:?} ago");
        }
        let _ = writeln!(
            text,
            "  threads: {}",
            wz_runtime_tokio::liveness::threads_now()
        );
        let (panics, panic_text) = panics_so_far();
        let _ = writeln!(text, "  panics so far: {panics}");
        for line in panic_text {
            let _ = writeln!(text, "    {line}");
        }
        let _ = std::io::Write::write_all(&mut std::io::stderr(), text.as_bytes());
        std::process::abort();
    }
}

fn spawn_watchdog(watch: Arc<Watch>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("stability-watchdog".to_owned())
        .spawn(move || {
            let stall_ms = u64::try_from(watch.stall.as_millis()).unwrap_or(u64::MAX);
            while !watch.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                let now = watch.now_ms();
                let stalled = watch
                    .beats
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|beat| beat.stalled_for(now, stall_ms))
                    .cloned();
                if let Some(beat) = stalled {
                    watch.report_and_abort(&beat, now);
                }
            }
        })
        .expect("the watchdog thread starts")
}

/// Sleep for `wait` in short steps, marking `beat` at each: a thread that waits on purpose is not
/// stopped. Returns early once `stop` is set.
fn pause(beat: &Beat, wait: Duration, stop: Option<&AtomicBool>) {
    let until = Instant::now() + wait;
    loop {
        beat.mark(Op::Wait);
        if stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            return;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

fn wait_until(what: &str, beat: &Beat, within: Duration, done: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        pause(beat, Duration::from_millis(10), None);
    }
}

// ---------------------------------------------------------------------------------------------
// The program's transport: an in-memory pipe between two transports.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Side {
    Listening,
    Dialling,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Side::Listening => Side::Dialling,
            Side::Dialling => Side::Listening,
        }
    }
}

/// What the links of a run are, and what goes wrong on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Byte streams (`tcp/` locators): a send may block, take part of what it is offered, or find
    /// its link cut. A stream loses nothing, as a stream does not.
    Stream,
    /// Datagrams (`udp/` locators): a send may block or be lost whole.
    Datagram,
}

/// Faults per million sends.
struct Faults {
    would_block: u64,
    partial: u64,
    cut: u64,
    loss: u64,
}

impl Shape {
    fn locator(self) -> &'static str {
        match self {
            Shape::Stream => "tcp/192.0.2.100:7447",
            Shape::Datagram => "udp/192.0.2.100:7447",
        }
    }

    fn remote(self, n: usize) -> String {
        let port = 40_000 + n % 20_000;
        match self {
            Shape::Stream => format!("tcp/192.0.2.200:{port}"),
            Shape::Datagram => format!("udp/192.0.2.200:{port}"),
        }
    }

    fn faults(self) -> Faults {
        match self {
            Shape::Stream => Faults {
                would_block: 40_000,
                partial: 40_000,
                cut: 1_000,
                loss: 0,
            },
            Shape::Datagram => Faults {
                would_block: 40_000,
                partial: 0,
                cut: 0,
                loss: 20_000,
            },
        }
    }
}

enum Fault {
    None,
    WouldBlock,
    /// Take this many bytes of the send.
    Partial(usize),
    Cut,
    Loss,
}

/// An event the pipe tells a transport later, from its own thread, as a stack tells it.
#[derive(Clone, Copy)]
struct Pending {
    at: Instant,
    side: Side,
    link: u64,
    event: wz_ext_link_event_t,
}

/// The pipe between the two transports, and what it saw.
struct Pipe {
    shape: Shape,
    /// Each side's owned transport, at a stable address, as an address.
    owned: Mutex<HashMap<Side, usize>>,
    /// The listening side's listener link, 0 while it has none.
    listener: AtomicU64,
    /// Each open link and the link at the other end of it.
    peers: Mutex<HashMap<(Side, u64), u64>>,
    /// The address each datagram link sends from.
    sources: Mutex<HashMap<(Side, u64), CString>>,
    /// A link that refused bytes for being full, and the link whose send waits for it to drain.
    waiting: Mutex<HashMap<(Side, u64), (Side, u64)>>,
    faulty: AtomicBool,
    rng: Mutex<Rng>,
    deferred: Mutex<Vec<Pending>>,
    deferred_wake: Condvar,
    deferred_stop: AtomicBool,
    dials: AtomicUsize,
    sends: AtomicUsize,
    blocks: AtomicUsize,
    partials: AtomicUsize,
    cuts: AtomicUsize,
    losses: AtomicUsize,
    fulls: AtomicUsize,
    drains: AtomicUsize,
    closes: AtomicUsize,
    orphans: AtomicUsize,
    drops: AtomicUsize,
}

impl Pipe {
    /// A pipe of `shape`, faults off, and the thread that tells its deferred events.
    fn start(shape: Shape, seed: u64) -> (Arc<Self>, JoinHandle<()>) {
        let pipe = Arc::new(Self {
            shape,
            owned: Mutex::new(HashMap::new()),
            listener: AtomicU64::new(0),
            peers: Mutex::new(HashMap::new()),
            sources: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            faulty: AtomicBool::new(false),
            rng: Mutex::new(Rng::new(seed ^ 0xF4_17)),
            deferred: Mutex::new(Vec::new()),
            deferred_wake: Condvar::new(),
            deferred_stop: AtomicBool::new(false),
            dials: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            blocks: AtomicUsize::new(0),
            partials: AtomicUsize::new(0),
            cuts: AtomicUsize::new(0),
            losses: AtomicUsize::new(0),
            fulls: AtomicUsize::new(0),
            drains: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            orphans: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
        });
        let teller = Arc::clone(&pipe);
        let thread = std::thread::Builder::new()
            .name("stability-pipe".to_owned())
            .spawn(move || teller.tell_deferred())
            .expect("the pipe's thread starts");
        (pipe, thread)
    }

    fn stop(&self, thread: JoinHandle<()>) {
        self.deferred_stop.store(true, Ordering::SeqCst);
        self.deferred_wake.notify_all();
        thread.join().expect("the pipe's thread ends");
    }

    fn tell_deferred(&self) {
        let mut queue = self.deferred.lock().unwrap();
        loop {
            if self.deferred_stop.load(Ordering::SeqCst) {
                return;
            }
            let now = Instant::now();
            let mut due = Vec::new();
            queue.retain(|pending| {
                if pending.at <= now {
                    due.push(*pending);
                    false
                } else {
                    true
                }
            });
            if !due.is_empty() {
                drop(queue);
                for pending in due {
                    // A link closed since is refused by name; the stack's event is then moot.
                    let _ = unsafe {
                        wz_ext_transport_event(self.loan(pending.side), pending.link, pending.event)
                    };
                }
                queue = self.deferred.lock().unwrap();
                continue;
            }
            let wait = queue
                .iter()
                .map(|pending| pending.at.saturating_duration_since(now))
                .min()
                .unwrap_or(Duration::from_millis(50));
            queue = self.deferred_wake.wait_timeout(queue, wait).unwrap().0;
        }
    }

    fn defer(&self, after: Duration, side: Side, link: u64, event: wz_ext_link_event_t) {
        self.deferred.lock().unwrap().push(Pending {
            at: Instant::now() + after,
            side,
            link,
            event,
        });
        self.deferred_wake.notify_all();
    }

    /// The loan of `side`'s transport, or null once the test has dropped it (every call on a null
    /// loan is refused by name).
    fn loan(&self, side: Side) -> *const wz_ext_loaned_transport_t {
        match self.owned.lock().unwrap().get(&side) {
            Some(&raw) => unsafe { wz_ext_transport_loan(raw as *const wz_ext_owned_transport_t) },
            None => std::ptr::null(),
        }
    }

    fn owned(&self, side: Side) -> *mut wz_ext_owned_transport_t {
        let raw = *self
            .owned
            .lock()
            .unwrap()
            .get(&side)
            .expect("both transports are made before any session opens");
        raw as *mut wz_ext_owned_transport_t
    }

    fn peer_of(&self, side: Side, link: u64) -> Option<u64> {
        self.peers.lock().unwrap().get(&(side, link)).copied()
    }

    fn draw(&self, len: usize) -> Fault {
        if !self.faulty.load(Ordering::SeqCst) {
            return Fault::None;
        }
        let faults = self.shape.faults();
        let mut rng = self.rng.lock().unwrap();
        let roll = rng.below(1_000_000);
        let mut edge = faults.would_block;
        if roll < edge {
            return Fault::WouldBlock;
        }
        edge += faults.partial;
        if roll < edge {
            return if len > 1 {
                Fault::Partial(1 + rng.below(len as u64 - 1) as usize)
            } else {
                Fault::None
            };
        }
        edge += faults.cut;
        if roll < edge {
            return Fault::Cut;
        }
        edge += faults.loss;
        if roll < edge {
            return Fault::Loss;
        }
        Fault::None
    }

    /// Forget the pair `link` is in and tell the other end it closed, as a stack whose connection
    /// broke tells it. This end learns it from the call that cut it (its send answered closed, or
    /// its own close).
    fn unpair(&self, side: Side, link: u64) {
        let peer = {
            let mut peers = self.peers.lock().unwrap();
            let peer = peers.remove(&(side, link));
            if let Some(peer) = peer {
                peers.remove(&(side.other(), peer));
            }
            peer
        };
        {
            let mut sources = self.sources.lock().unwrap();
            sources.remove(&(side, link));
            if let Some(peer) = peer {
                sources.remove(&(side.other(), peer));
            }
        }
        {
            let ends = [Some((side, link)), peer.map(|peer| (side.other(), peer))];
            self.waiting.lock().unwrap().retain(|receiving, sending| {
                !ends.contains(&Some(*receiving)) && !ends.contains(&Some(*sending))
            });
        }
        if let Some(peer) = peer {
            let _ = unsafe {
                wz_ext_transport_event(self.loan(side.other()), peer, WZ_EXT_LINK_EVENT_CLOSED)
            };
        }
    }

    /// Cut every pair, telling both ends, as a stack whose interface went down does. Returns the
    /// ends cut, none when no link was up.
    fn cut_all(&self) -> usize {
        let ends: Vec<(Side, u64)> = {
            let mut peers = self.peers.lock().unwrap();
            let ends = peers.keys().copied().collect();
            peers.clear();
            ends
        };
        self.sources.lock().unwrap().clear();
        self.waiting.lock().unwrap().clear();
        let cut = ends.len();
        for (side, link) in ends {
            self.cuts.fetch_add(1, Ordering::SeqCst);
            let _ =
                unsafe { wz_ext_transport_event(self.loan(side), link, WZ_EXT_LINK_EVENT_CLOSED) };
        }
        cut
    }

    fn summary(&self) -> String {
        let n = |counter: &AtomicUsize| counter.load(Ordering::SeqCst);
        format!(
            "{:?}: dials {}, sends {}, would-blocks {}, partial sends {}, cuts {}, losses {}, \
             full refusals {}, drains {}, closes {}, sends on no pair {}, transport drops {}",
            self.shape,
            n(&self.dials),
            n(&self.sends),
            n(&self.blocks),
            n(&self.partials),
            n(&self.cuts),
            n(&self.losses),
            n(&self.fulls),
            n(&self.drains),
            n(&self.closes),
            n(&self.orphans),
            n(&self.drops),
        )
    }
}

struct SideCtx {
    pipe: Arc<Pipe>,
    side: Side,
}

unsafe fn ctx<'a>(context: *mut c_void) -> &'a SideCtx {
    &*(context as *const SideCtx)
}

unsafe extern "C" fn on_open(
    context: *mut c_void,
    link: wz_ext_link_t,
    kind: wz_ext_link_kind_t,
    locator: *const c_char,
) -> wz_ext_link_result_t {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    let locator = CStr::from_ptr(locator).to_str().unwrap_or("");
    if locator != pipe.shape.locator() {
        return WZ_EXT_LINK_CLOSED;
    }
    match (ctx.side, kind, pipe.shape) {
        (Side::Listening, WZ_EXT_LINK_STREAM_LISTEN, Shape::Stream)
        | (Side::Listening, WZ_EXT_LINK_DATAGRAM_LISTEN, Shape::Datagram) => {
            pipe.listener.store(link, Ordering::SeqCst);
            WZ_EXT_LINK_OK
        }
        (Side::Dialling, WZ_EXT_LINK_STREAM_DIAL, Shape::Stream) => {
            if !accept_and_pair(pipe, link) {
                return WZ_EXT_LINK_CLOSED;
            }
            // Reported up from the program's own thread, after open has answered.
            pipe.defer(
                Duration::from_millis(1),
                Side::Dialling,
                link,
                WZ_EXT_LINK_EVENT_CONNECTED,
            );
            WZ_EXT_LINK_WOULD_BLOCK
        }
        // A datagram link is up at once: there is no connection to make.
        (Side::Dialling, WZ_EXT_LINK_DATAGRAM, Shape::Datagram) => {
            if accept_and_pair(pipe, link) {
                WZ_EXT_LINK_OK
            } else {
                WZ_EXT_LINK_CLOSED
            }
        }
        _ => WZ_EXT_LINK_CLOSED,
    }
}

/// The listening program accepts the dialled `link` on its listener, under an address of its own,
/// and the two links are paired before the dial is answered, so neither side sends into nothing.
unsafe fn accept_and_pair(pipe: &Arc<Pipe>, link: u64) -> bool {
    let n = pipe.dials.fetch_add(1, Ordering::SeqCst);
    let remote = CString::new(pipe.shape.remote(n)).unwrap();
    let mut accepted: wz_ext_link_t = 0;
    let listener = pipe.listener.load(Ordering::SeqCst);
    if wz_ext_transport_accepted(
        pipe.loan(Side::Listening),
        listener,
        remote.as_ptr(),
        &mut accepted,
    ) != Z_OK
    {
        return false;
    }
    if pipe.shape == Shape::Datagram {
        let mut sources = pipe.sources.lock().unwrap();
        sources.insert((Side::Dialling, link), remote);
        sources.insert(
            (Side::Listening, accepted),
            CString::new(pipe.shape.locator()).unwrap(),
        );
    }
    let mut peers = pipe.peers.lock().unwrap();
    peers.insert((Side::Dialling, link), accepted);
    peers.insert((Side::Listening, accepted), link);
    true
}

unsafe extern "C" fn on_send(
    context: *mut c_void,
    link: wz_ext_link_t,
    data: *const u8,
    len: usize,
    written: *mut usize,
) -> wz_ext_link_result_t {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    let side = ctx.side;
    pipe.sends.fetch_add(1, Ordering::SeqCst);
    let Some(peer) = pipe.peer_of(side, link) else {
        pipe.orphans.fetch_add(1, Ordering::SeqCst);
        return WZ_EXT_LINK_CLOSED;
    };
    let datagram = pipe.shape == Shape::Datagram;
    let take = match pipe.draw(len) {
        Fault::None => len,
        Fault::WouldBlock => {
            pipe.blocks.fetch_add(1, Ordering::SeqCst);
            let after = Duration::from_millis(1 + pipe.rng.lock().unwrap().below(4));
            pipe.defer(after, side, link, WZ_EXT_LINK_EVENT_WRITABLE);
            return WZ_EXT_LINK_WOULD_BLOCK;
        }
        Fault::Partial(take) => {
            pipe.partials.fetch_add(1, Ordering::SeqCst);
            take
        }
        Fault::Cut => {
            pipe.cuts.fetch_add(1, Ordering::SeqCst);
            pipe.unpair(side, link);
            return WZ_EXT_LINK_CLOSED;
        }
        Fault::Loss => {
            pipe.losses.fetch_add(1, Ordering::SeqCst);
            *written = len;
            return WZ_EXT_LINK_OK;
        }
    };
    let source = if datagram {
        pipe.sources.lock().unwrap().get(&(side, link)).cloned()
    } else {
        None
    };
    // Registered before the bytes are handed over, so a drain that follows a full refusal at
    // once finds the sender waiting.
    pipe.waiting
        .lock()
        .unwrap()
        .insert((side.other(), peer), (side, link));
    let rc = wz_ext_transport_received(
        pipe.loan(side.other()),
        peer,
        data,
        take,
        source
            .as_ref()
            .map_or(std::ptr::null(), |source| source.as_ptr()),
    );
    if rc == WZ_EXT_ERR_LINK_FULL && !datagram {
        // Nothing was taken; the send waits for the other end to be read down.
        pipe.fulls.fetch_add(1, Ordering::SeqCst);
        return WZ_EXT_LINK_WOULD_BLOCK;
    }
    pipe.waiting.lock().unwrap().remove(&(side.other(), peer));
    match rc {
        Z_OK => {
            *written = take;
            WZ_EXT_LINK_OK
        }
        // A full receiver drops a datagram, as a socket's buffer does.
        WZ_EXT_ERR_LINK_FULL => {
            pipe.fulls.fetch_add(1, Ordering::SeqCst);
            pipe.losses.fetch_add(1, Ordering::SeqCst);
            *written = len;
            WZ_EXT_LINK_OK
        }
        // The other end is closing or gone.
        _ => WZ_EXT_LINK_CLOSED,
    }
}

unsafe extern "C" fn on_close(context: *mut c_void, link: wz_ext_link_t) {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    pipe.closes.fetch_add(1, Ordering::SeqCst);
    if ctx.side == Side::Listening {
        let _ = pipe
            .listener
            .compare_exchange(link, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    pipe.unpair(ctx.side, link);
}

unsafe extern "C" fn on_drained(context: *mut c_void, link: wz_ext_link_t) {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    pipe.drains.fetch_add(1, Ordering::SeqCst);
    let waiter = pipe.waiting.lock().unwrap().remove(&(ctx.side, link));
    if let Some((side, sender)) = waiter {
        let _ = wz_ext_transport_event(pipe.loan(side), sender, WZ_EXT_LINK_EVENT_WRITABLE);
    }
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    let ctx = Box::from_raw(context as *mut SideCtx);
    ctx.pipe.drops.fetch_add(1, Ordering::SeqCst);
}

/// A transport of `side` over the pipe, owned at a stable address.
fn make_transport(pipe: &Arc<Pipe>, side: Side) {
    let context = Box::into_raw(Box::new(SideCtx {
        pipe: Arc::clone(pipe),
        side,
    })) as *mut c_void;
    let calls = wz_ext_transport_t {
        context,
        open: Some(on_open),
        send: Some(on_send),
        close: Some(on_close),
        drained: Some(on_drained),
        drop: Some(on_drop),
    };
    let owned: *mut wz_ext_owned_transport_t =
        Box::into_raw(Box::new(unsafe { std::mem::zeroed() }));
    assert_eq!(unsafe { wz_ext_transport_new(owned, &calls) }, Z_OK);
    pipe.owned.lock().unwrap().insert(side, owned as usize);
}

/// Release the program's reference to `side`'s transport and free its slot. The pipe forgets it
/// first, so a late event of the pipe's finds no transport rather than a freed slot.
fn drop_transport(pipe: &Pipe, side: Side) {
    let raw = pipe
        .owned
        .lock()
        .unwrap()
        .remove(&side)
        .expect("the transport was made");
    let owned = raw as *mut wz_ext_owned_transport_t;
    unsafe {
        wz_ext_transport_drop(wz_ext_transport_move(owned));
        drop(Box::from_raw(owned));
    }
}

// ---------------------------------------------------------------------------------------------
// Callback contexts, each counted when made and when dropped.

#[derive(Default)]
struct Tally {
    made: AtomicUsize,
    calls: AtomicUsize,
    dropped: AtomicUsize,
}

#[derive(Default)]
struct Tallies {
    samples: Arc<Tally>,
    queries: Arc<Tally>,
    replies: Arc<Tally>,
}

impl Tallies {
    fn balanced(&self) -> bool {
        [&self.samples, &self.queries, &self.replies]
            .iter()
            .all(|tally| tally.made.load(Ordering::SeqCst) == tally.dropped.load(Ordering::SeqCst))
    }

    fn summary(&self) -> String {
        let one = |tally: &Arc<Tally>| {
            format!(
                "made {}, called {}, dropped {}",
                tally.made.load(Ordering::SeqCst),
                tally.calls.load(Ordering::SeqCst),
                tally.dropped.load(Ordering::SeqCst)
            )
        };
        format!(
            "sample closures {}; query closures {}; reply closures {}",
            one(&self.samples),
            one(&self.queries),
            one(&self.replies)
        )
    }
}

/// A closure context for `tally`, counted as made: the library owns it until it calls the drop.
fn tally_context(tally: &Arc<Tally>) -> *mut c_void {
    tally.made.fetch_add(1, Ordering::SeqCst);
    Arc::into_raw(Arc::clone(tally)) as *mut c_void
}

unsafe extern "C" fn tally_drop(context: *mut c_void) {
    let tally = Arc::from_raw(context as *const Tally);
    tally.dropped.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn tally_sample(_sample: *const z_loaned_sample_t, context: *mut c_void) {
    (*(context as *const Tally))
        .calls
        .fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn tally_reply(_reply: *mut z_loaned_reply_t, context: *mut c_void) {
    (*(context as *const Tally))
        .calls
        .fetch_add(1, Ordering::Relaxed);
}

/// Every queryable of the run answers with this.
const ANSWER: &CStr = c"answer-under-load";

unsafe extern "C" fn answer_query(query: *const z_loaned_query_t, context: *mut c_void) {
    (*(context as *const Tally))
        .calls
        .fetch_add(1, Ordering::Relaxed);
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, ANSWER.as_ptr()) == Z_OK {
        // A reply into a session that is closing is refused; the asker's deadline answers it.
        let _ = z_query_reply(
            query,
            z_query_keyexpr(query),
            z_bytes_move(&mut payload),
            std::ptr::null(),
        );
    }
}

unsafe fn bytes_of(payload: *const z_loaned_bytes_t) -> Vec<u8> {
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if payload.is_null() || z_bytes_to_slice(payload, &mut slice) != Z_OK {
        return Vec::new();
    }
    let loaned = z_slice_loan(&slice);
    let data = z_slice_data(loaned);
    let out = if data.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(data, z_slice_len(loaned)).to_vec()
    };
    z_slice_drop(z_slice_move(&mut slice));
    out
}

/// What the probe subscriber of the listening session was handed.
#[derive(Default)]
struct Heard {
    payloads: Mutex<Vec<Vec<u8>>>,
}

unsafe extern "C" fn heard_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    let heard = &*(context as *const Heard);
    let payload = bytes_of(z_sample_payload(sample));
    heard.payloads.lock().unwrap().push(payload);
}

unsafe extern "C" fn heard_drop(context: *mut c_void) {
    drop(Arc::from_raw(context as *const Heard));
}

#[derive(Default)]
struct Replies {
    payloads: Mutex<Vec<Vec<u8>>>,
    done: AtomicBool,
}

unsafe extern "C" fn replies_reply(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    let replies = &*(context as *const Replies);
    if z_reply_is_ok(reply) {
        let payload = bytes_of(z_sample_payload(z_reply_ok(reply)));
        replies.payloads.lock().unwrap().push(payload);
    }
}

unsafe extern "C" fn replies_drop(context: *mut c_void) {
    let replies = Arc::from_raw(context as *const Replies);
    replies.done.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------------------------
// Sessions and the calls the workers make.

/// The key expressions of the run. Synthetic.
const PROBE_KEY: &CStr = c"stress/probe";
const PROBE_ASK: &CStr = c"stress/ask/probe";
const EVERY_KEY: &CStr = c"stress/**";
const EVERY_ASK: &CStr = c"stress/ask/**";

unsafe fn view(key: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut ke, key.as_ptr()),
        Z_OK,
        "{key:?}"
    );
    ke
}

/// A config with `key` set to the shape's locator, carrying `transport`.
unsafe fn config_over(
    key: u8,
    locator: &str,
    transport: *mut wz_ext_owned_transport_t,
) -> z_owned_config_t {
    let locator = CString::new(locator).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, locator.as_ptr()),
        Z_OK
    );
    assert_eq!(
        wz_ext_config_transport(
            z_config_loan_mut(&mut cfg),
            wz_ext_transport_loan(transport)
        ),
        Z_OK
    );
    cfg
}

/// The listening session's probe: a subscriber that keeps what it hears and a queryable that
/// answers, through which the run shows the sessions it left still carry a put and a get.
struct Probe {
    heard: Arc<Heard>,
    subscriber: z_owned_subscriber_t,
    queryable: z_owned_queryable_t,
}

/// A session of the run and, for the listening one, its probe.
struct Held {
    session: z_owned_session_t,
    probe: Option<Probe>,
}

// SAFETY: the session and the entities are handles of the pico ABI's multi-threaded arm, whose
// calls may be made from any thread; the test frees each only under the slot's write lock, when
// no other thread holds it.
unsafe impl Send for Held {}
// SAFETY: as above; a shared reference reaches only calls the ABI makes safe to share.
unsafe impl Sync for Held {}

/// Where a side's current session lives. A worker holds the read lock for one call; the chaos
/// thread closes the session under the read lock too (a close races the calls, as a program's
/// close of a session its other threads still use does) and frees it under the write lock.
#[derive(Default)]
struct Slot(RwLock<Option<Box<Held>>>);

impl Slot {
    fn with<R>(&self, f: impl FnOnce(&z_owned_session_t) -> R) -> Option<R> {
        let guard = self.0.read().unwrap();
        guard.as_ref().map(|held| f(&held.session))
    }

    fn take(&self) -> Option<Box<Held>> {
        self.0.write().unwrap().take()
    }

    fn put(&self, held: Box<Held>) {
        let previous = self.0.write().unwrap().replace(held);
        assert!(previous.is_none(), "a slot holds one session at a time");
    }

    fn probe_heard(&self) -> Option<Arc<Heard>> {
        let guard = self.0.read().unwrap();
        guard
            .as_ref()
            .and_then(|held| held.probe.as_ref())
            .map(|probe| Arc::clone(&probe.heard))
    }
}

#[derive(Default)]
struct Slots {
    listening: Slot,
    dialling: Slot,
}

impl Slots {
    fn of(&self, side: Side) -> &Slot {
        match side {
            Side::Listening => &self.listening,
            Side::Dialling => &self.dialling,
        }
    }
}

/// Open `side`'s session over the pipe; `None` when the open fails (a dial with no listener, a
/// handshake lost to a fault).
unsafe fn open_side(pipe: &Arc<Pipe>, side: Side, tallies: &Tallies) -> Option<Box<Held>> {
    let key = match side {
        Side::Listening => Z_CONFIG_LISTEN_KEY,
        Side::Dialling => Z_CONFIG_CONNECT_KEY,
    };
    let mut cfg = config_over(key, pipe.shape.locator(), pipe.owned(side));
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) != Z_OK {
        return None;
    }
    let probe = (side == Side::Listening).then(|| declare_probe(&session, tallies));
    Some(Box::new(Held { session, probe }))
}

unsafe fn declare_probe(session: &z_owned_session_t, tallies: &Tallies) -> Probe {
    let heard = Arc::new(Heard::default());
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(heard_sample),
            Some(heard_drop),
            Arc::into_raw(Arc::clone(&heard)) as *mut c_void,
        ),
        Z_OK
    );
    let ke = view(PROBE_KEY);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut closure,
            Some(answer_query),
            Some(tally_drop),
            tally_context(&tallies.queries),
        ),
        Z_OK
    );
    let ke = view(PROBE_ASK);
    let mut opts: z_queryable_options_t = std::mem::zeroed();
    z_queryable_options_default(&mut opts);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut queryable,
            z_view_keyexpr_loan(&ke),
            z_closure_query_move(&mut closure),
            &opts,
        ),
        Z_OK
    );
    Probe {
        heard,
        subscriber,
        queryable,
    }
}

/// Close a session (again, if it was), undeclare its probe and free it.
unsafe fn release(held: Held) {
    let Held { mut session, probe } = held;
    if let Some(mut probe) = probe {
        z_undeclare_subscriber(z_subscriber_move(&mut probe.subscriber));
        z_undeclare_queryable(z_queryable_move(&mut probe.queryable));
    }
    let _ = z_close(z_session_loan(&session).cast_mut(), std::ptr::null());
    z_session_drop(z_session_move(&mut session));
}

/// Open `side` until it opens, within `within`.
unsafe fn open_until(
    pipe: &Arc<Pipe>,
    side: Side,
    tallies: &Tallies,
    beat: &Beat,
    within: Duration,
) -> Box<Held> {
    let deadline = Instant::now() + within;
    loop {
        beat.mark(Op::Open);
        if let Some(held) = open_side(pipe, side, tallies) {
            return held;
        }
        assert!(
            Instant::now() < deadline,
            "the {side:?} session did not open within {within:?}: {}",
            pipe.summary()
        );
        pause(beat, Duration::from_millis(100), None);
    }
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &[u8]) -> ZResult {
    let ke = view(key);
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
        Z_OK
    );
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        z_bytes_move(&mut bytes),
        std::ptr::null(),
    )
}

/// A get whose replies are counted and not waited for: its closure's drop is the library's word
/// that it is over, which the tally checks once the sessions are gone.
unsafe fn get(
    session: &z_owned_session_t,
    key: &CStr,
    tallies: &Tallies,
    timeout: Duration,
) -> ZResult {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(
            &mut closure,
            Some(tally_reply),
            Some(tally_drop),
            tally_context(&tallies.replies),
        ),
        Z_OK
    );
    let ke = view(key);
    let mut opts: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut opts);
    opts.timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    z_get(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        std::ptr::null(),
        z_closure_reply_move(&mut closure),
        &mut opts,
    )
}

unsafe fn subscriber_for(
    session: &z_owned_session_t,
    key: &CStr,
    tallies: &Tallies,
    hold: Duration,
) -> ZResult {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(tally_sample),
            Some(tally_drop),
            tally_context(&tallies.samples),
        ),
        Z_OK
    );
    let ke = view(key);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    let rc = z_declare_subscriber(
        z_session_loan(session),
        &mut subscriber,
        z_view_keyexpr_loan(&ke),
        z_closure_sample_move(&mut closure),
        std::ptr::null(),
    );
    std::thread::sleep(hold);
    z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
    rc
}

unsafe fn queryable_for(
    session: &z_owned_session_t,
    key: &CStr,
    tallies: &Tallies,
    hold: Duration,
) -> ZResult {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut closure,
            Some(answer_query),
            Some(tally_drop),
            tally_context(&tallies.queries),
        ),
        Z_OK
    );
    let ke = view(key);
    let mut opts: z_queryable_options_t = std::mem::zeroed();
    z_queryable_options_default(&mut opts);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    let rc = z_declare_queryable(
        z_session_loan(session),
        &mut queryable,
        z_view_keyexpr_loan(&ke),
        z_closure_query_move(&mut closure),
        &opts,
    );
    std::thread::sleep(hold);
    z_undeclare_queryable(z_queryable_move(&mut queryable));
    rc
}

unsafe fn token_for(session: &z_owned_session_t, key: &CStr, hold: Duration) -> ZResult {
    let ke = view(key);
    let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
    let rc = z_liveliness_declare_token(
        z_session_loan(session),
        &mut token,
        z_view_keyexpr_loan(&ke),
        std::ptr::null(),
    );
    std::thread::sleep(hold);
    let _ = z_liveliness_undeclare_token(z_liveliness_token_move(&mut token));
    rc
}

/// Put `probe` from `session` until the listening session's probe subscriber has heard it.
unsafe fn converge(
    session: &z_owned_session_t,
    heard: &Heard,
    probe: &str,
    beat: &Beat,
    within: Duration,
) {
    let deadline = Instant::now() + within;
    loop {
        beat.mark(Op::Recover);
        let _ = put(session, PROBE_KEY, probe.as_bytes());
        pause(beat, Duration::from_millis(20), None);
        if heard
            .payloads
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == probe.as_bytes())
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the probe {probe:?} never arrived within {within:?}"
        );
    }
}

/// Ask the listening session's probe queryable from `session` until a reply comes.
unsafe fn ask(session: &z_owned_session_t, beat: &Beat, within: Duration) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + within;
    loop {
        beat.mark(Op::Recover);
        let replies = Arc::new(Replies::default());
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(replies_reply),
                Some(replies_drop),
                Arc::into_raw(Arc::clone(&replies)) as *mut c_void,
            ),
            Z_OK
        );
        let ke = view(PROBE_ASK);
        let mut opts: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut opts);
        opts.timeout_ms = 1000;
        let rc = z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut opts,
        );
        assert_eq!(rc, Z_OK, "a get on an open session is taken");
        wait_until("the probe get to complete", beat, within, || {
            replies.done.load(Ordering::SeqCst)
        });
        let got = replies.payloads.lock().unwrap().clone();
        if !got.is_empty() {
            return got;
        }
        assert!(
            Instant::now() < deadline,
            "no get was answered within {within:?}"
        );
        pause(beat, Duration::from_millis(100), None);
    }
}

// ---------------------------------------------------------------------------------------------
// One quiet pair: open, carry a put and a get, declare and undeclare, close.

/// A listening and a dialling session over a pipe without faults, a put and a get between them,
/// a subscriber, a queryable and a token declared and undeclared on the dialler, and everything
/// closed and dropped. Every closure the library was handed is dropped by the end, and both
/// transports' drops have run.
fn quiet_pair(shape: Shape, run: &Run, watch: &Watch, beat: &Beat) {
    let (pipe, teller) = Pipe::start(shape, run.seed);
    watch.watch_pipe(Some(Arc::clone(&pipe)));
    let tallies = Tallies::default();
    make_transport(&pipe, Side::Listening);
    make_transport(&pipe, Side::Dialling);
    unsafe {
        let listener = open_until(
            &pipe,
            Side::Listening,
            &tallies,
            beat,
            run.scaled(Duration::from_secs(10)),
        );
        let dialler = open_until(
            &pipe,
            Side::Dialling,
            &tallies,
            beat,
            run.scaled(Duration::from_secs(10)),
        );
        let heard = Arc::clone(
            &listener
                .probe
                .as_ref()
                .expect("the listener has a probe")
                .heard,
        );
        converge(
            &dialler.session,
            &heard,
            "quiet",
            beat,
            run.scaled(Duration::from_secs(15)),
        );
        let answers = ask(&dialler.session, beat, run.scaled(Duration::from_secs(15)));
        assert!(
            answers.iter().all(|answer| answer == ANSWER.to_bytes()),
            "the probe answers with its payload: {answers:?}"
        );
        beat.mark(Op::Subscriber);
        assert_eq!(
            subscriber_for(&dialler.session, EVERY_KEY, &tallies, Duration::ZERO),
            Z_OK
        );
        beat.mark(Op::Queryable);
        assert_eq!(
            queryable_for(
                &dialler.session,
                c"stress/ask/quiet",
                &tallies,
                Duration::ZERO
            ),
            Z_OK
        );
        beat.mark(Op::Token);
        assert_eq!(
            token_for(&dialler.session, c"stress/alive/quiet", Duration::ZERO),
            Z_OK
        );
        beat.mark(Op::Teardown);
        release(*dialler);
        release(*listener);
    }
    beat.mark(Op::Teardown);
    pipe.stop(teller);
    drop_transport(&pipe, Side::Dialling);
    drop_transport(&pipe, Side::Listening);
    wait_until(
        "both transports to drop",
        beat,
        run.scaled(Duration::from_secs(10)),
        || pipe.drops.load(Ordering::SeqCst) == 2,
    );
    wait_until(
        "every closure of the pair to be dropped",
        beat,
        run.scaled(Duration::from_secs(10)),
        || tallies.balanced(),
    );
    watch.watch_pipe(None);
}

// ---------------------------------------------------------------------------------------------
// The storm.

#[derive(Default)]
struct OpCounts {
    calls: [AtomicUsize; 5],
    refused: [AtomicUsize; 5],
    /// Sessions opened by the chaos thread, per side (listening, dialling), and opens that failed.
    opened: [AtomicUsize; 2],
    open_failures: AtomicUsize,
}

const OP_NAMES: [&str; 5] = ["put", "get", "subscriber", "queryable", "token"];

impl OpCounts {
    fn count(&self, op: usize, rc: ZResult) {
        self.calls[op].fetch_add(1, Ordering::Relaxed);
        if rc != Z_OK {
            self.refused[op].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn calls(&self, op: usize) -> usize {
        self.calls[op].load(Ordering::SeqCst)
    }

    fn summary(&self) -> String {
        let mut text = String::new();
        for (op, name) in OP_NAMES.iter().enumerate() {
            let _ = write!(
                text,
                "{name} {} ({} refused), ",
                self.calls[op].load(Ordering::SeqCst),
                self.refused[op].load(Ordering::SeqCst)
            );
        }
        let _ = write!(
            text,
            "listening sessions opened {}, dialling sessions opened {}, failed opens {}",
            self.opened[0].load(Ordering::SeqCst),
            self.opened[1].load(Ordering::SeqCst),
            self.open_failures.load(Ordering::SeqCst)
        );
        text
    }
}

struct Storm {
    pipe: Arc<Pipe>,
    slots: Slots,
    tallies: Tallies,
    counts: OpCounts,
    stop: AtomicBool,
    scale: u32,
}

/// One worker: calls on either session, chosen by its own seeded draw, until the storm stops.
fn worker(storm: &Storm, index: usize, seed: u64, beat: &Beat) {
    let mut rng = Rng::new(seed ^ (index as u64).wrapping_mul(0x9E37));
    let data_key = CString::new(format!("stress/data/w{index}")).unwrap();
    let ask_key = CString::new(format!("stress/ask/w{index}")).unwrap();
    let alive_key = CString::new(format!("stress/alive/w{index}")).unwrap();
    let mut payload = vec![0u8; 140_000];
    for (n, byte) in payload.iter_mut().enumerate() {
        *byte = (n % 251) as u8;
    }
    let scale = storm.scale;
    while !storm.stop.load(Ordering::SeqCst) {
        let side = if rng.below(4) == 0 {
            Side::Listening
        } else {
            Side::Dialling
        };
        let roll = rng.below(100);
        let hold = Duration::from_millis(rng.below(3));
        let (op, mark) = match roll {
            0..=59 => (0, Op::Put),
            60..=69 => (1, Op::Get),
            70..=79 => (2, Op::Subscriber),
            80..=89 => (3, Op::Queryable),
            _ => (4, Op::Token),
        };
        // One put in a hundred is past a batch, so it is cut into fragments on the way.
        let size = if rng.below(100) == 0 {
            70_000 + rng.below(70_000) as usize
        } else {
            1 + rng.below(1_500) as usize
        };
        beat.mark(mark);
        let rc = storm.slots.of(side).with(|session| unsafe {
            match op {
                0 => put(session, &data_key, &payload[..size]),
                1 => get(
                    session,
                    EVERY_ASK,
                    &storm.tallies,
                    Duration::from_millis(500) * scale,
                ),
                2 => subscriber_for(session, EVERY_KEY, &storm.tallies, hold),
                3 => queryable_for(session, &ask_key, &storm.tallies, hold),
                _ => token_for(session, &alive_key, hold),
            }
        });
        if let Some(rc) = rc {
            storm.counts.count(op, rc);
        }
        beat.mark(Op::Idle);
        if rng.below(50) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    beat.rest();
}

/// The chaos thread: closes a session while the workers call on it, frees it, opens another, and
/// every `CUT_EVERY` rounds cuts every link of the pipe, until the storm stops. Rounds, not the
/// clock, place the cuts: the first falls in a round the seed draws among the first
/// `CUT_EVERY`, and a cut that finds no link up stays due the next round, since it injected
/// nothing.
fn chaos(storm: &Storm, seed: u64, beat: &Beat) {
    const CUT_EVERY: u64 = 10;
    let mut rng = Rng::new(seed ^ 0xC4A0_5C4A);
    // A stream of its own, so the rounds' sides and waits stay what the seed drew before.
    let mut until_cut = 1 + Rng::new(seed ^ 0x0C07_0C07).below(CUT_EVERY);
    while !storm.stop.load(Ordering::SeqCst) {
        // The listening session goes one time in eight: every dialler then loses its link at
        // once and dials into nothing until the next listener is up.
        let side = if rng.below(8) == 0 {
            Side::Listening
        } else {
            Side::Dialling
        };
        let slot = storm.slots.of(side);
        beat.mark(Op::Close);
        slot.with(|session| unsafe {
            z_close(z_session_loan(session).cast_mut(), std::ptr::null())
        });
        beat.mark(Op::Release);
        if let Some(held) = slot.take() {
            unsafe { release(*held) };
        }
        beat.mark(Op::Open);
        match unsafe { open_side(&storm.pipe, side, &storm.tallies) } {
            Some(held) => {
                storm.counts.opened[side as usize].fetch_add(1, Ordering::SeqCst);
                slot.put(held);
            }
            None => {
                storm.counts.open_failures.fetch_add(1, Ordering::SeqCst);
            }
        }
        until_cut -= 1;
        if until_cut == 0 {
            beat.mark(Op::Cut);
            until_cut = if storm.pipe.cut_all() > 0 {
                CUT_EVERY
            } else {
                1
            };
        }
        let wait = Duration::from_millis(20 + rng.below(130)) * storm.scale;
        pause(beat, wait, Some(&storm.stop));
    }
    beat.rest();
}

/// How long past its seconds a storm may run to make its mix whole. A storm that needs it all has
/// a cause: no link comes up again, or a thread makes no progress.
const MIX_GRACE: Duration = Duration::from_secs(60);

/// What the storm has yet to do of what it is named for, as the failure a run that ended without
/// it reports: a call no worker has made, no dialling session the chaos thread opened, or a fault
/// of its shape the pipe has not injected. `None` once the mix is whole; every count only grows.
fn mix_missing(storm: &Storm) -> Option<String> {
    for (op, name) in OP_NAMES.iter().enumerate() {
        if storm.counts.calls(op) == 0 {
            return Some(format!("no {name} was made: {}", storm.counts.summary()));
        }
    }
    if storm.counts.opened[Side::Dialling as usize].load(Ordering::SeqCst) == 0 {
        return Some(format!(
            "the chaos thread opened no dialling session: {}",
            storm.counts.summary()
        ));
    }
    let pipe = &storm.pipe;
    let shaped = match pipe.shape {
        Shape::Stream => ("no send was split", &pipe.partials),
        Shape::Datagram => ("no datagram was lost", &pipe.losses),
    };
    for (missing, counter) in [
        ("no send was made to block", &pipe.blocks),
        ("no link was cut", &pipe.cuts),
        shaped,
    ] {
        if counter.load(Ordering::SeqCst) == 0 {
            return Some(format!("{missing}: {}", pipe.summary()));
        }
    }
    None
}

/// The storm over `shape`: workers and the chaos thread for the run's seconds and until its mix is
/// whole, faults on; then, faults off, a put and a get across the sessions the storm left; then
/// everything closed. Returns what was counted.
fn storm(shape: Shape, run: &Run, watch: &Watch, main: &Beat, beats: &[Arc<Beat>]) -> String {
    let (pipe, teller) = Pipe::start(shape, run.seed);
    watch.watch_pipe(Some(Arc::clone(&pipe)));
    make_transport(&pipe, Side::Listening);
    make_transport(&pipe, Side::Dialling);
    let storm = Storm {
        pipe: Arc::clone(&pipe),
        slots: Slots::default(),
        tallies: Tallies::default(),
        counts: OpCounts::default(),
        stop: AtomicBool::new(false),
        scale: run.scale,
    };
    let within = run.scaled(Duration::from_secs(15));
    unsafe {
        storm.slots.listening.put(open_until(
            &pipe,
            Side::Listening,
            &storm.tallies,
            main,
            within,
        ));
        storm.slots.dialling.put(open_until(
            &pipe,
            Side::Dialling,
            &storm.tallies,
            main,
            within,
        ));
    }
    pipe.faulty.store(true, Ordering::SeqCst);

    std::thread::scope(|scope| {
        let (chaos_beat, worker_beats) = beats.split_first().expect("a beat for the chaos thread");
        // The scope joins every thread it started; a handle dropped here detaches nothing.
        for (index, beat) in worker_beats.iter().take(run.workers).enumerate() {
            let storm = &storm;
            let seed = run.seed;
            let _ = std::thread::Builder::new()
                .name(format!("stability-worker-{index}"))
                .spawn_scoped(scope, move || worker(storm, index, seed, beat))
                .expect("a worker thread starts");
        }
        let storm_ref = &storm;
        let seed = run.seed;
        let _ = std::thread::Builder::new()
            .name("stability-chaos".to_owned())
            .spawn_scoped(scope, move || chaos(storm_ref, seed, chaos_beat))
            .expect("the chaos thread starts");
        pause(main, Duration::from_secs(run.seconds), None);
        // A loaded host makes fewer rounds and sends in the same seconds; the storm runs on until
        // its mix is whole, so the run grades the library and not the host's speed.
        let grace = Instant::now() + run.scaled(MIX_GRACE);
        while mix_missing(&storm).is_some() && Instant::now() < grace {
            pause(main, Duration::from_millis(20), None);
        }
        storm.stop.store(true, Ordering::SeqCst);
        main.mark(Op::Join);
    });

    // The faults stop; the sessions the storm left must carry a put and a get again. A dialler
    // that the pico preset gave up redialling is replaced, which is the program's remedy too.
    pipe.faulty.store(false, Ordering::SeqCst);
    main.mark(Op::Recover);
    unsafe {
        if storm.slots.listening.with(|_| ()).is_none() {
            storm.slots.listening.put(open_until(
                &pipe,
                Side::Listening,
                &storm.tallies,
                main,
                within,
            ));
        }
        if let Some(held) = storm.slots.dialling.take() {
            release(*held);
        }
        storm.slots.dialling.put(open_until(
            &pipe,
            Side::Dialling,
            &storm.tallies,
            main,
            within,
        ));
        let heard = storm
            .slots
            .listening
            .probe_heard()
            .expect("the listening session has its probe");
        storm
            .slots
            .dialling
            .with(|session| {
                converge(
                    session,
                    &heard,
                    "after-the-storm",
                    main,
                    run.scaled(Duration::from_secs(30)),
                )
            })
            .expect("the dialling session is in its slot");
        let answers = storm
            .slots
            .dialling
            .with(|session| ask(session, main, run.scaled(Duration::from_secs(30))))
            .expect("the dialling session is in its slot");
        assert!(
            answers.iter().all(|answer| answer == ANSWER.to_bytes()),
            "the probe answers with its payload after the storm: {answers:?}"
        );
    }

    main.mark(Op::Teardown);
    for side in [Side::Dialling, Side::Listening] {
        if let Some(held) = storm.slots.of(side).take() {
            unsafe { release(*held) };
        }
    }
    pipe.stop(teller);
    drop_transport(&pipe, Side::Dialling);
    drop_transport(&pipe, Side::Listening);
    wait_until(
        "both transports to drop",
        main,
        run.scaled(Duration::from_secs(10)),
        || pipe.drops.load(Ordering::SeqCst) == 2,
    );
    wait_until(
        "every closure the library was handed to be dropped",
        main,
        run.scaled(Duration::from_secs(15)),
        || storm.tallies.balanced(),
    );
    watch.watch_pipe(None);

    // The run did what it is named for: every call was made, the sessions came and went, and the
    // pipe injected each fault of its shape.
    if let Some(missing) = mix_missing(&storm) {
        panic!("{missing}");
    }
    format!(
        "{}\n  calls: {}\n  closures: {}",
        pipe.summary(),
        storm.counts.summary(),
        storm.tallies.summary()
    )
}

/// The most allocations a storm may leave behind. A leak of one allocation per call, or per
/// session the chaos thread opens, is many times this over a run; what stays below it is state the
/// runtime keeps once made.
const STORM_GROWTH_BOUND: isize = 4096;

fn storm_run(shape: Shape) {
    count_panics();
    let run = Run::from_env();
    eprintln!(
        "stability {shape:?}: seed {} (WZ_STABILITY_SEED reruns this mix), {} s, {} workers",
        run.seed, run.seconds, run.workers
    );
    let watch = Watch::new(&run);
    let main = watch.beat("main");
    let mut beats = vec![watch.beat("chaos")];
    for index in 0..run.workers {
        beats.push(watch.beat(&format!("worker-{index}")));
    }
    let watchdog = spawn_watchdog(Arc::clone(&watch));

    // One quiet pair first, so what the library makes once (its runtimes, its tables) is made
    // before the count that the storm is held to.
    quiet_pair(shape, &run, &watch, &main);
    main.mark(Op::Wait);
    let before = settled_allocations(Duration::from_secs(3), run.scaled(Duration::from_secs(12)));
    let counted = storm(shape, &run, &watch, &main, &beats);
    main.mark(Op::Wait);
    let after = settled_allocations(Duration::from_secs(3), run.scaled(Duration::from_secs(12)));
    main.mark(Op::Teardown);

    watch.stop.store(true, Ordering::SeqCst);
    watchdog.join().expect("the watchdog ends");
    let (panics, panic_text) = panics_so_far();
    eprintln!(
        "stability {shape:?}: {counted}\n  allocations held: {before} before, {after} after \
         ({} bytes now)",
        LIVE_BYTES.load(Ordering::SeqCst)
    );
    assert_eq!(
        panics, 0,
        "a thread panicked during the run (seed {}): {panic_text:#?}",
        run.seed
    );
    assert!(
        after - before < STORM_GROWTH_BOUND,
        "the storm left {} allocations behind (bound {STORM_GROWTH_BOUND}, seed {})",
        after - before,
        run.seed
    );
}

#[test]
#[ignore = "stress run of the pico C ABI, seconds long; Layer S runs via --ignored"]
fn calls_on_every_thread_over_a_stream_that_blocks_splits_and_cuts_neither_stall_nor_leak() {
    storm_run(Shape::Stream);
}

#[test]
#[ignore = "stress run of the pico C ABI, seconds long; Layer S runs via --ignored"]
fn calls_on_every_thread_over_datagrams_that_are_lost_or_blocked_neither_stall_nor_leak() {
    storm_run(Shape::Datagram);
}

/// Pairs opened and closed one after another, the same work each time: what one pair leaves
/// behind, the next adds to. The count after each pair is read once the process has settled, and
/// over the second half of the run (the first half makes what is made once) it may grow by less
/// than one allocation for every two pairs, with a floor of eight for a short run. Under valgrind
/// the lane runs a few pairs, and the leak checker's own verdict is the one that counts there.
#[test]
#[ignore = "stress run of the pico C ABI, seconds long; Layer S runs via --ignored"]
fn sessions_opened_and_closed_in_sequence_leave_no_allocation_behind() {
    count_panics();
    let run = Run::from_env();
    eprintln!(
        "stability sequence: seed {}, {} pairs",
        run.seed, run.cycles
    );
    let watch = Watch::new(&run);
    let main = watch.beat("main");
    let watchdog = spawn_watchdog(Arc::clone(&watch));
    let mut after_each = Vec::with_capacity(run.cycles);
    for _ in 0..run.cycles {
        quiet_pair(Shape::Stream, &run, &watch, &main);
        main.mark(Op::Wait);
        after_each.push(settled_allocations(
            Duration::from_millis(500),
            run.scaled(Duration::from_secs(3)),
        ));
    }
    main.mark(Op::Teardown);
    watch.stop.store(true, Ordering::SeqCst);
    watchdog.join().expect("the watchdog ends");

    let half = run.cycles / 2;
    let growth = after_each[run.cycles - 1] - after_each[half - 1];
    let allowed = isize::try_from((run.cycles - half) / 2)
        .unwrap_or(isize::MAX)
        .max(8);
    let (panics, panic_text) = panics_so_far();
    eprintln!("stability sequence: allocations held after each pair: {after_each:?}");
    assert_eq!(
        panics, 0,
        "a thread panicked during the run: {panic_text:#?}"
    );
    assert!(
        growth < allowed,
        "the second half of {} pairs left {growth} allocations behind (bound {allowed}): {after_each:?}",
        run.cycles
    );
}
