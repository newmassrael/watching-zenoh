// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What the pico C ABI does when memory runs out, and how much memory its traffic takes.
//!
//! Two instruments, both over the program's own transport (an in-memory pipe, no socket), on the
//! engine the build has, and both run by Layer S, never by a default `cargo test` (every test is
//! `#[ignore]`d):
//!
//! * **A failed allocation at every point of a call.** For `z_open`, `z_declare_subscriber`,
//!   `z_declare_queryable`, `z_declare_publisher`, `z_put` and `z_get`: a run with no failure
//!   counts the allocations the process makes while the call runs (N), and then for every n from
//!   1 until a run makes fewer than n, a run of its own whose n-th allocation fails. Each run is a
//!   process of its own (this executable, started again on one test with the point in its
//!   environment), because a failed allocation may end the process, and a process must be judged
//!   from outside then. A run ends in one of three ways: the call returned (its code, and once the
//!   sessions are closed whether every closure was dropped, both transports were let go and the
//!   process holds no more allocations than the run with no failure); the process ended in Rust's
//!   allocation-failure handler; or anything else (a signal, a failed assertion, a run that did
//!   not end in time), which fails every build.
//! * **The allocations of traffic between open sessions.** Once both sessions are open and
//!   their routes are made, puts (and gets) are counted: how many allocations the process made
//!   for them and how many bytes those asked for.
//!
//! What a build is held to depends on its memory, which `MEMORY_TAKEN_AT_OPEN` states. A build
//! that takes a session's memory at `z_open` and none after answers every failed allocation with
//! a named error and leaves nothing behind, and its traffic allocates nothing; both are asserted
//! there. A heap build allocates as it runs and ends the process in the handler when an
//! allocation fails; there each instrument measures and prints, and asserts what holds of every
//! build (no other end of a run, no panic, the counter sees the heap's allocations).
//!
//! The allocator below is this executable's own (`#[global_allocator]`), which is why the file is
//! an executable of its own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::{c_char, c_void, CStr};
use std::fmt::Write as _;
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_pico::app_transport::{
    wz_ext_config_transport, wz_ext_link_kind_t, wz_ext_link_result_t, wz_ext_link_t,
    wz_ext_loaned_transport_t, wz_ext_owned_transport_t, wz_ext_transport_accepted,
    wz_ext_transport_drop, wz_ext_transport_event, wz_ext_transport_loan, wz_ext_transport_move,
    wz_ext_transport_new, wz_ext_transport_received, wz_ext_transport_t, WZ_EXT_LINK_CLOSED,
    WZ_EXT_LINK_EVENT_CLOSED, WZ_EXT_LINK_EVENT_CONNECTED, WZ_EXT_LINK_EVENT_WRITABLE,
    WZ_EXT_LINK_OK, WZ_EXT_LINK_STREAM_DIAL, WZ_EXT_LINK_STREAM_LISTEN, WZ_EXT_LINK_WOULD_BLOCK,
};
use wz_capi_pico::result::{WZ_EXT_ERR_LINK_FULL, Z_ERR_SYSTEM_OUT_OF_MEMORY};
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query,
    z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher,
    z_declare_queryable, z_declare_subscriber, z_get, z_get_options_default, z_get_options_t,
    z_loaned_query_t, z_loaned_reply_t, z_loaned_sample_t, z_open, z_owned_bytes_t,
    z_owned_closure_query_t, z_owned_closure_reply_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_publisher_t, z_owned_queryable_t, z_owned_session_t, z_owned_subscriber_t,
    z_publisher_move, z_put, z_query_keyexpr, z_query_reply, z_queryable_move,
    z_queryable_options_default, z_queryable_options_t, z_reply_is_ok, z_session_drop,
    z_session_loan, z_session_loan_mut, z_session_move, z_subscriber_move, z_undeclare_publisher,
    z_undeclare_queryable, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// Whether this build takes a session's memory at `z_open` and none after. Then a failed
/// allocation is answered with a named error and leaves nothing behind, and traffic between open
/// sessions allocates nothing, and the tests below assert both. Both engines of this crate take
/// their memory from the heap as a session runs, where a failed allocation ends the process in
/// Rust's allocation-failure handler and every message allocates, so the tests measure and print
/// that and assert what holds of every build. A fixed-memory build sets this from its feature.
const MEMORY_TAKEN_AT_OPEN: bool = false;

/// The codes a call may answer a failed allocation with: pico's own for it
/// (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`).
const NAMED_ALLOCATION_ERRORS: [ZResult; 1] = [Z_ERR_SYSTEM_OUT_OF_MEMORY];

// ---------------------------------------------------------------------------------------------
// The allocator: every call counted, and one of them failed on request.

/// Allocations made and not yet freed, by every thread of the process.
static LIVE_ALLOCATIONS: AtomicIsize = AtomicIsize::new(0);
/// Whether a window is open: the allocations made while it is are counted, and one may fail.
static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);
/// Allocations made while the window was open, and the bytes they asked for.
static WINDOW_SEEN: AtomicU64 = AtomicU64::new(0);
static WINDOW_BYTES: AtomicU64 = AtomicU64::new(0);
/// The allocation of the window that fails, counted from 1; 0 fails none.
static FAIL_AT: AtomicU64 = AtomicU64::new(0);
/// Whether the window's failing allocation was reached.
static FIRED: AtomicBool = AtomicBool::new(false);

/// Count one allocation of `size` bytes; true when it is the one the window fails.
fn fails_here(size: usize) -> bool {
    if !WINDOW_OPEN.load(Ordering::SeqCst) {
        return false;
    }
    let n = WINDOW_SEEN.fetch_add(1, Ordering::SeqCst) + 1;
    WINDOW_BYTES.fetch_add(size as u64, Ordering::SeqCst);
    if n == FAIL_AT.load(Ordering::SeqCst) {
        FIRED.store(true, Ordering::SeqCst);
        return true;
    }
    false
}

struct Injecting;

// SAFETY: every call is forwarded to the system allocator unchanged, except the one the window
// fails, which returns null as an allocator out of memory does, and touches nothing.
unsafe impl GlobalAlloc for Injecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fails_here(layout.size()) {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fails_here(layout.size()) {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
    }

    // A failed reallocation leaves the block where it was, as the system's does.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if fails_here(new_size) {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Injecting = Injecting;

/// Open the window, failing its `fail_at`-th allocation (none for 0).
fn open_window(fail_at: u64) {
    FIRED.store(false, Ordering::SeqCst);
    WINDOW_SEEN.store(0, Ordering::SeqCst);
    WINDOW_BYTES.store(0, Ordering::SeqCst);
    FAIL_AT.store(fail_at, Ordering::SeqCst);
    WINDOW_OPEN.store(true, Ordering::SeqCst);
}

/// What the window saw.
struct Seen {
    allocations: u64,
    bytes: u64,
    fired: bool,
}

fn close_window() -> Seen {
    WINDOW_OPEN.store(false, Ordering::SeqCst);
    FAIL_AT.store(0, Ordering::SeqCst);
    Seen {
        allocations: WINDOW_SEEN.load(Ordering::SeqCst),
        bytes: WINDOW_BYTES.load(Ordering::SeqCst),
        fired: FIRED.load(Ordering::SeqCst),
    }
}

/// The fewest allocations the process held while it settled: the lowest count seen, once no
/// lower one has been seen for `quiet`, or at `longest`. A thread that is ending frees what it
/// held as it ends, so a single reading taken at once would count it.
fn settled_allocations(quiet: Duration, longest: Duration) -> isize {
    let start = Instant::now();
    let mut lowest = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
    let mut lowest_at = start;
    while start.elapsed() < longest && lowest_at.elapsed() < quiet {
        std::thread::sleep(Duration::from_millis(20));
        let now = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
        if now < lowest {
            lowest = now;
            lowest_at = Instant::now();
        }
    }
    lowest
}

// ---------------------------------------------------------------------------------------------
// Every panic of the process, a library thread's included.

static PANICS: AtomicUsize = AtomicUsize::new(0);

fn count_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.fetch_add(1, Ordering::SeqCst);
            previous(info);
        }));
    });
}

// ---------------------------------------------------------------------------------------------
// The program's transport: one stream pair between two transports, in memory. Nothing on the
// path a message takes allocates, so every allocation a window counts is the library's.

/// The locator the listening session listens on and the dialling session dials. Synthetic.
const LISTEN: &CStr = c"tcp/192.0.2.100:7447";
/// The address the listening program accepts the dial under. Synthetic.
const ACCEPTED_REMOTE: &CStr = c"tcp/192.0.2.200:41000";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Listening,
    Dialling,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Side::Listening => 0,
            Side::Dialling => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Side::Listening => Side::Dialling,
            Side::Dialling => Side::Listening,
        }
    }
}

#[derive(Default)]
struct Pipe {
    /// Each side's owned transport, at a stable address, as an address; 0 once dropped.
    owned: [AtomicUsize; 2],
    /// The listening side's listener link, 0 while it has none.
    listener: AtomicU64,
    /// Each side's end of the pair, 0 while there is no pair.
    ends: [AtomicU64; 2],
    /// A side's link whose send waits for the other side's end to be read down, 0 for none.
    waiting: [AtomicU64; 2],
    /// A dialled link to report connected, from the pipe's own thread, 0 for none.
    connecting: Mutex<u64>,
    connect_wake: Condvar,
    stopping: AtomicBool,
    /// The transports whose drop has run.
    drops: AtomicUsize,
}

impl Pipe {
    /// A pipe, and the thread that reports a dial connected after `open` has answered, as a
    /// stack reports a connection it made.
    fn start() -> (Arc<Self>, JoinHandle<()>) {
        let pipe = Arc::new(Self::default());
        let teller = Arc::clone(&pipe);
        let thread = std::thread::Builder::new()
            .name("allocation-faults-pipe".to_owned())
            .spawn(move || teller.tell_connected())
            .expect("the pipe's thread starts");
        (pipe, thread)
    }

    fn tell_connected(&self) {
        let mut connecting = self.connecting.lock().unwrap();
        loop {
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
            let link = std::mem::take(&mut *connecting);
            if link == 0 {
                connecting = self.connect_wake.wait(connecting).unwrap();
                continue;
            }
            drop(connecting);
            std::thread::sleep(Duration::from_millis(1));
            // A link closed since is refused by name; the report is then moot.
            let _ = unsafe {
                wz_ext_transport_event(self.loan(Side::Dialling), link, WZ_EXT_LINK_EVENT_CONNECTED)
            };
            connecting = self.connecting.lock().unwrap();
        }
    }

    fn stop(&self, thread: JoinHandle<()>) {
        self.stopping.store(true, Ordering::SeqCst);
        // Under the lock, so the thread is either waiting (and woken) or sees the flag next.
        let guard = self.connecting.lock().unwrap();
        self.connect_wake.notify_all();
        drop(guard);
        thread.join().expect("the pipe's thread ends");
    }

    /// The loan of `side`'s transport, or null once it was dropped (every call on a null loan is
    /// refused by name).
    fn loan(&self, side: Side) -> *const wz_ext_loaned_transport_t {
        match self.owned[side.index()].load(Ordering::SeqCst) {
            0 => std::ptr::null(),
            raw => unsafe { wz_ext_transport_loan(raw as *const wz_ext_owned_transport_t) },
        }
    }

    /// Forget the pair `link` is an end of and tell the other end it closed.
    fn unpair(&self, side: Side, link: u64) {
        if self.ends[side.index()]
            .compare_exchange(link, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        self.waiting[side.index()].store(0, Ordering::SeqCst);
        let peer = self.ends[side.other().index()].swap(0, Ordering::SeqCst);
        self.waiting[side.other().index()].store(0, Ordering::SeqCst);
        if peer != 0 {
            let _ = unsafe {
                wz_ext_transport_event(self.loan(side.other()), peer, WZ_EXT_LINK_EVENT_CLOSED)
            };
        }
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
    if CStr::from_ptr(locator) != LISTEN {
        return WZ_EXT_LINK_CLOSED;
    }
    match (ctx.side, kind) {
        (Side::Listening, WZ_EXT_LINK_STREAM_LISTEN) => {
            pipe.listener.store(link, Ordering::SeqCst);
            WZ_EXT_LINK_OK
        }
        (Side::Dialling, WZ_EXT_LINK_STREAM_DIAL) => {
            // The listening program accepts the dial, and the two ends are paired before the
            // dial is answered, so neither side sends into nothing.
            let mut accepted: wz_ext_link_t = 0;
            if wz_ext_transport_accepted(
                pipe.loan(Side::Listening),
                pipe.listener.load(Ordering::SeqCst),
                ACCEPTED_REMOTE.as_ptr(),
                &mut accepted,
            ) != Z_OK
            {
                return WZ_EXT_LINK_CLOSED;
            }
            pipe.ends[Side::Listening.index()].store(accepted, Ordering::SeqCst);
            pipe.ends[Side::Dialling.index()].store(link, Ordering::SeqCst);
            *pipe.connecting.lock().unwrap() = link;
            pipe.connect_wake.notify_all();
            WZ_EXT_LINK_WOULD_BLOCK
        }
        _ => WZ_EXT_LINK_CLOSED,
    }
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
    if pipe.ends[side.index()].load(Ordering::SeqCst) != link {
        return WZ_EXT_LINK_CLOSED;
    }
    let peer = pipe.ends[side.other().index()].load(Ordering::SeqCst);
    if peer == 0 {
        return WZ_EXT_LINK_CLOSED;
    }
    // Registered before the bytes are handed over, so a drain that follows a full refusal at
    // once finds the sender waiting.
    pipe.waiting[side.index()].store(link, Ordering::SeqCst);
    let rc = wz_ext_transport_received(pipe.loan(side.other()), peer, data, len, std::ptr::null());
    if rc == WZ_EXT_ERR_LINK_FULL {
        // Nothing was taken; the send waits for the other end to be read down.
        return WZ_EXT_LINK_WOULD_BLOCK;
    }
    pipe.waiting[side.index()].store(0, Ordering::SeqCst);
    if rc == Z_OK {
        *written = len;
        WZ_EXT_LINK_OK
    } else {
        // The other end is closing or gone.
        WZ_EXT_LINK_CLOSED
    }
}

unsafe extern "C" fn on_close(context: *mut c_void, link: wz_ext_link_t) {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    if ctx.side == Side::Listening {
        let _ = pipe
            .listener
            .compare_exchange(link, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    pipe.unpair(ctx.side, link);
}

unsafe extern "C" fn on_drained(context: *mut c_void, _link: wz_ext_link_t) {
    let ctx = ctx(context);
    let pipe = &ctx.pipe;
    let sender = ctx.side.other();
    let waiting = pipe.waiting[sender.index()].swap(0, Ordering::SeqCst);
    if waiting != 0 {
        let _ = wz_ext_transport_event(pipe.loan(sender), waiting, WZ_EXT_LINK_EVENT_WRITABLE);
    }
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    let ctx = Box::from_raw(context as *mut SideCtx);
    ctx.pipe.drops.fetch_add(1, Ordering::SeqCst);
}

/// A transport of `side` over the pipe, owned at a stable address.
fn make_transport(pipe: &Arc<Pipe>, side: Side) -> *mut wz_ext_owned_transport_t {
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
    pipe.owned[side.index()].store(owned as usize, Ordering::SeqCst);
    owned
}

/// Release the program's reference to `side`'s transport and free its slot. The pipe forgets it
/// first, so a late call of the pipe's finds no transport rather than a freed slot.
fn drop_transport(pipe: &Pipe, side: Side) {
    let raw = pipe.owned[side.index()].swap(0, Ordering::SeqCst);
    assert_ne!(
        raw, 0,
        "the {side:?} transport was made and is dropped once"
    );
    let owned = raw as *mut wz_ext_owned_transport_t;
    unsafe {
        wz_ext_transport_drop(wz_ext_transport_move(owned));
        drop(Box::from_raw(owned));
    }
}

// ---------------------------------------------------------------------------------------------
// Closures, counted when made and when dropped, and what they were handed. None allocates.

#[derive(Default)]
struct Counts {
    /// Closures handed to the library, and the drops it ran of them.
    made: AtomicUsize,
    dropped: AtomicUsize,
    /// Samples the listening session's subscriber was handed.
    heard: AtomicUsize,
    /// Replies the gets were handed, and the gets the library declared over (their closure's
    /// drop, which comes once whatever the get's end).
    replies: AtomicUsize,
    gets_over: AtomicUsize,
}

impl Counts {
    fn balanced(&self) -> bool {
        self.made.load(Ordering::SeqCst) == self.dropped.load(Ordering::SeqCst)
    }
}

/// A closure context for `counts`, counted as made: the library owns it until it runs the drop.
fn context(counts: &Arc<Counts>) -> *mut c_void {
    counts.made.fetch_add(1, Ordering::SeqCst);
    Arc::into_raw(Arc::clone(counts)) as *mut c_void
}

unsafe extern "C" fn counted_drop(context: *mut c_void) {
    let counts = Arc::from_raw(context as *const Counts);
    counts.dropped.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn get_over(context: *mut c_void) {
    let counts = Arc::from_raw(context as *const Counts);
    counts.gets_over.fetch_add(1, Ordering::SeqCst);
    counts.dropped.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, context: *mut c_void) {
    (*(context as *const Counts))
        .heard
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    if z_reply_is_ok(reply) {
        (*(context as *const Counts))
            .replies
            .fetch_add(1, Ordering::SeqCst);
    }
}

/// Every queryable answers with this.
const ANSWER: &CStr = c"answer";

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, _context: *mut c_void) {
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

// ---------------------------------------------------------------------------------------------
// Sessions and the calls under test.

/// The key the listening session hears and answers on, and the one a declaration under test
/// names. Synthetic.
const DATA_KEY: &CStr = c"faults/data";
const ASK_KEY: &CStr = c"faults/ask";
const DECLARED_KEY: &CStr = c"faults/declared/**";

/// How long a run waits for what it waits for: a crossing, a get's end, a drop.
const WAIT_BOUND: Duration = Duration::from_secs(10);
/// A get's own timeout.
const GET_TIMEOUT_MS: u64 = 2_000;

unsafe fn view(key: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut ke, key.as_ptr()),
        Z_OK,
        "{key:?}"
    );
    ke
}

/// A config with `key` set to the pipe's locator, carrying `transport`.
unsafe fn config_over(key: u8, transport: *mut wz_ext_owned_transport_t) -> z_owned_config_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, LISTEN.as_ptr()),
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

unsafe fn open_over(key: u8, transport: *mut wz_ext_owned_transport_t) -> z_owned_session_t {
    let mut cfg = config_over(key, transport);
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "a session opens over the pipe"
    );
    session
}

unsafe fn close(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null());
    z_session_drop(z_session_move(&mut session));
}

/// The closure of a subscriber that counts what it hears.
unsafe fn sample_closure(counts: &Arc<Counts>) -> z_owned_closure_sample_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(on_sample),
            Some(counted_drop),
            context(counts)
        ),
        Z_OK
    );
    closure
}

/// The closure of a queryable that answers `ANSWER`.
unsafe fn query_closure(counts: &Arc<Counts>) -> z_owned_closure_query_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut closure,
            Some(on_query),
            Some(counted_drop),
            context(counts)
        ),
        Z_OK
    );
    closure
}

/// The closure of a get that counts its replies and its end.
unsafe fn reply_closure(counts: &Arc<Counts>) -> z_owned_closure_reply_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(
            &mut closure,
            Some(on_reply),
            Some(get_over),
            context(counts)
        ),
        Z_OK
    );
    closure
}

unsafe fn declare_subscriber(
    session: &z_owned_session_t,
    key: &CStr,
    closure: &mut z_owned_closure_sample_t,
    subscriber: &mut z_owned_subscriber_t,
) -> ZResult {
    let ke = view(key);
    z_declare_subscriber(
        z_session_loan(session),
        subscriber,
        z_view_keyexpr_loan(&ke),
        z_closure_sample_move(closure),
        std::ptr::null(),
    )
}

unsafe fn declare_queryable(
    session: &z_owned_session_t,
    key: &CStr,
    closure: &mut z_owned_closure_query_t,
    queryable: &mut z_owned_queryable_t,
) -> ZResult {
    let ke = view(key);
    let mut opts: z_queryable_options_t = std::mem::zeroed();
    z_queryable_options_default(&mut opts);
    z_declare_queryable(
        z_session_loan(session),
        queryable,
        z_view_keyexpr_loan(&ke),
        z_closure_query_move(closure),
        &opts,
    )
}

unsafe fn put(session: &z_owned_session_t, payload: &mut z_owned_bytes_t) -> ZResult {
    let ke = view(DATA_KEY);
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        z_bytes_move(payload),
        std::ptr::null(),
    )
}

/// The bytes a put carries. Synthetic.
const PAYLOAD: [u8; 64] = [0x5A; 64];

unsafe fn payload() -> z_owned_bytes_t {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut bytes, PAYLOAD.as_ptr(), PAYLOAD.len()),
        Z_OK
    );
    bytes
}

unsafe fn get(session: &z_owned_session_t, closure: &mut z_owned_closure_reply_t) -> ZResult {
    let ke = view(ASK_KEY);
    let mut opts: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut opts);
    opts.timeout_ms = GET_TIMEOUT_MS;
    z_get(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        std::ptr::null(),
        z_closure_reply_move(closure),
        &mut opts,
    )
}

/// Wait until `done`, at most `within`; whether it came.
fn wait_for(within: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

/// The listening session, which hears `DATA_KEY` and answers `ASK_KEY`, and the dialling one,
/// over one pipe, both open; or the listening one alone, for the run that opens the dialler.
struct Pair {
    pipe: Arc<Pipe>,
    teller: JoinHandle<()>,
    dialling_transport: *mut wz_ext_owned_transport_t,
    counts: Arc<Counts>,
    listener: z_owned_session_t,
    subscriber: z_owned_subscriber_t,
    queryable: z_owned_queryable_t,
    dialler: Option<z_owned_session_t>,
}

impl Pair {
    /// The listening session and its entities, and the dialling session when `dial`: its
    /// route to the listener made (a put heard) and a get answered, so what a later call does is
    /// the call's own work and not the first exchange of a route.
    unsafe fn open(dial: bool) -> Self {
        let (pipe, teller) = Pipe::start();
        let counts = Arc::new(Counts::default());
        let listening_transport = make_transport(&pipe, Side::Listening);
        let dialling_transport = make_transport(&pipe, Side::Dialling);
        let listener = open_over(Z_CONFIG_LISTEN_KEY, listening_transport);
        let mut closure = sample_closure(&counts);
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            declare_subscriber(&listener, DATA_KEY, &mut closure, &mut subscriber),
            Z_OK
        );
        let mut closure = query_closure(&counts);
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            declare_queryable(&listener, ASK_KEY, &mut closure, &mut queryable),
            Z_OK
        );
        let mut pair = Self {
            pipe,
            teller,
            dialling_transport,
            counts,
            listener,
            subscriber,
            queryable,
            dialler: None,
        };
        if dial {
            let dialler = open_over(Z_CONFIG_CONNECT_KEY, dialling_transport);
            pair.dialler = Some(dialler);
            pair.converge();
        }
        pair
    }

    fn dialler(&self) -> &z_owned_session_t {
        self.dialler.as_ref().expect("the dialling session is open")
    }

    /// Put from the dialler until the listener hears one, then ask until a get is answered.
    unsafe fn converge(&self) {
        let deadline = Instant::now() + WAIT_BOUND;
        let heard = self.counts.heard.load(Ordering::SeqCst);
        while self.counts.heard.load(Ordering::SeqCst) == heard {
            assert!(
                Instant::now() < deadline,
                "no put crossed the pipe within {WAIT_BOUND:?}"
            );
            let mut bytes = payload();
            let _ = put(self.dialler(), &mut bytes);
            std::thread::sleep(Duration::from_millis(10));
        }
        loop {
            assert!(
                Instant::now() < deadline,
                "no get was answered within {WAIT_BOUND:?}"
            );
            let replies = self.counts.replies.load(Ordering::SeqCst);
            let over = self.counts.gets_over.load(Ordering::SeqCst);
            let mut closure = reply_closure(&self.counts);
            assert_eq!(get(self.dialler(), &mut closure), Z_OK, "a get is taken");
            assert!(
                wait_for(WAIT_BOUND, || self.counts.gets_over.load(Ordering::SeqCst)
                    > over),
                "a get did not end within {WAIT_BOUND:?}"
            );
            if self.counts.replies.load(Ordering::SeqCst) > replies {
                return;
            }
        }
    }

    /// Close both sessions, let both transports go and wait for the library to drop every closure
    /// and both transports. Whether each came within the bound.
    unsafe fn close(self) -> (bool, bool) {
        let Self {
            pipe,
            teller,
            dialling_transport: _,
            counts,
            listener,
            mut subscriber,
            mut queryable,
            dialler,
        } = self;
        if let Some(dialler) = dialler {
            close(dialler);
        }
        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_undeclare_queryable(z_queryable_move(&mut queryable));
        close(listener);
        pipe.stop(teller);
        drop_transport(&pipe, Side::Dialling);
        drop_transport(&pipe, Side::Listening);
        let dropped = wait_for(WAIT_BOUND, || pipe.drops.load(Ordering::SeqCst) == 2);
        let balanced = wait_for(WAIT_BOUND, || counts.balanced());
        (balanced, dropped)
    }
}

// ---------------------------------------------------------------------------------------------
// The calls a failed allocation is put into.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Open,
    DeclareSubscriber,
    DeclareQueryable,
    DeclarePublisher,
    Put,
    Get,
}

impl Call {
    const ALL: [Call; 6] = [
        Call::Open,
        Call::DeclareSubscriber,
        Call::DeclareQueryable,
        Call::DeclarePublisher,
        Call::Put,
        Call::Get,
    ];

    fn name(self) -> &'static str {
        match self {
            Call::Open => "z_open",
            Call::DeclareSubscriber => "z_declare_subscriber",
            Call::DeclareQueryable => "z_declare_queryable",
            Call::DeclarePublisher => "z_declare_publisher",
            Call::Put => "z_put",
            Call::Get => "z_get",
        }
    }

    /// The test that sweeps this call, which each of its runs is started as.
    fn test_name(self) -> &'static str {
        match self {
            Call::Open => "z_open_meets_a_failed_allocation_at_every_point_of_its_call",
            Call::DeclareSubscriber => {
                "z_declare_subscriber_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::DeclareQueryable => {
                "z_declare_queryable_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::DeclarePublisher => {
                "z_declare_publisher_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::Put => "z_put_meets_a_failed_allocation_at_every_point_of_its_call",
            Call::Get => "z_get_meets_a_failed_allocation_at_every_point_of_its_call",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|call| call.name() == name)
    }
}

/// The variable that starts a run: `<call>:<point>`, the point 0 for the run with no failure.
const RUN_VARIABLE: &str = "WZ_ALLOC_FAULT_RUN";
/// The line a run prints its verdict on.
const VERDICT_PREFIX: &str = "allocation-fault-run:";

/// What Rust's allocation-failure handler writes before it aborts the process.
fn ended_in_the_allocation_failure_handler(stderr: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.contains("memory allocation of ") && line.contains(" bytes failed"))
}

/// End the process at once when it aborts, with the code a shell gives an abort: the handler's
/// abort would otherwise leave a core dump for every one of a sweep's thousands of runs.
#[cfg(unix)]
fn end_at_once_on_abort() {
    const ABORT_EXIT: libc::c_int = 134;
    extern "C" fn on_abort(_signal: libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe and ends the process without running anything.
        unsafe { libc::_exit(ABORT_EXIT) }
    }
    // The handler's address, through a function pointer: a function item is not cast to an
    // integer directly.
    let handler: extern "C" fn(libc::c_int) = on_abort;
    // SAFETY: the handler calls one async-signal-safe function.
    unsafe { libc::signal(libc::SIGABRT, handler as libc::sighandler_t) };
}

#[cfg(not(unix))]
fn end_at_once_on_abort() {}

/// One run of `call` whose `point`-th allocation fails (none for 0), in this process: the
/// sessions the call needs, the call in the window, what it made undone, everything closed, and
/// the verdict printed for the process that started this one.
fn run_once(call: Call, point: u64) {
    count_panics();
    end_at_once_on_abort();
    unsafe {
        let mut pair = Pair::open(call != Call::Open);
        let counts = Arc::clone(&pair.counts);
        let (rc, seen) = match call {
            Call::Open => {
                let mut cfg = config_over(Z_CONFIG_CONNECT_KEY, pair.dialling_transport);
                let mut session: z_owned_session_t = std::mem::zeroed();
                open_window(point);
                let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
                let seen = close_window();
                if rc == Z_OK {
                    pair.dialler = Some(session);
                }
                (rc, seen)
            }
            Call::DeclareSubscriber => {
                let mut closure = sample_closure(&counts);
                let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
                open_window(point);
                let rc =
                    declare_subscriber(pair.dialler(), DECLARED_KEY, &mut closure, &mut subscriber);
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
                }
                (rc, seen)
            }
            Call::DeclareQueryable => {
                let mut closure = query_closure(&counts);
                let mut queryable: z_owned_queryable_t = std::mem::zeroed();
                open_window(point);
                let rc =
                    declare_queryable(pair.dialler(), DECLARED_KEY, &mut closure, &mut queryable);
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_queryable(z_queryable_move(&mut queryable));
                }
                (rc, seen)
            }
            Call::DeclarePublisher => {
                let ke = view(DATA_KEY);
                let mut publisher: z_owned_publisher_t = std::mem::zeroed();
                open_window(point);
                let rc = z_declare_publisher(
                    z_session_loan(pair.dialler()),
                    &mut publisher,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                );
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_publisher(z_publisher_move(&mut publisher));
                }
                (rc, seen)
            }
            Call::Put => {
                let mut bytes = payload();
                open_window(point);
                let rc = put(pair.dialler(), &mut bytes);
                (rc, close_window())
            }
            Call::Get => {
                let over = counts.gets_over.load(Ordering::SeqCst);
                let mut closure = reply_closure(&counts);
                open_window(point);
                let rc = get(pair.dialler(), &mut closure);
                let seen = close_window();
                // Taken or refused, the get ends: its closure's drop comes once either way.
                let _ = wait_for(WAIT_BOUND, || {
                    counts.gets_over.load(Ordering::SeqCst) > over
                });
                (rc, seen)
            }
        };
        let (balanced, dropped) = pair.close();
        // What the process holds once everything is closed, read where it is judged: a run whose
        // call returned after its failure, and the run with no failure it is held to.
        let held = if seen.fired || point == 0 {
            settled_allocations(Duration::from_millis(300), Duration::from_secs(3))
        } else {
            0
        };
        println!(
            "{VERDICT_PREFIX} fired={} rc={rc} allocations={} held={held} balanced={} \
             dropped={} panics={}",
            u8::from(seen.fired),
            seen.allocations,
            u8::from(balanced),
            u8::from(dropped),
            PANICS.load(Ordering::SeqCst),
        );
    }
}

/// What one run printed.
#[derive(Clone, Copy, Debug)]
struct Verdict {
    fired: bool,
    rc: ZResult,
    allocations: u64,
    held: isize,
    balanced: bool,
    dropped: bool,
    panics: usize,
}

fn parse_verdict(stdout: &str) -> Option<Verdict> {
    // libtest may have written the test's name on the line before the verdict.
    let line = stdout.lines().find_map(|line| {
        line.find(VERDICT_PREFIX)
            .map(|at| &line[at + VERDICT_PREFIX.len()..])
    })?;
    Some(Verdict {
        fired: field(line, "fired")? == "1",
        rc: field(line, "rc")?.parse().ok()?,
        allocations: field(line, "allocations")?.parse().ok()?,
        held: field(line, "held")?.parse().ok()?,
        balanced: field(line, "balanced")? == "1",
        dropped: field(line, "dropped")? == "1",
        panics: field(line, "panics")?.parse().ok()?,
    })
}

/// The value of `name=value` among the words of `line`.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('='))
}

/// How a run ended.
#[derive(Debug)]
enum Outcome {
    /// The call returned, and the run printed what it saw.
    Returned(Verdict),
    /// The process ended in Rust's allocation-failure handler.
    EndedInTheHandler,
    /// Any other end: a signal, a failed assertion of the run's own, no verdict, no end in time.
    Broken(String),
}

/// How long one run may take: two sessions over memory, one call, everything closed.
const RUN_BOUND: Duration = Duration::from_secs(60);

fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

#[cfg(unix)]
fn signal_of(status: &ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(status)
}

#[cfg(not(unix))]
fn signal_of(_status: &ExitStatus) -> Option<i32> {
    None
}

/// The last lines of `text`, for a report.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(12)..].join("\n    ")
}

/// Start this executable again on `call`'s test alone, as the run of `point`, and read how it
/// ended.
fn run_child(call: Call, point: u64) -> Outcome {
    let exe = std::env::current_exe().expect("the test executable has a path");
    let mut child = Command::new(exe)
        .args([
            call.test_name(),
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RUN_VARIABLE, format!("{}:{point}", call.name()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a run starts");
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + RUN_BOUND;
    let status = loop {
        match child.try_wait().expect("a run can be waited on") {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = stdout.join().expect("the run's stdout is read");
    let stderr = stderr.join().expect("the run's stderr is read");
    match status {
        None => Outcome::Broken(format!(
            "did not end within {RUN_BOUND:?}; stderr:\n    {}",
            tail(&stderr)
        )),
        Some(status) if status.success() => match parse_verdict(&stdout) {
            Some(verdict) => Outcome::Returned(verdict),
            None => Outcome::Broken(format!(
                "ended without its verdict; stdout:\n    {}",
                tail(&stdout)
            )),
        },
        Some(_) if ended_in_the_allocation_failure_handler(&stderr) => Outcome::EndedInTheHandler,
        Some(status) => Outcome::Broken(format!(
            "ended with {status} (signal {:?}); stderr:\n    {}",
            signal_of(&status),
            tail(&stderr)
        )),
    }
}

/// How many runs go at once: `WZ_ALLOC_FAULT_JOBS`, or the machine's parallelism.
fn jobs() -> usize {
    match std::env::var("WZ_ALLOC_FAULT_JOBS") {
        Ok(text) => text
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("WZ_ALLOC_FAULT_JOBS={text:?} is not a number"))
            .clamp(1, 64),
        Err(_) => std::thread::available_parallelism().map_or(4, usize::from),
    }
}

/// What the runs of a sweep came to.
#[derive(Default)]
struct Tally {
    in_the_handler: usize,
    named_errors: usize,
    absorbed: usize,
    not_reached: usize,
    failures: Vec<String>,
}

impl Tally {
    /// Judge the run of `point` against the run with no failure.
    fn judge(&mut self, call: Call, point: u64, outcome: Outcome, reference: &Verdict) {
        let mut broke = Vec::new();
        match outcome {
            Outcome::Broken(why) => broke.push(why),
            Outcome::EndedInTheHandler if MEMORY_TAKEN_AT_OPEN => {
                broke.push("the process ended in the allocation-failure handler".to_owned());
            }
            Outcome::EndedInTheHandler => self.in_the_handler += 1,
            Outcome::Returned(verdict) => {
                if verdict.panics != 0 {
                    broke.push(format!("{} panic(s)", verdict.panics));
                }
                if !verdict.balanced {
                    broke.push("a closure the library was handed was not dropped".to_owned());
                }
                if !verdict.dropped {
                    broke.push("a transport was not let go".to_owned());
                }
                if !verdict.fired {
                    if verdict.rc != Z_OK {
                        broke.push(format!(
                            "with no allocation failed the call returned {}",
                            verdict.rc
                        ));
                    }
                    self.not_reached += 1;
                } else {
                    if verdict.rc != Z_OK && !NAMED_ALLOCATION_ERRORS.contains(&verdict.rc) {
                        broke.push(format!(
                            "returned {}, not a named allocation error ({NAMED_ALLOCATION_ERRORS:?})",
                            verdict.rc
                        ));
                    }
                    if verdict.held > reference.held {
                        broke.push(format!(
                            "left {} allocation(s) behind once closed",
                            verdict.held - reference.held
                        ));
                    }
                    if verdict.rc == Z_OK {
                        self.absorbed += 1;
                    } else {
                        self.named_errors += 1;
                    }
                }
            }
        }
        for why in broke {
            self.failures
                .push(format!("{} at {point}: {why}", call.name()));
        }
    }
}

/// The test of `call`: a run of this process started by the sweep, or the sweep.
fn sweep(call: Call) {
    if let Ok(request) = std::env::var(RUN_VARIABLE) {
        let (name, point) = request
            .split_once(':')
            .unwrap_or_else(|| panic!("{RUN_VARIABLE}={request:?} is not <call>:<point>"));
        let started_as = Call::from_name(name)
            .unwrap_or_else(|| panic!("{RUN_VARIABLE}={request:?} names no call"));
        assert_eq!(
            started_as, call,
            "a run of {name} was started as the test of {call:?}"
        );
        let point = point
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{RUN_VARIABLE}={request:?}: the point is not a number"));
        run_once(call, point);
        return;
    }

    let engine = if cfg!(feature = "engine-tokio") {
        "tokio engine"
    } else {
        "cooperative engine"
    };
    let reference = match run_child(call, 0) {
        Outcome::Returned(verdict) => verdict,
        other => panic!(
            "{}: the run with no failure did not return: {other:?}",
            call.name()
        ),
    };
    assert!(
        !reference.fired && reference.rc == Z_OK,
        "{}: with no failure the call returns Z_OK: {reference:?}",
        call.name()
    );
    assert!(
        reference.balanced && reference.dropped && reference.panics == 0,
        "{}: the run with no failure leaves every closure and transport dropped and no panic: \
         {reference:?}",
        call.name()
    );
    if !MEMORY_TAKEN_AT_OPEN {
        assert!(
            reference.allocations > 0,
            "{}: a heap build allocates in the call, and a count of 0 means the counter sees \
             nothing",
            call.name()
        );
    }

    // Every point the run with no failure reached, then on past it until a run makes fewer
    // allocations than its point: the count moves a little from run to run, with the threads.
    let reach = reference.allocations;
    let last = reach + reach.max(256);
    let jobs = jobs();
    let mut tally = Tally::default();
    let mut next = 1u64;
    let mut end = None;
    while end.is_none() {
        assert!(
            next <= last,
            "{}: a run still met its failing allocation at {last}, past the {reach} the run \
             with no failure made",
            call.name()
        );
        let points: Vec<u64> = (next..=last).take(jobs).collect();
        next += points.len() as u64;
        let runs: Vec<(u64, JoinHandle<Outcome>)> = points
            .iter()
            .map(|&point| (point, std::thread::spawn(move || run_child(call, point))))
            .collect();
        for (point, run) in runs {
            let outcome = run.join().expect("a run's reader ends");
            let ended_here = matches!(&outcome, Outcome::Returned(verdict) if !verdict.fired);
            tally.judge(call, point, outcome, &reference);
            // The points of a batch come in order, so the first that ends is the least.
            if ended_here && point > reach && end.is_none() {
                end = Some(point);
            }
        }
    }
    let end = end.expect("the loop ends on an end");

    let mut report = String::new();
    let _ = write!(
        report,
        "{} ({engine}): {reach} allocation(s) in the call with none failed, {} held once closed; \
         points 1 to {} run: ended in the allocation-failure handler {}, returned a named error \
         {}, returned Z_OK {}, not reached {}",
        call.name(),
        reference.held,
        next - 1,
        tally.in_the_handler,
        tally.named_errors,
        tally.absorbed,
        tally.not_reached,
    );
    eprintln!("{report}; the first point no run reached: {end}");
    assert!(
        tally.failures.is_empty(),
        "{} run(s) of {} broke the contract:\n  {}",
        tally.failures.len(),
        call.name(),
        tally.failures.join("\n  ")
    );
}

// ---------------------------------------------------------------------------------------------
// Traffic between open sessions.

/// How many messages are exchanged before the count, so that what the library makes on the first
/// exchanges (a route, a buffer grown to its size) is made, and how many are counted.
const WARM_UP: usize = 20;
const COUNTED: usize = 200;

#[derive(Clone, Copy, Debug)]
enum Traffic {
    Puts,
    Gets,
}

/// One message of `traffic` from the dialler, waited for to its end.
unsafe fn exchange(pair: &Pair, traffic: Traffic) {
    match traffic {
        Traffic::Puts => {
            let heard = pair.counts.heard.load(Ordering::SeqCst);
            let mut bytes = payload();
            assert_eq!(put(pair.dialler(), &mut bytes), Z_OK, "a put is taken");
            assert!(
                wait_for(WAIT_BOUND, || pair.counts.heard.load(Ordering::SeqCst)
                    > heard),
                "a put did not cross within {WAIT_BOUND:?}"
            );
        }
        Traffic::Gets => {
            let replies = pair.counts.replies.load(Ordering::SeqCst);
            let over = pair.counts.gets_over.load(Ordering::SeqCst);
            let mut closure = reply_closure(&pair.counts);
            assert_eq!(get(pair.dialler(), &mut closure), Z_OK, "a get is taken");
            assert!(
                wait_for(WAIT_BOUND, || pair.counts.gets_over.load(Ordering::SeqCst)
                    > over),
                "a get did not end within {WAIT_BOUND:?}"
            );
            assert!(
                pair.counts.replies.load(Ordering::SeqCst) > replies,
                "a get between open sessions is answered"
            );
        }
    }
}

fn count_traffic(traffic: Traffic) {
    count_panics();
    let engine = if cfg!(feature = "engine-tokio") {
        "tokio engine"
    } else {
        "cooperative engine"
    };
    let seen = unsafe {
        let pair = Pair::open(true);
        for _ in 0..WARM_UP {
            exchange(&pair, traffic);
        }
        std::thread::sleep(Duration::from_millis(200));
        open_window(0);
        for _ in 0..COUNTED {
            exchange(&pair, traffic);
        }
        let seen = close_window();
        let (balanced, dropped) = pair.close();
        assert!(balanced, "every closure the library was handed is dropped");
        assert!(dropped, "both transports are let go");
        seen
    };
    eprintln!(
        "{traffic:?} between open sessions ({engine}): {} allocation(s) of {} bytes for {COUNTED} \
         messages, {:.1} a message",
        seen.allocations,
        seen.bytes,
        seen.allocations as f64 / COUNTED as f64,
    );
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a thread panicked");
    if MEMORY_TAKEN_AT_OPEN {
        assert_eq!(
            seen.allocations, 0,
            "{traffic:?} between open sessions allocate nothing in a fixed-memory build"
        );
    } else {
        assert!(
            seen.allocations > 0,
            "a heap build allocates for its {traffic:?}, and a count of 0 means the counter sees \
             nothing"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The tests.

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_open_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Open);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_subscriber_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclareSubscriber);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_queryable_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclareQueryable);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_publisher_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclarePublisher);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_put_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Put);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_get_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Get);
}

#[test]
#[ignore = "counts the allocations of traffic between open sessions; Layer S runs via --ignored"]
fn puts_between_open_sessions_are_counted_for_their_allocations() {
    count_traffic(Traffic::Puts);
}

#[test]
#[ignore = "counts the allocations of traffic between open sessions; Layer S runs via --ignored"]
fn gets_between_open_sessions_are_counted_for_their_allocations() {
    count_traffic(Traffic::Gets);
}
