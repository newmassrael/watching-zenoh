// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two pico sessions over the program's own transport, and an allocator that counts what they
//! allocate, written once for the executables that measure the memory of the pico C ABI.
//!
//! The transport is an in-memory pipe (no socket), so every allocation a window counts is the
//! library's or the test's own. The allocator counts every allocation made while a window is
//! open, keeps the part the calling thread made apart, and can fail one of them on request. A
//! test file includes this module and installs the allocator as its executable's own:
//!
//! ```text
//! #[path = "support/pipe_pair.rs"]
//! mod pipe_pair;
//! #[global_allocator]
//! static ALLOCATOR: pipe_pair::Injecting = pipe_pair::Injecting;
//! ```
//!
//! Each file uses the part of it its measurement needs.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::{c_char, c_void, CStr};
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
    WZ_EXT_LINK_GROUP, WZ_EXT_LINK_OK, WZ_EXT_LINK_STREAM_DIAL, WZ_EXT_LINK_STREAM_LISTEN,
    WZ_EXT_LINK_WOULD_BLOCK,
};
use wz_capi_pico::result::WZ_EXT_ERR_LINK_FULL;
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query,
    z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable,
    z_declare_subscriber, z_get, z_get_options_default, z_get_options_t, z_loaned_query_t,
    z_loaned_reply_t, z_loaned_sample_t, z_open, z_owned_bytes_t, z_owned_closure_query_t,
    z_owned_closure_reply_t, z_owned_closure_sample_t, z_owned_config_t, z_owned_queryable_t,
    z_owned_session_t, z_owned_subscriber_t, z_put, z_query_keyexpr, z_query_reply,
    z_queryable_move, z_queryable_options_default, z_queryable_options_t, z_reply_is_ok,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_subscriber_move,
    z_undeclare_queryable, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY,
    Z_CONFIG_MODE_KEY, Z_OK,
};

// ---------------------------------------------------------------------------------------------
// The allocator: every call counted, and one of them failed on request.

/// Allocations made and not yet freed, by every thread of the process.
pub(crate) static LIVE_ALLOCATIONS: AtomicIsize = AtomicIsize::new(0);
/// Whether a window is open: the allocations made while it is are counted, and one may fail.
static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);
/// Allocations made while the window was open, and the bytes they asked for.
static WINDOW_SEEN: AtomicU64 = AtomicU64::new(0);
static WINDOW_BYTES: AtomicU64 = AtomicU64::new(0);
/// The part of those the calling thread made (`mark_calling_thread`), and its bytes.
static WINDOW_CALLING_SEEN: AtomicU64 = AtomicU64::new(0);
static WINDOW_CALLING_BYTES: AtomicU64 = AtomicU64::new(0);
/// The allocation of the window that fails, counted from 1; 0 fails none.
static FAIL_AT: AtomicU64 = AtomicU64::new(0);
/// Whether the window's failing allocation was reached.
static FIRED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Whether this thread is the calling thread, whose allocations a window counts apart. A
    /// `const` initialisation of a type with no destructor, so reading it inside the allocator
    /// does not itself allocate.
    static CALLING: Cell<bool> = const { Cell::new(false) };
}

/// Count one allocation of `size` bytes; true when it is the one the window fails.
fn fails_here(size: usize) -> bool {
    if !WINDOW_OPEN.load(Ordering::SeqCst) {
        return false;
    }
    let n = WINDOW_SEEN.fetch_add(1, Ordering::SeqCst) + 1;
    WINDOW_BYTES.fetch_add(size as u64, Ordering::SeqCst);
    if CALLING.with(Cell::get) {
        WINDOW_CALLING_SEEN.fetch_add(1, Ordering::SeqCst);
        WINDOW_CALLING_BYTES.fetch_add(size as u64, Ordering::SeqCst);
    }
    if n == FAIL_AT.load(Ordering::SeqCst) {
        FIRED.store(true, Ordering::SeqCst);
        return true;
    }
    false
}

/// The allocator a test file installs as its executable's own (`#[global_allocator]`).
pub(crate) struct Injecting;

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

/// Count the allocations the thread that calls this makes while a window is open apart from every
/// other thread's (`Seen::calling_allocations`).
pub(crate) fn mark_calling_thread() {
    CALLING.with(|calling| calling.set(true));
}

/// Open the window, failing its `fail_at`-th allocation (none for 0).
pub(crate) fn open_window(fail_at: u64) {
    FIRED.store(false, Ordering::SeqCst);
    WINDOW_SEEN.store(0, Ordering::SeqCst);
    WINDOW_BYTES.store(0, Ordering::SeqCst);
    WINDOW_CALLING_SEEN.store(0, Ordering::SeqCst);
    WINDOW_CALLING_BYTES.store(0, Ordering::SeqCst);
    FAIL_AT.store(fail_at, Ordering::SeqCst);
    WINDOW_OPEN.store(true, Ordering::SeqCst);
}

/// What the window saw.
pub(crate) struct Seen {
    /// Allocations by every thread, and the bytes they asked for.
    pub(crate) allocations: u64,
    pub(crate) bytes: u64,
    /// The part of those the calling thread made.
    pub(crate) calling_allocations: u64,
    pub(crate) calling_bytes: u64,
    /// Whether the allocation the window was to fail was reached.
    pub(crate) fired: bool,
}

pub(crate) fn close_window() -> Seen {
    WINDOW_OPEN.store(false, Ordering::SeqCst);
    FAIL_AT.store(0, Ordering::SeqCst);
    Seen {
        allocations: WINDOW_SEEN.load(Ordering::SeqCst),
        bytes: WINDOW_BYTES.load(Ordering::SeqCst),
        calling_allocations: WINDOW_CALLING_SEEN.load(Ordering::SeqCst),
        calling_bytes: WINDOW_CALLING_BYTES.load(Ordering::SeqCst),
        fired: FIRED.load(Ordering::SeqCst),
    }
}

// ---------------------------------------------------------------------------------------------
// Every panic of the process, a library thread's included.

pub(crate) static PANICS: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn count_panics() {
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
pub(crate) const LISTEN: &CStr = c"tcp/192.0.2.100:7447";
/// The address the listening program accepts the dial under. Synthetic.
pub(crate) const ACCEPTED_REMOTE: &CStr = c"tcp/192.0.2.200:41000";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
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
pub(crate) struct Pipe {
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
            .name("pipe-pair".to_owned())
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

pub(crate) struct SideCtx {
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
pub(crate) fn make_transport(pipe: &Arc<Pipe>, side: Side) -> *mut wz_ext_owned_transport_t {
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
pub(crate) fn drop_transport(pipe: &Pipe, side: Side) {
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
pub(crate) struct Counts {
    /// Closures handed to the library, and the drops it ran of them.
    pub(crate) made: AtomicUsize,
    pub(crate) dropped: AtomicUsize,
    /// Samples the listening session's subscriber was handed.
    pub(crate) heard: AtomicUsize,
    /// Replies the gets were handed, and the gets the library declared over (their closure's
    /// drop, which comes once whatever the get's end).
    pub(crate) replies: AtomicUsize,
    pub(crate) gets_over: AtomicUsize,
}

impl Counts {
    fn balanced(&self) -> bool {
        self.made.load(Ordering::SeqCst) == self.dropped.load(Ordering::SeqCst)
    }
}

/// A closure context for `counts`, counted as made: the library owns it until it runs the drop.
pub(crate) fn context(counts: &Arc<Counts>) -> *mut c_void {
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
pub(crate) const ANSWER: &CStr = c"answer";

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
pub(crate) const DATA_KEY: &CStr = c"faults/data";
pub(crate) const ASK_KEY: &CStr = c"faults/ask";
pub(crate) const DECLARED_KEY: &CStr = c"faults/declared/**";

/// How long a run waits for what it waits for: a crossing, a get's end, a drop.
pub(crate) const WAIT_BOUND: Duration = Duration::from_secs(10);
/// A get's own timeout.
pub(crate) const GET_TIMEOUT_MS: u64 = 2_000;

pub(crate) unsafe fn view(key: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut ke, key.as_ptr()),
        Z_OK,
        "{key:?}"
    );
    ke
}

/// A config with `key` set to the pipe's locator, carrying `transport`.
pub(crate) unsafe fn config_over(
    key: u8,
    transport: *mut wz_ext_owned_transport_t,
) -> z_owned_config_t {
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

/// What a pair's sessions' configs are given besides the pipe, before they open.
pub(crate) type Shape = unsafe fn(&mut z_owned_config_t);

/// A config given nothing besides the pipe.
pub(crate) unsafe fn unshaped(_config: &mut z_owned_config_t) {}

pub(crate) unsafe fn open_over(
    key: u8,
    transport: *mut wz_ext_owned_transport_t,
) -> z_owned_session_t {
    open_over_shaped(key, transport, unshaped)
}

/// A session over the pipe whose config `shape` was handed first.
pub(crate) unsafe fn open_over_shaped(
    key: u8,
    transport: *mut wz_ext_owned_transport_t,
    shape: Shape,
) -> z_owned_session_t {
    let mut cfg = config_over(key, transport);
    shape(&mut cfg);
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "a session opens over the pipe"
    );
    session
}

pub(crate) unsafe fn close(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null());
    z_session_drop(z_session_move(&mut session));
}

/// The closure of a subscriber that counts what it hears.
pub(crate) unsafe fn sample_closure(counts: &Arc<Counts>) -> z_owned_closure_sample_t {
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
pub(crate) unsafe fn query_closure(counts: &Arc<Counts>) -> z_owned_closure_query_t {
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
pub(crate) unsafe fn reply_closure(counts: &Arc<Counts>) -> z_owned_closure_reply_t {
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

pub(crate) unsafe fn declare_subscriber(
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

pub(crate) unsafe fn declare_queryable(
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

pub(crate) unsafe fn put(session: &z_owned_session_t, payload: &mut z_owned_bytes_t) -> ZResult {
    let ke = view(DATA_KEY);
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        z_bytes_move(payload),
        std::ptr::null(),
    )
}

/// The bytes a put carries. Synthetic.
pub(crate) const PAYLOAD: [u8; 64] = [0x5A; 64];

pub(crate) unsafe fn payload() -> z_owned_bytes_t {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut bytes, PAYLOAD.as_ptr(), PAYLOAD.len()),
        Z_OK
    );
    bytes
}

pub(crate) unsafe fn get(
    session: &z_owned_session_t,
    closure: &mut z_owned_closure_reply_t,
) -> ZResult {
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
pub(crate) fn wait_for(within: Duration, done: impl Fn() -> bool) -> bool {
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
pub(crate) struct Pair {
    pub(crate) pipe: Arc<Pipe>,
    pub(crate) teller: JoinHandle<()>,
    pub(crate) dialling_transport: *mut wz_ext_owned_transport_t,
    pub(crate) counts: Arc<Counts>,
    pub(crate) listener: z_owned_session_t,
    pub(crate) subscriber: z_owned_subscriber_t,
    pub(crate) queryable: z_owned_queryable_t,
    pub(crate) dialler: Option<z_owned_session_t>,
}

impl Pair {
    /// The listening session and its entities, and the dialling session when `dial`: its
    /// route to the listener made (a put heard) and a get answered, so what a later call does is
    /// the call's own work and not the first exchange of a route.
    pub(crate) unsafe fn open(dial: bool) -> Self {
        Self::open_shaped(dial, unshaped)
    }

    /// As `open`, each session's config handed `shape` before it opens.
    pub(crate) unsafe fn open_shaped(dial: bool, shape: Shape) -> Self {
        let (pipe, teller) = Pipe::start();
        let counts = Arc::new(Counts::default());
        let listening_transport = make_transport(&pipe, Side::Listening);
        let dialling_transport = make_transport(&pipe, Side::Dialling);
        let listener = open_over_shaped(Z_CONFIG_LISTEN_KEY, listening_transport, shape);
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
            let dialler = open_over_shaped(Z_CONFIG_CONNECT_KEY, dialling_transport, shape);
            pair.dialler = Some(dialler);
            pair.converge();
        }
        pair
    }

    pub(crate) fn dialler(&self) -> &z_owned_session_t {
        self.dialler.as_ref().expect("the dialling session is open")
    }

    /// The listening session, which holds the subscriber and the queryable the dialler reaches.
    pub(crate) fn listener(&self) -> &z_owned_session_t {
        &self.listener
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
    pub(crate) unsafe fn close(self) -> (bool, bool) {
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
// Two sessions joined to one group over the program's transport.

/// The group both members join, a UDP group on an interface, which the program carries.
pub(crate) const GROUP: &CStr = c"udp/239.7.7.7:7447#iface=lan7";

/// Where each member's datagrams come from, as the other member hears them. Synthetic.
const MEMBER_SOURCES: [&CStr; 2] = [c"udp/192.0.2.10:7447", c"udp/192.0.2.11:7447"];

/// The group as the program carries it: each member's transport and its link to the group.
#[derive(Default)]
pub(crate) struct Group {
    /// Each member's owned transport, at a stable address, as an address; 0 once dropped.
    owned: [AtomicUsize; 2],
    /// Each member's group link, 0 while it has none.
    links: [AtomicU64; 2],
}

impl Group {
    fn loan(&self, member: usize) -> *const wz_ext_loaned_transport_t {
        match self
            .owned
            .get(member)
            .map_or(0, |owned| owned.load(Ordering::SeqCst))
        {
            0 => std::ptr::null(),
            raw => unsafe { wz_ext_transport_loan(raw as *const wz_ext_owned_transport_t) },
        }
    }
}

struct MemberCtx {
    group: Arc<Group>,
    member: usize,
}

unsafe fn member_ctx<'a>(context: *mut c_void) -> &'a MemberCtx {
    &*(context as *const MemberCtx)
}

unsafe extern "C" fn group_open(
    context: *mut c_void,
    link: wz_ext_link_t,
    kind: wz_ext_link_kind_t,
    locator: *const c_char,
) -> wz_ext_link_result_t {
    let ctx = member_ctx(context);
    if kind != WZ_EXT_LINK_GROUP || CStr::from_ptr(locator) != GROUP {
        return WZ_EXT_LINK_CLOSED;
    }
    ctx.group.links[ctx.member].store(link, Ordering::SeqCst);
    WZ_EXT_LINK_OK
}

/// A member's datagram is handed to the other member as one from the sender's address. Best
/// effort, as a datagram on a group is: one the other member cannot take now is lost.
unsafe extern "C" fn group_send(
    context: *mut c_void,
    link: wz_ext_link_t,
    data: *const u8,
    len: usize,
    written: *mut usize,
) -> wz_ext_link_result_t {
    let ctx = member_ctx(context);
    if ctx.group.links[ctx.member].load(Ordering::SeqCst) != link {
        return WZ_EXT_LINK_CLOSED;
    }
    let other = 1 - ctx.member;
    let peer = ctx.group.links[other].load(Ordering::SeqCst);
    if peer != 0 {
        let _ = wz_ext_transport_received(
            ctx.group.loan(other),
            peer,
            data,
            len,
            MEMBER_SOURCES[ctx.member].as_ptr(),
        );
    }
    *written = len;
    WZ_EXT_LINK_OK
}

unsafe extern "C" fn group_close(context: *mut c_void, link: wz_ext_link_t) {
    let ctx = member_ctx(context);
    let _ =
        ctx.group.links[ctx.member].compare_exchange(link, 0, Ordering::SeqCst, Ordering::SeqCst);
}

unsafe extern "C" fn group_drained(_context: *mut c_void, _link: wz_ext_link_t) {}

unsafe extern "C" fn group_drop(context: *mut c_void) {
    drop(Box::from_raw(context as *mut MemberCtx));
}

/// A member's transport over the group, owned at a stable address.
fn make_member_transport(group: &Arc<Group>, member: usize) -> *mut wz_ext_owned_transport_t {
    let context = Box::into_raw(Box::new(MemberCtx {
        group: Arc::clone(group),
        member,
    })) as *mut c_void;
    let calls = wz_ext_transport_t {
        context,
        open: Some(group_open),
        send: Some(group_send),
        close: Some(group_close),
        drained: Some(group_drained),
        drop: Some(group_drop),
    };
    let owned: *mut wz_ext_owned_transport_t =
        Box::into_raw(Box::new(unsafe { std::mem::zeroed() }));
    assert_eq!(unsafe { wz_ext_transport_new(owned, &calls) }, Z_OK);
    group.owned[member].store(owned as usize, Ordering::SeqCst);
    owned
}

/// A peer session joined to the group over `transport`.
unsafe fn open_member(transport: *mut wz_ext_owned_transport_t) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_MODE_KEY,
            c"peer".as_ptr()
        ),
        Z_OK
    );
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            GROUP.as_ptr()
        ),
        Z_OK
    );
    assert_eq!(
        wz_ext_config_transport(
            z_config_loan_mut(&mut cfg),
            wz_ext_transport_loan(transport)
        ),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "a member joins the group over the program's transport"
    );
    session
}

/// Two members of one group: the sender puts, and the receiver's subscriber counts what it hears.
pub(crate) struct GroupPair {
    group: Arc<Group>,
    pub(crate) counts: Arc<Counts>,
    sender: Option<z_owned_session_t>,
    receiver: Option<z_owned_session_t>,
    subscriber: z_owned_subscriber_t,
}

impl GroupPair {
    /// Both members joined and the receiver's subscriber declared, opened until a put of the
    /// sender's is heard: the receiver has admitted the sender by its JOIN.
    pub(crate) unsafe fn open() -> Self {
        let group = Arc::new(Group::default());
        let counts = Arc::new(Counts::default());
        let receiver = open_member(make_member_transport(&group, 1));
        let mut closure = sample_closure(&counts);
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            declare_subscriber(&receiver, DATA_KEY, &mut closure, &mut subscriber),
            Z_OK
        );
        let sender = open_member(make_member_transport(&group, 0));
        let pair = Self {
            group,
            counts,
            sender: Some(sender),
            receiver: Some(receiver),
            subscriber,
        };
        let deadline = Instant::now() + WAIT_BOUND;
        let heard = pair.counts.heard.load(Ordering::SeqCst);
        while pair.counts.heard.load(Ordering::SeqCst) == heard {
            assert!(
                Instant::now() < deadline,
                "no put crossed the group within {WAIT_BOUND:?}"
            );
            let mut bytes = payload();
            let _ = put(pair.sender(), &mut bytes);
            std::thread::sleep(Duration::from_millis(10));
        }
        pair
    }

    pub(crate) fn sender(&self) -> &z_owned_session_t {
        self.sender.as_ref().expect("the sending member is joined")
    }
}

impl Drop for GroupPair {
    fn drop(&mut self) {
        unsafe {
            let _ = z_undeclare_subscriber(z_subscriber_move(&mut self.subscriber));
            for session in [self.sender.take(), self.receiver.take()]
                .into_iter()
                .flatten()
            {
                close(session);
            }
            for member in 0..2 {
                let raw = self.group.owned[member].swap(0, Ordering::SeqCst);
                if raw != 0 {
                    let owned = raw as *mut wz_ext_owned_transport_t;
                    wz_ext_transport_drop(wz_ext_transport_move(owned));
                    drop(Box::from_raw(owned));
                }
            }
        }
    }
}
