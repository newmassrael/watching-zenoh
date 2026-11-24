// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What the pico C ABI on the cooperative engine allocates after a session opens, counted per
//! operation family.
//!
//! The target is a session that takes every byte it needs when it opens, from the configured
//! limits, and allocates nothing after (`docs/upstream-parity.md` D12). Two sessions open over
//! the program's own transport (an in-memory pipe, `support/pipe_pair.rs`), and once both are open
//! and their routes are made each operation family is counted in `WINDOWS` windows, each a warm-up
//! and then `ROUNDS` rounds with the allocator counting. A family that needs another pair (a group,
//! sessions opened with other settings) is counted on that pair, opened once the one before it is
//! closed (`Stage`). One line per family is printed:
//!
//! ```text
//! no-heap: <family> allocs=<n> bytes=<b> rounds=<r> windows=<k> max_allocs=<m>
//! no-heap: <family> not-built
//! ```
//!
//! `allocs` and `bytes` are the window that allocated least, `max_allocs` the window that
//! allocated most. The threads' interleaving (how many turns the receiving thread takes in a round,
//! what one round's messages leave for the next) only adds allocations to a window and never takes
//! away the ones the operation makes, so the least window is the operation's own cost and is what a
//! row grades; a row locked at 0 grades the most, since it claims no window allocates at all.
//!
//! With `WZ_NO_HEAP_READING` set, the lines are written to the file it names as well.
//!
//! With `WZ_NO_HEAP_SITES` set, each family is counted in one window of a few rounds and every
//! allocation of its counted rounds records its stack: one `no-heap-site:` line is printed per
//! round and site, the site being the innermost frame of a wz crate and the door the calling
//! thread entered, with the allocations a round made there. The family lines are not printed
//! then, since the records' own allocations fall in the windows; the gate reads no site line.
//! `scripts/lib/no_heap_ratchet_gate.py --check` holds those lines to `deploy/no_heap_ratchet.json`:
//! the allocations of a round may only fall, and a family that reached 0 stays there. Layer C1nh
//! builds and runs this file; its one test is `#[ignore]`d, so a default sweep does not count a
//! process it shares with other tests.
//!
//! Families that share a round are told apart by thread. Of a put round, the allocations of the
//! calling thread are the put's (the program's transport hands the bytes to the other session on
//! the sending thread, so its taking of them counts there too) and those of every other thread are
//! the subscriber's receiving and delivery; of a get round, the calling thread's are the get's and
//! every other thread's are the query's delivery, the queryable's reply and the reply's delivery.
//! Every other family counts every thread.
//!
//! A family counted over every thread reads what the operation caused only if the sessions'
//! own threads allocate nothing while no call is made: a read task that allocated on each of
//! its turns would add to a round whatever turns the round happened to take, which the host's
//! load and the threads' interleaving decide. The `idle` family holds that: its round is
//! `IDLE_SLICE` with no call made, every thread counted, and it reads 0 when a turn of the
//! sessions' loops allocates nothing.
//!
//! The allocator is installed as this executable's own (`#[global_allocator]`), which is why the
//! file is an executable of its own. A build with the tokio engine runs its sessions there and is
//! not the cooperative engine's, so it compiles none of this file.

#![cfg(not(feature = "engine-tokio"))]

use std::alloc::{GlobalAlloc, Layout};
use std::backtrace::Backtrace;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use wz_capi_pico::abi::z_owned_keyexpr_t;
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_move, z_declare_keyexpr, z_declare_publisher,
    z_encoding_from_str, z_encoding_move, z_keyexpr_move, z_owned_bytes_t, z_owned_encoding_t,
    z_owned_publisher_t, z_publisher_move, z_put, z_put_options_default, z_put_options_t,
    z_session_loan, z_timestamp_new, z_timestamp_t, z_undeclare_keyexpr, z_undeclare_publisher,
    z_view_keyexpr_loan, Z_OK,
};

#[path = "support/pipe_pair.rs"]
mod pipe_pair;

#[cfg(feature = "multicast-transport")]
use pipe_pair::GroupPair;
use pipe_pair::{
    close_window, count_panics, get, mark_calling_thread, open_window, payload, put, reply_closure,
    view, wait_for, Injecting, Pair, Seen, DATA_KEY, PANICS, WAIT_BOUND,
};

#[global_allocator]
static ALLOCATOR: Sited = Sited;

// ---------------------------------------------------------------------------------------------
// Where the allocations are made, recorded when `WZ_NO_HEAP_SITES` is set.

/// The variable that asks where each counted allocation is made, as well as how many there are.
const SITES_VARIABLE: &str = "WZ_NO_HEAP_SITES";
/// The prefix of a line that says where a round's allocations are made; the gate reads none.
const SITE_PREFIX: &str = "no-heap-site:";
/// The rounds a family is counted in, in one window, when its sites are recorded: a record
/// captures the stack of every allocation, which takes far longer than the allocation.
const SITE_ROUNDS: usize = 3;
/// No round's counted rounds are running.
const NO_ROUND: usize = usize::MAX;

/// Whether the sites are recorded.
static SITES_ON: AtomicBool = AtomicBool::new(false);
/// The round whose counted rounds are running, as its place in `Round::ALL`, or `NO_ROUND`.
static SITE_ROUND: AtomicUsize = AtomicUsize::new(NO_ROUND);
/// The stack of each recorded allocation and the place of its round, read only once every round
/// has run: reading a stack's symbols takes far longer than capturing it, and a round that took
/// that long would not see its traffic cross within the wait.
static SITES: Mutex<Vec<(usize, Backtrace)>> = Mutex::new(Vec::new());

thread_local! {
    /// Whether this thread is recording a site, whose own allocations are not recorded. A `const`
    /// initialisation of a type with no destructor, so reading it inside the allocator does not
    /// itself allocate.
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}

/// The pair's counting allocator, which also records where each allocation of a counted round
/// is made when the sites are asked for.
struct Sited;

// SAFETY: every call is forwarded to the pair's allocator unchanged; a record only reads the
// stack and writes this file's own table.
unsafe impl GlobalAlloc for Sited {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_site();
        unsafe { Injecting.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_site();
        unsafe { Injecting.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { Injecting.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_site();
        unsafe { Injecting.realloc(ptr, layout, new_size) }
    }
}

/// Record where the allocation being made is, when the sites are asked for and a round's counted
/// rounds are running. The record's own allocations are not recorded.
fn record_site() {
    if !SITES_ON.load(Ordering::Relaxed) {
        return;
    }
    let round = SITE_ROUND.load(Ordering::Relaxed);
    if round == NO_ROUND || RECORDING.with(Cell::get) {
        return;
    }
    RECORDING.with(|recording| recording.set(true));
    let stack = Backtrace::force_capture();
    SITES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((round, stack));
    RECORDING.with(|recording| recording.set(false));
}

/// A frame's symbol with the `<` of a trait implementation's path taken off.
fn bare(symbol: &str) -> &str {
    symbol.trim_start_matches('<')
}

/// Where an allocation was made, read off its stack: the innermost frame of a wz crate, with its
/// place in the source where the stack has one, and the outermost frame of the library, which on
/// the calling thread is the door the program called.
fn site_of(stack: &str) -> String {
    let mut frames: Vec<(&str, Option<&str>)> = Vec::new();
    for line in stack.lines().map(str::trim) {
        if let Some(at) = line.strip_prefix("at ") {
            if let Some(last) = frames.last_mut() {
                last.1.get_or_insert(at);
            }
        } else if let Some((index, symbol)) = line.split_once(": ") {
            if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) {
                frames.push((symbol, None));
            }
        }
    }
    let inner = frames
        .iter()
        .find(|(symbol, _)| bare(symbol).starts_with("wz_"));
    let door = frames
        .iter()
        .rev()
        .find(|(symbol, _)| bare(symbol).starts_with("wz_capi_pico::"));
    let place = |at: &Option<&str>| {
        at.map(|at| {
            at.rsplit_once("crates/")
                .map_or(at, |(_, rest)| rest)
                .to_owned()
        })
        .unwrap_or_default()
    };
    match (inner, door) {
        (Some((symbol, at)), Some((door, _))) => format!("{symbol} [{}] <- {door}", place(at)),
        (Some((symbol, at)), None) => format!("{symbol} [{}]", place(at)),
        (None, _) => String::from("(no wz frame)"),
    }
}

/// The rounds of a window: fewer when the sites are recorded.
fn rounds() -> usize {
    if SITES_ON.load(Ordering::Relaxed) {
        SITE_ROUNDS
    } else {
        ROUNDS
    }
}

/// The windows of a family: one when the sites are recorded.
fn windows() -> usize {
    if SITES_ON.load(Ordering::Relaxed) {
        1
    } else {
        WINDOWS
    }
}

/// Rounds of each family run before the count, so that what the library makes on the first
/// exchanges (a route, a buffer grown to its size) is made, and rounds counted.
const WARM_UP: usize = 20;
const ROUNDS: usize = 100;
/// The windows a family is counted in.
const WINDOWS: usize = 5;
/// How long the sessions are left before a window opens, so that what the warm-up started on
/// another thread has ended, and before it closes, so that what its own rounds started is counted
/// in it rather than lost from it, which would let a window read below the operation's cost.
const SETTLE: Duration = Duration::from_millis(100);
/// The prefix of every line the gate reads.
const PREFIX: &str = "no-heap:";
/// The variable that names a file the lines are written to as well, which the lane hands the gate.
const READING_VARIABLE: &str = "WZ_NO_HEAP_READING";

/// A key a declaration under count names, and none of the pair's own entities matches. Synthetic.
const DECLARED: &CStr = c"noheap/declared";

/// The encoding a put of the `put-encoded` family carries: a known id and a schema, which the put
/// carries on the wire. Synthetic.
const ENCODED: &CStr = c"text/plain;utf8";

/// One round of the `idle` family: this long with no call made.
const IDLE_SLICE: Duration = Duration::from_millis(10);

/// The room a put near the batch limit leaves for the frame and message headers around its
/// payload, so that the payload with them fits one batch of the build.
const BATCH_HEADROOM: usize = 64;

/// What a family's rounds do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Round {
    Idle,
    PublisherDeclare,
    PutSmall,
    PutBatch,
    Get,
    KeyexprDeclare,
    LivelinessToken,
    LivelinessGet,
    E2e,
    Replay,
    ConfigDocument,
    SubscriberDeclare,
    QueryableDeclare,
    MatchingListener,
    LivelinessSubscriber,
    QuerierDeclare,
    QuerierGet,
    ConfigClone,
    PublisherPut,
    Delete,
    PutEncoded,
    PutTimestamped,
    AdvancedPut,
    AdvancedHistory,
    GroupReceive,
    TransportEventsListener,
    E2eSenderDemux,
    E2eSupervision,
    InstanceKey,
    MessagePayload,
    SharedKeyIds,
}

impl Round {
    /// Every round, in the order they are counted.
    const ALL: [Round; 31] = [
        Round::Idle,
        Round::PublisherDeclare,
        Round::PutSmall,
        Round::PutBatch,
        Round::Get,
        Round::KeyexprDeclare,
        Round::LivelinessToken,
        Round::LivelinessGet,
        Round::E2e,
        Round::Replay,
        Round::ConfigDocument,
        Round::SubscriberDeclare,
        Round::QueryableDeclare,
        Round::MatchingListener,
        Round::LivelinessSubscriber,
        Round::QuerierDeclare,
        Round::QuerierGet,
        Round::ConfigClone,
        Round::PublisherPut,
        Round::Delete,
        Round::PutEncoded,
        Round::PutTimestamped,
        Round::AdvancedPut,
        Round::AdvancedHistory,
        Round::GroupReceive,
        Round::TransportEventsListener,
        Round::E2eSenderDemux,
        Round::E2eSupervision,
        Round::InstanceKey,
        Round::MessagePayload,
        Round::SharedKeyIds,
    ];

    /// The stage whose pair the round calls through.
    fn stage(self) -> Stage {
        match self {
            Round::GroupReceive => Stage::Group,
            Round::SharedKeyIds => Stage::SharedKeyIds,
            _ => Stage::Pipe,
        }
    }

    /// Whether the build has the capability the round exercises.
    fn built(self) -> bool {
        match self {
            Round::LivelinessToken => cfg!(feature = "liveliness"),
            Round::LivelinessGet => cfg!(feature = "liveliness-get"),
            Round::E2e => cfg!(all(feature = "e2e-sender", feature = "e2e-receiver")),
            Round::Replay => cfg!(feature = "replay-cache"),
            Round::ConfigDocument => cfg!(feature = "config-document"),
            Round::QueryableDeclare => cfg!(feature = "queryable"),
            Round::LivelinessSubscriber => cfg!(feature = "liveliness"),
            Round::QuerierDeclare | Round::QuerierGet => cfg!(feature = "query"),
            Round::AdvancedPut | Round::AdvancedHistory => cfg!(feature = "advanced"),
            Round::GroupReceive => cfg!(feature = "multicast-transport"),
            Round::TransportEventsListener => cfg!(feature = "connectivity"),
            Round::E2eSenderDemux => {
                cfg!(all(feature = "e2e-sender", feature = "e2e-sender-demux"))
            }
            Round::E2eSupervision => cfg!(feature = "e2e-supervision"),
            Round::MessagePayload => cfg!(feature = "message-payload"),
            Round::SharedKeyIds => cfg!(feature = "shared-key-ids"),
            Round::InstanceKey => {
                cfg!(all(
                    feature = "instance-key",
                    feature = "e2e-sender",
                    feature = "e2e-receiver"
                ))
            }
            Round::Idle
            | Round::PublisherDeclare
            | Round::PutSmall
            | Round::PutBatch
            | Round::Get
            | Round::KeyexprDeclare
            | Round::SubscriberDeclare
            | Round::MatchingListener
            | Round::ConfigClone
            | Round::PublisherPut
            | Round::Delete
            | Round::PutEncoded
            | Round::PutTimestamped => true,
        }
    }
}

/// Which allocations of its round a family counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    /// Every thread's.
    All,
    /// The calling thread's.
    Calling,
    /// Every thread's but the calling one's.
    Others,
}

/// The operation families the gate holds, each named as `deploy/no_heap_ratchet.json` names it.
const FAMILIES: [(&str, Round, Part); 35] = [
    ("idle", Round::Idle, Part::All),
    ("publisher-declare", Round::PublisherDeclare, Part::All),
    ("put-small", Round::PutSmall, Part::Calling),
    ("subscriber-receive-small", Round::PutSmall, Part::Others),
    ("put-batch", Round::PutBatch, Part::Calling),
    ("subscriber-receive-batch", Round::PutBatch, Part::Others),
    ("get", Round::Get, Part::Calling),
    ("queryable-reply", Round::Get, Part::Others),
    ("keyexpr-declare", Round::KeyexprDeclare, Part::All),
    ("liveliness-token", Round::LivelinessToken, Part::All),
    ("liveliness-get", Round::LivelinessGet, Part::All),
    ("e2e", Round::E2e, Part::All),
    ("replay", Round::Replay, Part::All),
    ("config-document", Round::ConfigDocument, Part::All),
    ("subscriber-declare", Round::SubscriberDeclare, Part::All),
    ("queryable-declare", Round::QueryableDeclare, Part::All),
    ("matching-listener", Round::MatchingListener, Part::All),
    (
        "liveliness-subscriber",
        Round::LivelinessSubscriber,
        Part::All,
    ),
    ("querier-declare", Round::QuerierDeclare, Part::All),
    ("querier-get", Round::QuerierGet, Part::Calling),
    ("config-clone", Round::ConfigClone, Part::All),
    ("publisher-put", Round::PublisherPut, Part::Calling),
    ("delete", Round::Delete, Part::Calling),
    ("put-encoded", Round::PutEncoded, Part::Calling),
    ("put-timestamped", Round::PutTimestamped, Part::Calling),
    ("advanced-put", Round::AdvancedPut, Part::Calling),
    (
        "advanced-subscriber-receive",
        Round::AdvancedPut,
        Part::Others,
    ),
    (
        "advanced-subscriber-history",
        Round::AdvancedHistory,
        Part::All,
    ),
    // What a group member's receive takes: the datagram read where it lies and handed to the
    // subscriber, on the receiving member's threads.
    ("group-receive", Round::GroupReceive, Part::Others),
    (
        "transport-events-listener",
        Round::TransportEventsListener,
        Part::All,
    ),
    ("e2e-sender-demux", Round::E2eSenderDemux, Part::All),
    ("e2e-supervision", Round::E2eSupervision, Part::All),
    ("instance-key", Round::InstanceKey, Part::All),
    ("message-payload", Round::MessagePayload, Part::All),
    // A put by a key's shared id and its reading by the listener that holds the dictionary, on
    // sessions opened with it.
    ("shared-key-ids", Round::SharedKeyIds, Part::All),
];

/// The allocations and bytes of `part` of what a window saw.
fn part_of(seen: &Seen, part: Part) -> (u64, u64) {
    match part {
        Part::All => (seen.allocations, seen.bytes),
        Part::Calling => (seen.calling_allocations, seen.calling_bytes),
        Part::Others => (
            seen.allocations - seen.calling_allocations,
            seen.bytes - seen.calling_bytes,
        ),
    }
}

/// The allocations and bytes of `part` in the window of `windows` that allocated least (of two as
/// few, the one of fewer bytes), and the allocations of the window that allocated most.
fn reading_of(windows: &[Seen], part: Part) -> (u64, u64, u64) {
    let counts = windows.iter().map(|seen| part_of(seen, part));
    let (allocs, bytes) = counts.clone().min().expect("a family has a window");
    let most = counts.map(|(n, _)| n).max().unwrap_or(allocs);
    (allocs, bytes, most)
}

// ---------------------------------------------------------------------------------------------
// The capabilities beyond the pair's own, set up once before their rounds.

/// The key the listening session holds a token on, which a liveliness get finds. Synthetic.
#[cfg(feature = "liveliness-get")]
const ALIVE: &CStr = c"noheap/alive";

/// A two-byte counter last, a 16-bit CRC over the header and the payload, an identifier split in
/// two and XORed with a constant, and a cell whose sender part is derived from the address. Synthetic.
#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
const E2E_PROFILE: &str = r#"{
  "name": "no-heap-demo",
  "fields": [
    {"name": "length", "bytes": 2},
    {"name": "ident", "bytes": 3, "xor": "0x3C3C3C",
     "split": [{"name": "app", "lsb": 12, "width": 12}, {"name": "msg", "lsb": 0, "width": 12}]},
    {"name": "crc", "bytes": 2},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "kind", "lsb": 28, "width": 4},
               {"name": "sender", "lsb": 0, "width": 28,
                "derive": {"from": "address", "mask": "0x0F00FF00", "xor": "0x77"}}]},
    {"name": "counter", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["length", "ident", "cell", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 2, "timeout_ms": 50},
  "judge": {"ident": "ident", "length": true},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"#;

/// The values the sender writes and the receiver expects. Synthetic.
#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
const E2E_VALUES: &str =
    r#"{"ident": {"app": 801, "msg": 99}, "cell": {"kind": 5}, "@address": 201986612}"#;

/// The room of a protected frame: the profile's thirteen header bytes and the payload.
#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
const E2E_FRAME_ROOM: usize = 64;

/// A sender and a receiver of one profile, and the clock the receiver judges by.
#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
struct E2e {
    sender: wz_capi_pico::e2e_sender::wz_ext_owned_e2e_sender_t,
    receiver: wz_capi_pico::e2e_receiver::wz_ext_owned_e2e_receiver_t,
    now_ms: u64,
}

#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
impl E2e {
    /// The pair whose receiver keeps one stream, named by the caller.
    unsafe fn new() -> Self {
        Self::judged_under(std::ptr::null())
    }

    /// The pair whose receiver keeps one slot per sender, taken by the first intact frame of a
    /// sender: the profile's cell carries the sender identity the slot is keyed by.
    #[cfg(feature = "e2e-sender-demux")]
    unsafe fn sender_keyed() -> Self {
        use wz_capi_pico::e2e_receiver::{
            wz_ext_e2e_receiver_options_default, wz_ext_e2e_receiver_options_t,
            WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL,
        };
        let mut options: wz_ext_e2e_receiver_options_t = std::mem::zeroed();
        wz_ext_e2e_receiver_options_default(&mut options);
        options.keying = WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL;
        options.streams = 1;
        Self::judged_under(&options)
    }

    /// A sender and a receiver of the synthetic profile, the receiver made under `options` (null:
    /// the defaults).
    unsafe fn judged_under(
        options: *const wz_capi_pico::e2e_receiver::wz_ext_e2e_receiver_options_t,
    ) -> Self {
        use wz_capi_pico::e2e_receiver::wz_ext_e2e_receiver_new;
        use wz_capi_pico::e2e_sender::wz_ext_e2e_sender_new;
        let profile = std::ffi::CString::new(E2E_PROFILE).expect("no NUL in the profile");
        let values = std::ffi::CString::new(E2E_VALUES).expect("no NUL in the values");
        let mut e2e = Self {
            sender: std::mem::zeroed(),
            receiver: std::mem::zeroed(),
            now_ms: 0,
        };
        assert_eq!(
            wz_ext_e2e_sender_new(
                &mut e2e.sender,
                profile.as_ptr(),
                values.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "the sender of the synthetic profile is made"
        );
        assert_eq!(
            wz_ext_e2e_receiver_new(
                &mut e2e.receiver,
                profile.as_ptr(),
                values.as_ptr(),
                options,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "the receiver of the synthetic profile is made"
        );
        e2e
    }

    /// Protect one payload and judge the frame.
    unsafe fn round(&mut self) {
        use wz_capi_pico::e2e_receiver::{
            wz_ext_e2e_receiver_judge, wz_ext_e2e_receiver_loan, wz_ext_e2e_verdict_t,
            WZ_EXT_E2E_FIRST, WZ_EXT_E2E_OK,
        };
        use wz_capi_pico::e2e_sender::{wz_ext_e2e_sender_loan, wz_ext_e2e_sender_protect};
        let payload = [0xA5u8; 16];
        let mut frame = [0u8; E2E_FRAME_ROOM];
        let mut written = 0usize;
        assert_eq!(
            wz_ext_e2e_sender_protect(
                wz_ext_e2e_sender_loan(&self.sender),
                0,
                payload.as_ptr(),
                payload.len(),
                frame.as_mut_ptr(),
                frame.len(),
                &mut written,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a payload is protected"
        );
        self.now_ms += 1;
        let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_e2e_receiver_judge(
                wz_ext_e2e_receiver_loan(&self.receiver),
                0,
                frame.as_ptr(),
                written,
                self.now_ms,
                &mut verdict,
            ),
            Z_OK,
            "a frame is judged"
        );
        assert!(
            verdict.status == WZ_EXT_E2E_OK || verdict.status == WZ_EXT_E2E_FIRST,
            "a frame protected in order is judged in order: {verdict:?}"
        );
    }

    unsafe fn drop_both(mut self) {
        use wz_capi_pico::e2e_receiver::{wz_ext_e2e_receiver_drop, wz_ext_e2e_receiver_move};
        use wz_capi_pico::e2e_sender::{wz_ext_e2e_sender_drop, wz_ext_e2e_sender_move};
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut self.sender));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut self.receiver));
    }
}

/// The schema of the message whose instances a keyer reads. Synthetic.
#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
const INSTANCE_SCHEMA: &CStr = cr#"
syntax = "proto3";
package syn.noheap;
message Reading {
  optional uint32 bay = 1;
  sint32 tilt = 2;
  bytes body = 3;
}
"#;

/// Three bays and two tilts: six instances, the tilt varying fastest. Synthetic.
#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
const INSTANCE_DESCRIPTION: &CStr = cr#"{
  "message": "syn.noheap.Reading",
  "fields": [
    {"path": "bay", "values": [12, 30, 44]},
    {"path": "tilt", "values": [-3, 5]}
  ],
  "report_interval_ms": 1000
}"#;

/// How many instances `INSTANCE_DESCRIPTION` makes: the streams the sender and the receiver keep.
#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
const INSTANCES: usize = 6;

/// A reading of bay 12 and tilt -3 (zigzagged to 5), with a body of one byte: instance 0, laid by
/// hand.
#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
const INSTANCE_PAYLOAD: [u8; 7] = [0x08, 0x0C, 0x10, 0x05, 0x1A, 0x01, 0x61];

/// A keyer at each end of a message whose instances are streams of the end-to-end doors: the
/// sending one protects a payload on its instance's counter, the receiving one judges the frame
/// in its instance's stream.
#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
struct Keyed {
    sending: wz_capi_pico::instance_key::wz_ext_owned_instance_keyer_t,
    receiving: wz_capi_pico::instance_key::wz_ext_owned_instance_keyer_t,
    sender: wz_capi_pico::e2e_sender::wz_ext_owned_e2e_sender_t,
    receiver: wz_capi_pico::e2e_receiver::wz_ext_owned_e2e_receiver_t,
    now_ms: u64,
}

#[cfg(all(
    feature = "instance-key",
    feature = "e2e-sender",
    feature = "e2e-receiver"
))]
impl Keyed {
    unsafe fn new() -> Self {
        use wz_capi_pico::e2e_receiver::{
            wz_ext_e2e_receiver_new, wz_ext_e2e_receiver_options_default,
            wz_ext_e2e_receiver_options_t,
        };
        use wz_capi_pico::e2e_sender::{
            wz_ext_e2e_sender_new, wz_ext_e2e_sender_options_default, wz_ext_e2e_sender_options_t,
        };
        let profile = std::ffi::CString::new(E2E_PROFILE).expect("no NUL in the profile");
        let values = std::ffi::CString::new(E2E_VALUES).expect("no NUL in the values");
        let mut keyed = Self {
            sending: Self::keyer(),
            receiving: Self::keyer(),
            sender: std::mem::zeroed(),
            receiver: std::mem::zeroed(),
            now_ms: 0,
        };
        let mut sending: wz_ext_e2e_sender_options_t = std::mem::zeroed();
        wz_ext_e2e_sender_options_default(&mut sending);
        sending.streams = INSTANCES;
        assert_eq!(
            wz_ext_e2e_sender_new(
                &mut keyed.sender,
                profile.as_ptr(),
                values.as_ptr(),
                &sending,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a sender of a stream per instance is made"
        );
        let mut receiving: wz_ext_e2e_receiver_options_t = std::mem::zeroed();
        wz_ext_e2e_receiver_options_default(&mut receiving);
        receiving.streams = INSTANCES;
        assert_eq!(
            wz_ext_e2e_receiver_new(
                &mut keyed.receiver,
                profile.as_ptr(),
                values.as_ptr(),
                &receiving,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a receiver of a stream per instance is made"
        );
        keyed
    }

    /// A keyer of `INSTANCE_DESCRIPTION` over `INSTANCE_SCHEMA`, keeping no last values.
    unsafe fn keyer() -> wz_capi_pico::instance_key::wz_ext_owned_instance_keyer_t {
        use wz_capi_pico::instance_key::wz_ext_instance_keyer_new;
        use wz_capi_pico::proto_file::wz_ext_proto_file_t;
        let files = [wz_ext_proto_file_t {
            name: c"syn/noheap.proto".as_ptr(),
            text: INSTANCE_SCHEMA.as_ptr(),
        }];
        let mut keyer: wz_capi_pico::instance_key::wz_ext_owned_instance_keyer_t =
            std::mem::zeroed();
        assert_eq!(
            wz_ext_instance_keyer_new(
                &mut keyer,
                files.as_ptr(),
                files.len(),
                INSTANCE_DESCRIPTION.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a keyer of the synthetic schema is made"
        );
        keyer
    }

    /// Protect the payload on its instance's stream and judge the frame in the same instance's.
    unsafe fn round(&mut self) {
        use wz_capi_pico::e2e_receiver::{
            wz_ext_e2e_receiver_loan, wz_ext_e2e_verdict_t, WZ_EXT_E2E_FIRST, WZ_EXT_E2E_OK,
        };
        use wz_capi_pico::e2e_sender::wz_ext_e2e_sender_loan;
        use wz_capi_pico::instance_key::{
            wz_ext_instance_key_t, wz_ext_instance_keyer_judge, wz_ext_instance_keyer_loan,
            wz_ext_instance_keyer_protect, WZ_EXT_INSTANCE_KEY_INDEXED,
        };
        let mut frame = [0u8; E2E_FRAME_ROOM];
        let mut written = 0usize;
        let mut key: wz_ext_instance_key_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_instance_keyer_protect(
                wz_ext_instance_keyer_loan(&self.sending),
                wz_ext_e2e_sender_loan(&self.sender),
                INSTANCE_PAYLOAD.as_ptr(),
                INSTANCE_PAYLOAD.len(),
                self.now_ms,
                frame.as_mut_ptr(),
                frame.len(),
                &mut written,
                std::ptr::null_mut(),
                &mut key,
            ),
            Z_OK,
            "a payload is protected on its instance's stream"
        );
        assert_eq!((key.status, key.instance), (WZ_EXT_INSTANCE_KEY_INDEXED, 0));
        self.now_ms += 1;
        let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_instance_keyer_judge(
                wz_ext_instance_keyer_loan(&self.receiving),
                wz_ext_e2e_receiver_loan(&self.receiver),
                frame.as_ptr(),
                written,
                self.now_ms,
                &mut key,
                &mut verdict,
            ),
            Z_OK,
            "a frame is judged in its instance's stream"
        );
        assert_eq!((key.status, key.instance), (WZ_EXT_INSTANCE_KEY_INDEXED, 0));
        assert!(
            verdict.status == WZ_EXT_E2E_OK || verdict.status == WZ_EXT_E2E_FIRST,
            "a frame protected in order is judged in order: {verdict:?}"
        );
    }

    unsafe fn drop_all(mut self) {
        use wz_capi_pico::e2e_receiver::{wz_ext_e2e_receiver_drop, wz_ext_e2e_receiver_move};
        use wz_capi_pico::e2e_sender::{wz_ext_e2e_sender_drop, wz_ext_e2e_sender_move};
        use wz_capi_pico::instance_key::{wz_ext_instance_keyer_drop, wz_ext_instance_keyer_move};
        wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&mut self.sending));
        wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&mut self.receiving));
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut self.sender));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut self.receiver));
    }
}

/// A catalog the payloads are of: the catalog reader's synthetic one, whose first message is put on
/// `demo/catalog/pose`.
#[cfg(feature = "message-payload")]
const CATALOG: &str = include_str!("../../wz-app-frame/catalog/synthetic.json5");

/// The schema of the catalog message's payload. Synthetic.
#[cfg(feature = "message-payload")]
const PAYLOAD_SCHEMA: &CStr = cr#"
syntax = "proto3";
package syn.noheap;
message Point {
  sint32 x = 1;
  sint32 y = 2;
}
message Pose {
  uint32 serial = 1;
  int32 offset = 2;
  string label = 5;
  Point origin = 8;
}
"#;

/// The room the encoded payload of a round takes, with headroom.
#[cfg(feature = "message-payload")]
const PAYLOAD_ROOM: usize = 64;

/// Two payloads of the catalog's first message under one schema, as a sending and a receiving
/// program hold them: one set by path and encoded, the other decoded and read back.
#[cfg(feature = "message-payload")]
struct MessagePayload {
    sending: wz_capi_pico::message_payload::wz_ext_owned_message_payload_t,
    receiving: wz_capi_pico::message_payload::wz_ext_owned_message_payload_t,
    serial: u64,
}

#[cfg(feature = "message-payload")]
impl MessagePayload {
    /// Both payloads. The catalog and the schema are dropped once they are made: a payload keeps
    /// its key expression and holds its schema.
    unsafe fn new() -> Self {
        use wz_capi_pico::message_catalog::{
            wz_ext_message_catalog_drop, wz_ext_message_catalog_move, wz_ext_message_catalog_new,
            wz_ext_owned_message_catalog_t,
        };
        use wz_capi_pico::message_payload::{
            wz_ext_owned_payload_schema_t, wz_ext_payload_schema_drop, wz_ext_payload_schema_move,
            wz_ext_payload_schema_new,
        };
        use wz_capi_pico::proto_file::wz_ext_proto_file_t;
        let text = std::ffi::CString::new(CATALOG).expect("no NUL in the catalog");
        let mut catalog: wz_ext_owned_message_catalog_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_message_catalog_new(&mut catalog, text.as_ptr(), std::ptr::null_mut()),
            Z_OK,
            "the synthetic catalog reads"
        );
        let files = [wz_ext_proto_file_t {
            name: c"syn/noheap.proto".as_ptr(),
            text: PAYLOAD_SCHEMA.as_ptr(),
        }];
        let mut schema: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_payload_schema_new(
                &mut schema,
                files.as_ptr(),
                files.len(),
                std::ptr::null_mut()
            ),
            Z_OK,
            "the synthetic schema reads"
        );
        let payload = Self {
            sending: Self::payload(&catalog, &schema),
            receiving: Self::payload(&catalog, &schema),
            serial: 0,
        };
        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(&mut schema));
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&mut catalog));
        payload
    }

    /// A payload of the catalog's first message, of type `syn.noheap.Pose`.
    unsafe fn payload(
        catalog: &wz_capi_pico::message_catalog::wz_ext_owned_message_catalog_t,
        schema: &wz_capi_pico::message_payload::wz_ext_owned_payload_schema_t,
    ) -> wz_capi_pico::message_payload::wz_ext_owned_message_payload_t {
        use wz_capi_pico::message_catalog::wz_ext_message_catalog_loan;
        use wz_capi_pico::message_payload::{
            wz_ext_message_payload_new, wz_ext_owned_message_payload_t, wz_ext_payload_schema_loan,
        };
        let mut payload: wz_ext_owned_message_payload_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_message_payload_new(
                &mut payload,
                wz_ext_message_catalog_loan(catalog),
                0,
                wz_ext_payload_schema_loan(schema),
                c"syn.noheap.Pose".as_ptr(),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a payload of the catalog's first message is made"
        );
        payload
    }

    /// Set two values by path, encode the payload, decode the bytes into the other and read the
    /// serial back.
    unsafe fn round(&mut self) {
        use wz_capi_pico::message_payload::{
            wz_ext_message_payload_decode, wz_ext_message_payload_encode,
            wz_ext_message_payload_get_uint, wz_ext_message_payload_loan,
            wz_ext_message_payload_set_int, wz_ext_message_payload_set_uint,
        };
        self.serial += 1;
        let sending = wz_ext_message_payload_loan(&self.sending);
        assert_eq!(
            wz_ext_message_payload_set_uint(sending, c"serial".as_ptr(), self.serial),
            Z_OK
        );
        assert_eq!(
            wz_ext_message_payload_set_int(sending, c"origin.x".as_ptr(), -3),
            Z_OK
        );
        let mut bytes = [0u8; PAYLOAD_ROOM];
        let mut written = 0usize;
        assert_eq!(
            wz_ext_message_payload_encode(sending, bytes.as_mut_ptr(), bytes.len(), &mut written),
            Z_OK,
            "the payload encodes into the room"
        );
        let receiving = wz_ext_message_payload_loan(&self.receiving);
        assert_eq!(
            wz_ext_message_payload_decode(receiving, bytes.as_ptr(), written),
            Z_OK,
            "the bytes decode"
        );
        let mut serial = 0u64;
        assert_eq!(
            wz_ext_message_payload_get_uint(receiving, c"serial".as_ptr(), &mut serial),
            Z_OK
        );
        assert_eq!(serial, self.serial, "the serial set is the serial read");
    }

    unsafe fn drop_both(mut self) {
        use wz_capi_pico::message_payload::{
            wz_ext_message_payload_drop, wz_ext_message_payload_move,
        };
        wz_ext_message_payload_drop(wz_ext_message_payload_move(&mut self.sending));
        wz_ext_message_payload_drop(wz_ext_message_payload_move(&mut self.receiving));
    }
}

/// The streams a supervisor's table has room for, and the bytes each keeps of its last payload.
#[cfg(feature = "e2e-supervision")]
const SUPERVISED_STREAMS: usize = 4;
#[cfg(feature = "e2e-supervision")]
const SUPERVISED_CELL: usize = 16;

/// A reception supervisor over the program's storage with one stream added, as a receiver of a
/// periodic message holds one: each round is a reception of the stream and a poll.
#[cfg(feature = "e2e-supervision")]
struct Supervision {
    supervisor: wz_capi_pico::stream_supervision::wz_ext_owned_stream_supervisor_t,
    /// The table and the value cells, which the supervisor owns until it is dropped.
    slots: Vec<wz_capi_pico::stream_supervision::wz_ext_stream_slot_t>,
    values: Vec<u8>,
    stream: u32,
}

#[cfg(feature = "e2e-supervision")]
impl Supervision {
    unsafe fn new() -> Self {
        use wz_capi_pico::stream_supervision::{
            wz_ext_stream_slot_t, wz_ext_stream_supervisor_add, wz_ext_stream_supervisor_loan,
            wz_ext_stream_supervisor_new,
        };
        let mut supervision = Self {
            supervisor: std::mem::zeroed(),
            slots: vec![std::mem::zeroed::<wz_ext_stream_slot_t>(); SUPERVISED_STREAMS],
            values: vec![0u8; SUPERVISED_STREAMS * SUPERVISED_CELL],
            stream: 0,
        };
        assert_eq!(
            wz_ext_stream_supervisor_new(
                &mut supervision.supervisor,
                supervision.slots.as_mut_ptr(),
                supervision.slots.len(),
                supervision.values.as_mut_ptr(),
                SUPERVISED_CELL,
                0,
                None,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "the supervisor is made over the program's storage"
        );
        // A deadline far past a window, so a round's poll judges the stream and tells no loss.
        assert_eq!(
            wz_ext_stream_supervisor_add(
                wz_ext_stream_supervisor_loan(&supervision.supervisor),
                1_000,
                2,
                1,
                false,
                &mut supervision.stream,
            ),
            Z_OK,
            "a stream is supervised"
        );
        supervision
    }

    /// Say the stream was received, with its payload, and poll.
    unsafe fn round(&self) {
        use wz_capi_pico::stream_supervision::{
            wz_ext_stream_supervisor_loan, wz_ext_stream_supervisor_poll,
            wz_ext_stream_supervisor_received,
        };
        let supervisor = wz_ext_stream_supervisor_loan(&self.supervisor);
        let payload = [0xC3u8; 8];
        assert_eq!(
            wz_ext_stream_supervisor_received(
                supervisor,
                self.stream,
                payload.as_ptr(),
                payload.len()
            ),
            Z_OK,
            "a reception is recorded"
        );
        let mut told = usize::MAX;
        assert_eq!(wz_ext_stream_supervisor_poll(supervisor, &mut told), Z_OK);
        assert_eq!(told, 0, "a stream received within its deadline is not lost");
    }

    unsafe fn drop_all(mut self) {
        use wz_capi_pico::stream_supervision::{
            wz_ext_stream_supervisor_drop, wz_ext_stream_supervisor_move,
        };
        wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(&mut self.supervisor));
        drop(self.slots);
        drop(self.values);
    }
}

/// A replay cache over a publisher of the dialling session on the key the listener hears.
#[cfg(feature = "replay-cache")]
struct Replay {
    publisher: z_owned_publisher_t,
    cache: wz_capi_pico::replay_publisher::wz_ext_owned_replay_publisher_t,
    /// The cache's storage, which it holds until it is dropped.
    storage: Vec<u8>,
    time_ms: u64,
}

#[cfg(feature = "replay-cache")]
impl Replay {
    unsafe fn new(pair: &Pair) -> Self {
        use wz_capi_pico::replay_publisher::{
            wz_ext_replay_publisher_new, wz_ext_replay_publisher_storage_size,
            wz_ext_replay_shape_t,
        };
        let ke = view(DATA_KEY);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(pair.dialler()),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK,
            "the replay cache's publisher is declared"
        );
        let shape = wz_ext_replay_shape_t {
            frame_max: pipe_pair::PAYLOAD.len(),
            depth: 4,
            instances: 1,
        };
        let size = wz_ext_replay_publisher_storage_size(&shape);
        assert!(size > 0, "a cache of {shape:?} has a size");
        let mut replay = Self {
            publisher,
            cache: std::mem::zeroed(),
            storage: vec![0u8; size],
            time_ms: 0,
        };
        assert_eq!(
            wz_ext_replay_publisher_new(
                &mut replay.cache,
                z_session_loan(pair.dialler()),
                wz_capi_pico::z_publisher_loan(&replay.publisher),
                replay.storage.as_mut_ptr(),
                replay.storage.len(),
                &shape,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "the replay cache is made"
        );
        replay
    }

    /// Record one frame in the ring and put it, and wait for the listener to hear it.
    unsafe fn round(&mut self, counts: &pipe_pair::Counts) {
        use wz_capi_pico::replay_publisher::{
            wz_ext_replay_publisher_loan, wz_ext_replay_publisher_put, WZ_EXT_REPLAY_SEND_PERIODIC,
        };
        let heard = counts.heard.load(Ordering::SeqCst);
        self.time_ms += 1;
        assert_eq!(
            wz_ext_replay_publisher_put(
                wz_ext_replay_publisher_loan(&self.cache),
                0,
                self.time_ms,
                pipe_pair::PAYLOAD.as_ptr(),
                pipe_pair::PAYLOAD.len(),
                WZ_EXT_REPLAY_SEND_PERIODIC,
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a frame is recorded and put"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a replay cache's put did not cross within {WAIT_BOUND:?}"
        );
    }

    unsafe fn drop_all(mut self) {
        use wz_capi_pico::replay_publisher::{
            wz_ext_replay_publisher_drop, wz_ext_replay_publisher_move,
        };
        wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&mut self.cache));
        z_undeclare_publisher(z_publisher_move(&mut self.publisher));
        drop(self.storage);
    }
}

/// The key the advanced publisher puts on and the advanced subscribers hear. Synthetic.
#[cfg(feature = "advanced")]
const ADVANCED_KEY: &CStr = c"noheap/advanced";

/// An advanced publisher of the dialling session with its cache on, and an advanced subscriber of
/// the listening session with its history on, both on `ADVANCED_KEY`: what a program of the
/// release profile's advanced plane holds.
#[cfg(feature = "advanced")]
struct Advanced {
    publisher: wz_capi_pico::advanced::ze_owned_advanced_publisher_t,
    subscriber: wz_capi_pico::advanced::ze_owned_advanced_subscriber_t,
}

#[cfg(feature = "advanced")]
impl Advanced {
    /// The publisher, with one sample in its cache that the subscriber heard, and the subscriber.
    unsafe fn new(pair: &Pair) -> Self {
        use wz_capi_pico::advanced::{
            ze_advanced_publisher_options_default, ze_advanced_publisher_options_t,
            ze_declare_advanced_publisher,
        };
        let ke = view(ADVANCED_KEY);
        let mut options: ze_advanced_publisher_options_t = std::mem::zeroed();
        ze_advanced_publisher_options_default(&mut options);
        options.cache.is_enabled = true;
        options.cache.max_samples = 4;
        let mut publisher = std::mem::zeroed();
        assert_eq!(
            ze_declare_advanced_publisher(
                z_session_loan(pair.dialler()),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                &options,
            ),
            Z_OK,
            "the advanced publisher is declared"
        );
        let mut advanced = Self {
            publisher,
            subscriber: Self::subscriber(pair),
        };
        advanced.put_and_hear(&pair.counts);
        advanced
    }

    /// An advanced subscriber of the listening session on `ADVANCED_KEY`, its history on, which
    /// counts what it hears as the pair's subscriber does.
    unsafe fn subscriber(pair: &Pair) -> wz_capi_pico::advanced::ze_owned_advanced_subscriber_t {
        use wz_capi_pico::advanced::{
            ze_advanced_subscriber_options_default, ze_advanced_subscriber_options_t,
            ze_declare_advanced_subscriber,
        };
        let ke = view(ADVANCED_KEY);
        let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
        ze_advanced_subscriber_options_default(&mut options);
        options.history.is_enabled = true;
        let mut closure = pipe_pair::sample_closure(&pair.counts);
        let mut subscriber = std::mem::zeroed();
        assert_eq!(
            ze_declare_advanced_subscriber(
                z_session_loan(pair.listener()),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                &mut options,
            ),
            Z_OK,
            "the advanced subscriber is declared"
        );
        subscriber
    }

    /// Put one sample through the advanced publisher, which its cache keeps, and wait for the
    /// advanced subscriber to hear it.
    unsafe fn put_and_hear(&mut self, counts: &pipe_pair::Counts) {
        use wz_capi_pico::advanced::{ze_advanced_publisher_loan, ze_advanced_publisher_put};
        let heard = counts.heard.load(Ordering::SeqCst);
        let mut bytes = payload();
        assert_eq!(
            ze_advanced_publisher_put(
                ze_advanced_publisher_loan(&self.publisher),
                z_bytes_move(&mut bytes),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "an advanced put is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "an advanced put did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Declare an advanced subscriber whose history asks the publisher's cache, wait for it to
    /// hear what the cache answers, and undeclare it.
    unsafe fn history(&self, pair: &Pair) {
        use wz_capi_pico::advanced::{
            ze_advanced_subscriber_move, ze_undeclare_advanced_subscriber,
        };
        let heard = pair.counts.heard.load(Ordering::SeqCst);
        let mut subscriber = Self::subscriber(pair);
        assert!(
            wait_for(WAIT_BOUND, || pair.counts.heard.load(Ordering::SeqCst)
                > heard),
            "a history did not cross within {WAIT_BOUND:?}"
        );
        assert_eq!(
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber)),
            Z_OK
        );
    }

    unsafe fn drop_both(mut self) {
        use wz_capi_pico::advanced::{
            ze_advanced_publisher_move, ze_advanced_subscriber_move,
            ze_undeclare_advanced_publisher, ze_undeclare_advanced_subscriber,
        };
        assert_eq!(
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut self.subscriber)),
            Z_OK
        );
        assert_eq!(
            ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&mut self.publisher)),
            Z_OK
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The rounds.

/// The open pair and what the families beyond it hold.
struct Bench {
    pair: Pair,
    /// The payload of a put near the batch limit.
    batch: Vec<u8>,
    /// The dialling session's publisher on the key the listener hears, which a publisher's put
    /// goes through and a matching listener is declared on.
    publisher: z_owned_publisher_t,
    /// The dialling session's querier on the key the listener's queryable answers.
    #[cfg(feature = "query")]
    querier: wz_capi_pico::z_owned_querier_t,
    /// The listening session's token, which a liveliness get finds.
    #[cfg(feature = "liveliness-get")]
    alive: wz_capi_pico::liveliness::z_owned_liveliness_token_t,
    #[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
    e2e: E2e,
    /// A sender and a receiver that keeps its streams per sender.
    #[cfg(all(feature = "e2e-sender", feature = "e2e-sender-demux"))]
    e2e_demux: E2e,
    #[cfg(feature = "e2e-supervision")]
    supervision: Supervision,
    #[cfg(all(
        feature = "instance-key",
        feature = "e2e-sender",
        feature = "e2e-receiver"
    ))]
    keyed: Keyed,
    #[cfg(feature = "message-payload")]
    message_payload: MessagePayload,
    #[cfg(feature = "replay-cache")]
    replay: Replay,
    #[cfg(feature = "advanced")]
    advanced: Advanced,
}

impl Bench {
    unsafe fn open() -> Self {
        let pair = Pair::open(true);
        let batch_len =
            wz_session_core::caps::PICO_UNICAST_BATCH_BYTES.saturating_sub(BATCH_HEADROOM);
        assert!(batch_len > 0, "the build's batch leaves room for a payload");
        #[cfg(feature = "liveliness-get")]
        let alive = {
            use wz_capi_pico::liveliness::{
                z_liveliness_declare_token, z_owned_liveliness_token_t,
            };
            let ke = view(ALIVE);
            let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
            assert_eq!(
                z_liveliness_declare_token(
                    z_session_loan(&pair.listener),
                    &mut token,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                ),
                Z_OK,
                "the listening session declares the token a liveliness get finds"
            );
            token
        };
        #[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
        let e2e = E2e::new();
        #[cfg(all(feature = "e2e-sender", feature = "e2e-sender-demux"))]
        let e2e_demux = E2e::sender_keyed();
        #[cfg(feature = "e2e-supervision")]
        let supervision = Supervision::new();
        #[cfg(all(
            feature = "instance-key",
            feature = "e2e-sender",
            feature = "e2e-receiver"
        ))]
        let keyed = Keyed::new();
        #[cfg(feature = "message-payload")]
        let message_payload = MessagePayload::new();
        #[cfg(feature = "replay-cache")]
        let replay = Replay::new(&pair);
        #[cfg(feature = "advanced")]
        let advanced = Advanced::new(&pair);
        let ke = view(DATA_KEY);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(pair.dialler()),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK,
            "the publisher a publisher's put goes through is declared"
        );
        #[cfg(feature = "query")]
        let querier = {
            let ke = view(pipe_pair::ASK_KEY);
            let mut querier: wz_capi_pico::z_owned_querier_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_pico::z_declare_querier(
                    z_session_loan(pair.dialler()),
                    &mut querier,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null_mut(),
                ),
                Z_OK,
                "the querier a querier's get goes through is declared"
            );
            querier
        };
        Self {
            pair,
            batch: vec![0x5A; batch_len],
            publisher,
            #[cfg(feature = "query")]
            querier,
            #[cfg(feature = "liveliness-get")]
            alive,
            #[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
            e2e,
            #[cfg(all(feature = "e2e-sender", feature = "e2e-sender-demux"))]
            e2e_demux,
            #[cfg(feature = "e2e-supervision")]
            supervision,
            #[cfg(all(
                feature = "instance-key",
                feature = "e2e-sender",
                feature = "e2e-receiver"
            ))]
            keyed,
            #[cfg(feature = "message-payload")]
            message_payload,
            #[cfg(feature = "replay-cache")]
            replay,
            #[cfg(feature = "advanced")]
            advanced,
        }
    }

    /// Run one round of `round`, waited for to its end where its end can be seen.
    unsafe fn run(&mut self, round: Round) {
        match round {
            Round::Idle => std::thread::sleep(IDLE_SLICE),
            Round::PublisherDeclare => self.publisher_declare(),
            Round::PutSmall => {
                let mut bytes = payload();
                self.put_and_hear(&mut bytes);
            }
            Round::PutBatch => {
                let mut bytes: z_owned_bytes_t = std::mem::zeroed();
                assert_eq!(
                    z_bytes_copy_from_buf(&mut bytes, self.batch.as_ptr(), self.batch.len()),
                    Z_OK
                );
                self.put_and_hear(&mut bytes);
            }
            Round::Get => self.get_and_reply(),
            Round::GroupReceive | Round::SharedKeyIds => {
                unreachable!("{round:?} runs on its own stage's pair")
            }
            Round::KeyexprDeclare => self.keyexpr_declare(),
            Round::LivelinessToken => {
                #[cfg(feature = "liveliness")]
                self.liveliness_token();
            }
            Round::LivelinessGet => {
                #[cfg(feature = "liveliness-get")]
                self.liveliness_get();
            }
            Round::E2e => {
                #[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
                self.e2e.round();
            }
            Round::Replay => {
                #[cfg(feature = "replay-cache")]
                self.replay.round(&self.pair.counts);
            }
            Round::ConfigDocument => {
                #[cfg(feature = "config-document")]
                config_document();
            }
            Round::SubscriberDeclare => self.subscriber_declare(),
            Round::QueryableDeclare => {
                #[cfg(feature = "queryable")]
                self.queryable_declare();
            }
            Round::MatchingListener => self.matching_listener(),
            Round::LivelinessSubscriber => {
                #[cfg(feature = "liveliness")]
                self.liveliness_subscriber();
            }
            Round::QuerierDeclare => {
                #[cfg(feature = "query")]
                self.querier_declare();
            }
            Round::QuerierGet => {
                #[cfg(feature = "query")]
                self.querier_get();
            }
            Round::ConfigClone => config_clone(),
            Round::PublisherPut => self.publisher_put(),
            Round::Delete => self.delete(),
            Round::PutEncoded => self.put_encoded(),
            Round::PutTimestamped => self.put_timestamped(),
            Round::AdvancedPut => {
                #[cfg(feature = "advanced")]
                self.advanced.put_and_hear(&self.pair.counts);
            }
            Round::AdvancedHistory => {
                #[cfg(feature = "advanced")]
                self.advanced.history(&self.pair);
            }
            Round::TransportEventsListener => {
                #[cfg(feature = "connectivity")]
                self.transport_events_listener();
            }
            Round::E2eSenderDemux => {
                #[cfg(all(feature = "e2e-sender", feature = "e2e-sender-demux"))]
                self.e2e_demux.round();
            }
            Round::E2eSupervision => {
                #[cfg(feature = "e2e-supervision")]
                self.supervision.round();
            }
            Round::InstanceKey => {
                #[cfg(all(
                    feature = "instance-key",
                    feature = "e2e-sender",
                    feature = "e2e-receiver"
                ))]
                self.keyed.round();
            }
            Round::MessagePayload => {
                #[cfg(feature = "message-payload")]
                self.message_payload.round();
            }
        }
    }

    unsafe fn subscriber_declare(&self) {
        let mut closure = pipe_pair::sample_closure(&self.pair.counts);
        let mut subscriber: wz_capi_pico::z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            pipe_pair::declare_subscriber(
                self.pair.dialler(),
                DECLARED,
                &mut closure,
                &mut subscriber
            ),
            Z_OK,
            "a subscriber is declared"
        );
        assert_eq!(
            wz_capi_pico::z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber)),
            Z_OK,
            "a subscriber is undeclared"
        );
    }

    #[cfg(feature = "queryable")]
    unsafe fn queryable_declare(&self) {
        let mut closure = pipe_pair::query_closure(&self.pair.counts);
        let mut queryable: wz_capi_pico::z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            pipe_pair::declare_queryable(
                self.pair.dialler(),
                DECLARED,
                &mut closure,
                &mut queryable
            ),
            Z_OK,
            "a queryable is declared"
        );
        assert_eq!(
            wz_capi_pico::z_undeclare_queryable(wz_capi_pico::z_queryable_move(&mut queryable)),
            Z_OK,
            "a queryable is undeclared"
        );
    }

    /// Declare a transport events listener on the dialling session and retract it: the
    /// connectivity door a program reaches after open.
    #[cfg(feature = "connectivity")]
    unsafe fn transport_events_listener(&self) {
        use wz_capi_pico::connectivity::{
            z_closure_transport_event, z_closure_transport_event_move,
            z_declare_transport_events_listener, z_owned_closure_transport_event_t,
            z_owned_transport_events_listener_t, z_transport_events_listener_move,
            z_undeclare_transport_events_listener,
        };
        let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
        assert_eq!(
            z_closure_transport_event(
                &mut closure,
                None,
                Some(counted_drop),
                pipe_pair::context(&self.pair.counts),
            ),
            Z_OK
        );
        let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
        assert_eq!(
            z_declare_transport_events_listener(
                z_session_loan(self.pair.dialler()),
                &mut listener,
                z_closure_transport_event_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK,
            "a transport events listener is declared"
        );
        assert_eq!(
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut listener)),
            Z_OK,
            "a transport events listener is undeclared"
        );
    }

    /// Declare a matching listener on the bench's publisher and retract it.
    unsafe fn matching_listener(&self) {
        use wz_capi_pico::matching::{
            z_closure_matching_status, z_closure_matching_status_move, z_matching_listener_move,
            z_owned_closure_matching_status_t, z_owned_matching_listener_t,
            z_publisher_declare_matching_listener, z_undeclare_matching_listener,
        };
        let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
        assert_eq!(
            z_closure_matching_status(
                &mut closure,
                None,
                Some(counted_drop),
                pipe_pair::context(&self.pair.counts),
            ),
            Z_OK
        );
        let mut listener: z_owned_matching_listener_t = std::mem::zeroed();
        assert_eq!(
            z_publisher_declare_matching_listener(
                wz_capi_pico::z_publisher_loan(&self.publisher),
                &mut listener,
                z_closure_matching_status_move(&mut closure),
            ),
            Z_OK,
            "a matching listener is declared"
        );
        assert_eq!(
            z_undeclare_matching_listener(z_matching_listener_move(&mut listener)),
            Z_OK,
            "a matching listener is undeclared"
        );
    }

    #[cfg(feature = "liveliness")]
    unsafe fn liveliness_subscriber(&self) {
        use wz_capi_pico::liveliness::z_liveliness_declare_subscriber;
        let ke = view(DECLARED);
        let mut closure = pipe_pair::sample_closure(&self.pair.counts);
        let mut subscriber: wz_capi_pico::z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_liveliness_declare_subscriber(
                z_session_loan(self.pair.dialler()),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a liveliness subscriber is declared"
        );
        assert_eq!(
            wz_capi_pico::z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber)),
            Z_OK,
            "a liveliness subscriber is undeclared"
        );
    }

    #[cfg(feature = "query")]
    unsafe fn querier_declare(&self) {
        let ke = view(DECLARED);
        let mut querier: wz_capi_pico::z_owned_querier_t = std::mem::zeroed();
        assert_eq!(
            wz_capi_pico::z_declare_querier(
                z_session_loan(self.pair.dialler()),
                &mut querier,
                z_view_keyexpr_loan(&ke),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a querier is declared"
        );
        assert_eq!(
            wz_capi_pico::z_undeclare_querier(wz_capi_pico::z_querier_move(&mut querier)),
            Z_OK,
            "a querier is undeclared"
        );
    }

    /// Ask the listener's queryable through the bench's querier and wait for the get's end.
    #[cfg(feature = "query")]
    unsafe fn querier_get(&self) {
        let counts = &self.pair.counts;
        let replies = counts.replies.load(Ordering::SeqCst);
        let over = counts.gets_over.load(Ordering::SeqCst);
        let mut closure = reply_closure(counts);
        assert_eq!(
            wz_capi_pico::z_querier_get(
                wz_capi_pico::z_querier_loan(&self.querier),
                std::ptr::null(),
                wz_capi_pico::z_closure_reply_move(&mut closure),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a querier's get is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.gets_over.load(Ordering::SeqCst)
                > over),
            "a querier's get did not end within {WAIT_BOUND:?}"
        );
        assert!(
            counts.replies.load(Ordering::SeqCst) > replies,
            "a querier's get between open sessions is answered"
        );
    }

    /// Put through the bench's publisher and wait for the listener to hear it.
    unsafe fn publisher_put(&self) {
        let counts = &self.pair.counts;
        let heard = counts.heard.load(Ordering::SeqCst);
        let mut bytes = payload();
        assert_eq!(
            wz_capi_pico::z_publisher_put(
                wz_capi_pico::z_publisher_loan(&self.publisher),
                wz_capi_pico::z_bytes_move(&mut bytes),
                std::ptr::null(),
            ),
            Z_OK,
            "a publisher's put is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a publisher's put did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Put from the dialler with an encoding that carries a schema, the encoding made for the put as
    /// a program makes one, and wait for the listener to hear it.
    unsafe fn put_encoded(&self) {
        let counts = &self.pair.counts;
        let heard = counts.heard.load(Ordering::SeqCst);
        let mut encoding: z_owned_encoding_t = std::mem::zeroed();
        assert_eq!(
            z_encoding_from_str(&mut encoding, ENCODED.as_ptr()),
            Z_OK,
            "an encoding with a schema is made"
        );
        let mut options: z_put_options_t = std::mem::zeroed();
        z_put_options_default(&mut options);
        options.encoding = z_encoding_move(&mut encoding).cast();
        let mut bytes = payload();
        let ke = view(DATA_KEY);
        assert_eq!(
            z_put(
                z_session_loan(self.pair.dialler()),
                z_view_keyexpr_loan(&ke),
                z_bytes_move(&mut bytes),
                &options,
            ),
            Z_OK,
            "a put with an encoding is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a put with an encoding did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Put from the dialler with a timestamp the program minted from the session's clock, as a
    /// program stamps its own samples, and wait for the listener to hear it.
    unsafe fn put_timestamped(&self) {
        let counts = &self.pair.counts;
        let heard = counts.heard.load(Ordering::SeqCst);
        let session = z_session_loan(self.pair.dialler());
        let mut stamp: z_timestamp_t = std::mem::zeroed();
        assert_eq!(
            z_timestamp_new(&mut stamp, session),
            Z_OK,
            "a timestamp is minted from the session's clock"
        );
        let mut options: z_put_options_t = std::mem::zeroed();
        z_put_options_default(&mut options);
        options.timestamp = &mut stamp;
        let mut bytes = payload();
        let ke = view(DATA_KEY);
        assert_eq!(
            z_put(
                session,
                z_view_keyexpr_loan(&ke),
                z_bytes_move(&mut bytes),
                &options,
            ),
            Z_OK,
            "a put with a timestamp is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a put with a timestamp did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Delete on the key the listener hears and wait for it to hear the delete.
    unsafe fn delete(&self) {
        let counts = &self.pair.counts;
        let heard = counts.heard.load(Ordering::SeqCst);
        let ke = view(DATA_KEY);
        assert_eq!(
            wz_capi_pico::z_delete(
                z_session_loan(self.pair.dialler()),
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK,
            "a delete is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a delete did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Declare a publisher and undeclare it, on the listening session: the dialler holds the
    /// publishers the other families go through, as many as a session of the pico preset holds
    /// (`MAX_PUBLISHERS`), and the one this family declares would be past them.
    unsafe fn publisher_declare(&self) {
        let ke = view(DATA_KEY);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(self.pair.listener()),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK,
            "a publisher is declared"
        );
        z_undeclare_publisher(z_publisher_move(&mut publisher));
    }

    /// Put `bytes` from the dialler and wait for the listener to hear it.
    unsafe fn put_and_hear(&self, bytes: &mut z_owned_bytes_t) {
        let counts = &self.pair.counts;
        let heard = counts.heard.load(Ordering::SeqCst);
        assert_eq!(put(self.pair.dialler(), bytes), Z_OK, "a put is taken");
        assert!(
            wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
            "a put did not cross within {WAIT_BOUND:?}"
        );
    }

    /// Ask the listener's queryable from the dialler and wait for the answer and the get's end.
    unsafe fn get_and_reply(&self) {
        let counts = &self.pair.counts;
        let replies = counts.replies.load(Ordering::SeqCst);
        let over = counts.gets_over.load(Ordering::SeqCst);
        let mut closure = reply_closure(counts);
        assert_eq!(
            get(self.pair.dialler(), &mut closure),
            Z_OK,
            "a get is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.gets_over.load(Ordering::SeqCst)
                > over),
            "a get did not end within {WAIT_BOUND:?}"
        );
        assert!(
            counts.replies.load(Ordering::SeqCst) > replies,
            "a get between open sessions is answered"
        );
    }

    unsafe fn keyexpr_declare(&self) {
        let ke = view(DECLARED);
        let session = z_session_loan(self.pair.dialler());
        let mut declared: z_owned_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_declare_keyexpr(session, &mut declared, z_view_keyexpr_loan(&ke)),
            Z_OK,
            "a key expression is declared"
        );
        assert_eq!(
            z_undeclare_keyexpr(session, z_keyexpr_move(&mut declared)),
            Z_OK,
            "a key expression is undeclared"
        );
    }

    #[cfg(feature = "liveliness")]
    unsafe fn liveliness_token(&self) {
        use wz_capi_pico::liveliness::{
            z_liveliness_declare_token, z_liveliness_token_move, z_liveliness_undeclare_token,
            z_owned_liveliness_token_t,
        };
        let ke = view(DECLARED);
        let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
        assert_eq!(
            z_liveliness_declare_token(
                z_session_loan(self.pair.dialler()),
                &mut token,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK,
            "a liveliness token is declared"
        );
        assert_eq!(
            z_liveliness_undeclare_token(z_liveliness_token_move(&mut token)),
            Z_OK,
            "a liveliness token is undeclared"
        );
    }

    #[cfg(feature = "liveliness-get")]
    unsafe fn liveliness_get(&self) {
        use wz_capi_pico::liveliness::{
            z_liveliness_get, z_liveliness_get_options_default, z_liveliness_get_options_t,
        };
        let counts = &self.pair.counts;
        let replies = counts.replies.load(Ordering::SeqCst);
        let over = counts.gets_over.load(Ordering::SeqCst);
        let ke = view(ALIVE);
        let mut closure = reply_closure(counts);
        let mut options: z_liveliness_get_options_t = std::mem::zeroed();
        assert_eq!(z_liveliness_get_options_default(&mut options), Z_OK);
        options.timeout_ms = pipe_pair::GET_TIMEOUT_MS;
        assert_eq!(
            z_liveliness_get(
                z_session_loan(self.pair.dialler()),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_reply_move(&mut closure),
                &mut options,
            ),
            Z_OK,
            "a liveliness get is taken"
        );
        assert!(
            wait_for(WAIT_BOUND, || counts.gets_over.load(Ordering::SeqCst)
                > over),
            "a liveliness get did not end within {WAIT_BOUND:?}"
        );
        assert!(
            counts.replies.load(Ordering::SeqCst) > replies,
            "a liveliness get finds the listening session's token"
        );
    }

    /// Undo what `open` set up, then close the pair: whether every closure was dropped and both
    /// transports were let go.
    unsafe fn close(self) -> (bool, bool) {
        #[cfg(feature = "liveliness-get")]
        {
            use wz_capi_pico::liveliness::{z_liveliness_token_move, z_liveliness_undeclare_token};
            let mut alive = self.alive;
            assert_eq!(
                z_liveliness_undeclare_token(z_liveliness_token_move(&mut alive)),
                Z_OK
            );
        }
        #[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
        self.e2e.drop_both();
        #[cfg(all(feature = "e2e-sender", feature = "e2e-sender-demux"))]
        self.e2e_demux.drop_both();
        #[cfg(feature = "e2e-supervision")]
        self.supervision.drop_all();
        #[cfg(all(
            feature = "instance-key",
            feature = "e2e-sender",
            feature = "e2e-receiver"
        ))]
        self.keyed.drop_all();
        #[cfg(feature = "message-payload")]
        self.message_payload.drop_both();
        #[cfg(feature = "replay-cache")]
        self.replay.drop_all();
        #[cfg(feature = "advanced")]
        self.advanced.drop_both();
        #[cfg(feature = "query")]
        {
            let mut querier = self.querier;
            assert_eq!(
                wz_capi_pico::z_undeclare_querier(wz_capi_pico::z_querier_move(&mut querier)),
                Z_OK
            );
        }
        let mut publisher = self.publisher;
        assert_eq!(
            z_undeclare_publisher(z_publisher_move(&mut publisher)),
            Z_OK
        );
        self.pair.close()
    }
}

/// The drop of a closure whose context is a [`pipe_pair::context`]: counted, as the pair's own
/// closures count theirs, so the close sees every closure the library was handed dropped.
unsafe extern "C" fn counted_drop(context: *mut std::ffi::c_void) {
    let counts = std::sync::Arc::from_raw(context as *const pipe_pair::Counts);
    counts.dropped.fetch_add(1, Ordering::SeqCst);
}

/// Make a config and a copy of it, and drop both, as a program does before it opens another
/// session.
unsafe fn config_clone() {
    use wz_capi_pico::{
        z_config_clone, z_config_default, z_config_drop, z_config_loan, z_config_move,
        z_owned_config_t,
    };
    let mut config: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut config), Z_OK);
    let mut copy: z_owned_config_t = std::mem::zeroed();
    assert_eq!(
        z_config_clone(&mut copy, z_config_loan(&config)),
        Z_OK,
        "the config is copied"
    );
    z_config_drop(z_config_move(&mut copy));
    z_config_drop(z_config_move(&mut config));
}

/// A document the zenoh-c ABI reads too, of which this ABI reads the `wz` member. Synthetic.
#[cfg(feature = "config-document")]
const DOCUMENT: &CStr = c"{ mode: \"peer\" }";

/// Make a config and hand it the document, as a program does before it opens another session.
#[cfg(feature = "config-document")]
unsafe fn config_document() {
    use wz_capi_pico::config_policy::wz_ext_config_document;
    use wz_capi_pico::{
        z_config_default, z_config_drop, z_config_loan_mut, z_config_move, z_owned_config_t,
    };
    let mut config: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut config), Z_OK);
    assert_eq!(
        wz_ext_config_document(z_config_loan_mut(&mut config), DOCUMENT.as_ptr()),
        Z_OK,
        "the document is taken"
    );
    z_config_drop(z_config_move(&mut config));
}

/// The open session pair a stage's rounds call through.
///
/// The measured build holds two sessions open at once: the release profile is merged onto
/// zenoh-pico's defconfig, which turns on `WZ_LIMITS_ZENOH_PICO`, and under it `HELD_SESSIONS` is 2
/// (`deploy/Kconfig.limits:204-207`). Each pair a family needs is therefore opened only after the
/// one before it is closed, and its windows open only once it is open and its route is made, so
/// what one pair's open or close leaves running is never counted in another pair's rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Two sessions over the program's pipe, and every capability set up beside them.
    Pipe,
    /// Two members of one group over the program's transport.
    Group,
    /// Two sessions over the program's pipe that hold one dictionary of key ids and name their
    /// keys by it.
    SharedKeyIds,
}

impl Stage {
    /// Every stage, in the order its pair is opened.
    const ALL: [Stage; 3] = [Stage::Pipe, Stage::Group, Stage::SharedKeyIds];

    /// The stage's pair, open; `None` in a build without the stage's capability, whose rounds are
    /// then all unbuilt.
    unsafe fn open(self) -> Option<Open> {
        match self {
            Stage::Pipe => Some(Open::Pipe(Bench::open())),
            Stage::Group => {
                #[cfg(feature = "multicast-transport")]
                {
                    Some(Open::Group(GroupPair::open()))
                }
                #[cfg(not(feature = "multicast-transport"))]
                {
                    None
                }
            }
            Stage::SharedKeyIds => {
                #[cfg(feature = "shared-key-ids")]
                {
                    Some(Open::SharedKeyIds(Pair::open_shaped(true, state_key_ids)))
                }
                #[cfg(not(feature = "shared-key-ids"))]
                {
                    None
                }
            }
        }
    }
}

/// A stage's pair, open.
enum Open {
    Pipe(Bench),
    #[cfg(feature = "multicast-transport")]
    Group(GroupPair),
    #[cfg(feature = "shared-key-ids")]
    SharedKeyIds(Pair),
}

impl Open {
    /// Run one round of `round`, which is a round of this pair's stage.
    unsafe fn run(&mut self, round: Round) {
        match self {
            Open::Pipe(bench) => bench.run(round),
            #[cfg(feature = "multicast-transport")]
            Open::Group(group) => group_put_and_hear(group),
            #[cfg(feature = "shared-key-ids")]
            Open::SharedKeyIds(pair) => pair_put_and_hear(pair),
        }
    }

    /// Close the pair: whether every closure the library was handed is dropped, and whether the
    /// transports the pair let go were dropped.
    unsafe fn close(self) -> (bool, bool) {
        match self {
            Open::Pipe(bench) => bench.close(),
            #[cfg(feature = "multicast-transport")]
            Open::Group(group) => {
                let counts = std::sync::Arc::clone(&group.counts);
                drop(group);
                // The group's transports are released by its drop, which counts none.
                (closures_dropped(&counts), true)
            }
            #[cfg(feature = "shared-key-ids")]
            Open::SharedKeyIds(pair) => pair.close(),
        }
    }
}

/// Whether every closure made with a context of `counts` was dropped within the bound.
#[cfg(feature = "multicast-transport")]
fn closures_dropped(counts: &pipe_pair::Counts) -> bool {
    wait_for(WAIT_BOUND, || {
        counts.made.load(Ordering::SeqCst) == counts.dropped.load(Ordering::SeqCst)
    })
}

/// Put on the group from its sending member and wait until the receiving member's subscriber hears
/// it: the round's control, so a round that heard nothing fails whatever it allocated.
#[cfg(feature = "multicast-transport")]
unsafe fn group_put_and_hear(group: &GroupPair) {
    let counts = &group.counts;
    let heard = counts.heard.load(Ordering::SeqCst);
    let mut bytes = payload();
    assert_eq!(
        put(group.sender(), &mut bytes),
        Z_OK,
        "a put on the group is taken"
    );
    assert!(
        wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
        "a put on the group was not heard within {WAIT_BOUND:?}"
    );
}

/// The id every node of the shared pair's deployment names `DATA_KEY` by. Synthetic.
#[cfg(feature = "shared-key-ids")]
const SHARED_ID: u16 = 40;

/// Hand a config of the shared pair the dictionary and state the pipe's endpoint `shared`, so
/// what either session sends over it names `DATA_KEY` by its id, with no declaration first.
#[cfg(feature = "shared-key-ids")]
unsafe fn state_key_ids(config: &mut wz_capi_pico::z_owned_config_t) {
    use wz_capi_pico::key_ids::{wz_ext_config_key_ids, wz_ext_config_key_wire_form_for};
    let ids = [SHARED_ID];
    let keys = [DATA_KEY.as_ptr()];
    assert_eq!(
        wz_ext_config_key_ids(
            wz_capi_pico::z_config_loan_mut(config),
            ids.as_ptr(),
            keys.as_ptr(),
            ids.len()
        ),
        Z_OK,
        "the config holds the dictionary"
    );
    assert_eq!(
        wz_ext_config_key_wire_form_for(
            wz_capi_pico::z_config_loan_mut(config),
            pipe_pair::LISTEN.as_ptr(),
            c"shared".as_ptr()
        ),
        Z_OK,
        "the pipe's endpoint names its keys by the dictionary"
    );
}

/// Put from `pair`'s dialler on the key its listener hears and wait for the listener to hear it.
#[cfg(feature = "shared-key-ids")]
unsafe fn pair_put_and_hear(pair: &Pair) {
    let counts = &pair.counts;
    let heard = counts.heard.load(Ordering::SeqCst);
    let mut bytes = payload();
    assert_eq!(put(pair.dialler(), &mut bytes), Z_OK, "a put is taken");
    assert!(
        wait_for(WAIT_BOUND, || counts.heard.load(Ordering::SeqCst) > heard),
        "a put did not cross within {WAIT_BOUND:?}"
    );
}

/// One window of `round`: the warm-up and the counted rounds.
unsafe fn window(open: &mut Open, round: Round) -> Seen {
    for _ in 0..WARM_UP {
        open.run(round);
    }
    std::thread::sleep(SETTLE);
    let place = Round::ALL
        .iter()
        .position(|of| *of == round)
        .unwrap_or(NO_ROUND);
    open_window(0);
    SITE_ROUND.store(place, Ordering::SeqCst);
    for _ in 0..rounds() {
        open.run(round);
    }
    std::thread::sleep(SETTLE);
    SITE_ROUND.store(NO_ROUND, Ordering::SeqCst);
    let seen = close_window();
    assert!(
        !seen.fired,
        "a window that fails nothing failed an allocation"
    );
    seen
}

/// Every window of `round`.
unsafe fn measure(open: &mut Open, round: Round) -> Vec<Seen> {
    let mut seen = Vec::with_capacity(windows());
    for _ in 0..windows() {
        seen.push(window(open, round));
    }
    seen
}

// ---------------------------------------------------------------------------------------------
// The test.

#[test]
#[ignore = "counts the allocations of every operation family after open; Layer C1nh runs via --ignored"]
fn allocations_after_open_are_counted_per_operation_family() {
    let mut names: Vec<&str> = FAMILIES.iter().map(|(name, _, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        FAMILIES.len(),
        "every family has a name of its own"
    );
    for round in Round::ALL {
        assert!(
            FAMILIES.iter().any(|(_, of, _)| *of == round),
            "{round:?} is counted by no family"
        );
    }

    SITES_ON.store(std::env::var_os(SITES_VARIABLE).is_some(), Ordering::SeqCst);
    count_panics();
    mark_calling_thread();
    let (seen, balanced, dropped) = unsafe {
        let mut seen: Vec<(Round, Vec<Seen>)> = Vec::new();
        let (mut balanced, mut dropped) = (true, true);
        for stage in Stage::ALL {
            let rounds: Vec<Round> = Round::ALL
                .into_iter()
                .filter(|round| round.built() && round.stage() == stage)
                .collect();
            if rounds.is_empty() {
                continue;
            }
            let Some(mut open) = stage.open() else {
                continue;
            };
            for round in rounds {
                seen.push((round, measure(&mut open, round)));
            }
            let (closures, transports) = open.close();
            balanced &= closures;
            dropped &= transports;
        }
        (seen, balanced, dropped)
    };
    assert!(balanced, "every closure the library was handed is dropped");
    assert!(dropped, "both transports are let go");
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a thread panicked");

    // With the sites recorded, a window's count holds the records' own allocations too, so the
    // reading is not printed: what is printed is each round's allocations a round, at each site.
    if SITES_ON.load(Ordering::SeqCst) {
        let stacks = std::mem::take(&mut *SITES.lock().unwrap_or_else(PoisonError::into_inner));
        let mut sites: BTreeMap<(usize, String), u64> = BTreeMap::new();
        for (round, stack) in stacks {
            *sites
                .entry((round, site_of(&stack.to_string())))
                .or_insert(0) += 1;
        }
        let mut lines: Vec<(usize, u64, String)> = sites
            .into_iter()
            .map(|((round, site), count)| (round, count, site))
            .collect();
        lines.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        for (round, count, site) in lines {
            let name = Round::ALL
                .get(round)
                .map_or_else(|| String::from("?"), |round| format!("{round:?}"));
            let per_round = count as f64 / SITE_ROUNDS as f64;
            println!("{SITE_PREFIX} {name} per_round={per_round:.2} {site}");
        }
        return;
    }

    let mut reading = String::new();
    for (name, round, part) in FAMILIES {
        let line = match seen.iter().find(|(of, _)| *of == round) {
            Some((_, windows)) => {
                let (allocs, bytes, most) = reading_of(windows, part);
                let least = format!("allocs={allocs} bytes={bytes} rounds={ROUNDS}");
                format!("{PREFIX} {name} {least} windows={WINDOWS} max_allocs={most}")
            }
            None => format!("{PREFIX} {name} not-built"),
        };
        println!("{line}");
        reading.push_str(&line);
        reading.push('\n');
    }
    if let Some(path) = std::env::var_os(READING_VARIABLE) {
        std::fs::write(&path, reading)
            .unwrap_or_else(|error| panic!("the reading is written to {path:?}: {error}"));
    }
}
