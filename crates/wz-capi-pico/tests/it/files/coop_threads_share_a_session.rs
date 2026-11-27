// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Threads that share one session of the cooperative engine and call its C doors at once, as
//! zenoh-pico's multi-threaded build lets a program: each of [`THREADS`] workers puts, puts through
//! a key expression it declares and undeclares around the put, gets, and declares and undeclares a
//! subscriber, on the one dialling session, in an order a fixed seed draws, while the session's
//! read task delivers beside them. Each worker's results are its own and so are asserted exactly:
//!
//! - every put reaches the listening peer once, and each worker's in the order it made them, those
//!   through a key expression it declared a moment before among them;
//! - every get ends with one answer, the key it asked;
//! - every declaration returns, reads back the key it was asked for, and its callback is let go of
//!   once;
//! - no call stops for good: a run in which no worker makes a call for [`STALL`] fails with what
//!   each worker was doing, instead of holding the test process;
//! - the session's tables of declared key expressions and of subscribers take as many rows after
//!   the run as before it, so a row or a key of the key arena the run leaked, or let go of twice,
//!   moves the count.
//!
//! `stability.rs` closes and opens sessions under its workers over a transport that injects faults
//! and counts what survives; this holds one session open over the loopback and checks each answer.
//! A race between these calls is what the race detector of Layer Vtsan reads; here it is a wrong
//! answer, or a debug build's check that the key arena is touched under its session's lock.
//!
//! ```text
//! cargo test -p wz-capi-pico --features object-pool --test it \
//!     files::coop_threads_share_a_session::
//! ```
#![cfg(all(
    feature = "os-host",
    feature = "peer",
    feature = "multi-thread",
    feature = "query",
    feature = "queryable"
))]

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::config_limits::ZEXT_CONFIG_LIMITS_KEY;
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_move, z_bytes_to_slice, z_close, z_closure_query,
    z_closure_query_move, z_closure_reply, z_closure_reply_move, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move,
    z_congestion_control_t, z_declare_keyexpr, z_declare_queryable, z_declare_subscriber, z_get,
    z_get_options_default, z_get_options_t, z_keyexpr_as_view_string, z_keyexpr_loan,
    z_keyexpr_move, z_loaned_bytes_t, z_loaned_keyexpr_t, z_loaned_query_t, z_loaned_reply_t,
    z_loaned_sample_t, z_open, z_owned_bytes_t, z_owned_config_t, z_owned_keyexpr_t,
    z_owned_queryable_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_put,
    z_put_options_default, z_put_options_t, z_query_keyexpr, z_query_reply, z_queryable_move,
    z_queryable_options_default, z_queryable_options_t, z_reply_is_ok, z_reply_ok,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_string_data,
    z_string_len, z_subscriber_move, z_undeclare_keyexpr, z_undeclare_queryable,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The workers that share the dialling session.
const THREADS: usize = 4;

/// The calls each worker makes.
const ROUNDS: u64 = 48;

/// The mix of the run: the same calls in the same order on every run, whatever the threads'
/// interleaving.
const SEED: u64 = 0x5EED_C0DE_0004;

/// How long a run may go with no worker making a call before it is a stop and not a wait. A get
/// waits at most [`GET_TIMEOUT`], well inside it.
const STALL: Duration = Duration::from_secs(30);

/// The timeout of each get; one that is not answered ends at it, with no reply.
const GET_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a worker waits for a get to end, or a peer for what was sent to it.
const ANSWER_WITHIN: Duration = Duration::from_secs(20);

/// pico's `Z_CONGESTION_CONTROL_BLOCK`: a put that waits for room rather than being dropped, so
/// every put is counted at the peer.
const CONGESTION_BLOCK: z_congestion_control_t = 1;

/// The most rows a measurement of a table's room declares before it is refused.
const ROOM_PROBE: usize = 64;

/// The keys of the run. Synthetic.
const EVERY_PUT: &CStr = c"stress/put/**";
const EVERY_ASK: &CStr = c"stress/ask/**";
const PROBE_PUT: &CStr = c"stress/put/probe";
const PROBE_ASK: &CStr = c"stress/ask/probe";
const PROBE_PAYLOAD: &[u8] = b"probe";

/// The calls a worker draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Call {
    /// A put on the worker's own key.
    Put = 1,
    /// A key expression declared, a put through it, and its undeclaration.
    DeclaredPut = 2,
    /// A get, waited for until it ends.
    Get = 3,
    /// A subscriber declared and undeclared.
    Subscribe = 4,
}

const CALLS: [Call; 4] = [Call::Put, Call::DeclaredPut, Call::Get, Call::Subscribe];

/// SplitMix64, as `stability.rs` draws its mix: the same sequence for the same seed everywhere.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn call(&mut self) -> Call {
        CALLS[(self.next_u64() % CALLS.len() as u64) as usize]
    }
}

/// What a worker is doing, read by the watch of the run.
#[derive(Default)]
struct Beat {
    /// Each call's start and end, so a run in which this stops moving made no call.
    steps: AtomicU64,
    /// The call under way (`Call as u8`), `0` between calls.
    doing: AtomicU8,
    round: AtomicU64,
}

impl Beat {
    fn start(&self, call: Call, round: u64) {
        self.round.store(round, Ordering::SeqCst);
        self.doing.store(call as u8, Ordering::SeqCst);
        self.steps.fetch_add(1, Ordering::SeqCst);
    }

    fn end(&self) {
        self.doing.store(0, Ordering::SeqCst);
        self.steps.fetch_add(1, Ordering::SeqCst);
    }

    fn report(&self) -> String {
        let doing = self.doing.load(Ordering::SeqCst);
        let call = CALLS.iter().find(|call| **call as u8 == doing);
        match call {
            Some(call) => format!("{call:?} in round {}", self.round.load(Ordering::SeqCst)),
            None => format!(
                "between calls after round {}",
                self.round.load(Ordering::SeqCst)
            ),
        }
    }
}

/// The dialling session the workers share.
struct Session(z_owned_session_t);

// SAFETY: the ABI's session handle may be used from any thread at once in a multi-threaded build,
// as zenoh-pico's is; it is let go of once, after every worker has ended.
unsafe impl Send for Session {}
// SAFETY: as `Send`.
unsafe impl Sync for Session {}

/// What the workers share.
struct Shared {
    dialler: Session,
    beats: Vec<Beat>,
    /// The workers that have ended, by return or by panic.
    ended: AtomicUsize,
}

impl Shared {
    fn steps(&self) -> u64 {
        self.beats
            .iter()
            .map(|beat| beat.steps.load(Ordering::SeqCst))
            .sum()
    }

    fn report(&self) -> String {
        self.beats
            .iter()
            .enumerate()
            .map(|(worker, beat)| format!("worker {worker}: {}", beat.report()))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Counts a worker's end however it ends, its unwinding included.
struct Ended<'a>(&'a AtomicUsize);

impl Drop for Ended<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// What one worker made.
#[derive(Clone, Copy, Debug, Default)]
struct Made {
    puts: u64,
    gets: u64,
    keyexprs: u64,
    subscribers: u64,
}

unsafe fn view(key: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut ke, key.as_ptr()),
        Z_OK,
        "{key:?}"
    );
    ke
}

/// The bytes of `payload`; none for a payload that cannot be read. Asserts nothing, so a callback
/// may call it.
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

/// The text of `keyexpr`; none for a key that cannot be read. Asserts nothing, so a callback may
/// call it.
unsafe fn text_of(keyexpr: *const z_loaned_keyexpr_t) -> Vec<u8> {
    let mut held: z_view_string_t = std::mem::zeroed();
    if keyexpr.is_null() || z_keyexpr_as_view_string(keyexpr, &mut held) != Z_OK {
        return Vec::new();
    }
    let loaned = z_view_string_loan(&held);
    let data = z_string_data(loaned);
    if data.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(data.cast::<u8>(), z_string_len(loaned)).to_vec()
}

unsafe fn open(endpoint_key: u8, endpoint: &str, limits: &str) -> z_owned_session_t {
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
    let limits = CString::new(limits).unwrap();
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            ZEXT_CONFIG_LIMITS_KEY,
            limits.as_ptr()
        ),
        Z_OK,
        "the build holds the limits {limits:?}"
    );
    let endpoint = CString::new(endpoint).unwrap();
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), endpoint_key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "the session opens on {endpoint:?}"
    );
    session
}

// ---------------------------------------------------------------------------------------------
// The listening peer: what it heard, and its answer to every get.

/// The payloads the listening peer's subscriber was handed, in the order it was handed them.
#[derive(Default)]
struct Heard {
    payloads: Mutex<Vec<Vec<u8>>>,
}

impl Heard {
    fn payloads(&self) -> Vec<Vec<u8>> {
        self.payloads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

unsafe extern "C" fn heard_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    let heard = &*(context as *const Heard);
    let payload = bytes_of(z_sample_payload(sample));
    if let Ok(mut payloads) = heard.payloads.lock() {
        payloads.push(payload);
    }
}

unsafe extern "C" fn heard_drop(context: *mut c_void) {
    drop(Arc::from_raw(context as *const Heard));
}

/// Every get is answered with the key it asked, so a worker can tell its answer from another's.
unsafe extern "C" fn answer_with_the_key(query: *const z_loaned_query_t, _context: *mut c_void) {
    let key = z_query_keyexpr(query);
    let text = text_of(key);
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    if z_bytes_copy_from_buf(&mut payload, text.as_ptr(), text.len()) == Z_OK {
        // A refused reply leaves the get with no answer, which its worker asserts.
        let _ = z_query_reply(query, key, z_bytes_move(&mut payload), std::ptr::null());
    }
}

/// The listening peer and what it holds.
struct Listener {
    session: z_owned_session_t,
    subscriber: z_owned_subscriber_t,
    queryable: z_owned_queryable_t,
    heard: Arc<Heard>,
}

unsafe fn listen(port: u16) -> Listener {
    // Every worker's get may be owed its end at once.
    let limits = format!("MAX_PENDING_FINALS={THREADS},MAX_PENDING_REPLIES={THREADS}");
    let session = open(
        Z_CONFIG_LISTEN_KEY,
        &format!("tcp/127.0.0.1:{port}"),
        &limits,
    );
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
    let ke = view(EVERY_PUT);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(&session),
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
            Some(answer_with_the_key),
            None,
            std::ptr::null_mut()
        ),
        Z_OK
    );
    let ke = view(EVERY_ASK);
    let mut opts: z_queryable_options_t = std::mem::zeroed();
    z_queryable_options_default(&mut opts);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(&session),
            &mut queryable,
            z_view_keyexpr_loan(&ke),
            z_closure_query_move(&mut closure),
            &opts,
        ),
        Z_OK
    );
    Listener {
        session,
        subscriber,
        queryable,
        heard,
    }
}

// ---------------------------------------------------------------------------------------------
// The calls a worker makes.

/// A put of `payload` on `key` that waits for room rather than being dropped.
unsafe fn put_on(
    session: &z_owned_session_t,
    key: *const z_loaned_keyexpr_t,
    payload: &[u8],
) -> ZResult {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
        Z_OK
    );
    let mut opts: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut opts);
    opts.congestion_control = CONGESTION_BLOCK;
    z_put(
        z_session_loan(session),
        key,
        z_bytes_move(&mut bytes),
        &opts,
    )
}

/// What one get was answered, and whether it has ended: its closure's drop is the library's word
/// that it has.
#[derive(Default)]
struct Replies {
    payloads: Mutex<Vec<Vec<u8>>>,
    ended: AtomicBool,
}

impl Replies {
    /// The answers, once the get has ended within `within`; `None` for a get still pending then.
    fn ended_within(&self, within: Duration) -> Option<Vec<Vec<u8>>> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.ended.load(Ordering::SeqCst) {
                return Some(
                    self.payloads
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }
}

unsafe extern "C" fn reply_heard(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    let replies = &*(context as *const Replies);
    let payload = if z_reply_is_ok(reply) {
        bytes_of(z_sample_payload(z_reply_ok(reply)))
    } else {
        b"an error reply".to_vec()
    };
    if let Ok(mut payloads) = replies.payloads.lock() {
        payloads.push(payload);
    }
}

unsafe extern "C" fn replies_end(context: *mut c_void) {
    let replies = Arc::from_raw(context as *const Replies);
    replies.ended.store(true, Ordering::SeqCst);
}

/// A get of `key`, sent.
unsafe fn get(session: &z_owned_session_t, key: &CStr) -> Arc<Replies> {
    let replies = Arc::new(Replies::default());
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(
            &mut closure,
            Some(reply_heard),
            Some(replies_end),
            Arc::into_raw(Arc::clone(&replies)) as *mut c_void,
        ),
        Z_OK
    );
    let ke = view(key);
    let mut opts: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut opts);
    opts.timeout_ms = u64::try_from(GET_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut opts,
        ),
        Z_OK,
        "the get of {key:?} is sent"
    );
    replies
}

unsafe extern "C" fn ignore_sample(_sample: *const z_loaned_sample_t, _context: *mut c_void) {}

unsafe extern "C" fn count_drop(context: *mut c_void) {
    let drops = Arc::from_raw(context as *const AtomicU64);
    drops.fetch_add(1, Ordering::SeqCst);
}

/// A subscriber on `key` whose callback's drop `drops` counts; the code of its declaration.
unsafe fn subscribe(
    session: &z_owned_session_t,
    key: &CStr,
    drops: &Arc<AtomicU64>,
) -> (ZResult, z_owned_subscriber_t) {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(ignore_sample),
            Some(count_drop),
            Arc::into_raw(Arc::clone(drops)) as *mut c_void,
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
    (rc, subscriber)
}

/// A key expression declared on `key`; the code of its declaration.
unsafe fn declare(session: &z_owned_session_t, key: &CStr) -> (ZResult, z_owned_keyexpr_t) {
    let ke = view(key);
    let mut declared: z_owned_keyexpr_t = std::mem::zeroed();
    let rc = z_declare_keyexpr(
        z_session_loan(session),
        &mut declared,
        z_view_keyexpr_loan(&ke),
    );
    (rc, declared)
}

/// What worker `worker` puts as its put number `seq`: whose it is, and where in its order.
fn payload(worker: usize, seq: u64) -> Vec<u8> {
    format!("{worker}:{seq}").into_bytes()
}

/// One worker's run: [`ROUNDS`] calls on the shared session, each checked as it returns.
fn work(worker: usize, shared: &Shared) -> Made {
    let _ended = Ended(&shared.ended);
    let beat = &shared.beats[worker];
    let session = &shared.dialler.0;
    let mut rng = Rng(SEED.wrapping_add(worker as u64));
    let drops = Arc::new(AtomicU64::new(0));
    let own_key = CString::new(format!("stress/put/t{worker}")).unwrap();
    let mut made = Made::default();
    for round in 0..ROUNDS {
        // The first rounds make every call once, whatever the seed draws after them.
        let call = if round < CALLS.len() as u64 {
            CALLS[(round as usize + worker) % CALLS.len()]
        } else {
            rng.call()
        };
        let at = format!("worker {worker}, round {round}, seed {SEED:#x}");
        beat.start(call, round);
        // SAFETY: the session is open until every worker has ended, and every handle made here is
        // let go of here, once.
        unsafe {
            match call {
                Call::Put => {
                    let ke = view(&own_key);
                    assert_eq!(
                        put_on(
                            session,
                            z_view_keyexpr_loan(&ke),
                            &payload(worker, made.puts)
                        ),
                        Z_OK,
                        "{at}: a put"
                    );
                    made.puts += 1;
                }
                Call::DeclaredPut => {
                    let key = CString::new(format!("stress/put/t{worker}/r{round}")).unwrap();
                    let (rc, mut declared) = declare(session, &key);
                    assert_eq!(rc, Z_OK, "{at}: the declaration of {key:?}");
                    assert_eq!(
                        text_of(z_keyexpr_loan(&declared)),
                        key.as_bytes(),
                        "{at}: the declared key reads back as it was asked"
                    );
                    assert_eq!(
                        put_on(
                            session,
                            z_keyexpr_loan(&declared),
                            &payload(worker, made.puts)
                        ),
                        Z_OK,
                        "{at}: a put through {key:?}"
                    );
                    made.puts += 1;
                    assert_eq!(
                        z_undeclare_keyexpr(z_session_loan(session), z_keyexpr_move(&mut declared)),
                        Z_OK,
                        "{at}: the undeclaration of {key:?}"
                    );
                    made.keyexprs += 1;
                }
                Call::Get => {
                    let key = CString::new(format!("stress/ask/t{worker}/r{round}")).unwrap();
                    let answers = get(session, &key).ended_within(ANSWER_WITHIN);
                    assert_eq!(
                        answers,
                        Some(vec![key.as_bytes().to_vec()]),
                        "{at}: the get of {key:?} ends with one answer, the key it asked"
                    );
                    made.gets += 1;
                }
                Call::Subscribe => {
                    let key = CString::new(format!("stress/sub/t{worker}/r{round}")).unwrap();
                    let (rc, mut subscriber) = subscribe(session, &key, &drops);
                    assert_eq!(rc, Z_OK, "{at}: the subscriber on {key:?}");
                    assert_eq!(
                        z_undeclare_subscriber(z_subscriber_move(&mut subscriber)),
                        Z_OK,
                        "{at}: the undeclaration of the subscriber on {key:?}"
                    );
                    made.subscribers += 1;
                }
            }
        }
        beat.end();
    }
    let deadline = Instant::now() + ANSWER_WITHIN;
    while drops.load(Ordering::SeqCst) < made.subscribers && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        made.subscribers,
        "worker {worker}: each subscriber's callback is let go of once"
    );
    made
}

/// Wait while the workers run; a run in which none makes a call for [`STALL`] fails with what
/// each was doing.
fn watch(shared: &Shared) {
    let mut seen = shared.steps();
    let mut moved = Instant::now();
    while shared.ended.load(Ordering::SeqCst) < THREADS {
        std::thread::sleep(Duration::from_millis(20));
        let steps = shared.steps();
        if steps != seen {
            seen = steps;
            moved = Instant::now();
            continue;
        }
        assert!(
            moved.elapsed() < STALL,
            "no worker made a call for {STALL:?} (seed {SEED:#x}): {}",
            shared.report()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The room of the session's tables.

/// How many key expressions the session declares before it refuses one, each declared on a key of
/// `phase` and undeclared after.
unsafe fn keyexpr_room(session: &z_owned_session_t, phase: &str) -> usize {
    let mut held = Vec::new();
    for at in 0..ROOM_PROBE {
        let key = CString::new(format!("stress/room/{phase}/k{at}")).unwrap();
        let (rc, declared) = declare(session, &key);
        if rc != Z_OK {
            break;
        }
        held.push(declared);
    }
    let room = held.len();
    for mut declared in held {
        assert_eq!(
            z_undeclare_keyexpr(z_session_loan(session), z_keyexpr_move(&mut declared)),
            Z_OK
        );
    }
    room
}

/// How many subscribers the session declares before it refuses one, each on a key of `phase` and
/// undeclared after.
unsafe fn subscriber_room(session: &z_owned_session_t, phase: &str) -> usize {
    let drops = Arc::new(AtomicU64::new(0));
    let mut held = Vec::new();
    for at in 0..ROOM_PROBE {
        let key = CString::new(format!("stress/room/{phase}/s{at}")).unwrap();
        let (rc, subscriber) = subscribe(session, &key, &drops);
        if rc != Z_OK {
            break;
        }
        held.push(subscriber);
    }
    let room = held.len();
    for mut subscriber in held {
        assert_eq!(
            z_undeclare_subscriber(z_subscriber_move(&mut subscriber)),
            Z_OK
        );
    }
    room
}

/// The room `measure` reads once it reads `before`, or the last it read within [`ANSWER_WITHIN`]:
/// a row a peer's answer still holds for a moment is not a row the run leaked.
fn room_settles_to(before: usize, mut measure: impl FnMut(usize) -> usize) -> usize {
    let deadline = Instant::now() + ANSWER_WITHIN;
    let mut attempt = 0;
    loop {
        let room = measure(attempt);
        if room == before || Instant::now() >= deadline {
            return room;
        }
        attempt += 1;
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------------------------
// The run.

/// Put a probe until the listener hears it, and get one until it is answered: the dialler then
/// knows the listener's subscriber and queryable, and every call of the run reaches them.
unsafe fn converge(dialler: &z_owned_session_t, heard: &Heard) {
    let deadline = Instant::now() + ANSWER_WITHIN;
    let probe = view(PROBE_PUT);
    while !heard
        .payloads()
        .iter()
        .any(|payload| payload == PROBE_PAYLOAD)
    {
        assert!(
            Instant::now() < deadline,
            "the listener never heard the probe put"
        );
        assert_eq!(
            put_on(dialler, z_view_keyexpr_loan(&probe), PROBE_PAYLOAD),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    loop {
        let answers = get(dialler, PROBE_ASK).ended_within(ANSWER_WITHIN);
        if answers == Some(vec![PROBE_ASK.to_bytes().to_vec()]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the listener never answered the probe get: {answers:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The puts the listener heard of each worker, in the order it heard them.
fn heard_by_worker(heard: &Heard) -> Vec<Vec<u64>> {
    let mut by_worker = vec![Vec::new(); THREADS];
    for payload in heard.payloads() {
        if payload == PROBE_PAYLOAD {
            continue;
        }
        let text = String::from_utf8(payload).expect("a worker's payload is text");
        let (worker, seq) = text.split_once(':').expect("a worker's payload");
        let worker: usize = worker.parse().expect("a worker's index");
        by_worker[worker].push(seq.parse().expect("a put's place in its order"));
    }
    by_worker
}

#[test]
fn threads_sharing_a_session_get_every_answer_they_ask_for() {
    let _program = crate::programs::admit();
    let port = free_port();
    // SAFETY: every handle is made here and let go of once at the end, after every worker ended.
    let listener = unsafe { listen(port) };
    // Each worker holds one subscriber, one declared key expression and one get at a time; twice
    // that, so a row let go of just after its call returns is no refusal of the next.
    let limits = format!(
        "MAX_SUBSCRIPTIONS={held},MAX_DECLARED_KEYEXPRS={held},MAX_PENDING_QUERIES={held}",
        held = 2 * THREADS
    );
    // SAFETY: as above.
    let dialler = unsafe {
        open(
            Z_CONFIG_CONNECT_KEY,
            &format!("tcp/127.0.0.1:{port}"),
            &limits,
        )
    };
    // SAFETY: both sessions are open.
    unsafe { converge(&dialler, &listener.heard) };
    // SAFETY: the dialler is open, and nothing else calls it now.
    let (keyexprs_before, subscribers_before) = unsafe {
        (
            keyexpr_room(&dialler, "before"),
            subscriber_room(&dialler, "before"),
        )
    };
    assert!(
        keyexprs_before >= THREADS && subscribers_before >= THREADS,
        "CONTROL: the dialler holds a row of each for every worker \
         ({keyexprs_before} key expressions, {subscribers_before} subscribers)"
    );

    let shared = Arc::new(Shared {
        dialler: Session(dialler),
        beats: (0..THREADS).map(|_| Beat::default()).collect(),
        ended: AtomicUsize::new(0),
    });
    let workers: Vec<_> = (0..THREADS)
        .map(|worker| {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name(format!("session-worker-{worker}"))
                .spawn(move || work(worker, &shared))
                .expect("a worker's thread")
        })
        .collect();
    watch(&shared);
    let made: Vec<Made> = workers
        .into_iter()
        .map(|worker| match worker.join() {
            Ok(made) => made,
            Err(panic) => std::panic::resume_unwind(panic),
        })
        .collect();
    for (worker, made) in made.iter().enumerate() {
        assert!(
            made.puts > 0 && made.gets > 0 && made.keyexprs > 0 && made.subscribers > 0,
            "CONTROL: worker {worker} made every call: {made:?}"
        );
    }

    let puts: u64 = made.iter().map(|made| made.puts).sum();
    let deadline = Instant::now() + ANSWER_WITHIN;
    while heard_by_worker(&listener.heard)
        .iter()
        .map(|seqs| seqs.len() as u64)
        .sum::<u64>()
        < puts
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    let heard = heard_by_worker(&listener.heard);
    for (worker, made) in made.iter().enumerate() {
        assert_eq!(
            heard[worker],
            (0..made.puts).collect::<Vec<_>>(),
            "worker {worker}'s puts reach the listener once each, in the order it made them \
             (seed {SEED:#x})"
        );
    }

    let dialler = &shared.dialler.0;
    // SAFETY: the dialler is open, and every worker has ended.
    let keyexprs_after = room_settles_to(keyexprs_before, |attempt| unsafe {
        keyexpr_room(dialler, &format!("after{attempt}"))
    });
    // SAFETY: as above.
    let subscribers_after = room_settles_to(subscribers_before, |attempt| unsafe {
        subscriber_room(dialler, &format!("after{attempt}"))
    });
    assert_eq!(
        (keyexprs_after, subscribers_after),
        (keyexprs_before, subscribers_before),
        "the run left the tables of declared key expressions and of subscribers as it found them"
    );

    let Ok(shared) = Arc::try_unwrap(shared) else {
        panic!("every worker has ended, and holds the shared state no more");
    };
    let Shared {
        dialler: Session(mut dialler),
        ..
    } = shared;
    let Listener {
        mut session,
        mut subscriber,
        mut queryable,
        heard: _,
    } = listener;
    // SAFETY: each handle is live and let go of once, here.
    unsafe {
        let _ = z_close(z_session_loan_mut(&mut dialler), std::ptr::null());
        z_session_drop(z_session_move(&mut dialler));
        assert_eq!(
            z_undeclare_subscriber(z_subscriber_move(&mut subscriber)),
            Z_OK
        );
        assert_eq!(
            z_undeclare_queryable(z_queryable_move(&mut queryable)),
            Z_OK
        );
        let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
}
