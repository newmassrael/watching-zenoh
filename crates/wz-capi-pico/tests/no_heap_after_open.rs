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
//! and then `ROUNDS` rounds with the allocator counting. One line per family is printed:
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

use std::ffi::CStr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use wz_capi_pico::abi::z_owned_keyexpr_t;
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_declare_keyexpr, z_declare_publisher, z_keyexpr_move, z_owned_bytes_t,
    z_owned_publisher_t, z_publisher_move, z_session_loan, z_undeclare_keyexpr,
    z_undeclare_publisher, z_view_keyexpr_loan, Z_OK,
};

#[path = "support/pipe_pair.rs"]
mod pipe_pair;

use pipe_pair::{
    close_window, count_panics, get, mark_calling_thread, open_window, payload, put, reply_closure,
    view, wait_for, Injecting, Pair, Seen, DATA_KEY, PANICS, WAIT_BOUND,
};

#[global_allocator]
static ALLOCATOR: Injecting = Injecting;

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
    LivelinessSub,
    QuerierDeclare,
    QuerierGet,
    ConfigClone,
    PublisherPut,
    Delete,
}

impl Round {
    /// Every round, in the order they are counted.
    const ALL: [Round; 20] = [
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
    ];

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
            | Round::Delete => true,
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
const FAMILIES: [(&str, Round, Part); 23] = [
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
    unsafe fn new() -> Self {
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
                std::ptr::null(),
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
    #[cfg(feature = "replay-cache")]
    replay: Replay,
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
        #[cfg(feature = "replay-cache")]
        let replay = Replay::new(&pair);
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
            #[cfg(feature = "replay-cache")]
            replay,
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

    unsafe fn publisher_declare(&self) {
        let ke = view(DATA_KEY);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(self.pair.dialler()),
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
        #[cfg(feature = "replay-cache")]
        self.replay.drop_all();
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

/// One window of `round`: the warm-up and the counted rounds.
unsafe fn window(bench: &mut Bench, round: Round) -> Seen {
    for _ in 0..WARM_UP {
        bench.run(round);
    }
    std::thread::sleep(SETTLE);
    open_window(0);
    for _ in 0..ROUNDS {
        bench.run(round);
    }
    std::thread::sleep(SETTLE);
    let seen = close_window();
    assert!(
        !seen.fired,
        "a window that fails nothing failed an allocation"
    );
    seen
}

/// Every window of `round`.
unsafe fn measure(bench: &mut Bench, round: Round) -> Vec<Seen> {
    let mut windows = Vec::with_capacity(WINDOWS);
    for _ in 0..WINDOWS {
        windows.push(window(bench, round));
    }
    windows
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

    count_panics();
    mark_calling_thread();
    let (seen, balanced, dropped) = unsafe {
        let mut bench = Bench::open();
        let seen: Vec<(Round, Vec<Seen>)> = Round::ALL
            .into_iter()
            .filter(|round| round.built())
            .map(|round| (round, measure(&mut bench, round)))
            .collect();
        let (balanced, dropped) = bench.close();
        (seen, balanced, dropped)
    };
    assert!(balanced, "every closure the library was handed is dropped");
    assert!(dropped, "both transports are let go");
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a thread panicked");

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
