// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The client node of the Zephyr image on the fixed-memory profile: the node of `run_client` in
//! `lib.rs` with every table it holds in a `static` this file declares. The node itself (its
//! storage, its factory, its documents and the loop that drives it) is
//! `wz_session_mcu::slot_node`, which `deploy/host-slot-node` runs too; this file is the board's
//! half of it: Zephyr's sockets as the stack (`wz_runtime_zephyr::net::ZephyrStack`), the board's
//! clock, entropy, address and identity, and its console and stack watch as the [`ZephyrPort`].
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, dialled | `NODE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | the link's receive buffer | `NODE.rx`, claimed by the session's driver | [`RX`] bytes |
//! | the frame being sent | `NODE.tx`, claimed by the session's driver | [`TX`] bytes |
//! | the observer, with the two queryables | `NODE.app` | the registry's own capacity |
//! | the endpoint it dials | [`crate::ENDPOINTS`], a `static` list | the connect manager's rows |
//! | the declarations it sends | [`DECLARED`], a `static` list | [`DOCS`] |
//!
//! # What this build is, and is not
//!
//! The node's own storage is above, and with it the Rust image has NO allocator: it declares none
//! (`zephyr_image_no_heap!`), `wz-runtime-zephyr` is built without its `alloc`, and the session
//! tier is the slot profile's, so no crate of the graph names `alloc`. The no-allocator link gate
//! takes that as its proof: a program that allocates anywhere does not link without a global
//! allocator. What it does NOT cover is the Zephyr kernel's own heap (its network stack and POSIX
//! layer), which the image still configures; `CONFIG_HEAP_MEM_POOL_SIZE` is what the kernel is
//! given for it, and what the kernel takes of it after start-up is measured, not assumed.
//!
//! The CMake build selects this profile with `CONFIG_WZ_FIXED_MEMORY` for the client node
//! (`CONFIG_WZ_ROLE_CLIENT`), the same switch the lwIP admin node has.

use core::fmt;

use wz::runtime_zephyr::glue::{log, log_args, stack_usage, yield_us};
use wz::runtime_zephyr::net::await_board_ipv4;
#[cfg(not(feature = "tls"))]
use wz::runtime_zephyr::net::{board_zid_fixed, ZephyrStack};
use wz::runtime_zephyr::stack::StackWatch;
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_runtime_coop::session_drive::SlotStack;
use wz_runtime_coop::{CoopRuntime, CoopTime};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_slot::SessionSlots;
#[cfg(not(feature = "get"))]
use wz_session_mcu::slot_node::Answering;
use wz_session_mcu::slot_node::{
    ClientNode, Declared, Document, Entities, NodeIdentity, NodePort, NodeStorage,
    SIGNING_KEY_BYTES,
};

use crate::{
    BATCH_SIZE, CONFIG_BODY, CONFIG_KEY, ENDPOINTS, IDLE_SLEEP_US, NODE_ID, STACK_CHECK_MS,
    STATUS_BODY, STATUS_KEY, TICK_HZ,
};

/// Sessions the node holds at most: the one it dials.
const SESSIONS: usize = 1;
/// The runtime's task table: a pump task per session, and nothing else runs as a task.
const TASKS: usize = SESSIONS;
/// Bytes of one task cell: the pump's handle and the application layer's state. The layer is a
/// few pointers, because a node that asks nothing keeps no table of requests (`Answering`, with
/// the pending-query limits at 0), and an `async fn` holds a by-value argument twice. A task the
/// cell cannot hold is refused and counted, and the loop says so on the console ("wz: FAIL - ...")
/// rather than run a node that never starts a session. A node that asks (`get`) keeps the session's
/// pending queries in that state, so its cell grows with the rows of that table
/// (`fixed_get::TASK_BYTES`, from sizes measured on the kit).
#[cfg(not(feature = "get"))]
const TASK_BYTES: usize = 384;
#[cfg(feature = "get")]
const TASK_BYTES: usize = crate::fixed_get::TASK_BYTES;
/// Timers the runtime holds: the handshake and lease deadlines of the session.
const TIMERS: usize = 4;
/// Extra bytes a link's receive buffer holds beyond one batch, so a datagram that carries a batch
/// and a transport header is not truncated.
const RX_SLACK: usize = 64;
/// The receive buffer of the session's driver.
const RX: usize = BATCH_SIZE as usize + RX_SLACK;
/// The storage the session's frames are encoded into: the largest frame it sends is one batch, which
/// is the budget the driver states as its link's frame bound.
const TX: usize = BATCH_SIZE as usize;
/// The queryables the node declares: its status and its config.
const DOCS: usize = 2;
/// How long the node waits for the board to have an address: a DHCP lease on a slow link takes
/// seconds, and a board with no link or no server never gets one.
const ADDRESS_WAIT_MS: u32 = 30_000;

/// The most the node's link sleeps when its session has nothing due sooner
/// (`CONFIG_WZ_IDLE_WAIT_MS`, handed to cargo as `WZ_IDLE_WAIT_MS`); 0 keeps the tick. The node
/// holds ONE session and its loop waits on nothing else, which is what lets its link sleep.
const IDLE_WAIT_MS: u32 = match parse_decimal(match option_env!("WZ_IDLE_WAIT_MS") {
    Some(text) => text,
    None => "0",
}) {
    Some(value) => value,
    None => panic!("WZ_IDLE_WAIT_MS is not a decimal number"),
};

/// A decimal number read when the image compiles, so that a value the build was given that is not
/// one (empty, a sign, a letter, past `u32`) stops the build instead of reading as zero.
pub(crate) const fn parse_decimal(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u32;
    let mut at = 0;
    while at < bytes.len() {
        let digit = bytes[at];
        if !digit.is_ascii_digit() {
            return None;
        }
        value = match value.checked_mul(10) {
            Some(shifted) => match shifted.checked_add((digit - b'0') as u32) {
                Some(next) => next,
                None => return None,
            },
            None => return None,
        };
        at += 1;
    }
    Some(value)
}

/// How often the loop says how many times it went round: the figure that tells a node that
/// sleeps from one that polls.
const LOOP_REPORT_MS: u64 = 5_000;

/// The loop's sleep between two dials, in the unit the node takes. The kernel sleep the image
/// states ([`IDLE_SLEEP_US`]) is a signed microsecond count, and one that is not positive would
/// let the loop spin above the network stack's threads.
const IDLE_SLEEP: u32 = {
    assert!(IDLE_SLEEP_US > 0, "the idle sleep is not positive");
    IDLE_SLEEP_US as u32
};

pub(crate) type Clock = ZephyrClock<TICK_HZ>;
#[cfg(not(feature = "tls"))]
type Stack = ZephyrStack;
#[cfg(feature = "tls")]
type Stack = crate::fixed_tls::Stack;

/// The table of session slots this image places, as the node's storage holds it: one type for the
/// assertion below and the probe.
type Slots = SessionSlots<
    CoopRuntime<Clock>,
    CoopTime<Clock>,
    <Stack as SlotStack>::Driver,
    ZephyrEntropy,
    SESSIONS,
>;
/// The bytes ONE typed session slot takes in this image, as the compiler lays it out for the
/// target the image is built for.
const SLOT_BYTES: usize = Slots::slot_bytes();

/// The measured size of one typed session slot, as the SIZE of a symbol: see `fixed_node.rs`.
#[cfg(feature = "slot-bytes-probe")]
#[no_mangle]
#[used]
pub static WZ_SESSION_SLOT_BYTES: [u8; SLOT_BYTES] = [0; SLOT_BYTES];

// The tables are held under the numbers the deploy file states for the machine (`session_pool`):
// the sessions fit the generated table, the runtime's tables fit the task and timer ceilings,
// ONE typed session slot, as the compiler lays it out for the target, fits the generated slot
// ceiling, and the registry holds the node's queryables. A deploy file that lowers a number, or
// an image that outgrows one, is a build failure that names the line.
const _: () = {
    use wz_session_core::caps::{MAX_QUERYABLES, MAX_TASKS, MAX_TIMERS};
    use wz_session_core::session_slot_pool_mcu::{SLOT_COUNT, SLOT_SIZE};
    assert!(
        SESSIONS <= SLOT_COUNT,
        "SESSIONS exceeds the generated session table"
    );
    assert!(
        TASKS <= MAX_TASKS,
        "TASKS exceeds the deploy file's max_tasks"
    );
    assert!(
        TIMERS <= MAX_TIMERS,
        "TIMERS exceeds the deploy file's max_timers"
    );
    assert!(
        SLOT_BYTES <= SLOT_SIZE,
        "one typed session slot exceeds the generated slot ceiling"
    );
    assert!(
        DOCS <= MAX_QUERYABLES,
        "DOCS exceeds the registry's queryable limit"
    );
};

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker
/// places it in `.bss` (RAM) and not in `.data` (RAM and a copy of it in flash): one non-zero byte
/// anywhere in a `static` moves all of it (`wz_session_mcu::slot_node`, shared with the host).
type Storage =
    NodeStorage<Clock, Stack, ZephyrEntropy, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>;

static NODE: Storage = Storage::new();

/// The queryables the node declares on each session, in the order of their registrations.
static DECLARED: Declared<DOCS> = Declared::new();

/// What the node answers: its connect status and its config, under its admin keys.
const DOCUMENTS: [Document; DOCS] = [
    Document {
        key: STATUS_KEY,
        body: STATUS_BODY,
    },
    Document {
        key: CONFIG_KEY,
        body: CONFIG_BODY,
    },
];

/// The board's console and sleep, and its stack watch: what the node's loop cannot know.
struct ZephyrPort {
    stack_watch: StackWatch,
    next_stack_check_ms: u64,
}

impl NodePort for ZephyrPort {
    const NAME: &'static str = "zephyr-wz-client";

    fn log(&mut self, line: fmt::Arguments<'_>) {
        log_args(line);
    }

    fn idle(&mut self, us: u32) {
        yield_us(i32::try_from(us).unwrap_or(i32::MAX));
    }

    /// The stack's high-water mark, when it rises. The read walks the whole stack, so it is made
    /// every [`STACK_CHECK_MS`] and not on every round; the mark persists, so a peak between two
    /// reads is not lost.
    fn observe(&mut self, now_ms: u64) {
        if now_ms < self.next_stack_check_ms {
            return;
        }
        self.next_stack_check_ms = now_ms + STACK_CHECK_MS;
        if let Some(usage) = self.stack_watch.observe_peak(stack_usage()) {
            log_args(format_args!(
                "stack: peak {} of {} bytes",
                usage.peak(),
                usage.size
            ));
        }
    }
}

/// Assemble the node and run it. Returns only when it cannot start; the value is the reason, as a
/// nonzero code the C `main()` prints. The heap client's `run_client`, over the statics above.
pub fn run() -> i32 {
    // The cookie-signing key is a secret, so it comes from the board's entropy source and a board
    // that cannot supply it stops the node: a predictable key is worse than no node.
    let mut key = [0u8; SIGNING_KEY_BYTES];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return 2;
    }
    let Some(address) = await_board_ipv4(ADDRESS_WAIT_MS) else {
        log(c"wz: FAIL - the board's interface never got an IPv4 address");
        return 1;
    };
    // Over the secure channel the node's zid is the one its key names (decision D1), and its
    // certificate is printed for the router's operator to pin; otherwise the board derives it.
    #[cfg(feature = "tls")]
    let channel = match crate::fixed_tls::identity() {
        Ok(channel) => channel,
        Err(why) => {
            log(why);
            return 2;
        }
    };
    #[cfg(feature = "tls")]
    let identity = {
        channel.certificate_pem(log_args);
        NodeIdentity::new(&channel.zid(), key)
    };
    #[cfg(not(feature = "tls"))]
    let identity = board_zid_fixed().and_then(|(zid, len)| NodeIdentity::new(&zid[..len], key));
    let Some(identity) = identity else {
        log(c"wz: FAIL - the board gave no identity to derive a zenoh id from");
        return 1;
    };

    #[cfg(not(feature = "tls"))]
    let stack = Stack::new(address, &NODE.rx, &NODE.tx);
    #[cfg(feature = "tls")]
    let stack = crate::fixed_tls::stack(address, &NODE.rx, &NODE.tx, channel);
    let stack = if IDLE_WAIT_MS > 0 {
        stack.with_idle_wait_ms(IDLE_WAIT_MS)
    } else {
        stack
    };
    // A node that asks has its getter's layer and application; one that only answers has neither.
    #[cfg(not(feature = "get"))]
    let (layer, mut app) = (Answering, ());
    #[cfg(feature = "get")]
    let (layer, mut app) = {
        crate::fixed_get::PLAN.set(&crate::fixed_get::ASK);
        (crate::fixed_get::layer(), crate::fixed_get::app())
    };
    let node = ClientNode {
        storage: &NODE,
        declared: &DECLARED,
        clock: Clock::default(),
        stack,
        identity,
        batch_size: BATCH_SIZE,
        entropy: || ZephyrEntropy,
        endpoints: &ENDPOINTS,
        documents: &DOCUMENTS,
        entities: Entities::NONE,
        layer,
        idle_sleep_us: IDLE_SLEEP,
        report_every_ms: LOOP_REPORT_MS,
    };
    let mut port = ZephyrPort {
        stack_watch: StackWatch::new(),
        next_stack_check_ms: 0,
    };
    // The line a lane (or a person at the console) waits for: who the node claims to be and the
    // router it dials.
    node.run(&mut port, &mut app, |_, zid_hex| {
        log_args(format_args!(
            "ZEPHYR-WZ-CLIENT READY {} {} {}",
            NODE_ID,
            zid_hex,
            env!("WZ_CLIENT_ENDPOINT")
        ));
    })
}
