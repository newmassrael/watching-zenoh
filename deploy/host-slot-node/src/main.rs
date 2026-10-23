// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The kit's fixed-memory client node as a Linux process.
//!
//! The node of `deploy/zephyr-admin-node/rust/src/fixed_client.rs`: a client of a router that
//! answers queries, with every table it holds in a `static` this file declares, over the session
//! host and the dialler every stack shares (`wz_session_mcu::slot_host`, `slot_dial`,
//! `slot_client`), and the host's sockets as the stack (`wz_runtime_posix::net::PosixStack`).
//! The node's storage, its factory and its loop are `wz_session_mcu::slot_node`'s, written once
//! for every platform; this file is the host's part of it: the command line, the console and the
//! sleep ([`Port`]), and the getter.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, dialled | `NODE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | the link's receive buffer | `NODE.rx`, claimed by the session's driver | [`RX`] bytes |
//! | the frame being sent | `NODE.tx`, claimed by the session's driver | [`TX`] bytes |
//! | the observer, with the queryables | `NODE.app` | the registry's own capacity |
//! | the endpoint it dials | [`ROUTER`], set once from the command line | the connect manager's row |
//! | the declarations it sends | [`DECLARATIONS`], a `static` slice | its length |
//!
//! # What this build is, and is not
//!
//! It is `#![no_std]` and `#![no_main]` and declares no allocator, so the toolchain's own refusal
//! to link a program that allocates is the proof that this one does not: the node's code never
//! calls `malloc`. What it does NOT cover is the kernel, which allocates for the process (socket
//! buffers, page tables); and the C library's start-up, which runs before `main`.
//!
//! It is the same session code as the kit's image. What differs is the clock, the entropy, the
//! date, the socket and the entry point (`wz-runtime-posix`).
//!
//! ```text
//! host-slot-node <router a.b.c.d:port> [--local a.b.c.d] [--doc KEY:BYTES]...
//! ```
//!
//! It dials `udp/<router>`, declares a queryable under each `--doc` key (at most two), and answers
//! every query with a document of BYTES bytes under the key the query asked.
#![no_std]
#![no_main]

use core::cell::OnceCell;
use core::ffi::{c_char, c_int, CStr};
use core::fmt::{self, Write};

use wz_runtime_posix::glue::{log, log_args, yield_us};
use wz_runtime_posix::slot::PosixStack;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps::MAX_QUERYABLES;
use wz_session_core::connect_endpoints::{ConnectEndpoints, ConnectEntry, EndpointText};
use wz_session_core::entropy::EntropySource;
use wz_session_mcu::connect_manager::EndpointSource;
#[cfg(not(feature = "get"))]
use wz_session_mcu::slot_node::Answering;
use wz_session_mcu::slot_node::{
    ClientNode, Declared, Document, NodeIdentity, NodePort, NodeStorage,
};

wz_runtime_posix::posix_image_no_heap!();

#[cfg(feature = "get")]
mod getter;

/// Sessions the node holds at most: the one it dials.
const SESSIONS: usize = 1;
/// The runtime's task table: a pump task per session, and nothing else runs as a task.
const TASKS: usize = SESSIONS;
/// Bytes of one task cell: the pump's handle and the application layer's state. A task the cell
/// cannot hold is refused and counted, and the loop says so on the console rather than run a node
/// that never starts a session. A node that asks (`get`) keeps the session's pending queries in
/// that state, nine rows of the key text and the sink each, which is what the larger cell is for.
///
/// Measured on 2026-10-23 by building the node with each size and running it against a port
/// nobody listens on, which spawns the session's task and says whether the cell held it: the
/// answering node is refused at 2,112 bytes and held at 2,176, and the asking node is refused at
/// 2,304 and held at 2,560. The cells are the next steps up with about a fifth to spare. The 1,024
/// bytes the answering node had before refused its task, and so did the revision before
/// `slot_node` (so it is not that change's doing). The kit's cell is 384 bytes
/// (`fixed_client.rs`) and holds the session there.
const TASK_BYTES: usize = if cfg!(feature = "get") { 3072 } else { 2560 };
/// Timers the runtime holds: the handshake and lease deadlines of the session.
const TIMERS: usize = 4;
/// The batch the node advertises: an Ethernet frame less the IPv4 and UDP headers, as the kit's.
const BATCH_SIZE: u16 = (1500 - 20 - 8) as u16;
/// Extra bytes a link's receive buffer holds beyond one batch, so a datagram that carries a batch
/// and a transport header is not truncated.
const RX_SLACK: usize = 64;
/// The receive buffer of the session's driver.
const RX: usize = BATCH_SIZE as usize + RX_SLACK;
/// The storage the session's frames are encoded into: the largest frame it sends is one batch.
const TX: usize = BATCH_SIZE as usize;
/// How long the loop sleeps between two dials of a router that is not up: it holds no socket then,
/// and would otherwise spin.
const IDLE_SLEEP_US: u32 = 1_000;
/// The most the node's link waits for a datagram when its session has nothing due sooner. This
/// image has ONE session ([`SESSIONS`]) and its loop waits on nothing else, so the link may sleep
/// until the session's next deadline (the lease, the keep-alive) instead of waking every
/// millisecond; with more sessions this would leave the others' sockets unread. The link wakes
/// for a datagram at once, and arms its timeout at a power of two not above the deadline, so no
/// deadline is late.
const IDLE_WAIT_MS: u32 = 1_000;
/// The longest document a `--doc` may ask for.
const DOC_MAX: usize = 4096;
/// The queryables the node declares: as many as the image's limit says (`.cargo/config.toml`).
const DOCS: usize = 2;
/// The longest zenoh id: 16 bytes.
const ZID_LEN: usize = 16;

type Clock = PosixClock;
type Stack = PosixStack;

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker
/// places it in `.bss` and not in `.data` (`wz_session_mcu::slot_node`, shared with the kit).
type Storage = NodeStorage<Clock, Stack, PosixEntropy, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>;

static NODE: Storage = Storage::new();

/// The command line may not ask for more documents than the registry holds queryables
/// (`.cargo/config.toml` states the limit the image is built with).
const _: () = assert!(
    DOCS <= MAX_QUERYABLES,
    "DOCS exceeds the registry's queryable limit"
);

/// The bytes every document is made of. A document is a prefix of this, so the body a queryable
/// holds (`&'static str`) is a slice of one `static` and costs no allocation.
static BODY: [u8; DOC_MAX] = [b'x'; DOC_MAX];

/// The router the node dials, set once from the command line before the node starts.
struct Router {
    endpoint: OnceCell<EndpointText>,
}

// SAFETY: the profile's rule: one thread runs the program, and the cell is written once, in `run`,
// before the node that reads it exists.
unsafe impl Sync for Router {}

static ROUTER: Router = Router {
    endpoint: OnceCell::new(),
};

impl EndpointSource for Router {
    fn generation(&self) -> u32 {
        0
    }

    fn endpoints(&self) -> (u32, ConnectEndpoints) {
        let mut out = ConnectEndpoints::new();
        if let Some(text) = self.endpoint.get() {
            let _ = out.push(ConnectEntry::single(text.clone()));
        }
        (0, out)
    }
}

/// The queryables the node declares on each session, in the order of their registrations: a
/// `&'static [Declaration]` whose length the command line chose (at most [`DOCS`]), held in
/// storage this file declares.
static DECLARED: Declared<DOCS> = Declared::new();

/// The host's console and its sleep: what the node's loop cannot know (`wz_session_mcu::slot_node`).
struct Port;

impl NodePort for Port {
    const NAME: &'static str = "host-slot-node";

    fn log(&mut self, line: fmt::Arguments<'_>) {
        log_args(line);
    }

    fn idle(&mut self, us: u32) {
        yield_us(us);
    }
}

/// What the command line asked for.
struct Args {
    router: ([u8; 4], u16),
    local: [u8; 4],
    docs: [Option<(&'static str, usize)>; DOCS],
    /// The key to ask, how many times, and how long a query may stay pending (zero is the
    /// default).
    #[cfg(feature = "get")]
    get: Option<getter::Ask>,
}

/// A NUL-terminated argument as text that lives as long as the process does: `argv` is not freed
/// before the process ends.
fn argument(argv: *const *const c_char, at: c_int) -> Option<&'static str> {
    // SAFETY: `at` is below `argc`, so `argv[at]` is a valid pointer to a NUL-terminated string
    // the C runtime keeps for the life of the process.
    let text = unsafe { CStr::from_ptr(*argv.offset(at as isize)) };
    text.to_str().ok()
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut out {
        *octet = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// `a.b.c.d:port`.
fn parse_peer(text: &str) -> Option<([u8; 4], u16)> {
    let (ip, port) = text.rsplit_once(':')?;
    Some((parse_ipv4(ip)?, port.parse().ok()?))
}

fn parse_args(argc: c_int, argv: *const *const c_char) -> Result<Args, &'static str> {
    #[cfg(not(feature = "get"))]
    const USAGE: &str =
        "usage: host-slot-node <router a.b.c.d:port> [--local a.b.c.d] [--doc KEY:BYTES]...";
    #[cfg(feature = "get")]
    const USAGE: &str = "usage: host-slot-node <router a.b.c.d:port> [--local a.b.c.d] \
                         [--doc KEY:BYTES]... [--get KEY --count N [--warmup N] [--timeout-ms MS] \
                         [--inflight K] [--mailbox]]";
    let mut router = None;
    let mut local = [0u8; 4];
    let mut docs = [None; DOCS];
    let mut taken = 0;
    #[cfg(feature = "get")]
    let (mut get_key, mut get_count, mut get_timeout, mut get_warmup) = (None, 0u32, 0u32, 0u32);
    #[cfg(feature = "get")]
    let (mut get_inflight, mut get_mailbox) = (1u32, false);
    let mut at = 1;
    while at < argc {
        let arg = argument(argv, at).ok_or(USAGE)?;
        match arg {
            #[cfg(feature = "get")]
            "--get" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                get_key = Some(value.ok_or(USAGE)?);
            }
            #[cfg(feature = "get")]
            "--count" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                get_count = value.ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
            }
            #[cfg(feature = "get")]
            "--warmup" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                get_warmup = value.ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
            }
            #[cfg(feature = "get")]
            "--inflight" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                get_inflight = value.ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
                if !(1..=getter::MAX_INFLIGHT as u32).contains(&get_inflight) {
                    return Err("--inflight is from 1 to 8");
                }
            }
            #[cfg(feature = "get")]
            "--mailbox" => get_mailbox = true,
            #[cfg(feature = "get")]
            "--timeout-ms" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                get_timeout = value.ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
            }
            "--local" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                local = parse_ipv4(value.ok_or(USAGE)?).ok_or(USAGE)?;
            }
            "--doc" => {
                at += 1;
                let value = if at < argc { argument(argv, at) } else { None };
                let (key, bytes) = value.ok_or(USAGE)?.rsplit_once(':').ok_or(USAGE)?;
                let bytes: usize = bytes.parse().map_err(|_| USAGE)?;
                if bytes > DOC_MAX || taken == DOCS {
                    return Err("a --doc is at most 4096 bytes, and there are at most two");
                }
                docs[taken] = Some((key, bytes));
                taken += 1;
            }
            other => router = Some(parse_peer(other).ok_or(USAGE)?),
        }
        at += 1;
    }
    #[cfg(feature = "get")]
    let get = match (get_key, get_count) {
        (Some(key), count) if count > get_warmup => Some(getter::Ask {
            key,
            count,
            timeout_ms: get_timeout,
            warmup: get_warmup,
            inflight: get_inflight,
            mailbox: get_mailbox,
        }),
        (None, 0) => None,
        _ => return Err(USAGE),
    };
    Ok(Args {
        router: router.ok_or(USAGE)?,
        local,
        docs,
        #[cfg(feature = "get")]
        get,
    })
}

/// The documents the command line asked for, as the node registers them, and how many. A document
/// is a prefix of [`BODY`], so its text is a slice of one `static` and costs no allocation. The
/// reason, as the console line, when one is not text.
fn documents(
    docs: &[Option<(&'static str, usize)>; DOCS],
) -> Result<([Document; DOCS], usize), &'static str> {
    let mut out = [Document { key: "", body: "" }; DOCS];
    let mut taken = 0;
    for (key, bytes) in docs.iter().flatten() {
        // `BODY` is `x` throughout, so any prefix of it is text.
        let body = core::str::from_utf8(&BODY[..*bytes]).map_err(|_| "a document is not text")?;
        out[taken] = Document { key, body };
        taken += 1;
    }
    Ok((out, taken))
}

/// Assemble the node and run it. Returns only when it cannot start (or, for a getter, when its
/// queries have ended); the value is the process's exit code.
fn run(args: Args) -> i32 {
    // The cookie-signing key is a secret, so it comes from the kernel's entropy and a host that
    // cannot supply it stops the node: a predictable key is worse than no node.
    let mut key = [0u8; 32];
    let mut zid = [0u8; ZID_LEN];
    let mut entropy = PosixEntropy;
    if entropy.try_fill_bytes(&mut key).is_err() || entropy.try_fill_bytes(&mut zid).is_err() {
        log("wz: FAIL - getrandom could not fill the signing key");
        return 2;
    }

    let mut endpoint = EndpointText::new();
    let [a, b, c, d] = args.router.0;
    if write!(endpoint, "udp/{a}.{b}.{c}.{d}:{}", args.router.1).is_err() {
        log("wz: FAIL - the router endpoint is longer than a locator row");
        return 2;
    }
    let _ = ROUTER.endpoint.set(endpoint);

    let Some(identity) = NodeIdentity::new(&zid, key) else {
        log("wz: FAIL - the zenoh id does not fit");
        return 2;
    };
    let (documents, taken) = match documents(&args.docs) {
        Ok(found) => found,
        Err(why) => {
            log(why);
            return 3;
        }
    };
    #[cfg(feature = "get")]
    if let Some(ask) = &args.get {
        getter::PLAN.set(ask);
    }

    let node = ClientNode {
        storage: &NODE,
        declared: &DECLARED,
        clock: Clock::default(),
        stack: Stack::new(args.local, &NODE.rx, &NODE.tx).with_idle_wait_ms(IDLE_WAIT_MS),
        identity,
        batch_size: BATCH_SIZE,
        entropy: || PosixEntropy,
        endpoints: &ROUTER,
        documents: &documents[..taken],
        #[cfg(not(feature = "get"))]
        layer: Answering,
        #[cfg(feature = "get")]
        layer: getter::layer(),
        idle_sleep_us: IDLE_SLEEP_US,
        // The kit says how many times its loop went round to tell a node that sleeps from one
        // that polls; the host's lab reads the getter's own lines instead.
        report_every_ms: 0,
    };
    #[cfg(not(feature = "get"))]
    let mut app = ();
    #[cfg(feature = "get")]
    let mut app = getter::app();
    // The line a lab (or a person at the console) waits for, once the node is built: who it claims
    // to be and the router it dials.
    node.run(&mut Port, &mut app, |port, zid_hex| {
        port.log(format_args!(
            "HOST-WZ-CLIENT READY {zid_hex} udp/{a}.{b}.{c}.{d}:{}",
            args.router.1
        ));
    })
}

#[no_mangle]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    match parse_args(argc, argv) {
        Ok(args) => run(args),
        Err(usage) => {
            log(usage);
            64
        }
    }
}
