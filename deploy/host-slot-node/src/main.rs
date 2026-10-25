// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The kit's fixed-memory client node as a Linux process.
//!
//! The node of `deploy/zephyr-admin-node/rust/src/fixed_client.rs`: a client of a router that
//! answers queries, with every table it holds in a `static` this file declares, over the session
//! host and the dialler every stack shares (`wz_session_mcu::slot_host`, `slot_dial`,
//! `slot_client`), and the host's sockets as the stack (`wz_runtime_posix::slot::PosixStack`),
//! which dials UDP or TCP as the router's locator names.
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
//! host-slot-node <router [udp/|tcp/|tls/]a.b.c.d:port> [--local a.b.c.d] [--doc KEY:BYTES]...
//! ```
//!
//! It dials the router (over UDP when the address names no scheme), declares a queryable under
//! each `--doc` key (at most two), and answers every query with a document of BYTES bytes under the
//! key the query asked. Built with `tls`, it can dial `tls/` (the secure channel, `tls.rs`), and
//! the line it prints when a session is established says whether the router's zid is the one the
//! key it proved names.
#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, CStr};

#[cfg(not(feature = "tls"))]
use host_slot_node_glue::fresh_zid;
#[cfg(feature = "tls")]
use host_slot_node_glue::tls;
use host_slot_node_glue::tuning::{
    BATCH_SIZE, DOC_MAX, IDLE_SLEEP_US, IDLE_WAIT_MS, RX, SESSIONS, TASKS, TASK_BYTES_ANSWERING,
    TASK_BYTES_ASKING, TIMERS, TX,
};
use host_slot_node_glue::{fresh_signing_key, ConsoleName, HostPort};
use wz_runtime_coop::session_drive::{IpEndpoint, Locator};
use wz_runtime_posix::glue::log;
#[cfg(feature = "tls")]
use wz_runtime_posix::glue::log_args;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::slot::PosixStack;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps::MAX_QUERYABLES;
use wz_session_mcu::dial::parse_locator;
#[cfg(not(feature = "get"))]
use wz_session_mcu::slot_client::Listening;
use wz_session_mcu::slot_node::Answering;
use wz_session_mcu::slot_node::{
    documents_of, BodyPool, ClientNode, Declared, Entities, NodeIdentity, NodePort, NodeStorage,
    SingleEndpoint,
};

wz_runtime_posix::posix_image_no_heap!();

#[cfg(feature = "get")]
mod getter;

/// Bytes of one task cell: the answering node's, or the asking node's when it can `get`
/// (`host_slot_node_glue::tuning` holds the measurements).
const TASK_BYTES: usize = if cfg!(feature = "get") {
    TASK_BYTES_ASKING
} else {
    TASK_BYTES_ANSWERING
};
/// The queryables the node declares: as many as the image's limit says (`.cargo/config.toml`).
const DOCS: usize = 2;

type Clock = PosixClock;
#[cfg(not(feature = "tls"))]
type Stack = PosixStack;
#[cfg(feature = "tls")]
type Stack = tls::Stack;

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
static BODY: BodyPool<DOC_MAX> = BodyPool::new();

/// The router the node dials, set once from the command line before the node starts.
static ROUTER: SingleEndpoint = SingleEndpoint::new();

/// The queryables the node declares on each session, in the order of their registrations: a
/// `&'static [Declaration]` whose length the command line chose (at most [`DOCS`]), held in
/// storage this file declares.
static DECLARED: Declared<DOCS> = Declared::new();

/// The name this front end's console lines carry.
struct Console;

impl ConsoleName for Console {
    const NAME: &'static str = "host-slot-node";
}

/// The host's console and its sleep: what the node's loop cannot know (`wz_session_mcu::slot_node`).
type Port = HostPort<Console>;

/// What the command line asked for.
struct Args {
    router: Locator,
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

/// `udp/a.b.c.d:port`, `tcp/a.b.c.d:port`, or `a.b.c.d:port`, which is UDP: the locator the
/// connect manager dials, read by the dialler's own reader.
fn parse_router(text: &str) -> Option<Locator> {
    if text.contains('/') {
        parse_locator(text).ok()
    } else {
        let (ip, port) = text.rsplit_once(':')?;
        Some(Locator::udp(IpEndpoint {
            addr: parse_ipv4(ip)?,
            port: port.parse().ok()?,
        }))
    }
}

fn parse_args(argc: c_int, argv: *const *const c_char) -> Result<Args, &'static str> {
    #[cfg(not(feature = "get"))]
    const USAGE: &str = "usage: host-slot-node <router [udp/|tcp/|tls/]a.b.c.d:port> \
                         [--local a.b.c.d] [--doc KEY:BYTES]...";
    #[cfg(feature = "get")]
    const USAGE: &str =
        "usage: host-slot-node <router [udp/|tcp/|tls/]a.b.c.d:port> [--local a.b.c.d] \
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
            other => router = Some(parse_router(other).ok_or(USAGE)?),
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

/// Assemble the node and run it. Returns only when it cannot start (or, for a getter, when its
/// queries have ended); the value is the process's exit code.
fn run(args: Args) -> i32 {
    // The cookie-signing key is a secret, so it comes from the kernel's entropy and a host that
    // cannot supply it stops the node: a predictable key is worse than no node.
    let key = match fresh_signing_key() {
        Ok(key) => key,
        Err(why) => {
            log(why);
            return 2;
        }
    };
    #[cfg(not(feature = "tls"))]
    let zid = match fresh_zid() {
        Ok(zid) => zid,
        Err(why) => {
            log(why);
            return 2;
        }
    };
    // Over the secure channel the node's zid is the one its key names (decision D1), and its
    // certificate is printed for the router's operator to pin.
    #[cfg(feature = "tls")]
    let (channel_identity, zid) = match tls::identity() {
        Ok(identity) => {
            identity.certificate_pem(log_args);
            (identity, identity.zid())
        }
        Err(why) => {
            log(why);
            return 2;
        }
    };

    if let Err(why) = ROUTER.set(&args.router) {
        log(why.message());
        return 2;
    }

    let Some(identity) = NodeIdentity::new(&zid, key) else {
        log("wz: FAIL - the zenoh id does not fit");
        return 2;
    };
    let (documents, taken) = match documents_of(&BODY, &args.docs) {
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
        #[cfg(not(feature = "tls"))]
        stack: Stack::new(args.local, &NODE.rx, &NODE.tx, PosixTcpDial)
            .with_idle_wait_ms(IDLE_WAIT_MS),
        #[cfg(feature = "tls")]
        stack: tls::stack(args.local, &NODE.rx, &NODE.tx, channel_identity)
            .with_idle_wait_ms(IDLE_WAIT_MS),
        listening: Listening::NONE,
        identity,
        batch_size: BATCH_SIZE,
        entropy: || PosixEntropy,
        endpoints: &ROUTER,
        documents: &documents[..taken],
        entities: Entities::NONE,
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
    node.run(&mut Port::new(), &mut app, |port, zid_hex| {
        port.log(format_args!(
            "HOST-WZ-CLIENT READY {zid_hex} {}",
            args.router
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
