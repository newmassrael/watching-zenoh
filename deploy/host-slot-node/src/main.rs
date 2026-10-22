// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The kit's fixed-memory client node as a Linux process.
//!
//! The node of `deploy/zephyr-admin-node/rust/src/fixed_client.rs`: a client of a router that
//! answers queries, with every table it holds in a `static` this file declares, over the session
//! host and the dialler every stack shares (`wz_session_mcu::slot_host`, `slot_dial`,
//! `slot_client`), and the host's sockets as the stack (`wz_runtime_posix::net::PosixStack`).
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

use core::cell::{Cell, OnceCell, RefCell, UnsafeCell};
use core::ffi::{c_char, c_int, CStr};
use core::fmt::Write;

use wz_runtime_coop::session_drive::{DriverPump, PumpSlots};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_runtime_posix::glue::{log, log_args, yield_us};
use wz_runtime_posix::slot::{PosixStack, PosixUdpDriver};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::connect_endpoints::{ConnectEndpoints, ConnectEntry, EndpointText};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{
    cookie_bytes, zid_bytes, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::connect_manager::EndpointSource;
use wz_session_mcu::slot_client::{
    register_document, Declaration, DeclarationKind, DocumentSinks, SlotClientNode,
};
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;

wz_runtime_posix::posix_image_no_heap!();

/// Sessions the node holds at most: the one it dials.
const SESSIONS: usize = 1;
/// The runtime's task table: a pump task per session, and nothing else runs as a task.
const TASKS: usize = SESSIONS;
/// Bytes of one task cell: the pump's handle and the application layer's state. Wider than the
/// kit's 384 because a pointer is eight bytes here, not four. A task the cell cannot hold is
/// refused and counted, and the loop says so on the console rather than run a node that never
/// starts a session.
const TASK_BYTES: usize = 1024;
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
/// The requests a session of this node holds: none, as the kit's client asks nothing.
type Requests = Requesters<NoReplies, NoReplies>;
type Driver = PosixUdpDriver;
type Stack = PosixStack;
type Slots = SessionSlots<CoopRuntime<Clock>, CoopTime<Clock>, Driver, PosixEntropy, SESSIONS>;
type Host = SessionHost<Clock, Stack, PosixEntropy, SESSIONS, SESSIONS>;

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker
/// places it in `.bss` and not in `.data`.
struct Statics {
    runtime: RuntimeCell<Clock, TASKS, TASK_BYTES, TIMERS>,
    sessions: Slots,
    pumps: PumpSlots<Clock, DriverPump<Driver>, SESSIONS>,
    app: SlotApp<DocumentSinks>,
    /// The receive buffers the links claim, one batch long each.
    rx: ByteCells<RX, SESSIONS>,
    /// The buffers the links' frames are encoded into, one batch long each.
    tx: ByteCells<TX, SESSIONS>,
}

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative loop on
// one thread, which is the only thing that reaches these tables; each member is `Sync` by the
// same rule.
unsafe impl Sync for Statics {}

impl Statics {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            app: SlotApp::new(),
            rx: ByteCells::new(),
            tx: ByteCells::new(),
        }
    }
}

static NODE: Statics = Statics::new();

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
/// `&'static [Declaration]` whose length the command line chose, held in storage this file
/// declares.
struct Declared {
    items: UnsafeCell<[Declaration; DOCS]>,
    len: Cell<usize>,
}

// SAFETY: the profile's rule: one thread runs the program, and the list is written only by
// `install_observer`, before the node that reads it exists.
unsafe impl Sync for Declared {}

const NO_DECLARATION: Declaration = Declaration {
    kind: DeclarationKind::Queryable,
    key: "",
};

static DECLARED: Declared = Declared {
    items: UnsafeCell::new([NO_DECLARATION; DOCS]),
    len: Cell::new(0),
};

impl Declared {
    /// Add a declaration. `false` when the list is full.
    fn push(&self, declaration: Declaration) -> bool {
        let at = self.len.get();
        if at == DOCS {
            return false;
        }
        // SAFETY: nothing holds a reference into the list yet (`all` is called after the last
        // push), and one thread runs the program.
        unsafe { (*self.items.get())[at] = declaration };
        self.len.set(at + 1);
        true
    }

    /// The declarations made so far, as the node holds them for the life of the process.
    fn all(&'static self) -> &'static [Declaration] {
        // SAFETY: called once, after the last `push`; nothing writes the list afterwards. The
        // pointer is to the first of `DOCS` declarations and `len` is at most `DOCS`.
        unsafe {
            core::slice::from_raw_parts(self.items.get().cast::<Declaration>(), self.len.get())
        }
    }
}

/// What the node makes its sessions from: the entropy, the parameters and the application layer
/// (the process-wide observer, with the queryables registered on it).
struct Factory {
    zid: [u8; ZID_LEN],
    key: [u8; 32],
    observer: &'static ObserverCell<DocumentSinks>,
}

impl SessionFactory<Clock> for Factory {
    type Entropy = PosixEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, DocumentSinks>;

    fn entropy(&mut self) -> PosixEntropy {
        PosixEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the receive slot holds whole.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Client,
            zid: zid_bytes(&self.zid),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: BATCH_SIZE,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: TxQueueConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }

    fn events(&mut self, handle: &SessionHandle<Clock>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requests::new())
    }
}

/// What the command line asked for.
struct Args {
    router: ([u8; 4], u16),
    local: [u8; 4],
    docs: [Option<(&'static str, usize)>; DOCS],
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
    const USAGE: &str =
        "usage: host-slot-node <router a.b.c.d:port> [--local a.b.c.d] [--doc KEY:BYTES]...";
    let mut router = None;
    let mut local = [0u8; 4];
    let mut docs = [None; DOCS];
    let mut taken = 0;
    let mut at = 1;
    while at < argc {
        let arg = argument(argv, at).ok_or(USAGE)?;
        match arg {
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
    Ok(Args {
        router: router.ok_or(USAGE)?,
        local,
        docs,
    })
}

/// Build the observer in `NODE.app`, where it stays, and register the node's queryables on it. The
/// reason, as the console line, when one is refused.
///
/// Its own function, not inlined into [`run`], for the stack: the observer itself is large and is
/// never a value.
#[inline(never)]
fn install_observer(
    docs: &[Option<(&'static str, usize)>; DOCS],
) -> Result<&'static ObserverCell<DocumentSinks>, &'static str> {
    let installed = NODE.app.install_with(|observer| {
        for doc in docs {
            let Some((key, bytes)) = doc else { continue };
            // `BODY` is `x` throughout, so any prefix of it is text.
            let body =
                core::str::from_utf8(&BODY[..*bytes]).map_err(|_| "a document is not text")?;
            register_document(&mut observer.queryables, key, body)
                .map_err(|_| "wz: FAIL - the node's observer refused a queryable")?;
            if !DECLARED.push(Declaration {
                kind: DeclarationKind::Queryable,
                key,
            }) {
                return Err("wz: FAIL - more documents than declarations");
            }
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err("wz: FAIL - the observer was installed twice"),
    }
}

/// Assemble the node and run it. Returns only when it cannot start; the value is the process's exit
/// code.
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

    let clock = Clock::default();
    let Some(runtime) = NODE.runtime.start(clock) else {
        log("wz: FAIL - the runtime was started twice");
        return 3;
    };
    let local = CoopLocalSet::new(&runtime);

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&zid, &mut zid_text);
    let zid_hex = zid_text.prefix();

    // The application's registrations, on the observer the session dispatches to. A node whose
    // registrations were refused would declare what nothing answers: stop instead, with the
    // reason.
    let observer = match install_observer(&args.docs) {
        Ok(observer) => observer,
        Err(why) => {
            log(why);
            return 3;
        }
    };
    let stack = Stack::new(args.local, &NODE.rx, &NODE.tx).with_idle_wait_ms(IDLE_WAIT_MS);
    let host: Host = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &NODE.sessions,
        &NODE.pumps,
        stack,
    );
    let factory = RefCell::new(Factory { zid, key, observer });
    let mut node = SlotClientNode::new(
        &host,
        stack,
        &factory,
        &ROUTER,
        SessionTimeouts::spec_defaults(),
        DECLARED.all(),
    );
    // The line a lab (or a person at the console) waits for: who the node claims to be and the
    // router it dials.
    log_args(format_args!(
        "HOST-WZ-CLIENT READY {zid_hex} udp/{a}.{b}.{c}.{d}:{}",
        args.router.1
    ));

    let mut established = false;
    let mut refused = (runtime.task_refusals(), runtime.timer_refusals());
    loop {
        local.run_until_idle();
        let now_ms = clock.now_us() / 1000;
        node.tick(now_ms);
        // A table the image sized too small refuses what it cannot hold and counts it; the
        // count moving is a node that is not doing what it was built to, so it is said.
        let now = (runtime.task_refusals(), runtime.timer_refusals());
        if now != refused {
            refused = now;
            log_args(format_args!(
                "wz: FAIL - the runtime refused a task or a timer: no cell {}, too large {}, timers {}",
                now.0.no_task_cell, now.0.too_large, now.1
            ));
        }
        // A line when the session comes and goes, which is all a lab waits for.
        if node.is_established() != established {
            established = !established;
            log_args(format_args!(
                "host-slot-node: session {}",
                if established { "established" } else { "lost" }
            ));
        }
        // The socket's own wait is what gives the CPU away while a session is held (its read waits
        // for a datagram). Between two dials of a router that is not up the node holds no socket:
        // it sleeps the tick itself then, or it spins.
        if !node.holds_session() {
            yield_us(IDLE_SLEEP_US);
        }
    }
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
