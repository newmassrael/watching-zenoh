// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the Zephyr image over Zephyr's own sockets on the fixed-memory profile
//! (`fixed-admin`, `CONFIG_WZ_FIXED_MEMORY` with a peer role on `CONFIG_WZ_NET_BACKEND_ZEPHYR_SOCKETS`):
//! the node of `wz_session_mcu::slot_admin::AcceptingAdminNode` with every table it holds in a
//! `static` this file declares, and no allocator.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, accepted and dialled | `STORAGE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | the link's receive buffer, the frame being sent | `STORAGE.rx`, `STORAGE.tx`, claimed by the session's driver | [`RX`], [`TX`] bytes |
//! | the observer, with the admin queryable and the config subscriber | [`install_observer`]'s `APP` | the registries' own capacities |
//! | the commanders of each verb | [`COMMANDERS`], read from the build when it compiles | [`MAX_COMMANDERS`] a verb |
//! | the host, the factory and the node | `STORAGE.run`, built once | [`RUN`] bytes, from the types' sizes |
//!
//! # What it takes, and from whom
//!
//! The node listens on `tls/` ([`TLS_PORT`]) and on nothing else: a zid is proven only by a secure
//! channel (decision D1 of `docs/session-lifecycle-intent.md`), and the authority over the four
//! lifecycle verbs is a function of the zid the link proved (decision D12). A peer that opens a
//! session over the channel is that peer's zid, and the verbs it asks are answered for it only if
//! the build listed it for them (`CONFIG_WZ_COMMANDERS_OPEN`, `_CLOSE`, `_RESET`, `_STATUS`, each a
//! comma-separated list of lowercase hex zids): a verb with no list is commanded by nobody. There
//! is no pipe on this image, so the lists are the whole authority, and an image built with none
//! binds the verbs for no one.
//!
//! # What this build is
//!
//! The Rust image has no allocator: it declares none (`zephyr_image_no_heap!`), and the session tier
//! is the slot profile's. The kernel's own heap (the network stack's and the POSIX layer's) is
//! `CONFIG_HEAP_MEM_POOL_SIZE`'s. The channel's arena is `CONFIG_MBEDTLS_HEAP_SIZE`'s, and the packet
//! and buffer pools a TLS server's first flight needs are the image's to state
//! (`overlays/qemu_admin_fixed_tls.conf` says why).

use core::cell::RefCell;
use core::fmt::Write;

use wz::runtime_zephyr::glue::{log, log_args, stack_usage, yield_us};
use wz::runtime_zephyr::net::await_board_ipv4;
use wz::runtime_zephyr::stack::StackWatch;
use wz::runtime_zephyr::stream::{ZephyrTcpDial, ZephyrTcpListener, ZephyrTcpSocket};
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_runtime_coop::ip_stack::IpTlsAcceptor;
use wz_runtime_coop::session_drive::{PumpSlots, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::entropy::EntropySource;
use wz_session_core::locator_directory::DirectoryZid;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed_with_open, AdminHost, AdminSinks, FixedNodeIdentity,
    FixedNodeStatus, Verbs,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::connect_manager::{CommanderList, Commanders, PeerStore, StoreNode};
use wz_session_mcu::run_arena::{run_bytes_needed, RunArena};
use wz_session_mcu::slot_admin::AcceptingAdminNode;
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;
use wz_tls_mbedtls::stream::{AcceptBudget, TlsDial, TlsListener};

use crate::fixed_tls::{self, Stack};
use crate::{BATCH_SIZE, IDLE_SLEEP_US, STACK_CHECK_MS, TICK_HZ};

/// The port the node accepts secure channels on.
pub const TLS_PORT: u16 = 7448;
/// Sessions the node holds at most, accepted and dialled together.
pub const SESSIONS: usize = 2;
/// Sessions a peer opened to the node that it holds at once.
const ACCEPTS: usize = 1;
/// Connections that may queue on the port before the node takes them off it.
const BACKLOG: u8 = 2;
/// The runtime's task table: a pump task per session, with room beside them.
const TASKS: usize = SESSIONS + 1;
/// Bytes of one task cell: the pump's handle and the application layer's state. The layer was about
/// 4.9 KB while its requesters (the registries of pending queries) were 4.8 KB of them, and an `async
/// fn` holds a by-value argument twice, so the cell was 12,288; with the limits this node does not use
/// stated as zero (`overlays/qemu_admin_fixed_tls.conf`) the pump's future is under 1,024 bytes (a cell
/// of 1,024 ran the whole witness on the kit, and a cell the future does not fit is refused at spawn,
/// which the witness would show), and the cell is twice that.
const TASK_BYTES: usize = 2048;
/// Timers the runtime holds: the handshake and lease deadlines of the sessions.
const TIMERS: usize = 4;
/// Extra bytes a link's receive buffer holds beyond one batch.
const RX_SLACK: usize = 64;
/// The receive buffer of a session's driver, and the storage its frames are encoded into.
const RX: usize = BATCH_SIZE as usize + RX_SLACK;
const TX: usize = BATCH_SIZE as usize;
/// The longest the listener lets one inbound handshake take, in milliseconds: a software P-256
/// handshake takes about a second and a half per role on the kit (Round 3495).
const ACCEPT_TIMEOUT_MS: u64 = 20_000;
/// The version the node reports.
const VERSION: &str = "wz-zephyr-admin-node";
/// How long the node waits for the board to have an address.
const ADDRESS_WAIT_MS: u32 = 30_000;
/// The widest locator text: `tls/255.255.255.255:65535`.
const LOCATOR_BYTES: usize = 32;
/// The most commanders one verb lists.
pub const MAX_COMMANDERS: usize = 4;

type Clock = ZephyrClock<TICK_HZ>;
type Driver = <Stack as SlotStack>::Driver;
type Host = SessionHost<Clock, Stack, ZephyrEntropy, SESSIONS, SESSIONS>;
type Acceptor = IpTlsAcceptor<
    TlsListener<ZephyrTcpListener>,
    wz::runtime_zephyr::net::ZephyrUdpSocket,
    ZephyrTcpSocket,
>;
type Node = AcceptingAdminNode<
    'static,
    Clock,
    Stack,
    Stack,
    Factory,
    Acceptor,
    SESSIONS,
    SESSIONS,
    ACCEPTS,
>;

/// The bytes of the arena the host, the factory and the node are built in: the sizes of the three,
/// so that a node that grows is a number that follows and not a start that fails.
const RUN: usize = run_bytes_needed(&[
    (core::mem::size_of::<Host>(), core::mem::align_of::<Host>()),
    (
        core::mem::size_of::<RefCell<Factory>>(),
        core::mem::align_of::<RefCell<Factory>>(),
    ),
    (core::mem::size_of::<Node>(), core::mem::align_of::<Node>()),
]);

type Slots =
    SessionSlots<CoopRuntime<Clock, Driver>, CoopTime<Clock>, Driver, ZephyrEntropy, SESSIONS>;
/// The bytes ONE typed session slot takes in this image, as the compiler lays it out for the target.
const SLOT_BYTES: usize = Slots::slot_bytes();

// The tables are held under the numbers the deploy file states for the machine (`session_pool`): the
// sessions fit the generated table, the runtime's tables fit the task and timer ceilings, and ONE
// typed session slot fits the generated slot ceiling. A deploy file that lowers a number, or an
// image that outgrows one, is a build failure that names the line.
const _: () = {
    use wz_session_core::caps::{MAX_TASKS, MAX_TIMERS};
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
};

/// The bytes of a cookie-signing key.
const SIGNING_KEY_BYTES: usize = 32;

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker places
/// it in `.bss`: one non-zero byte anywhere in a `static` moves all of it. What starts non-zero is in
/// [`Control`] and [`OPEN`], which are small.
struct Statics {
    runtime: RuntimeCell<Clock, TASKS, TASK_BYTES, TIMERS>,
    sessions: Slots,
    pumps: PumpSlots<Clock, <Stack as SlotStack>::Pump, SESSIONS, Driver>,
    /// The receive buffers the links claim, one batch long each.
    rx: ByteCells<RX, SESSIONS>,
    /// The buffers the links' frames are encoded into, one batch long each.
    tx: ByteCells<TX, SESSIONS>,
    /// The machines of what the node holds by its zid or dials, some 10 KB: here, with the other
    /// tables, and not on the stack of the thread that runs the node.
    peers: PeerStore,
    /// The host, the factory and the node, built once.
    run: RunArena<RUN>,
}

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative loop on one
// thread, which is the only thing that reaches these tables; each member is `Sync` by the same rule.
unsafe impl Sync for Statics {}

impl Statics {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            rx: ByteCells::new(),
            tx: ByteCells::new(),
            peers: PeerStore::new(),
            run: RunArena::new(),
        }
    }
}

static STORAGE: Statics = Statics::new();

/// What the node starts with and which is not zero: the counters and the write permit. Writes are
/// PERMITTED on this node: upstream's default is to refuse, and the node opts in, because being
/// reconfigured is what it is for.
struct Control {
    status: FixedNodeStatus<SESSIONS>,
    control: ConnectControl,
}

// SAFETY: the profile's rule: one cooperative loop on one thread reaches it.
unsafe impl Sync for Control {}

static CONTROL: Control = Control {
    status: FixedNodeStatus::new(true),
    control: ConnectControl::new(true),
};
static ADMIN: AdminHost<1024> = AdminHost::new();

/// The text of a build's commander list, or the empty list when the build states none.
macro_rules! commanders_of {
    ($name:literal) => {
        CommanderList::<MAX_COMMANDERS>::parse(match option_env!($name) {
            Some(text) => text,
            None => "",
        })
    };
}

/// The zids that may command each verb, read from the build when the image is compiled
/// (`CONFIG_WZ_COMMANDERS_*`): a text that is not a list of lowercase hex zids, or names more than
/// [`MAX_COMMANDERS`], stops the build. A verb with no list is commanded by nobody.
static OPEN_LIST: CommanderList<MAX_COMMANDERS> = commanders_of!("WZ_COMMANDERS_OPEN");
static CLOSE_LIST: CommanderList<MAX_COMMANDERS> = commanders_of!("WZ_COMMANDERS_CLOSE");
static RESET_LIST: CommanderList<MAX_COMMANDERS> = commanders_of!("WZ_COMMANDERS_RESET");
static STATUS_LIST: CommanderList<MAX_COMMANDERS> = commanders_of!("WZ_COMMANDERS_STATUS");

/// The one peer the build knows where to find (`CONFIG_WZ_PEER_NODE_ZID` and `_LOCATOR`): declared to
/// the node's directory at start as a permanent hint, so an `open` for that zid has a locator to dial
/// for it. Empty when the build states none.
static PEER_ZID: CommanderList<1> = CommanderList::parse(match option_env!("WZ_PEER_NODE_ZID") {
    Some(text) => text,
    None => "",
});
const PEER_LOCATOR: &str = match option_env!("WZ_PEER_NODE_LOCATOR") {
    Some(text) => text,
    None => "",
};

/// The node's in-band verbs: the store its connect manager holds the nodes in, judged by the lists
/// above. A `static` of its own, because it holds references and so does not start as zero bytes,
/// which is what keeps [`Storage`] in `.bss`. With `CONFIG_WZ_LIMIT_MAX_PEER_NODES` at its default
/// of zero the node has no room to hold a peer, and `open` answers `refused` for that, by name.
static OPEN: Verbs<StoreNode<Commanders>> = Verbs(StoreNode::new(
    &STORAGE.peers,
    Commanders {
        open: OPEN_LIST.as_slice(),
        close: CLOSE_LIST.as_slice(),
        reset: RESET_LIST.as_slice(),
        status: STATUS_LIST.as_slice(),
    },
));

/// The registrations the node's observer holds, all closed types: the config-write subscriber and
/// the admin queryable, which binds the in-band verbs.
type Sinks = AdminSinks<1024, SESSIONS, Verbs<StoreNode<Commanders>>>;

/// What the node makes its sessions from: the entropy, the parameters and the application layer (the
/// process-wide observer, with the node's own admin surface registered on it).
struct Factory {
    zid: [u8; CREDENTIAL_ZID_BYTES],
    key: [u8; SIGNING_KEY_BYTES],
    observer: &'static ObserverCell<Sinks>,
}

impl SessionFactory<Clock, Driver> for Factory {
    type Entropy = ZephyrEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, Sinks, Driver>;

    fn entropy(&mut self) -> ZephyrEntropy {
        ZephyrEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the receive slot holds whole. A node that accepts
    /// presents itself as a peer.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Peer,
            zid: zid_bytes(&self.zid),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: BATCH_SIZE,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }

    fn events(&mut self, handle: &SessionHandle<Clock, Driver>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// `tls/a.b.c.d:port` for `address`, in fixed text.
fn locator(address: [u8; 4]) -> FixedText<LOCATOR_BYTES> {
    let [a, b, c, d] = address;
    let mut text = FixedText::new();
    let _ = write!(text, "tls/{a}.{b}.{c}.{d}:{TLS_PORT}");
    text
}

/// Milliseconds on the kernel's monotonic tick: the clock the listener's deadline reads.
fn clock_ms() -> u64 {
    Clock::default().now_us() / 1000
}

/// Build the observer in `APP`, where it stays, and register the node's own surface on it: the
/// config-write subscriber and the admin queryable binding the in-band verbs. The reason, as the
/// console line, when one is refused.
///
/// Its own function, not inlined into [`start`], for the stack: the temporaries of the registration
/// are as large as a few KB, and a frame that holds them is held for as long as the node runs.
#[inline(never)]
fn install_observer(
    zid_hex: &str,
    locators: &[&str],
) -> Result<&'static ObserverCell<Sinks>, &'static core::ffi::CStr> {
    static APP: SlotApp<Sinks> = SlotApp::new();
    let identity = FixedNodeIdentity::new(zid_hex, "peer", VERSION, locators)
        .map_err(|_| c"wz: FAIL - the node's identity does not fit its fixed fields")?;
    let installed = APP.install_with(|observer| {
        if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &CONTROL.control)
            .is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused its config subscriber");
        }
        if host_admin_queryable_fixed_with_open(
            &mut observer.queryables,
            identity,
            &CONTROL.status,
            &ADMIN,
            Some(&CONTROL.control),
            Some(&CONTROL.control),
            &OPEN,
        )
        .is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused its admin queryable");
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err(c"wz: FAIL - the observer was installed twice"),
    }
}

/// The node, set up and not yet gone round: what [`run`]'s loop reads each pass.
struct Running {
    local: CoopLocalSet<Clock>,
    node: &'static mut Node,
}

/// Everything [`run`] does before the node's first round: the key, the address, the identity, the
/// listener and the node, set up. `Err` is the exit code of a node that could not start.
///
/// Out of line: [`run`] is the bottom of the main thread's stack for the node's whole life, so what
/// it holds is under every call the node makes, and the identity, the stack and the node's parts
/// are in this frame, which is gone before the first round.
#[inline(never)]
fn start() -> Result<Running, i32> {
    // The cookie-signing key is a secret, so it comes from the board's entropy source and a board
    // that cannot supply it stops the node: a predictable key is worse than no node.
    let mut key = [0u8; SIGNING_KEY_BYTES];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return Err(2);
    }
    let Some(address) = await_board_ipv4(ADDRESS_WAIT_MS) else {
        log(c"wz: FAIL - the board's interface never got an IPv4 address");
        return Err(1);
    };
    // The node's zid is the one its key names (decision D1), and its certificate is printed for the
    // peer's operator to pin.
    let channel = match fixed_tls::identity(c"CN=wz-zephyr-admin") {
        Ok(channel) => channel,
        Err(why) => {
            log(why);
            return Err(2);
        }
    };
    channel.certificate_pem(log_args);
    let zid: DirectoryZid = channel.zid();

    let mut zid_text: FixedText<33> = FixedText::new();
    write_zenoh_hex(&zid, &mut zid_text);
    let own_locator = locator(address);
    let observer = match install_observer(zid_text.prefix(), &[own_locator.prefix()]) {
        Ok(observer) => observer,
        Err(why) => {
            log(why);
            return Err(3);
        }
    };

    let Some(runtime) = STORAGE.runtime.start::<Driver>(Clock::default()) else {
        log(c"wz: FAIL - the runtime was started twice");
        return Err(3);
    };
    let local = CoopLocalSet::new(&runtime);
    let budget = AcceptBudget {
        clock: clock_ms,
        timeout_ms: ACCEPT_TIMEOUT_MS,
    };
    let stack = fixed_tls::accepting_stack(address, &STORAGE.rx, &STORAGE.tx, channel, budget);
    let Ok(port) = ZephyrTcpListener::listen(address, TLS_PORT, BACKLOG) else {
        log(c"wz: FAIL - the node could not listen on its secure port");
        return Err(3);
    };
    let Ok(listener) = TlsDial::new(ZephyrTcpDial, channel)
        .with_accept(budget)
        .listener(port)
    else {
        log(c"wz: FAIL - the node's listener could not take secure channels");
        return Err(3);
    };
    let acceptor = stack.tls_acceptor(listener);

    let host = STORAGE
        .run
        .put(|| {
            SessionHost::new(
                CoopLocalSet::new(&runtime),
                &STORAGE.sessions,
                &STORAGE.pumps,
                stack,
            )
        })
        .ok_or_else(|| {
            log(c"wz: FAIL - the node's arena was used before");
            3
        })?;
    let host: &'static Host = host;
    let factory = STORAGE
        .run
        .put(|| RefCell::new(Factory { zid, key, observer }))
        .ok_or(3)?;
    let factory: &'static RefCell<Factory> = factory;
    let node = AcceptingAdminNode::new(
        host,
        stack,
        acceptor,
        factory,
        &CONTROL.control,
        &STORAGE.peers,
        &CONTROL.status,
        zid_text.prefix(),
        "peer",
        SessionTimeouts::spec_defaults(),
    )
    .map_err(|_| {
        log(c"wz: FAIL - the node's admin keys do not fit");
        3
    })?;
    let node = STORAGE.run.put(|| node).ok_or(3)?;
    if let Some(peer) = PEER_ZID.as_slice().first() {
        let now_ms = Clock::default().now_us() / 1000;
        if node
            .core_mut()
            .declare_node(*peer, PEER_LOCATOR, now_ms)
            .is_err()
        {
            log(c"wz: FAIL - the peer the build names has no room in the node's directory");
            return Err(3);
        }
    }
    // The line a lane (or a person at the console) waits for: who the node claims to be and where it
    // takes secure channels.
    log_args(format_args!(
        "ZEPHYR-WZ-ADMIN READY {} {}",
        zid_text.prefix(),
        own_locator.prefix(),
    ));
    Ok(Running { local, node })
}

/// Assemble the node and run it. Returns only when it cannot start; the value is the reason, as a
/// nonzero code the C `main()` prints.
pub fn run() -> i32 {
    let running = match start() {
        Ok(running) => running,
        Err(code) => return code,
    };
    let clock = Clock::default();
    let mut reported = 0;
    // The node is the stack's only tenant, so its own reading of it is the one that counts: a line
    // when the peak grows, which a lane reads the last of.
    let mut stack = StackWatch::new();
    let mut next_stack_check_ms = 0u64;
    let mut arena_reported = 0usize;
    loop {
        running.local.run_until_idle();
        let now_ms = clock.now_us() / 1000;
        running.node.tick(now_ms);
        if now_ms >= next_stack_check_ms {
            next_stack_check_ms = now_ms + STACK_CHECK_MS;
            if let Some(usage) = stack.observe_peak(stack_usage()) {
                log_args(format_args!(
                    "stack: peak {} of {} bytes",
                    usage.peak(),
                    usage.size
                ));
            }
            // The channel's arena, read the same way: a line when its peak grows.
            if let Some((peak, size)) = fixed_tls::arena_peak_growth(&mut arena_reported) {
                log_args(format_args!("tls arena: peak {peak} of {size} bytes"));
            }
        }
        let sessions = CONTROL.status.session_count();
        if sessions != reported {
            reported = sessions;
            log_args(format_args!("zephyr-admin-node: {reported} session(s)"));
        }
        // The net stack's own threads, and the tick, need this thread's CPU: the sockets' stack is
        // run by the kernel, not polled from here, so every pass gives it a tick.
        yield_us(IDLE_SLEEP_US);
    }
}
