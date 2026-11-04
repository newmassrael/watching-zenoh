// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the Zephyr image over lwIP on the fixed-memory profile with its links on
//! `tcp/` (`fixed-tcp`, `CONFIG_WZ_LINK_TCP` beside `CONFIG_WZ_NET_BACKEND_LWIP_MAC` and
//! `CONFIG_WZ_FIXED_MEMORY`): `wz_session_mcu::slot_admin::AcceptingAdminNode` over the stack of
//! lwIP's streams (`wz_session_lwip::stream::LwipTcpStack`), with every table it holds in a `static`
//! this file declares, and no allocator. It is `fixed_node`'s twin with the datagram links replaced
//! by stream links: the MAC bring-up, the console lines and the admin surface are the same.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, accepted and dialled | `STORAGE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | a link's receive buffer, the frame being sent | `STORAGE.rx`, `STORAGE.tx`, claimed by the session's driver | [`RX`], [`TX`] bytes |
//! | the connections (control block's state and receive ring) | `STORAGE.connections`, the listener's queue | [`CELLS`] of [`CONN_RX`] bytes |
//! | the observer, with the admin queryable and the config subscriber | `STORAGE.app` | the registries' own capacities |
//! | the host, the factory and the node | `STORAGE.run`, built once | [`RUN`] bytes, from the types' sizes |
//!
//! # Waiting on a stack with no threads
//!
//! lwIP is polled, and a MAC's frames reach it only when the MAC is polled. A session's stream waits
//! (a dial's handshake, a write's wait for send-buffer room): each of its polls runs
//! `net_lwip::service_ports` first, which pumps every port, so a SYN-ACK that comes in through the
//! MAC is seen while the dial waits.

use core::cell::RefCell;
use core::fmt::Write;

use wz::link_lwip::LwipLink;
use wz::runtime_zephyr::glue::{log, log_args, stack_usage, yield_us};
use wz::runtime_zephyr::stack::StackWatch;
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_link_lwip::tcp::{LwipTcpListener, TcpSocketPool};
use wz_runtime_coop::ip_stack::IpAcceptor;
use wz_runtime_coop::session_drive::{PumpSlots, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::stream_link::NoStream;
use wz_runtime_coop::udp_link::NoDatagram;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_lwip::stream::{LwipTcpDial, LwipTcpListen, LwipTcpStack};
#[cfg(feature = "lifecycle-declared")]
use wz_session_mcu::admin_fixed::NoOpening;
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed_with_open, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
#[cfg(not(feature = "lifecycle-declared"))]
use wz_session_mcu::connect_manager::ControlledOpener;
use wz_session_mcu::connect_manager::PeerStore;
use wz_session_mcu::run_arena::{run_bytes_needed, RunArena};
use wz_session_mcu::slot_admin::AcceptingAdminNode;
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;

use crate::net_lwip::{service_ports, LwipMacNet, MAX_PORTS};
use crate::{BATCH_SIZE, BUSY_PASSES_MAX, IDLE_SLEEP_US, LISTEN_PORT, STACK_CHECK_MS, TICK_HZ};

/// Sessions the node holds at most, accepted and dialled together.
pub const SESSIONS: usize = 2;
/// Sessions a peer opened to the node that it holds at once.
const ACCEPTS: usize = 1;
/// Connections that may wait on the listener to be taken by the node's loop.
const QUEUE: usize = 1;
/// Cells of the connection pool: one for each session and one for a connection waiting to be taken.
pub const CELLS: usize = SESSIONS + QUEUE;
/// The receive ring of a connection: at least lwIP's receive window, which the port states
/// (`TCP_WND`, two segments of 1,460 bytes); a connect refuses less.
pub const CONN_RX: usize = 3072;
/// The runtime's task table: a pump task per session, with room beside them.
const TASKS: usize = SESSIONS + 1;
/// Bytes of one task cell: the pump's handle and the application layer's state (see `fixed_node`).
const TASK_BYTES: usize = 12288;
/// Timers the runtime holds: the handshake and lease deadlines of the sessions.
const TIMERS: usize = 4;
/// Extra bytes a link's receive buffer holds beyond one batch and its length.
const RX_SLACK: usize = 62;
/// The receive buffer of a session's driver: a batch behind its two-byte length, and slack.
pub const RX: usize = BATCH_SIZE as usize + 2 + RX_SLACK;
/// The buffer the driver's frames are encoded into: the room for the length ahead of a batch, and
/// the batch.
pub const TX: usize = BATCH_SIZE as usize + 2;
/// The widest locator text: `tcp/255.255.255.255:65535`.
const LOCATOR_BYTES: usize = 32;
/// The version the node reports.
const VERSION: &str = "wz-zephyr-admin-node";

type Clock = ZephyrClock<TICK_HZ>;
type Link = &'static LwipLink;
type Stack = LwipTcpStack<Link, CONN_RX, CELLS>;
type Driver = <Stack as SlotStack>::Driver;
type Host = SessionHost<Clock, Stack, ZephyrEntropy, SESSIONS, SESSIONS>;
type Acceptor = IpAcceptor<LwipTcpListen<Link, CONN_RX, QUEUE, CELLS>, NoDatagram, NoStream>;
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

/// The bytes of the arena the host, the factory and the node are built in: the sizes of the three, so
/// that a node that grows is a number that follows and not a start that fails.
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

// The tables are held under the numbers the deploy file states for the machine (`session_pool`), as
// `fixed_node` holds them.
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

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker places
/// it in `.bss`: one non-zero byte anywhere in a `static` moves all of it. What starts non-zero is in
/// [`Control`] and [`OPEN`], which are small.
struct Statics {
    runtime: RuntimeCell<Clock, TASKS, TASK_BYTES, TIMERS>,
    sessions: Slots,
    pumps: PumpSlots<Clock, <Stack as SlotStack>::Pump, SESSIONS, Driver>,
    /// The receive buffers the links claim.
    rx: ByteCells<RX, SESSIONS>,
    /// The buffers the links' frames are encoded into.
    tx: ByteCells<TX, SESSIONS>,
    /// The cells every connection is made in, dialled or accepted.
    connections: TcpSocketPool<CONN_RX, CELLS>,
    listener: LwipTcpListener<CONN_RX, QUEUE, CELLS>,
    /// The machines of what the node dials, some 10 KB: here, with the other tables, and not on the
    /// stack of the thread that runs the node.
    peers: PeerStore,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks>,
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
            connections: TcpSocketPool::new(),
            listener: LwipTcpListener::new(),
            peers: PeerStore::new(),
            admin: AdminHost::new(),
            app: SlotApp::new(),
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

/// How a lifecycle verb reaches the node (decision D7): the in-band query's opener, or none when the
/// image is built with the peers it holds declared (`CONFIG_WZ_LIFECYCLE_DECLARED`).
#[cfg(not(feature = "lifecycle-declared"))]
type Opener = ControlledOpener;
#[cfg(feature = "lifecycle-declared")]
type Opener = NoOpening;

/// The registrations the node's observer holds, all closed types: the config-write subscriber and the
/// admin queryable.
type Sinks = AdminSinks<1024, SESSIONS, Opener>;

/// What answers `GET @/<zid>/peer/session/open/<peer-zid>`: a `static` of its own, because it holds
/// references and so does not start as zero bytes, which is what keeps [`Statics`] in `.bss`.
#[cfg(not(feature = "lifecycle-declared"))]
static OPEN: Opener = ControlledOpener::new(&STORAGE.peers, &CONTROL.control);
/// The node of a build that declares its peers binds no verb, so its opener holds nothing.
#[cfg(feature = "lifecycle-declared")]
static OPEN: Opener = NoOpening;

/// What the node makes its sessions from: the entropy, the parameters and the application layer (the
/// process-wide observer, with the node's own admin surface registered on it).
struct Factory {
    zid: [u8; 6],
    key: [u8; 32],
    observer: &'static ObserverCell<Sinks>,
}

impl SessionFactory<Clock, Driver> for Factory {
    type Entropy = ZephyrEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, Sinks, Driver>;

    fn entropy(&mut self) -> ZephyrEntropy {
        ZephyrEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the receive buffer of a link holds whole.
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

/// `tcp/a.b.c.d:port` for `address`, in fixed text.
fn locator(address: [u8; 4]) -> FixedText<LOCATOR_BYTES> {
    let [a, b, c, d] = address;
    let mut text = FixedText::new();
    let _ = write!(text, "tcp/{a}.{b}.{c}.{d}:{LISTEN_PORT}");
    text
}

/// Build the observer in `STORAGE.app`, where it stays, and register the node's own surface on it: the
/// config-write subscriber and the admin queryable. The reason, as the console line, when one is
/// refused.
///
/// Its own function, not inlined into [`start`], for the stack: the temporaries of the registration are
/// as large as a few KB, and a frame that holds them is held for as long as the node runs.
#[inline(never)]
fn install_observer(
    zid_hex: &str,
    locators: &[&str],
) -> Result<&'static ObserverCell<Sinks>, &'static core::ffi::CStr> {
    let identity = FixedNodeIdentity::new(zid_hex, "peer", VERSION, locators)
        .map_err(|_| c"wz: FAIL - the node's identity does not fit its fixed fields")?;
    let installed = STORAGE.app.install_with(|observer| {
        if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &CONTROL.control)
            .is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused its config subscriber");
        }
        if host_admin_queryable_fixed_with_open(
            &mut observer.queryables,
            identity,
            &CONTROL.status,
            &STORAGE.admin,
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

/// Everything [`run`] does before the node's first round: the key, the identity, the listener, the
/// stack and the node, set up. `Err` is the exit code of a node that could not start.
///
/// Out of line: [`run`] is the bottom of the main thread's stack for the node's whole life, so what it
/// holds is under every call the node makes, and the identity, the stack and the node's parts are in
/// this frame, which is gone before the first round.
#[inline(never)]
fn start(net: &LwipMacNet) -> Result<Running, i32> {
    // The cookie-signing key is a secret, so it comes from the board's entropy source and a board that
    // cannot supply it stops the node: a predictable key is worse than no node.
    let mut key = [0u8; 32];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return Err(2);
    }
    let Some(runtime) = STORAGE.runtime.start::<Driver>(Clock::default()) else {
        log(c"wz: FAIL - the runtime was started twice");
        return Err(3);
    };
    let local = CoopLocalSet::new(&runtime);
    let zid = net.zid();
    let link: Link = net.link();
    let Some(&address) = net.addresses().first() else {
        log(c"wz: FAIL - the node has no interface to listen on");
        return Err(1);
    };

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&zid, &mut zid_text);
    let zid_hex = zid_text.prefix();

    // The locators: one per link, in fixed text, as the identity reports them.
    let mut locators = [const { FixedText::<LOCATOR_BYTES>::new() }; MAX_PORTS];
    let count = net.addresses().len();
    for (text, address) in locators.iter_mut().zip(net.addresses()) {
        *text = locator(*address);
    }
    let mut locator_refs = [""; MAX_PORTS];
    for (slot, text) in locator_refs.iter_mut().zip(&locators).take(count) {
        *slot = text.prefix();
    }

    // The application's registrations, on the observer every session of the node dispatches to. A node
    // whose registrations were refused would run without its admin space: stop instead.
    let observer = match install_observer(zid_hex, &locator_refs[..count]) {
        Ok(observer) => observer,
        Err(why) => {
            log(why);
            return Err(3);
        }
    };

    if STORAGE
        .listener
        .listen_in(LISTEN_PORT, &STORAGE.connections)
        .is_err()
    {
        log(c"wz: FAIL - the node could not listen on its tcp port");
        return Err(3);
    }
    let dial = LwipTcpDial::new(link, &STORAGE.connections).with_service(service_ports);
    let stack: Stack = Stack::new(address, &STORAGE.rx, &STORAGE.tx, dial);
    let acceptor =
        stack.acceptor(LwipTcpListen::new(link, &STORAGE.listener).with_service(service_ports));

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
        zid_hex,
        "peer",
        SessionTimeouts::spec_defaults(),
    )
    .map_err(|_| {
        log(c"wz: FAIL - the node's admin keys do not fit");
        3
    })?;
    let node = STORAGE.run.put(|| node).ok_or(3)?;
    // The line a lane (or a person at the console) waits for: who the node claims to be and where it
    // is, one locator per link.
    log_args(format_args!(
        "ZEPHYR-WZ-ADMIN READY {} {} {}",
        zid_hex, locator_refs[0], locator_refs[1],
    ));
    Ok(Running { local, node })
}

/// Assemble the node over `net` and run it. Returns only when it cannot start; the value is the
/// reason, as a nonzero code the C `main()` prints.
pub fn run(mut net: LwipMacNet) -> i32 {
    let running = match start(&net) {
        Ok(running) => running,
        Err(code) => return code,
    };
    let clock = Clock::default();
    let mut reported = 0;
    let mut generation = None;
    // The node is the stack's only tenant, so its own reading of it is the one that counts: a line
    // when the peak grows, which a lane reads the last of.
    let mut stack = StackWatch::new();
    let mut next_stack_check_ms = 0u64;
    let mut busy_passes = 0u32;
    loop {
        running.local.run_until_idle();
        let worked = net.pump();
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
        }
        let (written, endpoints) = CONTROL.control.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            log_args(format_args!(
                "zephyr-admin-node: connect/endpoints = {endpoints:?}"
            ));
        }
        let sessions = CONTROL.status.session_count();
        if sessions != reported {
            reported = sessions;
            log_args(format_args!("zephyr-admin-node: {reported} session(s)"));
        }
        // The net stack's own threads, and the tick, need this thread's CPU. A pass that took a frame
        // in has work the next pass does at once, so it does not wait first, for at most
        // BUSY_PASSES_MAX in a row (see `fixed_node`).
        if worked && busy_passes < BUSY_PASSES_MAX {
            busy_passes += 1;
        } else {
            busy_passes = 0;
            yield_us(IDLE_SLEEP_US);
        }
    }
}
