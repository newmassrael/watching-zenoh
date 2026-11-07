// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of this firmware with its links on `tcp/` (`fixed-memory-tcp`):
//! `wz_session_mcu::slot_admin::AcceptingAdminNode` over the stack of lwIP's streams
//! (`wz_session_lwip::stream::LwipTcpStack`), on the fixed-memory profile with every table it
//! holds in a `static` this file declares, and no allocator. It is `fixed.rs`'s twin with the
//! datagram links replaced by stream links, as the Zephyr image's `fixed_tcp.rs` is `fixed_node.rs`'s
//! (`deploy/zephyr-admin-node`): the same node, the same admin surface and the same console lines,
//! over the LAN9118 QEMU's mps2 machines carry instead of the kit's onboard MAC.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, accepted and dialled | `STORAGE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | a link's receive buffer, the frame being sent | `STORAGE.rx`, `STORAGE.tx`, claimed by the session's driver | [`RX`], [`TX`] bytes |
//! | the connections (control block's state and receive ring) | `STORAGE.connections`, the listener's queue | [`CELLS`] of [`CONN_RX`] bytes |
//! | the observer, with the admin queryable and the config subscriber | `STORAGE.app` | the registries' own capacities |
//! | the host, the factory and the node | `STORAGE.run`, built once | [`RUN`] bytes, from the types' sizes |
//! | the interface | `ETH0`, a cell of the Ethernet pool, and `ETHERNET` | one |
//!
//! # Waiting on a stack with no threads
//!
//! lwIP is polled, and a MAC's frames reach it only when the MAC is polled. A session's stream waits
//! (a dial's handshake, a write's wait for send-buffer room): each of its polls runs [`service`]
//! first, which polls the interface, so a SYN-ACK that comes in through the MAC is seen while the
//! dial waits.

use core::cell::RefCell;

use wz::link_lwip::ethernet::{EthernetIf, EthernetPool, Ipv4Config};
use wz::link_lwip::LwipLink;
use wz_eth_mac_lan9118::{Lan9118, MPS2_BASE};
use wz_link_lwip::tcp::{LwipTcpListener, TcpSocketPool};
use wz_runtime_coop::ip_stack::IpAcceptor;
use wz_runtime_coop::session_drive::{pump_task_cell_bytes, PumpSlots, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::stream_link::NoStream;
use wz_runtime_coop::udp_link::NoDatagram;
use wz_runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
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
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed_with_open, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::connect_manager::{ControlledOpener, PeerStore};
use wz_session_mcu::run_arena::{run_bytes_needed, RunArena};
use wz_session_mcu::slot_admin::AcceptingAdminNode;
use wz_session_mcu::slot_dial::{EventsOf, SessionFactory};
use wz_session_mcu::slot_host::SessionHost;

use crate::{fail, ClockSeededXorshift, SystickClockRef, ADDRESS, GLOBAL_CLOCK, LISTEN_PORT, ZID};

/// Sessions the node holds at most, accepted and dialled together.
const SESSIONS: usize = 2;
/// Sessions a peer opened to the node that it holds at once.
const ACCEPTS: usize = 1;
/// Connections that may wait on the listener to be taken by the node's loop.
const QUEUE: usize = 1;
/// Cells of the connection pool: one for each session and one for a connection waiting to be taken.
const CELLS: usize = SESSIONS + QUEUE;
/// The receive ring of a connection: at least lwIP's receive window, which the port states
/// (`TCP_WND`, two segments of 1,460 bytes); a connect refuses less.
const CONN_RX: usize = 3072;
/// The batch the node advertises: an Ethernet frame less the IPv4 and TCP headers, as a datagram's is
/// less the IPv4 and UDP ones.
const BATCH_SIZE: u16 = 1460;
/// The runtime's task table: a pump task per session and no other task. A session holds its task's
/// cell until its handles are let go, which is the moment its slot is freed, so a node never holds
/// more cells than sessions (`session_pool_exhaustion` fills a node's tables to exactly its sessions
/// and readmits a peer into the cell a closed session freed).
const TASKS: usize = SESSIONS;
/// Bytes of one task cell: what the task of a session is, as the compiler lays it out for this
/// image's types, and not a figure written beside it.
const TASK_BYTES: usize = pump_task_cell_bytes::<
    Clock,
    <Stack as SlotStack>::Pump,
    Driver,
    EventsOf<<Factory as SessionFactory<Clock, Driver>>::Events>,
>();
/// Timers the runtime holds: the handshake and lease deadlines of the sessions.
const TIMERS: usize = 4;
/// Extra bytes a link's receive buffer holds beyond one batch and its length.
const RX_SLACK: usize = 62;
/// The receive buffer of a session's driver: a batch behind its two-byte length, and slack.
const RX: usize = BATCH_SIZE as usize + 2 + RX_SLACK;
/// The buffer the driver's frames are encoded into: the room for the length ahead of a batch, and the
/// batch.
const TX: usize = BATCH_SIZE as usize + 2;
/// The node's locator, as the identity reports it.
const LOCATOR: &str = "tcp/10.0.2.15:7447";
/// The version the node reports.
const VERSION: &str = "wz-mcu-admin-node";

type Clock = SystickClockRef;
type Link = &'static LwipLink;
type Stack = LwipTcpStack<Link, CONN_RX, CELLS>;
type Driver = <Stack as SlotStack>::Driver;
type Host = SessionHost<Clock, Stack, ClockSeededXorshift, SESSIONS, SESSIONS>;
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

type Slots = SessionSlots<
    CoopRuntime<Clock, Driver>,
    CoopTime<Clock>,
    Driver,
    ClockSeededXorshift,
    SESSIONS,
>;
/// The bytes ONE typed session slot takes in this image, as the compiler lays it out for the target.
const SLOT_BYTES: usize = Slots::slot_bytes();

// The tables are held under the numbers the deploy file states for the machine (`session_pool`), as
// `fixed.rs` holds them.
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
    /// stack of the loop.
    peers: PeerStore,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks>,
    /// The host, the factory and the node, built once.
    run: RunArena<RUN>,
}

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative loop on one
// core, which is the only thing that reaches these tables; each member is `Sync` by the same rule.
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

// SAFETY: the profile's rule: one cooperative loop on one core reaches it.
unsafe impl Sync for Control {}

static CONTROL: Control = Control {
    status: FixedNodeStatus::new(true),
    control: ConnectControl::new(true),
};

/// The registrations the node's observer holds, all closed types: the config-write subscriber and the
/// admin queryable.
type Sinks = AdminSinks<1024, SESSIONS, ControlledOpener>;

/// What answers `GET @/<zid>/peer/session/open/<peer-zid>`: a `static` of its own, because it holds
/// references and so does not start as zero bytes, which is what keeps [`Statics`] in `.bss`.
static OPEN: ControlledOpener = ControlledOpener::new(&STORAGE.peers, &CONTROL.control);

/// The Ethernet interface's cell: the MAC and its frame buffer.
static ETH0: EthernetPool<Lan9118, 1> = EthernetPool::new();

/// The interface the stream stack's waits poll. A stream waits inside the node's own tick, and the
/// loop that owns the interface is the one that called it, so the interface is a `static` the wait
/// can reach, behind a cell that refuses a second borrow: a poll that finds the interface already
/// being polled does nothing.
struct Ethernet(RefCell<Option<EthernetIf<Lan9118>>>);

// SAFETY: the profile's rule: one cooperative loop on one core reaches it.
unsafe impl Sync for Ethernet {}

static ETHERNET: Ethernet = Ethernet(RefCell::new(None));

/// Move every frame the MAC holds into lwIP: what a stream's polls run first.
fn service() {
    if let Ok(mut interface) = ETHERNET.0.try_borrow_mut() {
        if let Some(interface) = interface.as_mut() {
            interface.poll();
        }
    }
}

/// What the node makes its sessions from: the entropy, the parameters and the application layer (the
/// process-wide observer, with the node's own admin surface registered on it).
struct Factory {
    key: [u8; 32],
    observer: &'static ObserverCell<Sinks>,
}

impl SessionFactory<Clock, Driver> for Factory {
    type Entropy = ClockSeededXorshift;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, Sinks, Driver>;

    fn entropy(&mut self) -> ClockSeededXorshift {
        ClockSeededXorshift::seeded()
    }

    /// zenoh 1.x's handshake shape, with a batch the receive buffer of a link holds whole.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Peer,
            zid: zid_bytes(&ZID),
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

/// Build the observer in `STORAGE.app`, where it stays, and register the node's own surface on it: the
/// config-write subscriber and the admin queryable. The reason when one is refused.
///
/// Its own function, not inlined into [`start`], for the stack: the temporaries of the registration are
/// as large as a few KB, and a frame that holds them is held for as long as the node runs.
#[inline(never)]
fn install_observer(
    zid_hex: &str,
    locators: &[&str],
) -> Result<&'static ObserverCell<Sinks>, &'static str> {
    let identity = FixedNodeIdentity::new(zid_hex, "peer", VERSION, locators)
        .map_err(|_| "the node's identity does not fit its fixed fields")?;
    let installed = STORAGE.app.install_with(|observer| {
        if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &CONTROL.control)
            .is_err()
        {
            return Err("the node's observer refused its config subscriber");
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
            return Err("the node's observer refused its admin queryable");
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err("the observer was installed twice"),
    }
}

/// The node, set up and not yet gone round: what [`run`]'s loop reads each pass.
struct Running {
    local: CoopLocalSet<Clock>,
    node: &'static mut Node,
    link: Link,
}

/// Everything [`run`] does before the node's first round: the interface, the key, the identity, the
/// listener, the stack and the node, set up. Out of line, as the Zephyr image's is: [`run`] is the
/// bottom of the stack for the node's whole life, so what it holds is under every call the node makes.
#[inline(never)]
fn start() -> Running {
    GLOBAL_CLOCK.init();
    let link: Link = LwipLink::init_static();
    // SAFETY: MPS2_BASE is the LAN9118 on every mps2 machine but an500, and nothing else in this
    // firmware drives it.
    let mut nic = unsafe { Lan9118::new(MPS2_BASE) };
    if let Err(e) = nic.init() {
        cortex_m_semihosting::hprintln!("admin-node: LAN9118 {:?}", e);
        fail("no Ethernet controller");
    }
    match EthernetIf::add_in(
        link,
        nic,
        Ipv4Config {
            address: ADDRESS,
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
        },
        &ETH0,
    ) {
        Ok(interface) => *ETHERNET.0.borrow_mut() = Some(interface),
        Err(_) => fail("lwIP refused the Ethernet interface"),
    }

    // The cookie-signing key: not a TRNG (QEMU's mps2 machines have none), a stream seeded from the
    // clock, as `fixed.rs` draws it.
    let mut key = [0u8; 32];
    let _ = ClockSeededXorshift::seeded().try_fill_bytes(&mut key);

    let Some(runtime) = STORAGE.runtime.start::<Driver>(SystickClockRef) else {
        fail("the runtime was started twice");
    };
    let local = CoopLocalSet::new(&runtime);

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&ZID, &mut zid_text);
    let zid_hex = zid_text.prefix();

    let observer = match install_observer(zid_hex, &[LOCATOR]) {
        Ok(observer) => observer,
        Err(why) => fail(why),
    };

    if STORAGE
        .listener
        .listen_in(LISTEN_PORT, &STORAGE.connections)
        .is_err()
    {
        fail("the node could not listen on its tcp port");
    }
    let dial = LwipTcpDial::new(link, &STORAGE.connections).with_service(service);
    let stack: Stack = Stack::new(ADDRESS, &STORAGE.rx, &STORAGE.tx, dial);
    let acceptor =
        stack.acceptor(LwipTcpListen::new(link, &STORAGE.listener).with_service(service));

    let Some(host) = STORAGE.run.put(|| {
        SessionHost::new(
            CoopLocalSet::new(&runtime),
            &STORAGE.sessions,
            &STORAGE.pumps,
            stack,
        )
    }) else {
        fail("the node's arena was used before");
    };
    let host: &'static Host = host;
    let Some(factory) = STORAGE.run.put(|| RefCell::new(Factory { key, observer })) else {
        fail("the node's arena was used before");
    };
    let factory: &'static RefCell<Factory> = factory;
    let node = match AcceptingAdminNode::new(
        host,
        stack,
        acceptor,
        factory,
        &CONTROL.control,
        &STORAGE.peers,
        &CONTROL.status,
        zid_hex,
        "peer",
        SessionTimeouts::from_build(),
    ) {
        Ok(node) => node,
        Err(_) => fail("the node's admin keys do not fit"),
    };
    let Some(node) = STORAGE.run.put(|| node) else {
        fail("the node's arena was used before");
    };
    cortex_m_semihosting::hprintln!("admin-node: listening on {} as {}", LOCATOR, zid_hex);
    Running { local, node, link }
}

/// The node's firmware: the same boot and loop as the datagram one, over the statics above.
pub fn run() -> ! {
    let running = start();
    let mut reported = 0;
    let mut generation = None;
    loop {
        running.local.run_until_idle();
        service();
        running.link.check_timeouts();
        running.node.tick(GLOBAL_CLOCK.now_us() / 1000);

        let (written, endpoints) = CONTROL.control.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            cortex_m_semihosting::hprintln!("admin-node: connect/endpoints = {:?}", endpoints);
        }
        let sessions = CONTROL.status.session_count();
        if sessions != reported {
            reported = sessions;
            cortex_m_semihosting::hprintln!("admin-node: {} session(s)", reported);
        }
    }
}
