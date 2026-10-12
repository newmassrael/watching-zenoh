// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node on the fixed-memory profile (fixed-memory step S9c): the node of
//! `main.rs` with every table it holds in a `static` this file declares, built over the
//! slot profile's pieces, with no allocator and no `extern crate alloc` in the image.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, dialled and accepted | `Statics::sessions`, `pumps`, the runtime's task table | `SESSIONS` |
//! | sockets | `Statics::sockets`: one cell per session and one for the listener | `SESSIONS + 1` |
//! | the listener's lanes | `Statics::listener` | `LANES` |
//! | the observer, with the admin queryable and the config subscriber | `Statics::app` | the registries' own capacities |
//! | the interface | `ETH0`, a cell of the Ethernet pool | one |
//! | the endpoints the node dials, the sessions it reports | the connect manager, `Statics::status` | `caps::MAX_STATIC_CONNECT`, `SESSIONS` |
//!
//! What the image still asks the heap for is the session tier's: the declarations the
//! node sends and receives are built and decoded as owned messages, which is the codec
//! owned mirrors' step. The image does not link yet, for that reason, and the S8 gate
//! says which crates carry it.

use core::cell::RefCell;

use wz::link_lwip::ethernet::{EthernetIf, EthernetPool, Ipv4Config};
use wz::link_lwip::rx_sockets::SessionRxPool;
use wz::link_lwip::LwipLink;
use wz::runtime_coop::session_drive::PumpSlots;
use wz::runtime_coop::session_runtime::SessionHandle;
use wz::runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz::session_lwip::admin_fixed::{
    host_admin_queryable_fixed, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz::session_lwip::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz::session_lwip::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz::session_lwip::driver::LwipUdpDriver;
use wz::session_lwip::listener::SessionListener;
use wz::session_lwip::session_host::SessionHost;
use wz::session_lwip::slot_node::{SessionFactory, SlotAdminNode};
use wz::session_lwip::{LwipLinks, LwipSessionLink};
use wz_eth_mac_lan9118::{Lan9118, MPS2_BASE};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{Requesters, SlotObserverOf};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;

use crate::{fail, ClockSeededXorshift, SystickClockRef, ADDRESS, GLOBAL_CLOCK, LISTEN_PORT, ZID};

/// Sessions the node holds at most, dialled and accepted together: the process's
/// `max_sessions`.
const SESSIONS: usize = 2;
/// Peers that may be admitted at once on the listening socket.
const LANES: usize = 1;
/// The runtime's task table: a pump task per session, with room beside them.
const TASKS: usize = SESSIONS + 1;
/// Bytes of one task cell: the pump's handle and the application layer's state. The
/// layer is about 4.9 KB (its requesters, which a node that asks nothing still has,
/// are 4.8 KB of them) and an `async fn` holds a by-value argument twice, so the cell
/// is sized for two of them and the handle; the same number the host test of the slot
/// node holds to the measured size.
const TASK_BYTES: usize = 12288;
/// Timers the runtime holds: the handshake and lease deadlines of the sessions.
const TIMERS: usize = 4;

// The tables above are held under the numbers the deploy file states for the machine
// (`session_pool`): the sessions fit the generated table, the runtime's tables fit the
// task and timer ceilings, and ONE typed session slot, as the compiler lays it out for
// the target, fits the generated slot ceiling. A deploy file that lowers a number, or an
// image that outgrows one, is a build failure that names the line.
const _: () = {
    use wz_session_core::caps::{MAX_TASKS, MAX_TIMERS};
    use wz_session_core::session_slot_pool_mcu::{SLOT_COUNT, SLOT_SIZE};
    assert!(SESSIONS <= SLOT_COUNT, "SESSIONS exceeds the generated session table");
    assert!(TASKS <= MAX_TASKS, "TASKS exceeds the deploy file's max_tasks");
    assert!(TIMERS <= MAX_TIMERS, "TIMERS exceeds the deploy file's max_timers");
    assert!(
        SessionSlots::<
            CoopRuntime<SystickClockRef>,
            CoopTime<SystickClockRef>,
            LwipUdpDriver,
            ClockSeededXorshift,
            SESSIONS,
        >::slot_bytes()
            <= SLOT_SIZE,
        "one typed session slot exceeds the generated slot ceiling"
    );
};
/// The node's locator, as the identity reports it.
const LOCATOR: &str = "udp/10.0.2.15:7447";

type Host =
    SessionHost<SystickClockRef, &'static LwipLink, ClockSeededXorshift, SESSIONS, SESSIONS>;
type Node<'a> =
    SlotAdminNode<'a, SystickClockRef, &'static LwipLink, Factory, SESSIONS, SESSIONS, LANES>;

/// Everything the node declares, in one `static`.
struct Statics {
    runtime: RuntimeCell<SystickClockRef, TASKS, TASK_BYTES, TIMERS>,
    sessions: SessionSlots<
        CoopRuntime<SystickClockRef>,
        CoopTime<SystickClockRef>,
        LwipUdpDriver,
        ClockSeededXorshift,
        SESSIONS,
    >,
    pumps: PumpSlots<SystickClockRef, LwipSessionLink<&'static LwipLink>, SESSIONS>,
    /// A cell for each session the node dials, and one for the listener's socket.
    sockets: SessionRxPool<{ SESSIONS + 1 }>,
    listener: SessionListener<LANES>,
    status: FixedNodeStatus<SESSIONS>,
    /// Writes are PERMITTED on this node: upstream's default is to refuse, and the node
    /// opts in, because being reconfigured is what it is for.
    control: ConnectControl,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks>,
}

/// The registrations the node's observer holds, all closed types: the config-write
/// subscriber and the admin queryable.
type Sinks = AdminSinks<1024, SESSIONS>;

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative
// loop on one core, which is the only thing that reaches these tables; each member is
// `Sync` by the same rule.
unsafe impl Sync for Statics {}

impl Statics {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            sockets: SessionRxPool::new(),
            listener: SessionListener::new(),
            status: FixedNodeStatus::new(true),
            control: ConnectControl::new(true),
            admin: AdminHost::new(),
            app: SlotApp::new(),
        }
    }
}

static NODE: Statics = Statics::new();
/// The Ethernet interface's cell: the MAC and its frame buffer.
static ETH0: EthernetPool<Lan9118, 1> = EthernetPool::new();

/// What the node makes its sessions from: the entropy, the parameters and the
/// application layer (the process-wide observer, with the node's own admin surface
/// registered on it).
struct Factory {
    key: [u8; 32],
    observer: &'static RefCell<SlotObserverOf<Sinks>>,
}

impl SessionFactory<SystickClockRef> for Factory {
    type Entropy = ClockSeededXorshift;
    type Events = SlotDispatch<SystickClockRef, NoReplies, NoReplies, Sinks>;

    fn entropy(&mut self) -> ClockSeededXorshift {
        ClockSeededXorshift::seeded()
    }

    /// zenoh 1.x's handshake shape, with a batch the MCU's 1536-byte receive slot holds
    /// whole.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: zid_bytes(&ZID),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1500,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }

    fn events(&mut self, handle: &SessionHandle<SystickClockRef>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// The node's firmware: the same boot and loop as the growable one, over the statics
/// above.
pub fn run() -> ! {
    GLOBAL_CLOCK.init();

    let link = LwipLink::init_static();
    // SAFETY: MPS2_BASE is the LAN9118 on every mps2 machine but an500, and nothing
    // else in this firmware drives it.
    let mut nic = unsafe { Lan9118::new(MPS2_BASE) };
    if let Err(e) = nic.init() {
        cortex_m_semihosting::hprintln!("admin-node: LAN9118 {:?}", e);
        fail("no Ethernet controller");
    }
    let mut ethernet = match EthernetIf::add_in(
        link,
        nic,
        Ipv4Config {
            address: ADDRESS,
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
        },
        &ETH0,
    ) {
        Ok(ethernet) => ethernet,
        Err(_) => fail("lwIP refused the Ethernet interface"),
    };

    let mut key = [0u8; 32];
    let _ = ClockSeededXorshift::seeded().try_fill_bytes(&mut key);

    let Some(runtime) = NODE.runtime.start(SystickClockRef) else {
        fail("the runtime was started twice");
    };
    let local = CoopLocalSet::new(&runtime);

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&ZID, &mut zid_text);
    let zid_hex = zid_text.prefix();

    // The application's registrations, on the observer every session of the node
    // dispatches to: the config-write subscriber and the admin queryable. A node whose
    // registrations were refused is not started, rather than started deaf.
    let mut observer = SlotObserverOf::<Sinks>::new();
    if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &NODE.control).is_err()
    {
        fail("the config subscriber was refused");
    }
    let identity = match FixedNodeIdentity::new(zid_hex, "peer", "wz-mcu-admin-node", &[LOCATOR]) {
        Ok(identity) => identity,
        Err(_) => fail("the node's identity does not fit"),
    };
    if host_admin_queryable_fixed(
        &mut observer.queryables,
        identity,
        &NODE.status,
        &NODE.admin,
        Some(&NODE.control),
        Some(&NODE.control),
    )
    .is_err()
    {
        fail("the admin queryable was refused");
    }
    let Ok(observer) = NODE.app.install(observer) else {
        fail("the observer was installed twice");
    };

    let host: Host = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &NODE.sessions,
        &NODE.pumps,
        link,
    );
    let links = LwipLinks::new(link, &NODE.sockets);
    let factory = RefCell::new(Factory { key, observer });
    let node = Node::new(
        &host,
        &links,
        &factory,
        &NODE.listener,
        &NODE.control,
        &NODE.status,
        zid_hex,
        "peer",
        LISTEN_PORT,
        SessionTimeouts::spec_defaults(),
    );
    let mut node = match node {
        Ok(node) => node,
        Err(_) => fail("the node's admin keys do not fit"),
    };
    cortex_m_semihosting::hprintln!("admin-node: listening on {} as {}", LOCATOR, zid_hex);

    let mut reported = 0;
    let mut generation = None;
    loop {
        local.run_until_idle();
        ethernet.poll();
        link.check_timeouts();
        node.tick(GLOBAL_CLOCK.now_us() / 1000);

        let (written, endpoints) = NODE.control.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            cortex_m_semihosting::hprintln!("admin-node: connect/endpoints = {:?}", endpoints);
        }
        let sessions = NODE.status.session_count();
        if sessions != reported {
            reported = sessions;
            cortex_m_semihosting::hprintln!("admin-node: {} session(s)", reported);
        }
    }
}
