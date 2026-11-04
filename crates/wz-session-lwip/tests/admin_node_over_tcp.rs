// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine's admin node over `tcp/` on lwIP (`tcp` feature): two nodes of the fixed-memory
//! profile, each `wz_session_mcu::slot_admin::AcceptingAdminNode` over the stack of lwIP's streams,
//! one told by a config write to hold a session with the other, which listens.
//!
//! The node is the one the Zephyr secure-channel admin node is: it takes the host, a binder, an
//! acceptor of the links a peer opened and the factory, so a node of `tcp/` links needs no node code
//! of its own. What this holds is that it fits the stack: B's connect manager dials A's `tcp/`
//! endpoint through the stack's dial, A's acceptor takes the connection, both ends establish, the
//! admin space is declared on each, each reports the other, and the session's rows name the links
//! as `tcp/`.
//!
//! Host-test level: no board runs it. lwIP is process-global: the test holds the harness's lock for
//! its whole body.

use std::cell::RefCell;

use wz_link_lwip::tcp::LwipTcpListener;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::tcp::TcpSocketPool;
use wz_link_lwip::LwipLink;
use wz_runtime_coop::ip_stack::IpAcceptor;
use wz_runtime_coop::session_drive::{PumpSlots, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::stream_link::NoStream;
use wz_runtime_coop::udp_link::NoDatagram;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::admin_connect::ConfigWriteBody;
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::WhatAmI;
use wz_session_lwip::stream::{LwipTcpDial, LwipTcpListen, LwipTcpStack};
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::connect_manager::{PeerStore, SlotState};
use wz_session_mcu::slot_admin::AcceptingAdminNode;
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;

/// A clock that never moves: no deadline fires, so a dial nobody answers waits its period for ever
/// and the sessions do only what the other end asks of them.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A deterministic stand-in for a board's TRNG.
struct Counting(u8);
impl wz_session_core::entropy::EntropySource for Counting {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

/// Sessions a node holds at most (dialled and accepted), and the accepted ones among them.
const N: usize = 2;
const ACCEPTED: usize = 1;
/// The runtime's task table and the bytes of one cell: a pump task per session, holding the
/// application layer (4,904 bytes, held twice by an `async fn`) and the pump's handle.
const TASKS: usize = 8;
const TASK_BYTES: usize = 12_288;
/// The receive buffer of a connection: the port's window is four segments of 536 bytes.
const RX: usize = 4_096;

type LinkRef = &'static LwipLink;
type Stack = LwipTcpStack<LinkRef, RX, N>;
type Driver = <Stack as SlotStack>::Driver;
type Pump = <Stack as SlotStack>::Pump;
type Rt = CoopRuntime<Frozen, Driver>;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, Driver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, Pump, P, Driver>;
type Host<const S: usize> = SessionHost<Frozen, Stack, Counting, S, S>;
type Acceptor = IpAcceptor<LwipTcpListen<LinkRef, RX, 1, ACCEPTED>, NoDatagram, NoStream>;

/// The cells a node's connections are made in: a pool with `static-link-storage` (a node's real
/// profile), nothing on the heap profile, where lwIP's connections are made on the heap.
#[cfg(feature = "static-link-storage")]
type Cells<const C: usize> = TcpSocketPool<RX, C>;
#[cfg(not(feature = "static-link-storage"))]
type Cells<const C: usize> = ();

const fn cells<const C: usize>() -> Cells<C> {
    #[cfg(feature = "static-link-storage")]
    {
        TcpSocketPool::new()
    }
    #[cfg(not(feature = "static-link-storage"))]
    {}
}

/// A node's dial over `link`, its connections made in `cells`.
fn dial(link: LinkRef, cells: &'static Cells<N>) -> LwipTcpDial<LinkRef, RX, N> {
    #[cfg(feature = "static-link-storage")]
    {
        LwipTcpDial::new(link, cells)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        let _: &() = cells;
        LwipTcpDial::new(link)
    }
}

/// `listener` listening on `port`, the connections it takes made in `cells`.
fn listen(
    listener: &'static LwipTcpListener<RX, 1, ACCEPTED>,
    port: u16,
    cells: &'static Cells<ACCEPTED>,
) -> Result<(), wz_link_lwip::tcp::TcpError> {
    #[cfg(feature = "static-link-storage")]
    {
        listener.listen_in(port, cells)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        let _: &() = cells;
        listener.listen(port)
    }
}
type Node<const S: usize> =
    AcceptingAdminNode<'static, Frozen, Stack, Stack, Factory<S>, Acceptor, S, S, ACCEPTED>;
type Sinks<const S: usize> = AdminSinks<1024, S>;

/// Everything one node declares, as an image would in its statics.
struct Statics<const S: usize> {
    runtime: RuntimeCell<Frozen, TASKS, TASK_BYTES, 4>,
    sessions: Slots<S>,
    pumps: Pumps<S>,
    /// The byte tables a link takes its buffers from: a receive buffer holds a batch with its
    /// length, a frame buffer the same.
    rx: ByteCells<2_050, S>,
    tx: ByteCells<2_050, S>,
    listener: LwipTcpListener<RX, 1, ACCEPTED>,
    /// The cells of the connections the node dials and of the ones its listener takes.
    dial_cells: Cells<N>,
    accept_cells: Cells<ACCEPTED>,
    status: FixedNodeStatus<S>,
    control: ConnectControl,
    peers: PeerStore,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks<S>>,
}

impl<const S: usize> Statics<S> {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            rx: ByteCells::new(),
            tx: ByteCells::new(),
            listener: LwipTcpListener::new(),
            dial_cells: cells::<N>(),
            accept_cells: cells::<ACCEPTED>(),
            status: FixedNodeStatus::new(true),
            control: ConnectControl::new(true),
            peers: PeerStore::new(),
            admin: AdminHost::new(),
            app: SlotApp::new(),
        }
    }
}

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

/// What the node makes its sessions from: the entropy, the parameters and the application layer
/// (the process-wide observer, with the node's own admin surface registered on it).
struct Factory<const S: usize> {
    zid: u8,
    observer: &'static ObserverCell<Sinks<S>>,
}

impl<const S: usize> SessionFactory<Frozen, Driver> for Factory<S> {
    type Entropy = Counting;
    type Events = SlotDispatch<Frozen, NoReplies, NoReplies, Sinks<S>, Driver>;

    fn entropy(&mut self) -> Counting {
        Counting(self.zid)
    }

    fn params(&mut self) -> SessionInitParams {
        params(self.zid)
    }

    fn events(&mut self, handle: &SessionHandle<Frozen, Driver>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// A node, built from its statics, with its runtime and the keys it answers under.
struct Rig<const S: usize> {
    local: CoopLocalSet<Frozen>,
    node: Node<S>,
    s: &'static Statics<S>,
    zid_hex: String,
    config_key: String,
}

fn hex_of(zid: u8) -> String {
    wz_session_core::zid_hex::zid_to_zenoh_hex(&[zid; 4])
}

fn rig<const S: usize>(s: &'static Statics<S>, link: LinkRef, zid: u8, port: u16) -> Rig<S> {
    let zid_hex = hex_of(zid);
    let runtime: Rt = s.runtime.start(Frozen).expect("the runtime starts once");
    let local = CoopLocalSet::new(&runtime);

    // The application's registrations, on the observer every session of the node dispatches to.
    let locator = format!("tcp/127.0.0.1:{port}");
    let identity = FixedNodeIdentity::new(&zid_hex, "peer", "wz-test", &[locator.as_str()])
        .expect("the identity fits");
    let (observer, ()) = s
        .app
        .install_with(|observer| {
            host_connect_writes_fixed(&mut observer.subscribers, &zid_hex, "peer", &s.control)
                .expect("the config subscriber is registered");
            host_admin_queryable_fixed(
                &mut observer.queryables,
                identity,
                &s.status,
                &s.admin,
                Some(&s.control),
                Some(&s.control),
            )
            .expect("the admin queryable is registered");
        })
        .expect("the observer is installed once");

    listen(&s.listener, port, &s.accept_cells).expect("the node listens");
    let stack = Stack::new([127, 0, 0, 1], &s.rx, &s.tx, dial(link, &s.dial_cells));
    let acceptor = stack.acceptor(LwipTcpListen::new(link, &s.listener));
    let host: &'static Host<S> = Box::leak(Box::new(SessionHost::new(
        CoopLocalSet::new(&runtime),
        &s.sessions,
        &s.pumps,
        stack,
    )));
    let factory: &'static RefCell<Factory<S>> =
        Box::leak(Box::new(RefCell::new(Factory { zid, observer })));
    let node = AcceptingAdminNode::new(
        host,
        stack,
        acceptor,
        factory,
        &s.control,
        &s.peers,
        &s.status,
        &zid_hex,
        "peer",
        SessionTimeouts::spec_defaults(),
    )
    .expect("the node's keys fit");
    Rig {
        local,
        node,
        s,
        config_key: format!("@/{zid_hex}/peer/config/connect/endpoints"),
        zid_hex,
    }
}

impl<const S: usize> Rig<S> {
    /// One turn: every task runs once, then the node ticks.
    fn turn(&mut self) {
        self.local.run_until_idle();
        self.node.tick(0);
    }

    /// Tell this node, as a config write would, to hold sessions with `endpoints`.
    fn write_endpoints(&self, endpoints: &str) {
        self.s.control.apply(
            &self.zid_hex,
            "peer",
            &self.config_key,
            ConfigWriteBody::Put(endpoints.as_bytes()),
        );
    }

    /// How many of the sessions a peer opened to this node, and how many this node dialled, are
    /// established.
    fn established(&self) -> (usize, usize) {
        let accepted = self
            .node
            .accepted()
            .filter(|session| session.actions().is_established())
            .count();
        let mut dialled = 0;
        self.node.core().for_each_dialled(|_, session| {
            dialled += usize::from(session.actions().is_established());
        });
        (accepted, dialled)
    }

    fn describe(&self) -> String {
        let mut states = Vec::new();
        self.node
            .core()
            .for_each_endpoint(|endpoint, state| states.push(format!("{endpoint} {state:?}")));
        format!(
            "established {:?}; endpoints {states:?}; slots in use {} refused {}; pump cells in use \
             {}; rx cells in use {}; listener waiting {} refused {}; control outcome {:?}",
            self.established(),
            self.s.sessions.in_use(),
            self.s.sessions.refused(),
            self.s.pumps.in_use(),
            self.s.rx.in_use(),
            self.s.listener.waiting(),
            self.s.listener.refused(),
            self.s.control.last_outcome(),
        )
    }
}

fn run<const A: usize, const B: usize>(
    a: &mut Rig<A>,
    b: &mut Rig<B>,
    what: &str,
    done: impl Fn(&Rig<A>, &Rig<B>) -> bool,
) {
    for _ in 0..400 {
        a.turn();
        b.turn();
        if done(a, b) {
            return;
        }
    }
    panic!(
        "{what}: not reached\nA: {}\nB: {}",
        a.describe(),
        b.describe()
    );
}

#[test]
fn a_written_tcp_endpoint_is_dialled_and_the_listening_node_accepts_it() {
    static A: Statics<N> = Statics::new();
    static B: Statics<N> = Statics::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let mut a = rig(&A, link, 0xa1, 47_801);
    let mut b = rig(&B, link, 0xb2, 47_802);

    // B is told to hold a session with A. Nothing else is said to either node.
    b.write_endpoints("[\"tcp/127.0.0.1:47801\"]");
    run(&mut a, &mut b, "B's session to A establishes", |a, b| {
        a.established() == (1, 0) && b.established() == (0, 1)
    });
    // The declarations of the admin space went out on each side, and each node reports the other.
    run(&mut a, &mut b, "each node reports the other", |a, b| {
        a.s.status.session_count() == 1 && b.s.status.session_count() == 1
    });

    let mut states = Vec::new();
    b.node.core().for_each_endpoint(|endpoint, state| {
        states.push((endpoint.to_string(), state));
    });
    assert_eq!(
        states,
        vec![("tcp/127.0.0.1:47801".to_string(), SlotState::Live)],
        "B holds one endpoint and a session is live for it"
    );
    assert_eq!(
        (A.sessions.in_use(), B.sessions.in_use()),
        (1, 1),
        "a slot for each end"
    );
    assert_eq!(
        (A.rx.in_use(), A.tx.in_use(), B.rx.in_use(), B.tx.in_use()),
        (1, 1, 1, 1),
        "each link took a receive buffer and a frame buffer from its node's tables"
    );
    assert_eq!(A.listener.refused(), 0);

    // THE ROW. The session A accepted names its link as `tcp/`, both ends.
    let session = a.node.accepted().next().expect("A holds B's session");
    let (src, dst) = session
        .actions()
        .with_admin_session(|view| {
            let (src, dst) = view.links.link(0).expect("a link");
            (src.to_string(), dst.to_string())
        })
        .expect("an established session has a row");
    assert_eq!(src, "tcp/127.0.0.1:47801", "A's end is its listening port");
    assert!(
        dst.starts_with("tcp/127.0.0.1:"),
        "B's end is a port the stack picked: {dst}"
    );
}
