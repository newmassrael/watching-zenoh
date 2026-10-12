// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the `session-slot` profile, whole (fixed-memory step S9c): two
//! nodes on one lwIP loopback, each built from the statics an image declares, one
//! writing the other's connection list over the wire, and the heap counted over
//! everything that happens after they are built.
//!
//! What it shows, in the order it happens:
//!
//! - THE DIAL AND THE ACCEPT. Node B is told to hold a session with node A
//!   (`ConnectControl::apply`, the decision a remote write reaches too). B's connect
//!   manager dials, through the slot dialler and the session host: a socket out of
//!   the static pool, a slot, a pump cell, a task cell. A's listener admits the
//!   `InitSyn` only after claiming the same three, and the two reach Established.
//!   The sessions run the declarations of the admin space on each other (a queryable
//!   on `@/<zid>/peer/**`, a subscriber on `.../config/**`), and each node reports
//!   the other as a `sessions[]` row and the endpoint as `live`.
//! - THE REMOTE WRITE. B puts a `connect/endpoints` list on A's config key over the
//!   session. A's config subscriber (`host_connect_writes_fixed`, on the process-wide
//!   observer) applies it to A's control, A's manager dials what it names (B), and B's
//!   listener admits A's session as its second.
//! - THE ROW. A session row read through the lend
//!   (`SessionLinkActions::with_admin_session`) is the row the heap form builds,
//!   field for field.
//! - THE REFUSAL. A node whose session table is smaller than its endpoint list
//!   dials what it can afford, and the endpoint the table has no slot for waits as a
//!   dial nobody answered: counted by the table that said no, reported as `waiting`,
//!   nothing grown and nothing left half-taken.
//!
//! The heap is counted over every window after setup. What is NOT claimed is the
//! drain of a staged admin reply to the wire, which is the codec mirrors' step, and the
//! stack the node takes, which is not measured here.
//!
//! lwIP is process-global: every test holds the harness's lock for its whole body.

// A refused claim hands back what it was offered, a whole driver and its socket,
// which is what makes the refusal free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::cell::RefCell;

use wz_link_lwip::rx_sockets::SessionRxPool;
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::PumpSlots;
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::admin_connect::ConfigWriteBody;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{Requesters, SlotObserverOf};
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::LwipUdpDriver;
use wz_session_lwip::listener::SessionListener;
use wz_session_lwip::session_host::SessionHost;
use wz_session_lwip::slot_node::{SessionFactory, SlotAdminNode};
use wz_session_lwip::{LwipLinks, LwipSessionLink};
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::connect_manager::SlotState;

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// A clock that never moves: no deadline fires, so a dial that nobody answers waits
/// its period for ever and the sessions do only what the other end asks of them.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A deterministic stand-in for a board's TRNG (the acceptor mints a cookie).
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

/// Sessions a node holds at most, and the listener's lanes.
const N: usize = 3;
const LANES: usize = 2;
/// The runtime's task table: a pump task per session, with room beside them.
const TASKS: usize = 8;
/// Bytes of one task cell: the pump's handle and the application layer's state. The
/// layer is 4904 B (its requesters, which a node that asks nothing still has, are 4872
/// of them) and an `async fn` holds a by-value argument twice (as the captured
/// argument and as the local it is moved into), so the cell is sized for two of them
/// and the handle. `the_task_cell_holds_the_application_layer_of_a_session` holds the
/// number to the measured size.
const TASK_BYTES: usize = 12288;

type Rt = CoopRuntime<Frozen>;
type LinkRef = &'static LwipLink;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, LwipSessionLink<LinkRef>, P>;
type Host<const S: usize> = SessionHost<Frozen, LinkRef, Counting, S, S>;
type Node<const S: usize> = SlotAdminNode<'static, Frozen, LinkRef, Factory<S>, S, S, LANES>;

/// Everything one node declares, as an image would in its statics.
struct Statics<const S: usize> {
    runtime: RuntimeCell<Frozen, TASKS, TASK_BYTES, 4>,
    sessions: Slots<S>,
    pumps: Pumps<S>,
    /// A cell for each session the node dials, and one for the listener's socket.
    sockets: SessionRxPool<{ N + 1 }>,
    listener: SessionListener<LANES>,
    status: FixedNodeStatus<S>,
    control: ConnectControl,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks<S>>,
}

impl<const S: usize> Statics<S> {
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

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

/// What the node makes its sessions from: the entropy, the parameters and the
/// application layer (the process-wide observer, with the node's own admin surface
/// registered on it).
struct Factory<const S: usize> {
    zid: u8,
    observer: &'static RefCell<SlotObserverOf<Sinks<S>>>,
}

/// The registrations the node's observer holds: all closed types.
type Sinks<const S: usize> = AdminSinks<1024, S>;

impl<const S: usize> SessionFactory<Frozen> for Factory<S> {
    type Entropy = Counting;
    type Events = SlotDispatch<Frozen, NoReplies, NoReplies, Sinks<S>>;

    fn entropy(&mut self) -> Counting {
        Counting(self.zid)
    }

    fn params(&mut self) -> SessionInitParams {
        params(self.zid)
    }

    fn events(&mut self, handle: &SessionHandle<Frozen>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// A node, built from its statics, with its runtime and the keys it answers under.
struct Rig<const S: usize> {
    runtime: Rt,
    local: CoopLocalSet<Frozen>,
    node: Node<S>,
    s: &'static Statics<S>,
    zid_hex: String,
    /// The key a write of this node's endpoint list arrives on, built once so a
    /// window that writes it allocates nothing of the test's own.
    config_key: String,
}

/// The zenoh hex form of the zid `params(zid)` gives a node.
fn hex_of(zid: u8) -> String {
    wz_session_core::zid_hex::zid_to_zenoh_hex(&[zid; 4])
}

fn rig<const S: usize>(s: &'static Statics<S>, link: LinkRef, zid: u8, port: u16) -> Rig<S> {
    let zid_hex = hex_of(zid);
    let runtime = s.runtime.start(Frozen).expect("the runtime starts once");
    let local = CoopLocalSet::new(&runtime);

    // The application's registrations, on the observer every session of the node
    // dispatches to: the config-write subscriber and the admin queryable.
    let mut observer = SlotObserverOf::<Sinks<S>>::new();
    host_connect_writes_fixed(&mut observer.subscribers, &zid_hex, "peer", &s.control)
        .expect("the config subscriber is registered");
    let locator = format!("udp/127.0.0.1:{port}");
    let identity = FixedNodeIdentity::new(&zid_hex, "peer", "wz-test", &[locator.as_str()])
        .expect("the identity fits");
    host_admin_queryable_fixed(
        &mut observer.queryables,
        identity,
        &s.status,
        &s.admin,
        Some(&s.control),
        Some(&s.control),
    )
    .expect("the admin queryable is registered");
    let observer = s
        .app
        .install(observer)
        .ok()
        .expect("the observer is installed once");

    let host: &'static Host<S> = Box::leak(Box::new(SessionHost::new(
        CoopLocalSet::new(&runtime),
        &s.sessions,
        &s.pumps,
        link,
    )));
    let links: &'static LwipLinks<LinkRef> = Box::leak(Box::new(LwipLinks::new(link, &s.sockets)));
    let factory: &'static RefCell<Factory<S>> =
        Box::leak(Box::new(RefCell::new(Factory { zid, observer })));
    let node = SlotAdminNode::new(
        host,
        links,
        factory,
        &s.listener,
        &s.control,
        &s.status,
        &zid_hex,
        "peer",
        port,
        SessionTimeouts::spec_defaults(),
    )
    .expect("the node's keys fit");
    Rig {
        runtime,
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

    fn established(&self) -> (usize, usize) {
        let accepted = self
            .node
            .accepted()
            .filter(|session| session.actions().is_established())
            .count();
        let mut dialled = 0;
        self.node.for_each_dialled(|_, session| {
            dialled += usize::from(session.actions().is_established());
        });
        (accepted, dialled)
    }

    /// What this node holds, for a failure message.
    fn describe(&self) -> String {
        let mut states = Vec::new();
        self.node
            .for_each_endpoint(|endpoint, state| states.push(format!("{endpoint} {state:?}")));
        format!(
            "established {:?}; endpoints {states:?}; slots in use {} refused {}; pump cells in use {} \
             refused {}; sockets in use {} refusals {}; tasks refused {:?}; listener {:?}; \
             control outcome {:?}",
            self.established(),
            self.s.sessions.in_use(),
            self.s.sessions.refused(),
            self.s.pumps.in_use(),
            self.s.pumps.refused(),
            self.s.sockets.in_use(),
            self.s.sockets.refusals(),
            self.runtime.task_refusals(),
            self.s.listener.counts(),
            self.s.control.last_outcome(),
        )
    }
}

/// The crates of the shell: what this step moved off the heap, and what a window of
/// this file must therefore never find asking for memory.
const SHELL: [&str; 4] = [
    "crates/wz-session-lwip",
    "crates/wz-session-mcu",
    "crates/wz-runtime-coop",
    "crates/wz-link-lwip",
];

/// What still asks for memory in these windows, and is the next step's: the declarations
/// the node sends and reads are built and decoded as OWNED messages (`Vec`s of
/// extensions, `HeapStr` keyexprs), which is the codec owned mirrors of
/// `wz-session-core` and the SCE runtime under them.
const MIRRORS: [&str; 3] = [
    "crates/wz-session-core",
    "backends/rust/forge-runtime",
    "out/wz-codecs",
];

/// The window's allocations, by the crate that asked for each: none by the shell, all by
/// the codec owned mirrors, and every one attributed. A shell that began to allocate
/// again would be the first name in the map; the mirrors going away would make the
/// map empty and `n` zero, which is the day this function becomes `n == 0`.
fn only_the_codec_mirrors_allocate(m: &Measurement, window: &str, n: usize) {
    let owners = m.owners();
    println!("{window}: {n} allocation(s), by crate: {owners:?}");
    let shell: usize = owners
        .iter()
        .filter(|(owner, _)| SHELL.contains(&owner.as_str()))
        .map(|(_, n)| *n)
        .sum();
    assert_eq!(shell, 0, "{window}: the shell asked for memory: {owners:?}");
    for owner in owners.keys() {
        assert!(
            MIRRORS.contains(&owner.as_str()),
            "{window}: {owner} asked for memory and is not a codec owned mirror: {owners:?}"
        );
    }
    assert_eq!(
        owners.values().sum::<usize>(),
        n,
        "{window}: every allocation is attributed to a crate"
    );
}

/// Turn both nodes until `done`, at most a bounded number of times.
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
fn a_written_endpoint_is_dialled_and_a_remote_write_makes_the_other_node_dial_back() {
    static A: Statics<N> = Statics::new();
    static B: Statics<N> = Statics::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let mut a = rig(&A, link, 0xa1, 7601);
    let mut b = rig(&B, link, 0xb2, 7602);
    let m = Measurement::attributing();

    // B is told to hold a session with A. Nothing else is said to either node.
    let ((), n) = m.count("dial and establish", || {
        b.write_endpoints("[\"udp/127.0.0.1:7601\"]");
        run(&mut a, &mut b, "B's session to A establishes", |a, b| {
            a.established() == (1, 0) && b.established() == (0, 1)
        });
        // The declarations of the admin space went out on each side, and each node
        // reports the other.
        run(&mut a, &mut b, "each node reports the other", |a, b| {
            a.s.status.session_count() == 1 && b.s.status.session_count() == 1
        });
    });
    only_the_codec_mirrors_allocate(&m, "dial and establish", n);
    let mut endpoint_states = Vec::new();
    b.node.for_each_endpoint(|endpoint, state| {
        endpoint_states.push((endpoint.to_string(), state));
    });
    assert_eq!(
        endpoint_states,
        vec![("udp/127.0.0.1:7601".to_string(), SlotState::Live)],
        "B holds one endpoint and a session is live for it"
    );
    assert_eq!(a.s.listener.counts().admitted, 1, "A admitted B's InitSyn");
    assert_eq!(
        (a.s.sessions.in_use(), b.s.sessions.in_use()),
        (1, 1),
        "a slot for each end"
    );

    // THE ROW. A's accepted session, read through the lend, is the row the heap form
    // builds for the same session.
    let session = a.node.accepted().next().expect("A holds B's session");
    let actions = session.actions();
    let lent = actions
        .with_admin_session(|view| {
            (
                view.peer_zid_hex.to_string(),
                view.whatami.map(str::to_string),
                (0..view.links.link_count())
                    .map(|i| {
                        let (src, dst) = view.links.link(i).expect("a link");
                        (src.to_string(), dst.to_string())
                    })
                    .collect::<Vec<_>>(),
                view.shm,
                view.region.map(str::to_string),
            )
        })
        .expect("an established session has a row");
    let peer_zid = actions.peer_zid().expect("the handshake named the peer");
    let heap = actions.admin_session(
        wz_session_core::zid_hex::zid_to_zenoh_hex(&peer_zid),
        actions
            .peer_whatami_wire()
            .and_then(wz_session_core::WhatAmI::from_wire)
            .map(|role| role.to_str().to_string()),
        None,
    );
    assert_eq!(
        lent,
        (
            heap.peer_zid_hex.clone(),
            heap.whatami.clone(),
            heap.links
                .iter()
                .map(|link| (link.src.clone(), link.dst.clone()))
                .collect::<Vec<_>>(),
            heap.shm,
            heap.region.clone(),
        ),
        "the lent row is the built row, field for field"
    );
    assert_eq!(lent.0, hex_of(0xb2), "and it names B");

    // THE REMOTE WRITE. B puts a list on A's config key over the session; A's config
    // subscriber applies it, A's manager dials B, and B's listener admits A's session.
    let before = a.s.control.endpoints().0;
    let ((), n) = m.count("remote write and dial back", || {
        let mut found = None;
        b.node.for_each_dialled(|_, session| {
            found.get_or_insert(session.actions().clone());
        });
        found
            .expect("B holds its session to A")
            .send_push_literal(&a.config_key, b"[\"udp/127.0.0.1:7602\"]", true)
            .expect("the Put leaves");
        run(&mut a, &mut b, "A's session to B establishes", |a, b| {
            a.established().1 == 1 && b.established().0 == 1
        });
    });
    only_the_codec_mirrors_allocate(&m, "remote write and dial back", n);
    assert_eq!(
        a.s.control.endpoints().0,
        before + 1,
        "the write moved A's control to a new generation"
    );
    assert_eq!(
        (a.established(), b.established()),
        ((1, 1), (1, 1)),
        "each node holds one session it accepted and one it dialled"
    );
    assert_eq!(b.s.listener.counts().admitted, 1, "B admitted A's InitSyn");
    assert_eq!(
        (a.s.sessions.refused(), b.s.sessions.refused()),
        (0, 0),
        "no table of either node was ever full"
    );
    assert_eq!(
        a.s.status.refusals(),
        Default::default(),
        "no status row was refused"
    );
}

/// The task cell has to hold the application layer of a session beside the pump's
/// handle, and what the layer is made of is printed here rather than guessed: a
/// task too large for its cell is refused, counted (`too_large`), and the session
/// it was to run is given back, which is what the first run of this file saw with a
/// cell sized by hand.
#[test]
fn the_task_cell_holds_the_application_layer_of_a_session() {
    let events = std::mem::size_of::<SlotDispatch<Frozen, NoReplies, NoReplies, Sinks<N>>>();
    let requesters = std::mem::size_of::<Requesters<NoReplies, NoReplies>>();
    println!(
        "application layer {events} B, of which requesters {requesters} B; cell {TASK_BYTES} B"
    );
    assert!(
        2 * events + 256 <= TASK_BYTES,
        "the cell ({TASK_BYTES} B) is smaller than two layers ({events} B each) and the \
         pump's handle"
    );
}

#[test]
fn a_node_with_fewer_slots_than_endpoints_dials_what_it_can_and_the_rest_waits() {
    static A: Statics<2> = Statics::new();
    static B: Statics<N> = Statics::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let mut a = rig(&A, link, 0xa3, 7611);
    let mut b = rig(&B, link, 0xb4, 7612);
    let m = Measurement::attributing();

    // Three endpoints for a node of two slots: B's (which answers), one nobody
    // listens on (the session is opened and its InitSyn goes nowhere), and a third.
    let ((), n) = m.count("three endpoints, two slots", || {
        a.write_endpoints("[\"udp/127.0.0.1:7612\",\"udp/127.0.0.1:7613\",\"udp/127.0.0.1:7614\"]");
        run(&mut a, &mut b, "A dials what it can afford", |a, _| {
            a.s.sessions.in_use() == 2 && a.s.sessions.refused() >= 1
        });
        for _ in 0..8 {
            a.turn();
            b.turn();
        }
    });
    only_the_codec_mirrors_allocate(&m, "three endpoints, two slots", n);
    let mut states = Vec::new();
    a.node
        .for_each_endpoint(|endpoint, state| states.push((endpoint.to_string(), state)));
    assert_eq!(states.len(), 3, "A manages all three endpoints");
    assert_eq!(
        states[0],
        ("udp/127.0.0.1:7612".to_string(), SlotState::Live)
    );
    assert_eq!(
        states[1],
        ("udp/127.0.0.1:7613".to_string(), SlotState::Live)
    );
    assert!(
        matches!(&states[2], (endpoint, SlotState::Waiting { .. }) if endpoint == "udp/127.0.0.1:7614"),
        "the endpoint the table has no slot for waits as a dial nobody answered: {states:?}"
    );
    assert_eq!(
        a.s.sessions.in_use(),
        2,
        "both slots hold a session, none half-taken"
    );
    assert!(
        a.s.sessions.refused() >= 1,
        "the table that said no counted it ({})",
        a.s.sessions.refused()
    );
    assert_eq!(
        b.s.listener.counts().admitted,
        1,
        "B admitted the one that reached it"
    );
}
