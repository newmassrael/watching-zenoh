// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 900 — one MCU program, two sessions: the fault-isolation
//! baseline.
//!
//! The topology every test here builds, on one cooperative local set over one
//! real lwIP instance (the loopback the host harness routes multicast over):
//!
//! - a CLIENT session, the initiator, dialling a router;
//! - the ROUTER it dials, an acceptor standing in for zenohd (a fixture, not a
//!   session under test);
//! - a GROUP session, a peer in a multicast group, run by
//!   [`spawn_multicast_session`];
//! - an INJECTOR socket that plays the other group member, so the group's
//!   traffic comes from a source that is not the group session's own socket.
//!
//! Each test puts a fault in ONE session and asserts both halves: the faulted
//! session reports the fault the way it reports it alone, and the other session
//! neither stalls nor sees its data changed. These are the tests the later
//! fixed-memory (no-heap) work must keep green; they say nothing about where a
//! session's memory comes from, only that sessions do not reach each other.
//!
//! What they do NOT cover: two network interfaces (the host stack has one
//! loopback), a real router, a real group peer, and the heap. A heap that one
//! session exhausts is exhausted for both: the heap profiles have no
//! per-session heap budget.

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use wz_codecs::push::PushOwnedVariant;
use wz_link_lwip::rx_sockets::{
    bind_session_multicast_rx, bind_session_rx, SessionRxSocket, SESSION_MULTICAST_GROUP_DEFAULT,
    SESSION_MULTICAST_RX_SLOTS,
};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole, UdpPeer,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverLoopOutcome, DriverOutcome, IterationEvent};
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_params::{MulticastOutcome, MulticastParams};
use wz_session_core::multicast_tx::{multicast_put_literal, multicast_tx_emit};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sn::{self, MulticastTxConduits};
use wz_session_core::WhatAmI;

use crate::links::LwipLinks;
use crate::multicast_drive::{spawn_multicast_session, LwipMulticastDriver, MulticastSession};

/// A clock the test moves. Every session reads the one runtime clock, so a
/// step moves all of them at once, as time does on a device.
#[derive(Clone, Default)]
struct StepClock(Arc<AtomicU64>);
impl StepClock {
    fn advance_ms(&self, ms: u64) {
        self.0.fetch_add(ms * 1000, Ordering::SeqCst);
    }
}
impl ClockSource for StepClock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
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

/// The unicast parameters. The router's and the client's zids differ from
/// each other and from the group session's.
fn unicast_params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
            .expect("key"),
    }
}

/// The group parameters: the group session's own, and the injected member's.
fn group_params(zid: &[u8], lease_ms: u64) -> MulticastParams {
    MulticastParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid.to_vec(),
        lease_ms,
        join_interval_ms: 1,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
    }
}

const GROUP_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
const MEMBER_ZID: &[u8] = &[0x01, 0x02, 0x03, 0x04];

/// The payloads of every Put a drive event carries, in order.
fn put_payloads(event: &IterationEvent<'_>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
        for m in messages.iter() {
            if let NetworkMessage::Push(p) = m {
                if let PushOwnedVariant::CodecZenohMsgPut(put) = &p.body {
                    let bytes =
                        wz_session_core::put_payload::inline_bytes(put).expect("an inline payload");
                    out.push(bytes.to_vec());
                }
            }
        }
    }
    out
}

/// The other group member: a socket of its own that multicasts to the group,
/// with its own SN conduits, so its frames pass the group session's per-peer
/// SN gate in order.
struct Member {
    socket: SessionRxSocket,
    params: MulticastParams,
    sn: MulticastTxConduits,
    group: u32,
    port: u16,
}

impl Member {
    fn new(link: &LwipLink, own_port: u16, group_port: u16, lease_ms: u64) -> Self {
        let params = group_params(MEMBER_ZID, lease_ms);
        let sn = MulticastTxConduits::new(sn::mask_from_res(params.seq_num_res));
        Self {
            socket: bind_session_rx(link, own_port).expect("bind member"),
            params,
            sn,
            group: SESSION_MULTICAST_GROUP_DEFAULT,
            port: group_port,
        }
    }

    fn join(&mut self) {
        let dgram = encode_join(&self.params, &self.sn);
        self.socket
            .send_to(self.group, self.port, &dgram)
            .expect("member JOIN");
    }

    fn put(&mut self, payload: &[u8]) {
        let item = multicast_put_literal("group/k", payload).expect("build put");
        for dgram in multicast_tx_emit(item, &mut self.sn, &self.params).datagrams {
            self.socket
                .send_to(self.group, self.port, &dgram)
                .expect("member put");
        }
    }
}

/// What a test reads back from the group session.
#[derive(Default)]
struct GroupLog {
    puts: RefCell<Vec<Vec<u8>>>,
    peers_lost: Cell<usize>,
}

/// What a test reads back from the router.
#[derive(Default)]
struct RouterLog {
    puts: RefCell<Vec<Vec<u8>>>,
}

type Actions = Rc<SessionLinkActions<CoopRuntime<StepClock>, CoopTime<StepClock>>>;

/// The two sessions under test and the router fixture, all on one local set.
struct TwoSessions {
    link: Rc<LwipLink>,
    clock: StepClock,
    local: CoopLocalSet<StepClock>,
    router: Actions,
    router_log: Rc<RouterLog>,
    client: Actions,
    client_task: CoopLocalJoinHandle<DriverOutcome>,
    group_log: Rc<GroupLog>,
    group_task: CoopLocalJoinHandle<MulticastOutcome>,
    group_stop: Rc<Cell<bool>>,
}

impl TwoSessions {
    /// Spawn the router, the client towards it and the group session.
    /// `group_socket` is the group session's socket, bound (and possibly
    /// already flooded) by the caller.
    fn spawn(
        link: Rc<LwipLink>,
        router_port: u16,
        group_socket: wz_link_lwip::rx_sockets::SessionMulticastRxSocket,
        group_port: u16,
    ) -> Self {
        let clock = StepClock::default();
        let runtime = CoopRuntime::new(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let links = LwipLinks::new(link.clone());

        let OpenedLink { sink, pump } = links.open_acceptor(router_port).expect("bind router");
        let router = new_session_actions(
            sink,
            unicast_params(0xa1),
            CoopTime::new(&runtime),
            Counting(1),
        );
        let router_log = Rc::new(RouterLog::default());
        let log = router_log.clone();
        // The fixture runs for the whole test; its handle is never awaited.
        let _router_task = spawn_session(
            &local,
            pump,
            router.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            move |event| log.puts.borrow_mut().extend(put_payloads(&event)),
        );

        let OpenedLink { sink, pump } = links
            .open_initiator(UdpPeer {
                addr: [127, 0, 0, 1],
                port: router_port,
            })
            .expect("open client");
        let client = SessionLinkActions::<CoopRuntime<StepClock>, CoopTime<StepClock>>::new_generic(
            sink,
            unicast_params(0xb1),
            CoopTime::new(&runtime),
        );
        let client_task = spawn_session(
            &local,
            pump,
            client.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Initiator,
                max_iters: None,
            },
            |_| {},
        );

        let group_log = Rc::new(GroupLog::default());
        let log = group_log.clone();
        let group_stop = Rc::new(Cell::new(false));
        let stop = group_stop.clone();
        let group_task = spawn_multicast_session(
            &local,
            link.clone(),
            MulticastSession {
                dispatcher: MulticastDispatcher::<4>::new(MulticastConfig::new(5_000)),
                driver: LwipMulticastDriver::new(
                    group_socket,
                    SESSION_MULTICAST_GROUP_DEFAULT,
                    group_port,
                ),
                params: group_params(GROUP_ZID, 10_000),
                tick_ms: 5,
                max_iters: None,
            },
            move |event| {
                log.puts.borrow_mut().extend(put_payloads(&event));
                if let IterationEvent::MulticastPeerLost(_) = event {
                    log.peers_lost.set(log.peers_lost.get() + 1);
                }
            },
            || None,
            move || stop.get(),
        );

        Self {
            link,
            clock,
            local,
            router,
            router_log,
            client,
            client_task,
            group_log,
            group_task,
            group_stop,
        }
    }

    fn established(&self) -> bool {
        self.client.is_established() && self.router.is_established()
    }

    /// Pump until `done` holds, at most `passes` times; the number taken.
    fn pump_until(&self, passes: usize, mut done: impl FnMut(&Self) -> bool) -> Option<usize> {
        for n in 0..passes {
            if done(self) {
                return Some(n);
            }
            self.local.run_until_idle();
        }
        done(self).then_some(passes)
    }

    /// The client answers: a Put it sends reaches the router intact.
    fn client_put_reaches_the_router(&self, payload: &[u8]) -> bool {
        self.client
            .send_push_literal("uni/k", payload, true)
            .expect("client put");
        self.pump_until(64, |s| {
            s.router_log
                .puts
                .borrow()
                .iter()
                .any(|p| p.as_slice() == payload)
        })
        .is_some()
    }

    fn group_puts(&self) -> usize {
        self.group_log.puts.borrow().len()
    }
}

impl Drop for TwoSessions {
    fn drop(&mut self) {
        let _ = self
            .link
            .leave_multicast_group(SESSION_MULTICAST_GROUP_DEFAULT);
    }
}

/// (1) GROUP SOCKET FLOOD. The group socket is flooded past its receive slots
/// before anything runs; the client must still complete its handshake WHILE
/// the group session works through the backlog, and the backlog must come out
/// intact and in order.
///
/// The discriminator is the backlog left when the handshake completes. The
/// group session handles one datagram per step and yields; a session that
/// drained its socket inside one poll (the synchronous loop's shape, or a task
/// that does not yield after a datagram) would have taken the whole backlog
/// before the client's first turn.
#[test]
fn a_flooded_group_socket_does_not_stall_the_client_session() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (router_port, group_port, member_port) = (7471u16, 7475u16, 7480u16);
    let group = SESSION_MULTICAST_GROUP_DEFAULT;
    let group_socket = bind_session_multicast_rx(&link, group, group_port).expect("join group");

    let mut member = Member::new(&link, member_port, group_port, 10_000);
    member.join();
    // One JOIN and FLOOD puts: more datagrams than the socket has slots.
    const FLOOD: usize = SESSION_MULTICAST_RX_SLOTS + 8;
    for i in 0..FLOOD {
        member.put(&[i as u8, 0x5a]);
    }
    link.poll_loopback();
    link.check_timeouts();
    // The socket's queue is a heapless 0.8 `spsc::Queue<_, SLOTS>`, which holds
    // one fewer than its slot count (measured: 10 of 41 dropped, not 9).
    let held = SESSION_MULTICAST_RX_SLOTS - 1;
    let dropped = group_socket.rx_drop_count() as usize;
    std::assert_eq!(
        dropped,
        FLOOD + 1 - held,
        "the flood overflowed the group socket's receive queue and the excess \
         was dropped there"
    );
    // The JOIN is the first datagram held; the rest are puts.
    let kept_puts = held - 1;

    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port);
    let passes = s
        .pump_until(64, TwoSessions::established)
        .expect("the client established while the group was flooded");
    let backlog_done = s.group_puts();
    std::assert!(
        backlog_done < kept_puts,
        "the handshake completed after {passes} passes with {backlog_done} of \
         {kept_puts} queued puts handled -- the group session must not take the \
         whole backlog before the client gets a turn"
    );

    s.pump_until(256, |s| s.group_puts() == kept_puts)
        .expect("the group session works through its backlog");
    let expected: Vec<Vec<u8>> = (0..kept_puts).map(|i| vec![i as u8, 0x5a]).collect();
    std::assert_eq!(
        *s.group_log.puts.borrow(),
        expected,
        "the backlog arrives intact and in order"
    );
    std::assert!(
        s.client_put_reaches_the_router(b"after the flood"),
        "the client still answers"
    );
    std::assert!(!s.group_task.is_finished() && !s.client_task.is_finished());
}

/// (2) GROUP PEER LEASE EXPIRY. The only other group member goes silent and
/// its lease runs out: the group session evicts it and stays Running (a new
/// member is admitted and heard), and the client session is untouched.
#[test]
fn a_group_peer_lease_expiry_leaves_the_client_session_alone() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (router_port, group_port, member_port) = (7472u16, 7476u16, 7481u16);
    let group = SESSION_MULTICAST_GROUP_DEFAULT;
    let group_socket = bind_session_multicast_rx(&link, group, group_port).expect("join group");

    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port);
    let mut member = Member::new(&link, member_port, group_port, 1_000);
    member.join();
    member.put(b"before");
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .expect("both sessions up, the member heard");

    // Past the member's 1 s lease, inside the client's 10 s one.
    s.clock.advance_ms(3_000);
    s.pump_until(64, |s| s.group_log.peers_lost.get() == 1)
        .expect("the group session evicts the silent member");

    std::assert!(s.established(), "the client session is still established");
    std::assert!(
        s.client_put_reaches_the_router(b"after the eviction"),
        "and still answers"
    );
    // The group session is still Running: a member that comes back is heard.
    let mut again = Member::new(&link, member_port + 10, group_port, 10_000);
    again.join();
    again.put(b"back");
    s.pump_until(64, |s| s.group_puts() == 2)
        .expect("the group session admits and hears a new member");
    std::assert!(!s.group_task.is_finished() && !s.client_task.is_finished());
}

/// (3) UNICAST CLOSE. The router closes the client's session: the client ends
/// as Terminated, and the group session keeps receiving.
#[test]
fn a_closed_client_session_leaves_the_group_session_receiving() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (router_port, group_port, member_port) = (7473u16, 7477u16, 7482u16);
    let group = SESSION_MULTICAST_GROUP_DEFAULT;
    let group_socket = bind_session_multicast_rx(&link, group, group_port).expect("join group");

    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port);
    let mut member = Member::new(&link, member_port, group_port, 10_000);
    member.join();
    member.put(b"one");
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .expect("both sessions up, the member heard");

    s.router.send_close_with_reason(CloseReason::Generic);
    s.pump_until(64, |s| s.client_task.is_finished())
        .expect("the client session ends on the router's Close");

    member.put(b"two");
    member.put(b"three");
    s.pump_until(64, |s| s.group_puts() == 3)
        .expect("the group session keeps receiving after the client ended");
    std::assert_eq!(
        *s.group_log.puts.borrow(),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    std::assert!(!s.group_task.is_finished());
}

/// (4) MULTICAST STOP. The group session is asked to stop: it ends as Stopped,
/// and the client session keeps running and answering.
#[test]
fn a_stopped_group_session_leaves_the_client_session_answering() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (router_port, group_port, member_port) = (7474u16, 7478u16, 7483u16);
    let group = SESSION_MULTICAST_GROUP_DEFAULT;
    let group_socket = bind_session_multicast_rx(&link, group, group_port).expect("join group");

    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port);
    let mut member = Member::new(&link, member_port, group_port, 10_000);
    member.join();
    member.put(b"one");
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .expect("both sessions up, the member heard");

    s.group_stop.set(true);
    s.pump_until(64, |s| s.group_task.is_finished())
        .expect("the group session stops on its flag");

    std::assert!(s.established(), "the client session is still established");
    std::assert!(
        s.client_put_reaches_the_router(b"after the stop"),
        "and still answers"
    );
    std::assert!(!s.client_task.is_finished());
}
