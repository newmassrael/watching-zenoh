// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The four fault-isolation scenarios of open-debt item 900, ON TARGET.
//!
//! The topology is the host baseline's (`crates/wz-session-lwip/src/
//! two_session_tests.rs`), built over this image's lwIP loopback instead of the
//! host harness's:
//!
//! - a CLIENT session, the initiator, dialling a router;
//! - the ROUTER it dials, an acceptor standing in for zenohd (a fixture in this
//!   image, as the acceptor e2e's peer is: the QEMU machine has no NIC here);
//! - a GROUP session, a peer in a multicast group, run by
//!   `spawn_multicast_session`;
//! - a MEMBER socket that plays the other group member, so the group's traffic
//!   comes from a source that is not the group session's own socket.
//!
//! All four share one `CoopLocalSet` inside the one FreeRTOS task. What
//! differs from the host: time is the kernel tick (the host steps a clock), so
//! the lease expiry is waited for in real time, and the group advertises the
//! deploy manifest's JOIN interval rather than 1 ms, since on a running clock a
//! 1 ms beacon would fill its own socket with its own JOINs.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use wz::link_lwip::rx_sockets::{
    bind_session_multicast_rx, bind_session_rx, SessionMulticastRxSocket, SessionRxSocket,
    SESSION_MULTICAST_GROUP_DEFAULT, SESSION_MULTICAST_RX_SLOTS,
};
use wz::link_lwip::LwipLink;
use wz::runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole, UdpPeer,
};
use wz::runtime_coop::session_runtime::new_session_actions;
use wz::runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz::runtime_freertos::{FreertosClock, FreertosEntropy};
use wz::session_lwip::multicast_drive::{
    spawn_multicast_session, LwipMulticastDriver, MulticastSession,
};
use wz::session_lwip::LwipLinks;
use wz_codecs::push::PushOwnedVariant;
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
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sn::{self, MulticastTxConduits};
use wz_session_core::WhatAmI;

use crate::board::{heap_free_bytes, TICK_HZ};

type Clock = FreertosClock<TICK_HZ>;
type Actions = Rc<SessionLinkActions<CoopRuntime<Clock>, CoopTime<Clock>>>;

/// The group's JOIN interval: the deploy manifest's
/// (`deploy/mcu_client_and_group.yaml`, `group.join_interval_ms`).
const GROUP_JOIN_INTERVAL_MS: u64 = 2_500;

/// The unicast parameters. The router's and the client's zids differ from
/// each other and from the group session's.
///
/// The cookie key is drawn through the board's entropy hook, the port the
/// router's cookie nonce already uses, as a shipped acceptor draws it
/// (`SigningKey::from_entropy`, as the acceptor e2e image does). On this QEMU
/// board the hook is a fixture (see `board::xApplicationGetRandomNumber`); the
/// image exercises the seam a real board fills with its TRNG, so the profile
/// code here does not change between the two. A literal key here would be
/// published with the repository, which `scripts/lib/literal_key_gate.py`
/// refuses outside a test-gated item. A hook that yields nothing fails the
/// scenario rather than running with a key it did not draw.
fn unicast_params(zid: u8) -> Result<SessionInitParams, String> {
    let cookie_signing_key = SigningKey::from_entropy(&mut FreertosEntropy)
        .map_err(|e| format!("draw the cookie signing key: {:?}", e))?;
    Ok(SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key,
    })
}

/// The group parameters: the group session's own, and the member's.
fn group_params(zid: &[u8], lease_ms: u64) -> MulticastParams {
    MulticastParams {
        whatami: WhatAmI::Peer,
        zid: zid.to_vec(),
        lease_ms,
        join_interval_ms: GROUP_JOIN_INTERVAL_MS,
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
                    if let Some(bytes) = wz_session_core::put_payload::inline_bytes(put) {
                        out.push(bytes.to_vec());
                    }
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
    port: u16,
}

impl Member {
    fn new(link: &LwipLink, own_port: u16, group_port: u16, lease_ms: u64) -> Result<Self, String> {
        let params = group_params(MEMBER_ZID, lease_ms);
        let sn = MulticastTxConduits::new(sn::mask_from_res(params.seq_num_res));
        Ok(Self {
            socket: bind_session_rx(link, own_port).map_err(|e| format!("bind member: {:?}", e))?,
            params,
            sn,
            port: group_port,
        })
    }

    fn join(&mut self) -> Result<(), String> {
        let dgram = encode_join(&self.params, &self.sn);
        self.socket
            .send_to(SESSION_MULTICAST_GROUP_DEFAULT, self.port, &dgram)
            .map_err(|e| format!("member JOIN: {:?}", e))
    }

    fn put(&mut self, payload: &[u8]) -> Result<(), String> {
        let item =
            multicast_put_literal("group/k", payload).map_err(|e| format!("build put: {:?}", e))?;
        for dgram in multicast_tx_emit(item, &mut self.sn, &self.params).datagrams {
            self.socket
                .send_to(SESSION_MULTICAST_GROUP_DEFAULT, self.port, &dgram)
                .map_err(|e| format!("member put: {:?}", e))?;
        }
        Ok(())
    }
}

/// What a scenario reads back from the group session.
#[derive(Default)]
struct GroupLog {
    puts: RefCell<Vec<Vec<u8>>>,
    peers_lost: Cell<usize>,
}

/// What a scenario reads back from the router.
#[derive(Default)]
struct RouterLog {
    puts: RefCell<Vec<Vec<u8>>>,
}

/// heap_4 bytes each link open took, measured as the free-heap delta around
/// it (the receive pool, its socket state and the driver around it).
#[derive(Clone, Copy, Default)]
pub struct OpenCost {
    pub router: usize,
    pub client: usize,
}

/// The two sessions under test and the router fixture, all on one local set.
struct TwoSessions {
    link: Rc<LwipLink>,
    clock: Clock,
    local: CoopLocalSet<Clock>,
    router: Actions,
    router_log: Rc<RouterLog>,
    client: Actions,
    client_task: CoopLocalJoinHandle<DriverOutcome>,
    group_log: Rc<GroupLog>,
    group_task: CoopLocalJoinHandle<MulticastOutcome>,
    group_stop: Rc<Cell<bool>>,
    cost: OpenCost,
}

impl TwoSessions {
    /// Spawn the router, the client towards it and the group session over
    /// `group_socket`, bound (and possibly already flooded) by the caller.
    fn spawn(
        link: Rc<LwipLink>,
        router_port: u16,
        group_socket: SessionMulticastRxSocket,
        group_port: u16,
    ) -> Result<Self, String> {
        let clock = Clock::default();
        let runtime = CoopRuntime::new(clock);
        let local = CoopLocalSet::new(&runtime);
        let links = LwipLinks::new(link.clone());

        let before = heap_free_bytes();
        let OpenedLink { sink, pump } = links
            .open_acceptor(router_port)
            .map_err(|e| format!("bind router: {:?}", e))?;
        let router_cost = before.saturating_sub(heap_free_bytes());
        let router = new_session_actions(
            sink,
            unicast_params(0xa1)?,
            CoopTime::new(&runtime),
            FreertosEntropy,
        );
        let router_log = Rc::new(RouterLog::default());
        let log = router_log.clone();
        // The fixture runs for the whole scenario; its handle is never awaited.
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

        let before = heap_free_bytes();
        let OpenedLink { sink, pump } = links
            .open_initiator(UdpPeer {
                addr: [127, 0, 0, 1],
                port: router_port,
            })
            .map_err(|e| format!("open client: {:?}", e))?;
        let client_cost = before.saturating_sub(heap_free_bytes());
        let client = SessionLinkActions::<CoopRuntime<Clock>, CoopTime<Clock>>::new_generic(
            sink,
            unicast_params(0xb1)?,
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

        Ok(Self {
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
            cost: OpenCost {
                router: router_cost,
                client: client_cost,
            },
        })
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

    /// Pump until `done` holds or `ms` of kernel time have passed; the
    /// milliseconds it took. For the scenario that waits on a lease, which a
    /// pass count cannot bound on a running clock.
    fn pump_for_ms(&self, ms: u64, mut done: impl FnMut(&Self) -> bool) -> Option<u64> {
        let start = self.clock.now_us();
        loop {
            let elapsed = (self.clock.now_us() - start) / 1000;
            if done(self) {
                return Some(elapsed);
            }
            if elapsed >= ms {
                return None;
            }
            self.local.run_until_idle();
        }
    }

    /// The client answers: a Put it sends reaches the router intact.
    fn client_put_reaches_the_router(&self, payload: &[u8]) -> bool {
        if self
            .client
            .send_push_literal("uni/k", payload, true)
            .is_err()
        {
            return false;
        }
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

/// Fail a scenario with a sentence, unless `cond` holds.
fn ensure(cond: bool, why: impl FnOnce() -> String) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(why())
    }
}

/// Bind the group socket on `group_port`; the heap it took.
fn bind_group(
    link: &LwipLink,
    group_port: u16,
) -> Result<(SessionMulticastRxSocket, usize), String> {
    let before = heap_free_bytes();
    let socket = bind_session_multicast_rx(link, SESSION_MULTICAST_GROUP_DEFAULT, group_port)
        .map_err(|e| format!("join group: {:?}", e))?;
    Ok((socket, before.saturating_sub(heap_free_bytes())))
}

/// What the flood scenario measured besides its verdict: the heap each
/// session's link open took, which is what STEP 0 of item 900 asks for.
pub struct PoolCosts {
    pub client: usize,
    pub group: usize,
    pub router_fixture: usize,
    pub member_fixture: usize,
}

/// (1) GROUP SOCKET FLOOD. The group socket is flooded past its receive slots
/// before anything runs; the client must still complete its handshake WHILE
/// the group session works through the backlog, and the backlog must come out
/// intact and in order. The discriminator is the backlog left when the
/// handshake completes (see the host twin).
pub fn flood(link: &Rc<LwipLink>) -> Result<(String, PoolCosts), String> {
    let (router_port, group_port, member_port) = (7471u16, 7475u16, 7480u16);
    let (group_socket, group_cost) = bind_group(link, group_port)?;

    let before = heap_free_bytes();
    let mut member = Member::new(link, member_port, group_port, 10_000)?;
    let member_cost = before.saturating_sub(heap_free_bytes());
    member.join()?;
    // One JOIN and FLOOD puts: more datagrams than the socket has slots.
    const FLOOD: usize = SESSION_MULTICAST_RX_SLOTS + 8;
    for i in 0..FLOOD {
        member.put(&[i as u8, 0x5a])?;
    }
    link.poll_loopback();
    link.check_timeouts();
    // The heapless spsc queue holds one fewer than its slot count.
    let held = SESSION_MULTICAST_RX_SLOTS - 1;
    let dropped = group_socket.rx_drop_count() as usize;
    ensure(dropped == FLOOD + 1 - held, || {
        format!(
            "the group socket dropped {dropped} of {} datagrams, expected {}",
            FLOOD + 1,
            FLOOD + 1 - held
        )
    })?;
    let kept_puts = held - 1;

    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port)?;
    let passes = s
        .pump_until(64, TwoSessions::established)
        .ok_or_else(|| String::from("the client did not establish while the group was flooded"))?;
    let backlog_done = s.group_puts();
    ensure(backlog_done < kept_puts, || {
        format!(
            "the handshake completed after {passes} passes with {backlog_done} of {kept_puts} \
             queued puts handled: the group session took the whole backlog first"
        )
    })?;
    s.pump_until(256, |s| s.group_puts() == kept_puts)
        .ok_or_else(|| {
            format!(
                "the group session handled {} of {kept_puts}",
                s.group_puts()
            )
        })?;
    let expected: Vec<Vec<u8>> = (0..kept_puts).map(|i| vec![i as u8, 0x5a]).collect();
    ensure(*s.group_log.puts.borrow() == expected, || {
        String::from("the backlog did not arrive intact and in order")
    })?;
    ensure(s.client_put_reaches_the_router(b"after the flood"), || {
        String::from("the client no longer answers after the flood")
    })?;
    ensure(
        !s.group_task.is_finished() && !s.client_task.is_finished(),
        || String::from("a session ended"),
    )?;
    let costs = PoolCosts {
        client: s.cost.client,
        group: group_cost,
        router_fixture: s.cost.router,
        member_fixture: member_cost,
    };
    Ok((
        format!(
            "{dropped} of {} dropped at the socket; client established after {passes} passes \
             with {backlog_done} of {kept_puts} queued puts handled; backlog {kept_puts} in \
             order; client answers",
            FLOOD + 1
        ),
        costs,
    ))
}

/// (2) GROUP PEER LEASE EXPIRY. The only other group member goes silent and
/// its lease runs out: the group session evicts it and stays Running (a new
/// member is admitted and heard), and the client session is untouched.
pub fn lease_expiry(link: &Rc<LwipLink>) -> Result<String, String> {
    let (router_port, group_port, member_port) = (7472u16, 7476u16, 7481u16);
    let (group_socket, _) = bind_group(link, group_port)?;
    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port)?;
    let mut member = Member::new(link, member_port, group_port, 1_000)?;
    member.join()?;
    member.put(b"before")?;
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .ok_or_else(|| String::from("both sessions up, the member heard: not reached"))?;
    // The silent member's socket goes: the image's lwIP port has four UDP
    // PCBs (router, client, group, member), and the returning member below
    // needs one. Dropping it sends nothing, so the member stays silent.
    drop(member);

    // The member's 1 s lease runs out in real time, inside the client's 10 s.
    let waited = s
        .pump_for_ms(5_000, |s| s.group_log.peers_lost.get() == 1)
        .ok_or_else(|| String::from("the group session did not evict the silent member in 5 s"))?;
    ensure(s.established(), || {
        String::from("the client session lost Established")
    })?;
    ensure(
        s.client_put_reaches_the_router(b"after the eviction"),
        || String::from("the client no longer answers after the eviction"),
    )?;
    let mut again = Member::new(link, member_port + 10, group_port, 10_000)?;
    again.join()?;
    again.put(b"back")?;
    s.pump_until(64, |s| s.group_puts() == 2)
        .ok_or_else(|| String::from("the group session did not hear a new member"))?;
    ensure(
        !s.group_task.is_finished() && !s.client_task.is_finished(),
        || String::from("a session ended"),
    )?;
    Ok(format!(
        "member evicted {waited} ms after going silent (lease 1000 ms); client still \
         established and answers; a new member is heard"
    ))
}

/// (3) UNICAST CLOSE. The router closes the client's session: the client ends,
/// and the group session keeps receiving.
pub fn unicast_close(link: &Rc<LwipLink>) -> Result<String, String> {
    let (router_port, group_port, member_port) = (7473u16, 7477u16, 7482u16);
    let (group_socket, _) = bind_group(link, group_port)?;
    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port)?;
    let mut member = Member::new(link, member_port, group_port, 10_000)?;
    member.join()?;
    member.put(b"one")?;
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .ok_or_else(|| String::from("both sessions up, the member heard: not reached"))?;

    s.router.send_close_with_reason(CloseReason::Generic);
    let passes = s
        .pump_until(64, |s| s.client_task.is_finished())
        .ok_or_else(|| String::from("the client session did not end on the router's Close"))?;

    member.put(b"two")?;
    member.put(b"three")?;
    s.pump_until(64, |s| s.group_puts() == 3).ok_or_else(|| {
        format!(
            "the group session heard {} of 3 puts after the client ended",
            s.group_puts()
        )
    })?;
    ensure(
        *s.group_log.puts.borrow() == vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
        || String::from("the group's puts changed"),
    )?;
    ensure(!s.group_task.is_finished(), || {
        String::from("the group session ended with the client")
    })?;
    Ok(format!(
        "client ended {passes} passes after the router's Close; group heard 3 of 3 puts in \
         order and is still running"
    ))
}

/// (4) MULTICAST STOP. The group session is asked to stop: it ends, and the
/// client session keeps running and answering.
pub fn multicast_stop(link: &Rc<LwipLink>) -> Result<String, String> {
    let (router_port, group_port, member_port) = (7474u16, 7478u16, 7483u16);
    let (group_socket, _) = bind_group(link, group_port)?;
    let s = TwoSessions::spawn(link.clone(), router_port, group_socket, group_port)?;
    let mut member = Member::new(link, member_port, group_port, 10_000)?;
    member.join()?;
    member.put(b"one")?;
    s.pump_until(64, |s| s.established() && s.group_puts() == 1)
        .ok_or_else(|| String::from("both sessions up, the member heard: not reached"))?;

    s.group_stop.set(true);
    let passes = s
        .pump_until(64, |s| s.group_task.is_finished())
        .ok_or_else(|| String::from("the group session did not stop on its flag"))?;
    ensure(s.established(), || {
        String::from("the client session lost Established")
    })?;
    ensure(s.client_put_reaches_the_router(b"after the stop"), || {
        String::from("the client no longer answers after the stop")
    })?;
    ensure(!s.client_task.is_finished(), || {
        String::from("the client session ended with the group")
    })?;
    Ok(format!(
        "group stopped {passes} passes after its flag; client still established and answers"
    ))
}
