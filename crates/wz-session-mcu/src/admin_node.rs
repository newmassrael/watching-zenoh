// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2837 (§5.23) — an MCU node whose connections a host controls at runtime,
//! as ONE thing a firmware ticks.
//!
//! The pieces are the earlier rounds': the config-write subscriber
//! (`crate::admin_host`), the admin GET queryable (`crate::admin_status`),
//! the connection manager and its dialer (`crate::connect_manager`,
//! `crate::dial`). [`crate::admin_node::AdminNode`] wires them to one
//! application-layer observer and adds the half none of them had: a session
//! a host can reach the node on in the first place.
//!
//! * The node LISTENS on a UDP port with an acceptor session. A host that
//!   connects there can write `connect/endpoints` and GET the node's status.
//!   When that session ends the node listens again on the next tick, so a
//!   host that goes away and comes back finds it.
//! * Every session, accepted or dialled, dispatches to the same observer, so
//!   a write or a GET arriving on any of them is answered the same way.
//! * Each tick reports every ESTABLISHED session, accepted and dialled, as
//!   the GET's `sessions`, which is how upstream lists transports.
//! * R2838 — once a session is established the node DECLARES, on it, what
//!   upstream's admin space declares: a queryable on `@/<zid>/<whatami>/**`
//!   and a subscriber on `@/<zid>/<whatami>/config/**`. A router forwards a
//!   GET or a PUT only to a face that declared a match, so without these a
//!   stock zenohd connected to the node holds a live session and still
//!   routes nothing to it. That is what the first run against one showed.
//!
//! ## Over whichever network stack the board has
//!
//! The node was written on lwIP and named for it. What it needs from the stack
//! is two things: a link that accepts on a port, and a link that dials an
//! address. Both are [`SessionLinks`], so the node is generic over `L` and a
//! board's network is a type parameter: lwIP's, Zephyr's sockets, or the
//! in-memory network its tests run on. The node's own code names none of them.
//!
//! A firmware's loop is then: run the task set, service its network (poll its
//! Ethernet interface, pump the stack's timers: the stack's business, done
//! beside this), and `tick` the node with the time.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopTime};
use wz_session_core::admin_config_space::write_config_space_pattern;
use wz_session_core::adminspace::admin_queryable_key;
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::registry_error::RegisterError;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::admin_host::{host_connect_writes, ConnectControl};
use crate::admin_status::{
    host_admin_queryable, DialStatus, EndpointStatus, NodeIdentity, NodeStatus,
};
use crate::app_layer::dispatch_to;
use crate::connect_manager::{ConnectManager, SlotState};
use crate::dial::{admin_session_of, EventSink, McuActions, UdpDialer};

/// Builds the sink each dialled session reports to.
type DialSink<C> = Box<dyn FnMut(&Rc<McuActions<C>>) -> EventSink>;

/// An MCU node a host can reach, and reconfigure, at runtime.
pub struct AdminNode<'a, L, C, P, A>
where
    L: SessionLinks,
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    A: FnMut(Rc<dyn BoxedLinkDriver>) -> Rc<McuActions<C>>,
{
    local: &'a CoopLocalSet<C>,
    links: Rc<L>,
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    status: &'static NodeStatus,
    manager: ConnectManager<UdpDialer<'a, L, C, P, DialSink<C>>>,
    listen_port: u16,
    timeouts: SessionTimeouts,
    accept: A,
    acceptor: Option<(CoopLocalJoinHandle<DriverOutcome>, Rc<McuActions<C>>)>,
    admin_key: String,
    config_key: String,
    /// The sessions the admin declarations have been sent on, by identity.
    declared: Vec<*const McuActions<C>>,
}

/// The declaration ids the node uses on each session; ids are per session.
const ADMIN_QUERYABLE_ID: u64 = 1;
const CONFIG_SUBSCRIBER_ID: u64 = 2;

/// Declare upstream's two admin-space interests on `actions`: `true` once
/// both went out.
fn declare_admin<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    admin_key: &str,
    config_key: &str,
) -> bool {
    // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
    actions
        .send_declare_queryable(ADMIN_QUERYABLE_ID, 0, Some(admin_key), false)
        .is_ok()
        && actions
            .send_declare_subscriber(CONFIG_SUBSCRIBER_ID, 0, Some(config_key))
            .is_ok()
}

impl<'a, L, C, P, A> AdminNode<'a, L, C, P, A>
where
    L: SessionLinks,
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    A: FnMut(Rc<dyn BoxedLinkDriver>) -> Rc<McuActions<C>>,
{
    /// A node that listens on `listen_port`, answers as `identity`, applies
    /// writes to `control` and reports through `status`, over the network `links`.
    ///
    /// `dial_params` gives each dialled session its parameters. `accept`
    /// builds the action bundle of each acceptor session over the sink it
    /// is given; an acceptor mints cookies, so this is where a board installs
    /// its entropy source (`wz_runtime_coop::session_runtime::new_session_actions`).
    ///
    /// `Err` when the node's own observer refuses its config subscriber or its
    /// admin queryable (see [`host_connect_writes`] and
    /// [`host_admin_queryable`]): a node that cannot host its admin space is
    /// not started, rather than started deaf. On the growable backing this
    /// never fails; on the fixed one it fails only for a key past
    /// `caps::MAX_KEYEXPR_BYTES`, since the observer is fresh.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local: &'a CoopLocalSet<C>,
        links: Rc<L>,
        control: &'static ConnectControl,
        status: &'static NodeStatus,
        identity: NodeIdentity,
        listen_port: u16,
        timeouts: SessionTimeouts,
        dial_params: P,
        accept: A,
    ) -> Result<Self, RegisterError> {
        let admin_key = admin_queryable_key(&identity.zid_hex, identity.whatami);
        let mut config_key = String::new();
        // Writing into a `String` cannot fail.
        let _ = write_config_space_pattern(&mut config_key, &identity.zid_hex, identity.whatami);
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        {
            let mut o = observer.borrow_mut();
            host_connect_writes(&mut o, &identity.zid_hex, identity.whatami, control)?;
            host_admin_queryable(&mut o, identity, status, Some(control), Some(control))?;
        }
        let dial_observer = observer.clone();
        let on_event: DialSink<C> = Box::new(move |actions| {
            Box::new(dispatch_to(dial_observer.clone(), actions.clone())) as EventSink
        });
        let dialer = UdpDialer::new(local, links.clone(), timeouts, dial_params, on_event);
        Ok(Self {
            local,
            links,
            observer,
            status,
            manager: ConnectManager::new(control, dialer),
            listen_port,
            timeouts,
            accept,
            acceptor: None,
            admin_key,
            config_key,
            declared: Vec::new(),
        })
    }

    /// The observer every session of this node dispatches to.
    pub fn observer(&self) -> &Rc<RefCell<ApplicationLayerObserver>> {
        &self.observer
    }

    /// The session a host reached this node on, while there is one.
    pub fn acceptor(&self) -> Option<&Rc<McuActions<C>>> {
        self.acceptor.as_ref().map(|(_, actions)| actions)
    }

    /// Advance the node to `now_ms`: listen again if the accepted session
    /// has ended, keep the dialled sessions in step with the control, and
    /// report every established session.
    pub fn tick(&mut self, now_ms: u64) {
        if self
            .acceptor
            .as_ref()
            .map_or(true, |(handle, _)| handle.is_finished())
        {
            // Let go of the ended session (and its socket) before binding
            // the port again. A bind that fails is retried next tick.
            self.acceptor = None;
            self.acceptor = self.listen();
        }
        self.manager.tick(now_ms);
        self.declare_on_new_sessions();
        let mut sessions: Vec<_> = self
            .acceptor
            .iter()
            .filter_map(|(_, actions)| admin_session_of(actions))
            .collect();
        sessions.extend(
            self.manager
                .sessions()
                .filter_map(|(_, session)| session.admin_session()),
        );
        self.status.set_sessions(sessions);
        self.status.set_endpoints(self.endpoint_statuses(now_ms));
    }

    /// R2846 — every written endpoint and where it stands, for the
    /// `status/connect` leg. `states()` and `sessions()` both walk the slots
    /// in list order and `sessions()` yields exactly the live ones, so the two
    /// are read side by side to say whether each live session is established.
    fn endpoint_statuses(&self, now_ms: u64) -> Vec<EndpointStatus> {
        let mut live = self.manager.sessions();
        self.manager
            .states()
            .map(|(endpoint, state)| EndpointStatus {
                endpoint: String::from(endpoint),
                status: match state {
                    SlotState::Live => DialStatus::Live {
                        established: live
                            .next()
                            .is_some_and(|(_, session)| session.actions().is_established()),
                    },
                    SlotState::Waiting { at_ms } => DialStatus::Waiting {
                        retry_in_ms: at_ms.saturating_sub(now_ms),
                    },
                    SlotState::Refused(why) => DialStatus::Refused {
                        reason: why.as_str(),
                    },
                },
            })
            .collect()
    }

    /// Send the admin declarations on every established session that has
    /// not had them, and forget the sessions that are gone.
    fn declare_on_new_sessions(&mut self) {
        let live: Vec<&Rc<McuActions<C>>> = self
            .acceptor
            .iter()
            .map(|(_, actions)| actions)
            .chain(self.manager.sessions().map(|(_, s)| s.actions()))
            .collect();
        self.declared
            .retain(|done| live.iter().any(|a| Rc::as_ptr(a) == *done));
        for actions in live {
            let key = Rc::as_ptr(actions);
            if actions.is_established()
                && !self.declared.contains(&key)
                && declare_admin(actions, &self.admin_key, &self.config_key)
            {
                self.declared.push(key);
            }
        }
    }

    fn listen(&mut self) -> Option<(CoopLocalJoinHandle<DriverOutcome>, Rc<McuActions<C>>)> {
        // The peer is whoever speaks first; the link learns it on receive.
        let OpenedLink { sink, pump } = self.links.open_acceptor(self.listen_port).ok()?;
        let actions = (self.accept)(sink);
        let on_event = dispatch_to(self.observer.clone(), actions.clone());
        let handle = spawn_session(
            self.local,
            pump,
            actions.clone(),
            CoopTime::new(self.local.runtime()),
            SessionDriveConfig {
                timeouts: self.timeouts,
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            on_event,
        );
        Some((handle, actions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    use wz_codecs::push::{Push, PushVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_runtime_coop::session_runtime::new_session_actions;
    use wz_runtime_coop::CoopRuntime;
    use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    use crate::memory::{MemoryLinks, MemoryNetwork};

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

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

    fn params(zid: u8) -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: wz_session_core::WhatAmI::Peer,
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

    fn put(key: &str, payload: &[u8]) -> DriverLoopOutcome {
        let mut push = Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(key.len() as u64),
                    suffix: Some(key),
                }),
            },
            ..Push::default()
        };
        if let PushVariant::CodecZenohMsgPut(ref mut msg) = push.body {
            msg.payload_len = Some(payload.len() as u64);
            msg.payload = Some(payload);
        }
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(
                push.try_into_owned().unwrap(),
            ))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// The node composed end to end over a network of in-memory ends: a
    /// `connect/endpoints` write arriving on the node's observer makes it dial
    /// the endpoint, the peer there completes the handshake, and the node then
    /// reports that session — the zid of the peer it reached — as its GET's
    /// `sessions`. The CONTROL is the same node before the write: it listens,
    /// reports no session, and dials nothing.
    ///
    /// The network is not any stack's: this is what the node does on every
    /// network, and the stack-specific witnesses (lwIP's, Zephyr's) show only
    /// that each stack's links satisfy the seam this runs through.
    #[test]
    fn a_written_endpoint_is_dialled_and_reported_by_the_node() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STATUS: NodeStatus = NodeStatus::new(true);

        let net = MemoryNetwork::new();
        let node_links = Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 2]));
        let far_links = MemoryLinks::new(net.clone(), [10, 0, 0, 1]);
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // The peer the write will name: a plain acceptor on 7522.
        let OpenedLink {
            sink: far_sink,
            pump: far_pump,
        } = far_links.open_acceptor(7522).expect("bind far peer");
        let far_actions =
            new_session_actions(far_sink, params(0xc3), CoopTime::new(&runtime), Counting(9));
        // R2838 — what the peer is told: every Declare the node sends it.
        let declares = Rc::new(core::cell::Cell::new(0usize));
        let seen = declares.clone();
        let _far = spawn_session(
            &local,
            far_pump,
            far_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    let n = messages
                        .iter()
                        .filter(|m| matches!(m, NetworkMessage::Declare(_)))
                        .count();
                    seen.set(seen.get() + n);
                }
            },
        );

        let accept_runtime = runtime.clone();
        let mut node = AdminNode::new(
            &local,
            node_links,
            &CONTROL,
            &STATUS,
            NodeIdentity {
                zid_hex: String::from("b1b1b1b1"),
                whatami: "peer",
                version: String::from("wz-test"),
                locators: vec![String::from("udp/10.0.0.2:7521")],
            },
            7521,
            SessionTimeouts::spec_defaults(),
            || params(0xb1),
            move |sink| {
                new_session_actions(
                    sink,
                    params(0xb1),
                    CoopTime::new(&accept_runtime),
                    Counting(1),
                )
            },
        )
        .expect("a fresh node takes its admin keys");

        // CONTROL: listening, nothing written, nothing reported.
        for _ in 0..16 {
            local.run_until_idle();
            node.tick(0);
        }
        std::assert!(node.acceptor().is_some(), "the node listens");
        std::assert!(STATUS.sessions().is_empty(), "CONTROL: no session yet");
        std::assert!(!far_actions.is_established(), "CONTROL: nothing dialled");

        node.observer()
            .borrow_mut()
            .dispatch_event(IterationEvent::Poll(&put(
                "@/b1b1b1b1/peer/config/connect/endpoints",
                br#"["udp/10.0.0.1:7522"]"#,
            )));
        // The tick that dials is not the tick that establishes: the session is
        // spawned and has not run, so nothing has been declared on it, and the
        // node keeps no record that would stop it declaring once it has.
        node.tick(0);
        std::assert!(
            node.manager
                .sessions()
                .all(|(_, session)| !session.actions().is_established()),
            "the dialled session has not run yet"
        );
        std::assert!(
            node.manager.sessions().count() == 1,
            "the write made the node dial"
        );
        std::assert!(
            node.declared.is_empty(),
            "nothing is declared on a session that is not established"
        );
        for _ in 0..64 {
            local.run_until_idle();
            node.tick(0);
            if !STATUS.sessions().is_empty() {
                break;
            }
        }
        let reported = STATUS.sessions();
        std::assert_eq!(reported.len(), 1, "the dialled session is reported");
        std::assert_eq!(reported[0].peer_zid_hex, zid_to_zenoh_hex(&[0xc3; 4]));
        std::assert!(far_actions.is_established(), "the peer holds it too");
        // R2846 — and `status/connect` says the same thing about the endpoint.
        std::assert_eq!(
            STATUS.endpoints(),
            [EndpointStatus {
                endpoint: String::from("udp/10.0.0.1:7522"),
                status: DialStatus::Live { established: true },
            }]
        );

        // R2838 — the peer was told what upstream's admin space tells a
        // router: the admin queryable and the config subscriber, once each.
        for _ in 0..16 {
            local.run_until_idle();
            node.tick(0);
        }
        std::assert_eq!(declares.get(), 2, "one queryable and one subscriber");
    }

    /// When the accepted session ends the node listens again, on the same port,
    /// as a NEW session: a host that goes away and comes back finds it. The
    /// listener is the half of the node a stack opens (`open_acceptor`), so this
    /// is the witness that the node lets go of the ended session's link before it
    /// asks the stack for the port again, which a network that refuses a second
    /// bind (this one does, as a real socket does) would otherwise turn into a
    /// node that never listens twice.
    #[test]
    fn the_node_listens_again_when_the_accepted_session_ends() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STATUS: NodeStatus = NodeStatus::new(true);

        let net = MemoryNetwork::new();
        let node_links = Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 2]));
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);
        let accept_runtime = runtime.clone();
        let mut node = AdminNode::new(
            &local,
            node_links,
            &CONTROL,
            &STATUS,
            NodeIdentity {
                zid_hex: String::from("b2b2b2b2"),
                whatami: "peer",
                version: String::from("wz-test"),
                locators: vec![String::from("udp/10.0.0.2:7531")],
            },
            7531,
            SessionTimeouts::spec_defaults(),
            || params(0xb2),
            move |sink| {
                new_session_actions(
                    sink,
                    params(0xb2),
                    CoopTime::new(&accept_runtime),
                    Counting(1),
                )
            },
        )
        .expect("a fresh node takes its admin keys");
        let listen_at = wz_runtime_coop::session_drive::UdpPeer {
            addr: [10, 0, 0, 2],
            port: 7531,
        };
        node.tick(0);
        // Weak: it does not hold the session's link (and so its port), and it
        // keeps the allocation, so the ended session's address cannot be handed
        // to its successor and make "a new session" read as "the same one".
        let first = Rc::downgrade(node.acceptor().expect("listening"));
        std::assert!(
            net.bind(listen_at, None).is_err(),
            "the listener holds the port"
        );

        // The accepted session ends (a host went away). `abort` marks it
        // finished at once but the executor drops its body, and the link with
        // it, only on its next sweep: a tick in between finds the port still
        // held, and the node must retry rather than give up.
        node.acceptor.as_ref().expect("listening").0.abort();
        node.tick(1);
        std::assert!(
            node.acceptor().is_none(),
            "the port is held until the executor drops the ended session"
        );

        // The firmware loop runs the executor, then ticks: now the port is
        // free, and the node listens again with a session of its own.
        local.run_until_idle();
        node.tick(2);
        let second = node.acceptor().expect("listening again");
        std::assert!(
            first.upgrade().is_none(),
            "the ended session is gone, neither the node nor the executor holds it"
        );
        std::assert!(
            !core::ptr::eq(first.as_ptr(), Rc::as_ptr(second)),
            "a new session, not the ended one"
        );
        std::assert!(
            net.bind(listen_at, None).is_err(),
            "and it holds the port again"
        );
    }

    /// The order a firmware loop really has: the executor runs, then the node
    /// ticks. A session that ended is already dropped by the executor by then, so
    /// the node's own hold on the session's link is all that is left on the port,
    /// and the node must let it go and listen again within the SAME tick. What it
    /// had declared on the ended session is forgotten with it, not kept for the
    /// life of the firmware.
    #[test]
    fn the_node_listens_again_at_once_when_the_executor_has_already_dropped_the_session() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STATUS: NodeStatus = NodeStatus::new(true);

        let net = MemoryNetwork::new();
        let node_links = Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 2]));
        let host_links = MemoryLinks::new(net.clone(), [10, 0, 0, 1]);
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);
        let accept_runtime = runtime.clone();
        let mut node = AdminNode::new(
            &local,
            node_links,
            &CONTROL,
            &STATUS,
            NodeIdentity {
                zid_hex: String::from("b3b3b3b3"),
                whatami: "peer",
                version: String::from("wz-test"),
                locators: vec![String::from("udp/10.0.0.2:7541")],
            },
            7541,
            SessionTimeouts::spec_defaults(),
            || params(0xb3),
            move |sink| {
                new_session_actions(
                    sink,
                    params(0xb3),
                    CoopTime::new(&accept_runtime),
                    Counting(1),
                )
            },
        )
        .expect("a fresh node takes its admin keys");
        node.tick(0);

        // A host reaches the node and the handshake completes.
        let OpenedLink { sink, pump } = host_links
            .open_initiator(wz_runtime_coop::session_drive::UdpPeer {
                addr: [10, 0, 0, 2],
                port: 7541,
            })
            .expect("host link");
        let host_actions =
            McuActions::<FrozenClock>::new_generic(sink, params(0xc1), CoopTime::new(&runtime));
        let _host = spawn_session(
            &local,
            pump,
            host_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Initiator,
                max_iters: None,
            },
            |_| {},
        );
        for _ in 0..64 {
            local.run_until_idle();
            node.tick(0);
            if !node.declared.is_empty() {
                break;
            }
        }
        std::assert!(host_actions.is_established(), "the host holds the session");
        std::assert_eq!(
            node.declared.len(),
            1,
            "the admin interests went out on the accepted session"
        );
        let first = Rc::downgrade(node.acceptor().expect("accepted"));

        // The session ends and the executor drops it before the node looks.
        node.acceptor.as_ref().expect("accepted").0.abort();
        local.run_until_idle();
        node.tick(1);

        let second = node
            .acceptor()
            .expect("listening again on the tick that found the session ended");
        std::assert!(
            first.upgrade().is_none(),
            "the ended session is gone, neither the node nor the executor holds it"
        );
        std::assert!(
            !core::ptr::eq(first.as_ptr(), Rc::as_ptr(second)),
            "a new session, not the ended one"
        );
        std::assert!(!second.is_established(), "and nobody has reached it yet");
        std::assert!(
            node.declared.is_empty(),
            "what was declared on the ended session is forgotten with it"
        );
    }
}
