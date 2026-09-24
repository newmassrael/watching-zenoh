// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2837 (§5.23) — an MCU node whose connections a host controls at runtime,
//! as ONE thing a firmware ticks.
//!
//! The pieces are the earlier rounds': the config-write subscriber
//! (`crate::admin_host`), the admin GET queryable (`crate::admin_status`),
//! the connection manager and its lwIP dialer (`crate::connect_manager`,
//! `crate::lwip_dialer`). [`crate::admin_node::AdminNode`] wires them to one
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
//! A firmware's loop is then: run the task set, poll its Ethernet interface,
//! pump the link's timers, and `tick` the node with the time.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use wz_session_core::admin_config_space::write_config_space_pattern;
use wz_session_core::adminspace::admin_queryable_key;

use wz_link_lwip::rx_sockets::bind_session_rx;
use wz_link_lwip::LwipLink;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopTime};
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::admin_host::{host_connect_writes, ConnectControl};
use crate::admin_status::{host_admin_queryable, NodeIdentity, NodeStatus};
use crate::app_layer::dispatch_to;
use crate::connect_manager::ConnectManager;
use crate::driver::{LwipUdpDriver, SharedSessionSocket};
use crate::lwip_dialer::{admin_session_of, EventSink, LwipUdpDialer, McuActions};
use crate::session_drive::{spawn_session, SessionDriveConfig, SessionRole};

/// Builds the sink each dialled session reports to.
type DialSink<C> = Box<dyn FnMut(&Rc<McuActions<C>>) -> EventSink>;

/// An MCU node a host can reach, and reconfigure, at runtime.
pub struct AdminNode<'a, C, P, A>
where
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    A: FnMut(Rc<dyn BoxedLinkDriver>) -> Rc<McuActions<C>>,
{
    local: &'a CoopLocalSet<C>,
    link: Rc<LwipLink>,
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    status: &'static NodeStatus,
    manager: ConnectManager<LwipUdpDialer<'a, C, P, DialSink<C>>>,
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

impl<'a, C, P, A> AdminNode<'a, C, P, A>
where
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    A: FnMut(Rc<dyn BoxedLinkDriver>) -> Rc<McuActions<C>>,
{
    /// A node that listens on `listen_port`, answers as `identity`, applies
    /// writes to `control` and reports through `status`.
    ///
    /// `dial_params` gives each dialled session its parameters. `accept`
    /// builds the action bundle of each acceptor session over the driver it
    /// is given; an acceptor mints cookies, so this is where a board installs
    /// its entropy source (`wz_runtime_coop::session_runtime::new_session_actions`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local: &'a CoopLocalSet<C>,
        link: Rc<LwipLink>,
        control: &'static ConnectControl,
        status: &'static NodeStatus,
        identity: NodeIdentity,
        listen_port: u16,
        timeouts: SessionTimeouts,
        dial_params: P,
        accept: A,
    ) -> Self {
        let admin_key = admin_queryable_key(&identity.zid_hex, identity.whatami);
        let mut config_key = String::new();
        // Writing into a `String` cannot fail.
        let _ = write_config_space_pattern(&mut config_key, &identity.zid_hex, identity.whatami);
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        {
            let mut o = observer.borrow_mut();
            host_connect_writes(&mut o, &identity.zid_hex, identity.whatami, control);
            host_admin_queryable(&mut o, identity, status, Some(control));
        }
        let dial_observer = observer.clone();
        let on_event: DialSink<C> = Box::new(move |actions| {
            Box::new(dispatch_to(dial_observer.clone(), actions.clone())) as EventSink
        });
        let dialer = LwipUdpDialer::new(local, link.clone(), timeouts, dial_params, on_event);
        Self {
            local,
            link,
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
        }
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
        let socket = bind_session_rx(&self.link, self.listen_port).ok()?;
        let socket: SharedSessionSocket = Rc::new(RefCell::new(socket));
        // The peer is whoever speaks first; the driver learns it on receive.
        let driver = Rc::new(LwipUdpDriver::new(socket, 0, 0));
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions = (self.accept)(sink);
        let on_event = dispatch_to(self.observer.clone(), actions.clone());
        let handle = spawn_session(
            self.local,
            self.link.clone(),
            driver,
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
            msg.payload_len = payload.len() as u64;
            msg.payload = payload;
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

    /// The node composed end to end over lwIP loopback: a `connect/endpoints`
    /// write arriving on the node's observer makes it dial the endpoint, the
    /// peer there completes the handshake, and the node then reports that
    /// session — the zid of the peer it reached — as its GET's `sessions`.
    /// The CONTROL is the same node before the write: it listens, reports no
    /// session, and dials nothing.
    #[test]
    fn a_written_endpoint_is_dialled_and_reported_by_the_node() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STATUS: NodeStatus = NodeStatus::new(true);

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // The peer the write will name: a plain acceptor on 7522.
        let far_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, 7522).expect("bind far peer"),
        ));
        let far_driver = Rc::new(LwipUdpDriver::new(far_socket, 0, 0));
        let far_sink: Rc<dyn BoxedLinkDriver> = far_driver.clone();
        let far_actions =
            new_session_actions(far_sink, params(0xc3), CoopTime::new(&runtime), Counting(9));
        // R2838 — what the peer is told: every Declare the node sends it.
        let declares = Rc::new(core::cell::Cell::new(0usize));
        let seen = declares.clone();
        let _far = spawn_session(
            &local,
            link.clone(),
            far_driver,
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
            link.clone(),
            &CONTROL,
            &STATUS,
            NodeIdentity {
                zid_hex: String::from("b1b1b1b1"),
                whatami: "peer",
                version: String::from("wz-test"),
                locators: vec![String::from("udp/127.0.0.1:7521")],
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
        );

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
                br#"["udp/127.0.0.1:7522"]"#,
            )));
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

        // R2838 — the peer was told what upstream's admin space tells a
        // router: the admin queryable and the config subscriber, once each.
        for _ in 0..16 {
            local.run_until_idle();
            node.tick(0);
        }
        std::assert_eq!(declares.get(), 2, "one queryable and one subscriber");
    }
}
