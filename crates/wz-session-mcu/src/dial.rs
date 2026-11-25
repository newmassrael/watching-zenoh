// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2831 (§5.23 `adminspace-write`) — the MCU node's dialer: what makes a
//! `udp/<ip>:<port>` endpoint in the connection control a live session.
//!
//! [`crate::connect_manager::ConnectManager`] decides WHEN to dial; this
//! module is the [`crate::connect_manager::Dialer`] that does it. A dial asks
//! the network stack, through `wz_runtime_coop::session_drive::SessionLinks`, for a link towards the endpoint
//! and spawns an INITIATOR session onto the firmware's local task set with
//! `wz_runtime_coop::session_drive::spawn_session` — the same call a deploy
//! `main()` writes for its one configured peer, so a written endpoint and a
//! compiled-in one are the same kind of session.
//!
//! R2835-era this was written on lwIP and named for it. Nothing in it is lwIP's
//! but the four lines that open a socket, so the socket is now the stack's
//! (`wz_runtime_coop::session_drive::SessionLinks::open_initiator`) and the rest is written once: a board whose
//! network is Zephyr's sockets dials a written endpoint with the same code a
//! board on lwIP does.
//!
//! ## What this build can dial
//!
//! UDP and TCP over IPv4 or IPv6, by address, as far as the node's stack has the link:
//! an endpoint is read into a [`Locator`](wz_runtime_coop::session_drive::Locator) by
//! `wz_runtime_coop::locator_text`, and a stack with no link of its
//! protocol (an lwIP image asked for `tcp/`) refuses it as `Unsupported`. A stack
//! built without IPv6 says so (`Bind::IPV6`, `SessionLinks::IPV6`): its endpoints are
//! read by [`parse_locator_for`], which refuses a bracketed address as `Unsupported`,
//! as the stack's socket would refuse the family, and its image holds the IPv4 reader
//! alone.
//!
//! An endpoint with another scheme, or one that carries upstream's `?metadata` /
//! `#config` parts, is refused as `Unsupported` too: this link honours
//! neither, and dialling it anyway would quietly drop what the writer asked
//! for. A host name is refused as `BadAddress`, since the node has no resolver.
//! All three are permanent for the text, which is why the manager does not
//! retry them; a TCP connection the other end refused is retried.
//!
//! ## How an ended session is read
//!
//! A session has ended when its task has finished. Whether it had been
//! established is remembered from the session's own
//! `SessionLinkActions::is_established`, sampled each time the manager asks,
//! and that is the one approximation here: a session that establishes and
//! drops between two ticks of the manager reads as never established, so its
//! re-dial continues the old outage's period instead of starting a fresh one.
//! It errs towards waiting longer, never towards dialling harder.

use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::{CoopRuntime, CoopTime};
use wz_session_core::session_actions::SessionLinkActions;

use crate::connect_manager::{DialFailed, DialRefused};

// The type of a session's action bundle is written once for every profile, and what
// reads an endpoint is the runtime's (`wz_runtime_coop::locator_text`). The dialler that OPENS a link and spawns a session is the
// growable profile's (`Rc` handles, a boxed sink per dial, links opened through
// `SessionLinks`); the slot profile's is `wz_session_lwip::slot_node::SlotDialer`,
// over the session host, whose tables the image declared (fixed-memory step S9c).
#[cfg(not(feature = "session-slot"))]
pub use heap::*;

/// The action bundle of one MCU session.
pub type McuActions<C> = SessionLinkActions<CoopRuntime<C>, CoopTime<C>>;

pub use wz_runtime_coop::locator_text::{parse_listen_locator, parse_locator, parse_locator_for};

/// What a stack's refusal to open a link means for the dial: a protocol it has
/// no link for is permanent for the endpoint, and an end that did not take the
/// link, a stack with nothing left to give or an address another socket holds is
/// a failed attempt of the outage.
pub fn dial_failed(refused: LinkOpenError) -> DialFailed {
    match refused {
        LinkOpenError::Unsupported => DialFailed::Refused(DialRefused::Unsupported),
        LinkOpenError::Refused => DialFailed::Unreachable,
        LinkOpenError::Exhausted | LinkOpenError::AddressInUse => DialFailed::Exhausted,
    }
}

#[cfg(not(feature = "session-slot"))]
mod heap {
    use alloc::boxed::Box;
    use alloc::rc::Rc;

    use wz_runtime_coop::session_drive::{
        spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
    };
    use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopTime};
    use wz_session_core::close_reason::CloseReason;
    use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::session_timeouts::SessionTimeouts;
    use wz_session_core::sn::sn_resolution_admitted;

    use super::{dial_failed, parse_locator_for, DialRefused, McuActions};
    use crate::connect_manager::{DialFailed, Dialer, Ended};
    use wz_runtime_coop::session_runtime::{SessionEntropy, SessionHandle};
    use wz_session_core::locator_directory::DirectoryZid;

    /// What a dialled session reports its iterations to — typically
    /// `crate::app_layer::dispatch_to` over the node's observer.
    pub type EventSink = Box<dyn FnMut(IterationEvent<'_, '_>)>;

    /// A session this dialer started.
    pub struct UdpSession<C: ClockSource + 'static> {
        handle: CoopLocalJoinHandle<DriverOutcome>,
        actions: SessionHandle<C>,
        established: bool,
    }

    impl<C: ClockSource + 'static> UdpSession<C> {
        /// The session's action bundle, to publish or declare through.
        pub fn actions(&self) -> &SessionHandle<C> {
            &self.actions
        }

        /// End the session's task now, without a Close on the wire. A test that
        /// must see a session end uses it; the manager hangs up through the
        /// [`Dialer`], which tells an established peer first.
        pub fn abort(&self) {
            self.handle.abort();
        }

        /// R2834 (§5.23 `adminspace-core`) — this session as a `sessions[]` entry
        /// of the node's admin GET, or `None` while it is not established.
        ///
        /// Upstream lists transports, and a transport exists only once its
        /// handshake has finished, so a session still dialling is not reported.
        /// The role is read off the wire through `WhatAmI::from_wire`; a role that
        /// never arrived stays `None`, which the answerer renders as upstream's
        /// `"unknown"`. SHM and the router link weight are `false` / `None`: this
        /// build has neither, which is what those values say.
        ///
        /// A firmware reports its dialled sessions each time round its loop with
        /// `NodeStatus::set_sessions`, collecting this over
        /// `ConnectManager::sessions`.
        #[cfg(feature = "adminspace-core")]
        pub fn admin_session(&self) -> Option<wz_admin::adminspace::AdminSession> {
            admin_session_of(&self.actions)
        }
    }

    /// R2837 — any MCU session as a `sessions[]` entry, dialled or accepted:
    /// `None` until it is established. What `UdpSession::admin_session` reports,
    /// for a session this dialer did not start (the node's acceptor).
    #[cfg(feature = "adminspace-core")]
    pub fn admin_session_of<C: ClockSource + 'static>(
        actions: &McuActions<C>,
    ) -> Option<wz_admin::adminspace::AdminSession> {
        use wz_admin::adminspace::SessionAdminRow;

        if !actions.is_established() {
            return None;
        }
        // R2860 — the row constructor the host runtimes share, so `links`, `shm`
        // and `region` are computed here exactly as they are there. An MCU session
        // holds no router graph, so it reports no weight.
        Some(
            actions.admin_session(
                actions
                    .peer_zid()
                    .map(|zid| wz_session_core::zid_hex::zid_to_zenoh_hex(&zid))
                    .unwrap_or_default(),
                actions
                    .peer_whatami_wire()
                    .and_then(wz_session_core::WhatAmI::from_wire)
                    .map(|role| alloc::string::String::from(role.to_str())),
                None,
            ),
        )
    }

    /// Dials UDP endpoints as initiator sessions on the firmware's task set, over
    /// whichever network stack `L` is.
    ///
    /// `params` is asked for a fresh [`SessionInitParams`] per dial, so each
    /// session can carry its own initial sequence number and cookie; `on_event`
    /// is asked for the sink each new session reports to.
    pub struct UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&SessionHandle<C>) -> EventSink,
    {
        local: &'a CoopLocalSet<C>,
        links: Rc<L>,
        timeouts: SessionTimeouts,
        max_iters: Option<usize>,
        params: P,
        on_event: E,
        /// The node's one entropy source, which each session dialled draws its handshake's
        /// secrets from through its binding.
        entropy: SessionEntropy,
    }

    impl<'a, L, C, P, E> UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&SessionHandle<C>) -> EventSink,
    {
        /// A dialer spawning onto `local`, over `links`, with the handshake
        /// deadlines `timeouts`, its sessions drawing from the node's `entropy`.
        pub fn new(
            local: &'a CoopLocalSet<C>,
            links: Rc<L>,
            timeouts: SessionTimeouts,
            params: P,
            on_event: E,
            entropy: SessionEntropy,
        ) -> Self {
            Self {
                local,
                links,
                timeouts,
                max_iters: None,
                params,
                on_event,
                entropy,
            }
        }

        /// Cap every session's iterations, for a test that must terminate.
        pub fn with_max_iters(mut self, max_iters: usize) -> Self {
            self.max_iters = Some(max_iters);
            self
        }

        /// One dial, made for the node `expected_zid` or for no node. The expectation is set
        /// before the session is spawned, so the handshake reads it at the InitAck.
        fn dial_expecting(
            &mut self,
            endpoint: &str,
            expected_zid: Option<DirectoryZid>,
        ) -> Result<UdpSession<C>, DialFailed> {
            let to = parse_locator_for(endpoint, L::IPV6).map_err(DialFailed::Refused)?;
            // A width the build's domain leaves out is the node's to change, not the endpoint's:
            // refused before a link is opened, and not retried.
            let params = (self.params)();
            sn_resolution_admitted(params.seq_num_res)
                .map_err(|_| DialFailed::Refused(DialRefused::SnResolution))?;
            // The stack picks the local port, one per session, and may have none
            // left to give: that is a failed attempt of this outage, not a refusal.
            let OpenedLink { sink, pump } = self.links.open_initiator(to).map_err(dial_failed)?;
            let runtime = self.local.runtime();
            // A bundle the heap has no room for is a session the node cannot afford now, as a
            // socket it has none of is: a failed attempt of this outage.
            let actions = McuActions::<C>::new_generic(sink, params, CoopTime::new(runtime))
                .map_err(|_| DialFailed::Exhausted)?;
            if let Some(zid) = expected_zid {
                actions.expect_peer_zid(zid);
            }
            let on_event = (self.on_event)(&actions);
            let handle = spawn_session(
                self.local,
                pump,
                actions.clone(),
                self.entropy.clone(),
                CoopTime::new(runtime),
                SessionDriveConfig {
                    timeouts: self.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: self.max_iters,
                },
                on_event,
            );
            Ok(UdpSession {
                handle,
                actions,
                established: false,
            })
        }
    }

    impl<'a, L, C, P, E> Dialer for UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&SessionHandle<C>) -> EventSink,
    {
        type Session = UdpSession<C>;

        fn classify(endpoint: &str) -> Result<(), DialRefused> {
            parse_locator_for(endpoint, L::IPV6).map(|_| ())
        }

        /// The session's handshake holds a dial made for a node to that node: the InitAck must
        /// carry its zid, or the session closes before the OpenSyn (decision D4), so a node may
        /// be opened by its zid over this dialer.
        const VERIFIES_NODES: bool = true;

        fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
            // A configured endpoint names no node, as upstream's `connect/endpoints` does not.
            self.dial_expecting(endpoint, None)
        }

        fn dial_for(
            &mut self,
            endpoint: &str,
            node: &DirectoryZid,
        ) -> Result<Self::Session, DialFailed> {
            self.dial_expecting(endpoint, Some(*node))
        }

        fn established(&mut self, session: &mut Self::Session) -> bool {
            session.established |= session.actions.is_established();
            session.established
        }

        fn remote(
            &self,
            session: &Self::Session,
        ) -> Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]> {
            session.actions.peer_zid_array()
        }

        fn ended(&mut self, session: &mut Self::Session) -> Option<Ended> {
            session.established |= session.actions.is_established();
            if !session.handle.is_finished() {
                return None;
            }
            Some(if session.established {
                Ended::AfterEstablished
            } else {
                Ended::BeforeEstablished
            })
        }

        fn hang_up(&mut self, session: Self::Session) {
            // An established peer is told; a half-open one has nothing to close.
            if session.actions.is_established() {
                session.actions.send_close_with_reason(CloseReason::Generic);
            }
            session.handle.abort();
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn a_stacks_refusal_is_permanent_only_for_a_protocol_it_lacks() {
        std::assert_eq!(
            dial_failed(LinkOpenError::Unsupported),
            DialFailed::Refused(DialRefused::Unsupported)
        );
        std::assert_eq!(dial_failed(LinkOpenError::Refused), DialFailed::Unreachable);
        std::assert_eq!(dial_failed(LinkOpenError::Exhausted), DialFailed::Exhausted);
        std::assert_eq!(
            dial_failed(LinkOpenError::AddressInUse),
            DialFailed::Exhausted
        );
    }
}

// What these tests build is the heap dialler over the in-memory network, which the
// slot profile does not have.
#[cfg(all(test, not(feature = "session-slot")))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;

    use wz_runtime_coop::session_drive::{
        spawn_session, LinkOpenError, Locator, OpenedLink, SessionDriveConfig, SessionLinks,
        SessionRole,
    };
    use wz_runtime_coop::session_runtime::{SessionEntropy, SessionHandle};
    use wz_runtime_coop::{ClockSource, CoopLocalSet};
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::session_timeouts::SessionTimeouts;

    use crate::connect_manager::{DialFailed, Dialer, Ended};
    use crate::memory::{MemoryLinks, MemoryNetwork};

    const NODE: [u8; 4] = [10, 0, 0, 2];
    const FAR: [u8; 4] = [10, 0, 0, 1];

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
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

    fn params(zid: u8) -> SessionInitParams {
        SessionInitParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [zid; 4].into(),
            seq_num_res: wz_session_core::policy::SnResolution::Bits32,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: vec![],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            policy: wz_session_core::policy::SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
            cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
                .expect("key")
                .into(),
            region: None,
        }
    }

    fn quiet(_: &SessionHandle<FrozenClock>) -> EventSink {
        Box::new(|_| {})
    }

    /// A width of sequence numbers the build's `sn-resolution` domain leaves out is refused by
    /// the dialer before it opens a link, as a refusal the manager does not retry; a width the
    /// domain holds is dialled.
    #[test]
    fn a_width_outside_the_sn_resolution_domain_is_refused_before_the_dial() {
        use wz_session_core::policy::SnResolution;
        use wz_session_core::policy_binding::PolicyValue;

        let net = MemoryNetwork::new();
        let near = Rc::new(MemoryLinks::new(net, NODE));
        let runtime = CoopRuntime::try_new(FrozenClock).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        for width in SnResolution::WIDTHS {
            let mut dialer = UdpDialer::new(
                &local,
                near.clone(),
                SessionTimeouts::from_build(),
                move || {
                    let mut stated = params(0xc2);
                    stated.seq_num_res = width;
                    stated
                },
                quiet,
                SessionEntropy::new(Counting(3)),
            )
            .with_max_iters(1);
            let dialled = dialer.dial("udp/10.0.0.1:7496");
            if <SnResolution as PolicyValue>::DOMAIN.contains(width) {
                std::assert!(dialled.is_ok(), "{}", width.id());
            } else {
                std::assert!(
                    matches!(dialled, Err(DialFailed::Refused(DialRefused::SnResolution))),
                    "{}",
                    width.id()
                );
            }
        }
    }

    /// A dial opens a real session towards the endpoint: an acceptor on the
    /// same network completes the handshake with it, and once the session's
    /// task ends it reads as ended AFTER establishing. The control is a dial
    /// nobody answers, which ends BEFORE establishing.
    #[test]
    fn a_dialled_endpoint_becomes_an_established_session() {
        let net = MemoryNetwork::new();
        // The acceptor's host and the dialling node's are two hosts on one net.
        let far = Rc::new(MemoryLinks::new(net.clone(), FAR));
        let near = Rc::new(MemoryLinks::new(net.clone(), NODE));
        let runtime = CoopRuntime::try_new(FrozenClock).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);

        // The acceptor the dial will reach.
        let OpenedLink {
            sink: acceptor_sink,
            pump: acceptor_pump,
        } = far.open_acceptor(7494).expect("bind acceptor");
        // An acceptor mints its cookie from a per-handshake nonce and refuses
        // to mint without an entropy source, so it is built through the seam
        // a board uses.
        let acceptor_actions = wz_runtime_coop::session_runtime::new_session_actions(
            acceptor_sink,
            params(0xa1),
            CoopTime::new(&runtime),
        )
        .expect("the heap has room");
        let _acceptor = spawn_session(
            &local,
            acceptor_pump,
            acceptor_actions.clone(),
            SessionEntropy::new(Counting(1)),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::from_build(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            |_| {},
        );

        let mut dialer = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xb1),
            quiet,
            SessionEntropy::new(Counting(2)),
        );
        let mut session = dialer.dial("udp/10.0.0.1:7494").expect("dialable");
        for _ in 0..64 {
            local.run_until_idle();
            if session.actions().is_established() {
                break;
            }
        }
        std::assert!(
            session.actions().is_established(),
            "the handshake completed\ninitiator: {:?}\nacceptor: {:?}",
            session.actions().trace_snapshot(),
            acceptor_actions.trace_snapshot()
        );
        std::assert!(acceptor_actions.is_established(), "on both ends");
        std::assert_eq!(dialer.ended(&mut session), None, "still live");

        // R2834 — the established session reports the acceptor it reached,
        // as the admin GET's `sessions[]` entry.
        #[cfg(feature = "adminspace-core")]
        {
            let entry = session.admin_session().expect("established, so reported");
            std::assert_eq!(
                entry.peer_zid_hex,
                wz_session_core::zid_hex::zid_to_zenoh_hex(&[0xa1; 4])
            );
            std::assert_eq!(entry.whatami.as_deref(), Some("peer"));
            std::assert_eq!(entry.links.len(), 1, "one UDP link");
            // R2841 — the link's ends, as upstream renders them: the dialled
            // side's dst is the endpoint it was given; its src is the address
            // the node is on and the port the stack chose.
            std::assert_eq!(entry.links[0].dst, "udp/10.0.0.1:7494");
            std::assert!(
                entry.links[0].src.starts_with("udp/10.0.0.2:")
                    && !entry.links[0].src.ends_with(":0"),
                "src {:?}",
                entry.links[0].src
            );
            // ... and the accepting side names the same link from its end.
            let accepted = admin_session_of(&acceptor_actions).expect("established");
            std::assert_eq!(accepted.links[0].src, "udp/10.0.0.1:7494");
            std::assert_eq!(accepted.links[0].dst, entry.links[0].src);
        }

        session.abort();
        std::assert_eq!(dialer.ended(&mut session), Some(Ended::AfterEstablished));

        // CONTROL: nobody listens on 7495, and the capped session ends first.
        let mut unanswered = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xc1),
            quiet,
            SessionEntropy::new(Counting(2)),
        )
        .with_max_iters(8);
        let mut lost = unanswered.dial("udp/10.0.0.1:7495").expect("dialable");
        // R2834 — CONTROL: a session nobody answered is not reported.
        #[cfg(feature = "adminspace-core")]
        std::assert!(lost.admin_session().is_none());
        for _ in 0..16 {
            local.run_until_idle();
        }
        std::assert_eq!(unanswered.ended(&mut lost), Some(Ended::BeforeEstablished));

        std::assert!(matches!(
            unanswered.dial("tcp/127.0.0.1:7447"),
            Err(DialFailed::Refused(DialRefused::Unsupported))
        ));
    }

    /// Decision D4 on the heap dialer: a dial made FOR a node holds the session to that node.
    /// The acceptor on the net is node `0xa1`; a dial for it establishes, a dial for another
    /// zid closes at the InitAck and ends before establishing, and a dial that names no node
    /// (a configured endpoint) admits whichever node answers, as it did before.
    #[test]
    fn a_dial_for_a_node_holds_the_session_to_that_node() {
        use wz_session_core::close_reason::CloseReason;
        use wz_session_core::credential_identity::zid_from_wire;

        fn verifies_nodes<D: Dialer>(_: &D) -> bool {
            D::VERIFIES_NODES
        }

        let net = MemoryNetwork::new();
        let far = Rc::new(MemoryLinks::new(net.clone(), FAR));
        let near = Rc::new(MemoryLinks::new(net.clone(), NODE));
        let runtime = CoopRuntime::try_new(FrozenClock).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);

        // Three acceptors, all node 0xa1, one per dial below.
        let mut acceptors = vec![];
        for port in [7494u16, 7495, 7496] {
            let OpenedLink { sink, pump } = far.open_acceptor(port).expect("bind acceptor");
            let actions = wz_runtime_coop::session_runtime::new_session_actions(
                sink,
                params(0xa1),
                CoopTime::new(&runtime),
            )
            .expect("the heap has room");
            let task = spawn_session(
                &local,
                pump,
                actions.clone(),
                SessionEntropy::new(Counting(1)),
                CoopTime::new(&runtime),
                SessionDriveConfig {
                    timeouts: SessionTimeouts::from_build(),
                    role: SessionRole::Acceptor,
                    max_iters: None,
                },
                |_| {},
            );
            acceptors.push((actions, task));
        }

        let mut dialer = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xb1),
            quiet,
            SessionEntropy::new(Counting(2)),
        );
        std::assert!(
            verifies_nodes(&dialer),
            "the heap dialer holds a dial to its node, so a node may be opened over it"
        );
        let node_a1 = zid_from_wire(&[0xa1; 4]).expect("a zid");
        let node_other = zid_from_wire(&[0xa2; 4]).expect("a zid");

        let mut right = dialer
            .dial_for("udp/10.0.0.1:7494", &node_a1)
            .expect("dialable");
        let wrong = dialer
            .dial_for("udp/10.0.0.1:7495", &node_other)
            .expect("dialable");
        let unnamed = dialer.dial("udp/10.0.0.1:7496").expect("dialable");
        for _ in 0..64 {
            local.run_until_idle();
        }

        std::assert!(right.actions().is_established(), "the node it was made for");
        std::assert_eq!(dialer.ended(&mut right), None, "and stays up");
        std::assert!(
            !wrong.actions().is_established(),
            "a session to another node than the one asked for is not a session to the zid"
        );
        // Closed at the InitAck, before any OpenSyn, with upstream's reason for it. The task is
        // not asked whether it has ended: it sleeps to its next deadline, which a clock that
        // never moves does not bring, so it ends on a clock that does.
        std::assert_eq!(
            wrong.actions().close_reason(),
            Some(CloseReason::Invalid),
            "{:?}",
            wrong.actions().trace_snapshot()
        );
        std::assert_eq!(
            wrong.actions().trace_snapshot().send_open_syn,
            0,
            "no OpenSyn goes to a node that was not asked for"
        );
        std::assert!(
            right.actions().close_reason().is_none() && unnamed.actions().close_reason().is_none(),
            "the others were not closed"
        );
        std::assert!(
            unnamed.actions().is_established(),
            "a configured endpoint names no node and admits the one that answers"
        );
        right.abort();
        unnamed.abort();
    }

    /// A stack with no link left to give is a failed attempt of the outage, not
    /// a refusal: the manager waits and tries again.
    #[test]
    fn a_stack_with_no_link_left_makes_the_dial_exhausted_and_not_refused() {
        struct NoLinks;
        impl SessionLinks for NoLinks {
            type Pump = wz_runtime_coop::link_cells::CellRc<crate::memory::MemoryEnd>;
            type Dial = wz_runtime_coop::session_drive::Dialled<Self::Pump>;
            type Waits = wz_runtime_coop::session_drive::NoWaits;
            fn waits(&self) -> Self::Waits {
                wz_runtime_coop::session_drive::NoWaits
            }
            fn open_acceptor(&self, _: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
            fn open_initiator(&self, _: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
        }
        let runtime = CoopRuntime::try_new(FrozenClock).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let mut dialer = UdpDialer::new(
            &local,
            Rc::new(NoLinks),
            SessionTimeouts::from_build(),
            || params(0xd1),
            quiet,
            SessionEntropy::new(Counting(2)),
        );
        std::assert!(matches!(
            dialer.dial("udp/10.0.0.1:7494"),
            Err(DialFailed::Exhausted)
        ));
        // And what is refused is refused before the stack is asked.
        std::assert!(matches!(
            dialer.dial("quic/10.0.0.1:7494"),
            Err(DialFailed::Refused(DialRefused::Unsupported))
        ));
    }
}
