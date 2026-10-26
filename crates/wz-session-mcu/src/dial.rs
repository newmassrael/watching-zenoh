// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2831 (§5.23 `adminspace-write`) — the MCU node's dialer: what makes a
//! `udp/<ipv4>:<port>` endpoint in the connection control a live session.
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
//! UDP and TCP over IPv4, by address, as far as the node's stack has the link:
//! an endpoint is read into a [`Locator`] here, and a stack with no link of its
//! protocol (an lwIP image asked for `tcp/`) refuses it as `Unsupported`. An
//! endpoint with another scheme, or one that carries upstream's `?metadata` /
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

use wz_runtime_coop::session_drive::{IpEndpoint, LinkOpenError, LinkProto, Locator};
use wz_runtime_coop::{CoopRuntime, CoopTime};
use wz_session_core::session_actions::SessionLinkActions;

use crate::connect_manager::{DialFailed, DialRefused};

// What reads an endpoint, and the type of a session's action bundle, is written once
// for every profile. The dialler that OPENS a link and spawns a session is the
// growable profile's (`Rc` handles, a boxed sink per dial, links opened through
// `SessionLinks`); the slot profile's is `wz_session_lwip::slot_node::SlotDialer`,
// over the session host, whose tables the image declared (fixed-memory step S9c).
#[cfg(not(feature = "session-slot"))]
pub use heap::*;

/// The action bundle of one MCU session.
pub type McuActions<C> = SessionLinkActions<CoopRuntime<C>, CoopTime<C>>;

/// Read `udp/<a.b.c.d>:<port>`, `tcp/<a.b.c.d>:<port>` or `tls/<a.b.c.d>:<port>`
/// into the locator it names.
pub fn parse_locator(endpoint: &str) -> Result<Locator, DialRefused> {
    let Some((proto, rest)) = [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls]
        .into_iter()
        .find_map(|proto| {
            let rest = endpoint.strip_prefix(proto.scheme())?.strip_prefix('/')?;
            Some((proto, rest))
        })
    else {
        return Err(DialRefused::Unsupported);
    };
    if rest.contains(['?', '#']) {
        return Err(DialRefused::Unsupported);
    }
    let (host, port) = rest.rsplit_once(':').ok_or(DialRefused::BadAddress)?;
    let port: u16 = digits(port).ok_or(DialRefused::BadAddress)?;
    if port == 0 {
        return Err(DialRefused::BadAddress);
    }
    let mut addr = [0u8; 4];
    let mut parts = host.split('.');
    for octet in &mut addr {
        *octet = parts
            .next()
            .and_then(digits)
            .ok_or(DialRefused::BadAddress)?;
    }
    if parts.next().is_some() {
        return Err(DialRefused::BadAddress);
    }
    Ok(Locator {
        proto,
        at: IpEndpoint { addr, port },
    })
}

/// What a stack's refusal to open a link means for the dial: a protocol it has
/// no link for is permanent for the endpoint, and an end that did not take the
/// link or a stack with nothing left to give is a failed attempt of the outage.
pub fn dial_failed(refused: LinkOpenError) -> DialFailed {
    match refused {
        LinkOpenError::Unsupported => DialFailed::Refused(DialRefused::Unsupported),
        LinkOpenError::Refused => DialFailed::Unreachable,
        LinkOpenError::Exhausted => DialFailed::Exhausted,
    }
}

/// Decimal digits only: `str::parse` would also take a leading `+`.
fn digits<T: core::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
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

    use super::{dial_failed, parse_locator, DialRefused, McuActions};
    use crate::connect_manager::{DialFailed, Dialer, Ended};
    use wz_session_core::locator_directory::DirectoryZid;

    /// What a dialled session reports its iterations to — typically
    /// `crate::app_layer::dispatch_to` over the node's observer.
    pub type EventSink = Box<dyn FnMut(IterationEvent<'_>)>;

    /// A session this dialer started.
    pub struct UdpSession<C: ClockSource + 'static> {
        handle: CoopLocalJoinHandle<DriverOutcome>,
        actions: Rc<McuActions<C>>,
        established: bool,
    }

    impl<C: ClockSource + 'static> UdpSession<C> {
        /// The session's action bundle, to publish or declare through.
        pub fn actions(&self) -> &Rc<McuActions<C>> {
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
        pub fn admin_session(&self) -> Option<wz_session_core::adminspace::AdminSession> {
            admin_session_of(&self.actions)
        }
    }

    /// R2837 — any MCU session as a `sessions[]` entry, dialled or accepted:
    /// `None` until it is established. What `UdpSession::admin_session` reports,
    /// for a session this dialer did not start (the node's acceptor).
    #[cfg(feature = "adminspace-core")]
    pub fn admin_session_of<C: ClockSource + 'static>(
        actions: &McuActions<C>,
    ) -> Option<wz_session_core::adminspace::AdminSession> {
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
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        local: &'a CoopLocalSet<C>,
        links: Rc<L>,
        timeouts: SessionTimeouts,
        max_iters: Option<usize>,
        params: P,
        on_event: E,
    }

    impl<'a, L, C, P, E> UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        /// A dialer spawning onto `local`, over `links`, with the handshake
        /// deadlines `timeouts`.
        pub fn new(
            local: &'a CoopLocalSet<C>,
            links: Rc<L>,
            timeouts: SessionTimeouts,
            params: P,
            on_event: E,
        ) -> Self {
            Self {
                local,
                links,
                timeouts,
                max_iters: None,
                params,
                on_event,
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
            let to = parse_locator(endpoint).map_err(DialFailed::Refused)?;
            // The stack picks the local port, one per session, and may have none
            // left to give: that is a failed attempt of this outage, not a refusal.
            let OpenedLink { sink, pump } = self.links.open_initiator(to).map_err(dial_failed)?;
            let runtime = self.local.runtime();
            let actions =
                McuActions::<C>::new_generic(sink, (self.params)(), CoopTime::new(runtime));
            if let Some(zid) = expected_zid {
                actions.expect_peer_zid(zid);
            }
            let on_event = (self.on_event)(&actions);
            let handle = spawn_session(
                self.local,
                pump,
                actions.clone(),
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
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        type Session = UdpSession<C>;

        fn classify(endpoint: &str) -> Result<(), DialRefused> {
            parse_locator(endpoint).map(|_| ())
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

// The endpoint parser is shared by both profiles' diallers, so its cases run on both.
#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn udp_tcp_or_tls_to_an_ipv4_address_is_dialable() {
        let at = IpEndpoint {
            addr: [127, 0, 0, 1],
            port: 7447,
        };
        std::assert_eq!(parse_locator("udp/127.0.0.1:7447"), Ok(Locator::udp(at)));
        std::assert_eq!(parse_locator("tcp/127.0.0.1:7447"), Ok(Locator::tcp(at)));
        // Whether a stack carries the secure channel is the stack's to say, not the parser's.
        std::assert_eq!(parse_locator("tls/127.0.0.1:7447"), Ok(Locator::tls(at)));
        for (text, why) in [
            ("quic/127.0.0.1:7447", DialRefused::Unsupported),
            ("tlsx/127.0.0.1:7447", DialRefused::Unsupported),
            ("tls/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("tcp/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("tcp/router.local:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1:7447#iface=eth0", DialRefused::Unsupported),
            ("udp/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("udp/router.local:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1", DialRefused::BadAddress),
            ("udp/127.0.0.1:0", DialRefused::BadAddress),
            ("udp/127.0.0.1:+80", DialRefused::BadAddress),
            ("udp/127.0.0.256:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1.5:7447", DialRefused::BadAddress),
            ("udp/[::1]:7447", DialRefused::BadAddress),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
    }

    #[test]
    fn a_stacks_refusal_is_permanent_only_for_a_protocol_it_lacks() {
        std::assert_eq!(
            dial_failed(LinkOpenError::Unsupported),
            DialFailed::Refused(DialRefused::Unsupported)
        );
        std::assert_eq!(dial_failed(LinkOpenError::Refused), DialFailed::Unreachable);
        std::assert_eq!(dial_failed(LinkOpenError::Exhausted), DialFailed::Exhausted);
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
        spawn_session, LinkOpenError, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
    };
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
            zid: vec![zid; 4],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
                .expect("key"),
        }
    }

    fn quiet(_: &Rc<McuActions<FrozenClock>>) -> EventSink {
        Box::new(|_| {})
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
        let runtime = CoopRuntime::new(FrozenClock);
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
            Counting(1),
        );
        let _acceptor = spawn_session(
            &local,
            acceptor_pump,
            acceptor_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            |_| {},
        );

        let mut dialer = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::spec_defaults(),
            || params(0xb1),
            quiet,
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
            SessionTimeouts::spec_defaults(),
            || params(0xc1),
            quiet,
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
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // Three acceptors, all node 0xa1, one per dial below.
        let mut acceptors = vec![];
        for port in [7494u16, 7495, 7496] {
            let OpenedLink { sink, pump } = far.open_acceptor(port).expect("bind acceptor");
            let actions = wz_runtime_coop::session_runtime::new_session_actions(
                sink,
                params(0xa1),
                CoopTime::new(&runtime),
                Counting(1),
            );
            let task = spawn_session(
                &local,
                pump,
                actions.clone(),
                CoopTime::new(&runtime),
                SessionDriveConfig {
                    timeouts: SessionTimeouts::spec_defaults(),
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
            SessionTimeouts::spec_defaults(),
            || params(0xb1),
            quiet,
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
            type Pump = Rc<crate::memory::MemoryEnd>;
            fn open_acceptor(&self, _: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
            fn open_initiator(&self, _: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
        }
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);
        let mut dialer = UdpDialer::new(
            &local,
            Rc::new(NoLinks),
            SessionTimeouts::spec_defaults(),
            || params(0xd1),
            quiet,
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
