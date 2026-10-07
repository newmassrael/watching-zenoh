// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipLinks` — lwIP's side of the session shell's `SessionLinks` seam.
//!
//! The shell (`wz-session-mcu`) opens two kinds of link and names no stack:
//! one that accepts on a port, one that dials an address. This is what each is on
//! lwIP: a session socket bound on the port for an acceptor, on a port lwIP
//! picks for an initiator, wrapped in the [`LwipUdpDriver`] that is the session's
//! outbound sink and paired with the [`LwipSessionLink`] the drive loop pumps.
//!
//! These are the four lines the admin node and its dialer used to carry for
//! themselves (`bind_session_rx`, `LwipUdpDriver::new`, the pair handed to
//! `spawn_session`), moved to the one place that knows the stack.

use alloc::rc::Rc;
use core::cell::RefCell;

use wz_link_lwip::rx_sockets::bind_session_rx;
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::session_drive::{LinkOpenError, OpenedLink, SessionLinks, UdpPeer};

use crate::driver::{LwipUdpDriver, SharedSessionSocket};
use crate::session_drive::LwipSessionLink;

/// The links of a node whose network stack is lwIP.
pub struct LwipLinks {
    link: Rc<LwipLink>,
}

impl LwipLinks {
    /// Links over `link`, the witness that lwIP is initialised.
    pub fn new(link: Rc<LwipLink>) -> Self {
        Self { link }
    }

    /// The stack handle, for a firmware that also pumps lwIP's timers.
    pub fn link(&self) -> &Rc<LwipLink> {
        &self.link
    }

    fn opened(
        &self,
        port: u16,
        peer: UdpPeer,
    ) -> Result<OpenedLink<<Self as SessionLinks>::Pump>, LinkOpenError> {
        // Port 0 asks lwIP for a free one, one per initiator session.
        let socket = bind_session_rx(&self.link, port).map_err(|_| LinkOpenError::Exhausted)?;
        let socket: SharedSessionSocket = Rc::new(RefCell::new(socket));
        let driver = Rc::new(LwipUdpDriver::new(
            socket,
            // An acceptor passes the unspecified address, which its first
            // inbound datagram overwrites; an initiator its configured peer.
            ipv4_addr_from_octets(peer.addr),
            peer.port,
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: LwipSessionLink::new(self.link.clone(), driver),
        })
    }
}

impl SessionLinks for LwipLinks {
    type Pump = LwipSessionLink<Rc<LwipLink>>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever speaks first; the driver learns it on receive.
        self.opened(
            port,
            UdpPeer {
                addr: [0; 4],
                port: 0,
            },
        )
    }

    fn open_initiator(&self, peer: UdpPeer) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        self.opened(0, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port that is taken is refused as exhaustion, which is what makes a dial
    /// retry and a listener try again, not a panic: the stack's own refusal is
    /// the stack's to report. It is free again once the end holding it is gone.
    #[test]
    fn a_port_already_bound_is_refused_as_exhaustion_and_free_again_once_released() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let links = LwipLinks::new(Rc::new(link));
        let held = links.open_acceptor(7551).expect("the first bind");
        std::assert!(
            matches!(links.open_acceptor(7551), Err(LinkOpenError::Exhausted)),
            "a second bind of the same port"
        );
        drop(held);
        std::assert!(
            links.open_acceptor(7551).is_ok(),
            "the port is free once its end is dropped"
        );
    }

    // A handshake needs the unicast open and accept emitters and the Init / Open
    // body codecs, which this crate compiles in only with the node's write
    // surface (`adminspace-write` forwards all four). Without them the initiator
    // opens its link and then says nothing, so this witness exists only where a
    // session can.
    #[cfg(feature = "adminspace-write")]
    mod handshake {
        use super::*;
        use alloc::vec;

        use wz_runtime_coop::session_drive::{spawn_session, SessionDriveConfig, SessionRole};
        use wz_runtime_coop::session_runtime::new_session_actions;
        use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
        use wz_session_core::link::BoxedLinkDriver;
        use wz_session_core::session_actions::SessionLinkActions;
        use wz_session_core::session_init_params::SessionInitParams;
        use wz_session_core::session_timeouts::SessionTimeouts;

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

        /// The links lwIP opens carry a real handshake: an acceptor bound on a port
        /// and an initiator towards it, on the loopback, both established, with the
        /// link's ends named from each side as upstream renders them. This is the
        /// witness that lwIP satisfies the seam the shell is written against; what
        /// the shell does with a link is witnessed once, on a network that is no
        /// stack's.
        #[test]
        fn lwip_links_carry_a_handshake_between_an_acceptor_and_an_initiator() {
            let (_serial, link) = wz_link_lwip::lwip_test_link();
            let links = LwipLinks::new(Rc::new(link));
            let runtime = CoopRuntime::new(FrozenClock);
            let local = CoopLocalSet::new(&runtime);

            let OpenedLink {
                sink: acceptor_sink,
                pump: acceptor_pump,
            } = links.open_acceptor(7541).expect("bind acceptor");
            let acceptor_link = acceptor_sink.clone();
            let acceptor_actions = new_session_actions(
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

            let OpenedLink {
                sink: initiator_sink,
                pump: initiator_pump,
            } = links
                .open_initiator(UdpPeer {
                    addr: [127, 0, 0, 1],
                    port: 7541,
                })
                .expect("open initiator");
            let initiator_link: Rc<dyn BoxedLinkDriver> = initiator_sink.clone();
            let initiator_actions = SessionLinkActions::<
                CoopRuntime<FrozenClock>,
                CoopTime<FrozenClock>,
            >::new_generic(
                initiator_sink, params(0xb1), CoopTime::new(&runtime)
            );
            let _initiator = spawn_session(
                &local,
                initiator_pump,
                initiator_actions.clone(),
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
                if initiator_actions.is_established() && acceptor_actions.is_established() {
                    break;
                }
            }
            std::assert!(
                initiator_actions.is_established(),
                "the handshake completed\ninitiator: {:?}\nacceptor: {:?}",
                initiator_actions.trace_snapshot(),
                acceptor_actions.trace_snapshot()
            );
            std::assert!(acceptor_actions.is_established(), "on both ends");

            // R2841 — the link's ends, as upstream renders them. The dialled side's
            // dst is the endpoint it was given; its src is the routed address and
            // the port lwIP chose, never zero.
            let dialled = initiator_link
                .link_endpoints()
                .expect("a dialled link has ends");
            std::assert_eq!(dialled.dst, "udp/127.0.0.1:7541");
            std::assert!(
                dialled.src.starts_with("udp/127.0.0.1:") && !dialled.src.ends_with(":0"),
                "src {:?}",
                dialled.src
            );
            // ... and the accepting side names the same link from its end.
            let accepted = acceptor_link
                .link_endpoints()
                .expect("learnt from the first datagram");
            std::assert_eq!(accepted.src, "udp/127.0.0.1:7541");
            std::assert_eq!(accepted.dst, dialled.src);
        }
    }
}
