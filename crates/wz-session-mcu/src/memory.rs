// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An in-memory UDP network, for testing the session shell without a stack.
//!
//! The shell is written once for every network stack, so it has to be tested
//! against something that is none of them. Before this module its tests ran on
//! lwIP, which made "the admin node works" and "the admin node works on lwIP" the
//! same claim and left no way to tell them apart. This network has no socket, no
//! thread and no clock: an end is a queue keyed by address and port, a send
//! pushes onto the queue of the end it names, and a receive pops from its own.
//!
//! It keeps the behaviour of a real UDP link that the shell depends on and
//! nothing else: an acceptor has no peer until the first datagram names one and
//! replies go to whoever spoke last; a datagram for an end nobody bound is
//! dropped without an error; a port is bound by one end at a time and is free
//! again when that end is dropped (the admin node binds its listen port anew when
//! an accepted session ends).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, OnceCell, RefCell};

use wz_runtime_coop::session_drive::{
    LinkOpenError, OpenedLink, SessionDatagramLink, SessionLinks, UdpPeer,
};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, RxFrame,
};
use wz_session_core::reliability::Reliability;

/// One datagram waiting at an end: who sent it and what it carries.
struct Waiting {
    from: UdpPeer,
    bytes: Vec<u8>,
}

/// The first port an initiator is given, the start of the ephemeral range.
const FIRST_EPHEMERAL_PORT: u16 = 49152;

/// The datagrams waiting at each bound end, by the address and port it is bound on.
type Queues = BTreeMap<([u8; 4], u16), VecDeque<Waiting>>;

/// A network of in-memory ends. Shared by `Rc`: every end holds the network it
/// was bound on.
pub struct MemoryNetwork {
    queues: RefCell<Queues>,
    next_ephemeral: Cell<u16>,
}

impl MemoryNetwork {
    /// A network with nothing bound.
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            queues: RefCell::new(BTreeMap::new()),
            next_ephemeral: Cell::new(FIRST_EPHEMERAL_PORT),
        })
    }

    /// Bind an end at `local`, sending to `peer` (`None` for an acceptor, which
    /// learns its peer from the first datagram). Refused when something is
    /// already bound there.
    pub fn bind(
        self: &Rc<Self>,
        local: UdpPeer,
        peer: Option<UdpPeer>,
    ) -> Result<Rc<MemoryEnd>, LinkOpenError> {
        let mut queues = self.queues.borrow_mut();
        let key = (local.addr, local.port);
        if queues.contains_key(&key) {
            return Err(LinkOpenError::Exhausted);
        }
        queues.insert(key, VecDeque::new());
        let end = MemoryEnd {
            net: self.clone(),
            local,
            peer: Cell::new(peer),
            endpoints: OnceCell::new(),
        };
        if let Some(peer) = peer {
            end.note_endpoints(peer);
        }
        Ok(Rc::new(end))
    }

    /// An unused port on `addr`, from the ephemeral range.
    fn free_port(&self, addr: [u8; 4]) -> Option<u16> {
        let queues = self.queues.borrow();
        for _ in 0..=u16::MAX - FIRST_EPHEMERAL_PORT {
            let port = self.next_ephemeral.get();
            self.next_ephemeral.set(if port == u16::MAX {
                FIRST_EPHEMERAL_PORT
            } else {
                port + 1
            });
            if !queues.contains_key(&(addr, port)) {
                return Some(port);
            }
        }
        None
    }

    /// How many datagrams are waiting at `addr:port`, for a test that asserts a
    /// send reached an end nobody has read yet.
    pub fn waiting_at(&self, addr: [u8; 4], port: u16) -> usize {
        self.queues
            .borrow()
            .get(&(addr, port))
            .map_or(0, VecDeque::len)
    }
}

/// `udp/a.b.c.d:port`, zenoh's rendering of a UDP locator.
fn udp_locator(at: UdpPeer) -> String {
    let [a, b, c, d] = at.addr;
    format!("udp/{a}.{b}.{c}.{d}:{}", at.port)
}

/// One end of a link on a [`MemoryNetwork`]: the session's outbound sink and the
/// drive loop's inbound pump in one object, as Zephyr's socket driver is.
pub struct MemoryEnd {
    net: Rc<MemoryNetwork>,
    local: UdpPeer,
    peer: Cell<Option<UdpPeer>>,
    endpoints: OnceCell<LinkEndpoints>,
}

impl MemoryEnd {
    /// Record the link's two ends the first time a peer is known, and never
    /// rename it after: the link is what the first datagram made it.
    fn note_endpoints(&self, peer: UdpPeer) {
        let _ = self.endpoints.set(LinkEndpoints::new(
            udp_locator(self.local),
            udp_locator(peer),
        ));
    }

    /// Where this end sends now, once it has a peer.
    pub fn peer(&self) -> Option<UdpPeer> {
        self.peer.get()
    }

    /// This end's own address and port.
    pub fn local(&self) -> UdpPeer {
        self.local
    }
}

impl Drop for MemoryEnd {
    fn drop(&mut self) {
        self.net
            .queues
            .borrow_mut()
            .remove(&(self.local.addr, self.local.port));
    }
}

impl BoxedLinkDriver for MemoryEnd {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        let Some(peer) = self.peer.get() else {
            // No peer yet: an acceptor has nothing to answer.
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        // A datagram for an end nobody bound is dropped silently, as UDP does.
        if let Some(queue) = self
            .net
            .queues
            .borrow_mut()
            .get_mut(&(peer.addr, peer.port))
        {
            queue.push_back(Waiting {
                from: self.local,
                bytes: bytes.to_vec(),
            });
        }
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.get()
    }
}

impl SessionDatagramLink for MemoryEnd {
    fn service(&self) {}

    fn try_recv(&self) -> Option<RxFrame> {
        let waiting = self
            .net
            .queues
            .borrow_mut()
            .get_mut(&(self.local.addr, self.local.port))?
            .pop_front()?;
        // Reply to whoever just spoke, which is how an acceptor learns its peer.
        self.peer.set(Some(waiting.from));
        self.note_endpoints(waiting.from);
        Some(RxFrame::new(waiting.bytes))
    }
}

/// A host on a [`MemoryNetwork`]: the [`SessionLinks`] a node under test opens
/// its links through, bound at one address.
pub struct MemoryLinks {
    net: Rc<MemoryNetwork>,
    host: [u8; 4],
}

impl MemoryLinks {
    /// The links of the host at `host` on `net`.
    pub fn new(net: Rc<MemoryNetwork>, host: [u8; 4]) -> Self {
        Self { net, host }
    }

    /// The network this host is on.
    pub fn network(&self) -> &Rc<MemoryNetwork> {
        &self.net
    }

    fn opened(end: Rc<MemoryEnd>) -> OpenedLink<Rc<MemoryEnd>> {
        OpenedLink {
            sink: end.clone(),
            pump: end,
        }
    }
}

impl SessionLinks for MemoryLinks {
    type Pump = Rc<MemoryEnd>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let end = self.net.bind(
            UdpPeer {
                addr: self.host,
                port,
            },
            None,
        )?;
        Ok(Self::opened(end))
    }

    fn open_initiator(&self, peer: UdpPeer) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let port = self
            .net
            .free_port(self.host)
            .ok_or(LinkOpenError::Exhausted)?;
        let end = self.net.bind(
            UdpPeer {
                addr: self.host,
                port,
            },
            Some(peer),
        )?;
        Ok(Self::opened(end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_A: [u8; 4] = [10, 0, 0, 1];
    const HOST_B: [u8; 4] = [10, 0, 0, 2];

    fn frame_bytes(frame: Option<RxFrame>) -> Option<Vec<u8>> {
        frame.map(|f| f.bytes.to_vec())
    }

    /// A datagram reaches the end it names, an acceptor answers whoever spoke
    /// first, and the link's two ends are what the first datagram made them.
    #[test]
    fn a_datagram_reaches_its_end_and_an_acceptor_answers_who_spoke() {
        let net = MemoryNetwork::new();
        let accepting = MemoryLinks::new(net.clone(), HOST_A)
            .open_acceptor(7447)
            .expect("bind");
        let dialling = MemoryLinks::new(net.clone(), HOST_B)
            .open_initiator(UdpPeer {
                addr: HOST_A,
                port: 7447,
            })
            .expect("open");

        std::assert!(
            frame_bytes(accepting.pump.try_recv()).is_none(),
            "CONTROL: quiet"
        );
        std::assert!(
            accepting.sink.link_endpoints().is_none(),
            "an acceptor has no link until a peer speaks"
        );

        std::assert!(matches!(
            dialling.sink.send_blocking(b"hello", Reliability::Reliable),
            LinkSendOutcome::Sent
        ));
        std::assert_eq!(
            frame_bytes(accepting.pump.try_recv()),
            Some(b"hello".to_vec())
        );
        let link = accepting
            .sink
            .link_endpoints()
            .expect("the first datagram made it");
        std::assert_eq!(link.src, "udp/10.0.0.1:7447");
        std::assert!(link.dst.starts_with("udp/10.0.0.2:"), "{}", link.dst);

        std::assert!(matches!(
            accepting
                .sink
                .send_blocking(b"world", Reliability::Reliable),
            LinkSendOutcome::Sent
        ));
        std::assert_eq!(
            frame_bytes(dialling.pump.try_recv()),
            Some(b"world".to_vec())
        );
    }

    /// A port is one end's until that end is dropped, a datagram for nobody is
    /// dropped without an error, and an initiator is given a port nobody holds.
    #[test]
    fn a_port_is_freed_when_its_end_is_dropped_and_a_lost_datagram_is_silent() {
        let net = MemoryNetwork::new();
        let links = MemoryLinks::new(net.clone(), HOST_A);
        let first = links.open_acceptor(7447).expect("bind");
        std::assert!(links.open_acceptor(7447).is_err(), "taken while it lives");
        drop(first);
        std::assert!(links.open_acceptor(7447).is_ok(), "free once it is dropped");

        let out = links
            .open_initiator(UdpPeer {
                addr: HOST_B,
                port: 9,
            })
            .expect("open");
        std::assert!(matches!(
            out.sink.send_blocking(b"x", Reliability::Reliable),
            LinkSendOutcome::Sent
        ));
        std::assert_eq!(net.waiting_at(HOST_B, 9), 0, "nobody bound there");

        let second = links
            .open_initiator(UdpPeer {
                addr: HOST_B,
                port: 9,
            })
            .expect("open");
        std::assert_ne!(out.pump.local().port, second.pump.local().port);
    }

    /// An initiator's port is one nobody holds, wherever the counter stands: it
    /// steps over a port an acceptor took inside the ephemeral range, and after
    /// the last port it comes back round to the start of the range.
    #[test]
    fn an_initiator_gets_a_free_port_stepping_over_taken_ones_and_wrapping() {
        let net = MemoryNetwork::new();
        let links = MemoryLinks::new(net.clone(), HOST_A);
        let peer = UdpPeer {
            addr: HOST_B,
            port: 9,
        };

        let _taken = links
            .open_acceptor(FIRST_EPHEMERAL_PORT)
            .expect("bind inside the range");
        let first = links.open_initiator(peer).expect("open");
        std::assert_eq!(
            first.pump.local().port,
            FIRST_EPHEMERAL_PORT + 1,
            "steps over the taken port"
        );

        net.next_ephemeral.set(u16::MAX);
        let last = links.open_initiator(peer).expect("open");
        std::assert_eq!(last.pump.local().port, u16::MAX);
        drop(first);
        let wrapped = links.open_initiator(peer).expect("open");
        std::assert_eq!(
            wrapped.pump.local().port,
            FIRST_EPHEMERAL_PORT + 1,
            "back to the start of the range, past the port still taken there"
        );
    }
}
