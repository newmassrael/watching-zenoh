// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! nothing else: a link's peer is fixed once known
//! (`wz_session_core::datagram_peer`), an acceptor's by the first `InitSyn` it
//! takes, and the session reads that peer's datagrams only; a datagram for an end nobody bound is
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
use wz_session_core::datagram_peer::{DatagramVerdict, ForeignCounts, PeerBinding};
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
    /// learns its peer from the first `InitSyn` it takes). Refused when something is
    /// already bound there.
    pub fn bind(
        self: &Rc<Self>,
        local: UdpPeer,
        peer: Option<UdpPeer>,
    ) -> Result<Rc<MemoryEnd>, LinkOpenError> {
        let mut queues = self.queues.borrow_mut();
        if queues.contains_key(&(local.addr, local.port)) {
            return Err(LinkOpenError::Exhausted);
        }
        Ok(self.claim(&mut queues, local, peer))
    }

    /// Bind an end on `addr` at a port nobody holds, taken from the ephemeral
    /// range, sending to `peer`. The port is found and claimed under one borrow of
    /// the network, so no value that could go stale between the two is ever
    /// handed out: what comes back is an end that already owns its port.
    pub fn bind_ephemeral(
        self: &Rc<Self>,
        addr: [u8; 4],
        peer: Option<UdpPeer>,
    ) -> Result<Rc<MemoryEnd>, LinkOpenError> {
        let mut queues = self.queues.borrow_mut();
        let port = self
            .next_unclaimed_port(&queues, addr)
            .ok_or(LinkOpenError::Exhausted)?;
        Ok(self.claim(&mut queues, UdpPeer { addr, port }, peer))
    }

    /// Register `local`'s queue and build the end that owns it. The caller has
    /// checked, under the borrow it passes in, that nothing is bound there.
    fn claim(
        self: &Rc<Self>,
        queues: &mut Queues,
        local: UdpPeer,
        peer: Option<UdpPeer>,
    ) -> Rc<MemoryEnd> {
        queues.insert((local.addr, local.port), VecDeque::new());
        let end = MemoryEnd {
            net: self.clone(),
            local,
            binding: match peer {
                Some(peer) => PeerBinding::dialled(peer),
                None => PeerBinding::accepting(),
            },
            endpoints: OnceCell::new(),
        };
        end.note_endpoints();
        Rc::new(end)
    }

    /// The next port on `addr`, from the ephemeral range, that `queues` does not
    /// hold. Only [`Self::bind_ephemeral`] calls it, with the borrow it then
    /// claims under.
    fn next_unclaimed_port(&self, queues: &Queues, addr: [u8; 4]) -> Option<u16> {
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
    binding: PeerBinding<UdpPeer>,
    endpoints: OnceCell<LinkEndpoints>,
}

impl MemoryEnd {
    /// Record the link's two ends once the peer is known. The peer never
    /// changes after, so neither do they.
    fn note_endpoints(&self) {
        let Some(peer) = self.binding.peer() else {
            return;
        };
        let _ = self.endpoints.set(LinkEndpoints::new(
            udp_locator(self.local),
            udp_locator(peer),
        ));
    }

    /// Where this end sends, once it has a peer.
    pub fn peer(&self) -> Option<UdpPeer> {
        self.binding.peer()
    }

    /// The datagrams this end has discarded for not being its peer's.
    pub fn foreign(&self) -> ForeignCounts {
        self.binding.foreign()
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
        let Some(peer) = self.binding.peer() else {
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
        loop {
            let waiting = self
                .net
                .queues
                .borrow_mut()
                .get_mut(&(self.local.addr, self.local.port))?
                .pop_front()?;
            // The peer's datagrams only; the InitSyn that binds an acceptor is
            // how it learns its peer, and anyone else's is let go.
            let verdict = self.binding.admit(waiting.from, &waiting.bytes);
            if verdict == DatagramVerdict::Bound {
                self.note_endpoints();
            }
            if verdict.is_taken() {
                return Some(RxFrame::new(waiting.bytes));
            }
        }
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
        let end = self.net.bind_ephemeral(self.host, Some(peer))?;
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

    /// An `InitSyn` header and a byte of body: what binds an accepting end.
    const SYN: &[u8] = &[0x01, 0x09];

    /// A datagram reaches the end it names, an acceptor answers the source of
    /// the InitSyn that bound it, and the link's two ends are that pair.
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

        std::assert!(wz_session_core::datagram_peer::is_init_syn(SYN));
        std::assert!(matches!(
            dialling.sink.send_blocking(SYN, Reliability::Reliable),
            LinkSendOutcome::Sent
        ));
        std::assert_eq!(frame_bytes(accepting.pump.try_recv()), Some(SYN.to_vec()));
        let link = accepting
            .sink
            .link_endpoints()
            .expect("the InitSyn bound it");
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

    /// The rule a real link keeps: once bound, the acceptor's session reads its
    /// peer only, and a datagram from another end neither reaches it nor moves
    /// where its replies go.
    #[test]
    fn a_bound_acceptor_lets_a_strangers_datagram_go_and_keeps_answering_its_peer() {
        let net = MemoryNetwork::new();
        let accepting = MemoryLinks::new(net.clone(), HOST_A)
            .open_acceptor(7447)
            .expect("bind");
        let to_acceptor = UdpPeer {
            addr: HOST_A,
            port: 7447,
        };
        let peer = MemoryLinks::new(net.clone(), HOST_B)
            .open_initiator(to_acceptor)
            .expect("open");
        let stranger = MemoryLinks::new(net.clone(), [10, 0, 0, 3])
            .open_initiator(to_acceptor)
            .expect("open");

        let send = |from: &OpenedLink<Rc<MemoryEnd>>, bytes: &[u8]| {
            std::assert!(matches!(
                from.sink.send_blocking(bytes, Reliability::Reliable),
                LinkSendOutcome::Sent
            ));
        };
        send(&stranger, b"early");
        send(&peer, SYN);
        std::assert_eq!(frame_bytes(accepting.pump.try_recv()), Some(SYN.to_vec()));
        std::assert_eq!(accepting.pump.peer(), Some(peer.pump.local()));

        send(&stranger, b"stray");
        send(&stranger, SYN);
        std::assert!(frame_bytes(accepting.pump.try_recv()).is_none());
        send(&accepting, b"reply");
        std::assert_eq!(frame_bytes(peer.pump.try_recv()), Some(b"reply".to_vec()));
        std::assert!(frame_bytes(stranger.pump.try_recv()).is_none());
        std::assert_eq!(
            accepting.pump.foreign(),
            ForeignCounts {
                strays: 2,
                refused: 1
            }
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
