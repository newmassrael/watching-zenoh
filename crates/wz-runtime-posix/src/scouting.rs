// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A scouting window's sockets on a host: one ASK socket pinned to each interface that can carry
//! multicast, and the socket joined to the scouting group, written once over either host's sockets
//! ([`MulticastSocket`]).
//!
//! The group socket (joined, bound on the group port) is an extra RECEIVE member and not a
//! condition of the window: upstream's `scout` receives on its per-interface sockets alone, and
//! zenoh-pico opens a link per interface when its config names none
//! (`vendor/zenoh-pico/src/session/scout.c` @
//! `_z_udp_unicast_interface_iterator_next(&iter)`). So the Scout leaves by an ask socket pinned to
//! each interface, and the Hello comes back to the socket the Scout left from, because both
//! references' responders reply unicast to the asker. A window whose group socket cannot be bound
//! goes on with the ask sockets; a host that lists no interface asks on the group socket alone, as
//! a floor; a window with neither is empty.
//!
//! A Scout is sent when AT LEAST ONE ask socket sent it (pico's rule, `scout.c` @
//! `return sent ? _Z_RES_OK : _Z_ERR_TRANSPORT_TX_FAILED;`): a node with one dead interface among
//! four must still discover. The rules of the window itself (what a Scout says, which datagrams
//! answer it, when it is over) are the session's, pumped over these sockets by the engine.

use alloc::vec::Vec;
use core::ffi::c_int;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_runtime_coop::udp_link::DatagramSocket;

use crate::group::MulticastSocket;
use crate::multicast::{bind_scout_asker, bind_scout_group};

/// One socket of a window: where it reads, where the Scout goes from it, and whether it asks.
pub struct ScoutMember<S> {
    socket: S,
    /// Where the Scout is written from this member: the group, or in a test the responder.
    peer: SocketAddr,
    asks: bool,
    /// A read of the socket failed in this drain: the drain drops the member as it ends.
    lost: bool,
}

impl<S> ScoutMember<S> {
    /// A member reading `socket`, which writes its Scout to `peer` when it `asks`.
    pub fn new(socket: S, peer: SocketAddr, asks: bool) -> Self {
        Self {
            socket,
            peer,
            asks,
            lost: false,
        }
    }
}

/// The sockets a window holds. A member that fails a read is dropped, as a link that is lost is,
/// and the window goes on with the rest: one interface going down does not end a window the others
/// can still answer on.
pub struct ScoutMembers<S> {
    members: Vec<ScoutMember<S>>,
    /// Where the next read starts, so one socket that is always ready cannot starve the others (a
    /// group socket is one anybody can send to).
    cursor: usize,
}

impl<S: MulticastSocket> ScoutMembers<S> {
    /// Open the group socket on `group:port` and one ask socket for each address of `locals`
    /// ([`Self::from_parts`] says what is kept when they fail). An ask socket is bound to its
    /// address and leaves by it; the address is handed to the socket layer as it was read from the
    /// interface table, so a window writes and reads no address text.
    pub fn open(group: IpAddr, port: u16, locals: &[Ipv4Addr]) -> Self {
        let group_member = bind_scout_group::<S>(group, port)
            .ok()
            .map(|bound| ScoutMember::new(bound.socket, bound.peer, false));
        let mut asking = Vec::new();
        for local in locals {
            // A refusal is the address's alone: it is left out and the others stand.
            if let Ok(bound) = bind_scout_asker::<S>(group, port, *local) {
                asking.push(ScoutMember::new(bound.socket, bound.peer, true));
            }
        }
        Self::from_parts(group_member, asking)
    }
}

impl<S: DatagramSocket> ScoutMembers<S> {
    /// The group member and the ask members as one window. With no ask member the group socket
    /// asks, which is the floor a host that lists no interface still scouts on; with neither,
    /// there is no window.
    pub fn from_parts(group: Option<ScoutMember<S>>, ask: Vec<ScoutMember<S>>) -> Self {
        let fell_back_to_group = ask.is_empty();
        let mut members = Vec::with_capacity(ask.len() + 1);
        if let Some(mut group) = group {
            group.asks = fell_back_to_group;
            members.push(group);
        }
        members.extend(ask);
        let this = Self { members, cursor: 0 };
        wz_session_core::diag_debug!(
            "scout: asking on {} socket(s); fell back to the group socket: {fell_back_to_group}",
            this.askers()
        );
        this
    }

    /// Whether the window has no socket at all.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// How many of the members ask.
    pub fn askers(&self) -> usize {
        self.members.iter().filter(|member| member.asks).count()
    }

    /// Write `scout` from every ask member: whether at least one sent it.
    pub fn send(&self, scout: &[u8]) -> bool {
        let mut sent = false;
        for member in self.members.iter().filter(|member| member.asks) {
            match member.socket.send_to(member.peer, scout) {
                Ok(()) => sent = true,
                Err(error) => {
                    wz_session_core::diag_debug!(
                        "scout: a Scout did not leave by {}: {error:?}",
                        member.peer
                    )
                }
            }
        }
        sent
    }

    /// Read every datagram that is waiting into `buffer`, handing each to `on_datagram`, and say
    /// whether any was. A member whose read fails is dropped, and the others keep their order.
    pub fn drain(&mut self, buffer: &mut [u8], mut on_datagram: impl FnMut(&[u8])) -> bool {
        let mut any = false;
        let count = self.members.len();
        for step in 0..count {
            let member = &mut self.members[(self.cursor + step) % count];
            loop {
                match member.socket.try_recv(buffer) {
                    Ok(Some((len, _from))) => {
                        any = true;
                        on_datagram(&buffer[..len]);
                    }
                    Ok(None) => break,
                    Err(error) => {
                        wz_session_core::diag_debug!("scout: a member was lost: {error:?}");
                        member.lost = true;
                        break;
                    }
                }
            }
        }
        if count > 0 {
            self.cursor = (self.cursor + 1) % count;
        }
        // Each lost member is marked where it lies, so one pass in order drops them all, with no
        // list of their places to sort first: the reads began at the cursor, not at the front.
        self.members.retain(|member| !member.lost);
        any
    }
}

impl<S: MulticastSocket> ScoutMembers<S> {
    /// Wait up to `timeout_ms` milliseconds for any member to have a datagram, returning at once
    /// when one has: a window that found nothing waits here rather than spin, and a Hello ends the
    /// wait as it arrives.
    pub fn wait(&self, timeout_ms: c_int) {
        let sockets: Vec<&S> = self.members.iter().map(|member| &member.socket).collect();
        S::wait_readable_any(&sockets, timeout_ms);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::net::PosixUdpSocket;
    use core::net::Ipv6Addr;

    fn loopback() -> PosixUdpSocket {
        PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a loopback socket")
    }

    /// A member on a fresh loopback socket that writes its Scout to `peer`.
    fn asking(peer: SocketAddr) -> ScoutMember<PosixUdpSocket> {
        ScoutMember::new(loopback(), peer, true)
    }

    /// With no ask member the group socket asks; with ask members it only listens; with neither
    /// there is no window.
    #[test]
    fn the_group_socket_asks_only_when_nothing_else_can() {
        let responder = loopback();
        let group = ScoutMember::new(loopback(), responder.local(), false);
        let alone = ScoutMembers::from_parts(Some(group), Vec::new());
        assert_eq!(alone.askers(), 1);
        assert!(alone.send(b"scout"), "the group socket asked");

        let group = ScoutMember::new(loopback(), responder.local(), true);
        let both = ScoutMembers::from_parts(Some(group), alloc::vec![asking(responder.local())]);
        assert_eq!(
            both.askers(),
            1,
            "the ask socket asks, the group socket listens"
        );

        let none = ScoutMembers::<PosixUdpSocket>::from_parts(None, Vec::new());
        assert!(none.is_empty());
        assert!(!none.send(b"scout"), "nobody to ask with");
    }

    /// A Scout is sent when one ask member sent it, past one that cannot: a member whose peer is an
    /// address nothing can be sent to.
    #[test]
    fn a_scout_is_sent_when_one_member_sent_it() {
        let responder = loopback();
        let dead = asking(SocketAddr::from(([0, 0, 0, 0], 0)));
        let members = ScoutMembers::from_parts(None, alloc::vec![dead, asking(responder.local())]);
        assert!(members.send(b"scout"));
        let mut got = [0u8; 16];
        let (len, _) = responder
            .recv_waiting(&mut got)
            .expect("no error")
            .expect("the Scout arrived");
        assert_eq!(&got[..len], b"scout");
        let dead_alone = ScoutMembers::from_parts(
            None,
            alloc::vec![asking(SocketAddr::from(([0, 0, 0, 0], 0)))],
        );
        assert!(!dead_alone.send(b"scout"), "no member sent it");
    }

    /// Every datagram waiting on every member is read, each whole, and a window with nothing
    /// waiting reads nothing; the wait returns at once when a datagram is queued and is waited out
    /// when none is.
    #[test]
    fn the_window_reads_every_member_and_waits_for_the_next_datagram() {
        let a = loopback();
        let b = loopback();
        let (a_at, b_at) = (a.local(), b.local());
        let mut members = ScoutMembers::from_parts(
            None,
            alloc::vec![
                ScoutMember::new(a, a_at, true),
                ScoutMember::new(b, b_at, true)
            ],
        );
        let mut buffer = [0u8; 64];
        assert!(!members.drain(&mut buffer, |_| panic!("nothing was sent")));

        let started = std::time::Instant::now();
        members.wait(50);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(40),
            "nothing queued"
        );

        let sender = loopback();
        sender.send_to(a_at, b"hello a").expect("sent");
        sender.send_to(b_at, b"hello b").expect("sent");
        sender.send_to(b_at, b"again b").expect("sent");
        let started = std::time::Instant::now();
        members.wait(5_000);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "a datagram queued"
        );
        let mut seen = Vec::new();
        assert!(members.drain(&mut buffer, |datagram| seen.push(datagram.to_vec())));
        seen.sort();
        assert_eq!(
            seen,
            [
                b"again b".to_vec(),
                b"hello a".to_vec(),
                b"hello b".to_vec()
            ]
        );
        assert!(!members.is_empty(), "no member was lost");
    }

    /// A member's socket for the window's reads alone: it hands out what the test queued, and
    /// fails every read once it is broken.
    struct Scripted {
        queued: core::cell::RefCell<Vec<&'static str>>,
        broken: core::cell::Cell<bool>,
    }

    impl DatagramSocket for Scripted {
        type Error = ();

        wz_runtime_coop::with_heap_link_seams! {
            type Waits = wz_runtime_coop::session_drive::NoWaits;
        }

        fn bind(_at: SocketAddr) -> Result<Self, ()> {
            Err(())
        }

        fn local(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        }

        fn send_to(&self, _to: SocketAddr, _bytes: &[u8]) -> Result<(), ()> {
            Ok(())
        }

        fn wait_readable(&self, _timeout_ms: c_int) {}

        fn times_out(&self) -> bool {
            false
        }

        fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, ()> {
            self.try_recv(buf)
        }

        fn try_recv(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, ()> {
            if self.broken.get() {
                return Err(());
            }
            let Some(datagram) = self.queued.borrow_mut().pop() else {
                return Ok(None);
            };
            let bytes = datagram.as_bytes();
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            Ok(Some((len, self.local())))
        }
    }

    /// A member whose read fails is dropped as the drain ends and the others stay in their order,
    /// whichever member the drain began at, every datagram of a live member still handed on; a
    /// window whose every member was lost is empty. Turned red by a drain that keeps a lost
    /// member, drops a live one or moves one, as removing by swap does.
    #[test]
    fn a_member_whose_read_fails_is_dropped_and_the_rest_keep_their_order() {
        let at = |port: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let member = |port: u16, broken: bool, queued: &[&'static str]| {
            let socket = Scripted {
                queued: core::cell::RefCell::new(queued.to_vec()),
                broken: core::cell::Cell::new(broken),
            };
            ScoutMember::new(socket, at(port), true)
        };
        let peers = |members: &ScoutMembers<Scripted>| -> Vec<SocketAddr> {
            members.members.iter().map(|member| member.peer).collect()
        };
        let mut members = ScoutMembers::from_parts(
            None,
            alloc::vec![
                member(1, true, &[]),
                member(2, false, &["two"]),
                member(3, true, &[]),
                member(4, false, &["four"]),
                member(5, true, &[]),
                member(6, false, &[]),
            ],
        );
        let mut buffer = [0u8; 16];
        let mut seen = Vec::new();
        assert!(members.drain(&mut buffer, |datagram| seen.push(datagram.to_vec())));
        assert_eq!(seen, [b"two".to_vec(), b"four".to_vec()]);
        assert_eq!(peers(&members), [at(2), at(4), at(6)]);

        // The cursor moved on by one, so this drain begins at the member at 4 and comes to the
        // one at 2 last: both ends are lost, out of the order the reads met them in.
        members.members[0].socket.broken.set(true);
        members.members[1].socket.queued.borrow_mut().push("again");
        members.members[2].socket.broken.set(true);
        seen.clear();
        assert!(members.drain(&mut buffer, |datagram| seen.push(datagram.to_vec())));
        assert_eq!(seen, [b"again".to_vec()]);
        assert_eq!(peers(&members), [at(4)]);

        members.members[0].socket.broken.set(true);
        assert!(!members.drain(&mut buffer, |_| panic!("no member reads")));
        assert!(members.is_empty(), "every member was lost");
    }

    /// A window asks from a socket bound to each address it is handed, and from none of an
    /// address the group's family refuses: an IPv4 address for an IPv6 group asks nothing. Turned
    /// red by an ask socket bound elsewhere than its address, or one made for the other family.
    #[test]
    fn an_ask_socket_is_bound_to_the_address_it_is_handed() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 255, 91, 79));
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_479, &[Ipv4Addr::LOCALHOST]);
        let askers: Vec<SocketAddr> = members
            .members
            .iter()
            .filter(|member| member.asks)
            .map(|member| member.socket.local())
            .collect();
        assert_eq!(
            askers.len(),
            1,
            "one ask socket, the group socket listening"
        );
        assert_eq!(askers[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let v6 = IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x231));
        let members = ScoutMembers::<PosixUdpSocket>::open(v6, 47_479, &[Ipv4Addr::LOCALHOST]);
        assert!(
            members
                .members
                .iter()
                .all(|member| member.socket.local().ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "no socket of an IPv4 address for an IPv6 group"
        );
    }

    /// A host's window is opened on the scouting group: whatever the host lists, every member it
    /// keeps asks the group and none is asked twice, and the group socket asks only when no
    /// interface could. A host without a multicast route may keep no member at all.
    #[test]
    fn a_window_opened_on_the_host_asks_the_group() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 255, 91, 78));
        let locals = crate::interfaces::multicast_interface_addresses().unwrap_or_default();
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_478, &locals);
        for member in &members.members {
            assert_eq!(member.peer, SocketAddr::new(group, 47_478));
        }
        assert!(members.askers() <= locals.len().max(1));
    }
}
