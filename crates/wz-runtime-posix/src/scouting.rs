// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A scouting window's sockets on a host: one ASK socket pinned to each interface that can carry
//! multicast and, with `scout-group-socket`, the socket joined to the scouting group, written once
//! over either host's sockets ([`MulticastSocket`]).
//!
//! The Scout leaves by an ask socket pinned to each interface, and the Hello comes back to the
//! socket the Scout left from, because both references' responders reply unicast to the asker:
//! zenoh-pico opens a link per interface when its config names none
//! (`vendor/zenoh-pico/src/session/scout.c` @
//! `_z_udp_unicast_interface_iterator_next(&iter)`), and reads on those links alone.
//!
//! The group socket (joined, bound on the group port) is a RECEIVE member beside them and not a
//! condition of the window, a behaviour zenoh-pico does not have: it hears a Hello sent to the
//! group rather than to the asker, and a host that lists no interface asks on it alone, as a
//! floor. A window whose group socket cannot be bound goes on with the ask sockets. Without the
//! switch a window has its ask sockets alone, and one with none has no member and ends at once,
//! as zenoh-pico's scout fails with no link (`vendor/zenoh-pico/src/session/scout.c` @
//! `return _z_scout_links_size(&scout->_links) > 0 ? _Z_RES_OK : _Z_ERR_TRANSPORT_OPEN_FAILED;`).
//!
//! A Scout is sent when AT LEAST ONE ask socket sent it (pico's rule, `scout.c` @
//! `return sent ? _Z_RES_OK : _Z_ERR_TRANSPORT_TX_FAILED;`): a node with one dead interface among
//! four must still discover. The rules of the window itself (what a Scout says, which datagrams
//! answer it, when it is over) are the session's, pumped over these sockets by the engine.

use core::ffi::c_int;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_runtime_coop::udp_link::DatagramSocket;
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps::MAX_SCOUT_INTERFACES;

use crate::group::MulticastSocket;
use crate::multicast::bind_scout_asker;
#[cfg(feature = "scout-group-socket")]
use crate::multicast::bind_scout_group;

/// One socket of a window: where it reads, where the Scout goes from it, and whether it asks.
pub struct ScoutMember<S> {
    socket: S,
    /// Where the Scout is written from this member: the group, or in a test the responder.
    peer: SocketAddr,
    /// Whether the Scout is written from it: every ask member does, and the group's socket only
    /// when the window has no ask member.
    #[cfg(feature = "scout-group-socket")]
    asks: bool,
    /// A read of the socket failed in this drain: the drain drops the member as it ends.
    lost: bool,
}

impl<S> ScoutMember<S> {
    /// An ask member reading `socket`, which writes its Scout to `peer`.
    pub fn new(socket: S, peer: SocketAddr) -> Self {
        Self {
            socket,
            peer,
            #[cfg(feature = "scout-group-socket")]
            asks: true,
            lost: false,
        }
    }

    /// Whether the Scout is written from this member. A window without the group's socket holds
    /// ask members alone.
    fn asks(&self) -> bool {
        #[cfg(feature = "scout-group-socket")]
        {
            self.asks
        }
        #[cfg(not(feature = "scout-group-socket"))]
        {
            true
        }
    }
}

/// A host socket a window waits on among its other members for a datagram: an entry of a set made
/// once with the window's members, so a wait collects nothing.
pub trait ReadableAmong: DatagramSocket {
    /// The socket as an entry of the set: the system's poll entry for it.
    type Entry;
    /// The socket's entry, made when it joins the set.
    fn readable_entry(&self) -> Self::Entry;
    /// Wait up to `timeout_ms` milliseconds for any socket of `set` to have a datagram, returning
    /// at once when one has; with none to wait on, the time passes. A failed wait returns early:
    /// the read that follows finds what there is.
    fn wait_readable_among(set: &mut [Self::Entry], timeout_ms: c_int);
}

/// The rows a window holds its members in: one for each interface it asks on, and the group's
/// socket.
const MEMBER_ROWS: usize = MAX_SCOUT_INTERFACES + GROUP_ROWS;

/// The row the group's socket takes beside the ask members.
#[cfg(feature = "scout-group-socket")]
const GROUP_ROWS: usize = 1;
#[cfg(not(feature = "scout-group-socket"))]
const GROUP_ROWS: usize = 0;

/// The sockets a window holds, in rows of their own: as zenoh-pico's scout holds its links in a
/// vector of `Z_MAX_NUM_SCOUT_INTERFACES` (`vendor/zenoh-pico/src/session/scout.c` @
/// `#define _ZP_STATIC_VECTOR_TEMPLATE_SIZE Z_MAX_NUM_SCOUT_INTERFACES`), a window asks on at
/// most `MAX_SCOUT_INTERFACES` interfaces, and the interfaces past them are left out and counted.
/// A member that fails a read is dropped, as a link that is lost is, and the window goes on with
/// the rest: one interface going down does not end a window the others can still answer on.
pub struct ScoutMembers<S: ReadableAmong> {
    members: BoundedVec<ScoutMember<S>, MEMBER_ROWS, Static>,
    /// What the window waits on, one entry for each member and in the members' order: made with
    /// them and dropped with each, so a wait hands the set as it stands.
    readable: BoundedVec<S::Entry, MEMBER_ROWS, Static>,
    /// The ask members the bound left out.
    left_out: usize,
    /// Where the next read starts, so one socket that is always ready cannot starve the others (a
    /// group socket is one anybody can send to).
    cursor: usize,
}

impl<S: MulticastSocket + ReadableAmong> ScoutMembers<S> {
    /// Open one ask socket for each address of `locals`, up to the window's bound, and, with
    /// `scout-group-socket`, the group socket on `group:port` after them
    /// (`listening_on_group`). An address past the bound opens nothing and is counted
    /// ([`Self::left_out`]); a socket that cannot be opened is left out and the others stand. An
    /// ask socket is bound to its address and leaves by it; the address is handed to the socket
    /// layer as it was read from the interface table, so a window writes and reads no address text.
    pub fn open(group: IpAddr, port: u16, locals: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        let mut members = Self::empty();
        for local in locals {
            if !members.room_to_ask() {
                members.left_out = members.left_out.saturating_add(1);
                continue;
            }
            // A refusal is the address's alone: it is left out and the others stand.
            if let Ok(bound) = bind_scout_asker::<S>(group, port, local) {
                members.ask_by(ScoutMember::new(bound.socket, bound.peer));
            }
        }
        if members.left_out > 0 {
            wz_session_core::diag_warn!(
                "scout: the window asks on {MAX_SCOUT_INTERFACES} interface(s); {} left out",
                members.left_out
            );
        }
        #[cfg(feature = "scout-group-socket")]
        let members = match bind_scout_group::<S>(group, port) {
            Ok(bound) => members.listening_on_group(bound.socket, bound.peer),
            Err(_) => members,
        };
        wz_session_core::diag_debug!(
            "scout: asking on {} of {} socket(s)",
            members.askers(),
            members.members.len()
        );
        members
    }
}

impl<S: ReadableAmong> ScoutMembers<S> {
    /// A window of no member.
    fn empty() -> Self {
        Self {
            members: BoundedVec::new_static(),
            readable: BoundedVec::new_static(),
            left_out: 0,
            cursor: 0,
        }
    }

    /// A window of the ask members `ask`, in their order, those past the bound left out
    /// ([`Self::ask_by`]); with none, there is no window.
    pub fn asking(ask: impl IntoIterator<Item = ScoutMember<S>>) -> Self {
        let mut this = Self::empty();
        for member in ask {
            this.ask_by(member);
        }
        this
    }

    /// Whether the window takes another ask member: it asks on at most `MAX_SCOUT_INTERFACES`.
    fn room_to_ask(&self) -> bool {
        self.askers() < MAX_SCOUT_INTERFACES
    }

    /// Take `member` as one that asks; past the bound it is dropped and counted, as zenoh-pico
    /// leaves out an interface past its scout's links (`vendor/zenoh-pico/src/session/scout.c` @
    /// `_Z_WARN("Scouting link limit reached, ignoring interface: %s", iface_name);`).
    pub fn ask_by(&mut self, member: ScoutMember<S>) {
        if !(self.room_to_ask() && self.admit(member)) {
            self.left_out = self.left_out.saturating_add(1);
        }
    }

    /// How many ask members the bound left out.
    pub fn left_out(&self) -> usize {
        self.left_out
    }

    /// The window with `socket`, joined to the scouting group, as a member that reads what the
    /// group carries; it writes the Scout to `peer` too when no member of the window asks, the
    /// floor a host that lists no interface still scouts on. Taken after the ask members, so that
    /// it is known whether one does.
    #[cfg(feature = "scout-group-socket")]
    pub fn listening_on_group(mut self, socket: S, peer: SocketAddr) -> Self {
        let asks = self.askers() == 0;
        self.admit(ScoutMember {
            socket,
            peer,
            asks,
            lost: false,
        });
        self
    }

    /// Take `member` with its entry of the set the window waits on: whether there was a row for
    /// it. The two tables have one bound and one length, so the entry has a row where the member
    /// had one.
    fn admit(&mut self, member: ScoutMember<S>) -> bool {
        let entry = member.socket.readable_entry();
        self.members.push(member).is_ok() && self.readable.push(entry).is_ok()
    }

    /// Whether the window has no socket at all.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// How many of the members ask.
    pub fn askers(&self) -> usize {
        self.members.iter().filter(|member| member.asks()).count()
    }

    /// Write `scout` from every ask member: whether at least one sent it.
    pub fn send(&self, scout: &[u8]) -> bool {
        let mut sent = false;
        for member in self.members.iter().filter(|member| member.asks()) {
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
        // Each member kept moves forward past the lost ones before it, its entry with it, so the
        // members and the set keep one order.
        let mut kept = 0;
        for at in 0..self.members.len() {
            if !self.members[at].lost {
                self.members.swap(kept, at);
                self.readable.swap(kept, at);
                kept += 1;
            }
        }
        while self.members.len() > kept {
            self.members.pop();
            self.readable.pop();
        }
        any
    }

    /// Wait up to `timeout_ms` milliseconds for any member to have a datagram, returning at once
    /// when one has: a window that found nothing waits here rather than spin, and a Hello ends the
    /// wait as it arrives. The set waited on is the one made with the members.
    pub fn wait(&mut self, timeout_ms: c_int) {
        S::wait_readable_among(&mut self.readable, timeout_ms);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::net::PosixUdpSocket;
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    fn loopback() -> PosixUdpSocket {
        PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a loopback socket")
    }

    /// A member on a fresh loopback socket that writes its Scout to `peer`.
    fn asking(peer: SocketAddr) -> ScoutMember<PosixUdpSocket> {
        ScoutMember::new(loopback(), peer)
    }

    /// With no ask member the group socket asks; with ask members it only listens. Turned red by
    /// a group socket that asks beside an ask member, or stays silent when it is the only member.
    #[cfg(feature = "scout-group-socket")]
    #[test]
    fn the_group_socket_asks_only_when_nothing_else_can() {
        let responder = loopback();
        let alone =
            ScoutMembers::asking(Vec::new()).listening_on_group(loopback(), responder.local());
        assert_eq!(alone.askers(), 1);
        assert!(alone.send(b"scout"), "the group socket asked");

        let both = ScoutMembers::asking([asking(responder.local())])
            .listening_on_group(loopback(), responder.local());
        assert_eq!(
            both.askers(),
            1,
            "the ask socket asks, the group socket listens"
        );
        assert_eq!(both.members.len(), 2);
    }

    /// A window of no member is no window: nothing to ask with.
    #[test]
    fn a_window_of_no_member_asks_nobody() {
        let none = ScoutMembers::<PosixUdpSocket>::asking(Vec::new());
        assert!(none.is_empty());
        assert!(!none.send(b"scout"), "nobody to ask with");
    }

    /// Without the group's socket a window holds the ask sockets its addresses gave and nothing
    /// else, and one given no address has no member, as zenoh-pico's scout opens no link then.
    /// Turned red by a window that joins the group without the switch.
    #[cfg(not(feature = "scout-group-socket"))]
    #[test]
    fn a_window_without_the_group_socket_holds_its_ask_sockets_alone() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 255, 91, 77));
        assert!(
            ScoutMembers::<PosixUdpSocket>::open(group, 47_477, core::iter::empty()).is_empty()
        );
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_477, [Ipv4Addr::LOCALHOST]);
        assert_eq!(members.members.len(), 1);
        assert_eq!(members.askers(), 1);
    }

    /// A Scout is sent when one ask member sent it, past one that cannot: a member whose peer is an
    /// address nothing can be sent to.
    #[test]
    fn a_scout_is_sent_when_one_member_sent_it() {
        let responder = loopback();
        let dead = asking(SocketAddr::from(([0, 0, 0, 0], 0)));
        let members = ScoutMembers::asking([dead, asking(responder.local())]);
        assert!(members.send(b"scout"));
        let mut got = [0u8; 16];
        let (len, _) = responder
            .recv_waiting(&mut got)
            .expect("no error")
            .expect("the Scout arrived");
        assert_eq!(&got[..len], b"scout");
        let dead_alone = ScoutMembers::asking([asking(SocketAddr::from(([0, 0, 0, 0], 0)))]);
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
        let mut members =
            ScoutMembers::asking([ScoutMember::new(a, a_at), ScoutMember::new(b, b_at)]);
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
        /// What the socket is in the window's set: the port of its member, so the set's order can
        /// be read against the members'.
        id: u16,
    }

    impl ReadableAmong for Scripted {
        type Entry = u16;

        fn readable_entry(&self) -> u16 {
            self.id
        }

        fn wait_readable_among(_set: &mut [u16], _timeout_ms: c_int) {}
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
    /// window whose every member was lost is empty. The set the window waits on is made with the
    /// members and follows each drop. Turned red by a drain that keeps a lost member, drops a live
    /// one or moves one, as removing by swap does, or by a set that leaves its members' order.
    #[test]
    fn a_member_whose_read_fails_is_dropped_and_the_rest_keep_their_order() {
        let at = |port: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let member = |port: u16, broken: bool, queued: &[&'static str]| {
            let socket = Scripted {
                queued: core::cell::RefCell::new(queued.to_vec()),
                broken: core::cell::Cell::new(broken),
                id: port,
            };
            ScoutMember::new(socket, at(port))
        };
        let peers = |members: &ScoutMembers<Scripted>| -> Vec<SocketAddr> {
            let peers: Vec<SocketAddr> = members.members.iter().map(|member| member.peer).collect();
            let set: Vec<SocketAddr> = members.readable.iter().map(|id| at(*id)).collect();
            assert_eq!(
                set, peers,
                "the set waited on is the members', in their order"
            );
            peers
        };
        let mut members = ScoutMembers::asking([
            member(1, true, &[]),
            member(2, false, &["two"]),
            member(3, true, &[]),
            member(4, false, &["four"]),
            member(5, true, &[]),
            member(6, false, &[]),
        ]);
        assert_eq!(peers(&members), (1..=6).map(at).collect::<Vec<_>>());
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
        assert!(members.readable.is_empty(), "and nothing is waited on");
    }

    /// A window asks on at most `MAX_SCOUT_INTERFACES` members: one past the bound is left out
    /// and counted, the first ones kept in their order, each with its entry of the set. Turned red
    /// by a window that keeps a member past the bound, or does not count the one it left out.
    #[test]
    fn a_window_keeps_the_bound_of_ask_members_and_counts_the_rest() {
        let bound = MAX_SCOUT_INTERFACES;
        let port = |k: usize| u16::try_from(k + 1).expect("a bound of a few rows");
        let at = |port: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let members = ScoutMembers::asking((0..=bound).map(|k| {
            let socket = Scripted {
                queued: core::cell::RefCell::new(Vec::new()),
                broken: core::cell::Cell::new(false),
                id: port(k),
            };
            ScoutMember::new(socket, at(port(k)))
        }));
        assert_eq!(members.askers(), bound);
        assert_eq!(members.left_out(), 1);
        let kept: Vec<u16> = members.readable.iter().copied().collect();
        assert_eq!(kept, (0..bound).map(port).collect::<Vec<_>>());
    }

    /// An address past the window's bound opens no socket: the window holds the bound's ask
    /// sockets and counts the rest. Turned red by a window that opens a socket it cannot keep, or
    /// asks on more interfaces than the bound.
    #[test]
    fn an_address_past_the_bound_opens_no_socket() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 255, 91, 76));
        let locals = core::iter::repeat(Ipv4Addr::LOCALHOST).take(MAX_SCOUT_INTERFACES + 2);
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_476, locals);
        assert_eq!(members.askers(), MAX_SCOUT_INTERFACES);
        assert_eq!(members.left_out(), 2);
        assert!(members.members.len() <= MAX_SCOUT_INTERFACES + GROUP_ROWS);
    }

    /// A window asks from a socket bound to each address it is handed, and from none of an
    /// address the group's family refuses: an IPv4 address for an IPv6 group asks nothing. Turned
    /// red by an ask socket bound elsewhere than its address, or one made for the other family.
    #[test]
    fn an_ask_socket_is_bound_to_the_address_it_is_handed() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 255, 91, 79));
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_479, [Ipv4Addr::LOCALHOST]);
        let askers: Vec<SocketAddr> = members
            .members
            .iter()
            .filter(|member| member.asks())
            .map(|member| member.socket.local())
            .collect();
        assert_eq!(
            askers.len(),
            1,
            "one ask socket, the group socket listening"
        );
        assert_eq!(askers[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let v6 = IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x231));
        let members = ScoutMembers::<PosixUdpSocket>::open(v6, 47_479, [Ipv4Addr::LOCALHOST]);
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
        let members = ScoutMembers::<PosixUdpSocket>::open(group, 47_478, locals.iter().copied());
        for member in &members.members {
            assert_eq!(member.peer, SocketAddr::new(group, 47_478));
        }
        assert!(members.askers() <= locals.len().max(1));
    }
}
