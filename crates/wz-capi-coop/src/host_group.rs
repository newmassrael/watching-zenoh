// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins over the host's own sockets.
//!
//! A group on a host is the two sockets upstream's multicast link is
//! (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.unicast_socket`): one joined to the
//! group, bound on the family's wildcard address and the group's port, that every member's
//! datagrams are read on, and one on a port of its own that this member sends from, so the source
//! a peer keys this member by names it and no other member of the host. Both are `wz_host_net`'s,
//! built by the plan the tokio runtime's group link is built by (`bind_joined` with the wildcard
//! bind, `bind_sender` as a link's send half), so the interface an `#iface=` names, the one a link
//! that names none takes, the memberships of `#join=`, the hop limit of `#ttl=`, the local address
//! of `#bind=`, the traffic class of `#dscp=`, the loopback and the refusal of an unpinned link
//! are one decision for both engines.
//!
//! What this module adds is the cooperative host's reading of the two: a datagram is taken when
//! one is queued and never waited for, since the wait is the engine's, which steps its groups at
//! their tick ([`GroupTransport::service`] does nothing here).

use core::cell::RefCell;
use std::io;
use std::net::{SocketAddr, UdpSocket};

use wz_host_net::multicast::{
    bind_joined, bind_sender, mark_traffic_class, raw_handle, wait_readable, wait_writable,
    Loopback, RxBind, SocketConfig,
};
use wz_runtime_coop::group_transport::{GroupJoiner, GroupSend, GroupTransport};
use wz_runtime_coop::session_drive::{LinkOpenError, LinkReadiness, LinkWritability};
use wz_runtime_coop::udp_link::UDP_RX_CAPACITY;
use wz_session_core::locator::{parse_locator, ParsedLocator, Proto};
use wz_session_core::policy::{MulticastLoopback, SessionPolicy};

/// The host's joiner of the groups a session's links are asked for
/// ([`IpLinks::with_groups`](wz_runtime_coop::ip_stack::IpLinks::with_groups)): each `udp/`
/// endpoint that names a multicast group is joined on the host's sockets, under the two link
/// policies of the session that joins it.
pub struct HostGroups {
    loopback: Loopback,
    link_requires_iface: bool,
    /// The port each endpoint that names port 0 was given when it was first joined: a join again
    /// after the link was lost binds the same one, so the group is addressed by one port for as
    /// long as the session holds it, as the tokio runtime's group face keeps it.
    ports: RefCell<Vec<(String, u16)>>,
}

impl HostGroups {
    /// The joiner of a session that runs under `policy`: its sockets take the
    /// `multicast-loopback` and `multicast-link-requires-iface` policies as `policy` holds them,
    /// as the tokio runtime's group sockets do.
    pub fn of_policy(policy: &SessionPolicy) -> Self {
        Self {
            loopback: match policy.multicast_loopback() {
                MulticastLoopback::OsDefault => Loopback::OsDefault,
                MulticastLoopback::On => Loopback::On,
                MulticastLoopback::Off => Loopback::Off,
            },
            link_requires_iface: policy.multicast_link_requires_iface(),
            ports: RefCell::new(Vec::new()),
        }
    }

    /// The port `endpoint` was given when it was first joined, if it named port 0 and was.
    fn port_given(&self, endpoint: &str) -> Option<u16> {
        self.ports
            .borrow()
            .iter()
            .find(|(named, _)| named == endpoint)
            .map(|(_, port)| *port)
    }
}

impl GroupJoiner for HostGroups {
    fn join(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        let group = group_of(endpoint).ok_or(LinkOpenError::Unsupported)?;
        let named_port = group.addr.port();
        let port = self.port_given(endpoint).unwrap_or(named_port);
        let transport = HostGroupTransport::join(&group, port, self).map_err(|e| {
            log::warn!("group {endpoint}: the host did not join it: {e}");
            LinkOpenError::Refused
        })?;
        if named_port == 0 && self.port_given(endpoint).is_none() {
            self.ports
                .borrow_mut()
                .push((endpoint.to_owned(), transport.group.port()));
        }
        Ok(Box::new(transport))
    }
}

/// The locator of `endpoint` when it names a UDP multicast group, which is what the host joins;
/// `None` for anything else, a unicast `udp/` address among them.
fn group_of(endpoint: &str) -> Option<ParsedLocator> {
    let parsed = parse_locator(endpoint).ok()?;
    (parsed.proto == Proto::Udp && parsed.addr.ip().is_multicast()).then_some(parsed)
}

/// One group joined on the host's sockets: the session's [`GroupTransport`].
pub struct HostGroupTransport {
    /// The joined socket the group is read on, `None` once the session has released the link.
    read: Option<UdpSocket>,
    /// The socket every datagram is sent from, `None` once the session has released the link.
    write: Option<UdpSocket>,
    /// The group and its port, where every datagram is sent.
    group: SocketAddr,
    rx: Vec<u8>,
    /// Whether the joined socket failed a receive: what the host reports of an interface that
    /// went away, and the end of the group's link.
    failed: bool,
}

impl HostGroupTransport {
    /// Join the group `group` names on `port` (its own port, or the one a first join of a port 0
    /// was given), as `groups` joins one. Port 0 is given its port by the bind of the joined
    /// socket, which the send socket addresses the group by, as upstream's multicast link reads
    /// the port of its bound socket (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
    /// `We may have bind to port 0, so we need to retrieve the actual port`).
    fn join(group: &ParsedLocator, port: u16, groups: &HostGroups) -> io::Result<Self> {
        let options = group.socket.as_deref();
        let config = SocketConfig {
            iface: options.and_then(|o| o.iface.as_deref()),
            ttl: group.mcast_ttl,
            extra_joins: &group.mcast_join,
            bind: options.and_then(|o| o.bind.as_deref()),
            loopback: groups.loopback,
            link_requires_iface: groups.link_requires_iface,
        };
        let address = group.addr.ip();
        let read = bind_joined(address, port, &config, RxBind::Wildcard)?;
        let port = match port {
            0 => read
                .socket
                .local_addr()?
                .as_socket()
                .map_or(0, |bound| bound.port()),
            named => named,
        };
        let write = bind_sender(address, port, &config, true)?;
        // `#dscp=` marks what this member sends, on the send half, which is the half upstream
        // marks.
        if let Some(dscp) = options.and_then(|o| o.dscp) {
            mark_traffic_class(&write.socket, &write.peer, dscp)?;
        }
        let mut to = read.peer;
        to.set_port(port);
        Ok(Self {
            read: Some(read.socket.into()),
            write: Some(write.socket.into()),
            group: to,
            rx: vec![0; UDP_RX_CAPACITY],
            failed: false,
        })
    }
}

/// The send socket's room asked by a thread other than the session's: a handle of its own to the
/// socket, so a wait made after the group was left asks a socket that is still open and never a
/// descriptor its close gave to something else.
struct SendRoom(UdpSocket);

impl LinkWritability for SendRoom {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        wait_writable(&self.0, timeout_us)
    }
}

/// The joined socket's input waited for by a thread other than the session's: a handle of its own
/// to the socket, as [`SendRoom`] is to the send socket, which the platform's wait names by its
/// descriptor beside the session's other links.
struct GroupInput(UdpSocket);

impl LinkReadiness for GroupInput {
    fn wait_readable(&self, timeout_ms: u32) {
        if let Some(handle) = self.handle() {
            wait_readable(&[handle], timeout_ms);
        }
    }

    fn handle(&self) -> Option<usize> {
        raw_handle(&self.0)
    }

    #[cfg(target_has_atomic = "ptr")]
    fn wait_readable_among(&self, others: &[std::sync::Arc<dyn LinkReadiness>], timeout_ms: u32) {
        let mut handles = Vec::with_capacity(others.len() + 1);
        handles.extend(self.handle());
        for other in others {
            match other.handle() {
                Some(handle) => handles.push(handle),
                // A wait this cannot name to the platform: the bounded look, so it is not starved
                // behind a wait on the others.
                None => return self.wait_readable(timeout_ms.min(1)),
            }
        }
        wait_readable(&handles, timeout_ms);
    }
}

impl GroupTransport for HostGroupTransport {
    fn open(&mut self) -> bool {
        self.read.is_some() && self.write.is_some()
    }

    fn close(&mut self) {
        // Closing the joined socket is leaving the group: the host drops its memberships with it.
        self.read = None;
        self.write = None;
    }

    fn service(&self) {}

    /// A host has no carrier to read here; what ends a group is its joined socket failing, which
    /// is what the host reports of an interface that went away.
    fn carrier_up(&self) -> bool {
        !self.failed
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as a multicast send is: the next beacon or retransmission is the retry.
        if let Some(socket) = &self.write {
            let _ = socket.send_to(datagram, self.group);
        }
    }

    // The send socket does not block: one with no room in its buffer refuses the datagram with
    // nothing sent, which is a full socket and not a lost datagram, and so is a send a signal cut
    // short. Anything else lost it.
    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        let Some(socket) = &self.write else {
            return GroupSend::Failed;
        };
        match socket.send_to(datagram, self.group) {
            Ok(sent) if sent == datagram.len() => GroupSend::Sent,
            Ok(_) => GroupSend::Failed,
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => GroupSend::Full,
                _ => {
                    log::warn!("group {}: its socket failed a send: {e}", self.group);
                    GroupSend::Failed
                }
            },
        }
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        match &self.write {
            Some(socket) => wait_writable(socket, timeout_us),
            // Released: the send that follows fails.
            None => true,
        }
    }

    fn writability(&self) -> Option<Box<dyn LinkWritability>> {
        let socket = self.write.as_ref()?.try_clone().ok()?;
        Some(Box::new(SendRoom(socket)))
    }

    // The joined socket's input, on a platform that has a wait to name it to; a group that was
    // left gives none.
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        let socket = self.read.as_ref()?.try_clone().ok()?;
        raw_handle(&socket)?;
        Some(Box::new(GroupInput(socket)))
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(socket) = &self.read else {
            return false;
        };
        match socket.recv_from(&mut self.rx) {
            Ok((len, from)) => {
                f(&self.rx[..len], from);
                true
            }
            // Nothing queued, or a signal cut the read short: the next step reads again.
            Err(e) => {
                let quiet = matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                );
                if !quiet {
                    log::warn!("group {}: its socket failed a receive: {e}", self.group);
                    self.failed = true;
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The joiner of a session under the build's policies.
    fn groups() -> HostGroups {
        HostGroups::of_policy(&SessionPolicy::defaults())
    }

    /// Only a `udp/` endpoint that names a multicast group is a group of the host: a unicast
    /// address, a stream locator on a group address and text that is no locator are refused as
    /// unsupported, before any socket is opened.
    #[test]
    fn an_endpoint_that_names_no_udp_group_is_not_joined() {
        for endpoint in [
            "udp/127.0.0.1:7447#iface=lo",
            "tcp/239.1.2.3:7447",
            "not a locator",
        ] {
            assert!(
                matches!(groups().join(endpoint), Err(LinkOpenError::Unsupported)),
                "{endpoint}"
            );
        }
        assert!(group_of("udp/239.1.2.3:7447#iface=lo").is_some());
        assert!(group_of("udp/[ff05::7a:7703]:7447").is_some());
    }

    /// The session's `multicast-loopback` reaches the sockets it joins with, each value the
    /// build lets a session select as the host's same value, and its
    /// `multicast-link-requires-iface` as it holds it.
    #[test]
    fn the_sockets_take_the_sessions_link_policies() {
        for (selected, on_the_socket) in [
            (MulticastLoopback::OsDefault, Loopback::OsDefault),
            (MulticastLoopback::On, Loopback::On),
            (MulticastLoopback::Off, Loopback::Off),
        ] {
            let mut policy = SessionPolicy::defaults();
            if policy.select_multicast_loopback(selected).is_err() {
                // A build that holds the policy at another value has no session that selects it.
                continue;
            }
            let joiner = HostGroups::of_policy(&policy);
            assert_eq!(joiner.loopback, on_the_socket, "{selected:?}");
            assert_eq!(
                joiner.link_requires_iface,
                policy.multicast_link_requires_iface()
            );
        }
    }

    /// The send socket's room is the group's: a datagram it takes is sent and the socket has room,
    /// asked by the session's loop or from outside it; a group that was left fails its send, has
    /// room at once for the send to fail on, and gives no wait to ask. A send socket aimed at a
    /// loopback port stands in for one joined to a group, which needs a multicast route.
    #[test]
    fn the_send_sockets_room_is_the_groups() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("a peer");
        let write = UdpSocket::bind("127.0.0.1:0").expect("a send socket");
        write.set_nonblocking(true).expect("non-blocking");
        let mut transport = HostGroupTransport {
            read: None,
            write: Some(write),
            group: peer.local_addr().expect("the peer's port"),
            rx: Vec::new(),
            failed: false,
        };
        let outside = transport.writability().expect("a wait from outside");
        assert_eq!(transport.try_send_to_group(b"datagram"), GroupSend::Sent);
        let mut got = [0u8; 16];
        let (len, _) = peer.recv_from(&mut got).expect("the datagram arrived");
        assert_eq!(&got[..len], b"datagram");
        assert!(transport.wait_for_room(1_000));
        assert!(outside.wait_writable(1_000));

        transport.close();
        assert_eq!(transport.try_send_to_group(b"left"), GroupSend::Failed);
        assert!(transport.wait_for_room(1_000));
        assert!(transport.writability().is_none());
        assert!(
            outside.wait_writable(1_000),
            "a wait made after the leave asks a socket still open"
        );
    }

    /// The joined socket's input is waited for from outside the session's loop: the wait is waited
    /// out while nothing is queued and returns long before its time once a datagram is, whether it
    /// waits on the group alone or beside another socket; a group that was left gives no wait. A
    /// socket on a loopback port stands in for one joined to a group, which needs a multicast
    /// route.
    #[test]
    fn the_joined_sockets_input_is_waited_for_from_outside_the_loop() {
        use std::time::{Duration, Instant};
        let read = UdpSocket::bind("127.0.0.1:0").expect("a joined socket");
        let to = read.local_addr().expect("its port");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("a peer");
        let other = UdpSocket::bind("127.0.0.1:0").expect("another link's socket");
        let mut transport = HostGroupTransport {
            read: Some(read),
            write: None,
            group: to,
            rx: Vec::new(),
            failed: false,
        };
        let ready = transport.readiness().expect("a wait from outside");
        let started = Instant::now();
        ready.wait_readable(50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "nothing queued: {:?}",
            started.elapsed()
        );
        let beside: std::sync::Arc<dyn LinkReadiness> = std::sync::Arc::new(GroupInput(other));
        let started = Instant::now();
        ready.wait_readable_among(&[std::sync::Arc::clone(&beside)], 50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "nothing queued on either: {:?}",
            started.elapsed()
        );

        peer.send_to(b"member", to).expect("sent");
        let started = Instant::now();
        ready.wait_readable_among(&[beside], 5_000);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a datagram queued: {:?}",
            started.elapsed()
        );
        let started = Instant::now();
        ready.wait_readable(5_000);
        assert!(started.elapsed() < Duration::from_secs(2));

        transport.close();
        assert!(transport.readiness().is_none(), "a group left gives none");
    }

    /// Two members of one group on this host: what one sends reaches the other, from the port of
    /// the sender's own send socket, and a member that left the group reads nothing and is not a
    /// failed link.
    #[test]
    #[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
    fn a_datagram_one_member_sends_reaches_another_from_its_send_socket() {
        let port = UdpSocket::bind("0.0.0.0:0")
            .and_then(|probe| probe.local_addr())
            .expect("a free port")
            .port();
        let endpoint = format!("udp/239.255.77.11:{port}");
        let joiner = HostGroups {
            loopback: Loopback::On,
            ..groups()
        };
        let mut a = joiner.join(&endpoint).expect("member a joins");
        let mut b = joiner.join(&endpoint).expect("member b joins");
        assert!(a.open() && b.open());
        a.send_to_group(b"hello group");
        let mut seen = None;
        for _ in 0..200 {
            if b.recv_with(&mut |bytes, from| seen = Some((bytes.to_vec(), from))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (bytes, from) = seen.expect("the datagram reached the other member");
        assert_eq!(bytes, b"hello group");
        assert_ne!(
            from.port(),
            port,
            "the source is the sender's own send socket"
        );
        b.close();
        assert!(!b.recv_with(&mut |_, _| panic!("a datagram for a member that left")));
        assert!(b.carrier_up(), "a released link is not a failed one");
    }
}
