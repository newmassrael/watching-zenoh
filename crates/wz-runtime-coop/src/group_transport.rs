// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`GroupTransport`] — what a multicast group session needs of the network
//! stack under it.
//!
//! The group drive loop was written against lwIP and named lwIP's types for what
//! it needs of a stack, which is four things: pump the stack's input path, say
//! whether the carrier is up, multicast one datagram to the group, and take one
//! inbound datagram with its source address. This trait is those four. The loop
//! (`wz-session-mcu`'s `group_drive`) is generic over it, as the unicast loop is
//! generic over [`SessionDatagramLink`](crate::session_drive::SessionDatagramLink);
//! lwIP supplies one implementation (`wz-session-lwip`) and Zephyr's sockets
//! another, so a board is not asked to carry the lwIP crate to run a group
//! session over some other stack.
//!
//! It is the multicast twin of that trait and not an extension of it because the
//! two differ where it counts: a unicast link retargets its replies to whoever
//! spoke last and a group never does, and the group's receive carries the source
//! address the §3.2 peer table is keyed by.
//!
//! Two more are the session machine's: `open` and `close` are how the loop
//! performs its `open_multicast_link` and `release_multicast_link` duties, so a
//! transport is the session's link only between the two.

use core::net::{Ipv4Addr, SocketAddr};

/// The interface a group is joined on and sent out of, in the form the group's family names one:
/// IPv4 by an address the interface holds (`IP_ADD_MEMBERSHIP`'s `imr_interface`,
/// `IP_MULTICAST_IF`), IPv6 by its index (`IPV6_JOIN_GROUP`'s `ipv6mr_interface`,
/// `IPV6_MULTICAST_IF`), as upstream zenoh joins an IPv6 group
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.join_multicast_v6(&dst_ip6, 0)`) and
/// sends out of an interface it names by index (`.set_multicast_if_v6(idx)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupInterface {
    /// The interface the stack's routing picks for the group, of either family.
    Routing,
    /// The IPv4 interface that holds this address.
    V4(Ipv4Addr),
    /// The interface of this index, for an IPv6 group. Zero is the stack's choice, as
    /// [`Self::Routing`] is.
    Index(u32),
}

impl GroupInterface {
    /// Whether the interface can be named to a group of `group`'s family: an IPv4 address names
    /// an interface to an IPv4 group only, an index to an IPv6 group only, and the routing's
    /// choice to either.
    pub const fn names_for(self, group: &SocketAddr) -> bool {
        matches!(
            (self, group),
            (GroupInterface::Routing, _)
                | (GroupInterface::V4(_), SocketAddr::V4(_))
                | (GroupInterface::Index(_), SocketAddr::V6(_))
        )
    }
}

/// One group session's whole I/O seam: the socket joined to the group, the group
/// address the loop multicasts to, and whatever the stack needs pumped.
///
/// The loop owns it exclusively for the life of the session (single task, one
/// consumer), which is why the sending and receiving halves take `&mut self`.
pub trait GroupTransport {
    /// Take this transport as the session's group link: the session machine's
    /// `open_multicast_link` duty. `false` when it cannot carry the group (its
    /// socket was released); the session then ends as a lost link before
    /// anything is sent.
    ///
    /// The socket is bound and joined to the group by whoever built the
    /// transport, out of the image's own socket pool, so opening does not bind:
    /// it is what makes that socket the session's link from here on.
    fn open(&mut self) -> bool;

    /// Release the group link: the session machine's `release_multicast_link`
    /// duty. A transport that owns its socket gives it back; one that borrows
    /// it lets the borrow go. Either way it sends and receives nothing after,
    /// and a later `open` fails.
    fn close(&mut self);

    /// Advance the stack's input path and timers by one pass. A stack the loop
    /// must pump (lwIP `NO_SYS`, polled from this thread) does its work here;
    /// one whose input runs on its own thread or ISR does nothing.
    fn service(&self);

    /// Whether the interface the group is joined on has a carrier. Read once per
    /// iteration; `false` ends the session as a lost link. A stack that has no
    /// carrier to report answers `true`.
    fn carrier_up(&self) -> bool;

    /// Multicast one datagram to the group. Best-effort like the AP loop's JOIN
    /// and data emit: multicast UDP has no acknowledgement, a failed send is
    /// non-fatal (the next cadence retries), and the error is dropped.
    fn send_to_group(&mut self, datagram: &[u8]);

    /// Lend the next inbound datagram and its source address to `f` WHERE THE
    /// TRANSPORT HOLDS IT, and let it go once `f` returns; `false` when nothing
    /// is queued. The source is the §3.2 peer key: an opaque equality key, so the
    /// only requirement is that one peer's datagrams always carry the same one.
    /// `f` must not call back into the transport.
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    /// An interface is named to a group in the group's own family, and the routing's choice to
    /// either: an address to an IPv6 group, or an index to an IPv4 one, names nothing.
    #[test]
    fn an_interface_is_named_to_a_group_of_its_own_family() {
        let v4 = SocketAddr::from(([224, 0, 0, 224], 7446));
        let v6 = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 7446));
        let address = GroupInterface::V4(Ipv4Addr::new(10, 0, 0, 2));
        let index = GroupInterface::Index(2);
        assert!(GroupInterface::Routing.names_for(&v4));
        assert!(GroupInterface::Routing.names_for(&v6));
        assert!(address.names_for(&v4));
        assert!(!address.names_for(&v6));
        assert!(index.names_for(&v6));
        assert!(!index.names_for(&v4));
    }
}
