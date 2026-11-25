// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one dial of an endpoint: its text read once, a host name resolved by the network's
//! resolver, and the walk over the host's addresses that passes from a refused address to the
//! next, at once or when the refusal comes later, answering one refusal once none is left.
//!
//! Dialing is cold: it runs once per link, never per message, so it is one body here for every
//! stack, and a stack's own part of a dial is the link it begins at one address
//! (`SessionLinks::begin_initiator`) and its resolver (`SessionLinks::resolve`). `begin` is
//! where a dial starts; a face holds the [`Begun`] dial and passes it on with
//! `HostWalk::pass_on` when the network refuses the address it is under way to.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::link_cells::CountKind;
use crate::locator_text::{read_dial_target, DialRefused, DialTarget, NamedHost, NamedLink};
use crate::session_drive::{LinkOpenError, LinkProto, SessionLinks};
use crate::transport::Refusal;

/// How many of the addresses a host name resolves to a dial of it tries, one at a time, in the
/// order the resolver answered them (RFC 6724's, as `getaddrinfo` sorts them). Fixed, so a face
/// holds its dial's addresses in the room the session reserved for the face and the resolver's
/// own list is let go of as soon as it is read.
pub const HOST_ADDRESSES: usize = 4;

/// What a place for a resolved address holds until one is written there; never dialled.
const UNRESOLVED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

/// The addresses of a named host a dial has not tried yet, each at the port the name is dialled
/// at, and the link the dial opens at each: it begins the first, and passes to the next in turn
/// when the network refuses the one it dials, at once or later (a connection refused once under
/// way), as zenoh-pico's open walks the resolver's answer
/// (`vendor/zenoh-pico/src/link/transport/tcp/tcp_posix.c` @ `it = it->ai_next`). None for a
/// dial of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostWalk {
    addresses: [SocketAddr; HOST_ADDRESSES],
    count: u8,
    next: u8,
    link: NamedLink,
}

impl HostWalk {
    /// No address to pass to: a dial of an address, or of a host past its last one.
    pub const NONE: Self = Self {
        addresses: [UNRESOLVED; HOST_ADDRESSES],
        count: 0,
        next: 0,
        link: NamedLink::Ip(LinkProto::Udp),
    };

    /// The addresses `links`' network resolves the host `name` to, each to be dialled with its
    /// link; those past the room are not kept (`SessionLinks::resolve`). The resolver may block
    /// for as long as the network's name service takes, so it is asked as a dial begins and
    /// never on a link's way.
    fn of_host<N: CountKind, L: SessionLinks<N>>(name: &NamedHost<'_>, links: &L) -> Self {
        let mut walk = Self {
            link: name.link(),
            ..Self::NONE
        };
        let count = links.resolve(name, &mut walk.addresses);
        walk.count = u8::try_from(count.min(HOST_ADDRESSES)).unwrap_or(0);
        walk
    }

    /// How many addresses are left to dial.
    pub fn left(&self) -> usize {
        usize::from(self.count.saturating_sub(self.next))
    }

    /// Begin a dial over `links` of the next address the network begins, passing over each one
    /// it refuses at once: the stack's dial, or the refusal of the last address tried, which is
    /// `refused` when none is left to try. Out of line: the first address of a host and the
    /// pass from a refused one share this one walk.
    #[inline(never)]
    pub(crate) fn pass_on<N: CountKind, L: SessionLinks<N>>(
        &mut self,
        links: &L,
        refused: LinkOpenError,
    ) -> Result<L::Dial, LinkOpenError> {
        let mut last = refused;
        while self.next < self.count {
            let Some(&at) = self.addresses.get(usize::from(self.next)) else {
                break;
            };
            self.next = self.next.wrapping_add(1);
            match links.begin_initiator(self.link.locator(at)) {
                Ok(pending) => return Ok(pending),
                Err(why) => last = why,
            }
        }
        Err(last)
    }
}

/// A dial begun: the stack's dial, and the addresses of its host it passes to when that one is
/// refused.
pub struct Begun<D> {
    /// The stack's dial of the address it is under way to.
    pub pending: D,
    /// The addresses left after it.
    pub walk: HostWalk,
}

impl<D> Begun<D> {
    /// The dial of an address, with none to pass to.
    pub fn alone(pending: D) -> Self {
        Self {
            pending,
            walk: HostWalk::NONE,
        }
    }
}

/// Begin a dial of `endpoint` over `links`, which the network answers later: of the address it
/// names, or of the first address of the host it names that the network begins, the rest kept
/// for the dial to pass to. The refusal is the locator's for a text no dial reaches
/// ([`read_dial_target`]) and for a host no dial of a name reaches over `links`
/// (`named_refusal`), asked before the resolver; the network's otherwise: the refusal of the
/// last address tried, and, for a host that resolves to no address,
/// [`LinkOpenError::Refused`], an answer of the network a later dial may not meet.
#[cold]
#[inline(never)]
pub(crate) fn begin<N: CountKind, L: SessionLinks<N>>(
    endpoint: &str,
    links: &L,
) -> Result<Begun<L::Dial>, Refusal> {
    let name = match read_dial_target(endpoint) {
        Ok(DialTarget::At(to)) => {
            return links
                .begin_initiator(to)
                .map(Begun::alone)
                .map_err(Refusal::Link)
        }
        Ok(DialTarget::Named(name)) => name,
        Err(refused) => return Err(Refusal::Locator(refused)),
    };
    if let Some(refused) = named_refusal(name.link(), L::RESOLVES) {
        return Err(Refusal::Locator(refused));
    }
    let mut walk = HostWalk::of_host::<N, L>(&name, links);
    match walk.pass_on::<N, L>(links, LinkOpenError::Refused) {
        Ok(pending) => Ok(Begun { pending, walk }),
        Err(refused) => Err(Refusal::Link(refused)),
    }
}

/// Why no dial of a host name reaches `link` over links whose network `resolves` names or does
/// not, or `None` for a name the resolver is asked for: a link that names its peer by the address
/// it dials would check or name an address and never the host written
/// ([`NamedLink::names_peer_by_address`]), and a network without a resolver has no address for
/// any name ([`DialRefused::NoResolver`]).
fn named_refusal(link: NamedLink, resolves: bool) -> Option<DialRefused> {
    if link.names_peer_by_address() {
        Some(DialRefused::PeerNamedByAddress)
    } else {
        (!resolves).then_some(DialRefused::NoResolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `tls/` host is refused by the reason a channel verifies an address, whatever the
    /// network resolves; a `udp/` or `tcp/` host is refused only over a network with no
    /// resolver, and handed to the resolver otherwise. Turned red by a `tls/` host handed to the
    /// resolver, by a name refused over a network that resolves, or by the reasons swapped.
    #[test]
    fn a_host_name_is_refused_before_the_resolver_only_where_no_dial_of_it_reaches() {
        let tls = NamedLink::Ip(LinkProto::Tls);
        assert_eq!(
            named_refusal(tls, true),
            Some(DialRefused::PeerNamedByAddress)
        );
        assert_eq!(
            named_refusal(tls, false),
            Some(DialRefused::PeerNamedByAddress)
        );
        for proto in [LinkProto::Udp, LinkProto::Tcp] {
            let link = NamedLink::Ip(proto);
            assert_eq!(named_refusal(link, true), None, "{proto:?}");
            assert_eq!(
                named_refusal(link, false),
                Some(DialRefused::NoResolver),
                "{proto:?}"
            );
        }
    }

    /// A `ws/` host is refused by the reason its request names an address, as a `tls/` one is.
    /// Turned red by a `ws/` host handed to the resolver.
    #[cfg(feature = "ws")]
    #[test]
    fn a_ws_host_name_is_refused_as_one_its_request_would_name_by_address() {
        assert_eq!(
            named_refusal(NamedLink::Ws, true),
            Some(DialRefused::PeerNamedByAddress)
        );
    }
}
