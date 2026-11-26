// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one dial of an endpoint: its text read once, a host name resolved by the network's
//! resolver, and the walk over the host's addresses that passes from a refused address to the
//! next, at once or when the refusal comes later, answering one refusal once none is left.
//!
//! Dialing is cold: it runs once per link, never per message, so it is one body here for every
//! stack, and a stack's own part of a dial is the link it begins at one address
//! (`SessionLinks::begin_initiator`) and its resolver (`SessionLinks::resolve`). The faces begin
//! a dial here (`LinkSupervisor::begin_dial`), hold the [`Begun`] dial and pass it on with
//! `HostWalk::pass_on` when the network refuses the address it is under way to.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::link_cells::CountKind;
use crate::locator_text::{read_dial_target, DialTarget, NamedHost, NamedLink};
use crate::session_drive::{LinkOpenError, LinkProto, SessionLinks};
use crate::transport::{EndpointRefusal, Refusal, TransportRefusal};

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
/// for the dial to pass to. Refused as [`TransportRefusal::Unreachable`], with the endpoint and
/// why: the locator's refusal for a text no dial over `links` reaches ([`read_dial_target`]),
/// asked before the resolver; the network's otherwise: the refusal of the last address tried,
/// and, for a host that resolves to no address, [`LinkOpenError::Refused`], an answer of the
/// network a later dial may not meet. Out of line and cold: every dial of every face begins here,
/// and each refusal is written into its answer in this one place.
#[cold]
#[inline(never)]
pub(crate) fn begin<N: CountKind, L: SessionLinks<N>>(
    endpoint: &str,
    links: &L,
) -> Result<Begun<L::Dial>, TransportRefusal> {
    begin_on::<N, L>(endpoint, links)
        .map_err(|why| TransportRefusal::Unreachable(EndpointRefusal::new(endpoint, why)))
}

/// `begin`, answering why a dial was refused without the endpoint.
// Always inlined: its one caller writes the endpoint into whichever refusal this answers.
#[inline(always)]
fn begin_on<N: CountKind, L: SessionLinks<N>>(
    endpoint: &str,
    links: &L,
) -> Result<Begun<L::Dial>, Refusal> {
    let name = match read_dial_target(endpoint, L::RESOLVES) {
        Ok(DialTarget::At(to)) => {
            return links
                .begin_initiator(to)
                .map(Begun::alone)
                .map_err(Refusal::Link)
        }
        Ok(DialTarget::Named(name)) => name,
        Err(refused) => return Err(Refusal::Locator(refused)),
    };
    let mut walk = HostWalk::of_host::<N, L>(&name, links);
    let pending = walk
        .pass_on::<N, L>(links, LinkOpenError::Refused)
        .map_err(Refusal::Link)?;
    Ok(Begun { pending, walk })
}
