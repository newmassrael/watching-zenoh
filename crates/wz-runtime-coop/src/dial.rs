// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one dial of an endpoint: its text read once, a host name resolved by the network's
//! resolver, and the walk over the host's addresses that passes from a refused address to the
//! next, at once or, with `dial-in-flight`, when the refusal comes later, answering one refusal
//! once none is left.
//!
//! Dialing is cold: it runs once per link, never per message. Its plane is one body generic over
//! nothing, [`dial_step`], which reads a [`LinkPlan`] (the endpoint's text, as the open wrote it
//! in the session's row, and whether the network resolves names) and a [`DialCursor`], and answers
//! what the dial asks of the stack next ([`DialAsk`]): a link begun at an address, a host
//! resolved, or the dial's refusal. What touches the stack's own types is the short shell that
//! does what it is asked (`begin`, `HostWalk::pass_on`): the stack begins a link at one
//! address (`SessionLinks::begin_initiator`) and resolves a name (`SessionLinks::resolve`), and
//! no trait object is made for the plane. The faces begin a dial here
//! (`LinkSupervisor::begin_dial`), hold the [`Begun`] dial and, with `dial-in-flight`, pass it on
//! with `HostWalk::pass_on` when the network refuses the address it is under way to. Without it
//! a begun dial keeps no address to pass to: the IP stack's dial is answered in the call that
//! begins it, so the walk of `begin` meets each refusal of it, as zenoh-pico's open walks the
//! resolver's answer inside its one call, and a dial another stack answers later is refused by
//! the refusal it answers.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::link_cells::CountKind;
#[cfg(feature = "dial-address-reader")]
use crate::locator_text::read_dial_target;
#[cfg(not(feature = "dial-address-reader"))]
use crate::locator_text::{read_dial_address, read_dial_host, DialRefused};
use crate::locator_text::{DialTarget, NamedHost, NamedLink};
use crate::session_drive::{LinkOpenError, LinkProto, Locator, SessionLinks};
use crate::transport::{EndpointRefusal, Refusal, TransportRefusal};

/// How many of the addresses a host name resolves to a dial of it tries, one at a time, in the
/// order the resolver answered them (RFC 6724's, as `getaddrinfo` sorts them). Fixed, so a face
/// holds its dial's addresses in the room the session reserved for the face and the resolver's
/// own list is let go of as soon as it is read.
pub const HOST_ADDRESSES: usize = 4;

/// What a place for a resolved address holds until one is written there; never dialled.
const UNRESOLVED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

/// What a dial of one endpoint is planned from, values of no type of the stack's: the endpoint's
/// text, as the open wrote it in the session's row of endpoints to dial, and whether the network
/// the dial runs on answers a host name with its addresses (`SessionLinks::RESOLVES`). Without
/// `dial-address-reader` the plan holds the reader of the text for that network in its place
/// (`read_dial_host` where it resolves, `read_dial_address` where it does not), picked where
/// the plan is made from the stack's constant, so a build links the readers its stacks read with
/// and no other.
#[derive(Debug, Clone, Copy)]
pub struct LinkPlan<'a> {
    endpoint: &'a str,
    #[cfg(feature = "dial-address-reader")]
    resolves: bool,
    #[cfg(not(feature = "dial-address-reader"))]
    read: fn(&'a str) -> Result<DialTarget<'a>, DialRefused>,
}

impl<'a> LinkPlan<'a> {
    /// The plan of a dial of `endpoint` over a network that `resolves` host names or not.
    // Always inlined, so the stack's constant picks the reader where the plan is made.
    #[inline(always)]
    pub fn new(endpoint: &'a str, resolves: bool) -> Self {
        Self {
            endpoint,
            #[cfg(feature = "dial-address-reader")]
            resolves,
            #[cfg(not(feature = "dial-address-reader"))]
            read: if resolves {
                read_dial_host
            } else {
                read_dial_address
            },
        }
    }

    /// The endpoint dialled.
    pub fn endpoint(&self) -> &'a str {
        self.endpoint
    }

    /// The dial's refusal for `why`: the endpoint is one the session dials, so it is refused as
    /// one the session cannot reach, naming it.
    pub fn refused(&self, why: Refusal) -> TransportRefusal {
        TransportRefusal::Unreachable(EndpointRefusal::new(self.endpoint, why))
    }
}

/// The addresses of a named host a dial has not tried yet, each at the port the name is dialled
/// at, and the link the dial opens at each: it begins the first, and passes to the next in turn
/// when the network refuses the one it dials, at once or, with `dial-in-flight`, later (a
/// connection refused once under way), as zenoh-pico's open walks the resolver's answer
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

    /// How many addresses are left to dial.
    pub fn left(&self) -> usize {
        usize::from(self.count.saturating_sub(self.next))
    }

    /// The locator of the next address left, which is then passed: `None` once none is left.
    fn next_locator(&mut self) -> Option<Locator> {
        if self.next >= self.count {
            return None;
        }
        let at = *self.addresses.get(usize::from(self.next))?;
        self.next = self.next.wrapping_add(1);
        Some(self.link.locator(at))
    }

    /// Begin a dial over `links` of the next address the network begins, passing over each one
    /// it refuses at once: the stack's dial, or the refusal of the last address tried, which is
    /// `refused` when none is left to try. Out of line: every dial a face passes on is begun by
    /// this one shell, and the walk itself is `next_locator`'s, generic over nothing.
    #[cfg(feature = "dial-in-flight")]
    #[inline(never)]
    pub(crate) fn pass_on<N: CountKind, L: SessionLinks<N>>(
        &mut self,
        links: &L,
        refused: LinkOpenError,
    ) -> Result<L::Dial, LinkOpenError> {
        let mut last = refused;
        while let Some(to) = self.next_locator() {
            match links.begin_initiator(to) {
                Ok(pending) => return Ok(pending),
                Err(why) => last = why,
            }
        }
        Err(last)
    }
}

/// Where a dial of one plan stands: whether its endpoint's text was read, and the addresses of
/// the host it names that are left to dial. A dial begins at [`DialCursor::START`] and keeps its
/// [`HostWalk`] once a link is begun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialCursor {
    read: bool,
    walk: HostWalk,
}

impl DialCursor {
    /// A dial whose endpoint has not been read yet.
    pub const START: Self = Self {
        read: false,
        walk: HostWalk::NONE,
    };

    /// The room the network's resolver writes the host's addresses in, at the front, when the
    /// dial asks for them ([`DialAsk::Resolve`]).
    pub fn room(&mut self) -> &mut [SocketAddr] {
        &mut self.walk.addresses
    }

    /// The resolver wrote `count` addresses at the front of [`Self::room`]: those past the room
    /// are not kept, and the dial walks them from the first.
    pub fn resolved(&mut self, count: usize) {
        self.walk.count = u8::try_from(count.min(HOST_ADDRESSES)).unwrap_or(0);
        self.walk.next = 0;
    }

    /// The addresses left after the one a link was begun at, for the dial to pass to later.
    pub fn walk(&self) -> HostWalk {
        self.walk
    }
}

/// What a dial asks of the stack next ([`dial_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialAsk<'a> {
    /// Begin a link at this locator: the address the endpoint names, or the next of its host's.
    Begin(Locator),
    /// Resolve this host into the cursor's room ([`DialCursor::room`]) and tell the cursor how
    /// many addresses were written ([`DialCursor::resolved`]).
    Resolve(NamedHost<'a>),
    /// No link is begun: why. The endpoint's own refusal for a text no dial reaches, read before
    /// any resolver is asked; the network's otherwise, the refusal of the last address tried, and
    /// [`LinkOpenError::Refused`] for a host that resolves to no address, an answer of the
    /// network a later dial may not meet.
    Refused(Refusal),
}

/// The next move of the dial of `plan` at `at`, after `last`, the network's refusal of the
/// address the dial was last asked to begin at (`None` when it asked none or the resolver was
/// asked): the endpoint's text is read at the first step, and an address it names is begun with
/// no address to pass to; a host it names is resolved, then each of its addresses begun in turn
/// until one is not refused at once. Out of line and generic over nothing: every dial of every
/// stack reads its text and walks its host here, in one body.
#[cold]
#[inline(never)]
pub fn dial_step<'a>(
    plan: &LinkPlan<'a>,
    at: &mut DialCursor,
    last: Option<LinkOpenError>,
) -> DialAsk<'a> {
    if !at.read {
        at.read = true;
        #[cfg(feature = "dial-address-reader")]
        let target = read_dial_target(plan.endpoint, plan.resolves);
        #[cfg(not(feature = "dial-address-reader"))]
        let target = (plan.read)(plan.endpoint);
        return match target {
            Ok(DialTarget::At(to)) => DialAsk::Begin(to),
            Ok(DialTarget::Named(name)) => {
                at.walk.link = name.link();
                DialAsk::Resolve(name)
            }
            Err(refused) => DialAsk::Refused(Refusal::Locator(refused)),
        };
    }
    match at.walk.next_locator() {
        Some(to) => DialAsk::Begin(to),
        None => DialAsk::Refused(Refusal::Link(last.unwrap_or(LinkOpenError::Refused))),
    }
}

/// A dial begun: the stack's dial, and, with `dial-in-flight`, the addresses of its host it
/// passes to when that one is refused once under way.
pub struct Begun<D> {
    /// The stack's dial of the address it is under way to.
    pub pending: D,
    /// The addresses left after it.
    #[cfg(feature = "dial-in-flight")]
    pub walk: HostWalk,
}

impl<D> Begun<D> {
    /// The dial of an address, with none to pass to.
    pub fn alone(pending: D) -> Self {
        Self {
            pending,
            #[cfg(feature = "dial-in-flight")]
            walk: HostWalk::NONE,
        }
    }
}

/// Begin a dial of `endpoint` over `links`, which the network answers later: of the address it
/// names, or of the first address of the host it names that the network begins, the rest kept
/// for the dial to pass to with `dial-in-flight`. Refused as [`TransportRefusal::Unreachable`],
/// with the endpoint and why ([`DialAsk::Refused`]). The shell of [`dial_step`] over the stack: it does what the
/// dial asks and nothing else, so its body is the stack's two calls and the loop.
#[cold]
#[inline(never)]
pub(crate) fn begin<N: CountKind, L: SessionLinks<N>>(
    endpoint: &str,
    links: &L,
) -> Result<Begun<L::Dial>, TransportRefusal> {
    let plan = LinkPlan::new(endpoint, L::RESOLVES);
    let mut at = DialCursor::START;
    let mut last = None;
    loop {
        match dial_step(&plan, &mut at, last) {
            DialAsk::Begin(to) => match links.begin_initiator(to) {
                Ok(pending) => {
                    return Ok(Begun {
                        pending,
                        #[cfg(feature = "dial-in-flight")]
                        walk: at.walk(),
                    })
                }
                Err(why) => last = Some(why),
            },
            DialAsk::Resolve(name) => {
                let found = links.resolve(&name, at.room());
                at.resolved(found);
            }
            DialAsk::Refused(why) => return Err(plan.refused(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use super::{dial_step, DialAsk, DialCursor, LinkPlan, HOST_ADDRESSES};
    use crate::locator_text::DialRefused;
    use crate::session_drive::{LinkOpenError, LinkProto, Locator};
    use crate::transport::{EndpointRefusal, Refusal, TransportRefusal};

    const HOST: &str = "tcp/router.example:7447";

    fn tcp(at: SocketAddr) -> DialAsk<'static> {
        DialAsk::Begin(Locator::ip(LinkProto::Tcp, at))
    }

    /// The host's addresses as a resolver answers them, at the name's port.
    fn addresses() -> [SocketAddr; 2] {
        [
            SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 7447)),
            SocketAddr::from(([127, 0, 0, 1], 7447)),
        ]
    }

    /// A dial of `HOST` stepped past its resolve, the resolver having written `found`.
    fn resolved(plan: &LinkPlan<'static>, found: &[SocketAddr]) -> DialCursor {
        let mut at = DialCursor::START;
        let DialAsk::Resolve(name) = dial_step(plan, &mut at, None) else {
            panic!("a host name is resolved first");
        };
        assert_eq!((name.host(), name.port()), ("router.example", 7447));
        for (place, address) in at.room().iter_mut().zip(found) {
            *place = *address;
        }
        at.resolved(found.len());
        at
    }

    /// An address is begun at the first step, with no resolver asked and no address to pass to;
    /// its refusal is the dial's. Read over a network without a resolver, whose dial reads an
    /// address with or without `dial-address-reader`. Turned red by an address read as a name, or
    /// a refusal of the address that asks for another one.
    #[test]
    fn an_address_is_begun_at_once_and_its_refusal_is_the_dials() {
        let plan = LinkPlan::new("tcp/127.0.0.1:7447", false);
        let mut at = DialCursor::START;
        assert_eq!(
            dial_step(&plan, &mut at, None),
            tcp(SocketAddr::from(([127, 0, 0, 1], 7447)))
        );
        assert_eq!(at.walk().left(), 0, "an address has none to pass to");
        assert_eq!(
            dial_step(&plan, &mut at, Some(LinkOpenError::Unsupported)),
            DialAsk::Refused(Refusal::Link(LinkOpenError::Unsupported))
        );
    }

    /// A host whose first address the network refuses is dialled at its second, in the order the
    /// resolver answered; the refusal of the last address tried is the dial's. Turned red when the
    /// walk stops at the first refusal, dials out of order, or answers an earlier refusal.
    #[test]
    fn an_endpoint_whose_first_address_refuses_dials_the_second() {
        let plan = LinkPlan::new(HOST, true);
        let [v6, v4] = addresses();
        let mut at = resolved(&plan, &[v6, v4]);
        assert_eq!(dial_step(&plan, &mut at, None), tcp(v6));
        assert_eq!(at.walk().left(), 1);
        assert_eq!(
            dial_step(&plan, &mut at, Some(LinkOpenError::Refused)),
            tcp(v4)
        );
        assert_eq!(at.walk().left(), 0);
        assert_eq!(
            dial_step(&plan, &mut at, Some(LinkOpenError::Exhausted)),
            DialAsk::Refused(Refusal::Link(LinkOpenError::Exhausted))
        );
    }

    /// A host that resolves to no address is refused as a link the other end did not take, which
    /// a later dial may find. Turned red by a refusal for good, or a dial begun at a place no
    /// address was written in.
    #[test]
    fn a_host_of_no_address_is_refused_as_not_taken() {
        let plan = LinkPlan::new(HOST, true);
        let mut at = resolved(&plan, &[]);
        assert_eq!(
            dial_step(&plan, &mut at, None),
            DialAsk::Refused(Refusal::Link(LinkOpenError::Refused))
        );
    }

    /// The resolver's addresses past the room are not kept. Turned red by a count past the room,
    /// which would walk addresses never written.
    #[test]
    fn addresses_past_the_room_are_not_kept() {
        let plan = LinkPlan::new(HOST, true);
        let mut at = DialCursor::START;
        assert!(matches!(
            dial_step(&plan, &mut at, None),
            DialAsk::Resolve(_)
        ));
        at.resolved(HOST_ADDRESSES + 3);
        assert_eq!(at.walk().left(), HOST_ADDRESSES);
    }

    /// A name is refused at the first step, before any resolver is asked, where no dial of it
    /// reaches the host written: over a network without a resolver, and over a link that names
    /// its peer by the address it dials. Turned red by a resolve asked for either.
    #[test]
    fn a_name_no_dial_reaches_is_refused_before_the_resolver() {
        let mut at = DialCursor::START;
        assert_eq!(
            dial_step(&LinkPlan::new(HOST, false), &mut at, None),
            DialAsk::Refused(Refusal::Locator(DialRefused::NoResolver))
        );
        let mut at = DialCursor::START;
        assert_eq!(
            dial_step(
                &LinkPlan::new("tls/router.example:7447", true),
                &mut at,
                None
            ),
            DialAsk::Refused(Refusal::Locator(DialRefused::PeerNamedByAddress))
        );
    }

    /// Without `dial-address-reader` an address over a network that resolves is its resolver's to
    /// read: the first step asks for it, out of its brackets, and the address the resolver answers
    /// is begun next, with none left to pass to. Turned red by an address read by the reader of
    /// addresses over such a network (a `Begin` at the first step).
    #[cfg(not(feature = "dial-address-reader"))]
    #[test]
    fn an_address_without_its_reader_is_the_resolvers_to_read() {
        let found = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 7447));
        let plan = LinkPlan::new("tcp/[::1]:7447", true);
        let mut at = DialCursor::START;
        let DialAsk::Resolve(name) = dial_step(&plan, &mut at, None) else {
            panic!("the address is handed to the resolver");
        };
        assert_eq!((name.host(), name.port()), ("::1", 7447));
        if let Some(place) = at.room().first_mut() {
            *place = found;
        }
        at.resolved(1);
        assert_eq!(dial_step(&plan, &mut at, None), tcp(found));
        assert_eq!(at.walk().left(), 0, "the one address is begun");
    }

    /// A dial's refusal names its endpoint as one the session dials, never one it listens on.
    /// Turned red when the roles are swapped, or the endpoint is left out.
    #[test]
    fn a_refused_dial_names_its_endpoint_as_one_to_dial() {
        let why = Refusal::Link(LinkOpenError::Refused);
        assert_eq!(
            LinkPlan::new(HOST, true).refused(why),
            TransportRefusal::Unreachable(EndpointRefusal::new(HOST, why))
        );
    }
}
