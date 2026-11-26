// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A multicast group's sockets as a node on a host opens them, without `std`: the joined socket
//! that reads the group, the socket a member sends from, and the policy both are made by.
//!
//! A multicast socket is made of policy as well as of calls: which interface an `#iface=` names,
//! what a link that names none joins and sends on, whether a refused membership ends the open,
//! which loopback a group gets, what the hop limit is, which address the sender binds. The rules
//! are the tokio runtime's (its host crate, `wz-host-net`, makes the same two sockets over
//! `socket2` for the AP engine), written here over the host's own sockets ([`MulticastSocket`]), so
//! that a host library without `std` opens a group as the one with it does. [`bind_joined`] makes
//! the socket that receives a group, [`bind_sender`] the one that only sends; each is bound,
//! non-blocking, and handed over with the group address its datagrams are written to.
//!
//! [`HostGroupTransport`] is the two as the transport of a session's group face, which the shared
//! group drive loop runs on: a datagram is taken when one is queued and never waited for, since
//! the wait is the engine's, which steps its groups at their tick.

use alloc::vec::Vec;
use core::ffi::c_int;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use wz_runtime_coop::group_transport::{GroupInterface, GroupRx, GroupSend, GroupTransport};
use wz_runtime_coop::udp_link::{unspecified_like, UDP_RX_CAPACITY};
use wz_session_core::byte_cells::ByteBuf;
use wz_session_core::group_locator::sent_by_own;
use wz_session_core::text_out::AddrText;

use crate::group::MulticastSocket;
use crate::interfaces::{self, IfaceResolveError};

/// Whether a same-host member of a group observes what a socket sends, as the
/// `multicast-loopback` policy states it. `OsDefault` sets nothing, which is what upstream does.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Loopback {
    /// Leave the system's setting alone.
    #[default]
    OsDefault,
    /// Set the loopback on.
    On,
    /// Set the loopback off.
    Off,
}

/// The multicast keys a UDP locator's `#` span carries, and the two link policies, as one value.
/// `Default` is a locator that states none: no interface pin, no extra groups, the system's hop
/// limit and loopback, an unpinned link allowed. The traffic class (`#dscp=`) is not here: it marks
/// the send socket once made ([`mark_traffic_class`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct SocketConfig<'a> {
    /// `#iface=<name-or-address>`: the interface the membership is installed on and egress leaves
    /// by.
    pub iface: Option<&'a str>,
    /// `#ttl=<n>`: the hop limit. `None` leaves the system's, which is 1: one subnet.
    pub ttl: Option<u32>,
    /// `#join=<group>` groups, joined beside the locator's own group, each of its family.
    pub extra_joins: &'a [IpAddr],
    /// `#bind=<address:port>`: the local address of the SENDING socket, of the group's family. The
    /// joined socket binds the wildcard of its family, or it would not receive the group.
    pub bind: Option<SocketAddr>,
    /// The `multicast-loopback` policy.
    pub loopback: Loopback,
    /// The `multicast-link-requires-iface` policy: a multicast LINK whose locator resolved to no
    /// interface is refused. A scouting socket is not a link and does not read it.
    pub link_requires_iface: bool,
}

/// What a joined socket binds locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxBind {
    /// The family's wildcard: what a multicast LINK reads on.
    Wildcard,
    /// The group address itself, where the platform lets a socket bind one: what a SCOUTING
    /// socket reads on.
    Group,
}

impl RxBind {
    /// Whether an IPv4 membership the kernel refuses is logged and passed over rather than ending
    /// the open: a scouting socket's, as upstream's scouting socket goes on past a join it is
    /// refused; a link's membership is the link, and its refusal ends it.
    fn skips_a_refused_v4_join(self) -> bool {
        match self {
            Self::Wildcard => false,
            Self::Group => true,
        }
    }
}

/// Why a locator's keys make no socket, found before any socket exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// `#iface=` is an address of the other family than the group's.
    IfaceFamily,
    /// `#iface=` names an interface that is absent, down or without a carrier.
    Iface(IfaceResolveError),
    /// `#iface=` names an interface that holds no address of the group's family. Upstream falls
    /// back on another interface there; a config that named one interface is not given another.
    IfaceHoldsNoAddress,
    /// `#iface=` is an IPv6 address that this many interfaces hold, where exactly one names an
    /// interface.
    IfaceHolders(usize),
    /// A `#join=` group is of the other family than the locator group's.
    Join,
    /// `#bind=` is an address of the other family than the group's.
    Bind,
    /// `#ttl=` is above the largest hop limit a datagram can carry.
    Ttl(u32),
    /// The `multicast-link-requires-iface` policy refuses a link whose locator chose no interface.
    NoInterfaceChosen,
    /// No interface holds the IPv6 address a link sends from, so it has no interface to leave by.
    NoHolder(Ipv6Addr),
    /// The interface of the IPv6 address a link sends from could not be resolved.
    Holder(Ipv6Addr, IfaceResolveError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IfaceFamily => f.write_str(
                "#iface= is an address of the other family than the group's (the protocols must \
                 match)",
            ),
            Self::Iface(e) => write!(f, "the interface #iface= names is {e}"),
            Self::IfaceHoldsNoAddress => f.write_str(
                "the interface #iface= names holds no address of the group's family, and no other \
                 interface is pinned in its place",
            ),
            Self::IfaceHolders(0) => {
                f.write_str("#iface= is an address no local interface holds")
            }
            Self::IfaceHolders(n) => write!(
                f,
                "#iface= is an address {n} interfaces hold, so it names none; give the interface's \
                 name instead"
            ),
            Self::Join => f.write_str("a #join= value is not a group of the locator's family"),
            Self::Bind => f.write_str("#bind= is not a literal address of the group's family"),
            Self::Ttl(ttl) => write!(f, "#ttl={ttl} is above the largest hop limit, 255"),
            Self::NoInterfaceChosen => f.write_str(
                "a multicast link needs an interface its locator chose (#iface=), and this one has \
                 none, so the multicast-link-requires-iface policy refuses it",
            ),
            Self::NoHolder(address) => write!(
                f,
                "no interface holds {}: a multicast link sends from an address of the \
                 interface it leaves by",
                AddrText(IpAddr::V6(*address))
            ),
            Self::Holder(address, e) => write!(
                f,
                "the interface of {} could not be resolved: {e}",
                AddrText(IpAddr::V6(*address))
            ),
        }
    }
}

/// Why a group's socket was not made: its locator's keys, or a call of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastError<E> {
    /// The locator's keys make no socket.
    Plan(PlanError),
    /// A call of the socket failed.
    Socket(E),
}

impl<E> From<PlanError> for MulticastError<E> {
    fn from(refused: PlanError) -> Self {
        Self::Plan(refused)
    }
}

impl<E: fmt::Debug> fmt::Display for MulticastError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(refused) => fmt::Display::fmt(refused, f),
            Self::Socket(e) => write!(f, "a call of its socket failed: {e:?}"),
        }
    }
}

/// Whether [`Plan::resolve`] reads `#join=`. A sender installs no membership, so it neither uses
/// nor refuses the list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinsRead {
    Yes,
    No,
}

/// A group and its locator's keys, resolved for the group's family before any socket exists: an
/// IPv4 interface is named by one of its addresses and an IPv6 one by its index, and a `#join=`
/// group is of the locator group's family.
///
/// Where the IPv6 arm differs from upstream, as the tokio runtime's does: a stated hop limit is
/// applied (upstream warns that it cannot), and the membership is installed on the pinned
/// interface (upstream joins an IPv6 group on interface 0 whatever `iface` names), so `#iface=`
/// means the same thing for either family.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    V4 {
        group: Ipv4Addr,
        iface: Option<Ipv4Addr>,
        joins: Vec<Ipv4Addr>,
    },
    V6 {
        group: Ipv6Addr,
        iface: Option<u32>,
        joins: Vec<Ipv6Addr>,
    },
}

/// Every `#join=` group as an address of the locator group's family (`of_family`), or the refusal
/// of the first of the other family, before any membership is installed: a receiver joined to some
/// of what it was told looks configured and is not.
fn joins_of<A>(joins: &[IpAddr], of_family: fn(IpAddr) -> Option<A>) -> Result<Vec<A>, PlanError> {
    joins
        .iter()
        .map(|join| of_family(*join).ok_or(PlanError::Join))
        .collect()
}

/// `address` when it is an IPv4 one.
fn v4_of(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// `address` when it is an IPv6 one.
fn v6_of(address: IpAddr) -> Option<Ipv6Addr> {
    match address {
        IpAddr::V6(v6) => Some(v6),
        IpAddr::V4(_) => None,
    }
}

/// The warning of an `#iface=` this host cannot resolve: the socket is left on the system's
/// interface, as a locator with no key is, and the key is never silently dropped.
fn unresolved(iface: &str) {
    wz_session_core::diag_warn!(
        "wz: locator #iface={iface} ignored for multicast \
         (interface resolution unavailable on this platform)"
    );
}

/// The `#iface=` of an IPv4 group: an address literal is the selector itself; a name is its
/// interface's first IPv4 address, once the interface is shown to be there, up and running.
fn iface_selector_v4(iface: &str) -> Result<Option<Ipv4Addr>, PlanError> {
    if let Ok(address) = iface.parse::<Ipv4Addr>() {
        return Ok(Some(address));
    }
    if iface.parse::<Ipv6Addr>().is_ok() {
        return Err(PlanError::IfaceFamily);
    }
    match interfaces::unicast_addresses_of_interface(iface) {
        Ok(addresses) => addresses
            .iter()
            .find_map(|address| match address {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .map(Some)
            .ok_or(PlanError::IfaceHoldsNoAddress),
        Err(IfaceResolveError::Undetermined) => {
            unresolved(iface);
            Ok(None)
        }
        Err(e) => Err(PlanError::Iface(e)),
    }
}

/// The `#iface=` of an IPv6 group, as the index its join and its egress take: an address literal
/// is the index of the one interface that holds it; a name is that interface's own index, once
/// the interface is shown to be there, up, running and holding an IPv6 address.
fn iface_selector_v6(iface: &str) -> Result<Option<u32>, PlanError> {
    if iface.parse::<Ipv4Addr>().is_ok() {
        return Err(PlanError::IfaceFamily);
    }
    if let Ok(address) = iface.parse::<Ipv6Addr>() {
        return match interfaces::interface_indices_of_address(IpAddr::V6(address)) {
            Ok(holders) => match holders.as_slice() {
                [index] => Ok(Some(*index)),
                several => Err(PlanError::IfaceHolders(several.len())),
            },
            Err(IfaceResolveError::Undetermined) => {
                unresolved(iface);
                Ok(None)
            }
            Err(e) => Err(PlanError::Iface(e)),
        };
    }
    match interfaces::unicast_addresses_of_interface(iface) {
        Ok(addresses) if addresses.iter().any(IpAddr::is_ipv6) => {
            match interfaces::interface_index_of_name(iface) {
                Ok(index) => Ok(Some(index)),
                Err(IfaceResolveError::Undetermined) => {
                    unresolved(iface);
                    Ok(None)
                }
                Err(e) => Err(PlanError::Iface(e)),
            }
        }
        Ok(_) => Err(PlanError::IfaceHoldsNoAddress),
        Err(IfaceResolveError::Undetermined) => {
            unresolved(iface);
            Ok(None)
        }
        Err(e) => Err(PlanError::Iface(e)),
    }
}

/// The hop limit `#ttl=` states, refused above what a datagram's header can carry.
fn hop_limit(cfg: &SocketConfig<'_>) -> Result<Option<u8>, PlanError> {
    cfg.ttl
        .map(|ttl| u8::try_from(ttl).map_err(|_| PlanError::Ttl(ttl)))
        .transpose()
}

impl Plan {
    /// Resolve `#iface=` and, for a receiver, `#join=` against the group's family, the interface
    /// first.
    fn resolve(group: IpAddr, cfg: &SocketConfig<'_>, joins: JoinsRead) -> Result<Self, PlanError> {
        Ok(match group {
            IpAddr::V4(group) => Self::V4 {
                group,
                iface: match cfg.iface {
                    Some(iface) => iface_selector_v4(iface)?,
                    None => None,
                },
                joins: match joins {
                    JoinsRead::Yes => joins_of(cfg.extra_joins, v4_of)?,
                    JoinsRead::No => Vec::new(),
                },
            },
            IpAddr::V6(group) => Self::V6 {
                group,
                iface: match cfg.iface {
                    Some(iface) => iface_selector_v6(iface)?,
                    None => None,
                },
                joins: match joins {
                    JoinsRead::Yes => joins_of(cfg.extra_joins, v6_of)?,
                    JoinsRead::No => Vec::new(),
                },
            },
        })
    }

    /// The interface an UNPINNED IPv4 multicast link joins and sends on: the first non-loopback
    /// IPv4 address of `candidates`, as upstream's link fills its local address from the
    /// unicast addresses of the multicast interfaces and joins and sends on it. An interface the
    /// locator pinned is kept, an IPv6 plan is unchanged (upstream joins it on index 0), and a host
    /// with no such address stays on the system's choice.
    fn with_link_default_iface(self, candidates: Option<Vec<IpAddr>>) -> Self {
        match self {
            Self::V4 {
                group,
                iface: None,
                joins,
            } => Self::V4 {
                group,
                iface: candidates.and_then(|addresses| {
                    addresses.into_iter().find_map(|address| match address {
                        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
                        _ => None,
                    })
                }),
                joins,
            },
            other => other,
        }
    }

    /// Whether the locator resolved to an interface: an `#iface=` this host could not resolve
    /// leaves the plan unpinned, as no key does, which is why this reads the plan and not the key.
    fn interface_is_chosen(&self) -> bool {
        match self {
            Self::V4 { iface, .. } => iface.is_some(),
            Self::V6 { iface, .. } => iface.is_some(),
        }
    }

    /// The `multicast-link-requires-iface` rule for a link, read on the plan [`Self::resolve`]
    /// made and before [`Self::with_link_default_iface`] fills one in, since the default is the
    /// choice nobody made; before any socket, so a refusal leaves no membership behind.
    fn require_chosen_interface(&self, cfg: &SocketConfig<'_>) -> Result<(), PlanError> {
        if cfg.link_requires_iface && !self.interface_is_chosen() {
            return Err(PlanError::NoInterfaceChosen);
        }
        Ok(())
    }

    /// The group itself, as an address.
    fn group(&self) -> IpAddr {
        match self {
            Self::V4 { group, .. } => IpAddr::V4(*group),
            Self::V6 { group, .. } => IpAddr::V6(*group),
        }
    }

    /// The wildcard address of the group's family on `port`.
    fn wildcard(&self, port: u16) -> SocketAddr {
        SocketAddr::new(unspecified_like(self.group()), port)
    }

    /// Where a datagram is written: the group itself.
    fn peer(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.group(), port)
    }

    /// What a joined socket binds: the wildcard, or the group itself where the caller reads on it
    /// and the platform lets a socket be bound to one. Windows binds the IPv4 wildcard whatever the
    /// family, as upstream's scouting socket does there.
    fn rx_bind_addr(&self, port: u16, rx_bind: RxBind) -> SocketAddr {
        match rx_bind {
            RxBind::Wildcard => self.wildcard(port),
            RxBind::Group if cfg!(unix) => self.peer(port),
            RxBind::Group => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        }
    }

    /// The local address the SENDING socket binds: `#bind=` when given, refused when it is of the
    /// other family than the group's; else the
    /// family's wildcard on a port the system picks. Either is then filled when it is unspecified
    /// ([`Self::fill_unspecified`]), as upstream fills the local address of its link.
    fn egress_local_addr(
        &self,
        bind: Option<SocketAddr>,
        iface: Option<&str>,
    ) -> Result<SocketAddr, PlanError> {
        let Some(local) = bind else {
            return Ok(self.fill_unspecified(self.wildcard(0), iface));
        };
        if local.is_ipv4() != self.group().is_ipv4() {
            return Err(PlanError::Bind);
        }
        Ok(self.fill_unspecified(local, iface))
    }

    /// Upstream's fill of an unspecified send address: the `#iface=` value's address of the
    /// group's family when the plan honoured one, else the first non-loopback address of the
    /// group's family on an interface that can carry multicast, else the wildcard unchanged. A
    /// specified address is returned as it is. An IPv6 link-local address is bound with its
    /// interface's scope, which the system needs to bind it at all; one whose interface cannot be
    /// named leaves the wildcard.
    fn fill_unspecified(&self, address: SocketAddr, iface: Option<&str>) -> SocketAddr {
        if !address.ip().is_unspecified() {
            return address;
        }
        let v6 = matches!(self, Self::V6 { .. });
        let of_family = |ip: &IpAddr| ip.is_ipv6() == v6;
        let chosen = match (self, iface) {
            (
                Self::V4 {
                    iface: Some(ip), ..
                },
                _,
            ) => Some(IpAddr::V4(*ip)),
            (Self::V6 { iface: Some(_), .. }, Some(name)) => match name.parse::<IpAddr>() {
                Ok(ip) => Some(ip).filter(of_family),
                Err(_) => interfaces::unicast_addresses_of_interface(name)
                    .ok()
                    .and_then(|ips| ips.into_iter().find(of_family)),
            },
            _ => interfaces::unicast_addresses_of_multicast_interfaces().and_then(|ips| {
                ips.into_iter()
                    .find(|ip| !ip.is_loopback() && of_family(ip))
            }),
        };
        let Some(ip) = chosen else {
            return address;
        };
        let mut filled = SocketAddr::new(ip, address.port());
        if let (SocketAddr::V6(v6address), IpAddr::V6(ip6)) = (&mut filled, ip) {
            // `fe80::/10`.
            if ip6.segments()[0] & 0xffc0 == 0xfe80 {
                let scope = match self {
                    Self::V6 {
                        iface: Some(index), ..
                    } => Some(*index),
                    _ => interfaces::interface_indices_of_address(ip)
                        .ok()
                        .and_then(|indices| indices.into_iter().next()),
                };
                match scope {
                    Some(scope) => v6address.set_scope_id(scope),
                    None => return address,
                }
            }
        }
        filled
    }

    /// The egress interface, when the plan has one.
    fn pin_egress<S: MulticastSocket>(&self, socket: &S) -> Result<(), S::Error> {
        match self {
            Self::V4 {
                iface: Some(address),
                ..
            } => socket.set_multicast_interface(GroupInterface::V4(*address)),
            Self::V6 {
                iface: Some(index), ..
            } => socket.set_multicast_interface(GroupInterface::Index(*index)),
            _ => Ok(()),
        }
    }

    /// The egress interface of a multicast LINK's send socket: the interface of the address it
    /// binds, `local`, as upstream's link sets it on its send socket. An IPv6 address no interface
    /// holds refuses the link; where there is no address to read one from (a host whose table
    /// cannot be read, the IPv6 wildcard) the plan's own egress is kept.
    fn pin_link_egress<S: MulticastSocket>(
        &self,
        socket: &S,
        local: SocketAddr,
    ) -> Result<(), MulticastError<S::Error>> {
        match local {
            SocketAddr::V4(local) => socket
                .set_multicast_interface(GroupInterface::V4(*local.ip()))
                .map_err(MulticastError::Socket),
            SocketAddr::V6(local) => {
                match link_egress_index_v6(local, interfaces::interface_indices_of_address)? {
                    Some(index) => socket
                        .set_multicast_interface(GroupInterface::Index(index))
                        .map_err(MulticastError::Socket),
                    None => self.pin_egress(socket).map_err(MulticastError::Socket),
                }
            }
        }
    }

    /// Join the group and every `#join=` group on the one socket and the one interface: the
    /// plan's, or the system's choice when it has none. `skip_refused_v4` logs a refused IPv4
    /// membership and goes on to the next group, which is a scouting socket's rule; an IPv6 join is
    /// always strict.
    fn join_groups<S: MulticastSocket>(
        &self,
        socket: &S,
        skip_refused_v4: bool,
    ) -> Result<(), S::Error> {
        match self {
            Self::V4 {
                group,
                iface,
                joins,
            } => {
                let on = iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
                for g in core::iter::once(group).chain(joins) {
                    match socket.join_group(IpAddr::V4(*g), GroupInterface::V4(on)) {
                        Ok(()) => {}
                        Err(e) if skip_refused_v4 => {
                            wz_session_core::diag_warn!(
                                "wz: unable to join multicast group {} on interface {}: {e:?}",
                                AddrText(IpAddr::V4(*g)),
                                AddrText(IpAddr::V4(on))
                            );
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Self::V6 {
                group,
                iface,
                joins,
            } => {
                let on = GroupInterface::Index(iface.unwrap_or(0));
                for g in core::iter::once(group).chain(joins) {
                    socket.join_group(IpAddr::V6(*g), on)?;
                }
            }
        }
        Ok(())
    }

    /// The `multicast-loopback` policy on `socket`; `OsDefault` sets nothing.
    fn loop_back<S: MulticastSocket>(socket: &S, policy: Loopback) -> Result<(), S::Error> {
        match policy {
            Loopback::OsDefault => Ok(()),
            Loopback::On => socket.set_multicast_loopback(true),
            Loopback::Off => socket.set_multicast_loopback(false),
        }
    }
}

/// The interface index an IPv6 link's send socket bound to `local` leaves by, with `holders`
/// answering which interfaces hold an address: the scope of a link-local address, else the first
/// holder. `None` where there is no address to read one from (the wildcard) or the holders cannot
/// be named, and the caller keeps the egress it has. Apart from the table, so that each case is
/// told without a host of that shape.
fn link_egress_index_v6(
    local: SocketAddrV6,
    holders: impl FnOnce(IpAddr) -> Result<Vec<u32>, IfaceResolveError>,
) -> Result<Option<u32>, PlanError> {
    if local.scope_id() != 0 {
        return Ok(Some(local.scope_id()));
    }
    if local.ip().is_unspecified() {
        return Ok(None);
    }
    match holders(IpAddr::V6(*local.ip())) {
        Ok(found) => match found.first() {
            Some(index) => Ok(Some(*index)),
            None => Err(PlanError::NoHolder(*local.ip())),
        },
        Err(IfaceResolveError::Undetermined) => Ok(None),
        Err(e) => Err(PlanError::Holder(*local.ip(), e)),
    }
}

/// A multicast socket made here: bound, non-blocking, with its memberships and options set, and
/// the group and port its datagrams are written to.
pub struct Bound<S> {
    /// The socket.
    pub socket: S,
    /// The group and port a datagram is sent to: the group itself.
    pub peer: SocketAddr,
}

/// Make the socket that receives `group` on `port` (and can send to it): bound shared with the
/// group's other members on this host, the egress interface pinned when the plan has one, the
/// group and every `#join=` group joined, the loopback policy and the hop limit applied.
///
/// `rx_bind` says what it binds and with it how a refused membership is read. A
/// [`RxBind::Wildcard`] socket is a multicast LINK: the `multicast-link-requires-iface` policy
/// applies to it, and an unpinned one joins and sends on upstream's chosen interface. A
/// [`RxBind::Group`] socket is a scouting socket, which does neither.
pub fn bind_joined<S: MulticastSocket>(
    group: IpAddr,
    port: u16,
    cfg: &SocketConfig<'_>,
    rx_bind: RxBind,
) -> Result<Bound<S>, MulticastError<S::Error>> {
    // Everything a key can refuse is resolved before a socket exists, so a refusal leaves no
    // membership behind.
    let plan = Plan::resolve(group, cfg, JoinsRead::Yes)?;
    let hops = hop_limit(cfg)?;
    let plan = match rx_bind {
        RxBind::Wildcard => {
            plan.require_chosen_interface(cfg)?;
            plan.with_link_default_iface(interfaces::unicast_addresses_of_multicast_interfaces())
        }
        RxBind::Group => plan,
    };
    let socket =
        S::bind_shared(plan.rx_bind_addr(port, rx_bind)).map_err(MulticastError::Socket)?;
    let configured = socket
        .make_nonblocking()
        .and_then(|()| plan.pin_egress(&socket))
        .and_then(|()| plan.join_groups(&socket, rx_bind.skips_a_refused_v4_join()))
        .and_then(|()| Plan::loop_back(&socket, cfg.loopback))
        .and_then(|()| match hops {
            Some(hops) => socket.set_multicast_hops(hops),
            None => Ok(()),
        });
    configured.map_err(MulticastError::Socket)?;
    Ok(Bound {
        socket,
        peer: plan.peer(port),
    })
}

/// Make a socket that only sends to `group` on `port`: bound to `#bind=` or the filled wildcard
/// on a port the system picks, the egress interface pinned, the loopback policy and the hop limit
/// applied. No membership: a sender needs none, so a `#join=` it would never use does not refuse it.
///
/// `link` says it is the send half of a multicast LINK, which leaves by the interface of the address
/// it binds (as upstream's link's send socket does) and is subject to
/// `multicast-link-requires-iface`; a scouting sender keeps `#iface=` or the system's choice.
pub fn bind_sender<S: MulticastSocket>(
    group: IpAddr,
    port: u16,
    cfg: &SocketConfig<'_>,
    link: bool,
) -> Result<Bound<S>, MulticastError<S::Error>> {
    let plan = Plan::resolve(group, cfg, JoinsRead::No)?;
    let hops = hop_limit(cfg)?;
    let plan = if link {
        plan.require_chosen_interface(cfg)?;
        plan.with_link_default_iface(interfaces::unicast_addresses_of_multicast_interfaces())
    } else {
        plan
    };
    let local = plan.egress_local_addr(cfg.bind, cfg.iface)?;
    let socket = S::bind(local).map_err(MulticastError::Socket)?;
    socket.make_nonblocking().map_err(MulticastError::Socket)?;
    if link {
        plan.pin_link_egress(&socket, local)?;
    } else {
        plan.pin_egress(&socket).map_err(MulticastError::Socket)?;
    }
    Plan::loop_back(&socket, cfg.loopback).map_err(MulticastError::Socket)?;
    if let Some(hops) = hops {
        socket
            .set_multicast_hops(hops)
            .map_err(MulticastError::Socket)?;
    }
    Ok(Bound {
        socket,
        peer: plan.peer(port),
    })
}

/// Mark what `socket` sends with the traffic class `dscp` (`#dscp=`), as written. A platform
/// whose socket of this family has no such option warns and sends unmarked, as upstream does.
pub fn mark_traffic_class<S: MulticastSocket>(socket: &S, dscp: u32) -> Result<(), S::Error> {
    if !socket.set_traffic_class(dscp)? {
        wz_session_core::diag_warn!(
            "{} DSCP is unsupported on this platform",
            if socket.local().is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            }
        );
    }
    Ok(())
}

/// One group joined on the host's sockets: a session's [`GroupTransport`]. The joined socket is
/// read, the send socket writes, and a datagram is taken only when one is queued. The joined socket
/// and the buffer it reads into are the transport's receive half ([`HostGroupReceive`]), which a
/// reader of the heap profile takes out of it (`GroupTransport::split_receive`) to hold apart
/// from the send socket the group's senders share.
pub struct HostGroupTransport<S: MulticastSocket> {
    /// The socket every datagram is sent from, `None` once the session has released the link.
    write: Option<S>,
    /// The group and its port, where every datagram is sent.
    group: SocketAddr,
    /// The receive half, `None` once taken out of the transport.
    receive: Option<HostGroupReceive<S>>,
}

/// The receive half of a group joined on the host's sockets: the joined socket, the buffer each
/// datagram is read into, and the datagram it lent and was asked to keep.
pub struct HostGroupReceive<S: MulticastSocket> {
    /// The joined socket the group is read on, `None` once the session has released the link.
    read: Option<S>,
    /// The address the group's own send socket sends from: what it sends comes back on the joined
    /// socket while the loopback is on, the system's default, and is dropped on receipt.
    own: Option<SocketAddr>,
    /// The group and its port, which a failed receive is reported against.
    group: SocketAddr,
    /// What each datagram is read into: a buffer the session lent, or the half's own.
    rx: GroupRx<Vec<u8>>,
    /// The length and source of the datagram the last receive lent, which lies in `rx` until the
    /// next receive reads into it.
    lent: Option<(usize, SocketAddr)>,
    /// The datagram asked to be kept ([`GroupTransport::keep`]), lent again by the next receive.
    kept: Option<(usize, SocketAddr)>,
    /// Whether the joined socket failed a receive: what the host reports of an interface that went
    /// away, and the end of the group's link.
    failed: bool,
    /// Whether a receive that passes no flag waits on the joined socket, up to its receive timeout:
    /// made so when the half is taken out of its transport, where a reader waits in it.
    waits: bool,
    /// The receive timeout last set on the joined socket, in milliseconds.
    armed_ms: Option<c_int>,
}

impl<S: MulticastSocket> HostGroupTransport<S> {
    /// The transport of the group `group` (its address and port), read on `read` and written
    /// from `write`, each made by [`bind_joined`] and [`bind_sender`], receiving into `rx` when
    /// its session lent a buffer, which is then as long as the group's batch, and otherwise into
    /// one of its own that reads a datagram up to the largest UDP payload whole. A datagram longer
    /// than the buffer is cut by the stack, which the session reads as a bad frame.
    pub fn new(read: S, write: S, group: SocketAddr, rx: Option<ByteBuf>) -> Self {
        let own = Some(write.local());
        Self {
            write: Some(write),
            group,
            receive: Some(HostGroupReceive::of(
                Some(read),
                own,
                group,
                GroupRx::lent_or_own(rx, || alloc::vec![0; UDP_RX_CAPACITY]),
            )),
        }
    }

    /// The group and port this transport sends to.
    pub fn group(&self) -> SocketAddr {
        self.group
    }
}

impl<S: MulticastSocket> HostGroupReceive<S> {
    /// The half that reads `read`, joined to `group`, into `rx`, dropping what `own` sent.
    fn of(
        read: Option<S>,
        own: Option<SocketAddr>,
        group: SocketAddr,
        rx: GroupRx<Vec<u8>>,
    ) -> Self {
        Self {
            read,
            own,
            group,
            rx,
            lent: None,
            kept: None,
            failed: false,
            waits: false,
            armed_ms: None,
        }
    }

    /// Wait in the joined socket's receive, for at most `timeout_us` as `now_us` reads it, for a
    /// datagram a member sent, past those the group's own send socket sent, and keep it for the
    /// next receive to lend: `true` once one is kept. The socket's timeout is set in whole
    /// milliseconds, again only when what is left of the time needs another, so a stream of
    /// datagrams sets it once. A half whose socket's receive does not wait waits for nothing.
    pub fn await_member(&mut self, timeout_us: u64, now_us: &mut dyn FnMut() -> u64) -> bool {
        if self.kept.is_some() {
            return true;
        }
        if !self.waits {
            return false;
        }
        let Some(socket) = &self.read else {
            return false;
        };
        let deadline_us = now_us().saturating_add(timeout_us);
        let mut left_us = timeout_us;
        loop {
            let ms = c_int::try_from(left_us.div_ceil(1000)).unwrap_or(c_int::MAX);
            if ms == 0 {
                return false;
            }
            if self.armed_ms != Some(ms) {
                if !socket.set_receive_timeout(ms) {
                    return false;
                }
                self.armed_ms = Some(ms);
            }
            match socket.recv_waiting(self.rx.as_mut_slice()) {
                Ok(Some((_, from))) if self.own.is_some_and(|own| sent_by_own(own, from)) => {
                    left_us = deadline_us.saturating_sub(now_us());
                }
                Ok(Some((len, from))) => {
                    self.kept = Some((len, from));
                    return true;
                }
                // The time ran out, or a signal cut the wait short: the read goes on.
                Ok(None) => return false,
                Err(e) => {
                    wz_session_core::diag_warn!(
                        "group {}: its socket failed a receive: {e:?}",
                        AddrText(self.group)
                    );
                    self.failed = true;
                    return false;
                }
            }
        }
    }

    /// Lend the next datagram a member sent to `f`, where it lies in the buffer: the one kept
    /// first, then one queued on the joined socket, past every datagram the group's own send
    /// socket sent. `false` when none is queued, the half was released, or the receive failed.
    fn receive(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        // A datagram kept lies in the receive buffer still: it is lent again from there.
        if let Some((len, from)) = self.kept.take() {
            f(self.rx.as_slice().get(..len).unwrap_or_default(), from);
            self.lent = Some((len, from));
            return true;
        }
        let Some(socket) = &self.read else {
            return false;
        };
        // Dropped here, as zenoh-pico's link drops it too.
        let own = self.own;
        loop {
            match socket.try_recv(self.rx.as_mut_slice()) {
                Ok(Some((_, from))) if own.is_some_and(|own| sent_by_own(own, from)) => {}
                Ok(Some((len, from))) => {
                    f(self.rx.as_slice().get(..len).unwrap_or_default(), from);
                    self.lent = Some((len, from));
                    return true;
                }
                // Nothing queued, or a signal cut the read short: the next step reads again.
                Ok(None) => return false,
                Err(e) => {
                    wz_session_core::diag_warn!(
                        "group {}: its socket failed a receive: {e:?}",
                        AddrText(self.group)
                    );
                    self.failed = true;
                    return false;
                }
            }
        }
    }

    /// Keep the datagram the last receive lent, for the next receive to lend again.
    fn keep_lent(&mut self) {
        self.kept = self.lent.take();
    }

    /// Receive nothing more. Closing the joined socket is leaving the group: the host drops its
    /// memberships with it.
    fn stop(&mut self) {
        self.read = None;
        self.lent = None;
        self.kept = None;
    }
}

impl<S: MulticastSocket + 'static> GroupTransport for HostGroupTransport<S> {
    // The datagram lies in the receive buffer, which nothing writes until the next receive: a
    // datagram kept is lent again from where it lies, and costs no copy.
    fn keeps_input(&self) -> bool {
        self.receive.is_some()
    }

    fn keep(&mut self) {
        if let Some(receive) = &mut self.receive {
            receive.keep_lent();
        }
    }

    // A lent buffer is the session's, which holds what it reads there until it asks for the next
    // datagram; a buffer of the transport's own is lent for the call, as the trait provides.
    fn lends_until_next_receive(&self) -> bool {
        self.receive
            .as_ref()
            .is_some_and(|receive| receive.rx.is_lent())
    }

    // Asked once the group is left, when no receive reads into the buffer again. A receive half
    // taken out of the transport keeps its buffer, which goes with it.
    fn give_back_rx(&mut self) -> Option<ByteBuf> {
        self.receive.as_mut()?.rx.give_back()
    }

    fn open(&mut self) -> bool {
        self.write.is_some()
            && self
                .receive
                .as_ref()
                .is_none_or(|receive| receive.read.is_some())
    }

    fn close(&mut self) {
        self.write = None;
        if let Some(receive) = &mut self.receive {
            receive.stop();
        }
    }

    // The engine waits, on its links and its groups at once, and steps a group at its tick: there
    // is nothing for the group to wait for here.
    fn service(&self) {}

    /// A host has no carrier to read here; what ends a group is its joined socket failing.
    fn carrier_up(&self) -> bool {
        !self.receive.as_ref().is_some_and(|receive| receive.failed)
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as a multicast send is: the next beacon or retransmission is the retry.
        if let Some(socket) = &self.write {
            let _ = socket.send_to(self.group, datagram);
        }
    }

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        let Some(socket) = &self.write else {
            return GroupSend::Failed;
        };
        match socket.send_to(self.group, datagram) {
            Ok(()) => GroupSend::Sent,
            Err(e) if S::found_no_room(&e) => GroupSend::Full,
            Err(e) => {
                wz_session_core::diag_warn!(
                    "group {}: its socket failed a send: {e:?}",
                    AddrText(self.group)
                );
                GroupSend::Failed
            }
        }
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        match &self.write {
            Some(socket) => socket.wait_writable(timeout_us),
            // Released: the send that follows fails.
            None => true,
        }
    }

    wz_runtime_coop::with_heap_link_seams! {
        fn room_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            self.write.as_ref()?.room_wait()
        }

        // The joined socket's input, on a platform that names it; a group that was left, or whose
        // receive half was taken out, names none.
        fn input_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            self.receive.as_ref()?.read.as_ref()?.input_wait()
        }

        // The half's reader is its own: the joined socket's receive may wait in it from here on,
        // where it can be given a time to wait for.
        fn split_receive(
            &mut self,
        ) -> Option<alloc::boxed::Box<dyn wz_runtime_coop::group_transport::GroupReceive>> {
            let mut receive = self.receive.take()?;
            receive.waits = S::CAN_SET_RECEIVE_TIMEOUT
                && receive
                    .read
                    .as_ref()
                    .is_some_and(S::make_receive_wait);
            Some(alloc::boxed::Box::new(receive))
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        match &mut self.receive {
            Some(receive) => receive.receive(f),
            None => false,
        }
    }
}

wz_runtime_coop::with_heap_link_seams! {
    impl<S: MulticastSocket> wz_runtime_coop::group_transport::GroupReceive for HostGroupReceive<S> {
        fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            self.receive(f)
        }

        fn keeps_input(&self) -> bool {
            true
        }

        fn keep(&mut self) {
            self.keep_lent();
        }

        fn lends_until_next_receive(&self) -> bool {
            self.rx.is_lent()
        }

        fn input_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            self.read.as_ref()?.input_wait()
        }

        fn failed(&self) -> bool {
            self.failed
        }

        fn awaits_input(&self) -> bool {
            self.waits && self.read.is_some()
        }

        fn await_input(&mut self, timeout_us: u64, now_us: &mut dyn FnMut() -> u64) -> bool {
            self.await_member(timeout_us, now_us)
        }

        fn close(&mut self) {
            self.stop();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::net::{PosixNetError, PosixUdpSocket};
    use core::ffi::c_int;
    // The tests open concrete sockets, whose datagram methods are the trait's; the code above
    // reaches them through the `MulticastSocket` bound alone.
    use wz_runtime_coop::udp_link::DatagramSocket;

    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 9);
    const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0x7a, 0x7709);

    /// A group lent a buffer receives into it where it lies, says the bytes stay there until its
    /// next receive, and gives the buffer back once as it is left. The CONTROL is a group that made
    /// its own: it lends a datagram for the call only and gives nothing back.
    #[test]
    fn a_group_lent_a_buffer_receives_into_it_and_gives_it_back_once() {
        use wz_session_core::byte_cells::{ByteCells, ByteSource};

        static CELLS: ByteCells<64, 1> = ByteCells::new();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let open = |rx: Option<ByteBuf>| {
            let read = PosixUdpSocket::bind(loopback).expect("a reading socket");
            let write = PosixUdpSocket::bind(loopback).expect("a sending socket");
            let to = read.local();
            HostGroupTransport::new(read, write, to, rx)
        };

        let mut own = open(None);
        assert!(
            !own.lends_until_next_receive(),
            "CONTROL: its own buffer is lent for the call"
        );
        own.close();
        assert!(
            own.give_back_rx().is_none(),
            "CONTROL: its own buffer stays"
        );

        let buf = CELLS.claim().expect("the cell");
        let base = buf.raw().0 as usize;
        let mut lent = open(Some(buf));
        assert!(lent.lends_until_next_receive());
        // From a member's socket: what the transport's own sender sends is dropped on receipt.
        let member = PosixUdpSocket::bind(loopback).expect("a member's socket");
        member.send_to(lent.group(), b"hello").expect("sent");
        let mut seen = None;
        for _ in 0..100_000 {
            if lent
                .recv_with(&mut |bytes, _| seen = Some((bytes.to_vec(), bytes.as_ptr() as usize)))
            {
                break;
            }
        }
        let (bytes, at) = seen.expect("the datagram");
        assert_eq!(bytes, b"hello");
        assert_eq!(at, base, "read where the lent buffer lies");
        lent.close();
        let back = lent.give_back_rx().expect("the lent buffer");
        assert!(lent.give_back_rx().is_none(), "given back once");
        assert_eq!(CELLS.in_use(), 1, "the session holds it until it lets go");
        drop(back);
        assert_eq!(CELLS.in_use(), 0);
    }

    /// What the group's own send socket sends comes back on the joined socket while the loopback is
    /// on, and a receive drops it and reads on to a member's datagram in the same call. The
    /// CONTROL is the member's datagram, taken with its source.
    #[test]
    fn a_group_drops_what_its_own_send_socket_sent() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let read = PosixUdpSocket::bind(loopback).expect("a reading socket");
        let write = PosixUdpSocket::bind(loopback).expect("a sending socket");
        let member = PosixUdpSocket::bind(loopback).expect("a member's socket");
        let to = read.local();
        let mut group = HostGroupTransport::new(read, write, to, None);
        group.send_to_group(b"own");
        group.send_to_group(b"own again");
        member.send_to(to, b"member").expect("sent");
        let mut seen = None;
        for _ in 0..100_000 {
            if group.recv_with(&mut |bytes, from| seen = Some((bytes.to_vec(), from))) {
                break;
            }
        }
        assert_eq!(
            seen,
            Some((b"member".to_vec(), member.local())),
            "the member's datagram, past the two its own sender sent"
        );
        assert!(!group.recv_with(&mut |_, _| panic!("its own datagrams were dropped")));
    }

    /// A socket option of `socket`, read back into a value of the type it is kept as.
    fn option<T: Copy>(socket: &PosixUdpSocket, level: c_int, name: c_int, mut value: T) -> T {
        let mut len = core::mem::size_of::<T>() as libc::socklen_t;
        // SAFETY: `value` and `len` are live and writable, and `len` is `value`'s size.
        let rc = unsafe {
            libc::getsockopt(
                socket.fd(),
                level,
                name,
                (&mut value as *mut T).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        value
    }

    fn v4_plan(iface: Option<Ipv4Addr>) -> Plan {
        Plan::V4 {
            group: GROUP,
            iface,
            joins: Vec::new(),
        }
    }

    /// An `#iface=` address literal is the selector of its own family and refused for the other,
    /// before anything is looked up; a `#join=` of the other family is refused, and a sender does
    /// not read the list at all.
    #[test]
    fn the_keys_resolve_against_the_groups_family() {
        let joins = [IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))];
        let cfg = SocketConfig {
            iface: Some("127.0.0.1"),
            extra_joins: &joins,
            ..SocketConfig::default()
        };
        assert_eq!(
            Plan::resolve(IpAddr::V4(GROUP), &cfg, JoinsRead::Yes),
            Ok(Plan::V4 {
                group: GROUP,
                iface: Some(Ipv4Addr::LOCALHOST),
                joins: alloc::vec![Ipv4Addr::new(239, 1, 2, 3)],
            })
        );
        assert_eq!(
            Plan::resolve(IpAddr::V6(GROUP_V6), &cfg, JoinsRead::Yes),
            Err(PlanError::IfaceFamily)
        );
        let v6_iface = SocketConfig {
            iface: Some("::1"),
            ..SocketConfig::default()
        };
        assert_eq!(
            Plan::resolve(IpAddr::V4(GROUP), &v6_iface, JoinsRead::No),
            Err(PlanError::IfaceFamily)
        );
        let bad_joins = [IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))];
        let other_family = SocketConfig {
            extra_joins: &bad_joins,
            ..SocketConfig::default()
        };
        assert_eq!(
            Plan::resolve(IpAddr::V4(GROUP), &other_family, JoinsRead::Yes),
            Err(PlanError::Join)
        );
        assert_eq!(
            Plan::resolve(IpAddr::V4(GROUP), &other_family, JoinsRead::No),
            Ok(v4_plan(None)),
            "a sender neither uses nor refuses the list"
        );
    }

    /// A hop limit above 255 is refused; one stated is kept, and none leaves the system's.
    #[test]
    fn a_hop_limit_above_a_byte_is_refused() {
        let ttl = |ttl| SocketConfig {
            ttl,
            ..SocketConfig::default()
        };
        assert_eq!(hop_limit(&ttl(Some(256))), Err(PlanError::Ttl(256)));
        assert_eq!(hop_limit(&ttl(Some(4))), Ok(Some(4)));
        assert_eq!(hop_limit(&ttl(None)), Ok(None));
    }

    /// An unpinned IPv4 link takes the first non-loopback IPv4 address offered; a pinned one and an
    /// IPv6 one are kept, and a host that offers nothing leaves the system's choice. Under the
    /// `multicast-link-requires-iface` policy only a plan the locator pinned passes.
    #[test]
    fn an_unpinned_link_takes_the_first_routable_ipv4_and_the_policy_refuses_it() {
        let offered = Some(alloc::vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        ]);
        assert_eq!(
            v4_plan(None).with_link_default_iface(offered.clone()),
            v4_plan(Some(Ipv4Addr::new(10, 0, 0, 5)))
        );
        let pinned = v4_plan(Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            pinned.clone().with_link_default_iface(offered.clone()),
            pinned
        );
        assert_eq!(v4_plan(None).with_link_default_iface(None), v4_plan(None));
        let v6 = Plan::V6 {
            group: GROUP_V6,
            iface: None,
            joins: Vec::new(),
        };
        assert_eq!(v6.clone().with_link_default_iface(offered), v6);

        let requires = SocketConfig {
            link_requires_iface: true,
            ..SocketConfig::default()
        };
        assert_eq!(
            v4_plan(None).require_chosen_interface(&requires),
            Err(PlanError::NoInterfaceChosen)
        );
        assert_eq!(pinned.require_chosen_interface(&requires), Ok(()));
        assert_eq!(
            v4_plan(None).require_chosen_interface(&SocketConfig::default()),
            Ok(())
        );
    }

    /// `#bind=` is an address of the group's family, and a specified one is bound as it is;
    /// with none, a pinned IPv4 plan binds its interface's address on a port the system picks.
    #[test]
    fn the_send_address_is_bind_or_the_pinned_interfaces() {
        let plan = v4_plan(Some(Ipv4Addr::LOCALHOST));
        assert_eq!(
            plan.egress_local_addr(Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000))), None),
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)))
        );
        assert_eq!(
            plan.egress_local_addr(Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 7000))), None),
            Err(PlanError::Bind),
            "the other family is refused"
        );
        assert_eq!(
            plan.egress_local_addr(None, Some("127.0.0.1")),
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        );
    }

    /// An IPv6 link leaves by the scope of a link-local address, else by the first interface that
    /// holds its address; the wildcard and an unreadable table keep the egress it has, and an
    /// address nobody holds, or whose interface is refused, refuses the link.
    #[test]
    fn an_ipv6_link_leaves_by_the_interface_of_its_address() {
        let at =
            |text: &str, scope| SocketAddrV6::new(text.parse().expect("an address"), 0, 0, scope);
        assert_eq!(
            link_egress_index_v6(at("fe80::1", 7), |_| panic!("a scope needs no lookup")),
            Ok(Some(7))
        );
        assert_eq!(
            link_egress_index_v6(at("::", 0), |_| panic!("the wildcard needs no lookup")),
            Ok(None)
        );
        assert_eq!(
            link_egress_index_v6(at("fd00::5", 0), |_| Ok(alloc::vec![4, 9])),
            Ok(Some(4))
        );
        assert_eq!(
            link_egress_index_v6(at("fd00::5", 0), |_| Ok(Vec::new())),
            Err(PlanError::NoHolder("fd00::5".parse().expect("an address")))
        );
        assert_eq!(
            link_egress_index_v6(at("fd00::5", 0), |_| Err(IfaceResolveError::Undetermined)),
            Ok(None)
        );
        assert_eq!(
            link_egress_index_v6(at("fd00::5", 0), |_| Err(IfaceResolveError::NotUp)),
            Err(PlanError::Holder(
                "fd00::5".parse().expect("an address"),
                IfaceResolveError::NotUp
            ))
        );
    }

    /// A scouting sender pinned by an address binds that address, leaves by it, and writes to the
    /// group; the loopback policy and the hop limit reach the socket, and the socket does not
    /// block.
    #[test]
    fn a_sender_is_bound_pinned_and_set_as_its_keys_say() {
        let cfg = SocketConfig {
            iface: Some("127.0.0.1"),
            ttl: Some(3),
            loopback: Loopback::Off,
            ..SocketConfig::default()
        };
        let sender = bind_sender::<PosixUdpSocket>(IpAddr::V4(GROUP), 7446, &cfg, false)
            .expect("a sender on the loopback");
        assert_eq!(sender.peer, SocketAddr::from((GROUP, 7446)));
        assert_eq!(sender.socket.local().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(sender.socket.local().port(), 0);
        let egress = option(
            &sender.socket,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            libc::in_addr { s_addr: 0 },
        );
        assert_eq!(
            Ipv4Addr::from(egress.s_addr.to_ne_bytes()),
            Ipv4Addr::LOCALHOST
        );
        assert_eq!(
            option(&sender.socket, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, -1),
            3
        );
        assert_eq!(
            option(
                &sender.socket,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_LOOP,
                -1
            ),
            0
        );
        // SAFETY: a plain system call on the socket's own descriptor.
        let flags = unsafe { libc::fcntl(sender.socket.fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0, "a sender does not block");
    }

    /// A link's sender leaves by the interface of the address it binds, `#bind=` here, whatever
    /// interface the host would have offered an unpinned link.
    #[test]
    fn a_link_sender_leaves_by_the_address_it_binds() {
        let cfg = SocketConfig {
            bind: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ..SocketConfig::default()
        };
        let sender = bind_sender::<PosixUdpSocket>(IpAddr::V4(GROUP), 7446, &cfg, true)
            .expect("a link's sender on the loopback");
        assert_eq!(sender.socket.local().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let egress = option(
            &sender.socket,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            libc::in_addr { s_addr: 0 },
        );
        assert_eq!(
            Ipv4Addr::from(egress.s_addr.to_ne_bytes()),
            Ipv4Addr::LOCALHOST
        );
    }

    /// The `multicast-link-requires-iface` policy refuses a link that pinned nothing, before a
    /// socket opens, and does not reach a scouting sender; a key a link cannot honour is refused
    /// the same way.
    #[test]
    fn a_refusal_of_the_keys_comes_before_any_socket() {
        let requires = SocketConfig {
            link_requires_iface: true,
            ..SocketConfig::default()
        };
        assert!(matches!(
            bind_sender::<PosixUdpSocket>(IpAddr::V4(GROUP), 7446, &requires, true),
            Err(MulticastError::Plan(PlanError::NoInterfaceChosen))
        ));
        assert!(matches!(
            bind_joined::<PosixUdpSocket>(IpAddr::V4(GROUP), 0, &requires, RxBind::Wildcard),
            Err(MulticastError::Plan(PlanError::NoInterfaceChosen))
        ));
        assert!(bind_sender::<PosixUdpSocket>(IpAddr::V4(GROUP), 7446, &requires, false).is_ok());
        let joins = [IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let bad = SocketConfig {
            extra_joins: &joins,
            ..SocketConfig::default()
        };
        assert!(matches!(
            bind_joined::<PosixUdpSocket>(IpAddr::V4(GROUP), 0, &bad, RxBind::Group),
            Err(MulticastError::Plan(PlanError::Join))
        ));
    }

    /// A link whose group is not one is not joined: the kernel refuses the membership, and the
    /// refusal is the socket's.
    #[test]
    fn a_link_to_an_address_that_is_no_group_is_refused_by_the_kernel() {
        let cfg = SocketConfig {
            iface: Some("127.0.0.1"),
            ..SocketConfig::default()
        };
        assert!(matches!(
            bind_joined::<PosixUdpSocket>(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                0,
                &cfg,
                RxBind::Wildcard
            ),
            Err(MulticastError::Socket(PosixNetError::Membership(
                libc::EINVAL
            )))
        ));
    }

    /// `#dscp=` marks what an IPv4 socket sends with the value as written.
    #[test]
    fn the_traffic_class_is_marked_as_written() {
        let socket =
            PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a socket");
        mark_traffic_class(&socket, 0x20).expect("marked");
        assert_eq!(option(&socket, libc::IPPROTO_IP, libc::IP_TOS, -1), 0x20);
    }

    /// A send that found no room is told from one that failed: only a refused send that left
    /// `EAGAIN` or `EINTR` is a full socket.
    #[test]
    fn only_a_send_refused_for_room_is_a_full_socket() {
        let full = |error| <PosixUdpSocket as MulticastSocket>::found_no_room(&error);
        assert!(full(PosixNetError::Send(-1, libc::EAGAIN)));
        assert!(full(PosixNetError::Send(-1, libc::EINTR)));
        assert!(!full(PosixNetError::Send(-1, libc::EPERM)));
        assert!(
            !full(PosixNetError::Send(3, libc::EAGAIN)),
            "a short send is no full socket"
        );
        assert!(!full(PosixNetError::Recv(libc::EAGAIN)));
    }

    // A wait made from outside the loop is a seam of the heap profile alone: a build that unifies
    // the slot profile in has neither the waits nor these two tests.
    wz_runtime_coop::with_heap_link_seams! {
        /// The send socket's room is the group's: a datagram it takes is sent and the socket has room,
        /// asked by the session's loop or from outside it; a group that was left fails its send, has
        /// room at once for the send to fail on, and gives no wait to ask. A send socket aimed at a
        /// loopback port stands in for one joined to a group, which needs a multicast route.
        #[test]
        fn the_send_sockets_room_is_the_groups() {
            use wz_runtime_coop::session_drive::LinkWaits;
            let waits = crate::net::PosixWaits;
            let peer =
                PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a peer");
            let write = PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("a send socket");
            write.make_nonblocking().expect("non-blocking");
            let mut transport = HostGroupTransport {
                write: Some(write),
                group: peer.local(),
                receive: Some(HostGroupReceive::of(
                    None,
                    None,
                    peer.local(),
                    GroupRx::lent_or_own(None, Vec::new),
                )),
            };
            let outside = transport.room_wait().expect("a wait from outside");
            assert_eq!(transport.try_send_to_group(b"datagram"), GroupSend::Sent);
            let mut got = [0u8; 16];
            let (len, _) = peer
                .recv_waiting(&mut got)
                .expect("no error")
                .expect("the datagram arrived");
            assert_eq!(&got[..len], b"datagram");
            assert!(transport.wait_for_room(1_000));
            assert!(waits.wait_room(outside, 1_000));

            transport.close();
            assert_eq!(transport.try_send_to_group(b"left"), GroupSend::Failed);
            assert!(transport.wait_for_room(1_000));
            assert!(transport.room_wait().is_none());
            assert!(
                waits.wait_room(outside, 1_000),
                "a wait on the handle after the leave answers, and the send that follows fails"
            );
        }

        /// The receive half taken out of a group reads what the group read: a member's datagram, past
        /// what the group's own send socket sent, kept and lent again from where it lies; the
        /// transport left behind opens, sends and receives nothing, and the half closed has left the
        /// group. Turned red by a split that leaves the joined socket with the transport
        /// (`HostGroupTransport::split_receive`), or an open that asks for the joined socket the half
        /// took (`HostGroupTransport::open`).
        #[test]
        fn a_groups_receive_half_reads_apart_from_its_send_half() {
            let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let read = PosixUdpSocket::bind(loopback).expect("a reading socket");
            let write = PosixUdpSocket::bind(loopback).expect("a sending socket");
            let member = PosixUdpSocket::bind(loopback).expect("a member's socket");
            let to = read.local();
            let mut group = HostGroupTransport::new(read, write, to, None);
            let mut half = group.split_receive().expect("the receive half");
            assert!(group.split_receive().is_none(), "taken out once");
            assert!(group.open(), "the send half opens without the joined socket");
            assert!(
                group.input_wait().is_none(),
                "the joined socket went with the half"
            );
            assert!(half.input_wait().is_some(), "the half waits on the joined socket");
            group.send_to_group(b"own");
            member.send_to(to, b"member").expect("sent");
            let mut seen = None;
            for _ in 0..100_000 {
                if half.recv_with(&mut |bytes, from| seen = Some((bytes.to_vec(), from))) {
                    break;
                }
            }
            assert_eq!(
                seen,
                Some((b"member".to_vec(), member.local())),
                "the member's datagram, past the one the group's own sender sent"
            );
            assert!(!group.recv_with(&mut |_, _| panic!("the send half received")));
            half.keep();
            let mut again = None;
            assert!(half.recv_with(&mut |bytes, from| again = Some((bytes.to_vec(), from))));
            assert_eq!(again, seen, "the kept datagram, lent again");
            assert!(group.carrier_up() && !half.failed());
            half.close();
            assert!(half.input_wait().is_none(), "a closed half has left the group");
            assert!(!half.recv_with(&mut |_, _| panic!("a closed half received")));
        }

        /// A receive half taken out of its group waits in its receive for a member's datagram, past
        /// what the group's own send socket sent, and keeps it for the next receive to lend; with
        /// nothing sent it waits its time out in the receive and keeps nothing. Turned red by a split
        /// that leaves the joined socket's receive returning at once (`make_receive_wait` not asked
        /// in `HostGroupTransport::split_receive`), or a wait that ends on the group's own datagram.
        #[test]
        fn a_groups_receive_half_waits_in_its_receive_past_its_own_datagrams() {
            use std::time::{Duration, Instant};

            let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let read = PosixUdpSocket::bind(loopback).expect("a reading socket");
            let write = PosixUdpSocket::bind(loopback).expect("a sending socket");
            let member = PosixUdpSocket::bind(loopback).expect("a member's socket");
            let to = read.local();
            let mut group = HostGroupTransport::new(read, write, to, None);
            let mut half = group.split_receive().expect("the receive half");
            assert!(half.awaits_input(), "a host's joined socket waits in its receive");
            let started = Instant::now();
            let mut now_us = || u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let waited = Instant::now();
            assert!(!half.await_input(30_000, &mut now_us), "nothing was sent");
            assert!(
                waited.elapsed() >= Duration::from_millis(25),
                "the time was waited out in the receive"
            );
            group.send_to_group(b"own");
            member.send_to(to, b"member").expect("sent");
            assert!(
                half.await_input(5_000_000, &mut now_us),
                "the member's datagram"
            );
            let mut seen = None;
            assert!(half.recv_with(&mut |bytes, from| seen = Some((bytes.to_vec(), from))));
            assert_eq!(
                seen,
                Some((b"member".to_vec(), member.local())),
                "kept past the group's own datagram, and lent by the next receive"
            );
        }

        /// The joined socket's input is waited for from outside the session's loop: the wait is waited
        /// out while nothing is queued and returns long before its time once a datagram is, alone or
        /// beside another socket; the datagram is then taken with its source, and a group that was left
        /// gives no wait and reads nothing, and is not a failed link.
        #[test]
        fn the_joined_sockets_input_is_waited_for_and_taken() {
            use std::time::{Duration, Instant};
            use wz_runtime_coop::session_drive::{LinkWait, LinkWaits};

            let read = PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("a joined socket");
            let to = read.local();
            let peer =
                PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a peer");
            let other = PosixUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("another link's socket");
            let mut transport = HostGroupTransport {
                write: None,
                group: to,
                receive: Some(HostGroupReceive::of(
                    Some(read),
                    None,
                    to,
                    GroupRx::lent_or_own(None, || alloc::vec![0; 64]),
                )),
            };
            let waits = crate::net::PosixWaits;
            let ready = LinkWait::input(transport.input_wait().expect("a wait from outside"));
            let started = Instant::now();
            waits.wait(&[ready], 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "nothing queued"
            );
            let beside = LinkWait::input(other.input_wait().expect("a wait"));
            let started = Instant::now();
            waits.wait(&[ready, beside], 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "nothing queued on either"
            );

            peer.send_to(to, b"member").expect("sent");
            let started = Instant::now();
            waits.wait(&[ready, beside], 5_000);
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "a datagram queued"
            );
            let mut seen = None;
            assert!(transport.recv_with(&mut |bytes, from| seen = Some((bytes.to_vec(), from))));
            assert_eq!(seen, Some((b"member".to_vec(), peer.local())));
            // A datagram kept lies in the receive buffer still, and is lent again from there.
            assert!(transport.keeps_input());
            transport.keep();
            let mut again = None;
            assert!(transport.recv_with(&mut |bytes, from| again = Some((bytes.to_vec(), from))));
            assert_eq!(again, seen, "the kept datagram, whole and from its member");
            assert!(!transport.recv_with(&mut |_, _| panic!("one datagram was sent")));

            transport.close();
            assert!(transport.input_wait().is_none(), "a group left gives none");
            assert!(!transport.recv_with(&mut |_, _| panic!("a datagram for a group that was left")));
            assert!(
                transport.carrier_up(),
                "a released link is not a failed one"
            );
        }
    }
}
