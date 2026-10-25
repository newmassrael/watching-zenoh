// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast sockets a node opens, built with no runtime.
//!
//! A multicast socket is made of policy and not only of calls: which interface an `#iface=` names,
//! what a link with none joins and sends on, whether a refused membership ends the bind, which
//! loopback a group gets, what the hop limit is. That policy is the same whichever runtime reads
//! from the socket, so it is built here once. [`bind_joined`] makes the socket that receives a
//! group (and sends to it), and [`bind_sender`] the one that only sends; each is a bound,
//! non-blocking `socket2::Socket` that a runtime adopts (tokio's `UdpSocket::from_std`, a
//! cooperative host's poll loop) together with the group address the datagrams are written to.
//!
//! What stays with the runtime is what is not socket policy: the datagram I/O, and the traffic
//! class (`#dscp=`), which the tokio runtime sets through its own socket type after adoption.

use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};

/// Whether a same-host member of a group observes what the socket sends, as the
/// `multicast-loopback` policy states it. `OsDefault` sets nothing, which is what upstream does
/// (it sets `IP_MULTICAST_LOOP` nowhere); `On` and `Off` set it on every multicast socket opened.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Loopback {
    /// Leave the operating system's setting alone.
    #[default]
    OsDefault,
    /// Set `IP_MULTICAST_LOOP` on.
    On,
    /// Set `IP_MULTICAST_LOOP` off.
    Off,
}

/// The multicast knobs a UDP locator's `#`-config span can carry, as one value rather than
/// several parameters.
///
/// zenoh names them together in one module (`config::UDP_MULTICAST_IFACE` / `_JOIN` / `_TTL`,
/// `zenoh-link-udp/src/lib.rs:108-112`) and consumes them in one function, so they travel together
/// here too. `Default` is the behaviour before there were keys to read: no interface pin, no extra
/// groups, the OS hop limit and the OS loopback.
///
/// The traffic class (`#dscp=`) is not here: it is set on the socket a runtime adopts, through
/// that runtime's own socket type.
#[derive(Debug, Default, Clone, Copy)]
pub struct SocketConfig<'a> {
    /// `#iface=<name-or-ip>` (R311y454): which interface's membership is installed and which one
    /// egress leaves by.
    pub iface: Option<&'a str>,
    /// `#ttl=<n>`: the multicast hop limit. `None` leaves the OS default, which is 1 — one subnet.
    pub ttl: Option<u32>,
    /// `#join=<group>` values, joined in addition to the locator's own group.
    pub extra_joins: &'a [String],
    /// R2791 — `#bind=<host:port>` (zenoh `BIND_SOCKET`): the LOCAL address the SENDING socket
    /// binds. Read by [`bind_sender`] only; the joined socket binds its family's wildcard or it
    /// cannot receive the group at all, which is the split upstream makes between the `ucast_sock`
    /// it binds here and the `mcast_sock` it does not.
    pub bind: Option<&'a str>,
    /// The `multicast-loopback` policy.
    pub loopback: Loopback,
}

impl SocketConfig<'_> {
    /// Parse every `#join=` value into a group address of the locator group's own family,
    /// `family` naming it for the refusal.
    ///
    /// Refused rather than skipped on a bad value, and refused BEFORE any membership is
    /// installed: a partially-joined receiver is subscribed to some of what it was told and silent
    /// about the rest, which is the shape that looks configured and is not. A group of the OTHER
    /// family is refused the same way, as upstream does: it parses each `join` as the group's own
    /// address type (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
    /// `let g: Ipv6Addr = g.parse().map_err(|e| zerror!("{}: {}", mcast_addr, e))?;`).
    fn parsed_joins<A: core::str::FromStr>(&self, family: &str) -> io::Result<Vec<A>> {
        self.extra_joins
            .iter()
            .map(|g| {
                g.parse::<A>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "#join={g} is not an {family} multicast group, and the \
                             locator's own group is {family}"
                        ),
                    )
                })
            })
            .collect()
    }
}

/// Whether [`Plan::resolve`] reads `#join=`. A sender installs no membership, so it must neither
/// use nor refuse the list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinsRead {
    Yes,
    No,
}

/// R3126 -- what a joined multicast socket binds locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxBind {
    /// The family wildcard: what a multicast LINK reads on (upstream's `mcast_sock`).
    Wildcard,
    /// The group address itself: what a SCOUTING socket reads on, on unix.
    Group,
}

impl RxBind {
    /// Whether an IPv4 membership the kernel refuses is skipped (and logged) rather than failing
    /// the bind.
    ///
    /// A scouting socket skips it, as upstream's does: `bind_mcast_port` joins the group on each
    /// interface address in turn and, when one join fails, warns and goes on
    /// (`zenoh/src/net/runtime/orchestrator.rs` @
    /// `Unable to join multicast group {} on interface {}: {}`); only a failure to create or bind
    /// the socket (and, for an IPv6 group, its one join on interface 0) ends the open. The join
    /// made here is on the interface the kernel chooses, which is the one a host with no default
    /// route cannot name, and a scout or a responder on such a host must still work over the
    /// interfaces it joins one by one. A multicast LINK keeps the strict reading: its membership is
    /// the link.
    fn skips_a_refused_v4_join(self) -> bool {
        match self {
            Self::Wildcard => false,
            Self::Group => true,
        }
    }
}

/// R2584 — a multicast group and its locator config, resolved for the group's address FAMILY
/// before any socket exists.
///
/// The families differ in every primitive a multicast socket needs. An IPv4 interface is selected
/// by one of its ADDRESSES and an IPv6 one by its INDEX. The hop limit is `IP_MULTICAST_TTL` for
/// v4 and `IPV6_MULTICAST_HOPS` for v6. And a `#join=` group must be the locator group's own
/// family. Both constructors take their family-specific steps from here, so the steps they share
/// are written once.
///
/// # Where the v6 arm differs from upstream, and why
///
/// - **The hop limit is honoured.** Upstream only logs a warning for a v6 `ttl`
///   (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
///   `"UDP multicast hop limit not supported for v6 socket: {}. See https://github.com/rust-lang/rust/pull/138744.",`).
///   That warning is about a missing std setter, not a protocol decision, and `socket2` has the
///   setter. So a v6 `#ttl=N` sends with a hop limit of N, where upstream sends with the OS
///   default of 1.
/// - **Membership is installed on the pinned interface.** Upstream joins a v6 group on interface
///   0, the kernel's choice, even when `iface` names one
///   (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.join_multicast_v6(&dst_ip6, 0)`), but
///   its v4 arm joins on the named interface. wz follows the v4 arm for both, so `#iface=` means
///   the same thing whichever family the group is.
enum Plan {
    V4 {
        group: std::net::Ipv4Addr,
        iface: Option<std::net::Ipv4Addr>,
        joins: Vec<std::net::Ipv4Addr>,
    },
    V6 {
        group: std::net::Ipv6Addr,
        iface: Option<u32>,
        joins: Vec<std::net::Ipv6Addr>,
    },
}

impl Plan {
    /// Resolve `#iface=` and, for a receiver, `#join=` against the group's family. The interface
    /// is resolved first, as before R2584.
    fn resolve(group: IpAddr, cfg: &SocketConfig<'_>, joins: JoinsRead) -> io::Result<Self> {
        use crate::link_interfaces::{multicast_iface_selector_v4, multicast_iface_selector_v6};

        Ok(match group {
            IpAddr::V4(group) => Self::V4 {
                group,
                iface: cfg
                    .iface
                    .map(multicast_iface_selector_v4)
                    .transpose()?
                    .flatten(),
                joins: match joins {
                    JoinsRead::Yes => cfg.parsed_joins("IPv4")?,
                    JoinsRead::No => Vec::new(),
                },
            },
            IpAddr::V6(group) => Self::V6 {
                group,
                iface: cfg
                    .iface
                    .map(multicast_iface_selector_v6)
                    .transpose()?
                    .flatten(),
                joins: match joins {
                    JoinsRead::Yes => cfg.parsed_joins("IPv6")?,
                    JoinsRead::No => Vec::new(),
                },
            },
        })
    }

    /// R3335 -- the interface an UNPINNED IPv4 multicast LINK joins and sends on: the first
    /// non-loopback IPv4 address `candidates` offers, which is what upstream's UDP multicast link
    /// does when no `#iface=` is given (it fills its local address from
    /// `get_unicast_addresses_of_multicast_interfaces()`, then `join_multicast_v4(&group,
    /// &src_ip4)` and `set_multicast_if_v4(src_ip4)` on that address:
    /// `io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.join_multicast_v4(&dst_ip4, &src_ip4)`).
    /// Until R3335 wz filled the BIND address from the same list (R2859) but joined on
    /// `INADDR_ANY` and pinned nothing, so on a host with several interfaces the kernel chose the
    /// membership and the egress, and the link's reported address and its membership could name
    /// different interfaces.
    ///
    /// `candidates` is an INPUT so a one-NIC host can prove the choice over a several-NIC list;
    /// the caller passes the live `unicast_addresses_of_multicast_interfaces()`. A `#iface=` the
    /// plan already resolved is kept as it is, an IPv6 plan is unchanged (upstream joins a v6
    /// group on index 0 whatever the address), and a host with no such address stays on
    /// `INADDR_ANY`, which is the address upstream falls through to.
    fn with_link_default_iface(self, candidates: Option<Vec<IpAddr>>) -> Self {
        match self {
            Self::V4 {
                group,
                iface: None,
                joins,
            } => Self::V4 {
                group,
                iface: candidates.and_then(|ips| {
                    ips.into_iter().find_map(|ip| match ip {
                        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
                        _ => None,
                    })
                }),
                joins,
            },
            other => other,
        }
    }

    fn domain(&self) -> Domain {
        match self {
            Self::V4 { .. } => Domain::IPV4,
            Self::V6 { .. } => Domain::IPV6,
        }
    }

    /// The wildcard address of the group's family, on `port`. A socket bound to a unicast address
    /// cannot receive datagrams addressed to the group.
    fn wildcard(&self, port: u16) -> SocketAddr {
        match self {
            Self::V4 { .. } => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
            Self::V6 { .. } => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
        }
    }

    /// R3126 -- the local address a joined socket binds: the wildcard, or the group itself where
    /// the caller reads on it and the platform lets a socket be bound to one. Windows binds the
    /// IPv4 wildcard whatever the family, as upstream does
    /// (`zenoh/src/net/runtime/orchestrator.rs` @ `std::net::Ipv4Addr::UNSPECIFIED.into()`), and
    /// that is the one bind a Windows socket can use to receive a group.
    fn rx_bind_addr(&self, port: u16, rx_bind: RxBind) -> SocketAddr {
        match rx_bind {
            RxBind::Wildcard => self.wildcard(port),
            RxBind::Group => {
                if cfg!(unix) {
                    self.peer(port)
                } else {
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port))
                }
            }
        }
    }

    /// R2791 — the local address the SENDING socket binds: `#bind=` when given, else the family
    /// wildcard on an EPHEMERAL port, which is both what this constructor bound before there was a
    /// key to read and what upstream falls back to. `group_port` names the group for the family
    /// check and the refusal only; it is never the local port.
    ///
    /// Upstream's counterpart is the `local_addr` its multicast manager derives for the
    /// `ucast_sock`
    /// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `let bind_addr = SocketAddr::from_str(bind_socket)?;`),
    /// and two of its properties are deliberate rather than incidental:
    ///
    /// - The value is parsed as a LITERAL `host:port`, never resolved. Upstream uses
    ///   `SocketAddr::from_str` here while the unicast dial path resolves the same key through a
    ///   name lookup, so mirroring the dial path's resolver would accept hostnames zenoh refuses
    ///   on this one.
    /// - A `bind` of the other family is REFUSED rather than ignored, in upstream's own words.
    ///   Binding IPv4 and joining IPv6 cannot work, and silently falling back to the wildcard
    ///   would egress from an address the operator did not ask for -- the same posture as the
    ///   group parse.
    ///
    /// R2859 — and upstream then fills an UNSPECIFIED `local_addr` from an interface address,
    /// which this does too ([`Self::fill_unspecified`]): the socket still bound the wildcard, and
    /// the bound address is what names the link. Upstream reports it as the multicast link's
    /// `src`, in the adminspace `sessions[]` row and in the stats registry's labels, so reporting
    /// `udp/0.0.0.0:<port>` would differ from upstream's interface address.
    fn egress_local_addr(
        &self,
        bind: Option<&str>,
        iface: Option<&str>,
        group_port: u16,
    ) -> io::Result<SocketAddr> {
        let Some(bind) = bind else {
            return Ok(self.fill_unspecified(self.wildcard(0), iface));
        };
        let bind_addr: SocketAddr = bind.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Couldn't parse UDP multicast bind address: {bind}"),
            )
        })?;
        let group = self.peer(group_port);
        match (bind_addr, group) {
            (SocketAddr::V6(local), SocketAddr::V4(dest)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Protocols must match: Cannot bind to IPv6 {local} and join IPv4 {dest}"),
            )),
            (SocketAddr::V4(local), SocketAddr::V6(dest)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Protocols must match: Cannot bind to IPv4 {local} and join IPv6 {dest}"),
            )),
            // Upstream fills after EITHER branch, so a `#bind=` naming the wildcard is filled
            // like no `#bind=` at all.
            _ => Ok(self.fill_unspecified(bind_addr, iface)),
        }
    }

    /// R2859 — upstream's fill of an unspecified multicast send address
    /// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `// Get default iface address to bind the socket on if provided`):
    /// the `#iface=` value's address in the group's family when one is given, else the first
    /// non-loopback address of the group's family on an interface that can carry multicast, else
    /// the wildcard unchanged. A specified address is returned as it is.
    ///
    /// One divergence, for bindability: an IPv6 LINK-LOCAL address is bound with the interface's
    /// scope id, where upstream sets the address alone. The kernel refuses to bind a link-local
    /// address without a scope, so the unscoped form would turn upstream's fill into a failed bind
    /// on exactly the hosts whose first v6 address is link-local.
    fn fill_unspecified(&self, addr: SocketAddr, iface: Option<&str>) -> SocketAddr {
        use crate::link_interfaces::{
            interface_indices_of_address, unicast_addresses_of_interface,
            unicast_addresses_of_multicast_interfaces,
        };

        if !addr.ip().is_unspecified() {
            return addr;
        }
        let v6 = matches!(self, Self::V6 { .. });
        let family = |ip: &IpAddr| ip.is_ipv6() == v6;
        let chosen = match (self, iface) {
            // The v4 plan already resolved `#iface=` to the address the membership and the
            // egress pin use; it is the one upstream picks.
            (
                Self::V4 {
                    iface: Some(ip), ..
                },
                _,
            ) => Some(IpAddr::V4(*ip)),
            // Only an `#iface=` the plan HONOURED (it resolved an index): a build without
            // `locator-iface` ignores the key, and the fill must not honour what the membership
            // and the egress pin did not.
            (Self::V6 { iface: Some(_), .. }, Some(name)) => match name.parse::<IpAddr>() {
                Ok(ip) => Some(ip).filter(family),
                Err(_) => unicast_addresses_of_interface(name)
                    .ok()
                    .and_then(|ips| ips.into_iter().find(family)),
            },
            _ => unicast_addresses_of_multicast_interfaces()
                .and_then(|ips| ips.into_iter().find(|ip| !ip.is_loopback() && family(ip))),
        };
        let Some(ip) = chosen else {
            return addr;
        };
        let mut filled = SocketAddr::new(ip, addr.port());
        if let (SocketAddr::V6(v6addr), IpAddr::V6(ip6)) = (&mut filled, ip) {
            // `fe80::/10`, spelled out: `is_unicast_link_local` postdates the MSRV.
            if ip6.segments()[0] & 0xffc0 == 0xfe80 {
                let scope = match self {
                    Self::V6 {
                        iface: Some(index), ..
                    } => Some(*index),
                    _ => interface_indices_of_address(ip)
                        .ok()
                        .and_then(|ix| ix.into_iter().next()),
                };
                match scope {
                    Some(scope) => v6addr.set_scope_id(scope),
                    // A link-local address with no known interface cannot be bound; the wildcard
                    // can.
                    None => return addr,
                }
            }
        }
        filled
    }

    /// Where a datagram is written: the group itself.
    fn peer(&self, port: u16) -> SocketAddr {
        match self {
            Self::V4 { group, .. } => SocketAddr::from((*group, port)),
            Self::V6 { group, .. } => SocketAddr::from((*group, port)),
        }
    }

    /// The egress interface, when `#iface=` pinned one.
    fn pin_egress(&self, raw: &Socket) -> io::Result<()> {
        match self {
            Self::V4 {
                iface: Some(addr), ..
            } => raw.set_multicast_if_v4(addr),
            Self::V6 {
                iface: Some(index), ..
            } => raw.set_multicast_if_v6(*index),
            _ => Ok(()),
        }
    }

    /// Join the locator's group and every `#join=` group, all on the SAME socket and the SAME
    /// membership interface. R311y832 — one bound port serving several groups is the point of
    /// `join` (zenoh `multicast.rs:316-347`), and zenoh passes one source interface to every join
    /// in that loop. Unpinned, the interface is the kernel's choice: `INADDR_ANY` for v4 and index
    /// 0 for v6 -- except a multicast LINK's v4 plan, which [`Self::with_link_default_iface`] has
    /// already pointed at upstream's chosen interface (R3335), so `iface` is `Some` by the time it
    /// gets here.
    ///
    /// `skip_refused_v4` turns a refused IPv4 membership into a warning and a move on to the next
    /// group, which is what a scouting socket does (see [`RxBind::skips_a_refused_v4_join`]); an
    /// IPv6 join is always strict.
    fn join_groups(&self, raw: &Socket, skip_refused_v4: bool) -> io::Result<()> {
        match self {
            Self::V4 {
                group,
                iface,
                joins,
            } => {
                let on = iface.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                for g in core::iter::once(group).chain(joins) {
                    match raw.join_multicast_v4(g, &on) {
                        Ok(()) => {}
                        Err(e) if skip_refused_v4 => {
                            log::warn!(
                                "wz: unable to join multicast group {g} on interface {on}: {e}"
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
                let on = iface.unwrap_or(0);
                for g in core::iter::once(group).chain(joins) {
                    // QNX: `libc` has no `ipv6_mreq` there, so socket2 has no IPv6 group join (it
                    // compiles the method out for `nto`). The request is refused, never skipped: a
                    // peer that asked for an IPv6 group must be told it is not in it. IPv4 joins
                    // are unaffected. The struct is POSIX's and could be written by hand, but its
                    // QNX header has not been read, so no layout is guessed here.
                    #[cfg(not(target_os = "nto"))]
                    raw.join_multicast_v6(g, on)?;
                    #[cfg(target_os = "nto")]
                    {
                        let _ = (g, on);
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "an IPv6 multicast group cannot be joined on QNX: libc has no ipv6_mreq",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// The `multicast-loopback` policy on this socket: whether a same-host member of the group
    /// observes what it sends. `OsDefault` sets nothing, which is what upstream does (it sets
    /// `IP_MULTICAST_LOOP` nowhere).
    fn loop_back(&self, raw: &Socket, policy: Loopback) -> io::Result<()> {
        let on = match policy {
            Loopback::OsDefault => return Ok(()),
            Loopback::On => true,
            Loopback::Off => false,
        };
        match self {
            Self::V4 { .. } => raw.set_multicast_loop_v4(on),
            Self::V6 { .. } => raw.set_multicast_loop_v6(on),
        }
    }

    /// `#ttl=`: the v4 TTL or the v6 hop limit, which is the same knob under each family's name.
    fn set_hop_limit(&self, raw: &Socket, ttl: u32) -> io::Result<()> {
        match self {
            Self::V4 { .. } => raw.set_multicast_ttl_v4(ttl),
            Self::V6 { .. } => raw.set_multicast_hops_v6(ttl),
        }
    }
}

/// A multicast socket built here: bound, non-blocking, with the memberships and options set, and
/// the group address its datagrams are written to.
#[derive(Debug)]
pub struct Bound {
    /// The socket, ready for a runtime to adopt.
    pub socket: Socket,
    /// The group and port a datagram is sent to (`LinkDriver::send` writes here in the tokio
    /// runtime): the group itself.
    pub peer: SocketAddr,
}

/// Make the socket that receives `group` on `port` (and sends to it): `SO_REUSEADDR` and, where it
/// exists, `SO_REUSEPORT` set before the bind, the egress interface pinned when `#iface=` names
/// one, the group and every `#join=` group joined, the loopback policy and the hop limit applied.
///
/// `rx_bind` says what it binds locally ([`RxBind`]) and with it how a refused membership is read.
/// A [`RxBind::Wildcard`] socket is a multicast LINK, and an unpinned one joins and sends on
/// upstream's chosen interface (R3335); a [`RxBind::Group`] socket is a scouting socket, which
/// does not.
///
/// This matches zenoh-pico, which sets `SO_REUSEADDR` and `SO_REUSEPORT` unconditionally on its
/// multicast listener before binding `0.0.0.0:port`
/// (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `setsockopt`): the
/// `pico -> wz` multicast interop is exactly the multi-listener case.
pub fn bind_joined(
    group: IpAddr,
    port: u16,
    cfg: &SocketConfig<'_>,
    rx_bind: RxBind,
) -> io::Result<Bound> {
    // Resolve BEFORE touching the socket, so a bad `#iface=` fails without leaving a
    // half-configured group membership behind. R311y832 — the extra `#join=` groups resolve here
    // too, for the same reason: a typo in the third of four groups must not leave two memberships
    // installed and the caller believing it has four.
    let plan = Plan::resolve(group, cfg, JoinsRead::Yes)?;
    // R3335 -- a multicast LINK (the wildcard-bound socket) with no `#iface=` joins and sends on
    // upstream's chosen interface rather than leaving it to the kernel. A scouting socket does
    // not: upstream joins those per interface (see `RxBind::skips_a_refused_v4_join`).
    let plan = match rx_bind {
        RxBind::Wildcard => plan.with_link_default_iface(
            crate::link_interfaces::unicast_addresses_of_multicast_interfaces(),
        ),
        RxBind::Group => plan,
    };

    // `SO_REUSEADDR` and `SO_REUSEPORT` must be set before the bind.
    let raw = Socket::new(plan.domain(), Type::DGRAM, Some(Protocol::UDP))?;
    raw.set_reuse_address(true)?;
    // `SO_REUSEPORT` is a unix socket option and socket2 has no setter for it elsewhere: the
    // first hosted Windows build of `transport-multicast` failed to compile on exactly this call.
    // Upstream sets it under `target_family = "unix"` only
    // (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.set_reuse_port(true)`); on Windows
    // `SO_REUSEADDR` alone is what lets several sockets bind the group port.
    #[cfg(unix)]
    raw.set_reuse_port(true)?;
    // A runtime that polls the socket needs it non-blocking.
    raw.set_nonblocking(true)?;
    // Egress interface: `IP_MULTICAST_IF` is independent of the bind address (the wildcard
    // below), because the multicast interface chooses the egress path, not the local name.
    plan.pin_egress(&raw)?;
    raw.bind(&plan.rx_bind_addr(port, rx_bind).into())?;

    // Every family-specific step stays on the `socket2` handle, so the two families share one
    // code path (tokio wraps neither the v6 hop limit nor the v6 egress interface).
    plan.join_groups(&raw, rx_bind.skips_a_refused_v4_join())?;
    plan.loop_back(&raw, cfg.loopback)?;
    // R311y832 — the hop limit. Set on THIS socket because this constructor's socket is the one
    // that sends as well as receives; zenoh splits the roles and sets it on its `ucast_sock`
    // (`multicast.rs:363`), which is the sending half there.
    if let Some(ttl) = cfg.ttl {
        plan.set_hop_limit(&raw, ttl)?;
    }
    Ok(Bound {
        socket: raw,
        peer: plan.peer(port),
    })
}

/// Make a socket that only sends to `group` on `port`: an ephemeral local port (or `#bind=`), the
/// egress interface pinned when `#iface=` names one, and the hop limit and the loopback policy
/// applied. No membership: a sender needs no group, so a `#join=` it would never use does not
/// refuse it either.
///
/// `link` says the socket is the send half of a multicast LINK. R3335 -- only a link pins its
/// unpinned egress to upstream's chosen interface (the `ucast_sock` of upstream's link calls
/// `set_multicast_if_v4` on its filled local address); the scouting senders that share this
/// constructor are not links and keep the kernel's choice.
///
/// `IP_MULTICAST_LOOP` is a property of the SENDING socket, so the policy belongs here as much as
/// on the joined socket; `OsDefault` sets nothing on either.
pub fn bind_sender(
    group: IpAddr,
    port: u16,
    cfg: &SocketConfig<'_>,
    link: bool,
) -> io::Result<Bound> {
    let plan = Plan::resolve(group, cfg, JoinsRead::No)?;
    let plan = if link {
        plan.with_link_default_iface(
            crate::link_interfaces::unicast_addresses_of_multicast_interfaces(),
        )
    } else {
        plan
    };
    // Without an iface this is exactly the `bind((UNSPECIFIED, 0))` the senders did before, so the
    // un-narrowed path is unchanged.
    let raw = Socket::new(plan.domain(), Type::DGRAM, Some(Protocol::UDP))?;
    raw.set_nonblocking(true)?;
    plan.pin_egress(&raw)?;
    // R2791 — `#bind=`. This is the socket upstream binds to it, and the fallback is the wildcard
    // this line used to pass unconditionally.
    raw.bind(&plan.egress_local_addr(cfg.bind, cfg.iface, port)?.into())?;
    plan.loop_back(&raw, cfg.loopback)?;
    // R311y832 — this is the SEND-only half, so the hop limit belongs here most directly; it is
    // zenoh's `ucast_sock`, the socket `multicast.rs:363` sets the TTL on.
    if let Some(ttl) = cfg.ttl {
        plan.set_hop_limit(&raw, ttl)?;
    }
    Ok(Bound {
        socket: raw,
        peer: plan.peer(port),
    })
}

#[cfg(test)]
mod tests;
