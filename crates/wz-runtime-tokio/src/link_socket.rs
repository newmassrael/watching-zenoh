// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2590 — the socket a link creates, configured from the locator's `#`-config
//! tail: `iface`, `bind` and `dscp`, the three `zenoh-link-commons` keys
//! (`io/zenoh-link-commons/src/lib.rs` @ `pub const BIND_SOCKET: &str = "bind";`).
//!
//! # One resolution, keyed by scheme and side
//!
//! Upstream does not read the three keys the same way in every link, and the
//! differences are observable, so [`LinkSocket::resolve`] is a table rather than
//! one rule. Each row below is what that link's own config reader does:
//!
//! | link | side | `iface` + `bind` | `bind` resolved | `bind` used | `dscp` |
//! |---|---|---|---|---|---|
//! | tcp | dial | refused | first non-multicast, else unbound | yes | yes |
//! | tcp | listen | accepted | same, then ignored | no | yes |
//! | tls | dial | refused | first, else an error | yes | yes |
//! | tls | listen | accepted | same, then ignored | no | yes |
//! | udp | dial | refused | first, else an error | yes | yes |
//! | udp | listen | accepted | not read | no | yes |
//! | quic, quic-datagram | both | refused | first, else an error | dial only | yes |
//! | ws | both | accepted | not read | no | no |
//!
//! Sources, by row: tcp reads through `TcpLinkConfig::new`
//! (`io/zenoh-links/zenoh-link-tcp/src/utils.rs`
//! @ `bind_socket = get_tcp_addrs(Address::from(bind_socket_str)).await?.next();`)
//! on both sides, and refuses the pair only in `new_link`
//! (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @ `if let (Some(_), Some(_)) = (config.get(BIND_INTERFACE), config.get(BIND_SOCKET)) {`);
//! `get_tcp_addrs` drops multicast addresses, which is why an all-multicast `bind` dials
//! unbound there. tls builds both of its configs with `get_tls_addr`
//! (`io/zenoh-links/zenoh-link-tls/src/utils.rs`
//! @ `bind_socket = Some(get_tls_addr(&Address::from(bind_socket_str)).await?);`),
//! which fails on an empty lookup. udp reads `bind` only in `new_link_inner`
//! (`io/zenoh-links/zenoh-link-udp/src/unicast.rs`
//! @ `.ok_or_else(|| zerror!("No UDP socket addr found bound to {}", address))?`).
//! quic refuses the pair inside `QuicSocketConfig::new`, which its listener
//! calls too (`io/zenoh-link-commons/src/quic/socket.rs`
//! @ `pub async fn new(epconf: &Config<'a>) -> ZResult<Self> {`). ws reads none
//! of the three; wz honours `iface` on it as it did before R2590, and that is
//! a wz extension this table does not widen.
//!
//! # Applying the options
//!
//! [`LinkSocket::configure`] sets the device and the DSCP on a socket before it
//! binds or connects, for tokio's `TcpSocket` and `UdpSocket` alike, through
//! [`SocketOptionTarget`]. The DSCP value is written as given to `IP_TOS` or
//! `IPV6_TCLASS`, chosen by the family of the address the socket was created
//! for, which is upstream's `set_dscp`
//! (`io/zenoh-link-commons/src/dscp.rs` @ `SocketAddr::V4(_) => socket.into().set_tos(dscp)?,`).
//! On a platform without the option upstream warns and continues, and so does
//! this.

use std::io;
use std::net::SocketAddr;

use wz_session_core::locator::{LinkSocketOptions, Proto};

/// Which end of a link a socket is being built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSide {
    /// A socket that connects to a peer.
    Dial,
    /// A socket that accepts peers.
    Listen,
}

/// The socket options a link applies, after its scheme's reader has run.
///
/// Built only by [`LinkSocket::resolve`] (or [`LinkSocket::NONE`]), so a value
/// in hand has already passed the scheme's refusals and carries a `bind` only
/// where that scheme dials from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSocket<'a> {
    iface: Option<&'a str>,
    bind: Option<SocketAddr>,
    dscp: Option<u32>,
}

/// How a scheme turns a `bind` string into an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindLookup {
    /// The key is not read.
    NotRead,
    /// The first resolved address that is not multicast; none leaves the
    /// socket unbound (tcp).
    FirstNonMulticast,
    /// The first resolved address; none is an error naming the scheme.
    FirstOrError(&'static str),
}

/// One row of the table in the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemeReader {
    refuses_iface_with_bind: bool,
    bind: BindLookup,
    reads_dscp: bool,
}

impl SchemeReader {
    fn of(proto: Proto, side: LinkSide) -> SchemeReader {
        let dial = side == LinkSide::Dial;
        match proto {
            Proto::Tcp => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: BindLookup::FirstNonMulticast,
                reads_dscp: true,
            },
            Proto::Tls => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: BindLookup::FirstOrError("TLS"),
                reads_dscp: true,
            },
            Proto::Udp => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: if dial {
                    BindLookup::FirstOrError("UDP")
                } else {
                    BindLookup::NotRead
                },
                reads_dscp: true,
            },
            Proto::Quic | Proto::QuicDatagram => SchemeReader {
                refuses_iface_with_bind: true,
                bind: BindLookup::FirstOrError("QUIC"),
                reads_dscp: true,
            },
            Proto::Ws => SchemeReader {
                refuses_iface_with_bind: false,
                bind: BindLookup::NotRead,
                reads_dscp: false,
            },
        }
    }
}

impl<'a> LinkSocket<'a> {
    /// A socket with no device, no local bind and no DSCP.
    pub const NONE: LinkSocket<'static> = LinkSocket {
        iface: None,
        bind: None,
        dscp: None,
    };

    /// Run `proto`'s reader for `side` over `options`: refuse what it refuses,
    /// resolve `bind` the way it does, and keep only what it applies.
    pub async fn resolve(
        options: &'a LinkSocketOptions,
        proto: Proto,
        side: LinkSide,
    ) -> io::Result<LinkSocket<'a>> {
        let reader = SchemeReader::of(proto, side);
        if reader.refuses_iface_with_bind && options.iface.is_some() && options.bind.is_some() {
            // Upstream's text, formatted the way its `bail!` formats it.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Using Config options `iface` and `bind` in conjunction is unsupported at this time iface \"bind\"",
            ));
        }
        let bind = match (reader.bind, options.bind.as_deref()) {
            (BindLookup::NotRead, _) | (_, None) => None,
            (BindLookup::FirstNonMulticast, Some(address)) => tokio::net::lookup_host(address)
                .await?
                .find(|addr| !addr.ip().is_multicast()),
            (BindLookup::FirstOrError(scheme), Some(address)) => Some(
                tokio::net::lookup_host(address)
                    .await?
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!("Couldn't resolve {scheme} bind address: {address}"),
                        )
                    })?,
            ),
        };
        Ok(LinkSocket {
            iface: options.iface.as_deref(),
            bind: if side == LinkSide::Dial { bind } else { None },
            dscp: if reader.reads_dscp {
                options.dscp
            } else {
                None
            },
        })
    }

    /// The device the socket is bound to, if any.
    pub fn iface(&self) -> Option<&'a str> {
        self.iface
    }

    /// The local address a dialing socket binds before it connects, if any.
    pub fn bind(&self) -> Option<SocketAddr> {
        self.bind
    }

    /// The value written to `IP_TOS` / `IPV6_TCLASS`, if any.
    pub fn dscp(&self) -> Option<u32> {
        self.dscp
    }

    /// Set the device and the DSCP on `socket`, created for `family`'s address
    /// family, before it binds or connects.
    pub(crate) fn configure<S: SocketOptionTarget>(
        &self,
        socket: &S,
        family: SocketAddr,
    ) -> io::Result<()> {
        if let Some(iface) = self.iface {
            socket.bind_device(iface)?;
        }
        if let Some(dscp) = self.dscp {
            match family {
                SocketAddr::V4(_) => socket.set_dscp_v4(dscp)?,
                SocketAddr::V6(_) => socket.set_dscp_v6(dscp)?,
            }
        }
        Ok(())
    }

    /// The address a dialing UDP-family socket binds: `bind` when given, else
    /// the unspecified address of the peer's family with an ephemeral port, as
    /// upstream's udp and quic dials do.
    pub(crate) fn dial_local_addr(&self, peer: SocketAddr) -> SocketAddr {
        use std::net::{Ipv4Addr, Ipv6Addr};
        self.bind.unwrap_or(match peer {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        })
    }
}

/// A socket [`LinkSocket::configure`] can set options on.
pub(crate) trait SocketOptionTarget {
    fn bind_device(&self, iface: &str) -> io::Result<()>;
    fn set_dscp_v4(&self, dscp: u32) -> io::Result<()>;
    fn set_dscp_v6(&self, dscp: u32) -> io::Result<()>;
}

/// The platform set on which tokio offers `set_tos_v4`, and the warning
/// upstream gives outside it.
macro_rules! dscp_v4 {
    ($socket:expr, $dscp:expr) => {{
        #[cfg(not(any(
            target_os = "fuchsia",
            target_os = "redox",
            target_os = "solaris",
            target_os = "illumos",
            target_os = "haiku",
            target_os = "wasi",
        )))]
        {
            $socket.set_tos_v4($dscp)
        }
        #[cfg(any(
            target_os = "fuchsia",
            target_os = "redox",
            target_os = "solaris",
            target_os = "illumos",
            target_os = "haiku",
            target_os = "wasi",
        ))]
        {
            let _ = ($socket, $dscp);
            log::warn!(
                "IPv4 DSCP is unsupported on platform {}",
                std::env::consts::OS
            );
            Ok(())
        }
    }};
}

/// The platform set on which tokio offers `set_tclass_v6`, and the warning
/// upstream gives outside it.
macro_rules! dscp_v6 {
    ($socket:expr, $dscp:expr) => {{
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "cygwin",
        ))]
        {
            $socket.set_tclass_v6($dscp)
        }
        #[cfg(not(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "cygwin",
        )))]
        {
            let _ = ($socket, $dscp);
            log::warn!(
                "IPv6 DSCP is unsupported on platform {}",
                std::env::consts::OS
            );
            Ok(())
        }
    }};
}

impl SocketOptionTarget for tokio::net::TcpSocket {
    fn bind_device(&self, iface: &str) -> io::Result<()> {
        crate::iface_bind::bind_socket_to_device(self, iface)
    }
    fn set_dscp_v4(&self, dscp: u32) -> io::Result<()> {
        dscp_v4!(self, dscp)
    }
    fn set_dscp_v6(&self, dscp: u32) -> io::Result<()> {
        dscp_v6!(self, dscp)
    }
}

impl SocketOptionTarget for tokio::net::UdpSocket {
    fn bind_device(&self, iface: &str) -> io::Result<()> {
        crate::iface_bind::bind_socket_to_device(self, iface)
    }
    fn set_dscp_v4(&self, dscp: u32) -> io::Result<()> {
        dscp_v4!(self, dscp)
    }
    fn set_dscp_v6(&self, dscp: u32) -> io::Result<()> {
        dscp_v6!(self, dscp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(iface: Option<&str>, bind: Option<&str>, dscp: Option<u32>) -> LinkSocketOptions {
        LinkSocketOptions {
            iface: iface.map(str::to_string),
            bind: bind.map(str::to_string),
            dscp,
        }
    }

    const ALL: [Proto; 6] = [
        Proto::Tcp,
        Proto::Tls,
        Proto::Udp,
        Proto::Quic,
        Proto::QuicDatagram,
        Proto::Ws,
    ];

    /// The `iface` + `bind` refusal lands exactly on upstream's five rows:
    /// every unicast dial except ws, and the quic listeners.
    #[tokio::test]
    async fn iface_with_bind_is_refused_where_upstream_refuses_it() {
        let both = options(Some("lo"), Some("127.0.0.1:0"), None);
        for proto in ALL {
            for side in [LinkSide::Dial, LinkSide::Listen] {
                let refused = LinkSocket::resolve(&both, proto, side).await.is_err();
                let expected = match (proto, side) {
                    (Proto::Ws, _) => false,
                    (Proto::Quic | Proto::QuicDatagram, _) => true,
                    (_, LinkSide::Dial) => true,
                    (_, LinkSide::Listen) => false,
                };
                assert_eq!(refused, expected, "{proto:?} {side:?}");
            }
        }
    }

    /// `bind` reaches only dials, and never ws; `dscp` reaches every side of
    /// every scheme but ws.
    #[tokio::test]
    async fn bind_reaches_dials_only_and_dscp_every_scheme_but_ws() {
        let opts = options(None, Some("127.0.0.1:4000"), Some(0x10));
        let local: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        for proto in ALL {
            for side in [LinkSide::Dial, LinkSide::Listen] {
                let socket = LinkSocket::resolve(&opts, proto, side).await.unwrap();
                let bound = side == LinkSide::Dial && proto != Proto::Ws;
                assert_eq!(socket.bind(), bound.then_some(local), "{proto:?} {side:?}");
                let marked = proto != Proto::Ws;
                assert_eq!(socket.dscp(), marked.then_some(0x10), "{proto:?} {side:?}");
            }
        }
    }

    /// tcp drops a multicast `bind` and dials unbound; tls keeps it, and the
    /// OS refuses it at bind time, as upstream's two readers do.
    #[tokio::test]
    async fn a_multicast_bind_is_dropped_by_tcp_only() {
        let opts = options(None, Some("224.0.0.1:0"), None);
        let tcp = LinkSocket::resolve(&opts, Proto::Tcp, LinkSide::Dial)
            .await
            .unwrap();
        assert_eq!(tcp.bind(), None);
        let tls = LinkSocket::resolve(&opts, Proto::Tls, LinkSide::Dial)
            .await
            .unwrap();
        assert_eq!(tls.bind(), Some("224.0.0.1:0".parse().unwrap()));
    }

    /// The listener side of udp does not look `bind` up, so an unresolvable
    /// one does not fail it; tcp's listener does look it up.
    #[tokio::test]
    async fn only_the_readers_that_look_bind_up_can_fail_on_it() {
        let opts = options(None, Some("no-such-host.invalid:0"), None);
        assert!(LinkSocket::resolve(&opts, Proto::Udp, LinkSide::Listen)
            .await
            .is_ok());
        assert!(LinkSocket::resolve(&opts, Proto::Ws, LinkSide::Dial)
            .await
            .is_ok());
        assert!(LinkSocket::resolve(&opts, Proto::Tcp, LinkSide::Listen)
            .await
            .is_err());
        assert!(LinkSocket::resolve(&opts, Proto::Udp, LinkSide::Dial)
            .await
            .is_err());
    }

    /// The DSCP a socket carries is the one the kernel reports back, on the
    /// option of the socket's own family.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn dscp_is_written_to_the_option_of_the_sockets_family() {
        let opts = options(None, None, Some(0x28));
        let socket = LinkSocket::resolve(&opts, Proto::Tcp, LinkSide::Dial)
            .await
            .unwrap();
        let v4 = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .configure(&v4, "127.0.0.1:1".parse().unwrap())
            .unwrap();
        assert_eq!(v4.tos_v4().unwrap(), 0x28);
        let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        socket.configure(&v6, "[::1]:1".parse().unwrap()).unwrap();
        assert_eq!(v6.tclass_v6().unwrap(), 0x28);
    }
}
