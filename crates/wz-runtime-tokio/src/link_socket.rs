// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2590 — the transport a link creates, configured from the locator's
//! `#`-config tail: `iface`, `bind` and `dscp`, the three `zenoh-link-commons`
//! keys (`io/zenoh-link-commons/src/lib.rs` @ `pub const BIND_SOCKET: &str = "bind";`),
//! the two TCP socket buffers R2591 added, and the two quinn transport keys
//! R2598 added.
//!
//! # One resolution, keyed by scheme and side
//!
//! Upstream does not read these keys the same way in every link, and the
//! differences are observable, so [`crate::link_socket::LinkSocket::resolve`] is a table rather than
//! one rule. Each row below is what that link's own config reader does:
//!
//! | link | side | `iface` + `bind` | `bind` resolved | `bind` used | `dscp` | `so_sndbuf`, `so_rcvbuf` | `initial_mtu`, `mtu_discovery_interval_secs` |
//! |---|---|---|---|---|---|---|---|
//! | tcp | dial | refused | first non-multicast, else unbound | yes | yes | yes | no |
//! | tcp | listen | accepted | same, then ignored | no | yes | yes | no |
//! | tls | dial | refused | first, else an error | yes | yes | yes | no |
//! | tls | listen | accepted | same, then ignored | no | yes | yes | no |
//! | udp | dial | refused | first, else an error | yes | yes | no | no |
//! | udp | listen | accepted | not read | no | yes | no | no |
//! | quic, quic-datagram | both | refused | first, else an error | dial only | yes | no | yes |
//! | ws | both | accepted | not read | no | no | no | no |
//!
//! R2598 added the last column, and it is the first one that is NOT a socket
//! option: `initial_mtu` and `mtu_discovery_interval_secs` configure quinn's
//! `TransportConfig` rather than the UDP socket beneath it
//! (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub const QUIC_INITIAL_MTU: &str = "initial_mtu";`).
//! They are the QUIC family's alone because they are declared by the commons
//! `quic` module, which no other link's reader reaches. They also have no
//! per-link-kind layer under them, unlike every other column: upstream's config
//! file has `tcp` and `tls` sections and no `quic` one, so
//! [`crate::link_socket::LinkDefaults::for_proto`] answers `NONE` for them and
//! the locator is the
//! only source.
//!
//! R2591 added the buffer column. The two buffer keys are TCP's
//! (`io/zenoh-link-commons/src/lib.rs` @ `pub const TCP_SO_SND_BUF: &str = "so_sndbuf";`),
//! read by `TcpLinkConfig::new` on both sides and by both of tls's configs, and
//! applied to the socket in the same step as the device and the DSCP
//! (`io/zenoh-link-commons/src/tcp.rs` @ `socket.set_send_buffer_size(size)?;`).
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
//! `LinkSocket::configure` sets the device and the DSCP on a socket before it
//! binds or connects, for tokio's `TcpSocket` and `UdpSocket` alike, through
//! the crate-private `SocketOptionTarget` trait. The DSCP value is written as given to `IP_TOS` or
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

/// R2592 — the per-link-kind configuration upstream merges UNDER every
/// endpoint of that kind: the base [`LinkSocket::resolve`] layers a locator's
/// own options over.
///
/// Upstream builds one parameter string per link kind from the zenoh config
/// file (`io/zenoh-link/src/lib.rs` @ `insert_config(LinkKind::Tcp, self.tcp_inspector.inspect_config(config));`)
/// and applies it to every dial and every listen of that kind, whichever path
/// produced the endpoint. wz had no such layer, so a node could set a socket
/// option per locator and never for a whole link kind.
///
/// The keys are exactly the socket keys upstream's inspectors put there:
/// `so_rcvbuf` and `so_sndbuf` for tcp
/// (`io/zenoh-links/zenoh-link-tcp/src/utils.rs` @ `ps.push((TCP_SO_RCV_BUF, &rx_buffer_size));`)
/// and for tls. Any other key is refused by [`LinkDefaults::set`]: a key upstream
/// never renders into this layer would make the layer a wz-only capability. The
/// tls inspector also renders certificate keys, which reach wz through
/// `TlsDialConfig` / `TlsAcceptConfig` rather than through socket options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkDefaults {
    tcp: LinkSocketOptions,
    tls: LinkSocketOptions,
}

/// Why [`LinkDefaults::set`] refused a span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkDefaultsError {
    /// Upstream renders no per-kind socket configuration for this link kind.
    NoLayerForKind(Proto),
    /// Upstream's inspector for this kind never renders this key.
    KeyNotInLayer {
        /// The link kind named.
        proto: Proto,
        /// The key it was given.
        key: String,
    },
    /// A key in the layer with an unusable value.
    BadValue(wz_session_core::locator::LocatorParseError),
}

impl core::fmt::Display for LinkDefaultsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoLayerForKind(proto) => {
                write!(
                    f,
                    "no per-link-kind socket configuration exists for {proto:?}"
                )
            }
            Self::KeyNotInLayer { proto, key } => write!(
                f,
                "`{key}` is not a key zenoh's {proto:?} link configuration carries \
                 (it carries `so_rcvbuf` and `so_sndbuf`)"
            ),
            Self::BadValue(e) => write!(f, "{e:?}"),
        }
    }
}

impl std::error::Error for LinkDefaultsError {}

impl LinkDefaults {
    /// The socket keys each link kind's layer carries, as upstream's inspectors
    /// render them.
    const KEYS: &'static [&'static str] = &["so_rcvbuf", "so_sndbuf"];

    /// Layer the `key=value;...` span onto `proto`'s defaults. A key the span
    /// names replaces the one already held; the rest are kept.
    pub fn set(&mut self, proto: Proto, span: &str) -> Result<(), LinkDefaultsError> {
        let slot = match proto {
            Proto::Tcp => &mut self.tcp,
            Proto::Tls => &mut self.tls,
            other => return Err(LinkDefaultsError::NoLayerForKind(other)),
        };
        if let Some(key) =
            wz_session_core::locator::config_span_keys(span).find(|k| !Self::KEYS.contains(k))
        {
            return Err(LinkDefaultsError::KeyNotInLayer {
                proto,
                key: key.to_string(),
            });
        }
        let named =
            LinkSocketOptions::from_config_span(span).map_err(LinkDefaultsError::BadValue)?;
        slot.so_rcvbuf = named.so_rcvbuf.or(slot.so_rcvbuf);
        slot.so_sndbuf = named.so_sndbuf.or(slot.so_sndbuf);
        Ok(())
    }

    /// The defaults a `proto` endpoint is layered on; none for a kind without
    /// a layer.
    pub fn for_proto(&self, proto: Proto) -> &LinkSocketOptions {
        match proto {
            Proto::Tcp => &self.tcp,
            Proto::Tls => &self.tls,
            _ => &LinkSocketOptions::NONE,
        }
    }
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
    so_sndbuf: Option<u32>,
    so_rcvbuf: Option<u32>,
    initial_mtu: Option<u16>,
    mtu_discovery_interval_secs: Option<u64>,
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
    reads_buffers: bool,
    /// R2598 — whether this scheme reads the two quinn transport keys. Only the
    /// QUIC family does: they are declared by `zenoh-link-commons`'s `quic`
    /// module, which no other link's reader reaches.
    reads_quic_mtu: bool,
}

impl SchemeReader {
    fn of(proto: Proto, side: LinkSide) -> SchemeReader {
        let dial = side == LinkSide::Dial;
        match proto {
            Proto::Tcp => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: BindLookup::FirstNonMulticast,
                reads_dscp: true,
                reads_buffers: true,
                reads_quic_mtu: false,
            },
            Proto::Tls => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: BindLookup::FirstOrError("TLS"),
                reads_dscp: true,
                reads_buffers: true,
                reads_quic_mtu: false,
            },
            Proto::Udp => SchemeReader {
                refuses_iface_with_bind: dial,
                bind: if dial {
                    BindLookup::FirstOrError("UDP")
                } else {
                    BindLookup::NotRead
                },
                reads_dscp: true,
                reads_buffers: false,
                reads_quic_mtu: false,
            },
            Proto::Quic | Proto::QuicDatagram => SchemeReader {
                refuses_iface_with_bind: true,
                bind: BindLookup::FirstOrError("QUIC"),
                reads_dscp: true,
                reads_buffers: false,
                reads_quic_mtu: true,
            },
            Proto::Ws => SchemeReader {
                refuses_iface_with_bind: false,
                bind: BindLookup::NotRead,
                reads_dscp: false,
                reads_buffers: false,
                reads_quic_mtu: false,
            },
        }
    }
}

impl<'a> LinkSocket<'a> {
    /// A socket with no device, no local bind, no DSCP and the kernel's
    /// buffer sizes.
    pub const NONE: LinkSocket<'static> = LinkSocket {
        iface: None,
        bind: None,
        dscp: None,
        so_sndbuf: None,
        so_rcvbuf: None,
        initial_mtu: None,
        mtu_discovery_interval_secs: None,
    };

    /// Run `proto`'s reader for `side` over the locator's `options` layered on
    /// `defaults`, this link kind's configured values: refuse what the reader
    /// refuses, resolve `bind` the way it does, and keep only what it applies.
    ///
    /// R2592 — the layering is upstream's, key by key: the per-link-kind
    /// configuration is the base and the endpoint's own parameters overwrite it
    /// (`io/zenoh-transport/src/unicast/manager.rs` @ `// Overwrite config with current endpoint parameters`),
    /// before the link's reader sees any of it. So a key the locator names wins,
    /// a key only the defaults name still applies, and every refusal below
    /// judges the merged set. Pass `&LinkSocketOptions::NONE` for no defaults.
    pub async fn resolve(
        options: &'a LinkSocketOptions,
        defaults: &'a LinkSocketOptions,
        proto: Proto,
        side: LinkSide,
    ) -> io::Result<LinkSocket<'a>> {
        let reader = SchemeReader::of(proto, side);
        let iface = options.iface.as_deref().or(defaults.iface.as_deref());
        let bind_key = options.bind.as_deref().or(defaults.bind.as_deref());
        if reader.refuses_iface_with_bind && iface.is_some() && bind_key.is_some() {
            // Upstream's text, formatted the way its `bail!` formats it.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Using Config options `iface` and `bind` in conjunction is unsupported at this time iface \"bind\"",
            ));
        }
        let bind = match (reader.bind, bind_key) {
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
            iface,
            bind: if side == LinkSide::Dial { bind } else { None },
            dscp: options.dscp.or(defaults.dscp).filter(|_| reader.reads_dscp),
            so_sndbuf: options
                .so_sndbuf
                .or(defaults.so_sndbuf)
                .filter(|_| reader.reads_buffers),
            so_rcvbuf: options
                .so_rcvbuf
                .or(defaults.so_rcvbuf)
                .filter(|_| reader.reads_buffers),
            // R2598 — the locator ALONE, deliberately, where every key above
            // falls back to the per-link-kind layer. Upstream's config file has
            // `tcp` and `tls` sections and NO `quic` one, so there is no layer
            // for these two to be merged under; `LinkDefaults::for_proto`
            // already answers `NONE` for the QUIC family, so an `.or(defaults)`
            // here would read as a layering that exists and cannot fire.
            initial_mtu: options.initial_mtu.filter(|_| reader.reads_quic_mtu),
            mtu_discovery_interval_secs: options
                .mtu_discovery_interval_secs
                .filter(|_| reader.reads_quic_mtu),
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

    /// The `SO_SNDBUF` a stream socket is given, if any.
    pub fn so_sndbuf(&self) -> Option<u32> {
        self.so_sndbuf
    }

    /// The `SO_RCVBUF` a stream socket is given, if any.
    pub fn so_rcvbuf(&self) -> Option<u32> {
        self.so_rcvbuf
    }

    /// R2598 — the maximum UDP payload quinn assumes before MTU discovery, if
    /// this scheme reads one.
    pub fn initial_mtu(&self) -> Option<u16> {
        self.initial_mtu
    }

    /// R2598 — the wait between completed MTU discovery runs, if this scheme
    /// reads one.
    pub fn mtu_discovery_interval_secs(&self) -> Option<u64> {
        self.mtu_discovery_interval_secs
    }

    /// R2598 — write this locator's quinn transport keys onto `transport`, the
    /// SINGLE seam both QUIC endpoint constructors go through.
    ///
    /// Mirrors upstream's `QuicMtuConfig::apply_to_transport`
    /// (`io/zenoh-link-commons/src/quic/utils.rs` @ `fn apply_to_transport(&self, quic_transport_conf: &mut TransportConfig) {`)
    /// call for call, including that a present interval REPLACES the whole
    /// `MtuDiscoveryConfig` rather than editing quinn's default in place.
    ///
    /// ⚠ `mtu_discovery_interval_secs` HAS NO BEHAVIOURAL WITNESS and the
    /// residue is named rather than papered over. quinn exposes no getter for
    /// the discovery config, and the interval only schedules a RE-RUN
    /// (`quinn-proto` @ `let next_mtud_activation = now + self.config.interval;`)
    /// which issues no probes at all on a path already at its ceiling. Measured
    /// on loopback, four arms — default and 1s, with and without discovery
    /// headroom — every one sent exactly 4 probes. quinn tests its own
    /// reactivation against a SYNTHETIC path for the same reason. So this line
    /// is witnessed by construction: it is the only route from the parsed value
    /// to quinn, and deleting it fails to compile the caller rather than
    /// quietly passing a test. `initial_mtu` beside it IS witnessed on the
    /// wire, and on BOTH sides, since a client-only apply still moves the
    /// client's own `max_datagram_size` by the full amount.
    #[cfg(feature = "transport-link-quic")]
    pub(crate) fn apply_quic_transport(&self, transport: &mut quinn::TransportConfig) {
        if let Some(mtu) = self.initial_mtu {
            transport.initial_mtu(mtu);
        }
        if let Some(interval) = self.mtu_discovery_interval_secs {
            let mut discovery = quinn::MtuDiscoveryConfig::default();
            discovery.interval(std::time::Duration::from_secs(interval));
            transport.mtu_discovery_config(Some(discovery));
        }
    }

    /// [`Self::configure`] plus the two buffer sizes, for the TCP socket under
    /// a tcp, tls or ws link. Only a stream socket takes them: the schemes
    /// whose reader keeps the buffers are exactly the ones that build one, so a
    /// datagram socket never needs a buffer setter.
    ///
    /// Gated on the two features whose TCP socket builders call it, the tcp
    /// connect and listen primitives and the ws dial.
    #[cfg(any(feature = "transport-link-tcp", feature = "transport-link-ws"))]
    pub(crate) fn configure_stream(
        &self,
        socket: &tokio::net::TcpSocket,
        family: SocketAddr,
    ) -> io::Result<()> {
        self.configure(socket, family)?;
        if let Some(size) = self.so_sndbuf {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(size) = self.so_rcvbuf {
            socket.set_recv_buffer_size(size)?;
        }
        Ok(())
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
    /// upstream's udp and quic dials do. Gated on those two dialers, its only
    /// callers, so a tcp- or ws-only build carries no dead method.
    #[cfg(any(feature = "transport-link-udp", feature = "transport-link-quic"))]
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
            ..LinkSocketOptions::NONE
        }
    }

    /// A locator's options resolved with no per-link-kind defaults under them.
    async fn resolve_alone(
        options: &LinkSocketOptions,
        proto: Proto,
        side: LinkSide,
    ) -> io::Result<LinkSocket<'_>> {
        LinkSocket::resolve(options, &LinkSocketOptions::NONE, proto, side).await
    }

    /// R2592 — the defaults layer: a key only the defaults name applies, a key
    /// the locator names wins, keys merge one by one, and a kind's defaults
    /// reach only that kind. These are the four cases measured on zenohd with
    /// `--cfg transport/link/tcp/...` before the layer was built.
    #[tokio::test]
    async fn a_locator_key_wins_over_its_kinds_default_key_by_key() {
        let mut defaults = LinkDefaults::default();
        defaults
            .set(Proto::Tcp, "so_rcvbuf=4096;so_sndbuf=8192")
            .unwrap();
        let tcp = defaults.for_proto(Proto::Tcp);

        let silent = LinkSocketOptions::NONE;
        let alone = LinkSocket::resolve(&silent, tcp, Proto::Tcp, LinkSide::Dial)
            .await
            .unwrap();
        assert_eq!(
            (alone.so_rcvbuf(), alone.so_sndbuf()),
            (Some(4096), Some(8192))
        );

        let own = LinkSocketOptions {
            so_rcvbuf: Some(16384),
            ..LinkSocketOptions::NONE
        };
        let merged = LinkSocket::resolve(&own, tcp, Proto::Tcp, LinkSide::Listen)
            .await
            .unwrap();
        assert_eq!(
            (merged.so_rcvbuf(), merged.so_sndbuf()),
            (Some(16384), Some(8192))
        );

        assert_eq!(defaults.for_proto(Proto::Tls), &LinkSocketOptions::NONE);
        assert_eq!(defaults.for_proto(Proto::Udp), &LinkSocketOptions::NONE);
    }

    /// R2592 — the layer carries only what upstream's inspectors render into
    /// it, and only for the kinds that have one.
    #[test]
    fn the_defaults_layer_refuses_what_upstream_never_puts_there() {
        let mut defaults = LinkDefaults::default();
        assert_eq!(
            defaults.set(Proto::Tcp, "so_rcvbuf=4096;bind=127.0.0.1:0"),
            Err(LinkDefaultsError::KeyNotInLayer {
                proto: Proto::Tcp,
                key: "bind".to_string(),
            })
        );
        assert_eq!(
            defaults.set(Proto::Udp, "so_rcvbuf=4096"),
            Err(LinkDefaultsError::NoLayerForKind(Proto::Udp))
        );
        assert!(matches!(
            defaults.set(Proto::Tls, "so_sndbuf=lots"),
            Err(LinkDefaultsError::BadValue(_))
        ));
        assert_eq!(
            defaults,
            LinkDefaults::default(),
            "a refused span changes nothing"
        );
        // A second span layers over the first rather than replacing it.
        defaults.set(Proto::Tls, "so_sndbuf=8192").unwrap();
        defaults.set(Proto::Tls, "so_rcvbuf=4096").unwrap();
        assert_eq!(
            defaults.for_proto(Proto::Tls),
            &LinkSocketOptions {
                so_rcvbuf: Some(4096),
                so_sndbuf: Some(8192),
                ..LinkSocketOptions::NONE
            }
        );
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
                let refused = resolve_alone(&both, proto, side).await.is_err();
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
                let socket = resolve_alone(&opts, proto, side).await.unwrap();
                let bound = side == LinkSide::Dial && proto != Proto::Ws;
                assert_eq!(socket.bind(), bound.then_some(local), "{proto:?} {side:?}");
                let marked = proto != Proto::Ws;
                assert_eq!(socket.dscp(), marked.then_some(0x10), "{proto:?} {side:?}");
            }
        }
    }

    /// R2591 — the TCP buffer keys reach tcp and tls, on both sides, and no
    /// other scheme.
    #[tokio::test]
    async fn the_buffer_keys_reach_tcp_and_tls_on_both_sides_only() {
        let opts = LinkSocketOptions {
            so_sndbuf: Some(8192),
            so_rcvbuf: Some(4096),
            ..LinkSocketOptions::NONE
        };
        for proto in ALL {
            for side in [LinkSide::Dial, LinkSide::Listen] {
                let socket = resolve_alone(&opts, proto, side).await.unwrap();
                let stream = matches!(proto, Proto::Tcp | Proto::Tls);
                assert_eq!(
                    socket.so_sndbuf(),
                    stream.then_some(8192),
                    "{proto:?} {side:?}"
                );
                assert_eq!(
                    socket.so_rcvbuf(),
                    stream.then_some(4096),
                    "{proto:?} {side:?}"
                );
            }
        }
    }

    /// R2598 — the two quinn transport keys reach the QUIC family on both
    /// sides and NO other scheme, swept over every `Proto` rather than a list.
    ///
    /// Both sides matter and the asymmetry is why this asserts them separately:
    /// each endpoint's own `initial_mtu` governs what THAT endpoint may send,
    /// so a build applying it on the dial alone still moves the dialer's own
    /// `max_datagram_size` by the full amount — measured on loopback before
    /// this test was written, which is exactly the half-build a dial-only
    /// assertion would have waved through.
    #[tokio::test]
    async fn the_quic_transport_keys_reach_the_quic_family_on_both_sides_only() {
        let opts = LinkSocketOptions {
            initial_mtu: Some(1400),
            mtu_discovery_interval_secs: Some(30),
            ..LinkSocketOptions::NONE
        };
        for proto in ALL {
            for side in [LinkSide::Dial, LinkSide::Listen] {
                let socket = resolve_alone(&opts, proto, side).await.unwrap();
                let quic = matches!(proto, Proto::Quic | Proto::QuicDatagram);
                assert_eq!(
                    socket.initial_mtu(),
                    quic.then_some(1400),
                    "{proto:?} {side:?}"
                );
                assert_eq!(
                    socket.mtu_discovery_interval_secs(),
                    quic.then_some(30),
                    "{proto:?} {side:?}"
                );
            }
        }
    }

    /// R2598 — these two keys have NO per-link-kind layer under them, unlike
    /// every other key this resolver carries.
    ///
    /// Upstream's config file has `tcp` and `tls` sections and no `quic` one,
    /// so there is nowhere for a default to come from. The assertion is that a
    /// silent locator stays silent even when a defaults value is handed in:
    /// were `resolve` to fall back the way it does for `dscp`, this reads the
    /// planted value back and fails.
    #[tokio::test]
    async fn the_quic_transport_keys_have_no_defaults_layer_to_fall_back_to() {
        let planted = LinkSocketOptions {
            initial_mtu: Some(9000),
            mtu_discovery_interval_secs: Some(7),
            ..LinkSocketOptions::NONE
        };
        for proto in [Proto::Quic, Proto::QuicDatagram] {
            let socket =
                LinkSocket::resolve(&LinkSocketOptions::NONE, &planted, proto, LinkSide::Dial)
                    .await
                    .unwrap();
            assert_eq!(socket.initial_mtu(), None, "{proto:?}");
            assert_eq!(socket.mtu_discovery_interval_secs(), None, "{proto:?}");
        }
    }

    /// R2591 — the buffers land on the socket: the kernel reports back twice
    /// what was set, its documented doubling (`man 7 socket`, `SO_SNDBUF`),
    /// which is also what `ss` showed for zenohd's own socket.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn the_buffers_are_the_ones_the_kernel_reports_back() {
        let opts = LinkSocketOptions {
            so_sndbuf: Some(8192),
            so_rcvbuf: Some(4096),
            ..LinkSocketOptions::NONE
        };
        let socket = resolve_alone(&opts, Proto::Tcp, LinkSide::Dial)
            .await
            .unwrap();
        let tcp = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .configure_stream(&tcp, "127.0.0.1:1".parse().unwrap())
            .unwrap();
        assert_eq!(tcp.send_buffer_size().unwrap(), 2 * 8192);
        assert_eq!(tcp.recv_buffer_size().unwrap(), 2 * 4096);
    }

    /// tcp drops a multicast `bind` and dials unbound; tls keeps it, and the
    /// OS refuses it at bind time, as upstream's two readers do.
    #[tokio::test]
    async fn a_multicast_bind_is_dropped_by_tcp_only() {
        let opts = options(None, Some("224.0.0.1:0"), None);
        let tcp = resolve_alone(&opts, Proto::Tcp, LinkSide::Dial)
            .await
            .unwrap();
        assert_eq!(tcp.bind(), None);
        let tls = resolve_alone(&opts, Proto::Tls, LinkSide::Dial)
            .await
            .unwrap();
        assert_eq!(tls.bind(), Some("224.0.0.1:0".parse().unwrap()));
    }

    /// The listener side of udp does not look `bind` up, so an unresolvable
    /// one does not fail it; tcp's listener does look it up.
    #[tokio::test]
    async fn only_the_readers_that_look_bind_up_can_fail_on_it() {
        let opts = options(None, Some("no-such-host.invalid:0"), None);
        assert!(resolve_alone(&opts, Proto::Udp, LinkSide::Listen)
            .await
            .is_ok());
        assert!(resolve_alone(&opts, Proto::Ws, LinkSide::Dial)
            .await
            .is_ok());
        assert!(resolve_alone(&opts, Proto::Tcp, LinkSide::Listen)
            .await
            .is_err());
        assert!(resolve_alone(&opts, Proto::Udp, LinkSide::Dial)
            .await
            .is_err());
    }

    /// The DSCP a socket carries is the one the kernel reports back, on the
    /// option of the socket's own family.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn dscp_is_written_to_the_option_of_the_sockets_family() {
        let opts = options(None, None, Some(0x28));
        let socket = resolve_alone(&opts, Proto::Tcp, LinkSide::Dial)
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
