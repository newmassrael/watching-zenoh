// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eu — mode-agnostic session-open orchestration over the R311et link
//! pipeline.
//!
//! [`dial_locator`] dispatches an [`AnyLocator`]'s scheme to a raw
//! transport (the mode-agnostic seam: a discovered locator is dialed the
//! same way regardless of how scouting found it).
//! [`connect_and_open_session`] dials, splits the connection into the
//! [`crate::link_pipeline`] read/write halves, wires the unicast session FSM
//! in the Initiator role, and drives the inbound handshake to Established —
//! returning the live [`OpenedSession`] handles for the caller to run the
//! steady state via [`crate::session_glue::drive_session_until_terminal`].
//!
//! This is the reusable lib form of the open path wz-ap-demo's `runner.rs`
//! assembles inline; R311ev makes the demo consume it (removing the
//! duplication). R311ew wired the static scouting -> parse -> dial -> open
//! seam; R311ez generalised the dial to a transport union so a `udp/...`
//! locator opens a datagram session ([`crate::udp_pipeline`]) the same way
//! a `tcp/...` locator opens a stream session. R311nv extends the union to
//! the serial tty backend ([`crate::serial_pipeline`]): a `serial/...`
//! locator dials through the link handshake into the same split path, with
//! the `AnyLocator` sum type ([`wz_session_core::locator`]) the scheme
//! dispatcher consumes.

use std::io;
use std::sync::Arc;

use sce_rust_runtime::Engine;
use tokio::net::{TcpListener, TcpStream};

use wz_runtime_core::TimeSource;
#[cfg(feature = "routing-namespace")]
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::locator::{
    parse_any_locator, AnyLocator, AnyLocatorError, LocatorParseError, Proto,
};
#[cfg(feature = "scouting-static")]
use wz_session_core::scout_static::synth_static_locators;
// R3b — the Z_EXT_AUTH dispatch installed by the auth-on open variants.
#[cfg(feature = "session-extauth")]
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

use crate::link_pipeline::{
    accept_tcp, bind_tcp, bind_tcp_host, dial_tcp, dial_tcp_host, wire_tcp_stream, TcpReadDriver,
};
use crate::runtime_impl::{TokioJoinHandle, TokioTime};
use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use crate::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver, CloseReason,
    DriverLoopOutcome, SessionActionsBinding, SessionInitParams, SessionLinkActions,
};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, TxFrame};

#[cfg(feature = "transport-link-udp")]
use crate::udp_pipeline::{dial_udp, wire_udp_socket, UdpReadDriver};
#[cfg(feature = "transport-link-udp")]
use std::net::SocketAddr;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;

// R311nv — the serial arm rides this tcp+unicast-gated module as an
// additive transport (like the udp arm above): a serial session-open build
// also carries tcp, so the SERIAL pieces are guarded only by the
// transport-link-serial feature here.
#[cfg(feature = "transport-link-serial")]
use crate::serial_pipeline::{dial_serial, wire_serial_stream, SerialReadDriver};
#[cfg(feature = "transport-link-serial")]
use tokio_serial::SerialStream;

// R311oa — the TLS arm, like serial, rides this tcp+unicast-gated module as
// an additive transport (transport-link-tls forwards transport-link-tcp, so
// this module is always compiled when TLS is). The stream type is the unified
// rustls `TlsStream<TcpStream>` produced by `tls_pipeline::dial_tls`/
// `accept_tls`; `dial_locator` never builds it (no cert config in a locator).
#[cfg(feature = "transport-link-tls")]
use crate::tls_pipeline::{dial_tls, wire_tls_stream, TlsReadDriver};
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::rustls::pki_types::ServerName;
// R311xk — the rustls `ClientConfig` is shared by `TlsDialConfig` and
// `QuicDialConfig`, so it is imported for EITHER backend (one import, no
// duplicate when both are on).
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
use tokio_rustls::rustls::ClientConfig;
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::TlsStream;

// R311xk — the QUIC arm, like tls, rides this tcp+unicast-gated module as an
// additive STREAM transport (transport-link-quic forwards transport-link-tcp).
// zenoh frames a batch over ONE bidirectional QUIC stream with the SAME
// StreamEnvelope length-prefix as TCP/TLS, so `wire_quic_stream` reuses the
// `stream_link` drivers over a `quinn::{SendStream,RecvStream}` pair. LIKE tls
// (and unlike ws), a `quic/...` dial needs cert config the locator cannot carry,
// threaded via `DialConfig.quic`.
#[cfg(feature = "transport-link-quic")]
use crate::quic_pipeline::{dial_quic, wire_quic_stream, QuicLink, QuicReadDriver};

// R311y8 — the QUIC DATAGRAM arm, like udp/ws, rides this tcp+unicast-gated
// module as an additive DATAGRAM transport. Reuses `DialConfig.quic` (same
// cert as the stream backend); `transport-link-quic-datagram` implies
// `transport-link-quic`.
#[cfg(feature = "transport-link-quic-datagram")]
use crate::quic_datagram_pipeline::{
    dial_quic_datagram, wire_quic_datagram, QuicDatagramLink, QuicDatagramReadDriver,
};

// R311ob — the WS arm, like udp, rides this tcp+unicast-gated module as an
// additive DATAGRAM transport. The stream type is the RFC6455
// `WebSocketStream<TcpStream>` produced by `ws_pipeline::dial_ws`/`accept_ws`.
// UNLIKE tls, `dial_locator` DOES build it (a `ws/...` locator needs no cert).
#[cfg(feature = "transport-link-ws")]
use crate::ws_pipeline::{dial_ws, wire_ws_stream, WsReadDriver};
#[cfg(feature = "transport-link-ws")]
use tokio_tungstenite::WebSocketStream;

// R311xi — the unixsock arm, like serial/tls, rides this tcp+unicast-gated
// module as an additive STREAM transport (transport-link-unixsock forwards
// transport-link-tcp, so this module is always compiled when unixsock is). A
// connected `UnixStream` reuses the same `stream_link` split as TCP via
// `wire_unixsock_stream`; UNLIKE tls (no cert config), a `unixsock-stream/...`
// locator dials directly through `dial_locator`, like `ws`/`udp`.
#[cfg(feature = "transport-link-unixsock")]
use crate::unixsock_pipeline::{dial_unixsock, wire_unixsock_stream, UnixsockReadDriver};
#[cfg(feature = "transport-link-unixsock")]
use tokio::net::UnixStream;

// R311xj — the vsock arm, like tls/unixsock, rides this tcp+unicast-gated
// module as an additive STREAM transport, but Linux-only (AF_VSOCK), so gated
// all(transport-link-vsock, target_os=linux). A connected `VsockStream` reuses
// the `stream_link` split via `tokio::io::split` (the TLS pattern);
// `dial_locator` builds it from a `vsock/<CID>:<PORT>` locator (no cert config,
// like ws/udp/unixsock).
#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
use crate::vsock_pipeline::{dial_vsock, wire_vsock_stream, VsockReadDriver};
#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
use tokio_vsock::VsockStream;

// R311y10 — the unixpipe arm: a same-host named-FIFO-pair link, Linux-only
// (the tokio `read_write` open-rendezvous knob is target_os=linux). A connected
// `UnixpipeLink` (a Receiver/Sender FIFO pair) reuses the shared `stream_link`
// StreamEnvelope drivers, like unixsock/vsock.
#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
use crate::unixpipe_pipeline::{
    dial_unixpipe, wire_unixpipe_stream, UnixpipeLink, UnixpipeReadDriver,
};

/// Default cadence at which [`connect_and_open_session`] sweeps the host
/// handshake deadline (R311il — the engine-free FSM arms no `<send delay>`,
/// so there is no SCE scheduler to pump) while waiting on the handshake. It
/// bounds only the *precision* of the open-deadline (a handshake timeout
/// fires within `[deadline, deadline + DEFAULT_OPEN_TICK_MS]`), never the
/// deadline itself — the window durations are the §2.5 single source of
/// truth carried in [`SessionTimeouts`] (`link.open_timeout` /
/// `init_ack.timeout` / `open_ack.timeout`). 50ms keeps the 2s/5s windows
/// accurate to <3% while the inbound `poll_event` races the tick so a frame
/// still resolves the instant it arrives.
pub const DEFAULT_OPEN_TICK_MS: u64 = 50;

/// Host-tier dial configuration threaded through the locator dial seam — the
/// wz analogue of zenoh-pico's `session_cfg`, which `_z_new_link_tls` reads at
/// link creation (`src/link/unicast/tls.c`). It carries the out-of-band
/// material a locator string cannot: today the TLS client config + server name
/// a `tls/...` dial needs. This is what makes the dial seam the SINGLE seam for
/// EVERY transport (R311oc) — `tls` is no longer special-cased to an explicit
/// path; it dials from a locator like `tcp`/`udp`/`ws`, just parameterised by
/// this config (exactly as pico threads `session_cfg`).
///
/// Signature-stable across feature toggles ([[feedback-signature-stability]]):
/// the struct is ALWAYS present, only its fields are cfg-gated, so the dial
/// seam's signature never shifts when `transport-link-tls` flips. Cert-free
/// transports (tcp/udp/ws/serial) ignore it — they take [`DialConfig::default`].
///
/// Taken BY REFERENCE by the dial seam, mirroring pico's
/// `const _z_config_t *session_cfg` (the config is session-scoped and shared:
/// a static-locator list or a reconnect re-reads the SAME config across many
/// dials, so borrowing expresses that — by-value would clone a shared thing
/// per attempt). The TLS material is cloned ONCE, lazily, only when a TLS dial
/// actually happens ([`dial_locator`]'s tls arm). A caller that holds the dial
/// future across a `join!` binds the config to a `let` so it outlives the
/// borrow — the idiomatic Rust handling of a borrow-across-await.
#[derive(Default)]
pub struct DialConfig {
    /// TLS client material for a `tls/...` dial. `None` (the default) => a
    /// `tls/...` locator dials to a typed `Unsupported` error (no certs to
    /// verify the peer with), so a TLS dial is opt-in by supplying this.
    #[cfg(feature = "transport-link-tls")]
    pub tls: Option<TlsDialConfig>,
    /// QUIC client material for a `quic/...` dial (R311xk). `None` (the default)
    /// => a `quic/...` locator dials to a typed `Unsupported` (no certs to
    /// verify the peer with), so a QUIC dial is opt-in by supplying this — the
    /// same shape as `tls`.
    #[cfg(feature = "transport-link-quic")]
    pub quic: Option<QuicDialConfig>,
}

/// The TLS material a `tls/...` dial needs beyond the locator's addr: the
/// rustls [`ClientConfig`] (root trust / optional client cert for mTLS) and the
/// [`ServerName`] to verify (SNI / cert-name). Mirrors the connect side of
/// pico's TLS `session_cfg` keys (`TLS_CONFIG_ROOT_CA_CERTIFICATE` /
/// `CONNECT_CERTIFICATE` / `VERIFY_NAME_ON_CONNECT`, `tls.c`).
#[cfg(feature = "transport-link-tls")]
pub struct TlsDialConfig {
    pub client_config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

/// The QUIC material a `quic/...` dial needs beyond the locator's addr (R311xk):
/// the rustls [`ClientConfig`] (TLS-1.3 + ALPN `hq-29`, from
/// [`crate::quic_config`]) and the SNI / cert server name. Mirrors
/// [`TlsDialConfig`] — the same cert-threading shape — diverging only in the
/// `server_name` TYPE: a `String`, because quinn's `Endpoint::connect` takes a
/// `&str` SNI (where tokio-rustls's connector takes a typed `ServerName`).
#[cfg(feature = "transport-link-quic")]
pub struct QuicDialConfig {
    pub client_config: Arc<ClientConfig>,
    pub server_name: String,
}

/// A dialed raw transport — the mode-agnostic dial seam's output, a union
/// spanning every link transport (R311ez TCP/UDP; R311nv serial).
/// [`wire_dialed_link`] consumes it into the uniform
/// `(InboundLink, Arc<dyn BoxedLinkDriver>, writer-handle)` triple regardless
/// of which arm it carries, so [`connect_and_open_session`] drives a TCP
/// stream session, a UDP datagram session, and a serial tty session through
/// one code path.
pub enum DialedLink {
    /// A connected stream, split downstream via [`wire_tcp_stream`].
    Tcp(TcpStream),
    /// A bound datagram socket + its unicast peer, shared downstream via
    /// [`wire_udp_socket`].
    #[cfg(feature = "transport-link-udp")]
    Udp { socket: UdpSocket, peer: SocketAddr },
    /// A connected + link-handshaked serial tty, split downstream via
    /// [`wire_serial_stream`] (R311nv). Unlike TCP/UDP, the serial link
    /// handshake (INIT/INIT|ACK) has ALREADY run by the time the stream is
    /// wrapped here — [`dial_serial`] (Initiator) / `accept_serial`
    /// (Responder) drive it before returning, so the steady-state split
    /// path is uniform with the other transports.
    #[cfg(feature = "transport-link-serial")]
    Serial(SerialStream),
    /// A connected + rustls-handshaked TLS-over-TCP stream, split downstream
    /// via [`wire_tls_stream`] (R311oa). Like serial, the handshake (here the
    /// TLS handshake) has ALREADY run by the time the stream is wrapped:
    /// [`crate::tls_pipeline::dial_tls`] (client) / [`crate::tls_pipeline::accept_tls`]
    /// (server) drive it before returning, so the steady-state split stays
    /// uniform with TCP. Produced by [`dial_locator`] when its [`DialConfig`]
    /// carries the TLS client config (R311oc — TLS now dials from a `tls/...`
    /// locator like every other transport), or by an explicit
    /// [`crate::tls_pipeline::dial_tls`] caller; either feeds
    /// `initiate_and_open_session` / `accept_and_open_session`.
    ///
    /// `Box`ed: a handshaked `TlsStream` carries the full rustls session
    /// state (buffers + crypto), so an unboxed variant would bloat every
    /// `DialedLink` value (incl. the small `Tcp` arm) to that size on the
    /// stack — boxing keeps the union compact (clippy `large_enum_variant`).
    #[cfg(feature = "transport-link-tls")]
    Tls(Box<TlsStream<TcpStream>>),
    /// A connected + WebSocket-handshaked stream, split downstream via
    /// [`wire_ws_stream`] (R311ob). DATAGRAM flow (each batch = one WS BINARY
    /// message), so the steady state is uniform with UDP, not TCP/TLS. UNLIKE
    /// TLS, a `ws/...` locator DOES dial through [`dial_locator`] (no cert
    /// config), so this is produced both there and by an explicit caller.
    ///
    /// `Box`ed: a `WebSocketStream` carries the RFC6455 protocol buffers, so
    /// an unboxed variant would bloat every `DialedLink` value on the stack
    /// (clippy `large_enum_variant`).
    #[cfg(feature = "transport-link-ws")]
    Ws(Box<WebSocketStream<TcpStream>>),
    /// A connected unix-domain stream, split downstream via
    /// [`wire_unixsock_stream`] (R311xi). A reliable byte STREAM like TCP, so
    /// the steady-state split is uniform with [`Self::Tcp`]. NOT `Box`ed: a
    /// `UnixStream` is a thin fd wrapper (no large handshake state, unlike the
    /// `TlsStream` / `WebSocketStream` arms), so it does not bloat the union.
    /// Produced by [`dial_locator`] for a `unixsock-stream/...` locator (no
    /// cert config needed, like `ws` / `udp`), or by an accepted `UnixStream`
    /// the acceptor wraps directly (no dial-time handshake, unlike serial/tls).
    #[cfg(feature = "transport-link-unixsock")]
    Unixsock(UnixStream),
    /// A connected AF_VSOCK stream, split downstream via [`wire_vsock_stream`]
    /// (R311xj). A reliable byte STREAM like TCP/unixsock, so the steady-state
    /// split is uniform with [`Self::Tcp`]. NOT `Box`ed (a `VsockStream` is a
    /// thin fd wrapper). Produced by [`dial_locator`] for a `vsock/<CID>:<PORT>`
    /// locator (no cert config, like ws/udp/unixsock). Linux-only (AF_VSOCK),
    /// gated with the backend.
    #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
    Vsock(VsockStream),
    /// A connected unix named-pipe (FIFO-pair) link, wired downstream via
    /// [`wire_unixpipe_stream`] (R311y10). A reliable byte STREAM like
    /// TCP/unixsock (the FIFO is streamed), so the steady-state is uniform with
    /// [`Self::Tcp`]. NOT `Box`ed (a [`UnixpipeLink`] is a thin Receiver/Sender
    /// fd pair). Produced by [`dial_locator`] for a `unixpipe/...` locator (no
    /// cert config, like unixsock/udp). Linux-only (the FIFO open-rendezvous),
    /// gated with the backend.
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    Unixpipe(UnixpipeLink),
    /// A connected + QUIC-handshaked link, split downstream via
    /// [`wire_quic_stream`] (R311xk). Like serial/tls, the handshake (here the
    /// QUIC + TLS-1.3 handshake) has ALREADY run by the time this is built —
    /// [`crate::quic_pipeline::dial_quic`] (client) / `accept_quic_on` (server)
    /// drive it and open the single bidirectional stream before returning, so
    /// the steady-state split stays uniform with TCP. `Box`ed: a [`QuicLink`]
    /// carries the endpoint + connection keep-alive handles + both stream halves
    /// (clippy `large_enum_variant`). Produced by [`dial_locator`] when its
    /// [`DialConfig`] carries `quic` (the TLS-style cert threading).
    #[cfg(feature = "transport-link-quic")]
    Quic(Box<QuicLink>),
    /// A connected + QUIC-handshaked DATAGRAM link, shared downstream via
    /// [`wire_quic_datagram`] (R311y8). Like [`Self::Quic`] the QUIC + TLS-1.3
    /// handshake has ALREADY run by the time this is built
    /// ([`crate::quic_datagram_pipeline::dial_quic_datagram`] /
    /// `accept_quic_datagram_on`), but the steady state is DATAGRAM (each batch =
    /// one QUIC datagram, no bidi stream), so it is uniform with UDP/WS, not
    /// TCP/TLS. `Box`ed for the same reason as [`Self::Quic`] (the endpoint +
    /// connection keep-alive handles; clippy `large_enum_variant`). Produced by
    /// [`dial_locator`] when its [`DialConfig`] carries `quic` (the same cert as
    /// the stream backend).
    #[cfg(feature = "transport-link-quic-datagram")]
    QuicDatagram(Box<QuicDatagramLink>),
}

impl DialedLink {
    /// The transport name of the dialed link (`"tcp"` / `"udp"` / `"serial"` /
    /// `"tls"` / `"ws"`) — the variant→name SSOT, so a caller can log or assert
    /// WHICH transport it dialed without re-matching the feature-gated arms.
    ///
    /// R311po — wz-ap-demo's `establish_link` logs this, and the Layer Z WS legs
    /// assert `"ws"` appears, turning the WebSocket transport into a logged
    /// WITNESS rather than an inference from the listener-port split. A future
    /// regression that quietly dialed TCP on a WS leg would flip this string and
    /// fail the assertion, where the port split alone would stay silently green.
    pub fn transport_name(&self) -> &'static str {
        match self {
            DialedLink::Tcp(_) => "tcp",
            #[cfg(feature = "transport-link-udp")]
            DialedLink::Udp { .. } => "udp",
            #[cfg(feature = "transport-link-serial")]
            DialedLink::Serial(_) => "serial",
            #[cfg(feature = "transport-link-tls")]
            DialedLink::Tls(_) => "tls",
            #[cfg(feature = "transport-link-ws")]
            DialedLink::Ws(_) => "ws",
            #[cfg(feature = "transport-link-unixsock")]
            DialedLink::Unixsock(_) => "unixsock",
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            DialedLink::Vsock(_) => "vsock",
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            DialedLink::Unixpipe(_) => "unixpipe",
            #[cfg(feature = "transport-link-quic")]
            DialedLink::Quic(_) => "quic",
            #[cfg(feature = "transport-link-quic-datagram")]
            DialedLink::QuicDatagram(_) => "quic-datagram",
        }
    }
}

/// Dial a parsed [`AnyLocator`] to its raw transport — the mode-agnostic dial
/// seam, dispatching on the locator's scheme.
///
/// `Ip(Proto::Tcp)` returns a connected [`TcpStream`] (split downstream by
/// [`wire_dialed_link`] via [`wire_tcp_stream`], per the R311et raw-dial
/// decision: the stream is dialed once and the split shape is chosen by the
/// consumer, not buried inside a unified driver).
///
/// `Ip(Proto::Udp)` binds an ephemeral local socket targeting the locator's
/// peer ([`dial_udp`]) when the `transport-link-udp` feature is compiled in;
/// downstream [`wire_udp_socket`] shares it into the read/write drivers. With
/// the feature off, a `udp/...` locator surfaces a typed `Unsupported` error
/// rather than silently mis-dialing.
///
/// `Serial` (R311nv, `transport-link-serial`) opens the tty and drives the
/// serial-link handshake to Connected ([`dial_serial`]) before wrapping the
/// stream — the one transport that handshakes at dial time, so the steady
/// state stays uniform. A `serial/...` string only reaches this arm when the
/// feature is on; otherwise it never parses to [`AnyLocator::Serial`].
///
/// `cfg` (R311oc) supplies out-of-band dial material a locator string cannot
/// carry — the TLS client config a `tls/...` dial needs, or the QUIC client
/// config a `quic/...` dial needs (R311xk). Cert-free transports
/// (tcp/udp/ws/serial/unixsock/vsock) ignore it; `tls` reads `cfg.tls` and
/// `quic` reads `cfg.quic` (absent => typed `Unsupported`). This is what lets
/// the dial seam handle EVERY transport uniformly — pico threads the same
/// material via `session_cfg`.
pub async fn dial_locator(locator: AnyLocator, cfg: &DialConfig) -> io::Result<DialedLink> {
    // `cfg` is consumed only by the tls / quic arms; discard it loudly in builds
    // without either backend so the always-present seam signature carries no
    // dead-param warning.
    #[cfg(not(any(feature = "transport-link-tls", feature = "transport-link-quic")))]
    let _ = cfg;
    match locator {
        AnyLocator::Ip(ip) => match ip.proto {
            Proto::Tcp => Ok(DialedLink::Tcp(dial_tcp(ip.addr).await?)),
            #[cfg(feature = "transport-link-udp")]
            Proto::Udp => Ok(DialedLink::Udp {
                socket: dial_udp(ip.addr).await?,
                peer: ip.addr,
            }),
            #[cfg(not(feature = "transport-link-udp"))]
            Proto::Udp => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "udp session-open requires the transport-link-udp feature",
            )),
            // R311oc — `tls/...` dials from the locator when `cfg.tls` supplies
            // the rustls client config + server name (pico parity: the dial
            // seam reads `session_cfg`). Absent config => typed `Unsupported`
            // (no certs to verify the peer), so a TLS dial is opt-in via the
            // config. `dial_tls` stays the primitive; this arm orchestrates it.
            #[cfg(feature = "transport-link-tls")]
            Proto::Tls => match &cfg.tls {
                // Clone the TLS material here, lazily — only when a TLS dial
                // actually happens (dial_tls owns its rustls config + name).
                Some(t) => Ok(DialedLink::Tls(Box::new(
                    dial_tls(ip.addr, t.client_config.clone(), t.server_name.clone()).await?,
                ))),
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "tls dial requires DialConfig.tls (rustls client config + server name)",
                )),
            },
            // With the backend feature off, the same `Unsupported` shape as the
            // udp arm — `tls/...` still parses, only its dial is absent.
            #[cfg(not(feature = "transport-link-tls"))]
            Proto::Tls => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tls session-open requires the transport-link-tls feature",
            )),
            // R311ob — UNLIKE tls, a `ws/...` locator dials directly here: WS
            // needs no cert config, so `dial_ws` (TCP connect + RFC6455 client
            // handshake) builds the link from the addr alone, exactly as `udp`
            // does. With the backend feature off, a typed `Unsupported` (same
            // shape as the udp arm), keeping the match exhaustive.
            #[cfg(feature = "transport-link-ws")]
            Proto::Ws => Ok(DialedLink::Ws(Box::new(dial_ws(ip.addr).await?))),
            #[cfg(not(feature = "transport-link-ws"))]
            Proto::Ws => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ws session-open requires the transport-link-ws feature",
            )),
            // R311xk — `quic/...` dials from the locator when `cfg.quic` supplies
            // the TLS-1.3 + ALPN rustls client config + SNI name (the tls model;
            // QUIC mandates a cert). Absent config => typed `Unsupported`, so a
            // QUIC dial is opt-in. `dial_quic` (build a client endpoint, connect,
            // open the one bidi stream) is the primitive; this arm orchestrates
            // it. Numeric only here (the `Named` arm below keeps the deferred
            // name dial); the SNI comes from `cfg.quic` (like `tls`), not the
            // numeric locator.
            #[cfg(feature = "transport-link-quic")]
            Proto::Quic => match &cfg.quic {
                // Clone the client config lazily — only on an actual QUIC dial.
                Some(q) => Ok(DialedLink::Quic(Box::new(
                    dial_quic(ip.addr, q.client_config.clone(), &q.server_name).await?,
                ))),
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "quic dial requires DialConfig.quic (rustls client config + SNI name)",
                )),
            },
            // With the backend off, the same `Unsupported` shape as the tls/udp
            // arms — `quic/...` still parses, only its dial is absent.
            #[cfg(not(feature = "transport-link-quic"))]
            Proto::Quic => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quic session-open requires the transport-link-quic feature",
            )),
            // R311y8 — `quic-datagram/...` dials from the locator when `cfg.quic`
            // supplies the cert (the SAME TLS-1.3 config as the `quic` stream
            // backend; quic-datagram implies transport-link-quic, so the field
            // is present). Absent config => typed `Unsupported`, like `quic`.
            // `dial_quic_datagram` (build a client endpoint, connect — no bidi
            // stream) is the primitive; this arm orchestrates it.
            #[cfg(feature = "transport-link-quic-datagram")]
            Proto::QuicDatagram => match &cfg.quic {
                Some(q) => Ok(DialedLink::QuicDatagram(Box::new(
                    dial_quic_datagram(ip.addr, q.client_config.clone(), &q.server_name).await?,
                ))),
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "quic-datagram dial requires DialConfig.quic (rustls client config + SNI name)",
                )),
            },
            // With the backend off, the same `Unsupported` shape as the quic/tls
            // arms — `quic-datagram/...` still parses, only its dial is absent.
            #[cfg(not(feature = "transport-link-quic-datagram"))]
            Proto::QuicDatagram => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quic-datagram session-open requires the transport-link-quic-datagram feature",
            )),
        },
        // R311ps — a DNS-named IP-family endpoint (`tcp/example.org:7447`). The
        // no_std parser classified the address token as a NAME; resolution is a
        // std-layer concern, so a `tcp` name dials via the std-resolver host
        // dial [`dial_tcp_host`] (which feeds the addr string to the resolver).
        // The datagram/TLS/WS protos keep the numeric-only contract for now:
        // their name dial is a typed `Unsupported`, a CLEAN extension point
        // (add the arm when a `ws/HOST` / `tls/HOST` dial is actually wanted),
        // NOT a silent fallback or a string-prefix special-case. The `Tcp` arm
        // is unconditional like the `Ip(Proto::Tcp)` arm above — tcp is the
        // always-on baseline stream transport.
        AnyLocator::Named { proto, host, port } => match proto {
            Proto::Tcp => Ok(DialedLink::Tcp(
                dial_tcp_host(&format!("{host}:{port}")).await?,
            )),
            other => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "DNS-name dial is wired only for tcp; {other:?} needs a numeric \
                     address (name resolution for this transport is not yet implemented)"
                ),
            )),
        },
        // R311nv — a `serial/...` endpoint dials through the tty backend:
        // `dial_serial` opens the device AND drives the serial-link
        // handshake (INIT -> INIT|ACK) to Connected before returning, so the
        // wrapped stream is ready for the uniform steady-state split. The
        // Initiator role is correct here: `dial_locator` is the dial (Initiator)
        // seam; the Responder side comes up via `accept_serial`.
        #[cfg(feature = "transport-link-serial")]
        AnyLocator::Serial(ep) => Ok(DialedLink::Serial(dial_serial(&ep).await?)),
        // R311ny — `AnyLocator::Serial` is an ALWAYS-present variant (the
        // serial locator leaf is ungated in wz-session-core), so this arm
        // must exist whatever this crate's features are. Without the serial
        // BACKEND feature it dials to a typed `Unsupported`, exactly as
        // `udp` does without `transport-link-udp` — keeping the match
        // exhaustive in every feature combination (no cross-crate skew: the
        // variant's gate and this arm's gate can no longer disagree).
        #[cfg(not(feature = "transport-link-serial"))]
        AnyLocator::Serial(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "serial session-open requires the transport-link-serial feature",
        )),
        // R311xi — a `unixsock-stream/...` endpoint dials through the unix
        // socket backend: `dial_unixsock` connects the `UnixStream`. UNLIKE
        // serial (which handshakes at dial time), the byte stream is ready for
        // the uniform split immediately — like tcp/ws. The Initiator side; the
        // Responder comes up via an accepted `UnixStream` (the acceptor/harness
        // owns the `UnixListener`, the not-yet-wired-here accept extension
        // point `bind_locator` documents). No cert config, so the locator dials
        // directly here (like `ws`/`udp`, unlike `tls`).
        #[cfg(feature = "transport-link-unixsock")]
        AnyLocator::Unixsock(ep) => Ok(DialedLink::Unixsock(dial_unixsock(&ep.path).await?)),
        // R311xi — `AnyLocator::Unixsock` is an ALWAYS-present variant (the
        // unixsock locator leaf is ungated in wz-session-core), so this arm
        // must exist whatever this crate's features are. Without the unixsock
        // BACKEND it dials to a typed `Unsupported`, exactly as `serial`/`udp`
        // do — keeping the match exhaustive in every feature combination (no
        // cross-crate skew: the variant's gate and this arm's gate cannot
        // disagree).
        #[cfg(not(feature = "transport-link-unixsock"))]
        AnyLocator::Unixsock(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unixsock session-open requires the transport-link-unixsock feature",
        )),
        // R311xj — a `vsock/<CID>:<PORT>` endpoint dials through the AF_VSOCK
        // backend: `dial_vsock` connects the `VsockStream` (no dial-time
        // handshake — ready for the uniform split, like tcp/unixsock). The
        // Initiator side; the Responder comes up via an accepted `VsockStream`
        // (the acceptor owns the `VsockListener`). No cert config, so it dials
        // directly here (like ws/udp/unixsock).
        #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
        AnyLocator::Vsock(ep) => Ok(DialedLink::Vsock(dial_vsock(ep.cid, ep.port).await?)),
        // R311xj — `AnyLocator::Vsock` is an ALWAYS-present, PLATFORM-INDEPENDENT
        // variant (the vsock locator leaf is ungated in wz-session-core), so
        // this arm must exist on every target / feature combo. Without the
        // backend (feature off, or a non-Linux target) it dials to a typed
        // `Unsupported`, exactly as serial/udp do — keeping the match exhaustive
        // and avoiding cross-crate/cross-target skew.
        #[cfg(not(all(feature = "transport-link-vsock", target_os = "linux")))]
        AnyLocator::Vsock(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vsock session-open requires the transport-link-vsock feature on a Linux target",
        )),
        // R311y10 — a `unixpipe/...` endpoint dials through the named-FIFO-pair
        // backend: `dial_unixpipe` opens the dialer's (receiver, sender) FIFO
        // ends (no dial-time handshake — the FIFO open IS the rendezvous, ready
        // for the uniform split, like unixsock). `dial_unixpipe` is SYNC (a FIFO
        // open is non-blocking) but must run within the tokio runtime, which this
        // async dial seam provides. No cert config (like unixsock/udp).
        #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
        AnyLocator::Unixpipe(ep) => Ok(DialedLink::Unixpipe(dial_unixpipe(&ep.path)?)),
        // R311y10 — `AnyLocator::Unixpipe` is an ALWAYS-present, PLATFORM-
        // INDEPENDENT variant (the unixpipe locator leaf is ungated in
        // wz-session-core), so this arm must exist on every target / feature
        // combo. Without the backend (feature off, or a non-Linux target) it
        // dials to a typed `Unsupported`, exactly as vsock/serial/udp do —
        // keeping the match exhaustive and avoiding cross-crate/cross-target skew.
        #[cfg(not(all(feature = "transport-link-unixpipe", target_os = "linux")))]
        AnyLocator::Unixpipe(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unixpipe session-open requires the transport-link-unixpipe feature on a Linux target",
        )),
    }
}

/// Classify a `--connect` / `--listen`-style endpoint string into the
/// [`AnyLocator`] the dial + accept seams consume — the routing decision, kept
/// PURE (no I/O) so the table is unit-tested without sockets or DNS.
/// [`dial_endpoint`] and [`accept_endpoint`] are thin async wrappers over
/// [`dial_locator`] / [`accept_locator`] respectively; both share THIS
/// classifier (R311pu — a listen string parses by the same rules a connect
/// string does, so the dial/accept routing is one source of truth).
///
/// R311ps — the only `--connect`-specific rule left here is the scheme-less
/// convenience: a bare `HOST:PORT` (no proto separator) is dialed as implicit
/// `tcp`, so `--connect 127.0.0.1:7447` works without a scheme. Everything else
/// — including a `tcp/HOST` DNS name — is classified by the shared
/// [`parse_any_locator`] seam, which now yields [`AnyLocator::Named`] for a
/// hostname. So DNS-vs-numeric routing is a property of the PARSED value, not a
/// raw-string re-inspection here: this dissolved the R311pm `starts_with("tcp/")`
/// special-case (scheme/address axis conflation) AND the dial_endpoint-vs-
/// open_session_at contract split — both paths now route the same parsed
/// `AnyLocator` through `dial_locator`.
///
/// R311py — `pub(crate)`: the connect/listen-string classifier SSOT, shared by
/// the THREE in-crate string→session seams ([`dial_endpoint`] → dialed link,
/// [`accept_endpoint`] → accepted link, [`crate::reconnect::reconnect_endpoint`]
/// → reconnect supervisor). It is NOT part of the public surface — a consumer
/// (e.g. wz-ap-demo) calls one of those orchestration seams, never the raw
/// classifier (R311pw briefly made it `pub` so the demo could hand-assemble the
/// reconnect orchestration; R311py moved that orchestration into the library
/// `reconnect_endpoint` seam, restoring the dial/accept seam discipline).
pub(crate) fn plan_endpoint(connect: &str) -> Result<AnyLocator, AnyLocatorError> {
    match parse_any_locator(connect) {
        Ok(locator) => Ok(locator),
        // Scheme-less `HOST:PORT` = implicit `tcp` (the `--connect` convenience;
        // zenoh locators otherwise always carry a scheme). Desugar to
        // `tcp/<connect>` and re-parse through the same classifier so a bare
        // numeric address and a bare hostname land as `Ip`/`Named` with `Tcp`
        // uniformly — no separate bare-host code path.
        Err(AnyLocatorError::Ip(LocatorParseError::MissingProtoSeparator)) => {
            parse_any_locator(&format!("tcp/{connect}"))
        }
        // Unknown scheme, malformed address, metadata suffix, malformed serial:
        // surface the typed parse error rather than guessing a transport.
        Err(e) => Err(e),
    }
}

/// Dial a `--connect`-style endpoint string to a raw [`DialedLink`] — the
/// std-layer dial seam, the single home of "turn a `--connect` string into a
/// dialed transport". [`plan_endpoint`] classifies the string into an
/// [`AnyLocator`] (applying only the scheme-less = `tcp` convenience), then
/// [`dial_locator`] — the SINGLE dial path, shared with the scouting /
/// static-deploy open path — performs the dial: a numeric endpoint via its
/// per-proto raw dial, a `tcp` DNS name via the std-resolver [`dial_tcp_host`].
///
/// R311ps — this no longer carries a bespoke DNS path beside `dial_locator`:
/// `dial_locator` itself handles the [`AnyLocator::Named`] case, so
/// [`open_session_at`] (the scouting / static-deploy entry) gained the same
/// scheme'd-hostname capability for free — DNS-capability is now a property of
/// the resolver layer, not of which caller invoked it. The scheme-LESS
/// convenience stays demo-only in [`plan_endpoint`] (configured zenoh locators
/// always carry a scheme).
///
/// `cfg` is forwarded to [`dial_locator`] for transports needing out-of-band
/// material (TLS); cert-free transports ignore it.
pub async fn dial_endpoint(connect: &str, cfg: &DialConfig) -> io::Result<DialedLink> {
    let locator = plan_endpoint(connect).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz dial: malformed / unsupported --connect {connect:?}: {e:?}"),
        )
    })?;
    dial_locator(locator, cfg).await
}

/// Accept-side dispatcher for [`accept_endpoint`]: bind + accept ONE inbound
/// link for the [`AnyLocator`]'s scheme, returning the same [`DialedLink`]
/// union the dial path produces so [`accept_and_open_session`] consumes one
/// concrete type whatever the role.
///
/// R311qa — delegates to [`bind_locator`] (the bind half, the SSOT the
/// multi-peer [`accept_loop`](crate::accept_loop) shares) then [`accept_bound`]
/// (accept ONE), rather than inlining the bind. The non-tcp `Unsupported`
/// surfaced here originates in `bind_locator`'s scheme match. The NON-tcp
/// handling is where the symmetry with [`dial_locator`] deliberately STOPS:
/// dial_locator pairs
/// each non-tcp scheme with a `#[cfg(feature)]` wired arm + a `#[cfg(not)]`
/// Unsupported arm, whereas accept_locator returns a single feature-blind
/// `Unsupported` for ws/tls/udp REGARDLESS of feature. Wiring a real accept
/// arm is not a one-arm change: an `accept_ws` is `bind_tcp` + `accept_tcp` +
/// `accept_ws(stream)` — a handshake over an already-accepted stream, two
/// primitives — unlike dial's single-call `dial_ws(addr)`. The `accept_ws` /
/// `accept_tls` primitives exist; they wire in when a verified cross-impl
/// acceptor caller lands (R63; R311pq: no cross-impl WS/TLS dialer to verify a
/// wz acceptor against). `Udp`'s acceptor would be a `bind` + first-`recv_from`
/// peer-learn (not a `TcpListener::accept`); `Serial`'s is a tty open
/// ([`accept_serial`](crate::serial_pipeline::accept_serial)) — both unwired
/// until their responder caller lands.
pub async fn accept_locator(locator: AnyLocator) -> io::Result<DialedLink> {
    accept_bound(bind_locator(locator).await?).await
}

/// Bind a listening [`TcpListener`] for an [`AnyLocator`]'s scheme — the
/// bind-only half of [`accept_locator`], split out so the multi-peer
/// [`accept_loop`](crate::accept_loop) can hold the listener and loop accepts
/// over it (R311qa), while the one-shot [`accept_locator`] binds-then-accepts a
/// single peer. The `Tcp` path mirrors dial's 3-layer seam: numeric [`bind_tcp`]
/// / DNS [`bind_tcp_host`]. Non-tcp schemes return a feature-blind typed
/// `Unsupported` — the same not-yet-wired extension point [`accept_locator`]
/// documents (ws/tls accept is `bind` + `accept` + handshake, udp is a
/// `recv_from` peer-learn, serial is a tty open).
pub async fn bind_locator(locator: AnyLocator) -> io::Result<TcpListener> {
    fn unsupported(detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("listen/accept is wired only for tcp; {detail}"),
        )
    }
    match locator {
        AnyLocator::Ip(ip) => match ip.proto {
            Proto::Tcp => bind_tcp(ip.addr).await,
            other => Err(unsupported(&format!(
                "{other:?} acceptor is a not-yet-wired extension point"
            ))),
        },
        AnyLocator::Named { proto, host, port } => match proto {
            Proto::Tcp => bind_tcp_host(&format!("{host}:{port}")).await,
            // A non-tcp NAME is unwired for two reasons (acceptor + non-tcp
            // name resolution), kept distinct from the numeric arm's message.
            other => Err(unsupported(&format!(
                "{other:?} acceptor and non-tcp name resolution are both unwired"
            ))),
        },
        AnyLocator::Serial(_) => Err(unsupported(
            "serial accept is a tty open (accept_serial), not a listen bind; unwired",
        )),
        // R311xi — a unixsock acceptor is a `UnixListener` bind + accept
        // (`unixsock_pipeline::bind_unixsock` / `accept_unixsock_on`), NOT a
        // `TcpListener` this seam returns, so it cannot fit here — the listen
        // side is owned by the acceptor / e2e harness (the same not-yet-wired
        // acceptor extension point ws/tls/udp document). The DIAL side IS wired
        // (`dial_locator` above); only the listen seam is unwired here.
        AnyLocator::Unixsock(_) => Err(unsupported(
            "unixsock accept is a UnixListener bind (bind_unixsock + accept_unixsock_on), \
             not a TcpListener; the listen side is owned by the acceptor, unwired here",
        )),
        // R311xj — a vsock acceptor is a `VsockListener` bind + accept
        // (`vsock_pipeline::bind_vsock` / `accept_vsock_on`), NOT the
        // `TcpListener` this seam returns, so it cannot fit here — the listen
        // side is owned by the acceptor / e2e harness (the same not-yet-wired
        // acceptor extension point ws/tls/udp/unixsock document). The DIAL side
        // IS wired (`dial_locator` above); only the listen seam is unwired here.
        AnyLocator::Vsock(_) => Err(unsupported(
            "vsock accept is a VsockListener bind (bind_vsock + accept_vsock_on), not a \
             TcpListener; the listen side is owned by the acceptor, unwired here",
        )),
        // R311y10 — a unixpipe acceptor is a `mkfifo` pair bind + open
        // (`unixpipe_pipeline::bind_unixpipe` / `accept_unixpipe_on`), NOT the
        // `TcpListener` this seam returns, so it cannot fit here — the listen
        // side is owned by the acceptor / e2e harness (the same not-yet-wired
        // acceptor extension point ws/tls/udp/unixsock/vsock document). The DIAL
        // side IS wired (`dial_locator` above); only the listen seam is unwired.
        AnyLocator::Unixpipe(_) => Err(unsupported(
            "unixpipe accept is a mkfifo pair bind (bind_unixpipe + accept_unixpipe_on), not a \
             TcpListener; the listen side is owned by the acceptor, unwired here",
        )),
    }
}

/// Log the bound address, accept one peer, log it, wrap as `DialedLink::Tcp` —
/// the accept-side counterpart to the Initiator's "connected to .. over .."
/// line. The "wz accept:" prefix tags the demo's logs; the e2e harness owns a
/// binary-name-tagged copy of this 3-line shape (it cannot share the prefix),
/// so the shared SSOT is the quiet [`bind_tcp`] / [`accept_tcp`] primitives,
/// not the logging. Logging here (not in the primitives) keeps them quiet like
/// their `dial_*` siblings.
async fn accept_bound(listener: TcpListener) -> io::Result<DialedLink> {
    log::info!("wz accept: listening on {}", listener.local_addr()?);
    let (stream, peer) = accept_tcp(listener).await?;
    log::info!("wz accept: accepted peer {peer}");
    Ok(DialedLink::Tcp(stream))
}

/// Accept a `--listen`-style endpoint string to a raw [`DialedLink`] — the
/// std-layer accept seam, symmetric to [`dial_endpoint`]. [`plan_endpoint`] is the
/// SHARED classifier (a listen string parses to an [`AnyLocator`] by the same
/// rules a connect string does — a scheme'd locator, or the scheme-less =
/// `tcp` convenience), then [`accept_locator`] performs the bind + accept.
///
/// R311pu — no `DialConfig` param (unlike [`dial_endpoint`]): the only cfg an
/// acceptor would consume is a TLS server config, and the TLS accept arm is a
/// not-yet-wired typed-`Unsupported` extension point in [`accept_locator`].
/// Adding the param now would be a dead param; it lands alongside the TLS
/// accept arm when a verified caller does. This is the accept-side counterpart
/// to the demo's `establish_link` Acceptor role, dissolving its inline
/// `TcpListener::bind` into the same library seam the Initiator role already
/// dials through.
/// R311qa — composes [`bind_endpoint`] + [`accept_bound`] (the one-shot mirror
/// of `bind_endpoint` + the multi-peer [`accept_loop`](crate::accept_loop)),
/// so the `plan_endpoint` classify + error-map lives once in `bind_endpoint`,
/// not duplicated here — the endpoint-layer analogue of
/// `accept_locator = accept_bound ∘ bind_locator`.
pub async fn accept_endpoint(listen: &str) -> io::Result<DialedLink> {
    accept_bound(bind_endpoint(listen).await?).await
}

/// Bind a `--listen`-style endpoint string to a listening [`TcpListener`] — the
/// bind-only seam symmetric to [`accept_endpoint`], consumed by the multi-peer
/// [`accept_loop`](crate::accept_loop) (a router/peer binds once, then holds the
/// listener and loops accepts). [`plan_endpoint`] classifies the string exactly
/// as [`accept_endpoint`] does; [`bind_locator`] performs the bind. Splitting
/// bind from the accept loop keeps `local_addr` observable before any peer
/// connects — the race-free bind/accept split [`bind_tcp`] established.
pub async fn bind_endpoint(listen: &str) -> io::Result<TcpListener> {
    let locator = plan_endpoint(listen).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz listen: malformed / unsupported --listen {listen:?}: {e:?}"),
        )
    })?;
    bind_locator(locator).await
}

/// Inbound read driver of a dialed link — the transport union on the read
/// side, so [`OpenedSession`] carries one concrete type whether the locator
/// dialed a stream or a datagram socket (the `LinkDriver` trait uses
/// `async fn`, which is not dyn-compatible, so the union is an enum rather
/// than a `Box<dyn LinkDriver>`). [`poll_and_dispatch_one`] drives it
/// generically via the [`LinkDriver`] impl, which forwards each method to the
/// inner driver.
pub enum InboundLink {
    Tcp(TcpReadDriver),
    #[cfg(feature = "transport-link-udp")]
    Udp(UdpReadDriver),
    #[cfg(feature = "transport-link-serial")]
    Serial(SerialReadDriver),
    #[cfg(feature = "transport-link-tls")]
    Tls(TlsReadDriver),
    #[cfg(feature = "transport-link-ws")]
    Ws(WsReadDriver),
    #[cfg(feature = "transport-link-unixsock")]
    Unixsock(UnixsockReadDriver),
    #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
    Vsock(VsockReadDriver),
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    Unixpipe(UnixpipeReadDriver),
    #[cfg(feature = "transport-link-quic")]
    Quic(QuicReadDriver),
    #[cfg(feature = "transport-link-quic-datagram")]
    QuicDatagram(QuicDatagramReadDriver),
}

impl LinkDriver for InboundLink {
    async fn open(&mut self) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.open().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.open().await,
            #[cfg(feature = "transport-link-serial")]
            InboundLink::Serial(d) => d.open().await,
            #[cfg(feature = "transport-link-tls")]
            InboundLink::Tls(d) => d.open().await,
            #[cfg(feature = "transport-link-ws")]
            InboundLink::Ws(d) => d.open().await,
            #[cfg(feature = "transport-link-unixsock")]
            InboundLink::Unixsock(d) => d.open().await,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            InboundLink::Vsock(d) => d.open().await,
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            InboundLink::Unixpipe(d) => d.open().await,
            #[cfg(feature = "transport-link-quic")]
            InboundLink::Quic(d) => d.open().await,
            #[cfg(feature = "transport-link-quic-datagram")]
            InboundLink::QuicDatagram(d) => d.open().await,
        }
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-serial")]
            InboundLink::Serial(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-tls")]
            InboundLink::Tls(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-ws")]
            InboundLink::Ws(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-unixsock")]
            InboundLink::Unixsock(d) => d.send(frame, reliability).await,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            InboundLink::Vsock(d) => d.send(frame, reliability).await,
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            InboundLink::Unixpipe(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-quic")]
            InboundLink::Quic(d) => d.send(frame, reliability).await,
            #[cfg(feature = "transport-link-quic-datagram")]
            InboundLink::QuicDatagram(d) => d.send(frame, reliability).await,
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        match self {
            InboundLink::Tcp(d) => d.close().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.close().await,
            #[cfg(feature = "transport-link-serial")]
            InboundLink::Serial(d) => d.close().await,
            #[cfg(feature = "transport-link-tls")]
            InboundLink::Tls(d) => d.close().await,
            #[cfg(feature = "transport-link-ws")]
            InboundLink::Ws(d) => d.close().await,
            #[cfg(feature = "transport-link-unixsock")]
            InboundLink::Unixsock(d) => d.close().await,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            InboundLink::Vsock(d) => d.close().await,
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            InboundLink::Unixpipe(d) => d.close().await,
            #[cfg(feature = "transport-link-quic")]
            InboundLink::Quic(d) => d.close().await,
            #[cfg(feature = "transport-link-quic-datagram")]
            InboundLink::QuicDatagram(d) => d.close().await,
        }
    }

    async fn poll_event(&mut self) -> LinkEvent {
        match self {
            InboundLink::Tcp(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-udp")]
            InboundLink::Udp(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-serial")]
            InboundLink::Serial(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-tls")]
            InboundLink::Tls(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-ws")]
            InboundLink::Ws(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-unixsock")]
            InboundLink::Unixsock(d) => d.poll_event().await,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            InboundLink::Vsock(d) => d.poll_event().await,
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            InboundLink::Unixpipe(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-quic")]
            InboundLink::Quic(d) => d.poll_event().await,
            #[cfg(feature = "transport-link-quic-datagram")]
            InboundLink::QuicDatagram(d) => d.poll_event().await,
        }
    }
}

/// Wire a [`DialedLink`] into the cooperating drivers the session FSM
/// consumes — the per-transport branch that converges on one shape: an
/// inbound [`InboundLink`] (`&mut LinkDriver` for the poll loop), an outbound
/// `Arc<dyn BoxedLinkDriver>` (`send_blocking` for the Lua actions), and the
/// writer-task join handle. TCP splits the stream ([`wire_tcp_stream`]); UDP
/// shares the socket ([`wire_udp_socket`]).
pub fn wire_dialed_link(
    dialed: DialedLink,
) -> (
    InboundLink,
    Arc<dyn BoxedLinkDriver + Send + Sync>,
    TokioJoinHandle<()>,
) {
    match dialed {
        DialedLink::Tcp(stream) => {
            let (inbound, outbound, handle) = wire_tcp_stream(stream);
            (InboundLink::Tcp(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-udp")]
        DialedLink::Udp { socket, peer } => {
            let (inbound, outbound, handle) = wire_udp_socket(socket, peer);
            (InboundLink::Udp(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-serial")]
        DialedLink::Serial(stream) => {
            let (inbound, outbound, handle) = wire_serial_stream(stream);
            (InboundLink::Serial(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-tls")]
        DialedLink::Tls(stream) => {
            let (inbound, outbound, handle) = wire_tls_stream(*stream);
            (InboundLink::Tls(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-ws")]
        DialedLink::Ws(stream) => {
            let (inbound, outbound, handle) = wire_ws_stream(*stream);
            (InboundLink::Ws(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-unixsock")]
        DialedLink::Unixsock(stream) => {
            let (inbound, outbound, handle) = wire_unixsock_stream(stream);
            (InboundLink::Unixsock(inbound), outbound, handle)
        }
        #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
        DialedLink::Vsock(stream) => {
            let (inbound, outbound, handle) = wire_vsock_stream(stream);
            (InboundLink::Vsock(inbound), outbound, handle)
        }
        #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
        DialedLink::Unixpipe(link) => {
            let (inbound, outbound, handle) = wire_unixpipe_stream(link);
            (InboundLink::Unixpipe(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-quic")]
        DialedLink::Quic(link) => {
            let (inbound, outbound, handle) = wire_quic_stream(*link);
            (InboundLink::Quic(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-quic-datagram")]
        DialedLink::QuicDatagram(link) => {
            let (inbound, outbound, handle) = wire_quic_datagram(*link);
            (InboundLink::QuicDatagram(inbound), outbound, handle)
        }
    }
}

/// Live handles for a session brought up to Established by
/// [`connect_and_open_session`]. The caller continues the steady state by
/// threading `inbound` + `actions` + `engine` into
/// [`crate::session_glue::drive_session_until_terminal`], and awaits
/// `writer_handle` during teardown so a tail frame the FSM enqueues during
/// its final transition still drains to the peer. `clock` is the shared
/// monotonic epoch (Copy) the open phase used, returned so the steady-state
/// loop and any lease comparator stay on the same epoch.
pub struct OpenedSession {
    pub engine: Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    pub actions: Arc<SessionLinkActions>,
    pub inbound: InboundLink,
    pub writer_handle: TokioJoinHandle<()>,
    pub clock: TokioTime,
}

/// Wall-clock budget for the terminal writer-drain — a wedged writer task
/// (stalled peer, full kernel send buffer) is dropped via timeout rather than
/// blocking teardown indefinitely. The single source for the figure the demo
/// R292 [`teardown::drain_writer`](../../wz-ap-demo/src/teardown.rs) and the
/// library [`OpenedSession::drain_to_close`] both apply.
pub const WRITER_DRAIN_MS: u64 = 50;

impl OpenedSession {
    /// Terminal drain after the steady-state drive loop returns: drop the two
    /// `Arc<SessionLinkActions>` holders of the outbound sender — the `engine`'s
    /// `SessionActionsBinding` clone and the caller-held `actions` — so the
    /// `writer_task`'s channel closes, then await that task BOUNDED by
    /// [`WRITER_DRAIN_MS`]. Consuming `self` makes the engine-before-actions-
    /// before-await order correct-by-construction instead of a doc-only invariant
    /// (the regression the R292 `teardown` typestate was built to forbid); the
    /// bounded await is the same wedged-writer defense as `teardown::drain_writer`
    /// rather than an unbounded block. Callers that drive a session to terminal
    /// and hold no Close-frame / liveliness obligation (e.g.
    /// [`crate::accept_loop`] faces) drain through this single primitive; the demo
    /// keeps its richer R292 chain (Close emit + token undeclare precede the same
    /// drop+drain) for the single-session app path.
    /// R311qi — the remote peer's zid as learned at handshake (the routing
    /// identity a peer-mesh graph keys faces on), or `None` if the INIT exchange
    /// did not surface it. Delegates to
    /// [`SessionLinkActions::peer_zid`](wz_session_core::session_actions::SessionLinkActions::peer_zid)
    /// — captured from the inbound InitSyn (Accepting side) or InitAck
    /// (Initiating side), so a face exposes it regardless of which side opened
    /// it. Read once the session is Established (the accept loop reads it at
    /// `FaceUp`).
    pub fn peer_zid(&self) -> Option<Vec<u8>> {
        self.actions.peer_zid()
    }

    /// R311y205 (transport-multilink IMPL-2b-ii) — the peer's captured ephemeral
    /// multilink pubkey (encoded ZPublicKey bytes), latched during the 0x4
    /// handshake, or `None` if this session did not negotiate multilink
    /// (max_links=1). The aggregation join reads it at `FaceUp` to bind a second
    /// link to the SAME logical session (config-equality against the first link's
    /// captured key).
    #[cfg(feature = "transport-multilink")]
    pub fn multilink_pubkey(&self) -> Option<Vec<u8>> {
        self.actions.multilink_pubkey()
    }

    /// R311y9 — public snapshot of this session's transport byte/message
    /// counters (`transport-stats`). Delegates to
    /// [`SessionLinkActions::stats_report`](wz_session_core::session_actions::SessionLinkActions::stats_report);
    /// the standalone read path (the adminspace `@/<zid>/.../stats` consumer
    /// stays P4). Returns a plain-integer
    /// [`wz_session_core::stats::TransportStatsReport`].
    #[cfg(feature = "transport-stats")]
    pub fn stats(&self) -> wz_session_core::stats::TransportStatsReport {
        self.actions.stats_report()
    }

    pub async fn drain_to_close(self) {
        let OpenedSession {
            engine,
            actions,
            inbound,
            writer_handle,
            clock,
        } = self;
        drop(inbound);
        drop(engine);
        drop(actions);
        let _ = clock.timeout(WRITER_DRAIN_MS, writer_handle).await;
    }
}

/// Why a session did not reach Established.
#[derive(Debug)]
pub enum OpenError {
    /// The locator string did not parse into a typed endpoint (R311ew —
    /// surfaced by [`open_session_at`] / [`open_session_static`] when a
    /// scouting-supplied or configured locator is malformed).
    BadLocator(AnyLocatorError),
    /// Dial failed (TCP connect refused, socket bind error), or the locator
    /// protocol is not compiled in (a `udp/...` locator with the
    /// `transport-link-udp` feature off surfaces a typed `Unsupported` here).
    Dial(io::Error),
    /// The link was lost mid-handshake (peer closed before OpenAck).
    LinkLost(LostCause),
    /// The FSM reached a terminal state before Established — e.g. a peer
    /// Close during the handshake.
    Terminal,
    /// A handshake timeout fired before Established: the peer did not
    /// complete the handshake within the §2.5 window (`init_ack.timeout` /
    /// `open_ack.timeout`, 2s each; `link.open_timeout` 5s). The host
    /// deadline-sweep raises the timeout event once
    /// [`connect_and_open_session`]'s tick advances past the deadline,
    /// driving the FSM to `Closing`.
    /// Distinguished from [`Self::Terminal`] via the close-reason trace: a
    /// timeout transition runs `set_close_reason_generic` (so
    /// `set_close_reason_count >= 1` with `CloseReason::Generic`), whereas a
    /// peer Close / link loss reaches `Closed` without a close-reason action.
    HandshakeTimeout,
    /// R311kc — the peer's InitAck size parameters exceeded our InitSyn
    /// advertisement (zenoh-pico `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION`,
    /// unicast/transport.c:123-140: every InitAck size parameter must be
    /// `<=` the InitSyn's). The dispatcher rejected the session — the FSM
    /// took the `framing.error` arm (Closing with `CloseReason::Invalid`,
    /// wire Close(INVALID)) and the open loop surfaces the typed reason
    /// here instead of folding it into [`Self::Terminal`].
    InitAckCapsRejected,
    /// R3b — a Z_EXT_AUTH method rejected the peer during the handshake (a bad
    /// usrpwd credential, unknown user, missing required sub-ext, or a malformed
    /// auth ext). The dispatcher took the `framing.error` arm (Closing with
    /// `CloseReason::Invalid`, wire Close(INVALID)); the open loop surfaces the
    /// carried [`AuthError`](wz_session_core::auth_dispatch::AuthError) here
    /// instead of folding it into [`Self::Terminal`]. The wz mirror of zenoh's
    /// establishment FSM `?`-propagating the usrpwd verify error into a close.
    #[cfg(feature = "session-extauth")]
    AuthRejected(wz_session_core::auth_dispatch::AuthError),
    /// R4a — the accept-side auth seam could not draw a fresh per-handshake
    /// challenge nonce from OS entropy (a sandbox without `/dev/urandom`). The
    /// handshake is aborted rather than reused with a stale nonce (the usrpwd /
    /// pubkey responder replay-defense contract); a near-impossible failure on a
    /// normal host, surfaced typed rather than panicked.
    #[cfg(feature = "session-extauth")]
    AuthEntropy(getrandom::Error),
    /// The bounded iteration budget elapsed before Established (test guard;
    /// production passes `None`).
    IterationLimit,
    /// Every configured static locator failed (parse / dial / handshake) —
    /// the static-mode "configured locators are wrong / unreachable"
    /// diagnostic (docs/scouting-fsm.md §2.4.3 reason #1). Only returned by
    /// [`open_session_static`].
    NoReachableLocator,
    /// R311py — the `--connect`-style string parsed to a valid locator that is
    /// NOT a reconnect target (a `serial/...` endpoint: no client reopen-task
    /// model, pico parity). Only returned by
    /// [`crate::reconnect::reconnect_endpoint`], which narrows the parsed
    /// [`AnyLocator`] to the reconnectable subset; the typed
    /// [`NotReconnectable`](wz_session_core::reconnect::NotReconnectable) is
    /// carried through rather than flattened to a string so the caller can
    /// distinguish it from a malformed-locator [`Self::BadLocator`].
    NotReconnectable(wz_session_core::reconnect::NotReconnectable),
}

/// Build the session action layer + SCE engine for an open path, ready for
/// role activation. Shared by [`connect_and_open_session`] (Initiator) and
/// [`accept_and_open_session`] (Accepting): both wire the same
/// [`SessionLinkActions`] + engine-free [`SessionFsmUnicastPolicy`] and
/// differ only in the role-start event they dispatch afterwards.
///
/// R311il — the engine is the engine-free
/// `SessionFsmUnicastPolicy<SessionActionsBinding>` built by
/// [`new_session_engine`]; no `LuaEngine` / `IScriptEngine` is involved
/// (the 18 actions are native trait methods on the binding).
fn wire_session_engine(
    outbound: Arc<dyn BoxedLinkDriver + Send + Sync>,
    params: SessionInitParams,
    clock: TokioTime,
) -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let actions = new_session_actions(outbound, params, clock);
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine)
}

/// Drive an already-activated session FSM to Established, bounded by the
/// host handshake deadline-sweep (R311fa / R311il). The role-agnostic open
/// loop shared by both open paths: the caller wires the link + engine and
/// dispatches the role-start event, then this races the cancel-safe inbound
/// poll against a `tick_interval_ms` cadence; on each tick the
/// [`HandshakeDeadlineTracker`] raises the elapsed timeout event — the
/// Initiator's `init_ack.timeout` / `open_ack.timeout` (2s) /
/// `link.open_timeout` (5s), and the Accepting side's
/// `accepting.inactivity_timeout` (1s, R311fb). A frame that arrives
/// first resolves the handshake without waiting for the next tick; the losing
/// `select!` branch is cancelled, safe because `poll_and_dispatch_one`'s only
/// await is `poll_event`, whose partial-read state lives in the driver's
/// `ReadState`.
///
/// Terminal mapping is role-agnostic. A pre-Established terminal reached via a
/// timeout transition that ran `set_close_reason_generic` (the Initiator's
/// Closing path) surfaces as [`OpenError::HandshakeTimeout`]; every other
/// pre-Established terminal surfaces as [`OpenError::Terminal`] — a peer
/// Close, a link loss to Closed, and the Accepting side's
/// `accepting.inactivity_timeout` -> Closed (which runs no close-reason action
/// per §2.7 anti-amplification). So a timed-out accept is reported as
/// `Terminal`, intentionally indistinguishable from a peer close: the silent
/// drop spends no Close frame on a possibly-spoofed peer.
/// pub(crate) for the A4b reconnect supervisor (`crate::reconnect`), which
/// re-runs this same open loop over a re-dialed link with the surviving
/// actions bundle.
pub(crate) async fn drive_open_loop(
    mut inbound: InboundLink,
    actions: Arc<SessionLinkActions>,
    mut engine: Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    writer_handle: TokioJoinHandle<()>,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    // R311il — the engine-free FSM arms no `<send delay>` (NoOpHal), so the
    // host owns every handshake deadline. The deadline VALUES are the §2.5
    // spec baseline — the same literals the SCXML `<send delay>`s carried
    // before the migration (deploy-config overrides are a later round); the
    // [`HandshakeDeadlineTracker`] owns the arming-key staleness logic
    // shared with the steady-state loop.
    let mut deadline_tracker = HandshakeDeadlineTracker::new(SessionTimeouts::spec_defaults());
    let mut iter: usize = 0;
    loop {
        // A4 (R311js) — Established is detected via the `established_at`
        // STATE slot (`is_established`), not the cumulative
        // `record_established_at` trace counter: the counter survives a
        // `reset_for_reopen`, so a reconnect re-run of this loop over the
        // surviving actions bundle would false-positive on the FIRST
        // connection's count and skip the re-handshake. Equivalent on a
        // fresh bundle (the same `Established.onentry` action populates
        // both).
        if actions.is_established() {
            return Ok(OpenedSession {
                engine,
                actions,
                inbound,
                writer_handle,
                clock,
            });
        }
        if engine.is_in_final_state() {
            // Pre-Established terminal. A handshake-timer transition on the
            // Initiator path ran `set_close_reason_generic` (count >= 1,
            // reason Generic); a peer Close / link loss / the silent accept
            // inactivity timeout reaches Closed without a close-reason action
            // (count == 0), so the Initiator timeout is distinguishable while
            // the accept timeout folds into Terminal (silent-drop by design).
            let trace = actions.trace_snapshot();
            return Err(
                if trace.set_close_reason_count >= 1 && trace.close_reason == CloseReason::Generic {
                    OpenError::HandshakeTimeout
                } else {
                    OpenError::Terminal
                },
            );
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return Err(OpenError::IterationLimit);
            }
            iter += 1;
        }
        // R311fa / R311il — the tracker (re-)arms the host handshake
        // deadline for the current state (per-phase keys re-arm on entry;
        // the Accepting children share one whole-handshake bound).
        let armed_deadline =
            deadline_tracker.poll(engine.get_current_state(), clock.now_monotonic_ms());
        // R311il — race the cancel-safe inbound poll against a `tick_interval_ms`
        // cadence; on each wake, raise the armed handshake timeout event once
        // its spec-sourced window has elapsed (host deadline-sweep — the
        // engine-free FSM arms no `<send delay>`, so there is no SCE
        // scheduler to pump). A frame that arrives first resolves the
        // handshake without waiting for the next tick.
        tokio::select! {
            outcome = poll_and_dispatch_one(&mut inbound, &actions, &mut engine) => {
                match outcome {
                    DriverLoopOutcome::LinkLost(cause) => {
                        return Err(OpenError::LinkLost(cause));
                    }
                    // R311kc — the dispatcher rejected a non-conforming
                    // InitAck (size params exceed our advertisement); the
                    // FSM is already Closing with CloseReason::Invalid.
                    // Surface the typed reason instead of looping to the
                    // generic terminal classification.
                    #[cfg(feature = "codec-init-body")]
                    DriverLoopOutcome::InitAckCapsRejected => {
                        return Err(OpenError::InitAckCapsRejected);
                    }
                    // R3b — a usrpwd method rejected the peer; the FSM is already
                    // Closing(Invalid). Surface the typed reason (mirrors the
                    // InitAckCapsRejected path) for both the initiator and the
                    // acceptor (both drive through this shared loop).
                    #[cfg(feature = "session-extauth")]
                    DriverLoopOutcome::AuthRejected(e) => {
                        return Err(OpenError::AuthRejected(e));
                    }
                    _ => {}
                }
            }
            _ = clock.sleep(tick_interval_ms) => {
                if let Some((deadline_ms, event)) = armed_deadline {
                    if clock.now_monotonic_ms() >= deadline_ms {
                        engine.process_event(event);
                    }
                }
            }
        }
    }
}

/// Dial `locator`, wire the connection into the link pipeline ([`DialedLink`]
/// -> [`wire_dialed_link`]: a stream splits into read/write halves, a
/// datagram socket is shared), wire the unicast session FSM in the Initiator
/// role, and drive the inbound handshake (peer InitAck -> OpenSyn -> peer
/// OpenAck) until the FSM records Established.
///
/// The handshake messages are transport-uniform — the only difference is
/// framing: TCP length-prefixes each through `StreamEnvelope`, UDP sends
/// one message per datagram (boundary == frame), and both decode through the
/// same `handle_inbound` path.
///
/// Wall-clock bounded by the host handshake deadline-sweep (R311fa /
/// R311il). The inbound poll is raced in a `tokio::select!` against a
/// `tick_interval_ms` cadence; once the [`HandshakeDeadlineTracker`]
/// reports the deadline armed by the current handshake state has elapsed
/// (`init_ack.timeout` / `open_ack.timeout`, 2s; `link.open_timeout`, 5s),
/// the loop raises the timeout event and the FSM transitions to `Closing` —
/// surfaced here as [`OpenError::HandshakeTimeout`]. So a peer that never
/// answers no longer hangs the loop (the prior `max_iters`-only bound was a
/// test guard, not a wall-clock deadline). The window durations are the
/// §2.5 single source of truth in [`SessionTimeouts`]; `tick_interval_ms`
/// only sets how finely the host samples the clock (see
/// [`DEFAULT_OPEN_TICK_MS`]). `poll_and_dispatch_one`
/// is cancel-safe (partial reads live in `TcpReadDriver`'s `ReadState`), so
/// the tick branch can cancel an in-flight read without losing wire bytes.
///
/// The Initiator activation is `OutboundStart` (-> LinkOpening; the
/// `link_driver_open` action is a no-op since the stream is already
/// connected) + `LinkOpened` (-> SentInitSyn, which fires `send_init_syn` —
/// the first wire byte, enqueued on the outbound channel). This is the same
/// sequence wz-ap-demo's `activate_role` dispatches for the Initiator role.
///
/// Established is detected via the `record_established_at` action counter,
/// which fires on the Established onentry regardless of sub-state — so this
/// helper does not depend on the generated FSM state-enum shape.
///
/// `max_iters` bounds the inbound poll loop for test determinism;
/// production passes `None` and relies on the handshake-timer deadline
/// above. `tick_interval_ms` is the SCE-scheduler pump cadence
/// ([`DEFAULT_OPEN_TICK_MS`] for production).
pub async fn connect_and_open_session(
    locator: AnyLocator,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session(dialed, params, clock, max_iters, tick_interval_ms).await
}

/// R3b — [`connect_and_open_session`] with a Z_EXT_AUTH dispatch installed: it
/// dials the locator then opens with auth, the additive auth-on sibling of the
/// bare connect. Used by the wz<->zenohd usrpwd interop e2e: wz dials a
/// usrpwd-guarded zenohd as a client and authenticates with a
/// `UsrPwdMethod::initiator` dispatch.
#[cfg(feature = "session-extauth")]
pub async fn connect_and_open_session_with_auth(
    locator: AnyLocator,
    params: SessionInitParams,
    auth: AuthDispatch,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_auth(dialed, params, auth, clock, max_iters, tick_interval_ms)
        .await
}

/// transport-lowlatency — [`connect_and_open_session`] that OFFERS the
/// lowlatency capability: dials the locator then opens with the lean-transport
/// offer staged on the session actions before the handshake drives. The InitSyn
/// carries the Z_EXT_LOWLATENCY unit ext, and if the peer reflects it the
/// established session uses the lean no-Frame data path. The additive
/// lowlatency-on sibling of the bare connect (signature-stable: existing callers
/// keep the bare open).
#[cfg(feature = "transport-lowlatency")]
pub async fn connect_and_open_session_with_lowlatency(
    locator: AnyLocator,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_lowlatency(dialed, params, clock, max_iters, tick_interval_ms)
        .await
}

/// session-extcompression — [`connect_and_open_session`] that OFFERS compression:
/// dials the locator then opens with the lz4-compression offer staged on the
/// session actions before the handshake drives. The InitSyn carries the
/// Z_EXT_COMPRESSION unit ext, and if the peer reflects it every post-establishment
/// batch is lz4-wrapped. Signature-stable additive sibling of the bare connect.
#[cfg(feature = "session-extcompression")]
pub async fn connect_and_open_session_with_compression(
    locator: AnyLocator,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_compression(dialed, params, clock, max_iters, tick_interval_ms)
        .await
}

/// session-extshm — [`connect_and_open_session`] that OFFERS SHM: dials the
/// locator then opens with the SHM capability offer staged. The InitSyn carries
/// the 0x2 SHM establishment unit ext; if the peer reflects it, an SHM-backed
/// `publish_shm` sends descriptors instead of bytes. Signature-stable additive
/// sibling.
#[cfg(feature = "session-extshm")]
pub async fn connect_and_open_session_with_shm(
    locator: AnyLocator,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_shm(dialed, params, clock, max_iters, tick_interval_ms).await
}

/// §5.21 routing-namespace — [`connect_and_open_session`] that installs a
/// namespace: dials the locator then opens with the decorator seeded. Every
/// application keyexpr on the resulting session is relative to `namespace`
/// (the public deploy seam for a namespaced peer, the
/// `connect_and_open_session_with_compression` sibling).
#[cfg(feature = "routing-namespace")]
pub async fn connect_and_open_session_with_namespace(
    locator: AnyLocator,
    params: SessionInitParams,
    namespace: OwnedNonWildKeyExpr,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_namespace(
        dialed,
        params,
        namespace,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// Bring up a session in the Initiator role from an already-connected
/// transport — the dialed-link half of [`connect_and_open_session`], split out
/// so a caller that already holds a connected stream (e.g. wz-ap-demo's
/// `establish_link`, which dials its own `TcpStream`) opens without re-dialing.
/// Symmetric to [`accept_and_open_session`]: both take a [`DialedLink`] and
/// differ only in the role-start activation; [`connect_and_open_session`] is
/// the `dial_locator` + this convenience wrapper for callers that start from a
/// locator string (scouting / static).
///
/// Activates the FSM in the Initiator role (`outbound.start` -> LinkOpening;
/// the `link_driver_open` action is a no-op since the transport is already
/// connected, then `link.opened` -> SentInitSyn fires `send_init_syn`, the
/// first wire byte) and drives the inbound handshake (peer InitAck -> OpenSyn
/// -> peer OpenAck) to Established. Wall-clock bounded by the FSM's handshake
/// timers exactly as [`connect_and_open_session`] (see [`drive_open_loop`]).
pub async fn initiate_and_open_session(
    connected: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R3b — [`initiate_and_open_session`] with a Z_EXT_AUTH dispatch installed on
/// the session actions before the handshake drives, so the four establishment
/// messages carry the negotiated auth sub-exts (a usrpwd initiator's offer +
/// HMAC). The additive auth-on sibling of the bare open: the many existing
/// callers keep the unauthenticated signature, while an auth deploy (or the
/// wz<->zenohd usrpwd interop e2e) calls this. Initiator side only — the
/// responder challenge nonce arrives on the peer InitAck, so there is no nonce
/// draw here (that is the accept path's `refresh_auth_challenge_nonce`).
#[cfg(feature = "session-extauth")]
pub async fn initiate_and_open_session_with_auth(
    connected: DialedLink,
    params: SessionInitParams,
    auth: AuthDispatch,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.install_auth_dispatch(auth);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y205 (transport-multilink) — [`initiate_and_open_session`] negotiating the
/// 0x4 Z_EXT_MULTILINK aggregation ext (the deploy set `max_links > 1`): installs
/// the OPEN-side ephemeral-pubkey dispatch (so the InitSyn / OpenSyn carry the 0x4
/// ext and the initiator captures the responder's ephemeral pubkey) and tags this
/// physical link's `reliability_pref` before the handshake drives. The additive
/// multilink-on sibling of the bare open. Initiator side; the acceptor mirrors via
/// [`accept_and_open_session_with_multilink`].
#[cfg(feature = "transport-multilink")]
pub async fn initiate_and_open_session_with_multilink(
    connected: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.install_multilink_dispatch(crate::multilink::open_multilink_dispatch());
    actions.set_link_reliability_pref(reliability_pref);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// transport-lowlatency — [`initiate_and_open_session`] with the lowlatency
/// capability offered on the session actions before the handshake drives, so the
/// InitSyn carries the Z_EXT_LOWLATENCY unit ext. The initiator side; the
/// acceptor reflects via [`accept_and_open_session_with_lowlatency`]. The
/// additive lowlatency-on sibling of the bare open.
#[cfg(feature = "transport-lowlatency")]
pub async fn initiate_and_open_session_with_lowlatency(
    connected: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.set_lowlatency_offer(true);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// session-extcompression — [`initiate_and_open_session`] with the compression
/// capability offered before the handshake drives (the InitSyn carries the
/// Z_EXT_COMPRESSION unit ext). Initiator side; the acceptor reflects via
/// [`accept_and_open_session_with_compression`].
#[cfg(feature = "session-extcompression")]
pub async fn initiate_and_open_session_with_compression(
    connected: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.set_compression_offer(true);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// session-extshm — [`initiate_and_open_session`] with the SHM capability offered
/// before the handshake drives (the InitSyn carries the 0x2 SHM establishment
/// ext). Initiator side; the acceptor reflects via
/// [`accept_and_open_session_with_shm`].
#[cfg(feature = "session-extshm")]
pub async fn initiate_and_open_session_with_shm(
    connected: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.set_shm_offer(true);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// §5.21 routing-namespace — [`initiate_and_open_session`] with the
/// per-participant namespace installed on the session actions before the drive
/// loop spins. Namespace is NOT handshake-negotiated (unlike lowlatency /
/// compression / shm); it is a unilateral LOCAL decorator that acts only on the
/// post-Established data plane, so it is simply seeded here. Initiator side; the
/// acceptor installs its own via [`accept_and_open_session_with_namespace`].
#[cfg(feature = "routing-namespace")]
pub async fn initiate_and_open_session_with_namespace(
    connected: DialedLink,
    params: SessionInitParams,
    namespace: OwnedNonWildKeyExpr,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.set_namespace(namespace);
    initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311ju — the single home of the Initiator bring-up sequence: build a
/// fresh engine over `actions`, dispatch the role-start activation
/// (`OutboundStart` -> LinkOpening, where `link_driver_open` is a no-op on
/// an already-connected transport; `LinkOpened` -> SentInitSyn, which fires
/// `send_init_syn` — the first wire byte), and drive [`drive_open_loop`] to
/// Established.
///
/// Extracted from the A4b session review (F1): the activation order is
/// protocol-critical and was repeated verbatim across
/// [`initiate_and_open_session`], `reconnect::open_session_with_reconnect`,
/// and every `reconnect` reopen attempt — three drift-prone copies. All
/// three now route here; the engine is built INSIDE so a reopen attempt
/// over a surviving actions bundle and a first open over a fresh one share
/// the exact same body.
pub(crate) async fn initiator_open(
    inbound: InboundLink,
    actions: Arc<SessionLinkActions>,
    writer_handle: TokioJoinHandle<()>,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    // Initiator activation -> SentInitSyn (send_init_syn enqueues InitSyn).
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// Bring up a session in the Accepting role from an already-accepted transport
/// — the listener half, symmetric to [`connect_and_open_session`]'s dial half.
///
/// The caller owns the listener and hands the accepted connection in as a
/// [`DialedLink`] (`DialedLink::Tcp(stream)` from a `TcpListener::accept`
/// result; the datagram acceptor is test-only). This wires it through the same
/// [`wire_dialed_link`] -> [`wire_session_engine`] path the dial side uses,
/// activates the FSM in the Accepting role (`inbound.start` ->
/// `Accepting.AwaitingInitSyn`), and drives the 4-way handshake (peer InitSyn
/// -> our InitAck -> peer OpenSyn -> our OpenAck) to Established.
///
/// Wall-clock bounded by the accept-side open-deadline (R311fb / R311il):
/// the `accepting.inactivity_timeout` armed on `Accepting` entry (1s, §2.5)
/// is raised by the same host deadline-sweep as the Initiator timers, so a
/// peer that connects then goes silent no longer hangs the loop (closing the
/// R311fa carry #2 — the Initiator path was bounded, the acceptor was not).
/// The drop is silent (the transition targets `Closed`, no Close frame —
/// §2.7 anti-amplification) and therefore surfaces as [`OpenError::Terminal`],
/// not a distinct timeout variant: a timed-out accept is intentionally
/// indistinguishable from a peer close (no reply is spent on a possibly-spoofed
/// peer). See [`drive_open_loop`] for the shared terminal mapping.
///
/// `max_iters` / `tick_interval_ms` carry the same meaning as on
/// [`connect_and_open_session`] (test-determinism poll bound + SCE-scheduler
/// pump cadence; production passes `None` + [`DEFAULT_OPEN_TICK_MS`]).
pub async fn accept_and_open_session(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);

    // Accepting activation -> AwaitingInitSyn, whose onentry arms
    // `accepting.inactivity_timeout` (the open-deadline this path enforces).
    engine.process_event(E::InboundStart);

    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R4a — [`accept_and_open_session`] with a Z_EXT_AUTH dispatch installed AND a
/// fresh per-handshake challenge nonce drawn here from OS entropy: the
/// accept-side counterpart of [`connect_and_open_session_with_auth`]. The SEAM
/// (not the caller) draws the nonce, so the per-accepted-handshake freshness the
/// usrpwd / pubkey responder replay-defense requires is enforced by
/// construction — a caller cannot forget it and reuse a stale challenge. The
/// caller builds the dispatch with the responder method(s) (the credential
/// lookup / accepted-key set); this injects the live nonce before the FSM fires
/// the InitAck challenge. zenoh draws `prng.gen()` per `StateAccept`; this is
/// the wz equivalent at the accept seam.
#[cfg(feature = "session-extauth")]
pub async fn accept_and_open_session_with_auth(
    accepted: DialedLink,
    params: SessionInitParams,
    auth: AuthDispatch,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.install_auth_dispatch(auth);
    // Fresh challenge nonce per accepted handshake (the replay defense) — drawn
    // from AP OS entropy here because the no_std session core cannot.
    let nonce = crate::session_glue::nonce_from_os_entropy().map_err(OpenError::AuthEntropy)?;
    actions.refresh_auth_challenge_nonce(nonce);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y205 (transport-multilink) — [`accept_and_open_session`] negotiating the
/// 0x4 Z_EXT_MULTILINK aggregation ext: installs the ACCEPT-side ephemeral-pubkey
/// dispatch (key-lookup disabled — accept any initiator key), draws a FRESH
/// per-handshake challenge nonce from OS entropy at the seam (the responder
/// replay-defense, by construction), and tags this link's `reliability_pref`. The
/// responder reflects the 0x4 ext in InitAck / OpenAck iff the peer offered it and
/// captures the initiator's ephemeral pubkey. Accept-side twin of
/// [`initiate_and_open_session_with_multilink`].
#[cfg(feature = "transport-multilink")]
pub async fn accept_and_open_session_with_multilink(
    accepted: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.install_multilink_dispatch(crate::multilink::accept_multilink_dispatch());
    actions.set_link_reliability_pref(reliability_pref);
    // Fresh challenge nonce per accepted handshake (the pubkey responder replay
    // defense) — drawn from AP OS entropy here because the no_std core cannot.
    let nonce = crate::session_glue::nonce_from_os_entropy().map_err(OpenError::AuthEntropy)?;
    actions.refresh_multilink_challenge_nonce(nonce);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// transport-lowlatency — [`accept_and_open_session`] that OFFERS the lowlatency
/// capability on the accept side: the acceptor reflects the Z_EXT_LOWLATENCY ext
/// in its InitAck iff the peer's InitSyn offered it (the `&=` merge runs on the
/// inbound InitSyn before the InitAck is emitted), so the established session
/// uses the lean no-Frame data path. The accept-side counterpart of
/// [`connect_and_open_session_with_lowlatency`].
#[cfg(feature = "transport-lowlatency")]
pub async fn accept_and_open_session_with_lowlatency(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.set_lowlatency_offer(true);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// session-extcompression — [`accept_and_open_session`] that OFFERS compression
/// on the accept side: the acceptor reflects the Z_EXT_COMPRESSION ext in its
/// InitAck iff the peer's InitSyn offered it (the `&=` merge), so the established
/// session lz4-wraps every batch. The accept-side counterpart of
/// [`connect_and_open_session_with_compression`].
#[cfg(feature = "session-extcompression")]
pub async fn accept_and_open_session_with_compression(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.set_compression_offer(true);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// §5.21 routing-namespace — [`accept_and_open_session`] that installs a
/// namespace on the ACCEPT side. The accept-side counterpart of
/// [`connect_and_open_session_with_namespace`]; the namespace is LOCAL (each
/// participant configures its own), never reflected from the peer.
#[cfg(feature = "routing-namespace")]
pub async fn accept_and_open_session_with_namespace(
    accepted: DialedLink,
    params: SessionInitParams,
    namespace: OwnedNonWildKeyExpr,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.set_namespace(namespace);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// session-extshm — [`accept_and_open_session`] that OFFERS SHM on the accept
/// side: the acceptor reflects the 0x2 SHM ext in its InitAck iff the peer's
/// InitSyn offered it (the `&=` merge). The accept-side counterpart of
/// [`connect_and_open_session_with_shm`].
#[cfg(feature = "session-extshm")]
pub async fn accept_and_open_session_with_shm(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.set_shm_offer(true);

    engine.process_event(E::InboundStart);
    drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// Open a session to a locator discovered by scouting — the mode-agnostic
/// per-locator seam (R311ew).
///
/// Both scouting modes feed this the same way, which is the whole point of
/// the seam: active mode's `ScoutOutcome::Discovered(String)`
/// (wz-runtime-tokio::scouting_glue) and static mode's
/// `synth_static_locators` entries are both zenoh locator strings. This
/// parses one via [`wz_session_core::locator::parse_locator`] and hands the
/// typed endpoint to [`connect_and_open_session`] — "a discovered locator
/// opens the same way regardless of how scouting found it" (the contract the
/// `locator` module doc states from the parse side).
pub async fn open_session_at(
    locator: &str,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let parsed = parse_any_locator(locator).map_err(OpenError::BadLocator)?;
    connect_and_open_session(parsed, params, cfg, clock, max_iters, tick_interval_ms).await
}

/// Open a session to the first reachable peer in a static `deploy.connect[]`
/// list — the static scouting mode (docs/scouting-fsm.md §2.4.3, scouting
/// expressed as *absent*: no FSM, the locators come from config verbatim).
///
/// [`synth_static_locators`] normalises the configured locators in deploy
/// order; each is tried via [`open_session_at`] and the first that reaches
/// Established wins. Per-locator failures are logged (no silent skip) so the
/// diagnostic trail survives; the call returns [`OpenError::NoReachableLocator`]
/// only when every configured locator failed — the static-mode "configured
/// locators are wrong / unreachable" diagnostic (§2.4.3 reason #1).
///
/// MVP single-session: zenoh-pico opens the first peer then `_z_new_peer`s
/// the rest (session.c:157-189); the multi-peer mesh is Phase D+, so this
/// opens exactly one session to the first reachable peer.
///
/// R311if — gated on `scouting-static` (the static-mode toggle); the
/// mode-agnostic [`open_session_at`] above stays ungated since active
/// scouting feeds it too.
#[cfg(feature = "scouting-static")]
pub async fn open_session_static(
    connect: &[String],
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    // R311ih — synth now yields the bounded seam (StaticLocators =
    // BoundedVec<BoundedString>); iterate via the slice Deref and pass each
    // locator as &str to the mode-agnostic open path.
    let locators = synth_static_locators(connect);
    if locators.is_empty() {
        return Err(OpenError::NoReachableLocator);
    }
    for locator in locators.iter() {
        match open_session_at(
            locator.as_str(),
            params.clone(),
            cfg,
            clock,
            max_iters,
            tick_interval_ms,
        )
        .await
        {
            Ok(opened) => return Ok(opened),
            Err(e) => {
                log::warn!(
                    "wz session-open: static locator {locator:?} failed: {e:?}; trying next"
                );
            }
        }
    }
    Err(OpenError::NoReachableLocator)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── R311pm/R311ps — dial-routing classifier (`plan_endpoint`). Pure (no
    //    socket / DNS I/O): proves the `--connect` two-path fork is dissolved
    //    and DNS-vs-numeric is a property of the PARSED value, not a string
    //    re-inspection. A name classifies to AnyLocator::Named for EVERY
    //    scheme; whether it can be DIALED is the dial-seam's concern below.

    #[test]
    fn scheme_less_numeric_classifies_as_implicit_tcp_ip() {
        // Bare `HOST:PORT` (no scheme) desugars to implicit `tcp`; a numeric
        // address parses to AnyLocator::Ip(Tcp), same as the explicit `tcp/`.
        assert_eq!(
            plan_endpoint("127.0.0.1:7447"),
            Ok(parse_any_locator("tcp/127.0.0.1:7447").unwrap())
        );
    }

    #[test]
    fn scheme_less_hostname_classifies_as_implicit_tcp_named() {
        // Bare `HOST:PORT` with a DNS name desugars to implicit tcp and
        // classifies as Named (the std resolver dials it at dial time).
        assert_eq!(
            plan_endpoint("example.org:7447"),
            Ok(AnyLocator::Named {
                proto: Proto::Tcp,
                host: "example.org".to_string(),
                port: 7447,
            })
        );
    }

    #[test]
    fn tcp_scheme_numeric_classifies_as_ip() {
        assert_eq!(
            plan_endpoint("tcp/127.0.0.1:7447"),
            Ok(parse_any_locator("tcp/127.0.0.1:7447").unwrap())
        );
    }

    #[test]
    fn tcp_scheme_hostname_classifies_as_named_same_as_scheme_less() {
        // R311pm/R311ps regression guard: `tcp/HOST` with a DNS hostname used
        // to die as a `BadAddress` parse reject (forking it from the bare-host
        // path). It now classifies as Named, and — the fork being dissolved —
        // to the SAME parsed value as the scheme-less form.
        assert_eq!(
            plan_endpoint("tcp/example.org:7447"),
            Ok(AnyLocator::Named {
                proto: Proto::Tcp,
                host: "example.org".to_string(),
                port: 7447,
            })
        );
        assert_eq!(
            plan_endpoint("tcp/example.org:7447"),
            plan_endpoint("example.org:7447"),
        );
    }

    #[test]
    fn ws_scheme_numeric_classifies_as_ip() {
        // A `ws/NUMERIC` locator classifies to Ip(Ws); the dial seam decides
        // WS reachability by feature — the classifier never special-cases it.
        assert_eq!(
            plan_endpoint("ws/127.0.0.1:7447"),
            Ok(parse_any_locator("ws/127.0.0.1:7447").unwrap())
        );
    }

    #[test]
    fn unknown_scheme_is_an_error() {
        // R311xk — `quic` is now a known proto, so the unknown-scheme example
        // moved to `bt` (still not-yet-wired), mirroring the locator.rs
        // `rejects_unknown_proto` fix.
        assert!(matches!(
            plan_endpoint("bt/00:11:22:33:44:55"),
            Err(AnyLocatorError::Ip(LocatorParseError::UnknownProto(_)))
        ));
    }

    #[test]
    fn malformed_address_is_an_error_not_named() {
        // A genuinely malformed `tcp/` (no port) stays a typed parse error,
        // not a guessed dial — the early typed error is preserved (vs the
        // pre-R311ps `starts_with` arm which routed it to a late connect error).
        assert!(matches!(
            plan_endpoint("tcp/no-port-here"),
            Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(_)))
        ));
    }

    // ── dial-side contract: only `tcp` dials a NAME. A udp/ws/tls name is a
    //    typed `Unsupported` returned BEFORE any I/O (no resolver, no socket) —
    //    a clean extension point, not a silent fallback.
    #[tokio::test]
    async fn non_tcp_named_dial_is_unsupported_without_io() {
        for s in [
            "udp/example.org:7447",
            "ws/example.org:7447",
            "tls/example.org:7447",
        ] {
            // DialedLink holds live streams (not Debug), so match rather than
            // expect_err; a non-tcp name must surface Unsupported before any I/O.
            match dial_endpoint(s, &DialConfig::default()).await {
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::Unsupported,
                    "{s} should be Unsupported (name dial only wired for tcp)"
                ),
                Ok(_) => panic!("{s} must not dial (name dial only wired for tcp)"),
            }
        }
    }

    // ── end-to-end: the public seam connects a numeric loopback both with
    //    and without the `tcp/` scheme, reaching the same DialedLink::Tcp.
    //    Numeric loopback only — the DNS routing is proven purely above, so
    //    this exercises no resolver (no-flaky: no /etc/hosts dependency).
    #[tokio::test]
    async fn dial_endpoint_connects_numeric_loopback_with_and_without_scheme() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();

        let bare = dial_endpoint(&format!("127.0.0.1:{port}"), &DialConfig::default())
            .await
            .expect("bare host:port dials");
        assert!(matches!(bare, DialedLink::Tcp(_)));

        let schemed = dial_endpoint(&format!("tcp/127.0.0.1:{port}"), &DialConfig::default())
            .await
            .expect("tcp/ host:port dials");
        assert!(matches!(schemed, DialedLink::Tcp(_)));
    }

    // ── accept-side contract (R311pu): symmetric to the dial side above. Only
    //    `tcp` is wired; a udp/ws/tls `--listen` is a typed `Unsupported`
    //    returned BEFORE any bind (no socket) — the same clean extension-point
    //    shape `dial_locator`'s non-tcp arms carry. The TCP accept path
    //    (bind + accept) is proven end-to-end by Layer E's ap_demo_round_trip
    //    (establish_link's Acceptor role now delegates to accept_endpoint); a
    //    port-race-free unit cannot mirror it because the acceptor owns the
    //    bind, hiding the OS-chosen port a dialing test would need.
    #[tokio::test]
    async fn non_tcp_listen_accept_is_unsupported_without_io() {
        for s in [
            "udp/127.0.0.1:7447",
            "ws/127.0.0.1:7447",
            "tls/127.0.0.1:7447",
        ] {
            match accept_endpoint(s).await {
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::Unsupported,
                    "{s} accept should be Unsupported (accept only wired for tcp)"
                ),
                Ok(_) => panic!("{s} must not accept (accept only wired for tcp)"),
            }
        }
    }
}
