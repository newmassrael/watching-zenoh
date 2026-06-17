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
use tokio::net::TcpStream;

use wz_runtime_core::TimeSource;
use wz_session_core::locator::{
    parse_any_locator, AnyLocator, AnyLocatorError, LocatorParseError, Proto,
};
#[cfg(feature = "scouting-static")]
use wz_session_core::scout_static::synth_static_locators;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

use crate::link_pipeline::{dial_tcp, dial_tcp_host, wire_tcp_stream, TcpReadDriver};
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
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::rustls::ClientConfig;
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::TlsStream;

// R311ob — the WS arm, like udp, rides this tcp+unicast-gated module as an
// additive DATAGRAM transport. The stream type is the RFC6455
// `WebSocketStream<TcpStream>` produced by `ws_pipeline::dial_ws`/`accept_ws`.
// UNLIKE tls, `dial_locator` DOES build it (a `ws/...` locator needs no cert).
#[cfg(feature = "transport-link-ws")]
use crate::ws_pipeline::{dial_ws, wire_ws_stream, WsReadDriver};
#[cfg(feature = "transport-link-ws")]
use tokio_tungstenite::WebSocketStream;

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
/// carry — today the TLS client config a `tls/...` dial needs. Cert-free
/// transports (tcp/udp/ws/serial) ignore it; `tls` reads `cfg.tls` (absent =>
/// typed `Unsupported`). This is what lets the dial seam handle EVERY transport
/// uniformly — pico threads the same material via `session_cfg`.
pub async fn dial_locator(locator: AnyLocator, cfg: &DialConfig) -> io::Result<DialedLink> {
    // `cfg` is consumed only by the tls arm; discard it loudly in builds
    // without that backend so the always-present seam signature carries no
    // dead-param warning.
    #[cfg(not(feature = "transport-link-tls"))]
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
    }
}

/// How a `--connect`-style endpoint string should be dialed — the routing
/// decision the [`dial_endpoint`] seam makes, extracted as a pure value so
/// the decision is exhaustively unit-testable without any socket / DNS I/O.
///
/// R311pm — this dissolves the pre-R311pm `--connect` two-path fork (the
/// wz-ap-demo binary's `connect.contains('/')` heuristic, which dialed a bare
/// `HOST:PORT` through the std resolver but routed a `tcp/...` form through
/// the numeric-only locator parser, so a `tcp/hostname` silently failed as a
/// `BadAddress` parse reject). The decision now lives in one place with one
/// table; [`dial_endpoint`] is a thin async wrapper over the two outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DialPlan {
    /// A scheme'd, parseable locator (`tcp`/`udp`/`ws`/`tls` numeric endpoint
    /// or `serial/...`), dialed via the mode-agnostic [`dial_locator`].
    Locator(AnyLocator),
    /// A `host:port` string for the std-resolver TCP dial ([`dial_tcp_host`]):
    /// a scheme-less `HOST:PORT` (implicit `tcp`), or a `tcp/HOST` whose host
    /// is a DNS name the numeric locator parser rejects. DNS resolution is a
    /// std-layer concern the no_std parser defers ([`wz_session_core::locator`]).
    TcpHost(String),
}

/// Classify a `--connect` endpoint string into a [`DialPlan`] — the dial
/// routing SSOT. Pure (no I/O), so the routing table below is verified
/// directly in unit tests; [`dial_endpoint`] performs the actual dial.
fn plan_dial(connect: &str) -> Result<DialPlan, AnyLocatorError> {
    match parse_any_locator(connect) {
        // A scheme'd, numeric (or serial) locator dials via the mode-agnostic
        // seam. `ws/...` / `tls/...` reachability is decided there by feature.
        Ok(locator) => Ok(DialPlan::Locator(locator)),
        // A scheme-less `HOST:PORT` is an implicit `tcp` endpoint dialed by
        // string, so the std resolver handles it (numeric or DNS alike). This
        // is the wz-ap-demo `--connect 127.0.0.1:7447` convenience form, kept
        // byte-for-byte (the prior bare-host `TcpStream::connect`).
        Err(AnyLocatorError::Ip(LocatorParseError::MissingProtoSeparator)) => {
            Ok(DialPlan::TcpHost(connect.to_string()))
        }
        // `tcp/HOST:PORT` with a DNS hostname: the numeric IP leaf rejects it
        // (`BadAddress`), but the std resolver can dial the name. Route it to
        // the SAME std-resolver TCP dial, sans scheme, so a hostname behaves
        // identically whether or not the `tcp/` scheme is written explicitly.
        // Only `tcp` gets this convenience — `udp`/`ws`/`tls` keep the
        // numeric-only contract (the parser defers their DNS, and no caller
        // needs it), so their `BadAddress` falls through to the error arm.
        Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(addr)))
            if connect.starts_with("tcp/") =>
        {
            Ok(DialPlan::TcpHost(addr))
        }
        // Unknown scheme, a non-tcp DNS host, a metadata suffix, an
        // out-of-range port, or a malformed `serial/...`: surface the typed
        // parse error rather than guessing a transport.
        Err(e) => Err(e),
    }
}

/// Dial a `--connect`-style endpoint string to a raw [`DialedLink`] — the
/// std-layer dial seam, the single home of "turn a connect string into a
/// dialed transport". It owns the parse + scheme dispatch + DNS routing the
/// wz-ap-demo binary previously re-assembled inline (R311pm): a scheme'd
/// numeric/serial locator dials via [`dial_locator`]; a scheme-less
/// `HOST:PORT` or a `tcp/HOST` DNS hostname dials via the std-resolver
/// [`dial_tcp_host`] (see [`plan_dial`] for the routing table).
///
/// Distinct from [`open_session_at`], which dials a scouting / static-deploy
/// locator: those are machine-supplied and numeric by the parser's contract,
/// so that path does not carry the human-typed-`--connect` DNS convenience.
///
/// `cfg` is forwarded to [`dial_locator`] for the transports that need
/// out-of-band material (TLS); cert-free transports ignore it.
pub async fn dial_endpoint(connect: &str, cfg: &DialConfig) -> io::Result<DialedLink> {
    let plan = plan_dial(connect).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz dial: malformed / unsupported --connect {connect:?}: {e:?}"),
        )
    })?;
    match plan {
        DialPlan::Locator(locator) => dial_locator(locator, cfg).await,
        DialPlan::TcpHost(host) => Ok(DialedLink::Tcp(dial_tcp_host(&host).await?)),
    }
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
    /// The bounded iteration budget elapsed before Established (test guard;
    /// production passes `None`).
    IterationLimit,
    /// Every configured static locator failed (parse / dial / handshake) —
    /// the static-mode "configured locators are wrong / unreachable"
    /// diagnostic (docs/scouting-fsm.md §2.4.3 reason #1). Only returned by
    /// [`open_session_static`].
    NoReachableLocator,
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

    // ── R311pm — dial-routing SSOT (`plan_dial`). These prove the
    //    `--connect` two-path fork is dissolved into one decision table,
    //    deterministically and with NO socket / DNS I/O: the routing is a
    //    pure function over the parsed scheme.

    #[test]
    fn scheme_less_host_routes_to_the_std_resolver_tcp_dial() {
        // A bare `HOST:PORT` (no scheme) is an implicit `tcp` endpoint dialed
        // by string, so the std resolver handles numeric and DNS alike.
        assert_eq!(
            plan_dial("127.0.0.1:7447"),
            Ok(DialPlan::TcpHost("127.0.0.1:7447".to_string()))
        );
        assert_eq!(
            plan_dial("example.org:7447"),
            Ok(DialPlan::TcpHost("example.org:7447".to_string()))
        );
    }

    #[test]
    fn tcp_scheme_numeric_routes_to_the_locator_dial() {
        // `tcp/NUMERIC` parses to a numeric locator dialed via dial_locator.
        assert_eq!(
            plan_dial("tcp/127.0.0.1:7447"),
            Ok(DialPlan::Locator(
                parse_any_locator("tcp/127.0.0.1:7447").unwrap()
            ))
        );
    }

    #[test]
    fn tcp_scheme_dns_host_routes_to_the_std_resolver_tcp_dial() {
        // R311pm regression guard: `tcp/HOST` with a DNS hostname previously
        // died as a `BadAddress` parse reject (the numeric IP leaf), forking
        // it away from the bare-host std-resolver path. It now routes to the
        // SAME std-resolver TCP dial, sans scheme — a hostname behaves
        // identically whether or not the `tcp/` scheme is written.
        assert_eq!(
            plan_dial("tcp/example.org:7447"),
            Ok(DialPlan::TcpHost("example.org:7447".to_string()))
        );
    }

    #[test]
    fn ws_scheme_numeric_routes_to_the_locator_dial() {
        // A `ws/NUMERIC` locator routes to dial_locator (where the WS backend
        // is feature-decided); the dial seam never special-cases it.
        assert_eq!(
            plan_dial("ws/127.0.0.1:7447"),
            Ok(DialPlan::Locator(
                parse_any_locator("ws/127.0.0.1:7447").unwrap()
            ))
        );
    }

    #[test]
    fn datagram_scheme_dns_host_is_not_silently_resolved() {
        // Only `tcp` gets the std-resolver convenience: `udp`/`ws`/`tls` keep
        // the numeric-only contract, so a DNS host surfaces the parse error
        // rather than a guessed dial.
        assert!(matches!(
            plan_dial("udp/example.org:7447"),
            Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(_)))
        ));
        assert!(matches!(
            plan_dial("ws/example.org:7447"),
            Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(_)))
        ));
    }

    #[test]
    fn unknown_scheme_is_an_error() {
        assert!(matches!(
            plan_dial("quic/1.2.3.4:7447"),
            Err(AnyLocatorError::Ip(LocatorParseError::UnknownProto(_)))
        ));
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
}
