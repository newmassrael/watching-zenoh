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
use std::sync::atomic::AtomicBool;
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
// R311y219 (transport-multilink) — `Priority` (unconditional) types the per-face
// QoS-priority `band` the `_with_multilink` entrypoints apply via
// `set_link_priority_range`; imported gated so a non-multilink build keeps the use
// set unchanged.
#[cfg(feature = "transport-multilink")]
use wz_session_core::qos::Priority;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

use crate::link_pipeline::{
    accept_tcp_on, bind_tcp, bind_tcp_host, dial_tcp, dial_tcp_host,
    wire_tcp_stream_with_lowlatency, TcpReadDriver,
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
use crate::tls_pipeline::{accept_tls, dial_tls, wire_tls_stream, TlsReadDriver};
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::rustls::pki_types::ServerName;
// R311xk — the rustls `ClientConfig` is shared by `TlsDialConfig` and
// `QuicDialConfig`, so it is imported for EITHER backend (one import, no
// duplicate when both are on).
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
use tokio_rustls::rustls::ClientConfig;
// The acceptor's server cert config, carried by `AcceptConfig::tls` and stored in
// `BoundListener::Tls` — the accept-side mirror of the dialer's `ClientConfig`.
#[cfg(feature = "transport-link-tls")]
use tokio_rustls::rustls::ServerConfig;
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
use crate::ws_pipeline::{accept_ws, dial_ws, wire_ws_stream, WsReadDriver};
#[cfg(feature = "transport-link-ws")]
use tokio_tungstenite::WebSocketStream;

// R311xi — the unixsock arm, like serial/tls, rides this tcp+unicast-gated
// module as an additive STREAM transport (transport-link-unixsock forwards
// transport-link-tcp, so this module is always compiled when unixsock is). A
// connected `UnixStream` reuses the same `stream_link` split as TCP via
// `wire_unixsock_stream`; UNLIKE tls (no cert config), a `unixsock-stream/...`
// locator dials directly through `dial_locator`, like `ws`/`udp`.
#[cfg(feature = "transport-link-unixsock")]
use crate::unixsock_pipeline::{
    accept_unixsock_on, bind_unixsock, dial_unixsock, wire_unixsock_stream, UnixsockReadDriver,
};
#[cfg(feature = "transport-link-unixsock")]
use tokio::net::{UnixListener, UnixStream};

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
/// R311y253 — `#[non_exhaustive]` + `with_*` builders, the same shape every
/// other options struct in this crate already uses (`QueryOptions`,
/// `PublishOptions`, `QueryableOptions`: "construct via `default` plus optional
/// `with_*` setters — never struct-literal externally"). `DialConfig` was the
/// lone exception, and the exception was a latent build break: BOTH its fields
/// are `#[cfg]`-gated, so an exhaustive struct literal only compiles for the one
/// feature combination its author happened to build with. Every literal in the
/// tree named exactly one field, so each was missing the other's — the tls-side
/// ones broke the moment `transport-link-quic` was on, and the quic-side ones
/// the moment `transport-link-tls` was. They compiled only because the curated CI
/// lanes enable tls XOR quic, never both; `--all-features` failed 6 test targets
/// with E0063. `#[non_exhaustive]` makes that fragile form UNREPRESENTABLE for
/// out-of-crate callers (integration tests under `tests/` are separate crates),
/// so a future third cfg-gated transport field cannot silently break them either.
#[derive(Default)]
#[non_exhaustive]
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

impl DialConfig {
    /// Supply the TLS client material for a `tls/...` dial. Chain onto
    /// [`DialConfig::default`]; a config without this dials a `tls/...` locator
    /// to a typed `Unsupported`.
    ///
    /// Hard-gated on `transport-link-tls` (the setter's parameter type
    /// [`TlsDialConfig`] is itself gated, so the signature cannot exist without
    /// the feature). This is the same "wire-data setter disappears when off"
    /// shape `QueryOptions::with_attachment` / `with_source_info` use, rather
    /// than the ungated no-op shape reserved for setters whose parameter type is
    /// always available.
    #[cfg(feature = "transport-link-tls")]
    pub fn with_tls(mut self, tls: TlsDialConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Supply the QUIC client material for a `quic/...` dial (also used by the
    /// QUIC-datagram transport, which reuses the same cert threading). Mirror of
    /// [`Self::with_tls`], hard-gated on `transport-link-quic` for the same
    /// reason (its [`QuicDialConfig`] parameter type is gated).
    #[cfg(feature = "transport-link-quic")]
    pub fn with_quic(mut self, quic: QuicDialConfig) -> Self {
        self.quic = Some(quic);
        self
    }
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

#[cfg(feature = "transport-link-tls")]
impl TlsDialConfig {
    /// Build server-auth-only TLS client material from a root-CA PEM, verifying
    /// that the peer's presented server cert chains to that root AND its SAN
    /// matches `server_name` ([`ServerNameVerification::Verify`](crate::tls_config::ServerNameVerification)).
    /// The consumer convenience a `tls/...` --connect needs (the demo's
    /// `--tls-ca`): the connect ADDRESS (a numeric `tls/1.2.3.4:port`, all wz's
    /// locator parser accepts) and the VERIFIED NAME are decoupled — dial by IP,
    /// verify by name — because rustls takes the name as an explicit
    /// [`ServerName`], not from the socket address. So one self-signed
    /// `localhost` cert can be dialed at `tls/127.0.0.1:port` and still verify,
    /// with no IP SAN required on the cert. For a self-signed leaf the cert IS
    /// its own root, so the same PEM serves as `root_ca_pem`.
    pub fn from_ca_pem(root_ca_pem: &[u8], server_name: &str) -> io::Result<Self> {
        let client_config = crate::tls_config::client_config_from_pem(
            root_ca_pem,
            None,
            crate::tls_config::ServerNameVerification::Verify,
        )?;
        let server_name = ServerName::try_from(server_name.to_owned()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TLS server name {server_name:?}: {e}"),
            )
        })?;
        Ok(Self {
            client_config,
            server_name,
        })
    }
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

#[cfg(feature = "transport-link-quic")]
impl QuicDialConfig {
    /// Build server-auth-only QUIC client material from a root-CA PEM — the QUIC
    /// sibling of [`TlsDialConfig::from_ca_pem`]. The rustls config is TLS-1.3 +
    /// ALPN `hq-29` ([`quic_client_config_from_pem`](crate::quic_config::quic_client_config_from_pem)),
    /// verifying the peer's server cert chains to `root_ca_pem` AND its SAN
    /// matches `server_name`. Like the TLS sibling, the connect ADDRESS (a numeric
    /// `quic/1.2.3.4:port`, all wz's locator parser accepts) and the VERIFIED NAME
    /// are decoupled — dial by IP, verify by name — because quinn takes the SNI as
    /// an explicit `&str`, not from the socket address. So one self-signed
    /// `localhost` cert can be dialed at `quic/127.0.0.1:port` and still verify,
    /// with no IP SAN required; the self-signed leaf IS its own root, so the same
    /// PEM serves as `root_ca_pem`.
    pub fn from_ca_pem(root_ca_pem: &[u8], server_name: &str) -> io::Result<Self> {
        let client_config = crate::quic_config::quic_client_config_from_pem(root_ca_pem, None)?;
        Ok(Self {
            client_config,
            server_name: server_name.to_owned(),
        })
    }
}

/// The ACCEPT-side config, mirror of [`DialConfig`]: the per-scheme server
/// material [`bind_locator`] / [`accept_endpoint`] consume to bind a listener
/// whose accept path needs more than the addr. Today only `tls` (the acceptor's
/// server cert); its dial twin is [`DialConfig::tls`]. `Default` (all `None`) is
/// the tcp/ws path (no cert), which is why the tcp-only multi-peer `bind_endpoint`
/// passes `AcceptConfig::default()`. R311y375.
#[derive(Default)]
#[non_exhaustive]
pub struct AcceptConfig {
    /// TLS server material for a `tls/...` acceptor. `None` (the default) => a
    /// `tls/...` listen binds to a typed `Unsupported` (no cert to present), so a
    /// TLS acceptor is opt-in by supplying this — the accept mirror of
    /// [`DialConfig::tls`] being opt-in for a dial.
    #[cfg(feature = "transport-link-tls")]
    pub tls: Option<TlsAcceptConfig>,
}

impl AcceptConfig {
    /// Supply the TLS server material for a `tls/...` acceptor. Chain onto
    /// [`AcceptConfig::default`]; a config without this binds a `tls/...` listen
    /// to a typed `Unsupported`. Hard-gated on `transport-link-tls` (its
    /// [`TlsAcceptConfig`] parameter type is gated), the accept mirror of
    /// [`DialConfig::with_tls`].
    #[cfg(feature = "transport-link-tls")]
    pub fn with_tls(mut self, tls: TlsAcceptConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

/// The TLS material a `tls/...` ACCEPTOR needs beyond the locator's addr: the
/// rustls [`ServerConfig`] (the cert chain + key it PRESENTS, optional client
/// auth). The accept-side mirror of [`TlsDialConfig`] — where the dialer carries
/// a `ClientConfig` + the name it verifies, the acceptor carries the
/// `ServerConfig` it presents. Mirrors the listen side of pico's TLS config keys
/// (`LISTEN_CERTIFICATE` / `LISTEN_PRIVATE_KEY`, `tls.c`).
#[cfg(feature = "transport-link-tls")]
pub struct TlsAcceptConfig {
    pub server_config: Arc<ServerConfig>,
}

#[cfg(feature = "transport-link-tls")]
impl TlsAcceptConfig {
    /// Build one-way-TLS server material from the acceptor's cert-chain + private
    /// key PEM (the demo's `--tls-cert` / `--tls-key`) — the acceptor convenience
    /// symmetric to [`TlsDialConfig::from_ca_pem`]. One-way TLS (no client auth,
    /// `client_ca_pem = None`): the acceptor presents its cert; the dialer
    /// verifies it against a CA (its `--tls-ca`), but the acceptor does not
    /// authenticate the dialer. mTLS is the `server_config_from_pem` client-CA arm
    /// when a verified caller needs it.
    pub fn from_cert_key_pem(cert_chain_pem: &[u8], private_key_pem: &[u8]) -> io::Result<Self> {
        Ok(Self {
            server_config: crate::tls_config::server_config_from_pem(
                cert_chain_pem,
                private_key_pem,
                None,
            )?,
        })
    }
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

/// A bound listening socket, keyed by transport scheme — the ACCEPT-side mirror
/// of [`DialedLink`]. [`bind_locator`] produces one per `--listen` scheme; the
/// consuming [`accept_bound`] dispatches on the variant to accept ONE peer and
/// run that scheme's post-accept handshake, yielding the SAME [`DialedLink`] the
/// dial side produces — so the downstream `wire_*` split is shared, dialed or
/// accepted. Adding a transport is one arm HERE + one in [`bind_locator`] + one
/// in [`accept_bound`], the symmetric counterpart of adding a `dial_locator` arm
/// plus a [`DialedLink`] variant (R311y375 — the accept side made symmetric to
/// the dial side, retiring the per-scheme `bind_locator`-returns-`TcpListener`
/// special-casing).
pub enum BoundListener {
    /// A bound TCP listener; [`accept_bound`] accepts a raw [`DialedLink::Tcp`].
    Tcp(TcpListener),
    /// A bound TCP listener whose accepted stream gets the RFC6455 SERVER upgrade
    /// ([`accept_ws`]) — ws LISTENS on plain TCP, so the listener type is the same
    /// as [`Self::Tcp`]; only the post-accept handshake differs. The acceptor
    /// mirror of `dial_locator`'s `Proto::Ws => dial_ws` (client upgrade).
    #[cfg(feature = "transport-link-ws")]
    Ws(TcpListener),
    /// A bound TCP listener whose accepted stream gets the rustls SERVER
    /// handshake ([`accept_tls`]) using the carried [`ServerConfig`] — tls, like
    /// ws, LISTENS on plain TCP; only the post-accept handshake differs. The
    /// acceptor mirror of `dial_locator`'s `Proto::Tls => dial_tls` (client
    /// handshake). The `Arc<ServerConfig>` (the cert it presents) is taken from
    /// [`AcceptConfig::tls`] at bind time and carried until the accept runs it.
    #[cfg(feature = "transport-link-tls")]
    Tls(TcpListener, Arc<ServerConfig>),
    /// A bound unix-domain [`UnixListener`]; [`accept_bound`] accepts a raw
    /// [`DialedLink::Unixsock`] with NO post-accept handshake (a `UnixStream` is
    /// wrapped directly, like `tcp`). The FIRST non-`TcpListener` variant
    /// (R311y378, accept-symmetry Stage 4) — the accept-side mirror of
    /// `dial_locator`'s `AnyLocator::Unixsock => DialedLink::Unixsock`, and the
    /// reason [`Self::accept_raw`] yields an [`AcceptedPeer`] (a unix accept has
    /// no IP peer) and [`Self::local_addr`] returns a typed error for it.
    #[cfg(feature = "transport-link-unixsock")]
    Unixsock(UnixListener),
}

/// The peer of a link accepted by [`BoundListener::accept_raw`] — an IP
/// [`SocketAddr`](std::net::SocketAddr) for the stream family (tcp/ws/tls, all
/// `TcpListener`-backed), or a non-IP marker for a unix/vsock family listener
/// whose accepted peer is anonymous (a unix `accept` yields an unnamed peer;
/// zenoh assigns it a fresh UUID, `unixsock_pipeline::accept_unixsock_on`). This
/// is the "revisit the peer type" [`BoundListener::accept_raw`]'s doc
/// anticipated for the first non-IP variant (R311y378).
///
/// [`Display`](std::fmt::Display) renders the "accepted peer {..}" log line the
/// one-shot [`accept_bound`] writes. The multi-peer
/// [`accept_loop`](crate::accept_loop) keys mesh faces on the IP `SocketAddr`
/// (`Face.peer`, zid-dedup, gossip locators), so a [`Self::NonIp`] peer has no
/// routable locator and is one-shot-accept-only until the mesh graph
/// generalizes — the loop rejects it with a typed `Unsupported` rather than
/// holding an unroutable face.
pub enum AcceptedPeer {
    /// The IP address of an accepted stream-family peer (tcp/ws/tls).
    Ip(std::net::SocketAddr),
    /// A non-IP transport peer (unixsock; later vsock/unixpipe) — anonymous, so
    /// the payload is the transport name for the log line, not an address.
    NonIp(&'static str),
}

impl std::fmt::Display for AcceptedPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptedPeer::Ip(addr) => write!(f, "{addr}"),
            AcceptedPeer::NonIp(name) => write!(f, "<anonymous {name} peer>"),
        }
    }
}

impl BoundListener {
    /// The transport name of the bound listener (`"tcp"` / `"ws"`) — the
    /// variant→name SSOT, the accept-side mirror of [`DialedLink::transport_name`],
    /// so a caller logs WHICH transport it is listening on without re-matching
    /// the feature-gated arms.
    pub fn transport_name(&self) -> &'static str {
        match self {
            BoundListener::Tcp(_) => "tcp",
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(_) => "ws",
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(..) => "tls",
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(_) => "unixsock",
        }
    }

    /// Log the "listening on {addr} ({transport})" line — observable before any
    /// peer connects (the race-free bind/accept split [`bind_tcp`] established).
    /// Composes [`Self::local_addr_display`] (the per-variant address) with
    /// [`Self::transport_name`], so the address-formatting SSOT lives in one place.
    fn log_listening(&self) -> io::Result<()> {
        log::info!(
            "wz accept: listening on {} ({})",
            self.local_addr_display()?,
            self.transport_name()
        );
        Ok(())
    }

    /// The bound local address rendered as a `String` — the per-variant address
    /// the runner's `--router` / `--peer` / `--router-hat` bind paths log (the
    /// cross-impl e2e greps `peer: listening on 127.0.0.1:`) and the address half
    /// of [`Self::log_listening`]. Returns a `String`, NOT a `SocketAddr`: each
    /// transport formats its OWN address type (the IP `SocketAddr` for the stream
    /// family tcp/ws/tls; a unix path / vsock CID for a future non-IP variant),
    /// rather than a uniform IP-typed accessor the non-IP transports could not
    /// satisfy — the accept-side counterpart of why the dial mirror [`DialedLink`]
    /// exposes only [`DialedLink::transport_name`], no uniform `local_addr`
    /// (R311y374). Total over the stream family; a future non-IP variant formats
    /// its own address here.
    pub fn local_addr_display(&self) -> io::Result<String> {
        Ok(match self {
            BoundListener::Tcp(l) => l.local_addr()?.to_string(),
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(l) => l.local_addr()?.to_string(),
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(l, _) => l.local_addr()?.to_string(),
            // A unix listener has no IP address; render the bound socket PATH
            // (the non-IP address type this per-variant String accessor exists
            // for, R311y374). An abstract/unnamed socket has no pathname.
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(l) => l
                .local_addr()?
                .as_pathname()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unnamed unix socket>".to_string()),
        })
    }

    /// The bound local address as a `SocketAddr` — for the stream-family callers
    /// that need the STRUCTURED address, not just its display: the demo's `--peer`
    /// and `--router-hat` bind paths derive the node zid from `.port()` and gate
    /// self-locator advertisement on `.ip().is_unspecified()`, neither of which a
    /// `String` ([`Self::local_addr_display`]) can serve. Fully-qualified
    /// `std::net::SocketAddr` in the signature because the bare import is
    /// `transport-link-udp`-gated here (this ungated accessor must compile no-udp).
    /// Total over the stream family (tcp/ws/tls, all `TcpListener`-backed); a
    /// future non-IP variant (unix path / vsock CID) has no `SocketAddr`, so such a
    /// caller must use [`Self::local_addr_display`] (the per-variant, non-IP-safe
    /// display) — this accessor is the one that will need a typed error there
    /// (R311y374, the reason `log_listening` formats a per-variant String).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            BoundListener::Tcp(l) => l.local_addr(),
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(l) => l.local_addr(),
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(l, _) => l.local_addr(),
            // A unix listener has no IP `SocketAddr` (R311y374 anticipated this
            // typed error for the first non-IP variant); an IP-address caller
            // (the demo's `--peer` / `--router-hat` zid-from-port derivation)
            // never binds unixsock, and a non-IP caller uses `local_addr_display`.
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unixsock listener has no IP SocketAddr; use local_addr_display",
            )),
        }
    }

    /// Accept ONE raw transport connection from a *borrowed* listener WITHOUT the
    /// per-scheme SERVER handshake — the non-blocking accept the multi-peer
    /// [`accept_loop`](crate::accept_loop) runs in its `select!` arm. The ws/tls
    /// SERVER handshake is (potentially) slow and peer-controlled, so it is
    /// DEFERRED into the spawned per-face open future ([`AcceptedLink::handshake`])
    /// rather than run here: a stalled handshake never blocks the loop from
    /// accepting the next peer (the "one peer's handshake never blocks another"
    /// invariant the loop doc states). The stream family (tcp/ws/tls) all accept
    /// from the same [`TcpListener`] — only the deferred handshake differs — so the
    /// returned [`AcceptedLink`] carries WHICH handshake to run. The borrowed,
    /// multi-accept counterpart of the consuming one-shot [`accept_bound`] (which
    /// handshakes inline for the one-shot session-open contract).
    ///
    /// The peer is an [`AcceptedPeer`] (R311y378), not a bare
    /// `std::net::SocketAddr`: the stream family (tcp/ws/tls) accepts from a
    /// `TcpListener` so its peer is an IP `SocketAddr` ([`AcceptedPeer::Ip`]),
    /// but the unix family has no IP peer ([`AcceptedPeer::NonIp`]) — the
    /// "future non-IP variant will revisit the peer type" this doc anticipated.
    /// [`Display`](std::fmt::Display) on [`AcceptedPeer`] renders the log line
    /// uniformly across both.
    pub async fn accept_raw(&self) -> io::Result<(AcceptedLink, AcceptedPeer)> {
        Ok(match self {
            BoundListener::Tcp(l) => {
                let (stream, peer) = accept_tcp_on(l).await?;
                (AcceptedLink::Tcp(stream), AcceptedPeer::Ip(peer))
            }
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(l) => {
                let (stream, peer) = accept_tcp_on(l).await?;
                (AcceptedLink::Ws(stream), AcceptedPeer::Ip(peer))
            }
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(l, server_config) => {
                let (stream, peer) = accept_tcp_on(l).await?;
                (
                    AcceptedLink::Tls(stream, server_config.clone()),
                    AcceptedPeer::Ip(peer),
                )
            }
            // R311y378 — the first non-IP accept: a unix `accept` yields a
            // `UnixStream` with an anonymous peer (discarded by
            // `accept_unixsock_on`), wrapped DIRECTLY (no post-accept handshake,
            // like `tcp`). The peer is `NonIp("unixsock")`.
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(l) => {
                let stream = accept_unixsock_on(l).await?;
                (
                    AcceptedLink::Unixsock(stream),
                    AcceptedPeer::NonIp("unixsock"),
                )
            }
        })
    }

    /// Extract the raw [`TcpListener`] for the TCP-only multi-peer paths — the
    /// concurrent [`accept_loop`](crate::accept_loop) and its [`bind_endpoint`]
    /// callers, which do not yet hold non-tcp faces. A non-tcp variant returns a
    /// typed `Unsupported`, the same shape a router/peer `--listen` surfaced
    /// before (their accept side was always tcp-only). Generalizing `accept_loop`
    /// to accept every [`BoundListener`] variant retires this accessor.
    pub fn into_tcp(self) -> io::Result<TcpListener> {
        match self {
            BoundListener::Tcp(l) => Ok(l),
            #[cfg(any(
                feature = "transport-link-ws",
                feature = "transport-link-tls",
                feature = "transport-link-unixsock"
            ))]
            other => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "the multi-peer accept loop is wired only for tcp; a {} listener needs \
                     the generalized accept_loop",
                    other.transport_name()
                ),
            )),
        }
    }
}

/// A raw transport connection accepted from a [`BoundListener`], carrying the
/// deferred per-scheme SERVER handshake — the in-flight state between
/// [`BoundListener::accept_raw`] (the fast, non-blocking accept the multi-peer
/// [`accept_loop`](crate::accept_loop) runs in its `select!` arm) and
/// [`Self::handshake`] (the ws/tls SERVER handshake, deferred to the spawned
/// per-face open future so a slow/stalled handshake never blocks the accept
/// loop). [`Self::handshake`] completes it into the SAME [`DialedLink`] the
/// consuming one-shot [`accept_bound`] yields inline — the split exists ONLY so
/// the loop can move the (potentially slow, peer-controlled) handshake off its
/// accept path. The accept-side counterpart of [`DialedLink`] mid-flight; the
/// stream family only (tcp/ws/tls all accept from a [`TcpListener`]).
pub enum AcceptedLink {
    /// A raw accepted TCP stream — no post-accept handshake; [`Self::handshake`]
    /// wraps it directly as [`DialedLink::Tcp`].
    Tcp(TcpStream),
    /// A raw accepted TCP stream awaiting the RFC6455 SERVER upgrade
    /// ([`accept_ws`]); [`Self::handshake`] runs it into [`DialedLink::Ws`].
    #[cfg(feature = "transport-link-ws")]
    Ws(TcpStream),
    /// A raw accepted TCP stream awaiting the rustls SERVER handshake
    /// ([`accept_tls`]) with the cert carried since bind; [`Self::handshake`] runs
    /// it into [`DialedLink::Tls`].
    #[cfg(feature = "transport-link-tls")]
    Tls(TcpStream, Arc<ServerConfig>),
    /// A raw accepted unix-domain stream — NO post-accept handshake (like
    /// [`Self::Tcp`]); [`Self::handshake`] wraps it directly as
    /// [`DialedLink::Unixsock`] (R311y378).
    #[cfg(feature = "transport-link-unixsock")]
    Unixsock(UnixStream),
}

impl AcceptedLink {
    /// Run the deferred per-scheme SERVER handshake, yielding the SAME
    /// [`DialedLink`] the dial side produces (so the downstream `wire_*` split is
    /// shared, dialed or accepted) — the acceptor twin of [`dial_locator`]'s
    /// per-scheme client handshake, and the mechanism SSOT the consuming one-shot
    /// [`accept_bound`] also drives. Runs in the spawned per-face open future (not
    /// the accept loop's `select!` arm), so a slow ws/tls handshake never stalls
    /// accepting the next peer.
    pub async fn handshake(self) -> io::Result<DialedLink> {
        Ok(match self {
            AcceptedLink::Tcp(stream) => DialedLink::Tcp(stream),
            #[cfg(feature = "transport-link-ws")]
            AcceptedLink::Ws(stream) => DialedLink::Ws(Box::new(accept_ws(stream).await?)),
            #[cfg(feature = "transport-link-tls")]
            AcceptedLink::Tls(stream, server_config) => {
                DialedLink::Tls(Box::new(accept_tls(stream, server_config).await?))
            }
            // No post-accept handshake — a `UnixStream` is wrapped directly, the
            // acceptor mirror of `dial_locator`'s direct `DialedLink::Unixsock`
            // (R311y378).
            #[cfg(feature = "transport-link-unixsock")]
            AcceptedLink::Unixsock(stream) => DialedLink::Unixsock(stream),
        })
    }

    /// The one-shot [`accept_bound`]'s "accepted peer {peer}{note}" log suffix —
    /// `""` for tcp, `"; ws server upgrade"` / `"; tls server handshake"` for the
    /// handshaking schemes (the completion-witness wording R311y375 obs#1 pinned,
    /// logged AFTER [`Self::handshake`] succeeds). A variant->note SSOT so the
    /// one-shot log stays byte-exact after delegating its accept+handshake
    /// mechanics to [`Self::handshake`].
    fn server_handshake_note(&self) -> &'static str {
        match self {
            AcceptedLink::Tcp(_) => "",
            #[cfg(feature = "transport-link-ws")]
            AcceptedLink::Ws(_) => "; ws server upgrade",
            #[cfg(feature = "transport-link-tls")]
            AcceptedLink::Tls(..) => "; tls server handshake",
            // Direct wrap, no server handshake (like tcp) — no completion note.
            #[cfg(feature = "transport-link-unixsock")]
            AcceptedLink::Unixsock(_) => "",
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
            Proto::Tcp => Ok(DialedLink::Tcp(
                dial_tcp(ip.addr, ip.iface.as_deref()).await?,
            )),
            #[cfg(feature = "transport-link-udp")]
            Proto::Udp => Ok(DialedLink::Udp {
                socket: dial_udp(ip.addr, ip.iface.as_deref()).await?,
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
                    dial_tls(
                        ip.addr,
                        t.client_config.clone(),
                        t.server_name.clone(),
                        ip.iface.as_deref(),
                    )
                    .await?,
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
            Proto::Ws => Ok(DialedLink::Ws(Box::new(
                dial_ws(ip.addr, ip.iface.as_deref()).await?,
            ))),
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
                    dial_quic(
                        ip.addr,
                        q.client_config.clone(),
                        &q.server_name,
                        ip.iface.as_deref(),
                    )
                    .await?,
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
                    dial_quic_datagram(
                        ip.addr,
                        q.client_config.clone(),
                        &q.server_name,
                        ip.iface.as_deref(),
                    )
                    .await?,
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
        AnyLocator::Named {
            proto,
            host,
            port,
            iface,
        } => match proto {
            Proto::Tcp => Ok(DialedLink::Tcp(
                dial_tcp_host(&format!("{host}:{port}"), iface.as_deref()).await?,
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
pub async fn accept_locator(locator: AnyLocator, cfg: &AcceptConfig) -> io::Result<DialedLink> {
    // R311y375 — bind + accept dispatch uniformly on the scheme: `bind_locator`
    // produces the scheme's `BoundListener` (consuming `cfg`'s server cert where a
    // scheme needs it) and `accept_bound` accepts one peer + runs that scheme's
    // post-accept handshake (the ws RFC6455 upgrade, the tls handshake, etc.). No
    // per-scheme special-case here — the symmetric mirror of dial_locator.
    accept_bound(bind_locator(locator, cfg).await?).await
}

/// Bind a listening [`TcpListener`] for an [`AnyLocator`]'s scheme — the
/// bind-only half of [`accept_locator`], split out so the multi-peer
/// [`accept_loop`](crate::accept_loop) can hold the listener and loop accepts
/// over it (R311qa), while the one-shot [`accept_locator`] binds-then-accepts a
/// single peer. Returns a [`BoundListener`] keyed by scheme (the accept-side
/// mirror of `dial_locator`'s [`DialedLink`]): `tcp` / `ws` bind a `TcpListener`
/// (ws upgrades per-accept), and the remaining schemes return a feature-blind
/// typed `Unsupported` extension point until their [`BoundListener`] arm lands.
pub async fn bind_locator(locator: AnyLocator, cfg: &AcceptConfig) -> io::Result<BoundListener> {
    fn unsupported(detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("listen/accept is wired only for tcp; {detail}"),
        )
    }
    // `cfg` is consumed only by the tls arm (its server cert); inert on a build
    // without the tls backend (mirrors dial_locator's DialConfig usage).
    #[cfg(not(feature = "transport-link-tls"))]
    let _ = cfg;
    match locator {
        AnyLocator::Ip(ip) => match ip.proto {
            Proto::Tcp => Ok(BoundListener::Tcp(
                bind_tcp(ip.addr, ip.iface.as_deref()).await?,
            )),
            // R311y374 — a `ws/...` acceptor LISTENS on plain TCP; the RFC6455
            // server upgrade happens per-accept in `accept_bound` (`accept_ws`
            // over the accepted stream), so the bind is the SAME `bind_tcp` the
            // `tcp` arm uses — only the `BoundListener` variant differs. With the
            // backend off, `Ws` falls to the catch-all `Unsupported` below.
            #[cfg(feature = "transport-link-ws")]
            Proto::Ws => Ok(BoundListener::Ws(
                bind_tcp(ip.addr, ip.iface.as_deref()).await?,
            )),
            // R311y375 — a `tls/...` acceptor also LISTENS on plain TCP; the rustls
            // SERVER handshake runs per-accept in `accept_bound`, using the
            // `ServerConfig` supplied here from `AcceptConfig.tls`. Absent the cert
            // config => typed `Unsupported`, so a TLS acceptor is opt-in — the
            // accept mirror of dial_locator's `Proto::Tls => match &cfg.tls`.
            #[cfg(feature = "transport-link-tls")]
            Proto::Tls => match &cfg.tls {
                Some(t) => Ok(BoundListener::Tls(
                    bind_tcp(ip.addr, ip.iface.as_deref()).await?,
                    t.server_config.clone(),
                )),
                None => Err(unsupported(
                    "tls acceptor requires AcceptConfig.tls (a server cert + key)",
                )),
            },
            other => Err(unsupported(&format!(
                "{other:?} acceptor is a not-yet-wired extension point"
            ))),
        },
        AnyLocator::Named {
            proto,
            host,
            port,
            iface,
        } => match proto {
            Proto::Tcp => Ok(BoundListener::Tcp(
                bind_tcp_host(&format!("{host}:{port}"), iface.as_deref()).await?,
            )),
            // A `ws/...` NAME acceptor: bind the resolved TCP host (the RFC6455
            // upgrade is per-accept, as in the numeric arm). Non-ws non-tcp names
            // stay unwired (acceptor + non-tcp name resolution both).
            #[cfg(feature = "transport-link-ws")]
            Proto::Ws => Ok(BoundListener::Ws(
                bind_tcp_host(&format!("{host}:{port}"), iface.as_deref()).await?,
            )),
            // A `tls/...` NAME acceptor: bind the resolved TCP host + carry the
            // server cert (the handshake is per-accept, as in the numeric arm).
            #[cfg(feature = "transport-link-tls")]
            Proto::Tls => match &cfg.tls {
                Some(t) => Ok(BoundListener::Tls(
                    bind_tcp_host(&format!("{host}:{port}"), iface.as_deref()).await?,
                    t.server_config.clone(),
                )),
                None => Err(unsupported(
                    "tls acceptor requires AcceptConfig.tls (a server cert + key)",
                )),
            },
            // A non-tcp NAME is unwired for two reasons (acceptor + non-tcp
            // name resolution), kept distinct from the numeric arm's message.
            other => Err(unsupported(&format!(
                "{other:?} acceptor and non-tcp name resolution are both unwired"
            ))),
        },
        AnyLocator::Serial(_) => Err(unsupported(
            "serial accept is a tty open (accept_serial), not a listen bind; unwired",
        )),
        // R311y378 (accept-symmetry Stage 4) — a unixsock acceptor binds a
        // `UnixListener` (`bind_unixsock`) into `BoundListener::Unixsock`, the
        // accept-side mirror of `dial_locator`'s `AnyLocator::Unixsock =>
        // DialedLink::Unixsock`. `AnyLocator::Unixsock` is an always-present
        // variant (ungated in wz-session-core), so the arm exists in BOTH
        // feature configs: backend-on binds; backend-off is a typed
        // `Unsupported` (no cross-crate gate skew — the variant's gate and this
        // arm's gate cannot disagree), exactly as the dial arm does.
        #[cfg(feature = "transport-link-unixsock")]
        AnyLocator::Unixsock(ep) => Ok(BoundListener::Unixsock(bind_unixsock(&ep.path).await?)),
        #[cfg(not(feature = "transport-link-unixsock"))]
        AnyLocator::Unixsock(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unixsock accept requires the transport-link-unixsock feature",
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

/// Log the bound address, accept one peer, run its scheme's SERVER handshake,
/// log it — the accept-side counterpart to the Initiator's "connected to .. over
/// .." line, and the ONE-SHOT (consuming) twin of the multi-accept
/// [`BoundListener::accept_raw`] + [`AcceptedLink::handshake`]. Delegates its
/// accept + per-scheme handshake mechanics to those two (the mechanism SSOT), so
/// adding a transport touches only [`AcceptedLink`], not here. The "wz accept:"
/// prefix tags the demo's logs; the e2e harness owns a binary-name-tagged copy of
/// this shape. The "; ws server upgrade" / "; tls server handshake" completion
/// note is logged AFTER the handshake succeeds (R311y375 obs#1) — a failed ws/tls
/// handshake returns the error here and never logs a spurious "accepted peer".
async fn accept_bound(listener: BoundListener) -> io::Result<DialedLink> {
    listener.log_listening()?;
    let (accepted, peer) = listener.accept_raw().await?;
    // The completion-witness note (R311y375 obs#1): read from the scheme BEFORE
    // the handshake consumes `accepted`, but LOGGED only after the handshake
    // SUCCEEDS below.
    let note = accepted.server_handshake_note();
    let link = accepted.handshake().await?;
    log::info!("wz accept: accepted peer {peer}{note}");
    Ok(link)
}

/// Accept ONE peer from a *borrowed* [`TcpListener`], wrapping it as a
/// [`DialedLink::Tcp`] — the multi-accept counterpart of [`accept_bound`] (which
/// CONSUMES the listener for the one-shot session-open contract). Borrowing keeps
/// the listener bound across accepts, so a host that serves N SEQUENTIAL clients
/// binds once via [`bind_endpoint`] then loops this + [`accept_and_open_session`],
/// opening and driving ONE session at a time (the caller's loop owns the
/// re-accept). This is the bind-once/accept-many seam at the session-open layer
/// that the [`crate::accept_loop`] docstring references — distinct from the full
/// [`accept_loop`](crate::accept_loop), which holds N CONCURRENT faces: this seam
/// suits a per-client-Session host (e.g. the demo's `--storage-host` admin mode,
/// where a pico `z_put` then a pico `z_get` are separate one-shot connections a
/// single 1:1 unicast Session cannot both serve). Reuses the [`accept_tcp_on`]
/// SSOT (accept + per-link TCP tuning); logs the "accepted peer" line here, quiet
/// like [`accept_bound`]'s primitive siblings.
pub async fn accept_bound_on(listener: &TcpListener) -> io::Result<DialedLink> {
    let (stream, peer) = accept_tcp_on(listener).await?;
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
pub async fn accept_endpoint(listen: &str, cfg: &AcceptConfig) -> io::Result<DialedLink> {
    // R311y374/375 — route through `accept_locator` (not `accept_bound` directly)
    // so a `ws/...` or `tls/...` listen string gets the per-scheme handshake its
    // scheme requires: `accept_locator` binds (consuming `cfg`'s server cert where
    // needed) + accepts + applies the handshake, while the tcp path stays
    // byte-identical (it delegates to `accept_bound`). The `plan_endpoint`
    // classify + error-map is kept here (mirrors `bind_endpoint`'s wrapping) so a
    // malformed `--listen` still surfaces the endpoint-layer error. `cfg` is the
    // accept mirror of `dial_endpoint`'s `DialConfig`.
    let locator = plan_endpoint(listen).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz listen: malformed / unsupported --listen {listen:?}: {e:?}"),
        )
    })?;
    accept_locator(locator, cfg).await
}

/// Bind a `--listen`-style endpoint string to a scheme-keyed [`BoundListener`] —
/// the bind-only seam symmetric to [`accept_endpoint`], consumed by the multi-peer
/// [`accept_loop`](crate::accept_loop) (a router/peer binds once, then holds the
/// listener and loops accepts). [`plan_endpoint`] classifies the string exactly
/// as [`accept_endpoint`] does; [`bind_locator`] performs the bind.
///
/// R311y376 (Stage 3) — the multi-peer accept loop now accepts every
/// [`BoundListener`] variant, so this seam yields the [`BoundListener`] directly
/// (was: projected to a raw [`TcpListener`] via [`BoundListener::into_tcp`], the
/// tcp-only-loop restriction). A cert-free listen (`tcp` / `ws`) binds; a `tls`
/// listen surfaces `Unsupported` here because the default [`AcceptConfig`] carries
/// no server cert (threading a router cert config is a follow-up). The one-shot
/// tcp-only sequential seam (the storage-host `accept_bound_on(&TcpListener)`
/// caller) projects via [`BoundListener::into_tcp`] at its own call site.
pub async fn bind_endpoint(listen: &str) -> io::Result<BoundListener> {
    let locator = plan_endpoint(listen).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz listen: malformed / unsupported --listen {listen:?}: {e:?}"),
        )
    })?;
    // The router/peer bind carries no acceptor cert (a `tls/...` router listen
    // surfaces `Unsupported` until a cert config is threaded); pass the default.
    bind_locator(locator, &AcceptConfig::default()).await
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
    // Universal framing (u16 prefix). The lowlatency open helpers call
    // `wire_dialed_link_with_lowlatency` with a flag they flip at Established.
    wire_dialed_link_with_lowlatency(dialed, Arc::new(AtomicBool::new(false)))
}

/// transport-lowlatency — [`wire_dialed_link`] sharing a lowlatency-wire flag
/// with the TCP link's read + write framing (the only link the lowlatency
/// negotiation is wired for today). The flag stays false through the handshake
/// and for every non-TCP link, so those wires are byte-identical to before; the
/// lowlatency open helper flips it at Established, switching the TCP frame prefix
/// to the 4-byte u32 zenoh lowlatency form.
pub fn wire_dialed_link_with_lowlatency(
    dialed: DialedLink,
    lowlatency: Arc<AtomicBool>,
) -> (
    InboundLink,
    Arc<dyn BoxedLinkDriver + Send + Sync>,
    TokioJoinHandle<()>,
) {
    match dialed {
        DialedLink::Tcp(stream) => {
            let (inbound, outbound, handle) = wire_tcp_stream_with_lowlatency(stream, lowlatency);
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
    /// R311y376 — the accept-side transport (ws/tls) SERVER handshake failed
    /// before the session handshake (a rejected rustls client, a malformed
    /// RFC6455 upgrade). The accept-side twin of [`Self::Dial`]: where a dialed
    /// face surfaces a failed client handshake as `Dial`, an accepted non-tcp face
    /// in the multi-peer [`accept_loop`](crate::accept_loop) surfaces its failed
    /// SERVER handshake here (a `FaceFailed`, isolated — one peer's bad handshake
    /// never sinks the loop). Only the loop's deferred-handshake path
    /// ([`AcceptedLink::handshake`]) produces it; the one-shot [`accept_bound`]
    /// returns the raw `io::Error` instead.
    AcceptHandshake(io::Error),
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

/// transport-qos (R311y216) — [`connect_and_open_session`] that OFFERS the QoS
/// transport: dials the locator then opens with the QoS offer staged on the
/// session actions before the handshake drives. The InitSyn carries the `ext_qos`
/// unit ext (id 0x1); if the peer reflects it the established session negotiates
/// `is_qos` on and prioritized traffic rides per-priority conduits. Signature-
/// stable additive sibling of the bare connect (the
/// [`connect_and_open_session_with_lowlatency`] twin; qos and lowlatency are
/// runtime-exclusive, so a caller picks one).
#[cfg(feature = "transport-qos")]
pub async fn connect_and_open_session_with_qos(
    locator: AnyLocator,
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_qos(dialed, params, clock, max_iters, tick_interval_ms).await
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
#[allow(clippy::too_many_arguments)]
pub async fn initiate_and_open_session_with_multilink(
    connected: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    actions.install_multilink_dispatch(crate::multilink::open_multilink_dispatch());
    actions.set_link_reliability_pref(reliability_pref);
    // R311y218 — compose the QoS offer with multilink (orthogonal at the actions
    // layer; only qos<->lowlatency conflict, and this path stages no lowlatency).
    #[cfg(feature = "transport-qos")]
    if qos {
        actions.set_qos_offer(true);
    }
    #[cfg(not(feature = "transport-qos"))]
    let _ = qos;
    // R311y219 — pin this aggregated link to its deploy-assigned QoS-priority band
    // so `select_link` routes each priority conduit to one link (the priority tier
    // of zenoh's per-channel select). Applied ONLY under a negotiated QoS offer; the
    // band type + setter are `all(multilink,qos)`-gated, so the whole block elides
    // without `transport-qos` and `band` is consumed as a no-op (signature-stable).
    #[cfg(feature = "transport-qos")]
    if qos {
        actions.set_link_priority_range(Some(
            wz_session_core::session_actions::LinkPriorityRange::new(band.0, band.1),
        ));
    }
    #[cfg(not(feature = "transport-qos"))]
    let _ = band;
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
    let lowlatency_wire = Arc::new(AtomicBool::new(false));
    let (inbound, outbound, writer_handle) =
        wire_dialed_link_with_lowlatency(connected, lowlatency_wire.clone());
    let actions = new_session_actions(outbound, params, clock);
    actions.set_lowlatency_offer(true);
    let opened = initiator_open(
        inbound,
        actions,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await?;
    // At Established: if the peer mirrored the ext (`is_lowlatency()`), switch the
    // link wire to the 4-byte u32 lowlatency prefix for all post-Established
    // (data / keepalive) frames. The handshake above already went out u16.
    if opened.actions.is_lowlatency() {
        lowlatency_wire.store(true, std::sync::atomic::Ordering::Release);
    }
    Ok(opened)
}

/// transport-qos (R311y216) — [`initiate_and_open_session`] with the QoS
/// transport capability offered on the session actions before the handshake
/// drives, so the InitSyn carries the `ext_qos` unit ext (id 0x1). The initiator
/// side; the acceptor reflects via [`accept_and_open_session_with_qos`]. When the
/// peer also offers, the established session negotiates `is_qos` on (the symmetric
/// `&=` AND) and a non-DEFAULT priority rides its own per-priority SN conduit; a
/// DEFAULT / non-negotiated session stays byte-identical to a pre-QoS session. The
/// additive qos-on sibling of the bare open.
#[cfg(feature = "transport-qos")]
pub async fn initiate_and_open_session_with_qos(
    connected: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    // Fresh actions stage only qos, so the lowlatency-exclusivity guard cannot
    // fire — the bool return is always true here (bare-discarded, as with the
    // lowlatency twin).
    actions.set_qos_offer(true);
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
#[allow(clippy::too_many_arguments)]
pub async fn accept_and_open_session_with_multilink(
    accepted: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.install_multilink_dispatch(crate::multilink::accept_multilink_dispatch());
    actions.set_link_reliability_pref(reliability_pref);
    // R311y218 — reflect the QoS offer on the accept side iff the peer offered it
    // (the `&=` merge finalizes it); orthogonal to the multilink 0x4 negotiation.
    #[cfg(feature = "transport-qos")]
    if qos {
        actions.set_qos_offer(true);
    }
    #[cfg(not(feature = "transport-qos"))]
    let _ = qos;
    // R311y219 — pin this aggregated link to its deploy-assigned QoS-priority band
    // (see the initiate twin). Applied ONLY under a negotiated QoS offer; the block
    // elides without `transport-qos` and `band` is consumed as a no-op.
    #[cfg(feature = "transport-qos")]
    if qos {
        actions.set_link_priority_range(Some(
            wz_session_core::session_actions::LinkPriorityRange::new(band.0, band.1),
        ));
    }
    #[cfg(not(feature = "transport-qos"))]
    let _ = band;
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
    let lowlatency_wire = Arc::new(AtomicBool::new(false));
    let (inbound, outbound, writer_handle) =
        wire_dialed_link_with_lowlatency(accepted, lowlatency_wire.clone());
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions.set_lowlatency_offer(true);

    engine.process_event(E::InboundStart);
    let opened = drive_open_loop(
        inbound,
        actions,
        engine,
        writer_handle,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await?;
    // At Established: switch to the 4-byte u32 lowlatency wire iff the peer's
    // InitSyn offered the ext (`is_lowlatency()`); the handshake went out u16.
    if opened.actions.is_lowlatency() {
        lowlatency_wire.store(true, std::sync::atomic::Ordering::Release);
    }
    Ok(opened)
}

/// transport-qos (R311y216) — [`accept_and_open_session`] that OFFERS the QoS
/// transport on the accept side: the acceptor reflects the `ext_qos` unit ext in
/// its InitAck iff the peer's InitSyn offered it (the `&=` merge runs on the
/// inbound InitSyn before the InitAck is emitted), so the established session
/// negotiates `is_qos` on only when BOTH sides offered. The accept-side
/// counterpart of [`connect_and_open_session_with_qos`].
#[cfg(feature = "transport-qos")]
pub async fn accept_and_open_session_with_qos(
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    // Fresh actions stage only qos, so the lowlatency-exclusivity guard cannot
    // fire — the bool return is always true here (bare-discarded).
    actions.set_qos_offer(true);

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
                iface: None,
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
                iface: None,
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

    // ── accept-side contract: a udp/tls `--listen` is a typed `Unsupported`
    //    returned BEFORE any bind (no socket) — the same clean extension-point
    //    shape `dial_locator`'s not-yet-wired non-tcp arms carry. `ws` is EXCLUDED
    //    when `transport-link-ws` is on: R311y374 wired the ws acceptor, so a
    //    `ws/…` listen now BINDS + accepts (blocking) — proven by the
    //    `wz_ws_acceptor_zenohd_interop` e2e instead — and asserting "unsupported
    //    before any bind" would hang here. With the backend off, ws is still an
    //    unwired extension point and stays in the list. The TCP accept path is
    //    proven end-to-end by Layer E's ap_demo_round_trip (establish_link's
    //    Acceptor role delegates to accept_endpoint); a port-race-free unit cannot
    //    mirror it because the acceptor owns the bind, hiding the OS-chosen port a
    //    dialing test would need. As each remaining scheme's acceptor lands, drop
    //    it from this list the same feature-aware way.
    #[tokio::test]
    async fn non_tcp_listen_accept_is_unsupported_without_io() {
        // `mut` is used only on the ws-off arm (the push); silence unused_mut when
        // ws is on and the list is already complete.
        #[allow(unused_mut)]
        let mut unwired = vec!["udp/127.0.0.1:7447", "tls/127.0.0.1:7447"];
        #[cfg(not(feature = "transport-link-ws"))]
        unwired.push("ws/127.0.0.1:7447");
        for s in unwired {
            match accept_endpoint(s, &AcceptConfig::default()).await {
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
