// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
// R311y473 — the single dialable-locator scheme table `advertised_locator`
// delegates to (and the adminspace per-link emitter shares).
use wz_session_core::link::InterceptorLink;
#[cfg(feature = "transport-link-serial")]
use wz_session_core::locator::SerialEndpoint;
use wz_session_core::locator::{
    parse_any_locator, AnyLocator, AnyLocatorError, LocatorParseError, ParsedLocator, Proto,
};
#[cfg(feature = "scouting-static")]
use wz_session_core::scout_static::{resolve_static_config, StaticRole};
// R311y808 — the static dial arm's retry reuses the crate's ONE transcription of
// zenoh's `ConnectionRetryConf` rather than growing a second schedule.
#[cfg(feature = "scouting-static")]
use crate::retry_period::RetryPolicy;
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
// R311y435 — re-exported so a caller of the `*_with_offer` entrypoints imports
// the offer type from the same module as the function that consumes it.
pub use wz_session_core::transport_mode::{SessionOffer, TransportMode};

use crate::link_pipeline::{
    accept_tcp_on, bind_tcp, bind_tcp_host, dial_tcp, dial_tcp_host,
    wire_tcp_stream_with_lowlatency, TcpReadDriver,
};
// R311y601 — the DNS-name seam for the schemes whose backend primitives take a
// `SocketAddr` and so cannot resolve for themselves. Gated on exactly the union
// of the arms that call it: `tcp` resolves inside `dial_tcp_host` /
// `bind_tcp_host` and never reaches here, so a tcp-only build would find these
// unused (a `-D warnings` failure, not a harmless import).
#[cfg(any(
    feature = "transport-link-tls",
    feature = "transport-link-ws",
    feature = "transport-link-quic",
    feature = "transport-link-quic-datagram",
    feature = "transport-link-udp",
))]
use crate::link_pipeline::{first_reachable, resolve_locator_addrs};
use crate::runtime_impl::TokioTime;
use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use crate::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver, CloseReason,
    DriverLoopOutcome, SessionActionsBinding, SessionInitParams, SessionLinkActions,
};
use crate::writer_queue::WriterHandle;
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, TxFrame};

#[cfg(feature = "transport-link-udp")]
use crate::udp_pipeline::{
    bind_udp_demux, dial_udp, dial_udp_host, wire_udp_demuxed, wire_udp_socket, NewUdpFace,
    UdpAcceptedInputs, UdpDemux, UdpReadDriver,
};
#[cfg(feature = "transport-link-udp")]
use std::net::SocketAddr;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;

// R311nv — the serial arm rides this tcp+unicast-gated module as an
// additive transport (like the udp arm above): a serial session-open build
// also carries tcp, so the SERIAL pieces are guarded only by the
// transport-link-serial feature here.
#[cfg(feature = "transport-link-serial")]
use crate::serial_pipeline::{
    dial_serial, drive_serial_handshake, open_serial_device, wire_serial_stream, SerialReadDriver,
};
#[cfg(feature = "transport-link-serial")]
use tokio_serial::SerialStream;
#[cfg(feature = "transport-link-serial")]
use wz_session_core::serial_link::SerialRole;

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
// The acceptor's server cert config, carried by `AcceptConfig::{tls,quic}` and
// stored in `BoundListener::Tls` (quic bakes it into its `Endpoint` at bind) — the
// accept-side mirror of the dialer's `ClientConfig`. Shared type: QUIC's server
// crypto is also a rustls `ServerConfig` (built by `quic_server_config_from_pem`),
// though a SEPARATE instance (TLS-1.3 + ALPN hq-29, not interchangeable with tls).
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
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
use crate::quic_pipeline::{
    accept_quic_incoming, bind_quic, complete_quic_accept, dial_quic, wire_quic_stream, QuicLink,
    QuicReadDriver,
};
// The bound QUIC server endpoint `BoundListener::Quic` carries (R311y401) — quinn's
// `Endpoint` owns the baked-in server crypto config, so the accept variant needs no
// separate `Arc<ServerConfig>` alongside it (unlike `BoundListener::Tls`). The
// deferred accept (R311y404) also threads a quinn `Incoming` (a pending, not-yet-
// handshaked connection arrival) as the `AcceptedLink::Quic` in-flight state.
#[cfg(feature = "transport-link-quic")]
use quinn::{Endpoint, Incoming};

// R311y8 — the QUIC DATAGRAM arm, like udp/ws, rides this tcp+unicast-gated
// module as an additive DATAGRAM transport. Reuses `DialConfig.quic` (same
// cert as the stream backend); `transport-link-quic-datagram` implies
// `transport-link-quic`.
#[cfg(feature = "transport-link-quic-datagram")]
use crate::quic_datagram_pipeline::{
    bind_quic_datagram, complete_quic_datagram_accept, dial_quic_datagram, wire_quic_datagram,
    QuicDatagramLink, QuicDatagramReadDriver,
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
    accept_unixsock_on, bind_unixsock, dial_unixsock, wire_unixsock_stream, UnixsockListener,
    UnixsockReadDriver,
};
#[cfg(feature = "transport-link-unixsock")]
use tokio::net::UnixStream;

// R311xj — the vsock arm, like tls/unixsock, rides this tcp+unicast-gated
// module as an additive STREAM transport, but Linux-only (AF_VSOCK), so gated
// all(transport-link-vsock, target_os=linux). A connected `VsockStream` reuses
// the `stream_link` split via `tokio::io::split` (the TLS pattern);
// `dial_locator` builds it from a `vsock/<CID>:<PORT>` locator (no cert config,
// like ws/udp/unixsock).
#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
use crate::vsock_pipeline::{
    accept_vsock_on, bind_vsock, dial_vsock, wire_vsock_stream, VsockReadDriver,
};
#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
use tokio_vsock::{VsockListener, VsockStream};

// R311y10 / R311y392 — the unixpipe arm: a same-host named-FIFO-pair link,
// Linux-only (the tokio `read_write` open-rendezvous knob is target_os=linux). A
// connected `UnixpipeLink` (a FIFO read/write pair) reuses the shared
// `stream_link` StreamEnvelope drivers, like unixsock/vsock. R311y392 made the
// acceptor MULTI-CLIENT + zenoh-wire-compatible: `bind_unixpipe` returns a
// `UnixpipeAcceptor` (the spawned-task + channel handle, the udp demux twin) and
// `accept_raw` awaits its next completed link.
#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
use crate::unixpipe_pipeline::{
    bind_unixpipe, dial_unixpipe, wire_unixpipe_stream, UnixpipeAcceptor, UnixpipeLink,
    UnixpipeReadDriver,
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
        Self::from_pem(
            root_ca_pem,
            server_name,
            None,
            crate::tls_config::ServerNameVerification::Verify,
        )
    }

    /// [`Self::from_ca_pem`] with both of its policy choices opened up: the mTLS
    /// client cert the dialer PRESENTS, and whether the peer cert's SAN must
    /// match the dialed name.
    ///
    /// It exists because a C-ABI caller does not get to choose them — the
    /// zenoh-pico config keys do. `Z_CONFIG_TLS_ENABLE_MTLS_KEY` +
    /// `Z_CONFIG_TLS_CONNECT_{CERTIFICATE,PRIVATE_KEY}` select the client auth,
    /// and `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY` selects the name policy,
    /// with pico's own default being `false` (its `z_pub_tls.c` inserts the key
    /// unconditionally, `"true"` only under `-V`). A constructor that hard-coded
    /// [`ServerNameVerification::Verify`](crate::tls_config::ServerNameVerification::Verify)
    /// could therefore serve the wz demo and NOT the drop-in, since the stock
    /// example dials `tls/127.0.0.1:<port>` while its bundled cert names
    /// `localhost` — the exact case `AnyName` exists for.
    ///
    /// `server_name` is still required with `AnyName`: rustls sends it as SNI
    /// regardless of whether the response is name-checked.
    pub fn from_pem(
        root_ca_pem: &[u8],
        server_name: &str,
        client_auth: Option<crate::tls_config::ClientAuthPem<'_>>,
        name_verification: crate::tls_config::ServerNameVerification,
    ) -> io::Result<Self> {
        let client_config =
            crate::tls_config::client_config_from_pem(root_ca_pem, client_auth, name_verification)?;
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
/// whose accept path needs more than the addr: `tls` (R311y375) and `quic` (R311y401),
/// each the acceptor's server cert; their dial twins are [`DialConfig`]`.{tls,quic}`.
/// `Default` (all `None`) is the cert-free tcp/ws/udp path, which is why the
/// cert-free multi-peer `bind_endpoint` passes `AcceptConfig::default()` (a mesh
/// caller threading a cert uses `bind_endpoint_with_config`, R311y405).
#[derive(Default)]
#[non_exhaustive]
pub struct AcceptConfig {
    /// TLS server material for a `tls/...` acceptor. `None` (the default) => a
    /// `tls/...` listen binds to a typed `Unsupported` (no cert to present), so a
    /// TLS acceptor is opt-in by supplying this — the accept mirror of
    /// [`DialConfig::tls`] being opt-in for a dial.
    #[cfg(feature = "transport-link-tls")]
    pub tls: Option<TlsAcceptConfig>,
    /// QUIC server material for a `quic/...` acceptor. `None` (the default) => a
    /// `quic/...` listen binds to a typed `Unsupported` (no cert to present), so a
    /// QUIC acceptor is opt-in by supplying this — the QUIC twin of [`Self::tls`]
    /// (a SEPARATE config: QUIC pins TLS-1.3 + ALPN hq-29, not interchangeable with
    /// the TLS-over-TCP server config). R311y401.
    #[cfg(feature = "transport-link-quic")]
    pub quic: Option<QuicAcceptConfig>,
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

    /// Supply the QUIC server material for a `quic/...` acceptor. The QUIC twin of
    /// [`Self::with_tls`]; a config without this binds a `quic/...` listen to a
    /// typed `Unsupported`. Hard-gated on `transport-link-quic`.
    #[cfg(feature = "transport-link-quic")]
    pub fn with_quic(mut self, quic: QuicAcceptConfig) -> Self {
        self.quic = Some(quic);
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
        Self::from_pem(cert_chain_pem, private_key_pem, None)
    }

    /// [`Self::from_cert_key_pem`] with the client-auth arm opened up — the
    /// accept-side mirror of [`TlsDialConfig::from_pem`], and there for the same
    /// reason: `Z_CONFIG_TLS_ENABLE_MTLS_KEY` is a config value a C caller sets,
    /// not a policy the acceptor gets to fix. `Some(ca)` REQUIRES a client cert
    /// chaining to that bundle; `None` is one-way TLS.
    pub fn from_pem(
        cert_chain_pem: &[u8],
        private_key_pem: &[u8],
        client_ca_pem: Option<&[u8]>,
    ) -> io::Result<Self> {
        Ok(Self {
            server_config: crate::tls_config::server_config_from_pem(
                cert_chain_pem,
                private_key_pem,
                client_ca_pem,
            )?,
        })
    }
}

/// The QUIC material a `quic/...` ACCEPTOR needs beyond the locator's addr: the
/// rustls [`ServerConfig`] it presents (the cert chain + key, TLS-1.3 + ALPN
/// hq-29). The QUIC twin of [`TlsAcceptConfig`] — a SEPARATE `ServerConfig` because
/// QUIC's crypto config (ALPN hq-29 + a TLS-1.3 pin) is not interchangeable with the
/// TLS-over-TCP one, which is why the demo builds it from its own `--quic-cert` /
/// `--quic-key` flags. The cert MATERIAL itself is interchangeable — the interop test
/// presents the same self-signed `localhost` cert as the tls acceptor — only the
/// built `ServerConfig` differs. R311y401.
#[cfg(feature = "transport-link-quic")]
pub struct QuicAcceptConfig {
    pub server_config: Arc<ServerConfig>,
}

#[cfg(feature = "transport-link-quic")]
impl QuicAcceptConfig {
    /// Build one-way-QUIC server material from the acceptor's cert-chain + private
    /// key PEM (the demo's `--quic-cert` / `--quic-key`) — the QUIC twin of
    /// [`TlsAcceptConfig::from_cert_key_pem`]. One-way (no client auth,
    /// `client_ca_pem = None`): the acceptor presents its cert; the dialer verifies
    /// it against a CA (its `--quic-ca`), but the acceptor does not authenticate the
    /// dialer. Delegates to [`quic_server_config_from_pem`](crate::quic_config::quic_server_config_from_pem)
    /// (the same builder the pre-existing `quic_e2e` raw accept path uses).
    pub fn from_cert_key_pem(cert_chain_pem: &[u8], private_key_pem: &[u8]) -> io::Result<Self> {
        Ok(Self {
            server_config: crate::quic_config::quic_server_config_from_pem(
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
    /// [`wire_udp_socket`] — the DIAL side (this link owns its socket).
    #[cfg(feature = "transport-link-udp")]
    Udp { socket: UdpSocket, peer: SocketAddr },
    /// An ACCEPTED datagram face from the multi-peer demux listener (R311y382):
    /// its RX is the demux pump's per-src channel and its TX is the SHARED
    /// listener socket, bundled in [`UdpAcceptedInputs`]; wired downstream via
    /// [`wire_udp_demuxed`]. Distinct from [`Self::Udp`] because an accepted face
    /// does NOT own a socket (the pump does) — it carries a channel receiver, a
    /// shared-socket clone, and the pump keep-alive. Accept-only: the dial side
    /// never produces it. `peer` is the datagram source the pump keyed on.
    #[cfg(feature = "transport-link-udp")]
    UdpDemuxed {
        inputs: UdpAcceptedInputs,
        peer: SocketAddr,
    },
    /// A connected + link-handshaked serial tty, split downstream via
    /// [`wire_serial_stream`] (R311nv). Unlike TCP/UDP, the serial link
    /// handshake (INIT/INIT|ACK) has ALREADY run by the time the stream is
    /// wrapped here — [`dial_serial`] (Initiator) / `accept_serial`
    /// (Responder) drive it before returning, so the steady-state split
    /// path is uniform with the other transports.
    ///
    /// R311y474 — carries the dialled [`SerialEndpoint`] alongside the stream. A
    /// tty's address is not readable off the stream the way a socket's is
    /// (`SerialStream` exposes no device name), so the endpoint that opened it is
    /// the only object that can name the link — and the adminspace `{src,dst}`
    /// view needs that name.
    #[cfg(feature = "transport-link-serial")]
    Serial {
        stream: SerialStream,
        endpoint: SerialEndpoint,
    },
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
            #[cfg(feature = "transport-link-udp")]
            DialedLink::UdpDemuxed { .. } => "udp",
            #[cfg(feature = "transport-link-serial")]
            DialedLink::Serial { .. } => "serial",
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
    /// A bound unix-domain [`UnixsockListener`]; [`accept_bound`] accepts a raw
    /// [`DialedLink::Unixsock`] with NO post-accept handshake (a `UnixStream` is
    /// wrapped directly, like `tcp`). The FIRST non-`TcpListener` variant
    /// (R311y378, accept-symmetry Stage 4) — the accept-side mirror of
    /// `dial_locator`'s `AnyLocator::Unixsock => DialedLink::Unixsock`, and the
    /// reason [`Self::accept_raw`] yields an [`AcceptedPeer`] (a unix accept has
    /// no IP peer) and [`Self::local_addr`] returns a typed error for it.
    ///
    /// Not a bare `UnixListener`: a unix listener also owns a FILESYSTEM
    /// artifact, so the variant carries the `{path}.lock` arbitration and the
    /// unlink-on-teardown that zenoh's `ListenerUnixSocketStream` carries
    /// (`unicast.rs`). Dropping this `BoundListener` therefore removes the
    /// socket file, which is why no caller has to.
    #[cfg(feature = "transport-link-unixsock")]
    Unixsock(UnixsockListener),
    /// A bound AF_VSOCK [`VsockListener`]; [`accept_bound`] accepts a raw
    /// [`DialedLink::Vsock`] with NO post-accept handshake (direct wrap, like
    /// `tcp` / `unixsock`). Non-IP like `unixsock` (the accepted peer is
    /// anonymous -> [`AcceptedPeer::NonIp`]); Linux-only (AF_VSOCK), gated with
    /// the backend (R311y379). `tokio_vsock::VsockListener::accept` is
    /// `&mut self`, which is why [`Self::accept_raw`] takes `&mut self` (the
    /// stream family's `&`-accept never forced it).
    #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
    Vsock(VsockListener),
    /// A bound MULTI-CLIENT unix named-pipe rendezvous (R311y392) — a
    /// [`UnixpipeAcceptor`] owning the shared request channel + a spawned acceptor
    /// task that runs each client's zenoh-compatible invitation handshake and
    /// feeds the completed links over a channel. [`accept_bound`] / the mesh loop
    /// accept a raw [`DialedLink::Unixpipe`] with NO post-accept handshake (the
    /// invitation handshake already ran in the task; direct wrap, like `tcp` /
    /// `unixsock` / `vsock`). Non-IP like the other same-host families (a FIFO open
    /// has no IP peer -> [`AcceptedPeer::NonIp`]); Linux-only (the `read_write`
    /// open-rendezvous), gated with the backend. Unlike the R311y380 single-
    /// connection acceptor, `accept_raw` now BLOCKS on the task's new-link channel
    /// (`recv`, cancel-safe) until a client completes the handshake — so unixpipe
    /// is MESH-CAPABLE (holds N ZID-keyed faces) exactly like the stream families,
    /// and the reject-throttle that bounded the old non-blocking accept is retired.
    /// The udp demux [`crate::udp_pipeline::UdpDemux`] analogue for a streamed,
    /// per-peer transport.
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    Unixpipe(UnixpipeAcceptor),
    /// A multi-peer DATAGRAM demux listener (R311y382) — the first
    /// structurally-datagram acceptor. UDP has no `accept()` yielding a per-peer
    /// socket: there is ONE bound socket serving N peers. [`bind_udp_demux`]
    /// spawns a pump task that is the sole `recv_from` owner and routes each
    /// datagram to its SOURCE's per-face channel; [`Self::accept_raw`] awaits a
    /// NEW src on the demux's new-face channel and hands back a
    /// [`AcceptedLink::UdpDemuxed`] whose RX is that src's channel (only its own
    /// datagrams — no cross-talk) and whose TX is the shared listener socket. The
    /// accepted peer is a REAL IP ([`AcceptedPeer::Ip`]) — the datagram source —
    /// so a UDP accept keys a mesh face; NO post-accept handshake (direct wrap,
    /// like `tcp`).
    ///
    /// This SUPERSEDES the R311y381 single-shot `Option<UdpSocket>` model, which
    /// held at most one udp face (a second `accept_raw` `Err`ed) and so had two
    /// honestly-flagged mesh gaps the demux retires: F1 CROSS-TALK (the first
    /// face's unconnected socket `recv_from`'d ANY source — now each face reads
    /// only its src's channel) and F2 PERPETUAL-THROTTLE (a consumed socket
    /// `Err`ed every mesh re-arm → the `Step::Accepted(Err)` throttle fired
    /// forever — now a second src is a real second face and no-new-src merely
    /// PENDS). The zenoh `LinkManagerUnicastUdp` (`accept_read_task`) mirror.
    ///
    /// KNOWN DIVERGENCE from zenoh (doc-only, deferred): zenoh keys unconnected
    /// links on `(src, dst)` + `IP_PKTINFO` (recovering the local dst a peer
    /// targeted); wz keys on `src` ONLY and replies from the single shared
    /// listener socket. Equivalent for a concrete-IP `--listen udp/HOST:P` bind
    /// (dst is invariant); for a WILDCARD `0.0.0.0` bind wz cannot reply from the
    /// exact local address the peer targeted — no worse than the superseded
    /// single-shot model. A one-shot spoofable src also leaves a `faces` map
    /// entry until a later datagram reaps it (the demux brings udp to PARITY with
    /// the uncapped TCP `accept_loop`, plus UDP src spoofability; zenoh caps at
    /// the transport-manager accept layer, not here) — bounded per-face by the
    /// pump's bounded channels, the map growth deferred.
    #[cfg(feature = "transport-link-udp")]
    Udp(UdpDemux),
    /// A bound QUIC server [`Endpoint`] (R311y401) — QUIC is UDP-based but
    /// CONNECTION-oriented, so unlike the udp DEMUX (one socket demuxing N sources)
    /// one bound endpoint yields a per-peer `Connection` via `accept`. The quinn
    /// `Endpoint` OWNS the server crypto config (baked in at [`bind_quic`] from
    /// [`AcceptConfig::quic`]), so this variant carries ONLY the endpoint — unlike
    /// [`Self::Tls`], which carries a separate `Arc<ServerConfig>` alongside its
    /// `TcpListener`. [`Self::accept_raw`] does only the cheap connection ARRIVAL
    /// ([`accept_quic_incoming`]: `endpoint.accept()`, no crypto), yielding an
    /// [`AcceptedLink::Quic`] that carries the pending `Incoming`; the crypto
    /// handshake + the first bidi stream are DEFERRED to [`AcceptedLink::handshake`]
    /// (R311y404), run in the spawned per-face open future — exactly the tls model
    /// (whose `accept_raw` does only the cheap TCP accept, crypto deferred). That
    /// deferral is what makes quic MESH-CAPABLE ([`Self::supports_mesh_multi_peer`]
    /// returns `true`): a slow peer handshake can no longer block the multi-peer
    /// [`accept_loop`](crate::accept_loop)'s `select!`, so one endpoint holds N
    /// ZID-keyed faces. The accepted peer is a REAL IP ([`AcceptedPeer::Ip`], from
    /// `Incoming::remote_address()` — named before the handshake), like udp. Reaching
    /// the mesh loop needs a quic cert, and every shipped listen caller now threads one
    /// (`--quic-cert`/`--quic-key` -> `AcceptConfig.quic`): the `--router` (R311y405),
    /// `--peer`, and `--router-hat` (R311y406) CLI paths, the one-shot `--listen quic/`
    /// (via [`accept_bound`]), and pico's `z_open(listen=quic/)`. So a quic listen binds
    /// whenever a cert is supplied; only a cert-LESS bind (a direct-API caller passing
    /// [`AcceptConfig::default`]) hits `bind_locator`'s cert-absence `Unsupported`.
    #[cfg(feature = "transport-link-quic")]
    Quic(Endpoint),
    /// A bound QUIC server [`Endpoint`] serving the unreliable-DATAGRAM transport
    /// (RFC9221, R311y408) — the datagram sibling of [`Self::Quic`]. Structurally
    /// identical at the accept layer (one bound endpoint yields a per-peer
    /// `Connection` via `accept`), so the accept seam MIRRORS `Quic` exactly: the
    /// crypto config is baked in at [`bind_quic_datagram`] from [`AcceptConfig::quic`]
    /// (datagrams reuse the SAME cert as the stream backend, matching zenoh, whose
    /// quic + quic_datagram links share the `transport.link.tls` block), and
    /// [`Self::accept_raw`] does only the cheap connection ARRIVAL
    /// ([`accept_quic_incoming`]) while the crypto DEFERS to
    /// [`AcceptedLink::handshake`] ([`complete_quic_datagram_accept`], which drops the
    /// `accept_bi` — datagrams open no stream). That deferral is what makes the
    /// datagram acceptor MESH-CAPABLE ([`Self::supports_mesh_multi_peer`] `true`),
    /// exactly like [`Self::Quic`] since R311y404. The accepted peer is a REAL IP
    /// ([`AcceptedPeer::Ip`], from `Incoming::remote_address()`). `transport-link-
    /// quic-datagram` implies `transport-link-quic`, so `accept_quic_incoming` is in
    /// scope.
    #[cfg(feature = "transport-link-quic-datagram")]
    QuicDatagram(Endpoint),
    /// A bound `serial/...` endpoint (R311y805) — the LAST scheme whose acceptor
    /// was an unwired extension point, and the only one that binds NOTHING: a tty
    /// has no listen queue, so [`SerialListener`] holds the endpoint and
    /// [`Self::accept_raw`] opens the device. The one variant whose accept is a
    /// LOCAL open rather than a peer arrival, which is why it is also the only
    /// one that can be exhausted (see [`SerialListener`] on the one-shot arming).
    ///
    /// Its post-accept SERVER handshake is the serial-LINK handshake
    /// (`drive_serial_handshake(.., SerialRole::Responder)`: await `INIT`, reply
    /// `INIT|ACK`) — peer-controlled and unbounded, so it DEFERS to
    /// [`AcceptedLink::handshake`] exactly like the tls/quic crypto, keeping the
    /// accept path itself unblocked. That handshake runs BEFORE the zenoh
    /// transport, which no other scheme does (serial_protocol.c:255-280).
    ///
    /// NOT mesh-capable ([`Self::supports_mesh_multi_peer`] is `false` here, the
    /// first `false` in the enum since R311y404): one tty = one peer. The mesh
    /// callers consult that at bind and fail fast, so a `--router --listen
    /// serial/...` reports "single-connection, not multi-peer" instead of
    /// accepting a face the loop would then drop; the one-shot [`accept_endpoint`]
    /// path — the demo's Acceptor role and pico's `z_open(listen=serial/)` — is
    /// what serves a serial listen.
    #[cfg(feature = "transport-link-serial")]
    Serial(SerialListener),
}

/// The "listener" state of a bound `serial/...` endpoint (R311y805) — a tty is
/// not a socket, so there is nothing to bind: this holds the parsed
/// [`SerialEndpoint`] plus the one-shot arming flag, and the DEVICE is opened
/// per-accept in [`BoundListener::accept_raw`]. That is upstream's shape, not an
/// approximation of it: zenoh's `new_listener` creates NO port either — it
/// records the endpoint and lets its accept task open the device
/// (`zenoh-link-serial/src/unicast.rs:321-373`, whose `receive` opens the
/// `ZSerial` and only then `accept()`s, `:436-453`).
///
/// A tty is POINT-TO-POINT: one device carries exactly one link. Upstream models
/// that with an `is_connected` gate its accept task spins on before re-opening
/// (`unicast.rs:430-433`), i.e. at most one live link at a time. wz's accept seam
/// carries no link-liveness feedback, so the honest model here is ONE accept per
/// bind: `armed` is cleared by the first [`BoundListener::accept_raw`] and every
/// later accept PARKS (`pending`) rather than re-opening the device. Parking, not
/// `Err`: an `Err` re-arms the accept loop's `Step::Accepted(Err)` throttle, which
/// is the R311y382 "F2 perpetual-throttle" spin the udp demux exists to kill. And
/// re-opening would be worse than either — a second fd on a LIVE tty splits the
/// read stream between two drivers.
#[cfg(feature = "transport-link-serial")]
pub struct SerialListener {
    /// The endpoint parsed out of the `serial/...` locator — the device the
    /// accept opens, and the address [`BoundListener::local_addr_display`] logs.
    endpoint: SerialEndpoint,
    /// Cleared by the first accept; see the type doc for why a second accept
    /// parks instead of re-opening the device.
    armed: bool,
}

#[cfg(feature = "transport-link-serial")]
impl SerialListener {
    /// The endpoint this listener was bound from — the device an accept opens.
    pub fn endpoint(&self) -> &SerialEndpoint {
        &self.endpoint
    }
}

/// The peer of a link accepted by [`BoundListener::accept_raw`] — an IP
/// [`SocketAddr`](std::net::SocketAddr) for the stream family (tcp/ws/tls, all
/// `TcpListener`-backed), or a non-IP marker for a unix/vsock family listener
/// whose accepted peer wz does NOT thread: a unix `accept` yields a genuinely
/// unnamed peer (zenoh assigns a fresh UUID, `unixsock_pipeline`), while a vsock
/// `accept` yields a real `(cid, port)` that wz discards (`vsock_pipeline`) —
/// session identity is the handshake zid, not the transport peer, so neither is
/// routed. This is the "revisit the peer type" [`BoundListener::accept_raw`]'s
/// doc anticipated for the first non-IP variant (R311y378).
///
/// [`Display`](std::fmt::Display) renders the "accepted peer {..}" log line the
/// one-shot [`accept_bound`] writes. The multi-peer
/// [`accept_loop`](crate::accept_loop) holds a mesh face per accepted peer keyed
/// by its handshake zid, NOT by the transport address: an [`Self::Ip`] peer AND a
/// mesh-capable [`Self::NonIp`] peer (unixsock / vsock / unixpipe — each a genuine
/// per-peer stream accept) both become held ZID-keyed faces (Slice B). Since
/// R311y392 the stream + same-host families are all mesh-capable, and R311y404 makes
/// quic mesh-capable too (its deferred-handshake split), so the loop's NON-mesh-capable
/// reject path (see [`AcceptedLink::supports_mesh_multi_peer`]) fires for NO transport
/// today — every bound listener holds N ZID-keyed faces. A quic listener reaches the
/// loop with a threaded cert: the `--router` (R311y405) + `--peer`/`--router-hat`
/// (R311y406) CLI paths and pico all thread one, as can a direct-API caller; only a
/// cert-LESS bind hits cert-absence.
///
/// `Clone`/`Debug`/`Eq` so it can ride [`Face`](crate::accept_loop::Face)`.peer`
/// (the field the loop threads through `FaceUp`/`FaceDown`/`FaceFailed`) and the
/// `#[derive(Debug)]` on [`AcceptEvent`](crate::accept_loop::AcceptEvent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedPeer {
    /// The IP address of an accepted peer with a routable transport address —
    /// the stream family (tcp/ws/tls, the accepted `TcpStream`'s peer) and udp
    /// (the datagram SOURCE the demux pump keyed the face on, R311y382). Its
    /// `SocketAddr` is the face's log/event tag; the mesh keys the face on the
    /// handshake zid, not this address.
    Ip(std::net::SocketAddr),
    /// A non-IP transport peer (unixsock / vsock / unixpipe) — wz does not thread
    /// the accepted peer address (unix: genuinely unnamed; vsock: a
    /// real cid:port it drops; unixpipe: a FIFO open has no peer at all), so the
    /// payload is the transport name for the log line. A mesh-capable non-IP
    /// acceptor (unixsock / vsock / unixpipe, R311y392) is held as a ZID-keyed mesh
    /// face (Slice B); the face's identity is the handshake zid, so the discarded
    /// transport address does not matter to routing.
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
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(_) => "vsock",
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(_) => "unixpipe",
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(_) => "udp",
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(_) => "quic",
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(_) => "quic-datagram",
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(_) => "serial",
        }
    }

    /// R311y470 — the LOCATOR to advertise for this listener: the string a
    /// FOREIGN peer has to be able to dial, given the bound address rendered by
    /// [`Self::local_addr_display`].
    ///
    /// Distinct from [`Self::transport_name`] on purpose. That is a LOG word and
    /// is pinned as one (`unixsock_e2e.rs` asserts `"unixsock"`), and reusing it
    /// as the locator SCHEME — which the advertise sites did — diverged on two of
    /// the nine variants:
    ///
    /// - `unixsock` is not a scheme at all. zenoh's is `unixsock-stream`
    ///   (`UNIXSOCKSTREAM_LOCATOR_PREFIX`) and so is wz's own
    ///   (`UNIXSOCK_SCHEME`), so the advertised string failed even wz's OWN
    ///   parser with `NotUnixsockScheme`.
    /// - `quic-datagram` is a wz-only spelling. zenoh gives BOTH its QUIC links
    ///   the `"quic"` scheme (`QUIC_LOCATOR_PREFIX` and
    ///   `QUIC_DATAGRAM_LOCATOR_PREFIX` are both `"quic"`) and selects between
    ///   them with the `rel` metadata key (`io/zenoh-link/src/lib.rs:165-171`);
    ///   an unknown scheme hits its `_ => bail!("Unicast not supported for {}
    ///   protocol")` arm (:183). wz keeps ACCEPTING `quic-datagram/...` inbound
    ///   (its explicit spelling), and emits the canonical one.
    ///
    /// This matters because these strings are not diagnostics: `run_router` /
    /// `run_peer` hand them to `set_self_locators`, which floods them through
    /// `LinkstateForwarder` into the neighbour graph and hence to peers.
    ///
    /// The match is WILDCARD-FREE, like [`Self::supports_mesh_multi_peer`] and
    /// [`Self::transport_name`]: a new variant must state its advertised scheme
    /// explicitly rather than inherit a log word that may not be one. That
    /// inheritance is exactly what produced both divergences above.
    /// R311y473 — the scheme table itself moved to
    /// [`InterceptorLink::locator_for`], which is now the ONE copy. This site
    /// keeps its own wildcard-free match because the thing it must state is which
    /// PROTOCOL a bound listener speaks; the scheme for that protocol is then not
    /// its business. The adminspace per-link `{src,dst}` emitter (R311y473) reads
    /// the same table, so the two cannot diverge the way a second copy would.
    pub fn advertised_locator(&self, address: &str) -> String {
        self.interceptor_link().locator_for(address)
    }

    /// R311y473 — which §5.16 link protocol this bound listener speaks. Extracted
    /// so [`Self::advertised_locator`] can delegate its scheme to the single
    /// [`InterceptorLink::locator_for`] table. Wildcard-free: a new
    /// `BoundListener` variant must name its protocol.
    pub fn interceptor_link(&self) -> InterceptorLink {
        match self {
            BoundListener::Tcp(_) => InterceptorLink::Tcp,
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(_) => InterceptorLink::Ws,
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(..) => InterceptorLink::Tls,
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(_) => InterceptorLink::UnixsockStream,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(_) => InterceptorLink::Vsock,
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(_) => InterceptorLink::Unixpipe,
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(_) => InterceptorLink::Udp,
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(_) => InterceptorLink::Quic,
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(_) => InterceptorLink::QuicDatagram,
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(_) => InterceptorLink::Serial,
        }
    }

    /// Whether this bound listener's acceptor is MESH-CAPABLE — i.e. wz's CURRENT
    /// accept path for it yields multiple DISTINCT per-peer connections, so the
    /// multi-accept [`accept_loop`](crate::accept_loop) can hold N faces off it.
    /// The BIND-time twin of [`AcceptedLink::supports_mesh_multi_peer`] (the loop's
    /// RUNTIME backstop, consulted per-accept in `Step::Accepted`): the two match
    /// the SAME transport to the SAME verdict, and a mesh CALLER (run_router)
    /// consults THIS one to fail-fast a non-mesh-capable `--listen` at bind rather
    /// than let the loop reject-throttle each accept forever (0 faces held). Since
    /// R311y392 the stream + same-host families are all `true`, and R311y404 flips
    /// `Quic` `false -> true` (its deferred-handshake split moves the crypto off the
    /// accept path, so a quic endpoint holds N per-peer faces like the rest). R311y805
    /// ends that run: `Serial` is `false`, the first since R311y404 — one tty
    /// carries one peer, so there is no N to hold, and upstream agrees (its serial
    /// listener gates re-accept on the previous link having dropped,
    /// `zenoh-link-serial/src/unicast.rs:430-433`). A SHIPPED quic listen DOES hit this predicate: the
    /// `--router` (R311y405) + `--peer`/`--router-hat` (R311y406) CLI paths and pico all
    /// thread a cert (`--quic-cert` -> `AcceptConfig.quic`), so `bind_locator` binds
    /// rather than cert-absence-rejecting; only a cert-LESS bind is rejected first. This
    /// match is wildcard-free so a new `BoundListener` variant forces an explicit mesh
    /// decision here (and its twin above).
    pub fn supports_mesh_multi_peer(&self) -> bool {
        match self {
            BoundListener::Tcp(_) => true,
            #[cfg(feature = "transport-link-ws")]
            BoundListener::Ws(_) => true,
            #[cfg(feature = "transport-link-tls")]
            BoundListener::Tls(..) => true,
            #[cfg(feature = "transport-link-unixsock")]
            BoundListener::Unixsock(_) => true,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(_) => true,
            // R311y392: the multi-client acceptor makes unixpipe mesh-capable, so
            // this flipped `false -> true` (its `AcceptedLink` twin too). The
            // acceptor holds N ZID-keyed faces exactly like the stream families.
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(_) => true,
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(_) => true,
            // R311y404 — quic joins the mesh-capable family (`false -> true`): its
            // deferred-handshake split (accept_raw does only the cheap
            // `accept_quic_incoming` arrival; the crypto + first bidi stream defer to
            // `AcceptedLink::handshake` in the spawned open future) moves the slow
            // crypto off the accept loop's `select!`, so one endpoint holds N
            // ZID-keyed faces like tls. Every shipped quic listen threads a cert
            // (`--quic-cert` -> `AcceptConfig.quic`): --router (R311y405), --peer /
            // --router-hat (R311y406), pico, and the one-shot --listen; so it binds and
            // reaches here. Only a cert-LESS bind is rejected at cert-absence first.
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(_) => true,
            // Mesh-capable for the SAME reason as `Quic` (deferred crypto handshake).
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(_) => true,
            // R311y805 — `false`, and not for a deferral reason: a tty is
            // POINT-TO-POINT, so one bound serial endpoint can only ever produce
            // ONE peer. Upstream's serial listener is the same shape (it re-opens
            // only after the previous link dropped, `unicast.rs:430-433`), so this
            // is parity, not a wz shortfall. The consequence is the one this
            // predicate exists for: a mesh caller (`run_router` / `drive_listen`)
            // fail-fasts the `--listen serial/...` at BIND with "single-connection,
            // not multi-peer" rather than accepting the link and letting the loop's
            // runtime backstop drop it. The one-shot `accept_endpoint` path serves a
            // serial listen, which is the path the demo's Acceptor role uses.
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(_) => false,
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
            // A vsock listener addresses by (cid, port), not an IP -- render the
            // bound AF_VSOCK address (the ephemeral port the kernel assigned to a
            // VMADDR_PORT_ANY bind is readable here, race-free).
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(l) => {
                let a = l.local_addr()?;
                format!("{}:{}", a.cid(), a.port())
            }
            // A unixpipe rendezvous has no IP -- render the bound listen BASE path
            // (the request-channel rendezvous); that IS its address (the non-IP
            // address type this per-variant String accessor exists for).
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(acc) => acc.base_path().to_string(),
            // A UDP demux listener HAS a real bound IP address (unlike the
            // same-host non-IP families), cached at bind -- always available (the
            // pump owns the socket; there is no consumed state, unlike the
            // superseded single-shot model).
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(demux) => demux.local_addr().to_string(),
            // QUIC binds a real UDP socket -> a real IP address (like udp), read
            // back from the quinn Endpoint (the ephemeral port a `:0` bind got is
            // readable here, race-free before any accept).
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(ep) => ep.local_addr()?.to_string(),
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(ep) => ep.local_addr()?.to_string(),
            // A serial endpoint's address is the DEVICE (or the pin pair),
            // rendered with the `#baudrate=` tail that makes it parse back --
            // `locator_address_with_config` is the same renderer the per-link
            // adminspace `{src,dst}` pair uses (R311y474), so the "listening on"
            // line is a string a peer can actually dial. Infallible: unlike a
            // socket's, this address is known at bind and no syscall reads it.
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(l) => l.endpoint.locator_address_with_config(),
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
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a vsock listener has no IP SocketAddr (it addresses by cid:port); \
                 use local_addr_display",
            )),
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unixpipe listener has no IP SocketAddr (it addresses by FIFO path); \
                 use local_addr_display",
            )),
            // UDP DOES have an IP `SocketAddr` (the bound listen addr) -- unlike
            // the same-host non-IP families, the first non-tcp variant that
            // returns `Ok` here (an `--peer` / `--router-hat` zid-from-port
            // derivation over a udp listen is well-defined). Cached at bind (the
            // demux pump owns the socket) -> always `Ok`, no consumed state.
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(demux) => Ok(demux.local_addr()),
            // QUIC HAS a real IP `SocketAddr` (the bound UDP socket), like udp ->
            // `Ok` (a well-defined `--peer`/`--router-hat` zid-from-port over a quic
            // listen), read from the quinn Endpoint.
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(ep) => ep.local_addr(),
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(ep) => ep.local_addr(),
            // A tty has no IP address at all (not even a same-host path the way
            // unixsock does); its address is a device node. Same typed error as the
            // other non-IP families -- a zid-from-port caller never binds serial.
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a serial listener has no IP SocketAddr (it addresses by tty device); \
                 use local_addr_display",
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
    pub async fn accept_raw(&mut self) -> io::Result<(AcceptedLink, AcceptedPeer)> {
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
            // R311y379 — the second non-IP accept: `accept_vsock_on` needs
            // `&mut VsockListener` (tokio_vsock's accept is `&mut self`), which
            // the `&mut self` receiver here supplies directly (no Mutex). Direct
            // wrap, anonymous peer -> NonIp, mirroring unixsock.
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            BoundListener::Vsock(l) => {
                let stream = accept_vsock_on(l).await?;
                (AcceptedLink::Vsock(stream), AcceptedPeer::NonIp("vsock"))
            }
            // R311y392 — the MULTI-CLIENT unixpipe accept: await the acceptor
            // task's next completed link (its zenoh-compatible invitation handshake
            // already ran INSIDE the task, so nothing multi-step runs in this
            // cancel-prone `select!` arm). `recv_new_link` is a bare `mpsc::recv`,
            // cancel-safe like the udp / dial-intent helpers -- a `select!`
            // dropping this accept never loses a buffered link (it stays in the
            // channel). On a CLOSED channel (the acceptor task ended) we PARK
            // (`pending`) rather than return `Err`: an `Err` would re-arm the
            // `Step::Accepted(Err)` throttle, exactly the spin the blocking accept
            // now avoids (the R311y380 non-blocking-accept throttle is retired).
            // Direct wrap, anonymous peer -> NonIp, mirroring unixsock/vsock;
            // unixpipe is now mesh-capable (holds N ZID-keyed faces).
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            BoundListener::Unixpipe(acc) => {
                let link = match acc.recv_new_link().await {
                    Some(link) => link,
                    None => std::future::pending::<UnixpipeLink>().await,
                };
                (
                    AcceptedLink::Unixpipe(link),
                    AcceptedPeer::NonIp("unixpipe"),
                )
            }
            // R311y382 — the multi-peer datagram accept: await a NEW src from the
            // demux pump (each `recv_new_face` yields the next distinct peer, so a
            // udp listener now holds N faces — F2's single-shot `Err` is retired).
            // The pump's per-src channel becomes this face's RX (only its own
            // datagrams — F1 cross-talk retired), the shared listener socket its
            // TX, bundled in `UdpAcceptedInputs`. The peer is a REAL IP (the
            // datagram source) -> `AcceptedPeer::Ip`, so a udp accept keys a mesh
            // face.
            //
            // CANCEL-SAFETY: `recv_new_face` is a bare `mpsc::Receiver::recv`,
            // cancel-safe like the loop's `recv_dial_intent` / `recv_reconcile`
            // helpers — a `select!` dropping this accept mid-recv never loses a
            // buffered `NewUdpFace` (it stays in the channel for the next accept).
            // On a CLOSED channel (`None`, the pump died on a `recv_from` error)
            // we PARK (`pending`) rather than return `Err`: an `Err` here would
            // re-arm the `Step::Accepted(Err)` throttle every interval, which is
            // exactly the F2 spin the demux exists to kill. A dead pump means "no
            // more faces will ever come", i.e. stop accepting -- a perpetually
            // pending accept arm, not a throttling one.
            #[cfg(feature = "transport-link-udp")]
            BoundListener::Udp(demux) => {
                let face = match demux.recv_new_face().await {
                    Some(face) => face,
                    None => std::future::pending::<NewUdpFace>().await,
                };
                let peer = face.peer;
                let inputs = demux.wire_inputs(face.inbound_rx);
                (
                    AcceptedLink::UdpDemuxed { inputs, peer },
                    AcceptedPeer::Ip(peer),
                )
            }
            // R311y404 — the QUIC accept, DEFERRED-handshake split (was inline at
            // R311y401): `accept_quic_incoming` does only the cheap connection ARRIVAL
            // (`endpoint.accept()`, no crypto), like tls's cheap TCP accept here. The
            // pending `Incoming` rides the `AcceptedLink::Quic` (with an `Endpoint`
            // keep-alive clone) into the spawned open future, where `handshake` runs
            // the crypto + first bidi stream (`complete_quic_accept`) OFF the accept
            // loop's `select!` — the reason quic is now loop-safe and mesh-capable. The
            // peer is a REAL IP, read from `Incoming::remote_address()` BEFORE the
            // handshake (unlike the old `connection.remote_address()`, which needed the
            // completed connection). `Box`ed (an `Incoming` carries the quinn proto
            // state, matching the boxed DialedLink::Quic on the far side).
            #[cfg(feature = "transport-link-quic")]
            BoundListener::Quic(ep) => {
                let incoming = accept_quic_incoming(ep).await?;
                let peer = incoming.remote_address();
                (
                    AcceptedLink::Quic {
                        incoming: Box::new(incoming),
                        endpoint: ep.clone(),
                    },
                    AcceptedPeer::Ip(peer),
                )
            }
            // R311y408 — the datagram twin of the `Quic` arm: the cheap connection
            // ARRIVAL (`accept_quic_incoming`, shared with the stream backend since
            // `transport-link-quic-datagram` implies `transport-link-quic`), crypto
            // DEFERRED to `handshake` (`complete_quic_datagram_accept`). Real-IP peer
            // from `Incoming::remote_address()` before the handshake.
            #[cfg(feature = "transport-link-quic-datagram")]
            BoundListener::QuicDatagram(ep) => {
                let incoming = accept_quic_incoming(ep).await?;
                let peer = incoming.remote_address();
                (
                    AcceptedLink::QuicDatagram {
                        incoming: Box::new(incoming),
                        endpoint: ep.clone(),
                    },
                    AcceptedPeer::Ip(peer),
                )
            }
            // R311y805 — the serial accept: the CHEAP half is a local tty open
            // (`open_serial_device`), and the peer-controlled serial-LINK handshake
            // (await `INIT`, reply `INIT|ACK`) DEFERS to `AcceptedLink::handshake`,
            // the same split tls/quic use for their crypto. A tty open is the one
            // accept in this enum that completes without any peer having arrived,
            // which is precisely why the handshake half must not run here: it is
            // the part that waits.
            //
            // ONE accept per bind (see `SerialListener`): the second and later
            // accepts PARK rather than re-open a device whose link is still live.
            // `pending` and not `Err`, for the R311y382 F2 reason -- an `Err` re-arms
            // the loop's throttle and spins. Reached only by a direct-API caller
            // today: the mesh loop rejects a serial listen at bind (not mesh-capable),
            // and the one-shot `accept_bound` consumes the listener after one accept.
            #[cfg(feature = "transport-link-serial")]
            BoundListener::Serial(l) => {
                if !l.armed {
                    std::future::pending::<()>().await;
                }
                l.armed = false;
                let stream = open_serial_device(&l.endpoint)?;
                (
                    AcceptedLink::Serial {
                        stream,
                        endpoint: l.endpoint.clone(),
                    },
                    AcceptedPeer::NonIp("serial"),
                )
            }
        })
    }

    // R2355 — `into_tcp` is GONE, and its own doc had asked for that: "Generalizing
    // `accept_loop` to accept every `BoundListener` variant retires this accessor."
    // R311y376 did the generalizing; the accessor outlived it by pointing at a
    // caller that was never the multi-peer loop at all. Its last user was the
    // demo's SEQUENTIAL storage-host seam, which now borrows the `BoundListener`
    // through `accept_bound_on` like its two siblings, so nothing in the tree
    // projects a listen endpoint down to tcp any more. Deleting it rather than
    // leaving it unused is the point: an accessor whose whole body is a typed
    // `Unsupported` for seven schemes is a gap that reads as a feature.
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
    /// A raw accepted AF_VSOCK stream — NO post-accept handshake (like
    /// [`Self::Tcp`] / [`Self::Unixsock`]); [`Self::handshake`] wraps it
    /// directly as [`DialedLink::Vsock`] (R311y379).
    #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
    Vsock(VsockStream),
    /// A connected unix named-pipe (FIFO-pair) link — NO post-accept handshake
    /// (like [`Self::Tcp`] / [`Self::Unixsock`] / [`Self::Vsock`]);
    /// [`Self::handshake`] wraps it directly as [`DialedLink::Unixpipe`]
    /// (R311y380). Already a connected [`UnixpipeLink`] (the FIFO open IS the
    /// rendezvous), unlike the stream family's raw `TcpStream` awaiting a wrap.
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    Unixpipe(UnixpipeLink),
    /// An ACCEPTED datagram face from the multi-peer demux listener — NO
    /// post-accept handshake (like [`Self::Tcp`]); [`Self::handshake`] wraps it
    /// directly as [`DialedLink::UdpDemuxed`] (R311y382). Carries the
    /// [`UdpAcceptedInputs`] (the pump's per-src channel + a shared listener
    /// socket clone + the pump keep-alive) — NOT an owned socket like the dial
    /// side's [`DialedLink::Udp`], because the demux pump owns the socket. `peer`
    /// is the datagram source the pump keyed this face on.
    #[cfg(feature = "transport-link-udp")]
    UdpDemuxed {
        inputs: UdpAcceptedInputs,
        peer: std::net::SocketAddr,
    },
    /// A pending QUIC connection ARRIVAL awaiting its DEFERRED crypto handshake
    /// (R311y404, was a completed inline link at R311y401) — the quinn `Incoming`
    /// that [`BoundListener::accept_raw`] took off `endpoint.accept()` WITHOUT
    /// running the crypto, plus the [`Endpoint`] keep-alive clone the resulting
    /// [`QuicLink`] needs. [`Self::handshake`] runs the crypto + first bidi stream
    /// (`complete_quic_accept`) into [`DialedLink::Quic`], deferred off the accept
    /// loop like the ws/tls SERVER handshake — the split that makes quic
    /// mesh-capable. The `Incoming` is `Box`ed (it carries the quinn proto state),
    /// matching the boxed [`DialedLink::Quic`] the handshake yields.
    #[cfg(feature = "transport-link-quic")]
    Quic {
        incoming: Box<Incoming>,
        endpoint: Endpoint,
    },
    /// A pending QUIC-DATAGRAM connection ARRIVAL awaiting its DEFERRED crypto
    /// handshake (R311y408) — the datagram twin of [`Self::Quic`]. Identical shape
    /// (the quinn `Incoming` [`BoundListener::accept_raw`] took off
    /// `endpoint.accept()` WITHOUT crypto + the [`Endpoint`] keep-alive clone);
    /// [`Self::handshake`] runs the crypto ([`complete_quic_datagram_accept`]) into
    /// [`DialedLink::QuicDatagram`], deferred off the accept loop like `Quic`. It
    /// drops the `accept_bi` the reliable path runs — datagrams open no stream.
    #[cfg(feature = "transport-link-quic-datagram")]
    QuicDatagram {
        incoming: Box<Incoming>,
        endpoint: Endpoint,
    },
    /// An OPEN tty awaiting its DEFERRED serial-LINK handshake (R311y805) — the
    /// `SerialStream` [`BoundListener::accept_raw`] opened WITHOUT waiting for the
    /// peer, plus the [`SerialEndpoint`] it was opened from (a `SerialStream`
    /// exposes no device name, and the downstream `wire_serial_stream` needs it for
    /// the adminspace `{src,dst}` pair). [`Self::handshake`] drives
    /// `SerialRole::Responder` — await `INIT`, reply `INIT|ACK` — into
    /// [`DialedLink::Serial`].
    ///
    /// The deferral is not a mirror of tls/quic's for its own sake: this handshake
    /// is UNBOUNDED (it retries on `RESET` the way `_z_connect_serial` does,
    /// serial_protocol.c:255-280), so running it in the accept path would block on
    /// a peer that may never come. It also runs BEFORE the zenoh transport, which
    /// no other scheme's does.
    #[cfg(feature = "transport-link-serial")]
    Serial {
        stream: SerialStream,
        endpoint: SerialEndpoint,
    },
}

impl AcceptedLink {
    /// Run the deferred per-scheme SERVER handshake, yielding the SAME
    /// [`DialedLink`] the dial side produces (so the downstream `wire_*` split is
    /// shared, dialed or accepted) — the acceptor twin of [`dial_locator`]'s
    /// per-scheme client handshake, and the mechanism SSOT the consuming one-shot
    /// [`accept_bound`] also drives. Runs in the spawned per-face open future (not
    /// the accept loop's `select!` arm), so a slow ws/tls/quic handshake never stalls
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
            // Direct wrap, the acceptor mirror of dial_locator's
            // `DialedLink::Vsock` (R311y379).
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            AcceptedLink::Vsock(stream) => DialedLink::Vsock(stream),
            // Direct wrap, the acceptor mirror of dial_locator's
            // `DialedLink::Unixpipe` (R311y380) — the FIFO link is already
            // connected, so like unixsock/vsock there is nothing to handshake.
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            AcceptedLink::Unixpipe(link) => DialedLink::Unixpipe(link),
            // Direct wrap (R311y382) — an accepted demux face has no server
            // handshake; the pump already queued its first datagram (the InitSyn)
            // on the channel, which `wire_udp_demuxed`'s read driver reads as
            // frame one.
            #[cfg(feature = "transport-link-udp")]
            AcceptedLink::UdpDemuxed { inputs, peer } => DialedLink::UdpDemuxed { inputs, peer },
            // R311y404 — the DEFERRED QUIC handshake (was a direct wrap at R311y401,
            // when the crypto ran inline in accept_raw): `complete_quic_accept` drives
            // the crypto (`incoming.await`) + accepts the first bidi stream here, in
            // the spawned open future, so a slow peer handshake never stalls the accept
            // loop — the ws/tls-server-handshake analogue. Yields the SAME
            // `DialedLink::Quic` the dial side produces (shared downstream wiring).
            #[cfg(feature = "transport-link-quic")]
            AcceptedLink::Quic { incoming, endpoint } => {
                DialedLink::Quic(Box::new(complete_quic_accept(*incoming, endpoint).await?))
            }
            // R311y408 — the DEFERRED QUIC-DATAGRAM handshake, the datagram twin of
            // the `Quic` arm: `complete_quic_datagram_accept` drives the crypto
            // (`incoming.await`) in the spawned open future, minus the `accept_bi`
            // (datagrams open no stream). Yields the SAME `DialedLink::QuicDatagram`
            // the dial side produces (shared downstream `wire_quic_datagram`).
            #[cfg(feature = "transport-link-quic-datagram")]
            AcceptedLink::QuicDatagram { incoming, endpoint } => DialedLink::QuicDatagram(
                Box::new(complete_quic_datagram_accept(*incoming, endpoint).await?),
            ),
            // R311y805 — the DEFERRED serial-LINK handshake, the Responder half of
            // the exchange `dial_serial` drives as Initiator: await `INIT`, reply
            // `INIT|ACK`, and leave the stream positioned exactly at the first
            // post-handshake byte so the zenoh transport bytes reach the split read
            // half intact. Composing it here with the accept's tty open reproduces
            // `serial_pipeline::accept_serial` exactly -- that one-call form stays
            // for callers holding their own endpoint; this seam needs the halves
            // apart. Yields the SAME `DialedLink::Serial` the dial side produces, so
            // `wire_dialed_link` is shared.
            #[cfg(feature = "transport-link-serial")]
            AcceptedLink::Serial {
                mut stream,
                endpoint,
            } => {
                drive_serial_handshake(&mut stream, SerialRole::Responder).await?;
                DialedLink::Serial { stream, endpoint }
            }
        })
    }

    /// Whether this accepted link's transport is a MESH-CAPABLE acceptor — i.e.
    /// wz's CURRENT accept path for it yields multiple DISTINCT per-peer accepted
    /// connections, so the multi-accept [`accept_loop`](crate::accept_loop) can
    /// hold N faces off one listener. Since R311y392 the stream + same-host families
    /// are `true`, and R311y404 flips `Quic` to `true` (its deferred-handshake split;
    /// see the loop-safety note below) — every accepted-link variant is now
    /// mesh-capable.
    ///
    /// `Unixpipe` flipped `false -> true` at R311y392 when the multi-client acceptor
    /// landed: unixpipe's invitation handshake + per-connection dedicated sub-pipe
    /// pair (the zenoh `UnicastPipeListener` protocol) now yields N distinct
    /// per-peer links from one listener, wired the udp-demux way (a spawned acceptor
    /// task feeds completed links over a channel; `accept_raw` blocks on `recv`).
    /// The old R311y380 `accept_unixpipe_on` was a single-connection non-blocking
    /// open — the only non-mesh transport, and the reason the reject-throttle
    /// existed; both are retired.
    ///
    /// This is the loop's RUNTIME backstop (consulted in the `Step::Accepted` arm of
    /// [`accept_loop`](crate::accept_loop)); its BIND-time twin on [`BoundListener`]
    /// fail-fasts a non-mesh `--listen` at the mesh caller. R311y404 flips `Quic`
    /// `false -> true`: its deferred-handshake split (the crypto runs in
    /// [`Self::handshake`], off the accept path) makes a quic accept loop-safe, so the
    /// backstop no longer rejects it. A quic listener reaches the loop with a threaded
    /// cert: the `--router` (R311y405) + `--peer`/`--router-hat` (R311y406) CLI paths
    /// and pico all thread one, as can a direct-API caller; only a cert-LESS bind is
    /// rejected at cert-absence first. This match is wildcard-free so a new
    /// `AcceptedLink` variant forces an explicit mesh decision here.
    pub fn supports_mesh_multi_peer(&self) -> bool {
        match self {
            AcceptedLink::Tcp(_) => true,
            #[cfg(feature = "transport-link-ws")]
            AcceptedLink::Ws(_) => true,
            #[cfg(feature = "transport-link-tls")]
            AcceptedLink::Tls(..) => true,
            #[cfg(feature = "transport-link-unixsock")]
            AcceptedLink::Unixsock(_) => true,
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            AcceptedLink::Vsock(_) => true,
            // R311y392: the multi-client acceptor makes unixpipe mesh-capable, so
            // this flipped `false -> true` (its `BoundListener` twin too).
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            AcceptedLink::Unixpipe(_) => true,
            #[cfg(feature = "transport-link-udp")]
            AcceptedLink::UdpDemuxed { .. } => true,
            // R311y404 — quic joins the mesh-capable family (`false -> true`, its
            // BoundListener twin too): the deferred-handshake split runs the crypto in
            // `handshake` (off the accept loop), so a quic accept is loop-safe and the
            // multi-peer loop holds N quic faces like tls.
            #[cfg(feature = "transport-link-quic")]
            AcceptedLink::Quic { .. } => true,
            // Mesh-capable for the SAME reason as `Quic` (deferred crypto handshake).
            #[cfg(feature = "transport-link-quic-datagram")]
            AcceptedLink::QuicDatagram { .. } => true,
            // R311y805 — `false`, matching its `BoundListener` twin: a tty is
            // point-to-point, so this acceptor yields exactly ONE peer and there is
            // no N for the loop to hold. This is the FIRST subject the loop's
            // reject arm has had since R311y404 emptied it -- though the bind-time
            // twin fail-fasts a mesh `--listen serial/...` first, so the reject
            // arm is reached only by a caller that skipped the bind-time check.
            #[cfg(feature = "transport-link-serial")]
            AcceptedLink::Serial { .. } => false,
        }
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
            #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
            AcceptedLink::Vsock(_) => "",
            #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
            AcceptedLink::Unixpipe(_) => "",
            #[cfg(feature = "transport-link-udp")]
            AcceptedLink::UdpDemuxed { .. } => "",
            // R311y404 — quic now DEFERS its crypto handshake to `handshake`
            // (`complete_quic_accept`), like tls, so it earns a completion witness note
            // (was `""` when the crypto ran inline in accept_raw). Mirrors the tls
            // wording; logged after the deferred handshake succeeds.
            #[cfg(feature = "transport-link-quic")]
            AcceptedLink::Quic { .. } => "; quic server handshake",
            // R311y408 — the datagram twin defers its crypto to `handshake` too, so
            // it earns the same completion-witness note (datagram-tagged).
            #[cfg(feature = "transport-link-quic-datagram")]
            AcceptedLink::QuicDatagram { .. } => "; quic-datagram server handshake",
            // R311y805 — serial defers a handshake too, but a LINK-level one (the
            // `INIT` / `INIT|ACK` exchange that precedes the zenoh transport), so
            // the note says which layer it completed rather than borrowing the
            // crypto wording.
            #[cfg(feature = "transport-link-serial")]
            AcceptedLink::Serial { .. } => "; serial link handshake",
        }
    }
}

/// The link schemes THIS BUILD can actually bind and dial, derived from the
/// very `#[cfg]` predicates that gate the [`dial_locator`] / [`bind_locator`]
/// arms below — not from a list of what zenoh carries.
///
/// R2070 (open-debt item 487) — the distinction has a cost that was measured
/// rather than argued. `zenoh_config::ZENOH_LINK_PROTOCOLS` names the nine
/// schemes a stock zenoh 1.5.0 can carry, and it is RIGHT for the emit
/// direction: a config generated for a real zenohd is coherent whatever this
/// build compiled in. But wz's own links are every one of them a cargo
/// feature, and the default build carries only `tcp` + `udp`. So a config
/// naming `vsock/...` passed `validate()` clean and then failed at bind —
/// exactly the post-start log line that verdict exists to precede.
///
/// It also answers the census question "which links does wz support", which
/// is not the same question as "which does this build have". A 2026-08-23
/// external review read the tree and reported `ws` as an ABSENT transport;
/// `ws` is implemented, gated, and has two zenohd interop witnesses, but it
/// is not a default feature, so a reader looking at default-build symbols
/// could not tell it from a gap. A list the build derives cannot mislead
/// that way: it says what THIS build has, and the feature that turns it on
/// is named right next to it.
///
/// The scheme set is deliberately NOT one-to-one with the feature set:
/// `transport-link-quic-datagram` adds no scheme, because its link declares
/// the prefix `"quic"` and shares it with the stream backend (the same
/// reason `ZENOH_LINK_PROTOCOLS` omits it).
///
/// Bound to reality by `zenoh_config`'s
/// `the_compiled_in_scheme_census_agrees_with_what_bind_locator_does`, which
/// asks `bind_endpoint` once per upstream scheme instead of re-reading this
/// list — so a backend added without a line here fails a test rather than
/// answering a config question wrongly. It lives over there because that is
/// where the OTHER list (`ZENOH_LINK_PROTOCOLS`) is in scope, and the point
/// of the check is that the two disagree in a known way.
pub const COMPILED_IN_LINK_SCHEMES: &[&str] = &[
    // `tcp` carries no arm-level cfg: this whole module is gated on
    // `transport-link-tcp`, so reaching this constant IS the tcp predicate.
    "tcp",
    #[cfg(feature = "transport-link-udp")]
    "udp",
    #[cfg(feature = "transport-link-tls")]
    "tls",
    #[cfg(feature = "transport-link-quic")]
    "quic",
    #[cfg(feature = "transport-link-serial")]
    "serial",
    #[cfg(feature = "transport-link-unixsock")]
    "unixsock-stream",
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    "unixpipe",
    #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
    "vsock",
    #[cfg(feature = "transport-link-ws")]
    "ws",
];

/// The sentence every cfg-off arm of [`dial_locator`] / [`bind_locator`] puts
/// in its `Unsupported` error, minus the feature name. It is what tells a
/// "this build lacks the backend" refusal apart from "the address did not
/// take" or "no cert was supplied", and so it is the discriminator
/// [`COMPILED_IN_LINK_SCHEMES`] is checked against.
pub const NOT_COMPILED_IN_MARKER: &str = "requires the transport-link-";

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
        // The `Tcp` arm is unconditional like the `Ip(Proto::Tcp)` arm above —
        // tcp is the always-on baseline stream transport.
        //
        // R311y601 — every remaining proto is wired here too, closing the
        // "`<proto>/HOST` DNS dial is Unsupported" residual the transport-link
        // atoms have carried since R311y305. zenoh resolves a locator name for
        // EVERY link family, not just tcp — `get_tls_addr`
        // (`io/zenoh-links/zenoh-link-tls/src/utils.rs:590`), `get_ws_addr`
        // (`zenoh-link-ws/src/lib.rs:79`) and `get_quic_addr`
        // (`zenoh-link-quic/src/utils.rs:502`) are the same `lookup_host` call
        // three times — so refusing one was a parity gap, not a narrowing. The
        // backend primitives take a `SocketAddr`, so each arm resolves through
        // the [`resolve_locator_addrs`] SSOT and walks the candidates with
        // [`first_reachable`]; the arm is otherwise its numeric twin verbatim.
        //
        // The match is EXHAUSTIVE per proto, with a `#[cfg(not(..))]` twin for
        // each backend — the shape `dial_locator`'s `Ip` arm and `bind_locator`
        // both already use, and the reason the former `other` catch-all is gone:
        // a NEW `Proto` variant must force a compile-time decision here rather
        // than silently inheriting "name dial unsupported" (the R311y408 lesson,
        // applied to the second match in this function).
        AnyLocator::Named {
            proto,
            host,
            port,
            iface,
        } => match proto {
            Proto::Tcp => Ok(DialedLink::Tcp(
                dial_tcp_host(&format!("{host}:{port}"), iface.as_deref()).await?,
            )),
            // R311y524 — a `udp/<name>:<port>` dial resolves like tcp's. pico
            // treats a named UDP endpoint as ordinary, resolving it through
            // `getaddrinfo(.., SOCK_DGRAM, IPPROTO_UDP)`
            // (`src/link/transport/udp/udp_posix.c:32-40`), so rejecting one was
            // a parity gap rather than a deliberate narrowing. The resolved
            // address is carried out of the dial because `DialedLink::Udp` needs
            // the concrete peer, which a name cannot supply.
            #[cfg(feature = "transport-link-udp")]
            Proto::Udp => {
                let (socket, peer) =
                    dial_udp_host(&format!("{host}:{port}"), iface.as_deref()).await?;
                Ok(DialedLink::Udp { socket, peer })
            }
            #[cfg(not(feature = "transport-link-udp"))]
            Proto::Udp => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "udp session-open requires the transport-link-udp feature",
            )),
            // A `ws/NAME:port` dial: resolve, then the numeric arm's `dial_ws`
            // (TCP connect + RFC6455 client handshake) per candidate. The
            // request URI `dial_ws` builds carries the RESOLVED address, exactly
            // as zenoh's `get_ws_url` does — it formats the URL from
            // `get_ws_addr(..)`, the resolved `SocketAddr`, not from the name
            // (`zenoh-link-ws/src/lib.rs:86-93`).
            #[cfg(feature = "transport-link-ws")]
            Proto::Ws => {
                let addrs = resolve_locator_addrs(&host, port).await?;
                let iface = iface.as_deref();
                Ok(DialedLink::Ws(Box::new(
                    first_reachable(addrs, &format!("ws/{host}:{port}"), |addr| {
                        dial_ws(addr, iface)
                    })
                    .await?,
                )))
            }
            #[cfg(not(feature = "transport-link-ws"))]
            Proto::Ws => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ws session-open requires the transport-link-ws feature",
            )),
            // A `tls/NAME:port` dial, and the SNI is the one place a named
            // locator is NOT its numeric twin: the name in the locator IS the
            // verified server name, which is what zenoh does
            // (`get_tls_server_name` = `ServerName::try_from(get_tls_host(..))`,
            // `zenoh-link-tls/src/utils.rs:605`). The numeric arm keeps reading
            // `cfg.tls.server_name` because a numeric locator carries no name to
            // verify against — that decoupling is a wz superset, and it applies
            // exactly where zenoh would need an IP SAN. So the rule is one line:
            // a locator that names the peer verifies against that name; one that
            // does not falls back to the configured name.
            //
            // A name that is not a valid TLS server name (an IP literal reaching
            // this arm cannot, by construction — it would have parsed as `Ip`)
            // is `InvalidInput`, NOT `Unsupported`: the transport is wired, the
            // argument is wrong.
            #[cfg(feature = "transport-link-tls")]
            Proto::Tls => match &cfg.tls {
                Some(t) => {
                    let server_name = ServerName::try_from(host.clone()).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("tls dial: {host:?} is not a valid TLS server name: {e}"),
                        )
                    })?;
                    let addrs = resolve_locator_addrs(&host, port).await?;
                    let iface = iface.as_deref();
                    Ok(DialedLink::Tls(Box::new(
                        first_reachable(addrs, &format!("tls/{host}:{port}"), |addr| {
                            dial_tls(addr, t.client_config.clone(), server_name.clone(), iface)
                        })
                        .await?,
                    )))
                }
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "tls dial requires DialConfig.tls (rustls client config + server name)",
                )),
            },
            #[cfg(not(feature = "transport-link-tls"))]
            Proto::Tls => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tls session-open requires the transport-link-tls feature",
            )),
            // A `quic/NAME:port` dial. The SNI follows the same rule as `tls`
            // above — the locator's name wins over `cfg.quic.server_name` —
            // which is also zenoh's (`get_quic_host` feeds the SNI,
            // `zenoh-link-quic/src/utils.rs:509`). quinn takes the SNI as a
            // `&str`, so there is no `ServerName` parse to fail here.
            #[cfg(feature = "transport-link-quic")]
            Proto::Quic => match &cfg.quic {
                Some(q) => {
                    let addrs = resolve_locator_addrs(&host, port).await?;
                    let iface = iface.as_deref();
                    Ok(DialedLink::Quic(Box::new(
                        first_reachable(addrs, &format!("quic/{host}:{port}"), |addr| {
                            dial_quic(addr, q.client_config.clone(), &host, iface)
                        })
                        .await?,
                    )))
                }
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "quic dial requires DialConfig.quic (rustls client config + SNI name)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic"))]
            Proto::Quic => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quic session-open requires the transport-link-quic feature",
            )),
            // A `quic-datagram/NAME:port` dial — the datagram twin of the arm
            // above, sharing `cfg.quic`'s cert and the locator-name SNI rule.
            #[cfg(feature = "transport-link-quic-datagram")]
            Proto::QuicDatagram => match &cfg.quic {
                Some(q) => {
                    let addrs = resolve_locator_addrs(&host, port).await?;
                    let iface = iface.as_deref();
                    Ok(DialedLink::QuicDatagram(Box::new(
                        first_reachable(addrs, &format!("quic-datagram/{host}:{port}"), |addr| {
                            dial_quic_datagram(addr, q.client_config.clone(), &host, iface)
                        })
                        .await?,
                    )))
                }
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "quic-datagram dial requires DialConfig.quic (rustls client config + SNI name)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic-datagram"))]
            Proto::QuicDatagram => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quic-datagram session-open requires the transport-link-quic-datagram feature",
            )),
        },
        // R311nv — a `serial/...` endpoint dials through the tty backend:
        // `dial_serial` opens the device AND drives the serial-link
        // handshake (INIT -> INIT|ACK) to Connected before returning, so the
        // wrapped stream is ready for the uniform steady-state split. The
        // Initiator role is correct here: `dial_locator` is the dial (Initiator)
        // seam; the Responder side comes up via `accept_serial`.
        #[cfg(feature = "transport-link-serial")]
        AnyLocator::Serial(ep) => Ok(DialedLink::Serial {
            stream: dial_serial(&ep).await?,
            endpoint: ep,
        }),
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
        // R311y10 / R311y392 — a `unixpipe/...` endpoint dials through the
        // named-FIFO backend: `dial_unixpipe` runs the client half of the zenoh
        // invitation handshake (detect the listener, reserve a dedicated pair,
        // 3-way suffix confirm) and returns the connected dedicated pair (no
        // post-dial session handshake — ready for the uniform split, like
        // unixsock). ASYNC now (the invitation handshake awaits the peer), running
        // within the tokio runtime this async dial seam provides. No cert config
        // (like unixsock/udp).
        #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
        AnyLocator::Unixpipe(ep) => Ok(DialedLink::Unixpipe(
            dial_unixpipe(&ep.path, ep.file_mask).await?,
        )),
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

/// Why a configured MESH dial target did not resolve to the numeric locator a
/// face loop holds in `FaceSources::dial_targets`.
///
/// Three outcomes, kept apart because they are three different operator
/// mistakes: the string is not an endpoint at all, it is a perfectly good
/// endpoint whose SHAPE has no address to identify it by, or it named a host
/// that does not resolve. Before R311y809 all three arrived as one
/// `invalid --connect dial target`, because the mesh hosts parsed the string
/// with a bare `str::parse::<SocketAddr>()` instead of the shared classifier.
#[derive(Debug)]
pub enum DialTargetError {
    /// Not a locator, and not the scheme-less `HOST:PORT` convenience either.
    /// Carries `plan_endpoint`'s typed reason (a code span, not a link: that
    /// classifier is `pub(crate)`, and a public doc linking a private item is
    /// exactly what Layer C1bz counts).
    Malformed(AnyLocatorError),
    /// A well-formed locator whose scheme the mesh DIAL side cannot carry —
    /// the endpoint shapes with no `SocketAddr`: `serial` / `unixsock-stream` /
    /// `unixpipe` / `vsock`.
    ///
    /// R2233 (open-debt item 585) — this used to mean "everything except
    /// `tcp`", because `accept_loop::dial_face` opened a bare
    /// `TcpStream::connect` and bypassed the [`dial_locator`] scheme
    /// dispatcher entirely. The dial side now goes THROUGH that dispatcher, so
    /// every IP-family scheme (`tcp` / `udp` / `tls` / `ws` / `quic` /
    /// `quic-datagram`) is mesh-dialable and this variant reports only what is
    /// still genuinely out of scope.
    ///
    /// The surviving limit is an IDENTITY one, not a transport one: before the
    /// handshake a mesh dial target's only name is its address (`accept_loop`'s
    /// dial dedup, the `desired` set, and the per-address re-dial schedule all
    /// key on it), and these four endpoint shapes have no address to be named
    /// by. Admitting one means giving that arm its own pre-handshake identity
    /// first — see [`mesh_dial_plan`], which is where the classification lives.
    UnsupportedScheme {
        /// The locator as configured, so the operator sees their own string.
        target: String,
        /// The scheme token that cannot be dialed on this side.
        scheme: &'static str,
    },
    /// An IP-family DNS name that did not resolve.
    Resolve(io::Error),
}

impl std::fmt::Display for DialTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "not a dialable endpoint: {e:?}"),
            Self::UnsupportedScheme { target, scheme } => write!(
                f,
                "{target:?} is a valid {scheme} locator, but a {scheme} endpoint has \
                 no address to identify it by before the handshake — which is what \
                 the mesh dial's dedup and its re-dial schedule key on; \
                 see session_open::mesh_dial_plan"
            ),
            Self::Resolve(e) => write!(f, "the host did not resolve: {e}"),
        }
    }
}

impl std::error::Error for DialTargetError {}

impl From<DialTargetError> for io::Error {
    /// The mesh hosts thread `io::Result`; this keeps the typed reason as the
    /// message rather than flattening every arm to one string at each site.
    fn from(e: DialTargetError) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
    }
}

/// Split a mesh dial target into the numeric IP endpoint the loop dials — the
/// dial PLAN — or hand the locator back when it has no such endpoint.
///
/// THE one place that answers "can the mesh dial side carry this locator", and
/// it answers with the [`ParsedLocator`] rather than a boolean so the caller
/// cannot re-derive the address by a second route. Both the configuration-time
/// resolver ([`resolve_mesh_dial_target`]) and the face loop's own seam read
/// it, so the policy is stated once.
///
/// `Ok` for every IP-family endpoint: it carries a `SocketAddr`, which is the
/// mesh dial's PRE-HANDSHAKE IDENTITY — the dedup key for "am I already dialing
/// this", the `desired` connect-set member, and the per-address re-dial
/// schedule's key. The scheme itself is no longer part of the question, because
/// [`dial_locator`] dispatches on it (R2233, open-debt item 585).
///
/// `Err` — carrying the locator back so the caller reports it in its own idiom —
/// for the four endpoint shapes that have no `SocketAddr` at all
/// (`serial` / `unixsock-stream` / `unixpipe` / `vsock`) and for
/// [`AnyLocator::Named`], whose address exists only after a DNS resolution this
/// synchronous seam deliberately does not perform: the face loop must never
/// block on a resolver, so a name is resolved at configuration time by
/// [`resolve_mesh_dial_target`] and reaches the loop already numeric.
pub fn mesh_dial_plan(locator: AnyLocator) -> Result<ParsedLocator, AnyLocator> {
    match locator {
        AnyLocator::Ip(parsed) => Ok(parsed),
        // Exhaustive, no catch-all: a new `AnyLocator` variant must force a
        // decision about its pre-handshake identity here rather than silently
        // inheriting "not mesh-dialable" (the R311y408 lesson).
        other @ (AnyLocator::Named { .. }
        | AnyLocator::Serial(_)
        | AnyLocator::Unixsock(_)
        | AnyLocator::Unixpipe(_)
        | AnyLocator::Vsock(_)) => Err(other),
    }
}

/// The scheme token of any [`AnyLocator`], for the messages that have to name
/// the scheme they are refusing.
///
/// Total by construction (every variant, every [`Proto`]) so no caller needs an
/// `unreachable!` arm — the shape the previous spelling of this mapping needed,
/// and the reason it is lifted out of the refusal site.
pub fn locator_scheme(locator: &AnyLocator) -> &'static str {
    fn proto_scheme(proto: Proto) -> &'static str {
        match proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Tls => "tls",
            Proto::Ws => "ws",
            Proto::Quic => "quic",
            Proto::QuicDatagram => "quic-datagram",
        }
    }
    match locator {
        AnyLocator::Ip(p) => proto_scheme(p.proto),
        AnyLocator::Named { proto, .. } => proto_scheme(*proto),
        AnyLocator::Serial(_) => "serial",
        AnyLocator::Unixsock(_) => "unixsock-stream",
        AnyLocator::Unixpipe(_) => "unixpipe",
        AnyLocator::Vsock(_) => "vsock",
    }
}

/// Resolve ONE configured mesh dial target — a `--connect`-style endpoint
/// string — into the numeric [`AnyLocator`] a face loop dials.
///
/// R2233 (open-debt item 585) — this used to return a bare [`SocketAddr`] and
/// reject every non-`tcp` scheme, because the loop dialed with
/// `TcpStream::connect`. It returns the LOCATOR now: the scheme has to survive
/// to the loop for [`dial_locator`] to dispatch on, and the address the loop
/// still needs as its dedup key is carried inside it ([`mesh_dial_plan`] is the
/// accessor, so the two can never be derived apart).
///
/// The returned locator is always [`AnyLocator::Ip`] — a name is resolved HERE,
/// at configuration time, where blocking on a resolver is free, and never in
/// the loop.
///
/// What this ALSO fixes is that the resolution was never the shared one. Both
/// mesh hosts parsed their `--connect` targets with a bare
/// `str::parse::<SocketAddr>()`, so a `tcp/1.2.3.4:7447` — zenoh's own
/// spelling, and what every other wz entry point accepts — was rejected as
/// malformed while the bare `1.2.3.4:7447` worked, and a DNS-named peer was
/// impossible. Routing through `plan_endpoint` — a code span because that
/// classifier is `pub(crate)` — makes the mesh read the same grammar as
/// `--listen`, `--connect` and the static deploy list:
///
/// - `tcp/HOST:PORT`, and the scheme-less `HOST:PORT` convenience, both land
///   as `tcp` through the one classifier rather than through two code paths.
/// - A DNS name of ANY IP-family scheme resolves through
///   [`resolve_locator_addrs`], the same resolver the single-session dial uses
///   (R2233 widened this from `tcp` alone: the resolution is the address
///   token's business, not the scheme's).
/// - An endpoint shape with no address at all gets
///   [`DialTargetError::UnsupportedScheme`], which REPORTS the surviving
///   pre-handshake-identity limit instead of disguising it as a malformed
///   string.
///
/// ONE DOCUMENTED DIVERGENCE from wz's single-session dial: a resolved name
/// yields the FIRST address, where `dial_locator` walks all of them. zenoh
/// takes the first too (`.next()`), and here it is additionally forced — the
/// address is the loop's dedup key, so "this target" has to be one address,
/// not a set.
pub async fn resolve_mesh_dial_target(target: &str) -> Result<AnyLocator, DialTargetError> {
    // A name is resolved HERE so the loop never blocks on a resolver; the
    // reconstruction keeps the scheme and the `#iface=` bind, and cannot keep
    // the multicast tail because `Named` does not carry one (a DNS-named
    // endpoint is not a multicast group).
    let locator = match plan_endpoint(target).map_err(DialTargetError::Malformed)? {
        AnyLocator::Named {
            proto,
            host,
            port,
            iface,
        } => {
            let addrs = crate::link_pipeline::resolve_locator_addrs(&host, port)
                .await
                .map_err(DialTargetError::Resolve)?;
            // `resolve_locator_addrs` rejects an empty result itself, so the
            // first element exists; taking it is zenoh's `.next()`.
            AnyLocator::Ip(ParsedLocator {
                proto,
                addr: addrs[0],
                iface,
                mcast_ttl: None,
                mcast_join: Vec::new(),
            })
        }
        other => other,
    };
    // ONE classification, shared with the loop's own seam: a locator this
    // rejects is one with no pre-handshake identity, whatever its scheme.
    match mesh_dial_plan(locator) {
        Ok(parsed) => Ok(AnyLocator::Ip(parsed)),
        Err(rejected) => Err(unsupported_mesh_dial(target, locator_scheme(&rejected))),
    }
}

/// One place builds the capability rejection, so every arm above reports it
/// the same way and the operator's own string always survives into the error.
fn unsupported_mesh_dial(target: &str, scheme: &'static str) -> DialTargetError {
    DialTargetError::UnsupportedScheme {
        target: target.to_string(),
        scheme,
    }
}

/// Accept-side dispatcher for [`accept_endpoint`]: bind + accept ONE inbound
/// link for the [`AnyLocator`]'s scheme, returning the same [`DialedLink`]
/// union the dial path produces so [`accept_and_open_session`] consumes one
/// concrete type whatever the role.
///
/// R311qa — delegates to [`bind_locator`] (the bind half, the SSOT the
/// multi-peer [`accept_loop`](crate::accept_loop) shares) then [`accept_bound`]
/// (accept ONE), rather than inlining the bind. The `Unsupported` still
/// surfaced here originates in `bind_locator`'s scheme match.
///
/// R311y805 — the asymmetry this doc used to describe is GONE, and the record of
/// it is kept because it was the reason the gap survived so long. It read: "the
/// NON-tcp handling is where the symmetry with `dial_locator` deliberately STOPS
/// ... accept_locator returns a single feature-blind `Unsupported` for ws/tls/udp
/// REGARDLESS of feature", and it argued that wiring an acceptor "is not a one-arm
/// change". Stage by stage every scheme was wired anyway — ws (R311y374), tls
/// (R311y375), unixsock/vsock/unixpipe (R311y378-380, y392), udp (R311y381-382),
/// quic (R311y401), quic-datagram (R311y408), and serial LAST (R311y805) — so
/// today accept_locator matches dial_locator arm for arm: every scheme has a
/// `#[cfg(feature)]` wired arm plus a `#[cfg(not)]` typed-`Unsupported` twin, and
/// the only feature-BLIND rejection left is a tls/quic bind with no server cert
/// (opt-in material, not an unwired seam). What remains asymmetric is not the
/// dispatch but the SHAPE of each accept: tls/quic/serial defer a peer-controlled
/// handshake to [`AcceptedLink::handshake`], which dial runs inline.
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
/// mirror of `dial_locator`'s [`DialedLink`]): `tcp` / `ws` / `tls` bind a
/// `TcpListener` (ws upgrades and tls handshakes per-accept), `udp` / `quic` /
/// `quic-datagram` bind a datagram socket or QUIC endpoint, `unixsock` / `vsock` /
/// `unixpipe` bind their same-host listener, and `serial` binds NOTHING (a tty has
/// no listen queue — `SerialListener` records the endpoint and the accept opens
/// the device). R311y805 wired the last of them, so no scheme is an unwired
/// extension point any more; what remains is per-scheme material, not dispatch — a
/// `tls` / `quic` listen without a server cert in [`AcceptConfig`] is a typed
/// `Unsupported`, and every scheme has a `#[cfg(not(feature))]` twin for a build
/// without its backend.
pub async fn bind_locator(locator: AnyLocator, cfg: &AcceptConfig) -> io::Result<BoundListener> {
    fn unsupported(detail: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("listen/accept is wired only for tcp; {detail}"),
        )
    }
    // `cfg` is consumed only by the tls + quic arms (their server cert); inert on a
    // build with neither backend (mirrors dial_locator's DialConfig usage).
    #[cfg(not(any(feature = "transport-link-tls", feature = "transport-link-quic")))]
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
            // backend off, a typed `Unsupported` (the same shape as the udp/quic
            // arms), keeping the `Proto` match EXHAUSTIVE — the accept mirror of
            // dial_locator's ws arm (R311y408 removed the Ip-arm catch-all).
            #[cfg(feature = "transport-link-ws")]
            Proto::Ws => Ok(BoundListener::Ws(
                bind_tcp(ip.addr, ip.iface.as_deref()).await?,
            )),
            #[cfg(not(feature = "transport-link-ws"))]
            Proto::Ws => Err(unsupported(
                "ws acceptor requires the transport-link-ws feature",
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
            // With the backend off, a typed `Unsupported` (the same shape as the
            // udp/quic arms), keeping the `Proto` match EXHAUSTIVE — the accept
            // mirror of dial_locator's tls not(feature) arm.
            #[cfg(not(feature = "transport-link-tls"))]
            Proto::Tls => Err(unsupported(
                "tls acceptor requires the transport-link-tls feature",
            )),
            // R311y382 — a `udp/...` acceptor binds the datagram socket on the
            // listen addr and spawns the demux pump (`bind_udp_demux`) into a
            // multi-peer `BoundListener::Udp`; `accept_raw` awaits each new src.
            // The accept mirror of dial_locator's `Proto::Udp => DialedLink::Udp`,
            // gated the same way, with the cfg-off twin returning a typed
            // `Unsupported` (a clearer message than the `other` catch-all).
            #[cfg(feature = "transport-link-udp")]
            Proto::Udp => Ok(BoundListener::Udp(
                bind_udp_demux(ip.addr, ip.iface.as_deref()).await?,
            )),
            #[cfg(not(feature = "transport-link-udp"))]
            Proto::Udp => Err(unsupported(
                "udp acceptor requires the transport-link-udp feature",
            )),
            // R311y401 — a `quic/...` acceptor binds a QUIC server `Endpoint` on the
            // listen addr, the crypto config baked in from `AcceptConfig.quic` (the
            // QUIC twin of the `Proto::Tls` arm). `bind_quic` is SYNC (`?`, not
            // `.await`). R311y454 — it DOES honour `#iface=` now: the claim that it
            // "takes no iface (a quinn Endpoint owns its socket)" was true only of
            // quinn's CONVENIENCE constructor, and it was this comment that recorded
            // the residual. `quic_server_endpoint` pre-binds a device-bound socket
            // and hands it to `Endpoint::new` instead, so the listen half is now
            // symmetric with the dial half and with every sibling acceptor above.
            // Absent the cert config => typed `Unsupported`, so a QUIC acceptor is
            // opt-in — the accept mirror of dial_locator's `Proto::Quic => match &cfg.quic`.
            #[cfg(feature = "transport-link-quic")]
            Proto::Quic => match &cfg.quic {
                Some(q) => Ok(BoundListener::Quic(bind_quic(
                    ip.addr,
                    q.server_config.clone(),
                    ip.iface.as_deref(),
                )?)),
                None => Err(unsupported(
                    "quic acceptor requires AcceptConfig.quic (a server cert + key)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic"))]
            Proto::Quic => Err(unsupported(
                "quic acceptor requires the transport-link-quic feature",
            )),
            // R311y408 — a `quic-datagram/...` acceptor binds a QUIC server
            // `Endpoint` serving the unreliable-datagram transport (RFC9221), the
            // crypto config baked in from `AcceptConfig.quic` (datagrams reuse the
            // SAME cert as the stream backend, matching zenoh's shared
            // `transport.link.tls` block). The exact datagram twin of the
            // `Proto::Quic` arm above: `bind_quic_datagram` is SYNC (`?`, not
            // `.await`) and — since R311y454, like its stream sibling — HONOURS
            // `#iface=`, through the one shared `quic_server_endpoint`. Absent
            // the cert config => typed `Unsupported`, so it is opt-in — the accept
            // mirror of dial_locator's `Proto::QuicDatagram => match &cfg.quic`.
            #[cfg(feature = "transport-link-quic-datagram")]
            Proto::QuicDatagram => match &cfg.quic {
                Some(q) => Ok(BoundListener::QuicDatagram(bind_quic_datagram(
                    ip.addr,
                    q.server_config.clone(),
                    ip.iface.as_deref(),
                )?)),
                None => Err(unsupported(
                    "quic-datagram acceptor requires AcceptConfig.quic (a server cert + key)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic-datagram"))]
            Proto::QuicDatagram => Err(unsupported(
                "quic-datagram acceptor requires the transport-link-quic-datagram feature",
            )),
            // R311y408 — the `Proto` match is EXHAUSTIVE: all 6 IP-family variants
            // carry a feature + not(feature) arm, mirroring dial_locator. No
            // catch-all — a NEW `Proto` variant forces a compile-time decision here
            // (the fail-fast the once-present `other` arm silently absorbed).
            // Adding the always-covered QuicDatagram arm exhausted the enum, which
            // made that catch-all unreachable under any ws+tls build (a
            // -D unreachable-patterns error the partial `--features quic-datagram`
            // build never surfaced — the y408 feature-split lesson).
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
            // R311y601 — the remaining three NAME acceptors, so the listen half
            // resolves names for every scheme its dial half does. Each resolves
            // through the [`resolve_locator_addrs`] SSOT and binds the first
            // candidate that takes, mirroring `bind_tcp_host`'s walk; the arm is
            // otherwise its numeric twin. Without these a deploy could dial
            // `quic/HOST:port` but not listen on one, and the asymmetry would
            // read as a transport gap rather than a missing four lines.
            #[cfg(feature = "transport-link-udp")]
            Proto::Udp => {
                let addrs = resolve_locator_addrs(&host, port).await?;
                let iface = iface.as_deref();
                Ok(BoundListener::Udp(
                    first_reachable(addrs, &format!("udp/{host}:{port}"), |addr| {
                        bind_udp_demux(addr, iface)
                    })
                    .await?,
                ))
            }
            #[cfg(not(feature = "transport-link-udp"))]
            Proto::Udp => Err(unsupported(
                "udp acceptor requires the transport-link-udp feature",
            )),
            // `bind_quic` / `bind_quic_datagram` are SYNC, so the walk's async
            // contract is satisfied by an `async move` wrapper rather than by a
            // different helper — the resolve-then-walk shape stays one.
            #[cfg(feature = "transport-link-quic")]
            Proto::Quic => match &cfg.quic {
                Some(q) => {
                    let addrs = resolve_locator_addrs(&host, port).await?;
                    let iface = iface.as_deref();
                    Ok(BoundListener::Quic(
                        first_reachable(addrs, &format!("quic/{host}:{port}"), |addr| async move {
                            bind_quic(addr, q.server_config.clone(), iface)
                        })
                        .await?,
                    ))
                }
                None => Err(unsupported(
                    "quic acceptor requires AcceptConfig.quic (a server cert + key)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic"))]
            Proto::Quic => Err(unsupported(
                "quic acceptor requires the transport-link-quic feature",
            )),
            #[cfg(feature = "transport-link-quic-datagram")]
            Proto::QuicDatagram => match &cfg.quic {
                Some(q) => {
                    let addrs = resolve_locator_addrs(&host, port).await?;
                    let iface = iface.as_deref();
                    Ok(BoundListener::QuicDatagram(
                        first_reachable(
                            addrs,
                            &format!("quic-datagram/{host}:{port}"),
                            |addr| async move {
                                bind_quic_datagram(addr, q.server_config.clone(), iface)
                            },
                        )
                        .await?,
                    ))
                }
                None => Err(unsupported(
                    "quic-datagram acceptor requires AcceptConfig.quic (a server cert + key)",
                )),
            },
            #[cfg(not(feature = "transport-link-quic-datagram"))]
            Proto::QuicDatagram => Err(unsupported(
                "quic-datagram acceptor requires the transport-link-quic-datagram feature",
            )),
            // With the ws / tls BACKEND off their arms above vanish, so the
            // `Proto` match is exhaustive only through these twins — the same
            // cfg/not(cfg) pairing every sibling arm carries. No catch-all: a
            // NEW `Proto` variant must force a decision here (R311y408).
            #[cfg(not(feature = "transport-link-ws"))]
            Proto::Ws => Err(unsupported(
                "ws acceptor requires the transport-link-ws feature",
            )),
            #[cfg(not(feature = "transport-link-tls"))]
            Proto::Tls => Err(unsupported(
                "tls acceptor requires the transport-link-tls feature",
            )),
        },
        // R311y805 — the LAST unwired acceptor scheme. A serial "bind" opens
        // nothing: `SerialListener` records the endpoint and `accept_raw` opens the
        // device, which is zenoh's own shape (`new_listener` creates no port
        // either; its accept task does, `unicast.rs:321-373`). The comment this
        // replaced ("a tty open, not a listen bind") was a true observation used as
        // a reason not to wire it -- but the seam does not require a listen queue,
        // only a `BoundListener` that can accept, and every non-socket sibling
        // (unixpipe's FIFO rendezvous, the udp demux) had already established that.
        // `AnyLocator::Serial` is an ALWAYS-present variant (the locator GRAMMAR is
        // ungated in wz-session-core, only the tty BACKEND is gated), so the arm
        // exists in both feature configs, exactly as the dial arm does.
        #[cfg(feature = "transport-link-serial")]
        AnyLocator::Serial(endpoint) => Ok(BoundListener::Serial(SerialListener {
            endpoint,
            armed: true,
        })),
        #[cfg(not(feature = "transport-link-serial"))]
        AnyLocator::Serial(_ep) => Err(unsupported(
            "serial acceptor requires the transport-link-serial feature",
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
        // R311y379 (accept-symmetry Stage 4, second arm) — a vsock acceptor
        // binds a `VsockListener` (`bind_vsock`) into `BoundListener::Vsock`, the
        // accept-side mirror of `dial_locator`'s `AnyLocator::Vsock =>
        // DialedLink::Vsock`. Like the dial arm, gated `all(transport-link-vsock,
        // target_os = "linux")` (AF_VSOCK is Linux-only), with the
        // cfg-off/non-Linux twin returning a typed `Unsupported` so the
        // always-present `AnyLocator::Vsock` variant stays exhaustive on every
        // target.
        #[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]
        AnyLocator::Vsock(ep) => Ok(BoundListener::Vsock(bind_vsock(ep.cid, ep.port)?)),
        #[cfg(not(all(feature = "transport-link-vsock", target_os = "linux")))]
        AnyLocator::Vsock(_ep) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vsock accept requires the transport-link-vsock feature on Linux",
        )),
        // R311y380 / R311y392 (accept-symmetry Stage 4, third arm) — a unixpipe
        // acceptor `mkfifo`s the base request channel + spawns the multi-client
        // acceptor task (`bind_unixpipe`, now ASYNC like `bind_udp_demux` — it
        // spawns a task) into `BoundListener::Unixpipe`, the accept-side mirror of
        // `dial_locator`'s `AnyLocator::Unixpipe => DialedLink::Unixpipe`. Like the
        // vsock arm, gated `all(transport-link-unixpipe, target_os = "linux")` (the
        // FIFO `read_write` open-rendezvous is Linux-only), with the
        // cfg-off/non-Linux twin returning a typed `Unsupported` so the
        // always-present `AnyLocator::Unixpipe` variant (ungated in
        // wz-session-core) stays exhaustive on every target. `udp` is the remaining
        // acceptor extension point.
        #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
        AnyLocator::Unixpipe(ep) => Ok(BoundListener::Unixpipe(
            bind_unixpipe(&ep.path, ep.file_mask).await?,
        )),
        #[cfg(not(all(feature = "transport-link-unixpipe", target_os = "linux")))]
        AnyLocator::Unixpipe(_ep) => Err(unsupported(
            "unixpipe accept requires the transport-link-unixpipe feature on Linux",
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
async fn accept_bound(mut listener: BoundListener) -> io::Result<DialedLink> {
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

/// Accept ONE peer from a *borrowed* [`BoundListener`] — the multi-accept
/// counterpart of `accept_bound` (which CONSUMES the listener for the one-shot
/// session-open contract). Borrowing keeps the listener bound across accepts, so
/// a host that serves N SEQUENTIAL clients binds once via [`bind_endpoint`] then
/// loops this + [`accept_and_open_session`], opening and driving ONE session at a
/// time (the caller's loop owns the re-accept). This is the bind-once/accept-many
/// seam at the session-open layer that the [`crate::accept_loop`] docstring
/// references — distinct from the full [`accept_loop`](crate::accept_loop), which
/// holds N CONCURRENT faces: this seam suits a per-client-Session host (e.g. the
/// demo's `--storage-host` admin mode, where a pico `z_put` then a pico `z_get`
/// are separate one-shot connections a single 1:1 unicast Session cannot both
/// serve).
///
/// R2355 — this took a `&TcpListener` and was the LAST seam in the tree that
/// forced a listen endpoint down to tcp. R311y376 generalized the concurrent
/// [`accept_loop`](crate::accept_loop) to hold any [`BoundListener`], and the
/// one-shot `accept_bound` was never tcp-only; this sequential seam was left
/// behind, so a `--storage-host --listen ws/...` failed at bind with a typed
/// `Unsupported` while the same string on `--router` or `--listen` worked. It now
/// runs the same two steps its two siblings do — [`BoundListener::accept_raw`]
/// then [`AcceptedLink::handshake`] — so the per-scheme SERVER upgrade (ws
/// RFC6455, tls rustls) happens here rather than being unreachable, and the
/// mechanism stays in [`AcceptedLink`] rather than being spelled a third time.
/// The "; ws server upgrade" / "; tls server handshake" note is read BEFORE the
/// handshake consumes `accepted` and logged only AFTER it succeeds, exactly as in
/// `accept_bound`, so a failed upgrade never logs a spurious "accepted peer".
///
/// R2355 — `accept_bound` is a CODE SPAN throughout this doc, not an intra-doc
/// link. It is a private fn and this one is `pub`, so each `[`..`]` form is a
/// broken public-doc link that Layer C1bz counts; rewriting this doc took that
/// from two to three and pushed the crate one over budget. A span says the same
/// thing and resolves, which is the repair the budget asks for — the budget
/// follows the links, never the other way round.
pub async fn accept_bound_on(listener: &mut BoundListener) -> io::Result<DialedLink> {
    let (accepted, peer) = listener.accept_raw().await?;
    let note = accepted.server_handshake_note();
    let link = accepted.handshake().await?;
    log::info!("wz accept: accepted peer {peer}{note}");
    Ok(link)
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
/// (was: projected to a raw [`tokio::net::TcpListener`] via a
/// `BoundListener::into_tcp` accessor, the tcp-only-loop restriction). The
/// cert-free shorthand for [`bind_endpoint_with_config`]: a `tcp` / `ws` / `udp`
/// listen binds; a `tls` / `quic` listen surfaces `Unsupported` because the
/// default [`AcceptConfig`] carries no server cert. A mesh `--router`/`--peer`
/// that threads its `--<scheme>-cert` uses [`bind_endpoint_with_config`]
/// (R311y405).
///
/// R2355 — EVERY caller of this seam now holds the [`BoundListener`]. The
/// sequential storage-host seam was the last one projecting to tcp, and
/// [`accept_bound_on`] borrows the listener instead, so `into_tcp` is deleted
/// rather than merely unused.
pub async fn bind_endpoint(listen: &str) -> io::Result<BoundListener> {
    bind_endpoint_with_config(listen, &AcceptConfig::default()).await
}

/// [`bind_endpoint`] with a caller-supplied [`AcceptConfig`] — the cert-threading
/// bind seam for a mesh `--router`/`--peer` that binds a `tls/...` or `quic/...`
/// listen, its `AcceptConfig.{tls,quic}` carrying the server cert the acceptor
/// presents (R311y405). [`plan_endpoint`] classifies the string exactly as
/// [`bind_endpoint`] does; [`bind_locator`] performs the bind, consuming `cfg`'s
/// server cert where the scheme needs it. The bind-only twin of [`accept_endpoint`]
/// (which already takes a `cfg`), so the accept and bind seams thread a cert the
/// same way; [`bind_endpoint`] is the `AcceptConfig::default()` (cert-free) form.
pub async fn bind_endpoint_with_config(
    listen: &str,
    cfg: &AcceptConfig,
) -> io::Result<BoundListener> {
    let locator = plan_endpoint(listen).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wz listen: malformed / unsupported --listen {listen:?}: {e:?}"),
        )
    })?;
    bind_locator(locator, cfg).await
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
    WriterHandle,
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
    WriterHandle,
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
        // R311y382 — an accepted demux face: RX is the pump's per-src channel,
        // TX the shared listener socket (both in `inputs`), wired the same
        // `InboundLink::Udp` shape as the dial side.
        #[cfg(feature = "transport-link-udp")]
        DialedLink::UdpDemuxed { inputs, peer } => {
            let (inbound, outbound, handle) = wire_udp_demuxed(inputs, peer);
            (InboundLink::Udp(inbound), outbound, handle)
        }
        #[cfg(feature = "transport-link-serial")]
        DialedLink::Serial { stream, endpoint } => {
            let (inbound, outbound, handle) = wire_serial_stream(stream, &endpoint);
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
    pub writer_handle: WriterHandle,
    pub clock: TokioTime,
}

// R311y519 — the wall-clock drain budget that used to live here
// (`WRITER_DRAIN_MS`) is GONE, not relocated. It could not tell a wedged peer
// from a slow one, so it expired mid-progress on a loaded host and discarded
// frames `z_put` had already answered `Z_OK` for. Its wedged-peer half moved
// onto ONE write as `writer_queue::WRITER_STALL_MS`, and its termination half
// became the queue SEAL — see `crate::writer_queue` for the full argument.

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

    /// R311y463 — the remote peer's WhatAmI role, or `None` if the INIT exchange
    /// never surfaced it. The sibling of [`Self::peer_zid`]: together they are the
    /// TWO inputs the routing boundary classifies a face by
    /// (`tier_of(peer_whatami_routing(..))`), and the tier decides whether the face
    /// is eligible for the CLIENT-only token / subscriber future-push and
    /// current-dump paths at all.
    ///
    /// `None` is kept DISTINCT from `Some(Peer)` on purpose, which is why this does
    /// not reuse `peer_whatami_routing`'s warn-and-default-to-Peer: at the routing
    /// boundary defaulting is correct (an unclassifiable face must route nothing
    /// dangerous), but for an OBSERVER "the role never arrived" and "the peer said
    /// peer" are different facts, and conflating them is what makes a face that
    /// silently routes nothing indistinguishable from one that correctly routes
    /// nothing. The wire -> role mapping stays the `WhatAmI::from_wire` SSOT rather
    /// than a second copy here.
    pub fn peer_whatami(&self) -> Option<wz_codecs::whatami::WhatAmI> {
        self.actions
            .peer_whatami_wire()
            .and_then(wz_codecs::whatami::WhatAmI::from_wire)
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
            clock: _,
        } = self;
        drop(inbound);
        drop(engine);
        drop(actions);
        // R311y519 — SEAL, then await to completion. The two local drops above
        // stay: releasing them first is what lets the writer finish a queue no
        // one is still adding to, and the seal is what makes termination
        // independent of whoever ELSE still holds a clone (on the accept path
        // the forwarder's `FaceEntry` does, and under `transport-multilink` it
        // cannot simply be released earlier). The previous wall-clock budget
        // could not distinguish a wedged peer from a slow one and discarded
        // acknowledged frames; that defence now lives on one write.
        writer_handle.drain().await;
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
    /// R311y817 — the peer's InitAck announced a `0x7` PATCH level ABOVE the
    /// one our InitSyn advertised (zenoh `PatchFsm::recv_init_ack`'s
    /// `bail!`, `ext/patch.rs:78-84`; zenoh-pico's `_Z_ERR_GENERIC` at
    /// `unicast/transport.c:142-148`). Same rule family as
    /// [`Self::InitAckCapsRejected`] — "less or equal than the one in the
    /// InitSyn" — applied to the establishment parameter that rides the ext
    /// chain rather than the body, so the body-only caps validator could
    /// never have seen it. The dispatcher took the
    /// `establishment.ext_rejected` arm (Closing with `CloseReason::Generic`,
    /// R311y823 — zenoh closes GENERIC for every extension handler's failure
    /// and reserves INVALID for the body's size parameters); typed separately
    /// because it diagnoses a protocol-revision mismatch, not an over-large
    /// size.
    ///
    /// Ungated, like its sibling above: an open loop's typed vocabulary is
    /// the same in every build, and only the arm that PRODUCES it needs the
    /// codec.
    InitAckPatchRejected,
    /// R3b — a Z_EXT_AUTH method rejected the peer during the handshake (a bad
    /// usrpwd credential, unknown user, missing required sub-ext, or a malformed
    /// auth ext). The dispatcher took the `establishment.ext_rejected` arm
    /// (Closing with `CloseReason::Generic`, wire Close(GENERIC), R311y823);
    /// the open loop surfaces the
    /// carried [`AuthError`](wz_session_core::auth_dispatch::AuthError) here
    /// instead of folding it into [`Self::Terminal`]. The wz mirror of zenoh's
    /// establishment FSM `?`-propagating the usrpwd verify error into a close.
    #[cfg(feature = "session-extauth")]
    AuthRejected(wz_session_core::auth_dispatch::AuthError),
    /// session-extqos (R311y506) — the peer's `init::ext::QoSLink` could not be
    /// reconciled with ours: a priority band on the wrong side of the
    /// containment, a contradicting reliability, both QoS forms at once, or an
    /// invalid z64 body. Every one is a `zerror!` bail-out inside zenoh's
    /// `QoSFsm::recv_init_syn` / `recv_init_ack` that aborts establishment, so
    /// the dispatcher took the `establishment.ext_rejected` arm (Closing with
    /// `CloseReason::Generic`, R311y823) and the typed reason surfaces here
    /// rather than folding into [`Self::Terminal`].
    #[cfg(feature = "session-extqos")]
    QosLinkRejected(wz_session_core::extqos::QosLinkError),
    /// session-extshm (R311y507) — the peer's `init::ext::Shm` challenge body
    /// did not decode. zenoh `bail!`s on this in `recv_init_syn`, aborting
    /// establishment; the dispatcher took the `establishment.ext_rejected` arm
    /// (Closing with `CloseReason::Generic`, R311y823) and the typed reason
    /// surfaces here. Acceptor-only, per that method's asymmetry.
    #[cfg(feature = "session-extshm")]
    ShmChallengeRejected,
    /// session-extshm (R311y507) — the SHM offer was accepted but this node
    /// could not publish its own POSIX auth segment (`/dev/shm` full, not
    /// mounted, permissions). A hard error rather than a silent downgrade.
    #[cfg(feature = "session-extshm")]
    ShmAuthSegment(std::io::Error),
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
    /// The static deploy config's `listen=` / `connect=` pair does not name a
    /// transport half this build can bring up — today only "both at once",
    /// which needs the `_z_new_peer` multi-peer path wz has no analog of.
    /// Raised BEFORE any socket is touched, by
    /// [`resolve_static_config`](wz_session_core::scout_static::resolve_static_config);
    /// pico's own answer to the same pair under `Z_FEATURE_UNICAST_PEER == 0`
    /// is `_Z_ERR_GENERIC` (`vendor/zenoh-pico/src/net/session.c:107-108`).
    /// Distinct from [`Self::NoReachableLocator`], which means the config was
    /// coherent and the peers were not there.
    #[cfg(feature = "scouting-static")]
    BadStaticConfig(wz_session_core::scout_static::StaticConfigError),
    /// R311py — the `--connect`-style string parsed to a valid locator that is
    /// NOT a reconnect target (a `serial/...` endpoint: no client reopen-task
    /// model, pico parity). Only returned by
    /// [`crate::reconnect::reconnect_endpoint`], which narrows the parsed
    /// [`AnyLocator`] to the reconnectable subset; the typed
    /// [`NotReconnectable`](wz_session_core::reconnect::NotReconnectable) is
    /// carried through rather than flattened to a string so the caller can
    /// distinguish it from a malformed-locator [`Self::BadLocator`].
    NotReconnectable(wz_session_core::reconnect::NotReconnectable),
    /// R311y435 — the [`SessionOffer`](wz_session_core::transport_mode::SessionOffer)
    /// asked for a capability whose cargo feature this build does not carry
    /// (e.g. [`TransportMode::LowLatency`](wz_session_core::transport_mode::TransportMode::LowLatency)
    /// without `transport-lowlatency`). Surfaced BEFORE the handshake drives, so
    /// no wire byte is emitted for a session that could not honour its own
    /// offer. Deliberately not a silent downgrade to the universal transport: a
    /// caller that configured the lean path and got the Frame-wrapped one would
    /// discover it only by packet capture. zenoh has no counterpart because its
    /// capabilities are always compiled in; this is the honest half of wz's
    /// compile-time feature elision.
    UnsupportedCapability(wz_session_core::transport_mode::UnsupportedCapability),
    /// R2376 — a reopen attempt's PLAN yielded no candidate to dial: the
    /// scouting window closed with no Hello, so there is no address to try.
    /// pico's `_Z_ERR_SCOUT_NO_RESULTS`, raised at the same point (`_z_open`'s
    /// scout branch, which errors when `len == 0`) and classified the same way
    /// — [`crate::reconnect::ReconnectingSession`]'s transient set admits it,
    /// so the supervisor scouts again after its backoff instead of abandoning
    /// the session.
    ///
    /// Distinct from [`Self::NoReachableLocator`], which means candidates
    /// existed and every one of them failed: this one means the plan produced
    /// none at all, and the two call for different operator action (nobody is
    /// answering the group, versus the peer that answered will not accept).
    NoTargets,
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
    writer_handle: WriterHandle,
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
                    // R311y817 — the ext-chain member of the same rule: the
                    // InitAck's PATCH level exceeded our InitSyn's. Same
                    // shape as the arm above; a distinct typed reason
                    // because a dialler retrying against a peer that speaks
                    // a newer revision needs a different answer than one
                    // that over-claimed a buffer size.
                    #[cfg(feature = "codec-init-body")]
                    DriverLoopOutcome::InitAckPatchRejected => {
                        return Err(OpenError::InitAckPatchRejected);
                    }
                    // R3b — a usrpwd method rejected the peer; the FSM is already
                    // Closing(Invalid). Surface the typed reason (mirrors the
                    // InitAckCapsRejected path) for both the initiator and the
                    // acceptor (both drive through this shared loop).
                    #[cfg(feature = "session-extauth")]
                    DriverLoopOutcome::AuthRejected(e) => {
                        return Err(OpenError::AuthRejected(e));
                    }
                    // session-extqos — the QoSLink containment refused the peer;
                    // the FSM is already Closing(Invalid). Same shape as the two
                    // arms above, for both roles (they share this loop).
                    #[cfg(all(feature = "session-extqos", feature = "codec-init-body"))]
                    DriverLoopOutcome::QosLinkRejected(e) => {
                        return Err(OpenError::QosLinkRejected(e));
                    }
                    // session-extshm — a malformed SHM challenge from an
                    // initiator; the FSM is already Closing(Invalid).
                    #[cfg(all(feature = "session-extshm", feature = "codec-init-body"))]
                    DriverLoopOutcome::ShmChallengeRejected => {
                        return Err(OpenError::ShmChallengeRejected);
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
    connect_and_open_session_with_offer(
        locator,
        params,
        SessionOffer::universal().with_mode(TransportMode::LowLatency),
        cfg,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y435 — the COMPOSING connect: dial the locator, then open with the whole
/// negotiated capability set. The deploy-facing seam; the
/// `connect_and_open_session_with_*` wrappers are each this call with one field
/// set.
///
/// This is what makes a composed session reachable from a real deployment rather
/// than only from a hand-built wz<->wz fixture, which is the gap R311y434 named
/// as its largest deliberate omission: it proved the composed lowlatency +
/// compression wire byte-for-byte between two wz peers, and it proved the lean
/// wire interoperates with zenohd (R311y372), but nothing dialled a zenohd with
/// BOTH offers staged, so the composition of those two proofs was an argument.
#[allow(clippy::too_many_arguments)]
pub async fn connect_and_open_session_with_offer(
    locator: AnyLocator,
    params: SessionInitParams,
    offer: SessionOffer,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    let dialed = dial_locator(locator, cfg).await.map_err(OpenError::Dial)?;
    initiate_and_open_session_with_offer(dialed, params, offer, clock, max_iters, tick_interval_ms)
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
    connect_and_open_session_with_offer(
        locator,
        params,
        SessionOffer::universal().with_mode(TransportMode::Qos),
        cfg,
        clock,
        max_iters,
        tick_interval_ms,
    )
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
    connect_and_open_session_with_offer(
        locator,
        params,
        SessionOffer::universal().with_compression(true),
        cfg,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// session-extshm (R311y507) — create this session's POSIX AUTH SEGMENT and
/// install it, when the offer asks for SHM.
///
/// zenoh builds ONE `AuthUnicast` per transport MANAGER (`manager.rs:295`,
/// under `is_shm`); wz builds one per SESSION, which is a superset in the same
/// direction the per-session `set_qos_offer` already is — one SHM session and
/// one non-SHM session can coexist under one node, and each carries its own
/// challenge. The segment is unlinked when the session's actions drop.
///
/// A failure to create it is a hard error, NOT a silent downgrade: the caller
/// asked for shared memory, and a session that quietly negotiated it away would
/// look identical to one that got it.
fn install_shm_authenticator(
    #[allow(unused_variables)] actions: &SessionLinkActions,
    #[allow(unused_variables)] offer: &SessionOffer,
) -> Result<(), OpenError> {
    #[cfg(feature = "session-extshm")]
    if offer.shm {
        let auth = crate::shm_auth_segment::PosixShmAuthenticator::new()
            .map_err(OpenError::ShmAuthSegment)?;
        actions.install_shm_auth(Box::new(auth));
    }
    Ok(())
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
    connect_and_open_session_with_offer(
        locator,
        params,
        SessionOffer::universal().with_shm(true),
        cfg,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
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
///
/// R2096 (open-debt item 516) — takes the whole [`SessionOffer`], where it used
/// to take a bare `qos: bool`. Two facts had become one: `qos` and `offer.mode`
/// would both have answered "does this session offer the QoS transport", and a
/// pair of parameters that can disagree is exactly the shape [`SessionOffer`]
/// exists to remove (its own doc: the both-on configuration must be
/// unrepresentable, not merely rejected). The OFFER is the SSOT — every caller
/// moved to it — so a node's `lowlatency` / `compression` / `shm` now reach the
/// aggregating dial as well as the single-link one. Before this the same flag
/// reached the wire on `--max-links 1` and nothing at all on `--max-links 2`.
///
/// `band` stays a separate parameter, and that is the same line
/// [`SessionOffer`] draws for multilink itself: the priority band is not
/// negotiated at the handshake, it is a LOCAL `select_link` routing decision,
/// and it is per PHYSICAL LINK where the offer is per session. It is applied
/// only under a QoS offer, which is now read off the offer rather than told
/// twice.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
pub async fn initiate_and_open_session_with_multilink(
    connected: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    offer: SessionOffer,
    band: (Priority, Priority),
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    initiator_open_offering(
        connected,
        params,
        offer,
        |actions| {
            actions.install_multilink_dispatch(crate::multilink::open_multilink_dispatch());
            actions.set_link_reliability_pref(reliability_pref);
            stage_link_priority_band(actions, &offer, band);
            Ok(())
        },
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y219 (transport-multilink) — pin an aggregated link to its
/// deploy-assigned QoS-priority band so `select_link` routes each priority
/// conduit to one link (the priority tier of zenoh's per-channel select).
///
/// Applied ONLY under a negotiated QoS offer, which R2096 reads off the
/// [`SessionOffer`] rather than off a second boolean saying the same thing. The
/// band type + setter are `all(multilink,qos)`-gated, so the whole body elides
/// without `transport-qos` and `band` is consumed as a no-op (signature-stable).
///
/// One function for both directions because the two used to be one copied
/// block, and the copy is how item 516's defect spread: whatever the dial path
/// staged, the accept path had to be edited separately to match.
#[cfg(feature = "transport-multilink")]
fn stage_link_priority_band(
    #[allow(unused_variables)] actions: &Arc<SessionLinkActions>,
    #[allow(unused_variables)] offer: &SessionOffer,
    #[allow(unused_variables)] band: (Priority, Priority),
) {
    #[cfg(feature = "transport-qos")]
    if offer.mode == TransportMode::Qos {
        actions.set_link_priority_range(Some(
            wz_session_core::session_actions::LinkPriorityRange::new(band.0, band.1),
        ));
    }
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
    initiate_and_open_session_with_offer(
        connected,
        params,
        SessionOffer::universal().with_mode(TransportMode::LowLatency),
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y435 — the COMPOSING initiator open: one entrypoint taking the whole
/// negotiated capability set, replacing the one-wrapper-per-capability shape
/// that made every combination unreachable.
///
/// The wrappers above are not deprecated — they stay as the named one-capability
/// spellings, and each is now literally a `SessionOffer` with one field set, so
/// the two surfaces cannot drift. What they could never do is compose: with one
/// `initiate_and_open_session_with_*` per capability, offering lowlatency AND
/// compression on one session needed a `_with_lowlatency_compression` wrapper,
/// and four capabilities would have needed sixteen. R311y434 hit exactly that
/// wall — it could prove the composed wire wz<->wz but could not dial a real
/// zenohd with both offers staged, so its cross-impl claim stayed an argument
/// rather than a measurement. This is the entrypoint that closes it.
///
/// The exclusive qos/lowlatency pair cannot be mis-staged here because
/// [`SessionOffer`] carries ONE
/// [`TransportMode`](wz_session_core::transport_mode::TransportMode); see that
/// type for why wz encodes upstream's `manager.rs:264` runtime bail as a
/// compile-time impossibility instead.
///
/// The link is wired with the 4-byte u32 lowlatency prefix ONLY for
/// [`TransportMode::LowLatency`](wz_session_core::transport_mode::TransportMode::LowLatency),
/// and even then the flag flips at Established, so the handshake goes out u16 in
/// every mode — zenoh likewise reconfigures the link only after `recv_open_ack`
/// (`io/zenoh-transport/src/unicast/establishment/open.rs:706`).
pub async fn initiate_and_open_session_with_offer(
    connected: DialedLink,
    params: SessionInitParams,
    offer: SessionOffer,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    initiate_and_open_session_with_staging(
        connected,
        params,
        offer,
        |_actions| Ok(()),
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R2221 (open-debt item 568) — [`initiate_and_open_session_with_offer`] with
/// the staging seam it already has EXPOSED to the caller.
///
/// # Why this is a public entrypoint and not another `_with_x` sibling
///
/// `initiator_open_offering`'s doc already names `stage` "one extension point
/// for staging that is not part of the offer", and item 516 is the record of
/// what growing a SIBLING per capability costs: the aggregating entrypoint was
/// written beside the offering one rather than through it, and three of four
/// capabilities then had no route through it at all. Every state a caller can
/// legitimately install before the first wire byte does not deserve its own
/// `pub async fn` here; it deserves the seam.
///
/// `stage` runs after the offer is applied and BEFORE any wire byte, so what it
/// installs is on the InitSyn. It returns [`OpenError`] because staging can
/// fail — the accept-side twin draws OS entropy — and because a caller whose
/// staging failed must not proceed to a handshake that would advertise
/// something else.
///
/// # What a caller may reach through it, said plainly
///
/// [`wz_session_core::session_actions::SessionLinkActions`]' own public surface,
/// which is where the negotiable state lives: `set_ext_chain` (the InitSyn ext
/// chain, e.g. announcing a protocol patch level other than
/// [`wz_session_core::extpatch::CURRENT_PATCH`]), `install_auth_dispatch`,
/// `set_max_reassembly_bytes`. Nothing here widens that surface; it makes the
/// EXISTING surface reachable at the one instant when installing on it still
/// changes the wire.
pub async fn initiate_and_open_session_with_staging<S>(
    connected: DialedLink,
    params: SessionInitParams,
    offer: SessionOffer,
    stage: S,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError>
where
    S: FnOnce(&Arc<SessionLinkActions>) -> Result<(), OpenError>,
{
    initiator_open_offering(
        connected,
        params,
        offer,
        stage,
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R2096 (open-debt item 516) — the initiator open that HONOURS a
/// [`SessionOffer`], with one extension point for staging that is not part of
/// the offer.
///
/// Both capability-aware initiator entrypoints run through here:
/// [`initiate_and_open_session_with_offer`] stages nothing extra, and
/// [`initiate_and_open_session_with_multilink`] stages the 0x4 dispatch, the
/// link's reliability preference and its QoS-priority band. That split is the
/// [`SessionOffer`] doc's own line drawn in code — the offer is the SSOT for
/// "which capability exts does the InitSyn carry", and multilink / reliability
/// pref / priority band are deliberately NOT in it because they are not
/// negotiated that way.
///
/// It exists because item 516 was the cost of NOT having it. The aggregating
/// entrypoint was written as a sibling rather than a caller, so it carried its
/// own `qos: bool` and re-derived a fraction of what `apply_offer` does; three
/// of the four capabilities then had no route through it at all, and the same
/// flag reached the wire on `--max-links 1` and nothing on `--max-links 2`. A
/// capability added to [`SessionOffer`] later now reaches both paths by
/// construction, which is the property the duplicate could not have.
///
/// `stage` runs after `apply_offer` and BEFORE the handshake drives, so
/// everything it installs is on the wire from the InitSyn onward. It returns
/// [`OpenError`] because the accept-side twin's staging draws OS entropy, which
/// can fail.
async fn initiator_open_offering<S>(
    connected: DialedLink,
    params: SessionInitParams,
    offer: SessionOffer,
    stage: S,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError>
where
    S: FnOnce(&Arc<SessionLinkActions>) -> Result<(), OpenError>,
{
    // R311y435 — the lean wiring is chosen at RUNTIME from the offer, but ONLY in
    // a build that has the lean transport at all. Without `transport-lowlatency`,
    // `apply_offer` rejects `TransportMode::LowLatency` below, so the branch is
    // unreachable — and compiling it anyway drags
    // `wire_dialed_link_with_lowlatency` into builds that can never take it. That
    // is not hypothetical: this entrypoint is unconditional where the
    // `*_with_lowlatency` wrapper it replaced was `#[cfg(transport-lowlatency)]`,
    // and Layer F measured the loss — the codec-close footprint delta fell from
    // 1944 to 600 bytes on `preset-ap-client`, which carries no lowlatency
    // feature. The cfg split restores the elision the wrapper's gate used to give
    // for free.
    #[cfg(feature = "transport-lowlatency")]
    let lowlatency_wire = Arc::new(AtomicBool::new(false));
    #[cfg(feature = "transport-lowlatency")]
    let (inbound, outbound, writer_handle) = if offer.mode == TransportMode::LowLatency {
        wire_dialed_link_with_lowlatency(connected, lowlatency_wire.clone())
    } else {
        wire_dialed_link(connected)
    };
    #[cfg(not(feature = "transport-lowlatency"))]
    let (inbound, outbound, writer_handle) = wire_dialed_link(connected);
    let actions = new_session_actions(outbound, params, clock);
    // Staged BEFORE the handshake drives, and BEFORE any wire byte: an offer
    // this build cannot honour fails here rather than opening a session whose
    // wire form silently differs from the configuration.
    actions
        .apply_offer(&offer)
        .map_err(OpenError::UnsupportedCapability)?;
    install_shm_authenticator(&actions, &offer)?;
    stage(&actions)?;
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
    #[cfg(feature = "transport-lowlatency")]
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
    initiate_and_open_session_with_offer(
        connected,
        params,
        SessionOffer::universal().with_mode(TransportMode::Qos),
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
    initiate_and_open_session_with_offer(
        connected,
        params,
        SessionOffer::universal().with_compression(true),
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
    initiate_and_open_session_with_offer(
        connected,
        params,
        SessionOffer::universal().with_shm(true),
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
    writer_handle: WriterHandle,
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
///
/// R2096 (open-debt item 516) — takes the whole [`SessionOffer`] for the same
/// reason as that twin, and it MOVES WITH IT deliberately: upstream builds
/// `StateOpen` (`io/zenoh-transport/src/unicast/establishment/open.rs:605-636`)
/// and `StateAccept` (`.../accept.rs:725-755`) from the SAME
/// `manager.config.unicast.{is_qos,is_lowlatency,is_compression}`, so a
/// capability is a property of the NODE and not of which end dialled. Leaving
/// the accept side on `qos: bool` would have made an aggregating node reflect
/// QoS and nothing else — the asymmetry item 517 records for the single-session
/// acceptor, re-introduced here on purpose.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
pub async fn accept_and_open_session_with_multilink(
    accepted: DialedLink,
    params: SessionInitParams,
    reliability_pref: crate::config::LinkReliabilityPref,
    offer: SessionOffer,
    band: (Priority, Priority),
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    accept_open_offering(
        accepted,
        params,
        offer,
        |actions| {
            actions.install_multilink_dispatch(crate::multilink::accept_multilink_dispatch());
            actions.set_link_reliability_pref(reliability_pref);
            stage_link_priority_band(actions, &offer, band);
            // Fresh challenge nonce per accepted handshake (the pubkey responder
            // replay defense) — drawn from AP OS entropy here because the no_std
            // core cannot.
            let nonce =
                crate::session_glue::nonce_from_os_entropy().map_err(OpenError::AuthEntropy)?;
            actions.refresh_multilink_challenge_nonce(nonce);
            Ok(())
        },
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
    accept_and_open_session_with_offer(
        accepted,
        params,
        SessionOffer::universal().with_mode(TransportMode::LowLatency),
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R311y435 — the COMPOSING acceptor open: the accept-side mirror of
/// [`initiate_and_open_session_with_offer`], taking the whole negotiated
/// capability set instead of one capability per wrapper.
///
/// An acceptor OFFERS in order to reflect: each ext is echoed in the InitAck
/// only when the peer's InitSyn carried it (the `&=` merge runs on the inbound
/// InitSyn before the InitAck is emitted), so this stages what the acceptor is
/// WILLING to negotiate and the peer decides. That is why the composed
/// cross-impl leg needs both ends to be able to stage a SET: an acceptor that
/// can only offer one capability at a time cannot reflect a peer that offered
/// two, and the composed session degrades to whichever single capability the
/// wrapper happened to name.
pub async fn accept_and_open_session_with_offer(
    accepted: DialedLink,
    params: SessionInitParams,
    offer: SessionOffer,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    accept_open_offering(
        accepted,
        params,
        offer,
        |_actions| Ok(()),
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// R2096 (open-debt item 516) — the accept-side twin of
/// [`initiator_open_offering`]: the acceptor open that HONOURS a
/// [`SessionOffer`], with one extension point for staging that is not part of
/// the offer.
///
/// The asymmetry with the initiator twin is upstream's, not this seam's: an
/// acceptor OFFERS in order to REFLECT (each ext is echoed in the InitAck only
/// when the peer's InitSyn carried it), so `stage` still has to run before the
/// drive — the `&=` merge reads the inbound InitSyn before the InitAck is
/// emitted, and anything staged after that merge would be staged too late.
///
/// `stage` returns [`OpenError`] because the aggregating caller draws a FRESH
/// per-handshake challenge nonce from OS entropy here (the responder replay
/// defence), which the no_std session core cannot do for itself.
async fn accept_open_offering<S>(
    accepted: DialedLink,
    params: SessionInitParams,
    offer: SessionOffer,
    stage: S,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError>
where
    S: FnOnce(&Arc<SessionLinkActions>) -> Result<(), OpenError>,
{
    // R311y435 — same compile-time elision as the initiator twin: without
    // `transport-lowlatency` the lean branch is unreachable (`apply_offer` rejects
    // the mode) and must not be compiled, or the lean wiring stops being dead code
    // in builds that cannot use it. See that function for the Layer F measurement.
    #[cfg(feature = "transport-lowlatency")]
    let lowlatency_wire = Arc::new(AtomicBool::new(false));
    #[cfg(feature = "transport-lowlatency")]
    let (inbound, outbound, writer_handle) = if offer.mode == TransportMode::LowLatency {
        wire_dialed_link_with_lowlatency(accepted, lowlatency_wire.clone())
    } else {
        wire_dialed_link(accepted)
    };
    #[cfg(not(feature = "transport-lowlatency"))]
    let (inbound, outbound, writer_handle) = wire_dialed_link(accepted);
    let (actions, mut engine) = wire_session_engine(outbound, params, clock);
    actions
        .apply_offer(&offer)
        .map_err(OpenError::UnsupportedCapability)?;
    install_shm_authenticator(&actions, &offer)?;
    stage(&actions)?;

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
    #[cfg(feature = "transport-lowlatency")]
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
    accept_and_open_session_with_offer(
        accepted,
        params,
        SessionOffer::universal().with_mode(TransportMode::Qos),
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
    accept_and_open_session_with_offer(
        accepted,
        params,
        SessionOffer::universal().with_compression(true),
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
    accept_and_open_session_with_offer(
        accepted,
        params,
        SessionOffer::universal().with_shm(true),
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
///
/// This is the dial-only spelling of [`open_session_static_config`] — the
/// `listen=`-unaware entry point, kept because it is what every existing
/// caller and the `--connect`-shaped deploy needs. It delegates rather than
/// duplicating the loop, so the two cannot disagree about what a static
/// config means.
#[cfg(feature = "scouting-static")]
pub async fn open_session_static(
    connect: &[String],
    params: SessionInitParams,
    cfg: &DialConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    open_session_static_config(
        StaticDeploy::connect(connect),
        params,
        cfg,
        &AcceptConfig::default(),
        clock,
        max_iters,
        tick_interval_ms,
    )
    .await
}

/// zenoh's `connect.retry` block plus its `connect.timeout_ms`, as the ONE
/// value that decides whether a failed static dial is re-attempted
/// (`DEFAULT_CONFIG.json5:37-68`).
///
/// The schedule itself is not re-implemented here: [`RetryPolicy`] is the
/// crate's single transcription of `ConnectionRetryConf`, already shared by the
/// client reconnect supervisor and the router peer auto-reconnect, so a fix to
/// the growth arithmetic cannot land on those two and miss this one.
///
/// # Upstream disables the retry through EITHER of two zeros
///
/// `connect_peers_single_link` takes its no-retry arm when
/// `retry_config.timeout().is_zero() || get_global_connect_timeout().is_zero()`
/// (`zenoh/src/net/runtime/orchestrator.rs:356`), and `timeout()` is just
/// `period_init_ms` re-read as a duration. So `period_init_ms = 0` and
/// `timeout_ms = 0` each independently mean "one attempt, then move on" — and
/// `timeout_ms: { client: 0 }` is exactly how a stock zenoh CLIENT is
/// configured, against `{ router: -1, peer: -1 }`. [`Self::retries`] is that
/// disjunction, named once, because the alternative is a hot re-dial loop: a
/// `period_init_ms` of `0` multiplied by any factor stays `0`.
#[cfg(feature = "scouting-static")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StaticConnectRetry {
    /// The growth schedule — zenoh's `connect.retry`. [`RetryPolicy::ZENOH_DEFAULT`]
    /// is what a config omitting the section resolves to (1s -> 2s -> 4s).
    pub policy: RetryPolicy,
    /// zenoh's `connect.timeout_ms`, bounding the WHOLE dial rather than one
    /// attempt: `None` is upstream's `-1` (infinite — the router and peer
    /// default), `Some(0)` is upstream's `0` (no retry — the client default),
    /// and `Some(ms)` is a positive bound.
    pub timeout_ms: Option<u64>,
}

#[cfg(feature = "scouting-static")]
impl StaticConnectRetry {
    /// Whether this actually re-attempts a failed dial — upstream's two-zero
    /// disjunction, spelled once. See the type docs.
    pub fn retries(&self) -> bool {
        self.policy.period_init_ms > 0 && self.timeout_ms != Some(0)
    }
}

/// The `connect` / `listen` block of a static deploy, as one value — the wz
/// shape of zenoh's `connect: {}` config section (`DEFAULT_CONFIG.json5:37-68`)
/// and of the `connect=` / `listen=` keys pico's `_z_locators_by_config` reads.
///
/// Carried as a struct rather than as three parameters because that is what it
/// IS upstream: one config block whose members are read together. The practical
/// consequence is that the next knob from that block lands here instead of on
/// [`open_session_static_config`]'s signature.
#[cfg(feature = "scouting-static")]
pub struct StaticDeploy<'a> {
    /// `deploy.listen` — present means bind and accept, and forces the node's
    /// `whatami` to `Peer`. See [`resolve_static_config`].
    pub listen: Option<&'a str>,
    /// `deploy.connect[]` — the locators to dial, in deploy order.
    pub connect: &'a [String],
    /// `connect.retry` + `connect.timeout_ms`. `None` is one attempt per
    /// locator then fall through to the next, which is upstream's own
    /// no-retry arm and what every caller had before R311y808.
    pub retry: Option<StaticConnectRetry>,
}

#[cfg(feature = "scouting-static")]
impl<'a> StaticDeploy<'a> {
    /// A dial-only deploy: `connect[]`, no `listen=`, no retry.
    pub fn connect(connect: &'a [String]) -> Self {
        Self {
            listen: None,
            connect,
            retry: None,
        }
    }

    /// Set `deploy.listen`. Chainable onto [`Self::connect`].
    pub fn with_listen(mut self, listen: &'a str) -> Self {
        self.listen = Some(listen);
        self
    }

    /// Set `connect.retry` + `connect.timeout_ms`. Chainable.
    pub fn with_retry(mut self, retry: StaticConnectRetry) -> Self {
        self.retry = Some(retry);
        self
    }
}

/// Bring up the transport half a static deploy config asks for — the
/// `listen=`-aware static-mode entry point, and the wz analog of pico's
/// `_z_open` reading `_z_locators_by_config`'s `peer_op`
/// (`vendor/zenoh-pico/src/net/session.c:87-118`, `:155-190`).
///
/// [`resolve_static_config`] decides which half from the `listen=` /
/// `connect=` pair, BEFORE any socket is touched; this then brings that half
/// up through the seam that already exists for it:
///
/// - [`StaticRole::Open`] — dial the connect list in deploy order, first
///   Established wins, exactly [`open_session_static`]'s contract above.
/// - [`StaticRole::Listen`] — [`accept_endpoint`] binds the one configured
///   endpoint and accepts on it, then [`accept_and_open_session`] drives the
///   Accepting half of the handshake. The node's `whatami` is forced to
///   [`WhatAmI::Peer`](wz_codecs::whatami::WhatAmI) first, because pico's
///   listen arm inserts `mode=peer` over whatever the config said
///   (`session.c:96`, `:110`) — its default is `Z_WHATAMI_CLIENT`
///   (`session.c:122`) and a client does not accept, so honouring the listen
///   endpoint while leaving the role a client would announce a node that
///   contradicts what it is doing.
///
/// An incoherent pair surfaces as [`OpenError::BadStaticConfig`]; an empty
/// resolved locator list is the "configured locators are wrong / unreachable"
/// diagnostic [`OpenError::NoReachableLocator`], which is where the empty
/// config lands now that static mode has no scouting to fall through to.
///
/// `accept_cfg` is consumed only by the Listen arm (a `tls/...` or `quic/...`
/// listen endpoint needs its server cert); the dial arm takes `cfg`. Both are
/// present rather than one being chosen at the call site because the config
/// — not the caller — decides which half runs.
///
/// # The dial arm's retry (R311y808)
///
/// [`StaticDeploy::retry`] selects between the two arms zenoh's
/// `connect_peers_single_link` has (`orchestrator.rs:345-370`), and wz had only
/// the first of:
///
/// - `None`, or a policy whose [`retries`](StaticConnectRetry::retries) is
///   false — ONE attempt per locator, falling through to the next on failure.
///   This is upstream's `retry_config.timeout().is_zero()` arm and the shape a
///   stock zenoh CLIENT is configured into (`timeout_ms: { client: 0 }`).
/// - a policy that retries — the current locator is re-attempted on its own
///   growing schedule and the walk does NOT advance past it. That pin is
///   upstream's, not an accident of this port: `peer_connector_retry` loops
///   until the endpoint connects and then returns `Ok`, so the later endpoints
///   are unreachable while it waits. `timeout_ms` is the only thing that ends
///   it, exactly as upstream's outer `tokio::time::timeout` is
///   (`orchestrator.rs:318-335`), and a `None` timeout is upstream's `-1` —
///   infinite, the router and peer default.
///
/// The wait itself comes from [`RetryPolicy`] /
/// [`RetryPeriod`](crate::retry_period::RetryPeriod), the crate's one
/// transcription of `ConnectionRetryConf`, so this arm cannot drift from the
/// client reconnect supervisor or the router auto-reconnect.
#[cfg(feature = "scouting-static")]
pub async fn open_session_static_config(
    deploy: StaticDeploy<'_>,
    params: SessionInitParams,
    cfg: &DialConfig,
    accept_cfg: &AcceptConfig,
    clock: TokioTime,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> Result<OpenedSession, OpenError> {
    // R311ih — the resolution yields the bounded seam (StaticLocators =
    // BoundedVec<BoundedString>); iterate via the slice Deref and pass each
    // locator as &str to the mode-agnostic open path.
    let StaticDeploy {
        listen,
        connect,
        retry,
    } = deploy;
    let resolved = resolve_static_config(listen, connect).map_err(OpenError::BadStaticConfig)?;
    let role = resolved.role;
    let locators = resolved.locators;
    if locators.is_empty() {
        return Err(OpenError::NoReachableLocator);
    }

    // The role decides the announced identity BEFORE either half runs, which
    // is pico's own order: `_z_locators_by_config` inserts `mode=peer` while
    // resolving, and `_z_open` reads the mode afterwards (session.c:110, :121).
    let mut params = params;
    if role.forces_peer_mode() {
        params.whatami = wz_codecs::whatami::WhatAmI::Peer;
    }

    if role == StaticRole::Listen {
        let endpoint = locators[0].as_str();
        log::info!("wz session-open: static listen endpoint {endpoint:?} (mode=peer)");
        let accepted = accept_endpoint(endpoint, accept_cfg)
            .await
            .map_err(OpenError::Dial)?;
        return accept_and_open_session(accepted, params, clock, max_iters, tick_interval_ms).await;
    }

    let dial = async {
        for locator in locators.iter() {
            // Fresh growth state per locator, matching `peer_connector_retry`
            // building its `period` on entry (orchestrator.rs:787-788).
            let mut period = retry.map(|r| r.policy.period());
            loop {
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
                        log::warn!("wz session-open: static locator {locator:?} failed: {e:?}");
                    }
                }
                // Upstream's no-retry arm: one attempt, then the next locator.
                let Some(period) = period
                    .as_mut()
                    .filter(|_| retry.is_some_and(|r| r.retries()))
                else {
                    log::warn!(
                        "wz session-open: static locator {locator:?} not retried; trying next"
                    );
                    break;
                };
                // Upstream's retry arm PINS this locator — `peer_connector_retry`
                // loops until it connects, so the walk never advances while it
                // waits. Only `timeout_ms` ends this, and it does so from the
                // outer bound below rather than from a second deadline here.
                let wait_ms = period.next_ms();
                log::info!(
                    "wz session-open: static locator {locator:?} unreachable; retry in {wait_ms}ms"
                );
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
            }
        }
        Err(OpenError::NoReachableLocator)
    };

    // zenoh wraps the WHOLE walk, not one attempt (orchestrator.rs:318-335), and
    // skips the wrap entirely when the timeout is zero — which is why a zero is
    // never turned into an instantly-elapsed bound here. `None` is upstream's
    // `-1`: no wrap, wait forever.
    match retry.and_then(|r| r.timeout_ms).filter(|ms| *ms > 0) {
        Some(ms) => tokio::time::timeout(std::time::Duration::from_millis(ms), dial)
            .await
            .unwrap_or(Err(OpenError::NoReachableLocator)),
        None => dial.await,
    }
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

    // ── dial-side contract: `tcp` and (R311y524) `udp` dial a NAME; ws/tls
    //    still surface a typed `Unsupported` BEFORE any I/O (no resolver, no
    //    socket) — a clean extension point, not a silent fallback.
    //
    //    `udp` LEFT this list at R311y524 because pico resolves a named UDP
    //    endpoint through `getaddrinfo(.., SOCK_DGRAM, IPPROTO_UDP)`
    //    (`src/link/transport/udp/udp_posix.c:32-40`), so refusing one was a
    //    parity gap. The positive arm is the test below.
    #[tokio::test]
    async fn ws_and_tls_named_dial_is_unsupported_without_io() {
        for s in ["ws/example.org:7447", "tls/example.org:7447"] {
            // DialedLink holds live streams (not Debug), so match rather than
            // expect_err; these must surface Unsupported before any I/O.
            match dial_endpoint(s, &DialConfig::default()).await {
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::Unsupported,
                    "{s} should be Unsupported (name dial not wired for it)"
                ),
                Ok(_) => panic!("{s} must not dial (name dial not wired for it)"),
            }
        }
    }

    /// R311y524 — a `udp/<name>:<port>` locator RESOLVES and dials.
    ///
    /// `localhost` rather than a public name on purpose: the property under
    /// test is that the udp arm reaches the resolver at all, and a name that
    /// needs the network would make this a connectivity test. The assertion is
    /// on the RESOLVED peer, not merely on success — a UDP dial is a bind plus
    /// `connect` and would succeed against a bogus address too, so checking the
    /// port and loopback-ness is what proves the name actually turned into the
    /// endpoint asked for.
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn a_named_udp_locator_resolves_and_dials() {
        match dial_endpoint("udp/localhost:17457", &DialConfig::default()).await {
            Ok(DialedLink::Udp { peer, .. }) => {
                assert_eq!(peer.port(), 17457, "the resolved peer kept the port");
                assert!(
                    peer.ip().is_loopback(),
                    "localhost must resolve to a loopback address, got {peer}"
                );
            }
            Ok(_) => panic!("a udp/ locator must dial to DialedLink::Udp"),
            Err(e) => panic!(
                "udp/localhost:17457 did not dial ({e}); pico resolves a named UDP \
                 endpoint through getaddrinfo, so this is the parity arm"
            ),
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

    // ── R311y809 — the MESH dial target resolution. The mesh hosts parsed their
    //    `--connect` targets with a bare `str::parse::<SocketAddr>()`, so they
    //    read a grammar no other wz entry point uses. These pin the three
    //    outcomes of routing that through `plan_endpoint` instead, and each one
    //    is a distinct operator mistake rather than three spellings of "bad
    //    string" — which is what the bare parse collapsed them to.

    #[tokio::test]
    async fn mesh_dial_target_takes_the_scheme_and_the_bare_spelling_alike() {
        // THE defect this seam closes: `tcp/HOST:PORT` is zenoh's own spelling
        // and what `--listen` on the same node accepts, yet the bare parse
        // rejected it while taking the scheme-less form. Both must land on the
        // identical address, through one classifier.
        let bare = resolve_mesh_dial_target("127.0.0.1:7447")
            .await
            .expect("bare host:port resolves");
        let schemed = resolve_mesh_dial_target("tcp/127.0.0.1:7447")
            .await
            .expect("tcp/ host:port resolves");
        assert_eq!(bare, schemed);
        let plan = mesh_dial_plan(bare).expect("a tcp target has an address identity");
        assert_eq!(plan.addr.port(), 7447);
        assert_eq!(plan.proto, Proto::Tcp);
    }

    #[tokio::test]
    async fn mesh_dial_target_resolves_a_name_of_any_ip_scheme() {
        // A DNS-named mesh peer was impossible before R311y809 (`str::parse::
        // <SocketAddr>` has no resolver) and, until R2233, possible only for
        // `tcp` — resolution had been written as a property of the SCHEME when it
        // is a property of the ADDRESS TOKEN. `localhost` is the one name a unit
        // may assume.
        for (target, proto) in [
            ("tcp/localhost:7447", Proto::Tcp),
            ("quic/localhost:7447", Proto::Quic),
            ("tls/localhost:7447", Proto::Tls),
        ] {
            let resolved = resolve_mesh_dial_target(target)
                .await
                .unwrap_or_else(|e| panic!("{target} resolves: {e}"));
            let plan = mesh_dial_plan(resolved).expect("a resolved name is numeric");
            assert!(
                plan.addr.ip().is_loopback(),
                "expected loopback for {target}, got {}",
                plan.addr
            );
            assert_eq!(plan.addr.port(), 7447);
            assert_eq!(plan.proto, proto, "the scheme must survive resolution");
        }
    }

    /// R2233 (open-debt item 585) — the INVERTED half of what this seam used to
    /// assert. `tls` / `ws` / `quic` / `udp` were refused here because
    /// `accept_loop::dial_face` bypassed [`dial_locator`] and opened a raw
    /// `TcpStream`; the loop dispatches on scheme now, so a mesh dial target of
    /// any IP-family scheme resolves — and the SCHEME reaches the loop, which is
    /// the whole point (a target flattened to a `SocketAddr` could only be TCP).
    #[tokio::test]
    async fn mesh_dial_target_now_carries_every_ip_scheme() {
        for (target, proto) in [
            ("tls/127.0.0.1:7447", Proto::Tls),
            ("ws/127.0.0.1:7447", Proto::Ws),
            ("quic/127.0.0.1:7447", Proto::Quic),
            ("udp/127.0.0.1:7447", Proto::Udp),
        ] {
            let resolved = resolve_mesh_dial_target(target)
                .await
                .unwrap_or_else(|e| panic!("{target} must now resolve: {e}"));
            let plan = mesh_dial_plan(resolved).expect("an IP endpoint has an address identity");
            assert_eq!(plan.proto, proto);
            assert_eq!(plan.addr, "127.0.0.1:7447".parse().unwrap());
        }
    }

    #[tokio::test]
    async fn mesh_dial_target_reports_the_endpoint_shape_it_cannot_identify() {
        // What SURVIVES the widening: an endpoint with no `SocketAddr` cannot be
        // a mesh dial target, because the mesh dial's dedup key, its `desired`
        // connect-set and its per-address re-dial schedule are all keyed by
        // address. This is an IDENTITY limit, not a transport one — and it is a
        // capability statement, so a `Malformed` here would be the old lie in a
        // new place.
        for (target, scheme) in [
            ("unixsock-stream//tmp/wz.sock", "unixsock-stream"),
            ("unixpipe//tmp/wz.pipe", "unixpipe"),
            ("vsock/3:7447", "vsock"),
            ("serial//dev/ttyUSB0#baudrate=115200", "serial"),
        ] {
            match resolve_mesh_dial_target(target).await {
                Err(DialTargetError::UnsupportedScheme {
                    target: got,
                    scheme: got_scheme,
                }) => {
                    assert_eq!(got, target, "the operator's own string must survive");
                    assert_eq!(got_scheme, scheme);
                }
                other => panic!("expected UnsupportedScheme for {target:?}, got {other:?}"),
            }
        }
    }

    /// The loop's own seam reads the SAME classification the resolver does, so a
    /// caller that hands `FaceSources::dial_targets` a locator directly (the
    /// field is public) gets the identical verdict. Both directions, so the
    /// classifier cannot pass by admitting everything.
    #[test]
    fn mesh_dial_plan_admits_exactly_the_endpoints_with_an_address() {
        for admitted in [
            "tcp/127.0.0.1:7447",
            "udp/127.0.0.1:7447",
            "tls/127.0.0.1:7447",
            "ws/127.0.0.1:7447",
            "quic/127.0.0.1:7447",
            "quic-datagram/127.0.0.1:7447",
        ] {
            let locator = parse_any_locator(admitted).expect("parses");
            let plan = mesh_dial_plan(locator).unwrap_or_else(|l| {
                panic!("{admitted} must be mesh-dialable, got {l:?}");
            });
            assert_eq!(plan.addr, "127.0.0.1:7447".parse().unwrap());
        }
        for refused in [
            // No address at all.
            "unixsock-stream//tmp/wz.sock",
            "unixpipe//tmp/wz.pipe",
            "vsock/3:7447",
            "serial//dev/ttyUSB0#baudrate=115200",
            // An address that exists only after a resolution this synchronous
            // seam does not perform — the loop must never block on a resolver.
            "tcp/example.org:7447",
        ] {
            let locator = parse_any_locator(refused).expect("parses");
            let scheme = locator_scheme(&locator);
            assert!(
                mesh_dial_plan(locator).is_err(),
                "{refused} ({scheme}) has no pre-handshake address identity"
            );
        }
    }

    #[tokio::test]
    async fn mesh_dial_target_still_rejects_a_string_that_is_not_an_endpoint() {
        // The widening must not swallow real garbage: a malformed target stays
        // `Malformed`, distinct from the capability arm above.
        match resolve_mesh_dial_target("not-an-endpoint").await {
            Err(DialTargetError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
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
        // `mut` is used only on the feature-off push arms; silence unused_mut
        // when every acceptor is wired and the list is already complete.
        #[allow(unused_mut)]
        let mut unwired = vec!["tls/127.0.0.1:7447"];
        // R311y381 wired the UDP acceptor (and R311y382 generalized it to a
        // multi-peer demux), so with `transport-link-udp` ON a `udp/…` listen
        // BINDS + accepts (blocking on the first datagram / new src) — asserting
        // "unsupported before any bind" would HANG (or AddrInUse-fail on a busy
        // port), exactly like the `ws` acceptor below. With the backend OFF a
        // `udp/…` listen is still an unwired extension point (`bind_locator`'s
        // cfg-off arm -> `Unsupported`), so it stays in the list there. This
        // mirrors the R311y374 ws exclusion; the udp accept path is proven e2e by
        // `udp_seam_e2e` / `mesh_accept_loop_holds_two_udp_peers` instead.
        #[cfg(not(feature = "transport-link-udp"))]
        unwired.push("udp/127.0.0.1:7447");
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

    /// CALLER fail-fast slice — pins the BIND-time mesh-capability predicate
    /// ([`BoundListener::supports_mesh_multi_peer`], the twin `run_router`
    /// consults at bind) at the TRUE polarity: a tcp listener is mesh-capable.
    /// The match is wildcard-free, so a NEW `BoundListener` variant forces a
    /// compile-time decision; this pins the value for tcp (a representative
    /// `true`). Since R311y392 the stream + same-host families are mesh-capable —
    /// `boundlistener_unixpipe_is_mesh_capable` pins the once-`false` unixpipe arm at
    /// its new `true` polarity; `boundlistener_quic_is_mesh_capable` (R311y404) pins
    /// quic at its new `true` polarity (was the once-`false` inline-handshake arm).
    #[tokio::test]
    async fn boundlistener_tcp_is_mesh_capable() {
        let l = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"), None)
            .await
            .expect("bind tcp");
        let listener = BoundListener::Tcp(l);
        assert!(
            listener.supports_mesh_multi_peer(),
            "a tcp listener is mesh-capable (N per-peer accepts off one listener)"
        );
    }

    /// R311y392 — the once-`false` unixpipe arm now pins at `true`: the
    /// multi-client acceptor (`bind_unixpipe`, async — it spawns the acceptor task)
    /// makes a unixpipe listener mesh-capable, so `run_router`'s bind-time fail-fast
    /// no longer rejects it. Replaces the retired
    /// `boundlistener_unixpipe_is_not_mesh_capable` (whose FALSE assertion the flip
    /// broke). The `AcceptedLink` twin is pinned by `acceptedlink_unixpipe_*` in
    /// accept_loop.
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn boundlistener_unixpipe_is_mesh_capable() {
        use crate::unixpipe_pipeline::bind_unixpipe;
        let base = std::env::temp_dir()
            .join(format!("wz-boundlistener-cap-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let acc = bind_unixpipe(&base, None)
            .await
            .expect("bind the unixpipe acceptor");
        let listener = BoundListener::Unixpipe(acc);
        assert!(
            listener.supports_mesh_multi_peer(),
            "a unixpipe listener is mesh-capable (multi-client acceptor, R311y392)"
        );
        drop(listener);
    }

    /// R311y404 — the once-`false` quic arm now pins at `true`: the
    /// deferred-handshake split (`accept_raw` does only the cheap
    /// `accept_quic_incoming` arrival; the crypto + first bidi stream defer to
    /// `AcceptedLink::handshake` in the spawned open future) moves the slow crypto off
    /// the accept loop's `select!`, so a quic endpoint holds N per-peer faces and its
    /// bind-time predicate is mesh-capable. Replaces the retired
    /// `boundlistener_quic_is_not_mesh_capable` (whose FALSE assertion the flip broke).
    /// The `AcceptedLink::Quic` twin's `true` is compiler-forced (the wildcard-free
    /// match); the end-to-end N-faces property is proven by
    /// `mesh_accept_loop_holds_two_quic_peers` in accept_loop.
    #[cfg(feature = "transport-link-quic")]
    #[tokio::test]
    async fn boundlistener_quic_is_mesh_capable() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config = crate::quic_config::quic_server_config_from_pem(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            None,
        )
        .expect("build quic server config");
        let ep = bind_quic(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            None,
        )
        .expect("bind quic endpoint");
        let listener = BoundListener::Quic(ep);
        assert!(
            listener.supports_mesh_multi_peer(),
            "a quic listener is mesh-capable (deferred-handshake split, R311y404)"
        );
        drop(listener);
    }

    /// R311y408 — the quic-DATAGRAM twin of `boundlistener_quic_is_mesh_capable`:
    /// pins the BIND-time predicate `BoundListener::QuicDatagram(_) => true` at its
    /// `true` polarity. The wildcard-free match compiler-forces the arm to EXIST but
    /// not its VALUE, so a wrong `false` would make `run_router`/`run_peer`'s
    /// bind-time mesh fail-fast wrongly reject a `--router quic-datagram/` bind with
    /// no other test catching it (the sibling-asymmetry the tcp/unixpipe/quic pins
    /// close). The `AcceptedLink::QuicDatagram` twin's `true` — consulted by the
    /// accept loop's `Step::Accepted` backstop — is pinned separately by
    /// `mesh_accept_loop_holds_two_quic_datagram_peers` in accept_loop.
    #[cfg(feature = "transport-link-quic-datagram")]
    #[tokio::test]
    async fn boundlistener_quic_datagram_is_mesh_capable() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config = crate::quic_config::quic_server_config_from_pem(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            None,
        )
        .expect("build quic server config");
        let ep = crate::quic_datagram_pipeline::bind_quic_datagram(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            None,
        )
        .expect("bind quic-datagram endpoint");
        let listener = BoundListener::QuicDatagram(ep);
        assert!(
            listener.supports_mesh_multi_peer(),
            "a quic-datagram listener is mesh-capable (deferred-handshake split, R311y408)"
        );
        drop(listener);
    }

    // ── R311y470 — the ADVERTISED locator must be one a FOREIGN peer can dial.
    //
    // `transport_name()` is a LOG word and is pinned as such (`unixsock_e2e.rs`
    // asserts `"unixsock"`). Reusing it as the locator SCHEME diverged twice:
    // wz emitted `unixsock/<path>`, which is not even its OWN scheme
    // (`UNIXSOCK_SCHEME = "unixsock-stream"`, matching zenoh's
    // `UNIXSOCKSTREAM_LOCATOR_PREFIX`), and `quic-datagram/<addr>`, a spelling
    // zenoh has no prefix for — it gives BOTH quic links the `"quic"` scheme and
    // separates them by `rel` (`io/zenoh-link/src/lib.rs:165-171`), so an
    // unknown scheme lands on its `_ => bail!("Unicast not supported")` arm
    // (:183). These strings are FLOODED to peers via `set_self_locators` ->
    // `LinkstateForwarder` -> the neighbour graph, so they are a wire surface.

    #[cfg(feature = "transport-link-unixsock")]
    #[tokio::test]
    async fn advertised_unixsock_locator_uses_the_zenoh_scheme_and_parses_back() {
        let path = std::env::temp_dir()
            .join(format!("wz-adv-{}.sock", std::process::id()))
            .display()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let listener = bind_endpoint(&format!("unixsock-stream/{path}"))
            .await
            .expect("bind a unixsock listener");
        let advertised = listener.advertised_locator(
            &listener
                .local_addr_display()
                .expect("a bound unixsock listener has a path"),
        );
        assert_eq!(
            advertised,
            format!("unixsock-stream/{path}"),
            "the advertised scheme is zenoh's UNIXSOCKSTREAM_LOCATOR_PREFIX, not the log word"
        );
        // The sharper half: it must PARSE BACK. `unixsock/<path>` does not —
        // wz's own leaf rejects it NotUnixsockScheme — so this arm alone shows
        // the pre-R311y470 string was undialable even wz-to-wz.
        assert_eq!(
            parse_any_locator(&advertised),
            Ok(AnyLocator::Unixsock(
                wz_session_core::locator::UnixsockEndpoint { path }
            )),
        );
        drop(listener);
    }

    #[cfg(feature = "transport-link-quic-datagram")]
    #[tokio::test]
    async fn advertised_quic_datagram_locator_uses_zenoh_quic_scheme_and_rel_metadata() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config = crate::quic_config::quic_server_config_from_pem(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            None,
        )
        .expect("build quic server config");
        let ep = crate::quic_datagram_pipeline::bind_quic_datagram(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            None,
        )
        .expect("bind quic-datagram endpoint");
        let listener = BoundListener::QuicDatagram(ep);
        let addr = listener
            .local_addr_display()
            .expect("a bound quic-datagram listener has an address");
        let advertised = listener.advertised_locator(&addr);
        assert_eq!(
            advertised,
            format!("quic/{addr}?rel=0"),
            "zenoh has no `quic-datagram` prefix — both its QUIC links are `quic` and \
             `rel=0` is what selects the datagram one"
        );
        // Round-trip: the zenoh-canonical spelling must still come back as the
        // DATAGRAM proto on the wz side. That only holds because R311y469 taught
        // the IP leaf to honour `rel`, so this pins the two rounds together.
        assert!(
            matches!(
                parse_any_locator(&advertised),
                Ok(AnyLocator::Ip(ref p)) if p.proto == Proto::QuicDatagram
            ),
            "the advertised quic-datagram locator must parse back as QuicDatagram"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn advertised_tcp_locator_is_scheme_plus_address() {
        // CONTROL: the 7 variants whose log word already IS their zenoh scheme
        // must be untouched by the two special arms.
        let listener = bind_endpoint("tcp/127.0.0.1:0")
            .await
            .expect("bind a tcp listener");
        let addr = listener.local_addr_display().expect("tcp listener addr");
        assert_eq!(listener.advertised_locator(&addr), format!("tcp/{addr}"));
        assert!(matches!(
            parse_any_locator(&listener.advertised_locator(&addr)),
            Ok(AnyLocator::Ip(_))
        ));
        drop(listener);
    }
}
