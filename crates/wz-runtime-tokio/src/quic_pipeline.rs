// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xk — QUIC session-open transport pipeline.
//!
//! The QUIC sibling of [`crate::tls_pipeline`]. zenoh-link-quic carries a zenoh
//! batch over ONE bidirectional QUIC stream per connection (unidirectional
//! streams rejected, `max_concurrent_bidi_streams = 1`), with the SAME
//! StreamEnvelope length-prefix framing as TCP/TLS (`is_streamed() = true`, MTU
//! `BatchSize::MAX`, `zenoh-link-quic/src/unicast.rs`). So the read/write
//! drivers in [`crate::stream_link`] are reused UNCHANGED: a
//! [`quinn::RecvStream`] is `AsyncRead`, a [`quinn::SendStream`] is
//! `AsyncWrite`, and they are ALREADY a split pair (`open_bi`/`accept_bi`
//! return both) — so unlike TCP (`into_split`) / TLS (`tokio::io::split`) this
//! module needs no split call at all.
//!
//! ## QUIC endpoint lifecycle (the wz keep-alive wrinkle)
//!
//! Unlike a TCP/unixsock/vsock socket (where the stream owns the OS fd), a QUIC
//! [`quinn::SendStream`]/[`RecvStream`] references its [`quinn::Connection`],
//! which references the [`quinn::Endpoint`]'s background driver (the UDP socket
//! pump). Dropping the `Endpoint` or `Connection` while the link is live would
//! tear the link down. Both are cheap `Clone` handles (Arc inside), so
//! [`QuicReadDriver`] holds a clone of each as a keep-alive for the link's
//! lifetime (the session-long inbound side). This is the QUIC analogue of WS's
//! bespoke `WsReadDriver` struct — a transport-specific read driver wrapping the
//! shared [`StreamReadDriver`] plus the resources the link must outlive.
//!
//! ## Certs ride the dial seam (not the locator), like TLS
//!
//! QUIC mandates TLS 1.3; its rustls config (TLS-1.3-only + ALPN `hq-29`) is
//! built by [`crate::quic_config`]. The dial needs cert material a `quic/...`
//! locator cannot carry, so — exactly like TLS (R311oc) — it is threaded via
//! [`crate::session_open::DialConfig`]`.quic`; a `quic/...` locator with no such
//! config dials to a typed `Unsupported`.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, Incoming, RecvStream, SendStream,
    ServerConfig as QuinnServerConfig, TransportConfig,
};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};

use wz_runtime_core::Runtime;

use crate::link_interfaces::ip_link_subject;
use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::{LinkDriver, LinkEvent, Reliability, TxFrame};
use wz_session_core::link::InterceptorLink;

/// A dialed / accepted QUIC link: the endpoint + connection (kept alive for the
/// link) and the single bidirectional stream's split halves. Produced by
/// [`dial_quic`] (client) / [`accept_quic_on`] (server) and consumed by
/// [`wire_quic_stream`].
pub struct QuicLink {
    /// The QUIC endpoint (UDP socket + driver). A `Clone` handle; kept alive
    /// because the connection's driver lives on it.
    pub endpoint: Endpoint,
    /// The QUIC connection. A `Clone` handle; kept alive because the streams
    /// reference it.
    pub connection: Connection,
    /// The outbound half of the one bidirectional stream (`AsyncWrite`).
    pub send: SendStream,
    /// The inbound half of the one bidirectional stream (`AsyncRead`).
    pub recv: RecvStream,
}

/// Inbound read driver of a QUIC link — the shared [`StreamReadDriver`] over a
/// [`quinn::RecvStream`], PLUS the keep-alive [`Endpoint`] + [`Connection`] the
/// link must outlive (see the module doc). Delegates the [`LinkDriver`] surface
/// to the inner stream driver; the framing / StreamEnvelope logic lives once in
/// [`crate::stream_link`]. The QUIC analogue of [`crate::ws_pipeline`]'s bespoke
/// `WsReadDriver`.
pub struct QuicReadDriver {
    inner: StreamReadDriver<RecvStream>,
    // Keep-alive: dropping either before the link closes would tear it down
    // (the RecvStream/SendStream reference the connection; the connection
    // references the endpoint driver). Both are cheap Arc-backed handles.
    _endpoint: Endpoint,
    _connection: Connection,
}

impl LinkDriver for QuicReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        self.inner.open().await
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        self.inner.send(frame, reliability).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }

    async fn poll_event(&mut self) -> LinkEvent {
        self.inner.poll_event().await
    }
}

/// Map a quinn / rustls error into the `io::Result` the pipeline surface speaks.
/// `pub(crate)` so the datagram sibling [`crate::quic_datagram_pipeline`] reuses
/// the one error-mapping SSOT (R311y8) rather than re-deriving it.
pub(crate) fn io_other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(err)
}

/// The unspecified bind address of the same IP family as `target` — a QUIC
/// client endpoint binds an ephemeral local UDP socket, and it must match the
/// target's family (a V4 socket cannot reach a V6 peer). Mirrors zenoh's
/// INADDR_ANY / in6addr_any auto-select on dial (`zenoh-link-quic` `new_link`).
/// `pub(crate)` so the datagram sibling [`crate::quic_datagram_pipeline`] shares
/// the one ephemeral-bind-family SSOT (R311y8).
pub(crate) fn client_bind_addr(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

/// Build a client [`Endpoint`] bound to an ephemeral local socket of `addr`'s
/// family, install the TLS-1.3 + ALPN-`hq-29` rustls `client_config`, and connect
/// to `addr` (SNI = `server_name`) — the shared QUIC client-handshake SSOT for
/// BOTH the stream backend ([`dial_quic`]) and the datagram backend
/// ([`crate::quic_datagram_pipeline::dial_quic_datagram`]). Returns the endpoint
/// (the caller keeps it alive — its driver pumps the connection) + the
/// established [`Connection`], BEFORE any stream is opened; the caller chooses
/// `open_bi` (stream) vs riding datagrams. Mirrors zenoh's `new_link` client half.
pub(crate) async fn connect_quic_client(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
    iface: Option<&str>,
) -> io::Result<(Endpoint, Connection)> {
    let mut endpoint = match iface {
        // No `#iface=`: the convenience `Endpoint::client` binds its own
        // ephemeral UDP socket (the original path).
        None => Endpoint::client(client_bind_addr(addr))?,
        // R311y236 — a device-bound QUIC client needs a PRE-built UDP socket
        // (`Endpoint::client` exposes no bind-device hook): build a std
        // `UdpSocket`, set `SO_BINDTODEVICE` on it, then hand it to
        // `Endpoint::new` with the tokio runtime. Off-feature / off-platform the
        // shared `bind_socket_to_device` warns and the socket stays unbound.
        Some(iface) => {
            let sock = std::net::UdpSocket::bind(client_bind_addr(addr))?;
            crate::iface_bind::bind_socket_to_device(&sock, iface)?;
            Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                sock,
                std::sync::Arc::new(quinn::TokioRuntime),
            )?
        }
    };
    let quic_crypto = QuicClientConfig::try_from(client_config).map_err(io_other)?;
    endpoint.set_default_client_config(QuinnClientConfig::new(Arc::new(quic_crypto)));
    let connection = endpoint
        .connect(addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    Ok((endpoint, connection))
}

/// Build a server [`Endpoint`] at `addr` presenting the TLS-1.3 + ALPN-`hq-29`
/// rustls `server_config`, capping application streams at `max_bidi`
/// bidirectional + 0 unidirectional — the shared QUIC server-endpoint SSOT for
/// BOTH the stream backend ([`bind_quic`], `max_bidi = 1` = exactly one
/// StreamEnvelope stream) and the datagram backend
/// ([`crate::quic_datagram_pipeline::bind_quic_datagram`], `max_bidi = 0` =
/// datagram-only). uni is always 0 (wz uses neither). The QUIC handshake rides
/// crypto frames, not application streams, so it completes regardless of the
/// limit. Mirrors zenoh's `new_listener` stream-limit setup.
///
/// R311y454 — `iface` is the LISTEN-side `#iface=<name>` honor, closing the
/// residual that only the dial half bound its socket to the named NIC. quinn's
/// convenience `Endpoint::server` owns the UDP socket it binds and exposes no
/// bind-device hook, so a device-bound listener needs the socket built FIRST:
/// bind, `SO_BINDTODEVICE`, then hand it to `Endpoint::new`. This is the exact
/// mirror of the dial-side [`connect_quic_client`] arm, and of zenoh's own
/// listener, which binds a UDP socket, calls `set_bind_to_device_udp_socket`, and
/// passes it to `Endpoint::new_with_abstract_socket`
/// (`zenoh-link-quic/src/unicast.rs:408-427`); `Endpoint::new` IS that call plus
/// `wrap_udp_socket`. Both stay on the `Endpoint::server` path when no iface is
/// named, so the un-narrowed listener is byte-for-byte the pre-R311y454 one.
///
/// The socket MUST reach quinn. Building it, setting the device on it and then
/// dropping it would leave a listener that passes every "binding to `lo` works"
/// and "an absent device gives ENODEV" test while honouring nothing — the syscall
/// ran, on a socket quinn never used. That failure mode is what the delivery-based
/// A/B in `tests/quic_e2e.rs` exists to catch.
///
/// Deliberate divergence, named because it is a divergence and not a port: wz
/// hardcodes `quinn::TokioRuntime` where zenoh asks `quinn::default_runtime()`.
/// wz-runtime-tokio IS the tokio runtime crate, so there is no other answer to
/// give, and the dial half already hardcodes it.
pub(crate) fn quic_server_endpoint(
    addr: SocketAddr,
    server_config: Arc<RustlsServerConfig>,
    max_bidi: u8,
    iface: Option<&str>,
) -> io::Result<Endpoint> {
    let quic_crypto = QuicServerConfig::try_from(server_config).map_err(io_other)?;
    let mut sc = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(0u8.into());
    transport.max_concurrent_bidi_streams(max_bidi.into());
    sc.transport_config(Arc::new(transport));
    match iface {
        // No `#iface=`: quinn binds its own socket (the original path).
        None => Endpoint::server(sc, addr),
        // A device-bound listener. `quinn::TokioRuntime` is spelled out because
        // this module also imports wz's OWN `TokioRuntime` (the
        // `wz_runtime_core::Runtime` impl) — two unrelated types, one name.
        Some(iface) => {
            let sock = std::net::UdpSocket::bind(addr)?;
            crate::iface_bind::bind_socket_to_device(&sock, iface)?;
            Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(sc),
                sock,
                Arc::new(quinn::TokioRuntime),
            )
        }
    }
}

/// Accept one inbound QUIC connection from a *borrowed* server [`Endpoint`] and
/// complete its handshake — the accept-handshake SSOT for the DATAGRAM backend
/// ([`crate::quic_datagram_pipeline::accept_quic_datagram_on`]). Composes the
/// fast [`accept_quic_incoming`] arrival with the crypto handshake
/// (`incoming.await`); returns the established [`Connection`] BEFORE any stream is
/// accepted, since the datagram path rides datagrams rather than `accept_bi`-ing a
/// stream. Datagram-only (`transport-link-quic-datagram`): the STREAM backend went
/// through the split [`accept_quic_incoming`] / [`complete_quic_accept`] halves at
/// R311y404 (so the crypto defers off the accept loop) and no longer routes here.
#[cfg(feature = "transport-link-quic-datagram")]
pub(crate) async fn accept_quic_connection(endpoint: &Endpoint) -> io::Result<Connection> {
    let incoming = accept_quic_incoming(endpoint).await?;
    incoming.await.map_err(io_other)
}

/// Dial a QUIC connection to `addr` (SNI `server_name`, TLS-1.3 + ALPN-`hq-29`
/// `client_config` from [`crate::quic_config`]) and open the single bidirectional
/// stream. Returns a [`QuicLink`] ready for [`wire_quic_stream`]. The primitive
/// [`crate::session_open::dial_locator`] calls for a `quic/...` locator carrying
/// [`crate::session_open::DialConfig`]`.quic`. Mirrors zenoh's `new_link`: the
/// shared [`connect_quic_client`] handshake, then `open_bi`.
pub async fn dial_quic(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
    iface: Option<&str>,
) -> io::Result<QuicLink> {
    let (endpoint, connection) =
        connect_quic_client(addr, client_config, server_name, iface).await?;
    // The initiator opens the one bidirectional stream; the responder
    // `accept_bi`s it (zenoh: open_bi on dial, accept_bi on listen).
    let (send, recv) = connection.open_bi().await.map_err(io_other)?;
    Ok(QuicLink {
        endpoint,
        connection,
        send,
        recv,
    })
}

/// Bind a QUIC server [`Endpoint`] at `addr` presenting `server_config` — the
/// accept-side "listen half" symmetric to [`dial_quic`]. Restricts the connection
/// to ONE bidirectional stream and ZERO unidirectional (the shared
/// [`quic_server_endpoint`] with `max_bidi = 1`), mirroring zenoh's
/// `new_listener`, so the QUIC link is exactly one StreamEnvelope byte stream.
/// The caller owns the returned `Endpoint` and loops [`accept_quic_on`] over it.
///
/// R311y454 — `iface` is the `#iface=<name>` LISTEN-side bind, the parameter
/// shape the sibling acceptors already use (`bind_tcp`,
/// [`crate::udp_pipeline::bind_udp_demux`]). Still SYNC: `Endpoint::server` was
/// already binding a std socket and reaching for the ambient tokio runtime, so
/// the pre-bound arm adds no await.
pub fn bind_quic(
    addr: SocketAddr,
    server_config: Arc<RustlsServerConfig>,
    iface: Option<&str>,
) -> io::Result<Endpoint> {
    quic_server_endpoint(addr, server_config, 1, iface)
}

/// Accept the ARRIVAL of one inbound QUIC connection attempt from a *borrowed*
/// server [`Endpoint`] WITHOUT completing its crypto handshake — the fast,
/// non-blocking HALF of the accept the multi-peer
/// [`accept_loop`](crate::accept_loop) runs in its `select!` arm. Returns the
/// pending [`Incoming`], whose [`Incoming::remote_address`] already names the peer
/// (before the handshake); the caller drives the crypto to completion LATER via
/// [`complete_quic_accept`], off the accept path. This is the QUIC analogue of the
/// cheap TCP `accept` that precedes the DEFERRED tls SERVER handshake — a stalled
/// peer handshake never blocks accepting the next peer, which is what makes the
/// quic acceptor mesh-capable (R311y404). `None` (endpoint closed) maps to an
/// `io` error, matching [`accept_quic_connection`].
pub async fn accept_quic_incoming(endpoint: &Endpoint) -> io::Result<Incoming> {
    endpoint
        .accept()
        .await
        .ok_or_else(|| io_other("quic endpoint closed before a peer connected"))
}

/// Complete an [`accept_quic_incoming`] arrival: drive the QUIC crypto handshake
/// to an established [`Connection`] (`incoming.await`), then accept the peer's
/// single bidirectional stream (`accept_bi`) — the DEFERRED, potentially-slow HALF
/// of the accept, run in the spawned per-face open future (never the accept loop's
/// `select!` arm), the tls-server-handshake analogue. Yields the SAME [`QuicLink`]
/// the inline [`accept_quic_on`] produces; `endpoint` is the keep-alive clone
/// (`Incoming` holds an internal `EndpointRef`, but the public [`QuicLink`]
/// contract carries an [`Endpoint`] handle so the link outlives the listener).
/// `accept_bi` resolves once the peer (the initiator) opens + writes the stream —
/// which the wz handshake does immediately (its InitSyn is the first wire byte).
pub async fn complete_quic_accept(incoming: Incoming, endpoint: Endpoint) -> io::Result<QuicLink> {
    let connection = incoming.await.map_err(io_other)?;
    let (send, recv) = connection.accept_bi().await.map_err(io_other)?;
    Ok(QuicLink {
        endpoint,
        connection,
        send,
        recv,
    })
}

/// Accept ONE inbound QUIC connection from a *borrowed* server [`Endpoint`],
/// complete its handshake, and accept the peer's single bidirectional stream — the
/// QUIC mirror of [`crate::link_pipeline::accept_tcp_on`], INLINE (crypto + stream
/// back to back). Composes the [`accept_quic_incoming`] arrival with the deferred
/// [`complete_quic_accept`], so the split-half primitives stay the one SSOT. Since
/// R311y404 BOTH the one-shot [`crate::session_open::accept_bound`] AND the
/// multi-peer accept loop go through the two halves directly (accept_raw's arrival +
/// handshake's completion, so the crypto defers off the accept path); the only
/// remaining caller of this inline entry is the wz<->wz `quic_e2e` test, which wants
/// the crypto + stream back-to-back in one call. Returns a [`QuicLink`] (the
/// endpoint is cloned in as the keep-alive).
pub async fn accept_quic_on(endpoint: &Endpoint) -> io::Result<QuicLink> {
    let incoming = accept_quic_incoming(endpoint).await?;
    complete_quic_accept(incoming, endpoint.clone()).await
}

/// Wire a [`QuicLink`] into the cooperating drivers the session FSM consumes: an
/// inbound [`QuicReadDriver`] (`&mut LinkDriver` for the poll loop), an outbound
/// `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver` for `send_blocking`), and
/// the [`writer_task`](crate::stream_link::writer_task) join handle. The
/// `SendStream`/`RecvStream` are already a split pair (no `into_split` /
/// `tokio::io::split`); the endpoint + connection ride into the read driver as
/// the link keep-alive (module doc). StreamEnvelope framing + write driver are
/// the SAME shared [`crate::stream_link`] code as TCP/TLS.
pub fn wire_quic_stream(
    link: QuicLink,
) -> (QuicReadDriver, Arc<StreamWriteDriver>, TokioJoinHandle<()>) {
    let QuicLink {
        endpoint,
        connection,
        send,
        recv,
    } = link;
    // R311y453 — the §5.16 subject: quinn reports the endpoint's bound address.
    let subject = ip_link_subject(InterceptorLink::Quic, endpoint.local_addr().ok());
    // R311y473 — the adminspace `{src,dst}` pair: the endpoint's bound address is
    // this end, quinn's `Connection::remote_address` the peer's.
    let endpoints = crate::link_interfaces::ip_link_endpoints(
        InterceptorLink::Quic,
        endpoint.local_addr().ok(),
        Some(connection.remote_address()),
    );
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(send, rx));
    // transport-lowlatency is a TCP-path negotiation; QUIC keeps the universal
    // u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        subject,
        endpoints,
    ));
    let inbound = QuicReadDriver {
        inner: StreamReadDriver::new(recv, Arc::new(std::sync::atomic::AtomicBool::new(false))),
        _endpoint: endpoint,
        _connection: connection,
    };
    (inbound, outbound, writer_handle)
}
