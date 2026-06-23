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
    ClientConfig as QuinnClientConfig, Connection, Endpoint, RecvStream, SendStream,
    ServerConfig as QuinnServerConfig, TransportConfig,
};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::{LinkDriver, LinkEvent, Reliability, TxFrame};

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
fn io_other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(err)
}

/// The unspecified bind address of the same IP family as `target` — a QUIC
/// client endpoint binds an ephemeral local UDP socket, and it must match the
/// target's family (a V4 socket cannot reach a V6 peer). Mirrors zenoh's
/// INADDR_ANY / in6addr_any auto-select on dial (`zenoh-link-quic` `new_link`).
fn client_bind_addr(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

/// Dial a QUIC connection to `addr`, verifying the server against `client_config`
/// (a TLS-1.3 + ALPN-`hq-29` rustls config from [`crate::quic_config`]) with
/// `server_name` as the SNI / cert name, then open the single bidirectional
/// stream. Returns a [`QuicLink`] ready for [`wire_quic_stream`].
///
/// The primitive [`crate::session_open::dial_locator`] calls when a `quic/...`
/// locator carries a [`crate::session_open::DialConfig`]`.quic` (the TLS-style
/// cert threading); also callable directly. Mirrors zenoh's `new_link`: bind a
/// client `Endpoint`, install the rustls client config, `connect`, `open_bi`.
pub async fn dial_quic(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
) -> io::Result<QuicLink> {
    let mut endpoint = Endpoint::client(client_bind_addr(addr))?;
    let quic_crypto = QuicClientConfig::try_from(client_config).map_err(io_other)?;
    endpoint.set_default_client_config(QuinnClientConfig::new(Arc::new(quic_crypto)));

    let connection = endpoint
        .connect(addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
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

/// Bind a QUIC server [`Endpoint`] at `addr` presenting `server_config` (a
/// TLS-1.3 + ALPN-`hq-29` rustls server config from [`crate::quic_config`]) —
/// the accept-side "listen half" symmetric to [`dial_quic`]. Restricts the
/// connection to ONE bidirectional stream and ZERO unidirectional, mirroring
/// zenoh's `new_listener` (`max_concurrent_uni_streams(0)` /
/// `max_concurrent_bidi_streams(1)`), so the QUIC link is exactly one
/// StreamEnvelope byte stream. The caller (the e2e harness / a future acceptor)
/// owns the returned `Endpoint` and loops [`accept_quic_on`] over it.
pub fn bind_quic(addr: SocketAddr, server_config: Arc<RustlsServerConfig>) -> io::Result<Endpoint> {
    let quic_crypto = QuicServerConfig::try_from(server_config).map_err(io_other)?;
    let mut sc = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(0u8.into());
    transport.max_concurrent_bidi_streams(1u8.into());
    sc.transport_config(Arc::new(transport));
    Endpoint::server(sc, addr)
}

/// Accept ONE inbound QUIC connection from a *borrowed* server [`Endpoint`],
/// complete its handshake, and accept the peer's single bidirectional stream —
/// the QUIC mirror of [`crate::link_pipeline::accept_tcp_on`]. Returns a
/// [`QuicLink`] (the endpoint is cloned in as the keep-alive). Borrowing the
/// endpoint lets a multi-peer acceptor loop. `accept_bi` resolves once the peer
/// (the initiator) opens + writes the stream — which the wz handshake does
/// immediately (the initiator's InitSyn is the first wire byte), so this is the
/// accept-side counterpart of a TCP `accept` resolving after `connect`.
pub async fn accept_quic_on(endpoint: &Endpoint) -> io::Result<QuicLink> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| io_other("quic endpoint closed before a peer connected"))?;
    let connection = incoming.await.map_err(io_other)?;
    let (send, recv) = connection.accept_bi().await.map_err(io_other)?;
    Ok(QuicLink {
        endpoint: endpoint.clone(),
        connection,
        send,
        recv,
    })
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
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(send, rx));
    let outbound = Arc::new(StreamWriteDriver::new(tx));
    let inbound = QuicReadDriver {
        inner: StreamReadDriver::new(recv),
        _endpoint: endpoint,
        _connection: connection,
    };
    (inbound, outbound, writer_handle)
}
