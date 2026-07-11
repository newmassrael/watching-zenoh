// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311oa — TLS-over-TCP session-open transport pipeline.
//!
//! The secured-stream sibling of [`crate::link_pipeline`] (plain TCP). A TLS
//! link IS a TCP byte stream with a rustls session wrapped around it, so it
//! reuses the transport-neutral byte-stream machinery in [`crate::stream_link`]
//! UNCHANGED — the [`StreamReadDriver`] framing `LinkDriver` impl, the
//! [`StreamWriteDriver`] channel, and the StreamEnvelope
//! [`writer_task`](crate::stream_link::writer_task). This module carries only
//! the TLS-specific dial/accept (the rustls handshake) and the split, since a
//! TLS stream is split with [`tokio::io::split`] (not `TcpStream::into_split`,
//! which has no analogue on a `TlsStream`). The link MTU is the unbounded
//! stream default (zenoh-pico's `_z_get_link_mtu_tls` = 65535, the TCP
//! ceiling), so — like TCP — the write driver overrides nothing.
//!
//! ## Cert config is threaded through the dial seam (not the locator string)
//!
//! zenoh-pico reads TLS cert material from the session config
//! (`_z_new_link_tls(zl, endpoint, session_cfg)`, `src/link/unicast/tls.c`).
//! wz mirrors this (R311oc): a `tls/...` locator dials through the generic
//! [`crate::session_open::dial_locator`] like every other transport, with the
//! rustls [`ClientConfig`] + server name supplied out-of-band via the threaded
//! [`crate::session_open::DialConfig`]`.tls`. A locator with no such config
//! dials to a typed `Unsupported` (no certs to verify the peer), so a TLS dial
//! is opt-in. This keeps the TLS POLICY (which roots to trust, which cert to
//! present) in the application — passed as config, not baked into a transport
//! string — while making the dial seam the single path for ALL transports.
//!
//! [`dial_tls`] / [`accept_tls`] are the PRIMITIVES `dial_locator` (and any
//! explicit caller, e.g. an acceptor that owns its `TcpListener::accept`) build
//! on; they produce a [`crate::session_open::DialedLink::Tls`] for
//! `initiate_and_open_session` / `accept_and_open_session`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{split, ReadHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};

/// Inbound read driver of a split [`TlsStream`] — the TLS instantiation of the
/// shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`] impl lives
/// once in [`crate::stream_link`] (a TLS link frames identically to TCP — same
/// StreamEnvelope, same `poll_framed`); this alias just pins the stream half to
/// the `tokio::io::split` read half of a `TlsStream<TcpStream>`.
pub type TlsReadDriver = StreamReadDriver<ReadHalf<TlsStream<TcpStream>>>;

/// Dial a TLS-over-TCP connection — TCP-connect to `addr`, then run the rustls
/// client handshake against `server_name` (SNI + cert-name verification)
/// using `config`. Returns the handshaked [`TlsStream`] ready for
/// [`wire_tls_stream`]. The trust policy is the caller's `config` (a
/// [`ClientConfig`] whose root store trusts the peer's cert). The primitive
/// `dial_locator` calls when a `tls/...` locator carries a
/// [`crate::session_open::DialConfig`]`.tls` (R311oc); also callable directly.
pub async fn dial_tls(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    iface: Option<&str>,
) -> io::Result<TlsStream<TcpStream>> {
    // R311y236 — the TCP under a TLS dial honours the locator `#iface=` bind via
    // the shared connect primitive (SO_BINDTODEVICE before connect).
    let tcp = crate::iface_bind::connect_tcp_bound(addr, iface).await?;
    let connector = TlsConnector::from(config);
    // `client::TlsStream` -> the unified `TlsStream` enum so the wire path is
    // one type for both roles (the byte stream is identical post-handshake).
    let tls = connector.connect(server_name, tcp).await?;
    Ok(TlsStream::Client(tls))
}

/// Accept side — wrap an already-accepted [`TcpStream`] in the rustls server
/// handshake using `config` (a [`ServerConfig`] carrying the cert chain +
/// private key). The acceptor's caller owns the `TcpListener::accept`; this is
/// the TLS analogue of handing `accept_and_open_session` a `DialedLink::Tcp`.
pub async fn accept_tls(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let acceptor = TlsAcceptor::from(config);
    let tls = acceptor.accept(tcp).await?;
    Ok(TlsStream::Server(tls))
}

/// Split a handshaked [`TlsStream`] into the cooperating drivers the session
/// FSM consumes: an inbound [`TlsReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`writer_task`](crate::stream_link::writer_task)
/// join handle. Mirrors [`crate::link_pipeline::wire_tcp_stream`]; a TLS stream
/// is split with [`tokio::io::split`] (no owned-half split exists) but
/// otherwise the StreamEnvelope framing and write driver are the SAME shared
/// [`crate::stream_link`] code.
pub fn wire_tls_stream(
    stream: TlsStream<TcpStream>,
) -> (TlsReadDriver, Arc<StreamWriteDriver>, TokioJoinHandle<()>) {
    let (reader, writer) = split(stream);
    let inbound = StreamReadDriver::new(reader);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(writer, rx));
    let outbound = Arc::new(StreamWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}
