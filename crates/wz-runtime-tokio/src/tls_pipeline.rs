// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use crate::link_interfaces::ip_link_subject;
use crate::stream_link::{
    peer_chain_deadline, sleep_until_unix, writer_task, ExpirySignal, StreamReadDriver,
    StreamWriteDriver,
};
use crate::writer_queue::WriterHandle;
use wz_session_core::link::InterceptorLink;

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
    link_socket: &crate::link_socket::LinkSocket<'_>,
) -> io::Result<TlsStream<TcpStream>> {
    // R311y236 — the TCP under a TLS dial honours the locator `#iface=` bind via
    // the shared connect primitive (SO_BINDTODEVICE before connect).
    // R2590 — and its `#bind=` and `#dscp=`: upstream's tls dial builds its TCP
    // through the same `TcpSocketConfig` its tcp dial does.
    let tcp = crate::iface_bind::connect_tcp_bound(addr, link_socket).await?;
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
/// R2609 — `handshake_timeout` bounds the rustls SERVER handshake, as upstream
/// bounds it on its listener builder
/// (`io/zenoh-links/zenoh-link-tls/src/unicast.rs` @ `.handshake_timeout(tls_handshake_timeout)`).
///
/// ⚠ It is NOT optional, and that is upstream's shape rather than a choice
/// made here: upstream reads the key with `.unwrap_or(..DEFAULT)`, so every
/// listener carries ten seconds and the key only MOVES it. A wz that bounded
/// only the locators naming the key would satisfy the config-key gate and
/// still diverge everywhere the key is absent.
///
/// ⚠ The bound is about reclaiming a stuck task, NOT about keeping the
/// acceptor alive: wz already runs this handshake in a spawned future rather
/// than the accept loop's `select!` arm, so a peer that never sends a
/// ClientHello cannot stall the listener with or without it. Upstream's own
/// motivation is stronger than wz's here, and saying otherwise would overstate
/// the parity.
pub async fn accept_tls(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    handshake_timeout: std::time::Duration,
) -> io::Result<TlsStream<TcpStream>> {
    let acceptor = TlsAcceptor::from(config);
    let tls = tokio::time::timeout(handshake_timeout, acceptor.accept(tcp))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "tls accept: the peer did not finish the handshake within {}ms",
                    handshake_timeout.as_millis()
                ),
            )
        })??;
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
/// R2608 — `close_link_on_expiration` arrives as the second argument because
/// the chain it needs is readable only before the split below, and the LOCATOR
/// that asked for it is three frames up the stack.
pub fn wire_tls_stream(
    stream: TlsStream<TcpStream>,
    closes_on_expiration: bool,
) -> (TlsReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // R311y453 — the §5.16 subject: a TLS link is a TCP socket underneath, so
    // its local address comes from the wrapped stream.
    // R2698 — the ACL's cert-common-name axis is filled HERE and only here, in
    // the same before-the-split window the expiry below explains: this is the
    // last moment `stream.get_ref().1` is a rustls connection. Read
    // UNCONDITIONALLY, unlike the expiry, because no config key gates whether a
    // rule may name a peer — the deadline is opt-in behaviour, the identity is
    // just what the link knows about itself.
    let subject = ip_link_subject(InterceptorLink::Tls, stream.get_ref().0.local_addr().ok())
        .with_cert_common_name(crate::stream_link::peer_chain_common_name(
            stream.get_ref().1.peer_certificates(),
        ));
    // R311y473 — the adminspace `{src,dst}` pair, read off the same wrapped TCP
    // socket and in the same before-the-split window as the subject above.
    let endpoints = crate::link_interfaces::ip_link_endpoints(
        InterceptorLink::Tls,
        stream.get_ref().0.local_addr().ok(),
        stream.get_ref().0.peer_addr().ok(),
    );
    // R2608 — the peer's chain is read HERE, before the split, because this is
    // the last moment it exists: `stream.get_ref().1` is the rustls connection
    // and `split` consumes the stream. Reading it after would need the raw fd,
    // which is reaching around the abstraction rather than through it.
    let expiry = closes_on_expiration
        .then(|| peer_chain_deadline(stream.get_ref().1.peer_certificates()))
        .flatten();
    let (reader, writer) = split(stream);
    // transport-lowlatency is a TCP-path negotiation; TLS keeps the universal
    // u16 prefix (an always-false flag).
    let mut inbound =
        StreamReadDriver::new(reader, Arc::new(std::sync::atomic::AtomicBool::new(false)));
    if let Some(deadline) = expiry {
        // An absent chain is NOT an immediate expiry — `peer_chain_deadline`
        // answers `None` there, as upstream does, and this arm never runs.
        let signal = Arc::new(ExpirySignal::default());
        inbound.set_expiry(Arc::clone(&signal));
        crate::runtime_pool::WzRuntime::Net.spawn(async move {
            sleep_until_unix(deadline).await;
            signal.fire();
        });
    }
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| writer_task(writer, queue));
    // transport-lowlatency is a TCP-path negotiation; TLS keeps the universal
    // u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        subject,
        endpoints,
    ));
    (inbound, outbound, writer_handle)
}
