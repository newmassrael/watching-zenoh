// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311et — canonical split-link session-open transport pipeline (TCP).
//!
//! The TCP instantiation of the transport-neutral byte-stream link machinery
//! in [`crate::stream_link`] (the read/write drivers + the StreamEnvelope
//! [`writer_task`](crate::stream_link::writer_task)). This module carries only
//! the TCP-specific dial + split; the framing drivers are shared with TLS
//! ([`crate::tls_pipeline`]) so the StreamEnvelope wire shape has a single
//! source of truth. See the module-level doc on [`crate::link_pipeline`]
//! (lib.rs) for why the read/write split is forced by the `&mut LinkDriver` /
//! `Arc<dyn BoxedLinkDriver>` shape mismatch and why the non-blocking channel
//! — not `Handle::block_on` — is the textbook sync-action / async-runtime
//! decoupling.
//!
//! ## Pieces
//!
//! - [`dial_tcp`] / [`dial_tcp_host`] — the TCP raw-dial primitives: a NUMERIC
//!   `SocketAddr` and a DNS-capable `host:port` STRING respectively, both ->
//!   connected [`TcpStream`]. The mode-agnostic `dial_locator(AnyLocator)`
//!   dispatcher (R311eu) routes a numeric `Proto::Tcp` endpoint to `dial_tcp`
//!   and an `AnyLocator::Named` tcp endpoint to `dial_tcp_host` (R311ps).
//! - [`wire_tcp_stream`] — splits a connected stream into the cooperating
//!   `(TcpReadDriver, Arc<`[`StreamWriteDriver`]`>, writer-task handle)`
//!   triple, building on the shared [`crate::stream_link`] drivers.
//! - [`TcpReadDriver`] — a type alias for the shared
//!   [`StreamReadDriver`]`<OwnedReadHalf>` (the framing `LinkDriver` impl lives
//!   once in [`crate::stream_link`]).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};

/// Inbound read driver of a split `TcpStream` — the TCP instantiation of the
/// shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`] impl lives
/// once in [`crate::stream_link`]; this alias just pins the stream half to
/// TCP's `OwnedReadHalf`. [`crate::tls_pipeline::TlsReadDriver`] is the TLS
/// sibling over a `ReadHalf<TlsStream<TcpStream>>`.
pub type TcpReadDriver = StreamReadDriver<OwnedReadHalf>;

/// Dial an outbound TCP connection to a NUMERIC endpoint — the raw-dial
/// primitive the mode-agnostic `dial_locator(Proto::Tcp)` dispatcher (R311eu)
/// routes a parsed [`SocketAddr`] to. Returns the connected [`TcpStream`]
/// unwrapped so the caller can choose its consumption shape: the session-open
/// path splits it via [`wire_tcp_stream`], while [`crate::TcpDriver::connect`]
/// wraps it in a unified driver. Connect-timeout / retry tuning is the
/// caller's concern (compose a `tokio::time::timeout`); the kernel default
/// applies otherwise.
///
/// Numeric only by construction: the no_std locator parser
/// ([`wz_session_core::locator`]) resolves a locator to a [`SocketAddr`],
/// deferring DNS to the std layer. [`dial_tcp_host`] is the DNS-capable
/// sibling for a `host:port` STRING.
pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

/// Dial an outbound TCP connection to a `host:port` STRING — the DNS-capable
/// sibling of [`dial_tcp`]. This is the std-layer home of the DNS resolution
/// the no_std locator parser ([`wz_session_core::locator`]) deliberately
/// defers (a hostname is not a numeric [`SocketAddr`]): `TcpStream::connect`
/// takes `ToSocketAddrs`, so a DNS name is resolved by the std resolver and
/// every resolved address is tried in order until one connects. A purely
/// numeric string (`"127.0.0.1:7447"`, `"[::1]:7447"`) routes through the
/// same call without touching the resolver.
///
/// Used by the session-open dial seam ([`crate::session_open::dial_endpoint`])
/// for a scheme-less `--connect HOST:PORT` and a `tcp/HOST` with a DNS
/// hostname; the numeric [`dial_tcp`] handles a parsed `tcp/` locator.
pub async fn dial_tcp_host(host: &str) -> io::Result<TcpStream> {
    TcpStream::connect(host).await
}

/// Bind a TCP listener on a `host:port` STRING and accept ONE inbound
/// connection — the accept-side primitive symmetric to [`dial_tcp_host`].
/// `TcpListener::bind` takes `ToSocketAddrs`, so a numeric `127.0.0.1:7447`,
/// a wildcard `0.0.0.0:7447`, or a DNS name all bind through the same call,
/// mirroring how the dial sibling resolves its target. Returns the accepted
/// [`TcpStream`] + the peer address; the caller splits it via
/// [`wire_tcp_stream`] exactly as the dial path does, so the steady state is
/// role-agnostic.
///
/// ONE-shot accept (not a loop): the session-open contract is a single peer
/// link, the accept-side mirror of the single [`TcpStream`] [`dial_tcp`] /
/// [`dial_tcp_host`] return. A multi-peer router would own its own accept
/// loop ABOVE this primitive, not inside it. The listening address is logged
/// before the (blocking) accept so a developer sees which port came up.
pub async fn accept_tcp(listen: &str) -> io::Result<(TcpStream, SocketAddr)> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("wz accept_tcp: listening on {}", listener.local_addr()?);
    let (stream, peer) = listener.accept().await?;
    log::info!("wz accept_tcp: accepted peer {peer}");
    Ok((stream, peer))
}

/// Split a connected [`TcpStream`] into the cooperating drivers the session
/// FSM consumes: an inbound [`TcpReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`writer_task`](crate::stream_link::writer_task)
/// join handle.
///
/// The `Arc` lets the FSM's `SessionLinkActions` keep the outbound side alive
/// while the writer task drains the channel; the handle is awaited during
/// teardown so a tail frame the FSM enqueued during its final transition still
/// reaches the peer before the socket closes.
pub fn wire_tcp_stream(
    stream: TcpStream,
) -> (TcpReadDriver, Arc<StreamWriteDriver>, TokioJoinHandle<()>) {
    let (reader, writer) = stream.into_split();
    let inbound = StreamReadDriver::new(reader);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(writer, rx));
    let outbound = Arc::new(StreamWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dial_tcp` surfaces a connect error rather than panicking when the
    /// target refuses (nothing listening on a freed loopback port).
    #[tokio::test]
    async fn dial_tcp_surfaces_connect_error() {
        // Bind then drop to obtain a port with no listener.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe bind");
        let dead = probe.local_addr().expect("probe addr");
        drop(probe);
        assert!(dial_tcp(dead).await.is_err(), "dial to closed port errors");
    }
}
