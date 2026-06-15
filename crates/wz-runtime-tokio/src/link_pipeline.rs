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
//! - [`dial_tcp`] — the single raw-dial primitive: `proto/addr:port` ->
//!   connected [`TcpStream`]. The mode-agnostic `dial_locator(ParsedLocator)`
//!   dispatcher (R311eu) routes a `Proto::Tcp` endpoint here.
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
use tokio::net::TcpStream;
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

/// Dial an outbound TCP connection — the single raw-dial primitive for the
/// stream transport. Returns the connected [`TcpStream`] unwrapped so the
/// caller can choose its consumption shape: the session-open path splits it
/// via [`wire_tcp_stream`], while [`crate::TcpDriver::connect`] wraps it in
/// a unified driver. Connect-timeout / retry tuning is the caller's concern
/// (compose a `tokio::time::timeout`); the kernel default applies otherwise.
pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect(addr).await
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
