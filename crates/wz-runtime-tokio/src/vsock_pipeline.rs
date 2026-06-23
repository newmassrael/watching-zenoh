// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xj — AF_VSOCK (VM<->host / VM<->VM) session-open transport pipeline.
//!
//! The vsock sibling of [`crate::link_pipeline`] (TCP) / [`crate::unixsock_pipeline`].
//! A vsock connection IS a reliable byte stream — `is_streamed() = true`,
//! `is_reliable() = true`, MTU `BatchSize::MAX` (zenoh's `VSOCK_DEFAULT_MTU`,
//! `io/zenoh-links/zenoh-link-vsock/src/{lib,unicast}.rs`) — so it reuses the
//! transport-neutral byte-stream machinery in [`crate::stream_link`] UNCHANGED:
//! the [`StreamReadDriver`] StreamEnvelope framing `LinkDriver` impl, the
//! [`StreamWriteDriver`] channel, and the
//! [`writer_task`](crate::stream_link::writer_task).
//!
//! Unlike TCP / unixsock (whose `into_split` yields owned halves), a
//! [`tokio_vsock::VsockStream`] has no owned-half split, so this module splits
//! it with [`tokio::io::split`] — exactly the shape [`crate::tls_pipeline`]
//! uses for its un-owned `TlsStream`. Otherwise the StreamEnvelope wire is the
//! SAME shared code: vsock is "TCP addressed by `(cid, port)` instead of
//! `ip:port`", with no filesystem artifact (UNLIKE unixsock — no socket file,
//! no lock-file lifecycle; `VsockListener::bind` is clean like `TcpListener`).
//!
//! ## Linux-only
//!
//! AF_VSOCK is a Linux socket family, so this whole module is
//! `#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]` (the
//! same platform gate zenoh-link-vsock carries) and pulls the Linux-only,
//! optional [`tokio_vsock`] dep. The `vsock/<CID>:<PORT>` LOCATOR parse is
//! platform-independent and lives ungated in
//! [`wz_session_core::locator`] — only this dial/accept BACKEND is gated. Off
//! Linux (or with the feature off) a `vsock/...` locator dials to a typed
//! `Unsupported` in [`crate::session_open::dial_locator`], like serial/udp.
//!
//! [`dial_vsock`] is the PRIMITIVE [`crate::session_open::dial_locator`] builds
//! on; [`wire_vsock_stream`] produces the
//! [`crate::session_open::DialedLink::Vsock`] split.

use std::io;
use std::sync::Arc;

use tokio::io::{split, ReadHalf};
use tokio::sync::mpsc;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};

/// Inbound read driver of a split [`VsockStream`] — the vsock instantiation of
/// the shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`] impl
/// lives once in [`crate::stream_link`] (a vsock link frames identically to TCP
/// — same StreamEnvelope, same `poll_framed`); this alias pins the stream half
/// to the [`tokio::io::split`] read half of a `VsockStream` (no owned-half
/// split exists, so — like [`crate::tls_pipeline::TlsReadDriver`] — it rides
/// `ReadHalf`, not TCP's `OwnedReadHalf`).
pub type VsockReadDriver = StreamReadDriver<ReadHalf<VsockStream>>;

/// Dial an outbound AF_VSOCK connection to `(cid, port)` — the raw-dial
/// primitive the mode-agnostic `dial_locator(AnyLocator::Vsock)` dispatcher
/// (R311xj) routes a parsed [`wz_session_core::locator::VsockEndpoint`] to.
/// Returns the connected [`VsockStream`] unwrapped so the caller chooses its
/// consumption shape ([`wire_vsock_stream`] for the session-open split).
///
/// No per-link tuning: a vsock socket has no Nagle / TCP options (the TCP
/// path's `configure_tcp_stream` has no vsock analogue) — mirroring zenoh's
/// `VsockStream::connect` with no extra socket setup (`unicast.rs`, `new_link`).
pub async fn dial_vsock(cid: u32, port: u32) -> io::Result<VsockStream> {
    VsockStream::connect(VsockAddr::new(cid, port)).await
}

/// Bind an AF_VSOCK listener at `(cid, port)` — the accept-side "listen half"
/// symmetric to dial's [`dial_vsock`], so a caller (the e2e harness, a future
/// acceptor) observes the bound listener BEFORE the blocking accept, race-free,
/// the same split [`crate::link_pipeline::bind_tcp`] established.
///
/// UNLIKE [`crate::unixsock_pipeline::bind_unixsock`], there is NO stale-file
/// cleanup: vsock leaves no filesystem artifact (`VsockListener::bind` is clean
/// like `TcpListener::bind`, zenoh `new_listener`). Binding `port =
/// VMADDR_PORT_ANY` lets the kernel assign an ephemeral port, readable via
/// `listener.local_addr()` (the race-free port-learn the dial side then targets).
pub fn bind_vsock(cid: u32, port: u32) -> io::Result<VsockListener> {
    VsockListener::bind(VsockAddr::new(cid, port))
}

/// Accept ONE inbound connection from a mutably-borrowed [`VsockListener`],
/// returning the accepted [`VsockStream`] — the vsock mirror of
/// [`crate::link_pipeline::accept_tcp_on`]. Takes `&mut` (NOT `&` like the TCP /
/// unixsock acceptors): `tokio_vsock::VsockListener::accept` is `&mut self`,
/// not `&self`, so the borrow follows the upstream API. A multi-peer acceptor
/// still loops over the one listener it owns (exclusive `&mut` across accepts).
/// The peer [`VsockAddr`] is discarded (no routing identity worth threading
/// here; the session learns the peer zid from the handshake, as for every
/// transport). No per-link tuning.
pub async fn accept_vsock_on(listener: &mut VsockListener) -> io::Result<VsockStream> {
    let (stream, _peer) = listener.accept().await?;
    Ok(stream)
}

/// Split a connected [`VsockStream`] into the cooperating drivers the session
/// FSM consumes: an inbound [`VsockReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`writer_task`](crate::stream_link::writer_task)
/// join handle. Mirrors [`crate::tls_pipeline::wire_tls_stream`] — a vsock
/// stream is split with [`tokio::io::split`] (no owned-half split) but
/// otherwise the StreamEnvelope framing + write driver are the SAME shared
/// [`crate::stream_link`] code.
pub fn wire_vsock_stream(
    stream: VsockStream,
) -> (VsockReadDriver, Arc<StreamWriteDriver>, TokioJoinHandle<()>) {
    let (reader, writer) = split(stream);
    let inbound = StreamReadDriver::new(reader);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(writer, rx));
    let outbound = Arc::new(StreamWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::locator::{VMADDR_CID_LOCAL, VMADDR_PORT_ANY};

    /// `bind_vsock` + `accept_vsock_on` + `dial_vsock` complete a loopback
    /// connection over `VMADDR_CID_LOCAL` — the vsock mirror of the unixsock /
    /// TCP round-trip.
    ///
    /// `#[ignore]`: AF_VSOCK loopback needs the `vsock_loopback` kernel module
    /// (`VMADDR_CID_LOCAL`), which is absent in the default dev/CI sandbox
    /// (no `/dev/vsock`). This runs on a vsock-capable host via
    /// `cargo test --features transport-link-vsock -- --ignored` — the same
    /// environment-gated shape the Layer Z cross-impl tests use. The data path
    /// it would exercise (StreamEnvelope over the split stream) is already
    /// proven by the TCP / TLS / unixsock lanes; this asserts the
    /// vsock-specific bind/accept/dial wiring on a host that supports it.
    #[tokio::test]
    #[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
    async fn bind_accept_dial_round_trip_on_cid_local() {
        let mut listener =
            bind_vsock(VMADDR_CID_LOCAL, VMADDR_PORT_ANY).expect("bind vsock loopback listener");
        let port = listener.local_addr().expect("bound local addr").port();
        let client = tokio::spawn(async move { dial_vsock(VMADDR_CID_LOCAL, port).await });
        let _server = accept_vsock_on(&mut listener)
            .await
            .expect("accept one peer");
        let _client_stream = client.await.expect("client task").expect("client connect");
    }
}
