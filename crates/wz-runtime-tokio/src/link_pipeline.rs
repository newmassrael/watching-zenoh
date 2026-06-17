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
    let stream = TcpStream::connect(addr).await?;
    configure_tcp_stream(&stream);
    Ok(stream)
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
    let stream = TcpStream::connect(host).await?;
    configure_tcp_stream(&stream);
    Ok(stream)
}

/// Bind a TCP listener on a NUMERIC endpoint — the accept-side "listen half"
/// symmetric to dial's numeric [`dial_tcp`] (which connects). Returns the
/// bound [`TcpListener`] so the caller observes `local_addr()` (the OS-chosen
/// port for a `:0` bind) BEFORE the blocking accept — which is what lets the
/// accept path be unit-tested race-free, the same way the dial loopback unit
/// learns its port. Quiet, like the dial primitives: logging is the caller's
/// concern (the Acceptor's "listening on" line; the Initiator's "connected
/// to"). Numeric only by construction, mirroring [`dial_tcp`]; [`bind_tcp_host`]
/// is the DNS-capable sibling.
pub async fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Bind a TCP listener on a `host:port` STRING — the DNS-capable sibling of
/// [`bind_tcp`], symmetric to [`dial_tcp_host`]. `TcpListener::bind` takes
/// `ToSocketAddrs`, so a hostname resolves via the std resolver and a numeric
/// string binds directly, through the same call the dial host primitive uses.
/// (Listen-side hostnames are unusual but the resolver path is identical.)
pub async fn bind_tcp_host(host: &str) -> io::Result<TcpListener> {
    TcpListener::bind(host).await
}

/// Accept ONE inbound connection from a bound [`TcpListener`] — the accept-side
/// completion of [`bind_tcp`] / [`bind_tcp_host`], returning the accepted
/// [`TcpStream`] + its peer address. Quiet (no log): the caller owns the
/// "listening on" / "accepted peer" lines, so the log prefix is the caller's
/// (the demo tags `wz accept:`, the e2e harness tags its binary name) — the
/// accept-side reason the dial primitives are also log-free.
///
/// ONE-shot (not a loop): the session-open contract is a single peer link, the
/// accept-side mirror of the single [`TcpStream`] [`dial_tcp`] returns. A
/// multi-peer router composes its own accept loop over [`bind_tcp`] above this.
pub async fn accept_tcp(listener: TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    let (stream, peer) = listener.accept().await?;
    configure_tcp_stream(&stream);
    Ok((stream, peer))
}

/// Apply zenoh's per-link TCP socket tuning to a freshly connected / accepted
/// stream: `TCP_NODELAY` on — disable Nagle so every wz frame ships at once,
/// the low-latency posture zenoh sets on every link (upstream
/// `LinkUnicastTcp::new`, `io/zenoh-links/zenoh-link-tcp/src/unicast.rs:55`).
/// `new` is zenoh's SHARED dial + accept link constructor, so both `dial_tcp` /
/// `dial_tcp_host` and `accept_tcp` route their stream through here — the SSOT
/// for wz's per-link TCP tuning.
///
/// Best-effort, matching zenoh (which `tracing::warn!`s and continues): a
/// nodelay-set failure is logged and the link proceeds (Nagle-on is a latency
/// degradation, not a correctness failure). The warning is the one log this
/// otherwise-quiet primitive emits, and only on the abnormal path.
///
/// `SO_LINGER` is DELIBERATELY NOT set, diverging from zenoh's `set_linger(10s)`
/// (unicast.rs:65): `tokio::net::TcpStream::set_linger` is deprecated because
/// SO_LINGER makes `close()` BLOCK the worker thread on drop — a footgun in an
/// async runtime. zenoh's synchronous socket layer can afford it; wz on tokio
/// must not blindly mirror it. The graceful-close intent (drain tail bytes
/// before teardown) is already served at the application layer by wz-ap-demo's
/// R292 teardown chain (writer drain + Close frame), and a normal non-linger
/// close still lets the kernel background-deliver queued bytes, so nothing is
/// lost — only the thread-blocking drop is avoided.
///
/// Distinct from R311pz's reverted `SO_REUSEADDR`: tokio's `TcpStream` does NOT
/// set nodelay by default, so this closes a REAL behavioral parity gap — and a
/// non-vacuous one (a unit reads `nodelay()` back and distinguishes
/// set-from-unset precisely because tokio's default is off).
fn configure_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        log::warn!("wz tcp: set_nodelay(true) failed (Nagle stays on): {e}");
    }
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

    /// `bind_tcp` + `accept_tcp` complete a loopback connection race-free: the
    /// test learns the OS-chosen port from the bound listener BEFORE the client
    /// connects, the accept-side mirror of session_open's dial loopback unit.
    /// Splitting bind from accept is what exposes `local_addr` and removes the
    /// port race the prior one-shot `accept_tcp(listen)` form could not avoid.
    #[tokio::test]
    async fn bind_tcp_then_accept_tcp_round_trip() {
        let listener = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"))
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, peer) = accept_tcp(listener).await.expect("accept one peer");
        client.await.expect("client task").expect("client connect");
        assert_eq!(peer.ip(), addr.ip(), "accepted peer is the loopback client");
        assert!(server.peer_addr().is_ok(), "server stream is connected");
    }

    /// `dial_tcp` + `accept_tcp` set `TCP_NODELAY` on both ends (zenoh per-link
    /// parity, `configure_tcp_stream`). NON-vacuous: tokio's `TcpStream`
    /// defaults to nodelay=OFF, so reading `nodelay()` back distinguishes
    /// set-from-unset — the R311pz lesson (its `SO_REUSEADDR` pin was vacuous
    /// because tokio already set that on Unix; nodelay is genuinely wz-set).
    /// `SO_LINGER` is intentionally NOT set (tokio deprecates it; see
    /// `configure_tcp_stream`), so there is nothing to assert for it.
    #[tokio::test]
    async fn dialed_and_accepted_streams_have_nodelay() {
        let listener = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"))
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = tokio::spawn(async move { dial_tcp(addr).await });
        let (server, _peer) = accept_tcp(listener).await.expect("accept one peer");
        let client_stream = client.await.expect("client task").expect("client dial");
        assert!(
            client_stream.nodelay().expect("read nodelay (dial side)"),
            "dial_tcp must set TCP_NODELAY (tokio default is off)"
        );
        assert!(
            server.nodelay().expect("read nodelay (accept side)"),
            "accept_tcp must set TCP_NODELAY (tokio default is off)"
        );
    }
}
