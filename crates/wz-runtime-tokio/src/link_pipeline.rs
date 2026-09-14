// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   dispatcher (R311eu) routes a numeric `InterceptorLink::Tcp` endpoint to `dial_tcp`
//!   and an `AnyLocator::Named` tcp endpoint to `dial_tcp_host` (R311ps).
//! - [`wire_tcp_stream`] — splits a connected stream into the cooperating
//!   `(TcpReadDriver, Arc<`[`StreamWriteDriver`]`>, writer-task handle)`
//!   triple, building on the shared [`crate::stream_link`] drivers.
//! - [`TcpReadDriver`] — a type alias for the shared
//!   [`StreamReadDriver`]`<OwnedReadHalf>` (the framing `LinkDriver` impl lives
//!   once in [`crate::stream_link`]).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{lookup_host, TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;

use crate::link_interfaces::{ip_link_endpoints, ip_link_subject};
use crate::link_socket::LinkSocket;
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::WriterHandle;
use wz_session_core::link::InterceptorLink;

/// Inbound read driver of a split `TcpStream` — the TCP instantiation of the
/// shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`] impl lives
/// once in [`crate::stream_link`]; this alias just pins the stream half to
/// TCP's `OwnedReadHalf`. [`crate::tls_pipeline::TlsReadDriver`] is the TLS
/// sibling over a `ReadHalf<TlsStream<TcpStream>>`.
pub type TcpReadDriver = StreamReadDriver<OwnedReadHalf>;

/// Dial an outbound TCP connection to a NUMERIC endpoint — the raw-dial
/// primitive the mode-agnostic `dial_locator(InterceptorLink::Tcp)` dispatcher (R311eu)
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
pub async fn dial_tcp(addr: SocketAddr, link_socket: &LinkSocket<'_>) -> io::Result<TcpStream> {
    // R311y236 — the `#iface=` connect helper lives in the ungated
    // [`crate::iface_bind`] module (NOT here) so `ws_pipeline` (which does NOT
    // pull `transport-link-tcp`) can also reach it without dragging in the whole
    // TCP stream pipeline.
    // R2355 — no `configure_tcp_stream` call here any more: the primitive tunes
    // the stream it returns, so tcp/ws/tls are tuned by the SAME step instead of
    // by three remembered ones (two of which were not taken).
    crate::iface_bind::connect_tcp_bound(addr, link_socket).await
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
pub async fn dial_tcp_host(host: &str, link_socket: &LinkSocket<'_>) -> io::Result<TcpStream> {
    // R311y236 — a device-bound named dial must resolve first, then connect each
    // candidate through a device-bound `TcpSocket` (the bind precedes connect);
    // `lookup_host` is the std resolver `TcpStream::connect` otherwise uses
    // internally, made explicit so each attempt can carry the bind. Tries in
    // resolved order until one connects.
    //
    // R2355 — the unbound arm walks the SAME resolved list through the SAME
    // primitive instead of handing the string to `TcpStream::connect`. That call
    // was the one remaining dial-side `TcpStream` producer outside
    // [`crate::iface_bind::connect_tcp_bound`], and it was reachable on the
    // DEFAULT path (`--connect HOST:PORT` with no `#iface=`) — so the tuning the
    // primitive now applies would have had a hole precisely where most dials go.
    // Behaviour is preserved: this is the resolver `TcpStream::connect` calls
    // internally, walked in the same order, which is the equivalence the
    // `Some(iface)` arm has relied on since R311y236.
    let mut last_err: Option<io::Error> = None;
    for addr in tokio::net::lookup_host(host).await? {
        match crate::iface_bind::connect_tcp_bound(addr, link_socket).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}"),
        )
    }))
}

/// Bind a TCP listener on a NUMERIC endpoint — the accept-side "listen half"
/// symmetric to dial's numeric [`dial_tcp`] (which connects). Returns the
/// bound [`TcpListener`] so the caller observes `local_addr()` (the OS-chosen
/// port for a `:0` bind) BEFORE the blocking accept — which is what lets the
/// accept path be unit-tested race-free, the same way the dial loopback unit
/// learns its port. Quiet, like the dial primitives: logging is the caller's
/// concern (the Acceptor's "listening on" line; the Initiator's "connected
/// to"). Numeric only by construction, mirroring [`dial_tcp`]; [`bind_tcp_host`]
/// is the DNS-capable sibling. Built through the [`bind_listener`] SSOT
/// (`TcpSocket` + backlog 1024, zenoh parity).
pub async fn bind_tcp(addr: SocketAddr, link_socket: &LinkSocket<'_>) -> io::Result<TcpListener> {
    bind_listener(addr, link_socket)
}

/// Bind a TCP listener on a `host:port` STRING — the DNS-capable sibling of
/// [`bind_tcp`], symmetric to [`dial_tcp_host`]. A hostname resolves via the std
/// resolver ([`lookup_host`]) and each resolved address is tried in order until
/// one binds (the listen-side mirror of how `TcpStream::connect` walks a
/// `ToSocketAddrs` set); a numeric string resolves to itself. Each candidate
/// goes through the same [`bind_listener`] SSOT, so the backlog / `SO_REUSEADDR`
/// posture holds whichever address binds. (Listen-side hostnames are unusual,
/// but `TcpSocket::bind` takes a single `SocketAddr`, so the resolve loop the
/// numeric path skips is hand-rolled here.)
pub async fn bind_tcp_host(host: &str, link_socket: &LinkSocket<'_>) -> io::Result<TcpListener> {
    let mut last_err: Option<io::Error> = None;
    for addr in lookup_host(host).await? {
        match bind_listener(addr, link_socket) {
            Ok(listener) => return Ok(listener),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("bind_tcp_host: no addresses resolved for {host:?}"),
        )
    }))
}

/// Resolve a `host:port` locator address to the candidate [`SocketAddr`]s a
/// non-TCP dial / bind should try, in resolver order.
///
/// The name-resolution SSOT for every scheme whose backend primitive takes a
/// `SocketAddr` and therefore cannot resolve for itself (`tls`, `ws`, `quic`,
/// `quic-datagram`, and the accept side of `udp`). TCP does not route through
/// here: [`dial_tcp_host`] / [`bind_tcp_host`] hand the whole string to
/// `TcpStream::connect` / their own bind walk, which already resolve.
///
/// ## Divergence from zenoh, stated because it is deliberate
///
/// zenoh resolves the same addresses with `lookup_host(..).next()` and uses the
/// FIRST result only — `get_tls_addr` (`io/zenoh-links/zenoh-link-tls/src/utils.rs:590`),
/// `get_ws_addr` (`io/zenoh-links/zenoh-link-ws/src/lib.rs:79`), `get_quic_addr`
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub async fn get_quic_addr`;
/// 1.10.0 moved it out of `zenoh-links/`) are the same four lines
/// three times. wz returns EVERY resolved address so the caller can walk them,
/// matching what wz's own `tcp` path has always done ([`dial_tcp_host`] walks
/// the `ToSocketAddrs` set) and what `TcpStream::connect` does for free. That is
/// a superset: on a host whose name resolves to one address the two are
/// identical, and on a dual-stack name whose first record is unreachable zenoh
/// fails where wz succeeds. It can never make wz fail where zenoh succeeds,
/// which is the property that makes the divergence safe to keep.
///
/// ⚠ R2606 (open-debt 732) — THAT LAST SENTENCE IS TRUE ABOUT OUTCOMES AND WAS
/// FALSE ABOUT TIME, which is why the bound on [`first_reachable`] exists. On
/// exactly the dual-stack name this paragraph calls wz's win, zenoh fails in no
/// time at all while wz used to spend the unreachable candidate's FULL upper
/// protocol timeout before trying the address that was listening — thirty
/// seconds for quic, measured. The divergence traded a fast failure for a slow
/// success, and the sentence above credited only the success half. It is kept
/// rather than rewritten because the outcome claim still holds; what it was
/// missing is named here.
///
/// # Errors
///
/// The resolver's own error, or [`io::ErrorKind::AddrNotAvailable`] when the
/// name resolves to an EMPTY set — which `lookup_host` reports as `Ok` with no
/// items, and which every caller would otherwise turn into a silent "no
/// candidates, nothing tried" success-shaped loop exit.
pub async fn resolve_locator_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}:{port}"),
        ));
    }
    Ok(addrs)
}

/// Try `dial` against each candidate address in turn and return the first
/// success — the walk half of [`resolve_locator_addrs`], factored out so every
/// named non-TCP scheme walks identically instead of hand-rolling the loop.
///
/// On total failure the LAST attempt's error is surfaced (not a synthesized
/// one), because that is the error a caller can act on: a name resolving to a
/// single unreachable address must report that address's `ConnectionRefused`,
/// not a generic "all candidates failed". `addrs` is never empty by
/// [`resolve_locator_addrs`]'s contract; the `AddrNotAvailable` fallback exists
/// only so a hand-built empty vector cannot silently return a success-shaped
/// error-free `None`.
/// R2606 (open-debt 732) — how long a NON-FINAL candidate may take before the
/// walk moves on.
///
/// The walk was written assuming a dial that cannot reach its peer fails
/// quickly. That holds for the TCP-backed schemes (`ws`, `tls`): a dead port
/// answers RST and `connect` returns at once. It is FALSE for the UDP-backed
/// ones (`udp`, `quic`, `quic-datagram`), where nothing answers and the dial
/// waits out the upper protocol's own timeout — for quic that is quinn's
/// default `max_idle_timeout`, which wz does not override, of THIRTY SECONDS
/// (`quinn-proto-0.11.14/src/config/transport.rs` @ `max_idle_timeout: Some(VarInt(30_000)),`).
///
/// MEASURED, and this is what the constant is derived from rather than chosen:
/// hosted run 34800714184 on `de9808c0` failed both quic certificate-expiry
/// witnesses with a mint-to-handshake gap of 30, 30, 30, 30 seconds and then
/// 60. Those witnesses bind `127.0.0.1` and dial `localhost`; on a runner whose
/// resolver answers `::1` first, the `::1` candidate burned a full idle timeout
/// before the walk reached the address that was listening. Four identical
/// values to the second are a fixed cost, not the scheduler stall an earlier
/// round diagnosed.
///
/// Three seconds is an order of magnitude below the 30 it is racing and orders
/// of magnitude above what a reachable peer needs on loopback or a LAN. ⚠ THE
/// RESIDUE, stated rather than hidden: a non-final candidate that genuinely
/// needs longer than this is treated as dead and the walk moves on. That is the
/// trade the walk exists to make — an address that will not answer inside the
/// bound is indistinguishable from one that never will.
pub const CANDIDATE_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub async fn first_reachable<T, F, Fut>(
    addrs: Vec<SocketAddr>,
    what: &str,
    mut dial: F,
) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let mut last_err: Option<io::Error> = None;
    // The LAST candidate is deliberately UNBOUNDED. There is nothing to move on
    // to, so bounding it would only swap one failure for another, and it is the
    // single-candidate case — the overwhelmingly common one, and the only shape
    // a machine whose resolver answers one address ever sees — that must behave
    // exactly as it did before this bound existed.
    let last = addrs.len().saturating_sub(1);
    for (i, addr) in addrs.into_iter().enumerate() {
        let attempt = dial(addr);
        let outcome = if i == last {
            attempt.await
        } else {
            match tokio::time::timeout(CANDIDATE_DIAL_TIMEOUT, attempt).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{what}: candidate {addr} did not answer within {}s; \
                         moving on to the next resolved address",
                        CANDIDATE_DIAL_TIMEOUT.as_secs()
                    ),
                )),
            }
        };
        match outcome {
            Ok(link) => return Ok(link),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {what}"),
        )
    }))
}

/// Listen backlog wz applies to every TCP listener — zenoh's `socket.listen(1024)`
/// (`io/zenoh-link-commons/src/tcp.rs` `new_listener`), vs tokio/mio's hard-coded
/// default of 128 (`mio` `TcpListener::bind`). The backlog is the kernel's queue
/// of completed-but-not-yet-`accept`ed connections; it bites a MULTI-peer
/// acceptor taking a burst of simultaneous dials before its accept loop drains
/// them. [`crate::accept_loop`] (R311qa) is exactly that loop — a burst of
/// concurrent dials queues here until its `accept_tcp_on` drains them — so the
/// deeper backlog is now a present need, not just zenoh construction parity. (The
/// one-shot [`accept_tcp`] single-peer path is unaffected by the depth.)
const LISTEN_BACKLOG: u32 = 1024;

/// Build a listening [`TcpListener`] through `TcpSocket` — the SSOT both
/// [`bind_tcp`] and [`bind_tcp_host`] route their resolved [`SocketAddr`]
/// through. Mirrors zenoh's `new_listener` (`io/zenoh-link-commons/src/tcp.rs`:
/// `TcpSocket` -> `set_reuseaddr(true)` -> `bind` -> `listen(1024)`). The reason
/// for `TcpSocket` over the simpler `TcpListener::bind` is the [`LISTEN_BACKLOG`]:
/// `TcpListener::bind` hard-codes mio's 128, and `TcpSocket::listen(n)` is
/// tokio's only custom-backlog path.
///
/// `set_reuseaddr(true)` is NOT the R311pz "de-risk" (that claim was false and
/// reverted — `TcpListener::bind` already sets `SO_REUSEADDR` on Unix, so it was
/// a no-op there). It is here to PRESERVE that Unix behavior now that the
/// listener is built through `TcpSocket`, which — unlike `TcpListener::bind` —
/// does NOT default the option on; omitting it would silently regress the
/// reuseaddr posture this crate has always had. (It also aligns the Windows
/// case, where mio deliberately skips it; wz does not target Windows, so that is
/// a side benefit, not the motive.)
fn bind_listener(addr: SocketAddr, link_socket: &LinkSocket<'_>) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    // R311y236 — honour a listen-side `#iface=` bind (SO_BINDTODEVICE) before
    // bind, so a listener can be pinned to a NIC (the accept-side mirror of the
    // dial-side connect bind). Feature/platform-gated in `bind_socket_to_device`.
    // R2590 — the DSCP rides the same step, as in upstream's
    // `TcpSocketConfig::socket_with_config`, and accepted streams inherit it. A
    // listen-side `LinkSocket` never carries a `bind`. R2591 — the buffer sizes
    // too; accepted streams inherit the listener's, as upstream's do.
    link_socket.configure_stream(&socket, addr)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Accept ONE inbound connection from a *borrowed* [`TcpListener`], applying the
/// per-link TCP tuning ([`configure_tcp_stream`]) and returning the accepted
/// [`TcpStream`] + its peer address. Quiet (no log): the caller owns the
/// "listening on" / "accepted peer" lines (the demo tags `wz accept:`, the e2e
/// harness tags its binary name) — the accept-side reason the dial primitives
/// are also log-free.
///
/// Borrowing (not consuming) the listener is what lets a multi-peer acceptor
/// call this in a loop: the listener stays bound across accepts. This is the
/// accept-side primitive the [`crate::accept_loop`] router/peer foundation
/// composes (R311qa) — the same shape zenoh's `accept_task`
/// (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs`) runs: a per-listener task
/// looping `accept()` and registering each new link. [`accept_tcp`] is the
/// one-shot wrapper for the single-peer session-open contract.
pub async fn accept_tcp_on(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    let (stream, peer) = listener.accept().await?;
    configure_tcp_stream(&stream);
    Ok((stream, peer))
}

/// Accept ONE inbound connection, *consuming* the [`TcpListener`] — the
/// one-shot session-open contract (the accept-side mirror of the single
/// [`TcpStream`] [`dial_tcp`] returns). Delegates to [`accept_tcp_on`], the SSOT
/// for the accept + per-link tuning; the by-value signature is the one-shot
/// marker (a single peer, then the listener drops). A multi-peer router holds
/// the listener and loops [`accept_tcp_on`] instead ([`crate::accept_loop`]).
pub async fn accept_tcp(listener: TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    accept_tcp_on(&listener).await
}

// R2355 — the per-link TCP tuning MOVED to `iface_bind::configure_tcp_stream`,
// next to the `connect_tcp_bound` primitive it now runs inside. This module is
// gated on `transport-link-tcp` and `transport-link-ws` does NOT pull tcp, so a
// tuning function that lived HERE was one the ws dial (and, through the same
// primitive, the tls dial) could not take — which is exactly what had happened.
// The accept half still applies it explicitly, because an accepted stream comes
// from a listener rather than from the dial primitive; the name is imported into
// this module's scope so `accept_tcp_on` reads unchanged.
//
// A `//` comment and not a `///` one: a doc comment on a `use` of a `pub(crate)`
// item spends Layer C1bz doc-link budget on links rustdoc cannot resolve, and
// this is a note about a move rather than API documentation.
use crate::iface_bind::configure_tcp_stream;

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
pub fn wire_tcp_stream(stream: TcpStream) -> (TcpReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // Universal framing: a fresh always-false lowlatency flag (the u16 batch
    // prefix). The lowlatency open helpers instead use the _with_lowlatency
    // variant to share a flag they flip at Established.
    wire_tcp_stream_with_lowlatency(stream, Arc::new(AtomicBool::new(false)))
}

/// transport-lowlatency — [`wire_tcp_stream`] sharing the link's lowlatency-wire
/// flag with BOTH the read ([`StreamReadDriver`]) and write ([`writer_task`])
/// framing, so both switch to the 4-byte LE u32 prefix once the open helper flips
/// it at Established. The flag stays false through the handshake and for every
/// universal link, so those wires are byte-identical to before.
pub fn wire_tcp_stream_with_lowlatency(
    stream: TcpStream,
    lowlatency: Arc<AtomicBool>,
) -> (TcpReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // R311y453 — the §5.16 subject is resolved BEFORE the split, while the
    // stream still owns its socket and can report its local address.
    let subject = ip_link_subject(InterceptorLink::Tcp, stream.local_addr().ok());
    // R311y473 — the adminspace `{src,dst}` pair, resolved in the same
    // before-the-split window and for the same reason: after `into_split` neither
    // half is the socket any more.
    let endpoints = ip_link_endpoints(
        InterceptorLink::Tcp,
        stream.local_addr().ok(),
        stream.peer_addr().ok(),
    );
    let (reader, writer) = stream.into_split();
    let inbound = StreamReadDriver::new(reader, lowlatency.clone());
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| writer_task(writer, queue));
    let outbound = Arc::new(StreamWriteDriver::new(tx, lowlatency, subject, endpoints));
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
        assert!(
            dial_tcp(dead, &LinkSocket::NONE).await.is_err(),
            "dial to closed port errors"
        );
    }

    /// `bind_tcp` + `accept_tcp` complete a loopback connection race-free: the
    /// test learns the OS-chosen port from the bound listener BEFORE the client
    /// connects, the accept-side mirror of session_open's dial loopback unit.
    /// Splitting bind from accept is what exposes `local_addr` and removes the
    /// port race the prior one-shot `accept_tcp(listen)` form could not avoid.
    #[tokio::test]
    async fn bind_tcp_then_accept_tcp_round_trip() {
        let listener = bind_tcp(
            "127.0.0.1:0".parse().expect("loopback addr"),
            &LinkSocket::NONE,
        )
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
        let listener = bind_tcp(
            "127.0.0.1:0".parse().expect("loopback addr"),
            &LinkSocket::NONE,
        )
        .await
        .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = tokio::spawn(async move { dial_tcp(addr, &LinkSocket::NONE).await });
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

    /// `bind_tcp` sets `SO_REUSEADDR` on its listener. NON-vacuous HERE (unlike
    /// R311pz's reverted vacuous version): the listener is now built through
    /// `TcpSocket` for the custom [`LISTEN_BACKLOG`], and `TcpSocket` does NOT
    /// default `SO_REUSEADDR` on — so removing the explicit `set_reuseaddr(true)`
    /// from `bind_listener` (the realistic regression this TcpSocket switch
    /// introduces) flips this read to false. The backlog (1024) itself is not
    /// getsockopt-readable, so it carries no unit guard — only the explicit
    /// construction + code review.
    #[tokio::test]
    async fn bind_tcp_listener_sets_so_reuseaddr() {
        let listener = bind_tcp(
            "127.0.0.1:0".parse().expect("loopback addr"),
            &LinkSocket::NONE,
        )
        .await
        .expect("bind loopback");
        let std_listener = listener.into_std().expect("into_std");
        let sock = socket2::Socket::from(std_listener);
        assert!(
            sock.reuse_address().expect("read SO_REUSEADDR"),
            "bind_listener must explicitly set SO_REUSEADDR (TcpSocket does not default it on)"
        );
    }

    /// R311y236 — `connect_tcp_bound` with `Some(iface)` builds a `TcpSocket` and
    /// connects (the SO_BINDTODEVICE bind precedes connect). Gated on
    /// `not(locator-iface)` so the bind is the warn-NOOP stub (no `socket2`, no
    /// root-only syscall): this proves the device-bound socket-build + connect
    /// wiring connects, WITHOUT the root-gated real bind (which zenoh likewise
    /// does not unit-test). Under `locator-iface` on Linux the same call attempts
    /// the real `SO_BINDTODEVICE` (needs CAP_NET_RAW), so that path is covered by
    /// compilation + the wz-session-core parse tests, not a CI unit test.
    /// (R2590: there is one socket-building path now, device or not.)
    #[cfg(not(feature = "locator-iface"))]
    #[tokio::test]
    async fn connect_tcp_bound_some_iface_connects_via_noop_stub() {
        let listener = bind_tcp(
            "127.0.0.1:0".parse().expect("loopback addr"),
            &LinkSocket::NONE,
        )
        .await
        .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let options = wz_session_core::locator::LinkSocketOptions {
            iface: Some("lo".to_string()),
            ..wz_session_core::locator::LinkSocketOptions::NONE
        };
        let client = tokio::spawn(async move {
            let link_socket = LinkSocket::resolve(
                &options,
                &wz_session_core::locator::LinkSocketOptions::NONE,
                wz_session_core::locator::Proto::Tcp,
                crate::link_socket::LinkSide::Dial,
            )
            .await?;
            crate::iface_bind::connect_tcp_bound(addr, &link_socket).await
        });
        let (_server, peer) = accept_tcp(listener).await.expect("accept one peer");
        let stream = client
            .await
            .expect("client task")
            .expect("Some(iface) arm connects on the noop stub");
        assert_eq!(
            peer.ip(),
            addr.ip(),
            "the Some(iface) arm reaches the loopback listener"
        );
        assert!(
            stream.peer_addr().is_ok(),
            "the device-bound-arm stream is connected"
        );
    }

    /// R2606 (open-debt 732) — a NON-FINAL candidate that never answers costs
    /// the walk [`CANDIDATE_DIAL_TIMEOUT`] and not the upper protocol's own
    /// timeout.
    ///
    /// This is the shape that redded hosted CI for four rounds: a witness
    /// binding `127.0.0.1` and dialing `localhost`, on a runner whose resolver
    /// answers `::1` first. The unreachable candidate held the walk for quinn's
    /// full 30-second default while the certificate under test expired.
    ///
    /// Virtual time (`start_paused`), so the bound is asserted rather than
    /// waited out: tokio advances the clock when every task is idle, which is
    /// exactly the state a candidate that never answers leaves it in.
    #[tokio::test(start_paused = true)]
    async fn an_unreachable_candidate_does_not_hold_the_walk() {
        let first = "127.0.0.1:1".parse().expect("addr");
        let second = "127.0.0.1:2".parse().expect("addr");
        let reached = first_reachable(vec![first, second], "probe", |addr| async move {
            if addr == first {
                // Never answers — a UDP-backed dial to an address nothing is
                // bound to, which returns no RST and simply waits.
                std::future::pending::<io::Result<SocketAddr>>().await
            } else {
                Ok(addr)
            }
        })
        .await
        .expect("the walk moves past the candidate that never answers");
        assert_eq!(
            reached, second,
            "the walk must reach the second candidate, not hang on the first"
        );
    }

    /// R2606 — the OTHER half of that design, and the arm that makes the first
    /// one mean something: the LAST candidate is deliberately NOT bounded.
    ///
    /// Without this a green above would also be produced by bounding every
    /// candidate, which is a different and worse design — it would cap the
    /// caller's patience on the single-address case that every machine with an
    /// ordinary resolver takes, turning a slow but real connect into a failure.
    #[tokio::test(start_paused = true)]
    async fn the_last_candidate_keeps_the_callers_patience() {
        let only = "127.0.0.1:1".parse().expect("addr");
        let walk = first_reachable(vec![only], "probe", |_| async move {
            std::future::pending::<io::Result<SocketAddr>>().await
        });
        // Far beyond the per-candidate bound. If the last candidate were
        // bounded too, the walk would have resolved with a TimedOut error.
        let outer = CANDIDATE_DIAL_TIMEOUT * 10;
        assert!(
            tokio::time::timeout(outer, walk).await.is_err(),
            "a single candidate must inherit the caller's patience, not the walk's bound"
        );
    }
}
