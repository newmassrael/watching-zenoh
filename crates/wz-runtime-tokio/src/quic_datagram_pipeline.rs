// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y8 — QUIC unreliable-DATAGRAM session-open transport pipeline (RFC9221).
//!
//! The datagram sibling of [`crate::quic_pipeline`]. Where reliable QUIC carries
//! a zenoh batch over ONE bidirectional QUIC STREAM with StreamEnvelope
//! length-prefix framing, this backend carries each batch as ONE QUIC unreliable
//! DATAGRAM ([`quinn::Connection::send_datagram`] / [`read_datagram`], RFC9221) —
//! the datagram boundary IS the framing, exactly like UDP ([`crate::udp_pipeline`])
//! and WS ([`crate::ws_pipeline`]). zenoh ships `zenoh-link-quic` +
//! `zenoh-link-quic_datagram` as sibling crates sharing the TLS config; the
//! datagram link advertises `rel=0` (unreliable). wz mirrors that split: this
//! module reuses the QUIC connection setup (endpoint + the TLS-1.3 + ALPN `hq-29`
//! rustls config from [`crate::quic_config`], the SAME `dial`/`accept`/keep-alive
//! shape as [`crate::quic_pipeline`]) but drops `open_bi`/`accept_bi` and the
//! StreamEnvelope drivers, swapping in the UDP read/write driver shape (shared
//! `Connection` handle, one datagram = one frame, no length prefix).
//!
//! ## Why a separate backend (not a quic-stream variant)
//!
//! A reliable QUIC link and a QUIC datagram link differ in framing (stream vs
//! datagram) and reliability (`rel=1` vs `rel=0`), so — like zenoh's two crates —
//! they are distinct link kinds. `transport-link-quic-datagram` IMPLIES
//! `transport-link-quic` because it reuses that backend's [`crate::quic_config`]
//! builders + the `quinn`/rustls stack; the only genuinely-new surface is the
//! datagram send/recv path and the per-datagram MTU.
//!
//! ## Keep-alive (the quic_pipeline wrinkle, same here)
//!
//! A [`quinn::Connection`] references the [`quinn::Endpoint`]'s background UDP
//! pump; dropping the endpoint while the link is live tears it down. Both are
//! cheap Arc-backed `Clone` handles, so [`QuicDatagramReadDriver`] holds a clone
//! of each for the link's lifetime (the session-long inbound side), the QUIC
//! analogue of UDP sharing its `Arc<UdpSocket>`.
//!
//! ## Per-datagram MTU
//!
//! QUIC caps a datagram at the path's `max_datagram_size` (conservative at
//! handshake, grows with MTU discovery). A frame larger than that fails
//! `send_datagram` with `TooLarge`, so [`QuicDatagramWriteDriver::link_mtu`]
//! reports the negotiated max (captured at wire time, floored at
//! [`QUIC_DATAGRAM_LINK_MTU`]); the transport's `negotiated_batch_mtu` mins it
//! against the negotiated batch and fragments a larger frame into emittable
//! datagrams — the wz analogue of the UDP link's 1450 cap
//! ([`crate::udp_pipeline::UDP_LINK_MTU`]).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::{Connection, Endpoint};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};

// R311y13 — the QUIC handshake SSOT (client connect / server endpoint / accept)
// is shared from quic_pipeline; this module owns only the datagram-vs-stream
// delta (no open_bi/accept_bi, max_bidi=0, the datagram read/write drivers).
use crate::link_interfaces::{ip_link_endpoints, ip_link_subject};
use crate::quic_pipeline::{accept_quic_connection, connect_quic_client, quic_server_endpoint};
use crate::writer_queue::{OutboundQueue, WriterHandle};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{InterceptorLink, LinkEndpoints, LinkSubject};
use wz_session_core::link::{LinkDropCause, LinkSendOutcome};

/// Conservative per-datagram MTU floor used when the connection has not yet
/// reported a negotiated `max_datagram_size` (the QUIC initial datagram budget
/// is ~1200 B). [`wire_quic_datagram`] prefers the real negotiated value when
/// present; this is only the fallback floor. It sits well below the unbounded
/// stream-default link MTU, so the transport's `negotiated_batch_mtu` min term
/// fragments a >MTU frame to it — the same invariant
/// [`crate::udp_pipeline::UDP_LINK_MTU`] holds. (quinn's `max_datagram_size`
/// already subtracts QUIC's per-packet framing overhead, so the negotiated value
/// is itself structurally below the stream default — no clamp needed.)
pub const QUIC_DATAGRAM_LINK_MTU: usize = 1200;

/// A dialed / accepted QUIC datagram link: the endpoint + connection, kept alive
/// for the link's lifetime. No streams — datagrams ride the [`Connection`]
/// directly. Produced by [`dial_quic_datagram`] (client) / [`accept_quic_datagram_on`]
/// (server) and consumed by [`wire_quic_datagram`].
pub struct QuicDatagramLink {
    /// The QUIC endpoint (UDP socket + driver). A `Clone` handle; kept alive
    /// because the connection's driver lives on it.
    pub endpoint: Endpoint,
    /// The QUIC connection. A `Clone` handle; datagrams are sent/received on it.
    pub connection: Connection,
}

/// Inbound read driver of a QUIC datagram link — owns a [`Connection`] clone for
/// `read_datagram`, PLUS the keep-alive [`Endpoint`] the link must outlive (see
/// the module doc). Impls [`LinkDriver`] with `poll_event` receiving one datagram
/// as one [`RxFrame`] (datagram boundary == message boundary, no StreamEnvelope
/// reassembly — the UDP shape, not the [`crate::quic_pipeline`] stream shape).
pub struct QuicDatagramReadDriver {
    connection: Connection,
    // Keep-alive: dropping the endpoint before the link closes would tear it
    // down (the connection references the endpoint driver). A cheap Arc handle.
    _endpoint: Endpoint,
}

impl LinkDriver for QuicDatagramReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // The connection is already established (from a live QuicDatagramLink);
        // open is unconditionally Ok, mirroring UdpReadDriver.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read side never sends — outbound goes via QuicDatagramWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather than
        // silently dropping the datagram (the UdpReadDriver contract).
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "QuicDatagramReadDriver does not send; outbound goes via QuicDatagramWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // QUIC has no per-link kernel close handshake on the read side; dropping
        // the last Connection/Endpoint clone closes the connection.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One datagram = one wire message (QUIC preserves datagram boundaries,
        // so no length-prefix reassembly). A read error means the connection
        // ended (transport error / peer close) -> Lost; OsError matches the
        // udp_pipeline / stream-driver convention for a link-level I/O failure
        // (the FSM maps every LostCause to LinkLost, so this is diagnostic
        // fidelity, not behavior).
        match self.connection.read_datagram().await {
            Ok(bytes) => LinkEvent::Rx(RxFrame::new(bytes.to_vec())),
            Err(_) => LinkEvent::Lost {
                cause: LostCause::OsError,
            },
        }
    }
}

/// Outbound write side — holds an `mpsc::UnboundedSender<Vec<u8>>` whose receiver
/// is owned by the [`quic_datagram_writer_task`], plus the per-datagram `mtu`
/// captured at wire time. Impls [`BoxedLinkDriver`] with a NON-blocking enqueue,
/// the same sync-from-async decoupling [`crate::udp_pipeline::UdpWriteDriver`]
/// uses (the sync Lua script-action handlers fire from inside a future the same
/// runtime drives, where a nested `block_on` would trip the reentrancy check;
/// the channel crosses that boundary cleanly).
pub struct QuicDatagramWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    mtu: usize,
    /// R311y453 — the §5.16 link-derived subject, resolved once at open.
    subject: LinkSubject,
    /// R311y474 — the adminspace `{src,dst}` locator pair, resolved once at open.
    endpoints: Option<LinkEndpoints>,
}

impl BoxedLinkDriver for QuicDatagramWriteDriver {
    // R311y453 — the §5.16 subject resolved at open. A field read, not a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y474 — the adminspace `{src,dst}` pair resolved at open. A field read.
    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.as_ref()
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        // QUIC datagrams are best-effort by definition; the Reliability hint is
        // the session FSM's concern. The transport TX path caps its fragment
        // budget to THIS link's MTU ([`Self::link_mtu`] feeds
        // `negotiated_batch_mtu`), so a well-formed session fragments an oversize
        // message to <= mtu datagrams before reaching this seam. The mtu guard
        // stays a loud defensive backstop: a caller that bypassed the negotiated
        // budget drops here rather than hand `send_datagram` a frame the
        // connection rejects with `TooLarge`.
        if bytes.len() > self.mtu {
            log::warn!(
                "wz-runtime-tokio: outbound quic datagram {} bytes > mtu {}; dropping",
                bytes.len(),
                self.mtu
            );
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound channel closed; dropping quic datagram ({e})");
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {
        // The connection is already established; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (after the owning
        // scope releases it) — the textbook channel idiom (mirrors
        // UdpWriteDriver::close_blocking).
    }

    fn link_mtu(&self) -> usize {
        // The QUIC datagram link's per-datagram frame budget — the negotiated
        // `max_datagram_size` captured at wire time (or the
        // [`QUIC_DATAGRAM_LINK_MTU`] floor). The transport reads it through
        // `negotiated_batch_mtu` to bound its TX fragment budget
        // (`min(link mtu, negotiated batch)`), so a >mtu message splits into
        // emittable datagrams instead of failing `send_datagram` with `TooLarge`.
        self.mtu
    }
}

/// Async writer task. Holds the shared [`Connection`] and drains the outbound
/// channel one frame at a time, queuing each payload as one QUIC datagram via
/// `send_datagram` (no envelope encode — datagram boundaries are the framing,
/// contrast [`crate::quic_pipeline`]'s StreamEnvelope writer). `send_datagram`
/// is non-blocking (it queues into the connection's datagram buffer; the
/// endpoint driver flushes it). Exits when the queue is SEALED and drained,
/// when every [`QuicDatagramWriteDriver`] clone has dropped, or when a
/// `send_datagram` fails (logged + bail) — see [`crate::writer_queue`] for why
/// the seal, and not sender liveness alone, is the teardown signal. This is the
/// one writer with no per-write bound to arm, because `send_datagram` queues
/// synchronously and cannot block on the peer.
pub async fn quic_datagram_writer_task(connection: Connection, mut queue: OutboundQueue) {
    while let Some(payload) = queue.next().await {
        if let Err(e) = connection.send_datagram(Bytes::from(payload)) {
            log::warn!(
                "wz-runtime-tokio: quic_datagram_writer_task send_datagram failed: {e}; closing"
            );
            return;
        }
    }
}

/// Dial a QUIC datagram connection to `addr`, verifying the server against
/// `client_config` (the SAME TLS-1.3 + ALPN-`hq-29` rustls config the reliable
/// QUIC link uses, from [`crate::quic_config`]) with `server_name` as the SNI —
/// then return the [`QuicDatagramLink`] WITHOUT opening any stream (datagrams
/// ride the connection). The datagram sibling of
/// [`crate::quic_pipeline::dial_quic`]; quinn enables datagrams by default
/// (`TransportConfig::datagram_{send,receive}_buffer_size = Some`), so the
/// default client config negotiates datagram support with the peer.
pub async fn dial_quic_datagram(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
    iface: Option<&str>,
) -> io::Result<QuicDatagramLink> {
    let (endpoint, connection) =
        connect_quic_client(addr, client_config, server_name, iface).await?;
    Ok(QuicDatagramLink {
        endpoint,
        connection,
    })
}

/// Bind a QUIC datagram server [`Endpoint`] at `addr` presenting `server_config`
/// (the SAME TLS-1.3 + ALPN-`hq-29` rustls server config as reliable QUIC) — the
/// accept-side "listen half" symmetric to [`dial_quic_datagram`]. Forbids BOTH
/// stream kinds (`max_concurrent_{uni,bidi}_streams(0)`) so the link is
/// datagram-only; datagrams stay enabled (quinn's default `TransportConfig`
/// advertises `max_datagram_frame_size`, so the peer may send to us). The caller
/// owns the returned `Endpoint` and loops [`accept_quic_datagram_on`] over it.
///
/// R311y454 — `iface` is the `#iface=<name>` LISTEN-side bind. It needs no code
/// of its own: the shared [`quic_server_endpoint`] owns the pre-bind +
/// `SO_BINDTODEVICE` arm, so the datagram backend inherits the honor from the
/// same SSOT that gives it the stream limits. One fix closed BOTH the quic and
/// quic-datagram listen residuals for exactly this reason.
pub fn bind_quic_datagram(
    addr: SocketAddr,
    server_config: Arc<RustlsServerConfig>,
    iface: Option<&str>,
) -> io::Result<Endpoint> {
    // Datagram-only: max_bidi = 0 (the shared quic_server_endpoint also pins
    // uni = 0). The QUIC handshake rides crypto frames, not application streams,
    // so it completes; datagrams are on by default (TransportConfig default sets
    // datagram_receive_buffer_size = Some). The datagram mirror of bind_quic's
    // max_bidi = 1.
    quic_server_endpoint(addr, server_config, 0, iface)
}

/// Accept ONE inbound QUIC datagram connection from a *borrowed* server
/// [`Endpoint`], completing its handshake — the datagram mirror of
/// [`crate::quic_pipeline::accept_quic_on`], minus the `accept_bi` (no streams).
/// Borrowing the endpoint lets a multi-peer acceptor loop. Returns a
/// [`QuicDatagramLink`] (the endpoint is cloned in as the keep-alive). The
/// connection resolves once the peer (initiator) completes the QUIC + TLS-1.3
/// handshake — which the wz initiator drives immediately.
pub async fn accept_quic_datagram_on(endpoint: &Endpoint) -> io::Result<QuicDatagramLink> {
    let connection = accept_quic_connection(endpoint).await?;
    Ok(QuicDatagramLink {
        endpoint: endpoint.clone(),
        connection,
    })
}

/// Complete the DEFERRED crypto handshake of a QUIC datagram connection ARRIVAL —
/// the pending `Incoming` that [`crate::session_open::BoundListener::accept_raw`]
/// took off `endpoint.accept()` WITHOUT running the crypto. The datagram mirror of
/// [`crate::quic_pipeline::complete_quic_accept`], minus the `accept_bi` (datagrams
/// open no stream). Run in the spawned per-face open future (via
/// [`crate::session_open::AcceptedLink::handshake`]) so a slow/stalled peer
/// handshake never blocks the multi-peer accept loop's `select!` — the split that
/// makes the quic-datagram ACCEPTOR mesh-capable, exactly as R311y404 did for the
/// reliable quic acceptor. The `endpoint` is the keep-alive clone the resulting
/// [`QuicDatagramLink`] must outlive on.
pub async fn complete_quic_datagram_accept(
    incoming: quinn::Incoming,
    endpoint: Endpoint,
) -> io::Result<QuicDatagramLink> {
    let connection = incoming.await.map_err(io::Error::other)?;
    Ok(QuicDatagramLink {
        endpoint,
        connection,
    })
}

/// Wire a [`QuicDatagramLink`] into the cooperating drivers the session FSM
/// consumes: an inbound [`QuicDatagramReadDriver`] (`&mut LinkDriver` for the
/// poll loop), an outbound `Arc<`[`QuicDatagramWriteDriver`]`>` (`BoxedLinkDriver`
/// for `send_blocking`), and the [`quic_datagram_writer_task`] join handle.
///
/// Unlike [`crate::quic_pipeline::wire_quic_stream`] there is no stream split:
/// the single [`Connection`] is shared (a cheap `Clone` handle) — a clone backs
/// the read driver's `read_datagram` while the writer task holds another for
/// `send_datagram`, the UDP shared-handle shape. The per-datagram `mtu` is the
/// connection's negotiated `max_datagram_size` (or the [`QUIC_DATAGRAM_LINK_MTU`]
/// floor when the peer has not advertised one) — already below the stream-default
/// link MTU by QUIC's per-packet framing overhead, so the transport's
/// `negotiated_batch_mtu` min term fragments to it with no clamp.
pub fn wire_quic_datagram(
    link: QuicDatagramLink,
) -> (
    QuicDatagramReadDriver,
    Arc<QuicDatagramWriteDriver>,
    WriterHandle,
) {
    let QuicDatagramLink {
        endpoint,
        connection,
    } = link;
    let mtu = connection
        .max_datagram_size()
        .unwrap_or(QUIC_DATAGRAM_LINK_MTU);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| {
        quic_datagram_writer_task(connection.clone(), queue)
    });
    // R311y453 — the §5.16 subject, off the quinn endpoint's bound address.
    let subject = ip_link_subject(InterceptorLink::QuicDatagram, endpoint.local_addr().ok());
    // R311y474 — the adminspace `{src,dst}` pair. `Connection::remote_address` is
    // infallible (a completed handshake HAS a peer), so the only `None` arm is a
    // failed `local_addr`. The scheme carries the `?rel=0` datagram marker via
    // `InterceptorLink::locator_for`, which is what makes the string DIALABLE — the
    // bare `quic/` spelling would name the reliable sibling transport (R311y470).
    //
    // The SRC is a deliberate SUPERSET of upstream. zenoh publishes
    // `quic_endpoint.local_addr()` verbatim (`zenoh-link-quic_datagram/src/unicast.rs`
    // :292, after the same UNSPECIFIED:0 client bind at :255-263), so a zenoh
    // client's own src reads `quic/0.0.0.0:<port>?rel=0` — a string nothing can dial
    // and not the address its peer sees. quinn already knows the concrete one for
    // THIS connection (`Connection::local_ip`, whose own doc names the wildcard-bind
    // case), so wz prefers it and keeps the endpoint's PORT, falling back to the
    // bound address only when quinn cannot say. The result is what upstream's
    // ACCEPTOR reports for the same link, which is what makes the pair mirror.
    let local = endpoint
        .local_addr()
        .ok()
        .map(|bound| match connection.local_ip() {
            Some(ip) => SocketAddr::new(ip, bound.port()),
            None => bound,
        });
    let endpoints = ip_link_endpoints(
        InterceptorLink::QuicDatagram,
        local,
        Some(connection.remote_address()),
    );
    let outbound = Arc::new(QuicDatagramWriteDriver {
        tx,
        mtu,
        subject,
        endpoints,
    });
    let inbound = QuicDatagramReadDriver {
        connection,
        _endpoint: endpoint,
    };
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::link::DEFAULT_LINK_MTU;

    /// The datagram MTU floor must bind BELOW the unbounded stream
    /// `DEFAULT_LINK_MTU`, else the transport's `negotiated_batch_mtu` min term
    /// is inert and a QUIC datagram link never fragments (the same invariant the
    /// UDP link's `UDP_LINK_MTU` holds). A const assertion so a constant
    /// regression fails the build.
    #[test]
    fn quic_datagram_mtu_floor_binds_below_stream_default() {
        const _: () = assert!(QUIC_DATAGRAM_LINK_MTU < DEFAULT_LINK_MTU);
    }

    /// `send_blocking` drops an oversize datagram (one larger than the captured
    /// link MTU) rather than enqueue it; the channel stays usable afterwards.
    /// The QUIC-datagram mirror of `udp_pipeline`'s oversize-drop guard.
    #[tokio::test]
    async fn write_driver_drops_oversize_datagram() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = QuicDatagramWriteDriver {
            subject: LinkSubject::UNKNOWN,
            endpoints: None,
            tx,
            mtu: QUIC_DATAGRAM_LINK_MTU,
        };
        // R2371 — the drop is stated by the return value as well as inferred
        // from the channel; see the stream-link twin for why both are kept.
        assert_eq!(
            driver.send_blocking(
                &vec![0u8; QUIC_DATAGRAM_LINK_MTU + 1],
                Reliability::BestEffort,
            ),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert_eq!(
            driver.send_blocking(b"ok", Reliability::BestEffort),
            LinkSendOutcome::Sent
        );
        // Only the in-range datagram reached the channel.
        assert_eq!(rx.recv().await.as_deref(), Some(b"ok".as_slice()));
        assert_eq!(driver.link_mtu(), QUIC_DATAGRAM_LINK_MTU);
    }
}
