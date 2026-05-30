// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ez — canonical datagram session-open transport pipeline (UDP).
//!
//! The datagram sibling of [`crate::link_pipeline`] (TCP). The session FSM
//! needs the link in the same two shapes a stream does — an async
//! `&mut LinkDriver` for the inbound poll loop and a sync
//! `Arc<dyn BoxedLinkDriver>` for the `send_blocking` fired from Lua
//! script-action handlers — but a UDP socket is NOT split into owned
//! read/write halves the way [`tokio::net::TcpStream::into_split`] gives.
//! Instead the one `UdpSocket` is shared via `Arc`: `tokio::net::UdpSocket`
//! takes `&self` for both `recv_from` and `send_to`, so a clone backs the
//! inbound [`UdpReadDriver`] while the [`udp_writer_task`] holds another and
//! drains the outbound channel. This is the structural difference the
//! R311es dial-constructor round flagged: "uniform driver consumption shape
//! is contingent on the read/write-split decision — TCP session-open splits
//! the stream, UDP shares one socket — so the shape is fixed at the
//! orchestration round, not the dial constructor".
//!
//! ## Pieces
//!
//! - [`dial_udp`] — the raw-dial primitive: bind an ephemeral local socket
//!   whose address family mirrors `peer` (a v4-bound socket cannot reach a
//!   v6 peer), returning it unwrapped so the caller chooses its consumption
//!   shape. The session-open path wires it via [`wire_udp_socket`];
//!   [`crate::UdpDriver::connect`] wraps the same bind in the unified
//!   single-driver shape.
//! - [`wire_udp_socket`] — shares the bound socket into the cooperating
//!   `(UdpReadDriver, Arc<UdpWriteDriver>, writer-task handle)` triple.
//! - [`UdpReadDriver`] — holds an `Arc<UdpSocket>`; impls [`LinkDriver`]
//!   with `poll_event` receiving one datagram. No framing prefix — UDP
//!   preserves message boundaries, so one datagram is exactly one wire
//!   message (contrast the TCP [`crate::poll_framed`] / `StreamEnvelope`
//!   length-prefix reassembly).
//! - [`UdpWriteDriver`] — holds the channel sender; impls
//!   [`BoxedLinkDriver`] with a non-blocking enqueue, mirroring
//!   [`crate::link_pipeline::TcpWriteDriver`] so the sync-action /
//!   async-runtime boundary is decoupled the same way.
//! - [`udp_writer_task`] — holds the shared socket + peer; drains the
//!   channel and writes each payload as one datagram (no envelope encode).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::session_glue::BoxedLinkDriver;
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

/// Maximum UDP payload (65535 IP datagram - 20 IPv4 header - 8 UDP header).
/// A larger frame is a wz-side encoder bug; the driver drops it loud rather
/// than handing `send_to` a buffer the kernel will reject.
const MAX_UDP_PAYLOAD: usize = 65507;

/// Bind an outbound UDP socket targeting `peer` — the raw-dial primitive for
/// the datagram transport. Returns the bound [`UdpSocket`] unwrapped so the
/// caller can choose its consumption shape: the session-open path shares it
/// via [`wire_udp_socket`], while [`crate::UdpDriver::connect`] wraps it in a
/// unified driver. The local bind address family mirrors `peer` (a v4-bound
/// socket cannot reach a v6 peer); the ephemeral port (`:0`) lets the kernel
/// assign — the peer learns this Initiator port from the first datagram's
/// source address.
pub async fn dial_udp(peer: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    UdpSocket::bind(bind_addr).await
}

/// Share a bound [`UdpSocket`] into the cooperating drivers the session FSM
/// consumes: an inbound [`UdpReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`UdpWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`udp_writer_task`] join handle.
///
/// Unlike [`crate::link_pipeline::wire_tcp_stream`], there is no owned
/// half-split: the single socket is wrapped in an `Arc` whose clones back
/// both directions (tokio's `UdpSocket` is `&self` for send and recv, so
/// concurrent send/recv on clones is sound). `peer` is the unicast target
/// every outbound datagram is addressed to. The handle is awaited during
/// teardown so a tail frame the FSM enqueued during its final transition
/// still reaches the peer before the socket drops.
pub fn wire_udp_socket(
    socket: UdpSocket,
    peer: SocketAddr,
) -> (UdpReadDriver, Arc<UdpWriteDriver>, TokioJoinHandle<()>) {
    let socket = Arc::new(socket);
    let inbound = UdpReadDriver::new(socket.clone());
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(udp_writer_task(socket, peer, rx));
    let outbound = Arc::new(UdpWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}

/// Inbound read side of the shared socket — owns an `Arc<UdpSocket>` and
/// impls [`LinkDriver`] with `poll_event` receiving one datagram as one
/// [`RxFrame`]. The send/open/close methods mirror
/// [`crate::link_pipeline::TcpReadDriver`]: open is a no-op (the socket is
/// already bound), close is a no-op (UDP has no teardown handshake; dropping
/// the last `Arc` releases the FD), and send fails loud (the FSM's outbound
/// path is the sibling [`UdpWriteDriver`]).
pub struct UdpReadDriver {
    socket: Arc<UdpSocket>,
}

impl UdpReadDriver {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

impl LinkDriver for UdpReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // The socket is already bound (from a live UdpSocket); open is
        // unconditionally Ok, mirroring UdpDriver::from_socket.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read side never sends — outbound goes via UdpWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather
        // than silently dropping the datagram.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "UdpReadDriver does not send; outbound goes via UdpWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // UDP has no kernel-level close handshake; dropping the Arc clones
        // releases the FD. No explicit shutdown needed.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One datagram = one wire message (UDP preserves boundaries, so no
        // length-prefix reassembly). Single datagram cap = MAX_UDP_PAYLOAD.
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        match self.socket.recv_from(&mut buf).await {
            Ok((n, _src)) => {
                buf.truncate(n);
                LinkEvent::Rx(RxFrame { bytes: buf })
            }
            Err(_) => LinkEvent::Lost {
                cause: LostCause::OsError,
            },
        }
    }
}

/// Outbound write side — holds an `mpsc::UnboundedSender<Vec<u8>>` whose
/// receiver is owned by the [`udp_writer_task`]. Impls [`BoxedLinkDriver`]
/// with a NON-blocking enqueue, the same sync-from-async decoupling
/// [`crate::link_pipeline::TcpWriteDriver`] uses: the sync Lua
/// script-action handlers fire from inside a future the same runtime drives,
/// where a nested `block_on` would trip the reentrancy check. The channel
/// crosses that boundary cleanly.
pub struct UdpWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl UdpWriteDriver {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl BoxedLinkDriver for UdpWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        // UDP link layer is best-effort by definition; the Reliability hint
        // is the session FSM's concern. Oversize is a wz-side encoder bug —
        // drop loud rather than enqueue a datagram send_to will reject.
        if bytes.len() > MAX_UDP_PAYLOAD {
            log::warn!(
                "wz-runtime-tokio: outbound datagram {} bytes > {MAX_UDP_PAYLOAD}; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound channel closed; dropping datagram ({e})");
        }
    }

    fn open_blocking(&self) {
        // The socket is already bound; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (after the
        // owning scope releases the Arc). Letting the receiver-drop signal
        // terminate the task is the textbook channel idiom (mirrors
        // TcpWriteDriver::close_blocking).
    }
}

/// Async writer task. Holds the shared `Arc<UdpSocket>` + the unicast `peer`
/// and drains the outbound channel one frame at a time, writing each payload
/// as one datagram via `send_to`. No envelope encode — UDP datagram
/// boundaries are the framing (contrast [`crate::link_pipeline::writer_task`],
/// which length-prefixes each payload through `StreamEnvelope`). Exits when
/// every [`UdpWriteDriver`] clone has dropped (receiver returns `None`) or a
/// `send_to` fails (logged + bail). UDP has no write-half shutdown, so the
/// task just returns.
pub async fn udp_writer_task(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        if let Err(e) = socket.send_to(&payload, peer).await {
            log::warn!("wz-runtime-tokio: udp_writer_task send_to failed: {e}; closing");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dial_udp` binds an ephemeral local socket whose family mirrors the
    /// peer; the bound local addr is a concrete v4 ephemeral port.
    #[tokio::test]
    async fn dial_udp_binds_ephemeral_v4() {
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("peer addr");
        let socket = dial_udp(peer).await.expect("bind ephemeral");
        let local = socket.local_addr().expect("local addr");
        assert!(local.is_ipv4(), "v4 peer -> v4 bind");
        assert_ne!(local.port(), 0, "kernel assigned a concrete port");
    }

    /// Oversize datagrams are dropped by `send_blocking` rather than enqueued;
    /// the channel stays usable afterwards.
    #[tokio::test]
    async fn write_driver_drops_oversize_datagram() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = UdpWriteDriver::new(tx);
        driver.send_blocking(&vec![0u8; MAX_UDP_PAYLOAD + 1], Reliability::BestEffort);
        driver.send_blocking(b"ok", Reliability::BestEffort);
        // Only the in-range datagram reached the channel.
        assert_eq!(rx.recv().await.as_deref(), Some(b"ok".as_slice()));
    }

    /// Two wired sockets exchange a raw datagram end to end: the writer task
    /// addresses `peer`, the read driver receives it as one `RxFrame` with no
    /// envelope strip (datagram boundary == message boundary).
    #[tokio::test]
    async fn wired_sockets_round_trip_one_datagram() {
        let a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
        let a_addr = a.local_addr().expect("a addr");
        let b_addr = b.local_addr().expect("b addr");

        let (_a_in, a_out, a_writer) = wire_udp_socket(a, b_addr);
        let (mut b_in, _b_out, _b_writer) = wire_udp_socket(b, a_addr);

        a_out.send_blocking(b"hello-datagram", Reliability::BestEffort);
        match b_in.poll_event().await {
            LinkEvent::Rx(frame) => assert_eq!(frame.bytes, b"hello-datagram"),
            other => panic!("expected Rx, got {other:?}"),
        }
        drop(a_out);
        let _ = a_writer.await;
    }
}
