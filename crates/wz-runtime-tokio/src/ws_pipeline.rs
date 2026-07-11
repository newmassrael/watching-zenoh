// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ob — WebSocket-over-TCP session-open transport pipeline.
//!
//! The DATAGRAM-flow sibling of [`crate::udp_pipeline`], not of TCP/TLS. A
//! WebSocket link rides a TCP connection, but zenoh-pico classes it as
//! `Z_LINK_CAP_FLOW_DATAGRAM` (`src/link/unicast/ws.c`,
//! `_z_new_link_ws`): the transport adds NO length prefix
//! (`__unsafe_z_prepare_wbuf` reserves the 2-byte prefix only for
//! `FLOW_STREAM`, `src/transport/common/tx.c:347`), because each zenoh batch
//! rides ONE WebSocket BINARY message whose frame boundary delimits it —
//! exactly the UDP model. So this module reuses NEITHER [`crate::stream_link`]
//! (StreamEnvelope framing) NOR a custom byte codec (contrast serial's COBS);
//! the WebSocket protocol layer ([`tokio_tungstenite`], RFC6455) provides the
//! message framing, and the drivers mirror [`crate::udp_pipeline`]'s
//! one-message-is-one-frame shape.
//!
//! ## Pieces
//!
//! - [`dial_ws`] — TCP-connect to the locator's addr, then run the WebSocket
//!   client handshake ([`tokio_tungstenite::client_async`]) to a connected
//!   [`WebSocketStream`]. Unlike TLS, no cert config is needed, so a `ws/...`
//!   locator dials directly through `dial_locator` (like `udp`).
//! - [`accept_ws`] — the server handshake ([`tokio_tungstenite::accept_async`])
//!   over an already-accepted [`TcpStream`].
//! - [`wire_ws_stream`] — splits the `WebSocketStream` (Sink + Stream) into a
//!   read half (poll loop) and a write half (writer task) via
//!   [`futures_util::StreamExt::split`]. A `WebSocketStream` needs `&mut` for
//!   both directions, so — unlike the UDP socket, which is `&self` and shared
//!   by `Arc` — it cannot be Arc-shared; the futures split is the analogue.
//! - [`WsReadDriver`] — reads one `Message::Binary` as one [`RxFrame`]
//!   (control / text frames are skipped). The MTU is the unbounded stream
//!   default (pico's `_z_get_link_mtu_ws` = 65535), so the write driver
//!   overrides nothing.
//! - [`ws_writer_task`] — drains the channel, sending each payload as one
//!   `Message::Binary` (no envelope encode — the WS message IS the framing).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, client_async, WebSocketStream};

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;

/// Dial a WebSocket-over-TCP connection — TCP-connect to `addr`, then run the
/// RFC6455 client handshake ([`client_async`]) over it, returning the
/// connected [`WebSocketStream`] ready for [`wire_ws_stream`]. The request URI
/// is `ws://{addr}/` (the `Host` header matches the dialed addr; wz<->wz uses
/// the root path). No cert config is involved, so — unlike TLS — a `ws/...`
/// session dials through the generic `dial_locator`, not a bespoke seam.
pub async fn dial_ws(
    addr: SocketAddr,
    iface: Option<&str>,
) -> io::Result<WebSocketStream<TcpStream>> {
    // R311y236 — the TCP under a WS dial honours the locator `#iface=` bind via
    // the shared connect primitive (SO_BINDTODEVICE before connect).
    let tcp = crate::iface_bind::connect_tcp_bound(addr, iface).await?;
    let url = format!("ws://{addr}/");
    let (ws, _resp) = client_async(url.as_str(), tcp)
        .await
        .map_err(io::Error::other)?;
    Ok(ws)
}

/// Accept side — run the RFC6455 server handshake ([`accept_async`]) over an
/// already-accepted [`TcpStream`]. The acceptor's caller owns the
/// `TcpListener::accept`; this is the WS analogue of handing
/// `accept_and_open_session` a `DialedLink::Tcp`.
pub async fn accept_ws(tcp: TcpStream) -> io::Result<WebSocketStream<TcpStream>> {
    accept_async(tcp).await.map_err(io::Error::other)
}

/// Split a handshaked [`WebSocketStream`] into the cooperating drivers the
/// session FSM consumes: an inbound [`WsReadDriver`] (`&mut LinkDriver` for the
/// poll loop), an outbound `Arc<`[`WsWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`ws_writer_task`] join handle. The handle is
/// awaited during teardown so a tail frame the FSM enqueued during its final
/// transition still reaches the peer before the socket closes.
pub fn wire_ws_stream(
    ws: WebSocketStream<TcpStream>,
) -> (WsReadDriver, Arc<WsWriteDriver>, TokioJoinHandle<()>) {
    let (sink, stream) = ws.split();
    let inbound = WsReadDriver::new(stream);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(ws_writer_task(sink, rx));
    let outbound = Arc::new(WsWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}

/// Inbound read side of the split WebSocket — owns the read half and impls
/// [`LinkDriver`] with `poll_event` receiving one `Message::Binary` as one
/// [`RxFrame`] (no envelope strip — the WS message boundary is the frame
/// boundary, like a UDP datagram). The send/open/close methods mirror
/// [`crate::udp_pipeline::UdpReadDriver`]: open is a no-op (already
/// handshaked), close is a no-op (the writer task sends the WS Close), and
/// send fails loud (outbound goes via [`WsWriteDriver`]).
pub struct WsReadDriver {
    read: SplitStream<WebSocketStream<TcpStream>>,
}

impl WsReadDriver {
    fn new(read: SplitStream<WebSocketStream<TcpStream>>) -> Self {
        Self { read }
    }
}

impl LinkDriver for WsReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // Already connected + handshaked; open is a no-op on this shape.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read side never sends — outbound goes via WsWriteDriver.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "WsReadDriver does not send; outbound goes via WsWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The WS Close handshake rides the writer task (sink.close on channel
        // drop); the read half just stops being polled.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One WS BINARY message = one wire frame (datagram flow, no
        // length-prefix reassembly). Control / text frames are not zenoh
        // payload, so skip them and keep reading (tungstenite auto-queues a
        // Pong for any Ping surfaced here). A Close frame or stream end is the
        // peer closing; a transport error is an OS-level loss.
        loop {
            match self.read.next().await {
                Some(Ok(Message::Binary(bytes))) => return LinkEvent::Rx(RxFrame::new(bytes)),
                Some(Ok(Message::Close(_))) | None => {
                    return LinkEvent::Lost {
                        cause: LostCause::PeerClosed,
                    }
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) => {
                    return LinkEvent::Lost {
                        cause: LostCause::OsError,
                    }
                }
            }
        }
    }
}

/// Outbound write side — holds an `mpsc::UnboundedSender<Vec<u8>>` whose
/// receiver is owned by the [`ws_writer_task`]. Impls [`BoxedLinkDriver`] with
/// a NON-blocking enqueue, the same sync-from-async decoupling
/// [`crate::udp_pipeline::UdpWriteDriver`] uses: the sync script-action
/// handlers fire from inside a future the same runtime drives, where a nested
/// `block_on` would trip the reentrancy check. The channel crosses that
/// boundary cleanly. No `link_mtu` override — pico's `_z_get_link_mtu_ws` is
/// the unbounded 65535 default a stream link inherits.
pub struct WsWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl WsWriteDriver {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl BoxedLinkDriver for WsWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Oversize: drop with a warn. zenoh's batch ceiling is 65535
            // (u16), so a larger frame is a wz-side encoder bug — loud.
            log::warn!(
                "wz-runtime-tokio: outbound ws frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound ws channel closed; dropping frame ({e})");
        }
    }

    fn open_blocking(&self) {
        // The WS handshake already ran (dial_ws / accept_ws); open is a no-op.
    }

    fn close_blocking(&self) {
        // The writer task sends the WS Close frame when every sender clone
        // drops (the owning scope releases the Arc) — the textbook
        // receiver-drop channel idiom, mirroring UdpWriteDriver::close_blocking.
    }
}

/// Async writer task. Owns the WebSocket write half (a [`SplitSink`]) and
/// drains the outbound channel one frame at a time, sending each payload as one
/// `Message::Binary` (no envelope encode — the WS message boundary IS the
/// framing, contrast [`crate::stream_link::writer_task`]'s StreamEnvelope).
/// Exits when every [`WsWriteDriver`] clone has dropped (receiver returns
/// `None`) or a send fails (logged + bail), closing the sink so the peer
/// observes a clean WebSocket Close.
pub async fn ws_writer_task(
    mut sink: SplitSink<WebSocketStream<TcpStream>, Message>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        if let Err(e) = sink.send(Message::Binary(payload)).await {
            log::warn!("wz-runtime-tokio: ws_writer_task send failed: {e}; closing");
            return;
        }
    }
    // Channel closed -> send a WS Close frame so the peer sees a clean close.
    let _ = sink.close().await;
}
