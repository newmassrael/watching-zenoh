// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311et — canonical split-link session-open transport pipeline (TCP).
//!
//! Lifts the read/write-split + writer-task idiom out of `wz-ap-demo`'s
//! `link_driver.rs` into the library, so the production session-open path
//! has a single, reusable home. See the module-level doc on
//! [`crate::link_pipeline`] (lib.rs) for why the split is forced by the
//! `&mut LinkDriver` / `Arc<dyn BoxedLinkDriver>` shape mismatch and why
//! the non-blocking channel — not `Handle::block_on` — is the textbook
//! sync-action / async-runtime decoupling.
//!
//! ## Pieces
//!
//! - [`dial_tcp`] — the single raw-dial primitive: `proto/addr:port` ->
//!   connected [`TcpStream`]. The mode-agnostic `dial_locator(ParsedLocator)`
//!   dispatcher (R311eu) routes a `Proto::Tcp` endpoint here; `TcpDriver::
//!   connect` also delegates to it so there is one connect path.
//! - [`wire_tcp_stream`] — splits a connected stream into the cooperating
//!   `(TcpReadDriver, Arc<TcpWriteDriver>, writer-task handle)` triple.
//! - [`TcpReadDriver`] — owns the read half; impls [`LinkDriver`] via the
//!   shared [`crate::poll_framed`] framing state machine.
//! - [`TcpWriteDriver`] — holds the channel sender; impls
//!   [`BoxedLinkDriver`] with a non-blocking enqueue.
//! - [`writer_task`] — owns the write half; drains the channel and frames
//!   each payload through the [`StreamEnvelope`] codec.
//!
//! Both directions route the wire shape through the codec catalog
//! ([`StreamEnvelope`]) rather than a hand-rolled length-prefix strip, so
//! the on-wire envelope has a single source of truth.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use wz_codecs::stream_envelope::StreamEnvelope;
use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::session_glue::BoxedLinkDriver;
use crate::{poll_framed, LinkDriver, LinkEvent, ReadState, Reliability, TxFrame};

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
/// FSM consumes: an inbound [`TcpReadDriver`] (`&mut LinkDriver` for the
/// poll loop), an outbound `Arc<`[`TcpWriteDriver`]`>` (`BoxedLinkDriver`
/// for `send_blocking`), and the [`writer_task`] join handle.
///
/// The `Arc` lets the FSM's `SessionLinkActions` keep the outbound side
/// alive while the writer task drains the channel; the handle is awaited
/// during teardown so a tail frame the FSM enqueued during its final
/// transition still reaches the peer before the socket closes.
pub fn wire_tcp_stream(
    stream: TcpStream,
) -> (TcpReadDriver, Arc<TcpWriteDriver>, TokioJoinHandle<()>) {
    let (reader, writer) = stream.into_split();
    let inbound = TcpReadDriver::new(reader);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(writer, rx));
    let outbound = Arc::new(TcpWriteDriver::new(tx));
    (inbound, outbound, writer_handle)
}

/// Inbound read half of the split — owns the [`OwnedReadHalf`] and impls
/// [`LinkDriver`] with `poll_event` reading one [`StreamEnvelope`] frame via
/// the shared [`crate::poll_framed`] state machine. The send/open/close
/// methods are no-ops (the inbound side never emits): the FSM's outbound
/// path is the sibling [`TcpWriteDriver`].
pub struct TcpReadDriver {
    reader: OwnedReadHalf,
    read_state: ReadState,
}

impl TcpReadDriver {
    fn new(reader: OwnedReadHalf) -> Self {
        Self {
            reader,
            read_state: ReadState::Idle,
        }
    }
}

impl LinkDriver for TcpReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // The stream is already connected (split from a live TcpStream);
        // open is unconditionally Ok, mirroring TcpDriver::from_stream.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read half never sends — outbound goes via TcpWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather
        // than silently dropping the frame.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "TcpReadDriver does not send; outbound goes via TcpWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The read half drops independently of the write half; no
        // explicit shutdown needed (the writer task shuts the write half
        // when its channel closes).
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        poll_framed(&mut self.read_state, &mut self.reader).await
    }
}

/// Outbound write half of the split — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver is owned by the
/// [`writer_task`]. Impls [`BoxedLinkDriver`] so the FSM's
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied with a NON-blocking
/// enqueue: the sync Lua script-action handlers fire from inside a future
/// the same runtime is driving, where a nested `block_on` would trip the
/// "Cannot start a runtime from within a runtime" reentrancy check. The
/// channel decouples that sync-from-async boundary cleanly.
pub struct TcpWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl TcpWriteDriver {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl BoxedLinkDriver for TcpWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Oversize: drop with a warn rather than overflow the u16
            // length prefix. zenoh-pico's Z_BATCH_UNICAST_SIZE ceiling is
            // 65535, so a larger frame is a wz-side encoder bug — loud.
            log::warn!(
                "wz-runtime-tokio: outbound frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound channel closed; dropping frame ({e})");
        }
    }

    fn open_blocking(&self) {
        // The stream is already connected; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (after the
        // owning scope releases the Arc). Explicit per-frame shutdown from
        // the FSM's release_link would race in-flight enqueues; letting
        // the receiver-drop signal terminate the task is the textbook
        // channel idiom.
    }
}

/// Async writer task. Owns the [`OwnedWriteHalf`] and drains the outbound
/// channel one frame at a time, encoding each payload into the Zenoh
/// streamed-link [`StreamEnvelope`] (u16 LE length prefix + payload) via the
/// codec, then writing + flushing. Exits when every [`TcpWriteDriver`] clone
/// has dropped (receiver returns `None`) or a write fails (logged + bail),
/// shutting the write half so the peer observes EOF rather than RST.
pub async fn writer_task(mut writer: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(payload) = rx.recv().await {
        // Defensive: send_blocking already rejects oversize frames, but a
        // future caller could bypass that check.
        let payload_len = match u16::try_from(payload.len()) {
            Ok(n) => n,
            Err(_) => {
                log::warn!(
                    "wz-runtime-tokio: writer_task received oversize frame ({} bytes); dropping",
                    payload.len()
                );
                continue;
            }
        };
        // Codec-routed wire shape (single source of truth for the
        // streamed-link envelope), mirroring TcpDriver::send.
        let wire = StreamEnvelope {
            payload_len,
            payload: payload.as_slice(),
        }
        .encode_to_vec();
        if let Err(e) = writer.write_all(&wire).await {
            log::warn!("wz-runtime-tokio: writer_task write failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.flush().await {
            log::warn!("wz-runtime-tokio: writer_task flush failed: {e}; closing");
            return;
        }
    }
    // Channel closed -> shut the write half cleanly (peer sees EOF, not RST).
    let _ = writer.shutdown().await;
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

    /// Oversize frames are dropped by `send_blocking` rather than
    /// overflowing the u16 prefix — the channel stays usable afterwards.
    #[tokio::test]
    async fn write_driver_drops_oversize_frame() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = TcpWriteDriver::new(tx);
        driver.send_blocking(&vec![0u8; 65_536], Reliability::Reliable);
        driver.send_blocking(b"ok", Reliability::Reliable);
        // Only the in-range frame reached the channel.
        assert_eq!(rx.recv().await.as_deref(), Some(b"ok".as_slice()));
    }
}
