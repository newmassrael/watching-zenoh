// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311oa — transport-neutral byte-stream link machinery.
//!
//! The single source of truth for "a byte stream + the Zenoh streamed-link
//! [`StreamEnvelope`] framing -> the session FSM's read/write drivers". Every
//! byte-stream transport whose wire framing is the StreamEnvelope length
//! prefix instantiates these SAME pieces, differing ONLY in the concrete
//! stream type:
//! - [`crate::link_pipeline`] (TCP) — `OwnedReadHalf` / `OwnedWriteHalf` from
//!   `TcpStream::into_split`;
//! - [`crate::tls_pipeline`] (TLS) — `ReadHalf` / `WriteHalf` of a
//!   `tokio_rustls::TlsStream<TcpStream>` from `tokio::io::split`.
//!
//! Extracted here (R311oa session review) so the read-driver logic is written
//! ONCE: a TLS link frames identically to a TCP link, so a separate
//! `TlsReadDriver` struct with a byte-for-byte copy of `TcpReadDriver`'s
//! `LinkDriver` impl would be a DRY/SSOT violation (contrast serial, whose
//! COBS framing genuinely differs and so keeps its own driver). The generic
//! [`StreamReadDriver<R>`] + per-transport type aliases give each transport a
//! readable name (`TcpReadDriver` / `TlsReadDriver`) over one impl.
//!
//! Datagram transports (UDP) do NOT use this module: a datagram preserves
//! message boundaries, so there is no length-prefix framing — `udp_pipeline`
//! carries its own boundary-as-frame drivers.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use wz_codecs::stream_envelope::StreamEnvelope;

use crate::{poll_framed, LinkDriver, LinkEvent, ReadState, Reliability, TxFrame};
use wz_session_core::link::BoxedLinkDriver;

/// Inbound read half of a split byte-stream link — owns the read half `R`
/// (any `AsyncRead`) and impls [`LinkDriver`] with `poll_event` reading one
/// [`StreamEnvelope`] frame via the shared [`crate::poll_framed`] state
/// machine. The send/open/close methods are no-ops: the inbound side never
/// emits — the FSM's outbound path is the sibling [`StreamWriteDriver`].
///
/// Generic over the stream half so the framing impl is written once;
/// [`crate::link_pipeline::TcpReadDriver`] and
/// [`crate::tls_pipeline::TlsReadDriver`] are type aliases that pin `R`.
pub struct StreamReadDriver<R> {
    reader: R,
    read_state: ReadState,
}

impl<R: AsyncRead + Unpin> StreamReadDriver<R> {
    // `pub(crate)` so each transport's `wire_*` constructs it over its own
    // split read half; the type is transport-neutral.
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            read_state: ReadState::Idle,
        }
    }
}

impl<R: AsyncRead + Unpin> LinkDriver for StreamReadDriver<R> {
    async fn open(&mut self) -> io::Result<()> {
        // The stream is already connected (split from a live stream); open is
        // unconditionally Ok.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read half never sends — outbound goes via StreamWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather than
        // silently dropping the frame.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "StreamReadDriver does not send; outbound goes via StreamWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The read half drops independently of the write half; no explicit
        // shutdown needed (the writer task shuts the write half on channel close).
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        poll_framed(&mut self.read_state, &mut self.reader).await
    }
}

/// Outbound write half of a split byte-stream link — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver is owned by the
/// [`writer_task`]. Impls [`BoxedLinkDriver`] so the FSM's
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied with a NON-blocking enqueue:
/// the sync script-action handlers fire from inside a future the same runtime
/// is driving, where a nested `block_on` would trip the "Cannot start a
/// runtime from within a runtime" reentrancy check. The channel decouples that
/// sync-from-async boundary cleanly.
///
/// Transport-neutral (a plain channel sender with a u16-prefix oversize guard,
/// carrying no per-transport state), so TCP and TLS share the one type.
pub struct StreamWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl StreamWriteDriver {
    pub(crate) fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl BoxedLinkDriver for StreamWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Oversize: drop with a warn rather than overflow the u16 length
            // prefix. zenoh-pico's Z_BATCH_UNICAST_SIZE ceiling is 65535, so a
            // larger frame is a wz-side encoder bug — loud.
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
        // owning scope releases the Arc). Explicit per-frame shutdown from the
        // FSM's release_link would race in-flight enqueues; letting the
        // receiver-drop signal terminate the task is the textbook channel idiom.
    }
}

/// Async writer task. Owns a stream write half `W` (any `AsyncWrite` — TCP's
/// `OwnedWriteHalf` or a rustls `WriteHalf<TlsStream<TcpStream>>`) and drains
/// the outbound channel one frame at a time, encoding each payload into the
/// Zenoh streamed-link [`StreamEnvelope`] (u16 LE length prefix + payload) via
/// the codec, then writing + flushing. Generic over the write half so the
/// StreamEnvelope framing is the single source of truth for every byte-stream
/// link. Exits when every write-driver clone has dropped (receiver returns
/// `None`) or a write fails (logged + bail), shutting the write half so the
/// peer observes EOF rather than RST.
pub async fn writer_task<W>(mut writer: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>)
where
    W: AsyncWrite + Unpin,
{
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
        // Codec-routed wire shape (single source of truth for the streamed-link
        // envelope), mirroring the per-transport driver's send.
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

    /// Oversize frames are dropped by `send_blocking` rather than overflowing
    /// the u16 prefix — the channel stays usable afterwards. (Transport-neutral
    /// guard; exercised here once for both the TCP and TLS write paths.)
    #[tokio::test]
    async fn write_driver_drops_oversize_frame() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = StreamWriteDriver::new(tx);
        driver.send_blocking(&vec![0u8; 65_536], Reliability::Reliable);
        driver.send_blocking(b"ok", Reliability::Reliable);
        // Only the in-range frame reached the channel.
        assert_eq!(rx.recv().await.as_deref(), Some(b"ok".as_slice()));
    }
}
