// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use wz_codecs::stream_envelope::StreamEnvelope;

use crate::writer_queue::OutboundQueue;
use crate::{poll_framed, LinkDriver, LinkEvent, ReadState, Reliability, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::LinkEndpoints;
use wz_session_core::link::LinkSubject;

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
    /// transport-lowlatency — shared with the sibling [`writer_task`] and flipped
    /// true by the lowlatency open helper at Established (only when the session
    /// negotiated lowlatency). While true, the streamed length prefix read is the
    /// 4-byte LE u32 zenoh lowlatency form (`unicast/lowlatency/link.rs`), not the
    /// 2-byte u16 batch form; false (the default) keeps the universal u16 prefix,
    /// so a non-lowlatency link and the handshake frames of a lowlatency link read
    /// byte-identically to before.
    lowlatency: Arc<AtomicBool>,
}

impl<R: AsyncRead + Unpin> StreamReadDriver<R> {
    // `pub(crate)` so each transport's `wire_*` constructs it over its own split
    // read half; the type is transport-neutral. `lowlatency` is the flag the
    // lowlatency open helper flips at Established (the TCP dial/accept path
    // threads a shared one; every non-lowlatency stream link passes a fresh
    // always-false flag, keeping the universal u16 prefix).
    pub(crate) fn new(reader: R, lowlatency: Arc<AtomicBool>) -> Self {
        Self {
            reader,
            read_state: ReadState::Idle,
            lowlatency,
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
        poll_framed(
            &mut self.read_state,
            &mut self.reader,
            self.lowlatency.load(Ordering::Acquire),
        )
        .await
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
    /// transport-lowlatency — flipped true by the lowlatency open helper at
    /// Established (a fresh always-false flag for every non-lowlatency link).
    /// While true, [`Self::send_blocking`] frames with the 4-byte LE u32 zenoh
    /// lowlatency prefix (`unicast/lowlatency/link.rs`); false keeps the universal
    /// 2-byte u16 [`StreamEnvelope`] batch prefix. The framing is decided HERE, at
    /// enqueue time (synchronous with the FSM's emit), NOT in the async
    /// [`writer_task`] — so a handshake frame enqueued while the flag is still
    /// false is framed u16 even if the writer drains it after the flip, closing
    /// the enqueue-vs-dequeue race a dequeue-time flag read would open.
    lowlatency: Arc<AtomicBool>,
    /// R311y453 — the §5.16 link-derived subject: this stream's scheme and the
    /// NICs its local address sits on. The type is deliberately transport-NEUTRAL
    /// (see above), so it can infer neither: six pipelines build it — tcp, tls,
    /// quic, unixsock, unixpipe and vsock — and each is the only place that knows
    /// its scheme AND whether it even has an IP address to resolve. Threaded
    /// through the constructor rather than guessed, so a new stream pipeline must
    /// state its subject to compile.
    subject: LinkSubject,
    /// R311y473 — this link's `{src,dst}` locator pair for the adminspace's
    /// per-link view. Threaded through the constructor for the SAME reason
    /// `subject` is: this type is transport-NEUTRAL and so can name neither its
    /// scheme nor its socket, while each of the six constructing pipelines can
    /// name both. `None` when the pipeline could not read one of the two ends —
    /// the admin host still emits the link (the COUNT stays truthful), with the
    /// ends left blank rather than guessed.
    endpoints: Option<LinkEndpoints>,
}

impl StreamWriteDriver {
    pub(crate) fn new(
        tx: mpsc::UnboundedSender<Vec<u8>>,
        lowlatency: Arc<AtomicBool>,
        subject: LinkSubject,
        endpoints: Option<LinkEndpoints>,
    ) -> Self {
        Self {
            tx,
            lowlatency,
            subject,
            endpoints,
        }
    }
}

impl BoxedLinkDriver for StreamWriteDriver {
    // R311y453 — the §5.16 subject the constructing pipeline resolved, since this
    // driver is shared across six of them. A field read, never a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y473 — the adminspace `{src,dst}` pair the constructing pipeline
    // resolved, for the same six-pipelines reason as the subject above.
    fn link_endpoints(&self) -> Option<&wz_session_core::link::LinkEndpoints> {
        self.endpoints.as_ref()
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Oversize: drop with a warn rather than overflow the length prefix.
            // zenoh-pico's Z_BATCH_UNICAST_SIZE ceiling is 65535 and the
            // negotiated lowlatency max (49152) is under it, so a larger frame is
            // a wz-side encoder bug — loud, in either framing mode.
            log::warn!(
                "wz-runtime-tokio: outbound frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return;
        }
        let wire = if self.lowlatency.load(Ordering::Acquire) {
            // transport-lowlatency — 4-byte LE u32 length prefix + payload (zenoh's
            // lowlatency streamed framing), NOT the u16 batch prefix.
            let mut wire = Vec::with_capacity(4 + bytes.len());
            wire.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            wire.extend_from_slice(bytes);
            wire
        } else {
            // Codec-routed wire shape (single source of truth for the streamed-link
            // envelope); `bytes.len() <= u16::MAX` is guaranteed above.
            StreamEnvelope {
                payload_len: bytes.len() as u16,
                payload: bytes,
            }
            .encode_to_vec()
        };
        if let Err(e) = self.tx.send(wire) {
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
/// `OwnedWriteHalf` or a rustls `WriteHalf<TlsStream<TcpStream>>`) and drains the
/// outbound queue one PRE-FRAMED wire at a time, writing + flushing each. The
/// length-prefix framing is applied by [`StreamWriteDriver::send_blocking`] at
/// enqueue time (synchronous with the FSM's emit), so a handshake frame enqueued
/// before a lowlatency flag flip stays u16-framed regardless of when it drains —
/// the writer never re-decides framing. Generic over the write half so it is the
/// single home for every byte-stream link.
///
/// R311y519 — exits on ANY of three signals, and the middle one is the new
/// teardown contract: the queue was SEALED and its remaining frames have been
/// handed over ([`OutboundQueue::next`]); every write-driver clone has dropped;
/// or a write failed / stalled past [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS)
/// on a sealed queue (logged + bail). The first two shut the write half so the
/// peer observes EOF rather than RST; a bail does not, because a peer that is
/// not reading will not read a shutdown either.
pub async fn writer_task<W>(mut writer: W, mut queue: OutboundQueue)
where
    W: AsyncWrite + Unpin,
{
    while let Some(wire) = queue.next().await {
        let write = async {
            writer.write_all(&wire).await?;
            writer.flush().await
        };
        match queue.guarded(write).await {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: writer_task write failed: {e}; closing");
                return;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: writer_task stalled past {} ms draining a sealed \
                     queue; the peer has stopped reading. Closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return;
            }
        }
    }
    // Queue finished -> shut the write half cleanly (peer sees EOF, not RST).
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
        let driver = StreamWriteDriver::new(
            tx,
            Arc::new(AtomicBool::new(false)),
            LinkSubject::UNKNOWN,
            None,
        );
        driver.send_blocking(&vec![0u8; 65_536], Reliability::Reliable);
        driver.send_blocking(b"ok", Reliability::Reliable);
        // Only the in-range frame reached the channel, u16-framed at enqueue
        // (2-byte LE len=2 + "ok"); the oversize frame was dropped.
        assert_eq!(
            rx.recv().await.as_deref(),
            Some([0x02, 0x00, b'o', b'k'].as_slice())
        );
    }
}
