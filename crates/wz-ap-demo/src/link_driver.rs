// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — bidirectional TCP link wiring.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds the cooperating drivers + writer task that bridge
// a single accepted `TcpStream` to the session-FSM's
// `&mut LinkDriver` inbound shape and `Arc<dyn BoxedLinkDriver>`
// outbound shape:
//
//   * `InboundReadDriver` — owns `OwnedReadHalf`; impls
//     [`LinkDriver`] with a `tokio::select!`-cancel-safe
//     length-prefixed framing reader (R265 partial-read state).
//   * `OutboundWriteDriver` — holds the channel sender; impls
//     [`BoxedLinkDriver`] with a non-blocking enqueue.
//   * `writer_task` — owns `OwnedWriteHalf`; drains the channel and
//     writes the Zenoh stream envelope (u16 LE length prefix +
//     payload) per frame.
//
// See the module-level comment block in `main.rs` for the
// architectural rationale (why the split is forced by
// `&mut LinkDriver` vs `Arc<dyn BoxedLinkDriver>` reconciliation,
// and why the channel decouples the sync-from-async boundary).

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use wz_runtime_tokio::session_glue::BoxedLinkDriver;
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

/// Inbound half of the bidirectional split — owns the read half of
/// the accepted TcpStream and implements [`LinkDriver`] with
/// poll_event reading one Zenoh stream envelope (u16 LE length
/// prefix + payload, mirroring zenoh-pico's
/// `_z_link_recv_t_msg_cap_flow_stream`).
///
/// The send/open/close methods are no-ops because the inbound side
/// never emits outbound bytes — the FSM's outbound path is wired
/// through [`OutboundWriteDriver`] (`BoxedLinkDriver` shape) held by
/// `SessionLinkActions`.
///
/// R265 — `read_state` carries partial-read bytes across
/// `tokio::select!` cancellations of `poll_event` so a future that
/// loses a select race does not drop in-flight wire bytes. Mirrors
/// the same state machine on `wz_runtime_tokio::TcpDriver`; see the
/// `wz_runtime_tokio::ReadState` doc-comment for the cancel-safety
/// rationale.
pub(crate) struct InboundReadDriver {
    reader: OwnedReadHalf,
    read_state: InboundReadState,
}

impl InboundReadDriver {
    pub(crate) fn new(reader: OwnedReadHalf) -> Self {
        Self {
            reader,
            read_state: InboundReadState::Idle,
        }
    }
}

/// R265 — cancel-safe partial-read state for
/// [`InboundReadDriver::poll_event`]. Mirrors `wz_runtime_tokio::
/// ReadState` (kept locally so the binary does not depend on a
/// library-internal type). See that doc-comment for the rationale.
#[derive(Default)]
enum InboundReadState {
    #[default]
    Idle,
    Length { prefix: [u8; 2], offset: usize },
    Payload { frame: Vec<u8>, offset: usize },
}

impl LinkDriver for InboundReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // Stream already opened by TcpListener::accept; the FSM's
        // outbound side calls open_blocking on OutboundWriteDriver
        // (which is also a no-op since accept established the
        // connection). Inbound open is therefore unconditionally Ok.
        Ok(())
    }

    async fn send(
        &mut self,
        _frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        // Inbound driver never sends — the FSM's script-actions
        // dispatch outbound via the OutboundWriteDriver Arc captured
        // by SessionLinkActions. Surface as NotConnected so any
        // accidental invocation fails loud rather than silently
        // swallowing.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "InboundReadDriver does not send; outbound goes via OutboundWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // Drop happens on the read half independently of the write
        // half close. No explicit shutdown needed.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // R265 — cancel-safe state machine; each `.await` is a
        // single `.read()` syscall, partial-read bytes survive
        // a `tokio::select!` drop in `self.read_state`. See
        // `InboundReadState` for the state graph and
        // `wz_runtime_tokio::ReadState` for the full rationale.
        loop {
            match &mut self.read_state {
                InboundReadState::Idle => {
                    self.read_state = InboundReadState::Length {
                        prefix: [0u8; 2],
                        offset: 0,
                    };
                }
                InboundReadState::Length { prefix, offset } => {
                    match self.reader.read(&mut prefix[*offset..]).await {
                        Ok(0) => {
                            self.read_state = InboundReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::PeerClosed,
                            };
                        }
                        Ok(n) => {
                            *offset += n;
                            if *offset == 2 {
                                let payload_len =
                                    u16::from_le_bytes(*prefix) as usize;
                                self.read_state = InboundReadState::Payload {
                                    frame: vec![0u8; payload_len],
                                    offset: 0,
                                };
                            }
                        }
                        Err(_) => {
                            self.read_state = InboundReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::OsError,
                            };
                        }
                    }
                }
                InboundReadState::Payload { frame, offset } => {
                    if *offset == frame.len() {
                        let bytes = std::mem::take(frame);
                        self.read_state = InboundReadState::Idle;
                        log::debug!(
                            "wz-ap-demo: inbound frame len={} bytes={:02x?}",
                            bytes.len(),
                            bytes
                        );
                        return LinkEvent::Rx(RxFrame { bytes });
                    }
                    match self.reader.read(&mut frame[*offset..]).await {
                        Ok(0) => {
                            self.read_state = InboundReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::PeerClosed,
                            };
                        }
                        Ok(n) => {
                            *offset += n;
                        }
                        Err(_) => {
                            self.read_state = InboundReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::OsError,
                            };
                        }
                    }
                }
            }
        }
    }
}

/// Outbound half of the bidirectional split — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver is owned by a
/// dedicated [`writer_task`] spawned in `run_demo`. Implements
/// [`BoxedLinkDriver`] so `SessionLinkActions::new`'s
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied.
///
/// `send_blocking` enqueues the transport-message bytes
/// synchronously (channel send is non-blocking and has no
/// `block_on`), which is the architecturally required shape: the
/// FSM script-action handlers (e.g. `send_init_ack_with_cookie`)
/// fire from the synchronous portion of `drive_session_until_terminal`,
/// and that loop is itself a future driven by the same Tokio
/// runtime. A `Handle::block_on` from inside such a future would
/// fail the "Cannot start a runtime from within a runtime"
/// reentrancy check; the channel decoupling keeps the
/// sync-from-async boundary clean.
///
/// Frame ordering is preserved because the channel is single-
/// producer-single-consumer in the demo (one Lua engine drives
/// one writer task) and `mpsc` preserves enqueue order.
pub(crate) struct OutboundWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl OutboundWriteDriver {
    pub(crate) fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl BoxedLinkDriver for OutboundWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Frame oversize: drop with a warn rather than overflow
            // the u16 length prefix. zenoh-pico's
            // `Z_BATCH_UNICAST_SIZE` ceiling is 65535, so a frame
            // larger than this is a wz-side encoder bug — surface
            // loudly.
            log::warn!(
                "wz-ap-demo: outbound frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-ap-demo: outbound channel closed; dropping frame ({e})");
        }
    }

    fn open_blocking(&self) {
        // TcpListener::accept already returned an established
        // stream; open is a no-op on this driver shape.
    }

    fn close_blocking(&self) {
        // The writer task is owned by `run_demo`'s scope and exits
        // when every Sender clone is dropped (after run_demo
        // returns). Explicit per-frame shutdown from the FSM's
        // `release_link` would race against in-flight enqueues;
        // letting the receiver-drop signal terminate the task is
        // the textbook channel idiom.
    }
}

/// Async writer task. Owns the [`OwnedWriteHalf`] and drains the
/// outbound channel one frame at a time, writing each frame's
/// Zenoh stream envelope (u16 LE length prefix + payload) and
/// flushing. Exits when every [`OutboundWriteDriver`] clone has
/// dropped (i.e. the receiver returns `None`) or when a write
/// fails (logged + bail).
pub(crate) async fn writer_task(
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        // Defensive: send_blocking already rejects oversize frames,
        // but assert here in case a future caller bypasses that
        // check.
        let len = match u16::try_from(payload.len()) {
            Ok(n) => n,
            Err(_) => {
                log::warn!(
                    "wz-ap-demo: writer_task received oversize frame ({} bytes); dropping",
                    payload.len()
                );
                continue;
            }
        };
        if let Err(e) = writer.write_all(&len.to_le_bytes()).await {
            log::warn!("wz-ap-demo: write length prefix failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.write_all(&payload).await {
            log::warn!("wz-ap-demo: write payload failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.flush().await {
            log::warn!("wz-ap-demo: flush failed: {e}; closing");
            return;
        }
    }
    // Channel closed → shut down the write half cleanly so the peer
    // observes EOF rather than RST.
    let _ = writer.shutdown().await;
}
