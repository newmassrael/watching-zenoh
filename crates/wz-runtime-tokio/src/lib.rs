// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `sce_link_runtime_tokio` — Tokio + mio epoll runtime for the
//! watching-zenoh AP linux target.
//!
//! Phase Z entry (R51). The trait surface here matches
//! `docs/runtime-crate-tokio.md` §2.1 minimum: open / send / close /
//! poll_event. Trust-class gating, io_uring opt-in, and pool-slot Rx
//! borrows are deferred to later rounds; the R51-R52 scope is the
//! 4-method baseline + a TCP impl + the R52 echo demo (publisher /
//! subscriber tokio tasks on loopback).
//!
//! No FSM here yet — the session_fsm.scxml R29 placeholder wiring is
//! a separate round (R54). For R52 the demo manually drives
//! encode → send → recv → decode without an FSM mediator.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Outbound payload to send over a link. The R51 baseline carries
/// raw bytes; future rounds extend to typed frames (carrying codec
/// metadata for re-encoding on the link side without copy).
pub struct TxFrame<'a> {
    pub bytes: &'a [u8],
}

/// Inbound frame received from a link. R51 baseline: owned `Vec<u8>`.
/// Future rounds (per docs/runtime-crate-tokio.md §2.3) will switch
/// this to a pool-slot borrow `RxFrame<'pool>` for zero-copy decode.
#[derive(Debug)]
pub struct RxFrame {
    pub bytes: Vec<u8>,
}

/// Reliability hint forwarded to the driver per session-fsm §6
/// outbound table. R51 baseline TCP impl ignores the hint (TCP is
/// reliable by definition); UDP/best-effort impl will honor it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    Reliable,
    BestEffort,
}

/// Single event source surfaced by a link driver. R51 baseline
/// emits only Ready / Rx / Lost; backpressure + framing_error +
/// tx_drained land when their consumers (codec-level decoder +
/// session FSM) are wired.
#[derive(Debug)]
pub enum LinkEvent {
    Ready,
    Rx(RxFrame),
    Lost { cause: LostCause },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostCause {
    PeerClosed,
    Timeout,
    OsError,
}

/// The 4-method `LinkDriver` trait. Matches
/// docs/runtime-crate-tokio.md §2.1. Trust-class flavored variants
/// (untrusted / session_arming / established_session) deferred to
/// later rounds; this baseline assumes established_session
/// (the trust class where all four methods are present).
#[allow(async_fn_in_trait)] // R51: simple trait; refine to Send bounds later
pub trait LinkDriver {
    async fn open(&mut self) -> io::Result<()>;
    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()>;
    async fn close(&mut self) -> io::Result<()>;
    async fn poll_event(&mut self) -> LinkEvent;
}

/// Minimal TCP driver. Reads/writes length-prefixed frames on a
/// single TcpStream: 4-byte BE length + bytes. The framing is
/// not yet wz-codec-driven (a real SCXML framer kind lands in a
/// later round); for R52 echo demo this manual framing is
/// sufficient.
pub struct TcpDriver {
    stream: Option<TcpStream>,
}

impl TcpDriver {
    /// Wrap an already-open TcpStream (acceptor side). The
    /// `open()` method is a no-op for this constructor.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl LinkDriver for TcpDriver {
    async fn open(&mut self) -> io::Result<()> {
        // R51 baseline: caller passes an already-open stream via
        // from_stream. Outbound dial flow (TcpStream::connect) lands
        // when the session FSM Initiator path is wired.
        if self.stream.is_some() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TcpDriver::open requires from_stream constructor",
            ))
        }
    }

    async fn send(
        &mut self,
        frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no stream"))?;
        let len: u32 = frame
            .bytes
            .len()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame > 4 GiB"))?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(frame.bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        if let Some(mut s) = self.stream.take() {
            s.shutdown().await?;
        }
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        let stream = match self.stream.as_mut() {
            Some(s) => s,
            None => return LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            },
        };
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            Err(_) => {
                return LinkEvent::Lost {
                    cause: LostCause::OsError,
                };
            }
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        match stream.read_exact(&mut buf).await {
            Ok(_) => LinkEvent::Rx(RxFrame { bytes: buf }),
            Err(_) => LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            },
        }
    }
}
