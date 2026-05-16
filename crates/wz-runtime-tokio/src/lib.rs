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
//! R54 entry. The R29 session_fsm.scxml script-action placeholders
//! are wired to `LinkDriver` through `session_glue::SessionLinkActions`
//! plus Lua-engine `register_global_function` registrations. The
//! generated state machine emit lives at `pub mod session_fsm_unicast`
//! and is composed via `session_glue::install_session_actions` for
//! every native dispatch from `<script>...</script>` action bodies.

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub mod session_glue;

/// Generated SCXML state machine for the unicast session FSM. The
/// emit comes from `sources/session/session_fsm_unicast.scxml` via
/// `build.rs`. Public re-export is module-form rather than
/// `pub use ::*` to keep the generated typenames (`StateXxx`,
/// `EventXxx`, …) namespaced under `session_fsm_unicast::`.
///
/// The build script strips every `#![...]` inner attribute from the
/// emitted file (R40 carry + R54 statechart extension); the lint
/// allows the generator originally carried are restored here as
/// OUTER attributes so the generated code's actual warnings (which
/// trip `warnings = "deny"` workspace policy) stay suppressed.
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(unused_assignments)]
#[allow(clippy::style)]
#[allow(clippy::complexity)]
pub mod session_fsm_unicast {
    include!(concat!(env!("OUT_DIR"), "/session_fsm_unicast_sm.rs"));
}

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

/// UDP datagram driver. R51 baseline assumes one peer; each
/// `send()` writes one datagram, each `poll_event()` receives one
/// datagram. No framing prefix — UDP preserves message boundaries.
/// Honors `Reliability::BestEffort` (the natural UDP semantic) and
/// silently drops the hint on `Reliability::Reliable` (the session
/// FSM's responsibility — UDP cannot enforce reliability at the
/// link layer).
pub struct UdpDriver {
    socket: Option<UdpSocket>,
    peer: Option<SocketAddr>,
}

impl UdpDriver {
    /// Wrap a bound UdpSocket + the remote peer the driver
    /// `send()` targets. R51 baseline: caller establishes the
    /// (socket, peer) pair externally; future rounds add an
    /// outbound-discovery + scout-driven peer-selection path.
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> Self {
        Self {
            socket: Some(socket),
            peer: Some(peer),
        }
    }
}

impl LinkDriver for UdpDriver {
    async fn open(&mut self) -> io::Result<()> {
        if self.socket.is_some() && self.peer.is_some() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UdpDriver::open requires from_socket constructor",
            ))
        }
    }

    async fn send(
        &mut self,
        frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        // UDP link layer is best-effort by definition; Reliability
        // hint is the session FSM's concern (it may resend on the
        // RELIABLE channel via a sequence-number window). Here we
        // just write the datagram.
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no socket"))?;
        let peer = self.peer.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no peer address")
        })?;
        socket.send_to(frame.bytes, peer).await?;
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        // UdpSocket has no kernel-level "close" handshake; dropping
        // the socket releases the FD. Set our handle to None so
        // subsequent calls report NotConnected.
        self.socket = None;
        self.peer = None;
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        let socket = match self.socket.as_ref() {
            Some(s) => s,
            None => return LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            },
        };
        // Single datagram size cap = 65507 bytes (max UDP payload).
        // R51 baseline allocates per-recv; production tuning will
        // use a recycled buffer pool (RFC §5.E lifecycle).
        let mut buf = vec![0u8; 65507];
        match socket.recv_from(&mut buf).await {
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
