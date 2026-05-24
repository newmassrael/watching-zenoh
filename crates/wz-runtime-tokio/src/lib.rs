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

use sce_forge_runtime::codec::SceCursor;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use wz_codecs::stream_envelope::StreamEnvelope;

pub mod session_glue;

/// R221 — zenoh keyexpr canonicalization mirror. Mirrors the
/// structural-only canonicalization performed by zenoh-pico's
/// `_z_keyexpr_canonize` so wz-side subscriber / queryable
/// registrations store the canonical form a peer would emit on the
/// wire. See `keyexpr_canon` module doc comment for the scope (no
/// lowercase / no NFC — pure structural) and the call-site wiring.
pub mod keyexpr_canon;

/// R223 — zenoh-style locality filter for subscribers and queryables.
/// Mirrors zenoh-pico's `z_locality_t` enum and the
/// `_z_locality_allows_local` / `_z_locality_allows_remote` helpers
/// so applications can register subscriptions that fire only on
/// session-local samples, only on remote samples, or both
/// (default). See `locality` module doc for the dispatch invariant
/// and the surface-vs-dispatch distinction.
pub mod locality;

/// R222 / R225 — application-layer `Sample` type for subscriber callbacks.
/// Mirrors zenoh-pico's `_z_sample_t` projection. R222 introduced the
/// three load-bearing fields (`keyexpr` / `kind` / `payload`); R225
/// extends the parity surface with `timestamp` / `encoding` / `qos` /
/// `attachment` / `source_info` / `reliability` so subscribers no longer
/// need to dig into `Push.extensions` to inspect Sample metadata. See
/// the `sample` module doc for the wire-decode origin of each field
/// and the `#[non_exhaustive]` future-additive contract.
pub mod sample;

/// R98 — application-layer subscriber registry. Routes decoded
/// `NetworkMessage::Push` records to user-registered callbacks
/// filtered by literal keyexpr. See `pubsub::SubscriberRegistry`
/// doc comment for the scope and threading contract.
///
/// R311h — pubsub module stays always-on at the wz-runtime-tokio
/// level (wire-side `codec-push` gating elides session_glue.rs's
/// Push surface; pubsub.rs requires the `wz_codecs::push::Push`
/// type unconditionally because dispatch_push / SampleKind
/// projection / Subscriber RAII reference it directly). The
/// `wz-codecs/codec-push` Cargo dep stays in the wz-runtime-tokio
/// base feature set so the Push module is always compiled.
/// Consumer-module gating cascade (Subscriber / declare_subscriber*
/// / publish* on codec-push) is deferred to R311m for atomic
/// per-cascade footprint per `feedback_signature_stability`
/// MEMORY anchor's architectural deferral carve-out.
pub mod pubsub;

/// R121j-5b — application-layer queryable registry. Q-side mirror of
/// [`pubsub::SubscriberRegistry`]: routes inbound
/// `NetworkMessage::Request` records (Query body arm) to user-
/// registered `on_query` callbacks, which emit Reply / Err records
/// via a [`query::QueryResponder`] borrow. The runtime wiring that
/// turns the accumulated `Vec<QueryReply>` into outbound Response
/// frames lands in R121j-5c. See `query` module doc comment for the
/// scope, threading, and Responder lifetime contract.
///
/// R307 — module-level gate on `feature = "query-queryable"`. Wz
/// consumers selecting `preset-mcu-minimal` (no query domain) or
/// hand-picking `runtime-tokio` without `query-queryable` get a
/// build with this module elided entirely; the `Session::declare_-
/// queryable` API surface in `session.rs` is gated on the same
/// feature so the symbol set is self-consistent.
#[cfg(feature = "query-queryable")]
pub mod query;

/// R121k-2 — application-layer remote-declaration registries. Route
/// decoded `Declare(Decl*|Undecl*)` records to user-registered
/// callbacks. This round lands `RemoteSubscriberRegistry`
/// (DeclSubscriber + UndeclSubscriber); R121k-3 adds
/// `RemoteQueryableRegistry`, R121k-4 adds `LivelinessRegistry`. The
/// dispatch wiring that fans inbound `Declare` envelopes through all
/// three lands in R121k-5. See `declare` module doc comment for the
/// scope and callback contract.
pub mod declare;

/// R121j-6 — application-layer reply registry. Z_get-side mirror of
/// [`query::QueryableRegistry`]: routes inbound
/// `NetworkMessage::Response(Reply|Err)` and
/// `NetworkMessage::ResponseFinal` records to per-rid callbacks
/// registered by `z_get`-side callers. Pending entries auto-
/// unregister on `ResponseFinal` (zenoh-pico "exactly one Final
/// terminates the chain" semantics). See `reply` module doc comment
/// for scope, callback shape, and threading.
///
/// R307 — module-level gate on `feature = "query-reply"`. The
/// `query-get` feature pulls this transitively because
/// `Session::get` registers a pending entry against
/// [`reply::ReplyRegistry`]; consumers that only declare queryables
/// (no `Session::get`) can disable both `query-get` and
/// `query-reply` and have the module elided entirely.
#[cfg(feature = "query-reply")]
pub mod reply;

/// R121k-7 — application-layer observer bundle. Combines the six
/// per-domain registries (subscribers, queryables, remote_subscribers,
/// remote_queryables, liveliness, replies) plus the queryable side's
/// pending-reply / pending-final staging buffers into one cohesive
/// struct so production callers drive the whole dispatch graph with
/// a single [`observer::ApplicationLayerObserver::dispatch`] call per
/// [`session_glue::IterationEvent`]. See `observer` module doc
/// comment for the rationale, dispatch flow, and what is NOT in
/// scope.
pub mod observer;

/// R228 — application-level [`session::Session`] bundle. Owns an
/// outbound [`session_glue::SessionLinkActions`] handle plus a
/// shared [`observer::ApplicationLayerObserver`] reference so a
/// single [`session::Session::publish`] call routes through both the
/// wire-side codec and the in-process subscriber loopback per
/// [`session::PublishOptions::allowed_destination`]. Mirrors
/// zenoh-pico's `_z_session_t`. R228 scope: literal-keyexpr Put +
/// Del. Aliased publish + full Sample metadata are R229+ carries.
pub mod session;

/// R252 — AP-profile concrete impls of the
/// [`wz_runtime_core::Runtime`] and [`wz_runtime_core::TimeSource`]
/// trait contracts authored in R251. [`runtime_impl::TokioRuntime`]
/// spawns tasks via `tokio::task::spawn` and wraps the returned
/// `tokio::task::JoinHandle` into a [`runtime_impl::TokioJoinHandle`]
/// that satisfies the trait's `Future<Output = Result<T,
/// RuntimeError>>` shape by mapping `tokio::task::JoinError` to
/// [`wz_runtime_core::RuntimeError::JoinFailed`].
/// [`runtime_impl::TokioTime`] samples a monotonic
/// `tokio::time::Instant` for `now_monotonic_ms` and yields via
/// `tokio::time::sleep(Duration)` for the async sleep contract. R252
/// lands the impl but leaves the 111 std/tokio call sites unchanged;
/// R253+ migrate them leaf-first, with `Session` last per the
/// §5.P "leaf crates first" guidance.
pub mod runtime_impl;

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
/// outbound table; also surfaces as the link-layer reliability
/// classification on inbound samples (zenoh-pico `z_reliability_t`
/// mirror). R51 baseline TCP impl ignores the hint on the outbound
/// path (TCP is reliable by definition); UDP/best-effort impl will
/// honor it. R226 added `Default` / `Hash` / `repr(u8)` so the same
/// enum can carry inbound `Sample.reliability` per the zenoh-pico
/// `_z_trigger_push` argument shape.
///
/// The default value matches zenoh-pico's
/// `Z_RELIABILITY_DEFAULT = Z_RELIABILITY_RELIABLE` contract — a
/// subscriber that does not inspect the field observes the most
/// permissive delivery guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Reliability {
    /// Best-effort delivery — samples may be dropped (zenoh-pico
    /// `Z_RELIABILITY_BEST_EFFORT`).
    BestEffort = 0,
    /// Reliable delivery — link layer guarantees ordering and delivery
    /// (zenoh-pico `Z_RELIABILITY_RELIABLE`, the default).
    #[default]
    Reliable = 1,
}

impl Reliability {
    /// Map a `reliable: bool` discriminator (the
    /// `DriverLoopOutcome::FramePayload.reliable` field shape) to the
    /// typed enum. Inbound dispatch uses this to project the
    /// frame-level bool into a `Sample.reliability` value.
    pub fn from_reliable_bool(reliable: bool) -> Self {
        if reliable {
            Reliability::Reliable
        } else {
            Reliability::BestEffort
        }
    }
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
/// single TcpStream using the Zenoh streamed-link wire envelope:
/// **2-byte little-endian length** + payload bytes. This matches
/// zenoh-pico's `_z_link_send_t_msg` /
/// `_z_link_recv_t_msg_cap_flow_stream` (`Z_LINK_CAP_FLOW_STREAM`
/// branch) at zenoh-pico/src/transport/common/{tx,rx}.c with
/// `_Z_MSG_LEN_ENC_SIZE = 2` (zenoh-pico/include/zenoh-pico/
/// protocol/definitions/core.h:32), and bounds the per-frame
/// payload to 65535 bytes which is also the upstream
/// `Z_BATCH_UNICAST_SIZE` ceiling.
///
/// R121h: the wire envelope is now expressed by
/// `sources/codecs/stream_envelope.scxml` (SCE codec_kind) and
/// rendered into `wz_codecs::stream_envelope::StreamEnvelope`. The
/// driver invokes the generated encoder on `send` and the generated
/// decoder on `poll_event` so the codec catalog is the single
/// source of truth for the on-wire shape. The 2-byte prefix read
/// at the start of `poll_event` is unavoidable until SCE exposes a
/// codec-level `MIN_FRAME_BYTES` associated constant (the wire
/// shape needs a length to size the second `read_exact`, and the
/// codec's `decode` requires the full frame in the cursor before
/// it can run). The duplication is bounded to a 2-byte `[u8; 2]`
/// length sniff; the structural decode runs through the codec.
pub struct TcpDriver {
    stream: Option<TcpStream>,
    /// R265 — partial-read state machine for the cancel-safe
    /// poll_event implementation. Carries the in-flight length
    /// prefix or payload bytes across `tokio::select!` cancellations
    /// of `poll_event`, so the next iteration resumes from the
    /// last byte offset rather than re-syncing from a mid-frame
    /// socket cursor. See [`ReadState`] for the state graph.
    read_state: ReadState,
}

/// R265 — cancel-safe partial-read state for [`TcpDriver::poll_event`]
/// (the same shape is mirrored on `wz-ap-demo`'s `InboundReadDriver`).
///
/// Background. The `tokio::io::AsyncReadExt::read_exact` future loops
/// internally over `.read()` calls; if its outer future is dropped
/// (e.g. by `tokio::select!` losing the race) any bytes already
/// consumed from the socket are discarded. For a length-prefixed
/// envelope (2 byte length, N byte payload) that means the next
/// poll re-reads from the socket cursor at an offset that no longer
/// aligns with a frame boundary, and the decoder mis-interprets
/// payload bytes as the next frame's length. R264 fixture surfaced
/// this when a sub-second sweep cadence inside `drive_session_until_-
/// terminal` race-cancelled `poll_and_dispatch_one` 10x/s.
///
/// Fix shape. The state machine keeps the partial-read buffers in
/// `&mut self`, and the only `.await` point per state transition is
/// a single `.read()` syscall. `AsyncReadExt::read` is documented as
/// cancel-safe (no bytes consumed if the future is dropped before
/// completion), so dropping `poll_event` mid-state leaves the
/// captured offset / buffer intact for the next invocation.
#[derive(Default)]
enum ReadState {
    /// No partial read in flight. Next `poll_event` enters
    /// `Length` and begins reading the 2-byte prefix.
    #[default]
    Idle,
    /// Length prefix partially read. `prefix[..offset]` holds the
    /// bytes consumed so far; `offset < 2`. Once `offset == 2`,
    /// the prefix is decoded and the state transitions to
    /// `Payload` with a sized buffer.
    Length { prefix: [u8; 2], offset: usize },
    /// Payload partially read into `frame[..offset]`; `frame`
    /// includes the 2-byte length prefix at `frame[..2]` so the
    /// codec decode at frame-complete operates on the wire-shape
    /// bytes verbatim. `offset < frame.len()` while reading;
    /// `offset == frame.len()` means the frame is complete and
    /// the state machine emits a `LinkEvent::Rx` + transitions
    /// back to `Idle` on the next iteration.
    Payload { frame: Vec<u8>, offset: usize },
}

impl TcpDriver {
    /// Wrap an already-open TcpStream (acceptor side). The
    /// `open()` method is a no-op for this constructor.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
            read_state: ReadState::Idle,
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

    async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no stream"))?;
        let payload_len: u16 = frame
            .bytes
            .len()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame > 65535 bytes"))?;
        let envelope = StreamEnvelope {
            payload_len,
            payload: frame.bytes.to_vec(),
        };
        let wire = envelope.encode_to_vec();
        stream.write_all(&wire).await?;
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
            None => {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                }
            }
        };
        // R265 — cancel-safe state machine. Each `.await` is a
        // single `.read()` syscall (cancel-safe per tokio
        // contract); the buffered partial read survives across
        // `tokio::select!` drops in `self.read_state`. See the
        // `ReadState` doc-comment for the cancellation rationale.
        // Frame-complete branch is the only exit path that emits
        // `LinkEvent::Rx`; error / EOF branches reset
        // `self.read_state` to `Idle` so a future open()+retry
        // path does not inherit a partial buffer from the lost
        // connection.
        loop {
            match &mut self.read_state {
                ReadState::Idle => {
                    self.read_state = ReadState::Length {
                        prefix: [0u8; 2],
                        offset: 0,
                    };
                }
                ReadState::Length { prefix, offset } => {
                    match stream.read(&mut prefix[*offset..]).await {
                        Ok(0) => {
                            self.read_state = ReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::PeerClosed,
                            };
                        }
                        Ok(n) => {
                            *offset += n;
                            if *offset == 2 {
                                let payload_len = u16::from_le_bytes(*prefix) as usize;
                                let mut frame = vec![0u8; 2 + payload_len];
                                frame[..2].copy_from_slice(prefix);
                                self.read_state = ReadState::Payload { frame, offset: 2 };
                            }
                        }
                        Err(_) => {
                            self.read_state = ReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::OsError,
                            };
                        }
                    }
                }
                ReadState::Payload { frame, offset } => {
                    if *offset == frame.len() {
                        // Frame complete. Take the buffer out
                        // before decoding so the state reset is
                        // visible if the codec rejects.
                        let bytes = std::mem::take(frame);
                        self.read_state = ReadState::Idle;
                        let mut cursor = SceCursor::new(&bytes);
                        return match StreamEnvelope::decode(&mut cursor) {
                            Ok(env) => LinkEvent::Rx(RxFrame { bytes: env.payload }),
                            Err(_) => LinkEvent::Lost {
                                cause: LostCause::PeerClosed,
                            },
                        };
                    }
                    match stream.read(&mut frame[*offset..]).await {
                        Ok(0) => {
                            self.read_state = ReadState::Idle;
                            return LinkEvent::Lost {
                                cause: LostCause::PeerClosed,
                            };
                        }
                        Ok(n) => {
                            *offset += n;
                        }
                        Err(_) => {
                            self.read_state = ReadState::Idle;
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

    async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // UDP link layer is best-effort by definition; Reliability
        // hint is the session FSM's concern (it may resend on the
        // RELIABLE channel via a sequence-number window). Here we
        // just write the datagram.
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no socket"))?;
        let peer = self
            .peer
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no peer address"))?;
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
            None => {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                }
            }
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
