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

// R311cb — TCP/UDP imports are wire-up-gated. cfg-off elides the
// tokio::net dependency at the driver-construction site (the tokio
// dep stays unconditional because session_glue.rs uses tokio::time +
// tokio::sync regardless of which link kind is enabled).
#[cfg(feature = "transport-link-tcp")]
use sce_forge_runtime::codec::SceCursor;
use std::io;
#[cfg(any(feature = "transport-link-tcp", feature = "transport-link-udp"))]
use std::net::SocketAddr;
#[cfg(feature = "transport-link-tcp")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "transport-link-tcp")]
use tokio::net::TcpStream;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;
#[cfg(feature = "transport-link-tcp")]
use wz_codecs::stream_envelope::StreamEnvelope;

pub mod session_glue;

// R311eo — generic SCXML script-action binders (bind_unit / bind_guard),
// extracted from session_glue and generalised over the deps type so the
// scouting FSM glue reuses them. Neutral module: depends on neither glue.
mod script_bind;

/// R221 — zenoh keyexpr canonicalization mirror. Mirrors the
/// structural-only canonicalization performed by zenoh-pico's
/// `_z_keyexpr_canonize` so wz-side subscriber / queryable
/// registrations store the canonical form a peer would emit on the
/// wire. See `keyexpr_canon` module doc comment for the scope (no
/// lowercase / no NFC — pure structural) and the call-site wiring.
// R311cf — keyexpr-canon gates the structural canonicalization mirror
// (mirrors zenoh-pico's `_z_keyexpr_canonize`). cfg-off: the module
// is unavailable; callers that need canonical form must construct
// keyexprs already in canonical shape. The other 7 keyexpr-* features
// (-literal, -mapping, -intersect, -includes, -wildcard-*, -dollar-star)
// are cluster-wide behaviors with no single anchor site — carried for
// per-site wire-up in a follow-up cascade.
// R311di-2 — keyexpr_canon moved to wz-session-core; re-export keeps
// `crate::keyexpr_canon::*` callsites verbatim across the wz-runtime-tokio
// surface (query.rs / pubsub.rs / session.rs / session_glue.rs).
#[cfg(feature = "keyexpr-canon")]
pub use wz_session_core::keyexpr_canon;

/// R223 — zenoh-style locality filter for subscribers and queryables.
/// Mirrors zenoh-pico's `z_locality_t` enum and the
/// `_z_locality_allows_local` / `_z_locality_allows_remote` helpers
/// so applications can register subscriptions that fire only on
/// session-local samples, only on remote samples, or both
/// (default). See `locality` module doc for the dispatch invariant
/// and the surface-vs-dispatch distinction.
// R311di-3 — locality moved to wz-session-core; re-export keeps every
// `crate::locality::*` callsite (pubsub.rs / query.rs / session.rs)
// verbatim across the wz-runtime-tokio surface.
pub use wz_session_core::locality;

/// R222 / R225 — application-layer `Sample` type for subscriber callbacks.
/// Mirrors zenoh-pico's `_z_sample_t` projection. R222 introduced the
/// three load-bearing fields (`keyexpr` / `kind` / `payload`); R225
/// extends the parity surface with `timestamp` / `encoding` / `qos` /
/// `attachment` / `source_info` / `reliability` so subscribers no longer
/// need to dig into `Push.extensions` to inspect Sample metadata. See
/// the `sample` module doc for the wire-decode origin of each field
/// and the `#[non_exhaustive]` future-additive contract.
// R311di-4 — sample moved to wz-session-core; re-export keeps every
// `crate::sample::*` callsite (pubsub.rs / session.rs / session_glue.rs)
// verbatim across the wz-runtime-tokio surface.
pub use wz_session_core::sample;

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
/// R311r — module is type-ungated. The `QueryableRegistry` struct,
/// the `QueryResponder` internal type, the `QueryReply` accumulator
/// enum, and the supporting types are always defined regardless of
/// the `query-queryable` feature so that
/// [`crate::query_event::QueryEvent`] / [`crate::query_event::ReplyEmitter`]
/// (the consumer-facing wrappers) and the type-ungated
/// `Session::declare_queryable{_aliased}` Result-form signatures
/// compile unconditionally. The wire-emit terminal step
/// (`QueryReply::into_response`) remains cfg-gated on `codec-response`
/// — the dispatch / loopback / staging paths stage `QueryReply`
/// records into a `Vec` without needing `codec-response`, so the
/// module body compiles cleanly under any consumer-feature subset.
pub mod query;

/// R311r — application-visible query callback wrappers. Always
/// compiled regardless of `query-queryable` feature state so the
/// type-ungated `Session::declare_queryable{_aliased}` signatures
/// have a valid parameter type in every build. See the module's own
/// doc-comment for the wrapper design rationale + the no-op
/// fall-through on the `query-queryable`-OFF build.
pub mod query_event;

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
/// R311s — module is type-ungated. The `ReplyRegistry` struct, the
/// `InboundReply` projection, the `ReplyHandle` opaque, and the
/// supporting types are always defined so the type-ungated
/// `Session::query` / `Querier` surface compiles unconditionally; the
/// wire-dispatch / wire-emit terminal steps inside reply.rs stay
/// cfg-gated on the corresponding codec features (codec-response /
/// codec-response-final) so feature-OFF builds elide them naturally.
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

/// R311y — per-runtime synchronization primitive aliases (`Mutex<T>`,
/// `RwLock<T>`) implementing the R311w option (a) decision lock on
/// §5.P Mutex/RwLock shape. The tokio profile binds the aliases to
/// `std::sync::*`; a future `wz-runtime-embassy::sync` module will
/// re-bind the same names to `embassy_sync::*` so cross-runtime call
/// sites can switch via cfg gate without renaming. See the module
/// doc-comment for the per-runtime alias rationale and the R311z+
/// migration roadmap.
pub mod sync;

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
// R311cb — transport-unicast gates the SCE-generated FSM module. The
// entire session_glue.rs depends on SessionFsmUnicast{Event,Policy},
// so cfg-off is intentionally not buildable until transport-multicast
// (currently reserved) introduces an alternate FSM. Default-on keeps
// the AP path compiling; the cfg site exists to wire the catalog
// promise to the source and to give the future multicast cascade a
// single edit point.
#[cfg(feature = "transport-unicast")]
#[allow(unused_assignments)]
#[allow(clippy::style)]
#[allow(clippy::complexity)]
pub mod session_fsm_unicast {
    include!(concat!(env!("OUT_DIR"), "/session_fsm_unicast_sm.rs"));
}

/// R311en — SCE-generated scouting FSM (active mode) per
/// docs/scouting-fsm.md §10. Same statechart pipeline as
/// `session_fsm_unicast`: build.rs shells out to `sce-codegen generate`
/// for `sources/session/scouting.scxml` and strips the inner-attribute
/// header; this wrapping module restores the lint allows as outer
/// attributes. The generated code is self-contained (state enum +
/// transition table + Lua-bound script dispatch). The host registration
/// of the scout_emit / record_hello_and_emit / emit_scout_timeout /
/// diag_scout_tx_failed actions + the UDP-multicast scouting link wiring
/// land in the R311en cascade body round; this milestone confirms the
/// SCXML -> sce-codegen statechart path.
// The allow set mirrors the inner-attribute suppression budget the SCE
// codegen self-declares at the head of scouting_sm.rs (the "audited
// 2026-04-15 against the W3C suite" block). build.rs strips those `#![..]`
// inner attrs so the file is include!()-able mid-module; this wrapper
// restores them as OUTER attrs, exactly as documented in build.rs
// emit_one. `unused_imports` covers the generated `use core::time::Duration`
// that the fully-qualified `core::time::Duration::from_millis` call site
// leaves unused; the rest cover the StatePolicy trait-shape fields the
// scouting fixture does not exercise.
#[cfg(feature = "scouting-active")]
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
pub mod scouting_fsm {
    include!(concat!(env!("OUT_DIR"), "/scouting_sm.rs"));
}

// R311ep — scouting FSM <-> multicast-link glue (active mode): the four
// scouting.scxml script actions + the async scout->hello drive loop.
#[cfg(feature = "scouting-active")]
pub mod scouting_glue;

// R311di-4 — Reliability moved to wz-session-core::reliability; the
// re-export keeps every `wz_runtime_tokio::Reliability` external
// callsite (9 caller files across tests / wz-integration-tests /
// wz-ap-demo) verbatim across the migration.
pub use wz_session_core::reliability::Reliability;

// R311di-5 — TxFrame / RxFrame / LinkEvent / LostCause moved to
// wz-session-core::link; tokio-specific LinkDriver trait + driver
// impls (TcpDriver / UdpDriver) stay in this crate. Re-exports keep
// every external callsite (`wz_runtime_tokio::{TxFrame, RxFrame,
// LinkEvent, LostCause}`) verbatim across the migration.
pub use wz_session_core::link::{LinkEvent, LostCause, RxFrame, TxFrame};

/// R311et — canonical split-link session-open transport pipeline. Lifts the
/// read/write-split + writer-task idiom (originally `wz-ap-demo`'s
/// `link_driver.rs`) into the library so the production session-open path
/// has a single home, parameterised by transport.
///
/// The session FSM needs the link in two shapes at once — an async
/// `&mut LinkDriver` for the inbound poll loop
/// ([`session_glue::drive_session_until_terminal`]) and a sync
/// `Arc<dyn BoxedLinkDriver>` for the outbound `send_blocking` fired from
/// Lua script-action handlers. A single `TcpStream` cannot satisfy both, so
/// this module splits it into an [`link_pipeline::TcpReadDriver`] (owns the
/// read half) plus an [`link_pipeline::TcpWriteDriver`] (a non-blocking
/// channel enqueue) drained by a dedicated [`link_pipeline::writer_task`].
/// The channel decouples the sync-action / async-runtime boundary WITHOUT
/// `Handle::block_on` (the [`session_glue::TokioLinkDriverAdapter`] path
/// carries a documented current-thread-runtime deadlock hazard and has
/// never driven a full bidirectional session); this split is the model the
/// production AP path actually uses.
#[cfg(feature = "transport-link-tcp")]
pub mod link_pipeline;

/// R311eu — mode-agnostic session-open orchestration over the R311et
/// [`link_pipeline`]. `dial_locator` dispatches a `ParsedLocator`'s protocol
/// to a raw transport; `connect_and_open_session` dials, splits into the
/// pipeline, wires the Initiator FSM, and drives the handshake to
/// Established. Gated on `transport-unicast` too because it drives the
/// `session_fsm_unicast` FSM.
#[cfg(all(feature = "transport-link-tcp", feature = "transport-unicast"))]
pub mod session_open;

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
#[cfg(feature = "transport-link-tcp")]
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
#[cfg(feature = "transport-link-tcp")]
#[derive(Default)]
pub(crate) enum ReadState {
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

/// R311et — shared cancel-safe framing read used by both [`TcpDriver`]
/// (the unified acceptor/adapter-path driver) and
/// [`link_pipeline::TcpReadDriver`] (the split read half on the production
/// session-open path). Reads one length-prefixed [`StreamEnvelope`] frame
/// from `src`, advancing `read_state` across `tokio::select!` cancellations
/// (each `.await` is a single cancel-safe `.read()` syscall), and returns
/// the codec-decoded payload as [`LinkEvent::Rx`] — or [`LinkEvent::Lost`]
/// on EOF / IO / codec error, resetting `read_state` to `Idle` so a retry
/// path does not inherit a partial buffer.
///
/// Extracted from the pre-R311et `TcpDriver::poll_event` body verbatim so
/// the framing state machine has a single home. `wz-ap-demo`'s duplicated
/// `InboundReadDriver` copy retires when the demo consumes `link_pipeline`
/// (R311ev); the wire shape stays codec-routed (the [`StreamEnvelope`]
/// decode is the single source of truth, not a hand-rolled prefix strip).
#[cfg(feature = "transport-link-tcp")]
pub(crate) async fn poll_framed<S>(read_state: &mut ReadState, src: &mut S) -> LinkEvent
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        match read_state {
            ReadState::Idle => {
                *read_state = ReadState::Length {
                    prefix: [0u8; 2],
                    offset: 0,
                };
            }
            ReadState::Length { prefix, offset } => match src.read(&mut prefix[*offset..]).await {
                Ok(0) => {
                    *read_state = ReadState::Idle;
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
                        *read_state = ReadState::Payload { frame, offset: 2 };
                    }
                }
                Err(_) => {
                    *read_state = ReadState::Idle;
                    return LinkEvent::Lost {
                        cause: LostCause::OsError,
                    };
                }
            },
            ReadState::Payload { frame, offset } => {
                if *offset == frame.len() {
                    // Frame complete. Take the buffer out before decoding
                    // so the state reset is visible if the codec rejects.
                    let bytes = std::mem::take(frame);
                    *read_state = ReadState::Idle;
                    let mut cursor = SceCursor::new(&bytes);
                    return match StreamEnvelope::decode(&mut cursor) {
                        Ok(env) => LinkEvent::Rx(RxFrame {
                            bytes: env.payload.to_vec(),
                        }),
                        Err(_) => LinkEvent::Lost {
                            cause: LostCause::PeerClosed,
                        },
                    };
                }
                match src.read(&mut frame[*offset..]).await {
                    Ok(0) => {
                        *read_state = ReadState::Idle;
                        return LinkEvent::Lost {
                            cause: LostCause::PeerClosed,
                        };
                    }
                    Ok(n) => {
                        *offset += n;
                    }
                    Err(_) => {
                        *read_state = ReadState::Idle;
                        return LinkEvent::Lost {
                            cause: LostCause::OsError,
                        };
                    }
                }
            }
        }
    }
}

#[cfg(feature = "transport-link-tcp")]
impl TcpDriver {
    /// Wrap an already-open TcpStream (acceptor side). The
    /// `open()` method is a no-op for this constructor.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
            read_state: ReadState::Idle,
        }
    }

    /// R311es — dial an outbound TCP connection to `addr` and wrap the
    /// resulting stream (Initiator side). This is the dial half of the
    /// scouting locator seam: a [`wz_session_core::locator::ParsedLocator`]
    /// with `proto = Tcp` carries the numeric `addr` this constructor
    /// connects to, mirroring [`from_stream`] for the acceptor side.
    ///
    /// `open()` is a no-op afterwards because the stream is already
    /// connected — same post-condition as `from_stream`. Connect-timeout
    /// / retry tuning is the caller's concern (compose a
    /// `tokio::time::timeout` around this); the kernel default applies
    /// otherwise, matching `wz-ap-demo`'s `establish_link` (runner.rs).
    ///
    /// R311et — the actual socket dial routes through the single raw-dial
    /// primitive [`link_pipeline::dial_tcp`], so this unified-driver
    /// constructor and the split session-open pipeline
    /// ([`link_pipeline::wire_tcp_stream`]) share one connect path. The
    /// mode-agnostic `dial_locator(ParsedLocator)` dispatcher (R311eu)
    /// dispatches a `Proto::Tcp` endpoint to `dial_tcp` and then splits the
    /// stream for the FSM, rather than burying the stream inside this
    /// driver — hence the raw-dial seam lives in `link_pipeline`.
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self::from_stream(link_pipeline::dial_tcp(addr).await?))
    }
}

#[cfg(feature = "transport-link-tcp")]
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
        // Borrowed zero-copy view over the in-scope frame buffer — the
        // SCE borrowed codec encodes directly from `frame.bytes` with
        // no owned copy (the envelope lives only until `encode_to_vec`).
        let envelope = StreamEnvelope {
            payload_len,
            payload: frame.bytes,
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
        // R311et — the cancel-safe framing state machine lives in the
        // shared [`poll_framed`] free fn so the split read half
        // ([`link_pipeline::TcpReadDriver`]) decodes identical wire
        // bytes. The `stream.is_none()` (closed) guard stays here because
        // it is `TcpDriver`-specific (the split read half always owns its
        // `OwnedReadHalf`).
        match self.stream.as_mut() {
            Some(stream) => poll_framed(&mut self.read_state, stream).await,
            None => LinkEvent::Lost {
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
#[cfg(feature = "transport-link-udp")]
pub struct UdpDriver {
    socket: Option<UdpSocket>,
    peer: Option<SocketAddr>,
}

#[cfg(feature = "transport-link-udp")]
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

    /// R311es — bind an ephemeral local UDP socket and target `peer`
    /// for unicast `send()` (Initiator side). This is the UDP dial half
    /// of the scouting locator seam: a
    /// [`wz_session_core::locator::ParsedLocator`] with `proto = Udp`
    /// carries the numeric `peer` this constructor targets, mirroring
    /// [`TcpDriver::connect`] for the datagram transport.
    ///
    /// Distinct from [`bind_multicast_v4`], which joins a scouting group;
    /// this dials a single already-discovered unicast peer. The local
    /// bind address family mirrors `peer` so an IPv6 locator binds an
    /// IPv6 socket (a v4-bound socket cannot reach a v6 peer).
    pub async fn connect(peer: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = match peer {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self::from_socket(socket, peer))
    }

    /// R311en — bind a UDP socket on a multicast group and join it,
    /// returning a driver whose `send()` multicasts to the group. This
    /// is the scouting link transport (docs/scouting-fsm.md §1.2): the
    /// default zenoh scout group is `224.0.0.224:7446`
    /// (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT`).
    ///
    /// The three setup steps must stay consistent, which is why they are
    /// folded into one constructor rather than left to the caller as
    /// `from_socket` does:
    ///   1. bind `0.0.0.0:port` (INADDR_ANY) — a socket bound to a
    ///      unicast address cannot receive datagrams addressed to the
    ///      group.
    ///   2. `join_multicast_v4(group, INADDR_ANY)` — subscribe on the
    ///      default interface; without the join the kernel drops group
    ///      datagrams even with the matching bind port.
    ///   3. `set_multicast_loop_v4(true)` — let a same-host peer (and
    ///      the loopback smoke test) observe the traffic; off by default
    ///      on some platforms.
    /// `peer` is set to `group:port` so `LinkDriver::send` writes the
    /// Scout datagram to the group.
    ///
    /// `tokio::net::UdpSocket` exposes the multicast setsockopt wrappers
    /// directly (it wraps `std::net::UdpSocket`), so no `socket2`
    /// dependency is pulled. SO_REUSEADDR is intentionally NOT set here:
    /// the single-receiver scouting deploy does not need multiple
    /// binders on the group port, and adding it would require dropping
    /// to `socket2`. Multi-listener support (if a future deploy needs
    /// two scouting consumers on one host) is the point where socket2
    /// would enter — flagged here so that decision is explicit, not
    /// silent.
    #[cfg(feature = "scouting-active")]
    pub async fn bind_multicast_v4(group: std::net::Ipv4Addr, port: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await?;
        socket.join_multicast_v4(group, std::net::Ipv4Addr::UNSPECIFIED)?;
        socket.set_multicast_loop_v4(true)?;
        let peer = SocketAddr::from((group, port));
        Ok(Self {
            socket: Some(socket),
            peer: Some(peer),
        })
    }
}

#[cfg(feature = "transport-link-udp")]
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
