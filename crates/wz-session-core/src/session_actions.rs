// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! chunk-5 — runtime-agnostic `SessionLinkActions` bundle + the
//! `SessionActionsBinding` newtype that carries the engine-free
//! `SessionFsmUnicastActions` trait impl.
//!
//! Hoisted verbatim from `wz-runtime-tokio::session_glue` (the AP shell)
//! so the lwIP MCU profile composes the same session machinery without
//! std / tokio. The struct + every inherent impl (the `new_generic`
//! constructor body, the action / accessor methods, the accept-side
//! admission guards) live here because an inherent impl must sit in the
//! type's defining crate; only the concrete `R = TokioRuntime` `new`
//! wrapper (`new_session_actions`) and the `Engine`-bound
//! `new_session_engine` factory stay AP-side (they name tokio /
//! sce-rust-runtime types).
//!
//! `R: SessionRuntime` threads the per-profile mutex + link-sink storage
//! (Stage 2b/2c); `T: TimeSource` the monotonic clock. The wire-emit
//! action bodies stay gated on their codec / handshake-role feature —
//! cfg-off is a documented no-emit no-op, not a build error.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
// AtomicU64 portability: the `no_std` (MCU) profile pulls `portable-atomic`
// (critical-section emulated AtomicU64 for thumbv6m et al.); the host / alloc
// profile uses the native `core::sync::atomic::AtomicU64`. The session_glue
// origin used portable-atomic unconditionally because the tokio crate always
// carries it; here it splits across the two session-core profiles.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "no_std")]
use portable_atomic::{AtomicU64, Ordering};

// CodecError is the return type of `encode_init_with_role` /
// `encode_open_with_role` only; gate it on those encoders' codecs so a
// consumer-plane-only subset (no handshake-body codec) does not see it unused.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use sce_forge_runtime::codec::CodecError;
use wz_runtime_core::TimeSource;

#[cfg(feature = "liveliness-token")]
use wz_codecs::declare::DeclareOwned;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zint::ExtZint;
#[cfg(feature = "codec-response")]
use wz_codecs::response::ResponseOwned;

use crate::action_trace::ActionTrace;
use crate::close_reason::CloseReason;
use crate::ext_chain_role::ExtChainRole;
use crate::link::{BoxedLinkDriver, SessionRuntime};
use crate::peer_init_caps::PeerInitCaps;
// A4 — the CachedDeclaration / ReplayDeclarationsError types stay ungated
// (the reconnect module rides this module's own alloc+session-unicast gate)
// so the signature-stable `replay_declarations` / `declaration_cache_snapshot`
// surface keeps its types when `session-reconnect` is off (R311g1).
use crate::reconnect::{CachedDeclaration, ReplayDeclarationsError};
// Reliability is the second arg of every `link_driver().send_blocking(..)`,
// so it is used iff at least one wire-emit body is active: the handshake /
// close encoders OR any consumer-plane frame emit (the frame_encode union).
// The R311jq batch-flush emits derive their channel via
// `frame_encode::frame_wire_reliability` (full-path return type), so
// `transport-batching` alone does not need this import.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-interest",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-final",
    feature = "liveliness-token",
))]
use crate::reliability::Reliability;
use crate::response_sink::ResponseSink;
use crate::send_declare_error::SendDeclareError;
use crate::send_wire_error::SendWireError;
use crate::session_fsm_unicast::SessionFsmUnicastActions as SessionFsmUnicastActionsTrait;
use crate::session_init_params::SessionInitParams;
use crate::signing_key::generate_cookie_hmac_sha256;

// inbound parse (handle_inbound)
use crate::inbound::{parse_inbound, InboundFrame};
use crate::parse_error::InboundParseError;

// metadata carriers for the *_with_meta action methods. UNGATED on purpose:
// `send_push_with_meta_*` / `send_request_query_with_meta` are
// signature-stable (R311j) — only their bodies are codec-gated, the
// signatures reference these types in every subset — so the import must be
// codec-agnostic (mirrors the ungated session_glue re-export it came from).
use crate::metadata::{PushMetadata, QueryMetadata};

// outbound zenoh-pico-safety gate for the declare-* action methods
#[cfg(any(
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
))]
use crate::keyexpr_canon::check_outbound_keyexpr_pico_safe;

// handshake encoders consumed by the wire-emit action bodies
#[cfg(feature = "codec-close")]
use crate::handshake_encode::encode_close;
#[cfg(feature = "codec-init-body")]
use crate::handshake_encode::encode_init;
#[cfg(feature = "codec-open-body")]
use crate::handshake_encode::encode_open;

// single-source borrowed reply builders (liveliness-token ResponseSink leg)
#[cfg(feature = "liveliness-token")]
use crate::declare::local_token::{build_final_reply, build_token_reply};

// Builder + frame-encode modules are imported by glob. The wire-emit action
// methods are signature-stable (R311j): their signatures are codec-agnostic
// and only the bodies are gated, so which builders a given subset actually
// calls varies by the fine declare-* / pubsub-* / query-* feature, not just
// the module-level codec. A glob import (exempt from the unused-import lint)
// absorbs that variation; a per-symbol cfg block would have to mirror every
// body gate and would silently break under the run-ci subset matrix (the
// documented hazard the move plan warns about). Each glob is gated only on its
// module's presence feature; the alloc-only `interest_build` / `frame_encode`
// modules are always present when this (alloc + session-unicast) module is.
// Each glob is gated on the union of features under which AT LEAST ONE of its
// symbols is used (a glob that brings in zero used names is itself flagged
// unused — the individual-name exemption does not cover an empty glob). The
// unions mirror the consuming method bodies' gates, NOT the module-presence
// codec, since a codec can be on while every method that calls the module is
// gated off (e.g. `liveliness-token` pulls `codec-declare` but uses none of
// the `declare_build` action builders).
#[cfg(any(
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-final",
))]
use crate::declare_build::*;
#[cfg(feature = "declare-interest")]
use crate::interest_build::*;
#[cfg(feature = "codec-push")]
use crate::push_build::*;
#[cfg(feature = "codec-request")]
use crate::request_build::*;
#[cfg(feature = "codec-response-final")]
use crate::response_final_build::*;

/// R311jp — TX batching accumulator state (zenoh-pico
/// `_z_transport_common_t::{_batch_state,_batch_count}` plus the shared TX
/// `_wbuf`, `Z_FEATURE_BATCHING` parity). `active == false` (the default)
/// preserves the pre-A3 per-message flush behavior. While active, `buf`
/// holds the OPEN outbound `T_MID_FRAME` — transport header byte +
/// `VLE(sn)` + N appended network-message bodies; an empty `buf` means no
/// frame is open yet. `count` mirrors pico's batch counter for
/// observability and tests; the flush trigger is the byte budget
/// (`params.batch_size`), never the count.
///
/// R311kf — the struct (and the `batch_tx` mutex around it) is UNGATED:
/// the mutex doubles as the session's TX-ORDER serialization lock (pico
/// holds its TX mutex across SN mint + wire write for every sender,
/// common/tx.c:273-305), which every build needs — with
/// `transport-batching` off, `active` stays `false` forever and only the
/// lock role remains (the empty `buf` costs three words).
#[derive(Debug, Default)]
pub struct BatchTx {
    /// `zp_batch_start` .. `zp_batch_stop` window flag
    /// (`_Z_BATCHING_ACTIVE` / `_Z_BATCHING_IDLE`).
    pub active: bool,
    /// The open outbound frame bytes (empty = none open).
    pub buf: Vec<u8>,
    /// Network messages absorbed into the open frame.
    pub count: usize,
}

pub struct SessionLinkActions<R: SessionRuntime, T: TimeSource> {
    /// R::LinkSink — the per-profile owning handle to the link write
    /// seam (tokio `Arc<dyn BoxedLinkDriver + Send + Sync>`, lwIP MCU
    /// `Rc<dyn BoxedLinkDriver>`). The generic action methods reach the
    /// pure `&dyn BoxedLinkDriver` through [`Self::link_driver`].
    pub driver: R::LinkSink,
    pub params: SessionInitParams,
    pub trace: R::Mutex<ActionTrace>,
    /// Cookie material captured from a peer's InitAck via
    /// `handle_inbound`. When populated this overrides
    /// `params.cookie` on the OpenSyn outbound, implementing the
    /// RFC §5.M echo contract on the Initiator side.
    pub inbound_cookie: R::Mutex<Option<Vec<u8>>>,
    /// R72b — monotonic timestamp in milliseconds of the most
    /// recently observed inbound KeepAlive frame. Populated by
    /// `handle_inbound` for `InboundFrame::KeepAlive`. Consumers
    /// compare this against `params.lease` to compute the lease
    /// deadline; an absent timestamp falls back to session-start
    /// time (lease counts from Established entry per session-fsm
    /// §2.5 keepalive semantics).
    ///
    /// Storage is `u64` milliseconds since the
    /// [`SessionLinkActions::clock`] epoch (R294: migrated from
    /// `std::time::Instant`). The lease comparator becomes a pure
    /// `u64` subtract `now_ms.saturating_sub(stamp_ms) >= lease_ms`;
    /// no `Duration` arithmetic, MCU-friendly (16-byte Duration
    /// halved to 8-byte u64), and the storage form matches the
    /// [`TimeSource::now_monotonic_ms`] contract that wz callers
    /// will use across AP + Phase W targets.
    pub last_inbound_keepalive_at: R::Mutex<Option<u64>>,
    /// R84 — monotonic timestamp in milliseconds captured when the
    /// session FSM enters the `Established` state. Populated by the
    /// `record_established_at()` Lua action wired to the
    /// `Established.onentry` block in `session_fsm_unicast.scxml`.
    /// Consumers (specifically `check_lease_deadline`) fall back to
    /// this stamp when `last_inbound_keepalive_at` is `None` so a
    /// peer that never sends a KeepAlive after handshake still
    /// reaches `lease.expired -> Closing` per session-fsm §2.5
    /// ("lease counts from Established entry"); the prior R77
    /// behaviour was `NoBaseline` indefinitely in that case.
    ///
    /// Storage form and clock semantics match
    /// `last_inbound_keepalive_at` — both are `u64` ms since the
    /// shared [`SessionLinkActions::clock`] epoch (R294 migration
    /// from `std::time::Instant`); the lease comparator subtracts
    /// them as pure `u64` arithmetic.
    pub established_at: R::Mutex<Option<u64>>,
    /// R294 — monotonic clock shared with the surrounding
    /// drive_session loop. `TokioTime` is `Copy + Clone` (R263), so
    /// every field that needs a `now_monotonic_ms()` read holds a
    /// value-copy; the epoch is shared because the runner.rs
    /// constructs one `TokioTime` and passes it to both
    /// `new_session_actions` and
    /// `drive_session_until_terminal`'s `clock` parameter (R263
    /// shared-epoch invariant). Tests that do not exercise the
    /// keepalive-or-lease comparator path may pass any fresh
    /// `TokioTime::new()`; the per-test isolated epoch is fine
    /// because there is no cross-test stamp comparison.
    pub clock: T,
    /// R86 — `zid` field captured from the most recent inbound
    /// `InitSyn` frame (`InboundFrame::Init { is_ack: false, .. }`).
    /// The Accepting side reads this slot inside
    /// `send_init_ack_with_cookie` to bind the outbound cookie's
    /// HMAC input to the peer's claimed identity per RFC §5.M
    /// anti-amplification: `cookie = HMAC-SHA256(cookie_signing_key,
    /// peer_zid)[..16]`. An absent slot means no InitSyn has
    /// arrived yet (handshake hasn't started) and the action falls
    /// back to `params.cookie` verbatim — callers that need strict
    /// HMAC-only behavior must validate the slot before signalling
    /// `inbound.start`.
    pub inbound_peer_zid: R::Mutex<Option<Vec<u8>>>,
    /// R89 — `cookie` field captured from the most recent inbound
    /// `OpenSyn` frame (`InboundFrame::Open { is_ack: false, .. }`).
    /// Set by `handle_inbound` for the Accepting side; consumed by
    /// the `cookie_valid()` guard which re-computes the expected
    /// HMAC-SHA256(cookie_signing_key, inbound_peer_zid)[..16] and
    /// compares it against this slot. RFC §5.M anti-amplification
    /// closes the loop opened by R86: R86 mints the cookie on the
    /// outbound InitAck; R89 verifies the same cookie on the
    /// inbound OpenSyn echo.
    ///
    /// Distinct from `inbound_cookie` (R62) which captures the
    /// Initiator-side InitAck.body.cookie for OpenSyn echo. Those
    /// two slots model the same wire field on opposite sides of
    /// the handshake — one slot per role keeps the dispatch
    /// unambiguous.
    pub inbound_opensyn_cookie: R::Mutex<Option<Vec<u8>>>,
    /// R68b — per-role ext chain slots. Indexed by `ExtChainRole`
    /// via `ext_chain_for`. Each slot lives behind its own `Mutex`
    /// so a setter can swap one chain without blocking the others
    /// (e.g. mid-handshake auth-step rotation can rewrite the
    /// OpenSyn chain without touching the InitSyn record).
    init_syn_ext: R::Mutex<Vec<ExtEntryOwned>>,
    init_ack_ext: R::Mutex<Vec<ExtEntryOwned>>,
    open_syn_ext: R::Mutex<Vec<ExtEntryOwned>>,
    open_ack_ext: R::Mutex<Vec<ExtEntryOwned>>,
    /// R121d — sizing parameters parsed from the peer's inbound
    /// `InitSyn`. The Accepting side caps its outbound InitAck
    /// `seq_num_res / req_id_res / batch_size` to `min(own,
    /// peer)` per the wire-spec invariant
    /// `InitAck.size <= InitSyn.size`. The reference enforcement
    /// is in zenoh-pico/src/transport/unicast/transport.c:123-140
    /// (`_z_unicast_handshake_open`) where the initiator rejects
    /// an InitAck that announces values larger than its own
    /// InitSyn with `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION`. Empty
    /// slot means no InitSyn has been parsed yet (handshake
    /// hasn't started) and `encode_init_with_role(is_ack=true)`
    /// falls back to `self.params` verbatim — test paths that
    /// emit InitAck directly without an inbound parse cycle
    /// (R60, layer3_init_body) continue to work.
    pub inbound_peer_init_caps: R::Mutex<Option<PeerInitCaps>>,
    /// R121e — outbound Frame sequence-number generator. The
    /// session-FSM Established-side path emits one `Frame`
    /// transport-message per outbound application-layer batch
    /// (PUSH, DECLARE, INTEREST, …); each Frame carries a
    /// VLE-encoded `sn` per zenoh-pico
    /// `_z_frame_encode`(transport.c:386-395). The first Frame
    /// uses `params.initial_sn` (matching the value announced in
    /// the OpenSyn/OpenAck body so the peer's reliable-channel
    /// SN-window tracking starts from the agreed origin) and
    /// each subsequent Frame uses the next position on the
    /// negotiated SN ring (`seq_num_res` → 7/14/28/63-bit per
    /// Zenoh RFC §5.O). The counter itself stays raw monotonic —
    /// the `u64` wrap is ring-transparent, `(n + 1) & mask` is
    /// the ring successor of `n & mask` across the `u64`
    /// boundary too — and the wire-visible value is masked at
    /// the mint ([`Self::next_outbound_frame_sn`]) and at the
    /// fragment walk (`frame_encode::fragment_body`). R311kb
    /// realized the R121e explicit-modulo carry via zenoh-pico
    /// `_z_sn_increment` parity (the F-5 consolidation).
    pub outbound_frame_sn: AtomicU64,
    /// R311ke — per-channel inbound Frame/Fragment SN gate state
    /// ([`crate::sn::RxSn`]), the zenoh-pico
    /// `_z_transport_peer_unicast_t._sn_rx_reliable` /
    /// `_sn_rx_best_effort` pair. Seeded by [`Self::handle_inbound`]
    /// from the peer's OpenSyn/OpenAck `initial_sn` (one before, so the
    /// first frame at exactly `initial_sn` passes — peer.c:212-214);
    /// consulted by the drive dispatcher's
    /// [`Self::admit_rx_frame_sn`] before a Frame payload or Fragment
    /// reaches the application layer. Handshake-scoped: reset by
    /// `reset_for_reopen` and re-seeded by the reopen handshake.
    pub rx_sn: R::Mutex<crate::sn::RxSn>,
    /// R311jp — TX batching accumulator (zenoh-pico
    /// `_z_transport_common_t::{_batch_state,_batch_count}` + the shared
    /// TX `_wbuf` parity, `Z_FEATURE_BATCHING`). Inactive by default —
    /// every [`Self::dispatch_network_message`] call flushes
    /// immediately, the pre-A3 behavior. [`Self::batch_start`] activates
    /// accumulation; see [`BatchTx`] for the buffer shape — the
    /// absorb/overflow state machine lives in the chokepoint itself
    /// (R311jq, all emits under the lock).
    /// R311kf — ungated: this mutex is ALSO the TX-order serialization
    /// lock (mint + emit under one hold, pico TX-mutex parity); see the
    /// [`BatchTx`] doc.
    pub batch_tx: R::Mutex<BatchTx>,
    /// R234 — outbound keyexpr mapping table. Mirrors zenoh-pico's
    /// `_z_session_t._local_resources` slot: every time
    /// [`Self::send_declare_keyexpr`] emits a `Declare(DeclKexpr)`
    /// the (mapping_id, suffix) pair is recorded here so a later
    /// `crate::session::Session::publish_aliased_auto` (or the
    /// loopback branch of a metadata-rich aliased publish) can
    /// resolve the literal form without the caller asserting it
    /// out-of-band. [`Self::send_undeclare_kexpr`] removes the
    /// entry so the resolver returns `None` for retracted ids.
    ///
    /// Mutex<HashMap> chosen over RwLock because table writes
    /// happen on the session-setup path (rare) and reads happen on
    /// the publish hot path (frequent but short-lived under a
    /// single-key lookup); the contended-write penalty of RwLock
    /// would dwarf the read parallelism gain at the expected
    /// access pattern.
    pub outbound_mappings: R::Mutex<HashMap<u64, String>>,
    /// A4 (session-reconnect) — declaration cache. Mirrors zenoh-pico's
    /// `_z_session_t._declaration_cache` slot
    /// (`include/zenoh-pico/net/session.h` under
    /// `Z_FEATURE_AUTO_RECONNECT`): every successful
    /// `send_declare_{keyexpr,subscriber,queryable,token}` /
    /// `send_interest_liveliness_{subscriber,get}` emit appends its
    /// argument tuple here (pico `_z_cache_declaration` at
    /// `_z_send_declare`, `src/net/primitives.c:52-63`); every successful
    /// `send_undeclare_*` / `send_interest_final` removes the first
    /// matching entry (pico `_z_prune_declaration` at
    /// `_z_send_undeclare`). After a transport re-open,
    /// [`Self::replay_declarations`] re-emits the entries in recorded
    /// order so the peer's declaration tables are rebuilt — entry order
    /// matters because an aliased declare must replay after the
    /// `DeclKexpr` that registered its `mapping_id`.
    ///
    /// Append/prune mirror pico's success-only discipline: a rejected
    /// emit caches nothing, and an undeclare whose emit path is
    /// feature-elided prunes nothing.
    #[cfg(feature = "session-reconnect")]
    pub declaration_cache: R::Mutex<Vec<CachedDeclaration>>,
    /// F2 — is the transport currently accepting data sends? `true` at
    /// construction (the bundle is built over a live link sink; the
    /// pre-handshake window keeps today's emit semantics), `false` when
    /// the FSM releases the link (`release_link`, Closing/Closed entry)
    /// or the reconnect supervisor tears the transport down for re-dial
    /// ([`Self::reset_for_reopen`]), `true` again when Established
    /// (re-)enters (`record_established_at`). The
    /// [`Self::dispatch_network_message`] chokepoint gates on it so a
    /// data send inside the RECONNECTING window rejects typed
    /// ([`SendWireError::TransportUnavailable`]) instead of silently
    /// vanishing into a dead writer channel — zenoh-pico's tx path fails
    /// on the dead transport's mutex/NULL
    /// (`_Z_ERR_TRANSPORT_NOT_AVAILABLE`); the handshake / CLOSE
    /// transport messages bypass the chokepoint and stay ungated.
    pub transport_available: R::Mutex<bool>,
    /// R239 — monotonic outbound `Request.request_id` allocator.
    /// Mirrors zenoh-pico's `_z_session_t._query_id` slot
    /// (`vendor/zenoh-pico/src/session/query.c:99` —
    /// `_z_zint_t qid = zn->_query_id++` post-increment from 0).
    /// Each `crate::session::Session::query` call (and any future
    /// caller emitting an outbound `Request(Query)` that registers
    /// a pending entry with [`crate::reply::ReplyRegistry`])
    /// reserves the next id through [`Self::alloc_next_request_id`]
    /// so wire and loopback branches see the same id without the
    /// caller threading an explicit counter.
    ///
    /// Starts at `0` matching the zenoh-pico convention so the first
    /// query emitted from this session uses `request_id = 0`; the
    /// peer's pending-table lookup is rid-keyed regardless of the
    /// starting value, so the choice is cosmetic. `Relaxed` ordering
    /// is sufficient — id uniqueness is the only invariant and
    /// `fetch_add` is atomic under every ordering.
    pub next_outbound_request_id: AtomicU64,
    /// R248 — monotonic outbound liveliness `token_id` allocator.
    /// Mirrors zenoh-pico's `_z_get_entity_id`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:58` — the entity-id
    /// counter consumed by `_z_declare_liveliness_token`). Each
    /// `crate::session::Session::declare_token` /
    /// `crate::session::Session::declare_token_aliased` call reserves
    /// the next id through [`Self::alloc_next_token_id`] so the
    /// `crate::session::LivelinessToken` RAII handle holds the same
    /// id used in the outbound `Declare(DeclToken)` wire frame and
    /// later matches it on the `Declare(UndeclToken)` retraction emit
    /// triggered by `Drop` / `undeclare`.
    ///
    /// Starts at `0` matching the queryside convention. The wire
    /// carries token ids as the `id` field of the inner
    /// `decl_token` / `undecl_token` codec, keyed independently from
    /// `subscriber_id`, `queryable_id`, and `request_id` on the peer
    /// (each entity type owns its own intmap on the receiver side per
    /// `zenoh-pico/src/net/liveliness.c:69` —
    /// `_local_tokens` vs `_remote_tokens` are distinct from
    /// `_remote_subscriptions` etc.), so a wz session that allocates
    /// `token_id = 0` while also having previously allocated
    /// `subscriber_id = 0` does not collide on the wire. `Relaxed`
    /// ordering matches the request-id rationale.
    pub next_outbound_token_id: AtomicU64,

    /// R279 — outbound liveliness-subscriber `interest_id` generator.
    /// Returns the next interest id and advances the internal counter
    /// by one. Consumed by
    /// [`Self::send_interest_liveliness_subscriber`] /
    /// [`Self::send_interest_final`] as the inner `Interest::interest_id`
    /// field, and kept on the
    /// `crate::session::LivelinessSubscriber` RAII handle so the
    /// `Drop` impl can emit the matching `InterestFinal` without the
    /// caller threading the id manually.
    ///
    /// Independent counter from the four sibling outbound id spaces
    /// (request / token / subscriber / queryable) so a wz session that
    /// allocates `interest_id = 0` while also having previously
    /// allocated `request_id = 0` does not collide on the wire — the
    /// peer indexes Interest acks via `_z_interest_t._id` which is a
    /// distinct table from the request / subscriber / queryable /
    /// token id spaces (`vendor/zenoh-pico/src/session/interest.c`:
    /// `_z_interests_local` list keyed by `_id`). Mirrors zenoh-pico's
    /// `_z_get_entity_id` consumed by
    /// `_z_register_liveliness_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:169-198`); first call
    /// returns `0` matching the post-increment-from-zero convention.
    /// `Relaxed` ordering — uniqueness is the only invariant.
    pub next_outbound_interest_id: AtomicU64,
}

/// R121f1 — wire-spec-mandatory Patch extension entry for the Init
/// transport-message ext chain. Zenoh's Init handshake includes a
/// `_Z_MSG_EXT_ID_INIT_PATCH` extension (header byte `0x07 |
/// _Z_MSG_EXT_ENC_ZINT = 0x27`, body = `zint64(_Z_CURRENT_PATCH = 1)`)
/// that announces the protocol patch level. Without it, zenoh-pico's
/// accepting side caps `iam._body._init._patch` to the peer's
/// announced value via the size-negotiation rule at
/// `vendor/zenoh-pico/src/transport/unicast/transport.c:237-241`:
///
/// ```c
/// #if Z_FEATURE_FRAGMENTATION == 1
///     if (iam._body._init._patch > tmsg._body._init._patch) {
///         iam._body._init._patch = tmsg._body._init._patch;
///     }
/// #endif
/// ```
///
/// But `_z_t_msg_make_init_ack`
/// (`vendor/zenoh-pico/src/protocol/definitions/transport.c:187-191`)
/// has already set `_Z_FLAG_T_Z` on the InitAck header before the cap
/// runs. The cap reduces `iam._patch` to `_Z_NO_PATCH = 0`, which
/// makes `_z_init_encode`
/// (`vendor/zenoh-pico/src/protocol/codec/transport.c:206-216`) skip
/// the patch-ext emit — but the header `Z=1` is now frozen onto the
/// wire. The peer (i.e. wz) reads `Z=1` and expects ext bytes, but
/// the payload terminates at the body — `NeedMoreBytes`, the wz
/// session FSM closes, and zenoh-pico logs `Connection accept
/// handshake failed with error -117`.
///
/// Mirroring zenoh-pico's `_z_t_msg_make_init_syn` / `make_init_ack`
/// invariant (`_patch = _Z_CURRENT_PATCH`) on the wz outbound side
/// keeps the negotiation symmetric — peer's `tmsg._patch = 1`,
/// `iam._patch` stays `1`, and the patch-ext bytes accompany the
/// `Z=1` header on the wire. This is the foreign-interop fix for the
/// R121f1 carry surfaced when wz initiator dialed zenoh-pico
/// peer-listen; the wz↔wz path (R121f) was symptom-free because
/// both ends previously emitted Init bodies with `Z=0`.
pub fn default_init_patch_ext_entry() -> ExtEntryOwned {
    // header byte layout per `vendor/zenoh-pico/include/zenoh-pico/
    // protocol/ext.h:47-65`:
    //   bits 0..3 = ext_id 0x07 (INIT_PATCH)
    //   bit 4     = M (mandatory) = 0
    //   bits 5..6 = enc = 0x01 (ZINT)
    //   bit 7     = Z (chain continuation) — encoder owns this bit
    //               via `encode_ext_chain`, so leave it cleared here.
    ExtEntryOwned {
        header: 0x07 | 0x20, // _Z_MSG_EXT_ID_INIT_PATCH literal
        body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 1 }),
    }
}

// R311dz-pre — bridge the observer's generic reply drain to the action
// bundle. The inherent `send_response` / `send_response_final`
// methods (below, in the `impl<R: SessionRuntime, T: TimeSource>` block) carry
// the real encode + enqueue; these trait methods delegate to them so
// `ApplicationLayerObserver::flush_pending<S: ResponseSink>` can drive any
// runtime's actions handle. The delegating `self.send_response(..)` calls
// resolve to the inherent methods (inherent shadows trait in method-call
// resolution), so there is no recursion. The method set is empty in a
// build with neither response codec, matching the trait's gated surface.
impl<R: SessionRuntime, T: TimeSource> ResponseSink for SessionLinkActions<R, T> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned) {
        self.send_response(response);
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        self.send_response_final(request_id);
    }
    // R283 / R311hn (Track 2) — drain targets for the declarer-side
    // interest-response borrowed emit seam. The registry/observer pass
    // borrowed args (no owned `DeclareOwned` crosses the seam); this AP
    // sink owns the encode by building a `DeclareOwned` and routing it
    // through the inherent `Self::send_declare` (encode via `VecSink` +
    // enqueue). An MCU sink would instead encode through `SliceSink` over
    // a stack buffer. Inherent-method resolution shadows nothing here
    // (these are distinct names from the inherent `send_declare`).
    // R311ho — the reply wire shape has a single source in
    // `wz-session-core::declare::local_token` (`build_token_reply` /
    // `build_final_reply`, borrowed). The AP sink derives the owned form
    // via `Declare::into_owned` and routes it through the inherent
    // `Self::send_declare` (encode via `VecSink` + enqueue); an MCU sink
    // encodes the same borrowed value through `SliceSink`. No reply-shape
    // duplication across profiles.
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        self.send_declare(
            build_token_reply(token_id, keyexpr, interest_id)
                .try_into_owned()
                .expect("local-token reply keyexpr is within MAX_KEYEXPR_BYTES"),
        );
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare_final_reply(&self, interest_id: u64) {
        self.send_declare(
            build_final_reply(interest_id)
                .try_into_owned()
                .expect("DeclFinal reply carries no bounded fields"),
        );
    }
    // F3/R311ka — drain target for the registry's staged get
    // terminations; delegates to the inherent twin (the same shape as
    // `send_response` / `send_response_final` above), so sweep callers
    // that hold the actions handle directly (the wz-ap-demo ticker)
    // need no trait import.
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, interest_id: u64) {
        SessionLinkActions::prune_liveliness_get_interest(self, interest_id);
    }
}

/// Generic-`R` constructor (Stage 2c) — the runtime-agnostic body behind the
/// concrete `new_session_actions` AP wrapper (in `wz-runtime-tokio`). Every
/// mutex slot is staged via `R::new_mutex` so the lwIP MCU profile composes
/// the same bundle against `critical_section::Mutex`; the tokio wrapper is a
/// thin `R = TokioRuntime` shim. The `None::<…>` / `Vec::<…>::new()` /
/// `HashMap::<…>::new()` arg annotations are mandatory: `R::Mutex<T>` is a
/// GAT projection (non-injective), so the element type cannot be inferred
/// back from the struct field type — it must be spelled at the `new_mutex`
/// argument.
impl<R: SessionRuntime, T: TimeSource> SessionLinkActions<R, T> {
    /// Construct a session action bundle for one logical FSM instance over
    /// any `R: SessionRuntime`. `driver` is the per-profile `R::LinkSink`
    /// (tokio `Arc<dyn BoxedLinkDriver + Send + Sync>`, lwIP `Rc<dyn _>`);
    /// `params` are captured by value; `clock` is the shared monotonic
    /// clock (R263 + R294) consumed by [`Self::handle_inbound`] and the
    /// `record_established_at` action.
    pub fn new_generic(
        driver: R::LinkSink,
        params: SessionInitParams,
        clock: T,
    ) -> R::ActionsHandle<T> {
        // R121e — seed the outbound Frame SN with `params.initial_sn`
        // so the first emitted Frame matches the value announced in
        // the OpenSyn/OpenAck body. The peer enforces this start
        // value via its reliable-channel window tracking
        // (zenoh-pico unicast/transport.c:182-194).
        let initial_frame_sn = params.initial_sn;
        // R311ja — wrap through the per-profile `wrap_actions` seam (tokio
        // `Arc`, lwIP `Rc`) so this one constructor serves both the
        // multi-thread AP handle and the single-task MCU handle without
        // naming a concrete pointer. `alloc::sync::Arc` here would wall the
        // bundle off ARMv6-M (no `target_has_atomic = "ptr"`).
        R::wrap_actions(Self {
            driver,
            params,
            trace: R::new_mutex(ActionTrace::default()),
            inbound_cookie: R::new_mutex(None::<Vec<u8>>),
            last_inbound_keepalive_at: R::new_mutex(None::<u64>),
            established_at: R::new_mutex(None::<u64>),
            transport_available: R::new_mutex(true),
            clock,
            inbound_peer_zid: R::new_mutex(None::<Vec<u8>>),
            inbound_opensyn_cookie: R::new_mutex(None::<Vec<u8>>),
            // R121f1 — default ext chains seed both Init roles with the
            // patch-extension entry that zenoh-pico's accept-side
            // size-negotiation requires. See
            // [`default_init_patch_ext_entry`] for the wire-spec
            // citation and the foreign-interop failure mode this
            // closes.
            init_syn_ext: R::new_mutex(vec![default_init_patch_ext_entry()]),
            init_ack_ext: R::new_mutex(vec![default_init_patch_ext_entry()]),
            open_syn_ext: R::new_mutex(Vec::<ExtEntryOwned>::new()),
            open_ack_ext: R::new_mutex(Vec::<ExtEntryOwned>::new()),
            inbound_peer_init_caps: R::new_mutex(None::<PeerInitCaps>),
            outbound_frame_sn: AtomicU64::new(initial_frame_sn),
            rx_sn: R::new_mutex(crate::sn::RxSn::default()),
            batch_tx: R::new_mutex(BatchTx::default()),
            outbound_mappings: R::new_mutex(HashMap::<u64, String>::new()),
            #[cfg(feature = "session-reconnect")]
            declaration_cache: R::new_mutex(Vec::<CachedDeclaration>::new()),
            next_outbound_request_id: AtomicU64::new(0),
            next_outbound_token_id: AtomicU64::new(0),
            next_outbound_interest_id: AtomicU64::new(0),
        })
    }
}

impl<R: SessionRuntime, T: TimeSource> SessionLinkActions<R, T> {
    /// Resolve the runtime-owned link sink (`R::LinkSink`) to the pure
    /// `&dyn BoxedLinkDriver` write seam. `R::LinkSink` is opaque in
    /// generic-`R` code — the tokio profile binds it to `Arc<dyn
    /// BoxedLinkDriver + Send + Sync>`, the lwIP MCU profile to `Rc<dyn
    /// BoxedLinkDriver>` — so the action methods cannot call
    /// `send_blocking` on `self.driver` directly; this accessor erases
    /// the per-profile refcount wrapper through [`R::link_driver`]. The
    /// returned reference borrows `self`, so the seam call composes
    /// inline (`self.link_driver().send_blocking(&wire, reliability)`).
    fn link_driver(&self) -> &dyn BoxedLinkDriver {
        R::link_driver(&self.driver)
    }

    /// R121d — derive the SessionInitParams the Accepting side
    /// will emit on the outbound InitAck. Caps `seq_num_res`,
    /// `req_id_res`, and `batch_size` to `min(self.params.x,
    /// peer.x)` when an InitSyn has been parsed (slot populated
    /// by [`handle_inbound`]); falls back to `self.params`
    /// unmodified when no peer caps are known yet. The result is
    /// a fresh `SessionInitParams` so the caller can pass it to
    /// the codec without consuming the canonical params slot.
    ///
    /// This is the textbook enforcement of the wire-spec
    /// invariant `InitAck.size <= InitSyn.size` documented in
    /// zenoh-pico/src/transport/unicast/transport.c:120-140
    /// ("Any of the size parameters in the InitAck must be less
    /// or equal than the one in the InitSyn"). Skipping it makes
    /// an external initiator reject the InitAck with
    /// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` and abort the
    /// session, which is the R121d immediate symptom this
    /// negotiation closes.
    pub fn init_ack_params(&self) -> SessionInitParams {
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        let mut params = self.params.clone();
        if let Some(p) = peer {
            params.seq_num_res = params.seq_num_res.min(p.seq_num_res);
            params.req_id_res = params.req_id_res.min(p.req_id_res);
            // R311cb — transport-batching gates the min(local, peer)
            // reduction on batch_size. cfg-off keeps the local
            // advertised batch_size as-is (no downward negotiation).
            #[cfg(feature = "transport-batching")]
            {
                params.batch_size = params.batch_size.min(p.batch_size);
            }
        }
        params
    }

    /// R311kb — the session's negotiated SN ring mask
    /// ([`crate::sn::mask_from_res`] over `min(own, peer)` `seq_num_res`),
    /// the zenoh-pico `_z_transport_common_t._sn_res` equivalent. `min` is
    /// role-symmetric: the acceptor caps against the InitSyn caps
    /// ([`Self::init_ack_params`] emits the same min), and the initiator's
    /// InitAck caps are already `<=` its own advertisement, so `min`
    /// reproduces the adopted value. Before any peer caps arrive the own
    /// advertisement applies — handshake frames carry no SN, so every data
    /// mint and reassembly compare runs after the slot is populated; the
    /// fallback only keeps the accessor total.
    pub fn negotiated_sn_mask(&self) -> u64 {
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        let res = match peer {
            Some(p) => self.params.seq_num_res.min(p.seq_num_res),
            None => self.params.seq_num_res,
        };
        crate::sn::mask_from_res(res)
    }

    /// R311kd — the session's effective outbound frame budget: the
    /// negotiated-min batch size, zenoh-pico parity for
    /// `mtu = min(link MTU, negotiated batch_size)` where the
    /// negotiated value is `min(own, peer)` (unicast/transport.c:47-49
    /// sizes the TX wbuf to exactly that). Closes the R311jm carry —
    /// before this, `dispatch_network_message` sized against the LOCAL
    /// advertisement only and a frame could exceed what the peer's RX
    /// buffer accepts.
    ///
    /// `0` is the wz "unset" sentinel on BOTH sides of the min (a wz
    /// peer advertises `params.batch_size` verbatim, so an unconfigured
    /// wz peer puts `0` on the wire): an unset side contributes the
    /// 65535 wire ceiling instead of a zero budget. zenoh-pico never
    /// advertises 0 (its default is `_Z_DEFAULT_UNICAST_BATCH_SIZE =
    /// 65535`), so the sentinel only fires wz<->wz.
    ///
    /// The peer side reads the captured [`PeerInitCaps`], i.e. the
    /// `transport-batching`-honored projection: with the feature off the
    /// projection clamps to 65535 ("never reduce", R311cb) and the min
    /// degrades to the local advertisement — the pre-R311kd behavior.
    pub fn negotiated_batch_mtu(&self) -> usize {
        const UNSET_BATCH_MTU: usize = 65_535;
        let own = match self.params.batch_size {
            0 => UNSET_BATCH_MTU,
            n => n as usize,
        };
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        match peer {
            Some(p) => match p.batch_size {
                0 => own,
                n => own.min(n as usize),
            },
            None => own,
        }
    }

    /// Replace the ext chain for the given role. Production callers
    /// stage their negotiation result here; the next outbound frame
    /// of `role` reads the new chain via the encoder.
    pub fn set_ext_chain(&self, role: ExtChainRole, entries: Vec<ExtEntryOwned>) {
        R::with_mutex_mut(self.ext_chain_slot(role), |slot| *slot = entries);
    }

    /// Lock the ext-chain slot for the given role and encode the
    /// frame body + chain in one shot, returning the wire bytes.
    ///
    /// Lock is held only across the encode call (microseconds);
    /// the actual `send_blocking` happens after the guard drops so
    /// a slow driver does not block sibling roles. `ExtEntry` does
    /// not implement `Clone` (sce-codegen output), so passing the
    /// slot by reference into the encoder is the cheapest path —
    /// no snapshot copy required.
    ///
    /// `pub` (not `pub(crate)`) so layer-3 integration tests in
    /// sibling crates can exercise the encode path directly,
    /// bypassing the `dispatch_script` singleton race that bites
    /// when multiple tests in one binary share the
    /// `INSTALLED`/Lua-engine globals.
    #[cfg(feature = "codec-init-body")]
    pub fn encode_init_with_role(
        &self,
        is_ack: bool,
        cookie_override: Option<&[u8]>,
        role: ExtChainRole,
    ) -> Result<Vec<u8>, CodecError> {
        // R121d — capped-to-peer params so the outbound InitAck
        // satisfies the wire-spec `InitAck.size <= InitSyn.size`
        // invariant. The owned clone is cheap (the heavy field is
        // `cookie_signing_key`, a 32-byte `Zeroizing<Vec<u8>>`) and
        // stays local to this call frame. R311di-pre-f5 — params
        // captured outside the with_mutex_mut closure since
        // `init_ack_params` also acquires `inbound_peer_init_caps`
        // and nested R::with_mutex_mut on the same SessionLinkActions
        // would deadlock on a per-profile mutex (lwIP critical_section
        // is non-reentrant; embassy_sync re-entry is undefined). The
        // chain slot stays inside the closure so the encode call
        // composes against `&chain` without an extra clone.
        let params_owned = if is_ack {
            Some(self.init_ack_params())
        } else {
            None
        };
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            let params = params_owned.as_ref().unwrap_or(&self.params);
            encode_init(params, is_ack, chain, cookie_override)
        })
    }

    #[cfg(feature = "codec-open-body")]
    pub fn encode_open_with_role(
        &self,
        is_ack: bool,
        cookie_override: Option<&[u8]>,
        role: ExtChainRole,
    ) -> Result<Vec<u8>, CodecError> {
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            encode_open(&self.params, is_ack, cookie_override, chain)
        })
    }

    fn ext_chain_slot(&self, role: ExtChainRole) -> &R::Mutex<Vec<ExtEntryOwned>> {
        match role {
            ExtChainRole::InitSyn => &self.init_syn_ext,
            ExtChainRole::InitAck => &self.init_ack_ext,
            ExtChainRole::OpenSyn => &self.open_syn_ext,
            ExtChainRole::OpenAck => &self.open_ack_ext,
        }
    }

    pub fn trace_snapshot(&self) -> ActionTrace {
        R::with_mutex_mut(&self.trace, |t| t.clone_via_copy())
    }

    /// Initiator-side inbound dispatch — parse the wire bytes, and if
    /// the frame is `Init` with the `_Z_FLAG_T_INIT_A` discriminator
    /// set (i.e. peer InitAck), capture the cookie payload into
    /// `inbound_cookie` so the next OpenSyn echoes it verbatim per
    /// RFC §5.M.
    ///
    /// Returns the parsed `InboundFrame` so the caller can drive the
    /// session FSM (`Engine::process_event`) with the typed event;
    /// `handle_inbound` itself does not advance the FSM — that wiring
    /// belongs in a follow-up round when the inbound-event channel
    /// from `LinkDriver::poll_event` lands.
    pub fn handle_inbound(&self, bytes: &[u8]) -> Result<InboundFrame, InboundParseError> {
        let frame = parse_inbound(bytes)?;
        match &frame {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init {
                is_ack: true, body, ..
            } => {
                if let Some(cookie) = &body.cookie {
                    R::with_mutex_mut(&self.inbound_cookie, |slot| {
                        *slot = Some(cookie.as_slice().to_vec());
                    });
                }
                // R311kb — capture the InitAck's sizing caps too: the
                // initiator adopts the acceptor's (already-capped) final
                // values, mirroring zenoh-pico's client arm
                // (unicast/transport.c `_z_unicast_transport_create` reads
                // `param._seq_num_res` from the InitAck). Feeds
                // [`Self::negotiated_sn_mask`] so both roles resolve the
                // same SN ring; the packed `sn_res` byte is wire-identical
                // on InitSyn and InitAck, so the decoder is shared.
                R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| {
                    *slot = Some(PeerInitCaps::from_init_body(body.sn_res, body.batch_size));
                });
            }
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init {
                is_ack: false,
                body,
                ..
            } => {
                // R86 — Accepting-side InitSyn arrival: capture the
                // peer's claimed zid so the next send_init_ack_with_cookie
                // can HMAC-bind the outbound cookie to it per RFC §5.M.
                R::with_mutex_mut(&self.inbound_peer_zid, |slot| {
                    *slot = Some(body.zid.as_slice().to_vec());
                });
                // R121d — capture the peer's announced sizing caps
                // so `init_ack_params` can enforce the wire-spec
                // `InitAck.size <= InitSyn.size` rule on the
                // outbound InitAck (zenoh-pico
                // unicast/transport.c:123-140 rejection condition).
                R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| {
                    *slot = Some(PeerInitCaps::from_init_body(body.sn_res, body.batch_size));
                });
            }
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open {
                is_ack: false,
                body,
                ..
            } => {
                // R89 — Accepting-side OpenSyn arrival: capture the
                // echoed cookie so the `cookie_valid()` guard can
                // re-HMAC peer_zid and compare against this slot.
                // Closes the loop opened by R86 (outbound cookie
                // mint) — RFC §5.M anti-amplification on both
                // sides of the handshake.
                if let Some(cookie) = &body.cookie {
                    R::with_mutex_mut(&self.inbound_opensyn_cookie, |slot| {
                        *slot = Some(cookie.as_slice().to_vec());
                    });
                }
                // R311ke — the peer's announced initial_sn seeds the RX
                // SN gate baselines (peer.c:212-214: both channels one
                // before, so the first frame at initial_sn passes).
                // Sequential mutex scopes (negotiated_sn_mask takes
                // inbound_peer_init_caps), never nested.
                let mask = self.negotiated_sn_mask();
                R::with_mutex_mut(&self.rx_sn, |s| s.seed(mask, body.initial_sn));
            }
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open {
                is_ack: true, body, ..
            } => {
                // R311ke — Initiator-side OpenAck arrival: the acceptor's
                // initial_sn seeds the RX gate exactly as the OpenSyn
                // seeds it on the accepting side (pico captures
                // `_initial_sn_rx` from either body, transport.c:196/270).
                let mask = self.negotiated_sn_mask();
                R::with_mutex_mut(&self.rx_sn, |s| s.seed(mask, body.initial_sn));
            }
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { .. } => {
                // R72b — record receive time so the lease deadline
                // comparator (now_ms - stamp_ms < lease_ms) advances.
                // R294 — read `self.clock.now_monotonic_ms()` (shared
                // epoch with drive_session_until_terminal's clock
                // param) so the lease comparator's later `now_ms`
                // read is on the same monotonic scale.
                let now = self.clock.now_monotonic_ms();
                R::with_mutex_mut(&self.last_inbound_keepalive_at, |slot| {
                    *slot = Some(now);
                });
            }
            _ => {}
        }
        Ok(frame)
    }

    /// R311kc — initiator-side InitAck params admission, the dispatcher
    /// pre-classify twin of [`Self::cookie_valid`] /
    /// [`Self::half_open_cap_available`]: every InitAck size parameter
    /// must be `<=` our InitSyn advertisement (`self.params`), the
    /// zenoh-pico `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` rejection
    /// condition (unicast/transport.c:123-140). `false` means the peer
    /// ENLARGED a parameter and the session must be rejected — the
    /// dispatcher drives the FSM's `framing.error` arm (Closing with
    /// `CloseReason::Invalid`, the wire's "invalid parameters" close
    /// reason) instead of admitting `InitAckReceived`.
    ///
    /// Validates the RAW wire fields the caller pulls off the decoded
    /// InitAck body — NOT the captured [`PeerInitCaps`] slot, whose
    /// `transport-batching`-off projection clamps the peer batch_size to
    /// 65535 and would mask exactly the enlargement this guard rejects.
    #[cfg(feature = "codec-init-body")]
    pub fn init_ack_caps_acceptable(
        &self,
        sn_res_byte: Option<u8>,
        batch_size: Option<u16>,
    ) -> bool {
        !crate::peer_init_caps::init_ack_exceeds_advertisement(
            self.params.seq_num_res,
            self.params.req_id_res,
            self.params.batch_size,
            sn_res_byte,
            batch_size,
        )
    }

    /// R311ke — per-channel inbound Frame/Fragment SN admission, the
    /// zenoh-pico `_z_sn_precedes` gate of unicast/rx.c:100-185: every
    /// inbound FRAME / FRAGMENT SN must half-window-follow the channel's
    /// last accepted SN; a pass stores it as the new baseline. `false`
    /// means stale / duplicate / reordered — the dispatcher drops the
    /// frame without advancing the FSM (pico's silent drop; TCP cannot
    /// produce it, UDP unicast can). The reliable-channel reassembly
    /// chain is cleared by the drive helper on rejection, mirroring
    /// pico's dbuf-clear (rx.c:112-113).
    pub fn admit_rx_frame_sn(&self, reliable: bool, sn: u64) -> bool {
        // Sequential mutex scopes: the mask accessor takes
        // `inbound_peer_init_caps`, then `rx_sn` — disjoint, never nested
        // (the non-reentrant MCU critical_section forbids nesting).
        let mask = self.negotiated_sn_mask();
        R::with_mutex_mut(&self.rx_sn, |s| s.admit(mask, reliable, sn))
    }

    /// R121e / R311kb — outbound Frame sequence-number mint. Returns
    /// the SN for the next outbound Frame as a position on the ring of
    /// `sn_mask` ([`Self::negotiated_sn_mask`]) and advances the
    /// internal counter by one — zenoh-pico `_z_sn_increment` parity,
    /// closing the R121e explicit-modulo carry.
    ///
    /// The first call returns `params.initial_sn & sn_mask` (the
    /// counter is seeded by `new_session_actions`; a conforming
    /// `initial_sn` is already on the ring, so the announced
    /// OpenSyn/OpenAck origin and the first wire SN agree); subsequent
    /// calls return successive ring positions. Masking the returned
    /// value of a raw monotonic `fetch_add` IS the ring walk:
    /// consecutive counter values project to ring-consecutive masked
    /// values, across both the mask seam and the `u64` wrap.
    ///
    /// Atomic `SeqCst` is the textbook default for cross-task
    /// monotonicity. The hot path is one outbound Frame per
    /// application-layer batch — the atomic cost is in the noise
    /// vs. the codec encode + TCP write below it.
    pub fn next_outbound_frame_sn(&self, sn_mask: u64) -> u64 {
        self.outbound_frame_sn.fetch_add(1, Ordering::SeqCst) & sn_mask
    }

    /// Transport-framing chokepoint for every outbound network message —
    /// zenoh-pico `_z_transport_tx_send_n_msg_inner` parity
    /// (`src/transport/common/tx.c`). The chokepoint OWNS the frame
    /// sequence number (R311jq): SNs are frame-scoped, minted only when a
    /// frame opens, so batching never burns SNs on appended messages and
    /// the wire SN cadence stays inside the peer's `_z_sn_precedes`
    /// half-window whatever the batch length (zenoh-pico
    /// `src/transport/utils.c:80` — `distance <= half(window)`; the
    /// R311jp message-scoped mint could exceed it at small
    /// `seq_num_res`). Senders hand a per-type body encoder
    /// (`crate::frame_encode::*_body`) plus the codec's worst-case bound;
    /// the chokepoint decides framing:
    ///
    /// ```text
    ///   batching active → absorb into the open frame under the batch
    ///                     lock (open / append / overflow-reopen /
    ///                     oversize — all emits inside the lock so
    ///                     concurrent senders cannot reorder frames)
    ///   otherwise       → mint SN, encode one frame, emit (fragmenting
    ///                     on MTU overflow per transport-fragmentation)
    /// ```
    ///
    /// Compiled iff a network-message sender routes through it. This is the
    /// wire-emit feature union (cf. the `Reliability` import) MINUS the three
    /// handshake-only codecs (codec-init/open/close): INIT/OPEN/CLOSE carry no
    /// frame sequence number and are never fragmented, so they keep their own
    /// direct emit. Keep in sync with the routed `send_*` methods — every
    /// `dispatch_*` typed wrapper (push / response / response-final /
    /// request / declare / interest) lands here.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-final",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    fn dispatch_network_message<P>(
        &self,
        reliable: bool,
        worst_case_payload: usize,
        encode_body: P,
    ) -> Result<(), SendWireError>
    where
        P: Fn(
            &mut sce_forge_runtime::codec::VecSink<'_>,
        ) -> Result<(), sce_forge_runtime::codec::CodecError>,
    {
        // F2 — transport-availability gate (pico
        // `_Z_ERR_TRANSPORT_NOT_AVAILABLE` parity): inside the
        // RECONNECTING window (link released / reset for re-dial, not yet
        // re-Established) a data send must reject typed rather than
        // vanish into a dead writer channel. Single gate — every
        // network-message send routes through this chokepoint.
        if !R::with_mutex_mut(&self.transport_available, |g| *g) {
            return Err(SendWireError::TransportUnavailable);
        }
        // Outbound MTU = the negotiated-min batch budget
        // ([`Self::negotiated_batch_mtu`]: min(own, peer) with `0` as the
        // unset/65535 sentinel — R311kd closes the R311jm "honor the
        // peer's advertised batch_size" carry). (UDP's 65507-byte datagram
        // cap is below the 65535 default, so a UDP deployment expecting
        // >64 KB payloads must configure `batch_size <= 65507`.) R311jp —
        // the same budget bounds the batching accumulator (pico shares one
        // `_wbuf` capacity between both concerns). Resolved before the
        // batch lock for the same disjoint-mutex discipline as `sn_mask`
        // below (the accessor takes `inbound_peer_init_caps`).
        let mtu = self.negotiated_batch_mtu();

        // R311kb — the negotiated SN ring every mint below walks
        // ([`Self::negotiated_sn_mask`]). Resolved here, before the batch
        // lock: the accessor takes the `inbound_peer_init_caps` mutex, and
        // session mutex scopes stay disjoint by discipline.
        let sn_mask = self.negotiated_sn_mask();

        // R311jq / R311kf — ONE `batch_tx` lock hold covers the WHOLE TX
        // decision: the batching absorb / overflow-reopen / oversize arms
        // AND the immediate frame-per-message path, mint through emit.
        // pico holds its TX mutex across SN mint + wire write for EVERY
        // sender (common/tx.c:273-305 — `_z_transport_tx_get_sn` runs
        // inside `_z_transport_tx_send_n_msg_inner` under the mutex), so
        // mint order == wire order. Before R311kf the immediate path
        // minted outside the lock and emitted after it: two concurrent
        // non-batched senders could put a later SN on the wire first, and
        // the peer's half-window RX gate drops the earlier frame as stale
        // (the mint-vs-enqueue carry). One lock also closes the
        // batch_start boundary race — a sender that saw the window closed
        // cannot emit between a concurrent absorb's mint and its flush.
        // AP profile: std Mutex around a writer-channel enqueue — cheap.
        // MCU profile: critical_section — single-task drive model, and the
        // lwIP send under the section is bounded by the negotiated MTU;
        // revisit if a preemptive MCU profile lands (documented caveat).
        R::with_mutex_mut(&self.batch_tx, |batch| {
            #[cfg(feature = "transport-batching")]
            if batch.active {
                use crate::frame_encode::{begin_frame, frame_flags, frame_wire_reliability};
                let encode_into = |buf: &mut Vec<u8>| {
                    let mut sink = sce_forge_runtime::codec::VecSink::new(buf);
                    encode_body(&mut sink).expect("VecSink is infallible");
                };
                // At most two iterations: an overflow flushes the open
                // frame and falls through to the open-fresh-frame arm
                // (pico `_z_transport_tx_batch_overflow` rollback+retry).
                loop {
                    if batch.buf.is_empty() {
                        let sn = self.next_outbound_frame_sn(sn_mask);
                        batch.buf.reserve(1 + 10 + worst_case_payload);
                        begin_frame(&mut batch.buf, sn, frame_flags(reliable));
                        encode_into(&mut batch.buf);
                        if batch.buf.len() > mtu {
                            // The message alone exceeds the budget — the
                            // batch cannot carry it; emit it through the
                            // oversize path (fragment chain, or as-is when
                            // fragmentation is off), still under the lock.
                            let frame = core::mem::take(&mut batch.buf);
                            batch.count = 0;
                            self.emit_frame_or_fragments(&frame, sn, reliable, mtu, sn_mask);
                        } else {
                            batch.count = 1;
                        }
                        return;
                    }
                    let wpos = batch.buf.len();
                    encode_into(&mut batch.buf);
                    if batch.buf.len() <= mtu {
                        batch.count += 1;
                        return;
                    }
                    // Overflow: roll the partial encode back, flush the
                    // open frame, loop into the open-fresh-frame arm.
                    batch.buf.truncate(wpos);
                    let prev = core::mem::take(&mut batch.buf);
                    batch.count = 0;
                    let channel = frame_wire_reliability(&prev);
                    self.link_driver().send_blocking(&prev, channel);
                }
            }
            // With transport-batching off the window flag never reads
            // true; the binding only serves the lock role (R311g1
            // signature-stable closure under the gate).
            #[cfg(not(feature = "transport-batching"))]
            let _ = batch;

            // Immediate path (batching off or window closed):
            // frame-per-message, mint + encode + emit under the SAME lock
            // hold (pico TX-mutex parity, R311kf).
            let sn = self.next_outbound_frame_sn(sn_mask);
            let wire = crate::frame_encode::encode_frame_envelope(
                sn,
                crate::frame_encode::frame_flags(reliable),
                worst_case_payload,
                &encode_body,
            );
            self.emit_frame_or_fragments(&wire, sn, reliable, mtu, sn_mask);
        });
        Ok(())
    }

    /// R311jq — terminal emit for one already-encoded outbound frame:
    /// send as-is when it fits `mtu`, else re-frame the network-message
    /// body as a `T_MID_FRAGMENT` chain (zenoh-pico
    /// `_z_transport_tx_send_fragment` parity). Shared by the immediate
    /// path and the batching oversize arm so the fragment decision stays
    /// in one place.
    ///
    /// The FRAME body is the tail after the 1-byte header + `VLE(sn)`;
    /// slice it rather than re-encoding (`vle_width` = base-128 width of
    /// `sn`). The discarded oversize FRAME consumed `sn`; the fragment
    /// chain reserves a fresh contiguous counter block via a single
    /// atomic fetch-add — `fragment_body` projects it onto the ring of
    /// `sn_mask` (R311kb) — so the chunk SNs stay ring-consecutive even
    /// if a concurrent sender mints outbound SNs (the reassembly
    /// dispatcher aborts a non-consecutive chain). The one skipped SN
    /// per oversize message never reaches the wire and stays far inside
    /// the peer's SN half-window (bounded: 1 per oversize message, vs
    /// the fragment chain consuming `count` SNs itself).
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-final",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    fn emit_frame_or_fragments(
        &self,
        frame: &[u8],
        sn: u64,
        reliable: bool,
        mtu: usize,
        sn_mask: u64,
    ) {
        let reliability = if reliable {
            Reliability::Reliable
        } else {
            Reliability::BestEffort
        };
        #[cfg(feature = "transport-fragmentation")]
        {
            if frame.len() > mtu {
                let body = &frame[1 + crate::frame_encode::vle_width(sn)..];
                let count = crate::frame_encode::fragment_count(body.len(), mtu) as u64;
                let base = self.outbound_frame_sn.fetch_add(count, Ordering::SeqCst);
                for frag in crate::frame_encode::fragment_body(body, reliable, mtu, base, sn_mask) {
                    self.link_driver().send_blocking(&frag, reliability);
                }
                return;
            }
        }
        #[cfg(not(feature = "transport-fragmentation"))]
        let _ = (sn, mtu, sn_mask);
        self.link_driver().send_blocking(frame, reliability);
    }

    /// R311jq — drain the open batch frame to the link, if any. Private
    /// emit engine shared by [`Self::batch_flush`] / [`Self::batch_stop`] /
    /// the pre-CLOSE drain in [`Self::send_close_with_reason`] / the
    /// express post-dispatch flush. Keeps the `active` flag untouched.
    /// The emit runs INSIDE the batch lock so a drain cannot interleave
    /// with a concurrent absorb's flush (frame order is wire-visible —
    /// the peer's half-window SN check drops reordered frames).
    #[cfg(feature = "transport-batching")]
    fn flush_open_batch(&self) {
        R::with_mutex_mut(&self.batch_tx, |batch| {
            if batch.buf.is_empty() {
                return;
            }
            batch.count = 0;
            let frame = core::mem::take(&mut batch.buf);
            let channel = crate::frame_encode::frame_wire_reliability(&frame);
            self.link_driver().send_blocking(&frame, channel);
        });
    }

    /// zenoh-pico `zp_batch_start` parity — open a batching window: every
    /// subsequent network-message send accumulates into one outbound
    /// `T_MID_FRAME` (up to the `batch_size` byte budget) instead of
    /// flushing per message, until [`Self::batch_flush`] /
    /// [`Self::batch_stop`] / an overflow / an express message drains it.
    ///
    /// Idempotent: re-starting an already-active window is a no-op that
    /// keeps the open frame. (pico returns an error there, but only because
    /// `_z_transport_start_batching` HOLDS the TX mutex for the whole
    /// window — re-entry would self-deadlock. wz locks per operation, so
    /// double-start has no hazard to guard.)
    ///
    /// R311g signature-stability — the method exists across feature
    /// states; minus `transport-batching` it rejects with
    /// [`SendWireError::FeatureDisabled`].
    pub fn batch_start(&self) -> Result<(), SendWireError> {
        #[cfg(feature = "transport-batching")]
        {
            R::with_mutex_mut(&self.batch_tx, |batch| batch.active = true);
            Ok(())
        }
        #[cfg(not(feature = "transport-batching"))]
        Err(SendWireError::FeatureDisabled)
    }

    /// zenoh-pico `zp_batch_flush` parity — send the currently batched
    /// messages now, keeping the batching window active.
    pub fn batch_flush(&self) -> Result<(), SendWireError> {
        #[cfg(feature = "transport-batching")]
        {
            self.flush_open_batch();
            Ok(())
        }
        #[cfg(not(feature = "transport-batching"))]
        Err(SendWireError::FeatureDisabled)
    }

    /// zenoh-pico `zp_batch_stop` parity — close the batching window and
    /// send the currently batched messages. Deactivates BEFORE draining
    /// (the `api.c` order: `_z_transport_stop_batching` then
    /// `_z_send_n_batch`) so a send racing the stop goes out directly
    /// rather than landing in a window that is closing.
    pub fn batch_stop(&self) -> Result<(), SendWireError> {
        #[cfg(feature = "transport-batching")]
        {
            R::with_mutex_mut(&self.batch_tx, |batch| batch.active = false);
            self.flush_open_batch();
            Ok(())
        }
        #[cfg(not(feature = "transport-batching"))]
        Err(SendWireError::FeatureDisabled)
    }

    /// R311jq — typed chokepoint entries: each hands its per-type body
    /// encoder (`crate::frame_encode::*_body`, the single home of the
    /// encode projection) to [`Self::dispatch_network_message`], which
    /// owns the frame SN. cfg = the union of the routed `send_*` callers
    /// (a build where no caller exists must not carry the dead symbol).
    #[cfg(feature = "codec-push")]
    fn dispatch_push(
        &self,
        push: wz_codecs::push::PushOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::push::Push::MAX_ENCODED_BYTES,
            crate::frame_encode::push_body(&push),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(any(
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-final",
        feature = "liveliness-token",
    ))]
    fn dispatch_declare(
        &self,
        declare: wz_codecs::declare::DeclareOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::declare::Declare::MAX_ENCODED_BYTES,
            crate::frame_encode::declare_body(&declare),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(feature = "codec-request")]
    fn dispatch_request(
        &self,
        request: wz_codecs::request::RequestOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::request::Request::MAX_ENCODED_BYTES,
            crate::frame_encode::request_body(&request),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(feature = "codec-response")]
    fn dispatch_response(
        &self,
        response: wz_codecs::response::ResponseOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::response::Response::MAX_ENCODED_BYTES,
            crate::frame_encode::response_body(&response),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(feature = "codec-response-final")]
    fn dispatch_response_final(
        &self,
        response_final: wz_codecs::response_final::ResponseFinalOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::response_final::ResponseFinal::MAX_ENCODED_BYTES,
            crate::frame_encode::response_final_body(&response_final),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(feature = "declare-interest")]
    fn dispatch_interest(
        &self,
        interest: wz_codecs::interest::InterestOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            reliable,
            wz_codecs::interest::Interest::MAX_ENCODED_BYTES,
            crate::frame_encode::interest_body(&interest),
        )
    }

    /// R311jp — express short-circuit, zenoh-pico parity: an
    /// express-flagged message is encoded into the open batch like any
    /// other, then the whole frame is flushed immediately (`tx.c`
    /// `_z_transport_tx_get_express_status` arm calls
    /// `_z_transport_tx_flush_buffer` right after the encode). The
    /// `send_push_*_with_meta_*` senders call this after their dispatch;
    /// the express bit is only derivable where QoS metadata exists, which
    /// today is the Push metadata path.
    #[cfg(feature = "codec-push")]
    fn flush_batch_if_express(&self, meta: &PushMetadata) {
        #[cfg(feature = "transport-batching")]
        if meta
            .qos
            .as_ref()
            .is_some_and(crate::sample::QosLevel::is_express)
        {
            self.flush_open_batch();
        }
        #[cfg(not(feature = "transport-batching"))]
        let _ = meta;
    }

    /// R239 — outbound `Request.request_id` generator. Returns the
    /// next rid and advances the internal counter by one. Mirrors
    /// zenoh-pico's `_z_unsafe_register_pending_query`
    /// (`vendor/zenoh-pico/src/session/query.c:99` —
    /// `_z_zint_t qid = zn->_query_id++` post-increment from 0). The
    /// first call returns `0`; each subsequent call returns the next
    /// integer.
    ///
    /// `Relaxed` ordering is sufficient — uniqueness is the only
    /// invariant the caller depends on and `fetch_add` is atomic
    /// under every ordering. The wire `req_id_res` resolution window
    /// (`params.req_id_res = 0..=3` → 8/16/32/64-bit) is not enforced
    /// here either; production code with long-running sessions
    /// emitting more than `1 << req_bits` queries needs an explicit
    /// modulo (same carry as
    /// [`Self::next_outbound_frame_sn`]).
    pub fn alloc_next_request_id(&self) -> u64 {
        self.next_outbound_request_id
            .fetch_add(1, Ordering::Relaxed)
    }

    /// R248 — outbound liveliness `token_id` generator. Returns the
    /// next token id and advances the internal counter by one. The
    /// id is consumed by [`Self::send_declare_token`] /
    /// [`Self::send_undeclare_token`] as the inner
    /// `decl_token`/`undecl_token` codec's `id` field and is kept on
    /// the `crate::session::LivelinessToken` RAII handle so the
    /// `Drop` impl can retract the same id without the caller
    /// threading it manually.
    ///
    /// Mirrors zenoh-pico's `_z_get_entity_id` consumed by
    /// `_z_declare_liveliness_token`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:58`); first call
    /// returns `0` matching the post-increment-from-zero convention.
    /// `Relaxed` ordering — uniqueness is the only invariant.
    pub fn alloc_next_token_id(&self) -> u64 {
        self.next_outbound_token_id.fetch_add(1, Ordering::Relaxed)
    }

    /// R279 — outbound liveliness-subscriber `interest_id` generator.
    /// Returns the next interest id and advances the internal counter
    /// by one. The id is consumed by
    /// [`Self::send_interest_liveliness_subscriber`] /
    /// [`Self::send_interest_final`] as the inner `Interest::interest_id`
    /// field and is kept on the
    /// `crate::session::LivelinessSubscriber` RAII handle so the
    /// `Drop` impl can emit the matching `InterestFinal` (ending the
    /// `FUTURE` flow) without the caller threading the id manually.
    ///
    /// Mirrors zenoh-pico's `_z_get_entity_id` consumed by
    /// `_z_register_liveliness_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:169-198`); first call
    /// returns `0` matching the post-increment-from-zero convention.
    /// `Relaxed` ordering — uniqueness is the only invariant.
    pub fn alloc_next_interest_id(&self) -> u64 {
        self.next_outbound_interest_id
            .fetch_add(1, Ordering::Relaxed)
    }

    /// R121e — encode + dispatch a `Push` (literal keyexpr, `Put`
    /// payload) on the outbound link, wrapped in a single-message
    /// `Frame` transport-envelope.
    ///
    /// Wire shape composed by this method
    /// (`encode_frame_with_push` + `build_push_literal` +
    /// `MsgPut::encode`):
    ///
    /// ```text
    ///   [parent_flags | T_MID_FRAME (0x05)]
    ///     VLE(sn) | Push.encode_bytes:
    ///       [push.header | M_derived] [WireexprLocal.encode] [MsgPut.encode]
    ///         MsgPut: [header 0x01] [VLE(payload_len)] [payload bytes]
    /// ```
    ///
    /// `keyexpr_suffix` carries the literal keyexpr string inline
    /// (no DECLARE alias indirection). `value` is the
    /// application-layer payload bytes. `reliable=true` sets
    /// `FLAG_T_FRAME_R` on the parent Frame header (mirrors
    /// zenoh-pico transport.c:380); the AP MVP pub/sub path
    /// passes `true` because the only consumer (z_sub) declares
    /// its subscription on the reliable channel by default.
    ///
    /// Preconditions (caller-enforced):
    ///   * The session FSM has reached the `Established` state
    ///     (post `send_open_ack` on Accepting side, post
    ///     `send_open_syn` echo + InitAck dispatch on Initiator
    ///     side). Sending a `Frame` before Established violates
    ///     the session-fsm §2.6 "Frame is established-only"
    ///     invariant and the peer drops the bytes — zenoh-pico
    ///     `unicast/transport.c::_z_unicast_recv_frame_t` guards
    ///     the non-Established state explicitly. Callers
    ///     typically poll [`trace_snapshot`] for
    ///     `send_open_ack > 0` (acceptor) or
    ///     `record_established_at > 0` (both sides) before the
    ///     first invocation.
    ///   * The underlying [`BoxedLinkDriver`] is non-blocking
    ///     OR the channel-decoupling pattern is in place
    ///     (`OutboundWriteDriver` in wz-ap-demo). Calling this
    ///     from inside an async future driven by the same Tokio
    ///     runtime as the driver's writer task — with a driver
    ///     that synchronously calls `block_on` — would trip the
    ///     "Cannot start a runtime from within a runtime" check.
    ///     `TokioLinkDriverAdapter`'s `send_blocking` calls
    ///     `block_on`; the wz-ap-demo binary substitutes the
    ///     mpsc-channel `OutboundWriteDriver` precisely to avoid
    ///     this trap (see wz-ap-demo `OutboundWriteDriver` doc).
    pub fn send_push_literal(
        &self,
        keyexpr_suffix: &str,
        value: &[u8],
        reliable: bool,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_literal(keyexpr_suffix, value)?;
            self.dispatch_push(push, reliable)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (keyexpr_suffix, value, reliable);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R121g — encode + dispatch a `Declare(DeclKexpr)` on the
    /// outbound link, registering `mapping_id -> suffix` in the
    /// peer's keyexpr table. After the peer has parsed this frame
    /// (zenoh-pico's `_z_session_recv_declaration` populates the
    /// table), the publisher may emit aliased Pushes carrying only
    /// `mapping_id` (and optionally a per-Push suffix) via
    /// [`send_push_aliased`].
    ///
    /// DECLARE outbound is hard-coded to the reliable channel — the
    /// session-FSM SN window enforces ordering between this frame
    /// and any subsequent aliased Push on the same channel, so the
    /// peer's table is guaranteed populated before a referencing
    /// Push arrives. A best-effort DECLARE would race against the
    /// aliased Push and the peer's resolver would reject the id;
    /// best-effort DECLARE has no production semantics in zenoh-pico.
    ///
    /// Preconditions match [`send_push_literal`] (the session FSM
    /// must have reached `Established`; the driver must be
    /// non-blocking or the channel-decoupling pattern must be in
    /// place to avoid `block_on`-in-runtime panic).
    ///
    /// R311g1 signature-stability retrofit — method signature stays
    /// `pub fn send_declare_keyexpr(...) -> Result<(), SendDeclareError>`
    /// across feature states; only the body branches on `declare-keyexpr`.
    /// When the feature is off, the method returns
    /// `Err(SendDeclareError::FeatureDisabled)` (fail-fast typed reject)
    /// rather than `Ok(())` (which would falsely promise a wire emit)
    /// or compiler-error-via-missing-symbol (which would re-introduce
    /// the `#[cfg(feature)] pub fn` anti-pattern). See
    /// `feedback_signature_stability` MEMORY note + R311g
    /// `send_close_with_reason` precedent.
    pub fn send_declare_keyexpr(
        &self,
        mapping_id: u64,
        suffix: &str,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-keyexpr")]
        {
            // R300 — pre-emit gate. Both checks run BEFORE any wire
            // bytes leave or any mapping-table side effect; on Err
            // the session-link state is unchanged.
            if mapping_id == 0 {
                return Err(SendDeclareError::ReservedMappingIdZero);
            }
            check_outbound_keyexpr_pico_safe(suffix)?;
            let declare = build_declare_kexpr(mapping_id, suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // R234 — record the (mapping_id, suffix) pair in the
            // outbound table so later `publish_aliased_auto` calls
            // can resolve the literal without caller assertion.
            // Insertion happens AFTER the wire send so a driver-side
            // panic does not leave a table entry that the peer never
            // saw. Mirrors zenoh-pico's `_z_register_resource` which
            // executes on the local-side declaration emit path.
            R::with_mutex_mut(&self.outbound_mappings, |table| {
                table.insert(mapping_id, suffix.to_string());
            });
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::Keyexpr {
                mapping_id,
                suffix: suffix.to_string(),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-keyexpr"))]
        {
            let _ = (mapping_id, suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
    }

    /// R121g — encode + dispatch a DECLARE-aliased `Push` (id != 0).
    /// Mirror of [`send_push_literal`] for the
    /// after-DECLARE-registration path. The caller MUST have
    /// invoked [`send_declare_keyexpr`] earlier on the same session
    /// (or relied on a prior in-band DECLARE) so the peer's keyexpr
    /// table contains a `mapping_id` entry; otherwise the peer
    /// drops the Push with an "unknown wireexpr id" error.
    ///
    /// `suffix=None` emits a pure-aliased Push (the declared
    /// literal is the full keyexpr). `suffix=Some(s)` emits a
    /// composite Push (the declared prefix + `s`) — useful when
    /// one DECLARE registers a common prefix and many Pushes carry
    /// the per-instance tail.
    pub fn send_push_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        value: &[u8],
        reliable: bool,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_aliased(mapping_id, suffix, value)?;
            self.dispatch_push(push, reliable)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (mapping_id, suffix, value, reliable);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R219 — encode + dispatch a literal-keyexpr `Push(MsgDel)` on
    /// the outbound link. Delete-keyexpr signal mirror of
    /// [`Self::send_push_literal`]: zenoh-pico's subscriber callback
    /// fires with `z_sample_kind = DELETE` on receipt.
    ///
    /// `MsgDel` carries no payload so the action accepts only the
    /// keyexpr suffix. Reliability gating + Established-state
    /// preconditions match [`Self::send_push_literal`].
    pub fn send_push_del_literal(
        &self,
        keyexpr_suffix: &str,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_literal(keyexpr_suffix)?;
            self.dispatch_push(push, reliable)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (keyexpr_suffix, reliable);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R219 — encode + dispatch a DECLARE-aliased `Push(MsgDel)`
    /// (id != 0) on the outbound link. Delete-keyexpr signal mirror
    /// of [`Self::send_push_aliased`]. Same prior-`DeclKexpr`
    /// precondition as the Put variant: the peer must have absorbed
    /// a Declare for `mapping_id` earlier on the same session so
    /// the receive-side resolver can map it back to a literal
    /// keyexpr before firing the subscriber callback.
    pub fn send_push_del_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_aliased(mapping_id, suffix)?;
            self.dispatch_push(push, reliable)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (mapping_id, suffix, reliable);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R233 — metadata-bearing counterpart of [`send_push_literal`].
    /// Threads every caller-set [`PushMetadata`] field onto the
    /// outbound `MsgPut`/Push so the wire receiver projects the same
    /// `Sample` shape the loopback path produces from
    /// `PublishOptions`. Reliability gating, frame-SN minting, and
    /// driver dispatch mirror the metadata-stripped fast path; only
    /// the Push builder differs.
    pub fn send_push_with_meta_literal(
        &self,
        keyexpr_suffix: &str,
        value: &[u8],
        reliable: bool,
        meta: &PushMetadata,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_literal_with_meta(keyexpr_suffix, value, meta)?;
            self.dispatch_push(push, reliable)?;
            self.flush_batch_if_express(meta);
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (keyexpr_suffix, value, reliable, meta);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R233 — metadata-bearing counterpart of [`send_push_aliased`].
    pub fn send_push_with_meta_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        value: &[u8],
        reliable: bool,
        meta: &PushMetadata,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_aliased_with_meta(mapping_id, suffix, value, meta)?;
            self.dispatch_push(push, reliable)?;
            self.flush_batch_if_express(meta);
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (mapping_id, suffix, value, reliable, meta);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R233 — metadata-bearing counterpart of
    /// [`send_push_del_literal`]. `meta.encoding` is silently dropped
    /// because `_z_msg_del_t` carries no encoding slot; the loopback
    /// branch enforces the same projection so neither side surfaces
    /// an `encoding` on a Del Sample.
    pub fn send_push_del_with_meta_literal(
        &self,
        keyexpr_suffix: &str,
        reliable: bool,
        meta: &PushMetadata,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_literal_with_meta(keyexpr_suffix, meta)?;
            self.dispatch_push(push, reliable)?;
            self.flush_batch_if_express(meta);
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (keyexpr_suffix, reliable, meta);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R233 — metadata-bearing counterpart of
    /// [`send_push_del_aliased`].
    pub fn send_push_del_with_meta_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        reliable: bool,
        meta: &PushMetadata,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_aliased_with_meta(mapping_id, suffix, meta)?;
            self.dispatch_push(push, reliable)?;
            self.flush_batch_if_express(meta);
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (mapping_id, suffix, reliable, meta);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R121i — encode + dispatch a `Declare(DeclSubscriber)` on the
    /// outbound link, registering a subscription on the peer for the
    /// keyexpr resolved by `(keyexpr_mapping_id, keyexpr_suffix)`. The
    /// peer's inbound dispatch (zenoh-pico's
    /// `_z_session_recv_declaration` -> `_z_register_subscription`)
    /// inserts `subscriber_id -> keyexpr` into its local subscriber
    /// table; subsequent Pushes from this peer that match the
    /// declared keyexpr will then trigger the wz-side inbound
    /// callback path.
    ///
    /// `keyexpr_mapping_id == 0` with `keyexpr_suffix = Some(s)`
    /// registers a literal keyexpr (the SubscribeR carries its own
    /// suffix on the wire). `keyexpr_mapping_id != 0` with
    /// `keyexpr_suffix = None` aliases a previously-declared peer
    /// keyexpr mapping (the bandwidth-efficient form); the optional
    /// `Some(s)` adds a per-subscription tail suffix to that alias.
    ///
    /// Same reliable-channel preconditions as
    /// [`send_declare_keyexpr`]: the SN-window ordering guarantees
    /// the peer's subscriber table is populated before any matching
    /// Push arrives.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// `Err(FeatureDisabled)` when `declare-subscriber` off.
    pub fn send_declare_subscriber(
        &self,
        subscriber_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-subscriber")]
        {
            // R300 — reconstruct the full keyexpr from `(mapping_id,
            // suffix)` and gate-check it BEFORE wire emit so a
            // cross-boundary bug #3 shape (prefix=`"**"` +
            // suffix=`"/c/*"`) cannot slip past a suffix-only check.
            let reconstructed =
                self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
            check_outbound_keyexpr_pico_safe(&reconstructed)?;
            let declare =
                build_declare_subscriber(subscriber_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::Subscriber {
                subscriber_id,
                mapping_id: keyexpr_mapping_id,
                suffix: keyexpr_suffix.map(ToString::to_string),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-subscriber"))]
        {
            let _ = (subscriber_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
    }

    /// R121i-b — encode + dispatch a `Declare(DeclQueryable)` on the
    /// outbound link, registering a queryable on the peer for the
    /// keyexpr resolved by `(keyexpr_mapping_id, keyexpr_suffix)`.
    /// The peer's inbound dispatch (zenoh-pico's
    /// `_z_session_recv_declaration` ->
    /// `_z_register_questionable_queryable`) inserts
    /// `queryable_id -> keyexpr` into its local queryable table; any
    /// `Request(Query)` arriving from this peer that matches the
    /// declared keyexpr will then trigger the wz-side `on_query`
    /// callback path (R121j+).
    ///
    /// AP MVP emits the `has_info_ext = false` shape — see
    /// [`build_declare_queryable`] doc for the rationale and the
    /// future split path for `complete = true` / non-zero `distance`.
    ///
    /// Same reliable-channel preconditions as
    /// [`send_declare_keyexpr`]: the SN-window ordering guarantees
    /// the peer's queryable table is populated before any matching
    /// `Request(Query)` arrives.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// `Err(FeatureDisabled)` when `declare-queryable` off.
    pub fn send_declare_queryable(
        &self,
        queryable_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-queryable")]
        {
            // R300 — same gate shape as `send_declare_subscriber`.
            let reconstructed =
                self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
            check_outbound_keyexpr_pico_safe(&reconstructed)?;
            let declare =
                build_declare_queryable(queryable_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::Queryable {
                queryable_id,
                mapping_id: keyexpr_mapping_id,
                suffix: keyexpr_suffix.map(ToString::to_string),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-queryable"))]
        {
            let _ = (queryable_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
    }

    /// R121i-b — encode + dispatch a `Declare(DeclToken)` on the
    /// outbound link, registering a liveliness token on the peer for
    /// the keyexpr resolved by `(keyexpr_mapping_id,
    /// keyexpr_suffix)`. The peer's inbound dispatch inserts
    /// `token_id -> keyexpr` into its liveliness-token table; the
    /// declared token then participates in zenoh-pico's liveliness
    /// notification fan-out (Z_FEATURE_LIVELINESS path).
    ///
    /// No extension surface — zenoh-pico's `_z_decl_token_encode`
    /// always emits the bare `_z_decl_commons_encode(has_ext=false)`
    /// shape, so this builder's wire bytes are byte-stable across
    /// every `(id, mapping, suffix)` triple.
    ///
    /// Same reliable-channel preconditions as
    /// [`send_declare_keyexpr`] / [`send_declare_subscriber`].
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// `Err(FeatureDisabled)` when `declare-token` off.
    pub fn send_declare_token(
        &self,
        token_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-token")]
        {
            // R300 — same gate shape as `send_declare_subscriber`.
            let reconstructed =
                self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
            check_outbound_keyexpr_pico_safe(&reconstructed)?;
            let declare = build_declare_token(token_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::Token {
                token_id,
                mapping_id: keyexpr_mapping_id,
                suffix: keyexpr_suffix.map(ToString::to_string),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-token"))]
        {
            let _ = (token_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
    }

    /// R283 — encode + dispatch a pre-built `Declare(...)` envelope on
    /// the reliable outbound link. The declarer-side liveliness-token
    /// registry (`wz-session-core::declare::local_token`) builds the
    /// interest-response declarations (`Declare(DeclToken)` per matching
    /// held token, `Declare(DeclFinal)` terminator — each carrying the
    /// inbound `interest_id`) and the observer drains them through the
    /// `ResponseSink::send_declare` trait method, which resolves to this
    /// inherent method. Unlike `send_declare_token` (which builds the
    /// envelope from primitives + runs the R300 outbound-keyexpr gate),
    /// this takes a ready `DeclareOwned`: the registry already resolved
    /// the keyexpr from wz's own held-token state, which passed the
    /// outbound gate at `declare_token` time. Gated on `liveliness-token`
    /// (the only feature that stages outbound `Declare` through the
    /// sink); that feature transitively enables `codec-declare`, so
    /// `encode_frame_with_declare` is in scope.
    #[cfg(feature = "liveliness-token")]
    pub fn send_declare(&self, declare: DeclareOwned) {
        // F2 — this surface has no error channel; a transport-down
        // reject drops the emit exactly as the dead link would.
        let _ = self.dispatch_declare(declare, /*reliable=*/ true);
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclKexpr)` on the
    /// outbound link, retracting a previously declared keyexpr
    /// mapping (id) on the peer. The peer's inbound dispatch
    /// (zenoh-pico's `_z_session_recv_declaration` ->
    /// `_z_unregister_resource`) removes the `(id -> keyexpr)` entry;
    /// any subsequent Push from this peer that aliases the retracted
    /// id will be rejected by the peer's resolver.
    ///
    /// Reliable channel — same SN-window ordering reason as the
    /// DECLARE path: the peer must observe the retraction before any
    /// later Push that still aliases the id, otherwise the peer would
    /// dispatch the Push to the now-stale keyexpr.
    ///
    /// R311p — signature-stability per `feedback_signature_stability`
    /// MEMORY anchor (same sweep as R311o send_undeclare_token). Body
    /// cfg-gated on `all(declare-keyexpr, declare-undeclare)`; silent
    /// no-op when either feature is off (() return — no error channel,
    /// the outbound_mappings table prune is also gated so a feature-off
    /// build never populated the table to begin with).
    pub fn send_undeclare_kexpr(&self, mapping_id: u64) {
        #[cfg(all(feature = "declare-keyexpr", feature = "declare-undeclare"))]
        {
            let declare = build_undeclare_kexpr(mapping_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_declare(declare, /*reliable=*/ true);
            // R234 — drop the (mapping_id, suffix) pair so subsequent
            // `publish_aliased_auto` calls return `None` on this id and
            // the caller knows the alias is stale. Idempotent: removing
            // an absent id is a no-op. Mirrors zenoh-pico's
            // `_z_unregister_resource` invoked on the local-side
            // undeclare emit path.
            R::with_mutex_mut(&self.outbound_mappings, |table| {
                table.remove(&mapping_id);
            });
            // A4 — drop the matching replay entry (pico
            // `_z_prune_declaration` undeclare-filter on `_id`).
            #[cfg(feature = "session-reconnect")]
            self.prune_declaration(|entry| {
                matches!(entry, CachedDeclaration::Keyexpr { mapping_id: m, .. } if *m == mapping_id)
            });
        }
        #[cfg(not(all(feature = "declare-keyexpr", feature = "declare-undeclare")))]
        let _ = mapping_id;
    }

    /// R234 — look up the literal keyexpr a previously-emitted
    /// [`Self::send_declare_keyexpr`] registered for `mapping_id`.
    /// Returns `None` when no declaration was ever sent for that id
    /// OR when a subsequent [`Self::send_undeclare_kexpr`] retracted
    /// it. The owned `String` is cloned out of the table so the
    /// caller can release the table lock immediately and avoid
    /// holding the publish hot path under contention.
    ///
    /// zenoh-pico mirror: the read-side of
    /// `_z_session_t._local_resources`, queried via
    /// `_z_get_resource_by_id` on the publish path.
    pub fn resolve_outbound_mapping(&self, mapping_id: u64) -> Option<String> {
        R::with_mutex_mut(&self.outbound_mappings, |table| {
            table.get(&mapping_id).cloned()
        })
    }

    /// R283 — `true` once the session-FSM has entered the `Established`
    /// state (the `record_established_at` Lua action wired to
    /// `Established.onentry` in `session_fsm_unicast.scxml` has
    /// populated `established_at`). Cheap predicate: a single
    /// `Mutex<Option<Instant>>::is_some()` lookup; no clock read,
    /// no FSM traversal.
    ///
    /// Surfaces the session-fsm §2.5 Established invariant to the
    /// declare-side primitives so they can refuse an outbound wire
    /// emit before the handshake completes. zenoh-pico's
    /// `z_liveliness_declare_subscriber` enforces the same invariant
    /// implicitly: the application sequences declares AFTER `z_open`
    /// returns Z_OK (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h`
    /// API contract), so a peer that emits an Interest pre-Established
    /// is a protocol bug, not a runtime condition the peer can
    /// recover from.
    ///
    /// R311di-pre-f4: poison policy migrated from "PoisonError -> false"
    /// to the Runtime trait's cross-profile contract — `with_mutex_mut`
    /// recovers the inner value on poison (TokioRuntime::with_mutex_mut
    /// calls `poisoned.into_inner()`), so a poisoned `established_at`
    /// returns the last-stored `stamp.is_some()` outcome. The conservative
    /// "refuse-on-poison" wording above no longer applies because the
    /// per-profile mutex aliases (lwIP critical_section, embassy_sync)
    /// do not surface a PoisonError equivalent — the trait normalises
    /// the AP side to match.
    pub fn is_established(&self) -> bool {
        R::with_mutex_mut(&self.established_at, |slot| slot.is_some())
    }

    /// R300 — reconstruct the full literal keyexpr that the peer
    /// will canonize on the receive side from the wire's
    /// `(mapping_id, suffix)` carrier shape. The reconstruction
    /// feeds [`check_outbound_keyexpr_pico_safe`]: the SIGABRT-
    /// prone shape (`**` + literal + `*`-shape) can straddle the
    /// prefix / suffix boundary (e.g. prefix=`"**"` registered via
    /// an earlier [`Self::send_declare_keyexpr`], suffix=`"/c/*"`
    /// passed to [`Self::send_declare_subscriber`]), so a suffix-
    /// only check would miss it.
    ///
    /// Shape map (mirrors the four wire forms enumerated in
    /// `send_declare_subscriber` doc):
    ///
    /// | `mapping_id` | `suffix`         | Reconstructed             |
    /// |--------------|------------------|---------------------------|
    /// | `0`          | `None`           | `Err(MissingKeyexpr)`     |
    /// | `0`          | `Some(s)`        | `Ok(s.to_string())`       |
    /// | `id != 0`    | `None`           | `Ok(prefix.clone())` or `Err(UnknownMappingId(id))` |
    /// | `id != 0`    | `Some(tail)`     | `Ok(prefix || tail)` or `Err(UnknownMappingId(id))` |
    ///
    /// The composite-mode concatenation is a plain `String::push_str`
    /// (no `/` separator inserted) because the wire spec embeds the
    /// `/` in either prefix-trailing or suffix-leading position per
    /// the caller's intent — wz mirrors zenoh-pico's
    /// `_z_keyexpr_to_string` which never injects its own separator.
    // R309 — only `send_declare_subscriber` / `send_declare_queryable`
    // R310.5a — always compiled regardless of declare-* feature
    // subset to keep prod and test surfaces identical. The prior
    // `cfg(any(..., test))` shape silently diverged between `cargo
    // build --no-default-features` (helper elided) and `cargo test
    // --no-default-features` (helper visible), which is a refactor
    // hazard. `#[allow(dead_code)]` suppresses the unused-method
    // warning when every caller (`send_declare_subscriber` /
    // `_queryable` / `_token`) is feature-gated off; release-mode
    // dead-code elimination strips the symbol.
    //
    // chunk-5 — promoted to `pub` by the wz-session-core extraction: this
    // is a keyexpr-reconstruction query accessor, the direct sibling of the
    // already-`pub` [`Self::resolve_outbound_mapping`]. When the actions
    // type became the shared session-core SSOT its (id, suffix) -> keyexpr
    // resolution joined the public surface the cross-crate AP tests (the
    // `reconstruct_outbound_keyexpr_shape_table` fine-grained unit test,
    // kept tokio-side per the test_fixtures dev-dep-cycle rationale) and a
    // future MCU resolver reach through the re-exported type.
    #[allow(dead_code)]
    pub fn reconstruct_outbound_keyexpr(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
    ) -> Result<String, SendDeclareError> {
        match (mapping_id, suffix) {
            (0, None) => Err(SendDeclareError::MissingKeyexpr),
            (0, Some(s)) => Ok(s.to_string()),
            (id, None) => self
                .resolve_outbound_mapping(id)
                .ok_or(SendDeclareError::UnknownMappingId(id)),
            (id, Some(tail)) => self
                .resolve_outbound_mapping(id)
                .map(|mut prefix| {
                    prefix.push_str(tail);
                    prefix
                })
                .ok_or(SendDeclareError::UnknownMappingId(id)),
        }
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclSubscriber)` on
    /// the outbound link, retracting a previously declared
    /// subscription (id) on the peer. The peer drops the
    /// `subscriber_id -> keyexpr` entry from its subscriber table;
    /// subsequent matching Pushes will no longer route to this
    /// subscriber (the peer's other subscribers on the same keyexpr
    /// continue to receive).
    ///
    /// R311p — signature-stability per `feedback_signature_stability`
    /// MEMORY anchor. Body cfg-gated on
    /// `all(declare-subscriber, declare-undeclare)`; silent no-op when
    /// either feature is off. Couples with a future-round Subscriber
    /// Drop type-ungating that calls this unconditionally.
    pub fn send_undeclare_subscriber(&self, subscriber_id: u64) {
        #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
        {
            let declare = build_undeclare_subscriber(subscriber_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_declare(declare, /*reliable=*/ true);
            // A4 — drop the matching replay entry (pico
            // `_z_prune_declaration` undeclare-filter on `_id`).
            #[cfg(feature = "session-reconnect")]
            self.prune_declaration(|entry| {
                matches!(entry, CachedDeclaration::Subscriber { subscriber_id: s, .. } if *s == subscriber_id)
            });
        }
        #[cfg(not(all(feature = "declare-subscriber", feature = "declare-undeclare")))]
        let _ = subscriber_id;
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclQueryable)` on
    /// the outbound link, retracting a previously declared queryable
    /// (id) on the peer.
    ///
    /// R311p — signature-stability per `feedback_signature_stability`
    /// MEMORY anchor. Body cfg-gated on
    /// `all(declare-queryable, declare-undeclare)`; silent no-op when
    /// either feature is off. Couples with a future-round Queryable
    /// Drop type-ungating that calls this unconditionally.
    pub fn send_undeclare_queryable(&self, queryable_id: u64) {
        #[cfg(all(feature = "declare-queryable", feature = "declare-undeclare"))]
        {
            let declare = build_undeclare_queryable(queryable_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_declare(declare, /*reliable=*/ true);
            // A4 — drop the matching replay entry (pico
            // `_z_prune_declaration` undeclare-filter on `_id`).
            #[cfg(feature = "session-reconnect")]
            self.prune_declaration(|entry| {
                matches!(entry, CachedDeclaration::Queryable { queryable_id: q, .. } if *q == queryable_id)
            });
        }
        #[cfg(not(all(feature = "declare-queryable", feature = "declare-undeclare")))]
        let _ = queryable_id;
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclToken)` on the
    /// outbound link, retracting a previously declared liveliness
    /// token (id) on the peer.
    ///
    /// R311o — signature-stability per `feedback_signature_stability`
    /// MEMORY anchor. Body cfg-gated on
    /// `all(declare-token, declare-undeclare)`; silent no-op when
    /// either feature is off. Enables `crate::session::LivelinessToken`
    /// `Drop` to call this unconditionally without a matching cfg-gate
    /// at the call site (R311o type-ungating cascade prerequisite).
    pub fn send_undeclare_token(&self, token_id: u64) {
        #[cfg(all(feature = "declare-token", feature = "declare-undeclare"))]
        {
            let declare = build_undeclare_token(token_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_declare(declare, /*reliable=*/ true);
            // A4 — drop the matching replay entry (pico
            // `_z_prune_declaration` undeclare-filter on `_id`).
            #[cfg(feature = "session-reconnect")]
            self.prune_declaration(|entry| {
                matches!(entry, CachedDeclaration::Token { token_id: t, .. } if *t == token_id)
            });
        }
        #[cfg(not(all(feature = "declare-token", feature = "declare-undeclare")))]
        let _ = token_id;
    }

    /// R121i-c — encode + dispatch a `Declare(DeclFinal)` marker on
    /// the outbound link, terminating a declaration sequence.
    /// Reserved for the future Interest/Reply path (R121j+); the
    /// unsolicited DECLARE outbound path that the AP MVP uses today
    /// does not emit DeclFinal, but the action is provided so the
    /// state machine has the dispatch shape ready when Interest
    /// replies need to close a multi-DECLARE reply batch.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// Silent no-op when `declare-final` off (() return — no error
    /// channel; the peer observes a missing DeclFinal which is
    /// already the legal terminal-suppressed shape per the AP MVP
    /// contract, so no observable wire-protocol regression).
    pub fn send_declare_final(&self) {
        #[cfg(feature = "declare-final")]
        {
            let declare = build_declare_final();
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_declare(declare, /*reliable=*/ true);
        }
    }

    /// R279 — encode + dispatch an `Interest` network-message
    /// requesting future + (optionally) current `DeclToken` records
    /// from the peer, restricted to a specific keyexpr. Mirror of
    /// zenoh-pico's `_z_register_liveliness_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:169-198`) emit path,
    /// which calls `_z_n_interest_encode` with `flags = KEYEXPRS |
    /// TOKENS | RESTRICTED | FUTURE [| CURRENT]` (interest.c:204-209).
    ///
    /// Wire shape after the `N_MID_INTEREST` envelope (composes the
    /// outer header + interest_id with the inner `InterestBody`
    /// body_flags byte + R-gated wireexpr):
    ///
    /// ```text
    ///   [Interest.header = N_MID_INTEREST (0x19)
    ///                       | (history ? 0x20 : 0)  // C = CURRENT
    ///                       | 0x40                  // F = FUTURE (always)
    ///                       | (Z extensions = 0 here)]
    ///   VLE(interest_id)
    ///   [InterestBody.header = 0x01 (KE) | 0x08 (TO) | 0x10 (R)
    ///                          | (suffix.is_some() ? 0x20 : 0)  // N
    ///                          | 0x40                            // M (Local)
    ///                          ]
    ///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
    /// ```
    ///
    /// `history = true` instructs the peer to immediately replay the
    /// current matching `DeclToken` set (per zenoh-pico's
    /// `_z_liveliness_subscription_trigger_history` at
    /// `vendor/zenoh-pico/src/net/liveliness.c:133`); after that, the
    /// FUTURE bit keeps the subscription live so subsequent peer
    /// declarations / undeclarations stream in. `history = false`
    /// only registers for future events.
    ///
    /// `keyexpr_mapping_id == 0` with `keyexpr_suffix = Some(s)`
    /// targets a literal keyexpr (RESTRICTED + KE filter). Pure
    /// alias (mapping_id != 0, suffix=None) and composite
    /// (mapping_id != 0, suffix=Some) forms are emitted via the
    /// `Local` wireexpr arm; the `Nonlocal` arm (M=0) for keyexprs
    /// rooted in the peer's mapping table is reserved for a future
    /// `_nonlocal` companion builder mirroring the DECLARE pattern.
    ///
    /// Reliable channel — same SN-window ordering reason as the
    /// DECLARE path: the peer must observe the Interest before any
    /// matching DeclToken / UndeclToken arrives, otherwise the peer's
    /// `_z_interest_process_*` resolves to no-match and the
    /// declaration silently drops.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// Silent no-op when `declare-interest` off; the peer never
    /// observes the Interest emit, which means the liveliness
    /// subscription is silently inactive on this build — caller is
    /// expected to feature-detect before relying on liveliness
    /// notifications. () return — no error channel.
    pub fn send_interest_liveliness_subscriber(
        &self,
        interest_id: u64,
        history: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "declare-interest")]
        {
            let interest = build_interest_liveliness_subscriber(
                interest_id,
                history,
                keyexpr_mapping_id,
                keyexpr_suffix,
            )?;
            self.dispatch_interest(interest, /*reliable=*/ true)?;
            // A4 — record for post-reconnect replay (pico caches the
            // liveliness Interest via `_z_send_declare`,
            // `net/liveliness.c:209`).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::LivelinessSubscriberInterest {
                interest_id,
                history,
                mapping_id: keyexpr_mapping_id,
                suffix: keyexpr_suffix.map(ToString::to_string),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-interest"))]
        {
            let _ = (interest_id, history, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// liveliness-get — encode + dispatch a one-shot CURRENT liveliness
    /// `Interest` (C=1, F=0) requesting the peer's currently-alive token
    /// snapshot for the keyexpr resolved by `(keyexpr_mapping_id,
    /// keyexpr_suffix)`. The peer replies with one `interest_id`-tagged
    /// `Declare(DeclToken)` per matching live token, terminated by an
    /// `interest_id`-tagged `Declare(DeclFinal)`; because FUTURE is clear
    /// the peer does not stream subsequent events (the snapshot is
    /// one-shot). Mirror of [`Self::send_interest_liveliness_subscriber`]
    /// — the requester-side of the same declaration-plane protocol — but
    /// CURRENT-only.
    ///
    /// Reliable channel — same SN-window ordering reason as the
    /// subscriber Interest: the peer must observe the Interest before its
    /// `_z_interest_process_*` resolves the matching token set, otherwise
    /// the snapshot silently drops.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable. Returns
    /// `Err(FeatureDisabled)` when `declare-interest` is off (the peer
    /// never observes the Interest, so the get cannot complete).
    pub fn send_interest_liveliness_get(
        &self,
        interest_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "declare-interest")]
        {
            let interest =
                build_interest_liveliness_get(interest_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_interest(interest, /*reliable=*/ true)?;
            // A4 — record for post-reconnect replay (pico caches the
            // one-shot CURRENT Interest via `_z_send_declare`,
            // `net/liveliness.c:355`; never pruned there either — the
            // post-reconnect replay is a harmless re-snapshot whose
            // replies find no pending query).
            #[cfg(feature = "session-reconnect")]
            self.cache_declaration(CachedDeclaration::LivelinessGetInterest {
                interest_id,
                mapping_id: keyexpr_mapping_id,
                suffix: keyexpr_suffix.map(ToString::to_string),
            });
            Ok(())
        }
        #[cfg(not(feature = "declare-interest"))]
        {
            let _ = (interest_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R279 — encode + dispatch an `Interest(Final)` (no C, no F)
    /// network-message terminating a previously emitted Interest
    /// stream. Mirror of zenoh-pico's
    /// `_z_undeclare_liveliness_subscriber` at
    /// `vendor/zenoh-pico/src/net/liveliness.c:232-243`, which calls
    /// `_z_n_interest_encode` with `is_final = true`.
    ///
    /// Wire shape: two bytes — `[N_MID_INTEREST, VLE(interest_id)]`.
    /// No inner body, no extensions (the `_Z_INTEREST_NOT_FINAL_MASK`
    /// gate at `vendor/zenoh-pico/include/zenoh-pico/protocol/
    /// definitions/interest.h:35` — C||F — is clear for the final
    /// form, suppressing the body embed per
    /// `interest_body.scxml::body::present-if`).
    ///
    /// Reliable channel — the peer's `_z_interest_process_interest_final`
    /// (`vendor/zenoh-pico/src/session/interest.c:524`) removes the
    /// matching entry from its `_z_session_t._remote_interests` table.
    /// An unreliable Final would race against in-flight DeclToken
    /// replays and risk leaving a stale interest on the peer side.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// Silent no-op when `declare-interest` off.
    pub fn send_interest_final(&self, interest_id: u64) {
        #[cfg(feature = "declare-interest")]
        {
            let interest = build_interest_final(interest_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_interest(interest, /*reliable=*/ true);
            // A4 — drop the matching replay entry. pico's interest prune
            // filter matches any cached `_Z_N_INTEREST` by `_id`
            // (`_z_cache_declaration_undeclare_filter_interest`), so both
            // the subscriber and get Interest forms prune here.
            #[cfg(feature = "session-reconnect")]
            self.prune_declaration(|entry| entry.interest_id() == Some(interest_id));
        }
        #[cfg(not(feature = "declare-interest"))]
        let _ = interest_id;
    }

    /// R121j-1 — encode + dispatch a `Request(Query)` on the outbound
    /// link, sending a query to the peer for the keyexpr resolved by
    /// `(keyexpr_mapping_id, keyexpr_suffix)`. The peer's inbound
    /// dispatch (zenoh-pico's `_z_session_recv_request` ->
    /// `_z_trigger_queryables`) routes the query into every queryable
    /// callback registered for a matching keyexpr; each callback's
    /// reply is delivered back to this peer as a `Response(Reply)`
    /// carrying the same `rid`. Termination is signaled by the peer
    /// emitting `ResponseFinal` with this `rid`.
    ///
    /// AP MVP minimal shape: no consolidation, no parameters, no
    /// Query-level extensions, no Request-level extensions. The
    /// builder doc describes the layered helpers that lift those
    /// constraints when needed.
    ///
    /// Reliable channel — the peer must observe the Query and any
    /// out-of-order Reply / ResponseFinal must not race ahead of the
    /// Request itself. SN-window ordering on the reliable channel
    /// gives this guarantee; an unreliable Query could silently drop
    /// and leave the local z_get future hung indefinitely.
    /// R311j signature-stability retrofit per `feedback_signature_stability`
    /// MEMORY note — body cfg-gated on `codec-request`; silent no-op
    /// when the feature is off. The matching peer's z_get future hangs
    /// until its per-call timeout fires (documented minus-codec-request
    /// contract).
    pub fn send_request_query(
        &self,
        rid: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-request")]
        {
            let request = build_request_query(rid, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_request(request, /*reliable=*/ true)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-request"))]
        {
            let _ = (rid, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R240 — metadata-bearing counterpart of [`Self::send_request_query`].
    /// Threads the caller-supplied [`QueryMetadata`] bundle through
    /// the layered [`RequestQueryBuilder`] so the outbound
    /// `Request(Query)` carries (when set):
    ///
    /// * `meta.target` → Q_T flag + request_target ext entry
    ///   (`vendor/zenoh-pico/src/protocol/codec/network.c:140`)
    /// * `meta.consolidation` → Q_C flag + consolidation wire byte
    ///   (`vendor/zenoh-pico/src/protocol/codec/message.c:402-412`)
    /// * `meta.attachment` → Query-level attachment ext (id=0x03 ZBUF)
    /// * `meta.timeout_ms` → Request-level timeout ext (gated by the
    ///   `_z_n_msg_request_needed_exts._ext_timeout_ms != 0`
    ///   predicate at `network.c`).
    ///
    /// Empty slots elide the corresponding wire byte / ext so a
    /// `meta = QueryMetadata::default()` call produces the same wire
    /// frame as [`Self::send_request_query`]. Mirrors R233's
    /// [`Self::send_push_with_meta_literal`] pattern on the publish
    /// side — the queryable / z_get split now has matching
    /// metadata-bearing surfaces.
    ///
    /// Same reliability contract as the no-metadata form: hard-coded
    /// `reliable=true` per zenoh-pico's reliable-channel guarantee
    /// for the Query / Reply / Final correlation chain.
    /// R311j signature-stability retrofit — body cfg, signature stable.
    /// Silent no-op when `codec-request` off.
    pub fn send_request_query_with_meta(
        &self,
        rid: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        meta: &QueryMetadata,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-request")]
        {
            let mut builder = RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix);
            if let Some(target) = meta.target {
                builder = builder.request_target(target);
            }
            if let Some(consolidation) = meta.consolidation {
                builder = builder.consolidation(consolidation);
            }
            // Query source-info ext threading — gated on
            // `query-source-info` (the builder's `query_source_info`
            // setter gates with it). Ordered before attachment in the
            // builder; `build()` emits them in zenoh-pico Query body
            // order (source_info 0x01 → attachment 0x05) regardless of
            // setter call order.
            #[cfg(feature = "query-source-info")]
            if let Some(ref source_info) = meta.source_info {
                builder = builder.query_source_info(source_info.clone());
            }
            // Query attachment ext threading — gated on `query-attachment`
            // (the builder's `query_attachment` setter gates with it).
            #[cfg(feature = "query-attachment")]
            if let Some(attachment) = meta.attachment.as_deref() {
                // RequestQueryBuilder::query_attachment panics on
                // empty input (zenoh-pico's
                // `_z_n_msg_query_needed_exts` clears the ext on
                // len=0). The QueryMetadata caller's contract is
                // "attachment = Some(empty) means clear the ext";
                // honour that here without panicking by skipping
                // the attach call when the inner slice is empty.
                if !attachment.is_empty() {
                    builder = builder.query_attachment(attachment);
                }
            }
            if meta.timeout_ms != 0 {
                builder = builder.request_timeout_ms(meta.timeout_ms as u64);
            }
            let request = builder.build()?;
            self.dispatch_request(request, /*reliable=*/ true)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-request"))]
        {
            let _ = (rid, keyexpr_mapping_id, keyexpr_suffix, meta);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R121j-2 — encode + dispatch a `ResponseFinal(request_id)` on
    /// the outbound link, signaling that no more `Response(Reply)`
    /// messages will follow for `request_id`. The peer that issued
    /// the matching `Request(Query)` resolves its `z_get` future on
    /// receipt of this message (zenoh-pico's
    /// `_z_session_recv_response_final` -> `_z_pending_query_pop`).
    ///
    /// Always reliable — losing a ResponseFinal would leave the
    /// requesting peer's z_get future hung waiting for sequence
    /// termination. This is enforced by hard-coding `reliable=true`
    /// at the action layer; the helper builder accepts a flag for
    /// the fuzz / negative-test path but the production action does
    /// not expose it.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable.
    /// Silent no-op when `codec-response-final` off; the matching
    /// peer's `z_get` future hangs until its timeout fires, which
    /// is the documented minus-codec-response-final contract — the
    /// build that disables this codec accepts the hang behaviour
    /// in exchange for binary-size elision. () return — no error
    /// channel; this no-op cannot be elevated to a typed Err
    /// without growing a public error enum for an action that
    /// has historically been a fire-and-forget primitive.
    pub fn send_response_final(&self, request_id: u64) {
        #[cfg(feature = "codec-response-final")]
        {
            let response_final = build_response_final(request_id);
            // F2 — this surface has no error channel; a transport-down
            // reject drops the emit exactly as the dead link would.
            let _ = self.dispatch_response_final(response_final, /*reliable=*/ true);
        }
        #[cfg(not(feature = "codec-response-final"))]
        let _ = request_id;
    }

    /// R121j-5c-e2e — encode + dispatch an already-constructed
    /// [`Response`] on the outbound link. The Response is typically
    /// built upstream by [`ResponseReplyBuilder`] /
    /// [`ResponseErrBuilder`] (or composed from a
    /// `crate::query::QueryReply::into_response` call drained out of
    /// `crate::query::QueryableRegistry::dispatch_messages`).
    ///
    /// Always reliable — Reply data delivery loss would leave the
    /// requesting peer's `z_get` future waiting for a reply that never
    /// arrives, and then for the matching `ResponseFinal` that the
    /// queryable never re-emits (because from its perspective the
    /// reply was sent). Mirrors the [`send_response_final`] reliability
    /// choice. The lower-level [`encode_frame_with_response`] helper
    /// still accepts a `reliable` flag for fuzz / negative-test paths,
    /// but the production action layer pins it.
    ///
    /// Owns the `Response` so the caller can drain a `Vec<QueryReply>`
    /// via `.into_iter().map(QueryReply::into_response)` without
    /// intermediate clones. The dispatch path is:
    ///
    /// ```text
    /// QueryableRegistry.dispatch_messages(.., &mut pending_replies, &mut pending_final_rids);
    /// for reply in pending_replies.drain(..) { actions.send_response(reply.into_response()); }
    /// for rid   in pending_final_rids.drain(..) { actions.send_response_final(rid); }
    /// ```
    ///
    /// R311k — gated on `codec-response` (principled exemption from
    /// signature-stability sweep per `feedback_signature_stability`:
    /// arg type `Response` is itself feature-gated, so signature
    /// cannot stay stable without un-gating the type — deferred to
    /// R267 Session<R,T> reparam-adjacent architectural cascade).
    #[cfg(feature = "codec-response")]
    pub fn send_response(&self, response: ResponseOwned) {
        // F2 — this surface has no error channel; a transport-down
        // reject drops the emit exactly as the dead link would.
        let _ = self.dispatch_response(response, /*reliable=*/ true);
    }

    /// R284 — encode + dispatch a session-layer `Close` frame
    /// (`T_MID_CLOSE` with `_Z_FLAG_T_CLOSE_S` for session-close
    /// semantics, body carries the single-byte reason discriminator).
    /// Rust-side counterpart of the Lua-bound
    /// `send_close_frame_with_reason` action, taking `reason`
    /// explicitly rather than reading it from
    /// [`ActionTrace::close_reason`] — the caller is outside the
    /// scxml FSM and the trace slot would not have been pre-set by
    /// `set_close_reason_*` actions.
    ///
    /// Use case: signal-cancellation paths (SIGTERM / SIGINT) that
    /// exit `drive_session_until_terminal` without driving the FSM
    /// through its normal `Closing` state. Calling this primitive
    /// from such a path lets the peer observe an explicit graceful
    /// `Close` frame before the connection EOF, matching the
    /// zenoh-pico `_z_send_close` shape rather than a bare TCP RST.
    /// Mirrors `vendor/zenoh-pico/src/transport/unicast/transport.c`
    /// graceful-close path.
    ///
    /// Bumps `ActionTrace::send_close_frame_with_reason` for trace
    /// symmetry with the Lua-bound action — tests counting Close
    /// emits across script + Rust paths see the unified count.
    ///
    /// Independent of FSM state: this is a wire-side primitive that
    /// emits regardless of [`Self::is_established`]. A caller wanting
    /// state-conditional emit (e.g. only after Established) should
    /// gate at its own layer.
    ///
    /// R311g signature-stability retrofit — method signature stays
    /// `pub fn send_close_with_reason(&self, reason: CloseReason)`
    /// across feature states; only the body branches on `codec-close`.
    /// Consumers (e.g. `wz-ap-demo`'s typestate teardown) call this
    /// unconditionally without mirroring a `codec-close` feature in
    /// their own manifest. When the feature is off the body silently
    /// no-ops; the peer observes an abrupt link drop (TCP RST / EOF)
    /// instead of the MID 0x03 + reason byte, which is the documented
    /// minus-codec-close contract. This pattern is the textbook fix for
    /// the R311c regression that deleted the method signature behind
    /// `#[cfg(feature = "codec-close")]` and forced ap-demo to carry a
    /// consumer-side cfg mirror; future codec gates (R311h..R311l)
    /// follow the same body-cfg + stable-signature shape.
    pub fn send_close_with_reason(&self, reason: CloseReason) {
        #[cfg(feature = "codec-close")]
        {
            // R311jp — transport-message order parity (zenoh-pico tx.c
            // `_z_transport_tx_send_t_msg_inner` flushes an active batch
            // before encoding any t_msg): drain the open batch frame so
            // CLOSE never overtakes already-batched data frames on the
            // wire. Any future unicast t_msg sender (e.g. a KeepAlive
            // worker emit) must take the same pre-drain.
            #[cfg(feature = "transport-batching")]
            self.flush_open_batch();
            R::with_mutex_mut(&self.trace, |t| t.send_close_frame_with_reason += 1);
            let bytes = encode_close(reason as u8);
            self.link_driver()
                .send_blocking(&bytes, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-close"))]
        let _ = reason;
    }

    /// A4 — append one replay entry to the declaration cache. The
    /// success-only call sites (after each `dispatch_declare` /
    /// `dispatch_interest` in the typed emit methods) mirror pico's
    /// `_z_cache_declaration` running only on `_Z_RES_OK` from
    /// `_z_send_n_msg` (`src/net/primitives.c:56-60`).
    #[cfg(feature = "session-reconnect")]
    fn cache_declaration(&self, entry: CachedDeclaration) {
        R::with_mutex_mut(&self.declaration_cache, |cache| cache.push(entry));
    }

    /// A4 — remove the FIRST cache entry matching `pred`. First-match
    /// (not retain-all) mirrors pico's
    /// `_z_network_message_slist_drop_first_filter` in
    /// `_z_prune_declaration`: one undeclare retracts one declare, so
    /// re-declared ids keep their later entries.
    #[cfg(feature = "session-reconnect")]
    fn prune_declaration(&self, pred: impl Fn(&CachedDeclaration) -> bool) {
        R::with_mutex_mut(&self.declaration_cache, |cache| {
            if let Some(pos) = cache.iter().position(pred) {
                cache.remove(pos);
            }
        });
    }

    /// F3 — terminated-get prune: drop exactly the
    /// `LivelinessGetInterest` cache entry for `interest_id`
    /// (variant-precise — fresh-allocated ids cannot collide across
    /// kinds, but the filter encodes the intent: a live subscriber
    /// Interest must never be collateral). The requester emits no
    /// interest-FINAL for a one-shot get, so this drain — fed by the
    /// registry's staged DeclFinal / timeout terminations through the
    /// observer's `flush_pending` and the sweep tickers — is the
    /// entry's ONLY prune (zenoh-pico keeps the stale entry and replays
    /// it on reconnect; wz closes the leak). The `ResponseSink` trait
    /// method delegates here (inherent-twin shape). No-op without
    /// `session-reconnect` (no cache exists) per R311g1
    /// signature-stability.
    #[cfg(feature = "liveliness-get")]
    pub fn prune_liveliness_get_interest(&self, interest_id: u64) {
        #[cfg(feature = "session-reconnect")]
        self.prune_declaration(|entry| {
            matches!(
                entry,
                CachedDeclaration::LivelinessGetInterest { interest_id: id, .. }
                    if *id == interest_id
            )
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = interest_id;
    }

    /// A4 — snapshot of the declaration cache, in recorded (replay)
    /// order. Test/diagnostic surface; the replay itself goes through
    /// [`Self::replay_declarations`].
    ///
    /// R311g1 — signature-stability: always present; returns the empty
    /// vec when `session-reconnect` is off (no cache storage exists).
    pub fn declaration_cache_snapshot(&self) -> Vec<CachedDeclaration> {
        #[cfg(feature = "session-reconnect")]
        {
            R::with_mutex_mut(&self.declaration_cache, |cache| cache.clone())
        }
        #[cfg(not(feature = "session-reconnect"))]
        {
            Vec::new()
        }
    }

    /// A4 — reset the handshake-scoped half of the bundle so a fresh
    /// open-handshake can run over a replacement link. The wz mirror of
    /// pico's reopen creating a NEW `_z_transport_t` while
    /// `_z_session_t` survives (`_z_client_reopen_task_fn` re-running
    /// `_z_open`): wz's per-transport state lives on this bundle, so it
    /// is cleared field-by-field instead of being dropped wholesale.
    ///
    /// Cleared (per-transport): `inbound_cookie`,
    /// `inbound_opensyn_cookie`, `last_inbound_keepalive_at`,
    /// `established_at` (so [`Self::is_established`] reads `false` until
    /// the re-handshake completes), `inbound_peer_zid`,
    /// `inbound_peer_init_caps`, the RX SN gate (`rx_sn`, re-seeded by
    /// the reopen handshake's OpenSyn/OpenAck), the open batching window
    /// (`transport-batching`), and `outbound_frame_sn` (re-seeded to
    /// `params.initial_sn`, the value the re-handshake's OpenSyn
    /// announces — pico mints a fresh random initial SN per `_z_open`;
    /// wz reuses the params seed, equivalent because the peer adopts
    /// whatever the OpenSyn carries).
    ///
    /// Preserved (session-scoped): the declaration cache (the replay
    /// source), `outbound_mappings`, every `next_outbound_*` id
    /// allocator (handles hold issued ids across the reconnect), the
    /// ext-chain staging slots (outbound configuration, not peer
    /// state), and the action trace (cumulative diagnostics).
    ///
    /// R311g1 — signature-stability: silent no-op when
    /// `session-reconnect` is off.
    pub fn reset_for_reopen(&self) {
        #[cfg(feature = "session-reconnect")]
        {
            // F2 — close the data-send gate for the whole re-dial +
            // re-handshake window (release_link already closed it when the
            // FSM saw the loss; this also covers a reset without a prior
            // terminal). record_established_at re-opens it.
            R::with_mutex_mut(&self.transport_available, |g| *g = false);
            R::with_mutex_mut(&self.inbound_cookie, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_opensyn_cookie, |slot| *slot = None);
            R::with_mutex_mut(&self.last_inbound_keepalive_at, |slot| *slot = None);
            R::with_mutex_mut(&self.established_at, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_peer_zid, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot = None);
            // R311ke — the RX SN gate is handshake-scoped: the reopen
            // handshake's OpenSyn/OpenAck re-seeds both channels.
            R::with_mutex_mut(&self.rx_sn, |s| *s = crate::sn::RxSn::default());
            R::with_mutex_mut(&self.batch_tx, |batch| *batch = BatchTx::default());
            // SeqCst pairs with `next_outbound_frame_sn`'s fetch_add — the
            // reset must not reorder against a straggling in-flight mint.
            self.outbound_frame_sn
                .store(self.params.initial_sn, Ordering::SeqCst);
        }
    }

    /// A4 — re-emit every cached declaration, in recorded order, onto
    /// the (replacement) link. pico `_z_client_reopen_task_fn`'s
    /// declaration-cache walk (`src/net/session.c:255-270`): after the
    /// re-handshake reaches Established, the peer's declaration tables
    /// are empty, so the recorded `Declare` / `Interest` emits are
    /// replayed to rebuild them. Recorded order matters — an aliased
    /// declare replays after the `DeclKexpr` that registered its
    /// `mapping_id`.
    ///
    /// Re-runs the same builders as the original emits and routes
    /// through the same `dispatch_declare` / `dispatch_interest`
    /// chokepoint (fresh frame SN per R311jq — pico re-sends the cached
    /// *network* message through `_z_send_n_msg`, which also mints a
    /// fresh transport SN). Deliberately does NOT re-run the caching
    /// hooks (the entries are already cached) nor the R300 outbound
    /// gates / mapping-table insert (both ran at original declare time;
    /// the mapping table survives [`Self::reset_for_reopen`]).
    ///
    /// Returns the number of replayed entries. `Err` wraps a builder
    /// reject — an invariant breach for arguments that already built
    /// once (see [`ReplayDeclarationsError`]).
    ///
    /// R311g1 — signature-stability: `Err(FeatureDisabled)` when
    /// `session-reconnect` is off.
    pub fn replay_declarations(&self) -> Result<usize, ReplayDeclarationsError> {
        #[cfg(feature = "session-reconnect")]
        {
            let snapshot = R::with_mutex_mut(&self.declaration_cache, |cache| cache.clone());
            let count = snapshot.len();
            for entry in snapshot {
                self.replay_one(entry)?;
            }
            Ok(count)
        }
        #[cfg(not(feature = "session-reconnect"))]
        {
            Err(ReplayDeclarationsError::FeatureDisabled)
        }
    }

    /// A4 — replay one cache entry. Each arm re-runs the original
    /// emit's builder + dispatch under that emit's feature gate; the
    /// gated-off arms are unreachable by construction (the append hook
    /// that records a variant lives inside the same feature gate as the
    /// emit that replays it), kept as explicit no-ops so the match
    /// stays total across feature states.
    #[cfg(feature = "session-reconnect")]
    fn replay_one(&self, entry: CachedDeclaration) -> Result<(), ReplayDeclarationsError> {
        match entry {
            CachedDeclaration::Keyexpr { mapping_id, suffix } => {
                #[cfg(feature = "declare-keyexpr")]
                {
                    let declare = build_declare_kexpr(mapping_id, &suffix)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    self.dispatch_declare(declare, /*reliable=*/ true)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                }
                #[cfg(not(feature = "declare-keyexpr"))]
                let _ = (mapping_id, suffix);
            }
            CachedDeclaration::Subscriber {
                subscriber_id,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-subscriber")]
                {
                    let declare =
                        build_declare_subscriber(subscriber_id, mapping_id, suffix.as_deref())
                            .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    self.dispatch_declare(declare, /*reliable=*/ true)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                }
                #[cfg(not(feature = "declare-subscriber"))]
                let _ = (subscriber_id, mapping_id, suffix);
            }
            CachedDeclaration::Queryable {
                queryable_id,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-queryable")]
                {
                    let declare =
                        build_declare_queryable(queryable_id, mapping_id, suffix.as_deref())
                            .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    self.dispatch_declare(declare, /*reliable=*/ true)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                }
                #[cfg(not(feature = "declare-queryable"))]
                let _ = (queryable_id, mapping_id, suffix);
            }
            CachedDeclaration::Token {
                token_id,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-token")]
                {
                    let declare = build_declare_token(token_id, mapping_id, suffix.as_deref())
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    self.dispatch_declare(declare, /*reliable=*/ true)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                }
                #[cfg(not(feature = "declare-token"))]
                let _ = (token_id, mapping_id, suffix);
            }
            CachedDeclaration::LivelinessSubscriberInterest {
                interest_id,
                history,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-interest")]
                {
                    let interest = build_interest_liveliness_subscriber(
                        interest_id,
                        history,
                        mapping_id,
                        suffix.as_deref(),
                    )
                    .map_err(|e| ReplayDeclarationsError::Interest(e.into()))?;
                    self.dispatch_interest(interest, /*reliable=*/ true)
                        .map_err(ReplayDeclarationsError::Interest)?;
                }
                #[cfg(not(feature = "declare-interest"))]
                let _ = (interest_id, history, mapping_id, suffix);
            }
            CachedDeclaration::LivelinessGetInterest {
                interest_id,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-interest")]
                {
                    let interest =
                        build_interest_liveliness_get(interest_id, mapping_id, suffix.as_deref())
                            .map_err(|e| ReplayDeclarationsError::Interest(e.into()))?;
                    self.dispatch_interest(interest, /*reliable=*/ true)
                        .map_err(ReplayDeclarationsError::Interest)?;
                }
                #[cfg(not(feature = "declare-interest"))]
                let _ = (interest_id, mapping_id, suffix);
            }
        }
        Ok(())
    }
}

/// R311il — thin newtype that carries the generated
/// [`SessionFsmUnicastActionsTrait`] impl for the
/// [`crate::session_fsm_unicast::SessionFsmUnicastPolicy`] to own by
/// value. Wraps a clone of the caller's
/// [`R::ActionsHandle<T>`](crate::link::SessionRuntime::ActionsHandle) (the
/// per-profile shared bundle handle — tokio `Arc`, lwIP `Rc`) so the 18
/// native actions mutate the same shared state (trace / staging slots /
/// link driver) the caller reads back; the orphan rule forbids impl'ing the
/// foreign trait on the bare handle directly, so the local newtype carries
/// the impl. The methods reach the bundle through the handle's `Deref`.
///
/// Engine-free successor of the R79 Lua binding
/// (`install_session_actions` + the `register_*` family): the generated
/// trait replaces the per-name Lua closure registration, so no
/// `IScriptEngine` / `LuaEngine` is involved and the session path no
/// longer pulls `sce-rust-lua` — the second half of the runtime-schism
/// resolution after R311ik did the same for scouting.
pub struct SessionActionsBinding<R: SessionRuntime, T: TimeSource> {
    inner: R::ActionsHandle<T>,
}

impl<R: SessionRuntime, T: TimeSource> SessionActionsBinding<R, T> {
    /// Wrap a clone of the caller's
    /// [`R::ActionsHandle<T>`](crate::link::SessionRuntime::ActionsHandle) so
    /// the generated [`SessionFsmUnicastActionsTrait`] dispatches its 18
    /// actions against the shared state the caller reads back. Production
    /// callers reach this through `new_session_engine`; it is `pub` so a
    /// test can drive an individual action method directly (the
    /// engine-free successor of the retired `dispatch_script` shim).
    pub fn new(actions: R::ActionsHandle<T>) -> Self {
        Self { inner: actions }
    }
}

/// R311il — the 18 `session_fsm_unicast.scxml` `<sce:action>` operations
/// as native host-trait methods, replacing the R79 Lua-bound
/// `register_*` closures. Each body is the verbatim closure body of the
/// retired `bind_unit(lua, "<name>", actions, |a| { … })` registration,
/// with `a = &self.inner`.
///
/// Generic over `R: SessionRuntime` (Stage 2b-②): the actions reach the
/// runtime-owned `R::Mutex` staging slots through `R::with_mutex_mut` and
/// the link write seam through the inherent
/// [`SessionLinkActions::link_driver`] accessor — no profile-specific
/// `.lock()` or `R::LinkSink` access leaks into the method bodies.
/// `transport-unicast` is AP-hosted today, so `TokioRuntime` is the only
/// live `R`; the generic form is the move-enabling shape for the pending
/// `wz-session-core` hoist (the lwIP MCU profile binds the same trait).
///
/// The wire-emit actions stay gated on their codec / role feature
/// (`send_init_syn` etc.); cfg-off the method body is a silent no-op —
/// the FSM advances but emits no bytes, exactly the documented
/// minus-codec contract of [`SessionLinkActions::send_close_with_reason`].
/// A subset build that elides a codec genuinely cannot dial that leg, and
/// the host handshake deadline-sweep (see `drive_session_until_terminal`)
/// turns the resulting no-emit into an honest `*.timeout -> Closing`
/// rather than an indefinite hang.
impl<R: SessionRuntime, T: TimeSource> SessionFsmUnicastActionsTrait
    for SessionActionsBinding<R, T>
{
    fn link_driver_open(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |t| t.link_driver_open += 1);
        a.link_driver().open_blocking();
    }

    fn send_init_syn(&mut self) {
        // R311cd — session-unicast-open gates the open-side (Initiator)
        // wire emit. cfg-off: no-op (acceptor-only deploy cannot
        // outbound-dial; the SentInitSyn init_ack deadline then closes
        // the stalled handshake).
        #[cfg(all(feature = "codec-init-body", feature = "session-unicast-open"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_init_syn += 1);
            let bytes = a
                .encode_init_with_role(
                    /*is_ack=*/ false,
                    /*cookie_override=*/ None,
                    ExtChainRole::InitSyn,
                )
                .expect("InitSyn zid/cookie are protocol-bounded (zid 1..=16, no cookie on Syn)");
            a.link_driver().send_blocking(&bytes, Reliability::Reliable);
        }
    }

    fn send_open_syn(&mut self) {
        #[cfg(all(feature = "codec-open-body", feature = "session-unicast-open"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_open_syn += 1);
            // RFC §5.M echo contract: prefer the cookie captured from a
            // peer InitAck via handle_inbound; fall back to params.cookie
            // for tests that drive OpenSyn without an inbound parse cycle.
            // Cookie cloned out of the slot first — `encode_open_with_role`
            // re-acquires the ext-chain mutex, and a per-profile mutex is
            // non-reentrant (lwIP critical_section), so the slot guard must
            // drop before the encode call (2b-① reentrancy discipline).
            let cookie_override = R::with_mutex_mut(&a.inbound_cookie, |c| c.clone());
            let bytes = a
                .encode_open_with_role(
                    /*is_ack=*/ false,
                    cookie_override.as_deref(),
                    ExtChainRole::OpenSyn,
                )
                .expect("OpenSyn cookie echo is decode-bounded (peer InitAck cookie <= codec cap)");
            a.link_driver().send_blocking(&bytes, Reliability::Reliable);
        }
    }

    fn send_init_ack_with_cookie(&mut self) {
        // R311cd — session-unicast-accept gates the accept-side (Acceptor)
        // wire emit. cfg-off: no-op (initiator-only deploy cannot listen).
        #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_init_ack_with_cookie += 1);
            // R86 — Accepting-side cookie binding per RFC §5.M
            // anti-amplification. If the inbound InitSyn already arrived
            // (`inbound_peer_zid` slot populated by `handle_inbound`),
            // mint a fresh cookie via HMAC-SHA256(cookie_signing_key,
            // peer_zid)[..16] and pass it as the encode override; the
            // cookie is now bound to the specific peer's claimed
            // identity, not a deploy-static value. Falls back to
            // `params.cookie` verbatim if no peer_zid has been observed.
            // Cookie minted out of the slot first — `encode_init_with_role`
            // re-acquires `inbound_peer_init_caps` + the ext-chain mutex, so
            // the `inbound_peer_zid` guard must drop before the encode call
            // (non-reentrant per-profile mutex; 2b-① reentrancy discipline).
            let cookie_hmac: Option<Vec<u8>> = R::with_mutex_mut(&a.inbound_peer_zid, |slot| {
                slot.as_ref().map(|peer_zid| {
                    generate_cookie_hmac_sha256(&a.params.cookie_signing_key, peer_zid)
                })
            });
            let bytes = a
                .encode_init_with_role(
                    /*is_ack=*/ true,
                    cookie_hmac.as_deref(),
                    ExtChainRole::InitAck,
                )
                .expect("InitAck cookie is HMAC-SHA256[..16] (16 bytes, within codec cap)");
            a.link_driver().send_blocking(&bytes, Reliability::Reliable);
        }
    }

    fn send_open_ack(&mut self) {
        #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_open_ack += 1);
            // Accepting side OpenAck: cookie is consumed by the time we
            // get here (it travelled inbound on OpenSyn and was already
            // MAC-verified); the OpenAck shape omits it (parent.A=1
            // suppresses the cookie field per transport.c:300-302).
            let bytes = a
                .encode_open_with_role(
                    /*is_ack=*/ true,
                    /*cookie_override=*/ None,
                    ExtChainRole::OpenAck,
                )
                .expect("OpenAck omits the cookie field (A=1); only zid 1..=16 is bounded-copied");
            a.link_driver().send_blocking(&bytes, Reliability::Reliable);
        }
    }

    fn send_close_frame_with_reason(&mut self) {
        #[cfg(feature = "codec-close")]
        {
            let a = &self.inner;
            // Single trace lock — read the staged close reason, then bump
            // the emit counter (read-then-increment preserves the original
            // two-statement field-access order).
            let reason = R::with_mutex_mut(&a.trace, |t| {
                let reason = t.close_reason as u8;
                t.send_close_frame_with_reason += 1;
                reason
            });
            let bytes = encode_close(reason);
            a.link_driver().send_blocking(&bytes, Reliability::Reliable);
        }
    }

    fn release_link(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |t| t.release_link += 1);
        // F2 — the link is going away: close the data-send gate so a
        // straggling send rejects typed instead of racing the teardown.
        R::with_mutex_mut(&a.transport_available, |g| *g = false);
        a.link_driver().close_blocking();
    }

    fn enable_rx_tx_regions(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |t| t.enable_rx_tx_regions += 1);
    }

    fn record_established_at(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |t| t.record_established_at += 1);
        // R294 — `a.clock.now_monotonic_ms()` reads the shared monotonic
        // clock (same epoch as last_inbound_keepalive_at +
        // drive_session_until_terminal) so the lease comparator's u64
        // subtract stays on one scale. Read outside the slot closure.
        let now = a.clock.now_monotonic_ms();
        R::with_mutex_mut(&a.established_at, |slot| *slot = Some(now));
        // F2 — Established (re-)entry re-opens the data-send gate (the
        // supervisor replays cached declarations right after this fires).
        R::with_mutex_mut(&a.transport_available, |g| *g = true);
    }

    fn start_lease_monitor(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |t| t.start_lease_monitor += 1);
    }

    fn stop_lease_monitor(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |t| t.stop_lease_monitor += 1);
    }

    fn start_keepalive_worker(&mut self) {
        // R311cb — transport-keepalive gates the keepalive worker. cfg-off:
        // no-op (the FSM cannot enter the lease-monitored Established
        // sub-region's keepalive cadence). Wire-level KeepAlive parse is a
        // separate axis (codec-keep-alive).
        #[cfg(feature = "transport-keepalive")]
        {
            R::with_mutex_mut(&self.inner.trace, |t| t.start_keepalive_worker += 1);
        }
    }

    fn stop_keepalive_worker(&mut self) {
        #[cfg(feature = "transport-keepalive")]
        {
            R::with_mutex_mut(&self.inner.trace, |t| t.stop_keepalive_worker += 1);
        }
    }

    fn free_pool_slots(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |t| t.free_pool_slots += 1);
    }

    fn set_close_reason_generic(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| {
            trace.set_close_reason_count += 1;
            trace.close_reason = CloseReason::Generic;
        });
    }

    fn set_close_reason_invalid(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| {
            trace.set_close_reason_count += 1;
            trace.close_reason = CloseReason::Invalid;
        });
    }

    fn set_close_reason_expired(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| {
            trace.set_close_reason_count += 1;
            trace.close_reason = CloseReason::Expired;
        });
    }

    fn set_close_reason_unresponsive(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| {
            trace.set_close_reason_count += 1;
            trace.close_reason = CloseReason::Unresponsive;
        });
    }
}

/// R311il — accept-side admission guards (§2.7), evaluated by the host
/// dispatcher (`poll_and_dispatch_one`) before it injects an
/// `InitSynReceived` / `OpenSynReceived` event into the engine-free FSM.
///
/// The three caps depend on HOST state (the cookie HMAC + the half-open
/// table + the token bucket), not on the triggering event's wire payload,
/// so they cannot be native `cond=` guards in the statechart; the
/// dispatcher PRE-CLASSIFIES, injecting the event only when admission
/// passes and dropping silently otherwise (no Close frame —
/// anti-amplification per the §2.7 trust-class matrix). Engine-free
/// successors of the retired R89 `register_guard_fns` Lua bindings.
///
/// Generic over `R: SessionRuntime` (Stage 2c): the guard reads the
/// `R::Mutex` staging slots through `R::with_mutex_mut`; `transport-unicast`
/// is AP-hosted today, so `TokioRuntime` is the only live `R`.
impl<R: SessionRuntime, T: TimeSource> SessionLinkActions<R, T> {
    /// R57 placeholder constant (`true`) pending the half-open cap-quota
    /// implementation round. Kept as a named method (not inlined as `true`
    /// in the dispatcher) so the admission structure stays explicit and
    /// the future quota check has a single edit point.
    pub fn half_open_cap_available(&self) -> bool {
        true
    }

    /// R57 placeholder constant (`true`) pending the per-source
    /// token-bucket implementation round.
    pub fn accept_rate_token(&self) -> bool {
        true
    }

    /// R89 — the inbound half of R86's outbound cookie binding. The
    /// Accepting side stored `peer_zid` on InitSyn arrival
    /// (`inbound_peer_zid` slot) and minted a cookie via
    /// HMAC-SHA256(cookie_signing_key, peer_zid)[..16] on InitAck send
    /// (`send_init_ack_with_cookie`). The Initiator echoes that cookie
    /// verbatim on OpenSyn; here we re-compute the expected HMAC and
    /// compare against the captured inbound OpenSyn cookie
    /// (`inbound_opensyn_cookie` slot). Mismatch -> `false` -> the
    /// dispatcher drops the `OpenSynReceived` event so the FSM stays at
    /// SentInitAck instead of advancing to SentOpenAck.
    ///
    /// The counter increments on every invocation so tests can assert the
    /// guard actually fired (vs. R57's `bind_bool` placeholder which never
    /// executed any dynamic check).
    pub fn cookie_valid(&self) -> bool {
        R::with_mutex_mut(&self.trace, |t| t.cookie_valid_check += 1);

        // Defensive: any missing material rejects. A well-formed handshake
        // populates both slots before this guard runs. Each slot is read in
        // its own with_mutex_mut (sequential, no nesting).
        let peer_zid = match R::with_mutex_mut(&self.inbound_peer_zid, |s| s.clone()) {
            Some(z) => z,
            None => return false,
        };
        let echoed = match R::with_mutex_mut(&self.inbound_opensyn_cookie, |s| s.clone()) {
            Some(c) => c,
            None => return false,
        };
        let expected = generate_cookie_hmac_sha256(&self.params.cookie_signing_key, &peer_zid);
        // Byte-equality compare. Constant-time compare is overkill for a
        // single-peer test fixture path; if the HMAC verdict ever drives a
        // security-critical timing oracle on prod hardware, swap to
        // `subtle::ConstantTimeEq` here.
        echoed == expected
    }
}
