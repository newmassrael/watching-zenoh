// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use core::ops::Deref;
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(feature = "no_std")]
use portable_atomic::{AtomicU32, AtomicU64, Ordering};

// R311y215 — Priority threads through the Frame SN mint / conduit select and
// the ext_qos wire. A cheap Copy value type from the unconditional `qos`
// module, so it is always in scope even when `transport-qos` does not compile
// (the `FrameTxConduits` non-qos variant ignores it — no cfg-skew on the
// mint/dispatch signatures).
use crate::qos::Priority;

// CodecError is the return type of `encode_init_with_role` /
// `encode_open_with_role` only; gate it on those encoders' codecs so a
// consumer-plane-only subset (no handshake-body codec) does not see it unused.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use sce_forge_runtime::codec::CodecError;
use wz_runtime_core::TimeSource;

// R311y536 — the same union as its ONE consumer, `send_declare`'s signature.
// `dispatch_declare` names the type through its full path, so this import
// serves exactly one item and must carry exactly that item's gate; carrying a
// narrower one is what turned a `declare-subscriber`-without-`liveliness-token`
// build into E0425 the moment the method's own gate was widened.
#[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
use wz_codecs::declare::DeclareOwned;
use wz_codecs::ext_entry::ExtEntryOwned;
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
// Reliability is the signature type of the R311kw `send_wire` seam, so it
// is used iff at least one wire-emit body is active: the handshake / close
// encoders, any consumer-plane frame emit (the frame_encode union), the
// batch flush (`transport-batching` — its emits route through the seam
// since R311kw, so the former "full-path return type only" exclusion no
// longer holds), OR the keepalive emitter (`transport-keepalive`,
// R311kx). `send_wire` itself carries the same cfg union; the two move
// together.
#[cfg(feature = "routing-namespace")]
use crate::keyexpr_prefix::OwnedNonWildKeyExpr;
#[cfg(feature = "routing-namespace")]
use crate::namespace::NamespaceIngress;
// R311y516 — the establishment codecs enter this union ROLE-CONJOINED, not
// bare: see the `send_wire` seam below for why `codec-init-body` /
// `codec-open-body` alone carry no emit.
#[cfg(any(
    all(
        any(feature = "codec-init-body", feature = "codec-open-body"),
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ),
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
    feature = "transport-batching",
    feature = "transport-keepalive",
))]
use crate::reliability::Reliability;
use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
// R311y739 — this bundle owns `outbound_mappings`, so it IS the `M=0` id space
// an inbound resolver consults.
use crate::send_declare_error::SendDeclareError;
use crate::send_wire_error::SendWireError;
use crate::session_fsm_unicast::SessionFsmUnicastActions as SessionFsmUnicastActionsTrait;
use crate::session_init_params::SessionInitParams;
use crate::signing_key::generate_cookie_hmac_sha256;
use crate::wireexpr_resolve::OwnMappingSpace;

// inbound parse (handle_inbound)
use crate::inbound::{parse_inbound_consuming, InboundFrame};
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

// R3b — the Z_EXT_AUTH dispatch wired into the four handshake send/recv stages.
#[cfg(feature = "session-extauth")]
use crate::auth_dispatch::AuthDispatch;

// single-source borrowed reply builders (liveliness-token ResponseSink leg).
// R311y530 — `build_final_reply` dropped: the `DeclFinal` terminator now comes
// from the UNGATED `declare_build` twin so the same seam serves the
// session-local subscriber chain (which exists without `liveliness-token`).
#[cfg(feature = "liveliness-token")]
use crate::declare::local_token::build_token_reply;

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
// R311y350 — `declare-final` LEFT this list when R311y346 deleted
// `send_declare_final` (138f842), which was the only thing in this file that
// reached `declare_build` under that feature alone. The list names the features under
// which the glob IS used; a feature that no longer does belongs out of it, or the
// import is dead in exactly the subset the comment above predicts (C4c's
// `liveliness-sub-only` = codec-declare + declare-interest + liveliness-subscriber
// pulls `declare-final` and reaches no builder).
#[cfg(any(
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
))]
use crate::declare_build::*;
#[cfg(feature = "declare-interest")]
use crate::interest_build::*;
// R311y771 — `InterestKinds` named explicitly, not left to the glob above.
// The glob is gated on `declare-interest`; the type appears in the SIGNATURE
// of `send_interest_kinds`, and a cfg'd import behind a signature gated on a
// DIFFERENT cfg compiles in every lane that happens to carry both and breaks
// the ones that do not. Layer C1bz caught it as `cannot find type
// InterestKinds` while building the docs of nine downstream crates, none of
// which name the type — the first lane in this tree to build that subset.
// `alloc` is the honest gate: `interest_build` carries exactly that one,
// because an Interest is an `InterestOwned`.
#[cfg(feature = "alloc")]
use crate::interest_build::InterestKinds;
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
/// R311kf — the struct (and the `tx_mutex` lock around it) is UNGATED:
/// the mutex doubles as the session's TX-ORDER serialization lock (pico
/// holds its TX mutex across SN mint + wire write for every sender,
/// common/tx.c:273-305), which every build needs — with
/// `transport-batching` off, `active` stays `false` forever and only the
/// lock role remains (as of R311y835 that is ALL that remains — the staging
/// buffer used to ride the OFF build too, at three words).
///
/// R311y835 — the single open frame became `[BatchStage; N]`, one per
/// `Priority` conduit, and the drain walks them in ASCENDING priority. See
/// `BatchTx::stage_mut` for why that is the whole of temporal priority.
#[derive(Debug, Default)]
pub struct BatchTx {
    /// `zp_batch_start` .. `zp_batch_stop` window flag
    /// (`_Z_BATCHING_ACTIVE` / `_Z_BATCHING_IDLE`).
    pub active: bool,
    /// The per-priority open frames — `stages[i]` is the conduit whose wire
    /// priority byte is `i`. Without `transport-qos` there is exactly ONE
    /// conduit and the array is `[_; 1]`; without `transport-batching` nothing
    /// stages at all and the field is gone, leaving `BatchTx` its ungated
    /// TX-ORDER lock role alone (which is smaller than the pre-y835 shape, where
    /// an unused `buf` rode every build).
    #[cfg(feature = "transport-batching")]
    stages: BatchStages,
}

/// R311y835 — ONE priority conduit's staged outbound frame: the transport
/// header byte + `VLE(sn)` + N appended network-message bodies, plus pico's
/// batch counter for observability. An empty `buf` means no frame is open on
/// this conduit. Was `BatchTx`'s inline `buf` / `count` pair, lifted into a
/// value so the eight conduits can be an array rather than eight fields.
#[cfg(feature = "transport-batching")]
#[derive(Debug, Default)]
struct BatchStage {
    /// The open outbound frame bytes (empty = none open).
    buf: Vec<u8>,
    /// Network messages absorbed into the open frame. The flush trigger is
    /// the byte budget (`params.batch_size`), never this count.
    count: usize,
}

/// The staged conduits, sized by the build's priority space. `transport-qos`
/// is `alloc`-required by construction (it is a host/AP knob, never an MCU
/// no-alloc one), so eight `Vec` headers here cost nothing an MCU profile
/// pays: the OFF build keeps the single stage it always had.
#[cfg(all(feature = "transport-batching", feature = "transport-qos"))]
type BatchStages = [BatchStage; Priority::NUM];
#[cfg(all(feature = "transport-batching", not(feature = "transport-qos")))]
type BatchStages = [BatchStage; 1];

/// The staging apparatus rides `transport-batching` as a whole: both of its
/// consumers (`SessionLinkActions::dispatch_network_message`'s window arm and
/// `SessionLinkActions::flush_open_batch`) are gated on it, so off the feature
/// there is nothing to stage into and nothing to drain.
#[cfg(feature = "transport-batching")]
impl BatchTx {
    /// The conduit `priority` stages into. With `transport-qos` this is
    /// zenoh's `TransmissionPipeline::stage_in[priority]`
    /// (`io/zenoh-transport/src/common/pipeline.rs`) — each priority
    /// accumulates INDEPENDENTLY, which is what makes the drain order below a
    /// real scheduling decision rather than arrival order. Before R311y835 wz
    /// held one frame and flushed it whenever the priority changed, so a
    /// Background message staged first left the link BEFORE a RealTime message
    /// staged second: the wire carried the ext_qos band while the schedule
    /// ignored it.
    ///
    /// Without `transport-qos` there is one conduit and every priority indexes
    /// it — byte-identical to the pre-y835 single-`buf` batch. The same holds
    /// inside a `transport-qos` build on a session that did NOT negotiate QoS,
    /// because `SessionLinkActions::dispatch_network_message` forces
    /// `Priority::DEFAULT` there before reaching this seam.
    fn stage_mut(&mut self, priority: Priority) -> &mut BatchStage {
        &mut self.stages[Self::stage_index(priority)]
    }

    /// `priority` -> conduit index. The wire priority byte IS the index under
    /// `transport-qos` (`Priority::wire_byte`, 0..=7 ascending from `Control`),
    /// so index order IS wire-priority order and the ascending walk in
    /// `SessionLinkActions::flush_open_batch` is zenoh's strict-priority
    /// drain (`pipeline.rs` pulls `for prio in 0..NUM_PRIO`). Off the feature
    /// every priority collapses onto the single conduit.
    const fn stage_index(priority: Priority) -> usize {
        #[cfg(feature = "transport-qos")]
        {
            priority.wire_byte() as usize
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            let _ = priority;
            0
        }
    }

    /// The `Priority` conduit index `idx` carries — the inverse of
    /// `Self::stage_index`, used by the drain to route each flushed frame by
    /// its OWN conduit (y217 #3: splitting one conduit across links would trip
    /// the peer's per-conduit RX SN gate).
    const fn stage_priority(idx: usize) -> Priority {
        #[cfg(feature = "transport-qos")]
        {
            Priority::from_wire(idx as u8)
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            let _ = idx;
            Priority::DEFAULT
        }
    }
}

/// R311y214 — the unicast outbound Frame SN generator, SPLIT per
/// reliability channel: the atomic twin of the plain-`u64` multicast
/// [`crate::sn::TxSn`] (which the single-task multicast drive loop mints
/// under no lock). Both zenoh and zenoh-pico split the TX SN by
/// reliability even at one priority conduit: zenoh's non-QoS
/// `TransportPriorityTx { reliable, best_effort }` still holds two
/// generators (`io/zenoh-transport/src/common/priority.rs`), and pico's
/// `_z_transport_tx_get_sn(ztc, reliability)` mints from
/// `_sn_tx_reliable` / `_sn_tx_best_effort` (`src/transport/common/tx.c:52-59`).
/// wz's prior single shared `AtomicU64` was a divergence from BOTH: a
/// reliable and a best-effort Frame drew from ONE ring, so each channel
/// saw a gapped (but forward) SN cadence the peer's per-channel
/// `_z_sn_precedes` gate merely tolerated. Splitting makes each channel a
/// contiguous ring from `initial_sn`, matching pico exactly. Both channels
/// seed from the one `params.initial_sn` (the OpenSyn/OpenAck origin) and
/// share the negotiated ring mask. The mint stays lock-free (every mint
/// site already runs under `tx_mutex`; the atomic additionally keeps a
/// straggling reset from reordering — the SeqCst contract the reset store
/// pairs with). R311y215 arrays this per `Priority` conduit behind
/// `transport-qos`.
#[derive(Debug)]
pub struct AtomicTxSn {
    /// Next SN for the reliable channel (pico `_sn_tx_reliable`).
    reliable: AtomicU64,
    /// Next SN for the best-effort channel (pico `_sn_tx_best_effort`).
    best_effort: AtomicU64,
}

impl AtomicTxSn {
    /// Seed both channels at `initial_sn` (the OpenSyn/OpenAck origin) so
    /// the first Frame on either channel is exactly `initial_sn` — the peer
    /// seeds its per-channel RX gate one before this ([`crate::sn::RxSn::seed`]).
    pub fn new(initial_sn: u64) -> Self {
        Self {
            reliable: AtomicU64::new(initial_sn),
            best_effort: AtomicU64::new(initial_sn),
        }
    }

    /// Mint the next SN on `reliable`'s channel as a ring position of
    /// `mask`, advancing that channel one step (the atomic twin of
    /// [`crate::sn::TxSn::mint`]). Masking a raw monotonic `fetch_add` IS
    /// the ring walk — `(n + 1) & mask` is the ring successor of `n & mask`
    /// across the `u64` boundary too.
    pub fn mint(&self, reliable: bool, mask: u64) -> u64 {
        let slot = if reliable {
            &self.reliable
        } else {
            &self.best_effort
        };
        slot.fetch_add(1, Ordering::SeqCst) & mask
    }

    /// Reserve (burn) one SN on `reliable`'s channel WITHOUT returning it —
    /// the fragment-chain follow-on walk reserves `count - 1` SNs after the
    /// first fragment's already-minted `sn` so the chain is ring-consecutive
    /// on its own channel (R311y206).
    pub fn reserve_next(&self, reliable: bool) {
        let slot = if reliable {
            &self.reliable
        } else {
            &self.best_effort
        };
        slot.fetch_add(1, Ordering::SeqCst);
    }

    /// Re-seed BOTH channels to `initial_sn` on reopen (the fresh-rebuild
    /// path). SeqCst pairs with `mint` / `reserve_next` so the store cannot
    /// reorder against a straggling in-flight mint.
    pub fn reset(&self, initial_sn: u64) {
        self.reliable.store(initial_sn, Ordering::SeqCst);
        self.best_effort.store(initial_sn, Ordering::SeqCst);
    }
}

/// R311y215 (transport-qos) — the outbound Frame SN generators: ONE
/// [`AtomicTxSn`] per `Priority` conduit when `transport-qos` compiles (zenoh
/// `priority_tx: Arc<[TransportPriorityTx]>`, `universal/transport.rs`), else the
/// single R311y214 conduit. The array SHAPE is compile-time behind the feature
/// so an MCU no-alloc build never sizes a heap array by the runtime `is_qos`
/// flag; at runtime a non-QoS session mints only `conduit[Priority::DEFAULT]`
/// (the send seam forces `priority = Data` when `!is_qos()`), leaving the other
/// conduits idle. Every conduit is seeded from the one `initial_sn` (zenoh seeds
/// each `TransportPriorityTx` from the single `config.tx_initial_sn`).
///
/// The one-conduit-per-`(priority,reliability)` gate is what makes a multilink
/// priority-select SAFE (R311y216): `select_link` pins one conduit to one link,
/// so a reliable+high and a reliable+low Frame ride SEPARATE SN rings gated on
/// SEPARATE RX conduits — no cross-link stale-drop. Splitting ONE conduit across
/// links (a load-balancer) would reintroduce the hazard and is forbidden.
pub struct FrameTxConduits {
    #[cfg(feature = "transport-qos")]
    conduits: [AtomicTxSn; Priority::NUM],
    #[cfg(not(feature = "transport-qos"))]
    conduit: AtomicTxSn,
}

impl FrameTxConduits {
    /// Seed every conduit at `initial_sn` (the OpenSyn/OpenAck origin).
    pub fn new(initial_sn: u64) -> Self {
        Self {
            #[cfg(feature = "transport-qos")]
            conduits: core::array::from_fn(|_| AtomicTxSn::new(initial_sn)),
            #[cfg(not(feature = "transport-qos"))]
            conduit: AtomicTxSn::new(initial_sn),
        }
    }

    /// The `(priority)` conduit — `conduits[priority]` under `transport-qos`,
    /// the single conduit otherwise (priority ignored, no cfg-skew).
    #[inline]
    fn select(&self, _priority: Priority) -> &AtomicTxSn {
        #[cfg(feature = "transport-qos")]
        {
            &self.conduits[_priority as usize]
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            &self.conduit
        }
    }

    /// Mint the next SN for `(priority, reliable)` — see [`AtomicTxSn::mint`].
    pub fn mint(&self, priority: Priority, reliable: bool, mask: u64) -> u64 {
        self.select(priority).mint(reliable, mask)
    }

    /// Reserve one follow-on SN on `(priority, reliable)` — the fragment walk.
    pub fn reserve_next(&self, priority: Priority, reliable: bool) {
        self.select(priority).reserve_next(reliable);
    }

    /// Re-seed EVERY conduit to `initial_sn` on reopen.
    pub fn reset(&self, initial_sn: u64) {
        #[cfg(feature = "transport-qos")]
        for c in &self.conduits {
            c.reset(initial_sn);
        }
        #[cfg(not(feature = "transport-qos"))]
        self.conduit.reset(initial_sn);
    }
}

/// R311y205 (transport-multilink IMPL-2a) — the SHARED session kernel: the
/// ~30 fields that are one-per-logical-session regardless of how many physical
/// links carry it (SN generators, RX-SN gate, negotiated caps, peer identity,
/// id-spaces, declaration cache, namespace, the TX-order `tx_mutex`). Split out
/// of the former flat `SessionLinkActions` so a later multilink slice can share
/// ONE core across N per-link [`LinkState`]s on separate drive loops; the 5
/// per-link fields moved to [`LinkState`]. `SessionCore` holds NO reference to
/// a `LinkState`, so it is shareable independently of any one link. At N=1
/// (every build today) [`SessionLinkActions`] holds one `SessionCore` + one
/// `LinkState` behind the per-profile [`R::Shared`](crate::link::SessionRuntime::Shared)
/// pointer (Arc/Rc — see the `SessionLinkActions` doc): behavior / wire /
/// data-plane identical to the pre-split flat struct, though NOT
/// footprint-identical (the split adds two refcounted allocations per session —
/// a known MCU zero-cost debt, faithfulness-over-cost).
pub struct SessionCore<R: SessionRuntime, T: TimeSource> {
    /// R311y9 — per-session wire byte/message counters (`transport-stats`).
    /// Interior-mutable atomics, incremented at the [`Self::send_wire`] (TX)
    /// and [`crate::drive::dispatch_link_event`] (RX) seams; read via
    /// [`Self::stats_report`]. Off by default (the adminspace consumer is P4).
    #[cfg(feature = "transport-stats")]
    pub stats: crate::stats::TransportStats,
    pub params: SessionInitParams,
    /// The largest message this profile can REASSEMBLE, in bytes — the TX
    /// twin of the RX reassembly slot `CAP`. A fragment chain longer than
    /// this is refused at
    /// [`emit_frame_or_fragments`](SessionLinkActions::emit_frame_or_fragments)
    /// with [`SendWireError::ExceedsReassemblyCap`] instead of being emitted
    /// into a receiver that will drop it mid-stage.
    ///
    /// `usize::MAX` (the default) means "no cap", so a host that never calls
    /// [`set_max_reassembly_bytes`](SessionLinkActions::set_max_reassembly_bytes)
    /// keeps the pre-existing behavior byte for byte. The AP host sets it to
    /// its reassembly pool's slot size; the MCU hosts set theirs.
    ///
    /// Held behind `R::Mutex` rather than an atomic on purpose: ARMv6-M has
    /// no `target_has_atomic = "ptr"`, and every other configured-once slot
    /// on this struct uses the same seam.
    #[cfg(feature = "transport-fragmentation")]
    pub max_reassembly_bytes: R::Mutex<usize>,
    /// R2238 (open-debt item 580) — how many more `T_MID_FRAGMENT` messages
    /// this session may put on the wire. Each fragment of a chain draws ONE
    /// credit through `SessionLinkActions::take_fragment_tx_credit` (private,
    /// so a code span rather than an intra-doc link — on a public item's docs
    /// that link is BROKEN and spends the Layer C1bz budget) as it is emitted;
    /// when the draw fails the chain is abandoned and the send reports
    /// [`SendWireError::FragmentTxBudgetExhausted`].
    ///
    /// This is wz's answer to the finite batch pool upstream fragments
    /// against (`common/pipeline.rs`, `zgetbatch_rets!`), and the reason wz
    /// needed one at all: with an unbounded writer channel
    /// (`wz-runtime-tokio/src/serial_pipeline.rs`, `link_pipeline.rs` and
    /// their siblings all take `mpsc::unbounded_channel`) and a
    /// build-the-whole-chain-first encoder, there was no state in which some
    /// fragments had been sent and the rest could not be — so there was no
    /// place to report a chain abandon from, whatever the encoder could
    /// spell. The budget is what makes that state REACHABLE, and reaching it
    /// deterministically is what a gate can assert on.
    ///
    /// ⚠ It is a SESSION-wide resource, not a per-chain allowance, and the
    /// distinction is load-bearing rather than stylistic. A per-chain
    /// allowance would be knowable before the walk began, and the honest
    /// implementation of it would be a pre-check that refuses the whole
    /// message and emits nothing — which never reaches the mid-chain state
    /// at all. Shared, the credit another sender takes between two of this
    /// chain's fragments is not predictable from inside the chain, so the
    /// walk must stream and find out, exactly as upstream's does.
    ///
    /// The stop fragment itself does NOT draw a credit: it is the abandon
    /// NOTICE, not chain payload, and a budget that could not afford to say
    /// it had run out would leave the peer holding the buffer this whole
    /// mechanism exists to release. Upstream draws its stop batch outside
    /// the pool for the same reason (`WBatch::new_ephemeral`).
    ///
    /// `usize::MAX` (the default) means "unbounded" and is never decremented,
    /// so a host that never calls
    /// [`set_fragment_tx_budget`](SessionLinkActions::set_fragment_tx_budget)
    /// keeps the pre-existing behavior byte for byte.
    ///
    /// Held behind `R::Mutex` rather than an atomic for the same reason
    /// [`Self::max_reassembly_bytes`] is: ARMv6-M has no
    /// `target_has_atomic = "ptr"`.
    #[cfg(feature = "transport-fragmentation")]
    pub fragment_tx_budget: R::Mutex<usize>,
    pub trace: R::Mutex<ActionTrace>,
    /// Cookie material captured from a peer's InitAck via
    /// `handle_inbound`. When populated this overrides
    /// `params.cookie` on the OpenSyn outbound, implementing the
    /// RFC §5.M echo contract on the Initiator side.
    pub inbound_cookie: R::Mutex<Option<Vec<u8>>>,
    /// R311kv — the lease window the peer advertised in its OPEN body
    /// (milliseconds; `parse_inbound` already projected the wire T-flag
    /// seconds form back, R311ku). Captured by [`Self::handle_inbound`]
    /// from BOTH OpenSyn (accepting side) and OpenAck (initiating side)
    /// — zenoh-pico adopts `min(advertised, Z_TRANSPORT_LEASE)` at the
    /// same two arrival points (unicast/transport.c:193/269) and expires
    /// the session by it (unicast/lease.c:147). wz stores the raw
    /// advertisement; the deadline comparator applies the local cap
    /// ([`crate::drive::check_lease_deadline`]: `min(this,
    /// params.lease_ms)`) — the same store-raw / cap-at-check split as
    /// the multicast per-peer sweep (R311ks). `None` pre-OPEN: the local
    /// window governs alone.
    pub peer_open_lease_ms: R::Mutex<Option<u64>>,
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
    /// R311qh — the remote peer's zid learned at handshake, captured for the
    /// ROUTING layer from BOTH the inbound InitSyn (Accepting side) and the
    /// inbound InitAck (Initiating side) — the remote peer's stable network
    /// identity, the key a peer-mesh routing graph keys faces on. Distinct from
    /// [`inbound_peer_zid`](Self::inbound_peer_zid) by design: that slot is the
    /// R86 Accepting-side cookie-HMAC capture (InitSyn only —
    /// `r86_handle_inbound_init_ack_does_not_overwrite_peer_zid` forbids InitAck
    /// touching it, to avoid cross-role confusion), whereas this slot is the
    /// role-agnostic remote identity a face exposes once Established. Reset on
    /// re-handshake alongside the other captured slots.
    pub remote_peer_zid: R::Mutex<Option<Vec<u8>>>,
    /// R311td — the remote peer's WhatAmI role as the 2-bit INIT wire form
    /// (`InitBody::whatami()` = `cbyte & 0x03`: 0 Router, 1 Peer, 2 Client),
    /// captured at handshake from BOTH the inbound InitSyn (Accepting side) and
    /// the inbound InitAck (Initiating side), alongside
    /// [`remote_peer_zid`](Self::remote_peer_zid). Stored RAW — the 2-bit wire
    /// datum, NOT the API-form role byte: session-core is `#![no_std]` and
    /// routing-agnostic, so the routing boundary (the `linkstate_forward` driver)
    /// maps it to the graph's API-form WHATAMI_* role, exactly as it maps the raw
    /// `peer_zid` bytes to a routing `Zid`. Reset on re-handshake alongside the
    /// other captured slots. The gossip-policy prerequisite ("F1"): the graph can
    /// record a neighbour's real role instead of assuming peer.
    pub peer_whatami: R::Mutex<Option<u8>>,
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
    /// R311y813 — the per-handshake nonce that binds the Accepting side's
    /// cookie to THIS handshake, the wz analogue of the `cookie_nonce` zenoh
    /// keeps in its own accept state and compares the OpenSyn echo against
    /// (`unicast/establishment/accept.rs:359-395` mints, `:500-503` rejects a
    /// mismatch as "Unknown cookie").
    ///
    /// Both the mint (`SessionActionsBinding::send_init_ack_with_cookie`)
    /// and the verify ([`Self::cookie_valid`]) read THIS slot, so the acceptor
    /// admits exactly the cookie it minted for the handshake it is in. Before
    /// this slot existed the two sides agreed on a value derived from
    /// `(deploy key, peer zid)` alone, which is constant for the life of the
    /// process — a captured OpenSyn echo replayed forever.
    ///
    /// `None` is FAIL-CLOSED and is the only default: the no_std core draws no
    /// entropy (`getrandom` has no bare-metal backend), so the nonce is
    /// installed from outside via [`Self::refresh_cookie_nonce`] — by
    /// `new_session_actions` on the AP profile. An acceptor that never
    /// received one mints no HMAC cookie and its `cookie_valid` denies every
    /// OpenSyn; it does NOT fall back to the un-bound derivation, because a
    /// fallback is indistinguishable from the defect this slot removes.
    ///
    /// Survives [`Self::reset_for_reopen`] alongside the ext-chain staging
    /// slots and the auth challenge nonce, for the same reason: it is
    /// locally-sourced configuration rather than captured peer state, and the
    /// host that supplied it is the one positioned to refresh it. See
    /// [`Self::refresh_cookie_nonce`] for what an acceptor-role re-handshake
    /// owes.
    pub cookie_nonce: R::Mutex<Option<u64>>,
    /// R68b — per-role ext chain slots. Indexed by `ExtChainRole`
    /// via `ext_chain_for`. Each slot lives behind its own `Mutex`
    /// so a setter can swap one chain without blocking the others
    /// (e.g. mid-handshake auth-step rotation can rewrite the
    /// OpenSyn chain without touching the InitSyn record).
    init_syn_ext: R::Mutex<Vec<ExtEntryOwned>>,
    init_ack_ext: R::Mutex<Vec<ExtEntryOwned>>,
    open_syn_ext: R::Mutex<Vec<ExtEntryOwned>>,
    open_ack_ext: R::Mutex<Vec<ExtEntryOwned>>,
    /// R3b — the Z_EXT_AUTH dispatch (`session-extauth`). Holds the negotiated
    /// auth methods (usrpwd, ...) and mux/demuxes their per-stage sub-exts into
    /// the four handshake ext chains above. Default empty (no auth ext, admits
    /// every stage = zenoh `Auth::default()`); the AP layer installs a
    /// configured dispatch via [`Self::install_auth_dispatch`]. Behind its own
    /// mutex so a send stage advances a method's state without blocking the role
    /// ext slots (the "mid-handshake auth-step rotation" the slot comment above
    /// anticipated).
    #[cfg(feature = "session-extauth")]
    pub auth: R::Mutex<AuthDispatch>,
    /// session-extshm (R311y507) — the SHM establishment CHALLENGE-RESPONSE
    /// state (`crate::extshm::ShmAuthDispatch`): this node's published auth
    /// segment plus the challenge read out of the peer's. Behind its own mutex
    /// for the same reason `auth` is — a send stage advances it without blocking
    /// the role ext slots.
    ///
    /// Default EMPTY, which emits nothing at all: a deploy opts in by installing
    /// an authenticator ([`SessionLinkActions::install_shm_auth`]), exactly as
    /// zenoh's `auth_shm` is `None` unless the manager was configured with SHM.
    #[cfg(feature = "session-extshm")]
    pub shm_auth: R::Mutex<crate::extshm::ShmAuthDispatch>,
    /// transport-lowlatency — the negotiated lowlatency capability for THIS
    /// session (zenoh `TransportConfigUnicast::is_lowlatency`). Seeded with the
    /// local offer ([`Self::set_lowlatency_offer`]) at bring-up, then ANDed
    /// against the peer's InitSyn / InitAck offer
    /// ([`Self::negotiate_lowlatency_against_peer`], zenoh
    /// `is_lowlatency &= other_ext.is_some()`). When true post-establishment,
    /// the lean tx / rx data path drops the Frame(sn) wrapper + fragmentation
    /// (the wz mirror of zenoh `TransportUnicastLowlatency`). Behind its own
    /// mutex so the merge advances without blocking the role ext slots.
    #[cfg(feature = "transport-lowlatency")]
    pub is_lowlatency: R::Mutex<bool>,
    /// R311y578 — the NEGOTIATED protocol patch level for this session
    /// (zenoh `TransportConfigUnicast::patch`). Seeded at
    /// [`crate::extpatch::CURRENT_PATCH`] (wz's own announcement, R121f1)
    /// and `min()`-capped against the peer's Init announcement by
    /// [`Self::negotiate_patch_against_peer`], which is zenoh-pico's
    /// `if (iam._patch > tmsg._patch) iam._patch = tmsg._patch`
    /// (`transport.c:237-241`) on both sides.
    ///
    /// `None` until the first Init frame is admitted, and that is the point
    /// of the `Option` rather than a `u8` seeded at `CURRENT_PATCH`: before
    /// an exchange there IS no negotiated level, and a session that never
    /// saw an Init — a fixture, a mid-flow attach, a replay that starts
    /// after establishment — must not be handed wz's own announcement as
    /// though the peer had agreed to it. It reads back as
    /// [`crate::extpatch::NO_PATCH`], which keeps the markers off, which is
    /// the conservative direction: it reassembles chains a strict reader
    /// would refuse, rather than refusing chains a real peer is sending.
    ///
    /// Its one consumer today is
    /// [`Self::fragmentation_markers_negotiated`], the gate on the Fragment
    /// `0x2 First` / `0x3 Drop` chain-boundary rules. Ungated by feature:
    /// the level is core establishment state that wz already puts on the
    /// wire in every build, and a session that cannot read it back would
    /// silently pin the markers off.
    pub negotiated_patch: R::Mutex<Option<u8>>,
    /// transport-qos (R311y215) — the negotiated QoS-transport capability for
    /// THIS session (zenoh `TransportConfigUnicast::is_qos`). Seeded with the
    /// local offer ([`Self::set_qos_offer`]) at bring-up, then ANDed with the
    /// peer's Init `ext_qos` offer ([`Self::negotiate_qos_against_peer`], zenoh
    /// "both sides QoS or NoQoS"). When true it selects `Priority::NUM`
    /// per-priority SN conduits (else 1) and lets a non-DEFAULT Frame carry the
    /// `ext_qos` priority. Mutually exclusive with `is_lowlatency` (guarded at
    /// [`Self::set_qos_offer`]).
    #[cfg(feature = "transport-qos")]
    pub is_qos: R::Mutex<bool>,
    /// session-extqos (R311y506) — the per-link QoS METADATA half of the
    /// establishment state (zenoh `State::QoS { priorities, reliability }`,
    /// seeded from the endpoint's `prio=` / `rel=` metadata by
    /// `StateOpen::new` / `StateAccept::new`). Seeded locally by
    /// [`SessionLinkActions::set_qos_link_metadata`] at bring-up, then REPLACED
    /// by the directional merge against the peer's `QoSLink` body
    /// ([`SessionLinkActions::negotiate_qos_link_against_peer`]). Both fields
    /// `None` — the default — is exactly the state the presence-only UNIT ext
    /// encodes, so an un-configured `session-extqos` build is byte-identical on
    /// the wire to a bare `transport-qos` one.
    #[cfg(feature = "session-extqos")]
    pub qos_link: R::Mutex<crate::extqos::QosLinkState>,
    /// transport-compression — the negotiated compression capability for THIS
    /// session (zenoh `TransportConfigUnicast::is_compression`). Seeded with the
    /// local offer ([`Self::set_compression_offer`]) at bring-up, then ANDed
    /// against the peer's InitSyn / InitAck offer
    /// ([`Self::negotiate_compression_against_peer`], zenoh
    /// `is_compression &= other_ext.is_some()`). When true post-establishment,
    /// every outbound batch is lz4-wrapped at [`Self::send_wire`] and every
    /// inbound batch is un-wrapped at [`crate::drive::dispatch_link_event`]
    /// (the wz mirror of zenoh's per-batch compression). Behind its own mutex.
    #[cfg(feature = "transport-compression")]
    pub is_compression: R::Mutex<bool>,
    /// transport-shm — the negotiated SHM capability for THIS session (zenoh
    /// `negotiated_to_use_shm`). R3a: always false (the inert data-path
    /// machinery never fires); R3b's Z_EXT_SHM 0x2 challenge-response handshake
    /// flips it, after which an SHM-backed Put sends a descriptor + the 0x2 body
    /// marker instead of the bytes. Behind its own mutex.
    #[cfg(feature = "transport-shm")]
    pub is_shm: R::Mutex<bool>,
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
    /// `_z_sn_increment` parity (the F-5 consolidation). R311y214 —
    /// [`AtomicTxSn`], split per reliability channel (pico/zenoh parity).
    /// R311y215 — [`FrameTxConduits`]: one such pair per `Priority` conduit
    /// under `transport-qos` (else the single R311y214 pair); the
    /// `(priority, reliable)` of each mint selects the conduit + channel.
    pub outbound_frame_sn: FrameTxConduits,
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
    pub rx_sn: R::Mutex<crate::sn::RxConduits>,
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
    /// R311km — renamed from `batch_tx`: the name leads with the
    /// ungated lock role (pico `_z_transport_common_t._mutex_tx`
    /// parity); [`BatchTx`] keeps naming the guarded coalescing state.
    pub tx_mutex: R::Mutex<BatchTx>,
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
    /// §5.21 routing-namespace — the per-participant EGRESS prefix (the wz
    /// mirror of zenoh's `Namespace` decorator value). `None` until the AP
    /// layer installs it at session bring-up via [`Self::set_namespace`] (the
    /// `is_lowlatency` config-set-at-bringup pattern). A non-`None` value makes
    /// every LOCAL-ORIGIN send under this link relative to the namespace.
    /// Applied at the THREE local-origin emit paths: the unicast
    /// `Tp::send_network_message` arm (Push/Request/Declare/Interest) and the
    /// `send_response` reply seam — both ABOVE the shared `send_network_message`
    /// forwarder floor, so a router relay (which calls the floor directly) is
    /// never re-namespaced — plus the reconnect declaration replay
    /// ([`Self::replay_one`]), which re-decorates explicitly because it
    /// dispatches BELOW the floor (it cannot share the floor's decoration without
    /// also re-namespacing relays). Set once, but behind the runtime mutex
    /// because the bundle is shared `Arc` by install time.
    #[cfg(feature = "routing-namespace")]
    pub namespace_egress: R::Mutex<Option<OwnedNonWildKeyExpr>>,
    /// §5.21 routing-namespace — the stateful per-session INGRESS decorator
    /// (the `ENamespace` mirror): strips the namespace from inbound keyexprs,
    /// drops out-of-namespace messages, and correlates id-only undeclares
    /// against the declares it dropped. Its blocked-id / incomplete-alias state
    /// persists ACROSS frames for the session lifetime, so it lives in this
    /// per-unicast-link bundle (not a per-iteration local). `None` until
    /// [`Self::set_namespace`] installs it; driven by
    /// [`Self::apply_namespace_ingress`] from both owned-outcome mint points of
    /// the drive loop.
    #[cfg(feature = "routing-namespace")]
    pub namespace_ingress: R::Mutex<Option<NamespaceIngress>>,
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

    /// R311y72 — outbound ENTITY id generator for the `SourceInfo.eid` an
    /// entity (today the `ext-pubsub-advanced-publisher`) stamps onto its
    /// samples. zenoh-pico keeps ONE shared `_z_get_entity_id` for every
    /// entity (pub / sub / queryable / token); wz already split the wire
    /// id-spaces per purpose (request / token / interest above), so the
    /// SourceInfo entity id gets its own counter rather than borrowing the
    /// token-id space (R311y71 review: minting a publisher eid from
    /// `alloc_next_token_id` conflated two id namespaces). `AtomicU32`
    /// because `SourceInfo.eid` is a `u32` — no truncating `as u32` cast.
    /// `Relaxed`; first call returns `0`.
    pub next_outbound_entity_id: AtomicU32,

    /// R311y205 (transport-multilink IMPL-2b-iii) — the aggregation link set: the
    /// `R::Shared<LinkState>` of every physical link that carries this ONE logical
    /// session (the wz mirror of zenoh's `TransportUnicastUniversal.links`). Each
    /// entry is the SAME pointer the link's own [`SessionLinkActions`] binding
    /// holds as `self.link`, so a per-link F2 / lease write through the binding is
    /// seen here, and vice-versa. EMPTY for a non-aggregating session (feature-off
    /// builds omit the field; feature-on single-link sessions never push into it)
    /// — [`Self::select_link`] then returns `None` and `send_wire` keeps its
    /// single-link `self.link` path. The reliability-routed send selects a target
    /// from this set; the session-send gate is the OR over these links'
    /// `transport_available`, so the session survives until the set empties.
    ///
    /// A `std::sync::Mutex`, NOT the runtime `R::Mutex<T>` GAT: the latter's
    /// `where T: Send` naming-bound cannot be discharged for the opaque
    /// `R::Shared<LinkState>` element in generic-`R` struct WF (coop's
    /// `LinkState` is genuinely `!Send` — an `Rc` driver — so no unconditional
    /// bound is sound), whereas `std::sync::Mutex<T>` carries no naming-bound and
    /// is `Send + Sync` structurally on the only runtime that enables this
    /// feature (std `TokioRuntime`, `R::Shared = Arc`). AP-only + rsa-gated, so
    /// std is always present (see `lib.rs`).
    #[cfg(feature = "transport-multilink")]
    pub links: std::sync::Mutex<alloc::vec::Vec<R::Shared<LinkState<R>>>>,
    /// R311y205 (transport-multilink IMPL-2b-ii) — the 0x4 Z_EXT_MULTILINK
    /// establishment dispatch, installed by the AP layer at session bring-up when
    /// `max_links > 1` (the `install_auth_dispatch` discipline). `None` = this
    /// session does not negotiate multilink (feature-on max_links=1, or a link
    /// whose deploy did not enable aggregation) → the handshake emits NO 0x4 ext,
    /// byte-identical to a non-multilink handshake. Holds the rsa-free
    /// [`MultiLinkDispatch`](crate::extmultilink::MultiLinkDispatch) driving one
    /// ephemeral-pubkey method injected from the AP crate.
    #[cfg(feature = "transport-multilink")]
    pub multilink: R::Mutex<Option<crate::extmultilink::MultiLinkDispatch>>,
    /// R311y205 (transport-multilink IMPL-2b-ii) — the peer's ephemeral multilink
    /// pubkey, captured (as its canonical encoded ZPublicKey bytes) from the 0x4
    /// handshake and bound into this session's identity. The join gate compares a
    /// second link's captured pubkey against this (byte-equality IS config-
    /// equality on the ephemeral key, the wz analogue of zenoh's
    /// `init_existing_transport_unicast` pubkey check); a mismatch is an INVALID
    /// close, a match authorizes `add_link`. `None` until the 0x4 handshake
    /// completes (or on a non-multilink session).
    #[cfg(feature = "transport-multilink")]
    pub multilink_pubkey: R::Mutex<Option<alloc::vec::Vec<u8>>>,
}

/// R311y205 (transport-multilink IMPL-2a) — the PER-LINK state: exactly the 5
/// fields that belong to ONE physical link, not the logical session. Split out
/// of the former flat `SessionLinkActions`: `driver` is the per-link write seam
/// (reliability-segregated + per-link keepalive TX), the three stamps are the
/// per-link lease + keepalive baselines (a shared stamp would let a live link
/// keep a dead standby link's lease fresh so it is never reaped), and
/// `transport_available` is the per-link F2 send gate. A later multilink slice
/// gives each physical link its own `LinkState` while N of them share ONE
/// [`SessionCore`]; at N=1 (every build today) one `LinkState` pairs with one
/// `SessionCore` inside [`SessionLinkActions`] (both behind the `R::Shared`
/// pointer), behavior / wire / data-plane identical to the pre-split struct.
/// Parameterised by `R` only — none of the 5 fields name the clock `T`.
pub struct LinkState<R: SessionRuntime> {
    /// R::LinkSink — the per-profile owning handle to the link write
    /// seam (tokio `Arc<dyn BoxedLinkDriver + Send + Sync>`, lwIP MCU
    /// `Rc<dyn BoxedLinkDriver>`). The generic action methods reach the
    /// pure `&dyn BoxedLinkDriver` through [`SessionLinkActions::link_driver`].
    pub driver: R::LinkSink,
    /// R311la — monotonic timestamp in milliseconds of the most recent
    /// successfully parsed inbound transport message of ANY kind
    /// (Frame, Fragment, KeepAlive, handshake, Close — everything but
    /// `Unknown`). Stamped once at the [`SessionLinkActions::handle_inbound`]
    /// success chokepoint, the zenoh-pico `_received` parity point
    /// (unicast/rx.c:88 marks the flag for every decoded message; the
    /// lease task expires only when nothing arrived in the window,
    /// lease.c:141-149). The former R72b shape
    /// (`last_inbound_keepalive_at`, stamped in the KeepAlive arm
    /// alone) expired a peer that sent only data frames — and the
    /// R311kx TX suppression guarantees a busy peer sends no
    /// KeepAlives, so a sustained data flow was killed after one lease
    /// window. Consumers reach this through the
    /// [`crate::drive::lease_wake_deadline`] baseline
    /// (`max(established_at, this)`); an absent stamp falls back to
    /// Established entry per session-fsm §2.5.
    ///
    /// Storage is `u64` milliseconds since the
    /// [`SessionCore::clock`] epoch (R294: migrated from
    /// `std::time::Instant`). The lease comparator becomes a pure
    /// `u64` subtract `now_ms.saturating_sub(stamp_ms) >= lease_ms`;
    /// no `Duration` arithmetic, MCU-friendly (16-byte Duration
    /// halved to 8-byte u64), and the storage form matches the
    /// [`TimeSource::now_monotonic_ms`] contract that wz callers
    /// will use across AP + Phase W targets.
    pub last_inbound_at: R::Mutex<Option<u64>>,
    /// R311y632 (§17) — bytes of the CURRENT framing unit that have not been
    /// dispatched yet.
    ///
    /// One framing unit is a BATCH, not a message: zenoh walks a received unit
    /// to its end on both its datagram and its stream paths
    /// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`,
    /// `.../unicast/universal/rx.rs:220`) and pico decodes the next message out
    /// of the residue without re-reading the link
    /// (`vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`). This participant
    /// dispatched the FRONT of a unit and dropped the rest, and zenoh batches by
    /// default (`common/pipeline.rs:318` holds the batch instead of flushing it).
    ///
    /// Per LINK rather than per session, because a batch belongs to the link
    /// that carried it: two links of one aggregated session receive units
    /// independently and their residues must not interleave.
    ///
    /// Stored DECOMPRESSED. Compression wraps a whole unit, so what is parked
    /// here has already come out of the decompressor and must not go back in —
    /// which is why [`crate::drive::dispatch_pending`] re-enters at
    /// `dispatch_unit` and not at `dispatch_link_event`.
    pub pending_batch: R::Mutex<Option<Vec<u8>>>,
    /// R84 — monotonic timestamp in milliseconds captured when the
    /// session FSM enters the `Established` state. Populated by the
    /// `record_established_at()` Lua action wired to the
    /// `Established.onentry` block in `session_fsm_unicast.scxml`.
    /// Consumers (specifically `check_lease_deadline`) fall back to
    /// this stamp when `last_inbound_at` is `None` so a peer that
    /// never sends anything after handshake still reaches
    /// `lease.expired -> Closing` per session-fsm §2.5 ("lease counts
    /// from Established entry"); the prior R77 behaviour was
    /// `NoBaseline` indefinitely in that case.
    ///
    /// Storage form and clock semantics match
    /// `last_inbound_at` — both are `u64` ms since the
    /// shared [`SessionCore::clock`] epoch (R294 migration
    /// from `std::time::Instant`); the lease comparator subtracts
    /// them as pure `u64` arithmetic.
    pub established_at: R::Mutex<Option<u64>>,
    /// R311kw — monotonic timestamp in milliseconds of the most recent
    /// outbound wire emit on this link. Stamped by the
    /// [`SessionLinkActions::send_wire`] seam every TX path funnels through
    /// (handshake t_msg, CLOSE, Frame / Fragment, batch flush), the
    /// deadline-model equivalent of zenoh-pico's
    /// `_z_transport_common_t._transmitted` flag (transport.h:176; set on
    /// every send in common/tx.c:98/153, consumed by the keepalive tasks in
    /// unicast/lease.c:183/196 + multicast/lease.c:171 to suppress a
    /// KeepAlive when the line already spoke). pico resets the flag each
    /// `lease/Z_TRANSPORT_LEASE_EXPIRE_FACTOR` tick; wz stores the stamp and
    /// the keepalive emitter compares `now - stamp >= lease/factor` — the
    /// same store-raw / compare-at-check split as the R311ks multicast
    /// per-peer sweep. `None` until the first emit; storage form and clock
    /// epoch match `last_inbound_at` (u64 ms, R294 scale).
    pub last_outbound_at: R::Mutex<Option<u64>>,
    /// F2 — is the transport currently accepting data sends? `true` at
    /// construction (the bundle is built over a live link sink; the
    /// pre-handshake window keeps today's emit semantics), `false` when
    /// the FSM releases the link (`release_link`, Closing/Closed entry)
    /// or the reconnect supervisor tears the transport down for re-dial
    /// ([`SessionLinkActions::reset_for_reopen`]), `true` again when Established
    /// (re-)enters (`record_established_at`). The
    /// [`SessionLinkActions::dispatch_network_message`] chokepoint gates on it
    /// so a data send inside the RECONNECTING window rejects typed
    /// ([`SendWireError::TransportUnavailable`]) instead of silently
    /// vanishing into a dead writer channel — zenoh-pico's tx path fails
    /// on the dead transport's mutex/NULL
    /// (`_Z_ERR_TRANSPORT_NOT_AVAILABLE`); the handshake / CLOSE
    /// transport messages bypass the chokepoint and stay ungated.
    pub transport_available: R::Mutex<bool>,
    /// R311y205 (transport-multilink IMPL-2b-iii) — this physical link's traffic-
    /// class preference, set at dial / accept config time. The reliability-routed
    /// send seam ([`SessionCore::select_link`]) picks the [`Reliable`]-pref link
    /// for the reliable channel and the [`BestEffort`]-pref link for the
    /// best-effort channel (the wz mirror of zenoh's per-channel `select` over
    /// `(reliability, priority)`); [`Any`] links are the failover pool. Additive
    /// per-link field, so it changes no accessor signature.
    ///
    /// [`Reliable`]: LinkReliabilityPref::Reliable
    /// [`BestEffort`]: LinkReliabilityPref::BestEffort
    /// [`Any`]: LinkReliabilityPref::Any
    ///
    /// Interior-mutable so the AP dial / accept path sets it at bring-up (through
    /// the shared `R::Shared<LinkState>` handle, before the drive loop spins) via
    /// [`SessionLinkActions::set_link_reliability_pref`] — the same
    /// config-at-bringup discipline as `set_lowlatency_offer`. `Default` (`Any`)
    /// until set.
    #[cfg(feature = "transport-multilink")]
    pub reliability_pref: R::Mutex<LinkReliabilityPref>,
    /// R311y217 (transport-multilink + transport-qos) — the QoS-priority band this
    /// link carries, so [`SessionCore::select_link`] pins each `(priority,
    /// reliability)` conduit to ONE link (the priority tier of zenoh's per-channel
    /// `select`). `None` (the default until set) = no priority preference: the
    /// link is a reliability-only PARTIAL-tier candidate (still the primary route
    /// for its reliability class when no band covers the priority — NOT the
    /// `any`/first-alive failover tier), never a `full` priority match. Set at
    /// bring-up via
    /// [`SessionLinkActions::set_link_priority_range`], the same
    /// config-at-bringup discipline as [`Self::reliability_pref`]. Additive
    /// per-link field; changes no accessor signature.
    #[cfg(all(feature = "transport-multilink", feature = "transport-qos"))]
    pub priority_range: R::Mutex<Option<LinkPriorityRange>>,
}

/// R311y205 (transport-multilink IMPL-2b-iii) — the traffic-class preference a
/// physical link carries into the aggregation core, so the reliability-routed
/// send seam ([`SessionCore::select_link`]) can segregate the reliable channel
/// onto one link and the best-effort channel onto another (the wz mirror of
/// zenoh's per-channel `select`). Defined in the no_std session kernel (where
/// [`LinkState`] stores it) and re-exported by the AP config surface
/// (`wz_runtime_tokio::config::LinkReliabilityPref`), so the two agree by
/// construction. [`Any`](Self::Any) — the default — expresses NO preference
/// (the homogeneous single-link / failover pool).
#[cfg(feature = "transport-multilink")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkReliabilityPref {
    /// Prefer this link for the RELIABLE channel.
    Reliable,
    /// Prefer this link for the BEST-EFFORT channel.
    BestEffort,
    /// No preference — eligible for either channel (the failover default).
    #[default]
    Any,
}

/// R311y217 (transport-multilink + transport-qos) — the inclusive QoS-priority
/// band a physical link carries, so [`SessionCore::select_link`] can pin one
/// `(priority, reliability)` conduit to one link (the wz mirror of zenoh's
/// per-link `PriorityRange`, `commons/zenoh-protocol/src/core/mod.rs:315`).
/// Inclusive on both ends over the wire-order [`Priority`](crate::qos::Priority)
/// scale (0 = Control = highest ... 7 = Background = lowest); a link with band
/// `[start..=end]` covers priority `p` iff `start <= p <= end`. [`Self::width`]
/// (band size) is the selection tie-break — the SMALLEST covering band wins (the
/// most specific link, zenoh `tx.rs:56`). A `Copy` struct rather than zenoh's
/// `PriorityRange(RangeInclusive<Priority>)` newtype (ergonomic; identical
/// containment / width semantics), and [`Self::new`] orders its args so
/// `start <= end` always holds (zenoh's `len()` underflow-panics on a malformed
/// `start > end`; wz precludes it by construction).
///
/// R311y506 — the cfg gate WIDENED from `all(transport-multilink, transport-qos)`
/// to `transport-qos` alone. The band is zenoh's `PriorityRange`, and upstream
/// uses that ONE type for two consumers: per-link selection (the multilink tier)
/// AND the `init::ext::QoSLink` establishment body ([`crate::extqos`]). Gating it
/// on multilink made a `session-extqos` build without multilink unable to name
/// the range it negotiates — the widening keeps ONE range type rather than
/// growing a second, parallel definition. Pure widening: no build that had the
/// type loses it. The per-link `LinkState::priority_range` FIELD stays
/// multilink-gated (that one IS a link-selection input).
#[cfg(feature = "transport-qos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPriorityRange {
    start: crate::qos::Priority,
    end: crate::qos::Priority,
}

#[cfg(feature = "transport-qos")]
impl LinkPriorityRange {
    /// The inclusive band `[min(a,b) ..= max(a,b)]` — the two endpoints are
    /// ordered so the band is always valid regardless of which the caller passes
    /// first (no malformed `start > end`).
    pub fn new(a: crate::qos::Priority, b: crate::qos::Priority) -> Self {
        if a <= b {
            Self { start: a, end: b }
        } else {
            Self { start: b, end: a }
        }
    }

    /// Whether this band covers `priority` (inclusive both ends; the compare is
    /// [`Priority`](crate::qos::Priority)'s `Ord` = the 0..=7 wire order).
    pub fn contains(&self, priority: crate::qos::Priority) -> bool {
        self.start <= priority && priority <= self.end
    }

    /// The band size (count of priorities covered), the selection tie-break
    /// value: a narrower band is a more specific link and wins. Mirror of zenoh
    /// `PriorityRange::len` (`end - start + 1`; named `width` here to avoid the
    /// `len_without_is_empty` lint — a band is never empty, `width >= 1`).
    pub fn width(&self) -> usize {
        (self.end.wire_byte() as usize) - (self.start.wire_byte() as usize) + 1
    }

    /// The inclusive lower bound (the numerically SMALLEST wire priority, i.e.
    /// the highest-urgency end of the band). Needed by [`crate::extqos`] to pack
    /// the band into the `QoSLink` z64 body, where zenoh writes
    /// `*priorities.start()` at bit 3.
    #[cfg(feature = "session-extqos")]
    pub fn start(&self) -> crate::qos::Priority {
        self.start
    }

    /// The inclusive upper bound (the numerically LARGEST wire priority).
    /// zenoh writes `*priorities.end()` at bit 11 of the `QoSLink` body.
    #[cfg(feature = "session-extqos")]
    pub fn end(&self) -> crate::qos::Priority {
        self.end
    }

    /// `true` iff `self` is a SUPERSET of `other` — zenoh
    /// `PriorityRange::includes` (`commons/zenoh-protocol/src/core/mod.rs:331`,
    /// `self.start() <= other.start() && other.end() <= self.end()`). This is the
    /// containment the `QoSLink` negotiation applies in BOTH directions: the
    /// acceptor requires its own band to include the initiator's
    /// (`recv_init_syn`), the initiator requires the acceptor's to include its
    /// own (`recv_init_ack`).
    #[cfg(feature = "session-extqos")]
    pub fn includes(&self, other: &LinkPriorityRange) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// R311y205 (transport-multilink IMPL-2b-iii) — the illegal-state-unrepresentable
/// witness that a second link passed the aggregation config-equality gate. Its
/// single field is PRIVATE, so a `PubkeyBound` can be minted ONLY inside this
/// module — exclusively by [`SessionLinkActions::authorize_link`], which returns
/// `Some` only when the candidate link's captured ephemeral pubkey byte-matches
/// the session's bound pubkey. [`SessionLinkActions::add_link`] takes it by value,
/// so a link that failed (or skipped) the pubkey check cannot be attached to a
/// shared core: the type system, not a runtime assertion, forbids it.
#[cfg(feature = "transport-multilink")]
pub struct PubkeyBound(());

impl<R: SessionRuntime> LinkState<R> {
    /// Resolve the runtime-owned link sink (`R::LinkSink`) to the pure
    /// `&dyn BoxedLinkDriver` write seam. `R::LinkSink` is opaque in
    /// generic-`R` code — the tokio profile binds it to `Arc<dyn
    /// BoxedLinkDriver + Send + Sync>`, the lwIP MCU profile to `Rc<dyn
    /// BoxedLinkDriver>` — so the action methods cannot call
    /// `send_blocking` on `self.driver` directly; this accessor erases
    /// the per-profile refcount wrapper through [`R::link_driver`]. Reached
    /// from [`SessionLinkActions::link_driver`], which forwards to this.
    fn link_driver(&self) -> &dyn BoxedLinkDriver {
        R::link_driver(&self.driver)
    }
}

/// R311il / R311y205 — the runtime-agnostic session action bundle one logical
/// FSM instance drives. Consumers hold it as
/// [`R::ActionsHandle<T>`](crate::link::SessionRuntime::ActionsHandle) (tokio
/// `Arc<SessionLinkActions>`, lwIP MCU `Rc<SessionLinkActions>`).
///
/// Since the transport-multilink IMPL-2a struct-split it is the pairing of the
/// shared [`SessionCore`] and one [`LinkState`]; it [`Deref`]s to `SessionCore`
/// so the core-field accesses in the inherent methods (and in external
/// consumers, through the handle's own `Deref`) resolve transparently, while
/// the 5 per-link fields are reached explicitly through `self.link`.
///
/// R311y205 (transport-multilink IMPL-2b-i) — both halves are held behind the
/// per-profile [`R::Shared`](crate::link::SessionRuntime::Shared) pointer
/// (tokio `Arc`, lwIP `Rc`), NOT embedded by value. This is the core-sharing
/// mechanism the whole aggregation feature rests on: N physical links each hold
/// their own `SessionLinkActions` binding, all cloning ONE `R::Shared<SessionCore>`
/// (so they share the SN generator + per-channel rx-SN gate + peer identity +
/// caches) while each carries its own `R::Shared<LinkState>` (driver + per-link
/// lease stamps + F2 gate). The same one `R::Shared<LinkState>` is also placed
/// in the shared core's link set (`SessionCore::links`) so the reliability-routed
/// send seam can select it; cloning the pointer keeps the binding's view and the
/// core's view of a link IDENTICAL (a `del_link` / `transport_available` write
/// through either is seen by both). ONE type shape at every N — at N=1 (every
/// build today, and every MCU build always) both are refcount-1 pointers,
/// behavior / wire / data-plane identical to the pre-split flat struct.
pub struct SessionLinkActions<R: SessionRuntime, T: TimeSource> {
    /// Shared session kernel — SN/rx_sn/caps/identity/id-spaces/caches. Cloned
    /// (refcount) across every link that aggregates into this logical session.
    pub core: R::Shared<SessionCore<R, T>>,
    /// This binding's physical link. The SAME `R::Shared<LinkState>` is held in
    /// [`SessionCore::links`] under the multilink feature, so the link's F2 gate
    /// / lease stamps are one instance the binding and the send router share.
    pub link: R::Shared<LinkState<R>>,
}

/// The per-frame context [`SessionLinkActions::emit_frame_or_fragments`]
/// needs to decide between one frame and a fragment chain, and to route
/// whichever it emits.
///
/// Grouped rather than passed as six positional arguments: they are ONE
/// decision's inputs, they are resolved together at the top of
/// `dispatch_network_message` (before the `tx_mutex` hold), and they travel
/// together to both call sites. All `Copy`, so the grouping is free.
///
/// Carries the SAME feature gate as
/// [`SessionLinkActions::emit_frame_or_fragments`], its only consumer: a
/// build with none of these codecs (the lwIP MCU profiles reach it) emits
/// no network message at all, and an ungated struct is dead code the
/// workspace's `-D warnings` rejects.
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
#[derive(Clone, Copy)]
struct FrameEmit {
    /// The frame's own `ext_qos` — `Some(p)` iff the effective priority is
    /// non-DEFAULT, which is also how the emit reconstructs the SN conduit.
    ext_qos: Option<Priority>,
    /// The already-minted Frame SN. A fragment chain reuses it as the FIRST
    /// fragment's SN (R311y206) rather than re-minting a block.
    sn: u64,
    /// Reliable vs best-effort — selects the conduit and the frame's R flag.
    reliable: bool,
    /// The outbound budget one frame may occupy; over it, the message
    /// fragments (or is emitted as-is when fragmentation is compiled out).
    mtu: usize,
    /// The negotiated SN ring the chain's follow-on SNs walk.
    sn_mask: u64,
    /// This profile's reassembly cap — a chain longer than this is refused,
    /// because no same-profile peer could rejoin it. `usize::MAX` = no cap.
    max_reassembly_bytes: usize,
}

impl<R: SessionRuntime, T: TimeSource> Deref for SessionLinkActions<R, T> {
    type Target = SessionCore<R, T>;
    #[inline]
    fn deref(&self) -> &SessionCore<R, T> {
        // R311y205 (IMPL-2b-i) — `core` is an `R::Shared<SessionCore>`; the
        // pointer's own `Deref` resolves it to the shared kernel (auto-deref).
        &self.core
    }
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
///
/// R311y605 — built through [`crate::extpatch::encode_patch_ext`] rather than
/// from a literal here. The header was spelled `0x07 | 0x20` while
/// [`crate::extpatch::peer_patch`] — wz's own READER of this very entry —
/// matches on `PATCH_EXT_ID | EXT_ENC_Z64` through the named constants. Two
/// spellings of one wire fact, on the two sides of the same extension: had
/// either moved, wz would have emitted an extension its own reader skips, and
/// the only witness would have been a foreign peer. The literal is also why a
/// `grep extpatch` over this crate finds a complete reader and no emit, which
/// is how a stale "the Patch ext is not attached" claim survived in the
/// inventory and how THIS round first re-derived it.
pub fn default_init_patch_ext_entry() -> ExtEntryOwned {
    crate::extpatch::encode_patch_ext()
}

// R311dz-pre — bridge the observer's generic reply drain to the action
// bundle. The inherent `send_response` / `send_response_final`
// methods (below, in the `impl<R: SessionRuntime, T: TimeSource>` block) carry
// the real encode + enqueue; these trait methods delegate to them so
// The observer's reply drain (`flush_query_replies<S: ResponseSink>` and
// the composing `flush_pending`) can drive any runtime's actions handle.
// The delegating `self.send_response(..)` calls resolve to the inherent
// methods (inherent shadows trait in method-call resolution), so there is
// no recursion. The method set is empty in a build with neither response
// codec, matching the trait's gated surface.
//
// R311lq — `SessionLinkActions` is the full-session bundle, so it
// implements ALL THREE observer drain-sink concerns. They are separate
// `impl` blocks (one per cohesive trait) rather than one fat impl: the
// segregation lets a partial runtime sink (the multicast reply loop)
// implement only `ResponseSink` without being forced to satisfy the
// liveliness concerns.
// R311y739 — the outbound mapping table IS our id space, so the actions bundle
// that owns it is the thing an inbound resolver should be handed. Declaring it
// through the trait (rather than copying the table into the registry) keeps ONE
// copy of the fact: `send_declare_keyexpr` inserts and `send_undeclare_kexpr`
// removes, and a resolution one microsecond later sees both.
//
// A pure delegation to the existing R234 read side. The pairing matters more
// than the body: `resolve_outbound_mapping` was already the publish path's
// answer to "what did I alias id N to", and this makes the RECEIVE path ask the
// same question of the same table — before R311y739 the receive path could not
// ask it at all, so a peer naming our id was answered `None` and dropped.
impl<R: SessionRuntime, T: TimeSource> OwnMappingSpace for SessionLinkActions<R, T> {
    fn resolve_own_mapping(&self, id: u64) -> Option<String> {
        self.resolve_outbound_mapping(id)
    }
}

impl<R: SessionRuntime, T: TimeSource> ResponseSink for SessionLinkActions<R, T> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned) {
        self.send_response(response);
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        self.send_response_final(request_id);
    }
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
impl<R: SessionRuntime, T: TimeSource> DeclareReplySink for SessionLinkActions<R, T> {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        self.send_declare(
            build_token_reply(token_id, keyexpr, interest_id)
                .try_into_owned()
                .expect("local-token reply keyexpr is within MAX_KEYEXPR_BYTES"),
        );
    }
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, interest_id: u64) {
        // R311y530 — built through the UNGATED `declare_build` twin rather than
        // `local_token::build_final_reply`, so this arm compiles in a
        // `declare-subscriber`-without-`liveliness-token` build (the
        // `local_token` module is gated on the latter). Same bytes: both stamp
        // the I-flag + interest_id onto a bodyless `DeclFinal`.
        self.send_declare(crate::declare_build::build_declare_final_reply(interest_id));
    }
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        // A reply keyexpr longer than the bounded codec field cannot be encoded;
        // the chain's `DeclFinal` still terminates the peer's CURRENT interest,
        // so a skipped reply degrades to "no matching subscriber" rather than
        // leaving the peer's query unresolved.
        if let Ok(declare) = crate::declare_build::build_declare_subscriber_reply_with_id(
            interest_id,
            subscriber_id,
            keyexpr,
        ) {
            self.send_declare(declare);
        }
    }
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        // The inherent emit a routed subscriber's own teardown uses, reached
        // with the AGGREGATE decl id instead of a subscription id. One
        // emitter, so the retraction of an aggregate declaration is
        // byte-identical to any other id-only `UndeclSubscriber` — and, since
        // R2292 put both ids in one space, unambiguous on the peer.
        Self::send_undeclare_subscriber(self, subscriber_id);
    }
}

// F3/R311ka — drain target for the registry's staged get
// terminations; delegates to the inherent twin (the same shape as
// `send_response` / `send_response_final` above), so sweep callers
// that hold the actions handle directly (the wz-ap-demo ticker)
// need no trait import.
impl<R: SessionRuntime, T: TimeSource> LivelinessGetPrune for SessionLinkActions<R, T> {
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
            // R311y205 (IMPL-2a) — the 5 per-link fields are grouped into
            // `LinkState`, the rest into the shared `SessionCore`. IMPL-2b-i —
            // each half is wrapped in the per-profile `R::Shared` pointer (tokio
            // `Arc`, lwIP `Rc`) so N links can share ONE core; at N=1 both are
            // refcount-1 pointers, behavior-identical to the pre-split struct.
            // Every field initializer expression is verbatim.
            link: R::share(LinkState {
                driver,
                last_inbound_at: R::new_mutex(None::<u64>),
                pending_batch: R::new_mutex(None::<Vec<u8>>),
                established_at: R::new_mutex(None::<u64>),
                last_outbound_at: R::new_mutex(None::<u64>),
                transport_available: R::new_mutex(true),
                #[cfg(feature = "transport-multilink")]
                reliability_pref: R::new_mutex(LinkReliabilityPref::default()),
                #[cfg(all(feature = "transport-multilink", feature = "transport-qos"))]
                priority_range: R::new_mutex(None),
            }),
            core: R::share(SessionCore {
                #[cfg(feature = "transport-stats")]
                stats: crate::stats::TransportStats::default(),
                params,
                // "No cap" until a host declares one — a profile that never
                // configures its reassembly bound keeps the prior behavior.
                #[cfg(feature = "transport-fragmentation")]
                max_reassembly_bytes: R::new_mutex(usize::MAX),
                // "Unbounded" until a host declares a budget — a profile that
                // never configures one fragments exactly as it did before.
                #[cfg(feature = "transport-fragmentation")]
                fragment_tx_budget: R::new_mutex(usize::MAX),
                trace: R::new_mutex(ActionTrace::default()),
                inbound_cookie: R::new_mutex(None::<Vec<u8>>),
                peer_open_lease_ms: R::new_mutex(None::<u64>),
                clock,
                inbound_peer_zid: R::new_mutex(None::<Vec<u8>>),
                remote_peer_zid: R::new_mutex(None::<Vec<u8>>),
                peer_whatami: R::new_mutex(None::<u8>),
                inbound_opensyn_cookie: R::new_mutex(None::<Vec<u8>>),
                // R311y813 — fail-closed until a host with an entropy source
                // installs one; this crate has none to draw from.
                cookie_nonce: R::new_mutex(None::<u64>),
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
                // R3b — empty dispatch (no auth ext, admits all = zenoh
                // `Auth::default()`); the AP layer installs the configured one.
                #[cfg(feature = "session-extauth")]
                auth: R::new_mutex(AuthDispatch::default()),
                // transport-lowlatency — false until the AP layer offers it
                // (`set_lowlatency_offer`) and the peer's offer is ANDed in.
                #[cfg(feature = "transport-lowlatency")]
                is_lowlatency: R::new_mutex(false),
                // R311y578 — NOT YET NEGOTIATED. The first admitted Init
                // seeds it from wz's own announced level and caps it at the
                // peer's; until then there is no agreed level and the
                // Fragment chain-boundary markers stay off.
                negotiated_patch: R::new_mutex(None::<u8>),
                // transport-qos — false until the AP layer offers it
                // (`set_qos_offer`) and the peer's Init ext_qos offer is ANDed in.
                #[cfg(feature = "transport-qos")]
                is_qos: R::new_mutex(false),
                // session-extqos — no band / no reliability declared until the
                // AP config stages one (the wire stays the UNIT form).
                #[cfg(feature = "session-extqos")]
                qos_link: R::new_mutex(crate::extqos::QosLinkState::default()),
                #[cfg(feature = "transport-compression")]
                is_compression: R::new_mutex(false),
                #[cfg(feature = "transport-shm")]
                is_shm: R::new_mutex(false),
                // session-extshm — no authenticator until the AP installs one.
                #[cfg(feature = "session-extshm")]
                shm_auth: R::new_mutex(crate::extshm::ShmAuthDispatch::empty()),
                inbound_peer_init_caps: R::new_mutex(None::<PeerInitCaps>),
                outbound_frame_sn: FrameTxConduits::new(initial_frame_sn),
                rx_sn: R::new_mutex(crate::sn::RxConduits::default()),
                tx_mutex: R::new_mutex(BatchTx::default()),
                outbound_mappings: R::new_mutex(HashMap::<u64, String>::new()),
                #[cfg(feature = "session-reconnect")]
                declaration_cache: R::new_mutex(Vec::<CachedDeclaration>::new()),
                // §5.21 routing-namespace — `None` until the AP layer installs the
                // namespace via `set_namespace` at bring-up (the `is_lowlatency`
                // config-default pattern). Zero footprint when the feature is off.
                #[cfg(feature = "routing-namespace")]
                namespace_egress: R::new_mutex(None::<OwnedNonWildKeyExpr>),
                #[cfg(feature = "routing-namespace")]
                namespace_ingress: R::new_mutex(None::<NamespaceIngress>),
                next_outbound_request_id: AtomicU64::new(0),
                next_outbound_token_id: AtomicU64::new(0),
                next_outbound_interest_id: AtomicU64::new(0),
                next_outbound_entity_id: AtomicU32::new(0),
                // R311y205 (IMPL-2b-iii) — the aggregation link set starts
                // EMPTY. A single-link session (every non-aggregating open,
                // incl feature-on max_links=1) never registers a link here, so
                // `send_wire` keeps its single-link `self.link` path; the
                // multilink join populates it (link 1 at register, link 2+ at
                // add_link) only when a session actually aggregates.
                #[cfg(feature = "transport-multilink")]
                links: std::sync::Mutex::new(Vec::new()),
                #[cfg(feature = "transport-multilink")]
                multilink: R::new_mutex(None),
                #[cfg(feature = "transport-multilink")]
                multilink_pubkey: R::new_mutex(None),
            }),
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
    /// R311y205 (IMPL-2a) — forwards to [`LinkState::link_driver`] now that the
    /// `driver` field lives on the per-link `self.link`.
    fn link_driver(&self) -> &dyn BoxedLinkDriver {
        self.link.link_driver()
    }

    /// R311y453 — the §5.16 link-derived SUBJECT of this binding's link: the
    /// protocol it speaks and the NICs it sits on, resolved by the driver at open.
    ///
    /// A narrow public window onto the driver rather than making
    /// [`link_driver`](Self::link_driver) itself public: the routing forwarders'
    /// `InterceptorContext` impls need exactly this one datum, and publishing the
    /// whole write seam so they could reach it would hand every consumer
    /// `send_blocking` as well. Borrows `self`, so the read costs no allocation.
    pub fn link_subject(&self) -> Option<&crate::link::LinkSubject> {
        self.link_driver().link_subject()
    }

    /// R311y473 — this session's links as the adminspace renders them: the
    /// session-centric mirror of the array zenoh's `transport_unicast_to_json`
    /// builds from `transport.get_links()` (`net/runtime/adminspace.rs:607-637`).
    ///
    /// ONE entry per PHYSICAL link, which is the whole point. R311y472 put a real
    /// zenohd on the far end of the 0x4 aggregation envelope and read the verdict
    /// off ZENOH'S adminspace, because wz's own reported no links at all — the
    /// admin host hard-coded an empty vector. That was the atom's named S5
    /// residual, and this is the read side of closing it.
    ///
    /// The AGGREGATION SET is the source when it is populated (a multilink session
    /// registers its own first link into the set at join time, so the set is the
    /// complete picture, not the extra links). An empty set means a single-link
    /// session — including every session in a non-multilink build — and then this
    /// binding's own link is the one entry. The two cases are one method rather
    /// than a caller-side branch precisely so a caller cannot forget the second.
    ///
    /// A link whose driver cannot name its endpoints
    /// ([`BoxedLinkDriver::link_endpoints`] `None` — a test double, a FIFO pair, an
    /// MCU stack with no address) still gets an entry, with blank ends. The COUNT
    /// is the load-bearing fact for an admin client asking "is this one session
    /// over two links?", so dropping such a link would corrupt the answer in order
    /// to tidy a string.
    #[cfg(feature = "adminspace-core")]
    pub fn admin_links(&self) -> Vec<crate::adminspace::AdminLink> {
        self.link_endpoints_all()
            .into_iter()
            .map(|e| crate::adminspace::AdminLink {
                src: e.src,
                dst: e.dst,
            })
            .collect()
    }

    /// R2259 (open-debt item 593) — the same per-physical-link `(src, dst)`
    /// enumeration [`admin_links`](Self::admin_links) renders, WITHOUT the
    /// `adminspace-core` gate.
    ///
    /// The adminspace view was the first consumer of this walk and so owned it;
    /// the C `z_info_links` / link-events plane is the second, and it is
    /// compiled in builds that carry no adminspace at all. Duplicating the
    /// multilink branch into that plane would put the "one entry per PHYSICAL
    /// link" rule in two places, and the rule is exactly the fact R311y472
    /// measured wrong once already. So the walk moves here and the adminspace
    /// renderer becomes a projection of it — one derivation, two consumers.
    ///
    /// A link whose driver cannot name its endpoints still gets an entry with
    /// blank ends, for the reason `admin_links` states: the COUNT is the
    /// load-bearing answer.
    pub fn link_endpoints_all(&self) -> Vec<crate::link::LinkEndpoints> {
        let render = |driver: &dyn BoxedLinkDriver| match driver.link_endpoints() {
            Some(e) => e.clone(),
            None => crate::link::LinkEndpoints::default(),
        };
        #[cfg(feature = "transport-multilink")]
        {
            let links = self.links.lock().expect("multilink set mutex");
            if !links.is_empty() {
                return links.iter().map(|l| render(l.link_driver())).collect();
            }
        }
        alloc::vec![render(self.link_driver())]
    }

    /// R311y9 — public snapshot of this session's transport byte/message
    /// counters (`transport-stats`). The standalone read path (the adminspace
    /// `@/<zid>/.../stats` consumer stays P4); surfaced on the AP
    /// `OpenedSession` as `.stats()`. Returns a plain-integer
    /// [`crate::stats::TransportStatsReport`].
    #[cfg(feature = "transport-stats")]
    pub fn stats_report(&self) -> crate::stats::TransportStatsReport {
        self.stats.report()
    }

    /// R311kw — the one wire-emit seam: stamp [`Self::last_outbound_at`]
    /// and forward to the link driver. Every production TX path routes
    /// here (handshake t_msg senders, CLOSE, Frame / Fragment emits, the
    /// batch flush) so the keepalive emitter's idle window sees EVERY
    /// send — zenoh-pico parity: `_z_transport_tx_send_t_msg` /
    /// `_send_n_msg_inner` set `_transmitted = true` for every sender
    /// (common/tx.c:98/153); a TX path that bypassed the seam would
    /// make the emitter inject a redundant KeepAlive after real traffic.
    /// The stamp is read outside the slot closure (R294 discipline) and
    /// the slot guard drops before the blocking send so the
    /// non-reentrant MCU mutex never spans link IO.
    ///
    /// cfg = the union of the routed emit bodies (the `Reliability`
    /// import union above): the handshake / close encoders, the
    /// frame_encode consumer-plane union, the batch flush, and the
    /// keepalive emitter. A build with no active wire-emit body must
    /// not carry the dead seam (CI denies warnings on the minimal MCU
    /// lanes).
    // R311y205 — codec-close / transport-keepalive are NOT in this union: the
    // close + keepalive + link-close TX paths route through
    // [`Self::send_wire_this_link`] (per-link control, not reliability-routed),
    // so a build that enables ONLY codec-close / transport-keepalive (e.g. a
    // bare `transport-multicast` MCU lane) has no `send_wire` caller and must
    // not compile the dead seam. `emit_on_link` keeps the full union (both
    // send_wire and send_wire_this_link funnel through it).
    //
    // R311y516 — the establishment codecs are ROLE-CONJOINED here for the same
    // reason one level over: `codec-init-body` / `codec-open-body` describe a
    // CODEC, not an emit. The four senders that route INIT/OPEN through this
    // seam — `send_init_syn` / `send_open_syn` (`session-unicast-open`) and
    // `send_init_ack_with_cookie` / `send_open_ack`
    // (`session-unicast-accept`) — each carry a role conjunct of their own, so
    // a build with an establishment codec and NEITHER role encodes nothing and
    // must not compile the dead seam (`--features session-extqos,
    // codec-init-body` was the combination that reded `-D warnings`).
    #[cfg(any(
        all(
            any(feature = "codec-init-body", feature = "codec-open-body"),
            any(feature = "session-unicast-open", feature = "session-unicast-accept")
        ),
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
        feature = "transport-batching",
    ))]
    fn send_wire(&self, bytes: &[u8], reliability: Reliability, priority: Priority) {
        // R311y205 (transport-multilink IMPL-2b-iii) — reliability-routed data
        // send: an AGGREGATING session (`select_link` -> Some) emits on the
        // reliability-pref link (else first alive = failover) from the shared
        // link set — the wz mirror of zenoh's per-channel `select`; a SINGLE-link
        // session (empty set -> None) and every NON-feature build emit on this
        // binding's own `self.link`, byte-identical to today. Keepalive / close
        // are per-link and bypass routing ([`Self::send_wire_this_link`]).
        //
        // R311y217 — `priority` is the SECOND routing key: `select_link` pins each
        // `(priority, reliability)` conduit to one link. Callers MUST pass the
        // priority of the FRAME being emitted (for a batch flush that is the open
        // frame's `batch.priority`, NOT the triggering message's priority — else
        // one conduit splits across links and the peer's per-conduit RX SN gate
        // drops the reorder). A non-multilink build never routes, so the key is
        // unused there.
        #[cfg(not(feature = "transport-multilink"))]
        let _ = priority;
        #[cfg(feature = "transport-multilink")]
        if let Some(target) = self.select_link(reliability, priority) {
            self.emit_on_link(&target, bytes, reliability);
            return;
        }
        self.emit_on_link(&self.link, bytes, reliability);
    }

    /// R311y205 (transport-multilink IMPL-2b-iii) — emit a wire batch on ONE
    /// specific link: stamp THAT link's `last_outbound_at` (per-link keepalive
    /// suppression baseline), apply compression, and hand the bytes to its
    /// driver. The single seam both the reliability-routed [`Self::send_wire`]
    /// (data) and the per-link [`Self::send_wire_this_link`] (keepalive / close)
    /// funnel through, so every TX path stamps the link it actually used. At N=1
    /// `link` is always `&self.link`, byte-identical to the pre-split emit.
    ///
    /// R311y516 — the establishment codecs are ROLE-CONJOINED (see
    /// [`Self::send_wire`]): both funnels into this seam are themselves
    /// role-gated, so an establishment codec with neither unicast role reaches
    /// it from nowhere.
    #[cfg(any(
        all(
            any(feature = "codec-init-body", feature = "codec-open-body"),
            any(feature = "session-unicast-open", feature = "session-unicast-accept")
        ),
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
        feature = "transport-batching",
        feature = "transport-keepalive",
    ))]
    fn emit_on_link(&self, link: &LinkState<R>, bytes: &[u8], reliability: Reliability) {
        let now = self.clock.now_monotonic_ms();
        R::with_mutex_mut(&link.last_outbound_at, |slot| *slot = Some(now));

        // R2371 (`transport-stats`) — charge ONE wire write to the counters, on
        // the side the driver's `LinkSendOutcome` puts it.
        //
        // A write the driver ACCEPTED is one transport message of `wire_bytes`
        // on the wire; a write it REFUSED reached no wire at all, so it charges
        // `n_dropped` and leaves `bytes` / `t_msgs` alone — `bytes` is a counter
        // of SENT bytes, and counting a refused write there would make the two
        // disagree about the same event.
        //
        // The `1` is not a magic number: one call of this is one wire write, and
        // one wire write is one transport message in this tree (see the
        // `crate::stats` module docs on `t_msgs`). The byte figure travels with
        // it because `StatDrop` takes both and only the LowPass arm reads the
        // bytes — upstream's shape, kept rather than special-cased here.
        //
        // A CLOSURE rather than a method, deliberately: its only caller is this
        // seam, whose `#[cfg]` is a seventeen-feature union. As a method it
        // needed that union copied verbatim to stay alive in exactly the same
        // builds, and the copy went stale immediately — Layer C1m's no_std lwip
        // build compiles neither, and `-D dead-code` caught the method there.
        // A closure is scoped to the seam by construction, so the two cannot
        // drift apart at all.
        let count_tx_wire = |_wire_bytes: usize, _outcome: crate::link::LinkSendOutcome| {
            #[cfg(feature = "transport-stats")]
            match _outcome {
                crate::link::LinkSendOutcome::Sent => self.stats.inc_tx(_wire_bytes),
                crate::link::LinkSendOutcome::Dropped(_) => {
                    self.stats
                        .inc_tx_drop(crate::stats::StatDrop::Transport, 1, _wire_bytes)
                }
            }
        };
        // transport-compression — once compression is ACTIVE, every
        // post-establishment batch is lz4-wrapped here (the wz analogue of
        // zenoh's finalize-then-write-to-link), and the link layer then
        // length-frames the [BatchHeader][payload] (zenoh's
        // [length][header][payload]). Every condition — negotiated,
        // post-establishment, and NOT on a lean lowlatency link — lives in
        // `compresses_batches`, which the RX un-wrap consults too so the two
        // directions cannot disagree. R311y434 added the lowlatency conjunct: wz
        // used to wrap OUTSIDE the lean encode, which no zenoh peer can read.
        #[cfg(feature = "transport-compression")]
        if self.compresses_batches() {
            let wrapped = crate::compression::compress_batch(bytes);
            // transport-stats — count the ACTUAL wire bytes (post-compression).
            let outcome = link.link_driver().send_blocking(&wrapped, reliability);
            count_tx_wire(wrapped.len(), outcome);
            return;
        }
        let outcome = link.link_driver().send_blocking(bytes, reliability);
        count_tx_wire(bytes.len(), outcome);
    }

    /// R311y205 (transport-multilink IMPL-2b-iii) — emit on THIS binding's own
    /// link, bypassing reliability routing. Keepalive and CLOSE are per-link
    /// control (zenoh keepalives each link on its own timer; a link-only close
    /// targets that link), so they must reach the physical link the drive loop
    /// monitors — NOT the reliability-selected data link. At N=1 identical to
    /// [`Self::send_wire`].
    #[cfg(any(feature = "codec-close", feature = "transport-keepalive",))]
    fn send_wire_this_link(&self, bytes: &[u8], reliability: Reliability) {
        self.emit_on_link(&self.link, bytes, reliability);
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
            // R311kl — the min(local, peer) reduction on batch_size is
            // core transport (pico runs it outside every
            // Z_FEATURE_BATCHING gate, unicast/transport.c:135-140).
            // The former R311cb transport-batching gate skipped the
            // reduction with the feature off, so the InitAck ENLARGED
            // a smaller InitSyn advertisement and foreign pico
            // initiators rejected the session (R311fg).
            // R311kj — min over the EFFECTIVE own advertisement (0 =
            // unset would otherwise pin the InitAck to a literal 0 on
            // the wire); the peer side is already 0-normalized by the
            // from_init_body projection.
            params.batch_size = params.effective_batch_size().min(p.batch_size);
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

    /// R311qh — the remote peer's zid as learned at handshake (from the inbound
    /// InitSyn on the Accepting side, or the inbound InitAck on the Initiating
    /// side), or `None` before the INIT exchange has populated it. The routing
    /// layer's per-face peer identity — the key a peer-mesh graph keys faces on.
    /// Reads [`remote_peer_zid`](Self::remote_peer_zid); see that field for why
    /// it is distinct from the R86 cookie-HMAC slot.
    pub fn peer_zid(&self) -> Option<Vec<u8>> {
        R::with_mutex_mut(&self.remote_peer_zid, |slot| slot.clone())
    }

    /// R311td — the remote peer's WhatAmI role as the 2-bit INIT wire form
    /// (0 Router, 1 Peer, 2 Client), or `None` before the INIT exchange populated
    /// it. The raw wire datum (see [`peer_whatami`](Self::peer_whatami)); the
    /// routing boundary maps it to the graph's API-form role. Mirrors
    /// [`peer_zid`](Self::peer_zid) — raw wire identity here, routing-form derived
    /// at the driver — keeping session-core routing-agnostic.
    pub fn peer_whatami_wire(&self) -> Option<u8> {
        R::with_mutex_mut(&self.peer_whatami, |slot| *slot)
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
    /// R311kj — `0` ("unset") is an INTERNAL sentinel only: the own
    /// side reads [`SessionInitParams::effective_batch_size`] (the same
    /// value `encode_init` put on the wire — 0 never reaches a peer),
    /// and the peer side reads the captured [`PeerInitCaps`], whose
    /// `from_init_body` projection 0-normalizes a legacy/non-conforming
    /// wire 0 defensively. zenoh-pico never advertises 0 (default
    /// `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`) and ADOPTS a literal 0
    /// (transport.c:135-136), which is exactly why wz must not emit it.
    ///
    /// R311kl — feature-independent: the peer projection honors the
    /// advertisement in every build (the former R311cb
    /// `transport-batching` clamp made batching-off builds ignore the
    /// peer RX budget even for fragment sizing).
    pub fn negotiated_batch_mtu(&self) -> usize {
        // R311kj — both sides are 0-normalized at their SSOT
        // (own: effective_batch_size, the same value the InitSyn wire
        // carried; peer: the from_init_body projection), so the min is
        // a plain min — no sentinel arms here.
        //
        // R311nw — the LINK MTU joins the min as a third bound. A
        // frame-bounded link (serial: `SERIAL_MTU` 1500) caps the TX
        // budget below the negotiated batch so an oversize message
        // fragments to chunks the link can actually emit — exactly how
        // zenoh-pico sizes its TX wbuf `min(zl->_mtu, batch_size)`
        // (transport/unicast/transport.c:47). The advertised batch is
        // NOT itself reduced (pico does not either — the peer's RX
        // budget stays the full advertisement); only this TX-side budget
        // is link-capped. For an unbounded stream link the term is
        // [`BoxedLinkDriver::link_mtu`]'s `DEFAULT_LINK_MTU` (65535),
        // inert against the `u16` batch advertisements, so TCP / UDP are
        // unchanged.
        let own = self.params.effective_batch_size() as usize;
        let link = self.link_driver().link_mtu();
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        match peer {
            Some(p) => own.min(p.batch_size as usize).min(link),
            None => own.min(link),
        }
    }

    /// Declare the largest message this profile can reassemble, in bytes —
    /// see [`SessionCore::max_reassembly_bytes`]. The host passes its own
    /// reassembly pool's slot size (the AP tokio host: the
    /// `reassembly_pool_ap` `SLOT_SIZE`); nothing negotiates it, because it
    /// describes THIS side's staging budget, not the peer's.
    ///
    /// Configured once, before data flows. Sends above the cap are refused
    /// with [`SendWireError::ExceedsReassemblyCap`] rather than emitted into
    /// a chain the receiver drops mid-stage.
    #[cfg(feature = "transport-fragmentation")]
    pub fn set_max_reassembly_bytes(&self, bytes: usize) {
        R::with_mutex_mut(&self.max_reassembly_bytes, |slot| *slot = bytes);
    }

    /// The configured reassembly cap, or `usize::MAX` when the host declared
    /// none. Resolved BEFORE the `tx_mutex` hold by
    /// [`Self::dispatch_network_message`], for the same disjoint-mutex
    /// discipline `negotiated_batch_mtu` / `negotiated_sn_mask` follow.
    #[cfg(feature = "transport-fragmentation")]
    pub fn max_reassembly_bytes(&self) -> usize {
        R::with_mutex_mut(&self.max_reassembly_bytes, |slot| *slot)
    }

    /// R2238 (open-debt item 580) — declare how many more `T_MID_FRAGMENT`
    /// messages this session may emit; see
    /// [`SessionCore::fragment_tx_budget`]. `usize::MAX` restores the default
    /// "unbounded".
    ///
    /// This both SETS and REFILLS: a session whose budget ran out resumes
    /// fragmenting from the next chain onward once a host calls this again.
    /// There is no partial-chain resume — an abandoned chain is abandoned,
    /// which is what its stop fragment told the peer.
    #[cfg(feature = "transport-fragmentation")]
    pub fn set_fragment_tx_budget(&self, fragments: usize) {
        R::with_mutex_mut(&self.fragment_tx_budget, |slot| *slot = fragments);
    }

    /// Fragments this session may still emit, or `usize::MAX` when the host
    /// declared no budget.
    ///
    /// ⚠ Reading this to decide whether a chain will fit is exactly the
    /// pre-check [`SessionCore::fragment_tx_budget`] explains must not
    /// happen — the value can change between this read and the next
    /// fragment. It is here for hosts and tests to OBSERVE the resource, not
    /// for the emit path to plan against.
    #[cfg(feature = "transport-fragmentation")]
    pub fn fragment_tx_budget(&self) -> usize {
        R::with_mutex_mut(&self.fragment_tx_budget, |slot| *slot)
    }

    /// Draw ONE fragment credit, reporting whether it was available.
    ///
    /// The unbounded default (`usize::MAX`) always succeeds and never
    /// decrements, so an unconfigured session cannot exhaust and cannot
    /// saturate its own counter downward into a false exhaustion.
    ///
    /// ⚠ The cfg is [`Self::emit_frame_or_fragments`]' OWN, repeated —
    /// `transport-fragmentation` alone is not the condition. That method is
    /// this draw's only caller and is itself gated on a codec/declare arm
    /// existing to frame anything, so a build with fragmentation ON and every
    /// emitter OFF compiles the fragmenter and nothing that reaches it; the
    /// draw is then dead code and `-D warnings` refuses the crate. MEASURED,
    /// R2238: `--features transport-qos,transport-fragmentation,
    /// transport-batching,reassembly,session-multicast` is exactly that
    /// combination, and pre-push gate 4b is what found it — no lane this
    /// round ran by hand composes it. The repetition is deliberate rather
    /// than a helper: if the two lists ever disagree, THIS error is what says
    /// so, which a shared `allow(dead_code)` would have silenced instead.
    #[cfg(all(
        feature = "transport-fragmentation",
        any(
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
        )
    ))]
    fn take_fragment_tx_credit(&self) -> bool {
        R::with_mutex_mut(&self.fragment_tx_budget, |slot| {
            if *slot == usize::MAX {
                return true;
            }
            if *slot == 0 {
                return false;
            }
            *slot -= 1;
            true
        })
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
        // R311y816 — the ring origin is DERIVED here, not carried from
        // construction. `params.initial_sn` is a literal `0` at every host
        // (`wz-ap-demo/src/args.rs`, `wz-capi-core/src/drive.rs`,
        // `wz-replay/src/live.rs`, `wz-mcu-session-acceptor/src/lib.rs`), so
        // before this every wz session announced the same origin; both
        // upstreams announce a per-session one. This is zenoh's Open seam
        // exactly — `compute_sn(mine, other, resolution)` runs while BUILDING
        // the OpenSyn (`establishment/open.rs:440`) and the OpenAck
        // (`accept.rs:646`), never at transport construction, because the
        // peer zid and the negotiated FrameSN resolution are both INIT
        // results.
        //
        // Resolved OUTSIDE the ext-chain closure for the R311di-pre-f5
        // reason `encode_init_with_role` records above it: this reads
        // `remote_peer_zid` and (through `negotiated_sn_mask`)
        // `inbound_peer_init_caps`, and a nested `R::with_mutex_mut` would
        // deadlock the non-reentrant lwIP `critical_section`.
        let params_owned = self.open_params();
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            let params = params_owned.as_ref().unwrap_or(&self.params);
            encode_open(params, is_ack, cookie_override, chain)
        })
    }

    /// R311y816 — the Open-body params with the DERIVED `initial_sn`
    /// substituted, or `None` when the peer zid is not yet known (no INIT
    /// exchange has landed, which no production Open emit can be past).
    ///
    /// Re-seeding the TX conduits is part of the SAME call rather than a
    /// second step a caller could forget: the announced origin and the first
    /// minted Frame SN are one fact, and
    /// [`next_outbound_frame_sn`](Self::next_outbound_frame_sn)'s contract is
    /// that its first value equals what the Open body carried. Doing it here
    /// keeps that true for a value the constructor could not have known.
    ///
    /// The re-seed REWINDS the conduits to the origin, and that is a
    /// handshake-scoped operation, stated plainly rather than papered over:
    /// an Open frame carries no SN itself and is emitted exactly once per
    /// session incarnation, ahead of every data frame (the unicast FSM fires
    /// `send_open_syn` / `send_open_ack` on one transition each; a reopen
    /// runs `reset_for_reopen` and a fresh handshake). Calling this against
    /// a session that has already minted data SNs would rewind them, so it
    /// stays private to the encode seam.
    ///
    /// What IS idempotent is the VALUE: [`crate::initial_sn::derive_initial_sn`]
    /// is a pure function of `(own zid, peer zid, mask)`, so a redial to the
    /// same peer re-derives the same origin with nothing persisted between
    /// attempts — the multilink property zenoh's `compute_sn` comment names
    /// as the reason for hashing rather than drawing entropy.
    #[cfg(feature = "codec-open-body")]
    fn open_params(&self) -> Option<SessionInitParams> {
        let peer_zid = self.peer_zid()?;
        let mask = self.negotiated_sn_mask();
        let initial_sn = crate::initial_sn::derive_initial_sn(&self.params.zid, &peer_zid, mask);
        self.outbound_frame_sn.reset(initial_sn);
        let mut params = self.params.clone();
        params.initial_sn = initial_sn;
        Some(params)
    }

    fn ext_chain_slot(&self, role: ExtChainRole) -> &R::Mutex<Vec<ExtEntryOwned>> {
        match role {
            ExtChainRole::InitSyn => &self.init_syn_ext,
            ExtChainRole::InitAck => &self.init_ack_ext,
            ExtChainRole::OpenSyn => &self.open_syn_ext,
            ExtChainRole::OpenAck => &self.open_ack_ext,
        }
    }

    /// R3b — install the configured Z_EXT_AUTH dispatch. The AP layer builds it
    /// with the usrpwd method(s) + a fresh OS-entropy challenge nonce and calls
    /// this once at session bring-up, replacing the empty default (which emits
    /// no auth ext and admits every stage).
    #[cfg(feature = "session-extauth")]
    pub fn install_auth_dispatch(&self, dispatch: AuthDispatch) {
        R::with_mutex_mut(&self.auth, |slot| *slot = dispatch);
    }

    /// R3b — refresh the responder challenge nonce: a FRESH cryptographically
    /// random `nonce` per accepted handshake (the [`crate::extauth_usrpwd`]
    /// replay-defense contract). The no_std core draws no entropy, so the AP
    /// accept path supplies it before the InitAck stage — and again on a
    /// re-handshake, since the ext slots (and thus a stale auth ext) survive
    /// [`Self::reset_for_reopen`].
    #[cfg(feature = "session-extauth")]
    pub fn refresh_auth_challenge_nonce(&self, nonce: u64) {
        R::with_mutex_mut(&self.auth, |d| d.set_challenge_nonce(nonce));
    }

    /// R311y813 — install the per-handshake cookie nonce, the term that binds
    /// the Accepting side's anti-amplification cookie to ONE handshake (the
    /// `cookie_nonce` slot). Sibling of `refresh_auth_challenge_nonce` and
    /// supplied the same way and for the same reason: the no_std core draws no
    /// entropy, so the host that has a source installs it. Both siblings are
    /// named as code spans rather than links — one is `session-extauth`-gated
    /// and the other shares its name with a field, so a link would resolve in
    /// some feature subsets and ambiguously in the rest.
    ///
    /// **Ungated, unlike the auth nonce.** The cookie is not an optional
    /// extension — every acceptor mints one on InitAck — so a build that
    /// carries the accept path at all carries this, and gating it would make
    /// the fail-closed default the shipped behaviour in some feature subsets.
    ///
    /// Call it BEFORE the FSM reaches `SentInitAck`, i.e. before the InitSyn
    /// that starts the handshake is dispatched; the AP profile does it at
    /// construction (`new_session_actions`) so no accept seam can forget, the
    /// way the auth seam had to be remembered at each of its entry points.
    ///
    /// **On a re-handshake.** The slot survives
    /// [`reset_for_reopen`](Self::reset_for_reopen), so a bundle that
    /// re-handshakes IN THE ACCEPTOR ROLE and is not refreshed re-mints the
    /// cookie its previous handshake used — narrower than the deploy-lifetime
    /// window this round closed, but the same shape. wz's reopen path is the
    /// initiator-role auto-reconnect (`ReconnectingSession` builds a FRESH
    /// bundle per attempt), so nothing reaches it today; a host that later
    /// reopens as acceptor should call this again, exactly as the auth seam
    /// documents for its own nonce.
    pub fn refresh_cookie_nonce(&self, nonce: u64) {
        R::with_mutex_mut(&self.cookie_nonce, |slot| *slot = Some(nonce));
    }

    /// R311y813 — the installed per-handshake cookie nonce, or `None` when no
    /// host has supplied one (the fail-closed default).
    ///
    /// The acceptor's own state, exposed for the same reason zenoh carries its
    /// nonce out of `send_init_ack` in `SendInitAckOut`: something has to be
    /// able to say which handshake this is. In-process only — it is never
    /// serialized, and a test that wants to reproduce the minted cookie reads
    /// it here rather than assuming the derivation is nonce-free.
    pub fn cookie_nonce(&self) -> Option<u64> {
        R::with_mutex_mut(&self.cookie_nonce, |slot| *slot)
    }

    /// R3b — run `f` against the auth dispatch under its mutex. The recv-stage
    /// driver ([`crate::drive::dispatch_link_event`]) calls this to feed a
    /// parsed handshake frame's ext chain into the matching demux stage; the
    /// mutex detail stays here while the per-event stage routing stays at the
    /// drive seam (beside the existing per-event admission match).
    #[cfg(feature = "session-extauth")]
    pub fn with_auth<U>(&self, f: impl FnOnce(&mut AuthDispatch) -> U) -> U {
        R::with_mutex_mut(&self.auth, f)
    }

    /// R3b — run the auth dispatch's send stage for `role` and install the
    /// resulting auth ext (id [`AUTH_EXT_ID`](crate::extauth::AUTH_EXT_ID)) into
    /// that role's ext chain, IDEMPOTENTLY: any prior auth ext is dropped first
    /// so a re-handshake's re-send never duplicates it (the slots persist across
    /// `reset_for_reopen`). `None` (no method contributes) just clears any stale
    /// auth ext. The shipped methods' send stages are infallible; a fallible
    /// future method's failure would surface on the peer's recv-stage reject,
    /// not here, so a send-stage error is swallowed (no auth ext emitted).
    ///
    /// Gated on the UNION of its four send-action callers (each pairs a body
    /// codec with a role), so a `session-extauth`-only subset that compiles no
    /// send action does not carry it as dead code under `-D warnings`.
    #[cfg(all(
        feature = "session-extauth",
        any(feature = "codec-init-body", feature = "codec-open-body"),
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ))]
    fn stage_auth_send(
        &self,
        role: ExtChainRole,
        produce: impl FnOnce(
            &mut AuthDispatch,
        ) -> Result<Option<ExtEntryOwned>, crate::auth_dispatch::AuthError>,
    ) {
        let ext = R::with_mutex_mut(&self.auth, produce).ok().flatten();
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            chain.retain(|e| e.ext_id() != crate::extauth::AUTH_EXT_ID);
            if let Some(ext) = ext {
                chain.push(ext);
            }
        });
    }

    // ─────────────── R311y205 transport-multilink (IMPL-2b-ii) ───────────────

    /// Install the 0x4 Z_EXT_MULTILINK establishment dispatch, injected by the AP
    /// layer at session bring-up when `max_links > 1` (the
    /// [`Self::install_auth_dispatch`] discipline). Its presence is the
    /// "this session negotiates multilink" switch: an installed dispatch makes the
    /// four send sites emit the 0x4 ext and the recv seam consume it; without it
    /// the handshake is byte-identical to a non-multilink open. The concrete
    /// ephemeral-pubkey method is std-only (`rsa`), so it is built in the AP crate
    /// and handed in through the rsa-free [`MultiLinkDispatch`](crate::extmultilink::MultiLinkDispatch).
    #[cfg(feature = "transport-multilink")]
    pub fn install_multilink_dispatch(&self, dispatch: crate::extmultilink::MultiLinkDispatch) {
        R::with_mutex_mut(&self.multilink, |slot| *slot = Some(dispatch));
    }

    /// Refresh the responder challenge nonce on the installed multilink dispatch —
    /// a FRESH cryptographically-random `nonce` per accepted handshake (the pubkey
    /// responder replay-defense contract, [`Self::refresh_auth_challenge_nonce`]
    /// for the 0x4 ext). No-op when no dispatch is installed (max_links=1).
    #[cfg(feature = "transport-multilink")]
    pub fn refresh_multilink_challenge_nonce(&self, nonce: u64) {
        R::with_mutex_mut(&self.multilink, |slot| {
            if let Some(d) = slot.as_mut() {
                d.set_challenge_nonce(nonce);
            }
        });
    }

    /// Run `f` against the installed multilink dispatch (the recv-stage driver at
    /// [`crate::drive::dispatch_link_event`] feeds a parsed handshake frame's ext
    /// chain into the matching 0x4 demux stage, beside the auth demux).
    /// `None` when no dispatch is installed (max_links=1) — the peer's 0x4 ext, if
    /// any, is then ignored (this node did not negotiate multilink).
    #[cfg(feature = "transport-multilink")]
    pub fn with_multilink<U>(
        &self,
        f: impl FnOnce(&mut crate::extmultilink::MultiLinkDispatch) -> U,
    ) -> Option<U> {
        R::with_mutex_mut(&self.multilink, |slot| slot.as_mut().map(f))
    }

    /// Latch the peer's captured ephemeral multilink pubkey (encoded ZPublicKey
    /// bytes) out of the installed dispatch into [`SessionCore::multilink_pubkey`]
    /// — the session-identity slot the aggregation join gate compares against.
    /// Called from the recv seam after each 0x4 demux stage; idempotent (the
    /// dispatch surfaces the key only once the capturing stage has run, and the
    /// same key re-latches identically).
    #[cfg(feature = "transport-multilink")]
    pub fn capture_multilink_pubkey(&self) {
        let captured = R::with_mutex_mut(&self.multilink, |slot| {
            slot.as_ref().and_then(|d| d.captured_peer_pubkey())
        });
        if let Some(bytes) = captured {
            R::with_mutex_mut(&self.multilink_pubkey, |slot| *slot = Some(bytes));
        }
    }

    /// The peer's captured ephemeral multilink pubkey (encoded ZPublicKey bytes),
    /// or `None` before the 0x4 handshake latched it (or on a non-multilink
    /// session). The join gate's config-equality key.
    #[cfg(feature = "transport-multilink")]
    pub fn multilink_pubkey(&self) -> Option<Vec<u8>> {
        R::with_mutex_mut(&self.multilink_pubkey, |slot| slot.clone())
    }

    /// Set this binding's link reliability preference at bring-up (before the
    /// drive loop spins), through the shared `R::Shared<LinkState>` handle — the
    /// `set_lowlatency_offer` config-at-bringup discipline. Read by
    /// [`Self::select_link`] to segregate the reliable / best-effort channels.
    #[cfg(feature = "transport-multilink")]
    pub fn set_link_reliability_pref(&self, pref: LinkReliabilityPref) {
        R::with_mutex_mut(&self.link.reliability_pref, |s| *s = pref);
    }

    /// R311y217 — set this binding's link QoS-priority band at bring-up (before
    /// the drive loop spins), through the shared `R::Shared<LinkState>` handle —
    /// the `set_link_reliability_pref` config-at-bringup discipline. Read by
    /// [`Self::select_link`] to pin each `(priority, reliability)` conduit to one
    /// link. `None` clears the band (reliability-only, partial-tier candidate).
    #[cfg(all(feature = "transport-multilink", feature = "transport-qos"))]
    pub fn set_link_priority_range(&self, range: Option<LinkPriorityRange>) {
        R::with_mutex_mut(&self.link.priority_range, |s| *s = range);
    }

    /// Run the multilink dispatch's send stage for `role` and install the
    /// resulting 0x4 [`Z_EXT_MULTILINK`](crate::extmultilink::MULTILINK_EXT_ID)
    /// ext into that role's ext chain, IDEMPOTENTLY (a re-handshake never
    /// duplicates it) — the 0x4 twin of [`Self::stage_auth_send`]. NO dispatch
    /// installed (max_links=1) ⇒ no 0x4 ext staged, so the handshake stays
    /// byte-identical to a non-multilink open.
    #[cfg(all(
        feature = "transport-multilink",
        any(feature = "codec-init-body", feature = "codec-open-body"),
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ))]
    fn stage_multilink_send(
        &self,
        role: ExtChainRole,
        produce: impl FnOnce(
            &mut crate::extmultilink::MultiLinkDispatch,
        ) -> Result<Option<ExtEntryOwned>, crate::auth_dispatch::AuthError>,
    ) {
        let ext = R::with_mutex_mut(&self.multilink, |slot| {
            slot.as_mut().and_then(|d| produce(d).ok().flatten())
        });
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            chain.retain(|e| e.ext_id() != crate::extmultilink::MULTILINK_EXT_ID);
            if let Some(ext) = ext {
                chain.push(ext);
            }
        });
    }

    // ─────────── R311y205 transport-multilink aggregation (IMPL-2b-iii) ──────

    /// Reliability-routed link selection — the wz mirror of zenoh's per-channel
    /// `select` (`unicast/universal/tx.rs`): pick, among the ALIVE links of the
    /// aggregation set, the one preferring `reliability`'s channel; failing that,
    /// the first alive link (homogeneous / failover). `None` when the set is
    /// EMPTY (a single-link, non-aggregating session — [`Self::send_wire`] then
    /// uses `self.link`) OR when every link is dead (the send then falls through
    /// to `self.link`, whose F2 gate rejects it typed). Reads each link's
    /// `transport_available` (liveness) + `reliability_pref` under their mutexes.
    ///
    /// R311y205 (slice-1 MF-E) — gated on the EXACT codec union of its sole caller
    /// [`Self::send_wire`]: codec-close + transport-keepalive are EXCLUDED (those
    /// TX paths route through `send_wire_this_link`, not `send_wire`, so a build
    /// with ONLY codec-close / transport-keepalive has no `select_link` caller and
    /// must not carry the dead seam — the same cfg-skew class run-ci caught for
    /// `send_wire`). It names [`Reliability`] (codec-union-gated import), so a
    /// `transport-multilink`-only build with no data-send codec omits it too.
    #[cfg(all(
        feature = "transport-multilink",
        any(
            feature = "codec-init-body",
            feature = "codec-open-body",
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
            feature = "transport-batching",
        )
    ))]
    fn select_link(
        &self,
        reliability: Reliability,
        priority: Priority,
    ) -> Option<R::Shared<LinkState<R>>> {
        let links = self.links.lock().expect("multilink set mutex");
        if links.is_empty() {
            return None;
        }
        let want = match reliability {
            Reliability::Reliable => LinkReliabilityPref::Reliable,
            Reliability::BestEffort => LinkReliabilityPref::BestEffort,
        };
        // A non-qos build carries no per-link priority band, so selection degrades
        // to the reliability-only 2-tier (byte-identical to pre-y217); `priority`
        // is then unused (workspace warnings=deny).
        #[cfg(not(feature = "transport-qos"))]
        let _ = priority;
        let mut first_alive: Option<&R::Shared<LinkState<R>>> = None;
        // partial tier: a reliability-pref match with NO covering priority band
        // (in a non-qos build this IS the pre-y217 "preferred" tier).
        let mut partial: Option<&R::Shared<LinkState<R>>> = None;
        // full tier (qos only): reliability-pref match AND the band contains the
        // priority; keep the SMALLEST band (most specific), ties -> first-seen.
        #[cfg(feature = "transport-qos")]
        let mut full: Option<(&R::Shared<LinkState<R>>, usize)> = None;
        for l in links.iter() {
            if !R::with_mutex_mut(&l.transport_available, |g| *g) {
                continue;
            }
            if first_alive.is_none() {
                first_alive = Some(l);
            }
            if R::with_mutex_mut(&l.reliability_pref, |p| *p) != want {
                // Wrong reliability class -> only ever a first-alive fallback
                // (LinkReliabilityPref::Any never equals `want`, so it lands here
                // too — the failover pool, matching the pre-y217 contract and
                // zenoh's concrete-reliability primacy: a non-matching link can
                // never be a full/partial pick).
                continue;
            }
            // Reliability matches. In a qos build a covering band promotes this
            // link to the full tier.
            #[cfg(feature = "transport-qos")]
            if let Some(band) = R::with_mutex_mut(&l.priority_range, |r| *r) {
                if band.contains(priority) {
                    let width = band.width();
                    // Strict `>` (zenoh tx.rs:56): a later equal-width band does
                    // NOT displace the incumbent, so ties resolve to first-seen =
                    // a stable, non-flapping pin (one-conduit=one-link).
                    if full.map_or(true, |(_, prev)| prev > width) {
                        full = Some((l, width));
                    }
                    continue;
                }
            }
            // partial: reliability matches, no covering band.
            if partial.is_none() {
                partial = Some(l);
            }
        }
        #[cfg(feature = "transport-qos")]
        let selected = full.map(|(l, _)| l).or(partial).or(first_alive);
        #[cfg(not(feature = "transport-qos"))]
        let selected = partial.or(first_alive);
        selected.cloned()
    }

    /// Register the FIRST physical link of a session that is about to aggregate —
    /// idempotent: pushes `link` into the (previously empty) shared set so
    /// [`Self::select_link`] can route across it once a second link joins. Called
    /// at the multilink JOIN when link 2 arrives (link 1 was driving single-link
    /// with an empty set until then). A no-op if the set already holds links.
    #[cfg(feature = "transport-multilink")]
    pub fn register_first_link(&self, link: R::Shared<LinkState<R>>) {
        let mut links = self.links.lock().expect("multilink set mutex");
        if links.is_empty() {
            links.push(link);
        }
    }

    /// Attach a SECOND+ link's [`LinkState`] to this shared core's aggregation
    /// set. The [`PubkeyBound`] witness — constructible ONLY by
    /// [`Self::authorize_link`]'s config-equality check — proves the link
    /// presented the SAME ephemeral multilink pubkey, so a mismatched /
    /// unauthenticated link is unrepresentable as an `add_link` argument (the
    /// illegal-state-unrepresentable gate). Returns the new live link count.
    #[cfg(feature = "transport-multilink")]
    pub fn add_link(&self, link: R::Shared<LinkState<R>>, _bound: PubkeyBound) -> usize {
        let mut links = self.links.lock().expect("multilink set mutex");
        links.push(link);
        links.len()
    }

    /// Config-equality gate: authorize a second link IFF its captured ephemeral
    /// multilink pubkey is byte-equal to this session's bound pubkey
    /// ([`SessionCore::multilink_pubkey`]) — the wz analogue of zenoh's
    /// `init_existing_transport_unicast` pubkey check. `Some(PubkeyBound)` (the
    /// [`Self::add_link`] witness) on match; `None` on mismatch (the caller then
    /// closes the link INVALID) or when no pubkey is bound yet.
    #[cfg(feature = "transport-multilink")]
    pub fn authorize_link(&self, candidate_pubkey: &[u8]) -> Option<PubkeyBound> {
        let bound = R::with_mutex_mut(&self.multilink_pubkey, |slot| slot.clone());
        match bound {
            Some(b) if b.as_slice() == candidate_pubkey => Some(PubkeyBound(())),
            _ => None,
        }
    }

    /// Remove a link from the aggregation set on its loss / close (`del_link`),
    /// matched by pointer identity of the shared `LinkState`. Returns the number
    /// of links REMAINING — the whole-session teardown fires only when this hits
    /// `0` (the session survives while ≥1 link is in the set).
    #[cfg(feature = "transport-multilink")]
    pub fn del_link(&self, link: &R::Shared<LinkState<R>>) -> usize {
        let target: *const LinkState<R> = &**link;
        let mut links = self.links.lock().expect("multilink set mutex");
        links.retain(|l| {
            let p: *const LinkState<R> = &**l;
            !core::ptr::eq(p, target)
        });
        links.len()
    }

    /// Total links in the aggregation set (alive or not). `0` for a single-link
    /// (non-aggregating) session. The multilink join's `max_links` room check
    /// reads this.
    #[cfg(feature = "transport-multilink")]
    pub fn link_count(&self) -> usize {
        self.links.lock().expect("multilink set mutex").len()
    }

    /// The number of links currently ALIVE (`transport_available`). The session-
    /// send gate is `> 0` (the OR over links) — a session with an empty or all-
    /// dead set is down. Distinct from [`Self::link_count`] (which counts dead
    /// links too, e.g. a link mid-teardown before `del_link`).
    #[cfg(feature = "transport-multilink")]
    pub fn live_link_count(&self) -> usize {
        self.links
            .lock()
            .expect("multilink set mutex")
            .iter()
            .filter(|l| R::with_mutex_mut(&l.transport_available, |g| *g))
            .count()
    }

    /// The session-level send gate: is ANY link able to carry a data send? For an
    /// AGGREGATING session it is the OR over the link set's `transport_available`
    /// (the session is up while ≥1 link is live — a dead link fails over); for a
    /// SINGLE-link session (empty set) it is this binding's own `self.link` F2
    /// gate, byte-identical to the pre-multilink behavior. Read on the data send
    /// hot path ([`Self::dispatch_network_message`]) — gated on the SAME codec
    /// union as its sole caller so a minimal subset build (no data-send codec)
    /// does not carry it as dead code under `-D warnings`.
    #[cfg(all(
        feature = "transport-multilink",
        any(
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
        )
    ))]
    fn session_send_available(&self) -> bool {
        if self.link_count() > 0 {
            return self.live_link_count() > 0;
        }
        R::with_mutex_mut(&self.link.transport_available, |g| *g)
    }

    /// Non-multilink builds have no aggregation set — the send gate is always this
    /// binding's own link F2 gate. Same codec-union gate as the multilink variant.
    #[cfg(all(
        not(feature = "transport-multilink"),
        any(
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
        )
    ))]
    #[inline]
    fn session_send_available(&self) -> bool {
        R::with_mutex_mut(&self.link.transport_available, |g| *g)
    }

    /// The number of 0x4 Z_EXT_MULTILINK entries staged across this session's four
    /// establishment ext chains — the byte-level "did this handshake negotiate
    /// multilink?" probe. `0` for a non-multilink (max_links=1) open, whose
    /// handshake is byte-identical to today (no dispatch installed ⇒
    /// [`Self::stage_multilink_send`] stages nothing); `> 0` once a multilink send
    /// stage has run. Reads only the staged chains, no wire capture.
    #[cfg(feature = "transport-multilink")]
    pub fn staged_multilink_ext_count(&self) -> usize {
        let count_in = |slot: &R::Mutex<Vec<ExtEntryOwned>>| {
            R::with_mutex_mut(slot, |chain| {
                chain
                    .iter()
                    .filter(|e| e.ext_id() == crate::extmultilink::MULTILINK_EXT_ID)
                    .count()
            })
        };
        count_in(&self.init_syn_ext)
            + count_in(&self.init_ack_ext)
            + count_in(&self.open_syn_ext)
            + count_in(&self.open_ack_ext)
    }

    /// Emit a LINK-ONLY close (`FLAG_T_CLOSE_S` = 0) on THIS binding's link with
    /// `reason` — the aggregation-reject path. S=0 tells the peer to drop just
    /// THIS physical link while the logical session survives on its others (zenoh
    /// `close` with S unset).
    ///
    /// R311y839 — this is the UNCONDITIONAL S=0 emit, and it stays a separate
    /// method from [`Self::send_close_with_reason`] even though that one now
    /// derives the same flag. The reject fires on a link that is being refused
    /// entry to the set, so `close_scope_is_session` would read a count this link
    /// is not in and answer for the wrong session. (Until R311y839 the contrast
    /// this doc drew was with a hard-coded `S=1`; that literal is gone.)
    ///
    /// The reject reasons use zenoh's close-reason wire
    /// codes ([`CLOSE_REASON_MAX_LINKS`] / [`CLOSE_REASON_INVALID`]), NOT the wz
    /// [`CloseReason`] enum (whose discriminants differ), so the frame is
    /// cross-impl faithful. Emitted on the REJECTED link's own (throwaway) actions
    /// before it is dropped.
    #[cfg(all(feature = "transport-multilink", feature = "codec-close"))]
    pub fn send_link_close(&self, reason: u8) {
        let bytes = crate::handshake_encode::encode_close(reason, /*session=*/ false);
        self.send_wire_this_link(&bytes, Reliability::Reliable);
    }

    /// R311y839 — the SCOPE a teardown on THIS link should announce: `true` for a
    /// whole-session close (`FLAG_T_CLOSE_S` set), `false` when the session keeps
    /// running on links this one is not.
    ///
    /// Both Close emit sites route through here rather than through a literal,
    /// because the answer is a property of the LINK SET at emit time and neither
    /// site can see it otherwise. The teardown they serve is per-link by
    /// construction — the FSM's `Closing` fires on the drive loop of one link and
    /// its sibling `release_link` action removes exactly that link
    /// (`del_link(&a.link)`) — so before this method the announcement contradicted
    /// the action beside it: wz told the peer to delete the whole transport and
    /// then went on sending over the links it still held. zenoh's receiver acts on
    /// the difference (`delete()` vs `del_link(link)`,
    /// `io/zenoh-transport/src/unicast/universal/rx.rs:60-73`).
    ///
    /// The count is read BEFORE `release_link` runs, so this link is still in the
    /// set: `>= 2` means others survive it. `link_count()` is `0` for a session
    /// that never aggregated (the set is populated by `register_first_link` at
    /// join time), and `1` once this is the only member left, so both of those are
    /// the same answer — closing the only link IS closing the session.
    ///
    /// The single-link byte therefore does not move, and that is deliberate: the
    /// two references DISAGREE there and both are reachable. zenoh sends S=0 from
    /// every unicast site including the user-triggered whole-transport close
    /// (`unicast/universal/transport.rs:383-403`, whose comment records that S
    /// "should always be true for user-triggered close" and chooses `false` for
    /// multilink safety), while zenoh-pico's live lease-expiry close passes
    /// `link_only = false` and SETS the bit (`src/transport/unicast/lease.c:99` ->
    /// `_z_unicast_transport_close`, `transport.c:322-324`). Neither receiver can
    /// tell: zenoh's `del_link` on the last link closes the transport anyway
    /// (`universal/transport.rs:172-196`) and zenoh-pico never reads the bit at
    /// all (`src/transport/unicast/rx.c:309-316`). Only the multilink case changes
    /// an outcome, and there the answer is unanimous.
    #[cfg(feature = "codec-close")]
    fn close_scope_is_session(&self) -> bool {
        #[cfg(feature = "transport-multilink")]
        {
            self.link_count() <= 1
        }
        #[cfg(not(feature = "transport-multilink"))]
        {
            // No aggregation set exists, so a link is always the whole session.
            true
        }
    }

    /// transport-lowlatency — the AP layer's "this deploy offers lowlatency
    /// toward this peer" config, set once at session bring-up BEFORE the
    /// handshake drives (the wz analogue of zenoh
    /// `TransportManager::config.unicast.is_lowlatency` seeding the per-link
    /// establishment state). Seeds [`Self::is_lowlatency`]; the peer's offer is
    /// ANDed in by [`Self::negotiate_lowlatency_against_peer`].
    ///
    /// R311y216 — exclusivity guard, the reciprocal of [`Self::set_qos_offer`]'s
    /// (zenoh `manager.rs:264`: `'qos' and 'lowlatency' options are incompatible`,
    /// a SYMMETRIC and TOTAL check that bails whenever both are set, regardless of
    /// order). When a QoS offer is already staged, the lowlatency offer is REFUSED
    /// (`is_lowlatency` stays false, QoS wins) — the mirror of `set_qos_offer`
    /// refusing under a staged lowlatency. Together the two guards make the
    /// both-on state unrepresentable in EITHER staging order (first-staged wins),
    /// closing the y215 asymmetry where only `set_qos_offer` guarded. Returns
    /// `true` iff the offer was applied (a config validator can escalate on
    /// `false`); the `*_with_lowlatency` entrypoints stage only lowlatency on
    /// fresh actions, so the guard never fires there.
    #[cfg(feature = "transport-lowlatency")]
    pub fn set_lowlatency_offer(&self, offer: bool) -> bool {
        #[cfg(feature = "transport-qos")]
        if offer && self.is_qos() {
            return false;
        }
        R::with_mutex_mut(&self.is_lowlatency, |s| *s = offer);
        true
    }

    /// transport-lowlatency — AND the peer's InitSyn / InitAck lowlatency offer
    /// into the local capability: zenoh
    /// `state.is_lowlatency &= other_ext.is_some()`
    /// (`establishment/ext/lowlatency.rs:78`). Called from the establishment
    /// demux ([`crate::drive::dispatch_link_event`]) on every inbound Init
    /// frame, so the result is `local_offer && peer_offer`. The acceptor's merge
    /// lands on InitSyn arrival BEFORE it emits its InitAck (so the reflect is
    /// "still true after the AND"); the initiator's lands on InitAck arrival,
    /// finalizing the capability (zenoh finalizes lowlatency at the Init
    /// exchange — OpenSyn / OpenAck carry nothing).
    #[cfg(feature = "transport-lowlatency")]
    pub fn negotiate_lowlatency_against_peer(&self, peer_offered: bool) {
        R::with_mutex_mut(&self.is_lowlatency, |s| *s &= peer_offered);
    }

    /// R311y578 — cap this session's protocol patch level at the peer's
    /// announcement, the `min()` zenoh-pico writes as
    ///
    /// ```c
    /// if (iam._body._init._patch > tmsg._body._init._patch) {
    ///     iam._body._init._patch = tmsg._body._init._patch;
    /// }
    /// ```
    ///
    /// (`src/transport/unicast/transport.c:237-241`). Called from the
    /// establishment demux on every admitted Init frame, so the acceptor
    /// caps on InitSyn and the initiator on InitAck — the same both-sides
    /// shape as the lowlatency / compression merges above. Monotonically
    /// non-increasing, so a second Init cannot raise a level a first one
    /// lowered.
    pub fn negotiate_patch_against_peer(&self, peer_patch: u8) {
        R::with_mutex_mut(&self.negotiated_patch, |s| {
            // The first Init starts from wz's OWN announcement (R121f1 puts
            // `_Z_CURRENT_PATCH` on every Init wz sends), matching
            // zenoh-pico's `iam._patch` starting at its current level; a
            // later Init can only lower it further.
            let local = s.unwrap_or(crate::extpatch::CURRENT_PATCH);
            *s = Some(crate::extpatch::negotiate_patch(local, peer_patch));
        });
    }

    /// R311y838 — stage the ACCEPTOR's InitAck `0x7` PATCH entry at the level
    /// this session NEGOTIATED, in place of the `CURRENT` the slot was seeded
    /// with at construction.
    ///
    /// Both references answer the `min`, and both compute it at SEND time from
    /// the state the InitSyn left behind:
    ///
    /// ```text
    /// // zenoh, AcceptFsm::send_init_ack
    /// Ok(min(PatchType::CURRENT, state.patch))
    /// ```
    ///
    /// (`io/zenoh-transport/src/unicast/establishment/ext/patch.rs:180-186`,
    /// over the level `recv_init_syn` stored unexamined at :167-175, starting
    /// from `PatchType::NONE` when the InitSyn carried no entry), and
    ///
    /// ```c
    /// if (iam._body._init._patch > tmsg._body._init._patch) {
    ///     iam._body._init._patch = tmsg._body._init._patch;
    /// }
    /// ```
    ///
    /// (`src/transport/unicast/transport.c:237-241`) — pico's InitAck is BUILT
    /// carrying `_Z_CURRENT_PATCH` (`protocol/definitions/transport.c:178`) and
    /// then capped here, in the same block that caps the three size parameters.
    /// wz seeded its slot the way pico builds its message and then never ran
    /// pico's cap, so it announced `CURRENT` to every peer.
    ///
    /// ## Why this is not cosmetic
    ///
    /// The answer is the PEER's input, not ours. The negotiated level is the
    /// sole gate on the Fragment `First` / `Drop` chain-boundary markers
    /// (`PatchType::has_fragmentation_markers`), so answering above the peer's
    /// announcement tells it to expect markers on a link where they were never
    /// agreed — and an InitAck exceeding the InitSyn's level is one BOTH
    /// references refuse outright (zenoh `bail!`s at `ext/patch.rs:78-85`, pico
    /// returns `_Z_ERR_GENERIC` before building the OpenSyn at
    /// `transport.c:142-148`), which is the same rule wz itself enforces as an
    /// initiator ([`Self::init_ack_patch_acceptable`]).
    ///
    /// ## Replaced IN PLACE, not cleared and pushed
    ///
    /// Unlike `stage_capability` (a code span, not a link: it is private and
    /// cfg-gated on the four capability features, so a link would dangle in
    /// every subset that lacks them), whose entry is present only when the
    /// capability is still offered, this entry is unconditional — so the
    /// position it already holds in the chain is the wire order wz has emitted
    /// since R121f1, and only the VALUE byte is this round's business. pico
    /// likewise assigns into the message it already built rather than
    /// re-appending.
    ///
    /// ⚠ That position is a CONSERVATISM WITH NO WITNESS, measured rather than
    /// assumed: swapping this for `stage_capability`'s `retain` + `push` (which
    /// moves the entry to the chain's end whenever another ext was staged
    /// above) reds NOTHING across `wz-session-core`, `wz-runtime-tokio` and
    /// `wz-integration-tests`. Nothing should — an ext chain is order-free to
    /// both reference decoders, which walk it by header id. So this is the
    /// cheaper of two correct forms, chosen to avoid an unforced change to
    /// bytes the layer3 fixtures pin, and not a property any gate defends.
    ///
    /// The level is read BEFORE the chain guard is taken: both are per-profile
    /// mutexes and the MCU profile's is a non-reentrant critical section (the
    /// 2b-① discipline the Init encode sites follow for the same reason).
    #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
    fn stage_negotiated_patch(&self, role: ExtChainRole) {
        let level = self.negotiated_patch();
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            let entry = crate::extpatch::encode_patch_ext_at(level);
            match chain.iter().position(|e| e.ext_id() == entry.ext_id()) {
                Some(at) => chain[at] = entry,
                None => chain.push(entry),
            }
        });
    }

    /// R311y817 — the patch level THIS session put on its InitSyn, read back
    /// out of the staged chain rather than assumed.
    ///
    /// [`crate::extpatch::CURRENT_PATCH`] for every build that keeps the
    /// default slot ([`default_init_patch_ext_entry`], staged since R121f1),
    /// and [`crate::extpatch::NO_PATCH`] for one whose AP layer replaced the
    /// InitSyn chain with something that carries no patch entry. It is the
    /// `ism._body._init._patch` of zenoh-pico's InitAck check
    /// (`transport.c:142`) — the value we actually advertised, which is the
    /// only ceiling a peer can be held to.
    ///
    /// Projected through [`crate::extpatch::peer_patch`], the same function
    /// that reads a PEER's announcement, so the emitted entry and the ceiling
    /// derived from it cannot drift into two spellings (the R311y605 lesson on
    /// this exact extension).
    pub fn advertised_patch(&self) -> u8 {
        R::with_mutex_mut(&self.init_syn_ext, |chain| {
            crate::extpatch::peer_patch(chain)
        })
    }

    /// R311y817 — initiator-side InitAck PATCH admission: the ext-chain twin
    /// of `init_ack_caps_acceptable`, which validates the body's size
    /// parameters and structurally cannot see this one.
    ///
    /// `false` means the acceptor answered a level ABOVE our advertisement and
    /// the session must be rejected — zenoh `bail!`s out of
    /// `PatchFsm::recv_init_ack` (`ext/patch.rs:78-84`) and zenoh-pico returns
    /// `_Z_ERR_GENERIC` before it builds the OpenSyn (`transport.c:142-148`).
    /// The dispatcher drives the FSM's `framing.error` arm exactly as it does
    /// for the size parameters.
    ///
    /// Takes the peer's already-projected level rather than the ext chain so
    /// the caller reads the chain ONCE — [`crate::extpatch::peer_patch`] is
    /// also what feeds [`Self::negotiate_patch_against_peer`] on the very next
    /// step, and a rejected level must never reach that `min()`.
    pub fn init_ack_patch_acceptable(&self, peer_patch: u8) -> bool {
        crate::extpatch::init_ack_patch_acceptable(self.advertised_patch(), peer_patch)
    }

    /// R311y578 — the negotiated level itself, [`crate::extpatch::NO_PATCH`]
    /// before any Init has been admitted. Read by
    /// [`Self::fragmentation_markers_negotiated`]; exposed because a
    /// passive consumer reporting on a session wants the level, not only
    /// the one predicate wz currently derives from it.
    pub fn negotiated_patch(&self) -> u8 {
        R::with_mutex_mut(&self.negotiated_patch, |s| {
            s.unwrap_or(crate::extpatch::NO_PATCH)
        })
    }

    /// R311y578 — whether a patch level has been NEGOTIATED at all, as
    /// opposed to defaulting. Distinguishes "the peer announced patch 0"
    /// from "no Init has been seen", which read identically through
    /// [`Self::negotiated_patch`] and mean different things to anything
    /// reporting on a session it did not establish.
    pub fn patch_was_negotiated(&self) -> bool {
        R::with_mutex_mut(&self.negotiated_patch, |s| s.is_some())
    }

    /// R311y578 — zenoh `patch.has_fragmentation_markers()`: whether this
    /// session's peer emits the Fragment `0x2 First` / `0x3 Drop`
    /// chain-boundary markers, and therefore whether the reassembly Router
    /// may enforce them ([`crate::reassembly_dispatch::ReassemblyDispatcher::
    /// set_fragmentation_markers`]).
    pub fn fragmentation_markers_negotiated(&self) -> bool {
        crate::extpatch::has_fragmentation_markers(self.negotiated_patch())
    }

    /// transport-lowlatency — the negotiated lowlatency capability for this
    /// session. Read by the lean tx seam ([`Self::dispatch_network_message`])
    /// and the lean rx seam ([`crate::drive::dispatch_link_event`]); true only
    /// when BOTH peers offered the ext.
    #[cfg(feature = "transport-lowlatency")]
    pub fn is_lowlatency(&self) -> bool {
        R::with_mutex_mut(&self.is_lowlatency, |s| *s)
    }

    /// transport-qos (R311y215) — the AP layer's "this deploy offers the QoS
    /// transport toward this peer" config, set once at bring-up BEFORE the
    /// handshake drives (the `set_lowlatency_offer` config-at-bringup
    /// discipline). Seeds [`Self::is_qos`]; the peer's offer is ANDed in by
    /// [`Self::negotiate_qos_against_peer`].
    ///
    /// Exclusivity guard (zenoh `manager.rs:264`: `'qos' and 'lowlatency' are
    /// incompatible`): when a lowlatency offer is already staged, the QoS offer
    /// is REFUSED (`is_qos` stays false, lowlatency wins) — lowlatency's lean
    /// path has no Frame/SN, so per-priority conduits are meaningless there. The
    /// guard lives at this offer-injection point, not in the [`crate::extqos`]
    /// codec. A deploy that sets both is misconfigured; wz refuses the QoS
    /// offer gracefully rather than panicking (an AP config validator can
    /// escalate). Returns `true` iff the offer was applied.
    #[cfg(feature = "transport-qos")]
    pub fn set_qos_offer(&self, offer: bool) -> bool {
        #[cfg(feature = "transport-lowlatency")]
        if offer && self.is_lowlatency() {
            return false;
        }
        R::with_mutex_mut(&self.is_qos, |s| *s = offer);
        true
    }

    /// transport-qos (R311y215) — AND the peer's InitSyn / InitAck `ext_qos`
    /// offer into the local capability: zenoh treats "either side NoQoS" as
    /// NoQoS (`establishment/ext/qos.rs` `recv_init_*` `else { NoQoS }`), which
    /// `&=` reproduces. Called from the establishment demux
    /// ([`crate::drive::dispatch_link_event`]) on every inbound Init frame, so
    /// the result is `local_offer && peer_offer`. The acceptor's merge lands on
    /// InitSyn arrival BEFORE its InitAck reflect; the initiator's lands on
    /// InitAck arrival, finalizing the capability (QoS is negotiated at the Init
    /// exchange — Open carries nothing).
    #[cfg(feature = "transport-qos")]
    pub fn negotiate_qos_against_peer(&self, peer_offered: bool) {
        R::with_mutex_mut(&self.is_qos, |s| *s &= peer_offered);
    }

    /// transport-qos (R311y215) — the negotiated QoS-transport capability for
    /// this session. Read by the conduit selector (mint / admit) to choose
    /// `Priority::NUM` conduits vs 1, and by the Frame `ext_qos` writer (a
    /// non-DEFAULT priority rides the wire only when both peers negotiated QoS).
    /// True only when BOTH peers offered the ext.
    #[cfg(feature = "transport-qos")]
    pub fn is_qos(&self) -> bool {
        R::with_mutex_mut(&self.is_qos, |s| *s)
    }

    /// session-extqos (R311y506) — stage this link's QoS metadata (its priority
    /// band and/or reliability class) at bring-up, BEFORE the handshake drives:
    /// the wz counterpart of zenoh reading `prio=` / `rel=` off the endpoint's
    /// metadata in `StateOpen::new` / `StateAccept::new`
    /// (`establishment/ext/qos.rs` `State::new`).
    ///
    /// Both fields `None` (the default) keeps the presence-only UNIT ext on the
    /// wire; setting EITHER switches the emit to the z64 `QoSLink` form, because
    /// [`crate::extqos::encode_qos_ext_for`] owns that choice.
    ///
    /// The metadata is meaningful only on a session that also OFFERS QoS
    /// ([`Self::set_qos_offer`]) — zenoh reaches the metadata only inside the
    /// `is_qos` arm of `State::new`, and the stage seam honours the same
    /// condition, so a metadata-without-offer misconfiguration emits nothing
    /// rather than a `QoSLink` on a NoQoS link.
    #[cfg(feature = "session-extqos")]
    pub fn set_qos_link_metadata(&self, state: crate::extqos::QosLinkState) {
        R::with_mutex_mut(&self.qos_link, |s| *s = state);
    }

    /// session-extqos — the QoS metadata currently negotiated for this session:
    /// the staged local value before the handshake, the merged value after.
    #[cfg(feature = "session-extqos")]
    pub fn qos_link_metadata(&self) -> crate::extqos::QosLinkState {
        R::with_mutex_mut(&self.qos_link, |s| *s)
    }

    /// session-extqos (R311y506) — run the directional `QoSLink` merge against
    /// an inbound Init ext chain, the wz mirror of zenoh's
    /// `QoSFsm::recv_init_syn` (acceptor) / `recv_init_ack` (initiator).
    ///
    /// `is_ack` selects the direction, because the containment is NOT symmetric:
    /// the acceptor demands the initiator's band be a SUBSET of its own and
    /// adopts the initiator's; the initiator demands the acceptor's be a
    /// SUPERSET of its own and keeps its own. Both keep the narrower band — the
    /// asymmetry is only in which side that is.
    ///
    /// `Ok(())` also covers "the peer does no QoS": the caller's `&=` merge
    /// ([`Self::negotiate_qos_against_peer`]) has already driven `is_qos` false
    /// there, and zenoh likewise falls to `State::NoQoS` without an error. An
    /// `Err` is a handshake ABORT upstream (`?` out of the establishment FSM),
    /// so the caller tears the session down rather than degrading silently.
    #[cfg(all(feature = "session-extqos", feature = "codec-init-body"))]
    pub fn negotiate_qos_link_against_peer(
        &self,
        is_ack: bool,
        extensions: &[ExtEntryOwned],
    ) -> Result<(), crate::extqos::QosLinkError> {
        use crate::extqos::PeerQos;
        let peer = crate::extqos::peer_qos_ext_state(extensions)?;
        // Either side NoQoS drops the whole state (zenoh's `else { NoQoS }`
        // arm), and a NoQoS session carries no band to negotiate.
        let PeerQos::QoS(peer_state) = peer else {
            return Ok(());
        };
        if !self.is_qos() {
            return Ok(());
        }
        let mine = self.qos_link_metadata();
        let merged = if is_ack {
            crate::extqos::merge_qos_link_init_ack(&mine, &peer_state)?
        } else {
            crate::extqos::merge_qos_link_init_syn(&mine, &peer_state)?
        };
        self.set_qos_link_metadata(merged);
        self.apply_negotiated_qos_to_link(&merged);
        Ok(())
    }

    /// R311y514 — push the NEGOTIATED QoS metadata down onto this physical link's
    /// egress-selection inputs: the wz counterpart of zenoh's
    /// `link.reconfigure(TransportLinkUnicastConfig { priorities:
    /// state.transport.ext_qos.priorities(), reliability:
    /// state.transport.ext_qos.reliability(), .. })`, which BOTH sides run once
    /// establishment settles (`unicast/establishment/open.rs:694-706`,
    /// `accept.rs:818-830`). That reconfigured `link.config` is precisely what the
    /// egress `select` reads (`unicast/universal/tx.rs:81-90`), so upstream the
    /// handshake outcome — not the pre-handshake offer — is what routes traffic.
    ///
    /// Without this, wz negotiated a band faithfully and then ignored it: a link
    /// whose band the containment NARROWED kept attracting the priorities it had
    /// just given up, and [`Self::select_link`] could hand a message to a link the
    /// peer does not serve on that conduit.
    ///
    /// Only a `Some` outcome is applied, and that is not a shortcut — it is what
    /// makes this faithful. Upstream both the offer and the selection input come
    /// from ONE endpoint-metadata field, so a merged `None` implies the local side
    /// declared nothing, which implies `config.priorities` was ALREADY `None`
    /// before the reconfigure: the `None` arm is a no-op in zenoh too. wz reaches
    /// this seam with a second band source that never sees the wire (the deploy
    /// split [`Self::set_link_priority_range`] installs at bring-up), so writing
    /// `None` through would clear a band no negotiation ever contradicted —
    /// divergence dressed up as fidelity.
    ///
    /// The reliability half carries the same rule and one further limit: wz's
    /// [`LinkReliabilityPref::Any`] is "no preference", whereas zenoh's undeclared
    /// case falls back to the link's INTRINSIC class
    /// (`config.reliability.unwrap_or(Reliability::from(link.is_reliable()))`).
    /// That fallback difference is pre-existing and independent of the handshake;
    /// it is not silently folded in here.
    #[cfg(all(
        feature = "session-extqos",
        feature = "codec-init-body",
        feature = "transport-multilink"
    ))]
    fn apply_negotiated_qos_to_link(&self, merged: &crate::extqos::QosLinkState) {
        if let Some(band) = merged.priorities {
            self.set_link_priority_range(Some(band));
        }
        if let Some(reliability) = merged.reliability {
            self.set_link_reliability_pref(match reliability {
                crate::reliability::Reliability::Reliable => LinkReliabilityPref::Reliable,
                crate::reliability::Reliability::BestEffort => LinkReliabilityPref::BestEffort,
            });
        }
    }

    /// Non-multilink twin of [`Self::apply_negotiated_qos_to_link`]. A session
    /// with no aggregation set never runs [`Self::select_link`] — `send_wire`
    /// takes `self.link` directly — so there is no per-link selection input to
    /// reconfigure, and the negotiated metadata stays where
    /// [`Self::qos_link_metadata`] reports it. The arm exists so the call site
    /// stays unconditional, the discipline the R311mx note on the send seam's
    /// cfg arms already imposes in this file.
    #[cfg(all(
        feature = "session-extqos",
        feature = "codec-init-body",
        not(feature = "transport-multilink")
    ))]
    fn apply_negotiated_qos_to_link(&self, merged: &crate::extqos::QosLinkState) {
        let _ = merged;
    }

    /// R311y435 — stage a whole [`SessionOffer`] on FRESH actions: the single
    /// composition seam every deploy-facing open routes through.
    ///
    /// This exists because the granular `set_*_offer` setters compose only by
    /// convention. `set_qos_offer` and [`Self::set_lowlatency_offer`] each
    /// refuse when the other is already staged, so the both-on input resolves to
    /// "first-staged wins" — ORDER-DEPENDENT, where zenoh's check
    /// (`io/zenoh-transport/src/unicast/manager.rs:264-265`,
    /// `'qos' and 'lowlatency' options are incompatible`) is symmetric and
    /// total. Taking the exclusive choice as ONE
    /// [`TransportMode`](crate::transport_mode::TransportMode) removes the
    /// order: there is no input to this function that means "both", so the
    /// refusal branch is unreachable from here and the divergence cannot be
    /// observed by any caller that uses this seam.
    ///
    /// The orthogonal capabilities are staged unconditionally alongside the
    /// mode, because upstream composes them with every mode — R311y435 read all
    /// four pairs against zenoh's composed data path and only qos x lowlatency
    /// diverged. Forbidding `LowLatency + compression` or `LowLatency + shm`
    /// here would be a wz-only restriction on wires zenoh accepts.
    ///
    /// Errors only when this BUILD lacks a requested capability's cargo feature
    /// — never because of the offer's shape. Silently dropping the capability
    /// instead would ship a wire form the caller did not configure, and the
    /// same reasoning covers `compression` / `shm`, not just the mode.
    ///
    /// Must be called BEFORE the handshake drives (the `set_lowlatency_offer`
    /// config-at-bringup discipline): the peer's offers are ANDed in by the
    /// `negotiate_*_against_peer` merges on the inbound Init frames.
    pub fn apply_offer(
        &self,
        offer: &crate::transport_mode::SessionOffer,
    ) -> Result<(), crate::transport_mode::UnsupportedCapability> {
        use crate::transport_mode::TransportMode;

        match offer.mode {
            TransportMode::Universal => {}
            TransportMode::Qos => {
                #[cfg(feature = "transport-qos")]
                // Fresh actions carry no lowlatency offer, and `SessionOffer`
                // cannot express one alongside Qos, so the exclusivity guard is
                // unreachable here. Asserted rather than discarded: if it ever
                // fires, a caller reached this seam with pre-staged actions and
                // the "unrepresentable" claim above is false for that path.
                assert!(
                    self.set_qos_offer(true),
                    "apply_offer staged Qos on actions that already carry a \
                     lowlatency offer: SessionOffer cannot express both, so \
                     these actions were mutated before the offer was applied"
                );
                #[cfg(not(feature = "transport-qos"))]
                return Err(crate::transport_mode::UnsupportedCapability {
                    capability: "TransportMode::Qos",
                    feature: "transport-qos",
                });
            }
            TransportMode::LowLatency => {
                #[cfg(feature = "transport-lowlatency")]
                assert!(
                    self.set_lowlatency_offer(true),
                    "apply_offer staged LowLatency on actions that already carry \
                     a qos offer: SessionOffer cannot express both, so these \
                     actions were mutated before the offer was applied"
                );
                #[cfg(not(feature = "transport-lowlatency"))]
                return Err(crate::transport_mode::UnsupportedCapability {
                    capability: "TransportMode::LowLatency",
                    feature: "transport-lowlatency",
                });
            }
        }

        if offer.compression {
            #[cfg(feature = "session-extcompression")]
            self.set_compression_offer(true);
            #[cfg(not(feature = "session-extcompression"))]
            return Err(crate::transport_mode::UnsupportedCapability {
                capability: "compression",
                feature: "session-extcompression",
            });
        }
        if offer.shm {
            #[cfg(feature = "session-extshm")]
            self.set_shm_offer(true);
            #[cfg(not(feature = "session-extshm"))]
            return Err(crate::transport_mode::UnsupportedCapability {
                capability: "shm",
                feature: "session-extshm",
            });
        }
        // session-extqos — stage the link's QoS metadata. Unconditional on the
        // mode: the emit seam is already gated on `is_qos()`, so metadata staged
        // on a non-QoS session is inert rather than a second place to re-derive
        // the same condition (zenoh reaches the metadata only inside the
        // `is_qos` arm of `State::new`, which is the same guard).
        #[cfg(feature = "session-extqos")]
        if let Some(qos_link) = offer.qos_link {
            self.set_qos_link_metadata(qos_link);
        }

        Ok(())
    }

    /// §5.21 routing-namespace — install the per-participant namespace on this
    /// session bundle at AP bring-up, BEFORE the drive loop spins or any send
    /// fires (the `set_lowlatency_offer` config-at-bringup discipline). Seeds
    /// the EGRESS prefix and builds the stateful INGRESS [`NamespaceIngress`]
    /// from the SAME validated [`OwnedNonWildKeyExpr`], so the two decorator
    /// halves can never disagree on the prefix. zenoh installs the
    /// `Namespace`/`ENamespace` pair on the session's own face at open
    /// (`api/session.rs`).
    #[cfg(feature = "routing-namespace")]
    pub fn set_namespace(&self, namespace: OwnedNonWildKeyExpr) {
        R::with_mutex_mut(&self.namespace_ingress, |s| {
            *s = Some(NamespaceIngress::new(namespace.clone()));
        });
        R::with_mutex_mut(&self.namespace_egress, |s| *s = Some(namespace));
    }

    /// §5.21 routing-namespace — apply the stateful INGRESS decorator to one
    /// owned driver-loop outcome IN PLACE (strip + drop a `FramePayload`
    /// batch's messages before the observer fan-out). No-op when no namespace
    /// is installed, or for a non-`FramePayload` outcome. The drive loop calls
    /// this on the direct outcome (`drive_session_until_terminal`) AND on the
    /// reassembled completion (`report_outcome_reassembling`) — the two
    /// distinct owned-outcome mint points — BEFORE `on_event`, because the
    /// observer fans the same `&outcome` into every consumer registry.
    #[cfg(feature = "routing-namespace")]
    pub fn apply_namespace_ingress(&self, outcome: &mut crate::driver_loop::DriverLoopOutcome) {
        R::with_mutex_mut(&self.namespace_ingress, |slot| {
            if let Some(ing) = slot.as_mut() {
                crate::namespace::strip_outcome(ing, outcome);
            }
        });
    }

    /// §5.21 routing-namespace — re-apply the EGRESS decorator to a `Declare`
    /// that is dispatched DIRECTLY, past the unicast `Tp::send_network_message`
    /// egress arm (`dispatch_declare` sits BELOW the shared floor, on the
    /// forwarder's relay path, so it cannot itself decorate without
    /// re-namespacing relays). Two direct-dispatch paths need it: the LIVE
    /// `DeclareKeyExpr` alias DEFINITION ([`Self::send_declare_keyexpr`]), where
    /// the alias must be baked WITH the namespace so a later aliased Push/Request
    /// (passed through unchanged by the decorator, id != 0) resolves under the
    /// namespace at the peer instead of leaking to the bare keyexpr; and the
    /// reconnect declaration replay ([`Self::replay_one`]). The cache and the
    /// local `outbound_mappings` keep the BARE keyexpr — transparent namespace
    /// (bare to the app + local loopback, namespaced on the wire, the zenoh
    /// model). No-op when no namespace is installed.
    #[cfg(all(
        feature = "routing-namespace",
        any(
            feature = "declare-keyexpr",
            all(
                feature = "session-reconnect",
                any(
                    feature = "declare-subscriber",
                    feature = "declare-queryable",
                    feature = "declare-token"
                )
            )
        )
    ))]
    fn namespace_egress_declare(
        &self,
        mut d: wz_codecs::declare::DeclareOwned,
    ) -> Result<wz_codecs::declare::DeclareOwned, sce_forge_runtime::codec::CodecError> {
        R::with_mutex_mut(&self.namespace_egress, |slot| match slot.as_ref() {
            Some(ns) => crate::namespace::apply_egress_declare(ns, &mut d),
            None => Ok(()),
        })?;
        Ok(d)
    }

    /// §5.21 routing-namespace — the interest counterpart of
    /// [`Self::namespace_egress_declare`]. Only the reconnect replay
    /// ([`Self::replay_one`]) dispatches interests directly past the egress arm
    /// (the live liveliness interests route through the decorated send seam), so
    /// this is reconnect-gated.
    #[cfg(all(
        feature = "routing-namespace",
        feature = "session-reconnect",
        feature = "declare-interest"
    ))]
    fn namespace_egress_interest(
        &self,
        mut i: wz_codecs::interest::InterestOwned,
    ) -> Result<wz_codecs::interest::InterestOwned, sce_forge_runtime::codec::CodecError> {
        R::with_mutex_mut(&self.namespace_egress, |slot| match slot.as_ref() {
            Some(ns) => crate::namespace::apply_egress_interest(ns, &mut i),
            None => Ok(()),
        })?;
        Ok(i)
    }

    /// R311xr — stage (or clear) a UNIT capability offer in `role`'s ext chain,
    /// IDEMPOTENTLY (the generic mechanism the lowlatency / compression / shm
    /// establishment offers share, replacing the three near-identical
    /// `stage_X_send` bodies): the prior entry with this id is dropped first so a
    /// re-handshake never duplicates it (the slots persist across
    /// `reset_for_reopen`), then `build`'s ext is pushed iff `offer`. The
    /// per-capability `build` fn (e.g. [`crate::extlowlatency::encode_lowlatency_ext`])
    /// is the single source of both the id (which drives the idempotent retain)
    /// and the content — invoked once for the id (a 1-byte unit ext) and again to
    /// push, so no id param is threaded.
    ///
    /// Gated on the UNION of the three capabilities' send-action callers, so a
    /// subset build that compiles none does not carry it as dead code under
    /// `-D warnings`.
    #[cfg(all(
        any(
            feature = "transport-lowlatency",
            feature = "session-extcompression",
            feature = "session-extshm",
            feature = "transport-qos"
        ),
        feature = "codec-init-body",
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ))]
    /// session-extshm (R311y507) — stage the CHALLENGE form of the SHM
    /// establishment ext for `role`.
    ///
    /// Only the challenge: the legacy UNIT branch stays at the two Init call
    /// sites, visible there rather than hidden behind a helper that silently
    /// does one of two different things. That also keeps `stage_capability`'s
    /// caller set exactly what it was before this round.
    ///
    /// Self-clearing on the id, so a re-handshake REPLACES rather than
    /// accumulates — and since the two forms share id 0x2, that is also what
    /// stops a challenge and a UNIT marker ever riding one chain together.
    #[cfg(feature = "session-extshm")]
    fn stage_shm_challenge(
        &self,
        role: ExtChainRole,
        produce: impl Fn(&Self) -> Option<ExtEntryOwned>,
    ) {
        let produced = self.is_shm().then(|| produce(self)).flatten();
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            chain.retain(|e| e.ext_id() != crate::extshm::SHM_ESTABLISHMENT_EXT_ID);
            if let Some(ext) = produced {
                chain.push(ext);
            }
        });
    }

    /// R311y506 — the parameter widened from a bare `fn` pointer to
    /// `impl Fn`, so a capability whose encoded FORM depends on session state
    /// can use the same self-clearing stage seam instead of growing a parallel
    /// one. `session-extqos` is the case that needs it: the QoS ext is the UNIT
    /// form or the z64 `QoSLink` form depending on the staged metadata. Every
    /// pre-existing caller passes a `fn` item, which coerces unchanged.
    ///
    /// The `retain` keys on `ext_id()` (the 4-bit id FIELD), not on the full
    /// header, which is load-bearing here: the unit `QoS` and the z64 `QoSLink`
    /// share id `0x1` and zenoh forbids emitting both at once
    /// ("Extensions QoS and QoSOptimized cannot both be enabled at once"), so
    /// clearing by id is what makes a re-stage REPLACE rather than accumulate.
    ///
    /// R311y507 — gated on the exact condition under which it has a CALLER.
    /// Every call site is a capability stage inside the Init send blocks, so the
    /// condition is "some capability feature" AND the enclosing block's own cfg
    /// (`codec-init-body` plus one of the two unicast roles). Without this the
    /// helper is dead in any build lacking those, and `-D dead-code` refuses it
    /// — which is the right refusal: an `allow` here would also hide a helper
    /// that had genuinely lost its last caller.
    #[cfg(all(
        any(
            feature = "transport-lowlatency",
            feature = "transport-qos",
            feature = "session-extcompression",
            feature = "session-extshm",
        ),
        feature = "codec-init-body",
        any(feature = "session-unicast-open", feature = "session-unicast-accept",),
    ))]
    fn stage_capability(&self, role: ExtChainRole, offer: bool, build: impl Fn() -> ExtEntryOwned) {
        let ext_id = build().ext_id();
        R::with_mutex_mut(self.ext_chain_slot(role), |chain| {
            chain.retain(|e| e.ext_id() != ext_id);
            if offer {
                chain.push(build());
            }
        });
    }

    /// transport-compression — the negotiated compression capability for this
    /// session. Read by the lz4 tx wrap ([`Self::send_wire`]) and the rx un-wrap
    /// ([`crate::drive::dispatch_link_event`]); true only when BOTH peers offered
    /// the ext. The getter lives under `transport-compression` (the wrap reads
    /// it) while the setters live under `session-extcompression` (the handshake
    /// sets it) -- a bare `transport-compression` build has the inert wrap but no
    /// way to flip the flag, so it never engages.
    #[cfg(feature = "transport-compression")]
    pub fn is_compression(&self) -> bool {
        R::with_mutex_mut(&self.is_compression, |s| *s)
    }

    /// transport-compression (R311y434) — SSOT for "is the lz4 batch wrap ACTIVE
    /// on this session right now?". The single predicate BOTH the TX wrap
    /// ([`Self::emit_on_link`]) and the RX un-wrap
    /// ([`crate::drive::dispatch_link_event`]) consult, so the two cannot drift
    /// apart and leave one side wrapping what the other does not un-wrap — a
    /// hand-maintained pair of conditions is exactly how that breaks.
    ///
    /// Distinct from [`Self::is_compression`], which reports the NEGOTIATED
    /// capability. Three conjuncts, each mirroring zenoh:
    ///
    /// 1. the 0x6 ext negotiated on both sides (the `&=` merge);
    /// 2. post-establishment only. zenoh drives Init/Open on a link whose
    ///    `is_compression` is false (`establishment/open.rs:572`) and then
    ///    explicitly ships the OpenAck raw through a named workaround
    ///    (`unicast/link.rs:288-296`);
    /// 3. NOT lowlatency. This one is a CORRECTION, not a mirror of structure:
    ///    zenoh sets `is_compression` on a lowlatency link's `BatchConfig` too
    ///    (`open.rs:701` is independent of `:689`), but its lean tx serializes
    ///    straight to the link behind a 4-byte length prefix and never touches
    ///    `WBatch` / `BatchHeader` (`unicast/lowlatency/link.rs:33-73`), and its
    ///    lean rx never decompresses either. So upstream the negotiated capability
    ///    is INERT on a lean link. wz previously wrapped there anyway, which
    ///    emitted a wire no zenoh peer can read — self-consistent wz<->wz and
    ///    wire-incompatible with the reference impl.
    #[cfg(feature = "transport-compression")]
    pub fn compresses_batches(&self) -> bool {
        if !self.is_compression() || !self.is_established() {
            return false;
        }
        #[cfg(feature = "transport-lowlatency")]
        {
            !self.is_lowlatency()
        }
        #[cfg(not(feature = "transport-lowlatency"))]
        {
            // No lean transport exists in this build, so conjunct 3 holds trivially.
            true
        }
    }

    /// transport-shm — the negotiated SHM capability for this session (zenoh
    /// `negotiated_to_use_shm`). R3a: always false (the data path is inert);
    /// R3b's Z_EXT_SHM challenge handshake flips it. Read by the TX descriptor
    /// swap + the RX un-swap (R3b).
    #[cfg(feature = "transport-shm")]
    pub fn is_shm(&self) -> bool {
        R::with_mutex_mut(&self.is_shm, |s| *s)
    }

    /// session-extcompression — the AP layer's "this deploy offers compression
    /// toward this peer" config, set once at bring-up BEFORE the handshake drives
    /// (the wz analogue of zenoh `config.unicast.is_compression`). Seeds
    /// [`Self::is_compression`]; the peer's offer is ANDed in by
    /// [`Self::negotiate_compression_against_peer`].
    #[cfg(feature = "session-extcompression")]
    pub fn set_compression_offer(&self, offer: bool) {
        R::with_mutex_mut(&self.is_compression, |s| *s = offer);
    }

    /// session-extcompression — AND the peer's InitSyn / InitAck compression offer
    /// into the local capability: zenoh `is_compression &= other_ext.is_some()`
    /// (`establishment/ext/compression.rs:79/165`). Called from the establishment
    /// demux ([`crate::drive::dispatch_link_event`]) on every inbound Init frame,
    /// so the result is `local_offer && peer_offer`, finalized at the Init
    /// exchange (zenoh's Open stages are NOP).
    #[cfg(feature = "session-extcompression")]
    pub fn negotiate_compression_against_peer(&self, peer_offered: bool) {
        R::with_mutex_mut(&self.is_compression, |s| *s &= peer_offered);
    }

    /// session-extshm — the AP layer's "this deploy offers SHM toward this peer"
    /// config, set once at bring-up BEFORE the handshake drives. Seeds
    /// [`Self::is_shm`]; the peer's offer is ANDed in by
    /// [`Self::negotiate_shm_against_peer`].
    #[cfg(feature = "session-extshm")]
    pub fn set_shm_offer(&self, offer: bool) {
        R::with_mutex_mut(&self.is_shm, |s| *s = offer);
    }

    /// session-extshm — AND the peer's Init / InitAck SHM offer into the local
    /// capability (zenoh `is_shm &= other.is_some()`), called from the
    /// establishment demux on every inbound Init frame; the result is
    /// `local_offer && peer_offer`, finalized at the Init exchange.
    ///
    /// R311y507 — this is the CAPABILITY half only. With an authenticator
    /// installed the capability is no longer sufficient: `is_shm` is additionally
    /// gated on the CHALLENGE-RESPONSE completing
    /// ([`Self::shm_recv_open_syn`] / [`Self::shm_recv_open_ack`]), so a peer
    /// that offers SHM but cannot map our memory ends up with `is_shm = false`.
    #[cfg(feature = "session-extshm")]
    pub fn negotiate_shm_against_peer(&self, peer_offered: bool) {
        R::with_mutex_mut(&self.is_shm, |s| *s &= peer_offered);
    }

    /// session-extshm (R311y507) — what counts as "the peer offered SHM" on an
    /// inbound Init chain, which depends on WHICH mechanism this node is running.
    ///
    /// With an authenticator installed the peer's offer is the presence of
    /// zenoh's real `init::ext::Shm` (a ZBuf), because that is the only SHM
    /// extension a conforming peer sends — there is no separate capability
    /// marker upstream, the challenge IS the offer. Without one, it is the
    /// pre-R311y507 UNIT marker.
    ///
    /// Keeping the UNIT predicate for both would clear the capability the moment
    /// a peer spoke the real protocol: the acceptor's `&=` would drive `is_shm`
    /// false on the initiator's challenge and it would then stage no answer at
    /// all. Measured — that is exactly what happened before this existed, and it
    /// presented as "the challenge-response never completes".
    #[cfg(all(feature = "session-extshm", feature = "codec-init-body"))]
    pub fn shm_peer_offered(&self, extensions: &[ExtEntryOwned]) -> bool {
        if self.shm_auth_installed() {
            crate::extshm::peer_shm_zbuf_body(extensions).is_some()
        } else {
            crate::extshm::peer_offered_shm(extensions)
        }
    }

    /// session-extshm (R311y507) — install this node's SHM authenticator at
    /// bring-up, BEFORE the handshake drives (the `set_shm_offer`
    /// config-at-bringup discipline). Until this is called the dispatch is empty
    /// and wz emits no `init::ext::Shm` at all, which is byte-identical to a
    /// peer that does no SHM (zenoh's `auth_shm: None`).
    ///
    /// The authenticator is the `std` half — a real POSIX segment — so it is
    /// injected from the AP runtime rather than constructed here.
    #[cfg(feature = "session-extshm")]
    pub fn install_shm_auth(
        &self,
        authenticator: alloc::boxed::Box<dyn crate::extshm::ShmAuthenticator + Send + Sync>,
    ) {
        R::with_mutex_mut(&self.shm_auth, |d| {
            *d = crate::extshm::ShmAuthDispatch::install(authenticator)
        });
    }

    /// Whether a SHM authenticator is installed — i.e. whether this session can
    /// take part in the challenge-response at all. Read by the stage seams so a
    /// deploy without one keeps the pre-R311y507 wire.
    #[cfg(feature = "session-extshm")]
    pub fn shm_auth_installed(&self) -> bool {
        R::with_mutex_mut(&self.shm_auth, |d| d.is_installed())
    }

    /// Step 1 (INITIATOR) — the `init::ext::Shm` for our InitSyn: our segment id.
    #[cfg(feature = "session-extshm")]
    pub fn shm_send_init_syn(&self) -> Option<ExtEntryOwned> {
        R::with_mutex_mut(&self.shm_auth, |d| d.send_init_syn())
    }

    /// Step 2a (ACCEPTOR) — map the initiator's segment and remember its
    /// challenge. `Err` only for a malformed body, which zenoh aborts on.
    #[cfg(feature = "session-extshm")]
    pub fn shm_recv_init_syn(
        &self,
        extensions: &[ExtEntryOwned],
    ) -> Result<(), crate::extshm::ShmAuthError> {
        R::with_mutex_mut(&self.shm_auth, |d| d.recv_init_syn(extensions))
    }

    /// Step 2b (ACCEPTOR) — echo the initiator's challenge plus our segment id.
    #[cfg(feature = "session-extshm")]
    pub fn shm_send_init_ack(&self) -> Option<ExtEntryOwned> {
        R::with_mutex_mut(&self.shm_auth, |d| d.send_init_ack())
    }

    /// Step 3a (INITIATOR) — validate the echo against our own challenge, then
    /// map the acceptor's segment. A failure here is not an error: it clears the
    /// SHM capability and the session continues without shared memory.
    #[cfg(feature = "session-extshm")]
    pub fn shm_recv_init_ack(&self, extensions: &[ExtEntryOwned]) {
        // The `installed` guard is NOT optional: without an authenticator
        // `recv_init_ack` reports `false` because there is no exchange to
        // complete, and clearing on that would tear the SHM capability off every
        // deploy still using the UNIT offer/reflect. Measured — it broke the
        // pre-R311y507 wz<->wz SHM e2e, which is what the guard is here for.
        let (installed, proved) = R::with_mutex_mut(&self.shm_auth, |d| {
            (d.is_installed(), d.recv_init_ack(extensions))
        });
        if installed && !proved {
            R::with_mutex_mut(&self.is_shm, |s| *s = false);
        }
    }

    /// Step 3b (INITIATOR) — the `open::ext::Shm` for our OpenSyn: the challenge
    /// we read out of the acceptor's segment.
    #[cfg(feature = "session-extshm")]
    pub fn shm_send_open_syn(&self) -> Option<ExtEntryOwned> {
        R::with_mutex_mut(&self.shm_auth, |d| d.send_open_syn())
    }

    /// Step 4a (ACCEPTOR) — the initiator's echo of OUR challenge. This is where
    /// the ACCEPT side's `is_shm` is finally decided (zenoh sets
    /// `negotiated_to_use_shm` in `recv_open_syn`), so an installed
    /// authenticator turns the capability flag into a proof-gated one.
    #[cfg(feature = "session-extshm")]
    pub fn shm_recv_open_syn(&self, extensions: &[ExtEntryOwned]) {
        let (installed, proved) = R::with_mutex_mut(&self.shm_auth, |d| {
            (d.is_installed(), d.recv_open_syn(extensions))
        });
        if installed && !proved {
            R::with_mutex_mut(&self.is_shm, |s| *s = false);
        }
    }

    /// Step 4b (ACCEPTOR) — confirm with the literal `1`, and only when the
    /// exchange completed.
    #[cfg(feature = "session-extshm")]
    pub fn shm_send_open_ack(&self) -> Option<ExtEntryOwned> {
        let negotiated = self.is_shm();
        R::with_mutex_mut(&self.shm_auth, |d| d.send_open_ack(negotiated))
    }

    /// Step 4c (INITIATOR) — the acceptor's confirmation, which is where the
    /// OPEN side's `is_shm` is decided (zenoh `recv_open_ack`).
    #[cfg(feature = "session-extshm")]
    pub fn shm_recv_open_ack(&self, extensions: &[ExtEntryOwned]) {
        let (installed, confirmed) = R::with_mutex_mut(&self.shm_auth, |d| {
            (d.is_installed(), d.recv_open_ack(extensions))
        });
        if installed && !confirmed {
            R::with_mutex_mut(&self.is_shm, |s| *s = false);
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
        self.handle_inbound_consuming(bytes).map(|(frame, _)| frame)
    }

    /// R311y632 (§17) — the same, told how many bytes the message occupied.
    ///
    /// The length is what lets a caller walk to the NEXT message of a batch,
    /// and one framing unit is a batch: zenoh holds a batch open instead of
    /// flushing it per message (`zenoh-transport-1.5.0/src/common/pipeline.rs:318`)
    /// and both reference receivers walk a received unit to its end. It is
    /// returned from HERE rather than measured by a second parse in the caller,
    /// because a second parse of a data frame copies the whole payload again.
    ///
    /// `0` means the extent is unknown — an unrecognised MID — and a caller
    /// walking a batch must stop rather than guess where the next message
    /// starts. See [`crate::inbound::parse_inbound_consuming`].
    pub fn handle_inbound_consuming(
        &self,
        bytes: &[u8],
    ) -> Result<(InboundFrame, usize), InboundParseError> {
        let (frame, consumed) = parse_inbound_consuming(bytes)?;
        match &frame {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init {
                is_ack: true, body, ..
            } => {
                // R311qh — capture the acceptor's zid from the InitAck into the
                // routing identity slot (NOT `inbound_peer_zid`: R86 scopes that
                // slot to the Accepting-side cookie-HMAC capture, and
                // `r86_handle_inbound_init_ack_does_not_overwrite_peer_zid`
                // forbids InitAck touching it — cross-role confusion). The INIT
                // body is wire-identical on InitSyn and InitAck (both carry
                // `body.zid`), so this mirrors the `is_ack: false` capture below
                // into `remote_peer_zid`, giving the routing layer the remote
                // peer's identity for BOTH handshake directions.
                R::with_mutex_mut(&self.remote_peer_zid, |slot| {
                    *slot = Some(body.zid.as_slice().to_vec());
                });
                // R311td — capture the peer's WhatAmI role (raw 2-bit wire form)
                // alongside its zid. Both Init arms capture it (a face may be
                // opened from either side); the routing boundary maps wire -> the
                // graph's API-form role. The gossip-policy prerequisite ("F1").
                R::with_mutex_mut(&self.peer_whatami, |slot| {
                    *slot = Some(body.whatami());
                });
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
                // R311qh — also capture it into the role-agnostic routing
                // identity slot (the Initiating side captures the same from the
                // InitAck above), so a held face exposes its remote peer's zid
                // regardless of which side opened it.
                R::with_mutex_mut(&self.remote_peer_zid, |slot| {
                    *slot = Some(body.zid.as_slice().to_vec());
                });
                // R311td — capture the peer's WhatAmI role (raw 2-bit wire form)
                // alongside its zid; see the InitAck arm above for why both
                // directions capture it (the gossip-policy "F1" prerequisite).
                R::with_mutex_mut(&self.peer_whatami, |slot| {
                    *slot = Some(body.whatami());
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
                // R311kv — capture the peer's advertised lease (ms,
                // R311ku boundary projection) for the deadline
                // comparator's min(); pico adopts it at this same
                // OpenSyn arrival (unicast/transport.c:269).
                R::with_mutex_mut(&self.peer_open_lease_ms, |slot| {
                    *slot = Some(body.lease);
                });
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
                // R311kv — OpenAck mirror of the OpenSyn lease capture
                // (pico unicast/transport.c:193).
                R::with_mutex_mut(&self.peer_open_lease_ms, |slot| {
                    *slot = Some(body.lease);
                });
            }
            _ => {}
        }
        // R311la — RX-activity stamp, the zenoh-pico `_received` parity
        // point (unicast/rx.c:88 sets the flag for EVERY successfully
        // decoded transport message, and the lease task expires only
        // when nothing arrived in the window, lease.c:141-149). The
        // former R72b stamp lived in the KeepAlive arm alone, so a peer
        // sending only data frames was expired after one lease window —
        // and the R311kx TX suppression guarantees a busy peer sends no
        // KeepAlives, making the gap live. `Unknown` is excluded: pico
        // never reaches its stamp for an unrecognized MID (the decode
        // fails before rx.c:88), and the FSM tears the session down on
        // the FramingError projection anyway. R294 — the stamp shares
        // the monotonic epoch with the drive loop's clock.
        if !matches!(frame, InboundFrame::Unknown { .. }) {
            let now = self.clock.now_monotonic_ms();
            R::with_mutex_mut(&self.link.last_inbound_at, |slot| {
                *slot = Some(now);
            });
        }
        Ok((frame, consumed))
    }

    /// R311y632 (§17) — park the undispatched remainder of a framing unit.
    ///
    /// Empty input parks nothing: an absent residue and a zero-length one are
    /// the same fact, and storing `Some(vec![])` would make the drain hand the
    /// dispatcher an empty unit to fail on.
    pub fn park_pending_batch(&self, residue: &[u8]) {
        if residue.is_empty() {
            return;
        }
        R::with_mutex_mut(&self.link.pending_batch, |slot| {
            *slot = Some(residue.to_vec());
        });
    }

    /// R311y632 (§17) — take the parked remainder, if any.
    pub fn take_pending_batch(&self) -> Option<Vec<u8>> {
        R::with_mutex_mut(&self.link.pending_batch, |slot| slot.take())
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
    /// defensive 0-normalization (wire 0 -> 65535, R311kj) would turn a
    /// conforming literal 0 into exactly the enlargement this guard
    /// rejects.
    #[cfg(feature = "codec-init-body")]
    pub fn init_ack_caps_acceptable(
        &self,
        sn_res_byte: Option<u8>,
        batch_size: Option<u16>,
    ) -> bool {
        !crate::peer_init_caps::init_ack_exceeds_advertisement(
            self.params.seq_num_res,
            self.params.req_id_res,
            // R311kj — compare against the EFFECTIVE advertisement,
            // i.e. exactly the value encode_init put on the InitSyn
            // wire (0 = unset never reaches the wire).
            self.params.effective_batch_size(),
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
    pub fn admit_rx_frame_sn(&self, priority: Priority, reliable: bool, sn: u64) -> bool {
        // Sequential mutex scopes: the mask accessor takes
        // `inbound_peer_init_caps`, then `rx_sn` — disjoint, never nested
        // (the non-reentrant MCU critical_section forbids nesting).
        // R311y215 — the SN gate is per-(priority, reliable) conduit; a non-QoS
        // session passes `Priority::DEFAULT` and gates on the single conduit.
        let mask = self.negotiated_sn_mask();
        R::with_mutex_mut(&self.rx_sn, |s| s.admit(priority, mask, reliable, sn))
    }

    /// R121e / R311kb — outbound Frame sequence-number mint. Returns
    /// the SN for the next outbound Frame on `reliable`'s channel as a
    /// position on the ring of `sn_mask` ([`Self::negotiated_sn_mask`])
    /// and advances THAT channel's counter by one — zenoh-pico
    /// `_z_sn_increment` parity, closing the R121e explicit-modulo carry.
    /// R311y214 — the reliable and best-effort channels are independent
    /// rings ([`AtomicTxSn`]); `reliable` picks which.
    ///
    /// The first call on each channel returns `params.initial_sn & sn_mask`
    /// (both channels are seeded by `new_session_actions`; a conforming
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
    pub fn next_outbound_frame_sn(&self, priority: Priority, reliable: bool, sn_mask: u64) -> u64 {
        self.outbound_frame_sn.mint(priority, reliable, sn_mask)
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
        priority: Priority,
        reliable: bool,
        worst_case_payload: usize,
        _stats_class: crate::stats::NetworkStatsClass,
        encode_body: P,
    ) -> Result<(), SendWireError>
    where
        P: Fn(
            &mut sce_forge_runtime::codec::VecSink<'_>,
        ) -> Result<(), sce_forge_runtime::codec::CodecError>,
    {
        // R2371 (`transport-stats`) — the NETWORK-message counters. Charged here
        // and not at `emit_on_link` because one wire write carries a whole batch
        // of these: the wire seam counts transport messages, this one counts the
        // network messages inside them, and upstream keeps the same two families
        // apart for the same reason.
        //
        // Counted at ENTRY, before the availability gate and the batch lock, so
        // the number is "network messages this session was asked to send". A
        // message the gate rejects never reaches a wire and so never reaches
        // `n_dropped` either — `n_dropped` is the DRIVER's refusal, and
        // conflating a typed `Err` return with a silent wire drop would put two
        // different failures under one counter.
        #[cfg(feature = "transport-stats")]
        self.stats.inc_tx_network(&_stats_class);
        // R311y215 (transport-qos) — the EFFECTIVE Frame priority: the caller's
        // message priority when this session negotiated QoS, else forced to
        // DEFAULT (a non-QoS session has one PRIORITY conduit and writes no
        // ext_qos, so every Frame is Data — note it still splits by RELIABILITY
        // into two SN rings, the R311y222 batch key). `priority` then selects the
        // SN conduit at each
        // mint and (when != DEFAULT) the ext_qos the Frame carries. When
        // `transport-qos` does not compile, `priority` passes straight to the
        // single-conduit mint (ignored) — no cfg-skew.
        #[cfg(feature = "transport-qos")]
        let priority = if self.is_qos() {
            priority
        } else {
            Priority::DEFAULT
        };
        // R311y215 — the ext_qos this Frame/Fragment carries: `Some` ONLY for a
        // non-DEFAULT priority (zenoh writes `ext_qos` iff `!= DEFAULT`, so a
        // DEFAULT frame stays byte-identical to a pre-QoS frame). Computed once
        // and threaded into every framing path (batch open / immediate /
        // fragment) below. Without `transport-qos` there are no per-priority
        // conduits and no ext — always `None`.
        #[cfg(feature = "transport-qos")]
        let ext_qos: Option<Priority> = if priority != Priority::DEFAULT {
            Some(priority)
        } else {
            None
        };
        #[cfg(not(feature = "transport-qos"))]
        let ext_qos: Option<Priority> = None;
        // F2 — transport-availability gate (pico
        // `_Z_ERR_TRANSPORT_NOT_AVAILABLE` parity): inside the
        // RECONNECTING window (link released / reset for re-dial, not yet
        // re-Established) a data send must reject typed rather than
        // vanish into a dead writer channel. Single gate — every
        // network-message send routes through this chokepoint.
        // R311y205 (transport-multilink) — for an AGGREGATING session the gate is
        // the OR over the link set's `transport_available`: the session accepts
        // sends while ANY link is alive (a dead reliable link fails over to a live
        // one), so a per-link death must not reject a send the surviving links can
        // still carry. A single-link session (and every non-feature build) gates
        // on `self.link` exactly as before.
        if !self.session_send_available() {
            return Err(SendWireError::TransportUnavailable);
        }
        // transport-lowlatency — the lean send path (zenoh
        // `TransportBodyLowLatencyRef::Network(b) => write the bare
        // NetworkMessage`, codec/transport/mod.rs:47): when this session
        // negotiated lowlatency, emit the network message's OWN bytes with NO
        // Frame(sn) wrapper, NO fragmentation, and NO batching — `encode_body`
        // is already the bare NetworkMessage encoder (the same closure the Frame
        // path wraps). This precedes the MTU / SN / batch-lock machinery below,
        // which lowlatency deletes by design (zenoh's lowlatency transport tracks
        // no SN and never fragments — defrag and the half-window gate do not
        // exist on this path). Data sends only fire post-Established, by when the
        // capability is finalized (negotiated at the Init exchange), so reading
        // `is_lowlatency()` here needs no establishment guard.
        #[cfg(feature = "transport-lowlatency")]
        if self.is_lowlatency() {
            let mut wire = Vec::with_capacity(worst_case_payload);
            {
                let mut sink = sce_forge_runtime::codec::VecSink::new(&mut wire);
                encode_body(&mut sink).expect("VecSink is infallible");
            }
            self.send_wire(
                &wire,
                if reliable {
                    Reliability::Reliable
                } else {
                    Reliability::BestEffort
                },
                priority,
            );
            return Ok(());
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

        // This profile's own reassembly budget, resolved HERE for the same
        // reason as `mtu` and `sn_mask` above: the accessor takes a mutex,
        // and session mutex scopes stay disjoint by discipline. Without
        // `transport-fragmentation` nothing fragments, so no cap applies.
        #[cfg(feature = "transport-fragmentation")]
        let max_reassembly_bytes = self.max_reassembly_bytes();
        #[cfg(not(feature = "transport-fragmentation"))]
        let max_reassembly_bytes = usize::MAX;

        // R311jq / R311kf — ONE `tx_mutex` hold covers the WHOLE TX
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
        // MCU profile: critical_section — single-task drive model. R311kj
        // span precision: an oversize message emits its WHOLE fragment
        // chain under the hold (ceil(payload/MTU) sends — the chain MUST
        // stay wire-atomic: an interleaved higher-SN frame would advance
        // the peer's RX gate past the remaining fragments, R311ke); a
        // non-oversize call is at most two emits (overflow flush + one
        // frame), each within the negotiated MTU. Revisit if a
        // preemptive MCU profile lands (5.P caveat, R311kg/R311kj).
        R::with_mutex_mut(&self.tx_mutex, |batch| {
            #[cfg(feature = "transport-batching")]
            if batch.active {
                use crate::frame_encode::{begin_frame, frame_flags, frame_wire_reliability};
                let encode_into = |buf: &mut Vec<u8>| {
                    let mut sink = sce_forge_runtime::codec::VecSink::new(buf);
                    encode_body(&mut sink).expect("VecSink is infallible");
                };
                // R311y835 — every arm below works on THIS message's own
                // priority conduit (`BatchTx::stage_mut`); a message never
                // sees, and never flushes, another priority's staged frame.
                // At most two iterations: a RELIABILITY change (R311y222)
                // within the conduit OR an append overflow (pico
                // `_z_transport_tx_batch_overflow` rollback+retry) flushes this
                // conduit's open frame and falls through to the
                // open-fresh-frame arm, which is always terminal (it empties
                // the stage and returns).
                loop {
                    if batch.stage_mut(priority).buf.is_empty() {
                        let sn = self.next_outbound_frame_sn(priority, reliable, sn_mask);
                        let stage = batch.stage_mut(priority);
                        // +2 for a possible ext_qos ([0x31][VLE(priority)]) that
                        // begin_frame may append (symmetric with encode_frame_envelope).
                        stage.buf.reserve(1 + 10 + 2 + worst_case_payload);
                        begin_frame(&mut stage.buf, sn, frame_flags(reliable), ext_qos);
                        encode_into(&mut stage.buf);
                        if stage.buf.len() > mtu {
                            // The message alone exceeds the budget — the
                            // batch cannot carry it; emit it through the
                            // oversize path (fragment chain, or as-is when
                            // fragmentation is off), still under the lock.
                            let frame = core::mem::take(&mut stage.buf);
                            stage.count = 0;
                            // A refusal here leaves the stage EMPTY and
                            // `count = 0` — the take above already cleared it,
                            // so the rejected message stages nothing for a
                            // later flush to emit half of.
                            return self.emit_frame_or_fragments(
                                &frame,
                                FrameEmit {
                                    ext_qos,
                                    sn,
                                    reliable,
                                    mtu,
                                    sn_mask,
                                    max_reassembly_bytes,
                                },
                            );
                        } else {
                            stage.count = 1;
                        }
                        return Ok(());
                    }
                    // R311y222 — the open frame is ONE (priority, reliability)
                    // conduit. The PRIORITY half is now the stage index, so only
                    // the RELIABILITY half can still mismatch here: a non-QoS
                    // session has two reliability conduits, each its own Frame-SN
                    // ring (`AtomicTxSn { reliable, best_effort }`), so a
                    // best-effort message must not ride a reliable frame (or vice
                    // versa) even without transport-qos — read the open frame's own
                    // R flag so no stage field is needed. A mismatch flushes. This
                    // is a deliberate divergence from vendored zenoh-pico, which
                    // appends mixed-reliability into whatever frame is open
                    // (`tx.c` `_z_transport_tx_send_n_msg_inner`) — wz follows
                    // zenoh's per-(priority, reliability) frame boundary
                    // (`zenoh-codec` `CurrentFrame`/`NewFrame`).
                    // Read the open frame's reliability once (its own R flag) —
                    // reused as the flush channel below (`prev` is the same bytes).
                    let stage = batch.stage_mut(priority);
                    let open_channel = frame_wire_reliability(&stage.buf);
                    if open_channel != Reliability::from_reliable_bool(reliable) {
                        let prev = core::mem::take(&mut stage.buf);
                        stage.count = 0;
                        // Route the flushed frame by its OWN conduit — the frame's
                        // R flag (`open_channel`, read above) + this stage's
                        // priority — NOT the triggering message's reliability (this
                        // arm fires BECAUSE they differ; y217 #3, splitting one
                        // conduit across links would trip the peer's per-conduit RX
                        // SN gate).
                        self.send_wire(&prev, open_channel, priority);
                        continue;
                    }
                    let wpos = stage.buf.len();
                    encode_into(&mut stage.buf);
                    if stage.buf.len() <= mtu {
                        stage.count += 1;
                        return Ok(());
                    }
                    // Overflow: roll the partial encode back, flush this
                    // conduit's open frame, loop into the open-fresh-frame arm.
                    stage.buf.truncate(wpos);
                    let prev = core::mem::take(&mut stage.buf);
                    stage.count = 0;
                    let channel = frame_wire_reliability(&prev);
                    // Same conduit as the current message (this is the append
                    // overflow, not a conduit change), so `priority` is the open
                    // frame's own band.
                    self.send_wire(&prev, channel, priority);
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
            let sn = self.next_outbound_frame_sn(priority, reliable, sn_mask);
            let wire = crate::frame_encode::encode_frame_envelope(
                sn,
                crate::frame_encode::frame_flags(reliable),
                worst_case_payload,
                ext_qos,
                &encode_body,
            );
            self.emit_frame_or_fragments(
                &wire,
                FrameEmit {
                    ext_qos,
                    sn,
                    reliable,
                    mtu,
                    sn_mask,
                    max_reassembly_bytes,
                },
            )
        })
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
    /// `sn`). The oversize FRAME's already-minted `sn` IS the first
    /// fragment's SN; the chain reserves only the `count - 1` follow-on SNs
    /// (`fragment_body` projects the walk onto the ring of `sn_mask`, R311kb),
    /// so the chunk SNs are ring-consecutive from `sn` with NO skipped SN
    /// (R311y206 — matching zenoh `pipeline.rs` + the
    /// `multicast_frame_or_fragments` twin; the pre-y206 code discarded `sn`
    /// and reserved a fresh block, leaving a 1-SN wire gap). The caller's `sn`
    /// mint and this follow-on reserve both run inside the one `tx_mutex`
    /// hold, so the split reservation is atomic w.r.t. a concurrent sender
    /// (the reassembly dispatcher aborts a non-consecutive chain).
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
    fn emit_frame_or_fragments(&self, frame: &[u8], emit: FrameEmit) -> Result<(), SendWireError> {
        let FrameEmit {
            ext_qos,
            sn,
            reliable,
            mtu,
            sn_mask,
            max_reassembly_bytes,
        } = emit;
        let reliability = if reliable {
            Reliability::Reliable
        } else {
            Reliability::BestEffort
        };
        #[cfg(feature = "transport-fragmentation")]
        {
            if frame.len() > mtu {
                // The conduit the follow-on SNs reserve on IS the frame's conduit:
                // `ext_qos = Some(p)` iff the effective priority `p != DEFAULT`
                // (dispatch_network_message), and a DEFAULT frame carries `None`,
                // so `ext_qos.unwrap_or(DEFAULT)` reconstructs the effective
                // priority exactly (no separate param — keeps the arg count sane).
                let priority = ext_qos.unwrap_or(Priority::DEFAULT);
                // R311y215 — strip the frame's own ext_qos (if any) along with the
                // header + VLE(sn): the fragments below re-frame their OWN ext_qos,
                // so `body` must be ONLY the NetworkMessage batch (else the stale
                // `[0x31][priority]` prepends to the reassembled batch and breaks
                // the peer's parse_frame_payload).
                let body = crate::frame_encode::frame_wire_body(frame, sn, ext_qos);
                // `body` is EXACTLY what a receiver stages: the chunks below
                // carry it and nothing else, and the reassembler rejoins them
                // into it. So it is the right unit to test against the slot
                // cap — the framed `frame` would over-count by the header the
                // fragments strip, and the caller's payload would under-count
                // by the network-message envelope they keep.
                //
                // Refuse before the follow-on SN reserve and before the first
                // `send_wire`, so NO wire bytes leave and the chain reserves
                // none of the `count - 1` follow-on SNs.
                //
                // One SN is still spent: both callers mint `sn` before they
                // can know the encoded length (the batching arm frames into
                // `batch.buf`, the immediate arm into `encode_frame_envelope`),
                // so a refused send leaves a 1-SN gap in this conduit's ring.
                // That is the same 1-SN gap the pre-R311y206 fragment path put
                // on the wire routinely, which the note below records as
                // tolerated by the peer's half-window SN check — and here it
                // costs one SN on a path the caller is told failed, instead of
                // a message the caller was told succeeded. Closing the gap
                // means minting lazily after the encode, which is a bigger
                // change to the one-lock mint-through-emit discipline than
                // this error path earns.
                if body.len() > max_reassembly_bytes {
                    return Err(SendWireError::ExceedsReassemblyCap);
                }
                // R311y215 — a QoS chain carries an ext_qos on every fragment, so
                // the count (which the follow-on SN reserve below must match) uses
                // the same qos budget the `fragment_body` chunker does.
                // R2238 (open-debt item 580) — the chain STREAMS: one fragment
                // is built, paid for out of the session's finite fragment TX
                // budget, and written, and only then is the next one built.
                //
                // The pre-R2238 code reserved `count - 1` follow-on SNs up
                // front and then walked a `Vec` the encoder had already
                // materialised whole. Both halves of that are now per-fragment,
                // and the SN policy is UNCHANGED by it: the oversize frame's
                // already-minted `sn` IS the first fragment's SN and each
                // further fragment reserves exactly one more, so the chain
                // stays ring-consecutive from `sn` with no skipped SN
                // (R311y206; zenoh `io/zenoh-transport/src/common/pipeline.rs`
                // @ `fn on_next_fragment` reuses
                // the frame SN slot and the `multicast_frame_or_fragments`
                // twin does the same). Reserving as we go rather than in
                // advance is not a weakening: the whole walk runs inside the
                // one `tx_mutex` hold, which is what made the split
                // reservation atomic w.r.t. a concurrent sender in the first
                // place. What it BUYS is that an abandoned chain reserves
                // only the SNs it actually put on the wire, instead of
                // punching a `count`-wide hole in the conduit's ring.
                //
                // R311y215 — every reserve is on the SAME (priority, reliable)
                // conduit the first fragment minted from (the base-mint +
                // reserve MUST share one conduit key, else conduit[priority]
                // under-advances and reuses an SN).
                let mut chain = crate::frame_encode::FragmentChain::new(
                    body, reliable, mtu, sn, sn_mask, ext_qos,
                );
                let mut emitted = 0usize;
                while chain.remaining_fragments() > 0 {
                    // Read the SN BEFORE drawing, so it names the fragment
                    // this iteration is about to send — which is also the SN
                    // the stop fragment takes if the draw fails, keeping the
                    // conduit's ring gapless across the abandon.
                    let this_sn = chain.next_sn();
                    if !self.take_fragment_tx_credit() {
                        if emitted == 0 {
                            // Nothing left this session, and nothing has left
                            // for THIS message: there is no chain for a peer to
                            // be holding, so no marker is due. Upstream's
                            // equivalent arm restores the SN and writes nothing
                            // (`common/pipeline.rs`, `ext_first.is_some()`).
                            //
                            // wz cannot restore it: `sn` was minted by the
                            // caller before the encoded length was knowable, so
                            // a refused send leaves the same 1-SN gap
                            // `ExceedsReassemblyCap` above leaves, for the same
                            // reason and with the same tolerance.
                            return Err(SendWireError::FragmentTxBudgetExhausted);
                        }
                        // Fragments are already on the wire and the peer is
                        // staging them. Tell it to stop — the marker is the
                        // abandon NOTICE, not chain payload, so it is drawn
                        // OUTSIDE the budget (upstream's ephemeral stop batch
                        // is outside its pool for the same reason). It does
                        // spend an SN, which zenoh's receive-side `SeqNum::roll`
                        // requires of every accepted transport message.
                        let marker = crate::frame_encode::build_fragment_drop_wire(
                            this_sn, reliable, ext_qos,
                        );
                        self.outbound_frame_sn.reserve_next(priority, reliable);
                        self.send_wire(&marker, reliability, priority);
                        return Err(SendWireError::FragmentTxBudgetExhausted);
                    }
                    let frag = match chain.next() {
                        Some(f) => f,
                        // `remaining_fragments() > 0` and `next() == None` are
                        // the same predicate negated, so this arm is
                        // unreachable; breaking rather than panicking keeps the
                        // no_std profiles free of a formatter.
                        None => break,
                    };
                    if emitted > 0 {
                        self.outbound_frame_sn.reserve_next(priority, reliable);
                    }
                    // Every fragment rides the frame's conduit (`priority`
                    // reconstructed above == the SN-mint conduit) so the whole
                    // chain pins to one link (y217 one-conduit=one-link).
                    self.send_wire(&frag, reliability, priority);
                    emitted += 1;
                }
                return Ok(());
            }
        }
        #[cfg(not(feature = "transport-fragmentation"))]
        let _ = (sn, mtu, sn_mask, max_reassembly_bytes);
        // The frame's conduit reconstructed from its own ext_qos (`Some(p)` iff
        // `p != DEFAULT`, else `None -> DEFAULT`) — the same key the SN mint used.
        self.send_wire(frame, reliability, ext_qos.unwrap_or(Priority::DEFAULT));
        Ok(())
    }

    /// R311jq — drain the open batch frames to the link, if any. Private
    /// emit engine shared by [`Self::batch_flush`] / [`Self::batch_stop`] /
    /// the pre-CLOSE drain in [`Self::send_close_with_reason`] / the
    /// express post-dispatch flush. Keeps the `active` flag untouched.
    /// The emit runs INSIDE the batch lock so a drain cannot interleave
    /// with a concurrent absorb's flush (frame order is wire-visible —
    /// the peer's half-window SN check drops reordered frames).
    ///
    /// R311y835 — the walk is ASCENDING BY PRIORITY, and that ordering is the
    /// whole of wz's temporal priority. zenoh's transmission pipeline pulls
    /// `for prio in 0..NUM_PRIO` and returns the first conduit holding bytes
    /// (`io/zenoh-transport/src/common/pipeline.rs`), so a RealTime batch
    /// staged after a Background one still leaves the link first. Before this
    /// round wz held ONE frame and flushed it on every priority change, which
    /// made the wire order the ARRIVAL order: the ext_qos band was carried
    /// faithfully and then ignored by the schedule. Every conduit's frames stay
    /// in their own SN order because a conduit is emitted whole, in one pass,
    /// under one lock hold.
    #[cfg(feature = "transport-batching")]
    fn flush_open_batch(&self) {
        R::with_mutex_mut(&self.tx_mutex, |batch| {
            for idx in 0..batch.stages.len() {
                // The walk is over BANDS, not slots: the index names a priority
                // and the priority selects its stage, so the drain and the
                // staging seam agree by construction on which conduit is which.
                let priority = BatchTx::stage_priority(idx);
                let stage = batch.stage_mut(priority);
                if stage.buf.is_empty() {
                    continue;
                }
                stage.count = 0;
                let frame = core::mem::take(&mut stage.buf);
                let channel = crate::frame_encode::frame_wire_reliability(&frame);
                // Route each frame by its OWN conduit (y217 #3) — this drain path
                // carries no caller priority, so the band comes from the walk.
                self.send_wire(&frame, channel, priority);
            }
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
            R::with_mutex_mut(&self.tx_mutex, |batch| batch.active = true);
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
            R::with_mutex_mut(&self.tx_mutex, |batch| batch.active = false);
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
        priority: Priority,
        push: wz_codecs::push::PushOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        let class = self.outbound_push_class(&push);
        self.dispatch_network_message(
            priority,
            reliable,
            wz_codecs::push::Push::MAX_ENCODED_BYTES,
            class,
            crate::frame_encode::push_body(&push),
        )
    }

    /// R2371 (`transport-stats`) — classify an outbound `Push` for the network
    /// counters, resolving an aliased key expression through THIS session's own
    /// outbound mapping space.
    ///
    /// That table is the right one and the only right one: an `M=0` alias in a
    /// message we are SENDING names OUR id space, which is exactly what
    /// `outbound_mappings` holds
    /// ([`Self::resolve_outbound_mapping`]). So an outbound admin-space publish
    /// classifies as admin whether it went out literal or aliased — the accuracy
    /// the inbound side cannot have, because the peer's space lives on the face.
    ///
    /// Without `transport-stats` the class is never read, and building it would
    /// mean resolving a mapping (a mutex round-trip) per send for nothing, so
    /// the feature-off arm returns the control class without touching the table.
    #[cfg(feature = "codec-push")]
    fn outbound_push_class(
        &self,
        _push: &wz_codecs::push::PushOwned,
    ) -> crate::stats::NetworkStatsClass {
        #[cfg(feature = "transport-stats")]
        {
            crate::network_message::push_stats_class(_push, |id| self.resolve_outbound_mapping(id))
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            crate::stats::NetworkStatsClass::control()
        }
    }

    /// [`Self::outbound_push_class`] for a `Request`.
    #[cfg(feature = "codec-request")]
    fn outbound_request_class(
        &self,
        _request: &wz_codecs::request::RequestOwned,
    ) -> crate::stats::NetworkStatsClass {
        #[cfg(feature = "transport-stats")]
        {
            crate::network_message::request_stats_class(_request, |id| {
                self.resolve_outbound_mapping(id)
            })
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            crate::stats::NetworkStatsClass::control()
        }
    }

    /// [`Self::outbound_push_class`] for a `Response`.
    #[cfg(feature = "codec-response")]
    fn outbound_response_class(
        &self,
        _response: &wz_codecs::response::ResponseOwned,
    ) -> crate::stats::NetworkStatsClass {
        #[cfg(feature = "transport-stats")]
        {
            crate::network_message::response_stats_class(_response, |id| {
                self.resolve_outbound_mapping(id)
            })
        }
        #[cfg(not(feature = "transport-stats"))]
        {
            crate::stats::NetworkStatsClass::control()
        }
    }

    /// R311ms (Level B, B5b-2) — the UNICAST arm of the transport send seam:
    /// route a built [`NetworkMessage`](crate::network_message::NetworkMessage)
    /// to the matching `dispatch_*` family plus the express batch flush. The
    /// unicast twin of the multicast arm in
    /// [`Session::send_network_message`](../../wz_runtime_tokio/session/struct.Session.html);
    /// that seam (the `_z_send_n_msg` analogue) dispatches to one of the two
    /// arms on the transport tag.
    ///
    /// B5b-2 inhabits the Push arm (the publish data plane): `dispatch_push`
    /// mints the SN, frames, and batch-absorbs; then `express` drains the open
    /// batch window (the [`Self::flush_batch_if_express`] parity, lifted here
    /// so a publish that routes through the seam stays transport-agnostic — it
    /// no longer reaches into the unicast action bundle for the flush). R311mu
    /// (B5b-2b-2) added the Request arm (the z_get initiator path; a Query
    /// carries no express window). R311mw (B5b-2b-3) added the Declare arm (the
    /// liveliness-token declare / undeclare path; a Declare carries no express
    /// window either). R311mx (B5b-2b-4) added the Interest arm (the liveliness
    /// subscriber / get / final path; an Interest carries no express window
    /// either). The remaining outbound variant (Response) migrates as its
    /// operations move onto the seam; an inbound-only or not-yet-migrated
    /// variant returns [`SendWireError::FeatureDisabled`] (an honest no-emit
    /// reject, never a panic) — symmetric with the multicast arm. The fn gate
    /// widens to `any(codec-push, codec-request, codec-declare, declare-interest)`
    /// so a query-only (codec-request without codec-push), liveliness-token-only
    /// (codec-declare without either), or interest-only (declare-interest
    /// without any codec-*) build still carries the seam. NOTE: Interest is the
    /// unconditional `NetworkMessage` variant (no `codec-interest` feature
    /// exists), so the Interest arm + this gate disjunct key off
    /// `declare-interest`, not a `codec-*` feature.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-declare",
        feature = "declare-interest",
        feature = "codec-linkstate",
        feature = "codec-response",
        feature = "codec-response-final"
    ))]
    pub fn send_network_message(
        &self,
        msg: crate::network_message::NetworkMessage,
        reliable: bool,
        express: bool,
    ) -> Result<(), SendWireError> {
        // R311y220 — the DEFAULT-priority entry point: delegate to the
        // priority-carrying twin with `Priority::DEFAULT`, so every non-prioritized
        // caller (the ~12 `fan_out` control-plane sends + the base `publish`) stays
        // byte-identical to the prior hard-coded `dispatch_push(Priority::DEFAULT, ..)`.
        // Only `publish_qos` -> `fan_out_qos` routes an application-chosen priority
        // into the twin (the demo `--express-high`/`--low` reachability path).
        self.send_network_message_qos(msg, reliable, express, Priority::DEFAULT)
    }

    /// R311y220 — the priority-carrying twin of [`Self::send_network_message`]: the
    /// data-plane Push arm routes `priority` to [`Self::dispatch_push`] (the app's
    /// chosen QoS band, which `select_link` pins to one aggregated link) instead of
    /// the hard-coded DEFAULT. This differs from the base ONLY in the Push arm — all
    /// other arms are control-plane and IGNORE `priority` by construction (Declare /
    /// Oam self-specify `Priority::Control` inside their own dispatch; Request /
    /// Interest / Response carry no priority parameter at all), so a non-DEFAULT
    /// priority reaching a non-Push message is inert rather than mis-banded. A
    /// non-QoS session further clamps `priority` back to DEFAULT downstream in
    /// [`Self::dispatch_network_message`] (`is_qos()` gate), so the twin is a no-op
    /// on every build that has not negotiated per-priority conduits.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-declare",
        feature = "declare-interest",
        feature = "codec-linkstate",
        feature = "codec-response",
        feature = "codec-response-final"
    ))]
    pub fn send_network_message_qos(
        &self,
        msg: crate::network_message::NetworkMessage,
        reliable: bool,
        express: bool,
        priority: Priority,
    ) -> Result<(), SendWireError> {
        // `priority` is consumed ONLY in the `#[cfg(feature = "codec-push")]` Push
        // arm below. In a build where the fn-gate is satisfied by a NON-push codec
        // (codec-request / codec-declare / declare-interest / codec-linkstate /
        // codec-response{,-final}) the Push arm elides and `priority` would be an
        // unused binding (clippy `-D warnings` reject) — the same gate-skew class the
        // `_ => { let _ = (express, reliable); }` catch arm guards for the other
        // params. The guard is mutually exclusive with the Push arm's own
        // `#[cfg(codec-push)]`, so it can never double-bind.
        #[cfg(not(feature = "codec-push"))]
        let _ = priority;
        // R311nh — the match patterns are FULLY-QUALIFIED (no `use NetworkMessage`
        // alias). The fn-gate above is `any(codec-push, codec-request,
        // codec-declare, declare-interest)`, but each typed arm keys off its own
        // narrower origination gate (the Declare arm on the declare-* union, not
        // bare `codec-declare`). That makes the fn-gate WIDER than the arm union:
        // a `codec-declare`-only build (no origination feature) compiles the fn
        // with ONLY the `_ =>` catch arm, so a local `use` alias would go unused
        // (clippy `-D warnings` reject — the latent gate-skew). Fully-qualifying
        // each pattern removes the alias entirely, so import-usage no longer
        // depends on which arms compile: the unused-import failure class is
        // unrepresentable here regardless of the fn-gate / arm-gate skew.
        match msg {
            // Push data-plane arm (B5b-2): mint SN + frame + batch-absorb,
            // then `express` drains the open batch window (the
            // flush_batch_if_express parity).
            #[cfg(feature = "codec-push")]
            crate::network_message::NetworkMessage::Push(push) => {
                self.dispatch_push(priority, *push, reliable)?;
                #[cfg(feature = "transport-batching")]
                if express {
                    self.flush_open_batch();
                }
                #[cfg(not(feature = "transport-batching"))]
                let _ = express;
                Ok(())
            }
            // Request arm (R311mu, B5b-2b-2): the z_get initiator path. A
            // Query carries no express batch window — `dispatch_request`
            // mints the SN, frames, and batch-absorbs reliably, parity with
            // the prior `send_request_query` (which dispatched reliable with
            // no flush).
            #[cfg(feature = "codec-request")]
            crate::network_message::NetworkMessage::Request(request) => {
                let _ = express;
                self.dispatch_request(*request, reliable)
            }
            // Declare arm (R311mw, B5b-2b-3): the liveliness-token declare /
            // undeclare origination path. A Declare carries no express batch
            // window — `dispatch_declare` mints the SN, frames, and
            // batch-absorbs reliably, parity with the prior
            // `send_declare_token` / `send_undeclare_token` (which dispatched
            // reliable with no flush). R311mx — gated on the SAME declare-*
            // origination union as `dispatch_declare` (not bare `codec-declare`):
            // the arm exists exactly where it can dispatch, so a build that turns
            // `codec-declare` on with no origination feature routes a Declare to
            // the no-emit catch arm instead of referencing an absent dispatch.
            //
            // R311y513 — the ROUTING originator, added because the union above is an
            // APP-SURFACE union and a routing peer is not an app. A `routing-peer`
            // build pulls `codec-declare` (its own manifest calls the Declare wire
            // surface "part of a routing peer's contract") but NONE of the declare-*
            // features, which in this crate also switch on the `observer.rs`
            // session-declaration surface a mesh node never uses. So every Declare a
            // linkstate forwarder originated — the sub / qabl / token floods, the
            // tree-change re-advertise, and the terminating DeclareFinal that closes
            // a client's CURRENT interest — fell to the no-emit catch arm and
            // returned `FeatureDisabled`, silently. The condition mirrors the OAM arm
            // below EXACTLY and for the same reason: `codec-linkstate` + `codec-push`
            // is what a routing peer IS inside this crate. It compiles the send
            // dispatch and nothing else — no app surface follows it.
            #[cfg(any(
                feature = "declare-keyexpr",
                feature = "declare-subscriber",
                feature = "declare-queryable",
                feature = "declare-token",
                feature = "declare-final",
                feature = "liveliness-token",
                all(
                    feature = "codec-declare",
                    feature = "codec-linkstate",
                    feature = "codec-push"
                )
            ))]
            crate::network_message::NetworkMessage::Declare(declare) => {
                let _ = express;
                self.dispatch_declare(*declare, reliable)
            }
            // Interest arm (R311mx, B5b-2b-4): the liveliness subscriber /
            // get / final path. An Interest carries no express batch window —
            // `dispatch_interest` mints the SN, frames, and batch-absorbs
            // reliably, parity with the prior `send_interest_liveliness_*` /
            // `send_interest_final` (which dispatched reliable with no flush).
            // Interest is the unconditional `NetworkMessage` variant, so this
            // arm gates on `declare-interest` (the feature that authors the
            // liveliness interest path), not a `codec-*` feature.
            // R311y513 — the routing originator here too, and it is NOT theoretical:
            // the `routing-interest-pending-gc` broker (R311y512) PROPAGATES a
            // downstream client's CURRENT interest upstream through this very seam.
            // On a build without `declare-interest` every propagated copy would
            // return `FeatureDisabled`, the broker would count 0 copies sent, and it
            // would degrade — silently — into the inline answer it exists to replace.
            // Same `codec-linkstate` + `codec-push` routing marker as the Declare and
            // OAM arms; `interest_body` carries no feature gate at all, so nothing
            // else follows.
            #[cfg(any(
                feature = "declare-interest",
                all(feature = "codec-linkstate", feature = "codec-push")
            ))]
            crate::network_message::NetworkMessage::Interest(interest) => {
                let _ = express;
                self.dispatch_interest(interest, reliable)
            }
            // OAM-LINKSTATE arm (R311qz, c3d): the linkstate-peer routing TX
            // path. The forwarder floods a self-built topology carrier; like
            // Declare/Interest it carries no express batch window —
            // `dispatch_oam` mints the SN, frames, and batch-absorbs
            // reliably. Co-gated `codec-linkstate` (the OAM TX consumer) +
            // `codec-push` (the send infrastructure `dispatch_oam` rides). The
            // `routing-peer` feature PULLS `codec-push` (R311rd), so a routing
            // peer always compiles this arm; a `codec-linkstate`-only build
            // with no send path routes Oam to the no-emit catch arm instead
            // of an absent `dispatch_oam`.
            #[cfg(all(feature = "codec-linkstate", feature = "codec-push"))]
            crate::network_message::NetworkMessage::Oam(oam) => {
                let _ = express;
                self.dispatch_oam(oam, reliable)
            }
            // Response / ResponseFinal arms (R311uc): the linkstate-peer query
            // RETURN path. The forwarder relays a queryable's Reply back toward the
            // querier through this seam; like Declare/Request the reply carries no
            // express batch window — `dispatch_response{,_final}` mints the SN,
            // frames, and batch-absorbs reliably.
            #[cfg(feature = "codec-response")]
            crate::network_message::NetworkMessage::Response(response) => {
                let _ = express;
                self.dispatch_response(*response, reliable)
            }
            #[cfg(feature = "codec-response-final")]
            crate::network_message::NetworkMessage::ResponseFinal(response_final) => {
                let _ = express;
                self.dispatch_response_final(response_final, reliable)
            }
            // Not yet routed through the seam (or inbound-only). Honest no-emit
            // reject, never a panic — symmetric with the multicast arm. The
            // `reliable` discard keeps the param used when this is the only arm
            // present (e.g. a `codec-declare`-on build with no origination
            // feature, where every typed arm is cfg'd out).
            _ => {
                let _ = (express, reliable);
                Err(SendWireError::FeatureDisabled)
            }
        }
    }

    /// See [`Self::dispatch_push`]. Gated on the declare-* origination union
    /// (the features whose senders actually emit a `Declare`); the R311mx
    /// send-seam Declare arm carries the SAME gate so the arm exists exactly
    /// where `dispatch_declare` does (a build that turns `codec-declare` on
    /// without any origination feature — e.g. `declare-interest` alone — emits
    /// no `Declare`, so the seam routes it to the no-emit catch arm instead).
    #[cfg(any(
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-final",
        feature = "liveliness-token",
        // R311y513 — the ROUTING originator. Kept character-identical to the send
        // seam's arm gate: the arm must exist exactly where this fn does, and the
        // two drifting apart is the failure mode the R311mx note above describes.
        all(
            feature = "codec-declare",
            feature = "codec-linkstate",
            feature = "codec-push"
        ),
    ))]
    fn dispatch_declare(
        &self,
        declare: wz_codecs::declare::DeclareOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            // Declare = a control-plane message; zenoh `QoSType::DECLARE` = Control.
            Priority::Control,
            reliable,
            wz_codecs::declare::Declare::MAX_ENCODED_BYTES,
            // Control plane: `n_msgs` only, no payload cell (upstream's payload
            // labels cover the four data kinds).
            crate::stats::NetworkStatsClass::control(),
            crate::frame_encode::declare_body(&declare),
        )
    }

    /// See [`Self::dispatch_push`]. The OAM-LINKSTATE TX path (c3d
    /// linkstate-peer flood). The reserve hint is the fixed
    /// `Oam::MAX_ENCODED_BYTES`; the variable LinkStateList ZBuf payload
    /// grows the `VecSink` past it, and the oversize / fragment decision
    /// keys off the ACTUAL encoded length (not this hint), so a large
    /// multi-node flood fragments correctly — PROVIDED `transport-fragmentation`
    /// is on, which the `routing-peer` feature PULLS (R311rd); without it an
    /// oversize OAM is dropped at the `u16` stream guard. Co-gated on
    /// `codec-push`: the OAM TX rides the `dispatch_network_message` send
    /// infrastructure the data plane brings (`routing-peer` pulls codec-push), so
    /// `codec-linkstate` alone — an encode-only build — does not pull this
    /// send path (which would orphan it without `dispatch_network_message`).
    #[cfg(all(feature = "codec-linkstate", feature = "codec-push"))]
    fn dispatch_oam(
        &self,
        oam: wz_codecs::oam::OamOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            // OAM = a control-plane message; zenoh `QoSType::OAM` = Control.
            Priority::Control,
            reliable,
            wz_codecs::oam::Oam::MAX_ENCODED_BYTES,
            crate::stats::NetworkStatsClass::control(),
            crate::frame_encode::oam_body(&oam),
        )
    }

    /// See [`Self::dispatch_push`].
    #[cfg(feature = "codec-request")]
    fn dispatch_request(
        &self,
        request: wz_codecs::request::RequestOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        let class = self.outbound_request_class(&request);
        self.dispatch_network_message(
            // Request/Response = the data plane; zenoh default `Priority::Data`.
            Priority::DEFAULT,
            reliable,
            wz_codecs::request::Request::MAX_ENCODED_BYTES,
            class,
            crate::frame_encode::request_body(&request),
        )
    }

    /// See [`Self::dispatch_push`]. The linkstate-peer query RETURN path: a
    /// queryable's `Response` (Reply / Err) relayed back toward the querier.
    #[cfg(feature = "codec-response")]
    fn dispatch_response(
        &self,
        response: wz_codecs::response::ResponseOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        let class = self.outbound_response_class(&response);
        self.dispatch_network_message(
            Priority::DEFAULT,
            reliable,
            wz_codecs::response::Response::MAX_ENCODED_BYTES,
            class,
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
            Priority::DEFAULT,
            reliable,
            wz_codecs::response_final::ResponseFinal::MAX_ENCODED_BYTES,
            // A pure correlation marker — no key expression and no payload, so
            // it is control plane even though it closes a data-plane exchange.
            crate::stats::NetworkStatsClass::control(),
            crate::frame_encode::response_final_body(&response_final),
        )
    }

    /// See [`Self::dispatch_push`].
    ///
    /// R311y513 — same routing-originator widening as the send seam's Interest arm
    /// (the `routing-interest-pending-gc` broker propagates through it); the two
    /// gates are kept identical so the arm exists exactly where this fn does.
    #[cfg(any(
        feature = "declare-interest",
        all(feature = "codec-linkstate", feature = "codec-push")
    ))]
    fn dispatch_interest(
        &self,
        interest: wz_codecs::interest::InterestOwned,
        reliable: bool,
    ) -> Result<(), SendWireError> {
        self.dispatch_network_message(
            // Interest carries `QoSType::DECLARE` = Control (zenoh interests.rs).
            Priority::Control,
            reliable,
            wz_codecs::interest::Interest::MAX_ENCODED_BYTES,
            crate::stats::NetworkStatsClass::control(),
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

    /// R311y72 — outbound ENTITY id generator (the `SourceInfo.eid` a
    /// publisher stamps). Returns the next `u32` entity id and advances the
    /// counter; first call returns `0`. Drawn from its own id-space (not
    /// the token-id counter), the SSOT for "this session's next entity id".
    /// `Relaxed` — uniqueness within the session is the only invariant
    /// (cross-session collisions are keyed out by the accompanying zid).
    pub fn alloc_next_entity_id(&self) -> u32 {
        self.next_outbound_entity_id.fetch_add(1, Ordering::Relaxed)
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
        // The DEFAULT-priority case of the express variant below (one home for
        // the build + dispatch, priority DEFAULT so no ext_qos ever rides).
        self.send_push_literal_qos(keyexpr_suffix, value, reliable, Priority::DEFAULT)
    }

    /// R311y215 — the express (priority-carrying) twin of
    /// [`Self::send_push_literal`]: dispatch a `Put` Push on the given QoS
    /// `priority` conduit. On a session that negotiated QoS ([`Self::is_qos`]) a
    /// non-DEFAULT priority rides its OWN per-(priority, reliability) SN conduit
    /// and stamps the Frame's `ext_qos` (id `0x1`, z64); on a non-QoS session —
    /// or a build without `transport-qos` — the priority has NO wire effect (one
    /// conduit, no ext_qos) and this behaves exactly as
    /// [`Self::send_push_literal`], so the signature is feature-stable
    /// ([[feedback-signature-stability]]). The AP publish API threads
    /// `Publisher` / `put` priority here; the `WzConfig` -> [`Self::set_qos_offer`]
    /// negotiation plumbing and the priority-select multilink e2e that exercises
    /// a live non-DEFAULT send land in R311y216 (step 8).
    pub fn send_push_literal_qos(
        &self,
        keyexpr_suffix: &str,
        value: &[u8],
        reliable: bool,
        priority: Priority,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_literal(keyexpr_suffix, value)?;
            self.dispatch_push(priority, push, reliable)?;
            Ok(())
        }
        #[cfg(not(feature = "codec-push"))]
        {
            let _ = (keyexpr_suffix, value, reliable, priority);
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
            // R311y342 — the id space's OTHER end. The lower bound has been
            // gated since R300; the upper bound never was, so wz could emit an
            // alias id that neither upstream can hold: zenoh types
            // `DeclareKeyExpr.id` as `ExprId = u16` and zenoh-pico's
            // `_z_decl_kexpr_t` holds `uint16_t _id`, while our codec carries a
            // VLE u64 (deliberate — the shared wireexpr shape). Measured, not
            // argued: before this gate, `send_declare_keyexpr(65_536, ..)`
            // returned Ok and put the frame on the wire.
            if mapping_id > u64::from(u16::MAX) {
                return Err(SendDeclareError::MappingIdTooWideForWire(mapping_id));
            }
            check_outbound_keyexpr_pico_safe(suffix)?;
            let declare = build_declare_kexpr(mapping_id, suffix)?;
            // §5.21 routing-namespace — bake the namespace into the wire alias
            // DEFINITION (this is a direct `dispatch_declare`, below the egress
            // arm). The peer registers `id -> <ns>/<suffix>`, so a later aliased
            // Push/Request (which the decorator passes through unchanged, id != 0)
            // resolves UNDER the namespace at the peer instead of leaking to the
            // bare keyexpr; the local `outbound_mappings` below keeps the BARE
            // suffix for loopback resolution (transparent namespace, the zenoh
            // model). The reconnect replay re-applies the same via `replay_one`.
            #[cfg(feature = "routing-namespace")]
            let declare = self.namespace_egress_declare(declare)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            self.dispatch_push(Priority::DEFAULT, push, reliable)?;
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
            // R311ou — build half (R300 pico-safety gate + envelope) is the
            // shared `prepare_declare_subscriber` SSOT, also called by the
            // seam-routed `Session::declare_subscriber`; this wrapper keeps the
            // dispatch + reconnect-cache half (byte-stable-wire test callers +
            // any direct low-level caller).
            let declare =
                self.prepare_declare_subscriber(subscriber_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            self.cache_subscriber_declaration(subscriber_id, keyexpr_mapping_id, keyexpr_suffix);
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
        complete: bool,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-queryable")]
        {
            // R311ow — build half (R300 pico-safety gate + envelope) is the
            // shared `prepare_declare_queryable` SSOT, also called by the
            // seam-routed `Session::declare_queryable`; this wrapper keeps the
            // dispatch + reconnect-cache half (byte-stable-wire test callers +
            // any direct low-level caller). Mirror of the declare-subscriber
            // split landed in R311ou.
            let declare = self.prepare_declare_queryable(
                queryable_id,
                keyexpr_mapping_id,
                keyexpr_suffix,
                complete,
            )?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`), carrying `complete` so a
            // complete queryable survives the replay.
            self.cache_queryable_declaration(
                queryable_id,
                keyexpr_mapping_id,
                keyexpr_suffix,
                complete,
            );
            Ok(())
        }
        #[cfg(not(feature = "declare-queryable"))]
        {
            let _ = (queryable_id, keyexpr_mapping_id, keyexpr_suffix, complete);
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
    ///
    /// R311mw (Level B, B5b-2b-3) — the build half (resolve + R300 gate +
    /// envelope assembly) is now [`Self::prepare_declare_token`]; this wrapper
    /// keeps the dispatch + reconnect-cache half. The seam-routed
    /// `Session::declare_token` shares the same `prepare_declare_token` SSOT
    /// and routes the emit through the transport send seam instead, so the two
    /// paths cannot diverge on the pico-safety gate. The wrapper survives for
    /// its byte-stable-wire-shape callers (the session_glue tests + the
    /// wz-ap-demo task).
    pub fn send_declare_token(
        &self,
        token_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendDeclareError> {
        #[cfg(feature = "declare-token")]
        {
            let declare =
                self.prepare_declare_token(token_id, keyexpr_mapping_id, keyexpr_suffix)?;
            self.dispatch_declare(declare, /*reliable=*/ true)
                .map_err(SendDeclareError::from)?;
            // A4 — record for post-reconnect replay (pico
            // `_z_cache_declaration` on `_Z_RES_OK`).
            self.cache_token_declaration(token_id, keyexpr_mapping_id, keyexpr_suffix);
            Ok(())
        }
        #[cfg(not(feature = "declare-token"))]
        {
            let _ = (token_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
    }

    /// R311mw (Level B, B5b-2b-3) — the BUILD half of
    /// [`Self::send_declare_token`]: resolve the keyexpr from
    /// `(keyexpr_mapping_id, keyexpr_suffix)`, run the R300 outbound
    /// pico-safety gate, and assemble the `Declare(DeclToken)` envelope.
    /// Returns the built [`DeclareOwned`] for the caller to hand to the
    /// transport send seam
    /// ([`Session::send_network_message`](../../wz_runtime_tokio/session/struct.Session.html)),
    /// mirroring how `request_build::build_request_query_with_meta` is the
    /// build half the seam-routed z_get shares with `send_request_query`. The
    /// pico-safety gate stays SSOT here — both the seam-routed
    /// `Session::declare_token` and the `send_declare_token` wrapper call this,
    /// so the validation is authored exactly once.
    #[cfg(feature = "declare-token")]
    pub fn prepare_declare_token(
        &self,
        token_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<wz_codecs::declare::DeclareOwned, SendDeclareError> {
        // R300 — same gate shape as `send_declare_subscriber`. The full path
        // to `DeclareOwned` mirrors `dispatch_declare` — the module-level
        // `use` is `liveliness-token`-gated but this build half is reachable
        // under bare `declare-token` (the `send_declare_token` wrapper path).
        let reconstructed =
            self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
        check_outbound_keyexpr_pico_safe(&reconstructed)?;
        Ok(build_declare_token(
            token_id,
            keyexpr_mapping_id,
            keyexpr_suffix,
        )?)
    }

    /// R311ou — the BUILD half of [`Self::send_declare_subscriber`], mirroring
    /// [`Self::prepare_declare_token`]: resolve the keyexpr from
    /// `(keyexpr_mapping_id, keyexpr_suffix)`, run the R300 outbound
    /// pico-safety gate, and assemble the `Declare(DeclSubscriber)` envelope.
    /// Returns the built [`DeclareOwned`] for the caller to route through the
    /// transport send seam
    /// ([`Session::send_network_message`](../../wz_runtime_tokio/session/struct.Session.html)).
    ///
    /// The seam-routed `Session::declare_subscriber` (R311ou — the routed
    /// subscriber that pico's `_z_register_subscriber` emits when
    /// `allowed_origin` allows remote, `vendor/zenoh-pico/src/net/primitives.c:235`)
    /// and the `send_declare_subscriber` wrapper both call this, so the
    /// pico-safety gate + envelope assembly stay authored exactly once (build
    /// SSOT). Mirror of the declare-token split landed in R311mw (B5b-2b-3).
    #[cfg(feature = "declare-subscriber")]
    pub fn prepare_declare_subscriber(
        &self,
        subscriber_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<wz_codecs::declare::DeclareOwned, SendDeclareError> {
        let reconstructed =
            self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
        check_outbound_keyexpr_pico_safe(&reconstructed)?;
        Ok(build_declare_subscriber(
            subscriber_id,
            keyexpr_mapping_id,
            keyexpr_suffix,
        )?)
    }

    /// R311mw — append the post-emit reconnect-replay cache entry for a
    /// declared liveliness token. The session-level counterpart to the
    /// `Session::declare_token` seam emit: pico caches the declaration on
    /// `_Z_RES_OK` from `_z_send_n_msg`, so the cache is session-state
    /// bookkeeping AROUND the wire emit, not part of the transport seam (the
    /// same reason the z_get reply-pending register stays session-level in
    /// R311mu). Signature-stable: a no-op without `session-reconnect` (no cache
    /// storage exists) per R311g1, mirroring
    /// [`Self::prune_liveliness_get_interest`].
    #[cfg(feature = "declare-token")]
    pub fn cache_token_declaration(
        &self,
        token_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::Token {
            token_id,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (token_id, keyexpr_mapping_id, keyexpr_suffix);
    }

    /// R311ou — append the post-emit reconnect-replay cache entry for a
    /// declared subscriber (pico `_z_cache_declaration` on `_Z_RES_OK`). The
    /// session-level counterpart to the seam-routed
    /// `Session::declare_subscriber` emit, mirroring [`Self::cache_token_declaration`]:
    /// the cache is session-state bookkeeping AROUND the wire emit, not part of
    /// the transport seam, so it lives here rather than inside
    /// `send_network_message`. Shared by the `send_declare_subscriber` wrapper
    /// and the seam-routed declare so the cache shape is authored once.
    /// Signature-stable: a no-op without `session-reconnect`.
    pub fn cache_subscriber_declaration(
        &self,
        subscriber_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::Subscriber {
            subscriber_id,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (subscriber_id, keyexpr_mapping_id, keyexpr_suffix);
    }

    /// R311ow — the BUILD half of [`Self::send_declare_queryable`], the
    /// queryable sibling of [`Self::prepare_declare_subscriber`]: resolve the
    /// keyexpr from `(keyexpr_mapping_id, keyexpr_suffix)`, run the R300
    /// outbound pico-safety gate, and assemble the `Declare(DeclQueryable)`
    /// envelope. Returns the built [`DeclareOwned`] for the caller to route
    /// through the transport send seam
    /// ([`Session::send_network_message`](../../wz_runtime_tokio/session/struct.Session.html)).
    ///
    /// The seam-routed `Session::declare_queryable` (R311ow — the routed
    /// queryable that pico's `_z_register_queryable` emits when `allowed_origin`
    /// allows remote, `vendor/zenoh-pico/src/net/primitives.c:348`) and the
    /// `send_declare_queryable` wrapper both call this, so the pico-safety gate
    /// and envelope assembly stay authored exactly once (build SSOT). Mirror of
    /// the declare-subscriber split landed in R311ou.
    #[cfg(feature = "declare-queryable")]
    pub fn prepare_declare_queryable(
        &self,
        queryable_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        complete: bool,
    ) -> Result<wz_codecs::declare::DeclareOwned, SendDeclareError> {
        let reconstructed =
            self.reconstruct_outbound_keyexpr(keyexpr_mapping_id, keyexpr_suffix)?;
        check_outbound_keyexpr_pico_safe(&reconstructed)?;
        let mut declare =
            build_declare_queryable(queryable_id, keyexpr_mapping_id, keyexpr_suffix)?;
        // Stamp the local QueryableInfo completeness (the BestMatching producer
        // input). DEFAULT / incomplete omits the ext, so a plain queryable stays
        // byte-identical to before.
        set_declare_queryable_info(
            &mut declare,
            crate::queryable_info::QueryableInfo::local(complete),
        );
        Ok(declare)
    }

    /// R311ow — append the post-emit reconnect-replay cache entry for a
    /// declared queryable (pico `_z_cache_declaration` on `_Z_RES_OK`). The
    /// session-level counterpart to the seam-routed
    /// `Session::declare_queryable` emit, mirroring
    /// [`Self::cache_subscriber_declaration`]: the cache is session-state
    /// bookkeeping AROUND the wire emit, not part of the transport seam, so it
    /// lives here rather than inside `send_network_message`. Shared by the
    /// `send_declare_queryable` wrapper and the seam-routed declare so the
    /// cache shape is authored once. Signature-stable: a no-op without
    /// `session-reconnect`.
    pub fn cache_queryable_declaration(
        &self,
        queryable_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        complete: bool,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::Queryable {
            queryable_id,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
            complete,
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (queryable_id, keyexpr_mapping_id, keyexpr_suffix, complete);
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
    /// outbound gate at `declare_token` time.
    ///
    /// R311y536 — the gate is the UNION OF ITS CALLERS, and it used to be
    /// narrower than them. It read `liveliness-token` alone, described as
    /// "the only feature that stages outbound `Declare` through the sink",
    /// and that stopped being true when the routed SUBSCRIBER replies
    /// arrived: `send_declare_subscriber_reply` is `declare-subscriber`-gated
    /// and `send_declare_final_reply` is `any(liveliness-token,
    /// declare-subscriber)`-gated, so a build with `declare-subscriber` ON and
    /// `liveliness-token` OFF compiled two callers of a method that did not
    /// exist (E0599). R311y530 fixed the BUILDER half of exactly this — it
    /// routed the final reply through the ungated `declare_build` twin
    /// precisely so the arm would compile without `liveliness-token` — and
    /// left the SINK it calls still gated on the old feature. Fixing the
    /// producer and not auditing the consumer is the recurring shape; the rule
    /// this now follows is that a helper's cfg must be the OR of every arm
    /// that calls it, computed from the call sites rather than from the
    /// feature that happened to introduce it.
    ///
    /// The body needs `codec-declare` for `encode_frame_with_declare`, and
    /// BOTH gate features supply it (`liveliness-token = ["codec-declare"]`,
    /// `declare-subscriber = ["codec-declare"]`), so the widened gate keeps
    /// that dependency satisfied by construction rather than by coincidence.
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
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
            // R311y342 — the DECLARE twin's u16 wire bound, applied to the
            // retraction half. zenoh's `UndeclareKeyExpr { id: ExprId }` and
            // pico's `_z_undecl_kexpr_t { uint16_t _id }` are as narrow as
            // their declare counterparts, and this surface emits WITHOUT
            // consulting the mapping table (its doc's "removing an absent id
            // is a no-op" idempotence), so the gated twin does not bound it.
            // Dropped silently rather than reported because this signature has
            // no error channel by contract — the same reason a transport-down
            // reject drops the emit here.
            if mapping_id > u64::from(u16::MAX) {
                return;
            }
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
        R::with_mutex_mut(&self.link.established_at, |slot| slot.is_some())
    }

    /// R311kx — the governing lease window in milliseconds:
    /// `min(params.lease_ms, peer OPEN-advertised)`, falling back to the
    /// local window pre-OPEN (`peer_open_lease_ms` empty). The R311kv
    /// comparator's min hoisted to an accessor so the lease-expiry check
    /// ([`crate::drive::check_lease_deadline`]), the loop wake-deadline
    /// computation ([`crate::drive::lease_wake_deadline`]), and the
    /// keepalive TX cadence ([`crate::drive::keepalive_wake_deadline`])
    /// share one definition — zenoh-pico adopts the min once at OPEN
    /// arrival (unicast/transport.c:193/269) and every task reads the
    /// same `_common._lease`.
    pub fn adopted_lease_ms(&self) -> u64 {
        let peer = R::with_mutex_mut(&self.peer_open_lease_ms, |g| *g);
        match peer {
            Some(advertised) => advertised.min(self.params.lease_ms),
            None => self.params.lease_ms,
        }
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
            self.prune_token_declaration(token_id);
        }
        #[cfg(not(all(feature = "declare-token", feature = "declare-undeclare")))]
        let _ = token_id;
    }

    /// R311mw — drop the post-emit reconnect-replay cache entry for an
    /// undeclared liveliness token (first-match, pico `_z_prune_declaration`
    /// filter semantics). The session-level counterpart to the
    /// `LivelinessToken` teardown seam emit — shared by the
    /// `send_undeclare_token` wrapper and the seam-routed teardown so the
    /// prune is authored once. Signature-stable: a no-op without
    /// `session-reconnect` per R311g1, mirroring
    /// [`Self::prune_liveliness_get_interest`].
    #[cfg(all(feature = "declare-token", feature = "declare-undeclare"))]
    pub fn prune_token_declaration(&self, token_id: u64) {
        #[cfg(feature = "session-reconnect")]
        self.prune_declaration(
            |entry| matches!(entry, CachedDeclaration::Token { token_id: t, .. } if *t == token_id),
        );
        #[cfg(not(feature = "session-reconnect"))]
        let _ = token_id;
    }

    // R121i-c added `send_declare_final` here: encode + dispatch a bare
    // `Declare(DeclFinal)`, "reserved for the future Interest/Reply path
    // (R121j+) ... so the state machine has the dispatch shape ready when
    // Interest replies need to close a multi-DECLARE reply batch".
    //
    // R311y346 DELETES it. That future arrived and took the other road:
    // `build_declare_final_reply` (declare_build.rs) is the interest-response
    // terminator, live in the router (router_forward.rs, linkstate_forward.rs),
    // and it stamps the id the wire requires. The stub had ZERO callers and
    // could not have acquired a correct one -- it dispatched `build_declare_final`
    // NEAT, i.e. `interest_id: None`, and pico HARD-ERRORS on a DeclFinal with no
    // interest_id (`_Z_ERR_MESSAGE_ZENOH_DECLARATION_UNKNOWN`, declare_build.rs's
    // own :944-951 note). pico never emits that shape either: every emit runs
    // through `_z_optional_id_make_some(interest_id)`
    // (vendor/zenoh-pico/src/session/interest.c:185), so even the UNSOLICITED
    // peer-push sends `Some(0)`, not None. So this was not dead code awaiting a
    // caller; it was unreachable code that was wrong by construction.
    //
    // `build_declare_final` does NOT orphan on this deletion --
    // `build_declare_final_reply` reuses it and the codec tests name it.
    //
    // What the stub GESTURED at is real and wz does not have it: pico pushes its
    // whole declaration set to a freshly accepted peer and closes it with
    // DeclFinal(Some(0)) (interest.c:194-201, driven from
    // transport/unicast/accept.c:149). That is now declare-final's NAMED RESIDUAL
    // in the inventory rather than a stub standing in for it.

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
            self.cache_subscriber_interest(
                interest_id,
                history,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            Ok(())
        }
        #[cfg(not(feature = "declare-interest"))]
        {
            let _ = (interest_id, history, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R311mw/R311mx — append the post-emit reconnect-replay cache entry for a
    /// liveliness subscriber Interest. The session-level counterpart to the
    /// `Session::declare_liveliness_subscriber` seam emit — shared by the
    /// `send_interest_liveliness_subscriber` wrapper and the seam-routed
    /// declare so the cache is authored once. Signature-stable: a no-op without
    /// `session-reconnect` per R311g1, mirroring
    /// [`Self::cache_token_declaration`].
    #[cfg(feature = "declare-interest")]
    pub fn cache_subscriber_interest(
        &self,
        interest_id: u64,
        history: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::LivelinessSubscriberInterest {
            interest_id,
            history,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (interest_id, history, keyexpr_mapping_id, keyexpr_suffix);
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
            self.cache_get_interest(interest_id, keyexpr_mapping_id, keyexpr_suffix);
            Ok(())
        }
        #[cfg(not(feature = "declare-interest"))]
        {
            let _ = (interest_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R311mw/R311mx — append the post-emit reconnect-replay cache entry for a
    /// one-shot CURRENT liveliness get Interest. The session-level counterpart
    /// to the `Session::liveliness_get` seam emit — shared by the
    /// `send_interest_liveliness_get` wrapper and the seam-routed get.
    /// Signature-stable: a no-op without `session-reconnect` per R311g1,
    /// mirroring [`Self::cache_token_declaration`]. The matching drop is
    /// [`Self::prune_liveliness_get_interest`] (registry-fed at get
    /// termination), NOT an undeclare-emit prune.
    #[cfg(feature = "declare-interest")]
    pub fn cache_get_interest(
        &self,
        interest_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::LivelinessGetInterest {
            interest_id,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (interest_id, keyexpr_mapping_id, keyexpr_suffix);
    }

    /// R311y771 — encode + dispatch an `Interest` asking the peer for its
    /// SUBSCRIBER declarations matching `(keyexpr_mapping_id,
    /// keyexpr_suffix)`. The emit wz never had: until this round every
    /// `InterestOwned` leaving this crate carried `TO` and only `TO`, so a
    /// zenoh router — which propagates a subscriber declaration to a face
    /// ONLY if that face registered an interest with `options.subscribers()`
    /// (`hat/router/pubsub.rs:120-125`) — sent wz nothing, silently, and
    /// `RemoteSubscriberRegistry` stayed empty against zenohd no matter how
    /// many subscribers the far side declared.
    ///
    /// `current` requests the peer's CURRENT matching set (replayed as
    /// `interest_id`-tagged `Declare(DeclSubscriber)` records terminated by
    /// a `DeclFinal`) and `future` keeps the interest live for subsequent
    /// declare / undeclare events. zenoh uses BOTH from
    /// `declare_publisher_inner` (`api/session.rs:1370-1377`,
    /// `InterestMode::CurrentFuture`), which is what a matching listener
    /// wants: the current set seeds the verdict, the future stream drives
    /// the transitions.
    ///
    /// Reliable channel — same SN-window ordering reason as every other
    /// declaration-plane emit: the peer must observe the Interest before the
    /// declarations it asks for, or its interest table resolves to no-match
    /// and the replay is silently skipped.
    ///
    /// Terminated by [`Self::send_interest_final`] with the same
    /// `interest_id` — there is no dedicated subscriber-interest final,
    /// exactly as pico prunes any cached `_Z_N_INTEREST` by id.
    ///
    /// R311g1 — signature-stability: body cfg, signature stable. Returns
    /// `Err(FeatureDisabled)` when `declare-interest` is off; the caller
    /// cannot treat the absence as harmless, because a matching listener
    /// declared without the Interest is one that will never fire.
    pub fn send_interest_subscribers(
        &self,
        interest_id: u64,
        current: bool,
        future: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        // Signature-stable per R311g1; the BODY carries the `alloc` gate that
        // `InterestKinds` and every Interest builder sit behind. A no-alloc
        // build has no `InterestOwned` to emit, which is a build-time choice
        // the caller observes as a runtime reject.
        #[cfg(feature = "alloc")]
        {
            self.send_interest_kinds(
                interest_id,
                InterestKinds::SUBSCRIBERS,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            )
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = (
                interest_id,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R311y771 — the QUERYABLE-plane twin of
    /// [`Self::send_interest_subscribers`]. zenoh emits it from
    /// `declare_querier_inner` (`api/session.rs:1428-1435`) and its router
    /// gates queryable propagation on `options.queryables()` the same way
    /// (`hat/router/queries.rs:255-259`); what it feeds on the wz side is
    /// `RemoteQueryableRegistry`, behind `Querier::get_matching_status` and
    /// the querier-scoped matching listener.
    pub fn send_interest_queryables(
        &self,
        interest_id: u64,
        current: bool,
        future: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        // Same `alloc`-in-the-body shape as the subscriber wrapper above.
        #[cfg(feature = "alloc")]
        {
            self.send_interest_kinds(
                interest_id,
                InterestKinds::QUERYABLES,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            )
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = (
                interest_id,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// The emit SSOT the two wrappers above share — one dispatch, one cache
    /// append, so the subscriber and queryable planes cannot drift into two
    /// slightly different send paths. Public because an arbitrary
    /// [`InterestKinds`](crate::interest_build::InterestKinds) union is a
    /// legitimate thing to send (see
    /// [`crate::interest_build::build_interest_kinds`]): a caller wanting
    /// both planes should spend ONE interest id and ONE Final, not two.
    ///
    /// Deliberately NOT extended to the token kind. `TOKENS` is expressible
    /// through this door and will encode correctly, but the two liveliness
    /// wrappers own their own reconnect-cache shapes
    /// (`LivelinessSubscriberInterest` / `LivelinessGetInterest`) which carry
    /// the `history` flag this one does not; routing a token interest here
    /// would cache it under the wrong variant and replay it with the wrong
    /// mode. The type cannot forbid it, so it is stated.
    ///
    /// `alloc`-gated rather than signature-stable, and that is a deliberate
    /// exception to R311g1: the signature NAMES `InterestKinds`, which lives
    /// in the `alloc`-gated `interest_build` because an Interest IS an
    /// `InterestOwned`. A signature that survives into a feature state where
    /// its own parameter type does not exist is not stability, it is a build
    /// break — the shape Layer C1bz caught this round. The two named wrappers
    /// above stay signature-stable, because their parameters are scalars, and
    /// they are what a caller reaches for.
    #[cfg(feature = "alloc")]
    pub fn send_interest_kinds(
        &self,
        interest_id: u64,
        kinds: InterestKinds,
        current: bool,
        future: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) -> Result<(), SendWireError> {
        #[cfg(feature = "declare-interest")]
        {
            let interest = build_interest_kinds(
                interest_id,
                kinds,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            )?;
            self.dispatch_interest(interest, /*reliable=*/ true)?;
            self.cache_matching_interest(
                interest_id,
                kinds,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            Ok(())
        }
        #[cfg(not(feature = "declare-interest"))]
        {
            let _ = (
                interest_id,
                kinds,
                current,
                future,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            Err(SendWireError::FeatureDisabled)
        }
    }

    /// R311y771 — append the post-emit reconnect-replay cache entry for a
    /// subscriber / queryable Interest. The session-level counterpart to the
    /// matching-listener seam emit, mirroring
    /// [`Self::cache_subscriber_interest`]. Signature-stable: a no-op
    /// without `session-reconnect` per R311g1.
    ///
    /// A reconnect gives us a NEW face and zenoh keeps `remote_interests`
    /// PER FACE, so without this replay the peer stops feeding the registry
    /// while every matching listener stays registered — the silent half-dead
    /// state.
    #[cfg(all(feature = "declare-interest", feature = "alloc"))]
    pub fn cache_matching_interest(
        &self,
        interest_id: u64,
        kinds: InterestKinds,
        current: bool,
        future: bool,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        #[cfg(feature = "session-reconnect")]
        self.cache_declaration(CachedDeclaration::MatchingInterest {
            interest_id,
            kinds,
            current,
            future,
            mapping_id: keyexpr_mapping_id,
            suffix: keyexpr_suffix.map(ToString::to_string),
        });
        #[cfg(not(feature = "session-reconnect"))]
        let _ = (
            interest_id,
            kinds,
            current,
            future,
            keyexpr_mapping_id,
            keyexpr_suffix,
        );
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
            // A4 — drop the matching replay entry.
            self.prune_interest(interest_id);
        }
        #[cfg(not(feature = "declare-interest"))]
        let _ = interest_id;
    }

    /// R311mx — drop the post-emit reconnect-replay cache entry for a
    /// terminated liveliness Interest (first-match; pico's interest prune
    /// filter matches any cached `_Z_N_INTEREST` by `_id` —
    /// `_z_cache_declaration_undeclare_filter_interest` — so both the
    /// subscriber and get Interest forms prune here). The session-level
    /// counterpart to the `LivelinessSubscriber` teardown seam emit — shared
    /// by the `send_interest_final` wrapper and the seam-routed teardown.
    /// Signature-stable: a no-op without `session-reconnect` per R311g1,
    /// mirroring [`Self::prune_token_declaration`].
    #[cfg(feature = "declare-interest")]
    pub fn prune_interest(&self, interest_id: u64) {
        #[cfg(feature = "session-reconnect")]
        self.prune_declaration(|entry| entry.interest_id() == Some(interest_id));
        #[cfg(not(feature = "session-reconnect"))]
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
    /// * `meta.parameters` → Q_P flag + params slice, gated
    ///   `query-selector-parameters`
    /// * `meta.value` → Query-body VALUE ext (id=0x03 ZBUF: encoding +
    ///   payload) — emitted FIRST in the Query body ext chain — gated
    ///   `query-value` (R311y250)
    /// * `meta.source_info` → Query-body source-info ext (id=0x01 ZBUF),
    ///   gated `query-source-info`
    /// * `meta.attachment` → Query-body attachment ext (id=0x05 ZBUF),
    ///   gated `query-attachment`
    /// * `meta.timeout_ms` → Request-level timeout ext (gated by the
    ///   `_z_n_msg_request_needed_exts._ext_timeout_ms != 0`
    ///   predicate at `network.c`).
    ///
    /// The three Query-body exts emit in zenoh-pico's `_z_query_encode`
    /// order (value 0x03 → source_info 0x01 → attachment 0x05,
    /// `message.c:433-448`) regardless of `meta` field order.
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
            // R311mu (B5b-2b-2) — the RequestQueryBuilder assembly moved to
            // request_build::build_request_query_with_meta (the build/dispatch
            // split), so the seam-routed z_get path and this send_* wrapper
            // share one builder SSOT. This method keeps the dispatch half
            // (reliable, no batch flush — a Query carries no express window).
            let request =
                build_request_query_with_meta(rid, keyexpr_mapping_id, keyexpr_suffix, meta)?;
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
        // §5.21 routing-namespace — the reply EGRESS seam. Query replies flush
        // through this dedicated `dispatch_response` path, which bypasses BOTH
        // the `send_network_message` floor AND the unicast `Tp` send arm, so the
        // `Namespace` decorator must hook the local-origin reply HERE too (above
        // the forwarder floor) — otherwise a namespaced query's reply ships
        // un-prefixed and the querier's ingress strip drops it. zenoh decorates
        // `send_response` likewise (`net/routing/namespace.rs:106-109`).
        #[cfg(feature = "routing-namespace")]
        let mut response = response;
        #[cfg(feature = "routing-namespace")]
        R::with_mutex_mut(&self.namespace_egress, |slot| {
            if let Some(ns) = slot.as_ref() {
                let _ = crate::namespace::apply_egress_response(ns, &mut response);
            }
        });
        // F2 — this surface has no error channel; a transport-down
        // reject drops the emit exactly as the dead link would.
        let _ = self.dispatch_response(response, /*reliable=*/ true);
    }

    /// R284 — encode + dispatch a session-layer `Close` frame
    /// (`T_MID_CLOSE`, body carries the single-byte reason discriminator).
    /// R311y839 — `_Z_FLAG_T_CLOSE_S` is no longer implied by this method:
    /// it is derived per emit from the link set, so this frame is a
    /// whole-session close only when THIS link is the whole session. See
    /// `close_scope_is_session`.
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
            // R311y839 — the S flag is derived, not literal: this path tears down
            // ONE link, so it announces a whole-session close only when no other
            // link survives it. See `close_scope_is_session`.
            let bytes = encode_close(reason as u8, self.close_scope_is_session());
            // R311y205 (transport-multilink) — CLOSE is per-link (targets the
            // link this path is tearing down), not reliability-routed.
            self.send_wire_this_link(&bytes, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-close"))]
        let _ = reason;
    }

    /// R311kx — emit one KeepAlive transport message (the bare MID 0x04
    /// header, zenoh-pico `_zp_unicast_send_keep_alive` /
    /// `_z_t_msg_make_keep_alive`). The wire primitive behind the
    /// keepalive TX cadence ([`crate::drive::check_keepalive_deadline`]);
    /// routing through [`Self::send_wire`] re-stamps `last_outbound_at`,
    /// so each emit opens the next idle window by construction.
    ///
    /// R311jp — transport-message order parity (zenoh-pico tx.c
    /// `_z_transport_tx_send_t_msg_inner` flushes an active batch before
    /// encoding any t_msg): drain the open batch frame first so the
    /// KeepAlive never overtakes already-batched data frames on the wire
    /// — the exact future sender the [`Self::send_close_with_reason`]
    /// pre-drain comment named.
    ///
    /// Like the CLOSE primitive, this is wire-side and FSM-state-blind;
    /// the Established/teardown gating lives in the checker
    /// (`check_keepalive_deadline` consults `is_established` +
    /// `transport_available`). R311g signature-stability — the method
    /// exists across feature states; minus `transport-keepalive` the
    /// body silently no-ops (the FSM cannot enter the keepalive cadence
    /// there, per the `start_keepalive_worker` gate).
    pub fn send_keep_alive(&self) {
        #[cfg(feature = "transport-keepalive")]
        {
            #[cfg(feature = "transport-batching")]
            self.flush_open_batch();
            R::with_mutex_mut(&self.trace, |t| t.send_keep_alive += 1);
            let bytes = crate::handshake_encode::encode_keep_alive();
            // R311y205 (transport-multilink) — a keepalive is PER-LINK: it must
            // ride the physical link this drive loop monitors (so that link's
            // `last_outbound_at` is stamped and its peer's lease stays fresh), not
            // the reliability-routed data link. `send_wire_this_link` bypasses the
            // aggregation selector.
            self.send_wire_this_link(&bytes, Reliability::Reliable);
        }
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
    /// R311y435 — the gate is the UNION OF THE CALL SITES, not just
    /// `session-reconnect`. With `codec-declare` excluded its pullers go too,
    /// every caller compiles out, and this method became `never used` — which
    /// `-D warnings` turns into a build failure, not a warning. run-ci Layer F's
    /// minus-codec-declare lane hit exactly that and reported
    /// `SKIP (binary does not compile ...)`; a SKIP is green, so the lane
    /// measured nothing for as long as it existed.
    ///
    /// The union has TWO shapes and both are load-bearing. Four callers are
    /// undeclare paths gated on `declare-undeclare` AND their own `declare-*`
    /// (`send_undeclare_kexpr` / `_subscriber` / `_queryable`,
    /// `prune_token_declaration`). Two more — `prune_interest` and
    /// `prune_liveliness_get_interest` — are gated on `declare-interest` and
    /// `liveliness-get` ALONE, with no `declare-undeclare` conjunct. Writing the
    /// gate as one flat `all(declare-undeclare, any(...))` therefore deletes the
    /// method out from under those two, which is exactly what an earlier
    /// R311y435 revision did: it compiled everywhere the author checked and
    /// reddened Layer C1ax, a lane whose feature set reaches `prune_interest`
    /// without `declare-undeclare`. Enumerate the call sites mechanically before
    /// touching this.
    #[cfg(all(
        feature = "session-reconnect",
        any(
            all(
                feature = "declare-undeclare",
                any(
                    feature = "declare-keyexpr",
                    feature = "declare-subscriber",
                    feature = "declare-queryable",
                    feature = "declare-token"
                )
            ),
            feature = "declare-interest",
            feature = "liveliness-get"
        )
    ))]
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
    /// `inbound_opensyn_cookie`, `last_inbound_at`,
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
            // R311y211 — reconnect×multilink coherence guard (replaces the y205
            // `transport-multilink` × `session-reconnect` compile_error). This
            // makes `reset_for_reopen` a TOTAL function — safe to call in ANY
            // link-set state: when a survivor link is live the CORRECT action is
            // to PRESERVE it (skip the shared-core reset), because zeroing the
            // shared `rx_sn` / `outbound_frame_sn` would corrupt the survivor's
            // per-channel SN gate mid-stream (the exact hazard the XOR named).
            // It is not a bug to assert away: preserving a live survivor is the
            // right output for that input. Production reaches this skip arm only
            // as a safety net — a partial loss survives via `del_link` (SN
            // intact, no reset), and a whole-collapse is a fresh-core rebuild
            // (the accept loop drops the aggregate at `remaining == 0`, so the
            // next dial is a fresh primary); the single-link `ReconnectingSession`
            // supervisor runs on an EMPTY link set (`link_count == 0`), so the
            // guard is transparent to it. The coexistence unit test drives this
            // arm directly (`reset_for_reopen_preserves_shared_sn_while_a_link_
            // is_live`). The `live_link_count()` read is lock-atomic per call.
            #[cfg(feature = "transport-multilink")]
            if self.live_link_count() > 0 {
                return;
            }
            // F2 — close the data-send gate for the whole re-dial +
            // re-handshake window (release_link already closed it when the
            // FSM saw the loss; this also covers a reset without a prior
            // terminal). record_established_at re-opens it.
            R::with_mutex_mut(&self.link.transport_available, |g| *g = false);
            R::with_mutex_mut(&self.inbound_cookie, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_opensyn_cookie, |slot| *slot = None);
            R::with_mutex_mut(&self.link.last_inbound_at, |slot| *slot = None);
            R::with_mutex_mut(&self.link.established_at, |slot| *slot = None);
            // R311kw — the outbound stamp is per-transport: the replacement
            // link starts with no TX history (pico's fresh transport
            // initializes `_transmitted = 0`, unicast/transport.c:65).
            R::with_mutex_mut(&self.link.last_outbound_at, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_peer_zid, |slot| *slot = None);
            R::with_mutex_mut(&self.remote_peer_zid, |slot| *slot = None);
            R::with_mutex_mut(&self.peer_whatami, |slot| *slot = None);
            R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot = None);
            // R311ke — the RX SN gate is handshake-scoped: the reopen
            // handshake's OpenSyn/OpenAck re-seeds both channels.
            R::with_mutex_mut(&self.rx_sn, |s| *s = crate::sn::RxConduits::default());
            // §5.21 routing-namespace — the per-session INGRESS correlation is
            // handshake-scoped too: on reopen the remote re-handshakes with EMPTY
            // declaration tables + a RESTARTED id space, so a stale blocked-id
            // from before the reopen would swallow a re-declared entity's id-only
            // Undeclare* after it (the unicast twin of the multicast re-JOIN gap
            // the R311y107b session review found). Reset the correlation in place;
            // the namespace PREFIX is preserved (it is this node's config, not
            // peer state). No-op when no namespace is installed.
            #[cfg(feature = "routing-namespace")]
            R::with_mutex_mut(&self.namespace_ingress, |slot| {
                if let Some(ing) = slot.as_mut() {
                    ing.reset();
                }
            });
            R::with_mutex_mut(&self.tx_mutex, |batch| *batch = BatchTx::default());
            // SeqCst pairs with `next_outbound_frame_sn`'s fetch_add — the
            // reset must not reorder against a straggling in-flight mint.
            // R311y214 — resets BOTH reliability channels to the origin.
            self.outbound_frame_sn.reset(self.params.initial_sn);
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
                    #[cfg(feature = "routing-namespace")]
                    let declare = self
                        .namespace_egress_declare(declare)
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
                    #[cfg(feature = "routing-namespace")]
                    let declare = self
                        .namespace_egress_declare(declare)
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
                complete,
            } => {
                #[cfg(feature = "declare-queryable")]
                {
                    let mut declare =
                        build_declare_queryable(queryable_id, mapping_id, suffix.as_deref())
                            .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    // Re-stamp the completeness so a complete queryable replays
                    // complete, not silently incomplete (R311up).
                    set_declare_queryable_info(
                        &mut declare,
                        crate::queryable_info::QueryableInfo::local(complete),
                    );
                    #[cfg(feature = "routing-namespace")]
                    let declare = self
                        .namespace_egress_declare(declare)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                    self.dispatch_declare(declare, /*reliable=*/ true)
                        .map_err(|e| ReplayDeclarationsError::Declare(e.into()))?;
                }
                #[cfg(not(feature = "declare-queryable"))]
                let _ = (queryable_id, mapping_id, suffix, complete);
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
                    #[cfg(feature = "routing-namespace")]
                    let declare = self
                        .namespace_egress_declare(declare)
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
                    #[cfg(feature = "routing-namespace")]
                    let interest = self
                        .namespace_egress_interest(interest)
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
                    #[cfg(feature = "routing-namespace")]
                    let interest = self
                        .namespace_egress_interest(interest)
                        .map_err(|e| ReplayDeclarationsError::Interest(e.into()))?;
                    self.dispatch_interest(interest, /*reliable=*/ true)
                        .map_err(ReplayDeclarationsError::Interest)?;
                }
                #[cfg(not(feature = "declare-interest"))]
                let _ = (interest_id, mapping_id, suffix);
            }
            CachedDeclaration::MatchingInterest {
                interest_id,
                kinds,
                current,
                future,
                mapping_id,
                suffix,
            } => {
                #[cfg(feature = "declare-interest")]
                {
                    let interest = build_interest_kinds(
                        interest_id,
                        kinds,
                        current,
                        future,
                        mapping_id,
                        suffix.as_deref(),
                    )
                    .map_err(|e| ReplayDeclarationsError::Interest(e.into()))?;
                    #[cfg(feature = "routing-namespace")]
                    let interest = self
                        .namespace_egress_interest(interest)
                        .map_err(|e| ReplayDeclarationsError::Interest(e.into()))?;
                    self.dispatch_interest(interest, /*reliable=*/ true)
                        .map_err(ReplayDeclarationsError::Interest)?;
                }
                #[cfg(not(feature = "declare-interest"))]
                let _ = (interest_id, kinds, current, future, mapping_id, suffix);
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

    /// R311y205 (transport-multilink IMPL-2a) — the per-link [`LinkState`] this
    /// binding drives. The action methods that touch a per-link field
    /// (`release_link`, `record_established_at`) reach it through here, while
    /// the shared [`SessionCore`] fields (trace / staging slots) resolve through
    /// the handle's transparent `Deref`. This is the `{ core, link }` seam: at
    /// N=1 both live in the one shared handle; a later multilink slice makes the
    /// link per-binding (each of N drive loops carries its own `LinkState` over
    /// one shared `SessionCore`), an AP-only concern — the change is localized
    /// to this accessor's backing storage.
    #[inline]
    fn link(&self) -> &LinkState<R> {
        &self.inner.link
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
            // R3b — initiator usrpwd offer (Unit) staged into the InitSyn chain.
            #[cfg(feature = "session-extauth")]
            a.stage_auth_send(ExtChainRole::InitSyn, |d| d.open_init_syn());
            // R311y205 (transport-multilink IMPL-2b-ii) — the initiator's 0x4
            // Z_EXT_MULTILINK offer (its ephemeral pubkey), staged UN-wrapped into
            // the InitSyn chain iff a multilink dispatch is installed (max_links >
            // 1); no dispatch ⇒ no 0x4 ext (byte-identical handshake).
            #[cfg(feature = "transport-multilink")]
            a.stage_multilink_send(ExtChainRole::InitSyn, |d| d.open_init_syn());
            // transport-lowlatency / -compression / -shm — the initiator offers
            // each negotiated capability (a unit ext) in InitSyn iff this deploy
            // enabled it; `stage_capability` self-clears a stale ext when the
            // offer is off (zenoh `send_init_syn` emits the ext only when the
            // capability is set).
            #[cfg(feature = "transport-lowlatency")]
            a.stage_capability(
                ExtChainRole::InitSyn,
                a.is_lowlatency(),
                crate::extlowlatency::encode_lowlatency_ext,
            );
            // transport-qos — the initiator offers the QoS ext (id 0x1) in
            // InitSyn iff this deploy enabled it (zenoh `send_init_syn` emits
            // `ext_qos` only when the QoS transport is configured). Under
            // `session-extqos` the FORM follows the staged link metadata (unit
            // when none, z64 `QoSLink` when a band / reliability is declared) —
            // zenoh `State::to_exts`.
            #[cfg(all(feature = "transport-qos", not(feature = "session-extqos")))]
            a.stage_capability(
                ExtChainRole::InitSyn,
                a.is_qos(),
                crate::extqos::encode_qos_ext,
            );
            #[cfg(feature = "session-extqos")]
            a.stage_capability(ExtChainRole::InitSyn, a.is_qos(), || {
                crate::extqos::encode_qos_ext_for(&a.qos_link_metadata())
            });
            #[cfg(feature = "session-extcompression")]
            a.stage_capability(
                ExtChainRole::InitSyn,
                a.is_compression(),
                crate::extcompression::encode_compression_ext,
            );
            // session-extshm — the SHM establishment ext on InitSyn. With an
            // authenticator installed this is zenoh's real `init::ext::Shm`
            // CHALLENGE (a ZBuf carrying our segment id); without one it stays
            // the pre-R311y507 UNIT capability marker, so a deploy that never
            // installs one has a byte-identical handshake.
            // session-extshm — with an authenticator installed this is zenoh's
            // real `init::ext::Shm` CHALLENGE (a ZBuf carrying our segment id);
            // without one it stays the pre-R311y507 UNIT capability marker, so a
            // deploy that installs none has a byte-identical handshake.
            #[cfg(feature = "session-extshm")]
            if a.shm_auth_installed() {
                a.stage_shm_challenge(ExtChainRole::InitSyn, |a| a.shm_send_init_syn());
            } else {
                a.stage_capability(
                    ExtChainRole::InitSyn,
                    a.is_shm(),
                    crate::extshm::encode_shm_establishment_ext,
                );
            }
            let bytes = a
                .encode_init_with_role(
                    /*is_ack=*/ false,
                    /*cookie_override=*/ None,
                    ExtChainRole::InitSyn,
                )
                .expect("InitSyn zid/cookie are protocol-bounded (zid 1..=16, no cookie on Syn)");
            a.send_wire(&bytes, Reliability::Reliable, Priority::DEFAULT);
        }
    }

    fn send_open_syn(&mut self) {
        #[cfg(all(feature = "codec-open-body", feature = "session-unicast-open"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_open_syn += 1);
            // R3b — initiator usrpwd response (Zbuf {user, hmac}) staged into
            // the OpenSyn chain; HMACs over the nonce captured from InitAck.
            #[cfg(feature = "session-extauth")]
            a.stage_auth_send(ExtChainRole::OpenSyn, |d| d.open_open_syn());
            // R311y205 (transport-multilink IMPL-2b-ii) — the initiator's 0x4
            // OpenSyn challenge re-encryption, staged iff multilink is negotiated.
            #[cfg(feature = "transport-multilink")]
            a.stage_multilink_send(ExtChainRole::OpenSyn, |d| d.open_open_syn());
            // session-extshm (R311y507) — step 3b: answer the acceptor with the
            // challenge we read out of ITS segment. Nothing is staged when no
            // authenticator is installed (the pre-R311y507 Open chain) or when
            // the acceptor's segment could not be mapped, which is what makes
            // the acceptor's own check below fail closed.
            #[cfg(feature = "session-extshm")]
            a.stage_shm_challenge(ExtChainRole::OpenSyn, |a| a.shm_send_open_syn());
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
            a.send_wire(&bytes, Reliability::Reliable, Priority::DEFAULT);
        }
    }

    fn send_init_ack_with_cookie(&mut self) {
        // R311cd — session-unicast-accept gates the accept-side (Acceptor)
        // wire emit. cfg-off: no-op (initiator-only deploy cannot listen).
        #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_init_ack_with_cookie += 1);
            // R3b — responder usrpwd challenge (Z64 nonce) staged into the
            // InitAck chain. The AP accept path refreshes the nonce per
            // handshake before this fires (replay defense).
            #[cfg(feature = "session-extauth")]
            a.stage_auth_send(ExtChainRole::InitAck, |d| d.accept_init_ack());
            // R311y205 (transport-multilink IMPL-2b-ii) — the responder's 0x4
            // InitAck (its ephemeral pubkey + the encrypted challenge), staged iff
            // multilink is negotiated. The AP accept path refreshes the nonce
            // before this fires.
            #[cfg(feature = "transport-multilink")]
            a.stage_multilink_send(ExtChainRole::InitAck, |d| d.accept_init_ack());
            // transport-lowlatency / -compression / -shm — the acceptor REFLECTS
            // each capability in InitAck iff it is STILL offering after the
            // InitSyn `&=` merge (which ran at InitSyn arrival, before this send):
            // `stage_capability` reads the merged `is_X()`, so it pushes the ext
            // only when BOTH sides agreed (zenoh `recv_init_syn` ANDs, then
            // `send_init_ack` emits the ext only if the capability still holds).
            #[cfg(feature = "transport-lowlatency")]
            a.stage_capability(
                ExtChainRole::InitAck,
                a.is_lowlatency(),
                crate::extlowlatency::encode_lowlatency_ext,
            );
            // transport-qos — reflect the QoS ext in InitAck iff STILL offering
            // after the InitSyn `&=` merge (both sides agreed). Under
            // `session-extqos` the reflected metadata is the MERGED band (the
            // InitSyn containment ran before this send), so the initiator reads
            // back the band actually negotiated — zenoh `send_init_ack` calls
            // `to_exts` on the post-`recv_init_syn` state.
            #[cfg(all(feature = "transport-qos", not(feature = "session-extqos")))]
            a.stage_capability(
                ExtChainRole::InitAck,
                a.is_qos(),
                crate::extqos::encode_qos_ext,
            );
            #[cfg(feature = "session-extqos")]
            a.stage_capability(ExtChainRole::InitAck, a.is_qos(), || {
                crate::extqos::encode_qos_ext_for(&a.qos_link_metadata())
            });
            #[cfg(feature = "session-extcompression")]
            a.stage_capability(
                ExtChainRole::InitAck,
                a.is_compression(),
                crate::extcompression::encode_compression_ext,
            );
            // session-extshm — the ACCEPTOR's answer: the initiator's own
            // challenge echoed back beside our segment id (the InitSyn demux ran
            // before this send, so the echo is already known), else the UNIT
            // reflect when no authenticator is installed.
            // session-extshm — the ACCEPTOR's answer: the initiator's own
            // challenge echoed back beside our segment id (the InitSyn demux ran
            // before this send, so the echo is already known), else the UNIT
            // reflect when no authenticator is installed.
            #[cfg(feature = "session-extshm")]
            if a.shm_auth_installed() {
                a.stage_shm_challenge(ExtChainRole::InitAck, |a| a.shm_send_init_ack());
            } else {
                a.stage_capability(
                    ExtChainRole::InitAck,
                    a.is_shm(),
                    crate::extshm::encode_shm_establishment_ext,
                );
            }
            // R311y838 — the `0x7` PATCH answer, lowered to the NEGOTIATED
            // level. Staged here with the capability reflections above and for
            // the same reason: everything the acceptor answers is derived from
            // the post-InitSyn merge at send time, never from the value the
            // slot was constructed with. The patch was the one that still was
            // — `min()` had run and only the wire did not know.
            a.stage_negotiated_patch(ExtChainRole::InitAck);
            // R86 — Accepting-side cookie binding per RFC §5.M
            // anti-amplification. If the inbound InitSyn already arrived
            // (`inbound_peer_zid` slot populated by `handle_inbound`),
            // mint a fresh cookie via HMAC-SHA256(cookie_signing_key,
            // nonce || peer_zid)[..16] and pass it as the encode override; the
            // cookie is now bound to the specific peer's claimed
            // identity, not a deploy-static value. Falls back to
            // `params.cookie` verbatim if no peer_zid has been observed.
            // Cookie minted out of the slot first — `encode_init_with_role`
            // re-acquires `inbound_peer_init_caps` + the ext-chain mutex, so
            // the `inbound_peer_zid` guard must drop before the encode call
            // (non-reentrant per-profile mutex; 2b-① reentrancy discipline).
            //
            // R311y813 — the nonce is the second REQUIRED input, read from its
            // own slot in its own scope (sequential, never nested: the mutex is
            // non-reentrant on the MCU profile). Absent nonce mints NO HMAC
            // cookie: an acceptor with no per-handshake binding available must
            // not silently emit the replayable derivation, and `cookie_valid`
            // denies for the same reason, so the two halves fail together
            // rather than one of them degrading.
            let nonce: Option<u64> = R::with_mutex_mut(&a.cookie_nonce, |slot| *slot);
            let peer_zid: Option<Vec<u8>> =
                R::with_mutex_mut(&a.inbound_peer_zid, |slot| slot.clone());
            let cookie_hmac: Option<Vec<u8>> = match (peer_zid, nonce) {
                (Some(zid), Some(n)) => Some(generate_cookie_hmac_sha256(
                    &a.params.cookie_signing_key,
                    &zid,
                    n,
                )),
                _ => None,
            };
            let bytes = a
                .encode_init_with_role(
                    /*is_ack=*/ true,
                    cookie_hmac.as_deref(),
                    ExtChainRole::InitAck,
                )
                .expect("InitAck cookie is HMAC-SHA256[..16] (16 bytes, within codec cap)");
            a.send_wire(&bytes, Reliability::Reliable, Priority::DEFAULT);
        }
    }

    fn send_open_ack(&mut self) {
        #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
        {
            let a = &self.inner;
            R::with_mutex_mut(&a.trace, |t| t.send_open_ack += 1);
            // R3b — responder usrpwd accept (Unit) staged into the OpenAck
            // chain (reached only after accept_recv_open_syn verified the HMAC).
            #[cfg(feature = "session-extauth")]
            a.stage_auth_send(ExtChainRole::OpenAck, |d| d.accept_open_ack());
            // R311y205 (transport-multilink IMPL-2b-ii) — the responder's 0x4
            // OpenAck Unit confirmation, staged iff multilink is negotiated.
            #[cfg(feature = "transport-multilink")]
            a.stage_multilink_send(ExtChainRole::OpenAck, |d| d.accept_open_ack());
            // session-extshm (R311y507) — step 4b: the acceptor's confirmation,
            // the literal 1, emitted only once its own check passed (the OpenSyn
            // demux ran before this send).
            #[cfg(feature = "session-extshm")]
            a.stage_shm_challenge(ExtChainRole::OpenAck, |a| a.shm_send_open_ack());
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
            a.send_wire(&bytes, Reliability::Reliable, Priority::DEFAULT);
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
            // R311y205 (transport-multilink) — the FSM `Closing` close rides the
            // link whose drive loop reached Closing, and is not reliability-routed.
            // R311y839 — and its SCOPE follows that: the sibling `release_link`
            // action removes only this link, so the announcement says session only
            // when this link was the session. See `close_scope_is_session`.
            let bytes = encode_close(reason, a.close_scope_is_session());
            a.send_wire_this_link(&bytes, Reliability::Reliable);
        }
    }

    fn release_link(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |t| t.release_link += 1);
        // F2 — the link is going away: close the data-send gate so a
        // straggling send rejects typed instead of racing the teardown.
        // R311y205 (IMPL-2a) — the gate is per-link (`self.link()`).
        R::with_mutex_mut(&self.link().transport_available, |g| *g = false);
        // R311y205 (slice-1 MF-C) — remove THIS link's `LinkState` from the
        // shared aggregation set so `link_count()` reflects the LIVE topology
        // and a `max_links` slot recovers after a link dies (the join room check
        // reads `link_count()`, which would otherwise keep counting the dead
        // link forever). A no-op for a single-link (empty-set) session — releasing
        // the sole link stays the existing teardown path, N=1 behavior unchanged.
        #[cfg(feature = "transport-multilink")]
        a.del_link(&a.link);
        a.link_driver().close_blocking();
    }

    fn enable_rx_tx_regions(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |t| t.enable_rx_tx_regions += 1);
    }

    fn record_established_at(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |t| t.record_established_at += 1);
        // R294 — `a.clock.now_monotonic_ms()` reads the shared monotonic
        // clock (same epoch as last_inbound_at +
        // drive_session_until_terminal) so the lease comparator's u64
        // subtract stays on one scale. Read outside the slot closure.
        let now = a.clock.now_monotonic_ms();
        // R311y205 (IMPL-2a) — the established stamp + F2 gate are per-link.
        R::with_mutex_mut(&self.link().established_at, |slot| *slot = Some(now));
        // F2 — Established (re-)entry re-opens the data-send gate (the
        // supervisor replays cached declarations right after this fires).
        R::with_mutex_mut(&self.link().transport_available, |g| *g = true);
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
    /// HMAC-SHA256(cookie_signing_key, nonce || peer_zid)[..16] on InitAck
    /// send (`send_init_ack_with_cookie`). The Initiator echoes that cookie
    /// verbatim on OpenSyn; here we re-compute the expected HMAC and
    /// compare against the captured inbound OpenSyn cookie
    /// (`inbound_opensyn_cookie` slot). Mismatch -> `false` -> the
    /// dispatcher drops the `OpenSynReceived` event so the FSM stays at
    /// SentInitAck instead of advancing to SentOpenAck.
    ///
    /// R311y813 — the expected value is re-derived from the SAME
    /// `cookie_nonce` slot the mint read, which is what makes
    /// this a check on THIS handshake rather than on the deploy: zenoh states
    /// the same rule as `input.cookie_nonce != cookie.nonce -> Unknown cookie`
    /// (`unicast/establishment/accept.rs:500-503`). An absent nonce denies,
    /// like every other absent input here — an acceptor that cannot tell which
    /// handshake it is in must not admit one.
    ///
    /// The counter increments on every invocation so tests can assert the
    /// guard actually fired (vs. R57's `bind_bool` placeholder which never
    /// executed any dynamic check).
    pub fn cookie_valid(&self) -> bool {
        R::with_mutex_mut(&self.trace, |t| t.cookie_valid_check += 1);

        // Defensive: any missing material rejects. A well-formed handshake
        // populates every slot before this guard runs. Each slot is read in
        // its own with_mutex_mut (sequential, no nesting).
        let peer_zid = match R::with_mutex_mut(&self.inbound_peer_zid, |s| s.clone()) {
            Some(z) => z,
            None => return false,
        };
        let echoed = match R::with_mutex_mut(&self.inbound_opensyn_cookie, |s| s.clone()) {
            Some(c) => c,
            None => return false,
        };
        let nonce = match R::with_mutex_mut(&self.cookie_nonce, |s| *s) {
            Some(n) => n,
            None => return false,
        };
        let expected =
            generate_cookie_hmac_sha256(&self.params.cookie_signing_key, &peer_zid, nonce);
        // Byte-equality compare. Constant-time compare is overkill for a
        // single-peer test fixture path; if the HMAC verdict ever drives a
        // security-critical timing oracle on prod hardware, swap to
        // `subtle::ConstantTimeEq` here.
        echoed == expected
    }
}
