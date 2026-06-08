// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Session-FSM ↔ LinkDriver glue with real codec-driven wire bytes.
//!
//! R57 entry. The R54 baseline used literal placeholder bytes
//! (`b"INIT_SYN"`, `b"OPEN_SYN"`, …) for the 7 outbound link calls;
//! the placeholder pattern was an explicit hack flagged in R56's
//! self-review. R57 swaps every outbound to the real wz-codecs
//! encode path:
//!
//! - `send_init_syn` / `send_init_ack_with_cookie` build a
//!   `wz_codecs::init_body::InitBody` and prepend the
//!   `_Z_MID_T_INIT` transport-message header byte plus the
//!   parent.S / parent.A flag pattern from
//!   `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h`.
//! - `send_open_syn` / `send_open_ack` build a
//!   `wz_codecs::open_body::OpenBody` with the lease + initial_sn
//!   carrier and the `_Z_FLAG_T_OPEN_A` / `_Z_FLAG_T_OPEN_T`
//!   discriminators.
//! - `send_close_frame_with_reason` builds a
//!   `wz_codecs::close::Close` (single reason byte) and prepends
//!   `_Z_MID_T_CLOSE | _Z_FLAG_T_CLOSE_S` for a graceful session
//!   close (vs. link-only close).
//!
//! Production-correctness sourcing. The codec output is verified
//! byte-identical against zenoh-pico's own `_z_init_encode` /
//! `_z_open_encode` / `_z_close_encode` by the Layer 3 wire-interop
//! tests (`crates/wz-integration-tests/tests/layer3_{init_body,open_body,close}.rs`).
//! Re-using those codecs here therefore inherits the same byte-equiv
//! guarantee — `dispatch_script("send_init_syn")` now produces the
//! exact bytes a zenoh-pico peer would generate from the equivalent
//! `_z_t_msg_init_t` input.
//!
//! Field values flow through `SessionInitParams`. A production
//! caller supplies the per-deploy zid / whatami / version /
//! seq_num_res / req_id_res / batch_size / lease / initial_sn from
//! `deploy.yaml` (the source of truth per
//! `docs/wire-spec-subset.md` §4.4 + ARCHITECTURE.md §3.5);
//! integration tests pass fixed values so the wire bytes are
//! reproducible.
//!
//! Cookie material is supplied by the caller. R57 ships the cookie
//! handling as a "caller-owned bytes" interface — the
//! `SessionInitParams::cookie` field carries whatever the
//! `Accepting` side wants to sign and the `Established`-side
//! initiator echoes. The HMAC-SHA256 generation per RFC §5.M is
//! the consumer's responsibility (production callers compose
//! `sce_intrinsics_runtime::hmac_sha256` with a deploy-supplied
//! secret); the integration test uses a fixed 8-byte cookie so
//! the assertion against zenoh-pico's reference is deterministic.

// R311di-pre-a — HashMap + AtomicU64 imports route through no_std-compatible
// crates so the eventual extraction of session_glue.rs to wz-session-core
// (no_std + alloc) reuses the same dep surface. hashbrown is the upstream
// std::collections::HashMap implementation (std re-exports it); portable-
// atomic forwards to core::sync::atomic on AP and falls back via critical-
// section on MCU (wz-runtime-lwip pulls the same crate per R311bb).
//
// R311di-pre-d — Mutex direct ref routes through wz_runtime_tokio::sync::Mutex
// (R311y alias = `pub type Mutex<T> = std::sync::Mutex<T>;`), uniformising
// the migration path with the rest of the wz-runtime-tokio src tree. The
// eventual SessionState<R: Runtime> reparam at R311di proper will lift these
// field types to R::Mutex<T> via the GAT (declared on the Runtime trait via
// R311ar). Arc stays on std::sync::Arc for now — std::sync::Arc and
// alloc::sync::Arc are the same type, and the zero-cost relabel is deferred
// to R311di proper where the file moves to wz-session-core (no_std + alloc)
// and the import line becomes `use alloc::sync::Arc;`.
use std::sync::Arc;

use hashbrown::HashMap;
use portable_atomic::{AtomicU64, Ordering};

use crate::sync::Mutex;

// R311ei — the HMAC-SHA256 cookie primitive + SigningKey newtype moved
// to wz-session-core::signing_key; only the OS-entropy constructor stays
// here (as a free fn), so this crate keeps just the `Zeroizing` wrapper +
// `getrandom` deps (hmac / sha2 moved out with the primitive).
use zeroize::Zeroizing;

use sce_rust_runtime::Engine;

// R311il — the engine-free session FSM's generated host-action trait.
// Aliased so the trait name does not collide with host-side identifiers;
// the `SessionActionsBinding` newtype below carries the impl (the orphan
// rule forbids impl'ing the foreign trait on `Arc<SessionLinkActions>`
// directly). The state/event enums + `SessionFsmUnicastPolicy<A>` are
// reached via the `crate::session_fsm_unicast` re-export (lib.rs) of the
// runtime-agnostic `wz_session_core::session_fsm_unicast` codegen.
use crate::session_fsm_unicast::{
    SessionFsmUnicastActions as SessionFsmUnicastActionsTrait, SessionFsmUnicastPolicy,
};
use wz_session_core::session_timeouts::HandshakeDeadlineTracker;
// Re-exported: `drive_session_until_terminal` takes `&SessionTimeouts`, so
// consumers that drive a session (wz-e2e-harness, wz-ap-demo) reach the
// type through this crate's session API without a direct wz-session-core dep.
pub use wz_session_core::session_timeouts::SessionTimeouts;

// CodecError is consumed by the remaining outbound encoders in this
// file (encode_init_with_role / encode_open_with_role / the build_*
// helpers). The low-level encode_init / encode_open / encode_close
// frame builders (+ VecSink / SceSink / encode_frame_envelope) moved
// to wz-session-core (handshake_encode + frame_encode) so the tokio
// AP and lwIP MCU profiles share one outbound encode SSOT.
use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_zint::ExtZint;

// SCE owned-view absorb — the lifetime-free `*Owned` mirrors that the
// runtime stores / builds / dispatches. Decode reads a borrowed
// `Foo<'a>` then `.into_owned()`; encode builds a `*Owned` then
// `.as_borrowed()` / `.try_as_borrowed()` at the sink boundary. The
// borrowed imports above stay for the `::decode` calls and the
// `MAX_ENCODED_BYTES` capacity hints.
// Decl*Owned / DeclareOwnedVariant / Undecl* / DeclFinal / WireexprNonlocal
// moved out with the DECLARE builders (wz-session-core::declare_build).
// DeclareOwned stays — but its only remaining lib use is the `send_declare`
// param (gated `liveliness-token`, the sole feature that stages a ready
// `DeclareOwned` through the sink), so the import narrows to that feature;
// the variant is now only named by the declare coverage tests (imported in
// the test module).
#[cfg(feature = "liveliness-token")]
use wz_codecs::declare::DeclareOwned;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
// ExtZbufOwned / MsgPutOwned / MsgDelOwned / PushOwned(+Variant) moved
// out with the Push builders (wz-session-core::push_build); the only
// remaining session_glue use of PushOwnedVariant is the test module, so
// it is imported there.
// InterestOwned / InterestBodyOwned / ResponseFinalOwned / Wireexpr* moved
// out with the interest + response-final builders (wz-session-core
// interest_build / response_final_build); the Wireexpr types + wire_const
// are still named by the builder coverage tests, so they import in the test
// module.
#[cfg(feature = "codec-response")]
use wz_codecs::response::ResponseOwned;
// `SessionRuntime` (imported below) extends `wz_runtime_core::Runtime`, so
// the `R::new_mutex` / `R::with_mutex_mut` calls in the generic
// `SessionLinkActions` impls resolve through the supertrait — no direct
// `Runtime` import is needed once the concrete `new` (Stage 2c) delegates
// to `new_generic` and stops calling `TokioRuntime::new_mutex` directly.
use wz_runtime_core::TimeSource;
// R311dz-pre — `SessionLinkActions` impls `ResponseSink` (below) so the
// application-layer observer can drain replies through the IoC trait
// rather than this concrete type.
use wz_session_core::response_sink::ResponseSink;
// R311ho — single-source borrowed reply builders; the AP sink derives the
// owned form via `Declare::into_owned`.
#[cfg(feature = "liveliness-token")]
use wz_session_core::declare::local_token::{build_final_reply, build_token_reply};

use crate::runtime_impl::{TokioRuntime, TokioTime};

// R309 — `check_outbound_keyexpr_pico_safe` is consumed only by
// `send_declare_keyexpr` / `send_declare_subscriber` /
// `send_declare_queryable` / `send_declare_token`, each of which
// gates on its own declare-* feature. Gate the import on the union
// so a no-default-features build (or any subset that disables all
// four) does not surface as an unused-imports lint error.
#[cfg(any(
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
))]
use crate::keyexpr_canon::check_outbound_keyexpr_pico_safe;

use crate::{LinkDriver, LinkEvent, Reliability, TxFrame};

// R311ei — SigningKey + SigningKeyTooShort + the HMAC-SHA256 cookie
// primitive generate_cookie_hmac_sha256 moved to
// wz-session-core::signing_key (runtime-agnostic crypto/value
// construction). Re-exported so the crate::session_glue::{SigningKey,
// SigningKeyTooShort, generate_cookie_hmac_sha256} callsites
// (SessionInitParams.cookie_signing_key, the Accepting-side InitAck
// cookie path, wz-ap-demo, and the session_fsm_* tests) resolve
// unchanged across the reorg.
pub use wz_session_core::signing_key::{
    generate_cookie_hmac_sha256, SigningKey, SigningKeyTooShort,
};

/// R69 / R311ei — construct a `SigningKey` from OS-backed cryptographic
/// entropy. Pulls 32 bytes from `getrandom::getrandom` (Linux
/// `getrandom(2)` fallback to `/dev/urandom`; macOS `getentropy`) — the
/// RustCrypto-ecosystem standard for AP-side secret-key material. Length
/// is fixed at 32 so the result always satisfies the `>= 32` invariant
/// the [`SigningKey::new`] constructor enforces.
///
/// The fallible surface returns `getrandom::Error` so a deploy that runs
/// in a sandbox without entropy access (e.g. container without
/// `/dev/urandom`) sees a typed error rather than a panic.
///
/// **Why a free fn, not `SigningKey::new_random`.** `getrandom` has no
/// bare-metal backend (thumbv6m-none-eabi et al.), so it cannot live in
/// the MCU-cross-compiled `wz-session-core` crate where `SigningKey` now
/// lives. The orphan rule forbids defining an inherent method on
/// `SigningKey` from this crate, so the former `new_random` inherent
/// method is demoted to this free function (R311ei). The MCU sibling
/// sources entropy via `sce_intrinsics_runtime::rng` per the §5.I
/// intrinsics tier instead.
pub fn signing_key_from_os_entropy() -> Result<SigningKey, getrandom::Error> {
    let mut buf = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(buf.as_mut_slice())?;
    // SigningKey::new re-wraps the bytes in its own Zeroizing; 32 bytes
    // always satisfies the >= 32 length contract, so the construct is
    // infallible here. std::mem::take leaves the source wrapper zeroed.
    Ok(SigningKey::new(std::mem::take(&mut *buf))
        .expect("32-byte entropy buffer always satisfies the >= 32 length contract"))
}

// R311dl — the wire_const re-import moved into the test module: after the
// outbound builders (push/declare/interest/handshake) hoisted to
// wz-session-core, the only remaining session_glue references to
// wire_const::* are the builder coverage tests.

// R311ej — SessionInitParams moved to wz-session-core::session_init_params
// (pure owned value type, no codec coupling; unblocked by R311ei moving
// SigningKey there). Re-exported so the crate::session_glue::SessionInitParams
// callsites (SessionLinkActions::params field, session.rs, wz-ap-demo,
// the fixture_session_init_params test-support builder) resolve
// unchanged. DP3 leaf.
pub use wz_session_core::session_init_params::SessionInitParams;

// R311ed — CloseReason moved to wz-session-core::close_reason (a
// runtime-agnostic byte-valued discriminator, sibling of Reliability /
// qos). Re-exported so the `crate::session_glue::CloseReason` callsites
// (SessionLinkActions::send_close_with_reason, the Close codec tests,
// and wz-ap-demo::teardown) resolve unchanged. The wire encode
// (`reason as u8`) stays below next to the Close codec path. DP3 leaf.
pub use wz_session_core::close_reason::CloseReason;

// R311ef — ActionTrace moved to wz-session-core::action_trace (a pure
// no_std/no_alloc counter bag, sibling of qos / close_reason). The live
// `trace: R::Mutex<ActionTrace>` slot + the `trace_snapshot` accessor
// stay below (runtime-bound). Re-exported so the
// `crate::session_glue::ActionTrace` callsites resolve unchanged. DP3 leaf.
pub use wz_session_core::action_trace::ActionTrace;

// BoxedLinkDriver trait moved to wz-session-core::link (shared link-write
// seam for the tokio AP + lwIP MCU profiles). Re-exported so the
// TokioLinkDriverAdapter / UdpWriteDriver / TcpWriteDriver impls + external
// callers keep naming crate::session_glue::BoxedLinkDriver.
pub use wz_session_core::link::BoxedLinkDriver;
// Stage 2b — the runtime-tier extension that owns `R::LinkSink` (the
// per-profile storage of the link write seam). `SessionLinkActions<R,
// T>` bounds `R: SessionRuntime` so its `driver` field is `R::LinkSink`
// instead of a hard-coded `Arc<dyn BoxedLinkDriver>`; the generic
// action methods reach the seam through the inherent `Self::link_driver`
// accessor (which forwards to `R::link_driver`).
use wz_session_core::link::SessionRuntime;

/// Tokio multi-thread runtime adapter for a `LinkDriver`
/// implementation.
pub struct TokioLinkDriverAdapter<D: LinkDriver + Send + 'static> {
    driver: Mutex<D>,
    handle: tokio::runtime::Handle,
}

impl<D: LinkDriver + Send + 'static> TokioLinkDriverAdapter<D> {
    /// Wrap a driver + Tokio handle. The handle MUST point at a
    /// multi-thread runtime; using a current-thread runtime here
    /// would deadlock on the first script-action dispatch because
    /// `block_on` from inside the runtime's own worker thread
    /// requires another worker to make progress. The constructor
    /// panics fast on a current-thread runtime so the misuse is
    /// caught at construction site, not at the first dispatch.
    pub fn new(driver: D, handle: tokio::runtime::Handle) -> Self {
        assert_eq!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "TokioLinkDriverAdapter requires a multi-thread runtime; \
             block_on on a current-thread runtime worker would deadlock"
        );
        Self {
            driver: Mutex::new(driver),
            handle,
        }
    }
}

impl<D: LinkDriver + Send + 'static> BoxedLinkDriver for TokioLinkDriverAdapter<D> {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        let frame = TxFrame { bytes };
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.send(&frame, reliability));
    }

    fn open_blocking(&self) {
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.open());
    }

    fn close_blocking(&self) {
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.close());
    }
}

// R311ee — ExtChainRole moved to wz-session-core::ext_chain_role.
pub use wz_session_core::ext_chain_role::ExtChainRole;

// R311di-10 — SendDeclareError moved to wz-session-core::send_declare_error.
pub use wz_session_core::send_declare_error::SendDeclareError;

// W3 — shared typed reject for the non-DECLARE outbound wire-emit
// actions (push / request / interest).
pub use wz_session_core::send_wire_error::SendWireError;

/// Bundle of state shared across the 17 native script functions.
pub struct SessionLinkActions<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
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
    /// [`SessionLinkActions::new`] and
    /// [`drive_session_until_terminal`]'s `clock` parameter (R263
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
    /// each subsequent Frame uses the next integer modulo the
    /// SN resolution window (`params.seq_num_res` → 8/16/32/
    /// 64-bit per Zenoh RFC §5.O). For the AP MVP path the
    /// `AtomicU64` counter does not enforce explicit modulo —
    /// a session that emits more than `1 << sn_bits` frames
    /// will rely on the natural u64 wrap, which exceeds every
    /// configurable SN window. Production code with long-running
    /// sessions or strict SN-window validation needs the
    /// explicit modulo at `next_outbound_frame_sn` (R121e
    /// carry — surface when a measurement justifies it).
    pub outbound_frame_sn: AtomicU64,
    /// R234 — outbound keyexpr mapping table. Mirrors zenoh-pico's
    /// `_z_session_t._local_resources` slot: every time
    /// [`Self::send_declare_keyexpr`] emits a `Declare(DeclKexpr)`
    /// the (mapping_id, suffix) pair is recorded here so a later
    /// [`crate::session::Session::publish_aliased_auto`] (or the
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
    /// R239 — monotonic outbound `Request.request_id` allocator.
    /// Mirrors zenoh-pico's `_z_session_t._query_id` slot
    /// (`vendor/zenoh-pico/src/session/query.c:99` —
    /// `_z_zint_t qid = zn->_query_id++` post-increment from 0).
    /// Each [`crate::session::Session::query`] call (and any future
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
    /// [`crate::session::Session::declare_token`] /
    /// [`crate::session::Session::declare_token_aliased`] call reserves
    /// the next id through [`Self::alloc_next_token_id`] so the
    /// [`crate::session::LivelinessToken`] RAII handle holds the same
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
    /// [`crate::session::LivelinessSubscriber`] RAII handle so the
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

// R311eg — PeerInitCaps + its from_init_syn decoder moved to
// wz-session-core::peer_init_caps (pure no_std/no_alloc; the
// transport-batching gate moved with the decoder). Re-exported so the
// `crate::session_glue::PeerInitCaps` callsites (the
// inbound_peer_init_caps slot, the InitSyn dispatch arm, and the
// session_fsm_accepting_path tests) resolve unchanged. The live
// `R::Mutex<Option<PeerInitCaps>>` slot stays below (runtime-bound). DP3 leaf.
pub use wz_session_core::peer_init_caps::PeerInitCaps;

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

// R311di-pre-f2 / Stage 2c — the concrete `::new` constructor sits on the
// TokioRuntime-concrete impl block so callers (`SessionLinkActions::new(
// driver, params, clock)`) keep inferring `R = TokioRuntime` without a
// turbofish; it is now a thin wrapper that delegates to the generic
// `new_generic<R: SessionRuntime, T>` factory (Stage 2c — composes the same
// body via `R::new_mutex`). Generic-R callers (the future MCU profile,
// post-wz-session-core extraction) call `new_generic` directly; today the
// AP profile is still the sole live caller, so the concrete wrapper is the
// textbook backward-compat shape (mirrors the `TokioSession` alias /
// `impl<T> Session<TokioRuntime, T>` pattern from the R311cw-dh cascade —
// both establish a concrete-bound AP entry point on top of a generic struct).
// R311dz-pre — bridge the observer's generic reply drain to the concrete
// tokio actions. The inherent `send_response` / `send_response_final`
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
}

/// Generic-`R` constructor (Stage 2c) — the runtime-agnostic body of the
/// concrete [`SessionLinkActions::new`] below. Every mutex slot is staged
/// via `R::new_mutex` so the lwIP MCU profile composes the same bundle
/// against `critical_section::Mutex`; the tokio `new` is a thin
/// `R = TokioRuntime` wrapper. The `None::<…>` / `Vec::<…>::new()` /
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
    pub fn new_generic(driver: R::LinkSink, params: SessionInitParams, clock: T) -> Arc<Self> {
        // R121e — seed the outbound Frame SN with `params.initial_sn`
        // so the first emitted Frame matches the value announced in
        // the OpenSyn/OpenAck body. The peer enforces this start
        // value via its reliable-channel window tracking
        // (zenoh-pico unicast/transport.c:182-194).
        let initial_frame_sn = params.initial_sn;
        Arc::new(Self {
            driver,
            params,
            trace: R::new_mutex(ActionTrace::default()),
            inbound_cookie: R::new_mutex(None::<Vec<u8>>),
            last_inbound_keepalive_at: R::new_mutex(None::<u64>),
            established_at: R::new_mutex(None::<u64>),
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
            outbound_mappings: R::new_mutex(HashMap::<u64, String>::new()),
            next_outbound_request_id: AtomicU64::new(0),
            next_outbound_token_id: AtomicU64::new(0),
            next_outbound_interest_id: AtomicU64::new(0),
        })
    }
}

impl<T: TimeSource> SessionLinkActions<TokioRuntime, T> {
    /// Construct a session action bundle for one logical FSM instance.
    /// The `params` are captured by value; production callers
    /// supplying per-deploy values stage them once at session
    /// construction. `clock` is the shared monotonic clock (R263 +
    /// R294) consumed by [`Self::handle_inbound`] and the
    /// `record_established_at` Lua action; production callers pass
    /// the same `TokioTime` that [`drive_session_until_terminal`]
    /// receives so the lease comparator's `now_ms` and the recorded
    /// `keepalive_ms` / `established_ms` share an epoch.
    ///
    /// Thin `R = TokioRuntime` wrapper over [`Self::new_generic`]; the
    /// struct's `<R = TokioRuntime>` default keeps every existing
    /// `SessionLinkActions::new(driver, params, clock)` call site
    /// turbofish-free.
    pub fn new(
        driver: Arc<dyn BoxedLinkDriver + Send + Sync>,
        params: SessionInitParams,
        clock: T,
    ) -> Arc<Self> {
        Self::new_generic(driver, params, clock)
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
                    *slot = Some(PeerInitCaps::from_init_syn(body.sn_res, body.batch_size));
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

    /// R121e — outbound Frame sequence-number generator. Returns
    /// the SN to use for the next outbound Frame and advances the
    /// internal counter by one.
    ///
    /// The first call returns `params.initial_sn` (seeded by
    /// [`SessionLinkActions::new`]); subsequent calls return
    /// successive integers. The natural u64 wrap exceeds every
    /// configurable SN resolution window
    /// (`params.seq_num_res = 0..=3` → 8/16/32/64-bit per Zenoh
    /// RFC §5.O), so a session that emits fewer than `1 << 32`
    /// frames never reaches the boundary. Production code with
    /// long-running sessions OR strict SN-window validation must
    /// apply the explicit modulo here once a measurement justifies
    /// the cost (R121e carry — no consumer surfaces it yet).
    ///
    /// Atomic `SeqCst` is the textbook default for cross-task
    /// monotonicity. The hot path is one outbound Frame per
    /// application-layer batch — the atomic cost is in the noise
    /// vs. the codec encode + TCP write below it.
    pub fn next_outbound_frame_sn(&self) -> u64 {
        self.outbound_frame_sn.fetch_add(1, Ordering::SeqCst)
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
    /// the [`crate::session::LivelinessToken`] RAII handle so the
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
    /// [`crate::session::LivelinessSubscriber`] RAII handle so the
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.link_driver().send_blocking(&wire, reliability);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.link_driver()
            .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
            // R234 — drop the (mapping_id, suffix) pair so subsequent
            // `publish_aliased_auto` calls return `None` on this id and
            // the caller knows the alias is stale. Idempotent: removing
            // an absent id is a no-op. Mirrors zenoh-pico's
            // `_z_unregister_resource` invoked on the local-side
            // undeclare emit path.
            R::with_mutex_mut(&self.outbound_mappings, |table| {
                table.remove(&mapping_id);
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
    #[allow(dead_code)]
    fn reconstruct_outbound_keyexpr(
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
    /// either feature is off. Enables [`crate::session::LivelinessToken`]
    /// `Drop` to call this unconditionally without a matching cfg-gate
    /// at the call site (R311o type-ungating cascade prerequisite).
    pub fn send_undeclare_token(&self, token_id: u64) {
        #[cfg(all(feature = "declare-token", feature = "declare-undeclare"))]
        {
            let declare = build_undeclare_token(token_id);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_interest(sn, interest, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_interest(sn, interest, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_interest(sn, interest, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_request(sn, request, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_request(sn, request, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
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
            let sn = self.next_outbound_frame_sn();
            let wire =
                encode_frame_with_response_final(sn, response_final, /*reliable=*/ true);
            self.link_driver()
                .send_blocking(&wire, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-response-final"))]
        let _ = request_id;
    }

    /// R121j-5c-e2e — encode + dispatch an already-constructed
    /// [`Response`] on the outbound link. The Response is typically
    /// built upstream by [`ResponseReplyBuilder`] /
    /// [`ResponseErrBuilder`] (or composed from a
    /// [`crate::query::QueryReply::into_response`] call drained out of
    /// [`crate::query::QueryableRegistry::dispatch_messages`]).
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
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_response(sn, response, /*reliable=*/ true);
        self.link_driver()
            .send_blocking(&wire, Reliability::Reliable);
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
            R::with_mutex_mut(&self.trace, |t| t.send_close_frame_with_reason += 1);
            let bytes = encode_close(reason as u8);
            self.link_driver()
                .send_blocking(&bytes, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-close"))]
        let _ = reason;
    }
}

/// R311il — thin newtype that carries the generated
/// [`SessionFsmUnicastActionsTrait`] impl for the
/// [`crate::session_fsm_unicast::SessionFsmUnicastPolicy`] to own by
/// value. Wraps a clone of the caller's `Arc<`[`SessionLinkActions`]`>`
/// so the 18 native actions mutate the same shared state (trace / staging
/// slots / link driver) the caller reads back; the orphan rule forbids
/// impl'ing the foreign trait on `Arc<SessionLinkActions>` directly, so
/// the local newtype carries the impl.
///
/// Engine-free successor of the R79 Lua binding
/// (`install_session_actions` + the `register_*` family): the generated
/// trait replaces the per-name Lua closure registration, so no
/// `IScriptEngine` / `LuaEngine` is involved and the session path no
/// longer pulls `sce-rust-lua` — the second half of the runtime-schism
/// resolution after R311ik did the same for scouting.
pub struct SessionActionsBinding<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    inner: Arc<SessionLinkActions<R, T>>,
}

impl<R: SessionRuntime, T: TimeSource> SessionActionsBinding<R, T> {
    /// Wrap a clone of the caller's `Arc<`[`SessionLinkActions`]`>` so the
    /// generated [`SessionFsmUnicastActionsTrait`] dispatches its 18
    /// actions against the shared state the caller reads back. Production
    /// callers reach this through [`new_session_engine`]; it is `pub` so a
    /// test can drive an individual action method directly (the
    /// engine-free successor of the retired `dispatch_script` shim).
    pub fn new(actions: Arc<SessionLinkActions<R, T>>) -> Self {
        Self { inner: actions }
    }
}

/// Build a production session engine: an [`Engine`] over the generated
/// engine-free [`crate::session_fsm_unicast::SessionFsmUnicastPolicy`],
/// parameterised over a [`SessionActionsBinding`] wrapping a clone of
/// `actions`. The caller retains `actions` (to read trace / observe link
/// state) and drives the engine with [`drive_session_until_terminal`].
/// Mirrors [`crate::scouting_glue::new_scouting_engine`].
pub fn new_session_engine<T: TimeSource>(
    actions: &Arc<SessionLinkActions<TokioRuntime, T>>,
) -> Engine<SessionFsmUnicastPolicy<SessionActionsBinding<TokioRuntime, T>>> {
    let binding = SessionActionsBinding {
        inner: actions.clone(),
    };
    Engine::new(SessionFsmUnicastPolicy::new(binding))
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
/// the host handshake deadline-sweep (see [`drive_session_until_terminal`])
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
/// dispatcher ([`poll_and_dispatch_one`]) before it injects an
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

// ─────────────────────────── codec wiring ───────────────────────────

// encode_init / encode_open / encode_close + the encode_ext_chain
// helper moved to wz-session-core::handshake_encode (shared handshake
// encode SSOT for the tokio AP + lwIP MCU profiles). Re-imported so the
// action methods above (encode_init_with_role / encode_open_with_role /
// send_close_with_reason) keep calling the bare names.
#[cfg(feature = "codec-close")]
use wz_session_core::handshake_encode::encode_close;
#[cfg(feature = "codec-init-body")]
use wz_session_core::handshake_encode::encode_init;
#[cfg(feature = "codec-open-body")]
use wz_session_core::handshake_encode::encode_open;

// build_push_literal / build_push_aliased / build_push_del_literal /
// build_push_del_aliased moved to wz-session-core::push_build (shared
// Push builders for the tokio AP + lwIP MCU profiles). Re-exported so
// the action methods + the crate::session_glue::* paths keep the bare
// names.
#[cfg(feature = "codec-push")]
pub use wz_session_core::push_build::{
    build_push_aliased, build_push_del_aliased, build_push_del_literal, build_push_literal,
};

/// R233 — caller-supplied metadata for a publish wire branch. Owns
/// every field by value (`Option<…>`) so the
/// `SessionLinkActions::send_push_with_meta_*` surface can take an
/// already-constructed bundle without binding the caller to a
/// borrow lifetime. `PushMetadata::default()` (every field `None`)
/// reduces the wire shape to the metadata-stripped baseline that
/// [`build_push_literal`] / [`build_push_aliased`] /
/// [`build_push_del_literal`] / [`build_push_del_aliased`] emit.
///
/// Mirrors a subset of [`crate::session::PublishOptions`] — the
/// dispatch-time fields (locality / reliability / kind) live on
/// `PublishOptions`, the wire-encode-time metadata lives here. The
/// split keeps the wire encoder boundary clean: `session_glue`
/// stays oblivious to publisher locality predicates, and the
/// `session` module owns the conversion via
/// `PublishOptions::push_metadata`.
// R311di-9 — PushMetadata moved to wz-session-core::metadata.
pub use wz_session_core::metadata::PushMetadata;

/// R240 — Query-side counterpart of [`PushMetadata`]. Bundles the
/// caller-set [`crate::session::QueryOptions`] fields that route
/// through the layered [`RequestQueryBuilder`] so a
/// [`crate::session::Session::query`] call can hand them to
/// [`SessionLinkActions::send_request_query_with_meta`] without the
/// glue layer learning about `QueryOptions` directly.
///
/// Field coverage at R240 is *partial vs* [`crate::session::QueryOptions`]:
///
/// | QueryOptions field | Wire propagation slot |
/// |--------------------|-----------------------|
/// | `target`           | [`RequestQueryBuilder::request_target`] |
/// | `consolidation`    | [`RequestQueryBuilder::consolidation`] |
/// | `attachment`       | [`RequestQueryBuilder::query_attachment`] |
/// | `timeout_ms`       | [`RequestQueryBuilder::request_timeout_ms`] |
/// | `payload`          | R241+ carry — wz codec has no Q_B body slot yet |
/// | `encoding`         | R241+ carry — wz codec has no Q_E inline slot yet |
///
/// `payload` / `encoding` stay on
/// [`crate::session::QueryOptions`] as future-additive slots so a
/// later round that lands the Q_B / Q_E codec extensions surfaces
/// the propagation without an API break.
///
/// `#[derive(Default)]` makes the empty bundle trivially constructable
/// for the no-metadata fast path; [`Self::is_empty`] mirrors
/// [`PushMetadata::is_empty`] so callers can short-circuit the
/// builder allocation.
// R311di-9 — QueryMetadata moved to wz-session-core::metadata.
pub use wz_session_core::metadata::QueryMetadata;

// build_push_*_with_meta moved to wz-session-core::push_build alongside
// the private build_body_extensions / apply_chain_z_bits /
// build_push_outer_extensions / gated_* / build_msg_*_with_meta helpers
// (+ their co-located unit tests). Re-exported so callers keep the bare
// names.
#[cfg(feature = "codec-push")]
pub use wz_session_core::push_build::{
    build_push_aliased_with_meta, build_push_del_aliased_with_meta,
    build_push_del_literal_with_meta, build_push_literal_with_meta,
};

// build_declare_* / build_undeclare_* / build_declare_final moved to
// wz-session-core::declare_build (shared DECLARE builders for the tokio
// AP + lwIP MCU profiles). Re-exported so the action methods + the
// crate::session_glue::* paths keep the bare names.
#[cfg(feature = "codec-declare")]
pub use wz_session_core::declare_build::{
    build_declare_final, build_declare_kexpr, build_declare_queryable,
    build_declare_queryable_nonlocal, build_declare_subscriber, build_declare_subscriber_nonlocal,
    build_declare_token, build_declare_token_nonlocal, build_undeclare_kexpr,
    build_undeclare_queryable, build_undeclare_subscriber, build_undeclare_token,
};

// build_interest_* moved to wz-session-core::interest_build (shared
// INTEREST builders for the tokio AP + lwIP MCU profiles; the private
// build_liveliness_token_interest body-header SSOT moved with them).
// Re-exported so the action methods + crate::session_glue::* paths keep
// the bare names.
pub use wz_session_core::interest_build::{
    build_interest_final, build_interest_liveliness_get, build_interest_liveliness_subscriber,
};

// R311eh — the Request-builder cluster (build_request_query + the five
// build_request_query_with_{consolidation,parameters,attachment,
// timeout_ms,target} layered variants + RequestQueryBuilder + the two
// size-bound consts) moved to wz-session-core::request_build
// (runtime-agnostic wire-record construction, the mirror of R311dv's
// response_build). Re-exported here so crate::session_glue::* callers
// (session.rs z_get + the session_glue byte-stable regression tests)
// resolve unchanged across the reorg.
#[cfg(feature = "codec-request")]
pub use wz_session_core::request_build::{
    build_request_query, build_request_query_with_consolidation,
    build_request_query_with_parameters, build_request_query_with_target,
    build_request_query_with_timeout_ms, RequestQueryBuilder, QUERY_EXT_ZBUF_MAX_LEN,
    REQUEST_QUERY_PARAMETERS_MAX_LEN,
};
// build_request_query_with_attachment + the RequestQueryBuilder::query_attachment
// setter gate on query-attachment (the Query attachment encode vertical), so the
// re-export of the helper is split out under that combined gate.
#[cfg(all(feature = "codec-request", feature = "query-attachment"))]
pub use wz_session_core::request_build::build_request_query_with_attachment;

// R311ec — Priority + CongestionControl moved to wz-session-core::qos
// (the QoS packed-byte value types, runtime-agnostic siblings of
// Reliability / ConsolidationMode). Re-exported so the
// `crate::session_glue::{Priority, CongestionControl}` callsites
// (RequestQueryBuilder::request_qos_typed + the session_glue qos tests)
// resolve unchanged across the reorg. First DP3 leaf out of session_glue.
pub use wz_session_core::qos::{CongestionControl, Priority};

// R311di-8 — ConsolidationMode moved to wz-session-core::query_mode.
pub use wz_session_core::query_mode::ConsolidationMode;

// R311dv — the Response-builder cluster (build_response_{reply,err}_*
// + ResponseReplyBuilder + ResponseErrBuilder) moved to
// wz-session-core::response_build (runtime-agnostic wire-record
// construction). Re-exported here so crate::session_glue::* callers
// (query.rs into_response + the session_glue regression tests) resolve
// unchanged across the reorg.
#[cfg(feature = "codec-response")]
pub use wz_session_core::response_build::{
    build_response_err_aliased, build_response_err_literal, build_response_reply_aliased,
    build_response_reply_literal, encode_responder_ext_body, ResponseErrBuilder,
    ResponseReplyBuilder,
};
// R311ek — `encode_source_info_ext_body` is also consumed by the
// `codec-push` body-extension path (`build_body_extensions`), so it
// re-exports from the codec-feature-agnostic `source_info_ext` module
// under the union gate rather than from the `codec-response`-only
// `response_build` cluster above. This is what unblocks a
// `codec-push`-only subset (north-star arbitrary-composition mechanism ①).
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
pub use wz_session_core::source_info_ext::encode_source_info_ext_body;

// R311di-8 — QueryTarget moved to wz-session-core::query_mode.
pub use wz_session_core::query_mode::QueryTarget;

// build_response_final moved to wz-session-core::response_final_build
// (its own codec-response-final vertical, distinct from the
// codec-response response_build cluster). Re-exported so callers keep
// the bare name.
#[cfg(feature = "codec-response-final")]
pub use wz_session_core::response_final_build::build_response_final;

// encode_frame_envelope + the encode_frame_with_* family moved to
// wz-session-core::frame_encode (shared outbound encode SSOT for the tokio
// AP + lwIP MCU profiles). Re-exported so the action methods below + the
// external wz-ap-demo callsites keep naming
// crate::session_glue::encode_frame_with_*.
#[cfg(feature = "codec-declare")]
pub use wz_session_core::frame_encode::encode_frame_with_declare;
pub use wz_session_core::frame_encode::encode_frame_with_interest;
#[cfg(feature = "codec-push")]
pub use wz_session_core::frame_encode::encode_frame_with_push;
#[cfg(feature = "codec-request")]
pub use wz_session_core::frame_encode::encode_frame_with_request;
#[cfg(feature = "codec-response")]
pub use wz_session_core::frame_encode::encode_frame_with_response;
#[cfg(feature = "codec-response-final")]
pub use wz_session_core::frame_encode::encode_frame_with_response_final;

// ─────────────────────────── inbound parser ───────────────────────────

// InboundFrame + parse_inbound + inbound_to_fsm_event + the
// decode_ext_chain helper moved to wz-session-core::inbound (the MCU
// no_std profile needs the decode SSOT; the surrounding parse_error /
// network_message / driver_loop types were migrated in prior rounds).
// Re-exported so every callsite
// (`crate::session_glue::{InboundFrame, parse_inbound, inbound_to_fsm_event}`
// + the external `wz_runtime_tokio::session_glue::…`) keeps compiling unchanged.
#[cfg(feature = "transport-unicast")]
pub use wz_session_core::inbound::inbound_to_fsm_event;
pub use wz_session_core::inbound::{parse_inbound, InboundFrame};

// R311di-6 — InboundParseError + MAX_EXT_CHAIN_DEPTH moved to
// wz-session-core::parse_error. Re-exports keep every callsite
// (session_glue.rs internal + wz-runtime-tokio external) working
// verbatim across the migration.
pub use wz_session_core::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};

// R74 / R311di-11 — NetworkMessage + parse_frame_payload extracted to
// wz-session-core::network_message. Re-exported here so all callsite
// paths (`crate::session_glue::NetworkMessage`, the `parse_frame_payload`
// integration tests, the query / declare inbound-batch consumers) keep
// compiling unchanged. The 4 envelope MID constants (REQUEST / RESPONSE
// / RESPONSE_FINAL / OAM) that only the parse dispatcher consumed went
// with the move; PUSH / DECLARE / INTEREST remain in `wire_const` below
// because the outbound encode helpers (`build_push_*` / `build_declare_*`
// / `build_interest_*`) still reference them.
#[cfg(feature = "codec-frame")]
pub use wz_session_core::network_message::parse_frame_payload;
pub use wz_session_core::network_message::NetworkMessage;

// R76 / R311di-12 — DriverLoopOutcome extracted to
// wz-session-core::driver_loop. Re-exported here so callsites
// (`crate::session_glue::DriverLoopOutcome` + the {Sub,Query,Live}able
// IterationEvent adapters in declare/* + query.rs + driver-loop tests)
// keep compiling unchanged.
pub use wz_session_core::driver_loop::DriverLoopOutcome;

/// R76 — production driver loop unit. Poll a single `LinkEvent` from
/// `driver` and forward it through the inbound chain so the session
/// FSM advances without the caller hand-wiring
/// `handle_inbound` + `inbound_to_fsm_event` + `Engine::process_event`.
///
/// Mapping:
///   - `LinkEvent::Ready` → `SessionFsmUnicastEvent::LinkOpened`
///   - `LinkEvent::Rx(frame)` → parse + project + dispatch chain
///   - `LinkEvent::Lost { cause }` → `SessionFsmUnicastEvent::LinkLost`
///
/// `parse_inbound` errors are mapped to `FramingError` so the FSM's
/// `framing.error → Closing` transition fires; the caller receives
/// the typed `ParseError` outcome for logging.
///
/// This is the consumer wiring for the R68/R68a/R68c/R69b/R72/R73
/// inbound work — without an entry point that drives the chain, the
/// 8 commits would land as production-unreachable helpers (the
/// invariant the test-support split was supposed to enable). A
/// production-shaped session driver composes this in a loop until
/// the FSM reaches `Closed`.
pub async fn poll_and_dispatch_one<D: LinkDriver>(
    driver: &mut D,
    actions: &Arc<SessionLinkActions>,
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy<SessionActionsBinding>>,
) -> DriverLoopOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match driver.poll_event().await {
        LinkEvent::Ready => {
            engine.process_event(E::LinkOpened);
            DriverLoopOutcome::AdvancedFsm
        }
        LinkEvent::Lost { cause } => {
            engine.process_event(E::LinkLost);
            DriverLoopOutcome::LinkLost(cause)
        }
        LinkEvent::Rx(rx) => match actions.handle_inbound(&rx.bytes) {
            Ok(frame) => match inbound_to_fsm_event(&frame) {
                Some(event) => {
                    // R311il — §2.7 dispatcher admission pre-classify. The
                    // accept-side caps (half-open + token bucket on
                    // init_syn; cookie HMAC on open_syn) depend on HOST
                    // state, not on the triggering frame's wire payload, so
                    // the engine-free FSM carries no `cond=` for them — the
                    // dispatcher evaluates admission and injects the event
                    // only when it passes. Denial drops silently: no Close
                    // frame, no FSM advance (anti-amplification per the §2.7
                    // trust-class matrix). Engine-free successor of the
                    // retired Lua `cond="cookie_valid()"` transition guard.
                    let admit = match event {
                        E::InitSynReceived => {
                            actions.half_open_cap_available() && actions.accept_rate_token()
                        }
                        E::OpenSynReceived => actions.cookie_valid(),
                        _ => true,
                    };
                    if !admit {
                        return DriverLoopOutcome::SideEffectOnly;
                    }
                    engine.process_event(event);
                    DriverLoopOutcome::AdvancedFsm
                }
                None => match frame {
                    #[cfg(feature = "codec-frame")]
                    InboundFrame::Frame {
                        reliable,
                        sn,
                        payload,
                        has_ext,
                        extensions,
                    } => match parse_frame_payload(&payload) {
                        Ok(messages) => DriverLoopOutcome::FramePayload {
                            reliable,
                            sn,
                            messages,
                            has_ext,
                            extensions,
                        },
                        Err(codec_err) => {
                            engine.process_event(E::FramingError);
                            DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
                        }
                    },
                    #[cfg(feature = "codec-keep-alive")]
                    InboundFrame::KeepAlive { .. } => DriverLoopOutcome::SideEffectOnly,
                    // R311im — surface the decoded fragment to the drive
                    // loop, which owns the stateful ReassemblyDispatcher +
                    // clock. This pure helper cannot reassemble (no slot
                    // pool, no `now_ms`), so it hands the fragment up.
                    #[cfg(feature = "reassembly")]
                    InboundFrame::Fragment {
                        reliable,
                        sn,
                        more,
                        payload,
                        has_ext,
                        extensions,
                    } => DriverLoopOutcome::Fragment {
                        reliable,
                        sn,
                        more,
                        payload,
                        has_ext,
                        extensions,
                    },
                    #[cfg(feature = "codec-init-body")]
                    InboundFrame::Init { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    #[cfg(feature = "codec-open-body")]
                    InboundFrame::Open { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    #[cfg(feature = "codec-close")]
                    InboundFrame::Close { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    InboundFrame::Unknown { .. } => {
                        // inbound_to_fsm_event projects these to Some(event),
                        // so the outer Some arm handled them — this branch
                        // is unreachable.
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                },
            },
            Err(err) => {
                engine.process_event(E::FramingError);
                DriverLoopOutcome::ParseError(err)
            }
        },
    }
}

// R311di-7 — LeaseCheckOutcome moved to wz-session-core::lease.
pub use wz_session_core::lease::LeaseCheckOutcome;

/// R77 — compare `last_inbound_keepalive_at` against `params.lease`
/// and inject `SessionFsmUnicastEvent::LeaseExpired` when the
/// window has elapsed.
///
/// Production driver loops call this between
/// `poll_and_dispatch_one` iterations so a peer that stops sending
/// KeepAlives reaches the `lease.expired -> Closing(Expired)`
/// transition without the caller hand-wiring the deadline math.
/// This is the consumer wiring for the R72b `last_inbound_keepalive_at`
/// slot foreshadowed by `inbound_to_fsm_event`'s `KeepAlive -> None`
/// branch (lease-timer side effect orthogonal to the state graph).
///
/// `now_ms` is parameterised for test determinism. Production
/// callers pass `clock.now_monotonic_ms()` (the same clock used by
/// [`SessionLinkActions::clock`]); tests stage a stamp via
/// `last_inbound_keepalive_at` and pass `stamp_ms + offset_ms` as
/// `now_ms` so the comparator is deterministic without depending
/// on wall-clock progression during the test.
///
/// `params.lease_in_seconds` picks the integer unit per the
/// `_Z_FLAG_T_OPEN_T` wire semantics; the comparator multiplies
/// the seconds reading by 1000 before the `>=` check so the lease
/// arithmetic stays on the same `u64` ms scale as the stamp / now
/// inputs (R294 migration from `Duration::from_secs/from_millis`).
pub fn check_lease_deadline(
    actions: &Arc<SessionLinkActions>,
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy<SessionActionsBinding>>,
    now_ms: u64,
) -> LeaseCheckOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    let lease_ms = if actions.params.lease_in_seconds {
        actions.params.lease.saturating_mul(1000)
    } else {
        actions.params.lease
    };
    // R84 — baseline is the most recent of established_at and
    // last_inbound_keepalive_at. The KeepAlive stamp resets the lease
    // window per peer ping; the established_at stamp covers the
    // pre-first-KeepAlive window so the lease has a defined
    // start-of-counting at Established entry per session-fsm §2.5.
    let baseline = {
        let keepalive = *actions.last_inbound_keepalive_at.lock().unwrap();
        let established = *actions.established_at.lock().unwrap();
        match (established, keepalive) {
            (None, None) => None,
            (Some(e), None) => Some(e),
            (None, Some(k)) => Some(k),
            (Some(e), Some(k)) => Some(e.max(k)),
        }
    };
    match baseline {
        None => LeaseCheckOutcome::NoBaseline,
        Some(stamp_ms) if now_ms.saturating_sub(stamp_ms) >= lease_ms => {
            engine.process_event(E::LeaseExpired);
            LeaseCheckOutcome::Expired
        }
        Some(_) => LeaseCheckOutcome::WithinLease,
    }
}

// R83 / R311di-12 — IterationEvent extracted to
// wz-session-core::driver_loop. Re-exported here for callsites in
// declare/* IterationEvent adapters + drive_session test closures.
pub use wz_session_core::driver_loop::IterationEvent;

/// R76b — outcome of the production driver loop in
/// `drive_session_until_terminal`.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutcome {
    /// The engine reached a terminal state
    /// (`Engine::is_in_final_state() == true`) via FSM transition.
    /// Production callers exit the session lifecycle here; the
    /// outbound driver close has already been dispatched by the
    /// `Closed.onentry` script action chain.
    Terminated,
    /// The caller-supplied `max_iters` cap was reached without the
    /// engine reaching a terminal state. Test callers use this to
    /// bound runaway loops; production callers pass `None` for
    /// unlimited iteration.
    IterationLimit,
}

// ── R311im — reassembly pool wiring for the steady-state drive loop ──

#[cfg(feature = "reassembly")]
use wz_session_core::reassembly_dispatch::{
    Fragment as ReassemblyFragment, ReassemblyConfig, ReassemblyDispatcher,
};

/// Reassembly slot-pool dimensions for the unicast tokio session. R311in
/// — sourced from the SCE-codegen'd AP buffer-pool constants
/// ([`crate::reassembly_pool_ap`]), whose single SSOT is
/// `sources/network/reassembly_pool_ap.scxml` (`sce:kind="buffer-pool"`).
/// These replace the prior hand-transcribed `4 / 4096` literals; the
/// values, the spec §4 table, and the deploy.yaml block no longer drift
/// because there is now one SCE-owned, build-validated source.
///
/// The emit types the slot dims as `usize`, so they bind directly as the
/// dispatcher const generics (no cast). The AP machine's dims are larger
/// than the MCU's (32 / 65536 vs 4 / 4096) — the tokio host IS the AP
/// node, so it correctly uses the AP machine's pool.
#[cfg(feature = "reassembly")]
const REASSEMBLY_SLOTS: usize = crate::reassembly_pool_ap::SLOT_COUNT;
#[cfg(feature = "reassembly")]
const REASSEMBLY_SLOT_SIZE: usize = crate::reassembly_pool_ap::SLOT_SIZE;

/// The unicast tokio session's reassembly Router type. The std `alloc`
/// backing keeps each chain's staging buffer on the heap;
/// `REASSEMBLY_SLOT_SIZE` is the per-chain cap the dispatcher enforces
/// explicitly (so reassembly is bounded on the AP profile too).
#[cfg(feature = "reassembly")]
pub type TokioReassembly = ReassemblyDispatcher<REASSEMBLY_SLOTS, REASSEMBLY_SLOT_SIZE>;

/// Reassembly config (`per_peer_quota` / `reassembly_timeout_ms`) sourced
/// from the same SCE-codegen'd AP buffer-pool constants. The emit types
/// them as `u32`; [`ReassemblyConfig`] takes `u16` / `u64`, so the two
/// widening casts are the only adaptation.
#[cfg(feature = "reassembly")]
fn reassembly_config() -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_ap::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_ap::REASSEMBLY_TIMEOUT_MS as u64,
    )
}

/// Report one driver-loop outcome, additionally driving the reassembly
/// pool when the outcome is a `Fragment`. On chain completion the
/// reassembled bytes re-enter [`parse_frame_payload`], so the
/// application's per-MID dispatch sees a reassembled message exactly as it
/// sees a `T_MID_FRAME` payload; the resulting `FramePayload` (or
/// `ParseError`) is reported as a second `IterationEvent::Poll`.
/// Non-terminal ingests (Begun / Continued / Aborted / Refused) report
/// only the `Fragment` outcome. The peer ZID (the §2.3 chain key) is read
/// from the session's `inbound_peer_zid` slot.
#[cfg(feature = "reassembly")]
fn report_outcome_reassembling<F: FnMut(IterationEvent<'_>)>(
    outcome: &DriverLoopOutcome,
    reasm: &mut TokioReassembly,
    actions: &Arc<SessionLinkActions>,
    now_ms: u64,
    on_event: &mut F,
) {
    on_event(IterationEvent::Poll(outcome));
    let DriverLoopOutcome::Fragment {
        reliable,
        sn,
        more,
        payload,
        ..
    } = outcome
    else {
        return;
    };
    let zid_guard = actions.inbound_peer_zid.lock().unwrap();
    let zid: &[u8] = zid_guard.as_deref().unwrap_or(&[]);
    let mut completed: Option<DriverLoopOutcome> = None;
    reasm.ingest(
        ReassemblyFragment {
            zid,
            reliable: *reliable,
            sn: *sn,
            more: u8::from(*more),
            payload: payload.as_slice(),
        },
        now_ms,
        |msg| {
            completed = Some(match parse_frame_payload(msg) {
                Ok(messages) => DriverLoopOutcome::FramePayload {
                    reliable: *reliable,
                    sn: *sn,
                    messages,
                    // The reassembled bytes are the inner NetworkMessage
                    // batch; transport ext chains were per-fragment, so the
                    // reassembled message carries none.
                    has_ext: false,
                    extensions: Vec::new(),
                },
                Err(codec_err) => {
                    DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
                }
            });
        },
    );
    drop(zid_guard);
    if let Some(o) = completed {
        on_event(IterationEvent::Poll(&o));
    }
}

/// R76b — production driver loop. Composes `poll_and_dispatch_one`
/// (one LinkEvent per iteration) with a `tokio::select!` race
/// against a lease-deadline `tokio::time::sleep` so a peer that
/// stops sending KeepAlives reaches the `lease.expired -> Closing`
/// transition without the driver poll blocking indefinitely.
///
/// Each iteration:
///   1. Returns `Terminated` if `engine.is_in_final_state()` already.
///   2. Returns `IterationLimit` if `max_iters` is exhausted.
///   3. Reads `last_inbound_keepalive_at`. If `Some(stamp)`, computes
///      the remaining lease window via `stamp + lease - now`.
///   4. Selects between `poll_and_dispatch_one` and a sleep of the
///      remaining window. The first-to-complete branch's outcome is
///      applied (event dispatch or lease check); the other future
///      is cancelled.
///   5. Loop back to (1).
///
/// `max_iters = Some(n)` caps the iteration count for test
/// determinism. Production callers pass `None` for unlimited.
///
/// Cancel-safety. `tokio::select!` cancels the losing branch's
/// future. `poll_and_dispatch_one`'s only `.await` point is
/// `driver.poll_event()`; cancellation there is well-defined for
/// the in-tree `TcpDriver` / `UdpDriver` (tokio io futures are
/// cancel-safe at the read syscall boundary) and for the test
/// `QueueDriver` (synchronous pop). No bytes are lost across
/// cancellation.
///
/// Carry — the lease branch reads `Instant::now()` (std monotonic
/// clock) while the sleep uses `tokio::time` (which can be paused
/// via `tokio::time::pause` for test). Deterministic time-paused
/// testing of the lease branch requires a unified clock source;
/// this round trusts the R77 `check_lease_deadline` unit tests for
/// the leaf logic and uses wall-clock-short-lease integration
/// testing for the loop wiring.
///
/// R83 — `on_event` is the per-iteration observer callback. Each
/// time exactly one of the inner work paths completes (poll arm,
/// lease arm, or no-baseline await), the callback is invoked once
/// with the matching [`IterationEvent`] variant before the loop
/// continues. This is the textbook bridge between the producers
/// (R74 `FramePayload`, R76 `AdvancedFsm/LinkLost/ParseError`, R77
/// `LeaseCheckOutcome`) and downstream consumers (pub/sub topic
/// dispatcher, telemetry, logging) — without it the loop would
/// discard the outcomes silently. Test callers that do not care
/// about per-iteration events pass `|_| {}` as a no-op closure.
///
/// R260 + R294 — `clock: &T` (`T: TimeSource`) is the trait-mediated
/// clock used to race the lease deadline AND to read `now_ms` for
/// the lease comparator. The R260 round routed only the
/// `tokio::select!` sleep branch through `TimeSource::sleep`; R294
/// finished the migration by lifting the storage / comparator path
/// from `std::time::Instant` + `Duration::from_secs/from_millis`
/// to pure `u64` ms arithmetic. The lease deadline computation,
/// the remaining-window subtraction, and the
/// [`check_lease_deadline`] call now read `clock.now_monotonic_ms()`
/// directly; the [`SessionLinkActions::clock`] field carries a
/// value-copy of the same epoch so
/// [`SessionLinkActions::handle_inbound`] + the
/// `record_established_at` Lua action record `u64` ms stamps on
/// the same scale. Production AP callers pass `&TokioTime::new()`
/// (or any owned `TokioTime` reference); MCU callers will pass an
/// embassy / FreeRTOS impl once Phase W lwIP integration arrives.
///
/// R268 — the prior `on_tick: G` per-iteration tick parameter
/// (R262) was removed after R264 relocated the sole production
/// consumer ([`crate::reply::ReplyRegistry::sweep_timed_out`]) to
/// a dedicated peer task. Every remaining caller passed a no-op
/// closure, so the parameter was dead surface; sub-second sweep
/// cadence belongs in a peer task that does not race
/// `poll_and_dispatch_one` (which is not cancel-safe for
/// length-prefixed drivers — cancelling between the u16 length
/// read and the payload read drops captured bytes). Future
/// per-iteration observability uses can re-introduce a similar
/// hook when an actual consumer materialises (YAGNI hold).
pub async fn drive_session_until_terminal<D, F, T>(
    driver: &mut D,
    actions: &Arc<SessionLinkActions>,
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy<SessionActionsBinding>>,
    max_iters: Option<usize>,
    clock: &T,
    timeouts: &SessionTimeouts,
    mut on_event: F,
) -> DriverOutcome
where
    D: LinkDriver,
    F: FnMut(IterationEvent<'_>),
    T: TimeSource,
{
    let lease_ms = if actions.params.lease_in_seconds {
        actions.params.lease.saturating_mul(1000)
    } else {
        actions.params.lease
    };
    // R311il — host-owned handshake deadline tracker (the arming-key
    // staleness logic lives once in wz-session-core; see
    // [`HandshakeDeadlineTracker`]). The engine-free FSM arms no
    // `<send delay>`, so this loop owns every handshake deadline; in
    // Established the keepalive-resetting lease deadline takes over.
    let mut deadline_tracker = HandshakeDeadlineTracker::new(*timeouts);
    // R311im — the steady-state loop owns the reassembly Router (the
    // stateful slot pool + clock the engine-free slot FSM cannot own).
    // Established-only: fragments arriving before Established are reported
    // but not reassembled (this loop runs the data plane).
    #[cfg(feature = "reassembly")]
    let mut reasm = TokioReassembly::new(reassembly_config());
    let mut iter: usize = 0;
    loop {
        if engine.is_in_final_state() {
            return DriverOutcome::Terminated;
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return DriverOutcome::IterationLimit;
            }
            iter += 1;
        }
        // R311im — abort + reclaim any reassembly chain past its deadline.
        // Swept once per loop iteration (whenever an event or deadline
        // fires); in Established the lease deadline guarantees the loop
        // iterates well within the reassembly window.
        #[cfg(feature = "reassembly")]
        {
            reasm.sweep(clock.now_monotonic_ms());
        }
        // This iteration's deadline. During the handshake phases the
        // tracker yields the host-owned handshake deadline; in Established
        // it disarms and the keepalive-resetting lease deadline applies;
        // in Init / between there is none (block on the link poll).
        // `Some((abs_ms, Some(event)))` = handshake timeout to raise;
        // `Some((abs_ms, None))` = lease deadline (-> check_lease).
        let deadline: Option<(
            u64,
            Option<crate::session_fsm_unicast::SessionFsmUnicastEvent>,
        )> = match deadline_tracker.poll(engine.get_current_state(), clock.now_monotonic_ms()) {
            Some((deadline_ms, event)) => Some((deadline_ms, Some(event))),
            None => {
                let stamp_ms = *actions.last_inbound_keepalive_at.lock().unwrap();
                stamp_ms.map(|s| (s.saturating_add(lease_ms), None))
            }
        };
        match deadline {
            Some((deadline_ms, kind)) => {
                let now_ms = clock.now_monotonic_ms();
                let remaining_ms = deadline_ms.saturating_sub(now_ms);
                tokio::select! {
                    outcome = poll_and_dispatch_one(driver, actions, engine) => {
                        #[cfg(feature = "reassembly")]
                        report_outcome_reassembling(
                            &outcome,
                            &mut reasm,
                            actions,
                            clock.now_monotonic_ms(),
                            &mut on_event,
                        );
                        #[cfg(not(feature = "reassembly"))]
                        on_event(IterationEvent::Poll(&outcome));
                    }
                    _ = clock.sleep(remaining_ms) => match kind {
                        // Established lease deadline (existing R77 path).
                        None => {
                            let lease_outcome =
                                check_lease_deadline(actions, engine, clock.now_monotonic_ms());
                            on_event(IterationEvent::Lease(lease_outcome));
                        }
                        // Handshake timeout: raise the FSM event the arming
                        // state declared (`*.timeout -> Closing` / accept ->
                        // Closed). Each of the 5 events has a handler in its
                        // arming state, so the raise always advances out of
                        // that state — the loop cannot hot-spin re-raising.
                        Some(event) => {
                            engine.process_event(event);
                        }
                    }
                }
            }
            None => {
                let outcome = poll_and_dispatch_one(driver, actions, engine).await;
                #[cfg(feature = "reassembly")]
                report_outcome_reassembling(
                    &outcome,
                    &mut reasm,
                    actions,
                    clock.now_monotonic_ms(),
                    &mut on_event,
                );
                #[cfg(not(feature = "reassembly"))]
                on_event(IterationEvent::Poll(&outcome));
            }
        }
    }
}

// init_cbyte / pack_sn_res moved to wz-session-core::handshake_encode
// alongside encode_init (their sole production caller). The orphaned
// decode_ext_chain doc that had drifted onto init_cbyte was dropped —
// decode_ext_chain itself lives in wz-session-core::inbound.

// R311il — the Lua-binding helpers (`bind_close_reason`, `bind_bool`, the
// `bind_unit` / `bind_guard` imports, the `dispatch_script` test shim, and
// the build-audited `REGISTERED_SCRIPT_NAMES` mirror) were retired with
// the engine-free migration. The 18 actions are now native trait methods
// on `SessionActionsBinding` (above) and the 3 accept guards are
// `SessionLinkActions` methods (`cookie_valid` / `half_open_cap_available`
// / `accept_rate_token`); the compiler enforces the action set via the
// generated `SessionFsmUnicastActions` trait, so the build-time script
// name audit (`build.rs::audit_script_names`) is no longer needed and was
// removed with the crate's build.rs.

#[cfg(test)]
mod tests {
    use super::*;
    // The builder + frame coverage tests moved to wz-session-core's
    // *_build / frame_encode modules (co-located with the code they test),
    // so the wz-codecs types they named (PushOwnedVariant / DeclareOwnedVariant
    // / Wireexpr* / Push) left with them. The only remaining session_glue
    // test users are the action-layer tests: wire_const → send_close wire
    // bytes + reassembly Fragment tests; TestWire `.wire()` → send_request /
    // send_push wire-byte + reassembly tests.
    #[cfg(any(feature = "codec-close", feature = "reassembly"))]
    use wz_codecs::wire_const;
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "reassembly"
    ))]
    use wz_codecs_test_support::TestWire;

    /// R69 / R311ei — `signing_key_from_os_entropy` yields a 32-byte
    /// key (satisfies the >= 32 invariant by construction) and two
    /// successive calls produce distinct material with overwhelming
    /// probability (collision space = 2^256, never observed in
    /// practice). The test asserts both surfaces: length (via the
    /// public `len()`) AND distinctness — observed through the cookie
    /// MAC since the raw key bytes are private to wz-session-core. A
    /// regression that wires a constant entropy source (zero-fill,
    /// counter, etc.) fires loud on the distinctness assertion.
    #[test]
    fn signing_key_from_os_entropy_yields_distinct_32_byte_keys() {
        let a = signing_key_from_os_entropy().expect("AP entropy available");
        let b = signing_key_from_os_entropy().expect("AP entropy available");
        assert_eq!(a.len(), 32, "OS-entropy key must be 32 bytes");
        assert_eq!(b.len(), 32);
        // Distinctness is observed through the cookie MAC (the raw key
        // bytes are not publicly readable): distinct keys over the same
        // peer_zid produce distinct cookies.
        let peer_zid = vec![0x01, 0x02, 0x03, 0x04];
        assert_ne!(
            generate_cookie_hmac_sha256(&a, &peer_zid),
            generate_cookie_hmac_sha256(&b, &peer_zid),
            "two OS-entropy keys must produce distinct cookies (2^256 space)"
        );
    }

    // init_cbyte / pack_sn_res unit tests moved to
    // wz-session-core::handshake_encode (co-located with the fns).

    // ── R121e — outbound Push/Frame builder coverage ──

    /// R121j-5c-e2e — `SessionLinkActions::send_response` emits the
    /// exact same wire bytes as the underlying
    /// `encode_frame_with_response` helper with the SN drawn from
    /// `next_outbound_frame_sn`. The action layer must not silently
    /// transform the Response between the builder and the wire.
    #[cfg(feature = "codec-response")]
    #[test]
    fn send_response_emits_reliable_frame_with_seeded_sn() {
        // The wire-byte assertion depends on initial_sn (it seeds the
        // Frame SN), so override only that field on the
        // `fixture_session_init_params()` SSOT.
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 100;
        let (actions, driver) = crate::test_fixtures::recording_actions_with_params(params);

        let response = ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"21.0")
            .build()
            .unwrap();
        let expected_wire = encode_frame_with_response(
            100,
            ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"21.0")
                .build()
                .unwrap(),
            /*reliable=*/ true,
        );
        actions.send_response(response);

        assert_eq!(
            driver.frame_count(),
            1,
            "exactly one send_blocking call per send_response"
        );
        assert_eq!(
            driver.frame_bytes(0),
            expected_wire,
            "wire bytes must match encode_frame_with_response output byte-for-byte"
        );
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::Reliable,
            "Reply data delivery pinned reliable at the action layer"
        );
    }

    /// R284 — `send_close_with_reason` is the Rust-side counterpart of
    /// the Lua-bound `send_close_frame_with_reason` action. The two
    /// must produce byte-identical wire frames for the same
    /// `CloseReason`, otherwise a signal-cancellation path that uses
    /// the Rust primitive would emit a Close the peer cannot decode
    /// against the same zenoh-pico `_z_close_decode` reference the
    /// FSM-driven Close goes through.
    ///
    /// Four-vector check across all `CloseReason` variants pins the
    /// reason discriminator byte; `_Z_FLAG_T_CLOSE_S` (graceful
    /// session close) is hard-set inside `encode_close`, so the outer
    /// header byte is invariant. Reliable channel is hard-pinned too
    /// (zenoh-pico drops Close on best-effort).
    ///
    /// The trace counter for Close emits bumps once per call so a
    /// downstream test counting Close emits across the script + Rust
    /// paths sees the unified count.
    #[cfg(feature = "codec-close")]
    #[test]
    fn send_close_with_reason_emits_zenoh_pico_compatible_wire_bytes() {
        for (variant, reason_byte) in [
            (CloseReason::Generic, 0u8),
            (CloseReason::Invalid, 1u8),
            (CloseReason::Expired, 2u8),
            (CloseReason::Unresponsive, 3u8),
        ] {
            // Close is a fixed 2-byte frame (no SN field), so the
            // `recording_actions()` SSOT params are used verbatim.
            let (actions, driver) = crate::test_fixtures::recording_actions();
            assert_eq!(
                actions.trace_snapshot().send_close_frame_with_reason,
                0,
                "trace counter starts at zero",
            );

            actions.send_close_with_reason(variant);

            assert_eq!(
                driver.frame_count(),
                1,
                "exactly one wire emit per send_close_with_reason ({variant:?})",
            );
            // Outer header = T_MID_CLOSE | _Z_FLAG_T_CLOSE_S. Body =
            // reason byte. Total 2 bytes — Close has no other body
            // fields (the Close codec is a fixed single-byte
            // discriminator) and we hard-set FLAG_T_CLOSE_S to
            // request graceful session close.
            let expected = vec![
                wire_const::T_MID_CLOSE | wire_const::FLAG_T_CLOSE_S,
                reason_byte,
            ];
            assert_eq!(
                driver.frame_bytes(0),
                expected,
                "wire bytes must match encode_close output for {variant:?}",
            );
            assert_eq!(
                driver.frame_reliability(0),
                Reliability::Reliable,
                "Close pinned reliable — zenoh-pico drops Close on best-effort",
            );
            assert_eq!(
                actions.trace_snapshot().send_close_frame_with_reason,
                1,
                "trace counter bumps once per send_close_with_reason ({variant:?})",
            );
        }
    }

    /// R121j-5c-e2e — `send_response` and `send_response_final`
    /// advance the SN counter together so a `Reply` followed by its
    /// terminating `ResponseFinal` carry consecutive SNs on the
    /// reliable channel (zenoh-pico SN-window ordering depends on
    /// this; a Reply that races ahead of the Final out-of-order would
    /// stall the requester's z_get future).
    #[cfg(feature = "codec-response")]
    #[test]
    fn send_response_and_final_share_sn_counter() {
        // Asserts on the Frame SN byte, so override initial_sn on the
        // `fixture_session_init_params()` SSOT.
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 7;
        let (actions, driver) = crate::test_fixtures::recording_actions_with_params(params);

        actions.send_response(
            ResponseReplyBuilder::new(99, 0, Some("k"), b"v")
                .build()
                .unwrap(),
        );
        actions.send_response_final(99);

        assert_eq!(driver.frame_count(), 2);
        // Reply frame SN byte is at offset 1 (Frame header + VLE(sn)).
        assert_eq!(driver.frame_bytes(0)[1], 7, "first frame uses initial_sn=7");
        assert_eq!(
            driver.frame_bytes(1)[1],
            8,
            "second frame increments to 8 — Reply + ResponseFinal carry consecutive SNs",
        );
    }

    /// `SessionLinkActions::next_outbound_frame_sn` starts at
    /// `params.initial_sn` and increments by one per call. This
    /// pairs the SN seed contract with the increment contract so
    /// a regression on either side (off-by-one seed, wrong stride)
    /// fires loud.
    #[test]
    fn next_outbound_frame_sn_seeds_at_initial_sn_then_increments() {
        // The SN counter seeds from initial_sn; the driver is unused
        // (we only read the counter), so the `recording_actions_with_params`
        // SSOT driver discards the never-emitted frames.
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 42;
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
        assert_eq!(
            actions.next_outbound_frame_sn(),
            42,
            "first SN must equal params.initial_sn"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(),
            43,
            "subsequent SNs must increment by 1"
        );
        assert_eq!(actions.next_outbound_frame_sn(), 44);
    }

    // ── R311hw / R311hx (R311hz refactor) — codec & declare behavioural
    // NEG / isolation ──
    //
    // Layer F (codec-footprint) proves a `codec-*` feature's minus-<codec>
    // lane SHRINKS the binary; it does NOT prove the consumer-side
    // signature-stable emit path BEHAVES correctly when off. The
    // `feedback_signature_stability` contract (R311j / R311g1) requires the
    // `SessionLinkActions` send method to keep its signature and return
    // `Err(..::FeatureDisabled)` — an honest typed reject that emits NO
    // wire bytes (see the `FeatureDisabled` variant docs in
    // wz-session-core). Each guard below pins BOTH halves: the typed `Err`
    // AND `driver.frame_count() == 0`. R311hw covers the two `codec-*`
    // send gates (codec-push / codec-request → SendWireError); R311hx the
    // five declare gates (declare-keyexpr / -subscriber / -queryable /
    // -token → SendDeclareError, declare-interest → SendWireError).
    //
    // R311hz moved the fixture onto the `recording_actions()` SSOT in
    // `wz-runtime-tokio-test-support` (was an inline `SessionInitParams` +
    // `DiscardDriver` duplicate that bypassed `fixture_session_init_params`
    // and forced a hand-synced `any(not, ..)` cfg gate; both removed). The
    // per-test `#[cfg(not(feature = ..))]` gates stay — they select which
    // off-build runs each guard — and ride the existing C1j subset lanes
    // (handshake-only / pubsub-only / queryable-only / zget-reply-only /
    // liveliness-* / declare-observer), so no new lane is needed.

    /// R311hw — with `codec-push` OFF, the signature-stable
    /// `send_push_literal` must fail-fast with the typed
    /// `SendWireError::FeatureDisabled` reject and emit no wire bytes.
    /// Complements Layer F's footprint proof with the behavioural half of
    /// the signature-stability contract: a regression that silently
    /// un-gated the emit body would return `Ok(())` (or panic) here.
    #[cfg(not(feature = "codec-push"))]
    #[test]
    fn send_push_literal_rejects_with_feature_disabled_when_codec_push_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_push_literal("home/temp", b"data", true),
            Err(SendWireError::FeatureDisabled),
            "codec-push OFF: send_push_literal must return the typed \
             FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "codec-push OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hw — with `codec-request` OFF, the signature-stable
    /// `send_request_query` must fail-fast with
    /// `SendWireError::FeatureDisabled`. The query initiator surface stays
    /// callable (signature stable) but emits nothing on the wire.
    #[cfg(not(feature = "codec-request"))]
    #[test]
    fn send_request_query_rejects_with_feature_disabled_when_codec_request_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_request_query(7, 0, Some("home/temp")),
            Err(SendWireError::FeatureDisabled),
            "codec-request OFF: send_request_query must return the typed \
             FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "codec-request OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hx — with `declare-keyexpr` OFF, `send_declare_keyexpr` must
    /// reject with `SendDeclareError::FeatureDisabled` and leave the
    /// outbound mapping table untouched (no wire bytes, no side effect).
    #[cfg(not(feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_keyexpr_rejects_with_feature_disabled_when_declare_keyexpr_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_declare_keyexpr(1, "home/temp"),
            Err(SendDeclareError::FeatureDisabled),
            "declare-keyexpr OFF: send_declare_keyexpr must return the typed \
             FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "declare-keyexpr OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hx — with `declare-subscriber` OFF,
    /// `send_declare_subscriber` must reject with
    /// `SendDeclareError::FeatureDisabled`.
    #[cfg(not(feature = "declare-subscriber"))]
    #[test]
    fn send_declare_subscriber_rejects_with_feature_disabled_when_declare_subscriber_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_declare_subscriber(1, 0, Some("home/temp")),
            Err(SendDeclareError::FeatureDisabled),
            "declare-subscriber OFF: send_declare_subscriber must return the \
             typed FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "declare-subscriber OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hx — with `declare-queryable` OFF, `send_declare_queryable`
    /// must reject with `SendDeclareError::FeatureDisabled`.
    #[cfg(not(feature = "declare-queryable"))]
    #[test]
    fn send_declare_queryable_rejects_with_feature_disabled_when_declare_queryable_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_declare_queryable(1, 0, Some("home/temp")),
            Err(SendDeclareError::FeatureDisabled),
            "declare-queryable OFF: send_declare_queryable must return the \
             typed FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "declare-queryable OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hx — with `declare-token` OFF, `send_declare_token` must
    /// reject with `SendDeclareError::FeatureDisabled`.
    #[cfg(not(feature = "declare-token"))]
    #[test]
    fn send_declare_token_rejects_with_feature_disabled_when_declare_token_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_declare_token(1, 0, Some("home/temp")),
            Err(SendDeclareError::FeatureDisabled),
            "declare-token OFF: send_declare_token must return the typed \
             FeatureDisabled reject, not a falsely-Ok no-op or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "declare-token OFF: the typed reject must leave no wire bytes"
        );
    }

    /// R311hx — with `declare-interest` OFF,
    /// `send_interest_liveliness_subscriber` must reject with
    /// `SendWireError::FeatureDisabled` (this surface returns the
    /// wire-error type, not the declare-error type). The liveliness
    /// subscription is silently inactive on such a build; the typed
    /// reject is the caller's feature-detect signal.
    #[cfg(not(feature = "declare-interest"))]
    #[test]
    fn send_interest_liveliness_subscriber_rejects_with_feature_disabled_when_declare_interest_off()
    {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.send_interest_liveliness_subscriber(1, false, 0, Some("home/temp")),
            Err(SendWireError::FeatureDisabled),
            "declare-interest OFF: send_interest_liveliness_subscriber must \
             return the typed FeatureDisabled reject, not a falsely-Ok no-op \
             or a panic"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "declare-interest OFF: the typed reject must leave no wire bytes"
        );
    }

    // QosLevel / SourceInfo remain named by the send_push_with_meta action
    // test; TimestampHint / EncodingHint left with the push-builder meta
    // coverage tests (now wz-session-core::push_build).
    #[cfg(feature = "codec-push")]
    use crate::sample::{QosLevel, SourceInfo};

    // build_msg_put_with_meta / build_msg_del_with_meta /
    // build_push_outer_extensions unit tests moved to
    // wz-session-core::push_build (co-located with the private helpers).

    #[cfg(feature = "codec-push")]
    #[test]
    fn send_push_with_meta_literal_dispatches_metadata_frame_to_driver() {
        // End-to-end via the action surface + recording driver: the
        // emitted wire bytes must decode back to a Push carrying the
        // caller-set metadata. Pins the integration between
        // PushMetadata, build_push_literal_with_meta, and
        // encode_frame_with_push.
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = PushMetadata {
            source_info: Some(SourceInfo::new(&[0xCA, 0xFE], 5, 7)),
            qos: Some(QosLevel::from_raw(0x10)),
            ..Default::default()
        };
        actions
            .send_push_with_meta_literal("home/temp", b"data", true, &meta)
            .unwrap();

        assert_eq!(driver.frame_count(), 1);
        // The frame is `Frame + Push`. We don't decode the outer Frame
        // here (the layer-3 integration tests cover that path); instead
        // we re-encode an equivalent Push via build_push_literal_with_meta
        // and assert the trailing Push bytes are byte-identical to the
        // bytes that follow the Frame envelope in the recorded buffer.
        let standalone_push = build_push_literal_with_meta("home/temp", b"data", &meta).unwrap();
        let standalone_bytes = standalone_push.wire();
        assert!(
            driver
                .frame_bytes(0)
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "recorded frame must contain the with-meta Push bytes verbatim"
        );
    }

    // R233/R234 wire-side tests use the `recording_actions()` SSOT in
    // `wz-runtime-tokio-test-support` for the (actions, recording driver)
    // pair. The former local `publish_meta_fixture_params` + `CaptureDriver`
    // duplicate (a re-spelling of `fixture_session_init_params` +
    // `RecordingLinkDriver`) was folded into it. None of these tests assert
    // on the SN / version fields, so the SSOT params are used verbatim.

    // ── R234 outbound mapping table ──

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn send_declare_keyexpr_populates_outbound_mapping_table() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        assert!(
            actions.resolve_outbound_mapping(7).is_none(),
            "fresh table empty"
        );

        actions
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            actions.resolve_outbound_mapping(7).as_deref(),
            Some("home/temp"),
            "send_declare_keyexpr must record the (id, suffix) pair"
        );
        // Multiple declarations on different ids accumulate.
        actions
            .send_declare_keyexpr(8, "home/humidity")
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            actions.resolve_outbound_mapping(7).as_deref(),
            Some("home/temp")
        );
        assert_eq!(
            actions.resolve_outbound_mapping(8).as_deref(),
            Some("home/humidity")
        );
    }

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn send_declare_keyexpr_overwrites_existing_mapping_for_same_id() {
        // zenoh-pico's _z_register_resource OVERWRITES on
        // re-declaration with the same id (it's idempotent: same id,
        // possibly different suffix). The outbound table must mirror
        // that semantic so a caller re-declaring a mapping doesn't
        // see stale resolution for later publishes.
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/v1")
            .expect("hardcoded canonical literal keyexpr");
        actions
            .send_declare_keyexpr(7, "home/v2")
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            actions.resolve_outbound_mapping(7).as_deref(),
            Some("home/v2"),
            "re-declaring same id must replace the prior suffix"
        );
    }

    #[cfg(all(feature = "declare-keyexpr", feature = "declare-undeclare"))]
    #[test]
    fn send_undeclare_kexpr_removes_mapping_from_table() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        assert!(actions.resolve_outbound_mapping(7).is_some());

        actions.send_undeclare_kexpr(7);
        assert!(
            actions.resolve_outbound_mapping(7).is_none(),
            "undeclare must drop the table entry so later publishes fail typed"
        );
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn send_undeclare_kexpr_idempotent_on_unknown_id() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        // Calling undeclare on an id that was never declared must not
        // panic — the HashMap::remove on absent key is a no-op.
        actions.send_undeclare_kexpr(42);
        assert!(actions.resolve_outbound_mapping(42).is_none());
    }

    // ── R300 — outbound DECLARE-side gate ─────────────────────

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn send_declare_keyexpr_rejects_reserved_mapping_id_zero() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let err = actions
            .send_declare_keyexpr(0, "home/temp")
            .expect_err("mapping_id 0 is reserved");
        assert_eq!(err, SendDeclareError::ReservedMappingIdZero);
        assert_eq!(
            driver.frame_count(),
            0,
            "gate must reject pre-emit — no wire frame leaves on Err"
        );
        assert!(
            actions.resolve_outbound_mapping(0).is_none(),
            "gate must reject pre-side-effect — mapping table untouched on Err"
        );
    }

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn send_declare_keyexpr_rejects_pico_bug_three_pattern() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let err = actions
            .send_declare_keyexpr(7, "**/c/*")
            .expect_err("R299 bug #3 pattern must reject");
        match err {
            SendDeclareError::Keyexpr(
                crate::keyexpr_canon::OutboundKeyexprError::PicoBugThreeFamily {
                    keyexpr,
                    offending_chunk,
                },
            ) => {
                assert_eq!(keyexpr, "**/c/*");
                assert_eq!(offending_chunk, "*");
            }
            other => panic!("expected Keyexpr(PicoBugThreeFamily), got {other:?}"),
        }
        assert_eq!(driver.frame_count(), 0);
        assert!(actions.resolve_outbound_mapping(7).is_none());
    }

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn send_declare_keyexpr_rejects_structurally_invalid() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let err = actions
            .send_declare_keyexpr(7, "home//temp")
            .expect_err("empty chunk must reject");
        assert!(
            matches!(
                err,
                SendDeclareError::Keyexpr(
                    crate::keyexpr_canon::OutboundKeyexprError::NotCanonical(
                        crate::keyexpr_canon::KeyexprCanonError::EmptyChunk,
                    )
                ),
            ),
            "got {err:?}"
        );
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_subscriber_rejects_missing_keyexpr() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        // mapping_id = 0 + suffix = None → no keyexpr at all.
        let err = actions
            .send_declare_subscriber(1, 0, None)
            .expect_err("MissingKeyexpr");
        assert_eq!(err, SendDeclareError::MissingKeyexpr);
        assert_eq!(driver.frame_count(), 0);
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_subscriber_rejects_unknown_mapping_id() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        // mapping_id != 0 but no prior send_declare_keyexpr.
        let err = actions
            .send_declare_subscriber(1, 99, Some("/tail"))
            .expect_err("UnknownMappingId(99)");
        assert_eq!(err, SendDeclareError::UnknownMappingId(99));
        assert_eq!(driver.frame_count(), 0);
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_subscriber_rejects_cross_boundary_bug_three() {
        // This is the gate's raison d'etre: prefix=`**` registered
        // via send_declare_keyexpr, suffix=`/c/*` passed to
        // send_declare_subscriber — neither alone triggers bug #3,
        // but the reconstructed full keyexpr `**/c/*` does. A
        // suffix-only check would miss this.
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "**")
            .expect("prefix `**` is canonical + pico-safe in isolation");
        // 1 frame from the keyexpr declare; clear the count.
        let frames_before = driver.frame_count();
        assert_eq!(frames_before, 1);

        let err = actions
            .send_declare_subscriber(1, /*mapping_id=*/ 7, Some("/c/*"))
            .expect_err("reconstructed `**/c/*` must trigger bug #3 reject");
        match err {
            SendDeclareError::Keyexpr(
                crate::keyexpr_canon::OutboundKeyexprError::PicoBugThreeFamily { keyexpr, .. },
            ) => {
                assert_eq!(
                    keyexpr, "**/c/*",
                    "the gate must report the RECONSTRUCTED full keyexpr"
                );
            }
            other => panic!("expected cross-boundary PicoBugThreeFamily, got {other:?}"),
        }
        // No additional wire frame leaked — only the prior keyexpr
        // declare's frame is present.
        assert_eq!(driver.frame_count(), 1);
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_subscriber_accepts_safe_alias_form() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home")
            .expect("safe prefix");
        // Pure alias mode: mapping_id=7 + suffix=None → "home"
        actions
            .send_declare_subscriber(1, 7, None)
            .expect("alias to safe prefix");
        // Composite mode: mapping_id=7 + suffix=`/sensor` → "home/sensor"
        actions
            .send_declare_subscriber(2, 7, Some("/sensor"))
            .expect("composite to safe full keyexpr");
        // Literal mode: mapping_id=0 + suffix=Some("home/temp")
        actions
            .send_declare_subscriber(3, 0, Some("home/temp"))
            .expect("literal-mode safe keyexpr");
    }

    #[cfg(all(feature = "declare-queryable", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_queryable_inherits_gate() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        // Direct literal bug-three pattern.
        let err = actions
            .send_declare_queryable(1, 0, Some("**/foo/*"))
            .expect_err("queryable inherits the same gate");
        assert!(matches!(
            err,
            SendDeclareError::Keyexpr(
                crate::keyexpr_canon::OutboundKeyexprError::PicoBugThreeFamily { .. }
            )
        ));
        assert_eq!(driver.frame_count(), 0);
    }

    #[cfg(all(feature = "declare-token", feature = "declare-keyexpr"))]
    #[test]
    fn send_declare_token_inherits_gate() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let err = actions
            .send_declare_token(1, 0, Some("**/abc/*/def"))
            .expect_err("token inherits the same gate");
        assert!(matches!(
            err,
            SendDeclareError::Keyexpr(
                crate::keyexpr_canon::OutboundKeyexprError::PicoBugThreeFamily { .. }
            )
        ));
        assert_eq!(driver.frame_count(), 0);
    }

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn reconstruct_outbound_keyexpr_shape_table() {
        // `reconstruct_outbound_keyexpr` is a *private* method; the
        // crate-local `test_fixtures::recording_actions()` SSOT builds a
        // local-version `SessionLinkActions`, so the private call is in
        // scope here (the test-support sibling's copy would be the
        // dev-dependency cycle's second crate, out of scope — see the
        // `test_fixtures` module docs). The driver is unused (the test
        // reads the mapping table, never the wire).
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home")
            .expect("safe prefix registration");

        // (0, None) — protocol error
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(0, None),
            Err(SendDeclareError::MissingKeyexpr),
        );
        // (0, Some(s)) — literal mode
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(0, Some("a/b")),
            Ok("a/b".to_string()),
        );
        // (id, None) registered — pure alias
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(7, None),
            Ok("home".to_string()),
        );
        // (id, Some(tail)) registered — composite (no separator inj.)
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(7, Some("/sensor")),
            Ok("home/sensor".to_string()),
        );
        // (id, None) unregistered
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(99, None),
            Err(SendDeclareError::UnknownMappingId(99)),
        );
        // (id, Some(tail)) unregistered
        assert_eq!(
            actions.reconstruct_outbound_keyexpr(99, Some("/tail")),
            Err(SendDeclareError::UnknownMappingId(99)),
        );
    }

    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn resolve_outbound_mapping_returns_owned_string_independent_of_table() {
        // The returned String must be a clone — a caller holding it
        // across a later send_undeclare_kexpr must still see the
        // value they originally fetched. This pins the contract
        // that callers don't accidentally borrow the table slot.
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let resolved = actions.resolve_outbound_mapping(7).unwrap();
        actions.send_undeclare_kexpr(7);
        assert_eq!(resolved, "home/temp", "owned clone survives table mutation");
        assert!(actions.resolve_outbound_mapping(7).is_none());
    }

    // ── R240 wire-side QueryOptions propagation ──

    #[cfg(feature = "codec-request")]
    #[test]
    fn send_request_query_with_meta_empty_emits_same_bytes_as_no_meta() {
        // R240 short-circuit invariant: empty QueryMetadata MUST
        // produce the same wire frame as the no-metadata
        // send_request_query path so byte-stable callers (CI / fuzz
        // baselines) stay unchanged when QueryOptions::default() is
        // threaded through Session::query.
        let (actions_a, driver_a) = crate::test_fixtures::recording_actions();
        actions_a
            .send_request_query_with_meta(42, 0, Some("home/temp"), &QueryMetadata::default())
            .unwrap();
        let with_meta = driver_a.frame_bytes(0);

        let (actions_b, driver_b) = crate::test_fixtures::recording_actions();
        actions_b
            .send_request_query(42, 0, Some("home/temp"))
            .unwrap();
        let no_meta = driver_b.frame_bytes(0);

        assert_eq!(
            with_meta, no_meta,
            "empty QueryMetadata must produce byte-stable parity with the no-meta path"
        );
    }

    #[cfg(feature = "codec-request")]
    #[test]
    fn send_request_query_with_meta_target_emits_request_with_target_ext() {
        // build_request_query_with_target standalone re-encode
        // produces the same wire shape the action surface threads
        // when meta.target = Some(target). Pins the
        // QueryMetadata::target → RequestQueryBuilder::request_target
        // wiring.
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = QueryMetadata {
            target: Some(QueryTarget::All),
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        let standalone =
            build_request_query_with_target(42, 0, Some("home/temp"), QueryTarget::All).unwrap();
        let standalone_bytes = standalone.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-target Request bytes verbatim"
        );
    }

    #[cfg(feature = "codec-request")]
    #[test]
    fn send_request_query_with_meta_consolidation_emits_query_with_q_c_flag() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        let standalone = build_request_query_with_consolidation(
            42,
            0,
            Some("home/temp"),
            ConsolidationMode::Latest,
        )
        .unwrap();
        let standalone_bytes = standalone.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-consolidation Request bytes verbatim"
        );
    }

    #[cfg(all(feature = "codec-request", feature = "query-attachment"))]
    #[test]
    fn send_request_query_with_meta_attachment_emits_query_with_attachment_ext() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        let standalone =
            build_request_query_with_attachment(42, 0, Some("home/temp"), b"q-att").unwrap();
        let standalone_bytes = standalone.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-attachment Request bytes verbatim"
        );
    }

    #[cfg(all(feature = "codec-request", feature = "query-source-info"))]
    #[test]
    fn send_request_query_with_meta_source_info_emits_query_with_source_info_ext() {
        // The querier stamps its source-info on the outbound Query body
        // (ext 0x01 ZBUF). The meta-threading path and a standalone
        // RequestQueryBuilder::query_source_info build the same wire, so
        // the emitted frame must contain the standalone bytes verbatim.
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let si = wz_session_core::sample::SourceInfo::new(&[0xAA, 0xBB, 0xCC, 0xDD], 7, 42);
        let meta = QueryMetadata {
            source_info: Some(si.clone()),
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        let standalone = RequestQueryBuilder::new(42, 0, Some("home/temp"))
            .query_source_info(si)
            .build()
            .unwrap();
        let standalone_bytes = standalone.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-source-info Request bytes verbatim"
        );
    }

    #[cfg(all(feature = "codec-request", feature = "query-attachment"))]
    #[test]
    fn send_request_query_with_meta_empty_attachment_slice_skips_ext_without_panic() {
        // QueryOptions::with_attachment(empty Vec) → meta.attachment
        // = Some(empty) — RequestQueryBuilder::query_attachment
        // asserts non-empty, but the meta-threading path must guard
        // against the panic by skipping the attach call on an empty
        // inner slice. Wire frame ends up matching the
        // no-attachment shape.
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = QueryMetadata {
            attachment: Some(Vec::new()),
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        // No panic; frame ends up matching the no-meta baseline (meta
        // is not empty for is_empty() because attachment.is_some(),
        // but the wire emission elides the ext because the inner
        // slice is empty).
        let baseline = build_request_query(42, 0, Some("home/temp")).unwrap();
        let baseline_bytes = baseline.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(baseline_bytes.len())
                .any(|w| w == baseline_bytes),
            "empty-inner attachment must not change the wire bytes"
        );
    }

    #[cfg(feature = "codec-request")]
    #[test]
    fn send_request_query_with_meta_timeout_ms_emits_request_with_timeout_ext() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let meta = QueryMetadata {
            timeout_ms: 5_000,
            ..Default::default()
        };
        actions
            .send_request_query_with_meta(42, 0, Some("home/temp"), &meta)
            .unwrap();

        let standalone =
            build_request_query_with_timeout_ms(42, 0, Some("home/temp"), 5_000).unwrap();
        let standalone_bytes = standalone.wire();
        let frame = driver.frame_bytes(0);
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-timeout Request bytes verbatim"
        );
    }
}
