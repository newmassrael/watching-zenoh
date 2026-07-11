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
use crate::session_fsm_unicast::SessionFsmUnicastPolicy;
use wz_session_core::session_timeouts::HandshakeDeadlineTracker;
// Re-exported: `drive_session_until_terminal` takes `&SessionTimeouts`, so
// consumers that drive a session (wz-e2e-harness, wz-ap-demo) reach the
// type through this crate's session API without a direct wz-session-core dep.
pub use wz_session_core::session_timeouts::SessionTimeouts;

// chunk-5 — the outbound encoders that consumed CodecError / ExtZint /
// the `*Owned` codec mirrors (encode_init_with_role / encode_open_with_role
// / send_declare / send_response + the build_* helpers) moved with the
// `SessionLinkActions` impls to wz-session-core::session_actions, so those
// codec imports leave session_glue with them. The remaining session_glue
// surface (drive loop + lease/reassembly helpers + new_session_engine) does
// not name the codec owned types directly.
// `SessionRuntime` (imported below) extends `wz_runtime_core::Runtime`, so
// the `R::new_mutex` / `R::with_mutex_mut` calls in the generic
// `SessionLinkActions` impls resolve through the supertrait — no direct
// `Runtime` import is needed once the concrete `new` (Stage 2c) delegates
// to `new_generic` and stops calling `TokioRuntime::new_mutex` directly.
use wz_runtime_core::TimeSource;

use crate::runtime_impl::{TokioRuntime, TokioTime};

use crate::{LinkDriver, Reliability, TxFrame};

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

/// R3b — draw a fresh usrpwd challenge nonce from OS-backed cryptographic
/// entropy. The wz mirror of zenoh drawing `prng.gen::<u64>()` per accepted
/// handshake in usrpwd `StateAccept::new` (its `PseudoRng` is OS-entropy seeded
/// at transport-manager build). Pulls 8 bytes from `getrandom` (the same source
/// as `signing_key_from_os_entropy`) and little-endian-decodes them to a `u64`.
///
/// The no_std session core cannot draw entropy (`getrandom` has no bare-metal
/// backend), so the AP accept path draws the nonce here and supplies it to the
/// responder method via `SessionLinkActions::refresh_auth_challenge_nonce`. A
/// FRESH nonce per accepted handshake is the usrpwd replay defense — a reused
/// nonce lets a captured OpenSyn `{user, hmac}` replay against the responder.
/// The fallible surface returns `getrandom::Error` for the same
/// sandbox-without-entropy reason as the signing-key draw.
#[cfg(feature = "session-extauth")]
pub fn nonce_from_os_entropy() -> Result<u64, getrandom::Error> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
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
// Re-exported alongside `SessionInitParams` so a caller naming the param
// bundle also names its `whatami` field type from one place.
pub use wz_session_core::WhatAmI;

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
// chunk-5 — `SessionRuntime` (the runtime-tier extension owning `R::LinkSink`)
// is named only by the `SessionLinkActions` impls, which moved to
// wz-session-core::session_actions; the import left session_glue with them.

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

// chunk-5 — the SessionLinkActions bundle + SessionActionsBinding newtype
// + the default Init patch-ext seed moved to
// wz-session-core::session_actions (the runtime-agnostic struct + every
// inherent impl + the engine-free SessionFsmUnicastActions trait impl), so
// the lwIP MCU profile composes the same session machinery. Re-exported so
// the crate::session_glue::{SessionLinkActions, SessionActionsBinding,
// default_init_patch_ext_entry} callsites (session.rs, session_open.rs,
// new_session_engine below, wz-ap-demo, the test fixtures) resolve
// unchanged. The concrete R = TokioRuntime constructor
// (new_session_actions) + the Engine-bound new_session_engine factory stay
// below (AP-only — they name tokio / sce-rust-runtime types).
pub use wz_session_core::session_actions::default_init_patch_ext_entry;
// chunk-5 — re-aliased with the AP default type params restored. The
// session-core struct dropped its `= TokioRuntime` / `= TokioTime` defaults
// (those names are foreign to the no_std core), so the AP shell
// re-introduces them here; every `crate::session_glue::SessionLinkActions`
// / `SessionActionsBinding` usage stays turbofish-free across the reorg.
pub type SessionLinkActions<R = TokioRuntime, T = TokioTime> =
    wz_session_core::session_actions::SessionLinkActions<R, T>;
pub type SessionActionsBinding<R = TokioRuntime, T = TokioTime> =
    wz_session_core::session_actions::SessionActionsBinding<R, T>;

// R311eg — PeerInitCaps + its from_init_body decoder moved to
// wz-session-core::peer_init_caps (pure no_std/no_alloc; the decoder is
// feature-independent since R311kl). Re-exported so the
// `crate::session_glue::PeerInitCaps` callsites (the
// inbound_peer_init_caps slot, the InitSyn dispatch arm, and the
// session_fsm_accepting_path tests) resolve unchanged. The live
// `R::Mutex<Option<PeerInitCaps>>` slot stays below (runtime-bound). DP3 leaf.
pub use wz_session_core::peer_init_caps::PeerInitCaps;

/// chunk-5 — concrete `R = TokioRuntime` constructor for the session action
/// bundle. The struct + its generic `new_generic` factory now live in
/// `wz-session-core::session_actions`; an inherent `impl
/// SessionLinkActions<TokioRuntime, _>` cannot sit in this crate (orphan
/// rule — the type is foreign here), so the former `SessionLinkActions::new`
/// inherent method is demoted to this free fn (mirrors the
/// `signing_key_from_os_entropy` demotion at R311ei).
///
/// Production AP callers + the test fixtures call
/// `new_session_actions(driver, params, clock)`; a generic-`R` profile (the
/// lwIP MCU) calls `SessionLinkActions::new_generic` directly. `driver` is
/// the tokio `R::LinkSink` (`Arc<dyn BoxedLinkDriver + Send + Sync>`);
/// `clock` is the shared monotonic clock (R263 + R294) that
/// `drive_session_until_terminal` also receives, so the lease comparator's
/// `now_ms` and the recorded `keepalive_ms` / `established_ms` share an epoch.
pub fn new_session_actions<T: TimeSource>(
    driver: Arc<dyn BoxedLinkDriver + Send + Sync>,
    params: SessionInitParams,
    clock: T,
) -> Arc<SessionLinkActions<TokioRuntime, T>> {
    // R311ja — annotate `R = TokioRuntime` explicitly: `new_generic` now
    // returns the non-injective `R::ActionsHandle<T>` (this profile's `Arc`),
    // so neither the `Arc<dyn _>` driver arg nor the declared return type can
    // back-infer `R` the way the former `Arc<Self>` return did.
    SessionLinkActions::<TokioRuntime, T>::new_generic(driver, params, clock)
}

/// Build a production session engine: an [`Engine`] over the generated
/// engine-free [`crate::session_fsm_unicast::SessionFsmUnicastPolicy`],
/// parameterised over a [`SessionActionsBinding`] wrapping a clone of
/// `actions`. The caller retains `actions` (to read trace / observe link
/// state) and drives the engine with [`drive_session_until_terminal`].
/// Mirrors [`crate::scouting_glue::new_scouting_engine`].
///
/// Stage 4b — the construction body moved to the runtime-agnostic
/// [`wz_session_core::drive::new_session_engine`] so the AP profile + the
/// lwIP MCU sync loop build the FSM engine through one SSOT; this concrete
/// `R = TokioRuntime` entry delegates (the engine return type fixes `R`, no
/// call-site ambiguity).
pub fn new_session_engine<T: TimeSource>(
    actions: &Arc<SessionLinkActions<TokioRuntime, T>>,
) -> Engine<SessionFsmUnicastPolicy<SessionActionsBinding<TokioRuntime, T>>> {
    wz_session_core::drive::new_session_engine(actions)
}

// ─────────────────────────── codec wiring ───────────────────────────

// chunk-5 — the encode_init / encode_open / encode_close handshake
// encoders are consumed only by the wire-emit action bodies, which moved
// to wz-session-core::session_actions; their `use` left session_glue with
// them. The `pub use` re-exports below stay (public API surface for the
// crate::session_glue::* builder paths external callers + tests still name).

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
/// | `parameters`       | [`RequestQueryBuilder::parameters`] |
/// | `source_info`      | [`RequestQueryBuilder::query_source_info`] |
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

// Stage 3 — the synchronous dispatch core of `poll_and_dispatch_one` lives in
// wz-session-core so the lwIP MCU loop shares it; the AP async wrapper calls it
// after the one `.await`.
use wz_session_core::drive::dispatch_link_event;

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
    // Stage 3 — the synchronous dispatch core is the runtime-agnostic
    // `wz_session_core::drive::dispatch_link_event`; this AP wrapper keeps only
    // the one `.await` (the `D: LinkDriver` poll) the no_std core cannot host.
    dispatch_link_event(driver.poll_event().await, actions, engine)
}

// R311di-7 — LeaseCheckOutcome moved to wz-session-core::lease.
pub use wz_session_core::lease::LeaseCheckOutcome;

// Stage 4b — check_lease_deadline hoisted to the runtime-agnostic
// wz_session_core::drive (generic over R: SessionRuntime, reading the two
// baseline stamps through R::with_mutex_mut) so the AP tokio loop and the
// lwIP MCU sync loop share one lease comparator. Re-exported so
// drive_session_until_terminal + the callsite tests keep the bare name; a
// `&Arc<SessionLinkActions>` argument deref-coerces to the generic's
// `&SessionLinkActions<R, T>` parameter (same pattern as the already-shared
// report_outcome_reassembling).
pub use wz_session_core::drive::check_lease_deadline;

// R311kx — loop wake-deadline SSOT + keepalive TX emitter check. The
// wake helpers live beside the comparators in wz-session-core::drive so
// "the wake fired" and "the window elapsed" share one arithmetic; the
// keepalive pair is transport-keepalive-gated at the producer while the
// IterationEvent::KeepAlive observer variant stays ungated.
pub use wz_session_core::drive::lease_wake_deadline;
#[cfg(feature = "transport-keepalive")]
pub use wz_session_core::drive::{check_keepalive_deadline, keepalive_wake_deadline};
pub use wz_session_core::lease::KeepAliveCheckOutcome;

// R83 / R311di-12 — IterationEvent extracted to
// wz-session-core::driver_loop. Re-exported here for callsites in
// declare/* IterationEvent adapters + drive_session test closures.
pub use wz_session_core::driver_loop::IterationEvent;

// Stage 4b — DriverOutcome hoisted to wz_session_core::driver_loop so the
// AP drive_session_until_terminal + the lwIP MCU run_session share one
// terminal-result SSOT. Re-exported so this crate's callers keep the bare name.
pub use wz_session_core::driver_loop::DriverOutcome;

// ── R311im — reassembly pool wiring for the steady-state drive loop ──

// R311mk — the `TokioReassembly` Router type + `reassembly_config` were
// hoisted to the transport-agnostic `crate::reassembly` SSOT module so a
// `transport-multicast`-only build (no `transport-unicast`, hence no
// `session_glue`) can still reach the AP pool config. The unicast drive loop
// below imports them back under their bare names.
#[cfg(feature = "reassembly")]
use crate::reassembly::{reassembly_config, TokioReassembly};
// Stage 3 — the reassembly-pool ingest + completion re-parse is the
// const-generic `wz_session_core::drive::report_outcome_reassembling`; the AP
// drive loop passes its `TokioReassembly` dims (the `Fragment` type is now
// named only inside that shared helper).
#[cfg(feature = "reassembly")]
use wz_session_core::drive::report_outcome_reassembling;
// R311mh — sweep_reporting moved drive -> reassembly_dispatch (pure reassembly
// helper, not a unicast-drive one).
#[cfg(feature = "reassembly")]
use wz_session_core::reassembly_dispatch::sweep_reporting;

/// R76b — production driver loop. Composes `poll_and_dispatch_one`
/// (one LinkEvent per iteration) with a `tokio::select!` race
/// against a lease-deadline `tokio::time::sleep` so a peer that
/// stops sending KeepAlives reaches the `lease.expired -> Closing`
/// transition without the driver poll blocking indefinitely.
///
/// Each iteration:
///   1. Returns `Terminated` if `engine.is_in_final_state()` already.
///   2. Returns `IterationLimit` if `max_iters` is exhausted.
///   3. Reads `last_inbound_at`. If `Some(stamp)`, computes
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
        // iterates well within the reassembly window. `sweep_reporting` (the
        // shared SSOT with the MCU loop) raises a `ReassemblyTimeout` event
        // when an eviction occurs so the observer sees it.
        #[cfg(feature = "reassembly")]
        sweep_reporting(&mut reasm, clock.now_monotonic_ms(), &mut on_event);
        // This iteration's deadline. During the handshake phases the
        // tracker yields the host-owned handshake deadline; in Established
        // it disarms and the earlier of the lease-expiry deadline and the
        // keepalive TX deadline applies (R311kx — both via the
        // wz-session-core::drive wake helpers, so the arming shares the
        // comparators' arithmetic: baseline max(established_at, any-RX
        // `last_inbound_at` — R311la pico `_received` parity) + the
        // adopted min(local, peer) window; the prior arming read the
        // inbound stamp alone with the local window, so a silent peer
        // left the loop blocked on the link poll forever); in Init /
        // between there is none (block on
        // the link poll). `Some((abs_ms, Some(event)))` = handshake
        // timeout to raise; `Some((abs_ms, None))` = lease / keepalive
        // deadline (-> run both checks, each self-guarded).
        let deadline: Option<(
            u64,
            Option<crate::session_fsm_unicast::SessionFsmUnicastEvent>,
        )> = match deadline_tracker.poll(engine.get_current_state(), clock.now_monotonic_ms()) {
            Some((deadline_ms, event)) => Some((deadline_ms, Some(event))),
            None => {
                let lease_dl = lease_wake_deadline(actions);
                #[cfg(feature = "transport-keepalive")]
                let ka_dl = keepalive_wake_deadline(actions);
                #[cfg(not(feature = "transport-keepalive"))]
                let ka_dl: Option<u64> = None;
                match (lease_dl, ka_dl) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, None) => a,
                    (None, b) => b,
                }
                .map(|d| (d, None))
            }
        };
        match deadline {
            Some((deadline_ms, kind)) => {
                let now_ms = clock.now_monotonic_ms();
                let remaining_ms = deadline_ms.saturating_sub(now_ms);
                tokio::select! {
                    outcome = poll_and_dispatch_one(driver, actions, engine) => {
                        // §5.21 routing-namespace — strip the DIRECT decoded
                        // FramePayload before dispatch. Covers BOTH the
                        // reassembly-on path (where `report_outcome_reassembling`
                        // re-forwards this same `&outcome` for a whole frame) and
                        // the reassembly-off direct `on_event`; a fragment is not
                        // a FramePayload, so this is a no-op for it and its
                        // reassembled completion is stripped inside
                        // `report_outcome_reassembling` instead.
                        #[cfg(feature = "routing-namespace")]
                        let mut outcome = outcome;
                        #[cfg(feature = "routing-namespace")]
                        actions.apply_namespace_ingress(&mut outcome);
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
                        // Established lease / keepalive deadline. Both
                        // checks are deadline-self-guarded, so whichever
                        // armed the earlier wake fires and the other
                        // reports its within-window verdict truthfully
                        // (R311kx — the keepalive emit runs first: it is
                        // wire-side only and must not be starved by an
                        // Expired transition tearing the session down in
                        // the same wake).
                        None => {
                            #[cfg(feature = "transport-keepalive")]
                            {
                                let ka_outcome = check_keepalive_deadline(
                                    actions,
                                    clock.now_monotonic_ms(),
                                );
                                on_event(IterationEvent::KeepAlive(ka_outcome));
                            }
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
                // §5.21 routing-namespace — strip the DIRECT decoded FramePayload
                // before dispatch (the no-deadline arm; same rationale as the
                // `tokio::select!` poll arm above).
                #[cfg(feature = "routing-namespace")]
                let mut outcome = outcome;
                #[cfg(feature = "routing-namespace")]
                actions.apply_namespace_ingress(&mut outcome);
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
    /// `params.initial_sn` and walks the ring of the passed mask one
    /// step per call. This pairs the SN seed contract with the
    /// increment contract so a regression on either side (off-by-one
    /// seed, wrong stride) fires loud.
    #[test]
    fn next_outbound_frame_sn_seeds_at_initial_sn_then_increments() {
        // The SN counter seeds from initial_sn; the driver is unused
        // (we only read the counter), so the `recording_actions_with_params`
        // SSOT driver discards the never-emitted frames.
        let mask = wz_session_core::sn::mask_from_res(0x02);
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 42;
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            42,
            "first SN must equal params.initial_sn"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            43,
            "subsequent SNs must increment by 1"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            44
        );
    }

    /// R311kb — the mint wraps at the ring seam: an `initial_sn` at the
    /// top of a 7-bit ring is followed by 0, not `mask + 1` (zenoh-pico
    /// `_z_sn_increment` parity; the R121e explicit-modulo carry).
    #[test]
    fn next_outbound_frame_sn_wraps_at_ring_seam() {
        let mask = wz_session_core::sn::mask_from_res(0x00); // 7-bit ring
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = mask;
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            mask
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            0,
            "the mint must wrap mask -> 0 on the negotiated ring"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            1
        );
    }

    /// R311y214 — the reliable and best-effort channels are INDEPENDENT
    /// rings, each seeded from `params.initial_sn` (pico
    /// `_sn_tx_reliable` / `_sn_tx_best_effort` split, `common/tx.c:52-59`).
    /// A best-effort mint must NOT advance the reliable channel and vice
    /// versa — the prior single shared counter failed this (a best-effort
    /// Frame bumped the reliable SN, leaving a gap the peer's per-channel
    /// gate merely tolerated). This is the divergence slice-0 closes and
    /// the property the R311y215 per-priority conduits generalize.
    #[test]
    fn outbound_frame_sn_splits_reliable_and_best_effort_channels() {
        let mask = wz_session_core::sn::mask_from_res(0x02);
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 42;
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);

        // Both channels start at the announced origin.
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            42,
            "reliable #1"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, false, mask),
            42,
            "best-effort #1 is independent — starts at initial_sn, not 43"
        );
        // Interleave: each channel advances only itself.
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            43,
            "reliable #2"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            44,
            "reliable #3"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, false, mask),
            43,
            "best-effort #2 — a best-effort mint never advanced the reliable ring"
        );
    }

    /// R311y215 — the `is_qos` transport capability negotiates by AND of both
    /// sides (zenoh "either side NoQoS -> NoQoS"): a local offer ANDed with the
    /// peer's Init `ext_qos` offer. And it is mutually exclusive with
    /// `is_lowlatency` (zenoh `manager.rs:264`): a QoS offer staged after a
    /// lowlatency offer is refused at the offer-injection seam.
    ///
    /// R311y216 — the exclusivity is now SYMMETRIC and TOTAL (matching zenoh's
    /// order-independent `bail!`): the reciprocal guard also refuses a lowlatency
    /// offer staged after a QoS offer, so the both-on state is unrepresentable in
    /// EITHER staging order (first-staged wins).
    #[cfg(feature = "transport-qos")]
    #[test]
    fn is_qos_negotiates_by_and_and_is_lowlatency_exclusive() {
        let params = wz_runtime_tokio_test_support::fixture_session_init_params();
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
        assert!(!actions.is_qos(), "default: QoS not offered");
        assert!(actions.set_qos_offer(true), "offer applied");
        actions.negotiate_qos_against_peer(true);
        assert!(actions.is_qos(), "both sides QoS -> is_qos");
        actions.negotiate_qos_against_peer(false);
        assert!(
            !actions.is_qos(),
            "either side NoQoS -> NoQoS (the &= fold)"
        );

        // Exclusivity: a lowlatency offer refuses a later QoS offer.
        #[cfg(feature = "transport-lowlatency")]
        {
            let p2 = wz_runtime_tokio_test_support::fixture_session_init_params();
            let (a2, _d2) = crate::test_fixtures::recording_actions_with_params(p2);
            a2.set_lowlatency_offer(true);
            assert!(
                !a2.set_qos_offer(true),
                "is_qos && is_lowlatency incompatible -> the QoS offer is refused"
            );
            assert!(!a2.is_qos(), "the refused QoS offer left is_qos false");

            // R311y216 — the reciprocal direction: a QoS offer refuses a later
            // lowlatency offer, so the both-on state is unrepresentable in either
            // staging order (first-staged wins).
            let p3 = wz_runtime_tokio_test_support::fixture_session_init_params();
            let (a3, _d3) = crate::test_fixtures::recording_actions_with_params(p3);
            assert!(a3.set_qos_offer(true), "qos offer applies on fresh actions");
            assert!(
                !a3.set_lowlatency_offer(true),
                "is_lowlatency && is_qos incompatible -> the lowlatency offer is refused"
            );
            assert!(
                !a3.is_lowlatency(),
                "the refused lowlatency offer left is_lowlatency false"
            );
            assert!(a3.is_qos(), "the QoS offer (staged first) wins");
        }
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
            actions.send_declare_queryable(1, 0, Some("home/temp"), false),
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

    /// R311jp — with `transport-batching` OFF, the signature-stable batch
    /// window controls must fail-fast with the typed
    /// `SendWireError::FeatureDisabled` reject (no silent falsely-Ok window
    /// that would buffer nothing). Rides the C1j subset lanes — the
    /// coherent-subset base omits `transport-batching`.
    #[cfg(not(feature = "transport-batching"))]
    #[test]
    fn batch_controls_reject_with_feature_disabled_when_transport_batching_off() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        assert_eq!(
            actions.batch_start(),
            Err(SendWireError::FeatureDisabled),
            "transport-batching OFF: batch_start must return the typed reject"
        );
        assert_eq!(actions.batch_flush(), Err(SendWireError::FeatureDisabled));
        assert_eq!(actions.batch_stop(), Err(SendWireError::FeatureDisabled));
        assert_eq!(
            driver.frame_count(),
            0,
            "transport-batching OFF: the typed rejects must leave no wire bytes"
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
            .send_declare_queryable(1, 0, Some("**/foo/*"), false)
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

/// R311jm — TX-side fragmentation end-to-end: a publisher PUT whose serialized
/// FRAME exceeds the negotiated `batch_size` (MTU) is split into a
/// `T_MID_FRAGMENT` chain by the action layer (`dispatch_frame_or_fragment`),
/// and that chain reassembles — through the same `parse_inbound` +
/// `ReassemblyDispatcher` the AP drive loop runs — back to the byte-identical
/// network-message body a single (non-fragmented) PUT produces. The TX
/// counterpart of `tests/layer3_reassembly_rx.rs` (which proved the RX half),
/// closing zenoh-pico `_z_transport_tx_send_fragment` parity for the AP push
/// data plane.
#[cfg(all(test, feature = "transport-fragmentation", feature = "codec-push"))]
mod fragment_tx_tests {
    use super::{parse_inbound, InboundFrame, SessionInitParams};
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_core::reassembly_dispatch::{Fragment, ReassemblyConfig, ReassemblyDispatcher};

    #[test]
    fn oversize_push_fragments_and_reassembles_to_single_frame_body() {
        let mtu = 64u16;
        let keyexpr = "home/sensor/bulk";
        // 200 bytes: well over the 64-byte MTU, within the MsgPut payload
        // codec bound (`msg_put.scxml` max-size = 256).
        let value: Vec<u8> = (0..200u32).map(|i| (i * 3) as u8).collect();

        // Oversize send: a small negotiated batch_size forces fragmentation of
        // the ~200-byte PUT.
        let frag_params = SessionInitParams {
            batch_size: mtu,
            ..fixture_session_init_params()
        };
        let (actions, driver) = crate::test_fixtures::recording_actions_with_params(frag_params);
        actions
            .send_push_literal(keyexpr, &value, /*reliable=*/ true)
            .expect("send oversize push");

        let n = driver.frame_count();
        assert!(n > 1, "an oversize PUT must fragment, got {n} frame(s)");

        // Every emitted frame is a FRAGMENT within the MTU; reassemble through
        // the real RX path and check the SN/M-flag invariants the dispatcher
        // relies on.
        let mut reasm: ReassemblyDispatcher<4, 4096> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        let zid: &[u8] = &[0x09; 16];
        let mut reassembled: Option<Vec<u8>> = None;
        let mut prev_sn: Option<u64> = None;
        for i in 0..n {
            let frame = driver.frame_bytes(i);
            assert!(
                frame.len() <= mtu as usize,
                "fragment {i} is {} bytes, exceeds MTU {mtu}",
                frame.len()
            );
            let InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                ..
            } = parse_inbound(&frame).expect("parse emitted fragment")
            else {
                panic!("emitted frame {i} is not a Fragment");
            };
            assert!(reliable, "a reliable PUT keeps the R bit on every fragment");
            if let Some(p) = prev_sn {
                assert_eq!(sn, p + 1, "fragment SNs must be consecutive");
            }
            prev_sn = Some(sn);
            assert_eq!(
                more,
                i + 1 != n,
                "M (more) is set on every fragment but the final one",
            );
            reasm.ingest(
                Fragment {
                    peer_key: zid,
                    reliable,
                    sn,
                    more: u8::from(more),
                    payload: &payload,
                    priority: wz_session_core::qos::Priority::DEFAULT,
                },
                wz_session_core::sn::mask_from_res(0x02),
                0,
                |msg| reassembled = Some(msg.to_vec()),
            );
        }
        let reassembled = reassembled.expect("the fragment chain completes");

        // Reference: the same PUT with the default MTU is a single FRAME; its
        // body (after the 1-byte header + 1-byte VLE sn=0) is the serialized
        // Push the fragments must reproduce byte-for-byte.
        let ref_params = SessionInitParams {
            batch_size: 0,
            ..fixture_session_init_params()
        };
        let (ref_actions, ref_driver) =
            crate::test_fixtures::recording_actions_with_params(ref_params);
        ref_actions
            .send_push_literal(keyexpr, &value, true)
            .expect("send reference push");
        assert_eq!(
            ref_driver.frame_count(),
            1,
            "the default-MTU PUT must be a single frame"
        );
        let single = ref_driver.frame_bytes(0);
        assert_eq!(single[1], 0x00, "fixture initial_sn = 0 -> 1-byte VLE sn");
        let expected_body = single[2..].to_vec();

        assert_eq!(
            reassembled, expected_body,
            "reassembled fragments must reproduce the non-fragmented Push body byte-for-byte",
        );
    }
}

/// R311kf — TX serialization parity: SN mint order == wire order under
/// concurrent senders. pico holds its TX mutex across mint + write
/// (common/tx.c:273-305); wz's `tx_mutex` (R311km name) covers the immediate
/// path's mint + emit too, so the recorded wire SN sequence of N
/// concurrent frame-per-message sends is exactly the mint sequence. Any
/// regression that re-opens the mint→emit window surfaces here as an
/// out-of-order SN (a peer's half-window RX gate would drop that frame).
#[cfg(all(test, feature = "codec-push", feature = "codec-frame"))]
mod tx_order_tests {
    use super::{parse_inbound, InboundFrame};
    use wz_runtime_tokio_test_support::fixture_session_init_params;

    #[test]
    fn concurrent_sends_keep_mint_order_on_the_wire() {
        // 4 threads x 25 sends = 100 frames, inside the fixture's 7-bit
        // ring (seq_num_res=0 -> mask 127), so the expected wire sequence
        // is exactly 0..100 with no wrap arithmetic.
        let (actions, driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..25 {
                        actions
                            .send_push_literal("home/t", b"v", /*reliable=*/ true)
                            .expect("send");
                    }
                });
            }
        });
        assert_eq!(driver.frame_count(), 100);
        let mut sns = Vec::with_capacity(100);
        for i in 0..100 {
            let bytes = driver.frame_bytes(i);
            let InboundFrame::Frame { sn, .. } =
                parse_inbound(&bytes).expect("parse emitted frame")
            else {
                panic!("frame {i} is not a T_MID_FRAME");
            };
            sns.push(sn);
        }
        let expected: Vec<u64> = (0..100).collect();
        assert_eq!(
            sns, expected,
            "wire SN order must equal mint order (single mint+emit lock hold)"
        );
    }
}

/// R311kd — negotiated-min MTU: the outbound frame budget is
/// `min(own batch_size, peer-advertised batch_size)` with `0` as the
/// unset/65535 sentinel on either side (zenoh-pico sizes its TX wbuf to
/// `min(link MTU, negotiated batch_size)`, unicast/transport.c:47-49 —
/// the R311jm "honor the peer's advertised batch_size" carry).
/// Feature-independent since R311kl (the peer projection honors the
/// advertisement in every build); `codec-init-body` is needed to
/// capture the caps off a crafted InitAck through the production
/// `handle_inbound` path.
#[cfg(all(test, feature = "codec-init-body"))]
mod negotiated_mtu_tests {
    use super::SessionInitParams;
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    #[test]
    fn negotiated_batch_mtu_takes_min_of_own_and_peer() {
        let params = SessionInitParams {
            batch_size: 1024,
            ..fixture_session_init_params()
        };
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
        assert_eq!(
            actions.negotiated_batch_mtu(),
            1024,
            "no peer caps yet -> own advertisement"
        );
        // Peer InitAck advertises 512 — a conforming reduction (< own 1024).
        let wire = craft_initack_wire_with_caps(&[0xC0], 0x00, 512);
        actions.handle_inbound(&wire).expect("parse InitAck");
        assert_eq!(
            actions.negotiated_batch_mtu(),
            512,
            "peer reduction must bound the TX budget (negotiated min)"
        );
    }

    #[test]
    fn negotiated_batch_mtu_zero_is_unset_sentinel() {
        // Own unset (0) -> 65535 wire ceiling, not a zero budget.
        let (actions, _driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        assert_eq!(actions.negotiated_batch_mtu(), 65_535);
        // Peer 0 (an unconfigured wz peer advertises its params verbatim)
        // is the same sentinel: contributes the ceiling, not 0.
        let wire = craft_initack_wire_with_caps(&[0xC0], 0x00, 0);
        actions.handle_inbound(&wire).expect("parse InitAck");
        assert_eq!(
            actions.negotiated_batch_mtu(),
            65_535,
            "peer batch_size 0 = unset sentinel, not a zero budget"
        );
    }

    /// Behavioral: the peer's reduction — not the local advertisement —
    /// decides when a PUT fragments. Own side is unset (65535 ceiling);
    /// the peer's 64-byte budget must split the ~200-byte PUT into a
    /// fragment chain whose every frame fits the peer budget.
    #[cfg(all(feature = "transport-fragmentation", feature = "codec-push"))]
    #[test]
    fn peer_batch_reduction_fragments_oversize_put() {
        let (actions, driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        let wire = craft_initack_wire_with_caps(&[0xC0], 0x00, 64);
        actions.handle_inbound(&wire).expect("parse InitAck");

        let value: Vec<u8> = (0..200u32).map(|i| (i * 3) as u8).collect();
        actions
            .send_push_literal("home/sensor/bulk", &value, /*reliable=*/ true)
            .expect("send oversize push");

        let n = driver.frame_count();
        assert!(
            n > 1,
            "the peer's 64-byte budget must fragment the ~200-byte PUT, got {n} frame(s)"
        );
        for i in 0..n {
            assert!(
                driver.frame_bytes(i).len() <= 64,
                "fragment {i} exceeds the peer-advertised 64-byte budget"
            );
        }
    }
}

/// R311ke — unicast RX SN gate: handshake seeding + the reassembly
/// chain-clear a channel-gate rejection triggers. The half-window admit
/// logic itself is unit-tested in `wz_session_core::sn` (RxSn) and the
/// dispatcher wiring in `tests/session_fsm_driver_loop.rs`; these pin
/// the two stateful seams — OpenAck `initial_sn` seeds the gate through
/// the production `handle_inbound` path (peer.c:212-214 parity), and a
/// `RxSnRejected` outcome clears the channel's in-progress chain through
/// `report_outcome_reassembling` (rx.c dbuf-clear parity).
#[cfg(all(test, feature = "codec-open-body", feature = "codec-frame"))]
mod rx_sn_gate_tests {
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_wire_fixtures::craft_openack_wire;

    #[test]
    fn openack_initial_sn_seeds_rx_gate() {
        let (actions, _driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        actions
            .handle_inbound(&craft_openack_wire(5))
            .expect("parse OpenAck");
        assert!(
            !actions.admit_rx_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, 4),
            "a frame BEFORE the announced initial_sn is stale"
        );
        assert!(
            actions.admit_rx_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, 5),
            "the first frame at exactly initial_sn passes (decrement seed)"
        );
        assert!(
            !actions.admit_rx_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, 5),
            "and the duplicate of it is stale"
        );
        assert!(
            actions.admit_rx_frame_sn(wz_session_core::qos::Priority::DEFAULT, false, 5),
            "the best-effort channel was seeded too and gates independently"
        );
    }

    #[cfg(feature = "reassembly")]
    #[test]
    fn rx_sn_rejection_clears_in_progress_chain() {
        use wz_session_core::drive::report_outcome_reassembling;
        use wz_session_core::driver_loop::DriverLoopOutcome;
        use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};

        let (actions, _driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        let zid = vec![0x0A; 4];
        *actions.inbound_peer_zid.lock().unwrap() = Some(zid);

        let mut reasm: ReassemblyDispatcher<4, 4096> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
        let mut sink = |_e: wz_session_core::driver_loop::IterationEvent<'_>| {};

        // Begin a reliable chain (more=1) through the production helper.
        let begin = DriverLoopOutcome::Fragment {
            reliable: true,
            sn: 10,
            more: true,
            payload: vec![0x01],
            has_ext: false,
            extensions: Vec::new(),
            priority: wz_session_core::qos::Priority::DEFAULT,
        };
        report_outcome_reassembling(&begin, &mut reasm, &actions, 0, &mut sink);
        assert_eq!(reasm.active_chains(), 1, "chain armed");

        // A reliable-channel SN rejection clears it (pico dbuf-clear).
        let rejected = DriverLoopOutcome::RxSnRejected {
            reliable: true,
            sn: 9,
            priority: wz_session_core::qos::Priority::DEFAULT,
        };
        report_outcome_reassembling(&rejected, &mut reasm, &actions, 0, &mut sink);
        assert_eq!(
            reasm.active_chains(),
            0,
            "channel-gate rejection must clear the in-progress chain"
        );

        // A best-effort rejection leaves a reliable chain untouched.
        report_outcome_reassembling(&begin, &mut reasm, &actions, 0, &mut sink);
        let rejected_be = DriverLoopOutcome::RxSnRejected {
            reliable: false,
            sn: 9,
            priority: wz_session_core::qos::Priority::DEFAULT,
        };
        report_outcome_reassembling(&rejected_be, &mut reasm, &actions, 0, &mut sink);
        assert_eq!(
            reasm.active_chains(),
            1,
            "the clear is per-channel: best-effort rejection keeps the reliable chain"
        );
    }

    /// R311y221 — the unicast FRAGMENTED delivery preserves the chain's band
    /// end-to-end through the PRODUCTION caller (`report_outcome_reassembling` ->
    /// `reassembled_frame_outcome(*priority, ..)`, drive.rs), not just the leaf
    /// synthesizer in isolation. A two-fragment reliable chain at a non-DEFAULT
    /// band completes, and the synthesized whole-frame `FramePayload` must carry
    /// that band. Guards the exact wiring the leaf-only test cannot reach: a
    /// regression passing `Priority::DEFAULT` at the drive.rs call site would
    /// deliver a fragmented prioritized Put at DEFAULT while an un-fragmented one
    /// keeps its band, and this asserts against that.
    #[cfg(feature = "reassembly")]
    #[test]
    fn reassembly_caller_delivers_the_chain_band_end_to_end() {
        use std::cell::Cell;
        use wz_session_core::drive::report_outcome_reassembling;
        use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
        use wz_session_core::qos::Priority;
        use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};

        let (actions, _driver) =
            crate::test_fixtures::recording_actions_with_params(fixture_session_init_params());
        *actions.inbound_peer_zid.lock().unwrap() = Some(vec![0x0A; 4]);
        let mut reasm: ReassemblyDispatcher<4, 4096> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));

        // Capture the band of the whole-frame the PRODUCTION caller synthesizes
        // (Cell so the FnMut sink's borrow does not conflict with the read below).
        let delivered: Cell<Option<Priority>> = Cell::new(None);
        let mut sink = |e: IterationEvent<'_>| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { priority, .. }) = e {
                delivered.set(Some(*priority));
            }
        };

        // Two fragments (more=1 then more=0) reassemble to [0x00, 0xAA, 0xBB],
        // which parse_frame_payload accepts as one Unknown network record (the
        // R74 minimal-parse fixture) so the completion actually builds a
        // FramePayload. Both fragments ride the InteractiveHigh conduit.
        let f0 = DriverLoopOutcome::Fragment {
            reliable: true,
            sn: 20,
            more: true,
            payload: vec![0x00, 0xAA],
            has_ext: false,
            extensions: Vec::new(),
            priority: Priority::InteractiveHigh,
        };
        let f1 = DriverLoopOutcome::Fragment {
            reliable: true,
            sn: 21,
            more: false,
            payload: vec![0xBB],
            has_ext: false,
            extensions: Vec::new(),
            priority: Priority::InteractiveHigh,
        };
        report_outcome_reassembling(&f0, &mut reasm, &actions, 0, &mut sink);
        report_outcome_reassembling(&f1, &mut reasm, &actions, 0, &mut sink);

        assert_eq!(
            delivered.get(),
            Some(Priority::InteractiveHigh),
            "the reassembled whole-frame is delivered on the chain's band via the \
             drive.rs caller (report_outcome_reassembling), not DEFAULT"
        );
    }
}

/// R311jp — TX batching end-to-end: a `batch_start` window coalesces N
/// network messages into ONE outbound `T_MID_FRAME` (header + `VLE(sn)` + N
/// message bodies), bounded by the `batch_size` byte budget, drained by
/// `batch_flush` / `batch_stop` / overflow / express / pre-CLOSE. The TX
/// counterpart of the RX multi-message loop `parse_frame_payload` already
/// runs on every inbound frame — each test round-trips the emitted frame
/// through that same RX SSOT. zenoh-pico `Z_FEATURE_BATCHING` parity
/// (`zp_batch_start/flush/stop` + `src/transport/common/tx.c`).
#[cfg(all(
    test,
    feature = "transport-batching",
    feature = "codec-push",
    feature = "codec-frame"
))]
mod batch_tx_tests {
    use super::{parse_inbound, InboundFrame, SessionInitParams};
    use wz_codecs::wire_const;
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};

    /// Decode an emitted FRAME into its network-message list through the
    /// real RX path (`parse_inbound` + `parse_frame_payload`), returning
    /// `(sn, messages)`.
    fn decode_frame(frame: &[u8]) -> (u64, Vec<NetworkMessage>) {
        let InboundFrame::Frame { sn, payload, .. } =
            parse_inbound(frame).expect("parse emitted frame")
        else {
            panic!("emitted bytes are not a T_MID_FRAME");
        };
        let messages = parse_frame_payload(&payload).expect("parse frame payload");
        (sn, messages)
    }

    /// R311y222 — a batch frame is ONE (priority, reliability) conduit: a
    /// RELIABILITY change inside an open window flushes the open frame and
    /// reopens on the other reliability conduit, instead of absorbing a
    /// best-effort message into a reliable frame (or vice versa). This mod is
    /// gated on `transport-batching` but NOT `transport-qos`, so the assertion
    /// runs on a NON-QoS build too — the crux: the reliability conduit split is
    /// real without QoS (two Frame-SN rings), so the fix must be ungated. A
    /// deliberate wz divergence from zenoh-pico's blind mixed-reliability append,
    /// matching zenoh's per-frame reliability boundary.
    #[test]
    fn batch_reliability_change_flushes_open_frame() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.batch_start().expect("batch_start");

        // Open a RELIABLE frame in the window.
        actions
            .send_push_literal("home/batch", b"R", /*reliable=*/ true)
            .expect("reliable push opens the frame");
        assert_eq!(
            driver.frame_count(),
            0,
            "the reliable frame sits open in the batch window"
        );

        // A BEST-EFFORT message is a DIFFERENT (reliability) conduit — it must
        // flush the open reliable frame before opening its own, never ride it.
        actions
            .send_push_literal("home/batch", b"B", /*reliable=*/ false)
            .expect("best-effort push forces the reliability-change flush");
        assert_eq!(
            driver.frame_count(),
            1,
            "the reliability change flushed the open reliable frame (pre-y222 the \
             best-effort message was wrongly absorbed into the reliable frame)"
        );

        actions
            .batch_flush()
            .expect("batch_flush drains the open best-effort frame");
        assert_eq!(
            driver.frame_count(),
            2,
            "flush drains the open best-effort frame"
        );

        // Frame 0 is reliable (R flag set) + carries ONLY the reliable message;
        // frame 1 is best-effort (R clear) + carries ONLY the best-effort one.
        let f0 = driver.frame_bytes(0);
        let f1 = driver.frame_bytes(1);
        assert_ne!(
            f0[0] & wire_const::FLAG_T_FRAME_R,
            0,
            "frame 0 is the reliable frame (R set)"
        );
        assert_eq!(
            f1[0] & wire_const::FLAG_T_FRAME_R,
            0,
            "frame 1 is the best-effort frame (R clear)"
        );
        let (sn0, m0) = decode_frame(&f0);
        let (sn1, m1) = decode_frame(&f1);
        assert_eq!(
            m0.len(),
            1,
            "the best-effort message did NOT ride the reliable frame"
        );
        assert_eq!(
            m1.len(),
            1,
            "the best-effort frame carries only its own message"
        );
        // Each conduit's OWN SN ring seeds at the initial SN independently: if the
        // best-effort message had shared the reliable ring it would read sn=1.
        assert_eq!(sn0, 0, "reliable ring's first frame SN");
        assert_eq!(
            sn1, 0,
            "best-effort ring's first frame SN (independent ring)"
        );
    }

    /// Three batched PUTs coalesce into one frame whose body is the
    /// byte-exact concatenation of the three per-message frame bodies the
    /// unbatched path emits — and the RX loop yields all three messages.
    #[test]
    fn batched_pushes_coalesce_into_one_frame_with_concatenated_bodies() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.batch_start().expect("batch_start");
        for i in 0..3u8 {
            actions
                .send_push_literal("home/batch", &[i, i, i], /*reliable=*/ true)
                .expect("batched push");
        }
        assert_eq!(
            driver.frame_count(),
            0,
            "an open batch window must defer every wire emit"
        );
        actions.batch_flush().expect("batch_flush");
        assert_eq!(
            driver.frame_count(),
            1,
            "flush drains the window as exactly one frame"
        );

        let frame = driver.frame_bytes(0);
        let (sn, messages) = decode_frame(&frame);
        assert_eq!(sn, 0, "the frame keeps the OPENING message's SN");
        assert_eq!(messages.len(), 3, "RX loop must yield all batched messages");
        assert!(messages
            .iter()
            .all(|m| matches!(m, NetworkMessage::Push(_))));

        // Byte-exactness: the batched frame == the first unbatched frame +
        // the 2nd/3rd unbatched frames' bodies (header + VLE(sn) stripped;
        // fixture SNs 0..=2 are all 1-byte VLE).
        let (ref_actions, ref_driver) = crate::test_fixtures::recording_actions();
        for i in 0..3u8 {
            ref_actions
                .send_push_literal("home/batch", &[i, i, i], true)
                .expect("reference push");
        }
        assert_eq!(ref_driver.frame_count(), 3);
        let mut expected = ref_driver.frame_bytes(0);
        expected.extend_from_slice(&ref_driver.frame_bytes(1)[2..]);
        expected.extend_from_slice(&ref_driver.frame_bytes(2)[2..]);
        assert_eq!(
            frame, expected,
            "batched frame must be the unbatched frame + appended message bodies, byte-for-byte"
        );

        // R311jq pin — the 3-message batch consumed exactly ONE frame SN:
        // the next frame after the window is sn=1, gap-free (frame-scoped
        // SN; see batch_stop_drains_and_deactivates for the half-window
        // rationale).
        actions.batch_stop().expect("batch_stop");
        actions
            .send_push_literal("home/batch", b"after", true)
            .expect("post-window push");
        let (next_sn, _) = decode_frame(&driver.frame_bytes(1));
        assert_eq!(
            next_sn, 1,
            "a 3-message batch must consume exactly one frame SN"
        );
    }

    /// Overflow parity (`_z_transport_tx_batch_overflow`): when the next
    /// message would push the open frame past `batch_size`, the open frame
    /// flushes and the message re-opens a fresh frame — each emitted frame
    /// is byte-identical to its unbatched twin.
    #[test]
    fn batch_overflow_flushes_open_frame_and_reopens() {
        // Measure the single-PUT frame length first; budget exactly one.
        let (probe_actions, probe_driver) = crate::test_fixtures::recording_actions();
        probe_actions
            .send_push_literal("home/batch", &[0xAA; 8], true)
            .expect("probe push");
        let single_len = probe_driver.frame_bytes(0).len() as u16;

        let params = SessionInitParams {
            batch_size: single_len,
            ..fixture_session_init_params()
        };
        let (actions, driver) = crate::test_fixtures::recording_actions_with_params(params);
        actions.batch_start().expect("batch_start");
        actions
            .send_push_literal("home/batch", &[0xAA; 8], true)
            .expect("first push opens the frame");
        assert_eq!(driver.frame_count(), 0, "first message fits the budget");
        actions
            .send_push_literal("home/batch", &[0xAA; 8], true)
            .expect("second push overflows");
        assert_eq!(
            driver.frame_count(),
            1,
            "overflow must flush the open frame before re-opening"
        );
        actions.batch_stop().expect("batch_stop");
        assert_eq!(driver.frame_count(), 2, "stop drains the re-opened frame");

        for i in 0..2 {
            let (sn, messages) = decode_frame(&driver.frame_bytes(i));
            assert_eq!(messages.len(), 1, "each frame carries one message");
            assert_eq!(
                sn, i as u64,
                "frame SNs stay monotonic across the overflow re-open"
            );
        }
    }

    /// `batch_stop` drains AND deactivates: a send after stop flushes per
    /// message again (the pre-A3 behavior).
    #[test]
    fn batch_stop_drains_and_deactivates() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.batch_start().expect("batch_start");
        actions
            .send_push_literal("home/batch", b"a", true)
            .expect("batched push");
        actions.batch_stop().expect("batch_stop");
        assert_eq!(driver.frame_count(), 1, "stop drains the open frame");
        actions
            .send_push_literal("home/batch", b"b", true)
            .expect("direct push");
        assert_eq!(
            driver.frame_count(),
            2,
            "after stop, sends flush per message again"
        );
        // R311jq pin — SNs are FRAME-scoped: batching never burns an SN on
        // an appended message, so consecutive frames carry consecutive SNs
        // whatever the batch length. (The R311jp message-scoped mint left
        // gaps that could exceed the peer's `_z_sn_precedes` HALF-WINDOW —
        // zenoh-pico `src/transport/utils.c:80` — at small `seq_num_res`;
        // an equality assert here fires loud if per-message minting ever
        // creeps back.)
        let (sn0, _) = decode_frame(&driver.frame_bytes(0));
        let (sn1, _) = decode_frame(&driver.frame_bytes(1));
        assert_eq!(
            sn1,
            sn0 + 1,
            "frame SNs must be consecutive — appended messages mint no SN"
        );
    }

    /// Express parity (`_z_transport_tx_get_express_status` arm): an
    /// express-flagged publish is absorbed into the open frame and the
    /// whole frame flushes immediately.
    #[test]
    fn express_publish_flushes_the_open_batch_immediately() {
        use wz_session_core::metadata::PushMetadata;
        use wz_session_core::sample::QosLevel;

        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.batch_start().expect("batch_start");
        actions
            .send_push_literal("home/batch", b"plain", true)
            .expect("batched push");
        assert_eq!(driver.frame_count(), 0);

        let express_meta = PushMetadata {
            // `_Z_N_QOS_IS_EXPRESS_FLAG = 1 << 4` (zenoh-pico network.h:82).
            qos: Some(QosLevel::from_raw(1 << 4)),
            ..PushMetadata::default()
        };
        actions
            .send_push_with_meta_literal("home/batch", b"urgent", true, &express_meta)
            .expect("express push");
        assert_eq!(
            driver.frame_count(),
            1,
            "an express message drains the open frame immediately"
        );
        let (_, messages) = decode_frame(&driver.frame_bytes(0));
        assert_eq!(
            messages.len(),
            2,
            "the express message rides the same frame as the batched one"
        );
    }

    /// CLOSE pre-drain parity (`_z_transport_tx_send_t_msg_inner` flushes
    /// an active batch before any transport message): the batched data
    /// frame leaves BEFORE the CLOSE bytes.
    #[cfg(feature = "codec-close")]
    #[test]
    fn close_drains_the_open_batch_before_the_close_bytes() {
        use wz_session_core::close_reason::CloseReason;

        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.batch_start().expect("batch_start");
        actions
            .send_push_literal("home/batch", b"pending", true)
            .expect("batched push");
        actions.send_close_with_reason(CloseReason::Generic);
        assert_eq!(driver.frame_count(), 2, "open frame + CLOSE");
        assert_eq!(
            driver.frame_bytes(0)[0] & 0x1F,
            wire_const::T_MID_FRAME,
            "the batched data frame must leave first"
        );
        assert_eq!(
            driver.frame_bytes(1)[0] & 0x1F,
            wire_const::T_MID_CLOSE,
            "the CLOSE follows the drained batch"
        );
    }

    /// Oversize-while-batching parity (`tx.c` oversize fallback): the open
    /// frame drains first, then the oversize message takes the fragment
    /// path — wire order preserved.
    #[cfg(feature = "transport-fragmentation")]
    #[test]
    fn oversize_publish_drains_open_frame_then_fragments() {
        let params = SessionInitParams {
            batch_size: 64,
            ..fixture_session_init_params()
        };
        let (actions, driver) = crate::test_fixtures::recording_actions_with_params(params);
        actions.batch_start().expect("batch_start");
        actions
            .send_push_literal("home/batch", b"small", true)
            .expect("batched push");
        let oversize: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        actions
            .send_push_literal("home/batch", &oversize, true)
            .expect("oversize push");
        let n = driver.frame_count();
        assert!(n > 2, "open frame + a multi-chunk fragment chain, got {n}");
        assert_eq!(
            driver.frame_bytes(0)[0] & 0x1F,
            wire_const::T_MID_FRAME,
            "the drained batch frame must leave before the fragment chain"
        );
        for i in 1..n {
            assert_eq!(
                driver.frame_bytes(i)[0] & 0x1F,
                wire_const::T_MID_FRAGMENT,
                "every subsequent emit is a fragment chunk"
            );
        }
    }
}

/// A4 (session-reconnect) — declaration-cache + transport-replacement
/// behavioural guards. zenoh-pico `Z_FEATURE_AUTO_RECONNECT` parity at the
/// actions tier: declares append cache entries (`_z_cache_declaration`),
/// undeclares prune them (`_z_prune_declaration`), `reset_for_reopen`
/// clears exactly the handshake-scoped state (pico recreating
/// `_z_transport_t` while `_z_session_t` survives), and
/// `replay_declarations` re-emits the recorded entries byte-identically
/// onto the post-reset link (`_z_client_reopen_task_fn`'s cache walk). The
/// re-dial supervisor riding these seams is A4b.
#[cfg(all(
    test,
    feature = "session-reconnect",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "declare-undeclare",
    feature = "codec-push"
))]
mod reconnect_tx_tests {
    use std::sync::Arc;

    use wz_session_core::reconnect::{CachedDeclaration, SwappableLink};

    use crate::runtime_impl::TokioRuntime;

    /// F3 — the peer's `DeclFinal` terminating a liveliness get prunes
    /// exactly that get's cached Interest through the observer's
    /// `flush_pending` drain: a finished one-shot snapshot must not
    /// replay on reconnect (the requester never emits an interest-FINAL
    /// for a get, so this drain is the entry's only prune; zenoh-pico
    /// keeps the stale entry). A live subscriber Interest sharing the
    /// cache survives untouched.
    #[cfg(feature = "liveliness-get")]
    #[test]
    fn inbound_decl_final_prunes_cached_liveliness_get_interest() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::observer::ApplicationLayerObserver;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_interest_liveliness_subscriber(13, /*history=*/ false, 0, Some("home/liv"))
            .expect("liveliness subscriber interest");
        actions
            .send_interest_liveliness_get(14, 0, Some("home/get"))
            .expect("liveliness get interest");
        assert_eq!(
            actions.declaration_cache_snapshot().len(),
            2,
            "both Interest forms cached"
        );

        let finals = Arc::new(AtomicUsize::new(0));
        let mut observer = ApplicationLayerObserver::new();
        {
            let finals = finals.clone();
            observer
                .liveliness_gets
                .register_get(
                    14,
                    None,
                    |_reply| {},
                    move |_id| {
                        finals.fetch_add(1, Ordering::SeqCst);
                    },
                )
                .expect("register pending get");
        }

        // The peer's terminator arrives as a solicited Declare(DeclFinal)
        // tagged with the get's interest_id, inside a Frame payload.
        let declare = wz_codecs::declare::DeclareOwned {
            header: 0,
            interest_id: Some(14),
            extensions: None,
            body: wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclFinal(
                wz_codecs::decl_final::DeclFinal::default(),
            ),
        };
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        };
        observer.dispatch(IterationEvent::Poll(&outcome), &actions);

        assert_eq!(finals.load(Ordering::SeqCst), 1, "the get terminated");
        let cache = actions.declaration_cache_snapshot();
        assert_eq!(
            cache.len(),
            1,
            "the finished get's Interest is pruned from the replay cache"
        );
        assert!(
            matches!(
                cache[0],
                CachedDeclaration::LivelinessSubscriberInterest {
                    interest_id: 13,
                    ..
                }
            ),
            "the live subscriber Interest survives"
        );
    }

    /// Every cached-kind declare appends one entry in emit order; each
    /// matching undeclare prunes exactly its own entry (first-match,
    /// pico `_z_prune_declaration` filter semantics).
    #[test]
    fn declares_populate_and_undeclares_prune_the_cache() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/base")
            .expect("declare keyexpr");
        actions
            .send_declare_subscriber(10, 0, Some("home/sub"))
            .expect("declare subscriber");
        actions
            .send_declare_queryable(11, 0, Some("home/qry"), false)
            .expect("declare queryable");
        actions
            .send_declare_token(12, 0, Some("home/tok"))
            .expect("declare token");
        actions
            .send_interest_liveliness_subscriber(13, /*history=*/ false, 0, Some("home/liv"))
            .expect("liveliness subscriber interest");
        actions
            .send_interest_liveliness_get(14, 0, Some("home/get"))
            .expect("liveliness get interest");

        let cache = actions.declaration_cache_snapshot();
        assert_eq!(cache.len(), 6, "every cached-kind emit appends one entry");
        assert_eq!(
            cache[0],
            CachedDeclaration::Keyexpr {
                mapping_id: 7,
                suffix: "home/base".into()
            },
            "entries record in emit order (DeclKexpr first)"
        );

        // Prune one kind at a time; unrelated entries must survive.
        actions.send_undeclare_subscriber(10);
        assert_eq!(actions.declaration_cache_snapshot().len(), 5);
        actions.send_undeclare_queryable(11);
        actions.send_undeclare_token(12);
        actions.send_interest_final(13);
        actions.send_interest_final(14);
        let cache = actions.declaration_cache_snapshot();
        assert_eq!(
            cache,
            vec![CachedDeclaration::Keyexpr {
                mapping_id: 7,
                suffix: "home/base".into()
            }],
            "only the never-undeclared DeclKexpr entry survives"
        );
        actions.send_undeclare_kexpr(7);
        assert!(
            actions.declaration_cache_snapshot().is_empty(),
            "the final undeclare drains the cache"
        );

        // Unknown-id undeclare is a no-op prune (pico drop_first_filter
        // finding no match).
        actions.send_undeclare_subscriber(999);
        assert!(actions.declaration_cache_snapshot().is_empty());
    }

    /// R311up — a COMPLETE queryable stamps the QueryableInfo ext on the wire
    /// (the BestMatching producer signal) AND the reconnect-replay cache
    /// preserves the flag, so a complete queryable survives a reconnect without
    /// silently re-declaring as incomplete. An incomplete one OMITS the ext
    /// (DEFAULT, byte-identical to a plain declaration).
    #[test]
    fn a_complete_queryable_carries_completeness_on_the_wire_and_in_the_cache() {
        use super::{parse_inbound, InboundFrame};
        use wz_codecs::declare::DeclareOwnedVariant;
        use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
        use wz_session_core::queryable_info::read_queryable_info;

        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_queryable(11, 0, Some("home/qry"), true)
            .expect("complete queryable");
        actions
            .send_declare_queryable(12, 0, Some("home/inc"), false)
            .expect("incomplete queryable");

        let info_of = |frame: &[u8]| {
            let InboundFrame::Frame { payload, .. } =
                parse_inbound(frame).expect("parse emitted frame")
            else {
                panic!("emitted bytes are not a Frame");
            };
            match parse_frame_payload(&payload)
                .expect("parse payload")
                .first()
            {
                Some(NetworkMessage::Declare(d)) => match &d.body {
                    DeclareOwnedVariant::CodecZenohDeclQueryable(q) => {
                        read_queryable_info(q.extensions.as_ref())
                    }
                    _ => panic!("not a DeclareQueryable"),
                },
                other => panic!("expected a Declare, got {other:?}"),
            }
        };
        assert!(
            info_of(&driver.frame_bytes(0)).complete,
            "the complete queryable carries complete=true on the wire",
        );
        assert!(
            !info_of(&driver.frame_bytes(1)).complete,
            "the incomplete queryable omits the QueryableInfo ext (DEFAULT)",
        );

        // The reconnect-replay cache preserves each completeness.
        let cache = actions.declaration_cache_snapshot();
        assert!(
            cache.iter().any(|e| matches!(
                e,
                CachedDeclaration::Queryable {
                    queryable_id: 11,
                    complete: true,
                    ..
                }
            )),
            "the cached complete queryable preserves complete=true for replay",
        );
        assert!(
            cache.iter().any(|e| matches!(
                e,
                CachedDeclaration::Queryable {
                    queryable_id: 12,
                    complete: false,
                    ..
                }
            )),
            "the cached incomplete queryable preserves complete=false",
        );
    }

    /// `replay_declarations` after `reset_for_reopen` re-emits wire bytes
    /// byte-identical to the original declares: the SN re-seed makes the
    /// replayed frames repeat the original frame SNs, and the builders
    /// re-derive identical bodies from the cached argument tuples.
    #[test]
    fn replay_after_reset_re_emits_identical_wire_bytes() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/base")
            .expect("declare keyexpr");
        actions
            .send_declare_subscriber(10, 7, Some("/tail"))
            .expect("aliased subscriber declare");
        actions
            .send_interest_liveliness_subscriber(13, true, 0, Some("home/liv"))
            .expect("liveliness subscriber interest");
        let original: Vec<Vec<u8>> = (0..3).map(|i| driver.frame_bytes(i)).collect();

        actions.reset_for_reopen();
        // F2 — a send inside the post-reset window rejects typed: the
        // transport-availability gate stays closed until Established
        // re-entry (zenoh-pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE`).
        assert_eq!(
            actions.send_declare_keyexpr(8, "home/blocked"),
            Err(wz_session_core::send_declare_error::SendDeclareError::TransportUnavailable),
            "reconnect-window declare must reject, not silently vanish"
        );
        assert_eq!(
            actions.declaration_cache_snapshot().len(),
            3,
            "a rejected declare caches nothing"
        );
        // Simulate the re-handshake reaching Established (the supervisor
        // replays only after `drive_open_loop`; `record_established_at`
        // re-opens the gate) — direct-stamp idiom shared with
        // `reset_for_reopen_clears_handshake_scoped_state_only`.
        {
            use wz_runtime_core::Runtime;
            TokioRuntime::with_mutex_mut(&actions.link.transport_available, |g| *g = true);
        }
        let replayed = actions
            .replay_declarations()
            .expect("replay over validated cache entries cannot reject");
        assert_eq!(replayed, 3, "every cached entry replays");
        assert_eq!(driver.frame_count(), 6, "replay emits one frame per entry");
        for (i, expected) in original.iter().enumerate() {
            assert_eq!(
                &driver.frame_bytes(3 + i),
                expected,
                "replayed frame {i} must be byte-identical (same SN seed, \
                 same builder args, same alias order)"
            );
        }
        assert_eq!(
            actions.declaration_cache_snapshot().len(),
            3,
            "replay must not re-append (cache stays ready for the NEXT reconnect)"
        );
    }

    /// `reset_for_reopen` clears exactly the handshake-scoped state and
    /// preserves the session-scoped state (pico: new `_z_transport_t`,
    /// surviving `_z_session_t`).
    #[test]
    fn reset_for_reopen_clears_handshake_scoped_state_only() {
        use wz_runtime_core::Runtime;

        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions
            .send_declare_keyexpr(7, "home/base")
            .expect("declare keyexpr");

        // Stamp the handshake-scoped slots the open path would populate.
        TokioRuntime::with_mutex_mut(&actions.link.established_at, |slot| *slot = Some(42));
        TokioRuntime::with_mutex_mut(&actions.link.last_inbound_at, |slot| *slot = Some(43));
        TokioRuntime::with_mutex_mut(&actions.inbound_cookie, |slot| *slot = Some(vec![1, 2]));
        TokioRuntime::with_mutex_mut(&actions.inbound_peer_zid, |slot| *slot = Some(vec![9; 4]));
        assert!(actions.is_established());

        actions.reset_for_reopen();

        assert!(
            !actions.is_established(),
            "reset must drop Established so declare gates hold until re-handshake"
        );
        assert!(TokioRuntime::with_mutex_mut(
            &actions.link.last_inbound_at,
            |slot| slot.is_none()
        ));
        assert!(TokioRuntime::with_mutex_mut(
            &actions.inbound_cookie,
            |slot| slot.is_none()
        ));
        assert!(TokioRuntime::with_mutex_mut(
            &actions.inbound_peer_zid,
            |slot| slot.is_none()
        ));
        // Session-scoped survivors.
        assert_eq!(
            actions.resolve_outbound_mapping(7).as_deref(),
            Some("home/base"),
            "outbound mapping table survives the reset (replay re-declares it \
             to the PEER; local resolution never lapsed)"
        );
        assert_eq!(
            actions.declaration_cache_snapshot().len(),
            1,
            "the declaration cache IS the replay source — must survive"
        );
        // SN re-seed: the next emitted frame repeats the initial SN. The
        // probe send happens post-re-handshake in production, so re-open
        // the F2 transport gate first (Established re-entry does this via
        // `record_established_at`).
        TokioRuntime::with_mutex_mut(&actions.link.transport_available, |g| *g = true);
        let pre_reset_first_frame = driver.frame_bytes(0);
        actions
            .send_push_literal("home/x", b"p", true)
            .expect("post-reset push");
        let post = driver.frame_bytes(driver.frame_count() - 1);
        assert_eq!(
            post[1], pre_reset_first_frame[1],
            "post-reset frame must restart at params.initial_sn (1-byte VLE \
             SN at offset 1 for the fixture params)"
        );
    }

    /// R311y211 — reconnect×multilink coherence: with the y205
    /// `transport-multilink` × `session-reconnect` compile_error removed,
    /// `reset_for_reopen` must PRESERVE the shared outbound SN while a link is
    /// live (a surviving aggregate member keeps its per-channel gate mid-
    /// stream — resetting it would corrupt the survivor) and re-seed it only
    /// once the aggregate is empty (the single-link / fresh-rebuild path). This
    /// pins the runtime invariant that replaced the compile-time XOR.
    #[cfg(all(feature = "transport-multilink", feature = "session-reconnect"))]
    #[test]
    fn reset_for_reopen_preserves_shared_sn_while_a_link_is_live() {
        use wz_runtime_core::Runtime;

        let mask = wz_session_core::sn::mask_from_res(0x02);
        let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
        params.initial_sn = 42;
        let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);

        // Register the bundle's own link into the aggregation set and mark it
        // live -> a surviving aggregate member (`live_link_count() == 1`).
        actions.register_first_link(actions.link.clone());
        TokioRuntime::with_mutex_mut(&actions.link.transport_available, |g| *g = true);
        assert_eq!(actions.live_link_count(), 1);

        // Advance the shared outbound SN mid-stream: 42, 43, 44 -> counter 45.
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            42
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            43
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            44
        );

        // GUARD: a reset while a link is live is a no-op on the shared core ->
        // the SN continues from 45 (NOT re-seeded to 42) and the link stays
        // live (the F2 gate is not closed).
        actions.reset_for_reopen();
        assert_eq!(
            actions.live_link_count(),
            1,
            "the survivor stays live across a guarded reset"
        );
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            45,
            "a live-link reset must PRESERVE the shared outbound SN (guard no-op)"
        );

        // The aggregate collapses: `del_link` empties the set. A subsequent
        // reset IS the legal fresh-rebuild path and DOES re-seed the SN.
        assert_eq!(actions.del_link(&actions.link), 0);
        assert_eq!(actions.live_link_count(), 0);
        actions.reset_for_reopen();
        assert_eq!(
            actions.next_outbound_frame_sn(wz_session_core::qos::Priority::DEFAULT, true, mask),
            42,
            "with the aggregate empty the reset re-seeds the SN (fresh-rebuild)"
        );
    }

    /// `SwappableLink` delegates to whatever sink `swap` installed last —
    /// the transport-replacement seam the A4b supervisor swaps after
    /// re-dial (pico replacing `_z_session_t._tp` under the transport
    /// mutex). The supervisor's handle discipline is mirrored here: keep
    /// the TYPED `Arc<SwappableLink<_>>` for swapping and hand a coerced
    /// `Arc<dyn BoxedLinkDriver + Send + Sync>` clone to the actions
    /// bundle as its driver.
    #[test]
    fn swappable_link_redirects_sends_after_swap() {
        let first = crate::test_fixtures::recording_driver();
        let second = crate::test_fixtures::recording_driver();
        let link = Arc::new(SwappableLink::<TokioRuntime>::new(first.clone()));

        let actions = crate::test_fixtures::recording_actions_with_driver(link.clone());
        actions
            .send_declare_keyexpr(7, "home/base")
            .expect("declare via swappable link");
        assert_eq!(
            first.frame_count(),
            1,
            "pre-swap emits land on the first sink"
        );
        assert_eq!(second.frame_count(), 0);

        let old = link.swap(second.clone());
        drop(old);

        actions
            .send_declare_subscriber(10, 0, Some("home/sub"))
            .expect("declare after swap");
        assert_eq!(
            first.frame_count(),
            1,
            "post-swap emits must not reach the replaced sink"
        );
        assert_eq!(
            second.frame_count(),
            1,
            "post-swap emits land on the new sink"
        );
    }

    /// R311ki — `LocalSwappableLink` (the single-task / MCU twin of
    /// `SwappableLink`, RefCell-backed, no `Send` bound on the sink)
    /// delegates and redirects exactly as the mutex-backed seam does.
    /// `!Sync` by construction, so it CANNOT be the tokio actions
    /// driver (that is the point — it is the lwIP `Rc`-sink seam);
    /// the delegation contract is driven directly through the
    /// `BoxedLinkDriver` trait on one task here, and the no-`Send`
    /// composition with the lwIP profile is proved by the Layer G
    /// session-core cross-compile.
    #[test]
    fn local_swappable_link_redirects_sends_after_swap() {
        use wz_session_core::link::BoxedLinkDriver as _;
        use wz_session_core::reconnect::LocalSwappableLink;
        use wz_session_core::reliability::Reliability;

        let first = crate::test_fixtures::recording_driver();
        let second = crate::test_fixtures::recording_driver();
        let link = LocalSwappableLink::<TokioRuntime>::new(first.clone());

        link.send_blocking(b"frame-a", Reliability::Reliable);
        assert_eq!(first.frame_count(), 1, "pre-swap emit lands on first");
        assert_eq!(second.frame_count(), 0);

        let old = link.swap(second.clone());
        drop(old);

        link.send_blocking(b"frame-b", Reliability::Reliable);
        assert_eq!(
            first.frame_count(),
            1,
            "post-swap emits must not reach the replaced sink"
        );
        assert_eq!(
            second.frame_count(),
            1,
            "post-swap emits land on the new sink"
        );
        assert_eq!(second.frame_bytes(0), b"frame-b".to_vec());
    }
}

/// R311kj — the wire never carries the internal `batch_size = 0`
/// "unset" sentinel: `encode_init` advertises
/// `SessionInitParams::effective_batch_size()` (65535 when unset). A
/// zenoh-pico peer ADOPTS a literal 0 (unicast/transport.c:135-136) and
/// sizes a 0-byte TX wbuf from it (transport.c:47-49), so emitting 0
/// bricks interop — the R311kd zero-sentinel only patched the wz<->wz
/// MTU consult; this pins the wire emission itself.
#[cfg(all(test, feature = "codec-init-body"))]
mod init_advertisement_tests {
    use super::parse_inbound;
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_core::handshake_encode::encode_init;
    use wz_session_core::inbound::InboundFrame;

    #[test]
    fn unset_batch_size_advertises_wire_ceiling_not_zero() {
        let params = fixture_session_init_params(); // batch_size: 0 (unset)
        let wire = encode_init(&params, /*is_ack=*/ false, &[], None).expect("encode InitSyn");
        let InboundFrame::Init { body, .. } = parse_inbound(&wire).expect("parse own InitSyn")
        else {
            panic!("encoded InitSyn must parse as Init");
        };
        assert_eq!(
            body.batch_size,
            Some(65535),
            "the internal 0 sentinel must never reach the wire"
        );

        // A configured value passes through verbatim.
        let mut params = fixture_session_init_params();
        params.batch_size = 1024;
        let wire = encode_init(&params, false, &[], None).expect("encode InitSyn");
        let InboundFrame::Init { body, .. } = parse_inbound(&wire).expect("parse own InitSyn")
        else {
            panic!("encoded InitSyn must parse as Init");
        };
        assert_eq!(body.batch_size, Some(1024));
    }
}
