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

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use sce_rust_runtime::scripting::{IScriptEngine, NativeMethod, ScriptValue};
use sce_rust_runtime::Engine;

// R311g1 — CodecError / VecSink / SceSink are still needed in the
// minus-all-codecs lane because outbound `encode_frame_envelope` +
// `From<CodecError> for InboundParseError` reach them unconditionally
// (R311h..R311k cascade will gate the outbound encode_frame_* family
// at which point these can fold under the same cfg(any(...))).
use sce_forge_runtime::codec::{CodecError, SceSink, VecSink};
// SceCursor is consumed only by parse_inbound / parse_frame_payload /
// decode_ext_chain — every caller sits behind a codec feature gate
// so the import folds under the same union predicate.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use sce_forge_runtime::codec::SceCursor;
#[cfg(feature = "codec-close")]
use wz_codecs::close::Close;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_final::DeclFinal;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_kexpr::DeclKexpr;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_queryable::DeclQueryable;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_subscriber::DeclSubscriber;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_token::DeclToken;
#[cfg(feature = "codec-declare")]
use wz_codecs::declare::{Declare, DeclareVariant};
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
use wz_codecs::encoding::Encoding;
#[cfg(feature = "codec-response")]
use wz_codecs::err::Err;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-request"
))]
use wz_codecs::ext_zbuf::ExtZbuf;
use wz_codecs::ext_zint::ExtZint;
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::InitBody;
use wz_codecs::interest::Interest;
use wz_codecs::interest_body::InterestBody;
#[cfg(feature = "codec-keep-alive")]
use wz_codecs::keep_alive::KeepAlive;
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
use wz_codecs::msg_del::MsgDel;
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
use wz_codecs::msg_put::MsgPut;
use wz_codecs::oam::Oam;
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::OpenBody;
#[cfg(feature = "codec-push")]
use wz_codecs::push::{Push, PushVariant};
#[cfg(feature = "codec-request")]
use wz_codecs::query::Query;
#[cfg(feature = "codec-response")]
use wz_codecs::reply::{Reply, ReplyVariant};
#[cfg(feature = "codec-request")]
use wz_codecs::request::{Request, RequestVariant};
#[cfg(feature = "codec-response")]
use wz_codecs::response::{Response, ResponseVariant};
#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::ResponseFinal;
#[cfg(any(feature = "codec-request", feature = "codec-push"))]
use wz_codecs::timestamp::Timestamp;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_kexpr::UndeclKexpr;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_queryable::UndeclQueryable;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_subscriber::UndeclSubscriber;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_token::UndeclToken;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
#[cfg(feature = "codec-declare")]
use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
use wz_runtime_core::TimeSource;

use crate::runtime_impl::TokioTime;

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
use crate::keyexpr_canon::OutboundKeyexprError;

use crate::{LinkDriver, LinkEvent, LostCause, Reliability, TxFrame};

/// Cryptographic key for the anti-amplification cookie MAC.
///
/// Type-safe wrapper around `Zeroizing<Vec<u8>>` so the heap
/// allocation backing the key bytes is wiped on drop. Construction
/// validates the RFC §5.M length contract (>= 32 bytes); passing a
/// short slice returns `Err(SigningKeyTooShort)` instead of panicking
/// at the eventual HMAC call site (3rd review production-safety
/// retrospect: panic at construct vs. silent corruption).
///
/// The newtype hides the raw bytes from public API; only this
/// module's `generate_cookie_hmac_sha256` can read them, via
/// `as_slice`. Consumers store / move / clone a `SigningKey` like
/// any other value type but cannot accidentally serialise it or
/// log its inner bytes.
#[derive(Clone)]
pub struct SigningKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SigningKey {
    /// Manual Debug impl — never reveals the key bytes. Logs +
    /// panic backtraces show only the length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKeyTooShort(pub usize);

impl std::fmt::Display for SigningKeyTooShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cookie_signing_key must be >= 32 bytes per RFC §5.M (got {})",
            self.0
        )
    }
}

impl std::error::Error for SigningKeyTooShort {}

impl SigningKey {
    /// Construct a key from owned bytes. The input is moved into a
    /// `Zeroizing` wrapper; passing a shorter-than-32-byte slice
    /// returns the typed error without retaining the bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SigningKeyTooShort> {
        if bytes.len() < 32 {
            // Zeroize the rejected input before returning — the
            // caller's Vec<u8> would otherwise persist on the
            // stack until they explicitly drop it.
            let _ = Zeroizing::new(bytes);
            return Err(SigningKeyTooShort(0)); // length already inspected
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// R69 — construct a SigningKey from OS-backed cryptographic
    /// entropy. Pulls 32 bytes from `getrandom::getrandom` (Linux
    /// `getrandom(2)` fallback to `/dev/urandom`; macOS `getentropy`)
    /// — the RustCrypto-ecosystem standard for AP-side secret-key
    /// material. Length is fixed at 32 so the result always
    /// satisfies the `>= 32` invariant; the constructor cannot
    /// return `SigningKeyTooShort`.
    ///
    /// The fallible surface returns `getrandom::Error` so a deploy
    /// that runs in a sandbox without entropy access (e.g.
    /// container without `/dev/urandom`) sees a typed error rather
    /// than a panic.
    ///
    /// MCU sibling does NOT use this path — the wz-runtime-lwip
    /// build will source entropy via `sce_intrinsics_runtime::rng`
    /// per §5.I architectural-tier registry (intrinsics §2.5).
    /// Keeping the `getrandom` dep AP-only preserves the no_std
    /// contract on MCU builds.
    pub fn new_random() -> Result<Self, getrandom::Error> {
        let mut buf = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(buf.as_mut_slice())?;
        // The buf is already Zeroizing-wrapped, but `new` re-wraps
        // its input. Move the inner Vec out (preserving the wipe
        // on the original wrapper's drop should an early-return
        // occur in future edits).
        Ok(Self {
            bytes: Zeroizing::new(std::mem::take(&mut *buf)),
        })
    }

    /// Crate-internal slice view; not exposed to consumers.
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Anti-amplification cookie generated by the Accepting side on
/// InitAck and echoed back by the Initiator on OpenSyn.
///
/// **Wire shape**. HMAC-SHA256 output truncated to the first
/// 16 bytes (RFC §5.M cookie shape; the truncation matches
/// zenoh-pico's _z_t_msg_init_t._cookie ZSlice convention and is
/// the same width as a zid). The 32-byte raw HMAC is **not**
/// emitted on the wire; only the truncated 16-byte prefix.
///
/// **Key sourcing**. Caller passes a validated `SigningKey`
/// constructed via `SigningKey::new(bytes)`; length validation +
/// drop-time zeroize happen at the newtype layer so this function
/// is panic-free given a non-null key.
pub fn generate_cookie_hmac_sha256(cookie_signing_key: &SigningKey, peer_zid: &[u8]) -> Vec<u8> {
    let full = compute_hmac_sha256_full(cookie_signing_key.as_slice(), peer_zid);
    full[..16].to_vec()
}

/// Pure HMAC-SHA256 primitive — used by the cookie generator and
/// directly by the RFC 4231 test-vector cross-check. Returns the
/// untruncated 32-byte MAC; the cookie wire-shape truncation is
/// owned by `generate_cookie_hmac_sha256`.
fn compute_hmac_sha256_full(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any non-zero key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Transport-message header constants from
/// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h`.
/// Kept local (rather than re-exported from zenoh-pico-sys) so this
/// module does not pull the zenoh-pico FFI into its hot path on
/// MCU builds — wz-runtime-tokio is the AP/linux runtime, but the
/// constants themselves are wire-spec-frozen across both runtimes.
mod wire_const {
    #[cfg(feature = "codec-init-body")]
    pub const T_MID_INIT: u8 = 0x01;
    #[cfg(feature = "codec-open-body")]
    pub const T_MID_OPEN: u8 = 0x02;
    #[cfg(feature = "codec-close")]
    pub const T_MID_CLOSE: u8 = 0x03;
    /// Per-session liveness ping — zero-byte body; lease-timer
    /// reset on receive (transport.h:24 commentary, MID 0x04).
    #[cfg(feature = "codec-keep-alive")]
    pub const T_MID_KEEP_ALIVE: u8 = 0x04;
    /// Established-session payload carrier (transport.h:79 MID 0x05).
    /// Body = VLE sn + tail payload; optional ext chain between sn
    /// and payload when Z flag set (zenoh-pico skips non-mandatories
    /// on inbound, transport.c::_z_frame_decode L388).
    pub const T_MID_FRAME: u8 = 0x05;
    /// Reliable channel discriminator (1 = reliable, 0 = best-effort)
    /// for `_Z_MID_T_FRAME` per transport.h:80.
    pub const FLAG_T_FRAME_R: u8 = 0x20;

    /// InitAck discriminator (0 = InitSyn, 1 = InitAck).
    #[cfg(feature = "codec-init-body")]
    pub const FLAG_T_INIT_A: u8 = 0x20;
    /// Size parameters carrier (sn_res + batch_size present).
    #[cfg(feature = "codec-init-body")]
    pub const FLAG_T_INIT_S: u8 = 0x40;

    /// OpenAck discriminator (0 = OpenSyn, 1 = OpenAck).
    #[cfg(feature = "codec-open-body")]
    pub const FLAG_T_OPEN_A: u8 = 0x20;
    /// Lease in seconds (1) vs milliseconds (0).
    #[cfg(feature = "codec-open-body")]
    pub const FLAG_T_OPEN_T: u8 = 0x40;

    /// Session-close vs link-only close.
    #[cfg(feature = "codec-close")]
    pub const FLAG_T_CLOSE_S: u8 = 0x20;

    /// Transport-message ext-chain presence bit shared across every
    /// `_Z_MID_T_*` header (transport.h:44 `_Z_FLAG_T_Z = 0x80`).
    /// When set the parent header signals that one or more
    /// `ExtEntry` records follow the body bytes, terminated by an
    /// entry whose own `Z` bit is clear.
    ///
    /// R311g1 — gated on the same predicate as the
    /// [`crate::session_glue::parse_inbound`] `has_ext` extraction:
    /// the constant is only referenced from codec-feature-gated
    /// dispatch arms, so the minus-all-codecs lane drops it cleanly.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    pub const FLAG_T_Z: u8 = 0x80;

    /// Network-message MID for `Frame.payload` batch entries that
    /// wrap a query / put / del (network.h:36). First R74-decoded
    /// network MID.
    ///
    /// R311g — only callsite is the [`parse_frame_payload`] inbound
    /// dispatcher (itself gated on `codec-frame`) + the outbound
    /// `encode_frame_with_request` (gated on `codec-request`).
    ///
    /// R311j — gate broadened from `codec-frame` to `codec-request`:
    /// the request envelope is now its own atomic body codec with
    /// `codec-request = ["codec-frame"]` imply edge.
    #[cfg(feature = "codec-request")]
    pub const N_MID_REQUEST: u8 = 0x1C;
    /// R90 — Push envelope MID (network.h:35). Pub/sub data
    /// carrier wrapping a put / del inner body; sibling to
    /// `N_MID_REQUEST` minus the rid field per zenoh-pico
    /// `_z_push_encode`.
    ///
    /// R311h — gated on `codec-push`. Sole consumer is the
    /// `parse_frame_payload` `N_MID_PUSH` arm and the outbound
    /// `encode_frame_with_push` helper, both behind the same gate.
    #[cfg(feature = "codec-push")]
    pub const N_MID_PUSH: u8 = 0x1D;
    /// R91 — Response-final marker MID (network.h:38). Pure
    /// correlation marker closing a Request's reply stream per
    /// zenoh-pico `_z_response_final_encode`: 1-byte header +
    /// request_id VLE + optional ext-chain, no body.
    ///
    /// R311g — additionally gated on `codec-frame` because the only
    /// current call site is the `parse_frame_payload` dispatcher
    /// (Frame envelope → NetworkMessage::ResponseFinal). Both
    /// features must be on for the constant to have any live use;
    /// when either is off the constant elides cleanly.
    #[cfg(all(feature = "codec-response-final", feature = "codec-frame"))]
    pub const N_MID_RESPONSE_FINAL: u8 = 0x1A;
    /// R92 — OAM (Operations & Maintenance) MID (network.h:33).
    /// Diagnostic / control-plane envelope per zenoh-pico
    /// `_z_oam_encode`: header (with mid, enc, Z bits) plus a VLE
    /// id, optional ext-chain, and a body variant dispatched on
    /// `header.enc` (UNIT / ZINT / ZBUF re-using ext_* inner
    /// codecs).
    ///
    /// R311g — currently consumed only by [`parse_frame_payload`]
    /// (codec-frame-gated). Moves to a broader gate when a future
    /// round adds an OAM encoder.
    #[cfg(feature = "codec-frame")]
    pub const N_MID_OAM: u8 = 0x1F;
    /// R93/R94 — Interest envelope MID (network.h:39). Declarations
    /// discovery / liveliness subscriber registration carrier per
    /// zenoh-pico `_z_n_interest_encode`. R93 landed the envelope
    /// layer (is_final form, RESPONSE_FINAL sibling); R94 closed the
    /// inner body via the `header.C || header.F` disjunction present-
    /// if (interest_body sub-codec wraps the body_flags + R-gated
    /// wireexpr per `_z_interest_encode`).
    pub const N_MID_INTEREST: u8 = 0x19;
    /// R97 — Response envelope MID (network.h:37). Query reply
    /// carrier wrapping a reply (0x04) or err (0x05) inner body per
    /// zenoh-pico `_z_response_encode`. Wire-shape sibling to
    /// `N_MID_REQUEST`: header(N@5,M@6,Z@7) + rid VLE + wireexpr
    /// embed + Z-gated ext-chain + peek-byte body variant on the
    /// inner MID bit-range.
    ///
    /// R311k — gate broadened from `codec-frame` to `codec-response`:
    /// the response envelope is its own atomic body codec with
    /// `codec-response = ["codec-frame"]` imply edge, closing the
    /// fourth body-codec-implies-envelope edge.
    #[cfg(feature = "codec-response")]
    pub const N_MID_RESPONSE: u8 = 0x1B;
    /// R110/R115 — Declare envelope MID (network.h:34). Declarations
    /// envelope wrapping one of the nine sub-MID bodies (DECL_KEXPR
    /// 0x00 / DECL_SUBSCRIBER 0x01 / DECL_QUERYABLE 0x02 /
    /// DECL_TOKEN 0x03 / UNDECL_KEXPR 0x04 / UNDECL_SUBSCRIBER 0x05 /
    /// UNDECL_QUERYABLE 0x06 / UNDECL_TOKEN 0x07 / DECL_FINAL 0x08)
    /// per zenoh-pico `_z_declare_encode`. Wire-shape: header(I@5,
    /// Z@7) + optional interest_id VLE + Z-gated ext-chain + peek-
    /// byte inner declaration variant. R110a-e closed the wz-side
    /// authoring chain (9/9 sub-MIDs + envelope) and the byte-equiv
    /// Layer 3 wire-interop vs `_z_declare_encode`. R115 wires the
    /// inbound dispatch on this const so [`parse_frame_payload`]
    /// surfaces DECLARE records to the application layer.
    ///
    /// R311i — gated on `codec-declare`.
    #[cfg(feature = "codec-declare")]
    pub const N_MID_DECLARE: u8 = 0x1E;
}

/// Per-deploy parameters that drive the codec field values for the
/// 4-way handshake + close. Production callers source these from
/// `deploy.yaml`; tests pass fixed values for reproducible wire bytes.
#[derive(Debug, Clone)]
pub struct SessionInitParams {
    /// Protocol version (zenoh: 0x05 at the time of writing).
    pub version: u8,
    /// API-form whatami: `0x01` Router, `0x02` Peer, `0x04` Client.
    /// The codec packs the wire-form 2-bit field per
    /// `_z_whatami_to_uint8` (transport.c:31-37).
    pub whatami: u8,
    /// ZenohID — 1..=16 bytes. The codec encodes the length in the
    /// high 4 bits of `cbyte` as `zid_len - 1`.
    pub zid: Vec<u8>,
    /// Sequence-number resolution (0..=3 → 8 / 16 / 32 / 64-bit).
    pub seq_num_res: u8,
    /// Request-id resolution (0..=3).
    pub req_id_res: u8,
    /// Per-link batch size (bytes). Transport.h documents 1..=65535.
    pub batch_size: u16,
    /// Lease duration. The `lease_in_seconds` flag below picks the
    /// unit; the value itself is VLE-encoded inside the open body.
    pub lease: u64,
    /// `_Z_FLAG_T_OPEN_T` semantics: when true the wire encodes the
    /// `lease` field as seconds (set the flag); when false it
    /// encodes milliseconds (clear the flag).
    pub lease_in_seconds: bool,
    /// Initial sequence number for the reliable channel (VLE-encoded
    /// inside the open body).
    pub initial_sn: u64,
    /// Cookie material exchanged on the InitAck → OpenSyn echo path.
    ///
    /// On the Initiator side this is the bytes received in the
    /// peer's InitAck; the Initiator re-emits them verbatim in the
    /// OpenSyn frame so the peer can MAC-verify ownership of the
    /// session start.
    ///
    /// On the Accepting side this MUST be generated via
    /// `generate_cookie_hmac_sha256(cookie_signing_key, peer_zid)`
    /// per RFC §5.M. The integration test fixture matches this
    /// path so the wire bytes are reproducible across runs.
    pub cookie: Vec<u8>,

    /// Per-process secret key used by the Accepting side to MAC the
    /// outbound cookie. Constructed via `SigningKey::new(bytes)` so
    /// length validation (>= 32 bytes per RFC §5.M) + drop-time
    /// zeroize are enforced by the type. Initiator side does not
    /// consume this field; the cookie value flows inbound from the
    /// peer's InitAck instead.
    pub cookie_signing_key: SigningKey,
}

// `SessionInitParams` carries no test-only methods. The deterministic
// fixture builder (formerly `for_test`) moved out to the
// `wz-runtime-tokio-test-support` sibling crate at R71 so production
// builds of this crate no longer carry the test-only code path.
// `SessionInitParams` intentionally has no `Default` impl — production
// callers MUST source every field from `deploy.yaml` (or another
// configured source), and the fixture stays behind the test-support
// crate boundary.

/// Discrete close-reason discriminator. Mirrors the four close-reason
/// mutator actions emitted by `session_fsm_unicast.scxml`
/// (`set_close_reason_generic / invalid / expired / unresponsive`).
/// Encoded as a single byte in the Close codec body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseReason {
    /// Default close (set via `session.close` transition).
    #[default]
    Generic = 0,
    /// Framing error close.
    Invalid = 1,
    /// Lease expired close.
    Expired = 2,
    /// TX congestion / peer unresponsive close.
    Unresponsive = 3,
}

/// Counters + last-wire-bytes snapshot the integration tests inspect
/// to verify the script-action dispatch reached this side AND the
/// codec produced the expected wire shape.
#[derive(Debug, Default)]
pub struct ActionTrace {
    pub link_driver_open: u32,
    pub send_init_syn: u32,
    pub send_open_syn: u32,
    pub send_init_ack_with_cookie: u32,
    pub send_open_ack: u32,
    pub send_close_frame_with_reason: u32,
    pub release_link: u32,
    pub enable_rx_tx_regions: u32,
    pub start_lease_monitor: u32,
    pub stop_lease_monitor: u32,
    pub start_keepalive_worker: u32,
    pub stop_keepalive_worker: u32,
    pub free_pool_slots: u32,
    pub set_close_reason_count: u32,
    pub close_reason: CloseReason,
    /// R84 — incremented on `record_established_at()` script dispatch
    /// (Established.onentry). Pairs 1:1 with the
    /// `SessionLinkActions::established_at` timestamp slot so tests
    /// can assert both the counter side-effect AND the slot
    /// population in one pass.
    pub record_established_at: u32,
    /// R89 — incremented on every `cookie_valid()` guard invocation
    /// (SentInitAck -> SentOpenAck transition condition). Tests
    /// assert this counter to confirm the dynamic guard fired
    /// instead of a constant-true fallback. The verdict itself is
    /// observed indirectly via FSM state after the transition: if
    /// guard returned true the FSM advances to SentOpenAck, if
    /// false it stays at SentInitAck.
    pub cookie_valid_check: u32,
}

/// Sync RAII shim around an async `LinkDriver`. Production callers
/// supply this via `TokioLinkDriverAdapter`; tests supply a
/// recording implementation.
///
/// Send + Sync are required because the trait object captured by
/// each native-fn closure must outlive the closure's `'static`
/// bound and travel across worker threads on a Tokio multi-thread
/// runtime.
pub trait BoxedLinkDriver: Send + Sync {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability);
    fn open_blocking(&self);
    fn close_blocking(&self);
}

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

/// Outbound transport-message variant for ext-chain dispatch.
///
/// R68b plumbing: 4 negotiation-relevant frame roles each carry
/// their own ext chain (session-fsm §7 — QoS / QoSLink / Auth /
/// MultiLink / LowLatency). The encoder reads the appropriate
/// slot via `SessionLinkActions::ext_chain_for` so per-deploy
/// negotiation policy can stage distinct chains per role without
/// growing the `SessionInitParams` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtChainRole {
    InitSyn,
    InitAck,
    OpenSyn,
    OpenAck,
}

/// R300 — typed reject from the outbound DECLARE-side gate that
/// guards against (a) malformed keyexprs (structural canon
/// violations) and (b) zenoh-pico bug #3 SIGABRT patterns (R299
/// fixture). Returned by [`SessionLinkActions::send_declare_keyexpr`]
/// / `send_declare_subscriber` / `send_declare_queryable` /
/// `send_declare_token` instead of letting the failing emit reach
/// the wire (where pico would crash) or panic at
/// [`build_declare_kexpr`]'s `mapping_id != 0` assertion.
///
/// The gate runs BEFORE any wire bytes are produced or any
/// outbound-mapping-table side effect — every variant is a
/// no-emit reject (the session-link state is unchanged on Err).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDeclareError {
    /// The reconstructed keyexpr (resolved from `(mapping_id,
    /// suffix)` via the outbound mapping table) failed the
    /// pico-safety check. Inner [`OutboundKeyexprError`] separates
    /// structural canon violations from R299 bug #3 patterns.
    Keyexpr(OutboundKeyexprError),
    /// `send_declare_keyexpr(mapping_id = 0, ..)` — the keyexpr
    /// mapping id space reserves `0` for "literal" indication on
    /// the subscriber / queryable / token side, so registering a
    /// new mapping AT id 0 has no wire interpretation. Mirrors
    /// [`build_declare_kexpr`]'s `mapping_id != 0` assertion; the
    /// gate elevates the developer-visible failure mode from
    /// panic-at-builder to typed error-at-action.
    ReservedMappingIdZero,
    /// `send_declare_subscriber` / `_queryable` / `_token` was
    /// called with a `mapping_id != 0` that has no entry in
    /// [`SessionLinkActions::outbound_mappings`]. Either no prior
    /// [`SessionLinkActions::send_declare_keyexpr`] established
    /// the mapping, or a
    /// [`SessionLinkActions::send_undeclare_kexpr`] retracted it
    /// before this call. Sending the wire frame anyway would
    /// reach the peer as an "unknown wireexpr id" error.
    UnknownMappingId(u64),
    /// `send_declare_subscriber` / `_queryable` / `_token` was
    /// called with `mapping_id == 0` AND `keyexpr_suffix == None`
    /// — no keyexpr at all. The peer cannot resolve a missing
    /// keyexpr; the gate surfaces this as a typed protocol error
    /// instead of letting it reach the wire as a malformed
    /// DECLARE.
    MissingKeyexpr,
    /// R311g1 — the matching `declare-*` Cargo feature is OFF in
    /// this build, so the wire emit path is elided. The
    /// `SessionLinkActions` method signature stays stable
    /// regardless of feature configuration (per
    /// `feedback_signature_stability` — consumer-side cfg burden
    /// is absorbed by wz-runtime-tokio); the caller observes the
    /// build-time choice as an honest runtime reject rather than
    /// a silent `Ok(())` (which would falsely promise a wire
    /// emit) or a compile error (which would re-introduce the
    /// `#[cfg(feature)] pub fn` anti-pattern this round retires).
    ///
    /// Variant ordering: appended at end so existing match arms
    /// in downstream crates surface a non-exhaustive-match
    /// warning (when applicable) rather than silently rebind a
    /// prior variant.
    FeatureDisabled,
}

impl std::fmt::Display for SendDeclareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyexpr(e) => write!(f, "send_declare: {e}"),
            Self::ReservedMappingIdZero => f.write_str(
                "send_declare_keyexpr: mapping_id 0 is reserved \
                 (cannot register a new keyexpr mapping at id 0)",
            ),
            Self::UnknownMappingId(id) => write!(
                f,
                "send_declare: mapping_id {id} has no outbound entry \
                 (no preceding send_declare_keyexpr for this id, \
                 or it was undeclared before this call)"
            ),
            Self::MissingKeyexpr => f.write_str(
                "send_declare: mapping_id 0 requires a literal keyexpr \
                 suffix (received None)",
            ),
            Self::FeatureDisabled => f.write_str(
                "send_declare: matching declare-* Cargo feature is OFF \
                 in this build; wire emit elided (signature-stability \
                 contract — caller observes build-time choice as \
                 runtime reject)",
            ),
        }
    }
}

impl std::error::Error for SendDeclareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Keyexpr(e) => Some(e),
            _ => None,
        }
    }
}

impl From<OutboundKeyexprError> for SendDeclareError {
    fn from(e: OutboundKeyexprError) -> Self {
        Self::Keyexpr(e)
    }
}

/// Bundle of state shared across the 17 native script functions.
pub struct SessionLinkActions {
    pub driver: Arc<dyn BoxedLinkDriver>,
    pub params: SessionInitParams,
    pub trace: Mutex<ActionTrace>,
    /// Cookie material captured from a peer's InitAck via
    /// `handle_inbound`. When populated this overrides
    /// `params.cookie` on the OpenSyn outbound, implementing the
    /// RFC §5.M echo contract on the Initiator side.
    pub inbound_cookie: Mutex<Option<Vec<u8>>>,
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
    pub last_inbound_keepalive_at: Mutex<Option<u64>>,
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
    pub established_at: Mutex<Option<u64>>,
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
    pub clock: TokioTime,
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
    pub inbound_peer_zid: Mutex<Option<Vec<u8>>>,
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
    pub inbound_opensyn_cookie: Mutex<Option<Vec<u8>>>,
    /// R68b — per-role ext chain slots. Indexed by `ExtChainRole`
    /// via `ext_chain_for`. Each slot lives behind its own `Mutex`
    /// so a setter can swap one chain without blocking the others
    /// (e.g. mid-handshake auth-step rotation can rewrite the
    /// OpenSyn chain without touching the InitSyn record).
    init_syn_ext: Mutex<Vec<ExtEntry>>,
    init_ack_ext: Mutex<Vec<ExtEntry>>,
    open_syn_ext: Mutex<Vec<ExtEntry>>,
    open_ack_ext: Mutex<Vec<ExtEntry>>,
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
    pub inbound_peer_init_caps: Mutex<Option<PeerInitCaps>>,
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
    pub outbound_mappings: Mutex<HashMap<u64, String>>,
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

/// R121d — peer-announced sizing caps captured from `InitSyn` for
/// the Accepting-side negotiation rule
/// `InitAck.size <= InitSyn.size`. Defaults match
/// zenoh-pico's behaviour when the `_Z_FLAG_T_INIT_S` bit is
/// clear on InitSyn (zenoh-pico/src/protocol/codec/transport.c:267-269
/// — falls back to `_Z_DEFAULT_RESOLUTION_SIZE = 2` and
/// `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInitCaps {
    pub seq_num_res: u8,
    pub req_id_res: u8,
    pub batch_size: u16,
}

impl PeerInitCaps {
    /// Decode the InitSyn `sn_res` byte + optional `batch_size`
    /// field per the init_body codec (parent.S=1 carries both,
    /// parent.S=0 falls back to defaults). The `sn_res` byte is
    /// packed `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`
    /// per zenoh-pico transport.c:196-197.
    pub fn from_init_syn(sn_res_byte: Option<u8>, batch_size: Option<u16>) -> Self {
        // R311cb — transport-batching gates the peer-advertised
        // batch_size honoring. cfg-off forces 65535 (full MTU) and
        // ignores the peer's advertised value; honest semantic is
        // "we always batch up to the wire limit and never reduce."
        // The S-bit clear arm always returns 65535 regardless of the
        // feature state — that path is the peer-declined-S baseline,
        // not a negotiation outcome.
        #[cfg(feature = "transport-batching")]
        let honored_batch_size = batch_size.unwrap_or(65535);
        #[cfg(not(feature = "transport-batching"))]
        let honored_batch_size = 65535u16;
        match sn_res_byte {
            Some(b) => Self {
                seq_num_res: b & 0x03,
                req_id_res: (b >> 2) & 0x03,
                batch_size: honored_batch_size,
            },
            None => Self {
                // S bit clear → both peer defaults to
                // `_Z_DEFAULT_RESOLUTION_SIZE = 2` and
                // `_Z_DEFAULT_UNICAST_BATCH_SIZE = 65535`.
                seq_num_res: 2,
                req_id_res: 2,
                batch_size: 65535,
            },
        }
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
pub fn default_init_patch_ext_entry() -> ExtEntry {
    // header byte layout per `vendor/zenoh-pico/include/zenoh-pico/
    // protocol/ext.h:47-65`:
    //   bits 0..3 = ext_id 0x07 (INIT_PATCH)
    //   bit 4     = M (mandatory) = 0
    //   bits 5..6 = enc = 0x01 (ZINT)
    //   bit 7     = Z (chain continuation) — encoder owns this bit
    //               via `encode_ext_chain`, so leave it cleared here.
    ExtEntry {
        header: 0x07 | 0x20, // _Z_MSG_EXT_ID_INIT_PATCH literal
        body: ExtEntryVariant::CodecZenohExtZint(ExtZint { value: 1 }),
    }
}

impl SessionLinkActions {
    /// Construct a session action bundle for one logical FSM instance.
    /// The `params` are captured by value; production callers
    /// supplying per-deploy values stage them once at session
    /// construction. `clock` is the shared monotonic clock (R263 +
    /// R294) consumed by [`Self::handle_inbound`] and the
    /// `record_established_at` Lua action; production callers pass
    /// the same `TokioTime` that [`drive_session_until_terminal`]
    /// receives so the lease comparator's `now_ms` and the recorded
    /// `keepalive_ms` / `established_ms` share an epoch.
    pub fn new(
        driver: Arc<dyn BoxedLinkDriver>,
        params: SessionInitParams,
        clock: TokioTime,
    ) -> Arc<Self> {
        // R121e — seed the outbound Frame SN with `params.initial_sn`
        // so the first emitted Frame matches the value announced in
        // the OpenSyn/OpenAck body. The peer enforces this start
        // value via its reliable-channel window tracking
        // (zenoh-pico unicast/transport.c:182-194).
        let initial_frame_sn = params.initial_sn;
        Arc::new(Self {
            driver,
            params,
            trace: Mutex::new(ActionTrace::default()),
            inbound_cookie: Mutex::new(None),
            last_inbound_keepalive_at: Mutex::new(None),
            established_at: Mutex::new(None),
            clock,
            inbound_peer_zid: Mutex::new(None),
            inbound_opensyn_cookie: Mutex::new(None),
            // R121f1 — default ext chains seed both Init roles with the
            // patch-extension entry that zenoh-pico's accept-side
            // size-negotiation requires. See
            // [`default_init_patch_ext_entry`] for the wire-spec
            // citation and the foreign-interop failure mode this
            // closes.
            init_syn_ext: Mutex::new(vec![default_init_patch_ext_entry()]),
            init_ack_ext: Mutex::new(vec![default_init_patch_ext_entry()]),
            open_syn_ext: Mutex::new(Vec::new()),
            open_ack_ext: Mutex::new(Vec::new()),
            inbound_peer_init_caps: Mutex::new(None),
            outbound_frame_sn: AtomicU64::new(initial_frame_sn),
            outbound_mappings: Mutex::new(HashMap::new()),
            next_outbound_request_id: AtomicU64::new(0),
            next_outbound_token_id: AtomicU64::new(0),
            next_outbound_interest_id: AtomicU64::new(0),
        })
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
        let peer = *self.inbound_peer_init_caps.lock().unwrap();
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
    pub fn set_ext_chain(&self, role: ExtChainRole, entries: Vec<ExtEntry>) {
        *self.ext_chain_slot(role).lock().unwrap() = entries;
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
    ) -> Vec<u8> {
        let chain = self.ext_chain_slot(role).lock().unwrap();
        if is_ack {
            // R121d — capped-to-peer params so the outbound InitAck
            // satisfies the wire-spec `InitAck.size <= InitSyn.size`
            // invariant. The owned clone is cheap (the heavy field
            // is `cookie_signing_key`, which is a 32-byte
            // `Zeroizing<Vec<u8>>` clone) and stays local to this
            // call frame.
            let params = self.init_ack_params();
            encode_init(&params, is_ack, &chain, cookie_override)
        } else {
            encode_init(&self.params, is_ack, &chain, cookie_override)
        }
    }

    #[cfg(feature = "codec-open-body")]
    pub fn encode_open_with_role(
        &self,
        is_ack: bool,
        cookie_override: Option<&[u8]>,
        role: ExtChainRole,
    ) -> Vec<u8> {
        let chain = self.ext_chain_slot(role).lock().unwrap();
        encode_open(&self.params, is_ack, cookie_override, &chain)
    }

    fn ext_chain_slot(&self, role: ExtChainRole) -> &Mutex<Vec<ExtEntry>> {
        match role {
            ExtChainRole::InitSyn => &self.init_syn_ext,
            ExtChainRole::InitAck => &self.init_ack_ext,
            ExtChainRole::OpenSyn => &self.open_syn_ext,
            ExtChainRole::OpenAck => &self.open_ack_ext,
        }
    }

    pub fn trace_snapshot(&self) -> ActionTrace {
        self.trace.lock().unwrap().clone_via_copy()
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
                    *self.inbound_cookie.lock().unwrap() = Some(cookie.clone());
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
                *self.inbound_peer_zid.lock().unwrap() = Some(body.zid.clone());
                // R121d — capture the peer's announced sizing caps
                // so `init_ack_params` can enforce the wire-spec
                // `InitAck.size <= InitSyn.size` rule on the
                // outbound InitAck (zenoh-pico
                // unicast/transport.c:123-140 rejection condition).
                *self.inbound_peer_init_caps.lock().unwrap() =
                    Some(PeerInitCaps::from_init_syn(body.sn_res, body.batch_size));
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
                    *self.inbound_opensyn_cookie.lock().unwrap() = Some(cookie.clone());
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
                *self.last_inbound_keepalive_at.lock().unwrap() =
                    Some(self.clock.now_monotonic_ms());
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
    pub fn send_push_literal(&self, keyexpr_suffix: &str, value: &[u8], reliable: bool) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_literal(keyexpr_suffix, value);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (keyexpr_suffix, value, reliable);
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
            let declare = build_declare_kexpr(mapping_id, suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
            // R234 — record the (mapping_id, suffix) pair in the
            // outbound table so later `publish_aliased_auto` calls
            // can resolve the literal without caller assertion.
            // Insertion happens AFTER the wire send so a driver-side
            // panic does not leave a table entry that the peer never
            // saw. Mirrors zenoh-pico's `_z_register_resource` which
            // executes on the local-side declaration emit path.
            self.outbound_mappings
                .lock()
                .expect("outbound_mappings poisoned by an earlier panicked publish")
                .insert(mapping_id, suffix.to_string());
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
    ) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_aliased(mapping_id, suffix, value);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (mapping_id, suffix, value, reliable);
    }

    /// R219 — encode + dispatch a literal-keyexpr `Push(MsgDel)` on
    /// the outbound link. Delete-keyexpr signal mirror of
    /// [`Self::send_push_literal`]: zenoh-pico's subscriber callback
    /// fires with `z_sample_kind = DELETE` on receipt.
    ///
    /// `MsgDel` carries no payload so the action accepts only the
    /// keyexpr suffix. Reliability gating + Established-state
    /// preconditions match [`Self::send_push_literal`].
    pub fn send_push_del_literal(&self, keyexpr_suffix: &str, reliable: bool) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_literal(keyexpr_suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (keyexpr_suffix, reliable);
    }

    /// R219 — encode + dispatch a DECLARE-aliased `Push(MsgDel)`
    /// (id != 0) on the outbound link. Delete-keyexpr signal mirror
    /// of [`Self::send_push_aliased`]. Same prior-`DeclKexpr`
    /// precondition as the Put variant: the peer must have absorbed
    /// a Declare for `mapping_id` earlier on the same session so
    /// the receive-side resolver can map it back to a literal
    /// keyexpr before firing the subscriber callback.
    pub fn send_push_del_aliased(&self, mapping_id: u64, suffix: Option<&str>, reliable: bool) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_aliased(mapping_id, suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (mapping_id, suffix, reliable);
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
    ) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_literal_with_meta(keyexpr_suffix, value, meta);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (keyexpr_suffix, value, reliable, meta);
    }

    /// R233 — metadata-bearing counterpart of [`send_push_aliased`].
    pub fn send_push_with_meta_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        value: &[u8],
        reliable: bool,
        meta: &PushMetadata,
    ) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_aliased_with_meta(mapping_id, suffix, value, meta);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (mapping_id, suffix, value, reliable, meta);
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
    ) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_literal_with_meta(keyexpr_suffix, meta);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (keyexpr_suffix, reliable, meta);
    }

    /// R233 — metadata-bearing counterpart of
    /// [`send_push_del_aliased`].
    pub fn send_push_del_with_meta_aliased(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        reliable: bool,
        meta: &PushMetadata,
    ) {
        #[cfg(feature = "codec-push")]
        {
            let push = build_push_del_aliased_with_meta(mapping_id, suffix, meta);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_push(sn, push, reliable);
            let reliability = if reliable {
                Reliability::Reliable
            } else {
                Reliability::BestEffort
            };
            self.driver.send_blocking(&wire, reliability);
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (mapping_id, suffix, reliable, meta);
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
                build_declare_subscriber(subscriber_id, keyexpr_mapping_id, keyexpr_suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
            let declare = build_declare_queryable(queryable_id, keyexpr_mapping_id, keyexpr_suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
            let declare = build_declare_token(token_id, keyexpr_mapping_id, keyexpr_suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
            Ok(())
        }
        #[cfg(not(feature = "declare-token"))]
        {
            let _ = (token_id, keyexpr_mapping_id, keyexpr_suffix);
            Err(SendDeclareError::FeatureDisabled)
        }
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
            // R234 — drop the (mapping_id, suffix) pair so subsequent
            // `publish_aliased_auto` calls return `None` on this id and
            // the caller knows the alias is stale. Idempotent: removing
            // an absent id is a no-op. Mirrors zenoh-pico's
            // `_z_unregister_resource` invoked on the local-side
            // undeclare emit path.
            self.outbound_mappings
                .lock()
                .expect("outbound_mappings poisoned by an earlier panicked publish")
                .remove(&mapping_id);
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
        self.outbound_mappings
            .lock()
            .expect("outbound_mappings poisoned by an earlier panicked publish")
            .get(&mapping_id)
            .cloned()
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
    /// A poisoned `established_at` mutex (an earlier panicked Lua
    /// action) is treated as `false` — refusing emit on a corrupted
    /// FSM is the conservative + textbook response, matching the
    /// poison-recover idiom used elsewhere (see
    /// `crate::pubsub::Subscriber::drop`).
    pub fn is_established(&self) -> bool {
        self.established_at
            .lock()
            .map(|stamp| stamp.is_some())
            .unwrap_or(false)
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
    ) {
        #[cfg(feature = "declare-interest")]
        {
            let interest = build_interest_liveliness_subscriber(
                interest_id,
                history,
                keyexpr_mapping_id,
                keyexpr_suffix,
            );
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_interest(sn, interest, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
        }
        #[cfg(not(feature = "declare-interest"))]
        let _ = (interest_id, history, keyexpr_mapping_id, keyexpr_suffix);
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
    ) {
        #[cfg(feature = "codec-request")]
        {
            let request = build_request_query(rid, keyexpr_mapping_id, keyexpr_suffix);
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_request(sn, request, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-request"))]
        let _ = (rid, keyexpr_mapping_id, keyexpr_suffix);
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
    ) {
        #[cfg(feature = "codec-request")]
        {
            let mut builder = RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix);
            if let Some(target) = meta.target {
                builder = builder.request_target(target);
            }
            if let Some(consolidation) = meta.consolidation {
                builder = builder.consolidation(consolidation);
            }
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
            let request = builder.build();
            let sn = self.next_outbound_frame_sn();
            let wire = encode_frame_with_request(sn, request, /*reliable=*/ true);
            self.driver.send_blocking(&wire, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-request"))]
        let _ = (rid, keyexpr_mapping_id, keyexpr_suffix, meta);
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
            self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_response(&self, response: Response) {
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_response(sn, response, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
            self.trace
                .lock()
                .expect("trace poisoned by an earlier panicked Lua action")
                .send_close_frame_with_reason += 1;
            let bytes = encode_close(reason as u8);
            self.driver.send_blocking(&bytes, Reliability::Reliable);
        }
        #[cfg(not(feature = "codec-close"))]
        let _ = reason;
    }
}

impl ActionTrace {
    fn clone_via_copy(&self) -> Self {
        Self {
            link_driver_open: self.link_driver_open,
            send_init_syn: self.send_init_syn,
            send_open_syn: self.send_open_syn,
            send_init_ack_with_cookie: self.send_init_ack_with_cookie,
            send_open_ack: self.send_open_ack,
            send_close_frame_with_reason: self.send_close_frame_with_reason,
            release_link: self.release_link,
            enable_rx_tx_regions: self.enable_rx_tx_regions,
            start_lease_monitor: self.start_lease_monitor,
            stop_lease_monitor: self.stop_lease_monitor,
            start_keepalive_worker: self.start_keepalive_worker,
            stop_keepalive_worker: self.stop_keepalive_worker,
            free_pool_slots: self.free_pool_slots,
            set_close_reason_count: self.set_close_reason_count,
            close_reason: self.close_reason,
            record_established_at: self.record_established_at,
            cookie_valid_check: self.cookie_valid_check,
        }
    }
}

/// SCE-runtime session id the generated state-machine uses by default.
pub const SESSION_ID: &str = "session_fsm_unicast";

/// Wire the 17 native script functions referenced by
/// `session_fsm_unicast.scxml` onto the supplied script engine, then
/// create the SCE-runtime session that the generated state machine
/// dispatches against.
///
/// R79 — the process-global `INSTALLED` OnceLock retired after SCE
/// upstream commit `489e1922` deleted `lua_engine_singleton` /
/// `sce_rust_lua::register` and SCE commit `09906015` reshaped every
/// generated `Policy::new` to accept a per-instance
/// `Arc<dyn IScriptEngine>`. Each call to `install_session_actions`
/// now binds the 17 closures onto a caller-owned engine, so two
/// independent session FSMs in the same process bind their closures
/// onto separate engines — no cross-instance namespace race.
///
/// Caller pattern:
/// ```ignore
/// let lua: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
/// install_session_actions(actions.clone(), &lua);
/// let policy = SessionFsmUnicastPolicy::new(lua.clone());
/// let mut engine = Engine::new(policy);
/// ```
pub fn install_session_actions(
    actions: Arc<SessionLinkActions>,
    script_engine: &Arc<dyn IScriptEngine>,
) {
    script_engine.create_session(SESSION_ID);
    register_outbound_link_fns(script_engine.as_ref(), &actions);
    register_state_internal_fns(script_engine.as_ref(), &actions);
    register_guard_fns(script_engine.as_ref(), &actions);
}

// R71 — the former `rebind_session_actions_for_test` moved to the
// `wz-runtime-tokio-test-support` sibling crate as
// `install_session_actions_for_test`. R79 — that rebind helper is
// also retired upstream of R79's per-instance DI; test-support now
// simply constructs a fresh `LuaEngine` per test and calls
// `install_session_actions` with it. The three `register_*` helpers
// below remain `pub` so the test-support crate can compose them in
// patterns that vary the registration set (e.g. partial rebinds).

/// Register the 7 outbound link-driver script functions. Public only
/// to let `wz-runtime-tokio-test-support::install_session_actions_for_test`
/// compose the rebind path; production code reaches this through
/// `install_session_actions` instead.
pub fn register_outbound_link_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_unit(lua, "link_driver_open", actions, |a| {
        a.trace.lock().unwrap().link_driver_open += 1;
        a.driver.open_blocking();
    });

    // R311cd — session-unicast-open gates the open-side (Initiator)
    // wire emit script-actions. cfg-off: send_init_syn /
    // send_open_syn names are not bound, so a session FSM in the
    // Initiator role trips `function not found` at the
    // `<onentry>send_init_syn</onentry>` transition. Honest semantic:
    // open-side OFF means the deploy is acceptor-only (cannot
    // outbound-dial a peer). Default-on so the AP path keeps both
    // sides bindable.
    #[cfg(all(feature = "codec-init-body", feature = "session-unicast-open"))]
    bind_unit(lua, "send_init_syn", actions, |a| {
        a.trace.lock().unwrap().send_init_syn += 1;
        let bytes = a.encode_init_with_role(
            /*is_ack=*/ false,
            /*cookie_override=*/ None,
            ExtChainRole::InitSyn,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    #[cfg(all(feature = "codec-open-body", feature = "session-unicast-open"))]
    bind_unit(lua, "send_open_syn", actions, |a| {
        a.trace.lock().unwrap().send_open_syn += 1;
        // RFC §5.M echo contract: prefer the cookie captured from a
        // peer InitAck via handle_inbound; fall back to params.cookie
        // for tests that drive OpenSyn without an inbound parse cycle.
        let cookie_override = a.inbound_cookie.lock().unwrap().clone();
        let bytes = a.encode_open_with_role(
            /*is_ack=*/ false,
            cookie_override.as_deref(),
            ExtChainRole::OpenSyn,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    // R311cd — session-unicast-accept gates the accept-side (Acceptor)
    // wire emit script-actions. cfg-off: send_init_ack_with_cookie /
    // send_open_ack names are not bound, so a session FSM in the
    // Acceptor role trips `function not found`. Honest semantic:
    // accept-side OFF means the deploy is initiator-only (can dial
    // but cannot listen). Default-on so the AP path keeps both
    // sides bindable.
    #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
    bind_unit(lua, "send_init_ack_with_cookie", actions, |a| {
        a.trace.lock().unwrap().send_init_ack_with_cookie += 1;
        // R86 — Accepting-side cookie binding per RFC §5.M
        // anti-amplification. If the inbound InitSyn already arrived
        // (`inbound_peer_zid` slot populated by `handle_inbound`),
        // mint a fresh cookie via HMAC-SHA256(cookie_signing_key,
        // peer_zid)[..16] and pass it as the encode override; the
        // cookie is now bound to the specific peer's claimed
        // identity, not a deploy-static value. Falls back to
        // `params.cookie` verbatim if no peer_zid has been observed
        // (defensive — a well-formed handshake always populates the
        // slot before this script fires, since `Accepting.onentry`
        // is gated on `InitSynReceived`).
        let cookie_hmac: Option<Vec<u8>> =
            a.inbound_peer_zid.lock().unwrap().as_ref().map(|peer_zid| {
                generate_cookie_hmac_sha256(&a.params.cookie_signing_key, peer_zid)
            });
        let bytes = a.encode_init_with_role(
            /*is_ack=*/ true,
            cookie_hmac.as_deref(),
            ExtChainRole::InitAck,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
    bind_unit(lua, "send_open_ack", actions, |a| {
        a.trace.lock().unwrap().send_open_ack += 1;
        // Accepting side OpenAck: cookie is consumed by the time we
        // get here (it travelled inbound on OpenSyn and was already
        // MAC-verified); the OpenAck shape omits it (parent.A=1
        // suppresses the cookie field per transport.c:300-302).
        let bytes = a.encode_open_with_role(
            /*is_ack=*/ true,
            /*cookie_override=*/ None,
            ExtChainRole::OpenAck,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    #[cfg(feature = "codec-close")]
    bind_unit(lua, "send_close_frame_with_reason", actions, |a| {
        let reason = a.trace.lock().unwrap().close_reason as u8;
        a.trace.lock().unwrap().send_close_frame_with_reason += 1;
        let bytes = encode_close(reason);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    bind_unit(lua, "release_link", actions, |a| {
        a.trace.lock().unwrap().release_link += 1;
        a.driver.close_blocking();
    });
}

/// Register the 7 lifecycle / lease-monitor script functions. Public
/// for the same reason as `register_outbound_link_fns` — the
/// test-support crate composes it during the rebind path.
pub fn register_state_internal_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_unit(lua, "enable_rx_tx_regions", actions, |a| {
        a.trace.lock().unwrap().enable_rx_tx_regions += 1;
    });
    bind_unit(lua, "record_established_at", actions, |a| {
        a.trace.lock().unwrap().record_established_at += 1;
        // R294 — `a.clock.now_monotonic_ms()` reads the shared
        // monotonic clock (same epoch as
        // last_inbound_keepalive_at + drive_session_until_terminal)
        // so the lease comparator's u64 subtract stays on one scale.
        *a.established_at.lock().unwrap() = Some(a.clock.now_monotonic_ms());
    });
    bind_unit(lua, "start_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().start_lease_monitor += 1;
    });
    bind_unit(lua, "stop_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().stop_lease_monitor += 1;
    });
    // R311cb — transport-keepalive gates the SCXML script-action bind
    // for the keepalive worker. cfg-off: the action names are not
    // registered with the Lua engine, so a session FSM that reaches a
    // `<script>start_keepalive_worker</script>` body trips
    // `function not found` and fails the transition. Honest semantic:
    // keepalive-OFF means the FSM cannot enter the lease-monitored
    // Established sub-region. Default-on so the AP path still binds.
    // Wire-level KeepAlive parse (last_inbound_keepalive_at stamp) is
    // a separate axis governed by codec-keep-alive.
    #[cfg(feature = "transport-keepalive")]
    bind_unit(lua, "start_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().start_keepalive_worker += 1;
    });
    #[cfg(feature = "transport-keepalive")]
    bind_unit(lua, "stop_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().stop_keepalive_worker += 1;
    });
    bind_unit(lua, "free_pool_slots", actions, |a| {
        a.trace.lock().unwrap().free_pool_slots += 1;
    });
    bind_close_reason(
        lua,
        "set_close_reason_generic",
        actions,
        CloseReason::Generic,
    );
    bind_close_reason(
        lua,
        "set_close_reason_invalid",
        actions,
        CloseReason::Invalid,
    );
    bind_close_reason(
        lua,
        "set_close_reason_expired",
        actions,
        CloseReason::Expired,
    );
    bind_close_reason(
        lua,
        "set_close_reason_unresponsive",
        actions,
        CloseReason::Unresponsive,
    );
}

/// Register the 3 guard-condition script functions. Public for the
/// same reason as `register_outbound_link_fns` — the test-support
/// crate composes it during the rebind path.
///
/// R89 — signature gains `actions` parameter so `cookie_valid` can
/// dispatch dynamically against the inbound OpenSyn cookie + the
/// stored peer_zid + cookie_signing_key. `half_open_cap_available`
/// and `accept_rate_token` remain R57 placeholder constants pending
/// cap-quota / token-bucket implementation rounds.
pub fn register_guard_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_bool(lua, "half_open_cap_available", true);
    bind_bool(lua, "accept_rate_token", true);
    bind_guard(lua, "cookie_valid", actions, |a| {
        // R89 — cookie_valid is the inbound half of R86's outbound
        // cookie binding. The Accepting side stored peer_zid on
        // InitSyn arrival (R86 inbound_peer_zid slot) and minted a
        // cookie via HMAC-SHA256(cookie_signing_key, peer_zid)[..16]
        // on InitAck send (R86 send_init_ack_with_cookie). The
        // Initiator echoes that cookie verbatim on OpenSyn; here we
        // re-compute the expected HMAC and compare against the
        // captured inbound OpenSyn cookie (R89 inbound_opensyn_cookie
        // slot). Mismatch -> guard returns false -> FSM stays at
        // SentInitAck instead of advancing to SentOpenAck.
        //
        // The counter increments on every invocation so tests can
        // assert the guard actually fired (vs. R57's bind_bool
        // placeholder which never executed any dynamic check).
        a.trace.lock().unwrap().cookie_valid_check += 1;

        // Defensive: any missing material rejects. A well-formed
        // handshake populates both slots before this guard runs.
        let peer_zid = match a.inbound_peer_zid.lock().unwrap().clone() {
            Some(z) => z,
            None => return false,
        };
        let echoed = match a.inbound_opensyn_cookie.lock().unwrap().clone() {
            Some(c) => c,
            None => return false,
        };
        let expected = generate_cookie_hmac_sha256(&a.params.cookie_signing_key, &peer_zid);
        // Byte-equality compare. Constant-time compare is overkill
        // for a single-peer test fixture path; if the HMAC verdict
        // ever drives a security-critical timing oracle on prod
        // hardware, swap to `subtle::ConstantTimeEq` here.
        echoed == expected
    });
}

// ─────────────────────────── codec wiring ───────────────────────────

/// Build the wire bytes for an Init frame (InitSyn if `is_ack==false`,
/// InitAck if `is_ack==true`). The codec body is the wz `InitBody`,
/// verified byte-identical to zenoh-pico's `_z_init_encode` by
/// `crates/wz-integration-tests/tests/layer3_init_body.rs`. The
/// transport-message header is one byte: `(flags) | T_MID_INIT`.
#[cfg(feature = "codec-init-body")]
fn encode_init(
    params: &SessionInitParams,
    is_ack: bool,
    extensions: &[ExtEntry],
    cookie_override: Option<&[u8]>,
) -> Vec<u8> {
    let mut parent_flags = wire_const::FLAG_T_INIT_S;
    if is_ack {
        parent_flags |= wire_const::FLAG_T_INIT_A;
    }
    if !extensions.is_empty() {
        parent_flags |= wire_const::FLAG_T_Z;
    }

    // R86 — cookie carrier rules: InitSyn (is_ack=false) never
    // carries a cookie regardless of override. InitAck (is_ack=true)
    // uses cookie_override when supplied (production peer_zid binding
    // path from send_init_ack_with_cookie) and falls back to
    // params.cookie otherwise. cookie_override is silently ignored on
    // InitSyn because the wire-spec forbids the field there.
    let cbyte = init_cbyte(params.whatami, params.zid.len());
    let cookie_bytes: Option<Vec<u8>> = if is_ack {
        Some(
            cookie_override
                .map(|c| c.to_vec())
                .unwrap_or_else(|| params.cookie.clone()),
        )
    } else {
        None
    };
    let body = InitBody {
        version: params.version,
        cbyte,
        zid: params.zid.clone(),
        sn_res: Some(pack_sn_res(params.seq_num_res, params.req_id_res)),
        batch_size: Some(params.batch_size),
        cookie_len: cookie_bytes.as_ref().map(|c| c.len() as u64),
        cookie: cookie_bytes,
    };

    let ext_bytes = encode_ext_chain(extensions);
    let mut wire = Vec::with_capacity(1 + InitBody::MAX_ENCODED_BYTES + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_INIT);
    let s = (parent_flags >> 6) & 1;
    let a = (parent_flags >> 5) & 1;
    {
        let mut sink = VecSink::new(&mut wire);
        body.encode(&mut sink, s, a).expect("VecSink is infallible");
    }
    wire.extend_from_slice(&ext_bytes);
    wire
}

/// Build the wire bytes for an Open frame (OpenSyn / OpenAck). Body
/// is the wz `OpenBody`, verified byte-identical to zenoh-pico's
/// `_z_open_encode` by `tests/layer3_open_body.rs`.
///
/// `cookie_override` carries the OpenSyn echo path (RFC §5.M): when
/// the Initiator receives a peer InitAck via `handle_inbound`, the
/// captured cookie bytes are passed here so OpenSyn echoes them
/// verbatim. `None` falls back to `params.cookie` for tests that
/// drive OpenSyn directly without an inbound parse cycle. The
/// argument is ignored when `is_ack=true` (OpenAck carries no
/// cookie field per transport.c:300-302).
#[cfg(feature = "codec-open-body")]
fn encode_open(
    params: &SessionInitParams,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    extensions: &[ExtEntry],
) -> Vec<u8> {
    let mut parent_flags = 0u8;
    if params.lease_in_seconds {
        parent_flags |= wire_const::FLAG_T_OPEN_T;
    }
    if is_ack {
        parent_flags |= wire_const::FLAG_T_OPEN_A;
    }
    if !extensions.is_empty() {
        parent_flags |= wire_const::FLAG_T_Z;
    }

    let cookie_bytes: &[u8] = if !is_ack {
        cookie_override.unwrap_or(&params.cookie)
    } else {
        &[]
    };
    let body = OpenBody {
        lease: params.lease,
        initial_sn: params.initial_sn,
        cookie_len: if !is_ack {
            Some(cookie_bytes.len() as u64)
        } else {
            None
        },
        cookie: if !is_ack {
            Some(cookie_bytes.to_vec())
        } else {
            None
        },
    };

    let ext_bytes = encode_ext_chain(extensions);
    let mut wire = Vec::with_capacity(1 + OpenBody::MAX_ENCODED_BYTES + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_OPEN);
    let a = (parent_flags >> 5) & 1;
    {
        let mut sink = VecSink::new(&mut wire);
        body.encode(&mut sink, a).expect("VecSink is infallible");
    }
    wire.extend_from_slice(&ext_bytes);
    wire
}

/// Serialize a transport-message ext chain — concatenated
/// `ExtEntry::encode()` outputs with the per-entry `Z` bit
/// (`0x80`) flipped to mark chain continuation. Last entry gets
/// Z=0 (chain terminator); preceding entries get Z=1. Empty input
/// returns an empty `Vec` so call sites can unconditionally
/// `extend_from_slice` the result.
///
/// The encoder owns Z so authors never have to remember to flip
/// the bit between "this is a single-entry chain" (Z=0) and
/// "this is the last entry of an N-entry chain" (also Z=0). The
/// non-Z bits (`ext_id`, `M`, `enc`) stay author-set; the helper
/// preserves them via a byte-level patch on the first byte.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
fn encode_ext_chain(entries: &[ExtEntry]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(entries.len() * 4);
    let last = entries.len() - 1;
    for (i, entry) in entries.iter().enumerate() {
        let mut bytes = entry.encode_to_vec();
        // ExtEntry::encode pushes the header byte first (see
        // ext_entry codegen line 145); flip the Z bit per chain
        // position before emitting.
        if i == last {
            bytes[0] &= !0x80;
        } else {
            bytes[0] |= 0x80;
        }
        buf.extend_from_slice(&bytes);
    }
    buf
}

/// Build the wire bytes for a Close frame. Body is the wz `Close`
/// (single reason byte), verified byte-identical to zenoh-pico's
/// `_z_close_encode` by `tests/layer3_close.rs`. The
/// `_Z_FLAG_T_CLOSE_S` flag selects graceful session close (we
/// always set it — link-only close is a transport-layer concern
/// that the link driver handles directly).
#[cfg(feature = "codec-close")]
fn encode_close(reason: u8) -> Vec<u8> {
    let parent_flags = wire_const::FLAG_T_CLOSE_S;
    let mut wire = Vec::with_capacity(1 + Close::MAX_ENCODED_BYTES);
    wire.push(parent_flags | wire_const::T_MID_CLOSE);
    let mut sink = VecSink::new(&mut wire);
    Close { reason }
        .encode(&mut sink)
        .expect("VecSink is infallible");
    wire
}

/// R121e — build a `Push` network-message with a literal keyexpr
/// (id=0 + inline suffix) and a `Put` body carrying `value` as
/// payload bytes.
///
/// Wire-spec sourcing:
///
/// * `WireexprLocal { id: 0, suffix: Some(s) }` encodes as "the
///   keyexpr IS the literal string `s`, no DECLARE alias
///   indirection". `id = 0` is the Zenoh sentinel for "no
///   declared mapping" (zenoh-pico
///   `include/zenoh-pico/api/types.h::_z_keyexpr_set_no_id` path);
///   zenoh-pico's session-receive resolver
///   (`_z_session_recv_push`) treats id=0 + suffix=Some as the
///   literal-keyexpr path with no table lookup. This is the
///   simplest publisher shape — DECLARE-aliased Push (id != 0,
///   prior DeclKexpr to assign id → suffix) is a follow-up
///   optimisation for repeated-keyexpr traffic and is not on the
///   AP MVP critical path.
///
/// * `Push.header` carries:
///   - bits 0..4: MID = `N_MID_PUSH` (0x1D, network.h:34).
///   - bit 5:     `N` flag = 1 (suffix carrier present).
///   - bit 6:     `M` flag — derived from the WireexprLocal arm
///     at encode time (push.rs:189 `_derived_header`); MUST NOT
///     be set here.
///   - bit 7:     `Z` flag = 0 (no Push-level extensions for the
///     MVP path).
///
/// * `MsgPut` body carries:
///   - `header` = 0x01 (msg_put MID, no timestamp / encoding /
///     ext flags — payload-only Put per network.c:118).
///   - `payload_len` = `value.len()` VLE-encoded.
///   - `payload` = the application bytes.
///
/// Pure builder — no I/O, no FSM state coupling. Mirrors the
/// shape of [`encode_init`] / [`encode_open`] / [`encode_close`].
///
/// R311h — gated on `codec-push` (return type is the gated
/// `wz_codecs::push::Push`; principled exemption from the
/// signature-stability sweep per `feedback_signature_stability`).
#[cfg(feature = "codec-push")]
pub fn build_push_literal(keyexpr_suffix: &str, value: &[u8]) -> Push {
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = suffix_string.len() as u64;
    let payload_bytes = value.to_vec();
    let payload_len = payload_bytes.len() as u64;
    Push {
        // `N_MID_PUSH | N_flag(0x20)` — M flag derives from the
        // WireexprLocal arm at encode time (push.rs:189).
        header: wire_const::N_MID_PUSH | 0x20,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix_len),
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(MsgPut {
            header: 0x01,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len,
            payload: payload_bytes,
        }),
    }
}

/// R121g — build a `Push` network-message that references a peer-
/// declared keyexpr mapping. Mirror of [`build_push_literal`] for
/// the DECLARE-aliased path: instead of carrying the full literal
/// suffix on every Push, the publisher first sends a
/// `Declare(DeclKexpr)` (via [`build_declare_kexpr`] / the
/// `send_declare_keyexpr` action) that registers `id` → "demo/test",
/// then emits subsequent Pushes carrying only that `id` (and
/// optionally a per-Push suffix appended to the declared prefix).
///
/// Wire-spec sourcing:
///
/// * `WireexprLocal { id: N, suffix: None }` — pure aliased Push.
///   The peer (z_sub) consults its keyexpr table built from prior
///   inbound `DeclKexpr` records (zenoh-pico's
///   `_z_session_recv_declaration` path) and resolves `id=N` to the
///   declared keyexpr. This is the bandwidth-efficient shape for
///   repeated-keyexpr publishers.
///
/// * `WireexprLocal { id: N, suffix: Some(s) }` — composite. The
///   peer concatenates its declared prefix with `s` to form the
///   effective keyexpr. Used when one DECLARE establishes a prefix
///   (e.g. `myhouse/sensors/`) and many publishers add per-sensor
///   suffixes (`temp`, `humidity`) without redeclaring.
///
/// Panics if `mapping_id == 0` — id zero is the literal-keyexpr
/// sentinel (`build_push_literal`'s arm). The split keeps the two
/// shapes apart at the API surface so a caller cannot silently
/// invert them.
#[cfg(feature = "codec-push")]
pub fn build_push_aliased(mapping_id: u64, suffix: Option<&str>, value: &[u8]) -> Push {
    assert!(
        mapping_id != 0,
        "build_push_aliased requires a non-zero mapping id; use build_push_literal for id=0",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let payload_bytes = value.to_vec();
    let payload_len = payload_bytes.len() as u64;
    // Push.header.N (bit 5, 0x20) is the "suffix carrier present"
    // flag: set when the WireexprLocal carries a non-None suffix,
    // clear for a pure-aliased Push (`suffix=None`). The peer's
    // wireexpr decoder reads this bit to decide whether to expect
    // `VLE(suffix_len) + suffix bytes` after the id; an out-of-sync
    // N flag drops the codec into an offset-shifted read of the
    // following MsgPut header, which the peer surfaces as
    // `Unknown message type received` (zenoh-pico
    // `_z_network_message_decode` MID switch on a stale byte).
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | n_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(MsgPut {
            header: 0x01,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len,
            payload: payload_bytes,
        }),
    }
}

/// R219 — build a literal-keyexpr `Push` whose body is a `MsgDel`
/// (delete-keyexpr signal) instead of `MsgPut`. Mirror of
/// [`build_push_literal`] for the deletion-of-resource path that
/// zenoh-pico emits on `z_delete` (`vendor/zenoh-pico/src/api/api.c`
/// `z_delete` → `_z_write` with `Z_SAMPLE_KIND_DELETE`).
///
/// Wire-shape differences from [`build_push_literal`]:
///
/// * `MsgDel` body carries:
///   - `header` = 0x02 (msg_del MID, no timestamp / ext flags
///     — payload-less Del per network.c:118 mapping table).
///   - No `payload_len` / `payload` fields — `MsgDel` is a marker
///     message; the keyexpr identifies the resource being deleted.
/// * Push.header N flag (0x20) is set the same as the literal-keyexpr
///   Put path; M flag derives at encode time from the WireexprLocal
///   arm selection.
///
/// Subscriber-side observation: zenoh-pico's `_z_trigger_subscriptions`
/// fires the registered callback with `z_sample_kind = DELETE`. The
/// stock `z_sub` example does not surface the kind in its printout
/// (only the keyexpr + payload), so an integration test against
/// `z_sub` sees the Del as a `Received` line with an empty value
/// substring — distinguishable from a Put-with-empty-value only by
/// the wz-side codec round-trip witness.
#[cfg(feature = "codec-push")]
pub fn build_push_del_literal(keyexpr_suffix: &str) -> Push {
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = suffix_string.len() as u64;
    Push {
        // `N_MID_PUSH | N_flag(0x20)` — M flag derives from the
        // WireexprLocal arm at encode time (push.rs:189). Identical
        // header shape to the Put path; only the inner body MID
        // (0x02 vs 0x01) and the absence of payload bytes differ
        // on the wire.
        header: wire_const::N_MID_PUSH | 0x20,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix_len),
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgDel(MsgDel {
            header: 0x02,
            timestamp: None,
            extensions: None,
        }),
    }
}

/// R219 — build a DECLARE-aliased `Push` whose body is `MsgDel`.
/// Mirror of [`build_push_aliased`] for the deletion path. Same
/// aliased-keyexpr precondition as the Put variant: the peer must
/// have absorbed a `Declare(DeclKexpr(mapping_id, ...))` earlier
/// so its keyexpr table can resolve the id.
///
/// Panics if `mapping_id == 0` — id zero is the literal-keyexpr
/// sentinel ([`build_push_del_literal`]'s arm). The split keeps
/// the two shapes apart at the API surface so a caller cannot
/// silently invert them.
#[cfg(feature = "codec-push")]
pub fn build_push_del_aliased(mapping_id: u64, suffix: Option<&str>) -> Push {
    assert!(
        mapping_id != 0,
        "build_push_del_aliased requires a non-zero mapping id; use build_push_del_literal for id=0",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    // Same N-flag derivation as build_push_aliased: bit 5 set when
    // a per-Push suffix tail is present, cleared for the
    // pure-aliased shape. The flag has identical decoder semantics
    // regardless of the inner body MID (Put vs Del).
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | n_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgDel(MsgDel {
            header: 0x02,
            timestamp: None,
            extensions: None,
        }),
    }
}

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
#[derive(Debug, Clone, Default)]
pub struct PushMetadata {
    /// Body-level timestamp (zenoh-pico `_z_m_push_commons_t._timestamp`,
    /// gated by `_Z_FLAG_Z_P_T` for Put / `_Z_FLAG_Z_D_T` for Del).
    pub timestamp: Option<crate::sample::TimestampHint>,
    /// Body-level encoding (Put kind only; zenoh-pico `_z_msg_del_t`
    /// has no encoding slot so a `Del` build_push call ignores this
    /// field even when set).
    pub encoding: Option<crate::sample::EncodingHint>,
    /// Body-level source identification (ext_id=0x01 ENC_ZBUF).
    pub source_info: Option<crate::sample::SourceInfo>,
    /// Body-level attachment blob (ext_id=0x03 ENC_ZBUF).
    pub attachment: Option<Vec<u8>>,
    /// Outer-level QoS metadata (Push extension ext_id=0x01 ENC_ZINT).
    pub qos: Option<crate::sample::QosLevel>,
}

impl PushMetadata {
    /// `true` when every metadata slot is `None` — callers can use
    /// this to short-circuit to the no-metadata `build_push_*` fast
    /// paths without paying the with-meta builder cost.
    pub fn is_empty(&self) -> bool {
        self.timestamp.is_none()
            && self.encoding.is_none()
            && self.source_info.is_none()
            && self.attachment.is_none()
            && self.qos.is_none()
    }
}

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
#[derive(Debug, Clone, Default)]
pub struct QueryMetadata {
    /// Reply target hint (`Q_T` flag on the outbound Query). `None`
    /// elides the target byte → peer decodes
    /// `Z_QUERY_TARGET_DEFAULT` = `BEST_MATCHING`.
    pub target: Option<QueryTarget>,
    /// Reply consolidation hint (`Q_C` flag + consolidation byte).
    /// `None` elides → peer decodes `Z_CONSOLIDATION_MODE_AUTO`.
    pub consolidation: Option<ConsolidationMode>,
    /// Query-level attachment blob (ext_id=0x03 ZBUF on the Query
    /// ext chain). `None` elides the ext.
    pub attachment: Option<Vec<u8>>,
    /// Request-level timeout in milliseconds. `0` elides the ext
    /// per zenoh-pico's `_z_n_msg_request_needed_exts` predicate
    /// (`msg->_ext_timeout_ms != 0`).
    pub timeout_ms: u32,
}

impl QueryMetadata {
    /// `true` when every wire-propagatable slot is empty — callers
    /// can use this to short-circuit
    /// [`SessionLinkActions::send_request_query`]'s no-metadata fast
    /// path. Symmetric to [`PushMetadata::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.target.is_none()
            && self.consolidation.is_none()
            && self.attachment.is_none()
            && self.timeout_ms == 0
    }
}

/// R233 — build the body-level extension chain (`source_info` +
/// `attachment`) for a `MsgPut` or `MsgDel`. Returns `None` when
/// both fields are absent so the caller can leave
/// `MsgPut.extensions` / `MsgDel.extensions` as `None` and avoid
/// emitting an empty `<u8;ZBuf>` chain. Z chain-continuation flags
/// on the produced entries are NOT pre-set — the SCE-emitted
/// `MsgPut::encode` / `MsgDel::encode` iterate the chain and the
/// surrounding wire serializer applies the Z bit at the right
/// position via the per-entry codec emit.
#[cfg(feature = "codec-push")]
fn build_body_extensions(
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> Option<Vec<ExtEntry>> {
    let mut exts: Vec<ExtEntry> = Vec::new();
    if let Some(si) = source_info {
        let prefix = si.zid_prefix();
        if !prefix.is_empty() {
            let body_bytes = encode_source_info_ext_body(prefix, si.eid, si.sn);
            exts.push(ExtEntry {
                // ENC_ZBUF(0x40) | id_source_info(0x01). No M flag —
                // source_info is informational (zenoh-pico
                // `_z_msg_ext_t._source_info` emit at
                // message.c:_z_push_body_encode_extensions has no M
                // bit). Z chain-continuation bit applied below.
                header: 0x40 | 0x01,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: body_bytes.len() as u64,
                    value: body_bytes,
                }),
            });
        }
    }
    if let Some(bytes) = attachment {
        let owned = bytes.to_vec();
        exts.push(ExtEntry {
            // ENC_ZBUF(0x40) | id_attachment(0x03). Attachment is
            // informational; M flag stays clear (zenoh-pico
            // `_z_push_body_encode_extensions` at message.c emits
            // the attachment ext without M). Z chain bit applied
            // below.
            header: 0x40 | 0x03,
            body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                value_len: owned.len() as u64,
                value: owned,
            }),
        });
    }
    if exts.is_empty() {
        return None;
    }
    apply_chain_z_bits(&mut exts);
    Some(exts)
}

/// R233 — set the `Z` (chain-continuation, 0x80) bit on every
/// `ExtEntry` in a chain except the last. The SCE-emitted
/// `MsgPut::encode` / `MsgDel::encode` / `Push::encode` paths iterate
/// the extension `Vec` and call each entry's own `encode` without
/// adjusting the chain-continuation bit; the author owns Z. Mirrors
/// the explicit flip pattern in [`encode_ext_chain`] (used for
/// transport-message chains) so body / outer Push chains share the
/// same invariant. Single-entry chains keep Z=0 (terminator).
#[cfg(feature = "codec-push")]
fn apply_chain_z_bits(entries: &mut [ExtEntry]) {
    if entries.is_empty() {
        return;
    }
    let last = entries.len() - 1;
    for (i, entry) in entries.iter_mut().enumerate() {
        if i == last {
            entry.header &= !0x80;
        } else {
            entry.header |= 0x80;
        }
    }
}

/// R233 — build the outer Push extension chain (currently only QoS).
/// Returns `None` when no outer extension is requested so the caller
/// can leave `Push.extensions = None` and clear the Push-header Z
/// bit. zenoh-pico mirror: `_z_n_msg_encode_push` outer-ext switch
/// at network.c — qos lands on the outer chain, source_info /
/// attachment on the body chain (`_z_push_body_encode_extensions`).
#[cfg(feature = "codec-push")]
fn build_push_outer_extensions(qos: Option<crate::sample::QosLevel>) -> Option<Vec<ExtEntry>> {
    let mut exts: Vec<ExtEntry> = Vec::new();
    if let Some(q) = qos {
        exts.push(ExtEntry {
            // ENC_ZINT(0x20) | id_qos(0x01). No M flag — qos is
            // informational per zenoh-pico `_z_n_msg_encode_push`
            // outer-chain emit (network.c).
            header: 0x20 | 0x01,
            body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                value: q.raw as u64,
            }),
        });
    }
    if exts.is_empty() {
        return None;
    }
    apply_chain_z_bits(&mut exts);
    Some(exts)
}

/// R233 — build a `MsgPut` body carrying caller-set metadata
/// (timestamp, encoding, source_info, attachment). Sets the
/// `_Z_FLAG_Z_P_T` (0x20) and `_Z_FLAG_Z_P_E` (0x40) header bits to
/// signal the optional inline fields to the peer decoder.
/// Extensions are attached as a body-level chain via
/// [`build_body_extensions`]; the SCE-emitted `MsgPut::encode`
/// surfaces them per zenoh-pico's
/// `_z_push_body_encode_extensions` order.
#[cfg(feature = "codec-push")]
fn build_msg_put_with_meta(
    payload: &[u8],
    timestamp: Option<&crate::sample::TimestampHint>,
    encoding: Option<&crate::sample::EncodingHint>,
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> MsgPut {
    let payload_bytes = payload.to_vec();
    let payload_len = payload_bytes.len() as u64;
    let extensions = build_body_extensions(source_info, attachment);
    let mut put = MsgPut {
        header: 0x01,
        timestamp: timestamp.map(|t| t.to_codec()),
        encoding: encoding.map(|e| e.to_codec()),
        extensions,
        payload_len,
        payload: payload_bytes,
    };
    if put.timestamp.is_some() {
        put.set_t(true);
    }
    if put.encoding.is_some() {
        put.set_e(true);
    }
    if put.extensions.is_some() {
        put.set_z(true);
    }
    put
}

/// R233 — build a `MsgDel` body carrying caller-set metadata
/// (timestamp, source_info, attachment). zenoh-pico's `_z_msg_del_t`
/// carries no encoding slot, so `encoding` is intentionally absent
/// from the parameter list — the loopback path drops opts.encoding
/// for Del kind in `crate::session::build_loopback_sample` and the
/// wire path drops it here, keeping wire-vs-loopback parity. Sets
/// the `_Z_FLAG_Z_D_T` (0x20) header bit when a timestamp is
/// attached.
#[cfg(feature = "codec-push")]
fn build_msg_del_with_meta(
    timestamp: Option<&crate::sample::TimestampHint>,
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> MsgDel {
    let extensions = build_body_extensions(source_info, attachment);
    let mut del = MsgDel {
        header: 0x02,
        timestamp: timestamp.map(|t| t.to_codec()),
        extensions,
    };
    if del.timestamp.is_some() {
        del.set_t(true);
    }
    if del.extensions.is_some() {
        del.set_z(true);
    }
    del
}

/// R233 — metadata-bearing counterpart of [`build_push_literal`].
/// Routes timestamp / encoding into the inline `MsgPut` fields,
/// source_info / attachment into the body extension chain, and qos
/// into the outer Push extension chain. The Push-header Z bit (0x80)
/// is OR'd when an outer extension is present.
#[cfg(feature = "codec-push")]
pub fn build_push_literal_with_meta(
    keyexpr_suffix: &str,
    value: &[u8],
    meta: &PushMetadata,
) -> Push {
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | 0x20 | z_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(keyexpr_suffix.to_string()),
            }),
        },
        extensions: outer_exts,
        body: PushVariant::CodecZenohMsgPut(build_msg_put_with_meta(
            value,
            meta.timestamp.as_ref(),
            meta.encoding.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )),
    }
}

/// R233 — metadata-bearing counterpart of [`build_push_aliased`].
#[cfg(feature = "codec-push")]
pub fn build_push_aliased_with_meta(
    mapping_id: u64,
    suffix: Option<&str>,
    value: &[u8],
    meta: &PushMetadata,
) -> Push {
    assert!(
        mapping_id != 0,
        "build_push_aliased_with_meta requires a non-zero mapping id; \
         use build_push_literal_with_meta for id=0",
    );
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | n_flag | z_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: outer_exts,
        body: PushVariant::CodecZenohMsgPut(build_msg_put_with_meta(
            value,
            meta.timestamp.as_ref(),
            meta.encoding.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )),
    }
}

/// R233 — metadata-bearing counterpart of [`build_push_del_literal`].
/// `encoding` is dropped silently because `_z_msg_del_t` carries no
/// encoding slot — the loopback path enforces the same projection
/// in `crate::session::build_loopback_sample`.
#[cfg(feature = "codec-push")]
pub fn build_push_del_literal_with_meta(keyexpr_suffix: &str, meta: &PushMetadata) -> Push {
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | 0x20 | z_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(keyexpr_suffix.to_string()),
            }),
        },
        extensions: outer_exts,
        body: PushVariant::CodecZenohMsgDel(build_msg_del_with_meta(
            meta.timestamp.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )),
    }
}

/// R233 — metadata-bearing counterpart of [`build_push_del_aliased`].
#[cfg(feature = "codec-push")]
pub fn build_push_del_aliased_with_meta(
    mapping_id: u64,
    suffix: Option<&str>,
    meta: &PushMetadata,
) -> Push {
    assert!(
        mapping_id != 0,
        "build_push_del_aliased_with_meta requires a non-zero mapping id; \
         use build_push_del_literal_with_meta for id=0",
    );
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Push {
        header: wire_const::N_MID_PUSH | n_flag | z_flag,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: outer_exts,
        body: PushVariant::CodecZenohMsgDel(build_msg_del_with_meta(
            meta.timestamp.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )),
    }
}

/// R121g — build a `Declare` network-message that registers a
/// literal-keyexpr mapping. The peer's inbound dispatch
/// (zenoh-pico's `_z_session_recv_declaration` →
/// `_z_register_resource`) inserts `mapping_id → suffix` into its
/// local keyexpr table, after which any inbound Push with
/// `WireexprLocal { id: mapping_id, suffix: None }` resolves to the
/// declared literal.
///
/// Wire shape (per
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:52-63`):
///
/// ```text
///   [DeclKexpr.header = _Z_DECL_KEXPR_MID(0x00)
///                       | (suffix.is_some() ? _Z_DECL_KEXPR_FLAG_N(0x20) : 0)
///                       | (WireexprLocal ? B5-ν derived 0x40 : 0)]
///   VLE(mapping_id)
///   WireexprLocal.encode (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// Wrapped in a `Declare` envelope with the network MID header
/// `N_MID_DECLARE (0x1E)`, no `interest_id`, no extensions.
///
/// Panics if `mapping_id == 0` — id zero is reserved as the
/// literal-keyexpr sentinel and a DECLARE with id=0 has no
/// table-population semantics in zenoh-pico.
#[cfg(feature = "codec-declare")]
pub fn build_declare_kexpr(mapping_id: u64, suffix: &str) -> Declare {
    assert!(
        mapping_id != 0,
        "build_declare_kexpr requires a non-zero mapping id; id=0 is the literal-keyexpr sentinel",
    );
    let suffix_string = suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    Declare {
        // `N_MID_DECLARE (0x1E)` — no I (interest_id), no Z
        // (extensions); the MVP wires only the unsolicited
        // mapping-population shape that zenoh-pico emits on
        // `z_declare_keyexpr` without an Interest reply context.
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclKexpr(DeclKexpr {
            // Inner DeclKexpr header MUST carry `_Z_DECL_KEXPR_FLAG_N
            // (0x20)` when the keyexpr has a suffix string, per
            // `vendor/zenoh-pico/src/protocol/codec/declarations.c:52-58`.
            // The peer (zenoh-pico) gates the wireexpr suffix decode
            // on this bit (declarations.c:185); a missing N flag
            // drops the codec into an offset-shifted read of the
            // next message, surfaced as `Unknown message type
            // received` by `_z_network_message_decode`. The wz codec
            // does not auto-derive this flag from suffix presence —
            // author must set it explicitly.
            //
            // Inner arm = `WireexprLocal` (semantically correct: the
            // declared keyexpr lives in the local mapping table).
            // R121h-pre — SCE vendor pin e10619d3's B5-ν ownership
            // invert moved the wireexpr arm dispatch decision to the
            // parent's `<sce:import>` site
            // (sources/codecs/decl_kexpr.scxml). DeclKexpr deliberately
            // omits the `<sce:variant-dispatch>` child because its
            // header has no flag at bit 6 — the wireexpr arm choice
            // is a type-level refinement only and no parent derive
            // bit is emitted. The pre-R121h-pre WireexprNonlocal
            // workaround (used to suppress the codegen's spurious
            // 0x40 OR under the leaf-owned `tag="parent.M"` regime)
            // has retired with this pin bump.
            header: 0x20, // _Z_DECL_KEXPR_FLAG_N
            id: mapping_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len,
                    suffix: Some(suffix_string),
                }),
            },
        }),
    }
}

/// R121i — build a `Declare` network-message that registers a
/// subscriber on the peer for `(keyexpr_mapping_id, keyexpr_suffix)`.
/// Mirrors zenoh-pico `_z_decl_subscriber_encode` +
/// `_z_decl_commons_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:65-84`.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclSubscriber.header = _Z_DECL_SUBSCRIBER_MID (0x02)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x40 from parent.M
///                              dispatch on the wireexpr import,
///                              always set under the wz convention of
///                              Local-arm wireexpr)]
///   VLE(subscriber_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// The 0x40 M bit is NOT set in the author-supplied header here —
/// the SCE codegen ORs it in at encode time based on the
/// `<sce:variant-dispatch flag="header.M"/>` declared on the
/// wireexpr `<sce:import>` in `sources/codecs/decl_subscriber.scxml`
/// (post-R121h-pre B5-ν ownership invert). The N bit (0x20) IS
/// author-supplied because it gates wireexpr suffix presence — wz
/// codecs do not auto-derive that from the wireexpr field at emit
/// time (zenoh-pico's `_z_decl_commons_encode` reads the suffix
/// presence and sets N; wz mirrors this in the build helper rather
/// than in codegen).
///
/// The wireexpr arm is always `WireexprLocal` here — under the
/// R121h-pre invert + wireexpr.scxml `default="true"` on the
/// wireexpr_local arm, this also drives the codegen-derived M bit
/// in the parent header. `WireexprNonlocal` (literal-only) is
/// reserved for future Interest/Reply paths.
///
/// Convention (matches [`build_push_aliased`] / [`build_declare_kexpr`]):
///   - `keyexpr_mapping_id == 0, suffix = Some(s)`: literal — the
///     subscribed keyexpr is `s` itself (the peer parses VLE(0) +
///     VLE(len) + suffix bytes; id=0 is the wz literal-sentinel).
///   - `keyexpr_mapping_id == N, suffix = None`: alias — the
///     subscribed keyexpr is the peer's mapping for `N`.
///   - `keyexpr_mapping_id == N, suffix = Some(s)`: compound — the
///     subscribed keyexpr is mapping `N`'s prefix + `s`.
#[cfg(feature = "codec-declare")]
pub fn build_declare_subscriber(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
            // MID 0x02 (decl_subscriber) + N gate; M is codegen-
            // derived (see fn-level doc comment).
            header: 0x02 | n_flag,
            id: subscriber_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

/// R121i-b — build a `Declare` network-message that registers a
/// queryable on the peer for `(keyexpr_mapping_id, keyexpr_suffix)`.
/// Mirrors zenoh-pico `_z_decl_queryable_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:105-118`,
/// with `_z_decl_commons_encode` (declarations.c:65-80) providing the
/// shared `[header | id | wireexpr]` body.
///
/// AP MVP scope: the wz codec emits the `has_info_ext = false` shape
/// (no `_Z_MSG_EXT_ENC_ZINT | 0x01` `ExtQueryableInfo` tail). zenoh-
/// pico produces the same byte sequence when both `complete = false`
/// and `distance = 0`, which is the default `_z_queryable_infos_t`
/// shipped by `z_query_consolidation_default`. A future round (R121j)
/// that needs `complete = true` or non-zero `distance` will add a
/// separate `build_declare_queryable_with_info` helper carrying the
/// extra `Z` ext bytes; this helper's wire-byte contract for the
/// no-ext shape is pinned by the byte-compare test below.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclQueryable.header = _Z_DECL_QUERYABLE_MID (0x04)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x40 from parent.M
///                              dispatch on the wireexpr import,
///                              always set under the wz convention of
///                              Local-arm wireexpr)]
///   VLE(queryable_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// The codegen-derived M bit follows the same convention as
/// [`build_declare_subscriber`]: `<sce:variant-dispatch
/// flag="header.M"/>` on the wireexpr `<sce:import>` in
/// `sources/codecs/decl_queryable.scxml` (post-R121h-pre B5-ν
/// ownership invert) ORs 0x40 in for the `WireexprLocal` arm. The
/// author-supplied header carries the MID + optional N (suffix gate);
/// M is derived at encode time.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention mirrors
/// [`build_declare_subscriber`]:
///   - `(0, Some(s))`: literal — the queried keyexpr is `s` itself
///     (id=0 is the wz literal-sentinel).
///   - `(N, None)`: alias — the queried keyexpr is the peer's
///     mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + `s`.
#[cfg(feature = "codec-declare")]
pub fn build_declare_queryable(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
            // MID 0x04 (_Z_DECL_QUERYABLE_MID per
            // vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/declarations.h:32)
            // + N gate; M is codegen-derived.
            header: 0x04 | n_flag,
            id: queryable_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

/// R121i-b — build a `Declare` network-message that registers a
/// liveliness token on the peer for `(keyexpr_mapping_id,
/// keyexpr_suffix)`. Mirrors zenoh-pico `_z_decl_token_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:123-126`
/// (a thin `_z_decl_commons_encode` wrapper with `has_extensions =
/// false`).
///
/// Liveliness tokens are unconditionally zero-tail: the zenoh-pico
/// encoder has no extension surface at all (compare to DeclQueryable's
/// `ExtQueryableInfo`), so this builder's emit shape is byte-stable
/// for every `(id, mapping, suffix)` input.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclToken.header = _Z_DECL_TOKEN_MID (0x06)
///                        | (suffix.is_some() ? 0x20 : 0)
///                        | (codegen-derived: 0x40 from parent.M
///                          dispatch on the wireexpr import)]
///   VLE(token_id)
///   wireexpr.encode
/// ```
///
/// Same M-bit derivation contract as [`build_declare_subscriber`] /
/// [`build_declare_queryable`]: `<sce:variant-dispatch
/// flag="header.M"/>` on the wireexpr import in
/// `sources/codecs/decl_token.scxml`. The wireexpr arm is always
/// `WireexprLocal` here; `WireexprNonlocal` is reserved for future
/// Interest / Reply paths (R121j+).
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention matches the
/// other DECLARE builders (literal / alias / compound).
#[cfg(feature = "codec-declare")]
pub fn build_declare_token(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclToken(DeclToken {
            // MID 0x06 (_Z_DECL_TOKEN_MID per
            // vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/declarations.h:34)
            // + N gate; M is codegen-derived.
            header: 0x06 | n_flag,
            id: token_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

// ─── R121i-d: WireexprNonlocal-arm DECLARE builders ──────────────────
//
// Companions to `build_declare_subscriber` / `build_declare_queryable`
// / `build_declare_token` for the M=0 case (the wire byte that
// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:63`
// dubs `_Z_FLAG_N_..._M`, derived at the wireexpr `<sce:import>` from
// the variant arm — Local → 0x40 OR, Nonlocal → no OR).
//
// Encoder-perspective locality (sources/codecs/wireexpr.scxml docblock
// + zenoh-pico `_z_wireexpr_is_local` at core.h:182):
//
//   M = 1 (Local arm)    sender's wireexpr was rooted in the sender's
//                        own mapping table — i.e. wz declared the
//                        keyexpr's mapping_id itself.
//   M = 0 (Nonlocal arm) sender's wireexpr was rooted in the *peer's*
//                        mapping table — i.e. wz is referring to a
//                        mapping_id that was DeclKexpr'd by the peer
//                        and registered into wz's peer-keyexpr table.
//
// Use case (the gap these builders close — without them wz could not
// emit DECLARE traffic that references peer-declared mappings, which
// is the cross-validation surface that AP MVP inbound parsing
// (R121j-5+) will trigger). Pre-R121i-d, the four DECLARE builders
// hard-coded the WireexprLocal arm, so a wz acceptor that received a
// peer's DeclKexpr could not in turn DeclSubscriber against that
// peer's id without the codegen-derived M bit silently emitting M=1
// (wrong direction — would tell the peer "I own this mapping" when
// in fact the peer owns it).
//
// `build_declare_kexpr` (the mapping-population variant) deliberately
// has *no* `_nonlocal` companion: DeclKexpr's purpose is the sender
// installing a (id, literal) pair *into its own* mapping table; the
// inner wireexpr is the literal itself (id=0 + suffix sentinel), and
// encoder-perspective locality is by definition Local. A
// `build_declare_kexpr_nonlocal` would mean "I am declaring a mapping
// owned by you" — semantically void; zenoh-pico has no such encoder
// path and the peer would reject it (declarations.c:52 sets M=1 via
// the unconditional `_z_wireexpr_is_local(LOCAL)=true` of the
// freshly-built `_z_wireexpr_t`).
//
// `id == 0` rejection: in the Nonlocal arm, mapping_id 0 is also
// nonsense — zenoh-pico's `_Z_KEYEXPR_MAPPING_LOCAL` sentinel is
// `(uintptr_t)0` (core.h:151), so a remote-mapped id=0 would refer
// to "the peer's literal-sentinel slot" which has no table entry.
// Each `_nonlocal` builder panics on id=0 with the same shape as
// `build_declare_kexpr_rejects_zero_mapping_id`.

/// R121i-d — build a `Declare(DeclSubscriber)` that registers a
/// subscriber on the peer for a keyexpr rooted in the *peer's*
/// mapping table (M=0 wire arm). Mirror of [`build_declare_subscriber`]
/// for the Nonlocal case; see the module-level docblock above for the
/// encoder-perspective locality semantics.
///
/// `keyexpr_mapping_id` is the peer-declared mapping id; `keyexpr_suffix`
/// is the optional tail concatenated to that mapping's literal at the
/// peer (`None` = pure alias, `Some(s)` = composite). Panics on
/// `keyexpr_mapping_id == 0` (literal-sentinel inversion is not
/// representable in the Nonlocal arm — use [`build_declare_subscriber`]
/// with `(0, Some(s))` for literal subscriptions).
///
/// Wire shape after the `N_MID_DECLARE` envelope (mirror of the Local
/// builder's wire shape with the M-bit derivation flipped):
///
/// ```text
///   [DeclSubscriber.header = _Z_DECL_SUBSCRIBER_MID (0x02)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x00 from Nonlocal
///                              arm dispatch on the wireexpr import)]
///   VLE(subscriber_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
#[cfg(feature = "codec-declare")]
pub fn build_declare_subscriber_nonlocal(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_subscriber_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel, which is only representable \
         in the Local arm — call build_declare_subscriber instead",
    );
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
            header: 0x02 | n_flag,
            id: subscriber_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

/// R121i-d — build a `Declare(DeclQueryable)` for a keyexpr rooted in
/// the peer's mapping table (M=0 wire arm). Mirror of
/// [`build_declare_queryable`] for the Nonlocal case. The id=0
/// rejection rule from [`build_declare_subscriber_nonlocal`] applies
/// identically. Emit follows the `has_info_ext = false` shape
/// (default-state `_z_queryable_infos_t`); a future round adding
/// `complete` / `distance` will introduce a separate
/// `build_declare_queryable_nonlocal_with_info` helper.
#[cfg(feature = "codec-declare")]
pub fn build_declare_queryable_nonlocal(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_queryable_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel — call build_declare_queryable instead",
    );
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
            header: 0x04 | n_flag,
            id: queryable_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

/// R121i-d — build a `Declare(DeclToken)` for a keyexpr rooted in the
/// peer's mapping table (M=0 wire arm). Mirror of
/// [`build_declare_token`] for the Nonlocal case. Same id=0 rejection
/// rule as the other `_nonlocal` builders. DeclToken has no extension
/// surface at all, so the no-ext byte-stability contract is preserved.
#[cfg(feature = "codec-declare")]
pub fn build_declare_token_nonlocal(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_token_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel — call build_declare_token instead",
    );
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclToken(DeclToken {
            header: 0x06 | n_flag,
            id: token_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    }
}

/// R121i-c — build a `Declare(UndeclKexpr)` network-message that
/// retracts a previously declared keyexpr-mapping (id) on the peer.
/// Mirrors zenoh-pico `_z_undecl_kexpr_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:86-89`.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [UndeclKexpr.header = _Z_UNDECL_KEXPR_MID (0x01)]
///   VLE(mapping_id)
/// ```
///
/// UndeclKexpr has no wireexpr body and no Z-ext surface (unlike the
/// other three Undecl_* variants below): the retraction is purely
/// id-based because the peer already has the (id -> keyexpr) entry
/// from a prior `Declare(DeclKexpr)`. The Z bit is bit-7 of the
/// header and is left clear by every conformant zenoh-pico
/// emit — wz mirrors that contract.
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_kexpr(mapping_id: u64) -> Declare {
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohUndeclKexpr(UndeclKexpr {
            header: 0x01, // _Z_UNDECL_KEXPR_MID
            id: mapping_id,
        }),
    }
}

/// R121i-c — build a `Declare(UndeclSubscriber)` network-message that
/// retracts a previously declared subscription (id) on the peer.
/// Mirrors zenoh-pico `_z_undecl_subscriber_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:90-103`.
///
/// AP MVP scope: the wz UndeclSubscriber codec emits the no-ext
/// shape only. The wz codegen for UndeclSubscriber does not model
/// the optional `_z_decl_ext_keyexpr_encode` tail (declarations.c:38-50)
/// — the SCXML stops at `id`. Peers route undeclare by id alone, so
/// the ext is purely informational at this layer (used by routers for
/// cross-validation). Future rounds that need the ext_keyexpr surface
/// extend `sources/codecs/undecl_subscriber.scxml` with the optional
/// ext field + add a separate `build_undeclare_subscriber_with_keyexpr`
/// helper; the no-ext contract here stays byte-stable.
///
/// Wire shape:
///
/// ```text
///   [UndeclSubscriber.header = _Z_UNDECL_SUBSCRIBER_MID (0x03)]
///   VLE(subscriber_id)
/// ```
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_subscriber(subscriber_id: u64) -> Declare {
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
            header: 0x03, // _Z_UNDECL_SUBSCRIBER_MID
            id: subscriber_id,
        }),
    }
}

/// R121i-c — build a `Declare(UndeclQueryable)` network-message that
/// retracts a previously declared queryable (id) on the peer. Same
/// no-ext shape contract as [`build_undeclare_subscriber`]; mirrors
/// zenoh-pico `_z_undecl_queryable_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:120-122`.
///
/// Wire shape:
///
/// ```text
///   [UndeclQueryable.header = _Z_UNDECL_QUERYABLE_MID (0x05)]
///   VLE(queryable_id)
/// ```
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_queryable(queryable_id: u64) -> Declare {
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable {
            header: 0x05, // _Z_UNDECL_QUERYABLE_MID
            id: queryable_id,
        }),
    }
}

/// R121i-c — build a `Declare(UndeclToken)` network-message that
/// retracts a previously declared liveliness token (id) on the peer.
/// Same no-ext shape contract as [`build_undeclare_subscriber`];
/// mirrors zenoh-pico `_z_undecl_token_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:128-130`.
///
/// Wire shape:
///
/// ```text
///   [UndeclToken.header = _Z_UNDECL_TOKEN_MID (0x07)]
///   VLE(token_id)
/// ```
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_token(token_id: u64) -> Declare {
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohUndeclToken(UndeclToken {
            header: 0x07, // _Z_UNDECL_TOKEN_MID
            id: token_id,
        }),
    }
}

/// R121i-c — build a `Declare(DeclFinal)` marker that terminates a
/// declaration sequence on the wire. Mirrors zenoh-pico
/// `_z_decl_final_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:131-135`:
/// a single-byte `0x1A` marker with no body, no id, no ext.
///
/// DeclFinal is used by zenoh-pico as the sentinel that signals the
/// end of an Interest-driven declaration batch (router → peer
/// replay). For the unsolicited DECLARE outbound path the wz AP MVP
/// uses (R121g+), DeclFinal is not strictly required, but the helper
/// is provided so the future Interest/Reply path (R121j+) has the
/// terminator builder ready when it needs to close a multi-DECLARE
/// reply sequence.
///
/// Wire shape: `[N_MID_DECLARE, 0x1A]` — exactly two bytes.
#[cfg(feature = "codec-declare")]
pub fn build_declare_final() -> Declare {
    Declare {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareVariant::CodecZenohDeclFinal(DeclFinal {
            header: 0x1A, // _Z_DECL_FINAL_MID
        }),
    }
}

/// R279 — build an `Interest` network-message that subscribes to the
/// peer's `DeclToken` / `UndeclToken` stream restricted to a specific
/// keyexpr. Mirrors zenoh-pico `_z_n_interest_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:452-486` invoked
/// from `_z_register_liveliness_subscriber` with
/// `flags = KEYEXPRS | TOKENS | RESTRICTED | FUTURE [| CURRENT]`
/// (`vendor/zenoh-pico/src/net/liveliness.c:169-198` via
/// `vendor/zenoh-pico/src/session/interest.c:204-209`).
///
/// Wire shape (composed by `Interest::encode` from the
/// `sources/codecs/interest.scxml` envelope + `interest_body.scxml`
/// inner body):
///
/// ```text
///   [outer header = N_MID_INTEREST (0x19)
///                    | (history ? 0x20 : 0)   // C = CURRENT
///                    | 0x40                    // F = FUTURE
///                    | (Z extensions = 0 here)]
///   VLE(interest_id)
///   [InterestBody.header = 0x01 (KE) | 0x08 (TO) | 0x10 (R)
///                          | (suffix.is_some() ? 0x20 : 0) // N
///                          | 0x40                           // M (Local)
///                          ]
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// N/M bit positions on `InterestBody.header` (bits 5 and 6) coincide
/// with the C/F bit positions on the outer `Interest.header` — that
/// is intentional and matches zenoh-pico's `_Z_INTEREST_FLAG_COPY_MASK
/// = 0x9F` reorder at `vendor/zenoh-pico/src/protocol/codec/interest.c:37`:
/// the encoder hoists C/F to the outer header, clears them from the
/// body, and stores N/M (wireexpr codec flags) at the freed positions.
/// The two `header` bytes are distinct wire bytes so the apparent
/// overload causes no collision; the body carrier owns its own bit
/// layout per `interest_body.scxml::header` flags carrier definition.
///
/// `history = true` instructs the peer to immediately replay the
/// current matching `DeclToken` set (zenoh-pico's
/// `_z_liveliness_subscription_trigger_history` fires after the
/// register call); `history = false` only registers for future
/// events. The `FUTURE` (F) bit is always set — a wz liveliness
/// subscriber that does not want future events would
/// [`Self::send_interest_final`] immediately after the declare and
/// the peer would remove the interest before any future event
/// arrives, which is the wrong shape (use a one-shot Query path for
/// "current matching set only").
///
/// `keyexpr_mapping_id == 0` with `keyexpr_suffix = Some(s)` targets
/// a literal keyexpr. Pure-alias (mapping_id != 0, suffix=None) and
/// composite (mapping_id != 0, suffix=Some) forms emit via the
/// `Local` wireexpr arm; the `Nonlocal` arm (M=0) for keyexprs
/// rooted in the peer's mapping table is reserved for a future
/// `_nonlocal` companion builder mirroring the DECLARE pattern.
pub fn build_interest_liveliness_subscriber(
    interest_id: u64,
    history: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Interest {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);

    // Outer header: MID 0x19 | F (always) | C (if history). Z stays
    // clear — wz emits no Interest-level extensions today; the
    // wz-codecs envelope leaves bit 7 free for a future ext-chain.
    let c_flag = if history { 0x20u8 } else { 0x00u8 };
    let f_flag = 0x40u8;

    // Inner body header carries the appetite bits (KE/SU/QU/TO/AG),
    // the restricted gate (R), and the wireexpr codec flags (N/M).
    // For a liveliness subscriber we set KE (the interest carries a
    // keyexpr), TO (we want token records), and R (restricted to the
    // attached keyexpr). SU/QU/AG stay clear because the AP MVP does
    // not subscribe to peer-declared subscribers / queryables /
    // aggregated keyexprs through this path.
    let ke_flag = 0x01u8;
    let to_flag = 0x08u8;
    let r_flag = 0x10u8;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    let m_flag = 0x40u8; // Local arm (M=1)
    let body_header = ke_flag | to_flag | r_flag | n_flag | m_flag;

    Interest {
        header: wire_const::N_MID_INTEREST | c_flag | f_flag,
        interest_id,
        body: Some(InterestBody {
            header: body_header,
            keyexpr: Some(Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            }),
        }),
        extensions: None,
    }
}

/// R279 — build an `Interest(Final)` network-message (C=0, F=0) that
/// terminates a previously emitted Interest. Mirrors zenoh-pico's
/// `_z_make_interest_final` at
/// `vendor/zenoh-pico/src/protocol/definitions/interest.c:27` and the
/// encoder-side path through `_z_n_interest_encode(.., is_final=true)`
/// at `vendor/zenoh-pico/src/protocol/codec/network.c:452-486` (the
/// `is_final` branch skips the inner body emit per interest.c:43-46).
///
/// Wire shape: `[N_MID_INTEREST (0x19), VLE(interest_id)]` — exactly
/// two bytes for `interest_id <= 0xFF`. No inner body (the
/// `_Z_INTEREST_NOT_FINAL_MASK` gate at interest.h:35 — C||F — is
/// clear), no extensions.
pub fn build_interest_final(interest_id: u64) -> Interest {
    Interest {
        header: wire_const::N_MID_INTEREST,
        interest_id,
        body: None,
        extensions: None,
    }
}

/// R121j-1 — build a `Request` network-message that carries a
/// `Query` body, addressed to the keyexpr resolved by
/// `(keyexpr_mapping_id, keyexpr_suffix)`. Mirrors zenoh-pico
/// `_z_request_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:114-169` with the
/// `_Z_REQUEST_QUERY` tag-arm + `_z_query_encode` body at
/// `vendor/zenoh-pico/src/protocol/codec/message.c:394-451`.
///
/// AP MVP scope: emits the minimal Query shape with no consolidation
/// (`Z_CONSOLIDATION_MODE_DEFAULT`), no parameters, no Query-level
/// extensions (body / info / attachment), and no Request-level
/// extensions (qos / tstamp / target / budget / timeout_ms). Under
/// these defaults zenoh-pico's `_z_msg_query_required_extensions`
/// returns zero, `_z_n_msg_request_needed_exts` returns zero, and
/// the outer Z flag stays clear — the wire reduces to:
///
/// ```text
///   [Request.header = _Z_MID_N_REQUEST (0x1C)
///                      | (suffix.is_some() ? 0x20 : 0)   // N
///                      | codegen-derived 0x40             // M from Local
///                      | (Z extensions = 0 here)]
///   VLE(rid)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
///   [Query.header = _Z_MID_Z_QUERY (0x03)]   // no C / P / Z flags
/// ```
///
/// Future rounds add layered helpers:
///   - `build_request_query_with_consolidation(consolidation_mode)`
///     sets bit 5 (`_Z_FLAG_Z_Q_C`) + emits the 1-byte consolidation
///     value (message.c:411-413).
///   - `build_request_query_with_parameters(params)` sets bit 6
///     (`_Z_FLAG_Z_Q_P`) + emits the params slice (message.c:426-428).
///   - `build_request_query_with_exts(...)` adds the body / info /
///     attachment Query-level extensions or the qos / tstamp /
///     target / budget / timeout_ms Request-level extensions.
///
/// Each layered helper extends this byte-compare contract with its
/// own vectors; the minimal shape pinned here is the foundation.
///
/// `rid` is the request id the peer echoes back in its Response /
/// ResponseFinal; reuse by the caller is allowed but the AP MVP path
/// allocates a fresh `rid` per `z_get` to keep the in-flight Query
/// table simple.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention matches the
/// DECLARE builders:
///   - `(0, Some(s))`: literal — the queried keyexpr is `s` itself
///     (id=0 is the wz literal-sentinel).
///   - `(N, None)`: alias — the queried keyexpr is the peer's
///     mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + `s`.
#[cfg(feature = "codec-request")]
pub fn build_request_query(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Request {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Request {
        // MID 0x1C (_Z_MID_N_REQUEST) + N gate; M is codegen-derived
        // from the wireexpr Local arm. Z (outer ext) stays clear:
        // this minimal builder emits no Request-level extensions.
        header: 0x1C | n_flag,
        rid,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: keyexpr_mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: RequestVariant::CodecZenohQuery(Query {
            // MID 0x03 (_Z_MID_Z_QUERY) only. No C (consolidation),
            // no P (params), no Z (Query-level exts). The byte-
            // compare test below pins this minimal shape.
            header: 0x03,
            consolidation: None,
            parameters_len: None,
            parameters: None,
            extensions: None,
        }),
    }
}

/// R121j-2a — fluent builder for `Request(Query)` that composes the
/// layered options exposed individually by R121j-1a/1b/1c/1d/1e
/// (consolidation / parameters / Query-attachment / Request-timeout
/// / Request-target). The five one-shot helpers below stay as thin
/// wrappers around this builder so existing callers see no surface
/// change; the builder unlocks the multi-layer composition that the
/// one-shot helpers cannot express (each one-shot resets the
/// extensions vec, so chaining two of them via `.body` mutation
/// silently drops the first).
///
/// Setter validation (panic conditions) is preserved per layer:
/// `parameters` rejects empty / oversize, `query_attachment` rejects
/// empty / oversize, `request_timeout_ms` rejects zero. The default
/// values that zenoh-pico's encoder omits from the wire
/// (`ConsolidationMode::AUTO`, `QueryTarget::BEST_MATCHING`, empty
/// params / attachment, zero timeout) remain non-representable —
/// callers wanting any of those simply do not call the corresponding
/// setter, leaving the field as `None` in the builder so `build()`
/// emits the minimal-shape wire bytes that match zenoh-pico's
/// encode-on-non-default predicate at network.c / message.c.
///
/// Request-level extension ordering at `build()` time follows
/// zenoh-pico's `_z_request_encode` chain
/// (vendor/zenoh-pico/src/protocol/codec/network.c:122-167):
/// qos → tstamp → target → budget → timeout. The intermediate Z
/// chain-continuation bits are set on every entry except the last.
/// (Only target + timeout are implemented as setters today; qos /
/// tstamp / budget sub-setters layer in once their codec wiring lands
/// — see the audit-traced carry in the Round 121j-1d /1e entries.)
#[cfg(feature = "codec-request")]
pub struct RequestQueryBuilder {
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    // Query-layer settings.
    consolidation: Option<ConsolidationMode>,
    parameters: Option<Vec<u8>>,
    query_attachment: Option<Vec<u8>>,
    // Request-layer ext settings.
    request_qos: Option<u8>,
    request_tstamp: Option<Timestamp>,
    request_target: Option<QueryTarget>,
    request_budget: Option<u32>,
    request_timeout_ms: Option<u64>,
}

#[cfg(feature = "codec-request")]
impl RequestQueryBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_request_query`]: minimal Request(Query) envelope with
    /// the keyexpr arm (literal id=0 + Some, alias id=N + None,
    /// compound id=N + Some). Same id/suffix semantics.
    pub fn new(rid: u64, keyexpr_mapping_id: u64, keyexpr_suffix: Option<&str>) -> Self {
        Self {
            rid,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            consolidation: None,
            parameters: None,
            query_attachment: None,
            request_qos: None,
            request_tstamp: None,
            request_target: None,
            request_budget: None,
            request_timeout_ms: None,
        }
    }

    /// Set the Request-level qos extension to the caller-supplied
    /// packed byte. Bit layout per zenoh-pico's `_z_n_qos_create`
    /// (`vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h`):
    ///
    /// ```text
    ///   bits 0-2: priority (0-7; zenoh-pico z_priority_t)
    ///   bit  3:   nodrop   (1 = BLOCK on congestion; 0 = DROP)
    ///   bit  4:   express  (1 = express path; 0 = normal)
    ///   bits 5-7: reserved (zero)
    /// ```
    ///
    /// The setter is intentionally low-level — wz exposes the
    /// pre-packed byte so callers integrating directly with
    /// zenoh-pico-defined constants can pass `_z_n_qos_create`'s
    /// output verbatim. A typed wrapper layering over this setter
    /// (`.request_qos_typed(priority, congestion, express)`) is a
    /// future ergonomic refinement.
    ///
    /// Emit position in the Request-level ext chain is FIRST (qos →
    /// tstamp → target → budget → timeout), matching zenoh-pico's
    /// `_z_request_encode` order at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c`.
    pub fn request_qos(mut self, packed: u8) -> Self {
        self.request_qos = Some(packed);
        self
    }

    /// Typed wrapper over [`Self::request_qos`] — packs `(priority,
    /// congestion, express)` into the wire byte using the exact bit
    /// layout zenoh-pico's `_z_n_qos_create` produces at
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:84-89`:
    ///
    /// ```text
    ///   packed = (express << 4) | (nodrop << 3) | priority
    ///   where nodrop = (congestion == Block ? 1 : 0)
    /// ```
    ///
    /// Caller-facing typed inputs keep the priority / congestion /
    /// express semantics legible at the call site (vs the raw
    /// [`Self::request_qos`] packed-byte form). The wrapper does NOT
    /// validate the bit layout itself — it delegates to the same
    /// [`Self::request_qos`] storage so the chain emit path stays
    /// uniform.
    pub fn request_qos_typed(
        self,
        priority: Priority,
        congestion: CongestionControl,
        express: bool,
    ) -> Self {
        let packed = ((express as u8) << 4) | (congestion.wire_bit() << 3) | priority.wire_byte();
        self.request_qos(packed)
    }

    /// Set the Request-level timestamp extension. `time` is the
    /// 64-bit NTP-style timestamp the requester is correlating against
    /// (typically `Hal::now_ticks_*` lifted into the zenoh-pico NTP
    /// 64-bit shape); `zid` is the requester's zid bytes (1..=16 bytes
    /// per zenoh `_z_id_t` capacity at
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/core.h`'s
    /// `_Z_ID_LENGTH = 16`). Panics on empty zid (zenoh-pico's
    /// `_z_id_encode_as_slice` at
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:58-70` rejects
    /// zero-length zid as a zenoh-protocol violation) and on a zid
    /// longer than 16 bytes.
    ///
    /// Wire shape per `_z_request_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:132-137`:
    ///
    /// ```text
    ///   ext_header  = ENC_ZBUF(0x40) | id_tstamp(0x02)
    ///                 (NO M flag — zenoh-pico emits ext_tstamp as
    ///                  non-mandatory; the ext gets only the Z chain-
    ///                  continuation bit if a later ext follows.)
    ///   ext_value   = VLE(timestamp_body_len) + Timestamp.encode_bytes
    ///   Timestamp   = VLE(time) + VLE(zid_len) + zid_bytes
    /// ```
    ///
    /// Emit position in the Request-level ext chain is SECOND (qos →
    /// tstamp → target → budget → timeout), matching zenoh-pico's
    /// `_z_request_encode` order. The wire-shape match is verified by
    /// the byte-stable `request_query_builder_request_tstamp_emits_*`
    /// tests below.
    pub fn request_tstamp(mut self, time: u64, zid: &[u8]) -> Self {
        assert!(
            !zid.is_empty(),
            "RequestQueryBuilder::request_tstamp requires a non-empty zid \
             (zenoh-pico rejects len=0 as a protocol violation)",
        );
        assert!(
            zid.len() <= 16,
            "RequestQueryBuilder::request_tstamp zid length {} exceeds zenoh _Z_ID_LENGTH (16)",
            zid.len(),
        );
        self.request_tstamp = Some(Timestamp {
            time,
            zid_len: zid.len() as u64,
            zid: zid.to_vec(),
        });
        self
    }

    /// Set the Query-body consolidation mode. Subsequent calls
    /// overwrite (last-wins; standard builder idiom). See
    /// [`ConsolidationMode`] for the wire-byte contract.
    pub fn consolidation(mut self, mode: ConsolidationMode) -> Self {
        self.consolidation = Some(mode);
        self
    }

    /// Set the Query-body parameters slice. Panics on empty
    /// (zenoh-pico's encoder clears Q_P on empty) and on
    /// `len > REQUEST_QUERY_PARAMETERS_MAX_LEN` (wz codec bound).
    pub fn parameters(mut self, params: &[u8]) -> Self {
        assert!(
            !params.is_empty(),
            "RequestQueryBuilder::parameters requires a non-empty params slice",
        );
        assert!(
            params.len() <= REQUEST_QUERY_PARAMETERS_MAX_LEN,
            "params slice length {} exceeds wz Query codec's max-size ({})",
            params.len(),
            REQUEST_QUERY_PARAMETERS_MAX_LEN,
        );
        self.parameters = Some(params.to_vec());
        self
    }

    /// Set the Query-level attachment extension payload. Panics on
    /// empty and on `len > QUERY_EXT_ZBUF_MAX_LEN`.
    pub fn query_attachment(mut self, attachment: &[u8]) -> Self {
        assert!(
            !attachment.is_empty(),
            "RequestQueryBuilder::query_attachment requires a non-empty attachment slice",
        );
        assert!(
            attachment.len() <= QUERY_EXT_ZBUF_MAX_LEN,
            "attachment slice length {} exceeds wz ExtZbuf codec's max-size ({})",
            attachment.len(),
            QUERY_EXT_ZBUF_MAX_LEN,
        );
        self.query_attachment = Some(attachment.to_vec());
        self
    }

    /// Set the Request-level target extension. Wire mapping per
    /// [`QueryTarget::wire_byte`]; the M=1 mandatory marker is set on
    /// the emitted ExtEntry header per zenoh-pico convention
    /// (network.c:140).
    pub fn request_target(mut self, target: QueryTarget) -> Self {
        self.request_target = Some(target);
        self
    }

    /// Set the Request-level budget extension. Panics on zero
    /// (zenoh-pico's `_z_n_msg_request_needed_exts` at
    /// `vendor/zenoh-pico/src/protocol/definitions/network.c`
    /// declares `ext_budget = msg->_ext_budget != 0`, so a zero
    /// budget is encoded as "ext absent"). The value is the
    /// per-Query reply-volume budget; emit position sits between
    /// target and timeout in the Request-level ext chain.
    pub fn request_budget(mut self, value: u32) -> Self {
        assert!(
            value != 0,
            "RequestQueryBuilder::request_budget requires a non-zero budget; \
             zenoh-pico's ext_budget predicate clears the ext on zero",
        );
        self.request_budget = Some(value);
        self
    }

    /// Set the Request-level timeout extension. Panics on zero (the
    /// zenoh-pico encoder predicate clears the ext on zero).
    pub fn request_timeout_ms(mut self, timeout_ms: u64) -> Self {
        assert!(
            timeout_ms != 0,
            "RequestQueryBuilder::request_timeout_ms requires a non-zero timeout",
        );
        self.request_timeout_ms = Some(timeout_ms);
        self
    }

    /// Materialise the Request. Constructs the baseline envelope via
    /// [`build_request_query`], applies all Query-layer settings to
    /// the inner Query body, then assembles Request-level extensions
    /// in zenoh-pico's emit order with proper Z chain-continuation
    /// bits on intermediate entries.
    pub fn build(self) -> Request {
        let mut request = build_request_query(
            self.rid,
            self.keyexpr_mapping_id,
            self.keyexpr_suffix.as_deref(),
        );

        // Query-layer settings (consolidation / parameters /
        // Q-attachment). The codec gates these on Query.header
        // flags Q_C(0x20) / Q_P(0x40) / Q_Z(0x80).
        if let RequestVariant::CodecZenohQuery(ref mut query) = request.body {
            if let Some(mode) = self.consolidation {
                query.header |= 0x20;
                query.consolidation = Some(mode.wire_byte());
            }
            if let Some(params) = self.parameters {
                query.header |= 0x40;
                query.parameters_len = Some(params.len() as u64);
                query.parameters = Some(params);
            }
            if let Some(attachment) = self.query_attachment {
                query.header |= 0x80;
                query.extensions = Some(vec![ExtEntry {
                    header: 0x40 | 0x05, // ENC_ZBUF | id_attachment
                    body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                        value_len: attachment.len() as u64,
                        value: attachment,
                    }),
                }]);
            }
        } else {
            unreachable!(
                "build_request_query must produce a CodecZenohQuery body — \
                 the layered builder relies on this invariant"
            );
        }

        // Request-level extensions in zenoh-pico encode order: qos →
        // tstamp → target → budget → timeout (network.c:122-167).
        // Today qos + tstamp + target + budget + timeout are exposed;
        // any future ext lands in its position-correct slot here.
        let mut request_exts: Vec<ExtEntry> = Vec::new();
        if let Some(packed) = self.request_qos {
            request_exts.push(ExtEntry {
                // ENC_ZINT(0x20) | id_qos(0x01). No M flag — qos is
                // an informational hint, not mandatory per the
                // ext_qos M=0 convention at zenoh-pico
                // vendor/zenoh-pico/src/protocol/codec/network.c.
                // Z bit set below as a chain-continuation step if a
                // later ext follows.
                header: 0x20 | 0x01,
                body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                    value: packed as u64,
                }),
            });
        }
        if let Some(tstamp) = self.request_tstamp {
            // ENC_ZBUF(0x40) | id_tstamp(0x02). No M flag — zenoh-pico
            // emits ext_tstamp as non-mandatory at network.c:132-137
            // (only the Z chain-continuation bit is OR'd in, no
            // _Z_MSG_EXT_FLAG_M). Z bit set below as a chain step if
            // target / budget / timeout follow. The ext value carries
            // a self-describing length prefix (zenoh-pico's
            // `_z_timestamp_encode_ext` at message.c:95-100 emits
            // `_z_zsize_encode(ext_size)` before the Timestamp body;
            // wz's ExtZbuf encode at ext_zbuf.rs auto-emits
            // VLE(value_len) + bytes which matches that wire shape).
            let body_bytes = tstamp.encode_to_vec();
            request_exts.push(ExtEntry {
                header: 0x40 | 0x02,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: body_bytes.len() as u64,
                    value: body_bytes,
                }),
            });
        }
        if let Some(target) = self.request_target {
            request_exts.push(ExtEntry {
                // ENC_ZINT(0x20) | M(0x10) | id_target(0x04). Z bit
                // set below as a chain step if a later ext follows.
                header: 0x20 | 0x10 | 0x04,
                body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                    value: target.wire_byte() as u64,
                }),
            });
        }
        if let Some(budget) = self.request_budget {
            request_exts.push(ExtEntry {
                // ENC_ZINT(0x20) | id_budget(0x05). No M flag —
                // budget is informational per zenoh-pico's encode
                // pattern at network.c:144-149. Position between
                // target and timeout per the same source.
                header: 0x20 | 0x05,
                body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                    value: budget as u64,
                }),
            });
        }
        if let Some(timeout_ms) = self.request_timeout_ms {
            request_exts.push(ExtEntry {
                // ENC_ZINT(0x20) | id_timeout(0x06). M stays clear
                // (timeout is informational).
                header: 0x20 | 0x06,
                body: ExtEntryVariant::CodecZenohExtZint(ExtZint { value: timeout_ms }),
            });
        }

        if !request_exts.is_empty() {
            request.header |= 0x80; // N_Z (Request-level exts present)
                                    // Z chain-continuation: set 0x80 on every entry except
                                    // the last so the decoder loop consumes the whole chain.
            let last_idx = request_exts.len() - 1;
            for (i, ext) in request_exts.iter_mut().enumerate() {
                if i < last_idx {
                    ext.header |= 0x80;
                }
            }
            request.extensions = Some(request_exts);
        }

        request
    }
}

/// R121j-1h — mirror of zenoh-pico's `z_priority_t` enum at
/// `vendor/zenoh-pico/include/zenoh-pico/api/constants.h:241-251`.
/// 8 priorities, 0..=7, with `Data` as the default. The wire byte
/// occupies the qos packed byte's low 3 bits per
/// `_z_n_qos_create` at network.h:84-89.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Priority {
    /// `_Z_PRIORITY_CONTROL = 0`. Reserved for internal control
    /// messages in zenoh-pico (the leading-underscore name signals
    /// "implementation detail" upstream); application traffic should
    /// pick one of the public priorities below.
    Control = 0,
    /// `Z_PRIORITY_REAL_TIME = 1`. Highest application priority.
    RealTime = 1,
    /// `Z_PRIORITY_INTERACTIVE_HIGH = 2`.
    InteractiveHigh = 2,
    /// `Z_PRIORITY_INTERACTIVE_LOW = 3`.
    InteractiveLow = 3,
    /// `Z_PRIORITY_DATA_HIGH = 4`.
    DataHigh = 4,
    /// `Z_PRIORITY_DATA = 5` — `Z_PRIORITY_DEFAULT` per the same
    /// constants.h. Pick this when no other priority justifies an
    /// explicit override.
    Data = 5,
    /// `Z_PRIORITY_DATA_LOW = 6`.
    DataLow = 6,
    /// `Z_PRIORITY_BACKGROUND = 7`. Lowest priority.
    Background = 7,
}

impl Priority {
    /// Wire byte value as written into the qos packed byte's low 3
    /// bits. Mirrors the enum literal values verbatim per
    /// `_z_n_qos_create` at network.h:87.
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }
}

/// R121j-1h — mirror of zenoh-pico's `z_congestion_control_t` enum
/// at `vendor/zenoh-pico/include/zenoh-pico/api/constants.h:216-218`.
/// The wire mapping inverts the enum's integer value: `Block = 1`
/// in zenoh-pico's enum lifts into the `nodrop = 1` bit (bit 3) of
/// the qos packed byte per `_z_n_qos_create` at network.h:86-87.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionControl {
    /// `Z_CONGESTION_CONTROL_DROP = 0` (also `Z_CONGESTION_CONTROL_DEFAULT`).
    /// Messages may be dropped on congestion; nodrop bit cleared.
    Drop,
    /// `Z_CONGESTION_CONTROL_BLOCK = 1`. Producer blocks on
    /// congestion rather than dropping; nodrop bit set.
    Block,
}

impl CongestionControl {
    /// Wire-side `nodrop` bit value (0 for Drop, 1 for Block) that
    /// the qos packed byte's bit 3 carries. Named `wire_bit` rather
    /// than `wire_byte` to keep the boolean semantics legible at the
    /// call site in [`RequestQueryBuilder::request_qos_typed`].
    pub const fn wire_bit(self) -> u8 {
        match self {
            Self::Drop => 0,
            Self::Block => 1,
        }
    }
}

/// R121j-1a — explicit consolidation mode for the Query body. Mirrors
/// zenoh-pico's `z_consolidation_mode_t` enum
/// (vendor/zenoh-pico/include/zenoh-pico/api/constants.h:184-188) for
/// the three emitted modes; `AUTO` / `DEFAULT` (the encoder's "do not
/// transmit" sentinel `Z_CONSOLIDATION_MODE_DEFAULT =
/// Z_CONSOLIDATION_MODE_AUTO = -1`) is intentionally NOT representable
/// here — callers wanting that case call [`build_request_query`]
/// directly so the Q_C flag stays clear and the wire-byte count is
/// the minimal-shape baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsolidationMode {
    /// `Z_CONSOLIDATION_MODE_NONE = 0` — no consolidation; the
    /// peer forwards every reply in arrival order.
    None,
    /// `Z_CONSOLIDATION_MODE_MONOTONIC = 1` — the peer guarantees
    /// each reply for a given keyexpr is monotonic in some local
    /// ordering (typically timestamp).
    Monotonic,
    /// `Z_CONSOLIDATION_MODE_LATEST = 2` — the peer keeps only
    /// the latest reply per keyexpr; duplicates earlier in the
    /// stream are dropped.
    Latest,
}

impl ConsolidationMode {
    /// Wire byte value as written by zenoh-pico's `_z_uint8_encode`
    /// invocation in `_z_query_encode` (message.c:412). The mapping
    /// follows the enum literal values verbatim.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::None => 0u8,
            Self::Monotonic => 1u8,
            Self::Latest => 2u8,
        }
    }
}

/// R121j-1a — build a `Request(Query)` with an explicit
/// consolidation mode (one of the three "transmitted" zenoh-pico
/// modes). Wire shape extends [`build_request_query`]'s minimal
/// baseline by one byte:
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY (0x03) | _Z_FLAG_Z_Q_C (0x20)]
///   uint8(consolidation.wire_byte())   // <-- the layered addition
/// ```
///
/// The Q_C flag at bit 5 (`_Z_FLAG_Z_Q_C`) is set unconditionally
/// here — by construction the caller chose a non-AUTO mode, so
/// zenoh-pico's `has_consolidation` predicate
/// (`msg->_consolidation != Z_CONSOLIDATION_MODE_DEFAULT`,
/// message.c:402) is true and the encoder emits the flag + the byte.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` follow the same convention
/// as [`build_request_query`] (literal id=0 / alias / compound). No
/// params, no exts — those are separate layered helpers.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_consolidation(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    consolidation: ConsolidationMode,
) -> Request {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .consolidation(consolidation)
        .build()
}

/// R121j-1b — `parameters` slice max-size enforced by the wz Query
/// codec (sources/codecs/query.scxml's `sce:max-size="256"` on the
/// `parameters` field). Zenoh-pico's `_z_slice_t` is variable-length
/// upstream; wz's stripped-down scope bounds it at 256 to keep the
/// codec deterministic. The builder rejects `params.len() > 256` so
/// the caller surfaces the size violation at the call site rather
/// than as a runtime decoder error on the peer.
pub const REQUEST_QUERY_PARAMETERS_MAX_LEN: usize = 256;

/// R121j-1b — build a `Request(Query)` with an explicit parameters
/// slice (selector + key=value tail string in zenoh-pico, e.g.
/// `"category=temperature"`). Layered on top of [`build_request_query`]:
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY (0x03) | _Z_FLAG_Z_Q_P (0x40)]
///   VLE(params.len())                  // <-- the layered addition
///   params bytes
/// ```
///
/// The Q_P flag at bit 6 (`_Z_FLAG_Z_Q_P` per
/// vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/message.h:103)
/// is set unconditionally here — zenoh-pico's encoder sets it on any
/// non-empty `_parameters` slice (message.c:398-401), and the wz codec
/// gates the `parameters_len` / `parameters` field pair on `header.P`
/// (query.scxml's `sce:present-if="header.P"` on both).
///
/// Empty `params` is rejected (zenoh-pico's `has_params` predicate is
/// `_z_slice_check(&params) && params.len > 0`, so an empty slice
/// would clear Q_P and emit no params — the caller for an empty
/// case should call [`build_request_query`] directly). Slice length
/// above [`REQUEST_QUERY_PARAMETERS_MAX_LEN`] is also rejected to
/// match the wz codec's `sce:max-size="256"` bound.
///
/// `_implicit_anyke` (zenoh-pico's `**` / `?` selector convention
/// that prepends `_Z_QUERY_PARAMS_KEY_ANYKE` to the params at encode
/// time, message.c:414-425) is NOT modelled here — AP MVP simple
/// `z_get` does not set it. A future helper
/// (`build_request_query_with_parameters_and_anyke`) can layer the
/// anyke-prepend on top.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_parameters(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    params: &[u8],
) -> Request {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .parameters(params)
        .build()
}

/// R121j-1c — `attachment` slice max-size enforced by the wz ExtZbuf
/// codec (sources/codecs/ext_zbuf.scxml's `sce:max-size="32"` on
/// the `value` field). zenoh-pico's `_z_msg_ext_t.body._zbuf._val`
/// is variable-length upstream (no codec-level bound); wz's
/// stripped-down scope caps the ZBuf body at 32 bytes across all
/// ExtZbuf-encoded extensions (attachment, value-as-payload,
/// source_info-as-payload). A future round that needs larger
/// attachments either lifts the wz codec bound or adds a separate
/// `ExtZbufLarge` arm; until then the helper rejects oversize at
/// the call site so wz-to-wz interop does not silently fail at the
/// peer decoder. zenoh-pico peers accept arbitrarily large ZBuf
/// payloads, so wz-emit -> zenoh-pico-receive is unaffected.
pub const QUERY_EXT_ZBUF_MAX_LEN: usize = 32;

/// R121j-1c — build a `Request(Query)` with a single attachment
/// extension. Mirrors zenoh-pico's `_z_query_encode` attachment-ext
/// path (message.c:446-448): `_z_uint8_encode(extheader =
/// _Z_MSG_EXT_ENC_ZBUF | 0x05)` then `_z_bytes_encode(&attachment)`.
///
/// Wire shape (single-ext, attachment-only — no source_info, no
/// body/value ext):
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY(0x03) | _Z_FLAG_Z_Z(0x80)]
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZBUF(0x40) | ext_id(0x05)
///                       | Z(0x00, last entry)]               // = 0x45
///   VLE(attachment.len())
///   attachment bytes
/// ```
///
/// The Q_Z flag (Query-level, 0x80 = `_Z_FLAG_Z_Z` at the network
/// message layer per
/// vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/message.h:35)
/// signals "extension chain follows"; it is distinct from the
/// ext_entry.Z bit (chain-continuation marker, 0x80 on each entry
/// header except the last). With a single attachment ext, Q_Z is
/// set on Query.header and ext_entry.Z stays clear (no successor).
///
/// `ext_id = 0x05` is the attachment slot per zenoh-pico's
/// `_z_query_decode_extensions` switch (message.c:467: `case
/// _Z_MSG_EXT_ENC_ZBUF | 0x05: // Attachment`). The M flag
/// (mandatory, 0x10) stays clear — attachment is informational, the
/// peer may safely ignore it without breaking the query semantics
/// (matches zenoh-pico's encode shape at message.c:447 which emits
/// no M bit).
///
/// `attachment.is_empty()` is rejected: zenoh-pico's
/// `_z_msg_query_required_extensions` (message.c at the
/// `required_exts.attachment = _z_bytes_check(...) ? true : false`
/// site) only sets the attachment requirement when the bytes slice
/// is non-empty, so an empty attachment would silently clear the
/// ext from the wire and emit only the bare Query header (the
/// caller's intent is then plain `build_request_query`).
///
/// `attachment.len() > QUERY_EXT_ZBUF_MAX_LEN` is rejected to match
/// the wz codec's ExtZbuf bound; see the constant's doc-comment.
///
/// Source-info and body(Value) extensions are NOT covered by this
/// helper — separate concerns with their own sub-codec wiring
/// (source_info ext needs zid+eid+sn struct; body Value ext needs
/// the Value codec encoding+payload pair). Future
/// `build_request_query_with_source_info` /
/// `_with_body_value` / `_with_full_exts` helpers layer those.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_attachment(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    attachment: &[u8],
) -> Request {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .query_attachment(attachment)
        .build()
}

/// R121j-1d — build a `Request(Query)` carrying a Request-level
/// timeout extension. Mirrors zenoh-pico's `_z_request_encode`
/// timeout-ext path (vendor/zenoh-pico/src/protocol/codec/network.c:150-155):
/// `_z_uint8_encode(extheader = _Z_MSG_EXT_ENC_ZINT | 0x06)` followed
/// by `_z_zint64_encode(timeout_ms)`.
///
/// Wire shape (single Request-level ext, timeout-only — no qos /
/// tstamp / target / budget):
///
/// ```text
///   [Request.header | _Z_FLAG_Z_Z(0x80) | M_derived | N if suffix]
///   VLE(rid)
///   wireexpr.encode
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZINT(0x20) | ext_id_timeout(0x06)
///                       | Z(0x00, last entry)]                = 0x26
///   VLE(timeout_ms)                                       // ExtZint body
///   [Query.header = _Z_MID_Z_QUERY(0x03)]                 // inner body
/// ```
///
/// Two distinct Z bits at two layers — clarification:
/// 1. Request.header Z (0x80, `_Z_FLAG_Z_Z` at the network message
///    layer) gates the Request-level tlv-chain (Request.extensions).
///    This is set here.
/// 2. ExtEntry.header Z (0x80, chain-continuation marker on each
///    entry) signals "more entries follow"; for a single timeout ext
///    it stays clear (no successor).
///
/// `ext_id = 0x06` matches `_z_request_decode_extensions` case at
/// network.c:199-202 (`case 0x06 | _Z_MSG_EXT_ENC_ZINT`). M flag
/// (mandatory, 0x10) stays clear — timeout is informational; if the
/// peer ignores it the query simply doesn't time out at the peer's
/// table (matches zenoh-pico's encode at network.c:152 emitting no
/// M bit, unlike the target ext at line 140 which DOES set M).
///
/// `timeout_ms == 0` is rejected to match zenoh-pico's encoder
/// predicate `exts.ext_timeout_ms = msg->_ext_timeout_ms != 0`
/// (network.c at the `_z_n_msg_request_needed_exts` site at
/// vendor/zenoh-pico/src/protocol/definitions/network.c:29). A zero
/// timeout would silently clear the ext from the wire — the caller's
/// intent for "no timeout" is plain [`build_request_query`].
///
/// QoS / target / budget / tstamp Request-level exts are NOT covered
/// by this helper; sub-helpers for each follow the same pattern with
/// the appropriate ext_id and enc shape (qos/budget/timeout use
/// ZINT; tstamp uses ZBUF; target uses ZINT + M=1 since target is
/// mandatory for cross-router queries per network.c:140).
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_timeout_ms(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    timeout_ms: u64,
) -> Request {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .request_timeout_ms(timeout_ms)
        .build()
}

/// R121j-1e — explicit query-target enum for cross-router Query
/// dispatch. Mirrors zenoh-pico's `z_query_target_t`
/// (vendor/zenoh-pico/include/zenoh-pico/api/constants.h:262-266) for
/// the two transmitted values. `BEST_MATCHING (0)` is intentionally
/// NOT representable here — zenoh-pico's encoder predicate
/// `ext_target = _ext_target != Z_QUERY_TARGET_BEST_MATCHING`
/// (vendor/zenoh-pico/src/protocol/definitions/network.c:27) clears
/// the ext when the value is BEST_MATCHING, so callers wanting that
/// case use plain [`build_request_query`] and the wire bytes carry
/// no target ext (peer infers BEST_MATCHING from absence).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryTarget {
    /// `Z_QUERY_TARGET_ALL = 1` — every matching queryable
    /// receives the query and may reply.
    All,
    /// `Z_QUERY_TARGET_ALL_COMPLETE = 2` — only the queryables
    /// declared `complete = true` receive the query; useful when
    /// the client wants authoritative answers from peers that
    /// claim full coverage of the keyexpr.
    AllComplete,
}

impl QueryTarget {
    /// Wire byte value as written by zenoh-pico's `_z_zsize_encode`
    /// invocation in the `_z_request_encode` target-ext branch
    /// (network.c:142 `_z_zsize_encode(wbf, msg->_ext_target)`).
    /// `BEST_MATCHING (0)` is not present in this enum, so the
    /// wire byte is always `1` or `2`.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::All => 1u8,
            Self::AllComplete => 2u8,
        }
    }
}

/// R121j-1e — build a `Request(Query)` carrying a Request-level
/// query-target extension. Mirrors zenoh-pico's `_z_request_encode`
/// target-ext path (network.c:138-143): `_z_uint8_encode(extheader =
/// _Z_MSG_EXT_ENC_ZINT | 0x04 | _Z_MSG_EXT_FLAG_M)` followed by
/// `_z_zsize_encode(target_enum_value)`.
///
/// Wire shape (single Request-level ext, target-only):
///
/// ```text
///   [Request.header | _Z_FLAG_Z_Z(0x80) | M_derived | N if suffix]
///   VLE(rid)
///   wireexpr.encode
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZINT(0x20)
///                       | _Z_MSG_EXT_FLAG_M(0x10)
///                       | ext_id_target(0x04)
///                       | Z(0x00, last entry)]               = 0x34
///   VLE(target.wire_byte())                              // ExtZint body
///   [Query.header = _Z_MID_Z_QUERY(0x03)]
/// ```
///
/// `M = 1` on this ext header — target is **mandatory** for
/// cross-router dispatch (zenoh-pico network.c:140 ORs in
/// `_Z_MSG_EXT_FLAG_M` unconditionally for target, distinct from
/// timeout/qos/budget which leave M clear). A peer that does not
/// understand the target ext MUST reject the frame via
/// `_z_msg_ext_unknown_error` (per the ext_entry codec's M-flag
/// contract); routers without target awareness drop the query.
///
/// `ext_id = 0x04` matches `_z_request_decode_extensions` case at
/// network.c:186-191 (`case 0x04 | _Z_MSG_EXT_ENC_ZINT |
/// _Z_MSG_EXT_FLAG_M`).
///
/// `Z_QUERY_TARGET_BEST_MATCHING` (the default) is not part of
/// [`QueryTarget`] because zenoh-pico's encoder predicate clears
/// the ext on that value; the peer infers BEST_MATCHING from
/// ext-absence. Callers wanting BEST_MATCHING use plain
/// [`build_request_query`] and let the peer fall back to default.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_target(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    target: QueryTarget,
) -> Request {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .request_target(target)
        .build()
}

/// R121j-2 — build a `ResponseFinal` network-message that terminates
/// the multi-Reply sequence for `request_id`. Mirrors zenoh-pico
/// `_z_response_final_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:368-376`:
///
/// ```text
///   [ResponseFinal.header = _Z_MID_N_RESPONSE_FINAL (0x1A)]
///   VLE(request_id)
/// ```
///
/// AP MVP scope: minimal shape only — no Z(extensions) flag, no
/// trailing ExtEntry list. Future rounds that need RF-level
/// extensions (none defined in zenoh-pico today, but the wire format
/// reserves bit 7 for it via the `_Z_FLAG_Z_Z` carrier) extend this
/// helper with an exts-present variant.
///
/// ResponseFinal is a network-message envelope at the same layer as
/// `Declare` and `Request` — its `.encode_to_vec()` output is emitted
/// directly into the Frame payload without an additional wrapper
/// header. The 0x1A MID lives in the `_Z_MID_N_*` network-message
/// namespace (distinct from the inner DECLARE-body 0x1A
/// `_Z_DECL_FINAL_MID`, which is at a different layer).
///
/// `request_id` MUST equal the `rid` from the matching
/// [`build_request_query`] that opened the Query/Reply session.
#[cfg(feature = "codec-response-final")]
pub fn build_response_final(request_id: u64) -> ResponseFinal {
    ResponseFinal {
        // MID 0x1A (_Z_MID_N_RESPONSE_FINAL). Z bit-7 stays clear:
        // minimal shape has no RF-level extensions.
        header: 0x1A,
        request_id,
        extensions: None,
    }
}

/// R121j-3 — build a `Response(Reply(MsgPut))` network-message in
/// the minimal AP MVP shape (no Response-level exts, no Reply-level
/// consolidation, no Reply-level exts, no MsgPut timestamp /
/// encoding / exts). The wire is the queryable's data response to
/// an earlier `Request(Query)` keyed by `request_id`.
///
/// Mirrors the zenoh-pico encoder chain
/// `_z_response_encode -> _z_reply_encode -> _z_push_body_encode ->
/// _z_msg_put_encode`
/// (vendor/zenoh-pico/src/protocol/codec/network.c:241-304 +
/// vendor/zenoh-pico/src/protocol/codec/message.c:507-543 +
/// the put-encode at message.c:259-310).
///
/// Wire shape (literal-keyexpr case — `id=0 + suffix`):
///
/// ```text
///   [Response.header = _Z_MID_N_RESPONSE(0x1B)
///                       | _Z_FLAG_N_RESPONSE_N(0x20)         // suffix present
///                       | _Z_FLAG_N_RESPONSE_M(0x40)         // wireexpr Local arm (codegen-derived)
///                       | Z(0x00)]                           // no Response exts
///   VLE(request_id)
///   wireexpr Local: VLE(id=0), VLE(suffix.len()), suffix bytes
///   [Reply.header = _Z_MID_Z_REPLY(0x04)]                    // no C, no Z
///   [MsgPut.header = _Z_MID_Z_PUT(0x01)]                     // no T, no E, no Z
///   VLE(payload.len())
///   payload bytes
/// ```
///
/// `keyexpr_suffix` is required (no `Option<&str>`): the literal
/// shape's whole point is to carry the keyexpr inline, so an
/// empty / None literal would be a bug. For aliased-keyexpr replies
/// (publisher sent the matching Query through a mapped id), use
/// [`build_response_reply_aliased`].
///
/// Future R121j-3 sub-helpers (audit-traced carry):
/// `_with_consolidation(mode)` sets Reply.header.C(0x20) + 1-byte
/// consolidation; `_with_responder(zid, eid)` sets Response.header.Z
/// and emits the Responder ext (ext_id=0x03 ZBUF, zid+eid encoding
/// per network.c:281-291); `_with_reply_del(...)` swaps the MsgPut
/// arm for a MsgDel arm (delete instead of put as the reply payload).
#[cfg(feature = "codec-response")]
pub fn build_response_reply_literal(
    request_id: u64,
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Response {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_reply_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    Response {
        // MID 0x1B | N 0x20 (suffix present) | M codegen-derived
        // (Local arm sets 0x40). Z stays clear (no Response exts).
        header: 0x1B | 0x20,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohReply(Reply {
            // MID 0x04 only; no C (consolidation), no Z (Reply exts).
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                // MID 0x01 only; no T/E/Z gates.
                header: 0x01,
                timestamp: None,
                encoding: None,
                extensions: None,
                payload_len: payload.len() as u64,
                payload: payload.to_vec(),
            }),
        }),
    }
}

/// R121j-3 — build a `Response(Reply(MsgPut))` for a peer-declared
/// keyexpr mapping (aliased path). Mirror of
/// [`build_response_reply_literal`] for the case where the original
/// `Request(Query)` keyexpr resolved via a `Declare(DeclKexpr)`
/// previously sent in this session. The queryable replies referencing
/// the same mapping_id so the requester's wireexpr table resolves
/// the response to the original query keyexpr.
///
/// Convention matches the DECLARE / Request builders:
///   - `(N, None)`: pure alias — Reply targets peer's mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + suffix `s`.
///
/// Panics on `mapping_id == 0` — id=0 is the literal-keyexpr sentinel;
/// for literal replies use [`build_response_reply_literal`].
#[cfg(feature = "codec-response")]
pub fn build_response_reply_aliased(
    request_id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
    payload: &[u8],
) -> Response {
    assert!(
        mapping_id != 0,
        "build_response_reply_aliased requires a non-zero mapping id; \
         use build_response_reply_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Response {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohReply(Reply {
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                header: 0x01,
                timestamp: None,
                encoding: None,
                extensions: None,
                payload_len: payload.len() as u64,
                payload: payload.to_vec(),
            }),
        }),
    }
}

/// R121j-4 — build a `Response(Err)` network-message in the minimal
/// AP MVP shape (no Response-level exts, no Err encoding, no Err
/// exts). The wire is the queryable's error response to a Query that
/// it could not service — mirror of [`build_response_reply_literal`]
/// with the inner body arm swapped from `Reply` (MID 0x04) to `Err`
/// (MID 0x05). Same Response envelope shape: a peer expecting either
/// a Reply or Err discriminates on the inner MID byte after the
/// Response header / rid / wireexpr / Z-gated exts.
///
/// Mirrors zenoh-pico `_z_response_encode -> _z_err_encode` chain
/// (vendor/zenoh-pico/src/protocol/codec/network.c:241-304 +
/// vendor/zenoh-pico/src/protocol/codec/message.c:545+).
///
/// Wire shape (literal-keyexpr case — `id=0 + suffix`):
///
/// ```text
///   [Response.header = _Z_MID_N_RESPONSE(0x1B)
///                       | _Z_FLAG_N_RESPONSE_N(0x20)
///                       | _Z_FLAG_N_RESPONSE_M(0x40)
///                       | Z(0x00)]
///   VLE(request_id)
///   wireexpr Local: VLE(id=0), VLE(suffix.len()), suffix bytes
///   [Err.header = _Z_MID_Z_ERR(0x05)]            // no E, no Z
///   VLE(payload.len())
///   payload bytes
/// ```
///
/// `payload` is the error message body. zenoh-pico's `_z_err_encode`
/// at message.c:545+ writes `[Err.header | E | Z]` then the
/// E-gated Encoding sub-codec, then the Z-gated extension chain
/// (source_info / attachment), then always-present payload_len + bytes.
/// The minimal helper here emits only the always-present pair — no
/// encoding hint, no source-info, no attachment.
#[cfg(feature = "codec-response")]
pub fn build_response_err_literal(
    request_id: u64,
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Response {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_err_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    Response {
        header: 0x1B | 0x20, // MID | N (M codegen-derived from Local)
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohErr(Err {
            // MID 0x05 only; no E (encoding), no Z (exts).
            header: 0x05,
            encoding: None,
            extensions: None,
            payload_len: payload.len() as u64,
            payload: payload.to_vec(),
        }),
    }
}

/// R121j-4 — build a `Response(Err)` for a peer-declared keyexpr
/// mapping (aliased path). Mirror of [`build_response_err_literal`]
/// for the aliased case — same convention as the other DECLARE /
/// Request / Reply aliased builders ((N,None) pure alias /
/// (N,Some) compound). Panics on mapping_id=0.
#[cfg(feature = "codec-response")]
pub fn build_response_err_aliased(
    request_id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
    payload: &[u8],
) -> Response {
    assert!(
        mapping_id != 0,
        "build_response_err_aliased requires a non-zero mapping id; \
         use build_response_err_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Response {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohErr(Err {
            header: 0x05,
            encoding: None,
            extensions: None,
            payload_len: payload.len() as u64,
            payload: payload.to_vec(),
        }),
    }
}

/// R121j-2b — fluent builder for `Response(Reply)` that composes the
/// Reply-layer + Response-layer options on top of the minimal-shape
/// baseline provided by [`build_response_reply_literal`] /
/// [`build_response_reply_aliased`]. Mirror of [`RequestQueryBuilder`]
/// on the Response side.
///
/// Keyexpr convention (matches the rest of the wz builder family):
///   - `(0, Some(s))`: literal — Reply carries inline keyexpr suffix `s`.
///   - `(N, None)`: pure alias — Reply targets peer's mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + suffix `s`.
///
/// Reply-layer setters today: `consolidation` (R121j-3a), `reply_del`
/// body-arm swap (R121j-3d), and `responder` envelope-level ext
/// (R121j-3c). R121j-3b (Reply-body source_info as a Reply-LEVEL ext)
/// is wire-absent per zenoh-pico `_z_reply_encode` at
/// `src/protocol/codec/message.c:507-519` (no extensions chain on the
/// Reply body); the carry was retracted in Round 121j-4-retract.
#[cfg(feature = "codec-response")]
pub struct ResponseReplyBuilder {
    request_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    payload: Vec<u8>,
    // Reply-body-arm selector. Default false = MsgPut (the put-data
    // reply); .reply_del() flips to MsgDel (the delete-keyexpr reply).
    // Payload is unused when body_kind_del is true — the MsgDel body
    // carries no payload, just an optional timestamp + ext chain.
    body_kind_del: bool,
    // Reply-layer settings.
    consolidation: Option<ConsolidationMode>,
    // R121j-3c: Response-ENVELOPE-level responder ext (ext_id 0x03 ZBUF).
    // Tuple = (zid bytes 1..=16, eid). Distinct from R121j-4b Err.source_info
    // (Err-body-level): responder sits on the outer Response.extensions
    // chain, applies symmetrically to Reply and Err bodies, and is keyed
    // by zenoh-pico ext_id 0x03 per network.c:281-291. The Reply/Err inner
    // body is unaffected; envelope-level Z(0x80) on Response.header
    // signals chain presence.
    responder: Option<(Vec<u8>, u32)>,
}

#[cfg(feature = "codec-response")]
impl ResponseReplyBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_response_reply_literal`] / [`build_response_reply_aliased`]:
    /// minimal Response(Reply) envelope with the keyexpr arm
    /// (literal id=0 + Some, alias id=N + None, compound id=N + Some).
    pub fn new(
        request_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        payload: &[u8],
    ) -> Self {
        Self {
            request_id,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            payload: payload.to_vec(),
            body_kind_del: false,
            consolidation: None,
            responder: None,
        }
    }

    /// Set the Reply-body consolidation mode. Subsequent calls
    /// overwrite (last-wins). Mirror of
    /// [`RequestQueryBuilder::consolidation`] — same
    /// [`ConsolidationMode`] enum, same wire-byte contract, applied to
    /// `Reply.header._Z_FLAG_Z_R_C(0x20)` + 1-byte consolidation.
    pub fn consolidation(mut self, mode: ConsolidationMode) -> Self {
        self.consolidation = Some(mode);
        self
    }

    /// Swap the inner Reply body arm from `MsgPut` (the default
    /// put-data reply) to `MsgDel` (the delete-keyexpr reply). The
    /// payload supplied to [`Self::new`] is dropped on the MsgDel
    /// path — `MsgDel` carries no payload, only an optional
    /// timestamp + ext chain.
    ///
    /// Mirrors zenoh-pico's `_z_reply_encode` dispatch on the inner
    /// MID byte: `_Z_MID_Z_PUT(0x01)` vs `_Z_MID_Z_DEL(0x02)`. The
    /// outer Response envelope (header / rid / wireexpr) is identical
    /// between the two arms; only the body inner MID + body shape
    /// differs.
    pub fn reply_del(mut self) -> Self {
        self.body_kind_del = true;
        self
    }

    /// R121j-3c — attach a `responder` extension to the outer Response
    /// envelope. `zid` is the responder's ZenohId (1..=16 raw bytes,
    /// packed as `(zid_len - 1) << 4` in the leading byte per
    /// zenoh-pico's `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`).
    /// `eid` is the responder's entity-id (z-int).
    ///
    /// **Envelope-level vs body-level**: the responder ext sits on
    /// `Response.extensions` (alongside future qos / timestamp exts —
    /// network.c emit order is qos → tstamp → responder), NOT on the
    /// Reply body's own extensions chain. The Reply body has no
    /// extensions surface (see `_z_reply_encode` message.c:507-519);
    /// envelope-level identification of the responding queryable is
    /// the wire-level shape regardless of Reply vs Err inner body.
    ///
    /// Today this lands as the sole entry in `Response.extensions`
    /// (no Z chain-continuation bit). When future envelope exts (qos,
    /// tstamp) land, the chain-plumb step mirrors
    /// [`RequestQueryBuilder::build`] at
    /// session_glue.rs:2772-2782.
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn responder(mut self, zid: &[u8], eid: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseReplyBuilder::responder requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.responder = Some((zid.to_vec(), eid));
        self
    }

    /// Materialise the Response. Constructs the baseline envelope via
    /// the existing literal-or-aliased builder, then applies the
    /// Reply-layer settings. Panics on `(mapping_id=0, suffix=None)`
    /// because the literal path requires an inline keyexpr suffix.
    pub fn build(self) -> Response {
        let mut response = if self.keyexpr_mapping_id == 0 {
            let suffix = self.keyexpr_suffix.as_deref().unwrap_or_else(|| {
                panic!(
                    "ResponseReplyBuilder literal path (mapping_id=0) requires \
                     a non-empty keyexpr_suffix; use mapping_id != 0 for aliased",
                )
            });
            build_response_reply_literal(self.request_id, suffix, &self.payload)
        } else {
            build_response_reply_aliased(
                self.request_id,
                self.keyexpr_mapping_id,
                self.keyexpr_suffix.as_deref(),
                &self.payload,
            )
        };

        if let ResponseVariant::CodecZenohReply(ref mut reply) = response.body {
            if self.body_kind_del {
                // Swap MsgPut arm for MsgDel arm. The MsgPut allocated
                // by build_response_reply_literal/aliased gets dropped
                // here — the perf cost is one wasted MsgPut struct per
                // del-reply build, acceptable for the additive shape
                // of this round. A future refactor can split the
                // baseline helpers to expose envelope-only construction
                // without the put body, but the present additive
                // shape keeps the one-shot helpers unchanged.
                reply.body = ReplyVariant::CodecZenohMsgDel(MsgDel {
                    header: 0x02, // _Z_MID_Z_DEL
                    timestamp: None,
                    extensions: None,
                });
            }
            if let Some(mode) = self.consolidation {
                reply.header |= 0x20; // _Z_FLAG_Z_R_C
                reply.consolidation = Some(mode.wire_byte());
            }
        } else {
            unreachable!(
                "build_response_reply_* must produce a CodecZenohReply body — \
                 the layered builder relies on this invariant"
            );
        }

        // Envelope-level extension (Response.extensions). Today the
        // only ext we expose is responder (R121j-3c); future qos /
        // tstamp setters layer in here with the same Vec<ExtEntry>
        // chain-plumb idiom used in RequestQueryBuilder.build.
        if let Some((zid, eid)) = self.responder {
            let value = encode_responder_ext_body(&zid, eid);
            response.header |= 0x80; // _Z_FLAG_Z_Z on Response envelope
            response.extensions = Some(vec![ExtEntry {
                // ENC_ZBUF(0x40) | id_responder(0x03). No M flag and no
                // Z chain-continuation (sole envelope ext today).
                header: 0x40 | 0x03,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: value.len() as u64,
                    value,
                }),
            }]);
        }

        response
    }
}

/// R121j-2b — fluent builder for `Response(Err)` that composes the
/// Err-layer options on top of the minimal-shape baseline provided by
/// [`build_response_err_literal`] / [`build_response_err_aliased`].
/// Mirror of [`ResponseReplyBuilder`] for the Err inner-body arm.
///
/// Err-layer setters today: `encoding(id, schema)` (R121j-4a),
/// `source_info(zid, eid, sn)` (R121j-4b), and the envelope-level
/// `responder(zid, eid)` (R121j-3c, applied symmetrically with
/// [`ResponseReplyBuilder::responder`]). R121j-4c (Err.attachment) is
/// wire-absent per zenoh-pico `_z_err_encode` at
/// `src/protocol/codec/message.c:545-573` (only `encoding` flag-driven
/// inline encode + source_info ext are emitted); the carry was
/// retracted in Round 121j-4-retract.
#[cfg(feature = "codec-response")]
pub struct ResponseErrBuilder {
    request_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    payload: Vec<u8>,
    // Err-layer settings. Tuple = (id, optional schema). packed_id =
    // (id << 1) | has_schema computed at build() time.
    encoding: Option<(u32, Option<String>)>,
    // R121j-4b: Err-body source_info ext (ext_id 0x01 ZBUF). Tuple =
    // (zid bytes 1..=16, eid, sn). zid owned to outlive the builder;
    // wire body packed at build() time via
    // [`encode_source_info_ext_body`] and wrapped in an ExtZbuf entry.
    source_info: Option<(Vec<u8>, u32, u32)>,
    // R121j-3c: Response-ENVELOPE-level responder ext (ext_id 0x03 ZBUF).
    // Identical shape and emit-site to [`ResponseReplyBuilder::responder`]
    // — Response envelope ext applies symmetrically to Reply and Err
    // inner bodies (zenoh-pico network.c:281-291 has one encoder branch
    // that fires for both _Z_RESPONSE_BODY_REPLY and _Z_RESPONSE_BODY_ERR).
    responder: Option<(Vec<u8>, u32)>,
}

#[cfg(feature = "codec-response")]
impl ResponseErrBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_response_err_literal`] / [`build_response_err_aliased`]:
    /// minimal Response(Err) envelope with the keyexpr arm
    /// (literal id=0 + Some, alias id=N + None, compound id=N + Some).
    pub fn new(
        request_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        payload: &[u8],
    ) -> Self {
        Self {
            request_id,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            payload: payload.to_vec(),
            encoding: None,
            source_info: None,
            responder: None,
        }
    }

    /// Set the Err encoding hint. `id` is the zenoh-pico content-type
    /// prefix (e.g. 4 = application/json — see
    /// `vendor/zenoh-pico/include/zenoh-pico/api/constants.h`);
    /// `schema` is the optional schema fragment appended after the
    /// prefix. The wire `packed_id = (id << 1) | has_schema_bit`
    /// composition follows zenoh-pico's `_z_encoding_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/core.c` — the LSB carries
    /// the schema-present discriminator so the decoder can parse the
    /// optional suffix conditionally.
    pub fn encoding(mut self, id: u32, schema: Option<&str>) -> Self {
        self.encoding = Some((id, schema.map(str::to_string)));
        self
    }

    /// R121j-4b — set the Err-body `source_info` extension. `zid` is the
    /// peer's ZenohId (1..=16 raw bytes; `(zid_len - 1) << 4` packs the
    /// length into the leading ext byte per zenoh-pico's
    /// `_z_source_info_encode_ext` at
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:243-254`). `eid`
    /// is the peer's entity-id; `sn` is the per-source sequence number
    /// that scopes Reply ordering on the requester side.
    ///
    /// The ext lands as the sole entry in `Err.extensions` because
    /// zenoh-pico's `_z_err_encode` (`message.c:545-573`) emits
    /// source_info as the only ext-chain element with header
    /// `_Z_MSG_EXT_ENC_ZBUF | 0x01` and no Z chain-continuation bit.
    /// When future Err-level exts land they will plumb the chain bits
    /// through a `Vec<ExtEntry>` build mirroring
    /// [`RequestQueryBuilder::build`].
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn source_info(mut self, zid: &[u8], eid: u32, sn: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseErrBuilder::source_info requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.source_info = Some((zid.to_vec(), eid, sn));
        self
    }

    /// R121j-3c — attach a `responder` extension to the outer Response
    /// envelope. Mirror of [`ResponseReplyBuilder::responder`]: same
    /// wire bytes, same emit site (`Response.extensions`), same
    /// `_Z_FLAG_Z_Z(0x80)` envelope-level header bit. Provided on
    /// ErrBuilder because zenoh-pico's `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291` runs
    /// the same responder-ext branch for Reply and Err inner bodies;
    /// the wire is symmetric.
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn responder(mut self, zid: &[u8], eid: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseErrBuilder::responder requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.responder = Some((zid.to_vec(), eid));
        self
    }

    /// Materialise the Response. Constructs the baseline envelope via
    /// the existing literal-or-aliased builder, then applies the
    /// Err-layer settings. Panics on `(mapping_id=0, suffix=None)`
    /// because the literal path requires an inline keyexpr suffix.
    pub fn build(self) -> Response {
        let mut response = if self.keyexpr_mapping_id == 0 {
            let suffix = self.keyexpr_suffix.as_deref().unwrap_or_else(|| {
                panic!(
                    "ResponseErrBuilder literal path (mapping_id=0) requires \
                     a non-empty keyexpr_suffix; use mapping_id != 0 for aliased",
                )
            });
            build_response_err_literal(self.request_id, suffix, &self.payload)
        } else {
            build_response_err_aliased(
                self.request_id,
                self.keyexpr_mapping_id,
                self.keyexpr_suffix.as_deref(),
                &self.payload,
            )
        };

        if let ResponseVariant::CodecZenohErr(ref mut err) = response.body {
            if let Some((id, schema)) = self.encoding {
                err.header |= 0x40; // _Z_FLAG_Z_E (Err encoding present)
                let has_schema = schema.is_some();
                let packed = (id << 1) | if has_schema { 1 } else { 0 };
                err.encoding = Some(Encoding {
                    packed_id: packed,
                    schema_len: schema.as_ref().map(|s| s.len() as u64),
                    schema,
                });
            }
            if let Some((zid, eid, sn)) = self.source_info {
                let value = encode_source_info_ext_body(&zid, eid, sn);
                // _Z_FLAG_Z_Z(0x80) signals ext-chain presence to the
                // peer's `_z_err_decode` (message.c:594-595).
                err.header |= 0x80;
                err.extensions = Some(vec![ExtEntry {
                    // ENC_ZBUF(0x40) | id_source_info(0x01). No M flag
                    // (informational hint) and no Z chain-continuation
                    // (single entry today; the chain-plumb step lands
                    // once a second Err ext exists, mirroring
                    // RequestQueryBuilder.build at
                    // session_glue.rs:2772-2782).
                    header: 0x40 | 0x01,
                    body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                        value_len: value.len() as u64,
                        value,
                    }),
                }]);
            }
        } else {
            unreachable!(
                "build_response_err_* must produce a CodecZenohErr body — \
                 the layered builder relies on this invariant"
            );
        }

        // Envelope-level extension (Response.extensions). Mirror of the
        // same step in [`ResponseReplyBuilder::build`] — the responder
        // ext is shared between Reply and Err envelopes.
        if let Some((zid, eid)) = self.responder {
            let value = encode_responder_ext_body(&zid, eid);
            response.header |= 0x80; // _Z_FLAG_Z_Z on Response envelope
            response.extensions = Some(vec![ExtEntry {
                header: 0x40 | 0x03,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: value.len() as u64,
                    value,
                }),
            }]);
        }

        response
    }
}

/// R121j-4b — encode the value bytes of a `source_info` extension per
/// zenoh-pico's `_z_source_info_encode_ext` at
/// `vendor/zenoh-pico/src/protocol/codec/message.c:243-254`.
///
/// Wire layout (the bytes this fn returns; the surrounding ExtZbuf
/// codec prepends its own `VLE(value_len)` length prefix that maps to
/// zenoh-pico's leading `zsize(ext_size)`):
///
///   [byte 0]            `((zid_len - 1) << 4)` — high nibble carries
///                        `zid_len - 1` (1..=16 valid, encoded 0..=15).
///   [byte 1..1+zid_len] raw zid bytes (caller's MSB-first id slice).
///   [VLE u64]            `eid`.
///   [VLE u64]            `sn`.
///
/// Panics if `zid.len()` is outside `1..=16` (the caller's setter
/// guards this; the inner assertion is defence-in-depth).
#[cfg(feature = "codec-response")]
fn encode_source_info_ext_body(zid: &[u8], eid: u32, sn: u32) -> Vec<u8> {
    assert!(
        (1..=16).contains(&zid.len()),
        "source_info zid length must be 1..=16 (zenoh-pico ZenohId wire constraint)"
    );
    // Capacity = 1 leading byte + zid + VLE(u32) worst-case (5 bytes) ×2.
    let mut out = Vec::with_capacity(1 + zid.len() + 5 + 5);
    out.push(((zid.len() as u8) - 1) << 4);
    out.extend_from_slice(zid);
    encode_vle_u64_into(&mut out, eid as u64);
    encode_vle_u64_into(&mut out, sn as u64);
    out
}

/// R121j-4b — base-128 VLE u64 emit into a `Vec<u8>`. Mirrors the
/// inline loop in [`encode_frame_envelope`] and zenoh-pico's
/// `_z_zsize_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/core.c`. Free-function shape
/// because source_info ext-body construction happens before any
/// `SceSink` is in scope — the ext body lives inside `ExtZbuf.value`
/// and the surrounding codec sink only sees the already-built `Vec`.
#[cfg(feature = "codec-response")]
fn encode_vle_u64_into(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// R121j-3c — encode the value bytes of a `responder` extension per
/// zenoh-pico's `_z_response_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`.
///
/// Wire layout (the bytes this fn returns; the surrounding ExtZbuf
/// codec prepends its own `VLE(value_len)` length prefix that maps to
/// zenoh-pico's leading `zsize(ext_size)`):
///
///   [byte 0]            `((zid_len - 1) << 4)` — high nibble carries
///                        `zid_len - 1` (1..=16 valid, encoded 0..=15).
///   [byte 1..1+zid_len] raw zid bytes.
///   [VLE u64]            `eid`.
///
/// Distinct from [`encode_source_info_ext_body`] in that no `sn`
/// trailer is emitted — responder identifies the entity, source_info
/// identifies the entity + per-source sequence position.
///
/// Panics if `zid.len()` is outside `1..=16` (the caller's setter
/// guards this; the inner assertion is defence-in-depth).
#[cfg(feature = "codec-response")]
fn encode_responder_ext_body(zid: &[u8], eid: u32) -> Vec<u8> {
    assert!(
        (1..=16).contains(&zid.len()),
        "responder zid length must be 1..=16 (zenoh-pico ZenohId wire constraint)"
    );
    // Capacity = 1 leading byte + zid + VLE(u32) worst-case (5 bytes).
    let mut out = Vec::with_capacity(1 + zid.len() + 5);
    out.push(((zid.len() as u8) - 1) << 4);
    out.extend_from_slice(zid);
    encode_vle_u64_into(&mut out, eid as u64);
    out
}

/// R121h-perf-bump-3 — single-allocation transport-envelope encode.
/// Composes the parent-flags byte, `VLE(sn)`, and a sink-encoded
/// payload into one growable `Vec`, eliminating the prior
/// `payload.encode_to_vec()` + `Frame.encode_to_vec()` +
/// `wire.extend_from_slice(&body_bytes)` chain (3 allocations per
/// hot-path emit). For typical 1–2 KB payloads the reserved capacity
/// is also dramatically smaller than the 64 KB `Frame::MAX_ENCODED_BYTES`
/// ceiling, since the inner codec's worst-case bound is used directly.
///
/// The `VLE(sn)` loop is bit-identical to `Frame::encode`'s sn block
/// — it IS the wire format (zenoh-pico VLE base-128 encoding per
/// `vendor/zenoh-pico/src/protocol/codec/core.c`), not consumer-tunable
/// logic. Inlining here does not duplicate semantics.
fn encode_frame_envelope<P>(
    sn: u64,
    parent_flags: u8,
    worst_case_payload: usize,
    payload_encode: P,
) -> Vec<u8>
where
    P: FnOnce(&mut VecSink<'_>) -> Result<(), CodecError>,
{
    let mut wire = Vec::with_capacity(1 + 10 + worst_case_payload);
    wire.push(parent_flags | wire_const::T_MID_FRAME);
    {
        let mut sink = VecSink::new(&mut wire);
        let mut _vle = sn;
        while _vle >= 0x80 {
            sink.write_u8((_vle as u8 & 0x7F) | 0x80)
                .expect("VecSink is infallible");
            _vle >>= 7;
        }
        sink.write_u8(_vle as u8).expect("VecSink is infallible");
        payload_encode(&mut sink).expect("VecSink is infallible");
    }
    wire
}

/// R121j-3 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Response` network-message in its payload.
/// Mirror of the other `encode_frame_with_*` helpers (PUSH /
/// DECLARE / REQUEST / RESPONSE_FINAL).
///
/// Reply data delivery is on the reliable channel by default — a
/// dropped Reply leaves the requester's `z_get` waiting for a
/// reply that never arrives, then for the matching
/// `ResponseFinal` that the queryable never re-emits (because from
/// its perspective the reply was sent). The default `reliable=true`
/// is the production-safe choice; callers passing `false` accept
/// the consequence.
#[cfg(feature = "codec-response")]
pub fn encode_frame_with_response(sn: u64, response: Response, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Response::MAX_ENCODED_BYTES, |sink| {
        response.encode(sink)
    })
}

/// R121j-2 — build the wire bytes for a `Frame` transport-message
/// carrying a single `ResponseFinal` network-message in its payload.
/// Mirror of the other `encode_frame_with_*` helpers (PUSH /
/// DECLARE / REQUEST).
///
/// ResponseFinal is unconditionally reliable in zenoh-pico's model:
/// dropping a ResponseFinal would leave the requesting peer's
/// `z_get` future hung waiting for sequence termination. The default
/// `reliable=true` is the production-safe choice; callers passing
/// `false` accept the consequence (typically only fuzz / negative
/// tests).
#[cfg(feature = "codec-response-final")]
pub fn encode_frame_with_response_final(
    sn: u64,
    response_final: ResponseFinal,
    reliable: bool,
) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, ResponseFinal::MAX_ENCODED_BYTES, |sink| {
        response_final.encode(sink)
    })
}

/// R121j-1 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Request` network-message in its payload. Mirror
/// of [`encode_frame_with_push`] / [`encode_frame_with_declare`] for
/// the REQUEST outbound path.
///
/// Like the DECLARE outbound path, Request(Query) goes on the
/// reliable channel by default — the peer's responder side needs to
/// see the Query to dispatch into its queryable callback; an
/// unreliable Query could silently drop and leave the local
/// `z_get` future hung without a Response or ResponseFinal. Callers
/// that pass `reliable=false` accept that risk explicitly.
#[cfg(feature = "codec-request")]
pub fn encode_frame_with_request(sn: u64, request: Request, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Request::MAX_ENCODED_BYTES, |sink| {
        request.encode(sink)
    })
}

/// R121g — build the wire bytes for a `Frame` transport-message
/// carrying a single `Declare` network-message in its payload.
/// Mirror of [`encode_frame_with_push`] for the DECLARE outbound
/// path.
///
/// `parent_flags` carries `FLAG_T_FRAME_R (0x20)` when `reliable`,
/// matching zenoh-pico's `_z_frame_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`.
/// DECLARE outbound is always reliable in the AP MVP path — the
/// session-FSM reliable-channel SN window orders DECLARE before
/// any dependent aliased Push, so the peer's keyexpr table is
/// populated before the first resolving Push arrives. Callers
/// passing `reliable=false` accept that the DECLARE may arrive
/// after a referencing Push and the peer's resolver will reject
/// the unknown id — useful only for fuzz / negative tests.
#[cfg(feature = "codec-declare")]
pub fn encode_frame_with_declare(sn: u64, declare: Declare, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Declare::MAX_ENCODED_BYTES, |sink| {
        declare.encode(sink)
    })
}

/// R279 — build the wire bytes for a `Frame` transport-message
/// carrying a single `Interest` network-message in its payload.
/// Mirror of [`encode_frame_with_declare`] for the INTEREST outbound
/// path (declarations-discovery / liveliness-subscriber registration).
///
/// `parent_flags` carries `FLAG_T_FRAME_R (0x20)` when `reliable`,
/// matching zenoh-pico's `_z_frame_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`. INTEREST
/// outbound is always reliable in the wz path: the peer's
/// `_z_interest_process_*` runs against an ordered stream of
/// DeclToken / UndeclToken / InterestFinal records on the reliable
/// channel, and the SN-window orders the Interest before any peer
/// reply just as the DECLARE path orders DeclSubscriber before any
/// resolving Push. Callers passing `reliable=false` accept that the
/// Interest may arrive after a peer-side state change and the peer's
/// resolver may serve a stale history snapshot — useful only for
/// fuzz / negative tests.
pub fn encode_frame_with_interest(sn: u64, interest: Interest, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Interest::MAX_ENCODED_BYTES, |sink| {
        interest.encode(sink)
    })
}

/// R121e — build the wire bytes for a `Frame` transport-message
/// (T_MID_FRAME) carrying a single `Push` network-message in its
/// payload.
///
/// Wire shape (composes the transport-envelope header byte that
/// lives outside the body codec's scope with `Frame.encode_to_vec()`'s
/// `VLE(sn) + payload` body):
///
/// ```text
///   [parent_flags | T_MID_FRAME (0x05)]
///     VLE(sn) | push.encode_bytes
/// ```
///
/// `parent_flags` carries `FLAG_T_FRAME_R` (0x20) when
/// `reliable`, matching zenoh-pico's `_z_frame_encode` per
/// `vendor/zenoh-pico/src/protocol/codec/transport.c:380`.
/// `FLAG_T_Z` (0x80) — Frame-level transport extensions — is not
/// set: the MVP pub/sub path has no use for transport-level
/// Frame extensions and the wireless QoS / Auth ext chains live
/// on the InitSyn / InitAck negotiation paths (see
/// `ExtChainRole`).
///
/// The `Frame { sn, payload }.encode_to_vec()` body is verified
/// byte-identical to zenoh-pico's `_z_frame_encode` by
/// `crates/wz-integration-tests/tests/layer3_frame.rs`. This
/// helper composes only the one transport header byte that
/// `Frame::encode` does not emit.
#[cfg(feature = "codec-push")]
pub fn encode_frame_with_push(sn: u64, push: Push, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    encode_frame_envelope(sn, parent_flags, Push::MAX_ENCODED_BYTES, |sink| {
        push.encode(sink)
    })
}

// ─────────────────────────── inbound parser ───────────────────────────

/// Parsed inbound transport-message frame surfaced by `parse_inbound`.
///
/// R68a baseline. The variant set covers the three transport bodies
/// the Initiator side cares about during handshake + close:
/// `Init` / `Open` / `Close`. The `has_ext` field on each variant
/// records whether the parent header's Z flag was set so the caller
/// can dispatch ext-chain decoding (R68c) without re-parsing the
/// header byte; the chain itself is decoded by `decode_ext_chain`.
/// `Unknown { mid }` covers MIDs outside the {INIT, OPEN, CLOSE}
/// triad — the caller may forward them to a higher-layer dispatch
/// (e.g. KeepAlive / Frame / Fragment) or drop them.
///
/// No `Debug` derive: the wz-codecs structs (`InitBody`/`OpenBody`)
/// are sce-codegen output and only derive `Default`. Callers
/// pattern-match the variant and inspect typed fields directly; a
/// log-style print on the whole frame is rare and can be composed
/// at the call site if needed.
pub enum InboundFrame {
    /// `_Z_MID_T_INIT` (0x01). `is_ack` mirrors the
    /// `_Z_FLAG_T_INIT_A` discriminator; `has_ext` mirrors the
    /// transport-header Z flag and corresponds to
    /// `!extensions.is_empty()` when R68c decode succeeds.
    #[cfg(feature = "codec-init-body")]
    Init {
        is_ack: bool,
        has_ext: bool,
        body: InitBody,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_OPEN` (0x02). `is_ack` mirrors `_Z_FLAG_T_OPEN_A`;
    /// `lease_in_seconds` mirrors `_Z_FLAG_T_OPEN_T`.
    #[cfg(feature = "codec-open-body")]
    Open {
        is_ack: bool,
        lease_in_seconds: bool,
        has_ext: bool,
        body: OpenBody,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_CLOSE` (0x03). `reason` is the single body byte.
    #[cfg(feature = "codec-close")]
    Close {
        reason: u8,
        has_ext: bool,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_KEEP_ALIVE` (0x04). Empty-body liveness ping; the
    /// only payload is the optional ext chain (Z flag-gated). The
    /// FSM uses receipt to reset the lease timer per
    /// session-fsm §2.5 keepalive_interval semantics.
    #[cfg(feature = "codec-keep-alive")]
    KeepAlive {
        has_ext: bool,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_FRAME` (0x05). Established-session payload carrier:
    /// `reliable` mirrors `_Z_FLAG_T_FRAME_R`; `sn` is the VLE
    /// sequence number; `payload` is the tail bytes (the inner
    /// NetworkMessage batch — higher-layer codec dispatch is the
    /// caller's responsibility). Z-flagged frames have their ext
    /// chain decoded into `extensions` between `sn` and `payload`
    /// to mirror zenoh-pico's `_z_msg_ext_skip_non_mandatories`
    /// path (transport.c::_z_frame_decode L388).
    ///
    /// R311g — variant gated on `codec-frame`. When the feature is
    /// off the `T_MID_FRAME` arm in `parse_inbound` falls through to
    /// `InboundFrame::Unknown { mid: 0x05 }`, which the FSM dispatch
    /// in `inbound_to_fsm_event` maps to `FramingError` (graceful
    /// session teardown rather than silent data loss).
    #[cfg(feature = "codec-frame")]
    Frame {
        reliable: bool,
        sn: u64,
        payload: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntry>,
    },
    /// MID outside the handshake/close/keepalive set.
    Unknown { mid: u8 },
}

/// Error surface for `parse_inbound`. Distinct from `CodecError` so
/// callers can react to "empty wire" (link delivered a zero-byte
/// frame, programming error) without conflating it with codec-level
/// `NeedMoreBytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundParseError {
    /// The frame was zero bytes — no transport-message header to
    /// dispatch on.
    Empty,
    /// The body codec rejected the wire (truncated, VLE overflow,
    /// etc.).
    Codec(CodecError),
    /// R68c — the transport header set the Z flag but the trailing
    /// ext chain exceeded `MAX_EXT_CHAIN_DEPTH` without surfacing a
    /// chain-terminator entry (Z bit clear). Mirrors
    /// `ext_envelope.scxml::on-overflow="reject"` so a malformed
    /// peer cannot pin the decoder into an unbounded loop.
    ExtChainOverflow,
}

impl std::fmt::Display for InboundParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "inbound frame was empty (no transport header)"),
            Self::Codec(e) => write!(f, "inbound body codec rejected wire: {:?}", e),
            Self::ExtChainOverflow => write!(
                f,
                "inbound ext chain exceeded MAX_EXT_CHAIN_DEPTH={} without terminator",
                MAX_EXT_CHAIN_DEPTH
            ),
        }
    }
}

/// R68c — upper bound on ext-chain entries decoded per inbound
/// frame. Mirrors `ext_envelope.scxml::max-depth="8"` so the wz
/// inbound decoder fails closed on the same chain length zenoh-pico
/// would already reject. Production deploys with a higher ceiling
/// would have to bump this AND `ext_envelope.scxml` together.
pub const MAX_EXT_CHAIN_DEPTH: usize = 8;

impl std::error::Error for InboundParseError {}

impl From<CodecError> for InboundParseError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

/// Parse a single transport-message frame from `bytes`.
///
/// The first byte carries `(flags<<5) | mid` — the low 5 bits are
/// the message ID, the high 3 bits are the per-MID flag set + the
/// shared Z flag (`0x80`) for the ext chain. R68a baseline decodes
/// the body via the wz codec set and reports the Z flag via
/// `has_ext`; the ext-chain bytes themselves are left in the
/// trailing portion of `bytes` for R68c to consume.
///
/// R311g1 — `has_ext` / `cursor` are conditionally bound via
/// `#[cfg(any(feature = "codec-init-body", ..))]` matching the union
/// of feature predicates of the dispatch arms below. A build with
/// every codec feature off (e.g. `scripts/measure-codec-footprint.sh`
/// `minus-all-codecs` lane) elides both bindings entirely, leaving
/// only the Unknown fall-through arm. R311g previously suppressed the
/// minus-all-codecs warning via `#[allow(unused_variables, unused_mut)]`;
/// the explicit `cfg(any(...))` predicate is the textbook replacement
/// per `feedback_signature_stability` MEMORY note's "annotation = last
/// resort" rule. Adding a new body codec feature (R311h..R311l) extends
/// this predicate.
pub fn parse_inbound(bytes: &[u8]) -> Result<InboundFrame, InboundParseError> {
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mid = header & 0x1F;
    // R311g1 — `flags` extraction is gated on the same predicate as
    // the dispatch arms that consume it; when every codec-* is off
    // (minus-all-codecs lane) only the Unknown fall-through arm
    // remains and `flags` would otherwise be unused.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let flags = header & 0xE0;
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let has_ext = (flags & wire_const::FLAG_T_Z) != 0;
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let mut cursor = SceCursor::new(&bytes[1..]);
    match mid {
        #[cfg(feature = "codec-init-body")]
        wire_const::T_MID_INIT => {
            let body = InitBody::decode(&mut cursor, (flags >> 6) & 1, (flags >> 5) & 1)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Init {
                is_ack: (flags & wire_const::FLAG_T_INIT_A) != 0,
                has_ext,
                body,
                extensions,
            })
        }
        #[cfg(feature = "codec-open-body")]
        wire_const::T_MID_OPEN => {
            let body = OpenBody::decode(&mut cursor, (flags >> 5) & 1)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Open {
                is_ack: (flags & wire_const::FLAG_T_OPEN_A) != 0,
                lease_in_seconds: (flags & wire_const::FLAG_T_OPEN_T) != 0,
                has_ext,
                body,
                extensions,
            })
        }
        #[cfg(feature = "codec-close")]
        wire_const::T_MID_CLOSE => {
            let body = Close::decode(&mut cursor)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Close {
                reason: body.reason,
                has_ext,
                extensions,
            })
        }
        #[cfg(feature = "codec-frame")]
        wire_const::T_MID_FRAME => {
            // sn first (VLE), then optional ext chain (Z-gated),
            // then tail payload to end of cursor.
            let sn = cursor.read_vle_u64().map_err(InboundParseError::Codec)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            let remaining = cursor.remaining();
            let payload = cursor
                .peek_slice(remaining)
                .map_err(InboundParseError::Codec)?
                .to_vec();
            cursor
                .advance(remaining)
                .map_err(InboundParseError::Codec)?;
            Ok(InboundFrame::Frame {
                reliable: (flags & wire_const::FLAG_T_FRAME_R) != 0,
                sn,
                payload,
                has_ext,
                extensions,
            })
        }
        #[cfg(feature = "codec-keep-alive")]
        wire_const::T_MID_KEEP_ALIVE => {
            // KeepAlive body is empty (zero-byte payload); the
            // decode call is a no-op but kept for symmetry with the
            // other MIDs and to preserve the "every wire-mapped
            // codec routes through its generated decoder" invariant.
            let _body = KeepAlive::decode(&mut cursor)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::KeepAlive {
                has_ext,
                extensions,
            })
        }
        other => Ok(InboundFrame::Unknown { mid: other }),
    }
}

/// R74 — one application-layer message inside a `Frame.payload` batch.
///
/// `Frame.payload` models `Vec<NetworkMessage>` per
/// `docs/wire-spec-subset.md` §4 (the Established-session payload
/// carrier; zenoh-pico maps it to `_z_network_message_t`). Each
/// record starts with a header byte where bits 0..4 carry the network
/// MID and bits 5..7 carry per-MID flags + the shared Z bit. The full
/// network-MID set is 7 wide (PUSH 0x1D, REQUEST 0x1C, RESPONSE 0x1B,
/// RESPONSE_FINAL 0x1A, DECLARE 0x1E, INTEREST 0x19, OAM 0x1F per
/// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:33-39`).
///
/// R74 ships the first application-layer envelope decoder — `Request`
/// — because `wz_codecs::request` is the only network-envelope codec
/// authored so far. Unknown MIDs surface as `Unknown { mid, body }`
/// absorbing the rest of the payload bytes verbatim; the batch parse
/// stops at the first Unknown because skipping past an unknown body
/// without a length-aware decoder would risk misaligning the cursor.
///
/// No `Debug` derive on the wrapped `Request` — wz-codecs structs only
/// derive `Default` (sce-codegen output, see
/// `crates/wz-codecs/tests/smoke.rs` header). The manual `Debug` impl
/// below surfaces the variant kind without recursing into codec fields
/// so `DriverLoopOutcome` can keep its `#[derive(Debug)]`.
pub enum NetworkMessage {
    /// Network MID `_Z_MID_N_REQUEST` (0x1C). Carries a query / put /
    /// del wrapped in a Wireexpr + request-id envelope with response
    /// correlation. Decoded via `wz_codecs::request::Request`. The
    /// `Box` keeps the enum variant size small — `Request` carries
    /// `Wireexpr` + a `RequestVariant` whose arms hold MsgPut / MsgDel
    /// / Query structs, making the inline form much larger than the
    /// `Unknown` variant.
    #[cfg(feature = "codec-request")]
    Request(Box<Request>),
    /// R90 — Network MID `_Z_MID_N_PUSH` (0x1D). Pub/sub data
    /// carrier wrapping a put / del inner body — same envelope
    /// shape as `Request` minus the rid field. The `Box` mirrors
    /// the `Request` variant's size-balancing rationale.
    ///
    /// R311h — gated on `codec-push` (the `Push` type itself
    /// disappears when the feature is off).
    #[cfg(feature = "codec-push")]
    Push(Box<Push>),
    /// R91 — Network MID `_Z_MID_N_RESPONSE_FINAL` (0x1A). Pure
    /// correlation marker that closes a Request's reply stream;
    /// payload is header + request_id VLE only (no embed, no
    /// inner body). Inlined (no `Box`) because the struct is
    /// small — just three integer fields plus an optional ext
    /// vec.
    #[cfg(feature = "codec-response-final")]
    ResponseFinal(ResponseFinal),
    /// R92 — Network MID `_Z_MID_N_OAM` (0x1F). Diagnostic /
    /// control-plane envelope; header (mid+enc+Z) + VLE id +
    /// optional ext-chain + body variant on `header.enc` (UNIT
    /// / ZINT / ZBUF inner codec). The body variant arms hold
    /// `ExtUnit` / `ExtZint` / `ExtZbuf` — small enough to inline
    /// like `ResponseFinal`.
    Oam(Oam),
    /// R93/R94 — Network MID `_Z_MID_N_INTEREST` (0x19).
    /// Declarations discovery / liveliness subscriber registration
    /// envelope; header (mid+C+F+Z) + VLE interest_id + (C||F)-gated
    /// inner body + Z-gated ext-chain. R94 closed the body via the
    /// interest_body sub-codec (body_flags byte + R-gated wireexpr).
    /// Inlined (no `Box`) because the struct is small — header byte
    /// + u64 + optional body + optional ext vec.
    Interest(Interest),
    /// R97 — Network MID `_Z_MID_N_RESPONSE` (0x1B). Query reply
    /// carrier wrapping a reply (0x04) or err (0x05) inner body
    /// dispatched via peek-byte on the inner MID bit-range. Same
    /// envelope shape as `Request` minus the body kind set. The
    /// `Box` keeps the enum variant size small — `Response`
    /// carries `Wireexpr` + `ResponseVariant` whose arms hold
    /// Reply / Err structs, making the inline form larger than
    /// the `Unknown` variant (mirrors the Request sizing
    /// rationale).
    #[cfg(feature = "codec-response")]
    Response(Box<Response>),
    /// R110/R115 — Network MID `_Z_MID_N_DECLARE` (0x1E). Declarations
    /// envelope wrapping one of the nine sub-MID inner bodies
    /// (DECL_KEXPR / DECL_SUBSCRIBER / DECL_QUERYABLE / DECL_TOKEN /
    /// UNDECL_KEXPR / UNDECL_SUBSCRIBER / UNDECL_QUERYABLE /
    /// UNDECL_TOKEN / DECL_FINAL) dispatched via peek-byte on the
    /// inner header MID. R110a-e closed the wz-side authoring chain
    /// and the byte-equiv Layer 3 wire-interop vs zenoh-pico
    /// `_z_declare_encode`; R115 wires the inbound dispatch so a
    /// peer-emitted DECLARE record surfaces here. The `Box` mirrors
    /// the `Request`/`Push`/`Response` sizing rationale — `Declare`
    /// carries an optional interest_id + ext vec + the inner
    /// `DeclareVariant` whose arms hold the nine sub-body structs,
    /// making the inline form much larger than `Unknown`.
    ///
    /// R311i — gated on `codec-declare`.
    #[cfg(feature = "codec-declare")]
    Declare(Box<Declare>),
    /// Header byte's MID falls outside the
    /// {REQUEST, PUSH, RESPONSE_FINAL, OAM, INTEREST, RESPONSE, DECLARE}
    /// subset wz-codecs has authored envelope coverage for. `body`
    /// carries the rest of the payload bytes (header byte included)
    /// verbatim so a future per-MID decoder can re-parse without
    /// losing data; the parse stops here to avoid mis-cursor-advancing
    /// across an unknown body length.
    Unknown { mid: u8, body: Vec<u8> },
}

impl std::fmt::Debug for NetworkMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "codec-request")]
            Self::Request(_) => f.write_str("Request(..)"),
            #[cfg(feature = "codec-push")]
            Self::Push(_) => f.write_str("Push(..)"),
            #[cfg(feature = "codec-response-final")]
            Self::ResponseFinal(_) => f.write_str("ResponseFinal(..)"),
            Self::Oam(_) => f.write_str("Oam(..)"),
            Self::Interest(_) => f.write_str("Interest(..)"),
            #[cfg(feature = "codec-response")]
            Self::Response(_) => f.write_str("Response(..)"),
            #[cfg(feature = "codec-declare")]
            Self::Declare(_) => f.write_str("Declare(..)"),
            Self::Unknown { mid, body } => {
                write!(f, "Unknown {{ mid: {mid:#04x}, body_len: {} }}", body.len())
            }
        }
    }
}

/// R74 — decode a `Frame.payload` byte slice into the in-order batch
/// of network messages it carries.
///
/// Loop shape: peek the cursor's next byte, mask to `mid = byte & 0x1F`,
/// dispatch to the matching envelope decoder. On `N_MID_REQUEST` calls
/// `Request::decode` which re-reads the header byte itself (peek-byte
/// primitive per RFC §5.B Y3 atomic 2b-ii) so no double-consumption.
/// On any other MID, absorbs the remaining bytes as `Unknown { mid,
/// body }` and terminates the batch loop — see
/// [`NetworkMessage::Unknown`] for the rationale.
///
/// An empty `bytes` slice returns `Ok(vec![])` (an empty batch is a
/// valid Frame.payload — the transport envelope is fine, no
/// application-layer records).
///
/// Codec errors propagate as `CodecError`. The caller is responsible
/// for deciding whether to surface them as a transport-FSM
/// `FramingError` (current `poll_and_dispatch_one` behavior, since the
/// transport envelope already parsed but the application-layer batch
/// is malformed) or to log and continue with the partially-decoded
/// batch.
///
/// R311g — gated on `codec-frame`. The only caller is the
/// `InboundFrame::Frame` arm in [`poll_and_dispatch_one`] (also
/// codec-frame-gated), so a codec-frame-OFF build never reaches a
/// caller; cfg-gating the definition itself elides ~80 lines of
/// dispatch + the `NetworkMessage` decoders for every body codec
/// without leaving an orphan public symbol. When R311h..R311k land
/// the body-codec cascades, individual match arms inside this
/// function will gain their own per-body cfg (e.g. `N_MID_PUSH`
/// under `codec-push`).
#[cfg(feature = "codec-frame")]
pub fn parse_frame_payload(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        let header = cursor.peek_slice(1)?[0];
        let mid = header & 0x1F;
        match mid {
            #[cfg(feature = "codec-request")]
            wire_const::N_MID_REQUEST => {
                let req = Request::decode(&mut cursor)?;
                messages.push(NetworkMessage::Request(Box::new(req)));
            }
            #[cfg(feature = "codec-push")]
            wire_const::N_MID_PUSH => {
                let push = Push::decode(&mut cursor)?;
                messages.push(NetworkMessage::Push(Box::new(push)));
            }
            #[cfg(feature = "codec-response-final")]
            wire_const::N_MID_RESPONSE_FINAL => {
                let rf = ResponseFinal::decode(&mut cursor)?;
                messages.push(NetworkMessage::ResponseFinal(rf));
            }
            wire_const::N_MID_OAM => {
                let oam = Oam::decode(&mut cursor)?;
                messages.push(NetworkMessage::Oam(oam));
            }
            wire_const::N_MID_INTEREST => {
                let interest = Interest::decode(&mut cursor)?;
                messages.push(NetworkMessage::Interest(interest));
            }
            #[cfg(feature = "codec-response")]
            wire_const::N_MID_RESPONSE => {
                let resp = Response::decode(&mut cursor)?;
                messages.push(NetworkMessage::Response(Box::new(resp)));
            }
            #[cfg(feature = "codec-declare")]
            wire_const::N_MID_DECLARE => {
                let decl = Declare::decode(&mut cursor)?;
                messages.push(NetworkMessage::Declare(Box::new(decl)));
            }
            _ => {
                let rem = cursor.remaining();
                let body = cursor.peek_slice(rem)?.to_vec();
                cursor.advance(rem)?;
                messages.push(NetworkMessage::Unknown { mid, body });
                break;
            }
        }
    }
    Ok(messages)
}

/// R69b — map a parsed inbound transport frame to the matching
/// session-FSM external event variant.
///
/// Drives the receive half of the unicast session lifecycle:
/// `inbound bytes ─→ parse_inbound ─→ inbound_to_fsm_event ─→
/// Engine::process_event` so the FSM consumes peer frames without
/// the caller hand-writing the discriminator match.
///
/// `Unknown { mid }` maps to `FramingError` because an unhandled
/// MID at this dispatch layer is a wire-spec violation — the peer
/// sent a transport-message ID the codec set does not implement,
/// and the FSM's framing-error transition is the correct response
/// (Close(generic) on the link).
///
/// `KeepAlive` returns `None` because it is NOT a state-transition
/// trigger in `session_fsm_unicast.scxml` — keepalive receipt only
/// resets the lease timer (a side effect orthogonal to the state
/// graph). Callers wire that side-effect on the `None` branch
/// (e.g. invoke `Hal::now_ticks_ms` and reset the lease deadline)
/// rather than calling `Engine::process_event` with a spurious
/// event.
///
/// `Frame` returns `None` for the same reason at the FSM layer
/// (Frame receipt is the carrier for application-layer pub/sub
/// messages, not a session-state trigger). Callers on the `None`
/// branch route `Frame.payload` through [`parse_frame_payload`] to
/// surface the in-batch `NetworkMessage` records — see R74 wiring in
/// [`poll_and_dispatch_one`].
pub fn inbound_to_fsm_event(
    frame: &InboundFrame,
) -> Option<crate::session_fsm_unicast::SessionFsmUnicastEvent> {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match frame {
        #[cfg(feature = "codec-init-body")]
        InboundFrame::Init { is_ack: false, .. } => Some(E::InitSynReceived),
        #[cfg(feature = "codec-init-body")]
        InboundFrame::Init { is_ack: true, .. } => Some(E::InitAckReceived),
        #[cfg(feature = "codec-open-body")]
        InboundFrame::Open { is_ack: false, .. } => Some(E::OpenSynReceived),
        #[cfg(feature = "codec-open-body")]
        InboundFrame::Open { is_ack: true, .. } => Some(E::OpenAckReceived),
        #[cfg(feature = "codec-close")]
        InboundFrame::Close { .. } => Some(E::PeerClose),
        #[cfg(feature = "codec-keep-alive")]
        InboundFrame::KeepAlive { .. } => None,
        #[cfg(feature = "codec-frame")]
        InboundFrame::Frame { .. } => None,
        InboundFrame::Unknown { .. } => Some(E::FramingError),
    }
}

/// R76 — outcome of a single iteration of the production driver
/// loop. Five observable outcomes the caller dispatches on: a typed
/// FSM event reached the engine; a KeepAlive parsed and updated the
/// lease stamp but did not advance the FSM (R72b); a Frame envelope
/// parsed and its payload decoded into a `NetworkMessage` batch the
/// application layer should dispatch (R74); the wire bytes failed to
/// parse (the helper raises `FramingError` to the FSM and returns
/// `ParseError` for logging); or the link itself terminated.
///
/// No `derive(Debug)`: the `FramePayload.extensions` field is
/// `Vec<ExtEntry>` and `ExtEntry` is wz-codecs sce-codegen output that
/// only derives `Default`. The manual `Debug` impl below summarizes
/// each variant without recursing into codec fields so existing test
/// assertions of the form `{outcome:?}` keep working.
pub enum DriverLoopOutcome {
    /// A typed `SessionFsmUnicastEvent` reached `Engine::process_event`;
    /// any state transition triggered by the event has completed.
    AdvancedFsm,
    /// The inbound frame parsed to a `KeepAlive` record. The lease
    /// stamp was updated inside `handle_inbound` (R72b); the engine
    /// state is unchanged.
    SideEffectOnly,
    /// R74 — the inbound frame parsed to a `Frame` transport envelope
    /// whose tail payload decoded into a batch of `NetworkMessage`
    /// records. The session FSM is unchanged (Frame receipt is not a
    /// session-state trigger); the application layer dispatches
    /// `messages` against its per-MID handler set.
    FramePayload {
        reliable: bool,
        sn: u64,
        messages: Vec<NetworkMessage>,
        has_ext: bool,
        extensions: Vec<ExtEntry>,
    },
    /// `parse_inbound` rejected the wire bytes, OR the Frame envelope
    /// parsed but `parse_frame_payload` could not decode an authored
    /// network-MID envelope inside the payload batch (e.g. a truncated
    /// `Request` body). The helper has already injected `FramingError`
    /// into the engine so the session-fsm `framing.error` transition
    /// fires; the variant is returned so the caller can log the
    /// underlying error.
    ParseError(InboundParseError),
    /// The link reported `LostCause`. The helper has injected
    /// `LinkLost` into the engine so the `link.lost` transition
    /// fires; the cause is returned for logging.
    LinkLost(LostCause),
}

impl std::fmt::Debug for DriverLoopOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdvancedFsm => f.write_str("AdvancedFsm"),
            Self::SideEffectOnly => f.write_str("SideEffectOnly"),
            Self::FramePayload {
                reliable,
                sn,
                messages,
                has_ext,
                extensions,
            } => f
                .debug_struct("FramePayload")
                .field("reliable", reliable)
                .field("sn", sn)
                .field("messages", messages)
                .field("has_ext", has_ext)
                .field("ext_count", &extensions.len())
                .finish(),
            Self::ParseError(e) => write!(f, "ParseError({e:?})"),
            Self::LinkLost(c) => write!(f, "LinkLost({c:?})"),
        }
    }
}

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
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy>,
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

/// R77 — outcome of a single lease-deadline check against
/// `SessionLinkActions`' baseline stamps.
///
/// Baseline selection (R84): the lease counts from
/// `max(established_at, last_inbound_keepalive_at)` — whichever is
/// most recent. Both slots being `None` means the FSM has not
/// reached Established yet AND no peer KeepAlive has been
/// observed (e.g. pre-handshake), and the helper defers via
/// `NoBaseline`. The prior R77 baseline was `last_inbound_keepalive_at`
/// alone, which left `NoBaseline` pinned indefinitely until the
/// first peer KeepAlive — violating session-fsm §2.5 ("lease
/// counts from Established entry").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCheckOutcome {
    /// Both `established_at` and `last_inbound_keepalive_at` are
    /// `None`. The helper makes no decision and does NOT inject
    /// `LeaseExpired`. In practice this surfaces only pre-Established
    /// (since `Established.onentry` populates `established_at` per
    /// R84). Production callers treat this as "still polling".
    NoBaseline,
    /// `now.duration_since(baseline) < params.lease` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper performed no FSM mutation; engine state is
    /// unchanged.
    WithinLease,
    /// `now.duration_since(baseline) >= params.lease` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper has invoked
    /// `engine.process_event(SessionFsmUnicastEvent::LeaseExpired)`
    /// so the session-fsm `lease.expired -> Closing(Expired)`
    /// transition fires.
    Expired,
}

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
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy>,
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

/// R83 — per-iteration event surfaced to the
/// [`drive_session_until_terminal`] observer callback. Each
/// iteration of the driver loop runs exactly one branch of the
/// inner `tokio::select!` (or the no-baseline `await`) and fires
/// the callback with the matching variant before looping.
///
/// Variant choice mirrors the loop body's two work paths:
///
/// - [`IterationEvent::Poll`] fires when the
///   [`poll_and_dispatch_one`] arm completes — i.e. the link
///   produced a `LinkEvent`. The borrowed [`DriverLoopOutcome`]
///   reflects whatever the dispatch helper returned: typed FSM
///   advance, `KeepAlive` side-effect, R74 `FramePayload` with
///   the decoded `NetworkMessage` batch, `ParseError`, or
///   `LinkLost`. Application-layer dispatch reads
///   `FramePayload.messages` here.
/// - [`IterationEvent::Lease`] fires when the lease-deadline
///   sleep arm wins the `tokio::select!` race — i.e. the peer
///   has gone silent. The carried [`LeaseCheckOutcome`] is the
///   helper's verdict (`NoBaseline` / `WithinLease` / `Expired`);
///   on `Expired` the FSM has already been advanced to `Closing`
///   inside the helper, so the next loop top will return
///   `Terminated`.
///
/// The borrow `'a` is the loop iteration's stack frame. Observers
/// that need to retain outcome data across iterations must clone
/// the relevant fields (e.g. `FramePayload.messages.clone()`) into
/// owned storage; the reference does not outlive the callback.
///
/// Synchronous contract. The callback runs inside the
/// `tokio::select!` arm, so heavy work blocks the loop. Callers
/// with expensive consumers should buffer (`Vec`, `mpsc::Sender`)
/// inside the closure and drain on a separate task.
///
/// `Copy` because both variants are payload-cheap: `Poll` carries
/// only a `&DriverLoopOutcome` reference (references are `Copy`),
/// and `Lease(LeaseCheckOutcome)` is itself a unit-only enum that
/// derives `Copy`. Making `IterationEvent` `Copy` lets a single
/// observer callback fan the same event out to multiple
/// `dispatch_iteration_event` consumers (subscriber + queryable
/// registries) without having to manually re-construct the variant
/// or split the dispatch into separate iterations.
#[derive(Clone, Copy)]
pub enum IterationEvent<'a> {
    /// `poll_and_dispatch_one` returned. The borrowed outcome
    /// covers all five `DriverLoopOutcome` variants.
    Poll(&'a DriverLoopOutcome),
    /// `tokio::time::sleep` won the select race against the poll
    /// future; `check_lease_deadline` has already run and its
    /// verdict is carried here. `Copy` because the enum has only
    /// unit variants.
    Lease(LeaseCheckOutcome),
}

impl std::fmt::Debug for IterationEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poll(o) => write!(f, "Poll({o:?})"),
            Self::Lease(o) => write!(f, "Lease({o:?})"),
        }
    }
}

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
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy>,
    max_iters: Option<usize>,
    clock: &T,
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
        let lease_deadline_ms = {
            let stamp_ms = *actions.last_inbound_keepalive_at.lock().unwrap();
            stamp_ms.map(|s| s.saturating_add(lease_ms))
        };
        match lease_deadline_ms {
            Some(deadline_ms) => {
                let now_ms = clock.now_monotonic_ms();
                let remaining_ms = deadline_ms.saturating_sub(now_ms);
                tokio::select! {
                    outcome = poll_and_dispatch_one(driver, actions, engine) => {
                        on_event(IterationEvent::Poll(&outcome));
                    }
                    _ = clock.sleep(remaining_ms) => {
                        let lease_outcome =
                            check_lease_deadline(actions, engine, clock.now_monotonic_ms());
                        on_event(IterationEvent::Lease(lease_outcome));
                    }
                }
            }
            None => {
                let outcome = poll_and_dispatch_one(driver, actions, engine).await;
                on_event(IterationEvent::Poll(&outcome));
            }
        }
    }
}

/// Decode a transport-message ext chain in place. Terminates when
/// an entry's `Z` bit is clear OR when `MAX_EXT_CHAIN_DEPTH` is
/// reached (the latter returns `ExtChainOverflow` so a malformed
/// peer cannot pin the decoder into an unbounded loop). The
/// cursor's `peek_slice` raises `NeedMoreBytes` when the wire
/// truncates mid-entry, which propagates up as `Codec(NeedMoreBytes)`.
///
/// R311g1 — function definition is conditional on the union of all
/// codec features whose `parse_inbound` arms call into it. The
/// `minus-all-codecs` lane (all codec-* off) elides every caller and
/// — under this `cfg(any(...))` predicate — the function definition
/// itself, removing the previous `#[allow(dead_code)]` annotation.
/// Adding a new body codec feature (R311h..R311l) extends the
/// predicate. Per `feedback_signature_stability` MEMORY note's
/// "annotation = last resort" rule: prefer explicit cfg over allow.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
fn decode_ext_chain(cursor: &mut SceCursor<'_>) -> Result<Vec<ExtEntry>, InboundParseError> {
    let mut entries = Vec::new();
    for _ in 0..MAX_EXT_CHAIN_DEPTH {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        entries.push(entry);
        if !z {
            return Ok(entries);
        }
    }
    Err(InboundParseError::ExtChainOverflow)
}

/// Pack the `cbyte` field per zenoh-pico's `_z_whatami_to_uint8`
/// (transport.c:31-37) + `(zid_len - 1) << 4` (transport.c:189-192).
#[cfg(feature = "codec-init-body")]
fn init_cbyte(api_whatami: u8, zid_len: usize) -> u8 {
    debug_assert!(
        (1..=16).contains(&zid_len),
        "zid_len must be 1..=16 (wire constraint, transport.h)"
    );
    let whatami_wire = (api_whatami >> 1) & 0x03;
    whatami_wire | (((zid_len as u8 - 1) & 0x0F) << 4)
}

/// Pack `sn_res` per transport.c:196-197:
/// `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`.
#[cfg(feature = "codec-init-body")]
fn pack_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

// ─────────────────────────── helpers ───────────────────────────

fn bind_unit<F>(lua: &dyn IScriptEngine, name: &str, actions: &Arc<SessionLinkActions>, body: F)
where
    F: Fn(&Arc<SessionLinkActions>) + Send + Sync + 'static,
{
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        body(&captured);
        ScriptValue::Null
    });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}

fn bind_close_reason(
    lua: &dyn IScriptEngine,
    name: &str,
    actions: &Arc<SessionLinkActions>,
    reason: CloseReason,
) {
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        let mut trace = captured.trace.lock().unwrap();
        trace.set_close_reason_count += 1;
        trace.close_reason = reason;
        ScriptValue::Null
    });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}

fn bind_bool(lua: &dyn IScriptEngine, name: &str, value: bool) {
    let cb: NativeMethod =
        Box::new(move |_args: &[ScriptValue]| -> ScriptValue { ScriptValue::Bool(value) });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}

/// R89 — dynamic boolean guard binding. The closure receives the
/// captured `Arc<SessionLinkActions>` and returns a `bool` verdict
/// per invocation; sibling to `bind_unit` (which returns Null) and
/// `bind_bool` (which returns a constant). Used by `cookie_valid()`
/// to re-HMAC peer_zid against the inbound OpenSyn cookie at guard
/// evaluation time rather than at registration time.
fn bind_guard<F>(lua: &dyn IScriptEngine, name: &str, actions: &Arc<SessionLinkActions>, body: F)
where
    F: Fn(&Arc<SessionLinkActions>) -> bool + Send + Sync + 'static,
{
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        ScriptValue::Bool(body(&captured))
    });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}

// R71 — the former `dispatch_script` test shim moved to the
// `wz-runtime-tokio-test-support` sibling crate. Production callers
// drive script actions via `Engine::process_event` (which validates
// against generated SCXML transition guards before invoking the Lua
// closure); the direct-by-name dispatch would be a Lua-injection
// surface in production code paths and therefore lives behind the
// test-support crate boundary.

/// Single-source-of-truth list of every script-action name the
/// `register_*` family installs onto the Lua engine. The build
/// script (`build.rs::audit_script_names`) reads this constant
/// directly via `include_str!` parsing and compares it against the
/// SCXML's `<script>` bodies + `cond=` identifiers, so adding a
/// name in one place but not the other fails the build instead of
/// drifting silently. R60 consolidated the build-time and runtime
/// lists; previously they were hand-maintained twins (drift hazard
/// flagged in R59's self-review).
pub const REGISTERED_SCRIPT_NAMES: &[&str] = &[
    "link_driver_open",
    "send_init_syn",
    "send_open_syn",
    "send_init_ack_with_cookie",
    "send_open_ack",
    "send_close_frame_with_reason",
    "release_link",
    "enable_rx_tx_regions",
    "record_established_at",
    "start_lease_monitor",
    "stop_lease_monitor",
    "start_keepalive_worker",
    "stop_keepalive_worker",
    "free_pool_slots",
    "set_close_reason_generic",
    "set_close_reason_invalid",
    "set_close_reason_expired",
    "set_close_reason_unresponsive",
    "half_open_cap_available",
    "accept_rate_token",
    "cookie_valid",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-SHA256 cookie generator must produce 16-byte output and
    /// be deterministic given the same (key, peer_zid) inputs.
    /// Cross-checks against the RustCrypto `hmac` + `sha2` baseline
    /// — if either crate drifts on us the byte sequence will move
    /// and this test catches it before the wire interop tests fail.
    #[test]
    fn cookie_hmac_sha256_deterministic_16_byte_output() {
        let key = SigningKey::new(vec![0xAB; 32]).expect("32-byte key valid");
        let peer_zid = vec![0x01, 0x02, 0x03, 0x04];
        let cookie_a = generate_cookie_hmac_sha256(&key, &peer_zid);
        let cookie_b = generate_cookie_hmac_sha256(&key, &peer_zid);
        assert_eq!(cookie_a.len(), 16, "cookie wire width is 16 bytes");
        assert_eq!(cookie_a, cookie_b, "same inputs → same cookie");

        let different_peer = vec![0x05, 0x06, 0x07, 0x08];
        let cookie_c = generate_cookie_hmac_sha256(&key, &different_peer);
        assert_ne!(
            cookie_a, cookie_c,
            "different peer_zid must yield different cookie"
        );
    }

    /// R69 — SigningKey::new_random yields a 32-byte key (satisfies
    /// the >= 32 invariant by construction) and two successive
    /// calls produce distinct material with overwhelming probability
    /// (collision space = 2^256, never observed in practice).
    /// The test asserts both surfaces: length AND distinctness, so
    /// a regression that wires a constant entropy source (zero-fill,
    /// counter, etc.) fires loud.
    #[test]
    fn signing_key_new_random_yields_distinct_32_byte_keys() {
        let a = SigningKey::new_random().expect("AP entropy available");
        let b = SigningKey::new_random().expect("AP entropy available");
        assert_eq!(a.as_slice().len(), 32, "new_random must yield 32 bytes");
        assert_eq!(b.as_slice().len(), 32);
        assert_ne!(
            a.as_slice(),
            b.as_slice(),
            "two new_random calls must produce distinct keys (2^256 collision space)"
        );
    }

    /// Short-key reject is loud at construction site (RFC §5.M
    /// mandates >= 32 bytes; the typed constructor returns
    /// `Err(SigningKeyTooShort)` instead of letting a 16-byte key
    /// reach the wire-decode-time peer reject path).
    #[test]
    fn signing_key_short_returns_err() {
        let too_short = vec![0xAA; 16];
        let result = SigningKey::new(too_short);
        assert!(matches!(result, Err(SigningKeyTooShort(_))));
    }

    /// SigningKey Debug impl never leaks the bytes — only the
    /// length. Catches a regression where a future contributor
    /// adds `#[derive(Debug)]` (which would print the inner Vec).
    #[test]
    fn signing_key_debug_redacts_bytes() {
        let key = SigningKey::new(vec![0xDE; 32]).unwrap();
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("<redacted>"), "Debug must redact: {dbg}");
        assert!(!dbg.contains("DE"), "Debug must not leak hex: {dbg}");
    }

    /// RFC 4231 Test Case 1 — pinned cross-check against the public
    /// HMAC-SHA256 test vector. If RustCrypto's `hmac` + `sha2`
    /// crates ever regress, this assertion fires.
    ///
    /// Key  = 0x0b × 20
    /// Data = "Hi There"
    /// HMAC = b0344c61d8db38535ca8afceaf0bf12b
    ///        881dc200c9833da726e9376c2e32cff7
    #[test]
    fn rfc4231_test_case_1_full_hmac_sha256() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC1 byte mismatch");
    }

    /// RFC 4231 Test Case 2 — verifies the implementation handles
    /// the canonical "short key, longer data" combination correctly.
    ///
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    /// HMAC = 5bdcc146bf60754e6a042426089575c7
    ///        5a003f089d2739839dec58b964ec3843
    #[test]
    fn rfc4231_test_case_2_full_hmac_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = compute_hmac_sha256_full(key, data);
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC2 byte mismatch");
    }

    /// RFC 4231 Test Case 3 — uniform-byte key + uniform-byte data
    /// stresses the block-mix path (both key and data 20+ bytes,
    /// neither block-size-aligned to anything special).
    ///
    /// Key  = 0xaa × 20
    /// Data = 0xdd × 50
    /// HMAC = 773ea91e36800e46854db8ebd09181a7
    ///        2959098b3ef8c122d9635514ced565fe
    #[test]
    fn rfc4231_test_case_3_full_hmac_sha256() {
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];
        let mac = compute_hmac_sha256_full(&key, &data);
        let expected: [u8; 32] = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC3 byte mismatch");
    }

    /// RFC 4231 Test Case 4 — sequential-byte key (0x01..=0x19)
    /// with uniform-byte data. Catches off-by-one in key
    /// padding / inner-pad XOR.
    ///
    /// Key  = 0x01, 0x02, …, 0x19  (25 bytes)
    /// Data = 0xcd × 50
    /// HMAC = 82558a389a443c0ea4cc819899f2083a
    ///        85f0faa3e578f8077a2e3ff46729665b
    #[test]
    fn rfc4231_test_case_4_full_hmac_sha256() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = vec![0xcd; 50];
        let mac = compute_hmac_sha256_full(&key, &data);
        let expected: [u8; 32] = [
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2,
            0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4,
            0x67, 0x29, 0x66, 0x5b,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC4 byte mismatch");
    }

    /// RFC 4231 Test Case 5 — truncated-MAC scenario. RFC §4.5
    /// documents the truncation-to-128-bits use case which is
    /// exactly what `generate_cookie_hmac_sha256` does (truncate
    /// to first 16 bytes). The expected output here is the full
    /// MAC; the truncation invariant is asserted separately so a
    /// reader can see both the source MAC and the truncated form.
    ///
    /// Key  = 0x0c × 20
    /// Data = "Test With Truncation"
    /// HMAC = a3b6167473100ee06e0c796c2955552b
    ///        fa6f7c0a6a8aef8b93f860aab0cd20c5
    /// Truncated (first 16 bytes) = a3b6167473100ee06e0c796c2955552b
    #[test]
    fn rfc4231_test_case_5_truncation_invariant() {
        let key = vec![0x0c; 20];
        let data = b"Test With Truncation";
        let full = compute_hmac_sha256_full(&key, data);
        let expected_full: [u8; 32] = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
            0x55, 0x2b, 0xfa, 0x6f, 0x7c, 0x0a, 0x6a, 0x8a, 0xef, 0x8b, 0x93, 0xf8, 0x60, 0xaa,
            0xb0, 0xcd, 0x20, 0xc5,
        ];
        assert_eq!(full, expected_full, "RFC 4231 TC5 full MAC");
        // First 16 bytes — the cookie wire-shape truncation
        // matches RFC §4.5 96/128-bit MAC truncation. Asserts
        // that generate_cookie_hmac_sha256's slice [..16] yields
        // exactly the RFC truncated form.
        let expected_truncated: [u8; 16] = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
            0x55, 0x2b,
        ];
        assert_eq!(
            &full[..16],
            expected_truncated.as_slice(),
            "RFC 4231 TC5 truncated"
        );
    }

    /// RFC 4231 Test Case 6 — block-size+ key triggers the
    /// "key longer than block size, hash first" path
    /// (HMAC algorithm pre-hashes the key when len > 64).
    ///
    /// Key  = 0xaa × 131
    /// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    /// HMAC = 60e431591ee0b67f0d8a26aacbf5b77f
    ///        8e0bc6213728c5140546040f0ee37f54
    #[test]
    fn rfc4231_test_case_6_full_hmac_sha256() {
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC6 byte mismatch");
    }

    /// RFC 4231 Test Case 7 — block-size+ key AND block-size+
    /// data. Stresses both the key-prehash path AND the multi-
    /// block message absorption path.
    ///
    /// Key  = 0xaa × 131
    /// Data = "This is a test using a larger than block-size key
    ///         and a larger than block-size data. ..."
    /// HMAC = 9b09ffa71b942fcb27635fbcd5b0e944
    ///        bfdc63644f0713938a7f51535c3a35e2
    #[test]
    fn rfc4231_test_case_7_full_hmac_sha256() {
        let key = vec![0xaa; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0,
            0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53,
            0x5c, 0x3a, 0x35, 0xe2,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC7 byte mismatch");
    }

    /// init_cbyte must match zenoh-pico's transport.c:189-192
    /// packing exactly — Layer 3 byte-equiv depends on this.
    #[cfg(feature = "codec-init-body")]
    #[test]
    fn init_cbyte_packs_whatami_and_zid_len() {
        // whatami=Peer(0x02), zid_len=4 → wire whatami = (0x02>>1)&3 = 0x01
        // zid_len_m1 = 3 → cbyte = 0x01 | (3 << 4) = 0x31
        assert_eq!(init_cbyte(0x02, 4), 0x31);
        // whatami=Router(0x01), zid_len=1 → wire whatami = (0x01>>1)&3 = 0
        // zid_len_m1 = 0 → cbyte = 0
        assert_eq!(init_cbyte(0x01, 1), 0x00);
        // whatami=Client(0x04), zid_len=16 → wire whatami = (0x04>>1)&3 = 0x02
        // zid_len_m1 = 15 → cbyte = 0x02 | (15 << 4) = 0xF2
        assert_eq!(init_cbyte(0x04, 16), 0xF2);
    }

    /// pack_sn_res must match transport.c:196-197 packing exactly.
    #[cfg(feature = "codec-init-body")]
    #[test]
    fn pack_sn_res_layout_matches_transport_h() {
        assert_eq!(pack_sn_res(0, 0), 0x00);
        assert_eq!(pack_sn_res(3, 0), 0x03);
        assert_eq!(pack_sn_res(0, 3), 0x0C);
        assert_eq!(pack_sn_res(3, 3), 0x0F);
        assert_eq!(pack_sn_res(2, 1), 0x06);
    }

    // ── R121e — outbound Push/Frame builder coverage ──

    /// `build_push_literal` populates the Push struct with the
    /// header / wireexpr / msg_put shape the wire-spec calls for:
    /// `N_MID_PUSH | N_flag` in the header (M derives at encode),
    /// `WireexprLocal { id=0, suffix=Some(s) }` for the literal
    /// keyexpr, and `MsgPut` with the supplied payload bytes.
    #[test]
    fn build_push_literal_shapes_struct_for_literal_keyexpr() {
        let push = build_push_literal("demo/test", b"hello");
        // header bits: N_MID_PUSH (0x1D) | N flag (0x20) = 0x3D.
        // M flag (0x40) is set at encode time, not on the struct.
        assert_eq!(
            push.header, 0x3D,
            "Push.header must carry N_MID_PUSH (0x1D) | N flag (0x20); M derives at encode"
        );
        match &push.keyexpr.body {
            WireexprVariant::WireexprLocal(arm) => {
                assert_eq!(arm.id, 0, "literal-keyexpr path uses id=0 sentinel");
                assert_eq!(
                    arm.suffix.as_deref(),
                    Some("demo/test"),
                    "suffix must carry the literal keyexpr string"
                );
                assert_eq!(
                    arm.suffix_len,
                    Some(9),
                    "suffix_len must match suffix.len() so the encoder emits the VLE width"
                );
            }
            WireexprVariant::WireexprNonlocal(_) => {
                panic!("literal-keyexpr path must select the WireexprLocal arm (M=1)")
            }
        }
        match &push.body {
            PushVariant::CodecZenohMsgPut(put) => {
                assert_eq!(put.header, 0x01, "MsgPut header MID = 0x01 with no flags");
                assert_eq!(
                    put.payload, b"hello",
                    "MsgPut.payload carries the application bytes verbatim"
                );
                assert_eq!(
                    put.payload_len, 5,
                    "MsgPut.payload_len must match payload.len() for the VLE writer"
                );
                assert!(put.timestamp.is_none(), "no timestamp flag on the MVP path");
                assert!(put.encoding.is_none(), "no encoding flag on the MVP path");
                assert!(
                    put.extensions.is_none(),
                    "no MsgPut-level extensions on the MVP path"
                );
            }
            other => panic!(
                "MVP build_push_literal must emit MsgPut body, got {:?}",
                match other {
                    PushVariant::CodecZenohMsgDel(_) => "MsgDel",
                    PushVariant::Default { .. } => "Default",
                    PushVariant::CodecZenohMsgPut(_) => unreachable!(),
                }
            ),
        }
        assert!(
            push.extensions.is_none(),
            "no Push-level extensions on the MVP path"
        );
    }

    /// `encode_frame_with_push` composes the transport-envelope
    /// header byte (T_MID_FRAME | parent_flags) with the
    /// `Frame.encode_to_vec()` body (VLE(sn) + payload). With reliable=true
    /// the FLAG_T_FRAME_R bit appears in the header byte.
    #[test]
    fn encode_frame_with_push_emits_transport_header_plus_frame_body() {
        // Empty-payload Push at sn=0 keeps the assertion focused on
        // the transport-envelope header byte and the Frame body
        // shape. Push::default()'s wire bytes are independently
        // pinned by layer3_push.rs's byte-equiv test.
        let push = Push::default();
        let push_bytes = push.encode_to_vec();

        // Reliable Frame at sn=0.
        let wire_reliable = encode_frame_with_push(0, Push::default(), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R (0x20) on the parent header byte"
        );
        // Body shape: VLE(sn=0) = single byte 0x00, followed by
        // Push.encode_to_vec() bytes verbatim.
        assert_eq!(wire_reliable[1], 0x00, "Frame.sn=0 VLE width = 1 byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            push_bytes.as_slice(),
            "tail of Frame envelope must be the Push.encode_to_vec() bytes byte-for-byte"
        );

        // Best-effort Frame: same shape minus FLAG_T_FRAME_R.
        let wire_best_effort = encode_frame_with_push(0, Push::default(), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must NOT set FLAG_T_FRAME_R; only T_MID_FRAME in the header"
        );
    }

    /// `encode_frame_with_push` round-trips the sn VLE width
    /// boundaries (single-byte 0..=127, two-byte 128..=16383,
    /// etc.) so a downstream `parse_frame_payload` consumer can
    /// recover the original sn. The Frame.encode body's VLE writer
    /// is shared with layer3_frame.rs's byte-equiv coverage; this
    /// test pins the transport-envelope wrapper around it.
    #[test]
    fn encode_frame_with_push_carries_vle_sn_across_widths() {
        for sn in [0u64, 1, 127, 128, 16383, 16384, 1_000_000] {
            let wire = encode_frame_with_push(sn, Push::default(), true);
            // Round-trip through parse_inbound to recover the
            // sn — it carries us through both the transport-header
            // byte decode AND the Frame.sn VLE decode.
            let parsed = parse_inbound(&wire).expect("parse_inbound on round-tripped Frame");
            match parsed {
                InboundFrame::Frame {
                    sn: parsed_sn,
                    reliable,
                    ..
                } => {
                    assert_eq!(parsed_sn, sn, "sn must round-trip through encode+parse");
                    assert!(
                        reliable,
                        "reliable=true → FLAG_T_FRAME_R → InboundFrame.reliable=true"
                    );
                }
                // InboundFrame intentionally omits Debug derive
                // (sce-codegen wz-codecs structs only derive
                // Default, so a wrapping `#[derive(Debug)]` here
                // would not compile). Fall back to a variant-name
                // string for the panic.
                other => panic!(
                    "encode_frame_with_push must produce an InboundFrame::Frame; got {}",
                    match other {
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init { .. } => "Init",
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open { .. } => "Open",
                        #[cfg(feature = "codec-close")]
                        InboundFrame::Close { .. } => "Close",
                        #[cfg(feature = "codec-keep-alive")]
                        InboundFrame::KeepAlive { .. } => "KeepAlive",
                        InboundFrame::Unknown { .. } => "Unknown",
                        InboundFrame::Frame { .. } => unreachable!(),
                    }
                ),
            }
        }
    }

    /// R121g — `build_push_aliased` produces a `WireexprLocal`
    /// with the non-zero mapping id, while `build_push_literal`
    /// produces id=0 + inline suffix. The aliased Push is the
    /// efficient repeated-keyexpr shape that follows a peer-side
    /// `DeclKexpr` registration.
    #[test]
    fn build_push_aliased_carries_non_zero_id_with_optional_suffix() {
        let pure = build_push_aliased(7, None, b"hello");
        match &pure.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7, "pure aliased Push id must equal mapping_id");
                assert_eq!(w.suffix, None, "pure aliased Push must omit suffix");
                assert_eq!(w.suffix_len, None, "pure aliased Push must omit suffix_len");
            }
            _ => panic!("build_push_aliased must produce a WireexprLocal arm"),
        }
        match &pure.body {
            PushVariant::CodecZenohMsgPut(p) => {
                assert_eq!(p.payload, b"hello".to_vec());
                assert_eq!(p.payload_len, 5);
            }
            _ => panic!("build_push_aliased must wrap a MsgPut body"),
        }

        let composite = build_push_aliased(7, Some("tail"), b"hi");
        match &composite.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!("composite aliased Push must produce a WireexprLocal arm"),
        }
    }

    /// R121g — `build_push_aliased` rejects `mapping_id == 0` so a
    /// caller cannot silently produce a literal-keyexpr Push via
    /// the aliased entry point.
    #[test]
    #[should_panic(expected = "build_push_aliased requires a non-zero mapping id")]
    fn build_push_aliased_rejects_zero_mapping_id() {
        let _ = build_push_aliased(0, Some("demo"), b"");
    }

    /// R219 — `build_push_del_literal` produces a literal-keyexpr
    /// Push whose body is the `MsgDel` arm (inner header 0x02,
    /// no payload, no timestamp / extensions). The outer Push
    /// header + WireexprLocal shape match the Put literal path.
    #[test]
    fn build_push_del_literal_shapes_struct_for_literal_keyexpr() {
        let push = build_push_del_literal("demo/test");
        assert_eq!(
            push.header, 0x3D,
            "Push.header must carry N_MID_PUSH (0x1D) | N flag (0x20) — same as the Put literal path"
        );
        match &push.keyexpr.body {
            WireexprVariant::WireexprLocal(arm) => {
                assert_eq!(arm.id, 0, "literal-keyexpr path uses id=0 sentinel");
                assert_eq!(
                    arm.suffix.as_deref(),
                    Some("demo/test"),
                    "suffix must carry the literal keyexpr string"
                );
                assert_eq!(
                    arm.suffix_len,
                    Some(9),
                    "suffix_len must match suffix.len() for the VLE writer"
                );
            }
            WireexprVariant::WireexprNonlocal(_) => {
                panic!("literal-keyexpr path must select the WireexprLocal arm (M=1)")
            }
        }
        match &push.body {
            PushVariant::CodecZenohMsgDel(del) => {
                assert_eq!(del.header, 0x02, "MsgDel header MID = 0x02 with no flags");
                assert!(
                    del.timestamp.is_none(),
                    "MVP Del path emits no timestamp flag"
                );
                assert!(
                    del.extensions.is_none(),
                    "MVP Del path emits no MsgDel-level extensions"
                );
            }
            other => panic!(
                "build_push_del_literal must emit MsgDel body, got {:?}",
                match other {
                    PushVariant::CodecZenohMsgPut(_) => "MsgPut",
                    PushVariant::Default { .. } => "Default",
                    PushVariant::CodecZenohMsgDel(_) => unreachable!(),
                }
            ),
        }
        assert!(
            push.extensions.is_none(),
            "no Push-level extensions on the MVP path"
        );
    }

    /// R219 — `build_push_del_aliased` produces a DECLARE-aliased
    /// Push whose body is the `MsgDel` arm. Both pure-aliased
    /// (suffix=None) and composite-aliased (suffix=Some) shapes are
    /// exercised so the N-flag derivation matches the Put aliased
    /// path. The MsgDel body content is identical across shapes.
    #[test]
    fn build_push_del_aliased_carries_non_zero_id_with_optional_suffix() {
        let pure = build_push_del_aliased(7, None);
        assert_eq!(
            pure.header,
            wire_const::N_MID_PUSH,
            "pure aliased Push (no suffix) must clear the N flag",
        );
        match &pure.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7, "pure aliased Push id must equal mapping_id");
                assert_eq!(w.suffix, None, "pure aliased Push must omit suffix");
                assert_eq!(w.suffix_len, None, "pure aliased Push must omit suffix_len");
            }
            _ => panic!("build_push_del_aliased must produce a WireexprLocal arm"),
        }
        match &pure.body {
            PushVariant::CodecZenohMsgDel(d) => {
                assert_eq!(d.header, 0x02);
            }
            _ => panic!("build_push_del_aliased must wrap a MsgDel body"),
        }

        let composite = build_push_del_aliased(7, Some("tail"));
        assert_eq!(
            composite.header,
            wire_const::N_MID_PUSH | 0x20,
            "composite aliased Push (suffix present) must set the N flag",
        );
        match &composite.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!("composite aliased Push must produce a WireexprLocal arm"),
        }
        match &composite.body {
            PushVariant::CodecZenohMsgDel(d) => {
                assert_eq!(d.header, 0x02);
            }
            _ => panic!("composite aliased Push must wrap a MsgDel body"),
        }
    }

    /// R219 — `build_push_del_aliased` rejects `mapping_id == 0` so
    /// a caller cannot silently produce a literal-keyexpr Del Push
    /// via the aliased entry point.
    #[test]
    #[should_panic(expected = "build_push_del_aliased requires a non-zero mapping id")]
    fn build_push_del_aliased_rejects_zero_mapping_id() {
        let _ = build_push_del_aliased(0, Some("demo"));
    }

    /// R219 — round-trip the literal-keyexpr Del path through
    /// `encode_frame_with_push` + `parse_inbound` so the wz
    /// receive-side parser surfaces the `MsgDel` inner body
    /// (not `MsgPut`) on the decoded `Push`. Establishes the wire-
    /// shape witness that pairs with the e2e zenoh-pico interop
    /// test — z_sub's printout cannot distinguish Del from
    /// empty-Put, so the codec-level round-trip is the definitive
    /// proof that the wz-side encoder emits the Del MID.
    #[test]
    fn build_push_del_literal_round_trips_through_frame_decode_as_msg_del() {
        let push = build_push_del_literal("demo/test");
        let wire = encode_frame_with_push(/*sn=*/ 0, push, /*reliable=*/ true);
        let parsed = parse_inbound(&wire).expect("parse_inbound on Del-bearing Frame");
        let payload = match parsed {
            InboundFrame::Frame { payload, .. } => payload,
            _ => panic!("expected Frame variant from parse_inbound"),
        };
        let messages =
            parse_frame_payload(&payload).expect("parse_frame_payload on Del-bearing Frame");
        assert_eq!(
            messages.len(),
            1,
            "Frame must carry exactly one Push record after round-trip"
        );
        match &messages[0] {
            NetworkMessage::Push(p) => match &p.body {
                PushVariant::CodecZenohMsgDel(d) => {
                    assert_eq!(
                        d.header, 0x02,
                        "round-tripped MsgDel must preserve its MID byte"
                    );
                }
                other => panic!(
                    "round-tripped Push body must be MsgDel, got {:?}",
                    match other {
                        PushVariant::CodecZenohMsgPut(_) => "MsgPut",
                        PushVariant::Default { .. } => "Default",
                        PushVariant::CodecZenohMsgDel(_) => unreachable!(),
                    }
                ),
            },
            _ => panic!("expected NetworkMessage::Push from round-trip"),
        }
    }

    /// R121g — `build_declare_kexpr` wraps a `DeclKexpr` registering
    /// `mapping_id -> suffix` in a `Declare` envelope with the
    /// network MID header and no interest_id / no extensions.
    /// R121h-pre — under the SCE e10619d3 B5-ν ownership invert, the
    /// inner DeclKexpr carries the literal suffix via the
    /// `WireexprLocal` arm (semantically correct: the declared
    /// keyexpr lives in the local mapping table); DeclKexpr's
    /// `<sce:import>` site omits `<sce:variant-dispatch>` so no
    /// parent derive bit is emitted at bit 6.
    #[test]
    fn build_declare_kexpr_wraps_decl_kexpr_with_literal_suffix() {
        let declare = build_declare_kexpr(7, "demo/test");
        assert_eq!(
            declare.header,
            wire_const::N_MID_DECLARE,
            "Declare header must carry N_MID_DECLARE with no flag bits set",
        );
        assert!(
            declare.interest_id.is_none(),
            "MVP DECLARE has no interest_id"
        );
        assert!(
            declare.extensions.is_none(),
            "MVP DECLARE has no extensions"
        );
        match &declare.body {
            DeclareVariant::CodecZenohDeclKexpr(dk) => {
                assert_eq!(dk.id, 7, "DeclKexpr.id must equal mapping_id argument");
                assert_eq!(
                    dk.header, 0x20,
                    "DeclKexpr.header must carry _Z_DECL_KEXPR_FLAG_N (0x20)"
                );
                match &dk.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(
                            w.id, 0,
                            "inner Wireexpr.id is the literal-keyexpr sentinel 0"
                        );
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                        assert_eq!(w.suffix_len, Some(9));
                    }
                    _ => panic!(
                        "DeclKexpr.keyexpr must use the WireexprLocal arm under \
                         the SCE e10619d3 B5-ν invert (the parent's <sce:import> \
                         site omits <sce:variant-dispatch>, so no parent derive \
                         bit is emitted regardless of which arm is selected)"
                    ),
                }
            }
            _ => panic!("build_declare_kexpr must produce a CodecZenohDeclKexpr variant"),
        }
    }

    /// R121g — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_kexpr(7, "demo/test").encode_to_vec()` must equal
    /// zenoh-pico's `_z_decl_kexpr_encode` output for the same
    /// arguments. Authored as a byte-literal compare so a future
    /// codegen drift on either DeclKexpr.header derivation or
    /// WireexprNonlocal encoding shape surfaces immediately.
    ///
    /// Expected wire bytes from zenoh-pico
    /// (`vendor/zenoh-pico/src/protocol/codec/declarations.c:52-63`):
    ///   - DeclKexpr.header = `_Z_DECL_KEXPR_MID(0) | _Z_DECL_KEXPR_FLAG_N(0x20)` = `0x20`
    ///   - VLE(id=7) = `0x07`
    ///   - wireexpr.id VLE(0) = `0x00`
    ///   - wireexpr.suffix string = VLE(9) + 9 bytes of "demo/test"
    #[test]
    fn build_declare_kexpr_emits_zenoh_pico_compatible_wire_bytes() {
        let declare = build_declare_kexpr(7, "demo/test");
        let outer = declare.encode_to_vec();
        // Skip the outer Declare envelope header (0x1E) — that
        // single byte is the wz Declare codec's own emit; the rest
        // is the DeclKexpr inner body. The byte-compare gate sits
        // on the inner body so a regression in either the inner
        // header derivation OR the wireexpr body emit fires.
        let mut expected = vec![
            wire_const::N_MID_DECLARE, // outer Declare 0x1E
            0x20,                      // DeclKexpr.header = _Z_DECL_KEXPR_FLAG_N
            0x07,                      // VLE(mapping_id=7)
            0x00,                      // wireexpr.id VLE(0)
            0x09,                      // suffix_len VLE(9)
        ];
        expected.extend_from_slice(b"demo/test");
        assert_eq!(
            outer, expected,
            "build_declare_kexpr wire bytes must match zenoh-pico's \
             _z_decl_kexpr_encode output byte-for-byte"
        );
    }

    /// R121g — `build_declare_kexpr` rejects `mapping_id == 0` to
    /// keep the literal-keyexpr sentinel out of the DECLARE table.
    #[test]
    #[should_panic(expected = "build_declare_kexpr requires a non-zero mapping id")]
    fn build_declare_kexpr_rejects_zero_mapping_id() {
        let _ = build_declare_kexpr(0, "demo/test");
    }

    /// R121g — `encode_frame_with_declare` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.encode_to_vec()` wrapping
    /// as `encode_frame_with_push`, with `Declare.encode_to_vec()` as the
    /// inner payload bytes. Reliable / best-effort header flag
    /// behaviour mirrors the Push variant.
    #[test]
    fn encode_frame_with_declare_wraps_declare_in_frame_envelope() {
        let declare = build_declare_kexpr(7, "demo/test");
        let declare_bytes = declare.encode_to_vec();

        let wire_reliable = encode_frame_with_declare(0, build_declare_kexpr(7, "demo/test"), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            declare_bytes.as_slice(),
            "Frame body tail must be Declare.encode_to_vec() bytes verbatim",
        );

        let wire_best_effort =
            encode_frame_with_declare(0, build_declare_kexpr(7, "demo/test"), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    /// R121i — `build_declare_subscriber` produces a Declare envelope
    /// carrying a `DeclSubscriber` inner body whose author-supplied
    /// header carries the MID + optional N (suffix gate) but NOT the
    /// M flag (codegen-derived from parent.M dispatch). Three shapes
    /// exercise the three semantic cases: pure-alias (id=N + None),
    /// composite (id=N + Some), and literal (id=0 + Some).
    #[test]
    fn build_declare_subscriber_wraps_decl_subscriber_in_declare_envelope() {
        // Case 1 — pure alias to a peer-declared mapping (suffix=None).
        let alias = build_declare_subscriber(5, 7, None);
        assert_eq!(
            alias.header,
            wire_const::N_MID_DECLARE,
            "Declare envelope header must carry N_MID_DECLARE",
        );
        match &alias.body {
            DeclareVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(d.id, 5, "DeclSubscriber.id must equal subscriber_id");
                assert_eq!(
                    d.header, 0x02,
                    "header carries MID only; N clear (no suffix) and M is codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7, "Wireexpr.id must equal keyexpr_mapping_id");
                        assert!(w.suffix.is_none(), "alias case has no suffix");
                        assert!(w.suffix_len.is_none());
                    }
                    _ => panic!("DeclSubscriber.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_subscriber must produce CodecZenohDeclSubscriber"),
        }

        // Case 2 — composite: alias N + tail suffix.
        let composite = build_declare_subscriber(5, 7, Some("tail"));
        match &composite.body {
            DeclareVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(
                    d.header, 0x22,
                    "header MID 0x02 | N(0x20) when suffix present"
                );
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                        assert_eq!(w.suffix_len, Some(4));
                    }
                    _ => panic!("composite must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal: id=0 sentinel + suffix carries the keyexpr.
        let literal = build_declare_subscriber(5, 0, Some("demo/test"));
        match &literal.body {
            DeclareVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(d.header, 0x22, "literal case still sets N (suffix present)");
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "literal sentinel id=0");
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!("literal must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }
    }

    /// R121i — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_subscriber(5, 7, None).encode_to_vec()` must equal
    /// zenoh-pico's `_z_decl_subscriber_encode` /
    /// `_z_decl_commons_encode` output for the same arguments
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:65-84
    ///   + the `_z_wireexpr_encode` invocation at declarations.c:84).
    ///
    /// Three vectors lock the three semantic cases (alias /
    /// composite / literal) so a future codegen regression on either
    /// header derivation, wireexpr arm choice, or the M-bit emit
    /// path fires immediately.
    #[test]
    fn build_declare_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (subscriber_id=5, mapping_id=7, no
        // suffix). Wire shape (per declarations.c):
        //   outer Declare header 0x1E (N_MID_DECLARE)
        //   DeclSubscriber.header = MID(0x02) | M(0x40) = 0x42
        //                            (M=1 codegen-derived from
        //                             Local arm via the
        //                             <sce:variant-dispatch
        //                             flag="header.M"/> import-site
        //                             declaration in
        //                             decl_subscriber.scxml)
        //   VLE(subscriber_id=5)     = 0x05
        //   wireexpr Local id=7 only = 0x07
        let alias = build_declare_subscriber(5, 7, None);
        let alias_wire = alias.encode_to_vec();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x42,                      // MID(0x02) | M(0x40)
            0x05,                      // VLE(subscriber_id=5)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc"):
        //   DeclSubscriber.header = MID | N | M = 0x62
        //   VLE(5) = 0x05
        //   wireexpr.id VLE(7) = 0x07
        //   suffix_len VLE(3) = 0x03
        //   suffix bytes = "abc"
        let composite = build_declare_subscriber(5, 7, Some("abc"));
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x62, // MID | N | M
            0x05,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test"):
        //   DeclSubscriber.header = MID | N | M = 0x62
        //   VLE(5) = 0x05
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(9) = 0x09
        //   suffix bytes = "demo/test"
        let literal = build_declare_subscriber(5, 0, Some("demo/test"));
        let literal_wire = literal.encode_to_vec();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x62, 0x05, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-b — `build_declare_queryable` produces a Declare envelope
    /// carrying a `DeclQueryable` inner body. Mirror of the
    /// DeclSubscriber structural test, with MID swap 0x02 → 0x04 and
    /// the `WireexprLocal` arm preserved (M-bit codegen-derivation
    /// path identical).
    #[test]
    fn build_declare_queryable_wraps_decl_queryable_in_declare_envelope() {
        // Case 1 — pure alias to a peer-declared mapping (suffix=None).
        let alias = build_declare_queryable(9, 7, None);
        assert_eq!(
            alias.header,
            wire_const::N_MID_DECLARE,
            "Declare envelope header must carry N_MID_DECLARE",
        );
        match &alias.body {
            DeclareVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, 9, "DeclQueryable.id must equal queryable_id");
                assert_eq!(
                    d.header, 0x04,
                    "header carries MID 0x04 only; N clear (no suffix), M codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7, "Wireexpr.id must equal keyexpr_mapping_id");
                        assert!(w.suffix.is_none(), "alias case has no suffix");
                        assert!(w.suffix_len.is_none());
                    }
                    _ => panic!("DeclQueryable.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_queryable must produce CodecZenohDeclQueryable"),
        }

        // Case 2 — composite: alias N + tail suffix.
        let composite = build_declare_queryable(9, 7, Some("tail"));
        match &composite.body {
            DeclareVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(
                    d.header, 0x24,
                    "header MID 0x04 | N(0x20) when suffix present"
                );
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                        assert_eq!(w.suffix_len, Some(4));
                    }
                    _ => panic!("composite must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal: id=0 sentinel + suffix carries the keyexpr.
        let literal = build_declare_queryable(9, 0, Some("demo/test"));
        match &literal.body {
            DeclareVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.header, 0x24, "literal case still sets N (suffix present)");
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "literal sentinel id=0");
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!("literal must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }
    }

    /// R121i-b — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_queryable(...).encode_to_vec()` must equal zenoh-pico's
    /// `_z_decl_queryable_encode` output for the no-info-ext shape
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:105-118
    ///   with `has_info_ext = false` short-circuit at line 109).
    ///
    /// MID differs from DeclSubscriber (0x02 → 0x04) but the rest of
    /// the wire (id VLE + wireexpr body + M-bit OR convention) is
    /// identical — these three vectors lock the same alias /
    /// composite / literal trio. The `has_info_ext = true` variant
    /// (future ExtQueryableInfo tail) is out of scope for this round.
    #[test]
    fn build_declare_queryable_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (queryable_id=9, mapping_id=7, no
        // suffix). Wire shape:
        //   outer Declare header 0x1E (N_MID_DECLARE)
        //   DeclQueryable.header = MID(0x04) | M(0x40) = 0x44
        //   VLE(queryable_id=9)  = 0x09
        //   wireexpr Local id=7  = 0x07
        let alias = build_declare_queryable(9, 7, None);
        let alias_wire = alias.encode_to_vec();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x44,                      // MID(0x04) | M(0x40)
            0x09,                      // VLE(queryable_id=9)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "DeclQueryable alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc"):
        //   DeclQueryable.header = MID | N | M = 0x64
        //   VLE(9) = 0x09
        //   wireexpr.id VLE(7) = 0x07
        //   suffix_len VLE(3) = 0x03
        //   suffix bytes = "abc"
        let composite = build_declare_queryable(9, 7, Some("abc"));
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x64, // MID | N | M
            0x09,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "DeclQueryable composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test"):
        //   DeclQueryable.header = MID | N | M = 0x64
        //   VLE(9) = 0x09
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(9) = 0x09
        //   suffix bytes = "demo/test"
        let literal = build_declare_queryable(9, 0, Some("demo/test"));
        let literal_wire = literal.encode_to_vec();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x64, 0x09, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "DeclQueryable literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-b — `build_declare_token` produces a Declare envelope
    /// carrying a `DeclToken` inner body. Mirror of the DeclSubscriber
    /// / DeclQueryable structural test, with MID swap to 0x06.
    #[test]
    fn build_declare_token_wraps_decl_token_in_declare_envelope() {
        // Case 1 — pure alias.
        let alias = build_declare_token(11, 7, None);
        match &alias.body {
            DeclareVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.id, 11, "DeclToken.id must equal token_id");
                assert_eq!(
                    d.header, 0x06,
                    "header carries MID 0x06 only; N clear, M codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert!(w.suffix.is_none());
                    }
                    _ => panic!("DeclToken.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_token must produce CodecZenohDeclToken"),
        }

        // Case 2 — composite.
        let composite = build_declare_token(11, 7, Some("tail"));
        match &composite.body {
            DeclareVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.header, 0x26, "header MID 0x06 | N(0x20)");
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal.
        let literal = build_declare_token(11, 0, Some("demo/test"));
        match &literal.body {
            DeclareVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.header, 0x26);
                match &d.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0);
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    /// R121i-b — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_token(...).encode_to_vec()` must equal zenoh-pico's
    /// `_z_decl_token_encode` output
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:123-126).
    ///
    /// DeclToken's encode is a pure `_z_decl_commons_encode(has_ext =
    /// false)` wrapper — no extension surface at all. The three
    /// vectors lock the alias / composite / literal trio with MID
    /// 0x06.
    #[test]
    fn build_declare_token_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (token_id=11, mapping_id=7, no suffix).
        let alias = build_declare_token(11, 7, None);
        let alias_wire = alias.encode_to_vec();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x46,                      // MID(0x06) | M(0x40)
            0x0B,                      // VLE(token_id=11)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "DeclToken alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc").
        let composite = build_declare_token(11, 7, Some("abc"));
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x66, // MID(0x06) | N | M
            0x0B,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "DeclToken composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test").
        let literal = build_declare_token(11, 0, Some("demo/test"));
        let literal_wire = literal.encode_to_vec();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x66, 0x0B, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "DeclToken literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_subscriber_nonlocal`. Mirror of the Local-arm
    /// byte-compare with the M-bit OR convention flipped: the
    /// codegen-derived `_derived_header` at the wireexpr import site
    /// is 0x00 for the Nonlocal arm (decl_subscriber.scxml +
    /// wireexpr.scxml `<sce:arm value="0x00" type="wireexpr_nonlocal"/>`),
    /// so the emitted DeclSubscriber.header carries MID + N only, no
    /// M bit. Three vectors lock the alias / composite / multi-byte
    /// VLE boundary cases (literal id=0 is rejected by the builder so
    /// is exercised in the `_rejects_zero_mapping_id` panic test
    /// below, not here).
    #[test]
    fn build_declare_subscriber_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias to peer's mapping 7 (no suffix).
        //   DeclSubscriber.header = MID(0x02) | M(0x00) = 0x02
        let alias = build_declare_subscriber_nonlocal(5, 7, None);
        assert_eq!(
            alias.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE, // 0x1E outer
                0x02,                      // MID only, no N, no M
                0x05,                      // VLE(subscriber_id=5)
                0x07,                      // wireexpr.id VLE(7)
            ],
            "DeclSubscriber Nonlocal alias-case wire bytes must match \
             zenoh-pico reference (M bit clear)",
        );

        // Case 2 — composite: peer's mapping 7 + tail "abc".
        //   DeclSubscriber.header = MID | N | M(=0) = 0x22
        let composite = build_declare_subscriber_nonlocal(5, 7, Some("abc"));
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x22, // MID | N, no M
            0x05,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.encode_to_vec(),
            composite_expected,
            "DeclSubscriber Nonlocal composite-case wire bytes must \
             match zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE boundary on the peer's mapping id
        // (id=200 crosses the 7-bit VLE boundary; first byte = 0xC8,
        // second byte = 0x01). Pure alias to lock the VLE writer
        // regression surface on the Nonlocal arm.
        let large = build_declare_subscriber_nonlocal(5, 200, None);
        assert_eq!(
            large.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE,
                0x02,
                0x05,
                0xC8, // VLE(200) low 7 + cont bit
                0x01, // VLE(200) high byte
            ],
            "DeclSubscriber Nonlocal multi-byte VLE id wire bytes \
             must match zenoh-pico reference",
        );

        // Inner-arm sanity check — must be Nonlocal, not Local.
        match &alias.body {
            DeclareVariant::CodecZenohDeclSubscriber(d) => match &d.keyexpr.body {
                WireexprVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_subscriber_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclSubscriber"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_subscriber_nonlocal requires a non-zero mapping id")]
    fn build_declare_subscriber_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_subscriber_nonlocal(5, 0, Some("demo/test"));
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_queryable_nonlocal`. Mirror of the Local-arm
    /// byte-compare with MID swap 0x02 → 0x04 and the M-bit OR
    /// convention flipped to 0x00. No-info-ext shape (default-state
    /// `_z_queryable_infos_t`); a future round adding `complete` /
    /// `distance` will introduce a separate
    /// `build_declare_queryable_nonlocal_with_info` byte-compare.
    #[test]
    fn build_declare_queryable_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias.
        let alias = build_declare_queryable_nonlocal(9, 7, None);
        assert_eq!(
            alias.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE,
                0x04, // MID only, no N, no M
                0x09,
                0x07,
            ],
            "DeclQueryable Nonlocal alias-case wire bytes must match \
             zenoh-pico reference",
        );

        // Case 2 — composite.
        let composite = build_declare_queryable_nonlocal(9, 7, Some("abc"));
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x24, // MID | N, no M
            0x09,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.encode_to_vec(),
            composite_expected,
            "DeclQueryable Nonlocal composite-case wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE boundary on the peer's mapping id.
        let large = build_declare_queryable_nonlocal(9, 200, None);
        assert_eq!(
            large.encode_to_vec(),
            vec![wire_const::N_MID_DECLARE, 0x04, 0x09, 0xC8, 0x01,],
            "DeclQueryable Nonlocal multi-byte VLE id wire bytes must \
             match zenoh-pico reference",
        );

        match &alias.body {
            DeclareVariant::CodecZenohDeclQueryable(d) => match &d.keyexpr.body {
                WireexprVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_queryable_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclQueryable"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_queryable_nonlocal requires a non-zero mapping id")]
    fn build_declare_queryable_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_queryable_nonlocal(9, 0, Some("demo/test"));
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_token_nonlocal`. Mirror of the Local-arm byte-
    /// compare with MID swap to 0x06 and the M-bit OR flipped to 0x00.
    /// DeclToken has no extension surface — emit is byte-stable for
    /// every `(id, mapping, suffix)` input in either arm.
    #[test]
    fn build_declare_token_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        let alias = build_declare_token_nonlocal(11, 7, None);
        assert_eq!(
            alias.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE,
                0x06, // MID only, no N, no M
                0x0B, // VLE(token_id=11)
                0x07,
            ],
            "DeclToken Nonlocal alias-case wire bytes must match \
             zenoh-pico reference",
        );

        let composite = build_declare_token_nonlocal(11, 7, Some("abc"));
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x26, // MID | N, no M
            0x0B,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.encode_to_vec(),
            composite_expected,
            "DeclToken Nonlocal composite-case wire bytes must match \
             zenoh-pico reference",
        );

        let large = build_declare_token_nonlocal(11, 200, None);
        assert_eq!(
            large.encode_to_vec(),
            vec![wire_const::N_MID_DECLARE, 0x06, 0x0B, 0xC8, 0x01,],
            "DeclToken Nonlocal multi-byte VLE id wire bytes must match \
             zenoh-pico reference",
        );

        match &alias.body {
            DeclareVariant::CodecZenohDeclToken(d) => match &d.keyexpr.body {
                WireexprVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_token_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclToken"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_token_nonlocal requires a non-zero mapping id")]
    fn build_declare_token_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_token_nonlocal(11, 0, Some("demo/test"));
    }

    /// R121i-c — `build_undeclare_kexpr` produces a `Declare`
    /// envelope carrying an `UndeclKexpr` body. Two vectors lock both
    /// the single-byte VLE id case and the multi-byte VLE boundary
    /// (id >= 128) so a future codegen drift on the VLE writer
    /// surfaces immediately. Reference: zenoh-pico
    /// `_z_undecl_kexpr_encode` at declarations.c:86-89 —
    /// `[header(_Z_UNDECL_KEXPR_MID=0x01), VLE(id)]`, no Z ext, no
    /// wireexpr body.
    #[test]
    fn build_undeclare_kexpr_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE id (id=42 fits in 7 bits).
        let small = build_undeclare_kexpr(42);
        let small_wire = small.encode_to_vec();
        let small_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer
            0x01,                      // _Z_UNDECL_KEXPR_MID
            0x2A,                      // VLE(42) single byte
        ];
        assert_eq!(
            small_wire, small_expected,
            "UndeclKexpr small-id wire bytes must match zenoh-pico reference"
        );

        // Case 2 — multi-byte VLE id (id=200 crosses the 7-bit
        // boundary; first byte = 0xC8 (low 7 bits 0x48 + cont 0x80),
        // second byte = 0x01).
        let large = build_undeclare_kexpr(200);
        let large_wire = large.encode_to_vec();
        let large_expected = vec![
            wire_const::N_MID_DECLARE,
            0x01,
            0xC8, // (200 & 0x7F) | 0x80
            0x01, // 200 >> 7
        ];
        assert_eq!(
            large_wire, large_expected,
            "UndeclKexpr multi-byte VLE id wire bytes must match zenoh-pico reference"
        );

        // Inner-arm sanity check on the small-id case.
        match &small.body {
            DeclareVariant::CodecZenohUndeclKexpr(d) => {
                assert_eq!(d.header, 0x01, "header carries MID only; Z (bit-7) clear");
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_kexpr must produce CodecZenohUndeclKexpr"),
        }
    }

    /// R121i-c — `build_undeclare_subscriber` produces a `Declare`
    /// envelope carrying an `UndeclSubscriber` body in the no-ext
    /// shape (Z bit clear). Reference: zenoh-pico
    /// `_z_undecl_subscriber_encode` -> `_z_undecl_encode(.., has_keyexpr_ext=false)`
    /// at declarations.c:90-103. The wz UndeclSubscriber codec does
    /// not model the optional ext_keyexpr tail; this contract is
    /// locked by the two vectors below.
    #[test]
    fn build_undeclare_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_subscriber(42);
        let small_wire = small.encode_to_vec();
        assert_eq!(
            small_wire,
            vec![
                wire_const::N_MID_DECLARE,
                0x03, // _Z_UNDECL_SUBSCRIBER_MID
                0x2A, // VLE(42)
            ],
            "UndeclSubscriber small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_subscriber(200);
        let large_wire = large.encode_to_vec();
        assert_eq!(
            large_wire,
            vec![wire_const::N_MID_DECLARE, 0x03, 0xC8, 0x01,],
            "UndeclSubscriber multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareVariant::CodecZenohUndeclSubscriber(d) => {
                assert_eq!(d.header, 0x03);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_subscriber must produce CodecZenohUndeclSubscriber"),
        }
    }

    /// R121i-c — `build_undeclare_queryable` produces a `Declare`
    /// envelope carrying an `UndeclQueryable` body in the no-ext
    /// shape. MID = 0x05 (_Z_UNDECL_QUERYABLE_MID); rest matches
    /// `_z_undecl_encode` shape from declarations.c:120-122.
    #[test]
    fn build_undeclare_queryable_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_queryable(42);
        assert_eq!(
            small.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE,
                0x05, // _Z_UNDECL_QUERYABLE_MID
                0x2A,
            ],
            "UndeclQueryable small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_queryable(200);
        assert_eq!(
            large.encode_to_vec(),
            vec![wire_const::N_MID_DECLARE, 0x05, 0xC8, 0x01,],
            "UndeclQueryable multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareVariant::CodecZenohUndeclQueryable(d) => {
                assert_eq!(d.header, 0x05);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_queryable must produce CodecZenohUndeclQueryable"),
        }
    }

    /// R121i-c — `build_undeclare_token` produces a `Declare`
    /// envelope carrying an `UndeclToken` body in the no-ext shape.
    /// MID = 0x07 (_Z_UNDECL_TOKEN_MID); rest matches the
    /// `_z_undecl_encode` shape from declarations.c:128-130.
    #[test]
    fn build_undeclare_token_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_token(42);
        assert_eq!(
            small.encode_to_vec(),
            vec![
                wire_const::N_MID_DECLARE,
                0x07, // _Z_UNDECL_TOKEN_MID
                0x2A,
            ],
            "UndeclToken small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_token(200);
        assert_eq!(
            large.encode_to_vec(),
            vec![wire_const::N_MID_DECLARE, 0x07, 0xC8, 0x01,],
            "UndeclToken multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareVariant::CodecZenohUndeclToken(d) => {
                assert_eq!(d.header, 0x07);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_token must produce CodecZenohUndeclToken"),
        }
    }

    /// R121i-c — `build_declare_final` produces a `Declare` envelope
    /// carrying a single-byte `DeclFinal` marker. Reference: zenoh-
    /// pico `_z_decl_final_encode` at declarations.c:131-135 —
    /// `[header(_Z_DECL_FINAL_MID=0x1A)]`, no body, no id, no ext.
    /// The full wire is exactly 2 bytes (`N_MID_DECLARE` outer +
    /// `DeclFinal.header` inner); the byte-compare locks both.
    #[test]
    fn build_declare_final_emits_two_byte_marker() {
        let declare = build_declare_final();
        let wire = declare.encode_to_vec();
        assert_eq!(
            wire,
            vec![
                wire_const::N_MID_DECLARE, // 0x1E outer
                0x1A,                      // _Z_DECL_FINAL_MID inner
            ],
            "DeclFinal wire must equal [N_MID_DECLARE, _Z_DECL_FINAL_MID]",
        );

        match &declare.body {
            DeclareVariant::CodecZenohDeclFinal(d) => {
                assert_eq!(
                    d.header, 0x1A,
                    "DeclFinal.header must equal _Z_DECL_FINAL_MID"
                );
            }
            _ => panic!("build_declare_final must produce CodecZenohDeclFinal"),
        }
    }

    /// R279 — `build_interest_liveliness_subscriber` produces an
    /// `Interest` envelope with the inner `InterestBody` carrier
    /// emitting `flags = KEYEXPRS | TOKENS | RESTRICTED | FUTURE
    /// [| CURRENT]` per zenoh-pico's
    /// `_z_register_liveliness_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:169-198` via
    /// `vendor/zenoh-pico/src/session/interest.c:204-209`). Four
    /// vectors lock the four semantic cases (literal-future,
    /// literal-current, alias, composite) so a future codegen
    /// regression on either the outer C/F gate, the body N/M
    /// derivation, or the wireexpr arm choice fires immediately.
    #[test]
    fn build_interest_liveliness_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — literal keyexpr, history=false (FUTURE only).
        //   outer header = MID(0x19) | F(0x40) = 0x59
        //   VLE(interest_id=7) = 0x07
        //   body header = KE(0x01) | TO(0x08) | R(0x10) | N(0x20) | M(0x40) = 0x79
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(14) = 0x0E
        //   suffix bytes = "liveliness/dev"
        let future_only = build_interest_liveliness_subscriber(
            7,
            /*history=*/ false,
            /*mapping_id=*/ 0,
            Some("liveliness/dev"),
        );
        let future_only_wire = future_only.encode_to_vec();
        let mut future_only_expected = vec![
            0x59u8, // outer: MID | F
            0x07,   // VLE(interest_id=7)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0) literal sentinel
            0x0E,   // suffix_len VLE(14)
        ];
        future_only_expected.extend_from_slice(b"liveliness/dev");
        assert_eq!(
            future_only_wire, future_only_expected,
            "future-only literal Interest wire bytes must match zenoh-pico reference",
        );

        // Case 2 — literal keyexpr, history=true (CURRENT + FUTURE).
        //   outer header = MID | C(0x20) | F(0x40) = 0x79
        //   VLE(3) = 0x03
        //   body header = KE | TO | R | N | M = 0x79
        //   wireexpr.id VLE(0) | suffix_len VLE(1) | "a"
        let current_future = build_interest_liveliness_subscriber(
            3,
            /*history=*/ true,
            /*mapping_id=*/ 0,
            Some("a"),
        );
        let current_future_wire = current_future.encode_to_vec();
        let mut current_future_expected = vec![
            0x79u8, // outer: MID | C | F
            0x03,   // VLE(interest_id=3)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0)
            0x01,   // suffix_len VLE(1)
        ];
        current_future_expected.extend_from_slice(b"a");
        assert_eq!(
            current_future_wire, current_future_expected,
            "current+future literal Interest wire bytes must match zenoh-pico reference",
        );

        // Case 3 — pure alias (no suffix).
        //   outer header = MID | F = 0x59
        //   VLE(5) = 0x05
        //   body header = KE | TO | R | M (no N) = 0x59
        //   wireexpr.id VLE(11) = 0x0B  (no suffix bytes)
        let alias = build_interest_liveliness_subscriber(
            5, /*history=*/ false, /*mapping_id=*/ 11, None,
        );
        let alias_wire = alias.encode_to_vec();
        assert_eq!(
            alias_wire,
            vec![0x59u8, 0x05, 0x59, 0x0B],
            "alias Interest wire bytes must match zenoh-pico reference",
        );

        // Case 4 — composite (alias + tail).
        //   body header = KE | TO | R | N | M = 0x79
        //   wireexpr.id VLE(11) | suffix_len VLE(5) | "/tail"
        let composite = build_interest_liveliness_subscriber(
            5,
            /*history=*/ false,
            /*mapping_id=*/ 11,
            Some("/tail"),
        );
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![0x59u8, 0x05, 0x79, 0x0B, 0x05];
        composite_expected.extend_from_slice(b"/tail");
        assert_eq!(
            composite_wire, composite_expected,
            "composite alias Interest wire bytes must match zenoh-pico reference",
        );

        // Structural assertions on Case 1 — verify the InterestBody
        // is present and carries the expected wireexpr arm.
        match &future_only.body {
            Some(body) => {
                assert_eq!(
                    body.header, 0x79,
                    "InterestBody.header must carry KE | TO | R | N | M",
                );
                match &body.keyexpr {
                    Some(Wireexpr {
                        body: WireexprVariant::WireexprLocal(w),
                    }) => {
                        assert_eq!(w.id, 0, "literal-keyexpr → wireexpr.id=0 sentinel");
                        assert_eq!(
                            w.suffix.as_deref(),
                            Some("liveliness/dev"),
                            "literal suffix must round-trip",
                        );
                    }
                    _ => panic!(
                        "build_interest_liveliness_subscriber must wrap the keyexpr in WireexprLocal",
                    ),
                }
            }
            None => panic!(
                "future-only/current+future Interest must carry an InterestBody (C||F is set)",
            ),
        }
    }

    /// R279 — `build_interest_final` produces an `Interest` envelope
    /// in the C=0 F=0 Z=0 form. Mirror of zenoh-pico's
    /// `_z_make_interest_final` at
    /// `vendor/zenoh-pico/src/protocol/definitions/interest.c:27`. The
    /// wire reduces to `[N_MID_INTEREST, VLE(interest_id)]` — no inner
    /// body (the `_Z_INTEREST_NOT_FINAL_MASK` gate at interest.h:35 is
    /// clear so the body embed is suppressed) and no extensions.
    #[test]
    fn build_interest_final_emits_two_byte_marker() {
        let small = build_interest_final(7);
        let small_wire = small.encode_to_vec();
        assert_eq!(
            small_wire,
            vec![wire_const::N_MID_INTEREST, 0x07],
            "InterestFinal small-id wire bytes must equal [N_MID_INTEREST, VLE(id)]",
        );
        assert!(
            small.body.is_none(),
            "InterestFinal must carry no inner body — C||F is clear",
        );
        assert!(
            small.extensions.is_none(),
            "InterestFinal must carry no extensions — Z stays clear in the wz emit path",
        );

        let large = build_interest_final(200);
        assert_eq!(
            large.encode_to_vec(),
            vec![wire_const::N_MID_INTEREST, 0xC8, 0x01],
            "InterestFinal multi-byte VLE id wire bytes must match zenoh-pico reference",
        );
    }

    /// R121j-1 — `build_request_query` produces a Request envelope
    /// carrying a `Query` inner body in the minimal AP MVP shape (no
    /// consolidation, no params, no exts at either level). Three
    /// vectors lock the alias / composite / literal trio mirroring
    /// the DECLARE builders, but using `_Z_MID_N_REQUEST (0x1C)` for
    /// the outer header and `_Z_MID_Z_QUERY (0x03)` for the inner
    /// Query header.
    #[test]
    fn build_request_query_wraps_query_in_request_envelope() {
        // Case 1 — pure alias.
        let alias = build_request_query(42, 7, None);
        assert_eq!(
            alias.header, 0x1C,
            "Request header carries MID 0x1C only (no N since no suffix); \
             M is codegen-derived from the Local wireexpr arm at encode",
        );
        assert_eq!(alias.rid, 42, "Request.rid must equal the requested rid");
        match &alias.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert!(w.suffix.is_none());
            }
            _ => panic!("Request.keyexpr must use WireexprLocal arm"),
        }
        assert!(
            alias.extensions.is_none(),
            "minimal shape: no Request-level exts"
        );
        match &alias.body {
            RequestVariant::CodecZenohQuery(q) => {
                assert_eq!(
                    q.header, 0x03,
                    "Query.header is MID 0x03 only — no C / P / Z flags in minimal shape"
                );
                assert!(q.consolidation.is_none());
                assert!(q.parameters_len.is_none());
                assert!(q.parameters.is_none());
                assert!(q.extensions.is_none());
            }
            _ => panic!("Request.body must use CodecZenohQuery arm"),
        }

        // Case 2 — composite (id=7 + tail "tail").
        let composite = build_request_query(42, 7, Some("tail"));
        assert_eq!(
            composite.header, 0x3C,
            "Request header carries MID 0x1C | N(0x20) = 0x3C when suffix present",
        );
        match &composite.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!(),
        }

        // Case 3 — literal (id=0 sentinel + suffix carries the keyexpr).
        let literal = build_request_query(42, 0, Some("demo/test"));
        assert_eq!(
            literal.header, 0x3C,
            "literal case still sets N (suffix present)"
        );
        match &literal.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 0, "literal sentinel id=0");
                assert_eq!(w.suffix.as_deref(), Some("demo/test"));
            }
            _ => panic!(),
        }
    }

    /// R121j-1 — Wire-byte regression gate: the bytes emitted by
    /// `build_request_query(...).encode_to_vec()` must equal zenoh-pico's
    /// `_z_request_encode` + `_z_query_encode` output for the
    /// minimal-shape inputs (no consolidation, no params, no exts at
    /// either level). Three vectors lock the alias / composite /
    /// literal trio:
    ///
    /// References:
    ///   - `_z_request_encode` (vendor/zenoh-pico/src/protocol/codec/network.c:114-169)
    ///     — emits `[header | N | M | Z=0]`, `VLE(rid)`, `wireexpr.encode`,
    ///     and switches into `_z_query_encode` for `_Z_REQUEST_QUERY`.
    ///   - `_z_query_encode` (vendor/zenoh-pico/src/protocol/codec/message.c:394-451)
    ///     — emits `[header | C | P | Z]` then optional consolidation /
    ///     params / exts. In the minimal shape only the header byte
    ///     (0x03) is emitted.
    #[test]
    fn build_request_query_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (rid=42, mapping_id=7, no suffix).
        // Wire shape:
        //   Request.header = MID(0x1C) | M(0x40) = 0x5C
        //   VLE(rid=42)     = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   Query.header   = MID(0x03)
        let alias = build_request_query(42, 7, None);
        let alias_wire = alias.encode_to_vec();
        let alias_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x03, // Query: MID _Z_MID_Z_QUERY only
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "Request(Query) alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (rid=42, id=7 + suffix "abc"):
        //   Request.header = MID | N | M = 0x7C
        //   VLE(42) = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   wireexpr.suffix_len VLE(3) = 0x03
        //   wireexpr.suffix bytes = "abc"
        //   Query.header = 0x03
        let composite = build_request_query(42, 7, Some("abc"));
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            0x7C, // MID | N | M
            0x2A, 0x07, 0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        composite_expected.push(0x03); // Query MID
        assert_eq!(
            composite_wire, composite_expected,
            "Request(Query) composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (rid=42, id=0 + suffix "demo/test"):
        //   Request.header = MID | N | M = 0x7C
        //   VLE(42) = 0x2A
        //   wireexpr.id VLE(0) = 0x00
        //   wireexpr.suffix_len VLE(9) = 0x09
        //   wireexpr.suffix bytes = "demo/test"
        //   Query.header = 0x03
        let literal = build_request_query(42, 0, Some("demo/test"));
        let literal_wire = literal.encode_to_vec();
        let mut literal_expected = vec![0x7C, 0x2A, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        literal_expected.push(0x03); // Query MID
        assert_eq!(
            literal_wire, literal_expected,
            "Request(Query) literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121j-1a — Wire-byte regression gate for
    /// `build_request_query_with_consolidation`. The layered helper
    /// flips Q_C(0x20) on the Query header and appends a 1-byte
    /// consolidation value after the header byte. Three vectors lock
    /// the three transmitted modes (NONE / MONOTONIC / LATEST); the
    /// AUTO/DEFAULT case stays the responsibility of plain
    /// [`build_request_query`] (no Q_C, no extra byte).
    #[test]
    fn build_request_query_with_consolidation_emits_zenoh_pico_compatible_wire_bytes() {
        // Baseline shape derived from build_request_query alias case
        // (rid=42, mapping_id=7, no suffix): Request prefix bytes are
        // [0x5C, 0x2A, 0x07] (MID|M, VLE(42), VLE(7)). The Query
        // header changes from 0x03 to 0x23 (Q_C set) and the
        // consolidation byte follows.
        let cases: [(ConsolidationMode, u8); 3] = [
            (ConsolidationMode::None, 0x00),
            (ConsolidationMode::Monotonic, 0x01),
            (ConsolidationMode::Latest, 0x02),
        ];
        for (mode, expected_byte) in cases {
            let request = build_request_query_with_consolidation(42, 7, None, mode);
            let wire = request.encode_to_vec();
            let expected = vec![
                0x5C,          // Request: MID 0x1C | M 0x40
                0x2A,          // VLE(rid=42)
                0x07,          // wireexpr.id VLE(7)
                0x23,          // Query: MID 0x03 | Q_C 0x20
                expected_byte, // consolidation byte
            ];
            assert_eq!(
                wire, expected,
                "Request(Query+consolidation) wire bytes for mode {mode:?} \
                 must match zenoh-pico reference (msg.c:402-413)",
            );
        }

        // Inner-arm sanity: Query.header carries Q_C set + consolidation
        // is Some(wire_byte) — matches the Optional-field shape that
        // the codegen produces from query.scxml's `sce:present-if`.
        let r = build_request_query_with_consolidation(42, 7, None, ConsolidationMode::Monotonic);
        match &r.body {
            RequestVariant::CodecZenohQuery(q) => {
                assert_eq!(
                    q.header, 0x23,
                    "Query.header must carry MID(0x03) | Q_C(0x20)"
                );
                assert_eq!(q.consolidation, Some(0x01));
                assert!(
                    q.parameters_len.is_none() && q.parameters.is_none() && q.extensions.is_none(),
                    "consolidation-only layered helper must not set \
                     params or exts (those are separate helpers)",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    /// R121j-1a — wire byte mapping invariant for `ConsolidationMode`.
    /// The mapping mirrors zenoh-pico's `z_consolidation_mode_t` enum
    /// integer values (constants.h:185-187). A regression here would
    /// silently miswire the consolidation policy at the peer — the
    /// dedicated test guards the mapping independently of the encode
    /// path so a refactor that touches the `wire_byte` method without
    /// touching the encoder gets caught.
    #[test]
    fn consolidation_mode_wire_byte_matches_zenoh_pico_enum_values() {
        assert_eq!(ConsolidationMode::None.wire_byte(), 0u8);
        assert_eq!(ConsolidationMode::Monotonic.wire_byte(), 1u8);
        assert_eq!(ConsolidationMode::Latest.wire_byte(), 2u8);
    }

    /// R121j-1b — Wire-byte regression gate for
    /// `build_request_query_with_parameters`. The layered helper
    /// flips Q_P(0x40) on the Query header and appends VLE(len) +
    /// bytes after the header byte. Three vectors lock the small-
    /// params, multi-byte VLE boundary, and max-size (256) cases.
    /// The Q_C bit (0x20) stays clear because this helper does not
    /// layer consolidation (separate concern).
    #[test]
    fn build_request_query_with_parameters_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small params (alias case, rid=42, mapping_id=7,
        // no suffix; params="k=v"). Wire:
        //   Request: [0x5C, 0x2A, 0x07]      (MID|M, VLE(42), VLE(7))
        //   Query:   [0x43, 0x03, b'k', b'=', b'v']
        //              (MID(0x03) | Q_P(0x40), VLE(len=3), 3 bytes)
        let small = build_request_query_with_parameters(42, 7, None, b"k=v");
        let small_wire = small.encode_to_vec();
        let mut small_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x43, // Query: MID(0x03) | Q_P(0x40)
            0x03, // VLE(params_len=3)
        ];
        small_expected.extend_from_slice(b"k=v");
        assert_eq!(
            small_wire, small_expected,
            "Request(Query+params) small-params wire bytes must match \
             zenoh-pico reference (msg.c:398-401, 426-428)",
        );

        // Case 2 — multi-byte VLE boundary on params_len (params
        // length=128 crosses the 7-bit VLE boundary; first byte =
        // 0x80, second byte = 0x01). Lock the VLE writer regression
        // on the parameters_len field specifically.
        let mid_params: Vec<u8> = (0u8..128).collect();
        let mid = build_request_query_with_parameters(42, 7, None, &mid_params);
        let mid_wire = mid.encode_to_vec();
        let mut mid_expected = vec![
            0x5C, 0x2A, 0x07, 0x43, 0x80, // VLE(128) low 7 + cont bit
            0x01, // VLE(128) high byte
        ];
        mid_expected.extend_from_slice(&mid_params);
        assert_eq!(
            mid_wire, mid_expected,
            "Request(Query+params) multi-byte VLE params_len wire bytes \
             must match zenoh-pico reference",
        );

        // Case 3 — at max-size (256 bytes). VLE(256) = 0x80 0x02.
        let max_params: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
        let max = build_request_query_with_parameters(42, 7, None, &max_params);
        let max_wire = max.encode_to_vec();
        let mut max_expected = vec![0x5C, 0x2A, 0x07, 0x43, 0x80, 0x02];
        max_expected.extend_from_slice(&max_params);
        assert_eq!(
            max_wire, max_expected,
            "Request(Query+params) max-size params wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity check.
        match &small.body {
            RequestVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x43, "Query.header MID | Q_P");
                assert_eq!(q.parameters_len, Some(3));
                assert_eq!(q.parameters.as_deref(), Some(b"k=v".as_slice()));
                assert!(
                    q.consolidation.is_none() && q.extensions.is_none(),
                    "parameters-only helper must not set consolidation or exts",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    #[test]
    #[should_panic(expected = "RequestQueryBuilder::parameters requires a non-empty params slice")]
    fn build_request_query_with_parameters_rejects_empty_slice() {
        let _ = build_request_query_with_parameters(42, 7, None, b"");
    }

    #[test]
    #[should_panic(expected = "exceeds wz Query codec's max-size (256)")]
    fn build_request_query_with_parameters_rejects_over_max_size() {
        let over: Vec<u8> = vec![0u8; REQUEST_QUERY_PARAMETERS_MAX_LEN + 1];
        let _ = build_request_query_with_parameters(42, 7, None, &over);
    }

    /// R121j-1c — Wire-byte regression gate for
    /// `build_request_query_with_attachment`. The layered helper
    /// flips Q_Z(0x80) on the Query header and appends a single
    /// ext_entry with header 0x45 (ENC_ZBUF | ext_id=0x05) and an
    /// ExtZbuf body carrying VLE(len) + bytes. Three vectors lock
    /// the small-attachment, multi-byte VLE boundary (won't hit at
    /// max-size 32, but small-vs-byte-256 differs in single-byte
    /// VLE only here), and at-max (32-byte) cases. The Q_C / Q_P
    /// bits stay clear because this helper is attachment-only.
    #[test]
    fn build_request_query_with_attachment_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small attachment (alias case, rid=42, mapping_id=7,
        // no suffix; attachment = b"hi").
        //   Request: [0x5C, 0x2A, 0x07]      (MID|M, VLE(42), VLE(7))
        //   Query:   [0x83]                  (MID(0x03) | Q_Z(0x80))
        //   ExtEntry header: [0x45]          (ENC_ZBUF(0x40) | id(0x05))
        //   ExtZbuf: [0x02, b'h', b'i']      (VLE(2), bytes)
        let small = build_request_query_with_attachment(42, 7, None, b"hi");
        let small_wire = small.encode_to_vec();
        let mut small_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x83, // Query: MID(0x03) | Q_Z(0x80)
            0x45, // ExtEntry: ENC_ZBUF | id_attachment
            0x02, // ExtZbuf.value_len VLE(2)
        ];
        small_expected.extend_from_slice(b"hi");
        assert_eq!(
            small_wire, small_expected,
            "Request(Query+attachment) small-attachment wire bytes must \
             match zenoh-pico reference (msg.c:446-448)",
        );

        // Case 2 — at-max attachment (32 bytes, all-distinct sequence
        // 0..32). VLE(32) = 0x20 (single byte, fits in 7 bits).
        let max_attach: Vec<u8> = (0u8..32).collect();
        let max = build_request_query_with_attachment(42, 7, None, &max_attach);
        let max_wire = max.encode_to_vec();
        let mut max_expected = vec![
            0x5C, 0x2A, 0x07, 0x83, // Query header with Q_Z
            0x45, // ExtEntry header
            0x20, // VLE(32) single byte
        ];
        max_expected.extend_from_slice(&max_attach);
        assert_eq!(
            max_wire, max_expected,
            "Request(Query+attachment) max-size (32-byte) attachment wire \
             bytes must match zenoh-pico reference",
        );

        // Inner-arm sanity: Query.header carries Q_Z; extensions vec
        // has exactly one entry with the expected ext_id + ZBuf body.
        match &small.body {
            RequestVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x83, "Query.header MID(0x03) | Q_Z(0x80)");
                let exts = q
                    .extensions
                    .as_ref()
                    .expect("Q_Z set → extensions vec must be Some");
                assert_eq!(exts.len(), 1, "single attachment ext only");
                assert_eq!(
                    exts[0].header, 0x45,
                    "ExtEntry.header = ENC_ZBUF(0x40) | id_attachment(0x05)"
                );
                match &exts[0].body {
                    ExtEntryVariant::CodecZenohExtZbuf(zb) => {
                        assert_eq!(zb.value_len, 2);
                        assert_eq!(zb.value.as_slice(), b"hi".as_slice());
                    }
                    _ => panic!("attachment ext body must be CodecZenohExtZbuf"),
                }
                assert!(
                    q.consolidation.is_none() && q.parameters.is_none(),
                    "attachment-only helper must not set consolidation or params",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    #[test]
    #[should_panic(
        expected = "RequestQueryBuilder::query_attachment requires a non-empty attachment slice"
    )]
    fn build_request_query_with_attachment_rejects_empty_slice() {
        let _ = build_request_query_with_attachment(42, 7, None, b"");
    }

    #[test]
    #[should_panic(expected = "exceeds wz ExtZbuf codec's max-size (32)")]
    fn build_request_query_with_attachment_rejects_over_max_size() {
        let over: Vec<u8> = vec![0u8; QUERY_EXT_ZBUF_MAX_LEN + 1];
        let _ = build_request_query_with_attachment(42, 7, None, &over);
    }

    /// R121j-1d — Wire-byte regression gate for
    /// `build_request_query_with_timeout_ms`. The Request-level Z bit
    /// (0x80) on the outer header signals the Request.extensions
    /// chain follows the wireexpr; the ExtEntry header (0x26 =
    /// ENC_ZINT | id_timeout) precedes the Query body. Three vectors
    /// lock single-byte VLE timeout (50ms), multi-byte VLE boundary
    /// (1000ms = 0xE8 0x07), and large VLE (2^32 ms = 5-byte VLE).
    /// The Query body's MID byte (0x03) stays at the tail, after the
    /// Request-level exts — mirrors the zenoh-pico encoder order
    /// (network.c:122-167: header / rid / wireexpr / exts loop /
    /// body switch).
    #[test]
    fn build_request_query_with_timeout_ms_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE timeout (50ms fits in 7 bits).
        // Alias case rid=42, mapping_id=7, no suffix.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   VLE(rid=42) = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   ExtEntry.header = ENC_ZINT(0x20) | id_timeout(0x06) = 0x26
        //   ExtZint.value VLE(50) = 0x32
        //   Query.header = 0x03
        let small = build_request_query_with_timeout_ms(42, 7, None, 50);
        let small_wire = small.encode_to_vec();
        assert_eq!(
            small_wire,
            vec![
                0xDC, // Request: MID | M | N_Z
                0x2A, // VLE(rid=42)
                0x07, // wireexpr.id VLE(7)
                0x26, // ExtEntry: ENC_ZINT | id_timeout
                0x32, // ExtZint VLE(50)
                0x03, // Query.header (minimal)
            ],
            "Request(timeout=50ms,Query) wire bytes must match \
             zenoh-pico reference (network.c:122-167)",
        );

        // Case 2 — multi-byte VLE boundary (1000ms = 0xE8 0x07).
        let mid = build_request_query_with_timeout_ms(42, 7, None, 1000);
        let mid_wire = mid.encode_to_vec();
        assert_eq!(
            mid_wire,
            vec![
                0xDC, 0x2A, 0x07, 0x26, 0xE8, // VLE(1000) low 7 + cont
                0x07, // VLE(1000) high
                0x03,
            ],
            "Request(timeout=1000ms,Query) wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — large VLE (2^32 = 0x1_0000_0000 = 5-byte VLE in
        // base-128: 0x80 0x80 0x80 0x80 0x10).
        let large = build_request_query_with_timeout_ms(42, 7, None, 1u64 << 32);
        let large_wire = large.encode_to_vec();
        assert_eq!(
            large_wire,
            vec![
                0xDC, 0x2A, 0x07, 0x26, 0x80, 0x80, 0x80, 0x80, 0x10, // VLE(2^32)
                0x03,
            ],
            "Request(timeout=2^32 ms,Query) wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity: Request.extensions has 1 entry with ZInt
        // body; Query body is minimal-shape (no Q_C / Q_P / Q_Z).
        match &small.body {
            RequestVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x03, "Query.header minimal (no Q flags)");
                assert!(q.consolidation.is_none());
                assert!(q.parameters.is_none());
                assert!(q.extensions.is_none(), "no Q-level exts");
            }
            _ => panic!("expected CodecZenohQuery"),
        }
        let req_exts = small
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "single Request-level ext");
        assert_eq!(
            req_exts[0].header, 0x26,
            "Request ExtEntry.header = ENC_ZINT(0x20) | id_timeout(0x06)"
        );
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zi) => {
                assert_eq!(zi.value, 50);
            }
            _ => panic!("timeout ext body must be CodecZenohExtZint"),
        }
    }

    #[test]
    #[should_panic(
        expected = "RequestQueryBuilder::request_timeout_ms requires a non-zero timeout"
    )]
    fn build_request_query_with_timeout_ms_rejects_zero() {
        let _ = build_request_query_with_timeout_ms(42, 7, None, 0);
    }

    /// R121j-1e — Wire-byte regression gate for
    /// `build_request_query_with_target`. The target ext sets M=1
    /// (mandatory marker) on the ExtEntry.header, distinct from
    /// timeout / qos / budget which leave M clear. Two vectors lock
    /// the two transmitted target values (All=1 / AllComplete=2);
    /// BEST_MATCHING (0) is not representable in [`QueryTarget`] —
    /// the encoder predicate clears the ext on default, so absence
    /// of this helper's wire bytes is the BEST_MATCHING signal.
    #[test]
    fn build_request_query_with_target_emits_zenoh_pico_compatible_wire_bytes() {
        // Alias case rid=42, mapping_id=7, no suffix. For both target
        // values the wire shape differs only in the ExtZint body
        // (1 byte) since target ∈ {1, 2} both fit in single-byte VLE.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   ExtEntry.header = ENC_ZINT(0x20) | M(0x10) | id_target(0x04) = 0x34
        let cases: [(QueryTarget, u8); 2] =
            [(QueryTarget::All, 0x01), (QueryTarget::AllComplete, 0x02)];
        for (target, target_byte) in cases {
            let request = build_request_query_with_target(42, 7, None, target);
            let wire = request.encode_to_vec();
            assert_eq!(
                wire,
                vec![
                    0xDC,        // Request: MID | M | N_Z
                    0x2A,        // VLE(rid=42)
                    0x07,        // wireexpr.id VLE(7)
                    0x34,        // ExtEntry: ENC_ZINT | M | id_target
                    target_byte, // VLE(target_enum_value)
                    0x03,        // Query.header (minimal)
                ],
                "Request(target={target:?},Query) wire bytes must match \
                 zenoh-pico reference (network.c:138-143)",
            );
        }

        // Inner-arm sanity check on the All case.
        let r = build_request_query_with_target(42, 7, None, QueryTarget::All);
        let req_exts = r
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1);
        assert_eq!(
            req_exts[0].header, 0x34,
            "Request ExtEntry.header = ENC_ZINT(0x20) | M(0x10) | id_target(0x04)"
        );
        assert!(
            (req_exts[0].header & 0x10) != 0,
            "target ext MUST set the mandatory marker bit (M=1, 0x10) — peers \
             without target awareness reject the frame on unknown M-bit exts"
        );
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zi) => {
                assert_eq!(zi.value, 1);
            }
            _ => panic!("target ext body must be CodecZenohExtZint"),
        }
    }

    /// R121j-1e — wire byte mapping invariant for `QueryTarget`. The
    /// mapping mirrors zenoh-pico's `z_query_target_t` enum integer
    /// values (constants.h:263-264). BEST_MATCHING (0) is absent by
    /// design (the encoder predicate clears the ext on default).
    #[test]
    fn query_target_wire_byte_matches_zenoh_pico_enum_values() {
        assert_eq!(QueryTarget::All.wire_byte(), 1u8);
        assert_eq!(QueryTarget::AllComplete.wire_byte(), 2u8);
    }

    /// R121j-2a — Composition smoke test: two Query-layer settings
    /// (consolidation + parameters) applied via the builder produce
    /// wire bytes consistent with both layers. The two-layer shape
    /// is what the old one-shot helpers CANNOT produce because each
    /// resets the Query body's optional fields.
    #[test]
    fn request_query_builder_composes_consolidation_and_parameters() {
        // rid=42, mapping_id=7, no suffix.
        // Layers: consolidation=Monotonic, params=b"k=v".
        //   Request.header = MID(0x1C) | M(0x40) = 0x5C  (no N, no N_Z)
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07
        //   Query.header = MID(0x03) | Q_C(0x20) | Q_P(0x40) = 0x63
        //   consolidation byte = 0x01 (Monotonic)
        //   parameters_len VLE = 0x03
        //   "k=v" 3 bytes
        let request = RequestQueryBuilder::new(42, 7, None)
            .consolidation(ConsolidationMode::Monotonic)
            .parameters(b"k=v")
            .build();
        let wire = request.encode_to_vec();
        let mut expected = vec![
            0x5C, // Request: MID | M
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x63, // Query: MID | Q_C | Q_P
            0x01, // consolidation = Monotonic
            0x03, // parameters_len VLE(3)
        ];
        expected.extend_from_slice(b"k=v");
        assert_eq!(
            wire, expected,
            "Composed (consolidation + parameters) wire must carry both \
             layers — the regression that pre-R121j-2a one-shot \
             helpers couldn't express",
        );
    }

    /// R121j-2a — Composition full-stack: all 5 currently-exposed
    /// builder layers applied together. Verifies (1) Request-level
    /// ext ordering (target first, then timeout per zenoh-pico
    /// network.c:122-167), (2) Z chain-continuation bit on the
    /// intermediate target ext, (3) all three Query-layer flag bits
    /// (Q_C / Q_P / Q_Z) set together, (4) the attachment ext sits at
    /// the Query level (after Query.consolidation + parameters), not
    /// at the Request level.
    #[test]
    fn request_query_builder_composes_all_five_layers() {
        // rid=42, mapping_id=7, no suffix.
        // Layers: consolidation=Latest, params=b"k=v", q_attachment=b"at",
        //         req_target=All, req_timeout_ms=1000.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07
        //   Request ext 1: target (ENC_ZINT|M|id_target=0x34) | Z(0x80) = 0xB4
        //   ExtZint VLE(All=1) = 0x01
        //   Request ext 2: timeout (ENC_ZINT|id_timeout=0x26), no Z = 0x26
        //   ExtZint VLE(1000) = 0xE8 0x07
        //   Query.header = MID(0x03) | Q_C(0x20) | Q_P(0x40) | Q_Z(0x80) = 0xE3
        //   consolidation = Latest = 0x02
        //   parameters_len VLE(3) = 0x03
        //   "k=v"
        //   Q-attachment ext: header (ENC_ZBUF|id_attachment=0x45), no Z = 0x45
        //   ExtZbuf VLE(2) = 0x02
        //   "at"
        let request = RequestQueryBuilder::new(42, 7, None)
            .consolidation(ConsolidationMode::Latest)
            .parameters(b"k=v")
            .query_attachment(b"at")
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let wire = request.encode_to_vec();
        let mut expected = vec![
            0xDC, // Request: MID | M | N_Z
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            // Request-level ext chain: target(Z=1) → timeout(last)
            0xB4, // ENC_ZINT | M | id_target | Z(chain)
            0x01, // VLE(target=All=1)
            0x26, // ENC_ZINT | id_timeout, Z=0 (last)
            0xE8, 0x07, // VLE(timeout_ms=1000)
            // Query body
            0xE3, // Query: MID | Q_C | Q_P | Q_Z
            0x02, // consolidation = Latest
            0x03, // parameters_len VLE(3)
        ];
        expected.extend_from_slice(b"k=v");
        expected.extend_from_slice(&[
            0x45, // Q-attachment ext: ENC_ZBUF | id_attachment, Z=0
            0x02, // VLE(attachment_len=2)
        ]);
        expected.extend_from_slice(b"at");
        assert_eq!(
            wire, expected,
            "Five-layer composed wire must carry all settings — \
             verifies Request-level ext ordering + Z chain bit on \
             intermediate entry + all three Q-flag bits + Q-attachment \
             positioning",
        );

        // Inner-arm sanity.
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 2, "target + timeout exts");
        assert_eq!(
            req_exts[0].header & 0x80,
            0x80,
            "target ext must carry Z chain-continuation bit (more follows)",
        );
        assert_eq!(
            req_exts[1].header & 0x80,
            0x00,
            "timeout ext must NOT carry Z (it is the last entry)",
        );
    }

    /// R121j-1f — RequestQueryBuilder.request_qos emits a single
    /// Request-level ext at the head of the chain (qos → tstamp →
    /// target → budget → timeout) with header ENC_ZINT(0x20) |
    /// id_qos(0x01) and no M flag (qos is informational).
    #[test]
    fn request_query_builder_request_qos_emits_first_ext_with_no_m_flag() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05) // priority=5, no nodrop, no express
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "only qos ext was set");
        assert_eq!(
            req_exts[0].header,
            0x20 | 0x01,
            "qos ext header = ENC_ZINT(0x20) | id_qos(0x01); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x05,
                    "qos packed byte 0x05 lifts into ZINT VLE value verbatim"
                );
            }
            _ => panic!("qos ext body must be CodecZenohExtZint"),
        }
        assert_eq!(
            request.header & 0x80,
            0x80,
            "qos setter must flip N_Z(0x80) on Request.header (exts present)",
        );
    }

    /// R121j-1f — request_qos composes with request_target +
    /// request_timeout_ms in the correct zenoh-pico encode order:
    /// qos comes first (with Z-chain continuation), target next
    /// (with Z-chain continuation), timeout last (no Z).
    #[test]
    fn request_query_builder_request_qos_target_timeout_chain_order_matches_zenoh_pico() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("3 Request-level exts set → extensions must be Some");
        assert_eq!(req_exts.len(), 3, "qos + target + timeout");
        // qos first: ENC_ZINT | id_qos(1), Z continuation set
        assert_eq!(
            req_exts[0].header,
            0x80 | 0x20 | 0x01,
            "qos ext at index 0 must carry Z continuation (more follows)"
        );
        // target second: ENC_ZINT | M | id_target(4), Z continuation set
        assert_eq!(
            req_exts[1].header,
            0x80 | 0x20 | 0x10 | 0x04,
            "target ext at index 1 must carry M(0x10) + Z continuation"
        );
        // timeout last: ENC_ZINT | id_timeout(6), no Z
        assert_eq!(
            req_exts[2].header,
            0x20 | 0x06,
            "timeout ext at index 2 (last) must NOT carry Z"
        );
    }

    /// R121j-1g — RequestQueryBuilder.request_budget emits a single
    /// Request-level ext between target and timeout (per zenoh-pico
    /// _z_request_encode order) with header ENC_ZINT(0x20) |
    /// id_budget(0x05) and no M flag.
    #[test]
    fn request_query_builder_request_budget_emits_ext_between_target_and_timeout() {
        // Solo case: only budget set. Ext at index 0 (chain head), no
        // Z (it is the only ext, hence the last).
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_budget(0x1234_5678)
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("budget setter must populate exts");
        assert_eq!(req_exts.len(), 1, "only budget ext was set");
        assert_eq!(
            req_exts[0].header,
            0x20 | 0x05,
            "budget ext header = ENC_ZINT(0x20) | id_budget(0x05); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x1234_5678,
                    "budget u32 widens into u64 ZINT value verbatim"
                );
            }
            _ => panic!("budget ext body must be CodecZenohExtZint"),
        }

        // Chain-order case: qos + target + budget + timeout. Position
        // must be qos[0]->target[1]->budget[2]->timeout[3] per
        // zenoh-pico _z_request_encode at network.c:126-155. Z
        // continuation set on indices 0/1/2, clear on index 3.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_target(QueryTarget::All)
            .request_budget(100)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request.extensions.as_ref().expect("4 exts set");
        assert_eq!(req_exts.len(), 4, "qos + target + budget + timeout");
        assert_eq!(req_exts[0].header & 0x07, 0x01, "index 0: qos id");
        assert_eq!(req_exts[1].header & 0x07, 0x04, "index 1: target id");
        assert_eq!(
            req_exts[2].header & 0x07,
            0x05,
            "index 2: budget id (between target and timeout)"
        );
        assert_eq!(
            req_exts[3].header & 0x07,
            0x06,
            "index 3: timeout id (last)"
        );
        assert_eq!(
            req_exts[3].header & 0x80,
            0x00,
            "timeout last → Z must be clear"
        );
        assert_eq!(
            req_exts[2].header & 0x80,
            0x80,
            "budget at index 2 → Z must be set (timeout follows)"
        );
    }

    /// R121j-1g — request_budget rejects zero (mirrors zenoh-pico's
    /// ext_budget = budget != 0 encoder predicate at
    /// vendor/zenoh-pico/src/protocol/definitions/network.c:26).
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_budget requires a non-zero budget")]
    fn request_query_builder_budget_rejects_zero() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_budget(0)
            .build();
    }

    /// R121j-tstamp — request_tstamp emits one Request-level ext at
    /// the position between qos and target (qos → tstamp → target →
    /// budget → timeout) with header ENC_ZBUF(0x40) | id_tstamp(0x02)
    /// and NO M flag. The ext body is an ExtZbuf carrying the
    /// `Timestamp::encode_to_vec()` output verbatim.
    #[test]
    fn request_query_builder_request_tstamp_solo_emits_ext_with_no_m_flag() {
        // Solo case: only tstamp set. time=42, zid=[0xab, 0xcd] keeps
        // both VLE fields single-byte so the body bytes are auditable
        // without an online VLE encoder: [VLE(42), VLE(2), 0xab, 0xcd]
        // = [0x2a, 0x02, 0xab, 0xcd], len=4.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(42, &[0xab, 0xcd])
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "only tstamp ext was set");
        assert_eq!(
            req_exts[0].header,
            0x40 | 0x02,
            "tstamp ext header = ENC_ZBUF(0x40) | id_tstamp(0x02); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZbuf(zbuf) => {
                assert_eq!(
                    zbuf.value_len, 4,
                    "Timestamp encode = VLE(42)+VLE(2)+zid[2] = 4 bytes"
                );
                assert_eq!(
                    zbuf.value,
                    vec![0x2a, 0x02, 0xab, 0xcd],
                    "Timestamp body: VLE(time=42)=0x2a, VLE(zid_len=2)=0x02, zid=[0xab,0xcd]",
                );
            }
            _ => panic!("tstamp ext body must be CodecZenohExtZbuf"),
        }
        assert_eq!(
            request.header & 0x80,
            0x80,
            "tstamp setter must flip N_Z(0x80) on Request.header (exts present)",
        );
    }

    /// R121j-tstamp — chain position vs zenoh-pico encode order:
    /// qos[0] → tstamp[1] → target[2] → budget[3] → timeout[4], with
    /// Z chain-continuation on indices 0..=3 and Z clear on index 4.
    /// The five-ext sequence pins the entire Request-level ext chain
    /// against `_z_request_encode` at network.c:126-155.
    #[test]
    fn request_query_builder_full_chain_emits_zenoh_pico_encode_order() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_tstamp(7, &[0x01])
            .request_target(QueryTarget::All)
            .request_budget(100)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request.extensions.as_ref().expect("5 exts set");
        assert_eq!(
            req_exts.len(),
            5,
            "qos + tstamp + target + budget + timeout"
        );
        assert_eq!(req_exts[0].header & 0x07, 0x01, "index 0: qos id");
        assert_eq!(req_exts[1].header & 0x07, 0x02, "index 1: tstamp id");
        assert_eq!(req_exts[2].header & 0x07, 0x04, "index 2: target id");
        assert_eq!(req_exts[3].header & 0x07, 0x05, "index 3: budget id");
        assert_eq!(req_exts[4].header & 0x07, 0x06, "index 4: timeout id");
        // Encoding kind bits (bits 5-6: 0x20 = ZINT, 0x40 = ZBUF).
        assert_eq!(req_exts[0].header & 0x60, 0x20, "qos uses ENC_ZINT");
        assert_eq!(req_exts[1].header & 0x60, 0x40, "tstamp uses ENC_ZBUF");
        assert_eq!(req_exts[2].header & 0x60, 0x20, "target uses ENC_ZINT");
        assert_eq!(req_exts[3].header & 0x60, 0x20, "budget uses ENC_ZINT");
        assert_eq!(req_exts[4].header & 0x60, 0x20, "timeout uses ENC_ZINT");
        // M flag (bit 4): set on target only (M=1 per zenoh-pico),
        // clear on qos / tstamp / budget / timeout.
        assert_eq!(req_exts[0].header & 0x10, 0x00, "qos: M clear");
        assert_eq!(
            req_exts[1].header & 0x10,
            0x00,
            "tstamp: M clear (non-mandatory per zenoh-pico)"
        );
        assert_eq!(req_exts[2].header & 0x10, 0x10, "target: M set");
        assert_eq!(req_exts[3].header & 0x10, 0x00, "budget: M clear");
        assert_eq!(req_exts[4].header & 0x10, 0x00, "timeout: M clear");
        // Z chain-continuation: set on 0..=3, clear on 4.
        assert_eq!(req_exts[0].header & 0x80, 0x80, "qos: Z set (more follows)");
        assert_eq!(req_exts[1].header & 0x80, 0x80, "tstamp: Z set");
        assert_eq!(req_exts[2].header & 0x80, 0x80, "target: Z set");
        assert_eq!(req_exts[3].header & 0x80, 0x80, "budget: Z set");
        assert_eq!(req_exts[4].header & 0x80, 0x00, "timeout: Z clear (last)");
    }

    /// R121j-tstamp — request_tstamp rejects an empty zid (mirrors
    /// zenoh-pico's `_z_id_encode_as_slice` at message.c:58-70 which
    /// returns `_Z_ERR_MESSAGE_ZENOH_UNKNOWN` on len=0).
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_tstamp requires a non-empty zid")]
    fn request_query_builder_tstamp_rejects_empty_zid() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(0, &[])
            .build();
    }

    /// R121j-tstamp — request_tstamp rejects zid longer than the
    /// zenoh `_z_id_t` 16-byte capacity (`_Z_ID_LENGTH = 16` at
    /// vendor/zenoh-pico/include/zenoh-pico/protocol/core.h).
    #[test]
    #[should_panic(expected = "exceeds zenoh _Z_ID_LENGTH (16)")]
    fn request_query_builder_tstamp_rejects_zid_over_16_bytes() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(0, &[0u8; 17])
            .build();
    }

    /// R121j-1h — request_qos_typed packs `(Priority, CongestionControl,
    /// express)` into the wire byte exactly as zenoh-pico's
    /// `_z_n_qos_create` at network.h:84-89 produces:
    /// `(express << 4) | (nodrop << 3) | priority`. Verifies the byte
    /// then delegates to the same storage as request_qos so the chain
    /// emit path stays uniform — same Z chain-continuation / index
    /// semantics as the raw setter.
    #[test]
    fn request_qos_typed_packs_per_zenoh_pico_z_n_qos_create_layout() {
        // Drop + Background priority + no express: priority=7 → low 3
        // bits = 0b111; congestion Drop → nodrop=0; express=false →
        // bit4=0. Expected packed byte = 0x07.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::Background, CongestionControl::Drop, false)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zint) => {
                assert_eq!(zint.value, 0x07, "Background(7) + Drop + !express = 0x07");
            }
            _ => panic!("qos body must be ExtZint"),
        }

        // Block + RealTime + express: priority=1 (bits 0-2 = 0b001),
        // nodrop=1 (bit 3 = 0b1000), express=1 (bit 4 = 0b10000).
        // Expected packed byte = 0x10 | 0x08 | 0x01 = 0x19.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::RealTime, CongestionControl::Block, true)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x19,
                    "RealTime(1) + Block + express = 0x10|0x08|0x01"
                );
            }
            _ => panic!("qos body must be ExtZint"),
        }

        // Default (Data priority, Drop, !express): priority=5
        // (0b101), nodrop=0, express=0 → 0x05. Sanity check that the
        // default-aligned values produce a clean low-bits byte.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::Data, CongestionControl::Drop, false)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryVariant::CodecZenohExtZint(zint) => {
                assert_eq!(zint.value, 0x05, "Data(5) + Drop + !express = 0x05");
            }
            _ => panic!("qos body must be ExtZint"),
        }
    }

    /// R121j-1h — Priority::wire_byte and CongestionControl::wire_bit
    /// match the zenoh-pico enum literal values verbatim. Decouples
    /// the typed-wrapper test from RequestQueryBuilder so a future
    /// re-use of Priority / CongestionControl (e.g. in a Push-side
    /// QoS setter) inherits the same invariant.
    #[test]
    fn priority_and_congestion_wire_values_match_zenoh_pico_constants() {
        assert_eq!(Priority::Control.wire_byte(), 0);
        assert_eq!(Priority::RealTime.wire_byte(), 1);
        assert_eq!(Priority::InteractiveHigh.wire_byte(), 2);
        assert_eq!(Priority::InteractiveLow.wire_byte(), 3);
        assert_eq!(Priority::DataHigh.wire_byte(), 4);
        assert_eq!(Priority::Data.wire_byte(), 5);
        assert_eq!(Priority::DataLow.wire_byte(), 6);
        assert_eq!(Priority::Background.wire_byte(), 7);

        assert_eq!(CongestionControl::Drop.wire_bit(), 0);
        assert_eq!(CongestionControl::Block.wire_bit(), 1);
    }

    /// R121j-1h — request_qos_typed composes with request_target +
    /// request_timeout_ms identically to the raw request_qos setter
    /// (Z chain-continuation bits, ext order). Pins that the typed
    /// wrapper is purely a packing convenience over the raw setter.
    #[test]
    fn request_qos_typed_composes_with_chain_identically_to_raw_qos() {
        let typed = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::RealTime, CongestionControl::Block, true)
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let raw = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x19) // same packed byte as the typed call
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        assert_eq!(
            typed.encode_to_vec(),
            raw.encode_to_vec(),
            "typed and raw qos setters must produce byte-identical wire emit",
        );
    }

    /// R121j-2a — Per-setter validation flows through to the builder.
    /// Mirrors the one-shot helper rejection tests; the builder is
    /// where the panic actually fires now.
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::parameters")]
    fn request_query_builder_parameters_rejects_empty() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .parameters(b"")
            .build();
    }

    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_timeout_ms")]
    fn request_query_builder_timeout_rejects_zero() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_timeout_ms(0)
            .build();
    }

    /// R121j-1 — `encode_frame_with_request` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.encode_to_vec()` wrapping as
    /// the existing `encode_frame_with_push` / `encode_frame_with_declare`
    /// helpers, with `Request.encode_to_vec()` as the inner payload bytes.
    /// Reliable / best-effort header-flag behaviour mirrors the other
    /// two helpers so the SN-window ordering contract stays uniform
    /// across PUSH / DECLARE / REQUEST outbound paths.
    /// R121j-2 — Wire-byte regression gate: `build_response_final`
    /// emits the zenoh-pico `_z_response_final_encode` shape
    /// (network.c:368-376). Two vectors lock both the single-byte
    /// VLE rid and the multi-byte VLE boundary (rid=200) — the same
    /// boundary R121i-c uses to protect against codegen drift on
    /// the VLE writer's continuation-bit logic.
    #[cfg(feature = "codec-response-final")]
    #[test]
    fn build_response_final_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE rid (rid=42).
        let small = build_response_final(42);
        let small_wire = small.encode_to_vec();
        assert_eq!(
            small_wire,
            vec![
                0x1A, // _Z_MID_N_RESPONSE_FINAL (no Z flag)
                0x2A, // VLE(rid=42)
            ],
            "ResponseFinal small-rid wire bytes must match zenoh-pico reference",
        );

        // Case 2 — multi-byte VLE rid (rid=200, encodes as 0xC8 0x01).
        let large = build_response_final(200);
        let large_wire = large.encode_to_vec();
        assert_eq!(
            large_wire,
            vec![
                0x1A, 0xC8, // (200 & 0x7F) | 0x80
                0x01, // 200 >> 7
            ],
            "ResponseFinal multi-byte VLE rid wire bytes must match zenoh-pico reference",
        );

        assert_eq!(
            small.header, 0x1A,
            "header carries MID only; Z (bit-7) clear in minimal shape"
        );
        assert_eq!(small.request_id, 42);
        assert!(
            small.extensions.is_none(),
            "minimal shape: no RF-level extensions"
        );
    }

    /// R121j-2 — `encode_frame_with_response_final` produces the
    /// same Frame envelope wrap as the other `encode_frame_with_*`
    /// helpers, with `ResponseFinal.encode_to_vec()` as the payload bytes.
    /// Reliable / best-effort header-flag behaviour mirrors the
    /// other three helpers; the production action layer hard-codes
    /// reliable=true but the helper accepts the flag for fuzz /
    /// negative-test paths.
    #[cfg(feature = "codec-response-final")]
    #[test]
    fn encode_frame_with_response_final_wraps_in_frame_envelope() {
        let rf = build_response_final(42);
        let rf_bytes = rf.encode_to_vec();

        let wire_reliable = encode_frame_with_response_final(0, build_response_final(42), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            rf_bytes.as_slice(),
            "Frame body tail must be ResponseFinal.encode_to_vec() bytes verbatim",
        );

        let wire_best_effort = encode_frame_with_response_final(0, build_response_final(42), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    /// R121j-3 — Wire-byte regression gate for
    /// `build_response_reply_literal`. The minimal Response(Reply(MsgPut))
    /// chain wire shape after the inner `_z_msg_put_encode` arm — no
    /// Response-level exts, no Reply-level consolidation/exts, no
    /// MsgPut timestamp/encoding/exts. Two vectors lock the alias
    /// rid + small payload and the multi-byte VLE boundary (rid=200).
    #[test]
    fn build_response_reply_literal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small request_id (42), literal keyexpr "demo/test",
        // payload "hello-reply".
        //   Response.header = MID(0x1B) | N(0x20) | M(0x40 codegen) = 0x7B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=0 → 0x00, suffix_len(9) → 0x09, "demo/test"
        //   Reply.header = 0x04
        //   MsgPut.header = 0x01
        //   MsgPut.payload_len(11) → 0x0B
        //   payload "hello-reply"
        let small = build_response_reply_literal(42, "demo/test", b"hello-reply");
        let small_wire = small.encode_to_vec();
        let mut small_expected = vec![
            0x7B, // Response: MID | N | M
            0x2A, // VLE(rid=42)
            0x00, // wireexpr.id VLE(0) literal sentinel
            0x09, // wireexpr.suffix_len VLE(9)
        ];
        small_expected.extend_from_slice(b"demo/test");
        small_expected.push(0x04); // Reply.header MID only
        small_expected.push(0x01); // MsgPut.header MID only
        small_expected.push(0x0B); // payload_len VLE(11)
        small_expected.extend_from_slice(b"hello-reply");
        assert_eq!(
            small_wire, small_expected,
            "Response(Reply(MsgPut)) literal wire bytes must match \
             zenoh-pico reference chain (network.c:241-304 + \
             message.c:507-543 + message.c:259-310)",
        );

        // Case 2 — multi-byte VLE boundary on rid (200 = 0xC8 0x01).
        let large = build_response_reply_literal(200, "k", b"v");
        let large_wire = large.encode_to_vec();
        let large_expected = vec![
            0x7B, 0xC8, // VLE(200) low + cont
            0x01, // VLE(200) high
            0x00, // wireexpr id=0 literal
            0x01, // suffix_len(1)
            b'k', 0x04, // Reply.header
            0x01, // MsgPut.header
            0x01, // payload_len(1)
            b'v',
        ];
        assert_eq!(
            large_wire, large_expected,
            "Response(Reply) multi-byte VLE rid wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity.
        match &small.body {
            ResponseVariant::CodecZenohReply(reply) => {
                assert_eq!(reply.header, 0x04, "Reply.header MID only");
                assert!(reply.consolidation.is_none());
                assert!(reply.extensions.is_none());
                match &reply.body {
                    ReplyVariant::CodecZenohMsgPut(put) => {
                        assert_eq!(put.header, 0x01);
                        assert_eq!(put.payload_len, 11);
                        assert_eq!(put.payload.as_slice(), b"hello-reply");
                    }
                    _ => panic!("Reply.body must be CodecZenohMsgPut"),
                }
            }
            _ => panic!("Response.body must be CodecZenohReply"),
        }
    }

    #[test]
    #[should_panic(expected = "build_response_reply_literal requires a non-empty keyexpr suffix")]
    fn build_response_reply_literal_rejects_empty_suffix() {
        let _ = build_response_reply_literal(42, "", b"v");
    }

    /// R121j-3 — Wire-byte regression gate for
    /// `build_response_reply_aliased`. Three vectors lock the
    /// aliased / composite / aliased-large-VLE shapes.
    #[test]
    fn build_response_reply_aliased_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (rid=42, mapping_id=7, no suffix,
        // payload "v"). Wire:
        //   Response.header = MID(0x1B) | M(0x40, no N) = 0x5B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07 (no suffix; N flag clear)
        //   Reply.header = 0x04
        //   MsgPut.header = 0x01
        //   payload_len(1) → 0x01
        //   payload "v"
        let alias = build_response_reply_aliased(42, 7, None, b"v");
        let alias_wire = alias.encode_to_vec();
        assert_eq!(
            alias_wire,
            vec![
                0x5B, // Response: MID | M (no N)
                0x2A, 0x07, // wireexpr.id VLE(7)
                0x04, // Reply.header
                0x01, // MsgPut.header
                0x01, // payload_len(1)
                b'v',
            ],
            "Response(Reply) aliased no-suffix wire bytes must match \
             zenoh-pico reference",
        );

        // Case 2 — composite (rid=42, mapping_id=7, suffix "tail",
        // payload "data"). Wire:
        //   Response.header = MID | N | M = 0x7B
        //   wireexpr Local: id=7 + suffix_len(4) + "tail"
        let composite = build_response_reply_aliased(42, 7, Some("tail"), b"data");
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            0x7B, 0x2A, 0x07, // wireexpr.id
            0x04, // suffix_len(4)
        ];
        composite_expected.extend_from_slice(b"tail");
        composite_expected.push(0x04); // Reply.header
        composite_expected.push(0x01); // MsgPut.header
        composite_expected.push(0x04); // payload_len(4)
        composite_expected.extend_from_slice(b"data");
        assert_eq!(
            composite_wire, composite_expected,
            "Response(Reply) composite alias wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE alias (mapping_id=200).
        let large = build_response_reply_aliased(42, 200, None, b"x");
        let large_wire = large.encode_to_vec();
        assert_eq!(
            large_wire,
            vec![
                0x5B, 0x2A, 0xC8, 0x01, // wireexpr.id VLE(200)
                0x04, 0x01, 0x01, b'x',
            ],
            "Response(Reply) multi-byte VLE alias wire bytes must match \
             zenoh-pico reference",
        );
    }

    #[test]
    #[should_panic(expected = "build_response_reply_aliased requires a non-zero mapping id")]
    fn build_response_reply_aliased_rejects_zero_mapping_id() {
        let _ = build_response_reply_aliased(42, 0, Some("any"), b"v");
    }

    /// R121j-4 — Wire-byte regression gate for
    /// `build_response_err_literal`. Mirror of the Reply byte-compare
    /// with the inner body MID swap (0x04 → 0x05) and structural diff
    /// (Err has no payload prefix beyond payload_len; Reply wraps a
    /// MsgPut which itself has a MID byte before payload_len).
    /// Two vectors lock the small rid + literal keyexpr and the
    /// multi-byte VLE boundary.
    #[test]
    fn build_response_err_literal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — rid=42, literal "k", payload "fail".
        //   Response.header = MID(0x1B) | N(0x20) | M(0x40) = 0x7B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=0, suffix_len(1), "k"
        //   Err.header = 0x05
        //   payload_len(4) = 0x04
        //   "fail"
        let small = build_response_err_literal(42, "k", b"fail");
        let small_wire = small.encode_to_vec();
        let mut small_expected = vec![
            0x7B, 0x2A, 0x00, // wireexpr id=0
            0x01, // suffix_len(1)
            b'k', 0x05, // Err.header (no MsgPut layer above this!)
            0x04, // payload_len(4)
        ];
        small_expected.extend_from_slice(b"fail");
        assert_eq!(
            small_wire, small_expected,
            "Response(Err) literal wire bytes must match zenoh-pico \
             reference (network.c:241-304 + message.c:545+)",
        );

        // Case 2 — multi-byte VLE rid (200).
        let large = build_response_err_literal(200, "x", b"e");
        let large_wire = large.encode_to_vec();
        assert_eq!(
            large_wire,
            vec![
                0x7B, 0xC8, 0x01, // VLE(rid=200)
                0x00, // wireexpr id=0 literal
                0x01, // suffix_len(1)
                b'x', 0x05, // Err.header
                0x01, // payload_len(1)
                b'e',
            ],
            "Response(Err) multi-byte VLE rid wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity.
        match &small.body {
            ResponseVariant::CodecZenohErr(err) => {
                assert_eq!(err.header, 0x05, "Err.header MID only");
                assert!(err.encoding.is_none());
                assert!(err.extensions.is_none());
                assert_eq!(err.payload_len, 4);
                assert_eq!(err.payload.as_slice(), b"fail");
            }
            _ => panic!("Response.body must be CodecZenohErr"),
        }
    }

    #[test]
    #[should_panic(expected = "build_response_err_literal requires a non-empty keyexpr suffix")]
    fn build_response_err_literal_rejects_empty_suffix() {
        let _ = build_response_err_literal(42, "", b"v");
    }

    /// R121j-4 — Wire-byte regression gate for
    /// `build_response_err_aliased`. Mirror of the Reply aliased
    /// byte-compare with inner body MID swap.
    #[test]
    fn build_response_err_aliased_emits_zenoh_pico_compatible_wire_bytes() {
        // Pure alias: rid=42, mapping_id=7, no suffix, payload "e".
        let alias = build_response_err_aliased(42, 7, None, b"e");
        let alias_wire = alias.encode_to_vec();
        assert_eq!(
            alias_wire,
            vec![
                0x5B, // Response: MID | M (no N)
                0x2A, // VLE(rid=42)
                0x07, // wireexpr.id VLE(7)
                0x05, // Err.header
                0x01, // payload_len(1)
                b'e',
            ],
            "Response(Err) aliased no-suffix wire bytes must match \
             zenoh-pico reference",
        );

        // Composite: rid=42, mapping_id=7, suffix "tail", payload "data".
        let composite = build_response_err_aliased(42, 7, Some("tail"), b"data");
        let composite_wire = composite.encode_to_vec();
        let mut composite_expected = vec![
            0x7B, // Response: MID | N | M
            0x2A, 0x07, 0x04, // suffix_len(4)
        ];
        composite_expected.extend_from_slice(b"tail");
        composite_expected.push(0x05); // Err.header
        composite_expected.push(0x04); // payload_len(4)
        composite_expected.extend_from_slice(b"data");
        assert_eq!(
            composite_wire, composite_expected,
            "Response(Err) composite alias wire bytes must match \
             zenoh-pico reference",
        );
    }

    #[test]
    #[should_panic(expected = "build_response_err_aliased requires a non-zero mapping id")]
    fn build_response_err_aliased_rejects_zero_mapping_id() {
        let _ = build_response_err_aliased(42, 0, Some("any"), b"v");
    }

    /// R121j-3 — `encode_frame_with_response` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.encode_to_vec()` wrapping as
    /// the other helpers, with `Response.encode_to_vec()` as the inner
    /// payload bytes. Reply data delivery defaults to reliable.
    #[test]
    fn encode_frame_with_response_wraps_response_in_frame_envelope() {
        let response = build_response_reply_literal(42, "k", b"v");
        let response_bytes = response.encode_to_vec();

        let wire_reliable =
            encode_frame_with_response(0, build_response_reply_literal(42, "k", b"v"), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = 0x00");
        assert_eq!(
            &wire_reliable[2..],
            response_bytes.as_slice(),
            "Frame body tail must be Response.encode_to_vec() bytes verbatim",
        );

        let wire_best_effort =
            encode_frame_with_response(0, build_response_reply_literal(42, "k", b"v"), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    #[test]
    fn encode_frame_with_request_wraps_request_in_frame_envelope() {
        let request = build_request_query(42, 7, None);
        let request_bytes = request.encode_to_vec();

        let wire_reliable = encode_frame_with_request(0, build_request_query(42, 7, None), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R on the parent header",
        );
        assert_eq!(wire_reliable[1], 0x00, "sn=0 VLE = single byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            request_bytes.as_slice(),
            "Frame body tail must be Request.encode_to_vec() bytes verbatim",
        );

        let wire_best_effort =
            encode_frame_with_request(0, build_request_query(42, 7, None), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
        );
    }

    /// R121j-5c-e2e — `SessionLinkActions::send_response` emits the
    /// exact same wire bytes as the underlying
    /// `encode_frame_with_response` helper with the SN drawn from
    /// `next_outbound_frame_sn`. The action layer must not silently
    /// transform the Response between the builder and the wire.
    #[test]
    fn send_response_emits_reliable_frame_with_seeded_sn() {
        use crate::sync::Mutex;

        struct RecordingDriver {
            frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
        }
        impl BoxedLinkDriver for RecordingDriver {
            fn send_blocking(&self, bytes: &[u8], r: Reliability) {
                self.frames.lock().unwrap().push((bytes.to_vec(), r));
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }

        let driver = Arc::new(RecordingDriver {
            frames: Mutex::new(Vec::new()),
        });
        let params = SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 100,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        };
        let actions = SessionLinkActions::new(driver.clone(), params, TokioTime::new());

        let response = ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"21.0").build();
        let expected_wire = encode_frame_with_response(
            100,
            ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"21.0").build(),
            /*reliable=*/ true,
        );
        actions.send_response(response);

        let frames = driver.frames.lock().unwrap();
        assert_eq!(
            frames.len(),
            1,
            "exactly one send_blocking call per send_response"
        );
        assert_eq!(
            frames[0].0, expected_wire,
            "wire bytes must match encode_frame_with_response output byte-for-byte"
        );
        assert_eq!(
            frames[0].1,
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
        use crate::sync::Mutex;

        struct RecordingDriver {
            frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
        }
        impl BoxedLinkDriver for RecordingDriver {
            fn send_blocking(&self, bytes: &[u8], r: Reliability) {
                self.frames.lock().unwrap().push((bytes.to_vec(), r));
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }

        for (variant, reason_byte) in [
            (CloseReason::Generic, 0u8),
            (CloseReason::Invalid, 1u8),
            (CloseReason::Expired, 2u8),
            (CloseReason::Unresponsive, 3u8),
        ] {
            let driver = Arc::new(RecordingDriver {
                frames: Mutex::new(Vec::new()),
            });
            let params = SessionInitParams {
                version: 0x09,
                whatami: 0x02,
                zid: vec![0x01, 0x02, 0x03, 0x04],
                seq_num_res: 2,
                req_id_res: 2,
                batch_size: 65535,
                lease: 10_000,
                lease_in_seconds: false,
                initial_sn: 1,
                cookie: Vec::new(),
                cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                    .expect("32-byte demo key satisfies the >=32 invariant"),
            };
            let actions = SessionLinkActions::new(driver.clone(), params, TokioTime::new());
            assert_eq!(
                actions.trace_snapshot().send_close_frame_with_reason,
                0,
                "trace counter starts at zero",
            );

            actions.send_close_with_reason(variant);

            let frames = driver.frames.lock().unwrap();
            assert_eq!(
                frames.len(),
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
                frames[0].0, expected,
                "wire bytes must match encode_close output for {variant:?}",
            );
            assert_eq!(
                frames[0].1,
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
    #[test]
    fn send_response_and_final_share_sn_counter() {
        use crate::sync::Mutex;

        struct RecordingDriver {
            frames: Mutex<Vec<Vec<u8>>>,
        }
        impl BoxedLinkDriver for RecordingDriver {
            fn send_blocking(&self, bytes: &[u8], _r: Reliability) {
                self.frames.lock().unwrap().push(bytes.to_vec());
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }

        let driver = Arc::new(RecordingDriver {
            frames: Mutex::new(Vec::new()),
        });
        let params = SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 7,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        };
        let actions = SessionLinkActions::new(driver.clone(), params, TokioTime::new());

        actions.send_response(ResponseReplyBuilder::new(99, 0, Some("k"), b"v").build());
        actions.send_response_final(99);

        let frames = driver.frames.lock().unwrap();
        assert_eq!(frames.len(), 2);
        // Reply frame SN byte is at offset 1 (Frame header + VLE(sn)).
        assert_eq!(frames[0][1], 7, "first frame uses initial_sn=7");
        assert_eq!(
            frames[1][1], 8,
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
        // Driver harness — discard everything (the SN counter is
        // independent of driver wire-up).
        struct NullDriver;
        impl BoxedLinkDriver for NullDriver {
            fn send_blocking(&self, _bytes: &[u8], _r: Reliability) {}
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }
        let params = SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 42,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        };
        let actions = SessionLinkActions::new(Arc::new(NullDriver), params, TokioTime::new());
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

    /// R121j-2b — ResponseReplyBuilder with no setters must emit the
    /// exact same wire bytes as the baseline aliased helper. The
    /// builder is a strictly additive surface; it cannot silently
    /// change the minimal-shape output.
    #[test]
    fn response_reply_builder_no_setters_matches_aliased_baseline() {
        let direct = build_response_reply_aliased(42, 7, None, b"hello").encode_to_vec();
        let built = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .encode_to_vec();
        assert_eq!(
            direct, built,
            "ReplyBuilder.new+build must match build_response_reply_aliased byte-for-byte"
        );
    }

    /// R121j-2b — ResponseReplyBuilder.consolidation sets the
    /// `_Z_FLAG_Z_R_C(0x20)` bit on `Reply.header` and emits the 1-byte
    /// consolidation immediately after the header. Mirrors zenoh-pico
    /// `_z_reply_encode` at vendor/zenoh-pico/src/protocol/codec/message.c.
    #[test]
    fn response_reply_builder_consolidation_sets_r_c_flag_and_byte() {
        let baseline = build_response_reply_aliased(42, 7, None, b"hello").encode_to_vec();
        let with_c = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .consolidation(ConsolidationMode::Latest)
            .build()
            .encode_to_vec();
        // The C-bit-set wire differs from baseline only in the Reply.header
        // byte (R_C bit) and a freshly inserted consolidation byte (0x02 =
        // Latest) directly after it.
        assert_ne!(
            baseline, with_c,
            "consolidation setter must alter the wire bytes"
        );
        // Locate Reply.header in the encoded Response. The encoded layout
        // up through Reply.header is:
        //   Response.header(1) + VLE(rid) + wireexpr + Reply.header(1)
        // For (rid=42, mapping_id=7, suffix=None) the prefix is small and
        // we can pin the locations explicitly: Response.header at offset
        // 0, VLE(42)=1 byte at offset 1, wireexpr(id=7,no suffix)=1 byte
        // VLE(7) at offset 2, Reply.header at offset 3.
        assert_eq!(
            baseline[3] & 0x20,
            0,
            "baseline Reply.header must have R_C clear"
        );
        assert_eq!(
            with_c[3] & 0x20,
            0x20,
            "consolidation builder must set R_C(0x20) on Reply.header"
        );
        assert_eq!(
            with_c[4],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte must follow Reply.header carrying the wire-byte mapping"
        );
    }

    /// R121j-2b — ResponseErrBuilder with no setters must emit the
    /// exact same wire bytes as the baseline aliased helper.
    #[test]
    fn response_err_builder_no_setters_matches_aliased_baseline() {
        let direct = build_response_err_aliased(42, 7, None, b"oops").encode_to_vec();
        let built = ResponseErrBuilder::new(42, 7, None, b"oops")
            .build()
            .encode_to_vec();
        assert_eq!(
            direct, built,
            "ErrBuilder.new+build must match build_response_err_aliased byte-for-byte"
        );
    }

    /// R121j-2b — ResponseErrBuilder.encoding without schema sets the
    /// `_Z_FLAG_Z_E(0x40)` bit on `Err.header` and emits packed_id =
    /// (id << 1) | 0 with no schema_len / schema bytes.
    #[test]
    fn response_err_builder_encoding_no_schema_packs_id_left_shift_one() {
        let with_enc = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, None) // 4 = application/json prefix
            .build()
            .encode_to_vec();
        // Layout up through Err.header:
        //   Response.header(1) + VLE(42)(1) + VLE(7)(1) + Err.header(1) at offset 3
        assert_eq!(
            with_enc[3] & 0x40,
            0x40,
            "encoding builder must set E(0x40) on Err.header"
        );
        // Next byte is VLE(packed_id) where packed_id = 4<<1 = 8.
        // VLE(8) = single byte 0x08.
        assert_eq!(
            with_enc[4], 0x08,
            "no-schema packed_id = (id << 1) | 0; for id=4 this is 0x08"
        );
    }

    /// R121j-2b — ResponseErrBuilder.encoding with schema sets E,
    /// packs LSB=1, and emits the VLE schema_len + schema bytes.
    #[test]
    fn response_err_builder_encoding_with_schema_sets_lsb_and_emits_suffix() {
        let with_enc = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, Some("schema_v1"))
            .build()
            .encode_to_vec();
        assert_eq!(
            with_enc[3] & 0x40,
            0x40,
            "schema-bearing encoding still sets E on Err.header"
        );
        // packed_id = (4 << 1) | 1 = 9 → VLE single byte 0x09
        assert_eq!(
            with_enc[4], 0x09,
            "with-schema packed_id = (id << 1) | 1; for id=4 this is 0x09"
        );
        // VLE(schema_len = 9) = single byte 0x09, then "schema_v1" bytes
        assert_eq!(
            with_enc[5], 0x09,
            "schema_len VLE follows packed_id; 'schema_v1' length = 9"
        );
        assert_eq!(
            &with_enc[6..6 + 9],
            b"schema_v1",
            "schema bytes follow schema_len"
        );
    }

    /// R121j-2b — ResponseReplyBuilder literal path requires a
    /// non-empty keyexpr_suffix; (mapping_id=0, suffix=None) panics
    /// with the builder's diagnostic message at build() time.
    #[test]
    #[should_panic(
        expected = "ResponseReplyBuilder literal path (mapping_id=0) requires a non-empty keyexpr_suffix"
    )]
    fn response_reply_builder_literal_rejects_none_suffix() {
        let _ = ResponseReplyBuilder::new(42, 0, None, b"hello").build();
    }

    /// R121j-2b — ResponseErrBuilder literal path requires a
    /// non-empty keyexpr_suffix.
    #[test]
    #[should_panic(
        expected = "ResponseErrBuilder literal path (mapping_id=0) requires a non-empty keyexpr_suffix"
    )]
    fn response_err_builder_literal_rejects_none_suffix() {
        let _ = ResponseErrBuilder::new(42, 0, None, b"oops").build();
    }

    /// R121j-4b — ResponseErrBuilder.source_info sets `Err.header.Z(0x80)`
    /// and emits a single `ExtZbuf` ext entry with header
    /// `ENC_ZBUF(0x40) | id_source_info(0x01) = 0x41`. The value body is
    /// `[(zid_len-1)<<4, zid..., VLE(eid), VLE(sn)]` per zenoh-pico
    /// `_z_source_info_encode_ext` at `vendor/zenoh-pico/src/protocol/
    /// codec/message.c:243-254`.
    #[test]
    fn response_err_builder_source_info_emits_zbuf_ext_entry() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .source_info(&[0xAA; 4], 11, 17)
            .build()
            .encode_to_vec();
        // Layout up through Err.header: Response.header(1) + VLE(42)(1)
        // + VLE(7)(1) + Err.header(1) at offset 3. The source_info
        // setter must set Z(0x80) and leave E(0x40) clear (no encoding
        // in this test).
        assert_eq!(
            wire[3] & 0x80,
            0x80,
            "source_info builder must set Z(0x80) on Err.header"
        );
        assert_eq!(
            wire[3] & 0x40,
            0x00,
            "source_info-only builder must leave E(0x40) clear on Err.header"
        );
        // ExtEntry.header at offset 4: ENC_ZBUF(0x40) | id_source_info(0x01).
        // No Z chain-continuation bit because this is the sole entry.
        assert_eq!(
            wire[4], 0x41,
            "source_info ext header = ENC_ZBUF(0x40) | id_source_info(0x01); no Z chain bit on the sole entry"
        );
        // ExtZbuf value_len VLE at offset 5: leading byte(1) + zid(4)
        // + VLE(eid=11)(1) + VLE(sn=17)(1) = 7 bytes.
        assert_eq!(
            wire[5], 0x07,
            "ExtZbuf value_len = 1 leading + 4 zid + 1 VLE(eid) + 1 VLE(sn) = 7"
        );
        // value[0] = (4-1) << 4 = 0x30 at offset 6.
        assert_eq!(
            wire[6], 0x30,
            "leading byte = (zid_len-1) << 4 = 0x30 for zid_len=4"
        );
        // value[1..5] = zid bytes [0xAA; 4] at offsets 7..11.
        assert_eq!(
            &wire[7..11],
            &[0xAA; 4],
            "zid bytes follow the leading byte"
        );
        // value[5] = VLE(eid=11) at offset 11.
        assert_eq!(wire[11], 0x0B, "VLE(eid=11) = single byte 0x0B");
        // value[6] = VLE(sn=17) at offset 12.
        assert_eq!(wire[12], 0x11, "VLE(sn=17) = single byte 0x11");
        // Payload tail: VLE(payload_len=4) at offset 13, then "oops".
        assert_eq!(wire[13], 0x04, "VLE(payload_len=4) follows the ext chain");
        assert_eq!(
            &wire[14..18],
            b"oops",
            "payload bytes follow the length prefix"
        );
    }

    /// R121j-4b — `source_info` and `encoding` compose: both Err.header
    /// bits (E + Z) set, the encoded `Encoding` field sits between the
    /// header and the ext chain (Err::encode order at
    /// `wz-codecs/.../out/err.rs:171-200`).
    #[test]
    fn response_err_builder_source_info_composes_with_encoding() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, None)
            .source_info(&[0xBB; 1], 1, 2)
            .build()
            .encode_to_vec();
        // Err.header at offset 3: E(0x40) | Z(0x80) = 0xC0.
        assert_eq!(
            wire[3] & 0xC0,
            0xC0,
            "compose path must set both E(0x40) and Z(0x80) on Err.header"
        );
        // Encoding at offset 4: packed_id = (4<<1)|0 = 8 → VLE 0x08.
        // (Schema absent so no schema_len / schema bytes follow.)
        assert_eq!(
            wire[4], 0x08,
            "encoding packed_id = (id << 1) | 0; for id=4 this is 0x08"
        );
        // ExtEntry.header at offset 5: 0x41.
        assert_eq!(
            wire[5], 0x41,
            "ext header follows encoding when both are set"
        );
        // VLE(value_len=4) at offset 6 (1 leading + 1 zid + 1 VLE(eid) + 1 VLE(sn)).
        assert_eq!(
            wire[6], 0x04,
            "value_len = 1 + 1 + 1 + 1 = 4 for 1-byte zid"
        );
        // value[0] = (1-1)<<4 = 0x00 at offset 7.
        assert_eq!(wire[7], 0x00, "leading byte = 0x00 for zid_len=1");
        assert_eq!(wire[8], 0xBB, "zid byte");
        assert_eq!(wire[9], 0x01, "VLE(eid=1)");
        assert_eq!(wire[10], 0x02, "VLE(sn=2)");
        // VLE(payload_len=4) + "oops".
        assert_eq!(wire[11], 0x04, "payload_len VLE follows the ext body");
        assert_eq!(&wire[12..16], b"oops");
    }

    /// R121j-4b — source_info rejects zid lengths outside the
    /// zenoh-pico ZenohId wire constraint (1..=16, transport.h:31-37).
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::source_info requires zid length 1..=16")]
    fn response_err_builder_source_info_rejects_zid_too_long() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").source_info(&[0; 17], 0, 0);
    }

    /// R121j-4b — empty zid is also rejected (lower bound of 1..=16).
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::source_info requires zid length 1..=16")]
    fn response_err_builder_source_info_rejects_empty_zid() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").source_info(&[], 0, 0);
    }

    /// R121j-3c — ResponseReplyBuilder.responder sets
    /// `Response.header.Z(0x80)` (envelope-level), prepends a single
    /// `ExtZbuf` envelope ext (header `ENC_ZBUF(0x40) | id_responder(0x03)
    /// = 0x43`) carrying `[(zid_len-1)<<4, zid..., VLE(eid)]` per
    /// zenoh-pico `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`. The
    /// Reply inner body is unaffected — envelope ext is orthogonal to
    /// body bits.
    #[test]
    fn response_reply_builder_responder_emits_envelope_zbuf_ext_entry() {
        let baseline = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .encode_to_vec();
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .responder(&[0xAA; 4], 11)
            .build()
            .encode_to_vec();
        // Envelope: Response.header(1) + VLE(42)(1) + VLE(7)(1) = 3-byte
        // prefix; responder ext lands at offset 3 (no keyexpr suffix in
        // the aliased mapping_id=7 + None path).
        assert_eq!(
            wire[0],
            baseline[0] | 0x80,
            "responder must set Z(0x80) on Response.header; other base bits preserved"
        );
        assert_eq!(
            wire[3], 0x43,
            "envelope ext header = ENC_ZBUF(0x40) | id_responder(0x03); no Z chain bit on sole entry"
        );
        assert_eq!(
            wire[4], 0x06,
            "ExtZbuf value_len = 1 leading + 4 zid + 1 VLE(eid) = 6"
        );
        assert_eq!(wire[5], 0x30, "leading byte = (4-1) << 4 for zid_len=4");
        assert_eq!(&wire[6..10], &[0xAA; 4], "raw zid bytes");
        assert_eq!(wire[10], 0x0B, "VLE(eid=11)");
        // Inner Reply.header was at offset 3 in baseline; the envelope
        // ext adds 8 bytes (1 header + 1 value_len + 6 value), so
        // Reply.header is now at offset 11 with the same byte value.
        assert_eq!(
            wire[11], baseline[3],
            "inner Reply.header preserved at the offset shifted by the envelope ext (8 bytes)"
        );
        assert_eq!(
            wire.len(),
            baseline.len() + 8,
            "wire length grows by exactly the envelope ext size (1+1+6=8 bytes)"
        );
    }

    /// R121j-3c — responder (envelope-level) composes with consolidation
    /// (Reply-body-level): the bits land on different bytes — Z on
    /// Response.header, C on Reply.header — so the two setters are
    /// orthogonal and may be applied in either order with the same
    /// wire result.
    #[test]
    fn response_reply_builder_responder_composes_with_consolidation() {
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .responder(&[0xBB; 1], 1)
            .consolidation(ConsolidationMode::Latest)
            .build()
            .encode_to_vec();
        // Envelope Z set on Response.header at offset 0.
        assert_eq!(
            wire[0] & 0x80,
            0x80,
            "envelope-level Z(0x80) on Response.header"
        );
        // Envelope ext: header(0x43) + VLE(value_len = 1+1+1 = 3) + body(3)
        // at offsets 3..8. Body = [0x00, 0xBB, 0x01].
        assert_eq!(wire[3], 0x43);
        assert_eq!(
            wire[4], 0x03,
            "value_len = 1 leading + 1 zid + 1 VLE(eid) = 3"
        );
        assert_eq!(wire[5], 0x00, "leading byte = 0x00 for zid_len=1");
        assert_eq!(wire[6], 0xBB);
        assert_eq!(wire[7], 0x01, "VLE(eid=1)");
        // Inner Reply.header at offset 8 with consolidation C(0x20) bit
        // set; consolidation byte (LatestSamePeer = 0x02 wire byte) at
        // offset 9.
        assert_eq!(
            wire[8] & 0x20,
            0x20,
            "Reply.header.C(0x20) set by consolidation; orthogonal to envelope-level Z"
        );
        assert_eq!(
            wire[9],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte follows Reply.header"
        );
    }

    /// R121j-3c — ResponseErrBuilder.responder mirrors the Reply path:
    /// envelope-level Z(0x80) + single ExtEntry on Response.extensions.
    /// The Err inner body (header.E / header.Z for source_info) is
    /// independent of the envelope ext.
    #[test]
    fn response_err_builder_responder_emits_envelope_zbuf_ext_entry() {
        let baseline = ResponseErrBuilder::new(42, 7, None, b"oops")
            .build()
            .encode_to_vec();
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .responder(&[0xCC; 2], 5)
            .build()
            .encode_to_vec();
        assert_eq!(
            wire[0],
            baseline[0] | 0x80,
            "responder must set Z(0x80) on Response.header for Err path too"
        );
        assert_eq!(
            wire[3], 0x43,
            "same envelope ext header for both Reply and Err paths"
        );
        assert_eq!(
            wire[4], 0x04,
            "value_len = 1 leading + 2 zid + 1 VLE(eid) = 4"
        );
        assert_eq!(wire[5], 0x10, "leading byte = (2-1) << 4 for zid_len=2");
        assert_eq!(&wire[6..8], &[0xCC, 0xCC]);
        assert_eq!(wire[8], 0x05, "VLE(eid=5)");
        // Inner Err.header preserved (was at offset 3 in baseline, now
        // shifted by envelope ext size = 1 + 1 + 4 = 6 bytes).
        assert_eq!(
            wire[9], baseline[3],
            "inner Err.header preserved at offset shifted by envelope ext (6 bytes)"
        );
        assert_eq!(wire.len(), baseline.len() + 6);
    }

    /// R121j-3c — Err.responder (envelope) + Err.source_info (Err body)
    /// compose: envelope-level Z lands on Response.header, body-level
    /// Z lands on Err.header. Separate bytes, separate ext chains.
    #[test]
    fn response_err_builder_responder_composes_with_source_info() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .responder(&[0xDD; 1], 9)
            .source_info(&[0xEE; 1], 3, 4)
            .build()
            .encode_to_vec();
        // Envelope Z on Response.header.
        assert_eq!(
            wire[0] & 0x80,
            0x80,
            "envelope Z(0x80) on Response.header for responder"
        );
        // Envelope ext: 0x43 + VLE(3) + [0x00, 0xDD, 0x09] at offsets 3..8.
        assert_eq!(wire[3], 0x43);
        assert_eq!(wire[4], 0x03, "envelope responder value_len = 3");
        assert_eq!(&wire[5..8], &[0x00, 0xDD, 0x09]);
        // Err.header at offset 8 with Z(0x80) set by source_info.
        // E(0x40) clear because no encoding.
        assert_eq!(
            wire[8] & 0x80,
            0x80,
            "Err.header.Z(0x80) set by source_info; orthogonal to envelope Z"
        );
        assert_eq!(
            wire[8] & 0x40,
            0x00,
            "Err.header.E(0x40) clear (no encoding)"
        );
        // Err body ext: 0x41 + VLE(value_len = 1+1+1+1 = 4) + body(4)
        // at offsets 9..14.
        assert_eq!(wire[9], 0x41, "Err body ext header = source_info (0x41)");
        assert_eq!(wire[10], 0x04, "source_info value_len = 4");
        assert_eq!(&wire[11..15], &[0x00, 0xEE, 0x03, 0x04]);
    }

    /// R121j-3c — responder rejects zid lengths outside 1..=16 on
    /// both Reply and Err builders (zenoh-pico ZenohId wire constraint,
    /// transport.h:31-37).
    #[test]
    #[should_panic(expected = "ResponseReplyBuilder::responder requires zid length 1..=16")]
    fn response_reply_builder_responder_rejects_zid_too_long() {
        let _ = ResponseReplyBuilder::new(42, 7, None, b"hello").responder(&[0; 17], 0);
    }

    /// R121j-3c — ResponseErrBuilder.responder shares the same wire
    /// constraint.
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::responder requires zid length 1..=16")]
    fn response_err_builder_responder_rejects_empty_zid() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").responder(&[], 0);
    }

    /// R121j-3c — direct check on the helper that builds the
    /// responder ext-body bytes. Distinct from source_info in that no
    /// `sn` trailer is emitted.
    #[test]
    fn encode_responder_ext_body_matches_zenoh_pico_layout() {
        // zid_len=3 → leading byte = (3-1)<<4 = 0x20
        let bytes = encode_responder_ext_body(&[0xCA, 0xFE, 0xBA], 0x4000);
        assert_eq!(
            bytes[0], 0x20,
            "leading byte packs zid_len-1 in high nibble"
        );
        assert_eq!(
            &bytes[1..4],
            &[0xCA, 0xFE, 0xBA],
            "raw zid follows the leading byte"
        );
        // VLE(16384) = 0x80 0x80 0x01
        assert_eq!(
            &bytes[4..7],
            &[0x80, 0x80, 0x01],
            "VLE(eid=16384) = 0x80 0x80 0x01"
        );
        assert_eq!(bytes.len(), 7, "total = 1 leading + 3 zid + 3 VLE(eid) = 7");
    }

    /// R121j-4b — direct check on the helper that builds the
    /// source_info ext-body bytes. Locks the wire shape independently
    /// of the builder so future helpers (Push.source_info, Query
    /// source_info) can re-use the helper with the same guarantees.
    #[test]
    fn encode_source_info_ext_body_matches_zenoh_pico_layout() {
        // zid_len=2 → leading byte = (2-1)<<4 = 0x10
        let bytes = encode_source_info_ext_body(&[0xDE, 0xAD], 0x80, 0x4000);
        // Expected: [0x10, 0xDE, 0xAD, VLE(0x80)..., VLE(0x4000)...]
        // VLE(0x80): 0x80 needs 2 bytes (first 0x80|0x00=0x80, second 0x01)
        // VLE(0x4000): 0x4000 needs 3 bytes (0x80, 0x80, 0x01)
        assert_eq!(
            bytes[0], 0x10,
            "leading byte packs zid_len-1 in high nibble"
        );
        assert_eq!(
            &bytes[1..3],
            &[0xDE, 0xAD],
            "raw zid follows the leading byte"
        );
        // VLE(128) = 0x80, 0x01 (continuation bit on first byte, value 1 in second)
        assert_eq!(
            &bytes[3..5],
            &[0x80, 0x01],
            "VLE(eid=128) = 0x80 0x01 (2 bytes)"
        );
        // VLE(16384) = 0x80, 0x80, 0x01
        assert_eq!(
            &bytes[5..8],
            &[0x80, 0x80, 0x01],
            "VLE(sn=16384) = 0x80 0x80 0x01 (3 bytes)"
        );
        assert_eq!(
            bytes.len(),
            8,
            "total = 1 leading + 2 zid + 2 VLE(eid) + 3 VLE(sn) = 8"
        );
    }

    /// R121j-3d — ResponseReplyBuilder.reply_del() swaps the inner
    /// ReplyVariant arm from CodecZenohMsgPut to CodecZenohMsgDel.
    /// Wire-level effect: inner MID byte flips from 0x01 (Put) to
    /// 0x02 (Del); the payload bytes the constructor received are
    /// dropped (MsgDel has no payload).
    #[test]
    fn response_reply_builder_reply_del_swaps_inner_arm_to_msgdel() {
        let put_wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .encode_to_vec();
        let del_wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .reply_del()
            .build()
            .encode_to_vec();
        // Layout up through Reply.header: Response.header(1) + VLE(42)(1) +
        // VLE(7)(1) + Reply.header(1) at offset 3. Inner MID at offset 4.
        assert_eq!(put_wire[4], 0x01, "Put path inner MID = _Z_MID_Z_PUT(0x01)");
        assert_eq!(del_wire[4], 0x02, "Del path inner MID = _Z_MID_Z_DEL(0x02)");
        // The Del wire is shorter than Put because MsgPut emits VLE(payload_len)
        // + payload bytes (1 + 5 = 6 bytes for b"hello") while MsgDel emits
        // nothing after its header. Specifically del_wire ends right after
        // the Reply.header for MsgDel (no Reply exts, no MsgDel exts).
        assert!(
            del_wire.len() < put_wire.len(),
            "Del wire must be strictly shorter than Put wire (no payload)",
        );
        // Pinpoint: Put adds VLE(5) + 5 payload bytes = 6 bytes after the
        // inner MID byte. Del adds nothing. So Put length - Del length == 6.
        assert_eq!(
            put_wire.len() - del_wire.len(),
            6,
            "Del path must drop exactly VLE(5)+5 = 6 payload bytes from the Put baseline",
        );
    }

    /// R121j-3d — reply_del() composes with consolidation. The
    /// Reply.header.C bit must still be set when MsgDel + consolidation
    /// are combined; the consolidation byte sits between Reply.header
    /// and the MsgDel inner MID, not between Put header and payload.
    #[test]
    fn response_reply_builder_reply_del_composes_with_consolidation() {
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .reply_del()
            .consolidation(ConsolidationMode::Latest)
            .build()
            .encode_to_vec();
        // Reply.header at offset 3 must carry R_C(0x20).
        assert_eq!(
            wire[3] & 0x20,
            0x20,
            "consolidation must set R_C(0x20) on Reply.header even on Del path"
        );
        // Consolidation byte at offset 4 (between Reply.header and MsgDel).
        assert_eq!(
            wire[4],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte follows Reply.header"
        );
        // MsgDel inner MID at offset 5.
        assert_eq!(wire[5], 0x02, "MsgDel inner MID follows consolidation byte");
    }

    // ── R233 wire encoder for PublishOptions metadata ──

    use crate::sample::{EncodingHint, QosLevel, SourceInfo, TimestampHint};

    #[test]
    fn push_metadata_is_empty_returns_true_only_when_all_fields_none() {
        let empty = PushMetadata::default();
        assert!(empty.is_empty());

        let with_ts = PushMetadata {
            timestamp: Some(TimestampHint::default()),
            ..Default::default()
        };
        assert!(!with_ts.is_empty());

        let with_qos = PushMetadata {
            qos: Some(QosLevel::from_raw(0)),
            ..Default::default()
        };
        assert!(!with_qos.is_empty());
    }

    #[test]
    fn build_msg_put_with_meta_sets_timestamp_field_and_t_flag() {
        let ts = TimestampHint {
            time: 0xDEAD_BEEF_CAFE_BABE,
            zid: vec![0xAA, 0xBB],
        };
        let put = build_msg_put_with_meta(b"payload", Some(&ts), None, None, None);
        assert!(put.timestamp.is_some(), "set_t routes through Option");
        assert_eq!(put.timestamp.as_ref().unwrap().time, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(put.timestamp.as_ref().unwrap().zid, vec![0xAA, 0xBB]);
        assert!(put.t(), "T flag must be set when timestamp is attached");
        assert!(!put.e(), "E flag must remain clear when encoding is absent");
        assert!(!put.z(), "Z flag must remain clear without body extensions");
    }

    #[test]
    fn build_msg_put_with_meta_sets_encoding_field_and_e_flag() {
        let enc = EncodingHint {
            packed_id: 13,
            schema: Some("application/json".into()),
        };
        let put = build_msg_put_with_meta(b"payload", None, Some(&enc), None, None);
        assert!(put.encoding.is_some());
        assert_eq!(put.encoding.as_ref().unwrap().packed_id, 13);
        assert_eq!(
            put.encoding.as_ref().unwrap().schema.as_deref(),
            Some("application/json")
        );
        // schema_len round-trips from the original schema's byte length.
        assert_eq!(
            put.encoding.as_ref().unwrap().schema_len,
            Some("application/json".len() as u64)
        );
        assert!(put.e(), "E flag must be set when encoding is attached");
        assert!(
            !put.t(),
            "T flag must remain clear when timestamp is absent"
        );
    }

    #[test]
    fn build_msg_put_with_meta_attaches_source_info_ext_and_sets_z_flag() {
        let si = SourceInfo::new(&[0x11, 0x22, 0x33, 0x44], 7, 42);
        let put = build_msg_put_with_meta(b"payload", None, None, Some(&si), None);
        let exts = put.extensions.as_deref().expect("body ext chain populated");
        assert_eq!(exts.len(), 1);
        // source_info ext: ENC_ZBUF(0x40) | ext_id(0x01) — M and Z bits
        // are NOT pre-set; Z bit application happens at codec emit time.
        assert_eq!(exts[0].header & 0x4F, 0x41);
        assert!(
            put.z(),
            "Z flag must be set when body extensions are present"
        );
        if let ExtEntryVariant::CodecZenohExtZbuf(z) = &exts[0].body {
            // First byte of source_info payload is `(zidlen - 1) << 4`.
            assert_eq!(z.value[0], (4 - 1) << 4);
            assert_eq!(&z.value[1..5], &[0x11, 0x22, 0x33, 0x44]);
        } else {
            panic!("source_info must use ExtZbuf body");
        }
    }

    #[test]
    fn build_msg_put_with_meta_attaches_attachment_ext_after_source_info() {
        // Both source_info + attachment together — order matters: pico's
        // _z_push_body_encode_extensions emits source_info before
        // attachment so the chain position must mirror that ordering.
        let si = SourceInfo::new(&[0xDE, 0xAD], 7, 0);
        let put =
            build_msg_put_with_meta(b"payload", None, None, Some(&si), Some(b"attach-payload"));
        let exts = put.extensions.as_deref().expect("body ext chain populated");
        assert_eq!(exts.len(), 2, "source_info + attachment = 2 entries");
        assert_eq!(exts[0].header & 0x4F, 0x41, "source_info first");
        assert_eq!(exts[1].header & 0x4F, 0x43, "attachment second");
        if let ExtEntryVariant::CodecZenohExtZbuf(z) = &exts[1].body {
            assert_eq!(z.value, b"attach-payload");
        } else {
            panic!("attachment must use ExtZbuf body");
        }
    }

    #[test]
    fn build_msg_put_with_meta_leaves_extensions_none_on_empty_inputs() {
        let put = build_msg_put_with_meta(b"payload", None, None, None, None);
        assert!(put.extensions.is_none());
        assert!(!put.z(), "Z flag must remain clear with no extensions");
        assert!(!put.t(), "T flag clear with no timestamp");
        assert!(!put.e(), "E flag clear with no encoding");
    }

    #[test]
    fn build_msg_del_with_meta_carries_timestamp_but_not_encoding_param() {
        // The MsgDel builder's parameter list intentionally has no
        // encoding slot — _z_msg_del_t has no encoding field on the
        // wire. This test pins that the API forbids a caller from
        // accidentally attaching encoding to a Del wire form.
        let ts = TimestampHint {
            time: 0x0102_0304_0506_0708,
            zid: vec![0x99],
        };
        let del = build_msg_del_with_meta(Some(&ts), None, None);
        assert!(del.timestamp.is_some());
        assert!(del.t(), "T flag set when Del carries timestamp");
        assert!(!del.z(), "Z flag clear with no extensions");
    }

    #[test]
    fn build_push_outer_extensions_emits_qos_with_zint_body() {
        let exts = build_push_outer_extensions(Some(QosLevel::from_raw(0b0001_1010)))
            .expect("qos populates outer chain");
        assert_eq!(exts.len(), 1);
        // ENC_ZINT(0x20) | id_qos(0x01); no M, no Z (single ext).
        assert_eq!(exts[0].header & 0x2F, 0x21);
        if let ExtEntryVariant::CodecZenohExtZint(z) = &exts[0].body {
            assert_eq!(z.value, 0b0001_1010);
        } else {
            panic!("qos must use ExtZint body");
        }
    }

    #[test]
    fn build_push_outer_extensions_returns_none_without_qos() {
        assert!(build_push_outer_extensions(None).is_none());
    }

    #[test]
    fn build_push_literal_with_meta_sets_push_header_z_bit_when_qos_attached() {
        let meta = PushMetadata {
            qos: Some(QosLevel::from_raw(0x10)),
            ..Default::default()
        };
        let push = build_push_literal_with_meta("home/temp", b"22.5", &meta);
        // Push.header bit 7 (0x80) = Z chain-continuation for outer
        // extensions. Must be set when an outer extension is present.
        assert_eq!(push.header & 0x80, 0x80);
        assert!(push.extensions.is_some());
        // No body metadata → MsgPut.extensions stays None.
        if let PushVariant::CodecZenohMsgPut(put) = &push.body {
            assert!(put.extensions.is_none());
            assert!(!put.z(), "MsgPut Z stays clear without body extensions");
        } else {
            panic!("CodecZenohMsgPut variant expected");
        }
    }

    #[test]
    fn build_push_literal_with_meta_round_trips_through_codec_encode_decode() {
        // End-to-end: build → encode_to_vec → decode → field equality.
        // Validates that the wire form survives SCE's encode/decode
        // path with every metadata field set, not just that the
        // in-memory Push struct shape is correct.
        let meta = PushMetadata {
            timestamp: Some(TimestampHint {
                time: 0x1122_3344_5566_7788,
                zid: vec![0xAA, 0xBB, 0xCC],
            }),
            encoding: Some(EncodingHint {
                packed_id: 5,
                schema: Some("text/plain".into()),
            }),
            source_info: Some(SourceInfo::new(&[0x01, 0x02, 0x03, 0x04], 7, 42)),
            attachment: Some(b"attach".to_vec()),
            qos: Some(QosLevel::from_raw(0b0001_1010)),
        };
        let push = build_push_literal_with_meta("home/temp", b"payload", &meta);
        let encoded = push.encode_to_vec();

        // Decode back via SCE-emitted cursor path. wz-codecs re-exports
        // SceCursor through the runtime crate; use the same path the
        // dispatcher takes when handling wire-arrived frames.
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&encoded);
        let decoded = Push::decode(&mut cursor).expect("Push round-trip decode");

        // Outer Push extensions: qos must round-trip.
        let outer = decoded
            .extensions
            .as_deref()
            .expect("outer ext chain present");
        assert_eq!(outer.len(), 1);
        if let ExtEntryVariant::CodecZenohExtZint(z) = &outer[0].body {
            assert_eq!(z.value, 0b0001_1010);
        } else {
            panic!("qos outer ext must decode to ExtZint");
        }

        // Inner MsgPut: timestamp/encoding/extensions round-trip.
        if let PushVariant::CodecZenohMsgPut(put) = &decoded.body {
            let ts = put.timestamp.as_ref().expect("timestamp round-trips");
            assert_eq!(ts.time, 0x1122_3344_5566_7788);
            assert_eq!(ts.zid, vec![0xAA, 0xBB, 0xCC]);
            let enc = put.encoding.as_ref().expect("encoding round-trips");
            assert_eq!(enc.packed_id, 5);
            assert_eq!(enc.schema.as_deref(), Some("text/plain"));
            let body_exts = put.extensions.as_deref().expect("body ext chain present");
            assert_eq!(body_exts.len(), 2, "source_info + attachment");
            // Use the runtime's dispatcher projection to validate the
            // bytes resolve back to the original metadata.
            let si = crate::sample::extract_source_info(body_exts)
                .expect("source_info round-trips through wire");
            assert_eq!(si.zid_len, 4);
            assert_eq!(si.zid_prefix(), &[0x01, 0x02, 0x03, 0x04][..]);
            assert_eq!(si.eid, 7);
            assert_eq!(si.sn, 42);
            let att = crate::sample::extract_attachment(body_exts)
                .expect("attachment round-trips through wire");
            assert_eq!(att, b"attach");
        } else {
            panic!("CodecZenohMsgPut variant expected");
        }
    }

    #[test]
    fn build_push_del_literal_with_meta_round_trips_metadata_minus_encoding() {
        // Del path: timestamp + source_info + attachment + qos must
        // round-trip; encoding has no parameter slot so the wire form
        // cannot carry it. Mirrors the loopback path's projection.
        let meta = PushMetadata {
            timestamp: Some(TimestampHint {
                time: 0xAABB_CCDD,
                zid: vec![0x42],
            }),
            encoding: Some(EncodingHint {
                packed_id: 99,
                schema: Some("ignored".into()),
            }),
            source_info: Some(SourceInfo::new(&[0xDE, 0xAD], 1, 2)),
            attachment: Some(b"del-att".to_vec()),
            qos: Some(QosLevel::from_raw(0x10)),
        };
        let push = build_push_del_literal_with_meta("home/temp", &meta);
        let encoded = push.encode_to_vec();
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&encoded);
        let decoded = Push::decode(&mut cursor).expect("Push(MsgDel) round-trip");

        if let PushVariant::CodecZenohMsgDel(del) = &decoded.body {
            assert_eq!(del.timestamp.as_ref().unwrap().time, 0xAABB_CCDD);
            let body_exts = del.extensions.as_deref().expect("body ext chain present");
            // Del bodies carry source_info + attachment but NOT encoding.
            assert_eq!(body_exts.len(), 2);
            let si = crate::sample::extract_source_info(body_exts).unwrap();
            assert_eq!(si.eid, 1);
            assert_eq!(si.sn, 2);
            let att = crate::sample::extract_attachment(body_exts).unwrap();
            assert_eq!(att, b"del-att");
        } else {
            panic!("CodecZenohMsgDel variant expected");
        }
    }

    #[test]
    fn send_push_with_meta_literal_dispatches_metadata_frame_to_driver() {
        // End-to-end via the action surface + recording driver: the
        // emitted wire bytes must decode back to a Push carrying the
        // caller-set metadata. Pins the integration between
        // PushMetadata, build_push_literal_with_meta, and
        // encode_frame_with_push.
        let driver = std::sync::Arc::new(crate::session_glue::tests::CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = PushMetadata {
            source_info: Some(SourceInfo::new(&[0xCA, 0xFE], 5, 7)),
            qos: Some(QosLevel::from_raw(0x10)),
            ..Default::default()
        };
        actions.send_push_with_meta_literal("home/temp", b"data", true, &meta);

        let frames = driver.frames.lock().unwrap();
        assert_eq!(frames.len(), 1);
        // The frame is `Frame + Push`. We don't decode the outer Frame
        // here (the layer-3 integration tests cover that path); instead
        // we re-encode an equivalent Push via build_push_literal_with_meta
        // and assert the trailing Push bytes are byte-identical to the
        // bytes that follow the Frame envelope in the recorded buffer.
        let standalone_push = build_push_literal_with_meta("home/temp", b"data", &meta);
        let standalone_bytes = standalone_push.encode_to_vec();
        assert!(
            frames[0]
                .0
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "recorded frame must contain the with-meta Push bytes verbatim"
        );
    }

    fn publish_meta_fixture_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 1,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        }
    }

    /// Minimal recording driver for R233 wire-side tests. Captures
    /// every send_blocking frame so the per-test asserts can compare
    /// against a re-encoded standalone Push.
    pub(super) struct CaptureDriver {
        frames: std::sync::Mutex<Vec<(Vec<u8>, Reliability)>>,
    }
    impl CaptureDriver {
        fn new() -> Self {
            Self {
                frames: std::sync::Mutex::new(Vec::new()),
            }
        }
    }
    impl BoxedLinkDriver for CaptureDriver {
        fn send_blocking(&self, bytes: &[u8], r: Reliability) {
            self.frames.lock().unwrap().push((bytes.to_vec(), r));
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    // ── R234 outbound mapping table ──

    #[test]
    fn send_declare_keyexpr_populates_outbound_mapping_table() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn send_declare_keyexpr_overwrites_existing_mapping_for_same_id() {
        // zenoh-pico's _z_register_resource OVERWRITES on
        // re-declaration with the same id (it's idempotent: same id,
        // possibly different suffix). The outbound table must mirror
        // that semantic so a caller re-declaring a mapping doesn't
        // see stale resolution for later publishes.
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn send_undeclare_kexpr_removes_mapping_from_table() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn send_undeclare_kexpr_idempotent_on_unknown_id() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        // Calling undeclare on an id that was never declared must not
        // panic — the HashMap::remove on absent key is a no-op.
        actions.send_undeclare_kexpr(42);
        assert!(actions.resolve_outbound_mapping(42).is_none());
    }

    // ── R300 — outbound DECLARE-side gate ─────────────────────

    #[test]
    fn send_declare_keyexpr_rejects_reserved_mapping_id_zero() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let err = actions
            .send_declare_keyexpr(0, "home/temp")
            .expect_err("mapping_id 0 is reserved");
        assert_eq!(err, SendDeclareError::ReservedMappingIdZero);
        assert!(
            driver.frames.lock().unwrap().is_empty(),
            "gate must reject pre-emit — no wire frame leaves on Err"
        );
        assert!(
            actions.resolve_outbound_mapping(0).is_none(),
            "gate must reject pre-side-effect — mapping table untouched on Err"
        );
    }

    #[test]
    fn send_declare_keyexpr_rejects_pico_bug_three_pattern() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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
        assert!(driver.frames.lock().unwrap().is_empty());
        assert!(actions.resolve_outbound_mapping(7).is_none());
    }

    #[test]
    fn send_declare_keyexpr_rejects_structurally_invalid() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn send_declare_subscriber_rejects_missing_keyexpr() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        // mapping_id = 0 + suffix = None → no keyexpr at all.
        let err = actions
            .send_declare_subscriber(1, 0, None)
            .expect_err("MissingKeyexpr");
        assert_eq!(err, SendDeclareError::MissingKeyexpr);
        assert!(driver.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn send_declare_subscriber_rejects_unknown_mapping_id() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        // mapping_id != 0 but no prior send_declare_keyexpr.
        let err = actions
            .send_declare_subscriber(1, 99, Some("/tail"))
            .expect_err("UnknownMappingId(99)");
        assert_eq!(err, SendDeclareError::UnknownMappingId(99));
        assert!(driver.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn send_declare_subscriber_rejects_cross_boundary_bug_three() {
        // This is the gate's raison d'etre: prefix=`**` registered
        // via send_declare_keyexpr, suffix=`/c/*` passed to
        // send_declare_subscriber — neither alone triggers bug #3,
        // but the reconstructed full keyexpr `**/c/*` does. A
        // suffix-only check would miss this.
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        actions
            .send_declare_keyexpr(7, "**")
            .expect("prefix `**` is canonical + pico-safe in isolation");
        // 1 frame from the keyexpr declare; clear the count.
        let frames_before = driver.frames.lock().unwrap().len();
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
        assert_eq!(driver.frames.lock().unwrap().len(), 1);
    }

    #[test]
    fn send_declare_subscriber_accepts_safe_alias_form() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn send_declare_queryable_inherits_gate() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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
        assert!(driver.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn send_declare_token_inherits_gate() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let err = actions
            .send_declare_token(1, 0, Some("**/abc/*/def"))
            .expect_err("token inherits the same gate");
        assert!(matches!(
            err,
            SendDeclareError::Keyexpr(
                crate::keyexpr_canon::OutboundKeyexprError::PicoBugThreeFamily { .. }
            )
        ));
        assert!(driver.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn reconstruct_outbound_keyexpr_shape_table() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
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

    #[test]
    fn resolve_outbound_mapping_returns_owned_string_independent_of_table() {
        // The returned String must be a clone — a caller holding it
        // across a later send_undeclare_kexpr must still see the
        // value they originally fetched. This pins the contract
        // that callers don't accidentally borrow the table slot.
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        actions
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let resolved = actions.resolve_outbound_mapping(7).unwrap();
        actions.send_undeclare_kexpr(7);
        assert_eq!(resolved, "home/temp", "owned clone survives table mutation");
        assert!(actions.resolve_outbound_mapping(7).is_none());
    }

    // ── R240 wire-side QueryOptions propagation ──

    #[test]
    fn query_metadata_default_is_empty() {
        let meta = QueryMetadata::default();
        assert!(meta.is_empty());
    }

    #[test]
    fn query_metadata_with_target_is_not_empty() {
        let meta = QueryMetadata {
            target: Some(QueryTarget::All),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_consolidation_is_not_empty() {
        let meta = QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_attachment_is_not_empty() {
        let meta = QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_timeout_ms_nonzero_is_not_empty() {
        let meta = QueryMetadata {
            timeout_ms: 5_000,
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn send_request_query_with_meta_empty_emits_same_bytes_as_no_meta() {
        // R240 short-circuit invariant: empty QueryMetadata MUST
        // produce the same wire frame as the no-metadata
        // send_request_query path so byte-stable callers (CI / fuzz
        // baselines) stay unchanged when QueryOptions::default() is
        // threaded through Session::query.
        let driver_a = std::sync::Arc::new(CaptureDriver::new());
        let actions_a = SessionLinkActions::new(
            driver_a.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        actions_a.send_request_query_with_meta(42, 0, Some("home/temp"), &QueryMetadata::default());
        let with_meta = driver_a.frames.lock().unwrap()[0].0.clone();

        let driver_b = std::sync::Arc::new(CaptureDriver::new());
        let actions_b = SessionLinkActions::new(
            driver_b.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        actions_b.send_request_query(42, 0, Some("home/temp"));
        let no_meta = driver_b.frames.lock().unwrap()[0].0.clone();

        assert_eq!(
            with_meta, no_meta,
            "empty QueryMetadata must produce byte-stable parity with the no-meta path"
        );
    }

    #[test]
    fn send_request_query_with_meta_target_emits_request_with_target_ext() {
        // build_request_query_with_target standalone re-encode
        // produces the same wire shape the action surface threads
        // when meta.target = Some(target). Pins the
        // QueryMetadata::target → RequestQueryBuilder::request_target
        // wiring.
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = QueryMetadata {
            target: Some(QueryTarget::All),
            ..Default::default()
        };
        actions.send_request_query_with_meta(42, 0, Some("home/temp"), &meta);

        let standalone =
            build_request_query_with_target(42, 0, Some("home/temp"), QueryTarget::All);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-target Request bytes verbatim"
        );
    }

    #[test]
    fn send_request_query_with_meta_consolidation_emits_query_with_q_c_flag() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        };
        actions.send_request_query_with_meta(42, 0, Some("home/temp"), &meta);

        let standalone = build_request_query_with_consolidation(
            42,
            0,
            Some("home/temp"),
            ConsolidationMode::Latest,
        );
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-consolidation Request bytes verbatim"
        );
    }

    #[test]
    fn send_request_query_with_meta_attachment_emits_query_with_attachment_ext() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        };
        actions.send_request_query_with_meta(42, 0, Some("home/temp"), &meta);

        let standalone = build_request_query_with_attachment(42, 0, Some("home/temp"), b"q-att");
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-attachment Request bytes verbatim"
        );
    }

    #[test]
    fn send_request_query_with_meta_empty_attachment_slice_skips_ext_without_panic() {
        // QueryOptions::with_attachment(empty Vec) → meta.attachment
        // = Some(empty) — RequestQueryBuilder::query_attachment
        // asserts non-empty, but the meta-threading path must guard
        // against the panic by skipping the attach call on an empty
        // inner slice. Wire frame ends up matching the
        // no-attachment shape.
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = QueryMetadata {
            attachment: Some(Vec::new()),
            ..Default::default()
        };
        actions.send_request_query_with_meta(42, 0, Some("home/temp"), &meta);

        // No panic; frame ends up matching the no-meta baseline (meta
        // is not empty for is_empty() because attachment.is_some(),
        // but the wire emission elides the ext because the inner
        // slice is empty).
        let baseline = build_request_query(42, 0, Some("home/temp"));
        let baseline_bytes = baseline.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(baseline_bytes.len())
                .any(|w| w == baseline_bytes),
            "empty-inner attachment must not change the wire bytes"
        );
    }

    #[test]
    fn send_request_query_with_meta_timeout_ms_emits_request_with_timeout_ext() {
        let driver = std::sync::Arc::new(CaptureDriver::new());
        let actions = SessionLinkActions::new(
            driver.clone(),
            publish_meta_fixture_params(),
            TokioTime::new(),
        );
        let meta = QueryMetadata {
            timeout_ms: 5_000,
            ..Default::default()
        };
        actions.send_request_query_with_meta(42, 0, Some("home/temp"), &meta);

        let standalone = build_request_query_with_timeout_ms(42, 0, Some("home/temp"), 5_000);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "frame must contain the with-timeout Request bytes verbatim"
        );
    }
}
