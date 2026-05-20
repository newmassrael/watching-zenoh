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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use sce_rust_runtime::scripting::{IScriptEngine, NativeMethod, ScriptValue};
use sce_rust_runtime::Engine;

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::close::Close;
use wz_codecs::decl_final::DeclFinal;
use wz_codecs::decl_kexpr::DeclKexpr;
use wz_codecs::decl_queryable::DeclQueryable;
use wz_codecs::decl_subscriber::DeclSubscriber;
use wz_codecs::decl_token::DeclToken;
use wz_codecs::declare::{Declare, DeclareVariant};
use wz_codecs::undecl_kexpr::UndeclKexpr;
use wz_codecs::undecl_queryable::UndeclQueryable;
use wz_codecs::undecl_subscriber::UndeclSubscriber;
use wz_codecs::undecl_token::UndeclToken;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::frame::Frame;
use wz_codecs::init_body::InitBody;
use wz_codecs::interest::Interest;
use wz_codecs::keep_alive::KeepAlive;
use wz_codecs::msg_put::MsgPut;
use wz_codecs::oam::Oam;
use wz_codecs::open_body::OpenBody;
use wz_codecs::push::{Push, PushVariant};
use wz_codecs::query::Query;
use wz_codecs::request::{Request, RequestVariant};
use wz_codecs::response::Response;
use wz_codecs::response_final::ResponseFinal;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

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
pub fn generate_cookie_hmac_sha256(
    cookie_signing_key: &SigningKey,
    peer_zid: &[u8],
) -> Vec<u8> {
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
    pub const T_MID_INIT: u8 = 0x01;
    pub const T_MID_OPEN: u8 = 0x02;
    pub const T_MID_CLOSE: u8 = 0x03;
    /// Per-session liveness ping — zero-byte body; lease-timer
    /// reset on receive (transport.h:24 commentary, MID 0x04).
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
    pub const FLAG_T_INIT_A: u8 = 0x20;
    /// Size parameters carrier (sn_res + batch_size present).
    pub const FLAG_T_INIT_S: u8 = 0x40;

    /// OpenAck discriminator (0 = OpenSyn, 1 = OpenAck).
    pub const FLAG_T_OPEN_A: u8 = 0x20;
    /// Lease in seconds (1) vs milliseconds (0).
    pub const FLAG_T_OPEN_T: u8 = 0x40;

    /// Session-close vs link-only close.
    pub const FLAG_T_CLOSE_S: u8 = 0x20;

    /// Transport-message ext-chain presence bit shared across every
    /// `_Z_MID_T_*` header (transport.h:44 `_Z_FLAG_T_Z = 0x80`).
    /// When set the parent header signals that one or more
    /// `ExtEntry` records follow the body bytes, terminated by an
    /// entry whose own `Z` bit is clear.
    pub const FLAG_T_Z: u8 = 0x80;

    /// Network-message MID for `Frame.payload` batch entries that
    /// wrap a query / put / del (network.h:36). First R74-decoded
    /// network MID.
    pub const N_MID_REQUEST: u8 = 0x1C;
    /// R90 — Push envelope MID (network.h:35). Pub/sub data
    /// carrier wrapping a put / del inner body; sibling to
    /// `N_MID_REQUEST` minus the rid field per zenoh-pico
    /// `_z_push_encode`.
    pub const N_MID_PUSH: u8 = 0x1D;
    /// R91 — Response-final marker MID (network.h:38). Pure
    /// correlation marker closing a Request's reply stream per
    /// zenoh-pico `_z_response_final_encode`: 1-byte header +
    /// request_id VLE + optional ext-chain, no body.
    pub const N_MID_RESPONSE_FINAL: u8 = 0x1A;
    /// R92 — OAM (Operations & Maintenance) MID (network.h:33).
    /// Diagnostic / control-plane envelope per zenoh-pico
    /// `_z_oam_encode`: header (with mid, enc, Z bits) plus a VLE
    /// id, optional ext-chain, and a body variant dispatched on
    /// `header.enc` (UNIT / ZINT / ZBUF re-using ext_* inner
    /// codecs).
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
    /// R72b — monotonic `Instant` of the most recently observed
    /// inbound KeepAlive frame. Populated by `handle_inbound` for
    /// `InboundFrame::KeepAlive`. Consumers compare this against
    /// `params.lease` to compute the lease deadline; an absent
    /// timestamp falls back to session-start time (lease counts
    /// from Established entry per session-fsm §2.5 keepalive
    /// semantics).
    ///
    /// Resolution is `std::time::Instant`'s monotonic-since-process
    /// clock; the lease comparator is `now.duration_since(stamp) <
    /// lease`. No drift correction needed because both `now` and
    /// `stamp` read the same monotonic source.
    pub last_inbound_keepalive_at: Mutex<Option<Instant>>,
    /// R84 — monotonic `Instant` captured when the session FSM
    /// enters the `Established` state. Populated by the
    /// `record_established_at()` Lua action wired to the
    /// `Established.onentry` block in `session_fsm_unicast.scxml`.
    /// Consumers (specifically `check_lease_deadline`) fall back to
    /// this stamp when `last_inbound_keepalive_at` is `None` so a
    /// peer that never sends a KeepAlive after handshake still
    /// reaches `lease.expired -> Closing` per session-fsm §2.5
    /// ("lease counts from Established entry"); the prior R77
    /// behaviour was `NoBaseline` indefinitely in that case.
    ///
    /// Resolution and clock semantics match
    /// `last_inbound_keepalive_at` — both use `std::time::Instant`
    /// so the lease comparator subtracts them with a single
    /// monotonic source.
    pub established_at: Mutex<Option<Instant>>,
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
        match sn_res_byte {
            Some(b) => Self {
                seq_num_res: b & 0x03,
                req_id_res: (b >> 2) & 0x03,
                batch_size: batch_size.unwrap_or(65535),
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
    /// construction.
    pub fn new(driver: Arc<dyn BoxedLinkDriver>, params: SessionInitParams) -> Arc<Self> {
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
            params.batch_size = params.batch_size.min(p.batch_size);
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
            InboundFrame::Init { is_ack: true, body, .. } => {
                if let Some(cookie) = &body.cookie {
                    *self.inbound_cookie.lock().unwrap() = Some(cookie.clone());
                }
            }
            InboundFrame::Init { is_ack: false, body, .. } => {
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
            InboundFrame::Open { is_ack: false, body, .. } => {
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
            InboundFrame::KeepAlive { .. } => {
                // R72b — record receive time so the lease deadline
                // comparator (now - stamp < lease) advances. Reading
                // Instant::now() inside the lock keeps the captured
                // stamp synchronous with the wire-arrival moment.
                *self.last_inbound_keepalive_at.lock().unwrap() = Some(Instant::now());
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
    pub fn send_declare_keyexpr(&self, mapping_id: u64, suffix: &str) {
        let declare = build_declare_kexpr(mapping_id, suffix);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_declare_subscriber(
        &self,
        subscriber_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        let declare = build_declare_subscriber(subscriber_id, keyexpr_mapping_id, keyexpr_suffix);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_declare_queryable(
        &self,
        queryable_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        let declare = build_declare_queryable(queryable_id, keyexpr_mapping_id, keyexpr_suffix);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_declare_token(
        &self,
        token_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        let declare = build_declare_token(token_id, keyexpr_mapping_id, keyexpr_suffix);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_undeclare_kexpr(&self, mapping_id: u64) {
        let declare = build_undeclare_kexpr(mapping_id);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclSubscriber)` on
    /// the outbound link, retracting a previously declared
    /// subscription (id) on the peer. The peer drops the
    /// `subscriber_id -> keyexpr` entry from its subscriber table;
    /// subsequent matching Pushes will no longer route to this
    /// subscriber (the peer's other subscribers on the same keyexpr
    /// continue to receive).
    pub fn send_undeclare_subscriber(&self, subscriber_id: u64) {
        let declare = build_undeclare_subscriber(subscriber_id);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclQueryable)` on
    /// the outbound link, retracting a previously declared queryable
    /// (id) on the peer.
    pub fn send_undeclare_queryable(&self, queryable_id: u64) {
        let declare = build_undeclare_queryable(queryable_id);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
    }

    /// R121i-c — encode + dispatch a `Declare(UndeclToken)` on the
    /// outbound link, retracting a previously declared liveliness
    /// token (id) on the peer.
    pub fn send_undeclare_token(&self, token_id: u64) {
        let declare = build_undeclare_token(token_id);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
    }

    /// R121i-c — encode + dispatch a `Declare(DeclFinal)` marker on
    /// the outbound link, terminating a declaration sequence.
    /// Reserved for the future Interest/Reply path (R121j+); the
    /// unsolicited DECLARE outbound path that the AP MVP uses today
    /// does not emit DeclFinal, but the action is provided so the
    /// state machine has the dispatch shape ready when Interest
    /// replies need to close a multi-DECLARE reply batch.
    pub fn send_declare_final(&self) {
        let declare = build_declare_final();
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_declare(sn, declare, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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
    pub fn send_request_query(
        &self,
        rid: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
    ) {
        let request = build_request_query(rid, keyexpr_mapping_id, keyexpr_suffix);
        let sn = self.next_outbound_frame_sn();
        let wire = encode_frame_with_request(sn, request, /*reliable=*/ true);
        self.driver.send_blocking(&wire, Reliability::Reliable);
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

    bind_unit(lua, "send_init_syn", actions, |a| {
        a.trace.lock().unwrap().send_init_syn += 1;
        let bytes = a.encode_init_with_role(
            /*is_ack=*/ false,
            /*cookie_override=*/ None,
            ExtChainRole::InitSyn,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

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
        let cookie_hmac: Option<Vec<u8>> = a
            .inbound_peer_zid
            .lock()
            .unwrap()
            .as_ref()
            .map(|peer_zid| {
                generate_cookie_hmac_sha256(&a.params.cookie_signing_key, peer_zid)
            });
        let bytes = a.encode_init_with_role(
            /*is_ack=*/ true,
            cookie_hmac.as_deref(),
            ExtChainRole::InitAck,
        );
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

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
        *a.established_at.lock().unwrap() = Some(Instant::now());
    });
    bind_unit(lua, "start_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().start_lease_monitor += 1;
    });
    bind_unit(lua, "stop_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().stop_lease_monitor += 1;
    });
    bind_unit(lua, "start_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().start_keepalive_worker += 1;
    });
    bind_unit(lua, "stop_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().stop_keepalive_worker += 1;
    });
    bind_unit(lua, "free_pool_slots", actions, |a| {
        a.trace.lock().unwrap().free_pool_slots += 1;
    });
    bind_close_reason(lua, "set_close_reason_generic", actions, CloseReason::Generic);
    bind_close_reason(lua, "set_close_reason_invalid", actions, CloseReason::Invalid);
    bind_close_reason(lua, "set_close_reason_expired", actions, CloseReason::Expired);
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
        Some(cookie_override.map(|c| c.to_vec()).unwrap_or_else(|| params.cookie.clone()))
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
    let mut wire = Vec::with_capacity(body.zid.len() + params.cookie.len() + 12 + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_INIT);
    wire.extend_from_slice(&body.encode(parent_flags));
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
        cookie: if !is_ack { Some(cookie_bytes.to_vec()) } else { None },
    };

    let ext_bytes = encode_ext_chain(extensions);
    let mut wire = Vec::with_capacity(cookie_bytes.len() + 24 + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_OPEN);
    wire.extend_from_slice(&body.encode(parent_flags));
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
fn encode_ext_chain(entries: &[ExtEntry]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(entries.len() * 4);
    let last = entries.len() - 1;
    for (i, entry) in entries.iter().enumerate() {
        let mut bytes = entry.encode();
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
fn encode_close(reason: u8) -> Vec<u8> {
    let parent_flags = wire_const::FLAG_T_CLOSE_S;
    let body = Close { reason };
    let mut wire = Vec::with_capacity(2);
    wire.push(parent_flags | wire_const::T_MID_CLOSE);
    wire.extend_from_slice(&body.encode());
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
pub fn encode_frame_with_request(sn: u64, request: Request, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    let frame = Frame {
        sn,
        payload: request.encode(),
    };
    let body_bytes = frame.encode();
    let mut wire = Vec::with_capacity(body_bytes.len() + 1);
    wire.push(parent_flags | wire_const::T_MID_FRAME);
    wire.extend_from_slice(&body_bytes);
    wire
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
pub fn encode_frame_with_declare(sn: u64, declare: Declare, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    let frame = Frame {
        sn,
        payload: declare.encode(),
    };
    let body_bytes = frame.encode();
    let mut wire = Vec::with_capacity(body_bytes.len() + 1);
    wire.push(parent_flags | wire_const::T_MID_FRAME);
    wire.extend_from_slice(&body_bytes);
    wire
}

/// R121e — build the wire bytes for a `Frame` transport-message
/// (T_MID_FRAME) carrying a single `Push` network-message in its
/// payload.
///
/// Wire shape (composes the transport-envelope header byte that
/// lives outside the body codec's scope with `Frame.encode()`'s
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
/// The `Frame { sn, payload }.encode()` body is verified
/// byte-identical to zenoh-pico's `_z_frame_encode` by
/// `crates/wz-integration-tests/tests/layer3_frame.rs`. This
/// helper composes only the one transport header byte that
/// `Frame::encode` does not emit.
pub fn encode_frame_with_push(sn: u64, push: Push, reliable: bool) -> Vec<u8> {
    let parent_flags = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0u8
    };
    let frame = Frame {
        sn,
        payload: push.encode(),
    };
    let body_bytes = frame.encode();
    let mut wire = Vec::with_capacity(body_bytes.len() + 1);
    wire.push(parent_flags | wire_const::T_MID_FRAME);
    wire.extend_from_slice(&body_bytes);
    wire
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
    Init {
        is_ack: bool,
        has_ext: bool,
        body: InitBody,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_OPEN` (0x02). `is_ack` mirrors `_Z_FLAG_T_OPEN_A`;
    /// `lease_in_seconds` mirrors `_Z_FLAG_T_OPEN_T`.
    Open {
        is_ack: bool,
        lease_in_seconds: bool,
        has_ext: bool,
        body: OpenBody,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_CLOSE` (0x03). `reason` is the single body byte.
    Close {
        reason: u8,
        has_ext: bool,
        extensions: Vec<ExtEntry>,
    },
    /// `_Z_MID_T_KEEP_ALIVE` (0x04). Empty-body liveness ping; the
    /// only payload is the optional ext chain (Z flag-gated). The
    /// FSM uses receipt to reset the lease timer per
    /// session-fsm §2.5 keepalive_interval semantics.
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
pub fn parse_inbound(bytes: &[u8]) -> Result<InboundFrame, InboundParseError> {
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mid = header & 0x1F;
    let flags = header & 0xE0;
    let has_ext = (flags & wire_const::FLAG_T_Z) != 0;
    let mut cursor = SceCursor::new(&bytes[1..]);
    match mid {
        wire_const::T_MID_INIT => {
            let body = InitBody::decode(&mut cursor, flags)?;
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
        wire_const::T_MID_OPEN => {
            let body = OpenBody::decode(&mut cursor, flags)?;
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
        wire_const::T_MID_FRAME => {
            // sn first (VLE), then optional ext chain (Z-gated),
            // then tail payload to end of cursor.
            let sn = cursor
                .read_vle_u64()
                .map_err(InboundParseError::Codec)?;
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
            Ok(InboundFrame::KeepAlive { has_ext, extensions })
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
    Request(Box<Request>),
    /// R90 — Network MID `_Z_MID_N_PUSH` (0x1D). Pub/sub data
    /// carrier wrapping a put / del inner body — same envelope
    /// shape as `Request` minus the rid field. The `Box` mirrors
    /// the `Request` variant's size-balancing rationale.
    Push(Box<Push>),
    /// R91 — Network MID `_Z_MID_N_RESPONSE_FINAL` (0x1A). Pure
    /// correlation marker that closes a Request's reply stream;
    /// payload is header + request_id VLE only (no embed, no
    /// inner body). Inlined (no `Box`) because the struct is
    /// small — just three integer fields plus an optional ext
    /// vec.
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
            Self::Request(_) => f.write_str("Request(..)"),
            Self::Push(_) => f.write_str("Push(..)"),
            Self::ResponseFinal(_) => f.write_str("ResponseFinal(..)"),
            Self::Oam(_) => f.write_str("Oam(..)"),
            Self::Interest(_) => f.write_str("Interest(..)"),
            Self::Response(_) => f.write_str("Response(..)"),
            Self::Declare(_) => f.write_str("Declare(..)"),
            Self::Unknown { mid, body } => write!(
                f,
                "Unknown {{ mid: {mid:#04x}, body_len: {} }}",
                body.len()
            ),
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
pub fn parse_frame_payload(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        let header = cursor.peek_slice(1)?[0];
        let mid = header & 0x1F;
        match mid {
            wire_const::N_MID_REQUEST => {
                let req = Request::decode(&mut cursor)?;
                messages.push(NetworkMessage::Request(Box::new(req)));
            }
            wire_const::N_MID_PUSH => {
                let push = Push::decode(&mut cursor)?;
                messages.push(NetworkMessage::Push(Box::new(push)));
            }
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
            wire_const::N_MID_RESPONSE => {
                let resp = Response::decode(&mut cursor)?;
                messages.push(NetworkMessage::Response(Box::new(resp)));
            }
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
        InboundFrame::Init { is_ack: false, .. } => Some(E::InitSynReceived),
        InboundFrame::Init { is_ack: true, .. } => Some(E::InitAckReceived),
        InboundFrame::Open { is_ack: false, .. } => Some(E::OpenSynReceived),
        InboundFrame::Open { is_ack: true, .. } => Some(E::OpenAckReceived),
        InboundFrame::Close { .. } => Some(E::PeerClose),
        InboundFrame::KeepAlive { .. } => None,
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
                    InboundFrame::KeepAlive { .. } => DriverLoopOutcome::SideEffectOnly,
                    InboundFrame::Init { .. }
                    | InboundFrame::Open { .. }
                    | InboundFrame::Close { .. }
                    | InboundFrame::Unknown { .. } => {
                        // inbound_to_fsm_event projects these to Some(event),
                        // so the outer Some arm handled them — this branch
                        // is unreachable.
                        unreachable!(
                            "inbound_to_fsm_event None branch is Frame/KeepAlive only"
                        )
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
/// `now` is parameterised for test determinism. Production callers
/// pass `Instant::now()`; tests stage a stamp via
/// `last_inbound_keepalive_at` and pass `stamp + offset` as `now`
/// so `duration_since` is deterministic without depending on
/// wall-clock progression during the test.
///
/// `params.lease_in_seconds` picks the integer unit per the
/// `_Z_FLAG_T_OPEN_T` wire semantics; the comparator converts the
/// integer through the matching `Duration` constructor before the
/// `>=` check.
pub fn check_lease_deadline(
    actions: &Arc<SessionLinkActions>,
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy>,
    now: Instant,
) -> LeaseCheckOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    let lease = if actions.params.lease_in_seconds {
        Duration::from_secs(actions.params.lease)
    } else {
        Duration::from_millis(actions.params.lease)
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
        Some(stamp) if now.duration_since(stamp) >= lease => {
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
pub async fn drive_session_until_terminal<D, F>(
    driver: &mut D,
    actions: &Arc<SessionLinkActions>,
    engine: &mut Engine<crate::session_fsm_unicast::SessionFsmUnicastPolicy>,
    max_iters: Option<usize>,
    mut on_event: F,
) -> DriverOutcome
where
    D: LinkDriver,
    F: FnMut(IterationEvent<'_>),
{
    let lease = if actions.params.lease_in_seconds {
        Duration::from_secs(actions.params.lease)
    } else {
        Duration::from_millis(actions.params.lease)
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
        let lease_deadline = {
            let stamp = *actions.last_inbound_keepalive_at.lock().unwrap();
            stamp.map(|s| s + lease)
        };
        match lease_deadline {
            Some(deadline) => {
                let now = Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                tokio::select! {
                    outcome = poll_and_dispatch_one(driver, actions, engine) => {
                        on_event(IterationEvent::Poll(&outcome));
                    }
                    _ = tokio::time::sleep(remaining) => {
                        let lease_outcome =
                            check_lease_deadline(actions, engine, Instant::now());
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
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        ScriptValue::Bool(value)
    });
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
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
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
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
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
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
            0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
            0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
            0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
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
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
            0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
            0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
            0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
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
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
            0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b,
            0xfa, 0x6f, 0x7c, 0x0a, 0x6a, 0x8a, 0xef, 0x8b,
            0x93, 0xf8, 0x60, 0xaa, 0xb0, 0xcd, 0x20, 0xc5,
        ];
        assert_eq!(full, expected_full, "RFC 4231 TC5 full MAC");
        // First 16 bytes — the cookie wire-shape truncation
        // matches RFC §4.5 96/128-bit MAC truncation. Asserts
        // that generate_cookie_hmac_sha256's slice [..16] yields
        // exactly the RFC truncated form.
        let expected_truncated: [u8; 16] = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
            0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b,
        ];
        assert_eq!(&full[..16], expected_truncated.as_slice(), "RFC 4231 TC5 truncated");
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
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
            0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
            0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
            0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
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
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
            0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
            0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
            0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC7 byte mismatch");
    }

    /// init_cbyte must match zenoh-pico's transport.c:189-192
    /// packing exactly — Layer 3 byte-equiv depends on this.
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
                assert!(put.extensions.is_none(), "no MsgPut-level extensions on the MVP path");
            }
            other => panic!("MVP build_push_literal must emit MsgPut body, got {:?}", match other {
                PushVariant::CodecZenohMsgDel(_) => "MsgDel",
                PushVariant::Default { .. } => "Default",
                PushVariant::CodecZenohMsgPut(_) => unreachable!(),
            }),
        }
        assert!(push.extensions.is_none(), "no Push-level extensions on the MVP path");
    }

    /// `encode_frame_with_push` composes the transport-envelope
    /// header byte (T_MID_FRAME | parent_flags) with the
    /// `Frame.encode()` body (VLE(sn) + payload). With reliable=true
    /// the FLAG_T_FRAME_R bit appears in the header byte.
    #[test]
    fn encode_frame_with_push_emits_transport_header_plus_frame_body() {
        // Empty-payload Push at sn=0 keeps the assertion focused on
        // the transport-envelope header byte and the Frame body
        // shape. Push::default()'s wire bytes are independently
        // pinned by layer3_push.rs's byte-equiv test.
        let push = Push::default();
        let push_bytes = push.encode();

        // Reliable Frame at sn=0.
        let wire_reliable = encode_frame_with_push(0, Push::default(), true);
        assert_eq!(
            wire_reliable[0],
            wire_const::FLAG_T_FRAME_R | wire_const::T_MID_FRAME,
            "reliable Frame must set FLAG_T_FRAME_R (0x20) on the parent header byte"
        );
        // Body shape: VLE(sn=0) = single byte 0x00, followed by
        // Push.encode() bytes verbatim.
        assert_eq!(wire_reliable[1], 0x00, "Frame.sn=0 VLE width = 1 byte 0x00");
        assert_eq!(
            &wire_reliable[2..],
            push_bytes.as_slice(),
            "tail of Frame envelope must be the Push.encode() bytes byte-for-byte"
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
                InboundFrame::Frame { sn: parsed_sn, reliable, .. } => {
                    assert_eq!(parsed_sn, sn, "sn must round-trip through encode+parse");
                    assert!(reliable, "reliable=true → FLAG_T_FRAME_R → InboundFrame.reliable=true");
                }
                // InboundFrame intentionally omits Debug derive
                // (sce-codegen wz-codecs structs only derive
                // Default, so a wrapping `#[derive(Debug)]` here
                // would not compile). Fall back to a variant-name
                // string for the panic.
                other => panic!(
                    "encode_frame_with_push must produce an InboundFrame::Frame; got {}",
                    match other {
                        InboundFrame::Init { .. } => "Init",
                        InboundFrame::Open { .. } => "Open",
                        InboundFrame::Close { .. } => "Close",
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
        assert!(declare.interest_id.is_none(), "MVP DECLARE has no interest_id");
        assert!(declare.extensions.is_none(), "MVP DECLARE has no extensions");
        match &declare.body {
            DeclareVariant::CodecZenohDeclKexpr(dk) => {
                assert_eq!(dk.id, 7, "DeclKexpr.id must equal mapping_id argument");
                assert_eq!(
                    dk.header, 0x20,
                    "DeclKexpr.header must carry _Z_DECL_KEXPR_FLAG_N (0x20)"
                );
                match &dk.keyexpr.body {
                    WireexprVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "inner Wireexpr.id is the literal-keyexpr sentinel 0");
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
    /// `build_declare_kexpr(7, "demo/test").encode()` must equal
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
        let outer = declare.encode();
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
    /// `[parent_flags | T_MID_FRAME]` + `Frame.encode()` wrapping
    /// as `encode_frame_with_push`, with `Declare.encode()` as the
    /// inner payload bytes. Reliable / best-effort header flag
    /// behaviour mirrors the Push variant.
    #[test]
    fn encode_frame_with_declare_wraps_declare_in_frame_envelope() {
        let declare = build_declare_kexpr(7, "demo/test");
        let declare_bytes = declare.encode();

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
            "Frame body tail must be Declare.encode() bytes verbatim",
        );

        let wire_best_effort = encode_frame_with_declare(0, build_declare_kexpr(7, "demo/test"), false);
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
                assert_eq!(d.header, 0x22, "header MID 0x02 | N(0x20) when suffix present");
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
    /// `build_declare_subscriber(5, 7, None).encode()` must equal
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
        let alias_wire = alias.encode();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x42,                       // MID(0x02) | M(0x40)
            0x05,                       // VLE(subscriber_id=5)
            0x07,                       // wireexpr.id VLE(7)
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
        let composite_wire = composite.encode();
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
        let literal_wire = literal.encode();
        let mut literal_expected = vec![
            wire_const::N_MID_DECLARE,
            0x62,
            0x05,
            0x00,
            0x09,
        ];
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
                assert_eq!(d.header, 0x24, "header MID 0x04 | N(0x20) when suffix present");
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
    /// `build_declare_queryable(...).encode()` must equal zenoh-pico's
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
        let alias_wire = alias.encode();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x44,                       // MID(0x04) | M(0x40)
            0x09,                       // VLE(queryable_id=9)
            0x07,                       // wireexpr.id VLE(7)
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
        let composite_wire = composite.encode();
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
        let literal_wire = literal.encode();
        let mut literal_expected = vec![
            wire_const::N_MID_DECLARE,
            0x64,
            0x09,
            0x00,
            0x09,
        ];
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
    /// `build_declare_token(...).encode()` must equal zenoh-pico's
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
        let alias_wire = alias.encode();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x46,                       // MID(0x06) | M(0x40)
            0x0B,                       // VLE(token_id=11)
            0x07,                       // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "DeclToken alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc").
        let composite = build_declare_token(11, 7, Some("abc"));
        let composite_wire = composite.encode();
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
        let literal_wire = literal.encode();
        let mut literal_expected = vec![
            wire_const::N_MID_DECLARE,
            0x66,
            0x0B,
            0x00,
            0x09,
        ];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "DeclToken literal-case wire bytes must match zenoh-pico reference"
        );
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
        let small_wire = small.encode();
        let small_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer
            0x01,                       // _Z_UNDECL_KEXPR_MID
            0x2A,                       // VLE(42) single byte
        ];
        assert_eq!(
            small_wire, small_expected,
            "UndeclKexpr small-id wire bytes must match zenoh-pico reference"
        );

        // Case 2 — multi-byte VLE id (id=200 crosses the 7-bit
        // boundary; first byte = 0xC8 (low 7 bits 0x48 + cont 0x80),
        // second byte = 0x01).
        let large = build_undeclare_kexpr(200);
        let large_wire = large.encode();
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
        let small_wire = small.encode();
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
        let large_wire = large.encode();
        assert_eq!(
            large_wire,
            vec![
                wire_const::N_MID_DECLARE,
                0x03,
                0xC8,
                0x01,
            ],
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
            small.encode(),
            vec![
                wire_const::N_MID_DECLARE,
                0x05, // _Z_UNDECL_QUERYABLE_MID
                0x2A,
            ],
            "UndeclQueryable small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_queryable(200);
        assert_eq!(
            large.encode(),
            vec![
                wire_const::N_MID_DECLARE,
                0x05,
                0xC8,
                0x01,
            ],
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
            small.encode(),
            vec![
                wire_const::N_MID_DECLARE,
                0x07, // _Z_UNDECL_TOKEN_MID
                0x2A,
            ],
            "UndeclToken small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_token(200);
        assert_eq!(
            large.encode(),
            vec![
                wire_const::N_MID_DECLARE,
                0x07,
                0xC8,
                0x01,
            ],
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
        let wire = declare.encode();
        assert_eq!(
            wire,
            vec![
                wire_const::N_MID_DECLARE, // 0x1E outer
                0x1A,                       // _Z_DECL_FINAL_MID inner
            ],
            "DeclFinal wire must equal [N_MID_DECLARE, _Z_DECL_FINAL_MID]",
        );

        match &declare.body {
            DeclareVariant::CodecZenohDeclFinal(d) => {
                assert_eq!(d.header, 0x1A, "DeclFinal.header must equal _Z_DECL_FINAL_MID");
            }
            _ => panic!("build_declare_final must produce CodecZenohDeclFinal"),
        }
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
            alias.header,
            0x1C,
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
        assert!(alias.extensions.is_none(), "minimal shape: no Request-level exts");
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
        assert_eq!(literal.header, 0x3C, "literal case still sets N (suffix present)");
        match &literal.keyexpr.body {
            WireexprVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 0, "literal sentinel id=0");
                assert_eq!(w.suffix.as_deref(), Some("demo/test"));
            }
            _ => panic!(),
        }
    }

    /// R121j-1 — Wire-byte regression gate: the bytes emitted by
    /// `build_request_query(...).encode()` must equal zenoh-pico's
    /// `_z_request_encode` + `_z_query_encode` output for the
    /// minimal-shape inputs (no consolidation, no params, no exts at
    /// either level). Three vectors lock the alias / composite /
    /// literal trio:
    ///
    /// References:
    ///   - `_z_request_encode` (vendor/zenoh-pico/src/protocol/codec/network.c:114-169)
    ///     — emits `[header | N | M | Z=0]`, `VLE(rid)`, `wireexpr.encode`,
    ///       and switches into `_z_query_encode` for `_Z_REQUEST_QUERY`.
    ///   - `_z_query_encode` (vendor/zenoh-pico/src/protocol/codec/message.c:394-451)
    ///     — emits `[header | C | P | Z]` then optional consolidation /
    ///       params / exts. In the minimal shape only the header byte
    ///       (0x03) is emitted.
    #[test]
    fn build_request_query_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (rid=42, mapping_id=7, no suffix).
        // Wire shape:
        //   Request.header = MID(0x1C) | M(0x40) = 0x5C
        //   VLE(rid=42)     = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   Query.header   = MID(0x03)
        let alias = build_request_query(42, 7, None);
        let alias_wire = alias.encode();
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
        let composite_wire = composite.encode();
        let mut composite_expected = vec![
            0x7C, // MID | N | M
            0x2A,
            0x07,
            0x03,
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
        let literal_wire = literal.encode();
        let mut literal_expected = vec![
            0x7C,
            0x2A,
            0x00,
            0x09,
        ];
        literal_expected.extend_from_slice(b"demo/test");
        literal_expected.push(0x03); // Query MID
        assert_eq!(
            literal_wire, literal_expected,
            "Request(Query) literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121j-1 — `encode_frame_with_request` produces the same
    /// `[parent_flags | T_MID_FRAME]` + `Frame.encode()` wrapping as
    /// the existing `encode_frame_with_push` / `encode_frame_with_declare`
    /// helpers, with `Request.encode()` as the inner payload bytes.
    /// Reliable / best-effort header-flag behaviour mirrors the other
    /// two helpers so the SN-window ordering contract stays uniform
    /// across PUSH / DECLARE / REQUEST outbound paths.
    #[test]
    fn encode_frame_with_request_wraps_request_in_frame_envelope() {
        let request = build_request_query(42, 7, None);
        let request_bytes = request.encode();

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
            "Frame body tail must be Request.encode() bytes verbatim",
        );

        let wire_best_effort = encode_frame_with_request(0, build_request_query(42, 7, None), false);
        assert_eq!(
            wire_best_effort[0],
            wire_const::T_MID_FRAME,
            "best-effort Frame must omit FLAG_T_FRAME_R",
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
        let actions = SessionLinkActions::new(Arc::new(NullDriver), params);
        assert_eq!(actions.next_outbound_frame_sn(), 42, "first SN must equal params.initial_sn");
        assert_eq!(actions.next_outbound_frame_sn(), 43, "subsequent SNs must increment by 1");
        assert_eq!(actions.next_outbound_frame_sn(), 44);
    }
}
