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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use sce_rust_runtime::scripting::{IScriptEngine, NativeMethod, ScriptValue};
use sce_rust_runtime::Engine;

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::close::Close;
use wz_codecs::ext_entry::ExtEntry;
use wz_codecs::init_body::InitBody;
use wz_codecs::keep_alive::KeepAlive;
use wz_codecs::open_body::OpenBody;
use wz_codecs::request::Request;

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
    /// network MID since `wz_codecs::request` is the only authored
    /// envelope codec — additional MIDs (PUSH 0x1D, RESPONSE 0x1B,
    /// DECLARE 0x1E, OAM 0x1F, RESPONSE_FINAL 0x1A, INTEREST 0x19
    /// per network.h:33-39) are documented in [`NetworkMessage`] and
    /// will land alongside their respective envelope codecs in
    /// follow-up rounds.
    pub const N_MID_REQUEST: u8 = 0x1C;
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
    /// R68b — per-role ext chain slots. Indexed by `ExtChainRole`
    /// via `ext_chain_for`. Each slot lives behind its own `Mutex`
    /// so a setter can swap one chain without blocking the others
    /// (e.g. mid-handshake auth-step rotation can rewrite the
    /// OpenSyn chain without touching the InitSyn record).
    init_syn_ext: Mutex<Vec<ExtEntry>>,
    init_ack_ext: Mutex<Vec<ExtEntry>>,
    open_syn_ext: Mutex<Vec<ExtEntry>>,
    open_ack_ext: Mutex<Vec<ExtEntry>>,
}

impl SessionLinkActions {
    /// Construct a session action bundle for one logical FSM instance.
    /// The `params` are captured by value; production callers
    /// supplying per-deploy values stage them once at session
    /// construction.
    pub fn new(driver: Arc<dyn BoxedLinkDriver>, params: SessionInitParams) -> Arc<Self> {
        Arc::new(Self {
            driver,
            params,
            trace: Mutex::new(ActionTrace::default()),
            inbound_cookie: Mutex::new(None),
            last_inbound_keepalive_at: Mutex::new(None),
            init_syn_ext: Mutex::new(Vec::new()),
            init_ack_ext: Mutex::new(Vec::new()),
            open_syn_ext: Mutex::new(Vec::new()),
            open_ack_ext: Mutex::new(Vec::new()),
        })
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
    pub fn encode_init_with_role(&self, is_ack: bool, role: ExtChainRole) -> Vec<u8> {
        let chain = self.ext_chain_slot(role).lock().unwrap();
        encode_init(&self.params, is_ack, &chain)
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
    register_guard_fns(script_engine.as_ref());
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
        let bytes = a.encode_init_with_role(/*is_ack=*/ false, ExtChainRole::InitSyn);
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
        // Accepting-side cookie material flows through params.cookie.
        // Production callers MUST populate it via
        // `generate_cookie_hmac_sha256(params.cookie_signing_key,
        //  peer_zid_from_inbound_InitSyn)` before install; the
        // Accepting side's per-handshake nonce / peer_zid binding
        // is the production caller's responsibility because session
        // FSM state (incoming peer_zid) is not yet propagated into
        // SessionLinkActions in R62 — inbound parser pass is a
        // later round.
        let bytes = a.encode_init_with_role(/*is_ack=*/ true, ExtChainRole::InitAck);
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
pub fn register_guard_fns(lua: &dyn IScriptEngine) {
    // R57 baseline: guard expressions always return true so the
    // accept-side hardening + cookie validation transitions advance
    // for the integration test. Cap quota / token-bucket / cookie
    // HMAC actual checks are RFC §5.M concerns and bind in a later
    // round (R58+) when the security-relevant state-keeping moves
    // out of placeholder territory.
    bind_bool(lua, "half_open_cap_available", true);
    bind_bool(lua, "accept_rate_token", true);
    bind_bool(lua, "cookie_valid", true);
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
) -> Vec<u8> {
    let mut parent_flags = wire_const::FLAG_T_INIT_S;
    if is_ack {
        parent_flags |= wire_const::FLAG_T_INIT_A;
    }
    if !extensions.is_empty() {
        parent_flags |= wire_const::FLAG_T_Z;
    }

    let cbyte = init_cbyte(params.whatami, params.zid.len());
    let body = InitBody {
        version: params.version,
        cbyte,
        zid: params.zid.clone(),
        sn_res: Some(pack_sn_res(params.seq_num_res, params.req_id_res)),
        batch_size: Some(params.batch_size),
        cookie_len: if is_ack {
            Some(params.cookie.len() as u64)
        } else {
            None
        },
        cookie: if is_ack { Some(params.cookie.clone()) } else { None },
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
    /// Header byte's MID falls outside the {REQUEST} subset wz-codecs
    /// has authored envelope coverage for. `body` carries the rest of
    /// the payload bytes (header byte included) verbatim so a future
    /// per-MID decoder can re-parse without losing data; the parse
    /// stops here to avoid mis-cursor-advancing across an unknown body
    /// length.
    Unknown { mid: u8, body: Vec<u8> },
}

impl std::fmt::Debug for NetworkMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(_) => f.write_str("Request(..)"),
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
/// `SessionLinkActions::last_inbound_keepalive_at`.
///
/// Three branches model the trichotomy the production driver needs
/// to dispatch on: stamp absent (no inbound KeepAlive observed yet,
/// lease decision deferred); stamp + lease > now (within the
/// window); stamp + lease <= now (helper has already injected
/// `LeaseExpired`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCheckOutcome {
    /// `last_inbound_keepalive_at` is `None`. The helper makes no
    /// decision and does NOT inject `LeaseExpired`. The production
    /// caller treats this as "still polling" until the first peer
    /// KeepAlive arrives.
    ///
    /// Carry: session-fsm §2.5 specifies that the lease counts
    /// from Established entry, but the runtime does not yet record
    /// an `established_at` Instant on `SessionLinkActions`. A
    /// follow-up round wires that hook; R77 honours R72b's design
    /// that only inbound KeepAlive populates the slot.
    NoBaseline,
    /// `now.duration_since(stamp) < params.lease`. The helper
    /// performed no FSM mutation; engine state is unchanged.
    WithinLease,
    /// `now.duration_since(stamp) >= params.lease`. The helper has
    /// invoked `engine.process_event(SessionFsmUnicastEvent::LeaseExpired)`
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
    let stamp = *actions.last_inbound_keepalive_at.lock().unwrap();
    match stamp {
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
}
