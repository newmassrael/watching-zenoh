// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `ze_advanced_*` — the ADVANCED pub/sub plane at the zenoh-c ABI.
//!
//! ## Why this module exists ONLY on the unstable arms
//!
//! Every type and function below is `#if defined(Z_FEATURE_UNSTABLE_API)` in
//! upstream's header (`zenoh_commons.h:1003`, `1069`, `1163`, `1228`, `5674`,
//! `6011`, `6029`). A build without that define does not declare them at all,
//! so exporting them there would put symbols in the cdylib that no program
//! compiled against that header can name — a surface with nothing to check it.
//! The crate mirrors upstream's `#if` with a `cfg` on the module in
//! [`crate`](crate), which is also why the layout table splits into a base half
//! and an unstable half: on the no-unstable arm there is no upstream size to
//! compare against.
//!
//! ## Nothing here is new protocol — the mechanism is the SHARED core
//!
//! wz already owns advanced pub/sub
//! ([`wz_runtime_tokio::advanced_publisher`] / [`wz_runtime_tokio::advanced_subscriber`],
//! graded against zenoh-ext), and `wz-capi-core`'s face registry already fans a
//! declaration out per face and replays it onto every future face. The sibling
//! `wz-capi-pico` binds the same core through pico's spelling
//! (`crates/wz-capi-pico/src/advanced.rs`). This module is the zenoh-c spelling
//! of that same plane: different struct sizes, different symbol names, one
//! implementation underneath.
//!
//! The per-face fan-out is load-bearing rather than uniform here. An advanced
//! publisher declares its OWN `@adv` cache queryable and `@adv` liveliness token
//! on the session it binds to, so a per-face declaration is the only shape in
//! which a subscriber's recovery GET can reach the cache at all.
//!
//! ## The two ABIs' option structs are NOT the same shape
//!
//! pico's `ze_advanced_subscriber_options_t` embeds a one-byte dummy for its
//! subscriber options; zenoh-c's embeds a real
//! [`z_subscriber_options_t`](crate::sub::z_subscriber_options_t) whose single
//! `allowed_origin` field is four bytes. So the two are 80 and 88 bytes
//! respectively and neither file may copy the other's numbers. Every struct here
//! is therefore MIRRORED FIELD FOR FIELD from upstream's header and Rust computes
//! the layout — the same discipline [`crate::publisher`] documents, and the
//! reason the layout gate can measure them against a C compiler instead of
//! against a transcription.
//!
//! ## The miss listener is installed AFTER the subscriber
//!
//! Upstream's `z_advanced_sub.c` declares the subscriber first and
//! `ze_advanced_subscriber_declare_background_sample_miss_listener` second, but
//! wz's `AdvancedSubscriber` takes both callbacks up front. So the subscriber is
//! declared with an `on_miss` that reads a shared slot and the listener fills
//! that slot. The slot is the mechanism that makes upstream's ordering work; it
//! is not a placeholder.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_runtime_tokio::advanced_cache::CacheConfig;
use wz_runtime_tokio::advanced_publisher::{
    AdvancedPublisherOptions, MissDetectionConfig, Sequencing,
};
use wz_runtime_tokio::advanced_subscriber::{
    AdvancedSubscriberOptions, HistoryConfig, Miss, RecoveryConfig,
};
use wz_runtime_tokio::sample::Sample;
use wz_runtime_tokio::sink::SampleView;

use crate::abi::{
    z_closure_drop_callback_t, z_loaned_keyexpr_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_sample_t, z_owned_closure_sample_t, z_owned_subscriber_t, Handle,
};
use crate::bytes::take_payload;
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::publisher::{z_publisher_options_t, z_publisher_put_options_t};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::sub::{subscriber_state_handle, z_subscriber_options_t, CClosure};
use crate::zid::{z_id_t, Z_ID_SIZE};

use wz_capi_core::faces::{AdvPubId, AdvSubId, SharedSession};

/// `true` when this build targets a zenoh-c compiled WITH
/// `Z_FEATURE_SHARED_MEMORY`. The advanced PUBLISHER is one of the types that
/// moves with it (224 without, 232 with — measured by upstream's own opaque-type
/// generator under zenoh-c's pinned toolchain; see
/// `scripts/check-capi-c-opaque-arms.sh`), and the advanced SUBSCRIBER is not.
const SHM: bool = cfg!(feature = "zenoh-c-shared-memory");

/// `ze_owned_advanced_publisher_t` / `ze_loaned_advanced_publisher_t`.
const ADV_PUB_SIZE: usize = if SHM { 232 } else { 224 };
/// `ze_owned_advanced_subscriber_t` — unmoved by either axis.
const ADV_SUB_SIZE: usize = 152;
/// `ze_owned_sample_miss_listener_t` — three pointers.
const MISS_LISTENER_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// entity global id
// ---------------------------------------------------------------------------

/// zenoh-c `z_entity_global_id_t` (`zenoh_opaque.h:522-524`): 20 bytes at
/// ALIGNMENT 4.
///
/// Opaque upstream, but the alignment is the tell — 4, not 8 — and a
/// `{ z_id_t; uint32_t }` is exactly what produces it: [`z_id_t`] is a bare
/// `uint8_t[16]` so it contributes alignment 1, and the `eid` alone sets the
/// struct's alignment. It crosses the boundary BY VALUE inside [`ze_miss_t`] and
/// as [`z_entity_global_id_zid`]'s argument, so both facts are ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_entity_global_id_t {
    /// The zid half.
    pub zid: z_id_t,
    /// The entity id half.
    pub eid: u32,
}

impl z_entity_global_id_t {
    /// The EMPTY id a gravestoned entity reports.
    ///
    /// R311y568 — named once. Five accessors now answer this question
    /// (`z_publisher_id` / `z_subscriber_id` / `z_queryable_id` /
    /// `z_querier_id` / the `ze_advanced_*` pair), and each of them needs the
    /// empty value on TWO paths — the panic fallback and the null-handle arm —
    /// so open-coding it would be ten copies of one literal.
    pub(crate) fn empty() -> Self {
        Self {
            zid: z_id_t::empty(),
            eid: 0,
        }
    }

    /// The id for an entity of `shared` whose per-entity identity is the
    /// address `handle`.
    ///
    /// The zid half is the SESSION's, which is what upstream reports too — a
    /// publisher or subscriber is not a separate node. The eid half is the
    /// handle's own address, narrowed: a per-entity value that is stable for the
    /// entity's life and distinct between live entities, which is the whole
    /// contract an entity id carries here.
    pub(crate) fn for_entity(
        shared: &wz_capi_core::faces::SharedSession,
        handle: *const std::ffi::c_void,
    ) -> Self {
        Self {
            zid: z_id_t { id: shared.zid() },
            eid: (handle as usize as u64 & u64::from(u32::MAX)) as u32,
        }
    }
}

/// The zid half of a global entity id (zenoh-c `z_entity_global_id_zid`,
/// `zenoh_commons.h:2643`).
///
/// # Safety
/// `this_` must be null or a valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_zid(this_: *const z_entity_global_id_t) -> z_id_t {
    guard_val(z_id_t::empty(), || {
        if this_.is_null() {
            return z_id_t::empty();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).zid }
    })
}

/// The entity-id half of a global entity id (zenoh-c `z_entity_global_id_eid`,
/// `zenoh_commons.h:2635`).
///
/// # Safety
/// `this_` must be null or a valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_eid(this_: *const z_entity_global_id_t) -> u32 {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).eid }
    })
}

// ---------------------------------------------------------------------------
// the miss closure
// ---------------------------------------------------------------------------

/// zenoh-c `ze_miss_t` (`zenoh_commons.h:1112-1121`) — 24 bytes at align 4.
#[repr(C)]
pub struct ze_miss_t {
    /// The source of the missed samples.
    pub source: z_entity_global_id_t,
    /// How many samples were missed.
    pub nb: u32,
}

/// The C callback a miss closure carries (`zenoh_commons.h:1132`).
pub type ze_closure_miss_callback_t =
    Option<unsafe extern "C" fn(miss: *const ze_miss_t, context: *mut c_void)>;

/// Owned miss closure (zenoh-c `ze_owned_closure_miss_t`) — TRANSPARENT
/// upstream, so it matches field for field, exactly as the sample closure does.
#[repr(C)]
pub struct ze_owned_closure_miss_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: ze_closure_miss_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned miss closure — the same three fields; `ze_closure_miss_loan` is a
/// pointer cast upstream.
#[repr(C)]
pub struct ze_loaned_closure_miss_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: ze_closure_miss_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved miss closure (zenoh-c `ze_moved_closure_miss_t`).
#[repr(C)]
pub struct ze_moved_closure_miss_t {
    pub(crate) _this: ze_owned_closure_miss_t,
}

impl ze_owned_closure_miss_t {
    /// The gravestone: no context, no callbacks.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper a miss listener holds — this plane's instantiation of
/// the shared [`crate::ffi::CClosure`] drop-once mechanism.
pub(crate) type CMissClosure = FfiClosure<ze_closure_miss_callback_t>;

// SAFETY: the same argument `crate::sub` makes for the sample closure, and it
// has to be made again rather than inherited, because the plane is different.
//
// A miss is raised on the session's drive task and nowhere else: the recovery
// machinery detects a sequence gap while DECODING an inbound sample, so the only
// caller of `call` is the same single task that dispatches samples. The C
// application thread never raises one — `ze_advanced_publisher_put` fans out
// `Locality::Remote` publishes (see `crate::put`), so it stages no loopback fire
// and drains no callback. `drop` runs only when the last `Arc` is released,
// which cannot overlap a live `call` because a running callback holds a
// reference.
unsafe impl Sync for CMissClosure {}

/// Construct a miss closure from its parts (zenoh-c `ze_closure_miss`,
/// `zenoh_commons.h:5965-5968`).
///
/// Note upstream's argument ORDER — `(this_, call, drop, context)` — which is not
/// the struct's field order; the `z_closure` macro dispatches here.
///
/// # Safety
/// `this_` must be valid and writable. `call` / `drop` must be null or valid C
/// function pointers, and `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss(
    this_: *mut ze_owned_closure_miss_t,
    call: ze_closure_miss_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = ze_owned_closure_miss_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Zero an owned miss closure (zenoh-c `ze_internal_closure_miss_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_closure_miss_null(this_: *mut ze_owned_closure_miss_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_closure_miss_t::null_value() };
    }
}

/// `true` iff the owned miss closure carries a callback (zenoh-c
/// `ze_internal_closure_miss_check`).
///
/// # Safety
/// `this_` must be null or a valid owned miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_closure_miss_check(
    this_: *const ze_owned_closure_miss_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).call }.is_some()
    })
}

/// Borrow a miss closure (zenoh-c `ze_closure_miss_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_loan(
    this_: *const ze_owned_closure_miss_t,
) -> *const ze_loaned_closure_miss_t {
    this_ as *const ze_loaned_closure_miss_t
}

/// Invoke a miss closure directly (zenoh-c `ze_closure_miss_call`,
/// `zenoh_commons.h:5976-5977`). A gravestone closure is a documented no-op.
///
/// # Safety
/// `closure` must be null or a valid loaned miss closure; `miss` must be null or
/// a valid miss value.
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_call(
    closure: *const ze_loaned_closure_miss_t,
    miss: *const ze_miss_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let (call, ctx) = unsafe { ((*closure).call, (*closure).context) };
        let Some(call) = call else {
            return;
        };
        // SAFETY: the caller's contract; an unwind across `extern "C"` is UB.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(miss, ctx);
        }));
    });
}

/// Drop a miss closure that was never installed (zenoh-c
/// `ze_closure_miss_drop`): run the C `drop(context)` and null the struct.
///
/// # Safety
/// `closure_` must be null or a valid moved miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_drop(closure_: *mut ze_moved_closure_miss_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once, and an unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = ze_owned_closure_miss_t::null_value();
        Z_OK
    });
}

// ---------------------------------------------------------------------------
// advanced publisher
// ---------------------------------------------------------------------------

/// zenoh-c `ze_advanced_publisher_heartbeat_mode_t` — a plain C enum, so an
/// `int`.
pub type ze_advanced_publisher_heartbeat_mode_t = std::ffi::c_int;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE` = 0, also the default.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE: ze_advanced_publisher_heartbeat_mode_t = 0;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC` = 1.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC: ze_advanced_publisher_heartbeat_mode_t = 1;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_SPORADIC` = 2.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_SPORADIC: ze_advanced_publisher_heartbeat_mode_t = 2;

/// zenoh-c `ze_advanced_publisher_cache_options_t` (`zenoh_commons.h:1004-1025`).
#[repr(C)]
pub struct ze_advanced_publisher_cache_options_t {
    /// Must be `true` for the cache to exist.
    pub is_enabled: bool,
    /// How many samples to keep per resource.
    pub max_samples: usize,
    /// Congestion control applied to cache replies.
    pub congestion_control: crate::publisher::z_congestion_control_t,
    /// Priority of cache replies.
    pub priority: crate::publisher::z_priority_t,
    /// Bypass batching for cache replies.
    pub is_express: bool,
}

/// zenoh-c `ze_advanced_publisher_sample_miss_detection_options_t`
/// (`zenoh_commons.h:1048-1062`).
#[repr(C)]
pub struct ze_advanced_publisher_sample_miss_detection_options_t {
    /// Must be `true` to add sequence numbers.
    pub is_enabled: bool,
    /// Whether and how to beacon last-sample presence.
    pub heartbeat_mode: ze_advanced_publisher_heartbeat_mode_t,
    /// Beacon period, when `heartbeat_mode` is not NONE.
    pub heartbeat_period_ms: u64,
}

/// zenoh-c `ze_advanced_publisher_options_t` (`zenoh_commons.h:1069-1093`).
#[repr(C)]
pub struct ze_advanced_publisher_options_t {
    /// The base publisher options.
    pub publisher_options: z_publisher_options_t,
    /// Cache settings.
    pub cache: ze_advanced_publisher_cache_options_t,
    /// Sample-miss-detection settings.
    pub sample_miss_detection: ze_advanced_publisher_sample_miss_detection_options_t,
    /// Announce this publisher through liveliness.
    pub publisher_detection: bool,
    /// Optional metadata keyexpr appended to the liveliness token.
    pub publisher_detection_metadata: *const z_loaned_keyexpr_t,
}

/// zenoh-c `ze_advanced_publisher_put_options_t` (`zenoh_commons.h:1100-1105`).
#[repr(C)]
pub struct ze_advanced_publisher_put_options_t {
    /// The base put options.
    pub put_options: z_publisher_put_options_t,
}

/// zenoh-c `ze_advanced_publisher_delete_options_t`
/// (`zenoh_commons.h:1031-1037`) — one embedded `z_publisher_delete_options_t`,
/// which is `{ const z_timestamp_t* timestamp; }`.
#[repr(C)]
pub struct ze_advanced_publisher_delete_options_t {
    /// Timestamp for the delete. Accepted for ABI compatibility; not read.
    pub timestamp: *const c_void,
}

/// Fill default cache options (zenoh-c
/// `ze_advanced_publisher_cache_options_default`, `zenoh_commons.h:5674`).
///
/// `is_enabled` is `true` HERE and cleared by
/// [`ze_advanced_publisher_options_default`] — upstream calls this one and then
/// overrides the flag, so a program that calls it directly (upstream's
/// `z_advanced_pub.c:55` does) gets the ENABLED form. The two defaults
/// disagreeing is upstream's shape, not a mistake here.
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_cache_options_default(
    this_: *mut ze_advanced_publisher_cache_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = ze_advanced_publisher_cache_options_t {
            is_enabled: true,
            max_samples: 1,
            congestion_control: crate::publisher::Z_CONGESTION_CONTROL_DROP,
            priority: crate::publisher::Z_PRIORITY_DATA,
            is_express: false,
        }
    };
}

/// Fill default sample-miss-detection options (zenoh-c
/// `ze_advanced_publisher_sample_miss_detection_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_sample_miss_detection_options_default(
    this_: *mut ze_advanced_publisher_sample_miss_detection_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = ze_advanced_publisher_sample_miss_detection_options_t {
            is_enabled: true,
            heartbeat_mode: ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE,
            heartbeat_period_ms: 0,
        }
    };
}

/// Fill default advanced-publisher options (zenoh-c
/// `ze_advanced_publisher_options_default`, `zenoh_commons.h:5783`).
///
/// Both sub-option blocks are filled by their own default and then have
/// `is_enabled` cleared — upstream's exact sequence, and the reason the two
/// defaults disagree with each other.
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_options_default(
    this_: *mut ze_advanced_publisher_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract, for this write and the three nested ones.
    unsafe {
        crate::publisher::z_publisher_options_default(&mut (*this_).publisher_options);
        ze_advanced_publisher_cache_options_default(&mut (*this_).cache);
        (*this_).cache.is_enabled = false;
        ze_advanced_publisher_sample_miss_detection_options_default(
            &mut (*this_).sample_miss_detection,
        );
        (*this_).sample_miss_detection.is_enabled = false;
        (*this_).publisher_detection = false;
        (*this_).publisher_detection_metadata = std::ptr::null();
    }
}

/// Fill default advanced-publisher put options (zenoh-c
/// `ze_advanced_publisher_put_options_default`, `zenoh_commons.h:5809`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_put_options_default(
    this_: *mut ze_advanced_publisher_put_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { crate::publisher::z_publisher_put_options_default(&mut (*this_).put_options) };
}

/// Fill default advanced-publisher delete options.
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_delete_options_default(
    this_: *mut ze_advanced_publisher_delete_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = ze_advanced_publisher_delete_options_t {
            timestamp: std::ptr::null(),
        }
    };
}

/// Owned advanced publisher (zenoh-c `ze_owned_advanced_publisher_t`,
/// `zenoh_opaque.h:933-935`). Handle in slot 0, zero-padded to upstream's size.
#[repr(C)]
pub struct ze_owned_advanced_publisher_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; ADV_PUB_SIZE - std::mem::size_of::<Handle>()],
}

/// Loaned advanced publisher — the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct ze_loaned_advanced_publisher_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; ADV_PUB_SIZE - std::mem::size_of::<Handle>()],
}

/// Moved advanced publisher (zenoh-c `ze_moved_advanced_publisher_t`).
#[repr(C)]
pub struct ze_moved_advanced_publisher_t {
    pub(crate) _this: ze_owned_advanced_publisher_t,
}

impl ze_owned_advanced_publisher_t {
    /// The gravestone value: a null handle and zeroed padding.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; ADV_PUB_SIZE - std::mem::size_of::<Handle>()],
        }
    }
}

/// Behind a `ze_owned_advanced_publisher_t` handle: the registry entry to
/// retract. Dropping it undeclares on every face, so an implicit `z_drop` and an
/// explicit `ze_undeclare_advanced_publisher` take the identical path.
struct AdvPubState {
    shared: Arc<SharedSession>,
    id: AdvPubId,
    /// R311y568 — the keyexpr this publisher was declared under, so
    /// [`ze_advanced_publisher_keyexpr`] can answer.
    keyexpr: crate::keyexpr::DeclaredKeyexpr,
}

impl Drop for AdvPubState {
    fn drop(&mut self) {
        self.shared.undeclare_advanced_publisher(self.id);
    }
}

/// Read the state behind a loaned advanced publisher.
///
/// # Safety
/// `this_` must be null, or a valid loaned advanced publisher whose handle slot
/// holds a live `AdvPubState` pointer.
unsafe fn adv_pub_state<'a>(
    this_: *const ze_loaned_advanced_publisher_t,
) -> Option<&'a AdvPubState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<AdvPubState>` this crate leaked.
    Some(unsafe { &*(handle as *const AdvPubState) })
}

/// R311y568 — an advanced publisher's session and declared keyexpr, for
/// [`crate::matching`]'s three advanced entry points.
///
/// A getter rather than making [`AdvPubState`] visible: the matching plane needs
/// exactly these two facts, and exposing the state would let it reach the
/// registry id, which is the field whose misuse would double-undeclare.
///
/// # Safety
/// As [`adv_pub_state`].
pub(crate) unsafe fn adv_pub_shared_and_keyexpr(
    this_: *const ze_loaned_advanced_publisher_t,
) -> Option<(Arc<SharedSession>, String)> {
    // SAFETY: the caller's contract, delegated.
    let state = unsafe { adv_pub_state(this_) }?;
    Some((state.shared.clone(), state.keyexpr.literal().to_owned()))
}

/// The wz options one C `ze_advanced_publisher_options_t` maps to.
///
/// `sample_miss_detection.is_enabled` selects the SEQUENCING mode, which is the
/// one mapping worth stating: sequence numbers are what let a subscriber notice
/// a gap at all, so enabling detection while leaving the sequencing at timestamp
/// would build a publisher whose subscribers can never miss anything.
///
/// # Safety
/// `options` must be null or a valid options struct.
unsafe fn advanced_publisher_options(
    options: *const ze_advanced_publisher_options_t,
) -> AdvancedPublisherOptions {
    let mut out = AdvancedPublisherOptions::default();
    // Upstream's own default has cache + miss detection + detection all OFF, so
    // a NULL options pointer must not inherit wz's richer `Default`.
    out.cache = None;
    out.sequencing = Sequencing::Timestamp;
    out.publisher_detection = false;
    out.sample_miss_detection = MissDetectionConfig::default();
    if options.is_null() {
        return out;
    }
    // SAFETY: the caller's contract, for every read below.
    unsafe {
        if (*options).cache.is_enabled {
            out.cache = Some(CacheConfig {
                max_samples: (*options).cache.max_samples.max(1),
            });
        }
        if (*options).sample_miss_detection.is_enabled {
            out.sequencing = Sequencing::SequenceNumber;
            let period_ms = (*options).sample_miss_detection.heartbeat_period_ms;
            if period_ms > 0 {
                let period = Duration::from_millis(period_ms);
                out.sample_miss_detection = match (*options).sample_miss_detection.heartbeat_mode {
                    ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC => {
                        MissDetectionConfig::default().heartbeat(period)
                    }
                    ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_SPORADIC => {
                        MissDetectionConfig::default().sporadic_heartbeat(period)
                    }
                    _ => MissDetectionConfig::default(),
                };
            }
        }
        out.publisher_detection = (*options).publisher_detection;
    }
    out
}

/// Declare an advanced publisher (zenoh-c `ze_declare_advanced_publisher`,
/// `zenoh_commons.h:6011-6014`).
///
/// # Safety
/// `session` must be a valid loaned session; `publisher` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `options` must be null or
/// a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_advanced_publisher(
    session: *const z_loaned_session_t,
    publisher: *mut ze_owned_advanced_publisher_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut ze_advanced_publisher_options_t,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *publisher = ze_owned_advanced_publisher_t::null_value() };

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        // The same outbound canon gate every declare in this crate hoists: the
        // per-face declare is best-effort, so a per-face reject would be
        // swallowed and the call would report success for a dead SSOT entry.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        // A heartbeat mode with a ZERO period is a publisher that would beacon in
        // a tight loop. Rejected before anything is declared, which is what the
        // pico ABI does and what upstream's own advanced publisher does.
        // SAFETY: the caller's contract.
        if !options.is_null()
            && unsafe {
                (*options).sample_miss_detection.is_enabled
                    && (*options).sample_miss_detection.heartbeat_mode
                        != ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE
                    && (*options).sample_miss_detection.heartbeat_period_ms == 0
            }
        {
            return Z_EINVAL;
        }
        // SAFETY: the caller's contract.
        let opts = unsafe { advanced_publisher_options(options) };
        let declared = ke.clone();
        let id = state.shared.declare_advanced_publisher(ke, opts);
        let mut boxed = Box::new(AdvPubState {
            shared: state.shared.clone(),
            id,
            keyexpr: crate::keyexpr::DeclaredKeyexpr::new(declared),
        });
        // Bind AFTER boxing — the state is at its final address only here.
        boxed.keyexpr.bind();
        // SAFETY: `publisher` was checked non-null above.
        unsafe { (*publisher).handle = Box::into_raw(boxed) as Handle };
        Z_OK
    })
}

/// Publish through an advanced publisher (zenoh-c
/// `ze_advanced_publisher_put`, `zenoh_commons.h:5799-5801`).
///
/// The payload — and the attachment inside `options` — are CONSUMED on every
/// path, as upstream specifies, so an error return still invalidates the
/// caller's values rather than leaving them a double-free.
///
/// # Safety
/// `this_` must be null or a valid loaned advanced publisher; `payload` must be
/// a valid moved bytes; `options` must be null or a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_put(
    this_: *const ze_loaned_advanced_publisher_t,
    payload: *mut z_moved_bytes_t,
    options: *mut ze_advanced_publisher_put_options_t,
) -> ZResult {
    guarded(|| {
        // Taken FIRST and unconditionally — see the doc note.
        // SAFETY: the caller's contract.
        let buf = unsafe { take_payload(payload) };
        if !options.is_null() {
            // SAFETY: the caller's contract.
            drop(unsafe { take_payload((*options).put_options.attachment) });
        }
        // SAFETY: the caller's contract.
        let (Some(state), Some(buf)) = (unsafe { adv_pub_state(this_) }, buf) else {
            return Z_ENULL;
        };
        state.shared.advanced_publisher_put(state.id, &buf);
        Z_OK
    })
}

/// Zero an owned advanced publisher (zenoh-c
/// `ze_internal_advanced_publisher_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_publisher_null(
    this_: *mut ze_owned_advanced_publisher_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_advanced_publisher_t::null_value() };
    }
}

// --- R311y568: the advanced planes' identity + matching accessors -----------

/// This advanced publisher's GLOBAL ENTITY ID (zenoh-c
/// `ze_advanced_publisher_id`).
///
/// Through the shared [`z_entity_global_id_t::for_entity`] constructor, like the
/// four base-plane accessors.
///
/// # Safety
/// `publisher` must be null or a valid loaned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_id(
    publisher: *const ze_loaned_advanced_publisher_t,
) -> z_entity_global_id_t {
    guard_val(z_entity_global_id_t::empty(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { adv_pub_state(publisher) } {
            Some(state) => {
                z_entity_global_id_t::for_entity(&state.shared, publisher as *const c_void)
            }
            None => z_entity_global_id_t::empty(),
        }
    })
}

/// The keyexpr this advanced publisher was declared under (zenoh-c
/// `ze_advanced_publisher_keyexpr`).
///
/// # Safety
/// `publisher` must be null or a valid loaned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_keyexpr(
    publisher: *const ze_loaned_advanced_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { adv_pub_state(publisher) } {
            Some(state) => state.keyexpr.as_loaned(),
            None => std::ptr::null(),
        }
    })
}

/// Publish a DELETE through an advanced publisher (zenoh-c
/// `ze_advanced_publisher_delete`).
///
/// The Del twin of [`ze_advanced_publisher_put`], routed through the SAME
/// registry entry so a Del and a Put from one advanced publisher carry the same
/// declared QoS and the same sequencing — the sample-miss detection a subscriber
/// runs counts both, which is why a Del must not bypass the counter.
///
/// ## The options' `timestamp` is ACCEPTED and NOT USED, and that is FAITHFUL
///
/// `ze_advanced_publisher_delete_options_t` embeds a
/// `z_publisher_delete_options_t`, whose only field is a timestamp — and the
/// base-plane [`crate::publisher::z_publisher_delete`] honours it. Here it is
/// deliberately ignored, because upstream ignores it too: an advanced publisher
/// OVERWRITES `put_options.timestamp` and `put_options.source_info` with its own
/// sequencing values (`vendor/zenoh-pico/src/api/advanced_publisher.c:402-407`),
/// which is the same reason
/// [`AdvancedPublisher::delete`](wz_runtime_tokio::advanced_publisher::AdvancedPublisher::delete)
/// takes no timestamp parameter. Honouring the caller's value here would let a C
/// program stamp a Del out of order with the Puts its own subscribers use to
/// detect misses.
///
/// # Safety
/// `this_` must be null or a valid loaned advanced publisher; `_options` must be
/// null or a valid delete-options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_delete(
    this_: *const ze_loaned_advanced_publisher_t,
    _options: *mut ze_advanced_publisher_delete_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { adv_pub_state(this_) }) else {
            return Z_ENULL;
        };
        if state.shared.advanced_publisher_delete(state.id) {
            Z_OK
        } else {
            Z_EINVAL
        }
    })
}

/// `true` iff the owned advanced publisher holds a live handle.
///
/// # Safety
/// `this_` must be null or a valid owned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_publisher_check(
    this_: *const ze_owned_advanced_publisher_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Borrow an advanced publisher (zenoh-c `ze_advanced_publisher_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_loan(
    this_: *const ze_owned_advanced_publisher_t,
) -> *const ze_loaned_advanced_publisher_t {
    this_ as *const ze_loaned_advanced_publisher_t
}

/// Mutably borrow an advanced publisher (zenoh-c
/// `ze_advanced_publisher_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_loan_mut(
    this_: *mut ze_owned_advanced_publisher_t,
) -> *mut ze_loaned_advanced_publisher_t {
    this_ as *mut ze_loaned_advanced_publisher_t
}

/// Retract an advanced publisher (zenoh-c
/// `ze_undeclare_advanced_publisher`).
///
/// # Safety
/// `this_` must be null or a valid moved advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_advanced_publisher(
    this_: *mut ze_moved_advanced_publisher_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<AdvPubState>` this crate leaked; its `Drop`
            // retracts the declaration on every face.
            drop(unsafe { Box::from_raw(handle as *mut AdvPubState) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = ze_owned_advanced_publisher_t::null_value() };
        }
        Z_OK
    })
}

/// Drop an advanced publisher (zenoh-c `ze_advanced_publisher_drop`) — what
/// `z_drop(z_move(pub))` dispatches to.
///
/// # Safety
/// `this_` must be null or a valid moved advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_drop(this_: *mut ze_moved_advanced_publisher_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there, so a
    // double drop is a no-op.
    let _ = unsafe { ze_undeclare_advanced_publisher(this_) };
}

// ---------------------------------------------------------------------------
// advanced subscriber
// ---------------------------------------------------------------------------

/// zenoh-c `ze_advanced_subscriber_history_options_t`
/// (`zenoh_commons.h:1163-1182`).
#[repr(C)]
pub struct ze_advanced_subscriber_history_options_t {
    /// Must be `true` to recover history at all.
    pub is_enabled: bool,
    /// Query late-joining publishers for their history too.
    pub detect_late_publishers: bool,
    /// Samples to query per resource; `0` = no limit.
    pub max_samples: usize,
    /// Maximum sample age to query, in MILLISECONDS; `0` = no limit.
    pub max_age_ms: u64,
}

/// zenoh-c `ze_advanced_subscriber_last_sample_miss_detection_options_t`
/// (`zenoh_commons.h:1189-1203`).
#[repr(C)]
pub struct ze_advanced_subscriber_last_sample_miss_detection_options_t {
    /// Must be `true` to detect a missing LAST sample.
    pub is_enabled: bool,
    /// Poll period for not-yet-received samples. `0` means "use the publisher's
    /// heartbeat instead", which is a trigger, not the absence of one.
    pub periodic_queries_period_ms: u64,
}

/// zenoh-c `ze_advanced_subscriber_recovery_options_t`
/// (`zenoh_commons.h:1210-1221`).
#[repr(C)]
pub struct ze_advanced_subscriber_recovery_options_t {
    /// Must be `true` to recover lost samples.
    pub is_enabled: bool,
    /// Last-sample-miss settings.
    pub last_sample_miss_detection: ze_advanced_subscriber_last_sample_miss_detection_options_t,
}

/// zenoh-c `ze_advanced_subscriber_options_t` (`zenoh_commons.h:1228-1256`).
#[repr(C)]
pub struct ze_advanced_subscriber_options_t {
    /// The base subscriber options — a real four-byte struct here, unlike the
    /// pico ABI's one-byte dummy. See the module note.
    pub subscriber_options: z_subscriber_options_t,
    /// History-recovery settings.
    pub history: ze_advanced_subscriber_history_options_t,
    /// Lost-sample-recovery settings.
    pub recovery: ze_advanced_subscriber_recovery_options_t,
    /// Timeout for history / recovery queries; `0` = use the default.
    pub query_timeout_ms: u64,
    /// Announce this subscriber through liveliness.
    pub subscriber_detection: bool,
    /// Optional metadata keyexpr appended to the liveliness token.
    pub subscriber_detection_metadata: *const z_loaned_keyexpr_t,
}

/// Fill default history options (zenoh-c
/// `ze_advanced_subscriber_history_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_history_options_default(
    this_: *mut ze_advanced_subscriber_history_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = ze_advanced_subscriber_history_options_t {
            is_enabled: true,
            detect_late_publishers: false,
            max_samples: 0,
            max_age_ms: 0,
        }
    };
}

/// Fill default last-sample-miss-detection options (zenoh-c
/// `ze_advanced_subscriber_last_sample_miss_detection_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_last_sample_miss_detection_options_default(
    this_: *mut ze_advanced_subscriber_last_sample_miss_detection_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = ze_advanced_subscriber_last_sample_miss_detection_options_t {
            is_enabled: true,
            periodic_queries_period_ms: 0,
        }
    };
}

/// Fill default recovery options (zenoh-c
/// `ze_advanced_subscriber_recovery_options_default`).
///
/// The same fill-then-clear shape the publisher options use: the nested
/// last-sample block is defaulted ENABLED and then cleared, so a program that
/// calls the nested default directly (upstream's `z_advanced_sub.c:70` does)
/// gets the enabled form.
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_recovery_options_default(
    this_: *mut ze_advanced_subscriber_recovery_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract, for this write and the nested one.
    unsafe {
        (*this_).is_enabled = true;
        ze_advanced_subscriber_last_sample_miss_detection_options_default(
            &mut (*this_).last_sample_miss_detection,
        );
        (*this_).last_sample_miss_detection.is_enabled = false;
    }
}

/// Fill default advanced-subscriber options (zenoh-c
/// `ze_advanced_subscriber_options_default`, `zenoh_commons.h:5937`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_options_default(
    this_: *mut ze_advanced_subscriber_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract, for this write and the nested ones.
    unsafe {
        crate::sub::z_subscriber_options_default(&mut (*this_).subscriber_options);
        ze_advanced_subscriber_history_options_default(&mut (*this_).history);
        (*this_).history.is_enabled = false;
        ze_advanced_subscriber_recovery_options_default(&mut (*this_).recovery);
        (*this_).recovery.is_enabled = false;
        (*this_).query_timeout_ms = 0;
        (*this_).subscriber_detection = false;
        (*this_).subscriber_detection_metadata = std::ptr::null();
    }
}

/// Owned advanced subscriber (zenoh-c `ze_owned_advanced_subscriber_t`,
/// `zenoh_opaque.h:950-952`).
#[repr(C)]
pub struct ze_owned_advanced_subscriber_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; ADV_SUB_SIZE - std::mem::size_of::<Handle>()],
}

/// Loaned advanced subscriber — the same layout.
#[repr(C)]
pub struct ze_loaned_advanced_subscriber_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; ADV_SUB_SIZE - std::mem::size_of::<Handle>()],
}

/// Moved advanced subscriber (zenoh-c `ze_moved_advanced_subscriber_t`).
#[repr(C)]
pub struct ze_moved_advanced_subscriber_t {
    pub(crate) _this: ze_owned_advanced_subscriber_t,
}

impl ze_owned_advanced_subscriber_t {
    /// The gravestone value: a null handle and zeroed padding.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; ADV_SUB_SIZE - std::mem::size_of::<Handle>()],
        }
    }
}

/// The slot a miss listener installs into, shared with every face's `on_miss`.
///
/// Behind a `Mutex` rather than an atomic cell because installation and removal
/// are rare and the read is on the miss path, which only runs when a gap is
/// actually detected.
type MissSlot = Arc<Mutex<Option<Arc<CMissClosure>>>>;

/// Behind a `ze_owned_advanced_subscriber_t` handle.
struct AdvSubState {
    shared: Arc<SharedSession>,
    id: AdvSubId,
    /// The miss closure the C side may install AFTER declaring — see the module
    /// note on ordering.
    miss: MissSlot,
    /// R311y568 — the keyexpr this subscriber was declared under, so
    /// [`ze_advanced_subscriber_keyexpr`] can answer.
    keyexpr: crate::keyexpr::DeclaredKeyexpr,
}

impl Drop for AdvSubState {
    fn drop(&mut self) {
        self.shared.undeclare_advanced_subscriber(self.id);
    }
}

/// Read the state behind a loaned advanced subscriber.
///
/// # Safety
/// `this_` must be null, or a valid loaned advanced subscriber whose handle slot
/// holds a live `AdvSubState` pointer.
unsafe fn adv_sub_state<'a>(
    this_: *const ze_loaned_advanced_subscriber_t,
) -> Option<&'a AdvSubState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<AdvSubState>` this crate leaked.
    Some(unsafe { &*(handle as *const AdvSubState) })
}

/// The wz options one C `ze_advanced_subscriber_options_t` maps to.
///
/// # Safety
/// `options` must be null or a valid options struct.
unsafe fn advanced_subscriber_options(
    options: *const ze_advanced_subscriber_options_t,
) -> AdvancedSubscriberOptions {
    let mut out = AdvancedSubscriberOptions::default();
    if options.is_null() {
        return out;
    }
    // SAFETY: the caller's contract, for every read below.
    unsafe {
        if (*options).recovery.is_enabled {
            let last = &(*options).recovery.last_sample_miss_detection;
            let mut recovery = RecoveryConfig::default();
            if last.is_enabled {
                if last.periodic_queries_period_ms > 0 {
                    recovery.periodic_queries =
                        Some(Duration::from_millis(last.periodic_queries_period_ms));
                } else {
                    // Upstream: "If set to 0, the last sample(s) miss detection
                    // will be performed based on publisher's heartbeat" — which
                    // is wz's `heartbeat` trigger, not "no trigger at all".
                    recovery.heartbeat = true;
                }
            }
            out.recovery = Some(recovery);
        }
        if (*options).history.is_enabled {
            let history = &(*options).history;
            // `HistoryConfig` is `#[non_exhaustive]`, so it is built from its
            // default and narrowed — the shape that survives a new field.
            let mut cfg = HistoryConfig::default();
            cfg.sample_depth = (history.max_samples > 0).then_some(history.max_samples);
            // Upstream carries an age in MILLISECONDS; wz's `_time=` selector
            // bound is in SECONDS. Converting rather than passing the number
            // through is the whole reason this is not a field copy.
            cfg.max_age = (history.max_age_ms > 0).then(|| history.max_age_ms as f64 / 1000.0);
            cfg.detect_late_publishers = history.detect_late_publishers;
            out.history = Some(cfg);
        }
        if (*options).query_timeout_ms > 0 {
            out.query_timeout = Duration::from_millis((*options).query_timeout_ms);
        }
    }
    out
}

/// Deliver one wz [`Miss`] to whatever C miss closure is installed.
///
/// A miss with no listener is silently dropped, which is upstream's behaviour
/// too: the listener is optional and the sample stream is unaffected by its
/// absence.
fn fire_miss(slot: &MissSlot, miss: &Miss) {
    let Ok(guard) = slot.lock() else {
        return;
    };
    let Some(closure) = guard.as_ref() else {
        return;
    };
    let Some(call) = closure.call else {
        return;
    };
    let mut zid = [0u8; Z_ID_SIZE];
    let n = miss.source_zid.len().min(zid.len());
    zid[..n].copy_from_slice(&miss.source_zid[..n]);
    let value = ze_miss_t {
        source: z_entity_global_id_t {
            zid: z_id_t { id: zid },
            eid: miss.source_eid,
        },
        nb: miss.nb,
    };
    let ctx = closure.context.0;
    // SAFETY: `call` is the C callback and `value` is valid for exactly this
    // call. An unwind out of it across `extern "C"` is UB and would tear down the
    // drive thread, so it is caught here.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(&value as *const ze_miss_t, ctx);
    }));
}

/// Declare an advanced subscriber the C side never holds (zenoh-c
/// `ze_declare_background_advanced_subscriber`): it lives until the session is
/// closed. Consumes the moved sample closure on every path.
///
/// R311y568.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be a valid loaned
/// keyexpr; `callback` must be a valid moved closure; `options` must be null or a
/// valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_background_advanced_subscriber(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_advanced_subscriber_options_t,
) -> ZResult {
    let mut sink = ze_owned_advanced_subscriber_t::null_value();
    // SAFETY: the caller's contract, delegated — the local sink absorbs the
    // handle the owned form would have written out and then goes out of scope
    // without reclaiming it, so the subscription lives until the session is
    // closed. See `crate::sub::z_declare_background_subscriber` for the full
    // argument, including why the discard is deliberate.
    unsafe { ze_declare_advanced_subscriber(session, &mut sink, key_expr, callback, options) }
}

/// Declare an advanced subscriber (zenoh-c `ze_declare_advanced_subscriber`,
/// `zenoh_commons.h:6029-6033`). Consumes the moved sample closure on every
/// path.
///
/// # Safety
/// `session` must be a valid loaned session; `subscriber` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure; `options` must be null or a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_advanced_subscriber(
    session: *const z_loaned_session_t,
    subscriber: *mut ze_owned_advanced_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_advanced_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *subscriber = ze_owned_advanced_subscriber_t::null_value() };

        // Consume the moved closure FIRST (consume-on-all-paths, as
        // `crate::sub` documents): from here the `CClosure` owns the C
        // `drop(context)` responsibility, so every early return frees the
        // caller's context exactly as upstream does.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = Arc::new(CClosure::new(owned.context, owned.call, owned.drop));
        *owned = z_owned_closure_sample_t::null_value();

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        let miss: MissSlot = Arc::new(Mutex::new(None));
        // SAFETY: the caller's contract.
        let opts = unsafe { advanced_subscriber_options(options) };
        let declared = ke.clone();
        let id = state.shared.declare_advanced_subscriber(ke, opts, {
            let closure = cclosure.clone();
            let miss = miss.clone();
            Arc::new(move || {
                let sample_cb = {
                    let mut inner = crate::sub::make_subscriber_callback(closure.clone());
                    // The advanced subscriber hands an OWNED `Sample`; the
                    // existing marshal reads `&dyn SampleView`, which `Sample`
                    // implements — so the two planes share one marshal instead of
                    // growing a second.
                    Box::new(move |sample: Sample| inner(&sample as &dyn SampleView))
                        as Box<dyn FnMut(Sample) + Send + 'static>
                };
                let miss_cb = {
                    let miss = miss.clone();
                    Box::new(move |m: Miss| fire_miss(&miss, &m))
                        as Box<dyn FnMut(Miss) + Send + 'static>
                };
                (sample_cb, miss_cb)
            })
        });
        let mut boxed = Box::new(AdvSubState {
            shared: state.shared.clone(),
            id,
            miss,
            keyexpr: crate::keyexpr::DeclaredKeyexpr::new(declared),
        });
        // Bind AFTER boxing — the state is at its final address only here.
        boxed.keyexpr.bind();
        // SAFETY: `subscriber` was checked non-null above.
        unsafe { (*subscriber).handle = Box::into_raw(boxed) as Handle };
        Z_OK
    })
}

/// Zero an owned advanced subscriber (zenoh-c
/// `ze_internal_advanced_subscriber_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_subscriber_null(
    this_: *mut ze_owned_advanced_subscriber_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_advanced_subscriber_t::null_value() };
    }
}

/// `true` iff the owned advanced subscriber holds a live handle.
///
/// # Safety
/// `this_` must be null or a valid owned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_subscriber_check(
    this_: *const ze_owned_advanced_subscriber_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// This advanced subscriber's GLOBAL ENTITY ID (zenoh-c
/// `ze_advanced_subscriber_id`).
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_id(
    subscriber: *const ze_loaned_advanced_subscriber_t,
) -> z_entity_global_id_t {
    guard_val(z_entity_global_id_t::empty(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { adv_sub_state(subscriber) } {
            Some(state) => {
                z_entity_global_id_t::for_entity(&state.shared, subscriber as *const c_void)
            }
            None => z_entity_global_id_t::empty(),
        }
    })
}

/// The keyexpr this advanced subscriber was declared under (zenoh-c
/// `ze_advanced_subscriber_keyexpr`).
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_keyexpr(
    subscriber: *const ze_loaned_advanced_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { adv_sub_state(subscriber) } {
            Some(state) => state.keyexpr.as_loaned(),
            None => std::ptr::null(),
        }
    })
}

/// Subscribe to the PUBLISHER-DETECTION liveliness plane in the background
/// (zenoh-c `ze_advanced_subscriber_detect_publishers_background`).
///
/// An advanced publisher declared with `publisher_detection` announces itself
/// with a liveliness token under `<keyexpr>/@adv/pub/**`; this is the
/// subscription that observes those tokens coming and going, so a C program can
/// learn WHICH publishers it is tracking rather than only that a sample was
/// missed.
///
/// Routed through [`ze_advanced_subscriber_detect_publishers`] — the OWNED form
/// this crate already exports — into a LOCAL handle that is then discarded, the
/// same background construction the rest of the crate uses. The subscription
/// therefore lives until the session is closed, which is upstream's contract for
/// a background declare.
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber; `callback`
/// must be a valid moved closure, consumed on every path; `options` must be null
/// or valid.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_detect_publishers_background(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut crate::liveliness::z_liveliness_subscriber_options_t,
) -> ZResult {
    let mut sink = z_owned_subscriber_t::null_value();
    // SAFETY: the caller's contract, delegated.
    unsafe { ze_advanced_subscriber_detect_publishers(subscriber, &mut sink, callback, options) }
}

/// Borrow an advanced subscriber (zenoh-c `ze_advanced_subscriber_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_loan(
    this_: *const ze_owned_advanced_subscriber_t,
) -> *const ze_loaned_advanced_subscriber_t {
    this_ as *const ze_loaned_advanced_subscriber_t
}

// R311y568 — REMOVED: ze_advanced_subscriber_loan_mut.
//
// Upstream declares no such function on EITHER arm (0 hits across every header
// in both oracles), so wz was exporting a `ze_`-prefixed symbol that is not part
// of the zenoh-c ABI. Nothing in the tree called it and no C program compiled
// against upstream's header could name it; what it did was make wz's exported
// surface a superset of the reference's, which is a different library wearing
// the same names. Found by the census's REVERSE direction, added the same round
// — the forward ratchet had been green over it since the plane landed.

/// Retract an advanced subscriber (zenoh-c
/// `ze_undeclare_advanced_subscriber`).
///
/// # Safety
/// `this_` must be null or a valid moved advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_advanced_subscriber(
    this_: *mut ze_moved_advanced_subscriber_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<AdvSubState>` this crate leaked; its `Drop`
            // retracts the declaration and releases the last closure reference.
            drop(unsafe { Box::from_raw(handle as *mut AdvSubState) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = ze_owned_advanced_subscriber_t::null_value() };
        }
        Z_OK
    })
}

/// Drop an advanced subscriber (zenoh-c `ze_advanced_subscriber_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_drop(this_: *mut ze_moved_advanced_subscriber_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there.
    let _ = unsafe { ze_undeclare_advanced_subscriber(this_) };
}

// ---------------------------------------------------------------------------
// the sample-miss listener
// ---------------------------------------------------------------------------

/// Owned sample-miss listener (zenoh-c `ze_owned_sample_miss_listener_t`).
#[repr(C)]
pub struct ze_owned_sample_miss_listener_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; MISS_LISTENER_SIZE - std::mem::size_of::<Handle>()],
}

/// Loaned sample-miss listener — the same layout.
#[repr(C)]
pub struct ze_loaned_sample_miss_listener_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; MISS_LISTENER_SIZE - std::mem::size_of::<Handle>()],
}

/// Moved sample-miss listener.
#[repr(C)]
pub struct ze_moved_sample_miss_listener_t {
    pub(crate) _this: ze_owned_sample_miss_listener_t,
}

impl ze_owned_sample_miss_listener_t {
    /// The gravestone value.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; MISS_LISTENER_SIZE - std::mem::size_of::<Handle>()],
        }
    }
}

/// Behind a `ze_owned_sample_miss_listener_t` handle: the slot to clear.
///
/// Clearing on drop is what makes `z_drop(z_move(listener))` stop the
/// notifications, and it is also what releases the last `Arc<CMissClosure>` —
/// running the C `drop(context)`.
struct MissListenerState {
    slot: MissSlot,
}

impl Drop for MissListenerState {
    fn drop(&mut self) {
        // Take the closure OUT under the lock and release it AFTER, so the C
        // `drop(context)` never runs while the slot is held: a drop that
        // re-entered the subscriber would otherwise deadlock on this mutex.
        let taken = self.slot.lock().ok().and_then(|mut guard| guard.take());
        drop(taken);
    }
}

/// Install the miss closure into `state`'s slot, replacing any previous one.
///
/// Shared by the owned and background forms so the two cannot diverge on what
/// installation means. The previous closure is released OUTSIDE the lock, for
/// the reason [`MissListenerState::drop`] states.
fn install_miss(state: &AdvSubState, closure: Arc<CMissClosure>) -> bool {
    let previous = match state.miss.lock() {
        Ok(mut guard) => guard.replace(closure),
        Err(poisoned) => poisoned.into_inner().replace(closure),
    };
    drop(previous);
    true
}

/// Install a sample-miss listener (zenoh-c
/// `ze_advanced_subscriber_declare_sample_miss_listener`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber; `listener`
/// must be valid and writable; `callback` must be a valid moved miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_declare_sample_miss_listener(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    listener: *mut ze_owned_sample_miss_listener_t,
    callback: *mut ze_moved_closure_miss_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Consume the moved closure FIRST.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = Arc::new(CMissClosure::new(owned.context, owned.call, owned.drop));
        *owned = ze_owned_closure_miss_t::null_value();

        if listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *listener = ze_owned_sample_miss_listener_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { adv_sub_state(subscriber) }) else {
            return Z_ENULL;
        };
        install_miss(state, cclosure);
        let boxed = Box::new(MissListenerState {
            slot: state.miss.clone(),
        });
        // SAFETY: `listener` was checked non-null above.
        unsafe { (*listener).handle = Box::into_raw(boxed) as Handle };
        Z_OK
    })
}

/// Install a sample-miss listener the C side never holds (zenoh-c
/// `ze_advanced_subscriber_declare_background_sample_miss_listener`,
/// `zenoh_commons.h:5831-5832`) — it lives as long as the subscriber does.
///
/// The difference from the owned form is ownership, not behaviour: with no
/// listener handle in the C side's hands nothing can retract it, so the closure
/// is released when the subscriber's own state drops. That is exactly upstream's
/// "background" contract, and it is why this does NOT allocate a
/// [`MissListenerState`] — a state whose only job is to be dropped by a call
/// that cannot happen would be a leak dressed as a lifecycle.
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber; `callback`
/// must be a valid moved miss closure.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_declare_background_sample_miss_listener(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    callback: *mut ze_moved_closure_miss_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Consume the moved closure FIRST, so an early return still runs the C
        // `drop(context)` exactly once.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = Arc::new(CMissClosure::new(owned.context, owned.call, owned.drop));
        *owned = ze_owned_closure_miss_t::null_value();

        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { adv_sub_state(subscriber) }) else {
            return Z_ENULL;
        };
        install_miss(state, cclosure);
        Z_OK
    })
}

/// Zero an owned sample-miss listener.
///
/// # Safety
/// `this_` must be null or a valid, writable owned listener.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_sample_miss_listener_null(
    this_: *mut ze_owned_sample_miss_listener_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_sample_miss_listener_t::null_value() };
    }
}

/// `true` iff the listener holds a live handle.
///
/// # Safety
/// `this_` must be null or a valid owned listener.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_sample_miss_listener_check(
    this_: *const ze_owned_sample_miss_listener_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// R311y568 — REMOVED: ze_sample_miss_listener_loan.
//
// Upstream declares no such function on EITHER arm (0 hits across every header
// in both oracles), so wz was exporting a `ze_`-prefixed symbol that is not part
// of the zenoh-c ABI. Nothing in the tree called it and no C program compiled
// against upstream's header could name it; what it did was make wz's exported
// surface a superset of the reference's, which is a different library wearing
// the same names. Found by the census's REVERSE direction, added the same round
// — the forward ratchet had been green over it since the plane landed.

/// Retract a sample-miss listener (zenoh-c
/// `ze_undeclare_sample_miss_listener`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_sample_miss_listener(
    this_: *mut ze_moved_sample_miss_listener_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<MissListenerState>` this crate leaked; its
            // `Drop` clears the slot and releases the C closure.
            drop(unsafe { Box::from_raw(handle as *mut MissListenerState) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = ze_owned_sample_miss_listener_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a sample-miss listener (zenoh-c `ze_sample_miss_listener_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_drop(this_: *mut ze_moved_sample_miss_listener_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there.
    let _ = unsafe { ze_undeclare_sample_miss_listener(this_) };
}

// ---------------------------------------------------------------------------
// publisher detection
// ---------------------------------------------------------------------------

/// Subscribe to the liveliness tokens of matching advanced PUBLISHERS (zenoh-c
/// `ze_advanced_subscriber_detect_publishers`).
///
/// The derived keyexpr is `<ke>/@adv/pub/**`, which is what wz's own advanced
/// subscriber builds (`advanced_ke::ke_pub_liveliness`) and what the pico ABI
/// builds — so the three agree on the namespace by construction rather than by
/// coincidence.
///
/// The handle handed back is an ordinary `z_owned_subscriber_t`, as upstream's
/// is: a C program drops it with the same `z_drop`.
///
/// # Safety
/// `subscriber` must be null or a valid loaned advanced subscriber;
/// `liveliness_subscriber` must be valid and writable; `callback` must be a
/// valid moved sample closure; `options` must be null or a valid liveliness
/// subscriber options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_detect_publishers(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    liveliness_subscriber: *mut z_owned_subscriber_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut crate::liveliness::z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Consume the moved closure FIRST.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        if liveliness_subscriber.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *liveliness_subscriber = z_owned_subscriber_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { adv_sub_state(subscriber) }) else {
            return Z_ENULL;
        };
        let Some(base) = state.shared.advanced_subscriber_keyexpr(state.id) else {
            return Z_EINVAL;
        };
        let ke = format!("{base}/@adv/pub/**");
        let history = if options.is_null() {
            false
        } else {
            // SAFETY: the caller's contract.
            unsafe { (*options).history }
        };
        // `LivelinessSubscriberOptions` is `#[non_exhaustive]`, so it is built
        // from its default and narrowed.
        let mut opts = wz_runtime_tokio::session::LivelinessSubscriberOptions::default();
        opts.history = history;
        let declared = ke.clone();
        let id = state.shared.declare_liveliness_subscriber(ke, opts, {
            let closure = Arc::new(cclosure);
            Arc::new(move || {
                Box::new(crate::liveliness::make_liveliness_callback(closure.clone())) as Box<_>
            })
        });
        // SAFETY: `liveliness_subscriber` was checked non-null above.
        unsafe {
            *liveliness_subscriber = z_owned_subscriber_t::from_handle(subscriber_state_handle(
                &state.shared,
                id,
                declared,
            ))
        };
        Z_OK
    })
}

// The self-consistency half of the layout contract, exactly as `crate::abi`
// documents: these catch a mistake in THIS file, and the C-compiler probe in
// Layer C1cc / C1ce catches the header moving underneath it.
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<z_entity_global_id_t>() == 20);
    assert!(align_of::<z_entity_global_id_t>() == 4);
    assert!(size_of::<ze_miss_t>() == 24);
    assert!(align_of::<ze_miss_t>() == 4);
    assert!(size_of::<ze_owned_closure_miss_t>() == 24);
    assert!(size_of::<ze_owned_advanced_publisher_t>() == ADV_PUB_SIZE);
    assert!(align_of::<ze_owned_advanced_publisher_t>() == 8);
    assert!(size_of::<ze_moved_advanced_publisher_t>() == ADV_PUB_SIZE);
    assert!(size_of::<ze_owned_advanced_subscriber_t>() == ADV_SUB_SIZE);
    assert!(align_of::<ze_owned_advanced_subscriber_t>() == 8);
    assert!(size_of::<ze_moved_advanced_subscriber_t>() == ADV_SUB_SIZE);
    assert!(size_of::<ze_owned_sample_miss_listener_t>() == MISS_LISTENER_SIZE);
    assert!(align_of::<ze_owned_sample_miss_listener_t>() == 8);
};
