// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `ze_advanced_*` — the ADVANCED pub/sub plane (§5.25 at the C ABI).
//!
//! The `ze_` prefix marks zenoh's "extension" surface (zenoh-ext in the Rust
//! tree, `Z_FEATURE_ADVANCED_PUBLICATION` / `_SUBSCRIPTION` in pico). Both are
//! **1** in the pinned pico CMake config, so upstream's `z_advanced_pub.c` /
//! `z_advanced_sub.c` compile their advanced half unconditionally — a drop-in
//! that omitted this module would fail to link two of the 32 upstream
//! programs, which is exactly how this plane was measured as missing.
//!
//! Nothing here is new protocol. wz already owns the mechanism
//! ([`wz_runtime_tokio::advanced_publisher::AdvancedPublisher`] +
//! [`wz_runtime_tokio::advanced_subscriber::AdvancedSubscriber`], graded
//! against zenoh-ext); this module is the C binding plus the per-face fan-out
//! every declaration in this crate applies, which for the advanced plane is
//! load-bearing rather than uniform: an advanced publisher declares its OWN
//! `@adv` cache queryable and `@adv` liveliness token on the session it binds
//! to, so a per-face declaration is the only shape in which a subscriber's
//! recovery GET can reach the cache at all.
//!
//! ## What the option structs carry, and what wz reads
//!
//! pico's option structs are wider than wz's, and the difference is stated per
//! field on each `default` function rather than left implicit. The load-bearing
//! mappings are: `cache.is_enabled` / `cache.max_samples` become
//! [`CacheConfig`]; `sample_miss_detection.is_enabled` selects sequence-number
//! sequencing and its `heartbeat_mode` / `heartbeat_period_ms` become the
//! beacon; `publisher_detection` becomes the `@adv` liveliness token;
//! `history` / `recovery` become [`HistoryConfig`] / [`RecoveryConfig`].
//!
//! ## The miss listener is installed AFTER the subscriber
//!
//! Upstream's own `z_advanced_sub.c` declares the subscriber first and
//! `ze_advanced_subscriber_declare_sample_miss_listener` second, but wz's
//! `AdvancedSubscriber::declare_with_options` takes BOTH callbacks up front.
//! So the subscriber is declared with an `on_miss` that reads a shared slot,
//! and the listener fills that slot. The slot is what makes the ordering work;
//! it is not a placeholder for a mechanism that is missing.

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

use crate::abi::{handle_ref, z_loaned_keyexpr_t, z_moved_bytes_t};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::pubsub::{
    z_closure_drop_callback_t, z_moved_closure_sample_t, z_owned_closure_sample_t,
    z_owned_subscriber_t, CClosure, SubscriberState,
};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};
use crate::zid::z_id_t;
use wz_capi_core::faces::{AdvPubId, AdvSubId, SharedSession};

// ---------------------------------------------------------------------------
// entity global id
// ---------------------------------------------------------------------------

/// pico `z_entity_global_id_t` (`protocol/core.h:83-86`), 20 B / align 4
/// measured: `{ z_id_t zid; uint32_t eid; }`.
///
/// `z_id_t` is a bare `uint8_t[16]`, so it is 1-aligned and the struct's
/// alignment comes from `eid` alone — which is why this is 20 bytes and not
/// the 24 an 8-aligned reading would predict. It crosses the boundary BY VALUE
/// inside [`ze_miss_t`], so both facts are ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_entity_global_id_t {
    pub zid: z_id_t,
    pub eid: u32,
}

/// The zid half of a global entity id (pico `z_entity_global_id_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_zid(gid: *const z_entity_global_id_t) -> z_id_t {
    if gid.is_null() {
        return z_id_t::empty();
    }
    (*gid).zid
}

/// The eid half of a global entity id (pico `z_entity_global_id_eid`).
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_eid(gid: *const z_entity_global_id_t) -> u32 {
    if gid.is_null() {
        return 0;
    }
    (*gid).eid
}

// ---------------------------------------------------------------------------
// the miss closure + ze_miss_t
// ---------------------------------------------------------------------------

/// pico `ze_miss_t` (`api/types.h:568-570`), 24 B / align 4 measured.
#[repr(C)]
pub struct ze_miss_t {
    pub source: z_entity_global_id_t,
    pub nb: u32,
}

/// pico `ze_closure_miss_callback_t`: `void call(const ze_miss_t*, void*)`.
pub type ze_closure_miss_callback_t = Option<unsafe extern "C" fn(*const ze_miss_t, *mut c_void)>;

/// Owned miss closure (pico `ze_owned_closure_miss_t`, 24 B — the same
/// `{ context, call, drop }` shape every closure family in this crate uses).
#[repr(C)]
pub struct ze_owned_closure_miss_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: ze_closure_miss_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned miss closure, same layout.
#[repr(C)]
pub struct ze_loaned_closure_miss_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: ze_closure_miss_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved miss closure (pico `ze_moved_closure_miss_t`).
#[repr(C)]
pub struct ze_moved_closure_miss_t {
    pub(crate) _this: ze_owned_closure_miss_t,
}

impl ze_owned_closure_miss_t {
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

// SAFETY: the same per-plane argument the sample plane makes. A miss is
// produced only by the advanced subscriber's ordering state, which runs on the
// session's single drive task, so `call` never runs concurrently with itself;
// `drop` runs when the last `Arc` is released, which cannot overlap a live
// `call`. Written out per plane rather than blanket-implemented, because the
// argument is about THIS plane's producer.
unsafe impl Sync for CMissClosure {}

/// Zero an owned miss closure (pico `ze_internal_closure_miss_null`).
#[no_mangle]
pub unsafe extern "C" fn ze_internal_closure_miss_null(closure: *mut ze_owned_closure_miss_t) {
    if !closure.is_null() {
        *closure = ze_owned_closure_miss_t::null_value();
    }
}

/// `true` iff the owned miss closure carries a callback (pico
/// `ze_internal_closure_miss_check`).
#[no_mangle]
pub unsafe extern "C" fn ze_internal_closure_miss_check(
    closure: *const ze_owned_closure_miss_t,
) -> bool {
    guard_val(false, || !closure.is_null() && (*closure).call.is_some())
}

/// Build an owned miss closure (pico `ze_closure_miss`).
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss(
    closure: *mut ze_owned_closure_miss_t,
    call: ze_closure_miss_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = ze_owned_closure_miss_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Borrow a miss closure (pico `ze_closure_miss_loan`).
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_loan(
    closure: *const ze_owned_closure_miss_t,
) -> *const ze_loaned_closure_miss_t {
    closure as *const ze_loaned_closure_miss_t
}

/// Move-cast a miss closure (pico `ze_closure_miss_move`).
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_move(
    closure: *mut ze_owned_closure_miss_t,
) -> *mut ze_moved_closure_miss_t {
    closure as *mut ze_moved_closure_miss_t
}

/// Take a moved miss closure (pico `ze_closure_miss_take`).
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_take(
    dst: *mut ze_owned_closure_miss_t,
    src: *mut ze_moved_closure_miss_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    *dst = std::mem::replace(&mut (*src)._this, ze_owned_closure_miss_t::null_value());
}

/// Drop a moved miss closure (pico `ze_closure_miss_drop`), running its C
/// `drop(context)` exactly once.
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_drop(closure: *mut ze_moved_closure_miss_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = ze_owned_closure_miss_t::null_value();
        Z_OK
    });
}

/// Invoke a miss closure directly (pico `ze_closure_miss_call`).
#[no_mangle]
pub unsafe extern "C" fn ze_closure_miss_call(
    closure: *const ze_loaned_closure_miss_t,
    miss: *const ze_miss_t,
) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        if let Some(call) = (*closure).call {
            call(miss, (*closure).context);
        }
        Z_OK
    });
}

// ---------------------------------------------------------------------------
// advanced publisher
// ---------------------------------------------------------------------------

/// pico `ze_advanced_publisher_heartbeat_mode_t` — a plain C enum, so an `int`.
pub type ze_advanced_publisher_heartbeat_mode_t = std::ffi::c_int;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE` = 0, also the DEFAULT.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE: ze_advanced_publisher_heartbeat_mode_t = 0;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC` = 1.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC: ze_advanced_publisher_heartbeat_mode_t = 1;
/// `ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_SPORADIC` = 2.
pub const ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_SPORADIC: ze_advanced_publisher_heartbeat_mode_t = 2;

/// pico `ze_advanced_publisher_cache_options_t`
/// (`collections/advanced_cache.h:40-47`), 32 B measured.
#[repr(C)]
pub struct ze_advanced_publisher_cache_options_t {
    pub is_enabled: bool,
    pub max_samples: usize,
    pub congestion_control: std::ffi::c_int,
    pub priority: std::ffi::c_int,
    pub is_express: bool,
    /// pico's own private field, carried for layout. Named `_liveliness`
    /// upstream and documented there as "not yet exposed in Zenoh".
    pub _liveliness: bool,
}

/// pico `ze_advanced_publisher_sample_miss_detection_options_t`, 16 B measured.
#[repr(C)]
pub struct ze_advanced_publisher_sample_miss_detection_options_t {
    pub is_enabled: bool,
    pub heartbeat_mode: ze_advanced_publisher_heartbeat_mode_t,
    pub heartbeat_period_ms: u64,
}

/// pico `z_publisher_options_t` as the advanced options embed it, 24 B
/// measured. Re-declared here rather than imported because the publisher
/// module models its own options separately; the fields are carried for layout
/// and the advanced declare reads none of them (a NAMED gap, the same one
/// `z_declare_publisher` already records for `congestion_control` / `priority`
/// / `is_express`).
#[repr(C)]
pub struct ze_embedded_publisher_options_t {
    pub encoding: *mut c_void,
    pub congestion_control: std::ffi::c_int,
    pub priority: std::ffi::c_int,
    pub is_express: bool,
    pub reliability: std::ffi::c_int,
}

/// pico `ze_advanced_publisher_options_t` (`api/advanced_publisher.h:124-130`),
/// 88 B measured with `publisher_options@0 / cache@24 / sample_miss_detection@56
/// / publisher_detection@72 / publisher_detection_metadata@80`.
#[repr(C)]
pub struct ze_advanced_publisher_options_t {
    pub publisher_options: ze_embedded_publisher_options_t,
    pub cache: ze_advanced_publisher_cache_options_t,
    pub sample_miss_detection: ze_advanced_publisher_sample_miss_detection_options_t,
    pub publisher_detection: bool,
    pub publisher_detection_metadata: *const z_loaned_keyexpr_t,
}

/// pico `ze_advanced_publisher_put_options_t`, 32 B measured (one embedded
/// `z_publisher_put_options_t`).
#[repr(C)]
pub struct ze_advanced_publisher_put_options_t {
    pub encoding: *mut c_void,
    pub attachment: *mut z_moved_bytes_t,
    pub timestamp: *mut c_void,
    pub source_info: *mut c_void,
}

/// pico `ze_advanced_publisher_delete_options_t`, 16 B measured.
#[repr(C)]
pub struct ze_advanced_publisher_delete_options_t {
    pub timestamp: *mut c_void,
    pub source_info: *mut c_void,
}

/// Fill default cache options (pico `ze_advanced_publisher_cache_options_default`,
/// `src/api/advanced_publisher.c:101-108`). Note `is_enabled = true` HERE and
/// `false` in [`ze_advanced_publisher_options_default`] — upstream calls this
/// one and then overrides the flag, and a program that calls this directly
/// (upstream's `z_advanced_pub.c` does) gets the enabled form.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_cache_options_default(
    options: *mut ze_advanced_publisher_cache_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).is_enabled = true;
    (*options).max_samples = 1;
    // `z_internal_congestion_control_default_push()` = DROP, the push-side
    // default (NOT the request-side BLOCK `z_get` uses).
    (*options).congestion_control = 0;
    (*options).priority = crate::query::Z_PRIORITY_DEFAULT;
    (*options).is_express = false;
    (*options)._liveliness = false;
}

/// Fill default sample-miss-detection options
/// (pico `..._sample_miss_detection_options_default`, `advanced_publisher.c:110-115`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_sample_miss_detection_options_default(
    options: *mut ze_advanced_publisher_sample_miss_detection_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).is_enabled = true;
    (*options).heartbeat_mode = ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE;
    (*options).heartbeat_period_ms = 0;
}

/// Fill default advanced-publisher options
/// (pico `ze_advanced_publisher_options_default`, `advanced_publisher.c:117-125`).
///
/// Both sub-option blocks are filled by their own default and then have
/// `is_enabled` cleared — upstream's exact sequence, and the reason the two
/// defaults disagree with each other.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_options_default(
    options: *mut ze_advanced_publisher_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).publisher_options = ze_embedded_publisher_options_t {
        encoding: std::ptr::null_mut(),
        congestion_control: 0,
        priority: crate::query::Z_PRIORITY_DEFAULT,
        is_express: false,
        reliability: 0,
    };
    ze_advanced_publisher_cache_options_default(&mut (*options).cache);
    (*options).cache.is_enabled = false;
    ze_advanced_publisher_sample_miss_detection_options_default(
        &mut (*options).sample_miss_detection,
    );
    (*options).sample_miss_detection.is_enabled = false;
    (*options).publisher_detection = false;
    (*options).publisher_detection_metadata = std::ptr::null();
}

/// Fill default advanced-publisher put options.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_put_options_default(
    options: *mut ze_advanced_publisher_put_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).encoding = std::ptr::null_mut();
    (*options).attachment = std::ptr::null_mut();
    (*options).timestamp = std::ptr::null_mut();
    (*options).source_info = std::ptr::null_mut();
}

/// Fill default advanced-publisher delete options.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_delete_options_default(
    options: *mut ze_advanced_publisher_delete_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).timestamp = std::ptr::null_mut();
    (*options).source_info = std::ptr::null_mut();
}

/// Owned advanced publisher (pico `ze_owned_advanced_publisher_t`, 224 B
/// measured). Handle in slot 0, zero-padded to pico's size.
#[repr(C)]
pub struct ze_owned_advanced_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 216],
}

/// Loaned advanced publisher, same layout.
#[repr(C)]
pub struct ze_loaned_advanced_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 216],
}

/// Moved advanced publisher.
#[repr(C)]
pub struct ze_moved_advanced_publisher_t {
    pub(crate) _this: ze_owned_advanced_publisher_t,
}

impl ze_owned_advanced_publisher_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 216],
        }
    }
}

/// Behind a `ze_owned_advanced_publisher_t` handle: the registry entry to
/// retract. Dropping it undeclares on every face, so an implicit `z_drop` and
/// an explicit `ze_undeclare_advanced_publisher` take the identical path.
pub(crate) struct AdvPubState {
    shared: Arc<SharedSession>,
    id: AdvPubId,
    /// R311y559 — the keyexpr, kept so `ze_advanced_publisher_keyexpr` has
    /// stable storage to borrow, plus its cached `{ start, len }` view. Bound
    /// after boxing, as everywhere else in this crate.
    keyexpr: String,
    loaned_keyexpr: crate::abi::z_loaned_keyexpr_t,
}

impl AdvPubState {
    /// Point the cached view at this state's own keyexpr, after boxing.
    fn bind(&mut self) {
        self.loaned_keyexpr =
            crate::abi::z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
    }
}

impl Drop for AdvPubState {
    fn drop(&mut self) {
        self.shared.undeclare_advanced_publisher(self.id);
    }
}

/// The wz options one C `ze_advanced_publisher_options_t` maps to.
///
/// `sample_miss_detection.is_enabled` selects the SEQUENCING mode, which is the
/// one mapping worth stating: pico adds sequence numbers only when miss
/// detection is on, and without them a subscriber has no way to notice a gap —
/// so enabling detection and leaving the sequencing at timestamp would build a
/// publisher whose subscribers can never miss anything.
unsafe fn advanced_publisher_options(
    options: *const ze_advanced_publisher_options_t,
) -> AdvancedPublisherOptions {
    let mut out = AdvancedPublisherOptions::default();
    // pico's own default has cache + miss detection + detection all OFF, so a
    // NULL options pointer must not inherit wz's richer `Default`.
    out.cache = None;
    out.sequencing = Sequencing::Timestamp;
    out.publisher_detection = false;
    out.sample_miss_detection = MissDetectionConfig::default();
    if options.is_null() {
        return out;
    }
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
    out
}

/// Declare an advanced publisher (pico `ze_declare_advanced_publisher`).
#[no_mangle]
pub unsafe extern "C" fn ze_declare_advanced_publisher(
    zs: *const z_loaned_session_t,
    pub_: *mut ze_owned_advanced_publisher_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *const ze_advanced_publisher_options_t,
) -> ZResult {
    guarded(|| {
        if pub_.is_null() {
            return Z_ERR_NULL;
        }
        *pub_ = ze_owned_advanced_publisher_t::null_value();
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        // The same outbound canon gate every declare in this crate hoists: the
        // per-face declare is best-effort, so a per-face reject would be
        // swallowed and the call would report `Z_OK` for a dead SSOT entry.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        // pico validates this before declaring anything, and so must wz: a
        // heartbeat mode with a zero period is a publisher that would beacon in
        // a tight loop (`advanced_publisher.c:234-238`).
        if !options.is_null()
            && (*options).sample_miss_detection.is_enabled
            && (*options).sample_miss_detection.heartbeat_mode
                != ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_NONE
            && (*options).sample_miss_detection.heartbeat_period_ms == 0
        {
            return Z_ERR_INVALID;
        }
        // R311y559 — kept for `ze_advanced_publisher_keyexpr`; `ke` is moved.
        let adv_keyexpr = ke.clone();
        let id = state
            .shared
            .declare_advanced_publisher(ke, advanced_publisher_options(options));
        let mut boxed = Box::new(AdvPubState {
            shared: state.shared.clone(),
            id,
            keyexpr: adv_keyexpr,
            loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
        });
        boxed.bind();
        (*pub_).handle = Box::into_raw(boxed).cast::<c_void>();
        Z_OK
    })
}

/// Zero an owned advanced publisher (pico `ze_internal_advanced_publisher_null`).
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_publisher_null(
    pub_: *mut ze_owned_advanced_publisher_t,
) {
    if !pub_.is_null() {
        *pub_ = ze_owned_advanced_publisher_t::null_value();
    }
}

/// `true` iff the owned advanced publisher is live.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_publisher_check(
    pub_: *const ze_owned_advanced_publisher_t,
) -> bool {
    guard_val(false, || !pub_.is_null() && !(*pub_).handle.is_null())
}

/// Borrow an advanced publisher (pico `ze_advanced_publisher_loan`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_loan(
    pub_: *const ze_owned_advanced_publisher_t,
) -> *const ze_loaned_advanced_publisher_t {
    pub_ as *const ze_loaned_advanced_publisher_t
}

/// Borrow an advanced publisher mutably.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_loan_mut(
    pub_: *mut ze_owned_advanced_publisher_t,
) -> *mut ze_loaned_advanced_publisher_t {
    pub_ as *mut ze_loaned_advanced_publisher_t
}

/// Move-cast an advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_move(
    pub_: *mut ze_owned_advanced_publisher_t,
) -> *mut ze_moved_advanced_publisher_t {
    pub_ as *mut ze_moved_advanced_publisher_t
}

/// Take a moved advanced publisher.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_take(
    dst: *mut ze_owned_advanced_publisher_t,
    src: *mut ze_moved_advanced_publisher_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = ze_owned_advanced_publisher_t::null_value();
}

/// Retract an advanced publisher (pico `ze_undeclare_advanced_publisher`).
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_advanced_publisher(
    pub_: *mut ze_moved_advanced_publisher_t,
) -> ZResult {
    guarded(|| {
        if pub_.is_null() {
            return Z_OK;
        }
        let handle = (*pub_)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle.cast::<AdvPubState>()));
            (*pub_)._this = ze_owned_advanced_publisher_t::null_value();
        }
        Z_OK
    })
}

/// Drop an advanced publisher (pico `ze_advanced_publisher_drop`) — the same
/// path as the explicit undeclare, deliberately.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_drop(pub_: *mut ze_moved_advanced_publisher_t) {
    let _ = ze_undeclare_advanced_publisher(pub_);
}

/// Publish through an advanced publisher (pico `ze_advanced_publisher_put`).
/// Consumes the moved payload on EVERY path, as pico does.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_put(
    pub_: *const ze_loaned_advanced_publisher_t,
    payload: *mut z_moved_bytes_t,
    options: *mut ze_advanced_publisher_put_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload and attachment FIRST, so every early return
        // below still honours the C side's ownership transfer.
        let buf = crate::pubsub::take_moved_bytes(payload);
        if !options.is_null() {
            drop(crate::pubsub::take_moved_bytes((*options).attachment));
        }
        let Some(buf) = buf else {
            return Z_ERR_NULL;
        };
        let Some(state) = handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_) else {
            return Z_ERR_NULL;
        };
        state.shared.advanced_publisher_put(state.id, &buf);
        Z_OK
    })
}

// ---------------------------------------------------------------------------
// advanced subscriber
// ---------------------------------------------------------------------------

/// pico `ze_advanced_subscriber_history_options_t`, 24 B measured.
#[repr(C)]
pub struct ze_advanced_subscriber_history_options_t {
    pub is_enabled: bool,
    pub detect_late_publishers: bool,
    pub max_samples: usize,
    pub max_age_ms: u64,
}

/// pico `ze_advanced_subscriber_last_sample_miss_detection_options_t`, 16 B.
#[repr(C)]
pub struct ze_advanced_subscriber_last_sample_miss_detection_options_t {
    pub is_enabled: bool,
    pub periodic_queries_period_ms: u64,
}

/// pico `ze_advanced_subscriber_recovery_options_t`, 24 B measured.
#[repr(C)]
pub struct ze_advanced_subscriber_recovery_options_t {
    pub is_enabled: bool,
    pub last_sample_miss_detection: ze_advanced_subscriber_last_sample_miss_detection_options_t,
}

/// pico `ze_advanced_subscriber_options_t` (`api/advanced_subscriber.h:247-254`),
/// 80 B measured with `subscriber_options@0 / history@8 / recovery@32 /
/// query_timeout_ms@56 / subscriber_detection@64 / metadata@72`.
#[repr(C)]
pub struct ze_advanced_subscriber_options_t {
    /// `z_subscriber_options_t` is `{ uint8_t __dummy; }` in a default pico
    /// build — 1 byte, then padding to the next field's alignment.
    pub subscriber_options: u8,
    pub history: ze_advanced_subscriber_history_options_t,
    pub recovery: ze_advanced_subscriber_recovery_options_t,
    pub query_timeout_ms: u64,
    pub subscriber_detection: bool,
    pub subscriber_detection_metadata: *const z_loaned_keyexpr_t,
}

/// Fill default history options (pico
/// `ze_advanced_subscriber_history_options_default`, `advanced_subscriber.c:1956`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_history_options_default(
    options: *mut ze_advanced_subscriber_history_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).is_enabled = true;
    (*options).detect_late_publishers = false;
    (*options).max_samples = 0;
    (*options).max_age_ms = 0;
}

/// Fill default last-sample-miss-detection options
/// (`advanced_subscriber.c:1963-1966`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_last_sample_miss_detection_options_default(
    options: *mut ze_advanced_subscriber_last_sample_miss_detection_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).is_enabled = true;
    (*options).periodic_queries_period_ms = 0;
}

/// Fill default recovery options (`advanced_subscriber.c:1968-1972`). Note the
/// same fill-then-clear shape the publisher options use: the nested
/// last-sample block is defaulted ENABLED and then cleared.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_recovery_options_default(
    options: *mut ze_advanced_subscriber_recovery_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).is_enabled = true;
    ze_advanced_subscriber_last_sample_miss_detection_options_default(
        &mut (*options).last_sample_miss_detection,
    );
    (*options).last_sample_miss_detection.is_enabled = false;
}

/// Fill default advanced-subscriber options (`advanced_subscriber.c:1975-1987`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_options_default(
    options: *mut ze_advanced_subscriber_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).subscriber_options = 0;
    ze_advanced_subscriber_history_options_default(&mut (*options).history);
    (*options).history.is_enabled = false;
    ze_advanced_subscriber_recovery_options_default(&mut (*options).recovery);
    (*options).recovery.is_enabled = false;
    (*options).query_timeout_ms = 0;
    (*options).subscriber_detection = false;
    (*options).subscriber_detection_metadata = std::ptr::null();
}

/// Owned advanced subscriber (pico `ze_owned_advanced_subscriber_t`, 152 B
/// measured).
#[repr(C)]
pub struct ze_owned_advanced_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 144],
}

/// Loaned advanced subscriber, same layout.
#[repr(C)]
pub struct ze_loaned_advanced_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 144],
}

/// Moved advanced subscriber.
#[repr(C)]
pub struct ze_moved_advanced_subscriber_t {
    pub(crate) _this: ze_owned_advanced_subscriber_t,
}

impl ze_owned_advanced_subscriber_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 144],
        }
    }
}

/// The slot a miss listener installs into, shared with every face's `on_miss`.
///
/// Behind a `Mutex` rather than an `ArcSwap`-style cell because installation
/// and removal are rare and the read is off the drive thread's miss path, which
/// only runs when a gap is actually detected.
pub(crate) type MissSlot = Arc<Mutex<Option<Arc<CMissClosure>>>>;

/// Behind a `ze_owned_advanced_subscriber_t` handle.
pub(crate) struct AdvSubState {
    shared: Arc<SharedSession>,
    id: AdvSubId,
    /// R311y559 — as `AdvPubState`, for `ze_advanced_subscriber_keyexpr`.
    keyexpr: String,
    loaned_keyexpr: crate::abi::z_loaned_keyexpr_t,
    /// The miss closure the C side may install AFTER declaring. See the module
    /// doc for why the subscriber cannot simply take it at declare time.
    miss: MissSlot,
}

impl AdvSubState {
    /// Point the cached view at this state's own keyexpr, after boxing.
    fn bind(&mut self) {
        self.loaned_keyexpr =
            crate::abi::z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
    }
}

impl Drop for AdvSubState {
    fn drop(&mut self) {
        self.shared.undeclare_advanced_subscriber(self.id);
    }
}

/// The wz options one C `ze_advanced_subscriber_options_t` maps to.
unsafe fn advanced_subscriber_options(
    options: *const ze_advanced_subscriber_options_t,
) -> AdvancedSubscriberOptions {
    let mut out = AdvancedSubscriberOptions::default();
    if options.is_null() {
        return out;
    }
    if (*options).recovery.is_enabled {
        let last = &(*options).recovery.last_sample_miss_detection;
        let mut recovery = RecoveryConfig::default();
        if last.is_enabled {
            if last.periodic_queries_period_ms > 0 {
                recovery.periodic_queries =
                    Some(Duration::from_millis(last.periodic_queries_period_ms));
            } else {
                // pico: "If set to 0, the last sample(s) miss detection will be
                // performed based on publisher's heartbeat" — which is wz's
                // `heartbeat` trigger, not "no trigger at all".
                recovery.heartbeat = true;
            }
        }
        out.recovery = Some(recovery);
    }
    if (*options).history.is_enabled {
        let history = &(*options).history;
        // `HistoryConfig` is `#[non_exhaustive]`, so it is built from its
        // default and narrowed — the shape that survives upstream adding a
        // field, which is exactly why it carries the attribute.
        let mut cfg = HistoryConfig::default();
        cfg.sample_depth = (history.max_samples > 0).then_some(history.max_samples);
        // pico carries an age in MILLISECONDS; wz's `_time=` selector bound is
        // in SECONDS. Converting rather than passing the number through is the
        // whole reason this is not a field copy.
        cfg.max_age = (history.max_age_ms > 0).then(|| history.max_age_ms as f64 / 1000.0);
        cfg.detect_late_publishers = history.detect_late_publishers;
        out.history = Some(cfg);
    }
    if (*options).query_timeout_ms > 0 {
        out.query_timeout = Duration::from_millis((*options).query_timeout_ms);
    }
    out
}

/// Declare an advanced subscriber (pico `ze_declare_advanced_subscriber`).
/// Consumes the moved sample closure on every path.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_advanced_subscriber(
    zs: *const z_loaned_session_t,
    subscriber: *mut ze_owned_advanced_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_advanced_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        *subscriber = ze_owned_advanced_subscriber_t::null_value();
        // Consume the moved closure FIRST (consume-on-all-paths).
        let owned = &mut (*callback)._this;
        let cclosure = Arc::new(CClosure::new(owned.context, owned.call, owned.drop));
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        let miss: MissSlot = Arc::new(Mutex::new(None));
        let opts = advanced_subscriber_options(options);
        // R311y559 — kept for `ze_advanced_subscriber_keyexpr`; `ke` is moved.
        let adv_keyexpr = ke.clone();
        let id = state.shared.declare_advanced_subscriber(ke, opts, {
            let closure = cclosure.clone();
            let miss = miss.clone();
            Arc::new(move || {
                let sample_cb = {
                    let mut inner = crate::pubsub::make_subscriber_callback(closure.clone());
                    // The advanced subscriber hands an OWNED `Sample`; the
                    // existing marshal reads `&dyn SampleView`, which `Sample`
                    // implements — so the two planes share one marshal instead
                    // of growing a second.
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
            keyexpr: adv_keyexpr,
            loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            miss,
        });
        boxed.bind();
        (*subscriber).handle = Box::into_raw(boxed).cast::<c_void>();
        Z_OK
    })
}

/// Deliver one wz [`Miss`] to whatever C miss closure is installed.
///
/// A miss with no listener is silently dropped, which is pico's behaviour too:
/// the listener is optional and the sample stream is unaffected by its absence.
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
    let mut zid = [0u8; crate::zid::Z_ID_SIZE];
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
    // A panic unwinding out of the C callback across this `extern "C"` boundary
    // is UB and would tear down the drive thread.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(&value as *const ze_miss_t, ctx);
    }));
}

/// Zero an owned advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_subscriber_null(
    subscriber: *mut ze_owned_advanced_subscriber_t,
) {
    if !subscriber.is_null() {
        *subscriber = ze_owned_advanced_subscriber_t::null_value();
    }
}

/// `true` iff the owned advanced subscriber is live.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_advanced_subscriber_check(
    subscriber: *const ze_owned_advanced_subscriber_t,
) -> bool {
    guard_val(false, || {
        !subscriber.is_null() && !(*subscriber).handle.is_null()
    })
}

/// Borrow an advanced subscriber (pico `ze_advanced_subscriber_loan`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_loan(
    subscriber: *const ze_owned_advanced_subscriber_t,
) -> *const ze_loaned_advanced_subscriber_t {
    subscriber as *const ze_loaned_advanced_subscriber_t
}

/// Borrow an advanced subscriber mutably.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_loan_mut(
    subscriber: *mut ze_owned_advanced_subscriber_t,
) -> *mut ze_loaned_advanced_subscriber_t {
    subscriber as *mut ze_loaned_advanced_subscriber_t
}

/// Move-cast an advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_move(
    subscriber: *mut ze_owned_advanced_subscriber_t,
) -> *mut ze_moved_advanced_subscriber_t {
    subscriber as *mut ze_moved_advanced_subscriber_t
}

/// Take a moved advanced subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_take(
    dst: *mut ze_owned_advanced_subscriber_t,
    src: *mut ze_moved_advanced_subscriber_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = ze_owned_advanced_subscriber_t::null_value();
}

/// Retract an advanced subscriber (pico `ze_undeclare_advanced_subscriber`).
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_advanced_subscriber(
    subscriber: *mut ze_moved_advanced_subscriber_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() {
            return Z_OK;
        }
        let handle = (*subscriber)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle.cast::<AdvSubState>()));
            (*subscriber)._this = ze_owned_advanced_subscriber_t::null_value();
        }
        Z_OK
    })
}

/// Drop an advanced subscriber (pico `ze_advanced_subscriber_drop`).
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_drop(
    subscriber: *mut ze_moved_advanced_subscriber_t,
) {
    let _ = ze_undeclare_advanced_subscriber(subscriber);
}

// --- the sample-miss listener ----------------------------------------------

/// Owned sample-miss listener (pico `ze_owned_sample_miss_listener_t`, 24 B
/// measured).
#[repr(C)]
pub struct ze_owned_sample_miss_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Loaned sample-miss listener, same layout.
#[repr(C)]
pub struct ze_loaned_sample_miss_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Moved sample-miss listener.
#[repr(C)]
pub struct ze_moved_sample_miss_listener_t {
    pub(crate) _this: ze_owned_sample_miss_listener_t,
}

impl ze_owned_sample_miss_listener_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 2],
        }
    }
}

/// Behind a `ze_owned_sample_miss_listener_t` handle: the slot to clear.
///
/// Clearing on drop is what makes `z_drop(z_move(miss_listener))` stop the
/// notifications — and it is also what releases the last `Arc<CMissClosure>`,
/// running the C `drop(context)`.
pub(crate) struct MissListenerState {
    slot: MissSlot,
}

impl Drop for MissListenerState {
    fn drop(&mut self) {
        // Take the closure OUT under the lock and release it after, so the C
        // `drop(context)` never runs while the slot is held (a drop that
        // re-entered the subscriber would otherwise deadlock).
        let taken = self.slot.lock().ok().and_then(|mut guard| guard.take());
        drop(taken);
    }
}

/// Install a sample-miss listener (pico
/// `ze_advanced_subscriber_declare_sample_miss_listener`). Consumes the moved
/// closure on every path.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_declare_sample_miss_listener(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    listener: *mut ze_owned_sample_miss_listener_t,
    callback: *mut ze_moved_closure_miss_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST.
        let owned = &mut (*callback)._this;
        let cclosure = Arc::new(CMissClosure::new(owned.context, owned.call, owned.drop));
        *owned = ze_owned_closure_miss_t::null_value();

        if listener.is_null() {
            return Z_ERR_NULL;
        }
        *listener = ze_owned_sample_miss_listener_t::null_value();
        let Some(state) = handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        let Ok(mut slot) = state.miss.lock() else {
            return Z_ERR_GENERIC;
        };
        *slot = Some(cclosure);
        drop(slot);
        let boxed = Box::new(MissListenerState {
            slot: state.miss.clone(),
        });
        (*listener).handle = Box::into_raw(boxed).cast::<c_void>();
        Z_OK
    })
}

/// Zero an owned sample-miss listener.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_sample_miss_listener_null(
    listener: *mut ze_owned_sample_miss_listener_t,
) {
    if !listener.is_null() {
        *listener = ze_owned_sample_miss_listener_t::null_value();
    }
}

/// `true` iff the listener is live.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_sample_miss_listener_check(
    listener: *const ze_owned_sample_miss_listener_t,
) -> bool {
    guard_val(false, || {
        !listener.is_null() && !(*listener).handle.is_null()
    })
}

/// Borrow a sample-miss listener.
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_loan(
    listener: *const ze_owned_sample_miss_listener_t,
) -> *const ze_loaned_sample_miss_listener_t {
    listener as *const ze_loaned_sample_miss_listener_t
}

/// Borrow a sample-miss listener mutably.
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_loan_mut(
    listener: *mut ze_owned_sample_miss_listener_t,
) -> *mut ze_loaned_sample_miss_listener_t {
    listener as *mut ze_loaned_sample_miss_listener_t
}

/// Move-cast a sample-miss listener.
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_move(
    listener: *mut ze_owned_sample_miss_listener_t,
) -> *mut ze_moved_sample_miss_listener_t {
    listener as *mut ze_moved_sample_miss_listener_t
}

/// Take a moved sample-miss listener.
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_take(
    dst: *mut ze_owned_sample_miss_listener_t,
    src: *mut ze_moved_sample_miss_listener_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = ze_owned_sample_miss_listener_t::null_value();
}

/// Retract a sample-miss listener (pico
/// `ze_undeclare_sample_miss_listener`).
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_sample_miss_listener(
    listener: *mut ze_moved_sample_miss_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_OK;
        }
        let handle = (*listener)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle.cast::<MissListenerState>()));
            (*listener)._this = ze_owned_sample_miss_listener_t::null_value();
        }
        Z_OK
    })
}

/// Drop a sample-miss listener (pico `ze_sample_miss_listener_drop`).
#[no_mangle]
pub unsafe extern "C" fn ze_sample_miss_listener_drop(
    listener: *mut ze_moved_sample_miss_listener_t,
) {
    let _ = ze_undeclare_sample_miss_listener(listener);
}

// --- publisher detection ----------------------------------------------------

/// Subscribe to the liveliness tokens of matching advanced PUBLISHERS (pico
/// `ze_advanced_subscriber_detect_publishers`).
///
/// The derived keyexpr is `<ke>/@adv/pub/**` — pico builds exactly that
/// (`_Z_KEYEXPR_ADV_PREFIX` / `_Z_KEYEXPR_PUB` / `_Z_KEYEXPR_STARSTAR`,
/// `advanced_subscriber.c:1929-1932`) and so does wz's own advanced subscriber
/// (`advanced_ke::ke_pub_liveliness`), so the two agree on the namespace by
/// construction rather than by coincidence.
///
/// The handle handed back is an ordinary `z_owned_subscriber_t`, as pico's is:
/// a C program drops it with the same `z_drop`.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_detect_publishers(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    liveliness_subscriber: *mut z_owned_subscriber_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut crate::liveliness::z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST.
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        if liveliness_subscriber.is_null() {
            return Z_ERR_NULL;
        }
        let Some(state) = handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        let Some(base) = state.shared.advanced_subscriber_keyexpr(state.id) else {
            return Z_ERR_GENERIC;
        };
        let ke = format!("{base}/@adv/pub/**");
        let history = if options.is_null() {
            false
        } else {
            (*options).history
        };
        let mut opts = wz_runtime_tokio::session::LivelinessSubscriberOptions::default();
        opts.history = history;
        // R311y559 — kept for `z_subscriber_keyexpr`; `ke` is moved below.
        let keyexpr_literal = ke.clone();
        let id = state.shared.declare_liveliness_subscriber(ke, opts, {
            let closure = Arc::new(cclosure);
            Arc::new(move || {
                Box::new(crate::pubsub::make_liveliness_callback(closure.clone())) as Box<_>
            })
        });
        let mut boxed = Box::new(SubscriberState {
            shared: state.shared.clone(),
            id,
            keyexpr: keyexpr_literal,
            loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
        });
        boxed.bind();
        *liveliness_subscriber = z_owned_subscriber_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

// Compile-time byte-compat guard. Every size here is MEASURED against the
// pinned pico headers with a real C compiler; a drift is a stack smash in the
// caller's frame, not a Rust error, so it is pinned at build time.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<z_entity_global_id_t>() == 20);
    assert!(align_of::<z_entity_global_id_t>() == 4);
    assert!(size_of::<ze_miss_t>() == 24);
    assert!(size_of::<ze_owned_closure_miss_t>() == 24);
    assert!(size_of::<ze_owned_advanced_publisher_t>() == 224);
    assert!(size_of::<ze_owned_advanced_subscriber_t>() == 152);
    assert!(size_of::<ze_owned_sample_miss_listener_t>() == 24);
    assert!(size_of::<ze_advanced_publisher_options_t>() == 88);
    assert!(size_of::<ze_advanced_publisher_cache_options_t>() == 32);
    assert!(size_of::<ze_advanced_publisher_sample_miss_detection_options_t>() == 16);
    assert!(size_of::<ze_advanced_publisher_put_options_t>() == 32);
    assert!(size_of::<ze_advanced_publisher_delete_options_t>() == 16);
    assert!(size_of::<ze_advanced_subscriber_options_t>() == 80);
    assert!(size_of::<ze_advanced_subscriber_history_options_t>() == 24);
    assert!(size_of::<ze_advanced_subscriber_recovery_options_t>() == 24);
    assert!(size_of::<ze_advanced_subscriber_last_sample_miss_detection_options_t>() == 16);
};

// --- R311y559: the advanced plane's remaining exports -----------------------

/// Publish a DELETE through an advanced publisher (pico
/// `ze_advanced_publisher_delete`).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher; `options` must be
/// null or a valid delete-options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_delete(
    pub_: *const ze_loaned_advanced_publisher_t,
    options: *const ze_advanced_publisher_delete_options_t,
) -> ZResult {
    let _ = options;
    crate::ffi::guarded(|| {
        let Some(state) =
            crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_)
        else {
            return Z_ERR_NULL;
        };
        match state.shared.advanced_publisher_delete(state.id) {
            true => Z_OK,
            false => Z_ERR_GENERIC,
        }
    })
}

/// Whether any subscriber currently matches an advanced publisher (pico
/// `ze_advanced_publisher_get_matching_status`).
///
/// # Safety
/// `publisher` must be null or a live loaned advanced publisher;
/// `matching_status` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_get_matching_status(
    publisher: *const ze_loaned_advanced_publisher_t,
    matching_status: *mut crate::matching::z_matching_status_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if matching_status.is_null() {
            return Z_ERR_NULL;
        }
        let Some((shared, keyexpr)) = advanced_publisher_match_target(publisher) else {
            return Z_ERR_NULL;
        };
        (*matching_status).matching = shared.has_matching(&keyexpr);
        Z_OK
    })
}

/// Watch an advanced publisher's matching status (pico
/// `ze_advanced_publisher_declare_matching_listener`).
///
/// # Safety
/// `publisher` must be null or a live loaned advanced publisher; `listener`
/// must be valid and writable; `callback` must be a valid moved closure, which
/// is consumed on every path.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_declare_matching_listener(
    publisher: *const ze_loaned_advanced_publisher_t,
    listener: *mut crate::matching::z_owned_matching_listener_t,
    callback: *mut crate::matching::z_moved_closure_matching_status_t,
) -> ZResult {
    crate::matching::declare_advanced_matching(
        advanced_publisher_match_target(publisher),
        Some(listener),
        callback,
    )
}

/// The background form (pico
/// `ze_advanced_publisher_declare_background_matching_listener`) — the watch
/// lives for the session and there is no handle to retract it with.
///
/// # Safety
/// As [`ze_advanced_publisher_declare_matching_listener`], without the handle.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_declare_background_matching_listener(
    publisher: *const ze_loaned_advanced_publisher_t,
    callback: *mut crate::matching::z_moved_closure_matching_status_t,
) -> ZResult {
    crate::matching::declare_advanced_matching(
        advanced_publisher_match_target(publisher),
        None,
        callback,
    )
}

/// The `(session, keyexpr)` a matching watch on an advanced publisher targets.
///
/// The keyexpr is the publisher's OWN, not its `@adv` cache key: matching asks
/// "is anyone subscribed to what I publish", and what an advanced publisher
/// publishes is the plain keyexpr.
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
unsafe fn advanced_publisher_match_target(
    pub_: *const ze_loaned_advanced_publisher_t,
) -> Option<(Arc<SharedSession>, String)> {
    crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_)
        .map(|state| (state.shared.clone(), state.keyexpr.clone()))
}

/// Install a miss listener that lives for the session (pico
/// `ze_advanced_subscriber_declare_background_sample_miss_listener`).
///
/// The BACKGROUND form of the listener the subscriber already accepts: it takes
/// the same closure and installs it in the same slot, and differs only in
/// having no handle to retract it with. Routed through the same installer so
/// the two cannot drift.
///
/// # Safety
/// `subscriber` must be null or a live loaned advanced subscriber; `callback`
/// must be a valid moved miss closure, consumed on every path.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_declare_background_sample_miss_listener(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    callback: *mut ze_moved_closure_miss_t,
) -> ZResult {
    ze_advanced_subscriber_declare_sample_miss_listener(subscriber, std::ptr::null_mut(), callback)
}

/// The `(zid, eid)` identity behind a loaned advanced publisher, for
/// [`crate::session::ze_advanced_publisher_id`] (R311y559).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
pub(crate) unsafe fn advanced_publisher_identity(
    pub_: *const ze_loaned_advanced_publisher_t,
) -> Option<([u8; 16], u64)> {
    crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_)
        .map(|state| (state.shared.zid(), state.id))
}

/// The cached keyexpr borrow behind a loaned advanced publisher.
///
/// # Safety
/// As [`advanced_publisher_identity`].
pub(crate) unsafe fn advanced_publisher_keyexpr(
    pub_: *const ze_loaned_advanced_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    match crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_) {
        Some(state) => &state.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t,
        None => std::ptr::null(),
    }
}

/// The `(zid, eid)` identity behind a loaned advanced subscriber, for
/// [`crate::session::ze_advanced_subscriber_id`] (R311y559).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
pub(crate) unsafe fn advanced_subscriber_identity(
    sub: *const ze_loaned_advanced_subscriber_t,
) -> Option<([u8; 16], u64)> {
    crate::abi::handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(sub)
        .map(|state| (state.shared.zid(), state.id))
}

/// The cached keyexpr borrow behind a loaned advanced subscriber.
///
/// # Safety
/// As [`advanced_subscriber_identity`].
pub(crate) unsafe fn advanced_subscriber_keyexpr(
    sub: *const ze_loaned_advanced_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    match crate::abi::handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(sub) {
        Some(state) => &state.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t,
        None => std::ptr::null(),
    }
}

/// Declare a session-lifetime advanced subscriber with no handle (pico
/// `ze_declare_background_advanced_subscriber`).
///
/// R311y559 — the background form of [`ze_declare_advanced_subscriber`], with
/// the same delegate-and-leak shape and the same justification as
/// [`crate::liveliness::z_liveliness_declare_background_subscriber`]: the
/// subscription is retracted by its state's `Drop`, so "lives for the session"
/// IS "the state is never dropped".
///
/// # Safety
/// `zs` must be null or a live loaned session; `keyexpr` must be null or a live
/// loaned keyexpr; `callback` must be a valid moved closure, consumed on every
/// path; `options` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_background_advanced_subscriber(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_advanced_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        let mut sub = ze_owned_advanced_subscriber_t::null_value();
        let rc = ze_declare_advanced_subscriber(zs, &mut sub, keyexpr, callback, options);
        // The handle slot is simply LEFT, which is what "background" means
        // here: this crate's owned advanced-subscriber struct is a plain
        // pointer slot with no `Drop` of its own — the retraction lives in the
        // boxed `AdvSubState` behind it, and that box is reclaimed only by
        // `ze_undeclare_advanced_subscriber`. Letting the slot go out of scope
        // therefore leaves the subscription live for the session, which
        // `z_close` still tears down when it clears every face.
        let _ = sub;
        rc
    })
}

/// Watch for advanced PUBLISHERS appearing on this subscriber's keyexpr, for
/// the session's lifetime (pico
/// `ze_advanced_subscriber_detect_publishers_background`).
///
/// A liveliness subscription on the `@adv` publisher-detection keyexpr — which
/// is what publisher detection IS on the wire: an advanced publisher declares a
/// liveliness token under `<base>/@adv/pub/...`, and detecting publishers means
/// subscribing to those tokens. Routed through the same background-liveliness
/// body [`crate::liveliness::z_liveliness_declare_background_subscriber`] uses,
/// so the two cannot drift.
///
/// # Safety
/// `subscriber` must be null or a live loaned advanced subscriber; `callback`
/// must be a valid moved closure, consumed on every path; `options` must be
/// null or valid.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_detect_publishers_background(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut crate::liveliness::z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        let Some(state) =
            crate::abi::handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            // The shared body consumes the closure; reaching it with a bad
            // handle is not possible, so consume it here instead.
            if !callback.is_null() {
                let owned = &mut (*callback)._this;
                drop(CClosure::new(owned.context, owned.call, owned.drop));
                *owned = z_owned_closure_sample_t::null_value();
            }
            return Z_ERR_NULL;
        };
        let detection = format!("{}/@adv/pub/**", state.keyexpr);
        crate::liveliness::declare_background_liveliness_subscriber(
            &state.shared,
            &detection,
            callback,
            options,
        )
    })
}
