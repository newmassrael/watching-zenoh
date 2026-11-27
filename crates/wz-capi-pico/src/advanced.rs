// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! Nothing here is new protocol. wz already owns the mechanism, in the neutral
//! `wz-ext-pubsub` (the publisher's composite, the subscriber's rules and the host that runs
//! them over an engine's port; graded against zenoh-ext); this module is the C binding. It
//! names no engine: the publisher's plane and the subscriber's host both go through the port,
//! so the tokio engine and the cooperative one run the same plane, and the per-face fan-out
//! every declaration in this crate applies is the engine's. That is load-bearing for the
//! advanced plane rather than uniform: an advanced publisher declares its OWN `@adv` cache
//! queryable and `@adv` liveliness token on the session it binds to, so a per-face declaration
//! is the only shape in which a subscriber's recovery GET can reach the cache at all.
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
//! ## The miss listeners are declared AFTER the subscriber
//!
//! Upstream's own `z_advanced_sub.c` declares the subscriber first and
//! `ze_advanced_subscriber_declare_sample_miss_listener` second, and any number
//! of listeners may follow. The C subscriber is one wz subscriber PER FACE, so
//! each face's wz subscriber reports into one set that belongs to the C handle
//! (`MissRooms`), and each C listener takes one room of it.
//!
//! R2814 — that set replaced a single slot a listener "installed into": a
//! second listener replaced the first, and dropping the first then silenced
//! the second. The slot existed because the wz subscriber took exactly one miss
//! callback at declare; wz's subscriber now has a registry of its own, and this
//! ABI's fan-in is a set for the same reason.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, NonNull};
use core::time::Duration;

use wz_capi_port::lodge::{Lodging, Strong};
use wz_capi_port::os::{condvar_in, mutex_in, Condvar, Mutex};
use wz_ext_pubsub::advanced_cache::{CacheConfig, RepliesConfig};
use wz_ext_pubsub::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherOn, AdvancedPublisherOptions, AdvancedPutOptions,
    MissDetectionConfig, Sequencing,
};
use wz_ext_pubsub::advanced_subscriber::FormsHandle;
use wz_ext_pubsub::advanced_subscriber::{
    AdvancedSubscriberOptions, Delivery, EngineSubscriber, HistoryConfig, HostError, LentCore,
    Miss, MissHandlers, OnSample, RecoveryConfig, SubscriberCore, SubscriberDetection,
};
use wz_session_core::publish_options::PublishError;

use crate::abi::{handle_ref, z_loaned_keyexpr_t, z_moved_bytes_t};
use crate::advanced_forms::{AnchorRooms, PicoSubscriberForms};
use crate::advanced_plane::PicoPlane;
use crate::entity::z_entity_global_id_t;
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::{declared_of, keyexpr_str, DeclaredKeyexpr};
use crate::prelude::*;
use crate::pubsub::{
    z_closure_drop_callback_t, z_moved_closure_sample_t, z_owned_closure_sample_t,
    z_owned_subscriber_t, CClosure,
};
use crate::result::{
    ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY,
    Z_ERR_TIMESTAMP_GENERATION_FAILED, Z_ERR_TRANSPORT_TX_FAILED, Z_OK,
};
use crate::session::{engine_held, session_handle, z_loaned_session_t, EngineHold};
use crate::write_filter::PicoSession;
use crate::zid::z_id_t;

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
            context: core::ptr::null_mut(),
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
// `drop` runs when its room is let go of, after the last call that read it
// (`MissRooms`). Written out per plane rather than blanket-implemented, because the
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
    guard_val(|| !closure.is_null() && (*closure).call.is_some())
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
    *dst = core::mem::replace(&mut (*src)._this, ze_owned_closure_miss_t::null_value());
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

/// pico `ze_advanced_publisher_heartbeat_mode_t` — a plain C enum, as wide as the target's C ABI
/// makes it (`crate::c_enum`).
pub type ze_advanced_publisher_heartbeat_mode_t = crate::c_enum::PicoEnum;
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
    pub congestion_control: crate::qos::z_congestion_control_t,
    pub priority: crate::qos::z_priority_t,
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

/// pico `ze_advanced_publisher_options_t` (`api/advanced_publisher.h:124-130`),
/// 88 B measured with `publisher_options@0 / cache@24 / sample_miss_detection@56
/// / publisher_detection@72 / publisher_detection_metadata@80`. With
/// `local-subscriber` the embedded options are 32 B, so 96 B with every later
/// field 8 B on.
///
/// `publisher_options` is the PLAIN publisher's own options type, not a second
/// spelling of its five fields: pico embeds a `z_publisher_options_t` and hands
/// it to `z_declare_publisher` (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `_Z_RETURN_IF_ERR(z_declare_publisher(zs, &pub->_val._publisher, keyexpr, &opt.publisher_options));`),
/// so the declaration that reads it is one function and the layout is one.
#[repr(C)]
pub struct ze_advanced_publisher_options_t {
    pub publisher_options: crate::pubsub::z_publisher_options_t,
    pub cache: ze_advanced_publisher_cache_options_t,
    pub sample_miss_detection: ze_advanced_publisher_sample_miss_detection_options_t,
    pub publisher_detection: bool,
    pub publisher_detection_metadata: *const z_loaned_keyexpr_t,
}

/// pico `ze_advanced_publisher_put_options_t`, 32 B measured (one embedded
/// `z_publisher_put_options_t`).
///
/// The embedded type is the plain publisher's own, not a second spelling of its
/// four fields. This struct used to list them itself, and in the wrong order:
/// `attachment` ahead of `timestamp`, where the header has `encoding`,
/// `timestamp`, `attachment`, `source_info`. A program that set the attachment
/// wrote it into the slot this side read as the timestamp, so the attachment was
/// never taken, and a program that set a timestamp had it read as an attachment.
/// Nothing saw it because nothing set either (upstream's example passes the
/// defaults), and the size assertion below holds for both orders. Embedding the
/// type is what makes the two layouts one.
#[repr(C)]
pub struct ze_advanced_publisher_put_options_t {
    pub put_options: crate::pubsub::z_publisher_put_options_t,
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
    (*options).congestion_control = crate::qos::Z_CONGESTION_CONTROL_DROP;
    (*options).priority = crate::qos::Z_PRIORITY_DEFAULT;
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
    crate::pubsub::z_publisher_options_default(&mut (*options).publisher_options);
    ze_advanced_publisher_cache_options_default(&mut (*options).cache);
    (*options).cache.is_enabled = false;
    ze_advanced_publisher_sample_miss_detection_options_default(
        &mut (*options).sample_miss_detection,
    );
    (*options).sample_miss_detection.is_enabled = false;
    (*options).publisher_detection = false;
    (*options).publisher_detection_metadata = core::ptr::null();
}

/// Fill default advanced-publisher put options.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_put_options_default(
    options: *mut ze_advanced_publisher_put_options_t,
) {
    if options.is_null() {
        return;
    }
    crate::pubsub::z_publisher_put_options_default(&mut (*options).put_options);
}

/// Fill default advanced-publisher delete options.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_delete_options_default(
    options: *mut ze_advanced_publisher_delete_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).timestamp = core::ptr::null_mut();
    (*options).source_info = core::ptr::null_mut();
}

/// The padding after the handle of an advanced publisher: to pico's 224 B on a 64-bit host, none
/// on a 32-bit one (`crate::abi::element_bytes`).
const PUBLISHER_PAD: usize = crate::abi::element_bytes(224) - core::mem::size_of::<*mut c_void>();

/// Owned advanced publisher (pico `ze_owned_advanced_publisher_t`, 224 B
/// measured on a 64-bit host). Handle in slot 0, zero-padded to pico's size.
#[repr(C)]
pub struct ze_owned_advanced_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; PUBLISHER_PAD],
}

/// Loaned advanced publisher, same layout.
#[repr(C)]
pub struct ze_loaned_advanced_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; PUBLISHER_PAD],
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
            handle: core::ptr::null_mut(),
            _pad: [0u8; PUBLISHER_PAD],
        }
    }
}

/// Behind a `ze_owned_advanced_publisher_t` handle: the composite, on this
/// session's plane. Dropping it retracts its entities in pico's order, so an
/// implicit `z_drop` and an explicit `ze_undeclare_advanced_publisher` take the
/// identical path.
pub(crate) struct AdvPubState {
    engine: crate::session::EngineHold,
    publisher: AdvancedPublisherOn<PicoPlane>,
    /// R311y559 — the cached `{ start, len }` view of the publisher's key, so
    /// `ze_advanced_publisher_keyexpr` has stable storage to borrow. Bound
    /// after boxing, as everywhere else in this crate.
    ///
    /// It is the WRAPPED PUBLISHER'S own key, declaration and all, as pico's
    /// `z_publisher_keyexpr(&pub->_publisher)` is: a put made on the loan
    /// aliases.
    loaned_keyexpr: crate::abi::z_loaned_keyexpr_t,
    /// What the loan names besides the key's text, in the state with the session it names.
    record: crate::keyexpr::RecordKey,
}

impl AdvPubState {
    /// Point the cached view at the wrapped publisher's own key, after boxing.
    fn bind(&mut self) {
        self.loaned_keyexpr = self.publisher.publisher().lend(&mut self.record);
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
    // R2485 — NONE is what a publisher with neither switch gets, and pico spells
    // that rule in one place: `vendor/zenoh-pico/src/api/advanced_publisher.c` @
    // `pub->_val._sequencing = _ZE_ADVANCED_PUBLISHER_SEQUENCING_NONE;` is the
    // else of a miss-detection / cache / else chain. wz seeded `Timestamp` here,
    // which nothing could observe until R2485 gave `Timestamp` a declare-time
    // precondition -- both values render the `uhlc` discriminator and mint no
    // seqnum, so the divergence was real and inert at the same time.
    out.sequencing = Sequencing::None;
    out.publisher_detection = false;
    out.sample_miss_detection = MissDetectionConfig::default();
    if options.is_null() {
        return out;
    }
    if (*options).cache.is_enabled {
        // R2596 — the three reply-QoS fields are READ now, through PICO's own
        // converters: its `Z_CONGESTION_CONTROL_BLOCK` is 1 where zenoh-c's is
        // 0, so the sibling ABI's mapping would invert the meaning. pico
        // applies these per reply itself
        // (`vendor/zenoh-pico/src/collections/advanced_cache.c`), and until now
        // wz read none of them.
        out.cache = Some(CacheConfig {
            max_samples: (*options).cache.max_samples.max(1),
            replies_config: RepliesConfig {
                priority: crate::qos::priority_from_pico((*options).cache.priority),
                congestion_control: crate::qos::congestion_from_pico(
                    (*options).cache.congestion_control,
                ),
                is_express: (*options).cache.is_express,
            },
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
    } else if (*options).cache.is_enabled {
        // R2485 — the middle arm of pico's chain: a cache without miss detection
        // selects Timestamp. `else if` and not a second `if`, because pico's own
        // chain lets miss detection win.
        out.sequencing = Sequencing::Timestamp;
    }
    out.publisher_detection = (*options).publisher_detection;
    // The metadata pico appends to the detection token's key in place of the `_`
    // chunk (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    // `// suffix = KE_ADV_PREFIX / KE_PUB / ZID / [ EID | KE_UHLC ] / [ meta | KE_EMPTY]`).
    // A NULL key is none, which `keyexpr_str` reports as `None`.
    out.publisher_detection_metadata =
        keyexpr_str((*options).publisher_detection_metadata).map(str::to_owned);
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
        let Some(handle) = session_handle(zs) else {
            return Z_ERR_NULL;
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
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
        // What the publisher inside is declared with: the embedded plain
        // options, read by the one function that reads them for a plain
        // publisher, and consumed at the point pico's `z_declare_publisher`
        // consumes them (after the validation above, before anything can fail).
        let declared = crate::pubsub::PublisherQos::declared_by(if options.is_null() {
            core::ptr::null()
        } else {
            &(*options).publisher_options
        });
        // The same outbound gate every declare in this crate hoists, so a key
        // no peer could take is refused with the code a plain publisher gives
        // it before anything is declared.
        if let Err(code) = crate::keyexpr::outbound_key(&ke) {
            return code;
        }
        let session = PicoSession::of(handle);
        // The publisher's source identity is the session's own zid, the one its
        // peers see in the handshake.
        let engine = session.engine.clone();
        // The publisher lies in a place of its session's, taken before anything is declared, so a
        // session with every place held refuses it and declares nothing, as pico answers a
        // publisher its heap cannot hold.
        let Some(slot) = crate::object_slot::Slot::<AdvPubState>::take_entity(
            &engine,
            crate::object_slot::Kind::AdvancedPublisher,
        ) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        let plane = PicoPlane::new(session.clone(), declared);
        let wz_options = advanced_publisher_options(options);
        let zid = engine.session_zid();
        // The publisher is declared in the state's place and the rest of the state written after
        // it, so a refused declaration leaves the place unwritten and the slot gives it back.
        let filled = slot.try_fill_in_place(|at| -> Result<(), AdvancedPublisherError> {
            let place = core::ptr::addr_of_mut!((*at).publisher)
                .cast::<core::mem::MaybeUninit<AdvancedPublisherOn<PicoPlane>>>();
            AdvancedPublisherOn::declare_in(&mut *place, plane, ke, wz_options, zid)?;
            core::ptr::addr_of_mut!((*at).engine).write(engine);
            core::ptr::addr_of_mut!((*at).loaned_keyexpr).write(
                crate::abi::z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            );
            core::ptr::addr_of_mut!((*at).record).write(crate::keyexpr::RecordKey::UNLENT);
            Ok(())
        });
        let state = match filled {
            Ok(state) => state,
            // A derived `@adv` key no peer could take is the caller's key and
            // not a failure of the session.
            Err(AdvancedPublisherError::InvalidAdvKeyexpr(_)) => return Z_ERR_INVALID,
            // A session whose ring of cached samples holds no record has no room for a cache, as
            // every fixed room of this ABI answers it.
            Err(AdvancedPublisherError::CacheRingUnavailable) => return Z_ERR_SYSTEM_OUT_OF_MEMORY,
            Err(_) => return Z_ERR_GENERIC,
        };
        // Bound where it lies: the place does not move until the undeclare gives it back.
        (*state).bind();
        (*pub_).handle = state.cast::<c_void>();
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
    guard_val(|| !pub_.is_null() && !(*pub_).handle.is_null())
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
            // Retracts the publisher's entities in pico's order, then gives its place back.
            crate::object_slot::release_entity(handle.cast::<AdvPubState>());
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
        // Consume the moved payload, attachment and encoding FIRST, so every
        // early return below still honours the C side's ownership transfer.
        let buf = crate::pubsub::take_moved_bytes(payload);
        // The moved attachment and encoding are held here for as long as the put reads them and
        // lent to it, as a plain put's are: the put copies them only into its cache's record.
        let mut attachment = None;
        let mut encoding = None;
        if !options.is_null() {
            let embedded = &(*options).put_options;
            attachment = crate::pubsub::read_moved_bytes(embedded.attachment);
            encoding = crate::encoding::take_moved_encoding(embedded.encoding);
            // The timestamp and the source info are NOT read: pico overwrites
            // both with the publisher's own sequencing before it sends
            // (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
            // `opt.put_options.timestamp = &timestamp;`), so a caller's value
            // never reaches the wire there and must not here.
        }
        let buf = match buf {
            Ok(Some(buf)) => buf,
            Ok(None) => return Z_ERR_NULL,
            Err(no_room) => return no_room.code(),
        };
        let Some(state) = handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_) else {
            return Z_ERR_NULL;
        };
        let mut put_options = AdvancedPutOptions::default();
        if let Some(attachment) = &attachment {
            put_options = put_options.with_attachment_lent(attachment.as_slice());
        }
        if let Some(encoding) = &encoding {
            put_options = put_options.with_encoding_ref(encoding.view());
        }
        advanced_publish_code(state.publisher.put_with(&buf, put_options))
    })
}

/// What an advanced put or delete answers for what the publisher did with the sample.
///
/// `Z_OK` when the write filter held the sample back as well as when it went out: the publisher
/// answers for the put, not for a recipient. A sample refused for want of a time answers
/// `Z_ERR_TIMESTAMP_GENERATION_FAILED`, the code pico's put returns when its `z_timestamp_new`
/// fails (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `_Z_CLEAN_RETURN_IF_ERR(z_timestamp_new(timestamp, &sess_rc), _z_session_rc_drop(&sess_rc));`):
/// a session with no time left, and the `trusted-only` policy withholding an untrusted clock's
/// stamp, which pico has no policy for and whose sample is as unmade. A sample the queue profile
/// dropped behind a held conduit answers pico's failed send, as a plain put does. A sample whose
/// record is longer than the session's ring of cached samples answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY`,
/// as every fixed room of this ABI does when it is full: pico's cache would have copied it to the
/// heap, and the ring has no room for it.
fn advanced_publish_code(sent: Result<usize, PublishError>) -> ZResult {
    match sent {
        Ok(_) => Z_OK,
        Err(PublishError::TimestampExhausted | PublishError::ClockUntrusted) => {
            Z_ERR_TIMESTAMP_GENERATION_FAILED
        }
        Err(PublishError::HeldConduit) => Z_ERR_TRANSPORT_TX_FAILED,
        Err(PublishError::ExceedsCacheRoom) => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        Err(_) => Z_ERR_GENERIC,
    }
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
    (*options).subscriber_detection_metadata = core::ptr::null();
}

/// The padding after the handle of an advanced subscriber: to pico's 152 B on a 64-bit host, none
/// on a 32-bit one (`crate::abi::element_bytes`).
const SUBSCRIBER_PAD: usize = crate::abi::element_bytes(152) - core::mem::size_of::<*mut c_void>();

/// Owned advanced subscriber (pico `ze_owned_advanced_subscriber_t`, 152 B
/// measured on a 64-bit host).
#[repr(C)]
pub struct ze_owned_advanced_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; SUBSCRIBER_PAD],
}

/// Loaned advanced subscriber, same layout.
#[repr(C)]
pub struct ze_loaned_advanced_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; SUBSCRIBER_PAD],
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
            handle: core::ptr::null_mut(),
            _pad: [0u8; SUBSCRIBER_PAD],
        }
    }
}

/// The C miss listeners declared on one C advanced subscriber, shared with
/// every face's wz subscriber, which reports into it, and lodged in the subscriber's place
/// ([`AdvSubKept`]). See the module doc.
pub(crate) type MissSlot = Strong<MissRooms>;

/// The rooms of one advanced subscriber's miss listeners, `MAX_SAMPLE_MISS_LISTENERS` of them,
/// reserved with the subscriber's place: a listener takes a room and gives it back, so declaring
/// one takes no memory, and one past the rooms is refused.
///
/// The book, under its lock, says which listener holds each room and how many calls read its
/// closure; a closure is written only while no call reads it (its room free, or its listener
/// leaving with no call left), so a call reads it unlocked and a listener may retract itself from
/// inside its own callback. A listener retracted while a call runs it is let go of by the last such
/// call, and the retraction waits for that unless it is made from inside a callback, which may be
/// that call: zenoh-pico's undeclare returns once its callback is finished (`_z_sync_group_wait`).
pub(crate) struct MissRooms {
    book: Mutex<MissBook>,
    vacated: Condvar,
    closures: [core::cell::UnsafeCell<Option<CMissClosure>>;
        wz_session_core::caps::MAX_SAMPLE_MISS_LISTENERS],
}

// SAFETY: a room's closure is read only by calls the book counts and written only while none
// does, under the book's lock; a C miss closure is called and let go of from any thread
// (`CMissClosure` is `Sync`).
unsafe impl Sync for MissRooms {}

/// Who holds each room of a [`MissRooms`].
struct MissBook {
    /// The id the next listener takes; ids grow, so a call reaches the listeners in the order
    /// they were declared, and `0` names none.
    next_id: u64,
    rooms: [MissRoom; wz_session_core::caps::MAX_SAMPLE_MISS_LISTENERS],
}

/// One room of a [`MissRooms`]: free while its id is `0`.
#[derive(Clone, Copy, Default)]
struct MissRoom {
    id: u64,
    /// The calls reading the room's closure now.
    calls: usize,
    /// Retracted: no call starts on it, and the last one running lets its closure go.
    leaving: bool,
    /// Declared with no handle, so its subscriber's release retracts it.
    background: bool,
}

impl MissRooms {
    /// Rooms all free, made in `place`, where they stay: the book's lock and the condition
    /// variable are made there ([`mutex_in`]).
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self`, aligned for it and holds none; the rooms are not
    /// moved from it until they are dropped there.
    unsafe fn write_in(place: NonNull<Self>) {
        let at = place.as_ptr();
        // SAFETY: the caller's: each field is made once through a pointer to it, not null as it
        // is inside the place.
        unsafe {
            mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).book)), |book| {
                book.write(MissBook {
                    next_id: 1,
                    rooms: [MissRoom::default(); wz_session_core::caps::MAX_SAMPLE_MISS_LISTENERS],
                })
            });
            condvar_in(NonNull::new_unchecked(addr_of_mut!((*at).vacated)));
            addr_of_mut!((*at).closures)
                .write(core::array::from_fn(|_| core::cell::UnsafeCell::new(None)));
        }
    }

    /// A free room for `closure`, `background` when no handle retracts it: the room's index, or
    /// the closure handed back when every room is taken, for the caller to let go of unlocked.
    fn insert(&self, closure: CMissClosure, background: bool) -> Result<usize, CMissClosure> {
        let mut guard = self.book.lock();
        let book = &mut *guard;
        let free = book
            .rooms
            .iter_mut()
            .zip(&self.closures)
            .enumerate()
            .find(|(_, (room, _))| room.id == 0);
        let Some((index, (room, cell))) = free else {
            return Err(closure);
        };
        // SAFETY: a free room's closure is read by no call, and it is written under the book's
        // lock.
        unsafe { *cell.get() = Some(closure) };
        *room = MissRoom {
            id: book.next_id,
            calls: 0,
            leaving: false,
            background,
        };
        book.next_id = book.next_id.wrapping_add(1).max(1);
        Ok(index)
    }

    /// Retract the listener in room `index` when it is `background` as asked: its closure goes
    /// now when no call runs it, else with the last call, which this waits for unless it is made
    /// from inside a callback.
    fn remove(&self, index: usize, background: bool) {
        let mut guard = self.book.lock();
        let Some((room, cell)) = guard.rooms.get_mut(index).zip(self.closures.get(index)) else {
            return;
        };
        if room.id == 0 || room.leaving || room.background != background {
            return;
        }
        room.leaving = true;
        let id = room.id;
        if room.calls == 0 {
            // SAFETY: the room is leaving and no call reads it, so none will.
            let closure = unsafe { (*cell.get()).take() };
            drop(guard);
            // The closure's `drop(context)` runs unlocked, as it may re-enter the session.
            drop(closure);
            self.vacate(index);
            return;
        }
        if crate::ffi::InCallback::here() {
            return;
        }
        while guard.rooms.get(index).is_some_and(|room| room.id == id) {
            guard = self.vacated.wait(guard);
        }
    }

    /// Retract every listener declared with no handle.
    fn leave_background(&self) {
        for index in 0..wz_session_core::caps::MAX_SAMPLE_MISS_LISTENERS {
            self.remove(index, true);
        }
    }

    /// Call `call` with each listener the rooms hold as it starts, in the order they were
    /// declared, each with the book unlocked: one retracted during the calls and not yet reached
    /// is not called, and one declared during them is not either.
    fn each(&self, mut call: impl FnMut(&CMissClosure)) {
        let end = self.book.lock().next_id;
        let mut from = 1;
        loop {
            let mut guard = self.book.lock();
            let next = guard
                .rooms
                .iter_mut()
                .zip(&self.closures)
                .enumerate()
                .filter(|(_, (room, _))| room.id >= from && room.id < end && !room.leaving)
                .min_by_key(|(_, (room, _))| room.id)
                .map(|(index, (room, cell))| {
                    room.calls = room.calls.saturating_add(1);
                    (index, room.id, cell)
                });
            drop(guard);
            let Some((index, id, cell)) = next else {
                break;
            };
            // SAFETY: this call is counted in the room's book, so its closure is not written
            // until the call leaves.
            if let Some(closure) = unsafe { (*cell.get()).as_ref() } {
                call(closure);
            }
            self.leave_call(index, cell);
            from = id.saturating_add(1);
        }
    }

    /// A call of room `index` returned: the last call of a retracted listener lets its closure go
    /// and gives the room back.
    fn leave_call(&self, index: usize, cell: &core::cell::UnsafeCell<Option<CMissClosure>>) {
        let mut guard = self.book.lock();
        let Some(room) = guard.rooms.get_mut(index) else {
            return;
        };
        room.calls = room.calls.saturating_sub(1);
        if !(room.leaving && room.calls == 0) {
            return;
        }
        // SAFETY: the room is leaving and this was the last call reading it.
        let closure = unsafe { (*cell.get()).take() };
        drop(guard);
        drop(closure);
        self.vacate(index);
    }

    /// Room `index`'s listener is gone, its closure let go of: the room is free, and a retraction
    /// waiting for it returns.
    fn vacate(&self, index: usize) {
        if let Some(room) = self.book.lock().rooms.get_mut(index) {
            *room = MissRoom::default();
        }
        self.vacated.notify_all();
    }

    /// The listeners declared and not retracted.
    #[cfg(all(test, feature = "engine-tokio"))]
    fn declared(&self) -> usize {
        self.book
            .lock()
            .rooms
            .iter()
            .filter(|room| room.id != 0 && !room.leaving)
            .count()
    }
}

/// Behind a `ze_owned_advanced_subscriber_t` handle, in a place of its session's
/// ([`AdvSubPlace`]).
pub(crate) struct AdvSubState {
    engine: crate::session::EngineHold,
    /// The subscriber the engine hosts, until its owner lets go of it. Dropping it retracts
    /// everything it declared, in the order the runtime's own subscriber does; a background
    /// subscriber is taken out to run on with its entities standing. Hosted on the engine as the
    /// build names it, so a build of one engine makes no table of the session's operations for it.
    subscriber: Option<EngineSubscriber<EngineHold>>,
    /// R311y559 — as `AdvPubState`, for `ze_advanced_subscriber_keyexpr`: a borrow of the key the
    /// subscriber keeps, which no copy of this state's doubles.
    loaned_keyexpr: crate::abi::z_loaned_keyexpr_t,
    /// The miss listeners the C side declares AFTER declaring this, lodged in the subscriber's
    /// place once it is filled ([`lodge_miss_set`]). See the module doc. The background ones'
    /// closures are counted in this subscriber's place and leave the rooms before its owner waits
    /// for them.
    miss: Option<MissSlot>,
    /// The count of the session the subscriber was declared on, which a background detection
    /// holds open as a background subscriber's closure does; read only while the session is open.
    /// `None` for a state made with no session (a face-less test subscriber).
    session: Option<crate::ffi::CountIn>,
}

/// An advanced subscriber's place: its state, which its owner lets go of, and what the host reads
/// past it ([`AdvSubKept`]); the last of the owner, the closure and the hold of the host's part
/// gives the place back (`crate::object_slot::Answering`).
pub(crate) type AdvSubPlace = crate::object_slot::Answering<AdvSubState, AdvSubKept>;

/// The C sample closure an advanced subscriber's host calls where its place keeps it, and for a
/// background subscriber a hold on its session's count, so the session's close waits for the
/// closure as pico's does (`_z_sync_group_wait`). Let go of in that order, when the host lets go
/// of the sample callback ([`let_go_adv_sample`]).
pub(crate) struct SampleKept {
    closure: CClosure,
    // Held for its drop, which lets the session's count go after the closure; never read.
    _session: Option<crate::ffi::HeldIn>,
}

impl SampleKept {
    /// `closure`, kept with `session`, the hold of a background subscriber's session.
    fn new(closure: CClosure, session: Option<crate::ffi::HeldIn>) -> Self {
        Self {
            closure,
            _session: session,
        }
    }
}

/// What an advanced subscriber's place keeps past its state for the host: the C sample closure
/// the host calls, with the hold on a background subscriber's session, taken out when the host
/// lets go of it; and the part the host's callbacks, gets and jobs share, lodged here, with the
/// hold of the place it keeps open until the host gives it back ([`let_go_core`]).
///
/// The miss listeners' set lies here too, with a keep of the place: the owned listeners' handles
/// reach it after the subscriber's owner let go, and its undeclare does not wait for them. So do
/// the forms that name the subscriber's entities, with a keep of their own, and the rooms of the
/// anchors those names stand on, each anchor keeping the place while it stands.
pub(crate) struct AdvSubKept {
    sample: SampleKept,
    core: SubscriberCore<EngineHold>,
    core_hold: core::mem::MaybeUninit<crate::ffi::HeldIn>,
    miss: core::mem::MaybeUninit<Lodging<MissRooms>>,
    miss_keep: core::mem::MaybeUninit<crate::ffi::KeptIn>,
    forms: core::mem::MaybeUninit<Lodging<PicoSubscriberForms>>,
    forms_keep: core::mem::MaybeUninit<crate::ffi::KeptIn>,
    anchors: AnchorRooms,
}

impl AdvSubKept {
    /// `sample` kept, with nothing lodged and no hold for it.
    fn new(sample: SampleKept) -> Self {
        Self {
            sample,
            core: SubscriberCore::vacant(),
            core_hold: core::mem::MaybeUninit::uninit(),
            miss: Lodging::vacant(),
            miss_keep: core::mem::MaybeUninit::uninit(),
            forms: Lodging::vacant(),
            forms_keep: core::mem::MaybeUninit::uninit(),
            anchors: AnchorRooms::new(),
        }
    }
}

/// The miss listeners' set of an advanced subscriber, lodged in its place, which a keep holds until
/// the set's last count is let go of ([`let_go_miss_place`]).
///
/// # Safety
/// `state` was filled for an `AdvSubPlace`, its owner holds it, and no set is lodged in it yet.
unsafe fn lodge_miss_set(state: *mut AdvSubState) -> MissSlot {
    let make = |place: NonNull<MissRooms>| {
        // SAFETY: the place is the subscriber's, valid for one set, holding none, never moved
        // while the set is counted.
        unsafe { MissRooms::write_in(place) }
    };
    // SAFETY: the caller's; the keep is written before the set is lodged, and the set lies in the
    // place, which stands until `let_go_miss_place` lets go of the keep, once, and takes no lock;
    // `make` makes the whole set there.
    unsafe {
        let kept = crate::object_slot::kept_at::<AdvSubState, AdvSubKept>(state);
        (*kept)
            .miss_keep
            .write(crate::object_slot::keep_entity::<AdvSubState, AdvSubKept>(
                state,
            ));
        Strong::lodge_in(
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*kept).miss)),
            make,
            let_go_miss_place,
            kept.cast::<c_void>(),
        )
    }
}

/// The last count of a subscriber's miss set was let go of: the keep of the place is too, which
/// gives the place back if its owner and every closure went first.
///
/// # Safety
/// `context` is the kept part of an advanced subscriber's place whose keep for the set was
/// written ([`lodge_miss_set`]) and is let go of once, here.
unsafe fn let_go_miss_place(context: *mut c_void) {
    let kept = context.cast::<AdvSubKept>();
    // SAFETY: the caller's: the keep is read out of the place once and dropped out of it.
    drop(unsafe { core::ptr::addr_of!((*kept).miss_keep).read().assume_init() });
}

/// The forms of an advanced subscriber's entities, lodged in its place beside the rooms of their
/// anchors, with a keep of the place held until the forms' last count is let go of
/// ([`let_go_forms_place`]); each anchor lodged keeps the place too while it stands.
///
/// # Safety
/// `state` was filled for an `AdvSubPlace`, its owner holds it until the subscriber's entities
/// are declared, and no forms are lodged in it yet.
unsafe fn lodge_forms(
    state: *mut AdvSubState,
    session: &PicoSession,
    base: DeclaredKeyexpr,
) -> Strong<PicoSubscriberForms> {
    // SAFETY: the caller's; the keep is written before the forms are lodged, and the forms and
    // the rooms lie in the place, which stands while the keep or an anchor's keep is held.
    unsafe {
        let kept = crate::object_slot::kept_at::<AdvSubState, AdvSubKept>(state);
        let keep = crate::object_slot::keep_entity::<AdvSubState, AdvSubKept>(state);
        let place = keep.count();
        (*kept).forms_keep.write(keep);
        let rooms = core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*kept).anchors));
        // Inside this block, so the call below is under its SAFETY: the place handed is the
        // subscriber's, valid for the forms, holding none, never moved while they are counted;
        // the rooms are vacant and stand as `write_in` asks.
        let make = |at: NonNull<PicoSubscriberForms>| {
            PicoSubscriberForms::write_in(at, session, base, rooms, Some(place));
        };
        Strong::lodge_in(
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*kept).forms)),
            make,
            let_go_forms_place,
            kept.cast::<c_void>(),
        )
    }
}

/// The last count of a subscriber's forms was let go of: the keep of the place is too, which
/// gives the place back if its owner, every closure and every anchor went first.
///
/// # Safety
/// `context` is the kept part of an advanced subscriber's place whose keep for the forms was
/// written ([`lodge_forms`]) and is let go of once, here.
unsafe fn let_go_forms_place(context: *mut c_void) {
    let kept = context.cast::<AdvSubKept>();
    // SAFETY: the caller's: the keep is read out of the place once and dropped out of it.
    drop(unsafe { core::ptr::addr_of!((*kept).forms_keep).read().assume_init() });
}

/// The host gave back the place of its part: the hold of the subscriber's place it kept open is
/// let go of, which gives the place back if its owner and every closure went first.
///
/// # Safety
/// `context` is the kept part of an advanced subscriber's place whose hold for the host's part
/// was written ([`declare_subscriber_state`]) and is let go of once, here.
unsafe fn let_go_core(context: *mut c_void) {
    let kept = context.cast::<AdvSubKept>();
    // SAFETY: the caller's: the hold is read out of the place once and dropped out of it, as its
    // drop may give the place back.
    drop(unsafe { core::ptr::addr_of!((*kept).core_hold).read().assume_init() });
}

/// The sample callback the host keeps for an advanced subscriber, lent over the subscriber's
/// place: it reads the C closure where the place keeps it, so nothing is allocated for it.
///
/// # Safety
/// `context` is an advanced subscriber's state in its place, whose kept closure is counted in the
/// place and not taken out yet ([`let_go_adv_sample`]).
unsafe fn hand_adv_sample(context: *mut c_void, sample: Delivery<'_>) {
    // SAFETY: the caller's: the place stands while the closure it keeps is counted in it.
    let kept = unsafe {
        &*crate::object_slot::kept_at::<AdvSubState, AdvSubKept>(context.cast::<AdvSubState>())
    };
    crate::pubsub::hand_sample(
        &kept.sample.closure,
        &wz_session_core::sink::SampleRef::of(sample.view()),
    );
}

/// The host let go of the sample callback, after its last call: the C closure is taken out of the
/// place and dropped, which may give the place back.
///
/// # Safety
/// As [`hand_adv_sample`]'s, called once, after the last call.
unsafe fn let_go_adv_sample(context: *mut c_void) {
    // SAFETY: the caller's: the closure the place keeps is taken out once, here, and dropped out
    // of it, as its drop may give the place back.
    drop(unsafe {
        let kept =
            crate::object_slot::kept_at::<AdvSubState, AdvSubKept>(context.cast::<AdvSubState>());
        core::ptr::addr_of!((*kept).sample).read()
    });
}

/// The miss listener the host holds from the start, lent over a count of the subscriber's miss
/// set: every C miss listener declared on the set hears the miss.
///
/// # Safety
/// `context` is a count of a miss set ([`MissSlot`]) not yet let go of ([`let_go_miss_set`]).
unsafe fn fire_adv_miss(context: *mut c_void, miss: Miss) {
    // SAFETY: the caller's: the count holds the set.
    let set = unsafe { Strong::<MissRooms>::value_of(context) };
    fire_miss(set, &miss);
}

/// Let go of the count of the miss set the host's listener held.
///
/// # Safety
/// As [`fire_adv_miss`]'s, called once, after the last call.
unsafe fn let_go_miss_set(context: *mut c_void) {
    // SAFETY: the caller's: the count was made by `Strong::into_raw` and is let go of once.
    drop(unsafe { Strong::<MissRooms>::from_raw(context) });
}

impl AdvSubState {
    /// Point the cached view at the key the subscriber keeps.
    fn bind(&mut self) {
        let keyexpr = self.keyexpr().unwrap_or_default();
        self.loaned_keyexpr =
            crate::abi::z_loaned_keyexpr_t::borrowed(keyexpr.as_ptr(), keyexpr.len());
    }

    /// The key the subscriber subscribes to, while its owner holds it.
    fn keyexpr(&self) -> Option<&str> {
        self.subscriber.as_ref().map(EngineSubscriber::keyexpr)
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
        // R2617 — the C twin's rewrite, for the same reason: private fields plus
        // exclusive-by-type triggers, and the branch was already exclusive.
        let recovery = if !last.is_enabled {
            RecoveryConfig::new()
        } else if last.periodic_queries_period_ms > 0 {
            RecoveryConfig::new()
                .with_periodic_queries(Duration::from_millis(last.periodic_queries_period_ms))
        } else {
            // pico: "If set to 0, the last sample(s) miss detection will be
            // performed based on publisher's heartbeat" — which is wz's
            // `heartbeat` trigger, not "no trigger at all".
            RecoveryConfig::new().with_heartbeat()
        };
        out.recovery = Some(recovery);
    }
    if (*options).history.is_enabled {
        let history = &(*options).history;
        // `HistoryConfig` is `#[non_exhaustive]`, so it is built from its
        // default and narrowed — the shape that survives upstream adding a
        // field, which is exactly why it carries the attribute.
        let mut cfg = HistoryConfig::default();
        cfg.sample_depth = (history.max_samples > 0).then_some(history.max_samples);
        // pico carries an age in MILLISECONDS, built into the `Duration` the
        // selector is written from without passing through seconds as `f64`.
        cfg.max_age =
            (history.max_age_ms > 0).then(|| core::time::Duration::from_millis(history.max_age_ms));
        cfg.detect_late_publishers = history.detect_late_publishers;
        out.history = Some(cfg);
    }
    if (*options).query_timeout_ms > 0 {
        out.query_timeout = Duration::from_millis((*options).query_timeout_ms);
    }
    // R2815 — honoured; see the zenoh-c twin. The fields were declared and
    // read by nothing, so `subscriber_detection = true` declared no token.
    if (*options).subscriber_detection {
        let mut detection = SubscriberDetection::new();
        if let Some(meta) = keyexpr_str((*options).subscriber_detection_metadata) {
            detection = detection.with_metadata(meta);
        }
        out.subscriber_detection = Some(detection);
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
        match declare_subscriber_state(zs, keyexpr, callback, options, false) {
            Ok(state) => {
                (*subscriber).handle = state.cast::<c_void>();
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// What an advanced subscriber's two entry points, owned and background, both make: the
/// subscriber on the session's engine, and its state in a place of the session's, taken before
/// anything is declared, so a session with every place held refuses it and declares nothing. The
/// C sample closure is kept in the place and counted in it, and a `background` subscriber's keeps
/// its session's count open beside it, so the session's close waits for it. Consumes the moved
/// sample closure on every path; a refused declaration lets go of the closure and of the place.
///
/// # Safety
/// As the doors': `zs` and `keyexpr` null or live loans, `callback` a valid moved closure,
/// `options` null or valid.
unsafe fn declare_subscriber_state(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_advanced_subscriber_options_t,
    background: bool,
) -> Result<*mut AdvSubState, ZResult> {
    // Consume the moved closure FIRST (consume-on-all-paths).
    let owned = &mut (*callback)._this;
    let closure = CClosure::uncounted(owned.context, owned.call, owned.drop);
    *owned = z_owned_closure_sample_t::null_value();

    // A closed session takes no declaration; the closure consumed above runs its drop.
    let handle = crate::session::open_session_handle(zs)?;
    let ke = crate::keyexpr::outbound_keyexpr(keyexpr)?;
    let engine = engine_held(handle);
    let slot = crate::object_slot::Slot::<AdvSubPlace>::take_entity(
        engine,
        crate::object_slot::Kind::AdvancedSubscriber,
    )
    .ok_or(Z_ERR_SYSTEM_OUT_OF_MEMORY)?;
    // pico builds this subscriber from plain entities, each declaring and
    // naming its key the way its own entry point does — see
    // `crate::advanced_forms`. The caller's key is what they derive from.
    // A key the caller did not declare is kept in the session's key arena, as any object of the
    // session keeps its key, so the subscriber's entities share its block and copy no text.
    let base = match declared_of(keyexpr) {
        Some(declared) => declared.share()?,
        None => DeclaredKeyexpr::literal_of_session(engine, ke)?,
    };
    let session = crate::session::session_count(zs);
    let state = slot
        .fill_answering(
            AdvSubState {
                engine: crate::session::EngineHold::clone(engine),
                subscriber: None,
                loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
                miss: None,
                session: Some(session),
            },
            AdvSubKept::new(SampleKept::new(closure, background.then(|| session.hold()))),
        )
        .cast::<AdvSubState>();
    // SAFETY: `state` was filled for an `AdvSubPlace` just above, and its owner holds it; the
    // closure is counted in the place before anything can call it or let it go, so the place
    // stands until the host lets go of the sample callback, and a C sample closure is called from
    // any thread (`CClosure` is `Sync` for it).
    let kept = unsafe { crate::object_slot::kept_at::<AdvSubState, AdvSubKept>(state) };
    // SAFETY: as above.
    let on_sample = unsafe {
        crate::object_slot::count_in_entity::<AdvSubState, AdvSubKept, _>(
            state,
            &mut (*kept).sample.closure,
        );
        OnSample::lent(
            hand_adv_sample,
            state.cast::<c_void>(),
            Some(let_go_adv_sample),
        )
    };
    // The host's part is lodged in the place, which a hold keeps open until the host gives the
    // part back, after the last of its callbacks, gets and jobs.
    // SAFETY: as above; the hold is written before the part is lent, and the part lies in the
    // place, which stands until `let_go_core` lets go of the hold, once, and takes no lock.
    let core = unsafe {
        (*kept)
            .core_hold
            .write(crate::object_slot::hold_entity::<AdvSubState, AdvSubKept>(
                state,
            ));
        LentCore::new(
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*kept).core)),
            let_go_core,
            kept.cast::<c_void>(),
        )
    };
    // SAFETY: as above; the forms are asked only while the subscriber's entities are declared,
    // below, while the owner holds the place.
    let forms = unsafe { lodge_forms(state, PicoSession::of(handle), base) };
    let opts =
        advanced_subscriber_options(options).with_declaration_forms(FormsHandle::lodged(forms));
    // SAFETY: as above.
    let miss = unsafe { lodge_miss_set(state) };
    let lent_miss = Strong::into_raw(miss.clone());
    // SAFETY: as above.
    unsafe { (*state).miss = Some(miss) };
    // SAFETY: the context is a count of the miss set, let go of once by `let_go_miss_set`; the
    // set is read through a shared borrow, which it admits from any thread.
    let misses = unsafe { MissHandlers::lent(fire_adv_miss, lent_miss, Some(let_go_miss_set)) };
    let declared = EngineSubscriber::declare_in(engine, ke, opts, on_sample, misses, core);
    match declared {
        Ok(subscriber) => {
            // SAFETY: as above; the state was filled with no subscriber, so the write lets go of
            // nothing in its place.
            unsafe { core::ptr::addr_of_mut!((*state).subscriber).write(Some(subscriber)) };
            (*state).bind();
            Ok(state)
        }
        Err(refused) => {
            // The refusal dropped the sample callback, which let the closure go, and the host's
            // part, whose place goes back once nothing holds it; the owner lets go of the place
            // with the state.
            crate::object_slot::retire_entity::<AdvSubState, AdvSubKept>(state);
            Err(match refused {
                // A bound that asks for nothing is the caller's, as upstream's own builder
                // refuses it.
                HostError::HistoryBoundZero { .. } => Z_ERR_INVALID,
                _ => Z_ERR_GENERIC,
            })
        }
    }
}

/// Let go of an advanced subscriber: everything it declared is retracted, which lets the host let
/// go of its sample callback after the last call, its background miss listeners leave the set,
/// the release waits for those closures (pico's `_z_sync_group_wait`) unless it is made from
/// inside a callback, and the place goes back with the last of the handle and the closures.
///
/// # Safety
/// `state` is a live handle [`declare_subscriber_state`] made, let go of once.
unsafe fn free_advanced_subscriber(state: *mut AdvSubState) {
    drop((*state).subscriber.take());
    if let Some(set) = (*state).miss.as_deref() {
        set.leave_background();
    }
    crate::object_slot::closures_of::<AdvSubState, AdvSubKept>(state).wait_none();
    crate::object_slot::retire_entity::<AdvSubState, AdvSubKept>(state);
}

/// Deliver one wz [`Miss`] to every declared C miss listener.
///
/// A miss with no listener is silently dropped, which is pico's behaviour too:
/// the listener is optional and the sample stream is unaffected by its absence.
fn fire_miss(slot: &MissRooms, miss: &Miss) {
    let source = miss.source();
    let mut zid = [0u8; crate::zid::Z_ID_SIZE];
    for (to, from) in zid.iter_mut().zip(source.zid()) {
        *to = *from;
    }
    let value = ze_miss_t {
        source: z_entity_global_id_t {
            zid: z_id_t { id: zid },
            eid: source.eid(),
        },
        nb: miss.nb(),
    };
    // Called with the set UNLOCKED (`each`), so a listener that undeclares itself from inside
    // its own callback does not deadlock, and with nothing copied out of it.
    slot.each(|closure| {
        let Some(call) = closure.call else {
            return;
        };
        let ctx = closure.context.0;
        let Some(_in_callback) = crate::ffi::InCallback::enter() else {
            return;
        };
        // A panic unwinding out of the C callback across this `extern "C"`
        // boundary is UB and would tear down the drive thread.
        let _ = crate::ffi::catch(|| unsafe {
            call(&value as *const ze_miss_t, ctx);
        });
    });
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
    guard_val(|| !subscriber.is_null() && !(*subscriber).handle.is_null())
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
            free_advanced_subscriber(handle.cast::<AdvSubState>());
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
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 2],
        }
    }
}

/// The word of an owned listener's handle that names its room in its subscriber's rooms, beside
/// the count of the rooms the handle holds: a number, never read through.
fn room_word(index: usize) -> *mut c_void {
    core::ptr::null_mut::<u8>()
        .wrapping_add(index)
        .cast::<c_void>()
}

/// The room [`room_word`] names.
fn room_of(word: *mut c_void) -> usize {
    word as usize
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
        // Consume the moved closure FIRST. Its room is what an undeclare waits on, so it is counted
        // in nothing.
        let cclosure = take_miss_closure(callback, CMissClosure::uncounted);

        if listener.is_null() {
            return Z_ERR_NULL;
        }
        *listener = ze_owned_sample_miss_listener_t::null_value();
        let Some(state) = handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        let Some(set) = state.miss.as_ref() else {
            return Z_ERR_NULL;
        };
        let room = match set.insert(cclosure, false) {
            Ok(room) => room,
            Err(refused) => {
                // Every room is taken: the closure runs its `drop(context)` here, unlocked, as
                // zenoh-pico refuses what its heap cannot hold.
                drop(refused);
                return Z_ERR_SYSTEM_OUT_OF_MEMORY;
            }
        };
        // The handle holds a count of the rooms, which keeps the subscriber's place, and its room.
        (*listener).handle = Strong::into_raw(set.clone());
        (*listener)._pad = [room_word(room), core::ptr::null_mut()];
        Z_OK
    })
}

/// Take the closure out of a moved miss closure, leaving the gravestone —
/// the consume-on-every-path step both listener forms open with — adopted by
/// `adopt`.
///
/// # Safety
/// `callback` must be non-null and point at a valid moved miss closure.
unsafe fn take_miss_closure(
    callback: *mut ze_moved_closure_miss_t,
    adopt: fn(*mut c_void, ze_closure_miss_callback_t, z_closure_drop_callback_t) -> CMissClosure,
) -> CMissClosure {
    let owned = &mut (*callback)._this;
    let cclosure = adopt(owned.context, owned.call, owned.drop);
    *owned = ze_owned_closure_miss_t::null_value();
    cclosure
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
    guard_val(|| !listener.is_null() && !(*listener).handle.is_null())
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
            let [room, _] = (*listener)._this._pad;
            // SAFETY: a live listener's handle is a count of its subscriber's rooms
            // (`Strong::into_raw`), let go of once, here, after its own room is given back: the
            // retraction returns when no call runs its closure and its `drop(context)` has run.
            let set = Strong::<MissRooms>::from_raw(handle);
            set.remove(room_of(room), false);
            drop(set);
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
/// The derived keyexpr is `<ke>/@adv/pub/**`, pico's
/// (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @ `_Z_KEYEXPR_APPEND_STR_ARRAY(&keyexpr, _Z_KEYEXPR_ADV_PREFIX, _Z_KEYEXPR_PUB, _Z_KEYEXPR_STARSTAR),`),
/// spelled by `wz_ext_pubsub::advanced_ke::publisher_detection_ke`, the one
/// place every advanced subscriber of wz derives it.
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
        let closure = CClosure::uncounted(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        if liveliness_subscriber.is_null() {
            return Z_ERR_NULL;
        }
        let Some(state) = handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        let Some(keyexpr) = state.keyexpr() else {
            return Z_ERR_NULL;
        };
        let ke = wz_ext_pubsub::advanced_ke::publisher_detection_ke(keyexpr);
        let history = if options.is_null() {
            false
        } else {
            (*options).history
        };
        // R2959 — upstream builds this listener with the plain
        // `z_liveliness_declare_subscriber`
        // (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
        // `z_liveliness_declare_subscriber(&sess_rc, liveliness_subscriber, z_keyexpr_loan(&keyexpr), callback, &opt);`),
        // so it gets that call's whole-key declaration and interest on it.
        // The subscriber's place is taken from its session before anything is declared, so a
        // session with no place left refuses the declaration and declares nothing.
        let engine = state.engine.clone();
        let Some(slot) = crate::object_slot::Slot::take_entity(
            &engine,
            crate::object_slot::Kind::LivelinessSubscriber,
        ) else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        // Its closure lies in the place, as a session's own liveliness subscriber's does, and its
        // handle is let go of as that one's is.
        match crate::liveliness::declare_liveliness_subscriber_in(
            &engine, slot, &ke, None, closure, history, None,
        ) {
            Ok(placed) => {
                *liveliness_subscriber = z_owned_subscriber_t {
                    handle: placed as *mut c_void,
                    _pad: [core::ptr::null_mut(); 3],
                };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

// Compile-time byte-compat guard. Every size here is MEASURED against the
// pinned pico headers with a real C compiler; a drift is a stack smash in the
// caller's frame, not a Rust error, so it is pinned at build time.
//
// The miss is a global id and a count, the same bytes on every host; the closure and the
// listener are three words on any host; the publisher and the subscriber are a handle padded to
// the 64-bit measurement, and the handle alone elsewhere (`crate::abi::element_bytes`).
const _: () = {
    use core::mem::size_of;
    const WORD: usize = size_of::<*mut c_void>();
    assert!(size_of::<ze_miss_t>() == 24);
    assert!(size_of::<ze_owned_closure_miss_t>() == 3 * WORD);
    assert!(size_of::<ze_owned_advanced_publisher_t>() == crate::abi::element_bytes(224));
    assert!(size_of::<ze_owned_advanced_subscriber_t>() == crate::abi::element_bytes(152));
    assert!(size_of::<ze_owned_sample_miss_listener_t>() == 3 * WORD);
};

// The option structs, as the 64-bit host lays them out. They mix pointers, `size_t`, `bool`,
// enums and `uint64_t`, whose alignment a 32-bit ABI decides (4 on 32-bit x86 Linux, 8 on
// Windows), so their 32-bit sizes are not these halved; the `repr(C)` mirrors of the header's
// fields take them from the target (the crate root says how a 32-bit build is held).
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::size_of;
    // The embedded `z_publisher_options_t` gains `allowed_destination` with
    // `local-subscriber` (24 -> 32 B), which moves everything after it.
    assert!(
        size_of::<ze_advanced_publisher_options_t>()
            == if cfg!(feature = "local-subscriber") {
                96
            } else {
                88
            }
    );
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
        // The underlying send's result, as upstream returns it from BOTH entry
        // points (`src/api/advanced_publisher.c:407,423` — one
        // `_z_publisher_*_impl` call each). A delete with no peer to hear it is
        // `Z_OK`, as a put with none is: the write filter holds it back and the
        // send that follows is not an error.
        advanced_publish_code(state.publisher.delete())
    })
}

/// Whether any subscriber currently matches an advanced publisher (pico
/// `ze_advanced_publisher_get_matching_status`): the wrapped publisher's own status,
/// as pico answers it (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `return z_publisher_get_matching_status(z_publisher_loan(&pub->_publisher), matching_status);`),
/// which is its write filter's.
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
        let Some(state) =
            crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(publisher)
        else {
            return Z_ERR_NULL;
        };
        (*matching_status).matching = state.publisher.publisher().filter_matches();
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
    crate::ffi::guarded(|| {
        crate::matching::declare_on_filter(
            advanced_publisher_filter(publisher),
            Some(listener),
            callback,
        )
    })
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
    crate::ffi::guarded(|| {
        crate::matching::declare_on_filter(advanced_publisher_filter(publisher), None, callback)
    })
}

/// The write filter a matching watch on an advanced publisher is declared on: its wrapped
/// publisher's, as pico's advanced publisher declares the listener on its publisher
/// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `return z_publisher_declare_matching_listener(z_publisher_loan(&publisher->_publisher), matching_listener, callback);`).
///
/// The key is the publisher's OWN, not its `@adv` cache key: matching asks "is anyone
/// subscribed to what I publish", and what an advanced publisher publishes is the plain
/// keyexpr.
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
unsafe fn advanced_publisher_filter<'a>(
    pub_: *const ze_loaned_advanced_publisher_t,
) -> Option<&'a crate::write_filter::WriteFilter> {
    crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_)
        .map(|state| state.publisher.publisher().filter())
}

/// Declare a miss listener that lives as long as its subscriber (pico
/// `ze_advanced_subscriber_declare_background_sample_miss_listener`).
///
/// The BACKGROUND form: the same closure joins the same set as the owned
/// form's, and there is no handle to retract it with, so it leaves when the
/// subscriber's own state does.
///
/// R2814 — this used to DELEGATE to the owned form with a null listener, and
/// the owned form refuses a null listener with `Z_ERR_NULL` after consuming the
/// closure: every background listener was dropped on arrival and the call
/// reported failure. Nothing called it with a check on the result. Sharing the
/// closure-taking step is what keeps the two forms from drifting; sharing the
/// entry point was the wrong seam, because the one thing the two forms differ
/// in — whether there is a handle — is exactly what the owned form validates.
///
/// # Safety
/// `subscriber` must be null or a live loaned advanced subscriber; `callback`
/// must be a valid moved miss closure, consumed on every path.
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_declare_background_sample_miss_listener(
    subscriber: *const ze_loaned_advanced_subscriber_t,
    callback: *mut ze_moved_closure_miss_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let mut cclosure = take_miss_closure(callback, CMissClosure::uncounted);
        let Some(state) = handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        // Counted in the subscriber's place, so its undeclare waits for this closure too and the
        // place stands until it is let go of.
        let Some(set) = state.miss.as_deref() else {
            return Z_ERR_NULL;
        };
        crate::object_slot::count_in_entity::<AdvSubState, AdvSubKept, _>(state, &mut cclosure);
        // No handle exists to remove it, which is what "background" means: the subscriber's
        // undeclare removes it.
        if let Err(refused) = set.insert(cclosure, true) {
            // Every room is taken: the closure is let go of here, unlocked.
            drop(refused);
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        }
        Z_OK
    })
}

/// The `(zid, eid)` identity behind a loaned advanced publisher, for
/// [`crate::session::ze_advanced_publisher_id`] (R311y559).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
pub(crate) unsafe fn advanced_publisher_identity(
    pub_: *const ze_loaned_advanced_publisher_t,
) -> Option<([u8; 16], wz_session_core::wire_id::EntityId)> {
    // The wrapped publisher's entity id, as pico's `ze_advanced_publisher_id` is
    // `z_publisher_id` of the publisher it wraps.
    crate::abi::handle_ref::<ze_loaned_advanced_publisher_t, AdvPubState>(pub_)
        .map(|state| (state.engine.zid(), state.publisher.eid()))
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
        None => core::ptr::null(),
    }
}

/// The `(zid, eid)` identity behind a loaned advanced subscriber, for
/// [`crate::session::ze_advanced_subscriber_id`] (R311y559).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
pub(crate) unsafe fn advanced_subscriber_identity(
    sub: *const ze_loaned_advanced_subscriber_t,
) -> Option<([u8; 16], wz_session_core::wire_id::EntityId)> {
    crate::abi::handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(sub).and_then(|state| {
        let subscriber = state.subscriber.as_ref()?;
        Some((state.engine.zid(), subscriber.id().eid()))
    })
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
        None => core::ptr::null(),
    }
}

/// Declare a session-lifetime advanced subscriber with no handle (pico
/// `ze_declare_background_advanced_subscriber`).
///
/// R311y559 — the background form of [`ze_declare_advanced_subscriber`]. The
/// subscriber is made as the owned form makes it and then run in the background
/// (`EngineSubscriber::background`): its entities stay declared for the session,
/// with no handle left to retract them.
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
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        match declare_subscriber_state(zs, keyexpr, callback, options, true) {
            Ok(state) => {
                // No handle is left, so nothing will retract what the subscriber declared: it
                // runs in the background, its entities standing until the session ends. Its owner
                // lets go of the place at once, with no wait, and the place stays with the sample
                // closure, which holds the session's count open, so the close waits for it.
                if let Some(subscriber) = (*state).subscriber.take() {
                    subscriber.background();
                }
                crate::object_slot::retire_entity::<AdvSubState, AdvSubKept>(state);
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Watch for advanced PUBLISHERS appearing on this subscriber's keyexpr, for
/// the session's lifetime (pico
/// `ze_advanced_subscriber_detect_publishers_background`).
///
/// A liveliness subscription on the `@adv` publisher-detection keyexpr — which
/// is what publisher detection IS on the wire: an advanced publisher declares a
/// liveliness token under `<base>/@adv/pub/...`, and detecting publishers means
/// subscribing to those tokens. Made as
/// [`crate::liveliness::z_liveliness_declare_background_subscriber`] makes its
/// subscriber, so the two cannot drift: its closure lies in a place of the
/// session's, whose owner lets go of it at once, and holds the session's count
/// open until the row lets go of it, so the close waits for it.
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
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST.
        let owned = &mut (*callback)._this;
        let closure = CClosure::uncounted(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let Some(state) =
            crate::abi::handle_ref::<ze_loaned_advanced_subscriber_t, AdvSubState>(subscriber)
        else {
            return Z_ERR_NULL;
        };
        // A closed session takes no declaration, and the count kept for it is read only while
        // the session is open.
        if state.engine.is_closed() {
            return crate::result::Z_ERR_SESSION_CLOSED;
        }
        let Some(keyexpr) = state.keyexpr() else {
            return Z_ERR_NULL;
        };
        let detection = wz_ext_pubsub::advanced_ke::publisher_detection_ke(keyexpr);
        let history = !options.is_null() && (*options).history;
        let engine = state.engine.clone();
        let Some(slot) = crate::object_slot::Slot::take_entity(
            &engine,
            crate::object_slot::Kind::LivelinessSubscriber,
        ) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        // SAFETY: the count kept in the state is its session's, read only while the session is
        // open, as checked above.
        let session = state
            .session
            .map(|count| unsafe { crate::session::session_hold_let_go(count) });
        match crate::liveliness::declare_liveliness_subscriber_in(
            &engine, slot, &detection, None, closure, history, session,
        ) {
            Ok(placed) => {
                // No handle will undeclare it: its owner lets go of it at once, with no wait.
                crate::object_slot::release_entity(placed);
                Z_OK
            }
            Err(code) => code,
        }
    })
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    /// The publisher-detection keyexpr is derived where every advanced subscriber derives it, and
    /// not spelled again in this file, by either detection door: a second spelling is a second
    /// place the namespace can move. The needle is assembled, so this test's own text is not a
    /// spelling of it.
    #[test]
    fn the_publisher_detection_keyexpr_is_not_spelled_here() {
        let spelling = concat!("@adv/pub/", "**\"");
        assert!(
            !include_str!("advanced.rs").contains(spelling),
            "the pico ABI spells the publisher-detection keyexpr instead of deriving it"
        );
        assert_eq!(
            wz_ext_pubsub::advanced_ke::publisher_detection_ke("demo/x"),
            concat!("demo/x/@adv/pub/", "**")
        );
    }

    /// A sample refused for want of a time answers pico's code for a timestamp it could not
    /// make (-68), whichever of the two reasons; a sample that went out, or that the write filter
    /// held back, is `Z_OK`; any other refusal stays generic.
    #[test]
    fn a_sample_refused_for_want_of_a_time_answers_picos_timestamp_code() {
        assert_eq!(advanced_publish_code(Ok(5)), Z_OK);
        assert_eq!(advanced_publish_code(Ok(0)), Z_OK);
        assert_eq!(
            advanced_publish_code(Err(PublishError::TimestampExhausted)),
            Z_ERR_TIMESTAMP_GENERATION_FAILED
        );
        assert_eq!(
            advanced_publish_code(Err(PublishError::ClockUntrusted)),
            Z_ERR_TIMESTAMP_GENERATION_FAILED
        );
        assert_eq!(
            advanced_publish_code(Err(PublishError::ExceedsCapacity)),
            Z_ERR_GENERIC
        );
        assert_eq!(
            advanced_publish_code(Err(PublishError::HeldConduit)),
            crate::result::Z_ERR_TRANSPORT_TX_FAILED,
            "a sample dropped behind a held conduit answers pico's failed send"
        );
        assert_eq!(
            advanced_publish_code(Err(PublishError::ExceedsCacheRoom)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY,
            "a sample longer than the cache ring answers the full room's code"
        );
    }

    /// R2596 — the cache's three reply-QoS fields REACH the config, through
    /// PICO's converters.
    ///
    /// The ABI-specific half matters: pico's `Z_CONGESTION_CONTROL_BLOCK` is
    /// `1` where zenoh-c's is `0`, so a mapping that borrowed the sibling ABI's
    /// conversion would invert this value and still compile. The fixture
    /// therefore asks for BLOCK by pico's spelling and asserts the typed
    /// `Block` comes out.
    #[test]
    fn the_cache_reply_qos_options_reach_the_cache_config() {
        // SAFETY: a zeroed options struct is a valid writable target for the
        // default fill, which overwrites every field before any read.
        let mut options: ze_advanced_publisher_options_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live, writable struct on this frame.
        unsafe { ze_advanced_publisher_options_default(&mut options) };
        options.cache.is_enabled = true;
        options.cache.max_samples = 4;
        options.cache.congestion_control = crate::qos::Z_CONGESTION_CONTROL_BLOCK;
        options.cache.priority = crate::qos::Z_PRIORITY_DEFAULT;
        options.cache.is_express = true;

        // SAFETY: `options` is live and fully initialised on this frame.
        let mapped = unsafe { advanced_publisher_options(&options) };
        let cache = mapped.cache.expect("an enabled cache maps to a config");
        assert_eq!(cache.max_samples, 4);
        assert_eq!(
            cache.replies_config.congestion_control,
            wz_session_core::qos::CongestionControl::Block,
            "pico spells BLOCK as 1; reading it as zenoh-c's 0 would invert this"
        );
        assert_eq!(
            cache.replies_config.priority,
            wz_session_core::qos::Priority::Data
        );
        assert!(cache.replies_config.is_express);
    }

    /// A miss closure that does nothing — only its MEMBERSHIP in the set is
    /// graded below, never a call.
    #[cfg(feature = "engine-tokio")]
    unsafe extern "C" fn ignore_miss(_miss: *const ze_miss_t, _ctx: *mut c_void) {}

    #[cfg(feature = "engine-tokio")]
    fn moved_miss_closure() -> ze_moved_closure_miss_t {
        ze_moved_closure_miss_t {
            _this: ze_owned_closure_miss_t {
                context: std::ptr::null_mut(),
                call: Some(ignore_miss),
                drop: None,
            },
        }
    }

    /// An advanced subscriber on the port of a face-less tokio session, and the set its miss
    /// listeners join. The subscriber's callback is a Rust closure, which holds no C context, so
    /// its state waits for nothing of its own.
    #[cfg(feature = "engine-tokio")]
    fn face_less_subscriber(
        shared: &Arc<wz_capi_core::faces::SharedSession>,
    ) -> (ze_owned_advanced_subscriber_t, MissSlot) {
        let engine = shared.as_engine();
        let subscriber = EngineSubscriber::declare(
            &engine,
            "demo/data",
            AdvancedSubscriberOptions::new(),
            |_| {},
        )
        .expect("a plain subscriber declares on a session with no face");
        let make = |place: NonNull<MissRooms>| {
            // SAFETY: the place is the box's, valid for one set, holding none, never moved.
            unsafe { MissRooms::write_in(place) }
        };
        // SAFETY: `make` makes the whole set in the place it is handed.
        let set: MissSlot = unsafe { Strong::try_boxed_in(make) }.expect("the test's heap");
        let slot = crate::object_slot::Slot::<AdvSubPlace>::take_entity(
            &engine,
            crate::object_slot::Kind::AdvancedSubscriber,
        )
        .expect("a place for an advanced subscriber");
        let state = slot.fill(crate::object_slot::Answering::keeping(
            AdvSubState {
                engine,
                subscriber: Some(subscriber),
                loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
                miss: Some(set.clone()),
                session: None,
            },
            // The C closure kept beside the state is counted in nothing and taken out by nothing:
            // the subscriber's callback is the Rust closure above.
            AdvSubKept::new(SampleKept::new(
                CClosure::uncounted(std::ptr::null_mut(), None, None),
                None,
            )),
        ));
        let owned = ze_owned_advanced_subscriber_t {
            handle: state.cast::<c_void>(),
            _pad: [0u8; SUBSCRIBER_PAD],
        };
        (owned, set)
    }

    /// The key a loaned advanced subscriber shows is read where its subscriber keeps it: the state
    /// holds no copy of its own. Turned red by a view bound to a copy of the key.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn a_subscribers_key_view_reads_the_key_its_subscriber_keeps() {
        let shared = Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let (owned, _miss) = face_less_subscriber(&shared);
        let state = owned.handle.cast::<AdvSubState>();
        let loaned = &owned as *const ze_owned_advanced_subscriber_t
            as *const ze_loaned_advanced_subscriber_t;
        // SAFETY: `state` is the live state behind `owned`, held on this frame until the undeclare
        // below consumes it.
        unsafe {
            (*state).bind();
            let kept = (*state)
                .subscriber
                .as_ref()
                .expect("the owner holds its subscriber")
                .keyexpr();
            let view = advanced_subscriber_keyexpr(loaned);
            assert_eq!(crate::keyexpr::keyexpr_str(view), Some("demo/data"));
            assert_eq!(
                (*view)._start,
                kept.as_ptr(),
                "the view reads the subscriber's key"
            );
            let mut moved = ze_moved_advanced_subscriber_t { _this: owned };
            ze_undeclare_advanced_subscriber(&mut moved);
        }
    }

    #[cfg(feature = "engine-tokio")]
    unsafe extern "C" fn count_miss_drop(context: *mut c_void) {
        // SAFETY: the context is the `AtomicUsize` the test keeps alive past every drop.
        let count = unsafe { &*(context as *const std::sync::atomic::AtomicUsize) };
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// An undeclare returns when the closures its callbacks run through have been released, and a
    /// background miss listener is one of them. The set outlives the subscriber here (an owned
    /// listener and the test both hold it), so the closure is released only because the state
    /// removes its background entries itself; a state that left them to the set's last holder
    /// waited for a release that never came.
    ///
    /// Control: removing the `leave_background()` of `free_advanced_subscriber` hangs the
    /// undeclare, which the bench run ends at its time limit.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn a_background_miss_listener_is_released_when_its_subscriber_is_undeclared() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let shared = Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let (owned, miss) = face_less_subscriber(&shared);
        let loaned = &owned as *const ze_owned_advanced_subscriber_t
            as *const ze_loaned_advanced_subscriber_t;
        let dropped = AtomicUsize::new(0);
        let mut background = ze_moved_closure_miss_t {
            _this: ze_owned_closure_miss_t {
                context: &dropped as *const AtomicUsize as *mut c_void,
                call: Some(ignore_miss),
                drop: Some(count_miss_drop),
            },
        };
        let mut listener = ze_owned_sample_miss_listener_t::null_value();
        let mut owned_closure = moved_miss_closure();
        // SAFETY: `loaned` points at a live subscriber on this frame; the closures are valid
        // moved closures and `listener` is a writable local.
        unsafe {
            assert_eq!(
                ze_advanced_subscriber_declare_background_sample_miss_listener(
                    loaned,
                    &mut background
                ),
                Z_OK
            );
            assert_eq!(
                ze_advanced_subscriber_declare_sample_miss_listener(
                    loaned,
                    &mut listener,
                    &mut owned_closure
                ),
                Z_OK
            );
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "held while declared");

        // SAFETY: the subscriber handle is live and consumed here.
        unsafe {
            let mut moved = ze_moved_advanced_subscriber_t { _this: owned };
            ze_undeclare_advanced_subscriber(&mut moved);
        }
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "the background closure is released by the time the undeclare returns"
        );
        assert_eq!(
            miss.declared(),
            1,
            "the owned listener, which has a handle of its own, is still declared"
        );
        // SAFETY: `listener` still holds its live handle.
        unsafe {
            ze_undeclare_sample_miss_listener(
                &mut listener as *mut ze_owned_sample_miss_listener_t
                    as *mut ze_moved_sample_miss_listener_t,
            );
        }
        assert_eq!(miss.declared(), 0);
    }

    /// R2814 — both listener forms land in the subscriber's set, and a
    /// retracted owned listener removes only itself.
    ///
    /// # What it grades
    ///
    /// Two defects, one per form. The BACKGROUND form delegated to the owned
    /// form with a null listener handle, which the owned form refuses with
    /// `Z_ERR_NULL` after consuming the closure — so it always failed and
    /// registered nothing. And the owned form "installed into" one slot, so a
    /// second listener replaced the first and retracting the first cleared the
    /// second. The subscriber is hosted on the port of a face-less tokio session: the set
    /// is the subject, and no face is needed to read it.
    ///
    /// # Control
    ///
    /// Restoring the background form's delegation reds the background assertion
    /// (`Z_ERR_NULL`, and one listener fewer).
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn miss_listeners_join_the_set_and_leave_it_one_at_a_time() {
        let shared = Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let (owned, miss) = face_less_subscriber(&shared);
        let loaned = &owned as *const ze_owned_advanced_subscriber_t
            as *const ze_loaned_advanced_subscriber_t;

        let mut first = ze_owned_sample_miss_listener_t::null_value();
        let mut second = ze_owned_sample_miss_listener_t::null_value();
        let (mut c1, mut c2) = (moved_miss_closure(), moved_miss_closure());
        // SAFETY: `loaned` points at a live subscriber on this frame; both listener slots are
        // writable locals and the closures valid moved closures.
        unsafe {
            assert_eq!(
                ze_advanced_subscriber_declare_sample_miss_listener(loaned, &mut first, &mut c1),
                Z_OK
            );
            assert_eq!(
                ze_advanced_subscriber_declare_sample_miss_listener(loaned, &mut second, &mut c2),
                Z_OK
            );
        }
        assert_eq!(
            miss.declared(),
            2,
            "a second owned listener joins the first rather than replacing it"
        );

        // SAFETY: `first` holds a live listener handle.
        let rc = unsafe {
            ze_undeclare_sample_miss_listener(
                &mut first as *mut ze_owned_sample_miss_listener_t
                    as *mut ze_moved_sample_miss_listener_t,
            )
        };
        assert_eq!(rc, Z_OK);
        assert_eq!(
            miss.declared(),
            1,
            "retracting one listener removes only its own entry"
        );

        let mut background = moved_miss_closure();
        // SAFETY: as above.
        let rc = unsafe {
            ze_advanced_subscriber_declare_background_sample_miss_listener(loaned, &mut background)
        };
        assert_eq!(
            (rc, miss.declared()),
            (Z_OK, 2),
            "the background form registers its listener and reports success"
        );

        // SAFETY: `second` holds a live handle; the subscriber is reclaimed last.
        unsafe {
            ze_undeclare_sample_miss_listener(
                &mut second as *mut ze_owned_sample_miss_listener_t
                    as *mut ze_moved_sample_miss_listener_t,
            );
            let mut moved = ze_moved_advanced_subscriber_t { _this: owned };
            ze_undeclare_advanced_subscriber(&mut moved);
        }
        assert_eq!(
            miss.declared(),
            0,
            "the release retracts the background one"
        );
    }

    /// A miss closure that counts its drops in the `AtomicUsize` it is given.
    #[cfg(feature = "engine-tokio")]
    fn counted_miss_closure(dropped: &std::sync::atomic::AtomicUsize) -> ze_moved_closure_miss_t {
        ze_moved_closure_miss_t {
            _this: ze_owned_closure_miss_t {
                context: dropped as *const std::sync::atomic::AtomicUsize as *mut c_void,
                call: Some(ignore_miss),
                drop: Some(count_miss_drop),
            },
        }
    }

    /// Declaring an owned and a background listener and retracting the owned one take no memory:
    /// each takes a room of the subscriber's place, and the owned one's handle keeps its room and
    /// a count of the rooms in its own words.
    ///
    /// # Control
    ///
    /// A handle boxed again, or a closure in an `Arc` of its own, counts an allocation.
    #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
    #[test]
    fn declaring_and_retracting_miss_listeners_takes_no_memory() {
        let shared = Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let (owned, miss) = face_less_subscriber(&shared);
        let loaned = &owned as *const ze_owned_advanced_subscriber_t
            as *const ze_loaned_advanced_subscriber_t;
        let mut listener = ze_owned_sample_miss_listener_t::null_value();
        let (mut owned_closure, mut background) = (moved_miss_closure(), moved_miss_closure());
        let mut codes = (Z_ERR_GENERIC, Z_ERR_GENERIC);
        let taken = crate::connectivity::tests::allocations(|| {
            // SAFETY: `loaned` points at a live subscriber on this frame; the closures are valid
            // moved closures and `listener` a writable local, whose handle is retracted here.
            unsafe {
                codes.0 = ze_advanced_subscriber_declare_sample_miss_listener(
                    loaned,
                    &mut listener,
                    &mut owned_closure,
                );
                codes.1 = ze_advanced_subscriber_declare_background_sample_miss_listener(
                    loaned,
                    &mut background,
                );
                ze_undeclare_sample_miss_listener(
                    &mut listener as *mut ze_owned_sample_miss_listener_t
                        as *mut ze_moved_sample_miss_listener_t,
                );
            }
        });
        assert_eq!(codes, (Z_OK, Z_OK));
        assert_eq!(taken, 0, "a listener takes a room and no memory");
        assert_eq!(
            miss.declared(),
            1,
            "the background listener stays until its subscriber goes"
        );
        // SAFETY: the subscriber handle is live and consumed here.
        unsafe {
            let mut moved = ze_moved_advanced_subscriber_t { _this: owned };
            ze_undeclare_advanced_subscriber(&mut moved);
        }
        assert_eq!(miss.declared(), 0);
    }

    /// With every room taken a listener of either form is refused with
    /// `Z_ERR_SYSTEM_OUT_OF_MEMORY` and its closure let go of at once, and a retracted listener
    /// gives its room back to the next one.
    ///
    /// # Control
    ///
    /// An `insert` that does not hand a refused closure back (dropping it elsewhere, or keeping
    /// it) breaks the drop counts; a `vacate` that leaves the room taken refuses the last
    /// declaration.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn a_listener_past_the_rooms_is_refused_and_let_go() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let shared = Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let (owned, miss) = face_less_subscriber(&shared);
        let loaned = &owned as *const ze_owned_advanced_subscriber_t
            as *const ze_loaned_advanced_subscriber_t;
        let rooms = wz_session_core::caps::MAX_SAMPLE_MISS_LISTENERS;
        let dropped = AtomicUsize::new(0);
        let mut listeners: Vec<ze_owned_sample_miss_listener_t> = (0..rooms)
            .map(|_| ze_owned_sample_miss_listener_t::null_value())
            .collect();
        // SAFETY: `loaned` points at a live subscriber on this frame; every listener slot is a
        // writable element of `listeners`, each retracted once below, and the subscriber goes last.
        unsafe {
            for listener in listeners.iter_mut() {
                let mut closure = counted_miss_closure(&dropped);
                assert_eq!(
                    ze_advanced_subscriber_declare_sample_miss_listener(
                        loaned,
                        listener,
                        &mut closure
                    ),
                    Z_OK
                );
            }
            assert_eq!(miss.declared(), rooms);

            let mut past = ze_owned_sample_miss_listener_t::null_value();
            let mut closure = counted_miss_closure(&dropped);
            assert_eq!(
                ze_advanced_subscriber_declare_sample_miss_listener(
                    loaned,
                    &mut past,
                    &mut closure
                ),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert!(past.handle.is_null(), "a refused listener has no handle");
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                1,
                "its closure is let go of at once"
            );
            let mut background = counted_miss_closure(&dropped);
            assert_eq!(
                ze_advanced_subscriber_declare_background_sample_miss_listener(
                    loaned,
                    &mut background
                ),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 2);

            let first = listeners.first_mut().expect("at least one room");
            ze_undeclare_sample_miss_listener(
                &mut *first as *mut ze_owned_sample_miss_listener_t
                    as *mut ze_moved_sample_miss_listener_t,
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 3);
            let mut again = counted_miss_closure(&dropped);
            assert_eq!(
                ze_advanced_subscriber_declare_sample_miss_listener(loaned, first, &mut again),
                Z_OK,
                "the retracted listener's room takes the next one"
            );

            for listener in listeners.iter_mut() {
                ze_undeclare_sample_miss_listener(
                    listener as *mut ze_owned_sample_miss_listener_t
                        as *mut ze_moved_sample_miss_listener_t,
                );
            }
            let mut moved = ze_moved_advanced_subscriber_t { _this: owned };
            ze_undeclare_advanced_subscriber(&mut moved);
        }
        assert_eq!(miss.declared(), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), rooms.saturating_add(3));
    }

    /// A listener retracted from inside a call goes once no call reads it: one the calls have not
    /// reached yet is let go of at once and not called, and the one being called is let go of by
    /// its call, when it returns.
    ///
    /// # Control
    ///
    /// An `each` that does not skip a leaving room calls the second listener; a `remove` that
    /// takes the closure of a room a call reads drops the first one inside its own call.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn a_listener_retracted_inside_a_call_goes_after_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut place = Box::<MissRooms>::new_uninit();
        // SAFETY: the box's place is valid for one set and holds none; the box does not move it,
        // and the set is whole once `write_in` returns.
        let rooms = unsafe {
            MissRooms::write_in(NonNull::from(&mut *place).cast::<MissRooms>());
            place.assume_init()
        };
        let (first_dropped, second_dropped) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let adopted = |dropped: &AtomicUsize| {
            let moved = counted_miss_closure(dropped);
            CMissClosure::uncounted(moved._this.context, moved._this.call, moved._this.drop)
        };
        let Ok(first) = rooms.insert(adopted(&first_dropped), false) else {
            panic!("a free room for the first listener");
        };
        let Ok(second) = rooms.insert(adopted(&second_dropped), false) else {
            panic!("a free room for the second listener");
        };
        let mut called = Vec::new();
        rooms.each(|listener| {
            called.push(listener.context.0);
            // As `fire_miss` marks the thread while it calls the program.
            let _in_callback = crate::ffi::InCallback::enter().expect("a thread is marked");
            rooms.remove(second, false);
            rooms.remove(first, false);
            assert_eq!(
                first_dropped.load(Ordering::SeqCst),
                0,
                "the call still reads its own closure"
            );
        });
        assert_eq!(
            called,
            vec![&first_dropped as *const AtomicUsize as *mut c_void]
        );
        assert_eq!(
            (
                first_dropped.load(Ordering::SeqCst),
                second_dropped.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        assert_eq!(rooms.declared(), 0);
    }

    /// R2815 — `subscriber_detection` and its metadata REACH the wz options.
    /// Both were declared and read by nothing, so a C program asking to be
    /// detectable got no token. The default fill is the control: it leaves
    /// detection off, and the mapping must say so too.
    ///
    /// Control: deleting the mapping block reds the second assertion.
    #[test]
    fn subscriber_detection_options_reach_the_wz_options() {
        // SAFETY: a zeroed struct is a valid writable target for the fill.
        let mut options: ze_advanced_subscriber_options_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live, writable struct on this frame.
        unsafe { ze_advanced_subscriber_options_default(&mut options) };
        // SAFETY: `options` is live and fully initialised on this frame.
        let off = unsafe { advanced_subscriber_options(&options) };
        assert!(
            off.subscriber_detection.is_none(),
            "the default asks for no detection"
        );

        let meta = "room/kitchen";
        let loaned = crate::abi::z_loaned_keyexpr_t::borrowed(meta.as_ptr(), meta.len());
        options.subscriber_detection = true;
        options.subscriber_detection_metadata = &loaned;
        // SAFETY: as above; `loaned` borrows `meta`, which outlives the call.
        let on = unsafe { advanced_subscriber_options(&options) };
        let detection = on
            .subscriber_detection
            .expect("subscriber_detection = true maps to a detection config");
        assert_eq!(detection.metadata.as_deref(), Some("room/kitchen"));
    }

    /// The DEFAULT a pico caller gets is pico's own — `Drop`, from
    /// `z_internal_congestion_control_default_push()` — not zenoh-ext's
    /// `Block`. Measured in `vendor/zenoh-pico/src/api/advanced_publisher.c`.
    #[test]
    fn the_pico_options_default_is_drop_not_the_rust_builders_block() {
        // SAFETY: a zeroed struct is a valid writable target for the fill.
        let mut cache: ze_advanced_publisher_cache_options_t = unsafe { std::mem::zeroed() };
        cache.is_express = true;
        // SAFETY: a live, writable struct on this frame.
        unsafe { ze_advanced_publisher_cache_options_default(&mut cache) };
        assert_eq!(
            cache.congestion_control,
            crate::qos::Z_CONGESTION_CONTROL_DROP
        );
        assert_eq!(cache.priority, crate::qos::Z_PRIORITY_DEFAULT);
        assert!(!cache.is_express);
    }

    /// An advanced publisher lies in a place of its session's from its declaration to its
    /// undeclare, and a session with every place held refuses one with nothing declared and no
    /// handle written. Turned red by a publisher that takes memory of its own instead of a place,
    /// or keeps its place past its undeclare.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn an_advanced_publisher_lies_in_a_place_of_its_session() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many advanced publisher places `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::AdvancedPublisher))
                    .collect();
            claimed.len()
        };
        let places = free(&engine);
        assert!(places > 0, "the session's limit admits advanced publishers");

        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed =
            unsafe { crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv".as_ptr()) };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        let mut publisher = ze_owned_advanced_publisher_t::null_value();
        // SAFETY: every pointer is live; null options are pico's defaults.
        let code =
            unsafe { ze_declare_advanced_publisher(loaned, &mut publisher, ke, core::ptr::null()) };
        assert_eq!(code, Z_OK);
        assert_eq!(free(&engine), places - 1, "the publisher holds one place");
        // SAFETY: the publisher is live and owned here, and given up by this call.
        let code =
            unsafe { ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&mut publisher)) };
        assert_eq!(code, Z_OK);
        assert_eq!(free(&engine), places, "its undeclare gives the place back");

        let held: Vec<Slot<u64>> =
            core::iter::from_fn(|| Slot::<u64>::take_entity(&engine, Kind::AdvancedPublisher))
                .collect();
        // SAFETY: as the declaration above.
        let code =
            unsafe { ze_declare_advanced_publisher(loaned, &mut publisher, ke, core::ptr::null()) };
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(
            publisher.handle.is_null(),
            "a refused publisher hands nothing back"
        );
        drop(held);

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// Counts the drops of the sample closure whose context is an `AtomicUsize`.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    unsafe extern "C" fn count_sample_drop(context: *mut c_void) {
        // SAFETY: the context is the `AtomicUsize` the test keeps alive past every drop.
        let count = unsafe { &*(context as *const std::sync::atomic::AtomicUsize) };
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// A moved sample closure that calls nothing and counts its drop in `dropped`.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    fn counted_sample_closure(
        dropped: &std::sync::atomic::AtomicUsize,
    ) -> z_moved_closure_sample_t {
        z_moved_closure_sample_t {
            _this: z_owned_closure_sample_t {
                context: dropped as *const std::sync::atomic::AtomicUsize as *mut c_void,
                call: None,
                drop: Some(count_sample_drop),
            },
        }
    }

    /// An advanced subscriber lies in a place of its session's: an owned one from its declaration
    /// to its undeclare, which returns with its closure let go of; a background one past its
    /// declaration, its closure let go of by the time the session's close returns; and a session
    /// with every place held refuses one with no handle written and its closure dropped. Turned
    /// red by a subscriber that takes memory of its own instead of a place, keeps its place past
    /// its undeclare, or runs in the background with a closure the close does not wait for.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn an_advanced_subscriber_lies_in_a_place_of_its_session() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_close, z_session_drop,
            z_session_loan, z_session_loan_mut, z_session_move,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many places of `kind` `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold, kind: Kind| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, kind)).collect();
            claimed.len()
        };

        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed =
            unsafe { crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv/sub".as_ptr()) };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        let places = free(&engine, Kind::AdvancedSubscriber);
        assert!(
            places > 0,
            "the session's limit admits advanced subscribers"
        );

        let owned_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&owned_drops);
        let mut subscriber = ze_owned_advanced_subscriber_t::null_value();
        // SAFETY: every pointer is live; null options are pico's defaults.
        let code = unsafe {
            ze_declare_advanced_subscriber(
                loaned,
                &mut subscriber,
                ke,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_OK);
        assert_eq!(
            free(&engine, Kind::AdvancedSubscriber),
            places - 1,
            "the subscriber holds one place"
        );
        assert_eq!(owned_drops.load(Ordering::SeqCst), 0, "held while declared");
        // SAFETY: the subscriber is live and owned here, and given up by this call.
        let code = unsafe {
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber))
        };
        assert_eq!(code, Z_OK);
        assert_eq!(
            free(&engine, Kind::AdvancedSubscriber),
            places,
            "its undeclare gives the place back"
        );
        assert_eq!(
            owned_drops.load(Ordering::SeqCst),
            1,
            "the undeclare returns with the closure let go of"
        );

        let held: Vec<Slot<u64>> =
            core::iter::from_fn(|| Slot::<u64>::take_entity(&engine, Kind::AdvancedSubscriber))
                .collect();
        let refused_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&refused_drops);
        // SAFETY: as the declaration above.
        let code = unsafe {
            ze_declare_advanced_subscriber(
                loaned,
                &mut subscriber,
                ke,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(
            subscriber.handle.is_null(),
            "a refused subscriber hands nothing back"
        );
        assert_eq!(
            refused_drops.load(Ordering::SeqCst),
            1,
            "a refused subscriber's closure is dropped"
        );
        drop(held);

        let background_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&background_drops);
        // SAFETY: as the declaration above.
        let code = unsafe {
            ze_declare_background_advanced_subscriber(
                loaned,
                ke,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_OK);
        assert_eq!(
            free(&engine, Kind::AdvancedSubscriber),
            places - 1,
            "a background subscriber holds its place past its declaration"
        );
        assert_eq!(background_drops.load(Ordering::SeqCst), 0);
        drop(engine);

        // SAFETY: the session is live and owned here.
        let code = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(code, Z_OK);
        assert_eq!(
            background_drops.load(Ordering::SeqCst),
            1,
            "the close returns with the background subscriber's closure let go of"
        );
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// An advanced subscriber that recovers runs a periodic job beside the part its host keeps in
    /// the subscriber's place: an owned one gives the place back with its undeclare, and a
    /// background one by the time its session's close returns, the job ending with the session.
    /// Turned red by a part whose place is never given back, or a close that leaves a job holding
    /// it in a session that runs no job again.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_recovering_advanced_subscribers_place_goes_back_with_its_job() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_close, z_session_drop,
            z_session_loan, z_session_loan_mut, z_session_move,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many advanced subscribers' places `engine` has free: each claimed, then all given
        // back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::AdvancedSubscriber))
                    .collect();
            claimed.len()
        };
        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed =
            unsafe { crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv/rec".as_ptr()) };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        // SAFETY: an options struct is plain data, filled with pico's defaults here.
        let mut options: ze_advanced_subscriber_options_t = unsafe { core::mem::zeroed() };
        // SAFETY: `options` is live.
        unsafe { ze_advanced_subscriber_options_default(&mut options) };
        options.recovery.is_enabled = true;
        options.history.is_enabled = true;
        let places = free(&engine);

        let owned_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&owned_drops);
        let mut subscriber = ze_owned_advanced_subscriber_t::null_value();
        // SAFETY: every pointer is live.
        let code = unsafe {
            ze_declare_advanced_subscriber(loaned, &mut subscriber, ke, &mut callback, &mut options)
        };
        assert_eq!(code, Z_OK, "a recovering subscriber declares");
        assert_eq!(free(&engine), places - 1);
        // SAFETY: the subscriber is live and owned here, and given up by this call.
        let code = unsafe {
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber))
        };
        assert_eq!(code, Z_OK);
        assert_eq!(free(&engine), places, "its undeclare gives the place back");
        assert_eq!(owned_drops.load(Ordering::SeqCst), 1);

        let background_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&background_drops);
        // SAFETY: as the declaration above.
        let code = unsafe {
            ze_declare_background_advanced_subscriber(loaned, ke, &mut callback, &mut options)
        };
        assert_eq!(code, Z_OK);
        assert_eq!(free(&engine), places - 1, "held past its declaration");

        // SAFETY: the session is live and owned here.
        let code = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(code, Z_OK);
        assert_eq!(background_drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            free(&engine),
            places,
            "the close returns with the place given back, its job ended"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// A background advanced subscriber whose four entities each stand on a name lodged in its
    /// place (the subscription, the heartbeat subscription, the late-publisher subscription and
    /// the detection token): the session's entries keep those names past the declaration, and the
    /// close lets them go, so the place is given back by the time the close returns. Turned red
    /// by a close that keeps an entry's key, whose lodged name then keeps the place, and the
    /// place's lender the session's engine, for ever.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_background_subscribers_lodged_names_go_back_with_the_close() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback_with, session_handle, z_close, z_session_drop,
            z_session_loan, z_session_loan_mut, z_session_move,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The subscriber's two subscriptions and four keys are past what a session opens with
        // unless its config states them.
        let mut session = listening_on_loopback_with(|config| {
            // SAFETY: `config` is the live config the open is about to consume.
            let stated = unsafe {
                crate::config::zp_config_insert(
                    config,
                    crate::config_limits::ZEXT_CONFIG_LIMITS_KEY,
                    c"MAX_SUBSCRIPTIONS=2,MAX_DECLARED_KEYEXPRS=4".as_ptr(),
                )
            };
            assert_eq!(stated, Z_OK);
        });
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::AdvancedSubscriber))
                    .collect();
            claimed.len()
        };
        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed = unsafe {
            crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv/named/**".as_ptr())
        };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        // SAFETY: an options struct is plain data, filled with pico's defaults here.
        let mut options: ze_advanced_subscriber_options_t = unsafe { core::mem::zeroed() };
        // SAFETY: `options` is live.
        unsafe { ze_advanced_subscriber_options_default(&mut options) };
        options.recovery.is_enabled = true;
        options.recovery.last_sample_miss_detection.is_enabled = true;
        options
            .recovery
            .last_sample_miss_detection
            .periodic_queries_period_ms = 0;
        options.history.is_enabled = true;
        options.history.detect_late_publishers = true;
        options.subscriber_detection = true;
        let places = free(&engine);

        let drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&drops);
        // SAFETY: every pointer is live.
        let code = unsafe {
            ze_declare_background_advanced_subscriber(loaned, ke, &mut callback, &mut options)
        };
        assert_eq!(code, Z_OK, "a subscriber with all four entities declares");
        assert_eq!(free(&engine), places - 1, "held past its declaration");

        // SAFETY: the session is live and owned here.
        let code = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(code, Z_OK);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            free(&engine),
            places,
            "the close lets the entries' names go, and with them the place"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// The miss listeners' set lies in the subscriber's place: a listener's handle that outlives
    /// its subscriber keeps the place, which the subscriber's undeclare does not wait for, and the
    /// listener's undeclare gives it back. Turned red by a set that never lets its keep of the
    /// place go, or an undeclare that waits for a listener's handle (the test hangs).
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_miss_listener_keeps_its_subscribers_place_until_it_goes() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };
        use std::sync::atomic::AtomicUsize;

        unsafe extern "C" fn no_miss(_miss: *const ze_miss_t, _context: *mut c_void) {}

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::AdvancedSubscriber))
                    .collect();
            claimed.len()
        };
        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed = unsafe {
            crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv/miss".as_ptr())
        };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        let places = free(&engine);

        let drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&drops);
        let mut subscriber = ze_owned_advanced_subscriber_t::null_value();
        // SAFETY: every pointer is live; null options are pico's defaults.
        let code = unsafe {
            ze_declare_advanced_subscriber(
                loaned,
                &mut subscriber,
                ke,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_OK);
        let mut on_miss = ze_moved_closure_miss_t {
            _this: ze_owned_closure_miss_t {
                context: core::ptr::null_mut(),
                call: Some(no_miss),
                drop: None,
            },
        };
        let mut listener = ze_owned_sample_miss_listener_t::null_value();
        // SAFETY: the subscriber is live, and the closure is a valid moved one.
        let code = unsafe {
            ze_advanced_subscriber_declare_sample_miss_listener(
                ze_advanced_subscriber_loan(&subscriber),
                &mut listener,
                &mut on_miss,
            )
        };
        assert_eq!(code, Z_OK);

        // SAFETY: the subscriber is live and owned here, and given up by this call.
        let code = unsafe {
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber))
        };
        assert_eq!(
            code, Z_OK,
            "the undeclare does not wait for the listener's handle"
        );
        assert_eq!(free(&engine), places - 1, "the listener keeps the place");
        // SAFETY: the listener is live and owned here, and given up by this call.
        let code = unsafe {
            ze_undeclare_sample_miss_listener(ze_sample_miss_listener_move(&mut listener))
        };
        assert_eq!(code, Z_OK);
        assert_eq!(free(&engine), places, "its undeclare gives the place back");

        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// An advanced subscriber's background publisher detection takes a liveliness subscriber's
    /// place of the session for its declaration and gives it back at once, its row holding the
    /// closure, which is let go of by the time the session's close returns; one asked for once the
    /// session is closed is refused with its closure dropped. Turned red by a detection whose place
    /// is kept past its declaration (no handle will give it back), or whose closure the close does
    /// not let go of.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_background_publisher_detections_closure_lies_in_its_row_until_the_close() {
        use crate::object_slot::{Kind, Slot};
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_close, z_session_drop,
            z_session_loan, z_session_loan_mut, z_session_move,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many places of `kind` `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold, kind: Kind| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, kind)).collect();
            claimed.len()
        };

        // SAFETY: a view is plain data, and the text is a live C string.
        let mut view: crate::abi::z_view_keyexpr_t = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        let viewed =
            unsafe { crate::keyexpr::z_view_keyexpr_from_str(&mut view, c"demo/adv/sub".as_ptr()) };
        assert_eq!(viewed, Z_OK);
        // SAFETY: the view is live for the rest of the frame.
        let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };
        let detections = free(&engine, Kind::LivelinessSubscriber);
        assert!(
            detections > 0,
            "the session's limit admits liveliness subscribers"
        );

        let kept_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&kept_drops);
        let mut kept = ze_owned_advanced_subscriber_t::null_value();
        // SAFETY: every pointer is live; null options are pico's defaults.
        let code = unsafe {
            ze_declare_advanced_subscriber(
                loaned,
                &mut kept,
                ke,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_OK);
        // SAFETY: `kept` is a live subscriber owned by this frame.
        let kept_loan = unsafe { ze_advanced_subscriber_loan(&kept) };
        let detect_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&detect_drops);
        // SAFETY: the loan is live; null options are pico's defaults.
        let code = unsafe {
            ze_advanced_subscriber_detect_publishers_background(
                kept_loan,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, Z_OK);
        assert_eq!(
            free(&engine, Kind::LivelinessSubscriber),
            detections,
            "the background detection's place goes back at once: no handle gives it back"
        );
        assert_eq!(detect_drops.load(Ordering::SeqCst), 0);
        drop(engine);

        // SAFETY: the session is live and owned here.
        let code = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(code, Z_OK);
        assert_eq!(
            detect_drops.load(Ordering::SeqCst),
            1,
            "the close returns with the background detection's closure let go of"
        );

        let closed_drops = AtomicUsize::new(0);
        let mut callback = counted_sample_closure(&closed_drops);
        // SAFETY: the loan is live, its session closed.
        let code = unsafe {
            ze_advanced_subscriber_detect_publishers_background(
                kept_loan,
                &mut callback,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, crate::result::Z_ERR_SESSION_CLOSED);
        assert_eq!(
            closed_drops.load(Ordering::SeqCst),
            1,
            "a detection refused on a closed session drops its closure"
        );

        // SAFETY: `kept` is live and owned here, and given up by this call; then the session.
        unsafe {
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut kept));
            z_session_drop(z_session_move(&mut session));
        }
        assert_eq!(kept_drops.load(Ordering::SeqCst), 1);
    }
}
