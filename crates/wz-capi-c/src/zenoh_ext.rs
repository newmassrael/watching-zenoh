// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — zenoh-ext's DEPRECATED standalone families:
//! `ze_publication_cache` and `ze_querying_subscriber`.
//!
//! ## Why these exist when `ze_advanced_*` already does
//!
//! R311y564's symbol census found 317 zenoh-c symbols wz did not define; by
//! R311y568 the archive arm was at 0 and the `unstable-shm` arm at 83, in
//! exactly two feature planes. These 18 symbols are the smaller plane, and the
//! debt ledger describes them accurately: "upstream's older standalone spellings
//! of ideas wz implements as `ze_advanced_*`".
//!
//! Upstream marks both families `@warning This API is deprecated`. That is a
//! reason to implement them EXACTLY as upstream does and not to grow them —
//! never a reason to omit them, because a symbol wz does not define is a program
//! upstream can write and wz cannot link. Deprecated is a statement about what
//! new code should use; it is not a statement about what a drop-in must export.
//!
//! ## Built ON this crate's own C entry points, deliberately
//!
//! Both families are composed from `z_declare_subscriber`, `z_declare_queryable`,
//! `z_get` and `z_query_reply` — the same public functions a C program would
//! call — rather than from the `SharedSession` registry underneath them. This
//! mirrors how upstream builds them (zenoh-ext is written against the zenoh API,
//! not against its internals) and it buys the property that matters here: the
//! cache's queryable and the querying subscriber's subscriber cannot drift from
//! an ordinary declaration, because they ARE ordinary declarations. A locality
//! rule, a canon gate or a QoS default added to the primitives reaches these for
//! free.
//!
//! ## `PublicationCache` semantics, read off upstream rather than guessed
//!
//! `zenoh-ext/src/publication_cache.rs` @ `PublicationCache`:
//!
//! - A subscriber on `key_expr` with `Locality::SessionLocal` — the cache stores
//!   what THIS session publishes, not what the network carries. Getting this
//!   wrong in the permissive direction would make the cache answer with samples
//!   the publisher never sent.
//! - A queryable on `key_expr/queryable_suffix` (plain `key_expr` when the suffix
//!   is NULL), carrying the caller's `queryable_origin` and `queryable_complete`.
//! - A per-RESOURCE ring keyed by `sample.key_expr()/suffix`, each bounded by
//!   `history`; a NEW key beyond `resources_limit` is DROPPED with the sample,
//!   never silently evicting another key.
//! - On a query whose keyexpr contains no `*`, reply from that exact key's ring;
//!   otherwise reply from every ring whose key INTERSECTS. Upstream branches on
//!   the literal presence of `*`, and this reproduces that rather than
//!   "improving" it — the two differ for a key holding a `$*`, and a difference
//!   from upstream is the defect this file exists to avoid.
//!
//! Upstream additionally filters each reply by the query's `_time` range. wz's
//! query view does not surface a parsed time range, so that filter is a NAMED
//! DIVERGENCE recorded in [`PUBLICATION_CACHE_TIME_RANGE_DIVERGENCE`] rather
//! than a silent omission: wz replies with the whole ring where upstream would
//! reply with a sub-range.
//!
//! ## `QueryingSubscriber` semantics
//!
//! `zenoh-c/src/querying_subscriber.rs:74-113` for the option defaults and
//! `zenoh-ext/src/querying_subscriber.rs` @ `QueryingSubscriber` for the
//! behaviour: a subscriber that
//! additionally issues a `get` at declaration time and merges the replies into
//! the same callback. `ze_querying_subscriber_get` issues another one later.
//!
//! wz's divergence here is the MERGE WINDOW, and it is named rather than hidden:
//! upstream buffers live publications until the initial query completes so the
//! callback sees history before live data. wz forwards both as they arrive. The
//! set of samples delivered is the same; the ORDER between a historical reply
//! and a concurrently-arriving live sample is not pinned. See
//! [`QUERYING_SUBSCRIBER_MERGE_DIVERGENCE`].

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_query_t, z_loaned_sample_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_sample_t, z_owned_bytes_t, z_owned_closure_sample_t, Handle,
};
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::{keyexpr_str, DeclaredKeyexpr};
use crate::publisher::{zc_locality_default, zc_locality_t};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};

/// The `_time` range filter upstream's publication cache applies to each reply
/// and wz does not. RECORDED, not silently dropped: a query carrying a `_time`
/// selector gets the whole ring here and a sub-range upstream.
pub const PUBLICATION_CACHE_TIME_RANGE_DIVERGENCE: &str =
    "ze_publication_cache ignores the query's _time range (zenoh-ext replies a sub-range)";

/// Upstream buffers live samples until the declaration-time query completes;
/// wz forwards both as they arrive. Same SET, unpinned ORDER.
pub const QUERYING_SUBSCRIBER_MERGE_DIVERGENCE: &str =
    "ze_querying_subscriber does not buffer live samples behind the initial query";

/// `ze_owned_publication_cache_t` / `ze_loaned_publication_cache_t`
/// (`zenoh_opaque.h:960-962,989-991`). Unmoved by either feature axis: the type
/// holds a boxed handle here and a `PublicationCache` upstream, and neither
/// `Z_FEATURE_UNSTABLE_API` nor `Z_FEATURE_SHARED_MEMORY` changes its size.
const PUB_CACHE_SIZE: usize = 128;
/// `ze_owned_querying_subscriber_t` / `ze_loaned_querying_subscriber_t`
/// (`zenoh_opaque.h:970-972,996-998`).
const QUERYING_SUB_SIZE: usize = 80;

// ── The option structs ────────────────────────────────────────────────────────

/// `ze_publication_cache_options_t` (`zenoh_commons.h:1274-1295`).
#[repr(C)]
pub struct ze_publication_cache_options_t {
    /// The suffix appended to `key_expr` for the cache's QUERYABLE. NULL means
    /// the queryable sits on `key_expr` itself.
    pub queryable_suffix: *const z_loaned_keyexpr_t,
    /// Which queries the cache's queryable will answer.
    pub queryable_origin: zc_locality_t,
    /// The `complete` flag for that queryable.
    pub queryable_complete: bool,
    /// Ring depth PER RESOURCE. Upstream's default is 1, not 0.
    pub history: usize,
    /// Distinct-key ceiling; 0 means unlimited (`zenoh-c
    /// publication_cache.rs:82` treats 0 as "do not call resources_limit").
    pub resources_limit: usize,
}

/// `ze_querying_subscriber_options_t` (`zenoh_commons.h:1304-1331`).
#[repr(C)]
pub struct ze_querying_subscriber_options_t {
    /// Which publications the underlying subscriber accepts.
    pub allowed_origin: zc_locality_t,
    /// The selector the declaration-time query uses. NULL means the
    /// subscriber's own keyexpr.
    pub query_selector: *const z_loaned_keyexpr_t,
    /// Target for that query.
    pub query_target: std::ffi::c_int,
    /// Consolidation for that query.
    pub query_consolidation: crate::get::z_query_consolidation_t,
    /// Accepted reply keyexprs for that query.
    pub query_accept_replies: std::ffi::c_int,
    /// Timeout in ms; 0 means "leave the default".
    pub query_timeout_ms: u64,
}

/// Upstream's defaults (`zenoh-c publication_cache.rs:46-55`). `history` is 1
/// and NOT 0 — a zeroed struct would build a cache that retains nothing, which
/// is the shape a `memset` caller would silently get.
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_publication_cache_options_default(
    this_: *mut ze_publication_cache_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        (*this_).queryable_suffix = std::ptr::null();
        (*this_).queryable_origin = zc_locality_default();
        (*this_).queryable_complete = false;
        (*this_).history = 1;
        (*this_).resources_limit = 0;
    }
}

/// Upstream's defaults (`zenoh-c querying_subscriber.rs:74-85`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_querying_subscriber_options_default(
    this_: *mut ze_querying_subscriber_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract, and the two nested defaults it delegates.
    unsafe {
        (*this_).allowed_origin = zc_locality_default();
        (*this_).query_selector = std::ptr::null();
        (*this_).query_target = crate::get::z_query_target_default();
        (*this_).query_consolidation = crate::get::z_query_consolidation_none();
        (*this_).query_accept_replies = crate::get::z_reply_keyexpr_default();
        (*this_).query_timeout_ms = 0;
    }
}

// ── The owned / loaned / moved handles ────────────────────────────────────────

macro_rules! ext_handle_type {
    ($owned:ident, $loaned:ident, $moved:ident, $size:ident) => {
        #[repr(C)]
        pub struct $owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        #[repr(C)]
        pub struct $loaned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        #[repr(C)]
        pub struct $moved {
            pub(crate) _this: $owned,
        }

        impl $owned {
            pub(crate) fn null_value() -> Self {
                Self {
                    handle: std::ptr::null_mut(),
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }
        }
    };
}

ext_handle_type!(
    ze_owned_publication_cache_t,
    ze_loaned_publication_cache_t,
    ze_moved_publication_cache_t,
    PUB_CACHE_SIZE
);
ext_handle_type!(
    ze_owned_querying_subscriber_t,
    ze_loaned_querying_subscriber_t,
    ze_moved_querying_subscriber_t,
    QUERYING_SUB_SIZE
);

const _: () = {
    assert!(std::mem::size_of::<ze_owned_publication_cache_t>() == PUB_CACHE_SIZE);
    assert!(std::mem::align_of::<ze_owned_publication_cache_t>() == 8);
    assert!(std::mem::size_of::<ze_owned_querying_subscriber_t>() == QUERYING_SUB_SIZE);
    assert!(std::mem::align_of::<ze_owned_querying_subscriber_t>() == 8);
};

// ── The publication cache ─────────────────────────────────────────────────────

/// One retained publication. Everything a reply must reproduce is COPIED at
/// cache time: the sample the callback sees is borrowed for exactly that call,
/// so keeping a pointer would be a use-after-free the moment the ring outlived
/// the callback — which is its entire purpose.
struct CachedSample {
    keyexpr: String,
    payload: Vec<u8>,
    kind: crate::abi::z_sample_kind_t,
    attachment: Option<Vec<u8>>,
    timestamp: Option<crate::timestamp::z_timestamp_t>,
}

/// The ring plus its bounds. Split out of [`PubCacheState`] so the two callbacks
/// can hold it WITHOUT holding the state that owns their own handles — a state
/// that owned its subscriber while its subscriber's callback owned the state
/// would be a reference cycle that never drops.
struct CacheCore {
    rings: Mutex<HashMap<String, VecDeque<CachedSample>>>,
    history: usize,
    resources_limit: usize,
    queryable_suffix: Option<String>,
}

impl CacheCore {
    /// Upstream's store step (`publication_cache.rs:260-283`): key the ring by
    /// `sample.key_expr()/suffix`, bound each ring by `history`, and DROP a
    /// sample whose key would exceed `resources_limit` rather than evicting a
    /// different key to make room.
    fn store(&self, sample: CachedSample) {
        let key = match &self.queryable_suffix {
            Some(suffix) => format!("{}/{}", sample.keyexpr, suffix),
            None => sample.keyexpr.clone(),
        };
        let mut rings = self.rings.lock().expect("publication cache ring poisoned");
        if let Some(queue) = rings.get_mut(&key) {
            if queue.len() >= self.history {
                queue.pop_front();
            }
            queue.push_back(sample);
            return;
        }
        if self.resources_limit != 0 && rings.len() >= self.resources_limit {
            // Upstream logs and drops. Dropping is the observable half, and it
            // is the half a test can see.
            return;
        }
        let mut queue = VecDeque::new();
        queue.push_back(sample);
        rings.insert(key, queue);
    }
}

/// The owned side: the two declarations plus the shared ring.
struct PubCacheState {
    /// Held so the ring's lifetime is the CACHE HANDLE's, not the last
    /// callback's. Both trampolines own their own clone, so this one is never
    /// read — dropping it would leave the ring alive purely by the accident of
    /// which declaration is torn down last, which is not a lifetime anyone
    /// could reason about.
    _core: Arc<CacheCore>,
    sub: crate::abi::z_owned_subscriber_t,
    qbl: crate::abi::z_owned_queryable_t,
    keyexpr: DeclaredKeyexpr,
}

impl Drop for PubCacheState {
    fn drop(&mut self) {
        // Undeclare through the SAME entry points a C program would use, so a
        // cache teardown and a hand-rolled one take one path.
        let mut moved_sub = crate::abi::z_moved_subscriber_t {
            _this: std::mem::replace(
                &mut self.sub,
                crate::abi::z_owned_subscriber_t::null_value(),
            ),
        };
        // SAFETY: `moved_sub` holds this cache's own live subscriber, moved out
        // exactly once by the `replace` above.
        unsafe { crate::sub::z_subscriber_drop(&mut moved_sub) };
        let mut moved_qbl = crate::abi::z_moved_queryable_t {
            _this: std::mem::replace(&mut self.qbl, crate::abi::z_owned_queryable_t::null_value()),
        };
        // SAFETY: as above, for the queryable.
        unsafe { crate::query::z_queryable_drop(&mut moved_qbl) };
    }
}

/// Read the state behind a loaned publication cache.
///
/// # Safety
/// `this_` must be null or a valid loaned cache whose handle slot holds a live
/// `PubCacheState` pointer.
unsafe fn pub_cache_state<'a>(
    this_: *const ze_loaned_publication_cache_t,
) -> Option<&'a PubCacheState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<PubCacheState>` this crate leaked.
    Some(unsafe { &*(handle as *const PubCacheState) })
}

/// The cache's SUBSCRIBER callback, as a C trampoline over an `Arc<CacheCore>`.
///
/// # Safety
/// Called by the subscriber plane with a valid loaned sample and this cache's
/// own context pointer.
unsafe extern "C" fn cache_on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    if sample.is_null() || context.is_null() {
        return;
    }
    // SAFETY: `context` is the `Arc<CacheCore>` raw pointer this file installed;
    // borrowed, never consumed — the drop callback owns the release.
    let core = unsafe { &*(context as *const CacheCore) };
    // SAFETY: the caller's contract, for every accessor below.
    let stored = unsafe {
        let ke = crate::sample::z_sample_keyexpr(sample);
        let Some(keyexpr) = keyexpr_str(ke) else {
            return;
        };
        let payload = crate::sample::z_sample_payload(sample);
        let mut owned_slice = crate::abi::z_owned_slice_t::null_value();
        let body = if crate::bytes::z_bytes_to_slice(payload, &mut owned_slice) == Z_OK {
            let loaned = crate::slice::z_slice_loan(&owned_slice);
            let data = crate::slice::z_slice_data(loaned);
            let len = crate::slice::z_slice_len(loaned);
            let out = if data.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data, len).to_vec()
            };
            let mut moved = crate::abi::z_moved_slice_t { _this: owned_slice };
            crate::slice::z_slice_drop(&mut moved);
            out
        } else {
            Vec::new()
        };
        let attachment_ptr = crate::sample::z_sample_attachment(sample);
        let attachment = if attachment_ptr.is_null() {
            None
        } else {
            let mut att_slice = crate::abi::z_owned_slice_t::null_value();
            if crate::bytes::z_bytes_to_slice(attachment_ptr, &mut att_slice) == Z_OK {
                let loaned = crate::slice::z_slice_loan(&att_slice);
                let data = crate::slice::z_slice_data(loaned);
                let len = crate::slice::z_slice_len(loaned);
                let out = if data.is_null() || len == 0 {
                    None
                } else {
                    Some(std::slice::from_raw_parts(data, len).to_vec())
                };
                let mut moved = crate::abi::z_moved_slice_t { _this: att_slice };
                crate::slice::z_slice_drop(&mut moved);
                out
            } else {
                None
            }
        };
        let ts_ptr = crate::sample::z_sample_timestamp(sample);
        let timestamp = if ts_ptr.is_null() {
            None
        } else {
            Some(std::ptr::read(ts_ptr))
        };
        CachedSample {
            keyexpr: keyexpr.to_owned(),
            payload: body,
            kind: crate::sample::z_sample_kind(sample),
            attachment,
            timestamp,
        }
    };
    core.store(stored);
}

/// Release the `Arc<CacheCore>` a trampoline context holds.
///
/// # Safety
/// `context` must be a pointer produced by `Arc::into_raw` on an
/// `Arc<CacheCore>`, released exactly once.
unsafe extern "C" fn cache_context_drop(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    drop(unsafe { Arc::from_raw(context as *const CacheCore) });
}

/// The cache's QUERYABLE callback: reply from the rings.
///
/// # Safety
/// Called by the queryable plane with a valid loaned query and this cache's own
/// context pointer.
unsafe extern "C" fn cache_on_query(query: *mut z_loaned_query_t, context: *mut c_void) {
    if query.is_null() || context.is_null() {
        return;
    }
    // SAFETY: as `cache_on_sample`.
    let core = unsafe { &*(context as *const CacheCore) };
    // SAFETY: the caller's contract.
    let Some(query_ke) = (unsafe { keyexpr_str(crate::query::z_query_keyexpr(query)) }) else {
        return;
    };
    let query_ke = query_ke.to_owned();
    let rings = core.rings.lock().expect("publication cache ring poisoned");
    // Upstream branches on the LITERAL presence of `*`, not on "is this a
    // pattern" — reproduced rather than improved, because a difference from
    // upstream here is exactly the defect this family exists to avoid.
    let exact = !query_ke.contains('*');
    for (key, queue) in rings.iter() {
        let matches = if exact {
            key == &query_ke
        } else {
            wz_runtime_tokio::keyexpr_match::keyexpr_intersect_patterns(
                &query_ke.split('/').collect::<Vec<_>>(),
                &key.split('/').collect::<Vec<_>>(),
            )
        };
        if !matches {
            continue;
        }
        for sample in queue {
            // SAFETY: every pointer below is built here and valid for the call.
            unsafe { reply_cached(query, sample) };
        }
    }
}

/// Reply one cached sample to `query`, reproducing its kind, attachment and
/// timestamp.
///
/// # Safety
/// `query` must be a valid loaned query.
unsafe fn reply_cached(query: *const z_loaned_query_t, sample: &CachedSample) {
    let mut view = crate::abi::z_view_keyexpr_t::null_value();
    // SAFETY: the string is a canonical keyexpr this cache stored from a live
    // sample, and the view borrows it for exactly the calls below.
    if unsafe {
        crate::keyexpr::z_view_keyexpr_from_substr(
            &mut view,
            sample.keyexpr.as_ptr() as *const std::ffi::c_char,
            sample.keyexpr.len(),
        )
    } != Z_OK
    {
        return;
    }
    // SAFETY: `view` was just initialised.
    let ke = unsafe { crate::keyexpr::z_view_keyexpr_loan(&view) };

    let mut attachment = z_owned_bytes_t::null_value();
    let attachment_ptr: *mut z_moved_bytes_t = match &sample.attachment {
        Some(bytes) => {
            // SAFETY: `bytes` is live for this call.
            unsafe {
                crate::bytes::z_bytes_copy_from_buf(&mut attachment, bytes.as_ptr(), bytes.len())
            };
            &mut crate::abi::z_moved_bytes_t { _this: attachment } as *mut _
        }
        None => std::ptr::null_mut(),
    };
    let timestamp_ptr = match &sample.timestamp {
        Some(ts) => ts as *const _ as *mut crate::timestamp::z_timestamp_t,
        None => std::ptr::null_mut(),
    };

    if sample.kind == crate::abi::Z_SAMPLE_KIND_DELETE {
        // SAFETY: `z_query_reply_del_options_default` assigns the WHOLE struct, so
        // the uninitialised slot is fully written before any field is read.
        let mut opts = unsafe {
            let mut slot =
                std::mem::MaybeUninit::<crate::query::z_query_reply_del_options_t>::uninit();
            crate::query::z_query_reply_del_options_default(slot.as_mut_ptr());
            slot.assume_init()
        };
        opts.timestamp = timestamp_ptr;
        opts.attachment = attachment_ptr;
        // SAFETY: all pointers are live for this call.
        unsafe { crate::query::z_query_reply_del(query, ke, &mut opts) };
        return;
    }

    let mut payload = z_owned_bytes_t::null_value();
    // SAFETY: `sample.payload` is live for this call.
    unsafe {
        crate::bytes::z_bytes_copy_from_buf(
            &mut payload,
            sample.payload.as_ptr(),
            sample.payload.len(),
        )
    };
    let mut moved_payload = z_moved_bytes_t { _this: payload };
    // SAFETY: as the del twin — the default writer assigns the whole struct.
    let mut opts = unsafe {
        let mut slot = std::mem::MaybeUninit::<crate::query::z_query_reply_options_t>::uninit();
        crate::query::z_query_reply_options_default(slot.as_mut_ptr());
        slot.assume_init()
    };
    opts.timestamp = timestamp_ptr;
    opts.attachment = attachment_ptr;
    // SAFETY: all pointers are live for this call; the payload is CONSUMED by
    // `z_query_reply` on every path, which is why it is built per reply.
    unsafe { crate::query::z_query_reply(query, ke, &mut moved_payload, &mut opts) };
}

/// Declare a publication cache (zenoh-c `ze_declare_publication_cache`,
/// `zenoh_commons.h:6101-6105`).
///
/// # Safety
/// `session` must be a valid loaned session; `pub_cache` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `options` must be null or
/// a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_publication_cache(
    session: *const z_loaned_session_t,
    pub_cache: *mut ze_owned_publication_cache_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut ze_publication_cache_options_t,
) -> ZResult {
    guarded(|| {
        if pub_cache.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *pub_cache = ze_owned_publication_cache_t::null_value() };

        // SAFETY: the caller's contract.
        let Some(ke) = (unsafe { keyexpr_str(key_expr) }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();

        // SAFETY: the caller's contract for the options struct.
        let (suffix, queryable_origin, queryable_complete, history, resources_limit) =
            unsafe { publication_cache_params(options) };
        let queryable_ke = match &suffix {
            Some(s) => format!("{ke}/{s}"),
            None => ke.clone(),
        };
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&queryable_ke).is_err()
        {
            return Z_EINVAL;
        }

        let core = Arc::new(CacheCore {
            rings: Mutex::new(HashMap::new()),
            // A 0 history would retain nothing while reporting success. Upstream
            // defaults it to 1; a caller who explicitly asks for 0 gets the same
            // floor the advanced cache applies, for the same reason.
            history: history.max(1),
            resources_limit,
            queryable_suffix: suffix,
        });

        // The SUBSCRIBER: session-local, because the cache stores what THIS
        // session publishes (`publication_cache.rs:220-223`).
        let mut sub_closure = z_owned_closure_sample_t::from_parts(
            Arc::into_raw(core.clone()) as *mut c_void,
            Some(cache_on_sample),
        );
        sub_closure.drop = Some(cache_context_drop);
        let mut moved_sub_closure = z_moved_closure_sample_t { _this: sub_closure };
        // SAFETY: the default writer assigns the whole struct.
        let mut sub_opts = unsafe {
            let mut slot = std::mem::MaybeUninit::<crate::sub::z_subscriber_options_t>::uninit();
            crate::sub::z_subscriber_options_default(slot.as_mut_ptr());
            slot.assume_init()
        };
        sub_opts.allowed_origin = crate::publisher::ZC_LOCALITY_SESSION_LOCAL;
        let mut sub = crate::abi::z_owned_subscriber_t::null_value();
        // SAFETY: the caller's session handle, plus locals built here.
        let rc = unsafe {
            crate::sub::z_declare_subscriber(
                session,
                &mut sub,
                key_expr,
                &mut moved_sub_closure,
                &mut sub_opts,
            )
        };
        if rc != Z_OK {
            return rc;
        }

        // The QUERYABLE, on `key_expr[/suffix]`.
        let mut view = crate::abi::z_view_keyexpr_t::null_value();
        // SAFETY: `queryable_ke` is live across the declare below.
        if unsafe {
            crate::keyexpr::z_view_keyexpr_from_substr(
                &mut view,
                queryable_ke.as_ptr() as *const std::ffi::c_char,
                queryable_ke.len(),
            )
        } != Z_OK
        {
            return Z_EINVAL;
        }
        let mut qbl_closure = crate::abi::z_owned_closure_query_t::from_parts(
            Arc::into_raw(core.clone()) as *mut c_void,
            Some(cache_on_query),
        );
        qbl_closure.drop = Some(cache_context_drop);
        let mut moved_qbl_closure = crate::abi::z_moved_closure_query_t { _this: qbl_closure };
        // SAFETY: the default writer assigns the whole struct.
        let mut qbl_opts = unsafe {
            let mut slot = std::mem::MaybeUninit::<crate::query::z_queryable_options_t>::uninit();
            crate::query::z_queryable_options_default(slot.as_mut_ptr());
            slot.assume_init()
        };
        qbl_opts.complete = queryable_complete;
        qbl_opts.allowed_origin = queryable_origin;
        let mut qbl = crate::abi::z_owned_queryable_t::null_value();
        // SAFETY: locals built here plus the caller's session handle.
        let rc = unsafe {
            crate::query::z_declare_queryable(
                session,
                &mut qbl,
                crate::keyexpr::z_view_keyexpr_loan(&view),
                &mut moved_qbl_closure,
                &mut qbl_opts,
            )
        };
        if rc != Z_OK {
            // The subscriber already landed; tear it down rather than leaking a
            // half-declared cache the caller has no handle to.
            let mut moved = crate::abi::z_moved_subscriber_t { _this: sub };
            // SAFETY: `sub` is this call's own live subscriber.
            unsafe { crate::sub::z_subscriber_drop(&mut moved) };
            return rc;
        }

        let mut boxed = Box::new(PubCacheState {
            _core: core,
            sub,
            qbl,
            keyexpr: DeclaredKeyexpr::new(ke),
        });
        // Bind AFTER boxing — the state is at its final address only here.
        boxed.keyexpr.bind();
        // SAFETY: `pub_cache` was checked non-null above.
        unsafe { (*pub_cache).handle = Box::into_raw(boxed) as Handle };
        Z_OK
    })
}

/// Read a `ze_publication_cache_options_t`, or upstream's defaults for NULL.
///
/// # Safety
/// `options` must be null or a valid options struct.
unsafe fn publication_cache_params(
    options: *const ze_publication_cache_options_t,
) -> (Option<String>, zc_locality_t, bool, usize, usize) {
    if options.is_null() {
        return (None, zc_locality_default(), false, 1, 0);
    }
    // SAFETY: the caller's contract, for every read below.
    unsafe {
        let suffix = keyexpr_str((*options).queryable_suffix).map(|s| s.to_owned());
        (
            suffix,
            (*options).queryable_origin,
            (*options).queryable_complete,
            (*options).history,
            (*options).resources_limit,
        )
    }
}

/// Declare a publication cache the C side never holds (zenoh-c
/// `ze_declare_background_publication_cache`).
///
/// The same deliberate discard the background subscriber and queryable use: the
/// handle is written into a local sink that goes out of scope without reclaiming
/// it, so the cache lives until the session closes.
///
/// # Safety
/// As [`ze_declare_publication_cache`], minus the out-parameter.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_background_publication_cache(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut ze_publication_cache_options_t,
) -> ZResult {
    let mut sink = ze_owned_publication_cache_t::null_value();
    // SAFETY: the caller's contract, delegated.
    let rc = unsafe { ze_declare_publication_cache(session, &mut sink, key_expr, options) };
    // The sink simply goes out of scope. It holds a RAW handle and implements no
    // `Drop`, so nothing reclaims the boxed state — which is exactly what
    // "background" means here. A `mem::forget` would be a no-op that merely
    // looked load-bearing, and clippy says so; the sibling background declares
    // in `sub` and `query` make the same discard for the same reason.
    rc
}

/// The keyexpr this cache was declared under (zenoh-c
/// `ze_publication_cache_keyexpr`). This is the PUBLICATION keyexpr, not the
/// queryable's suffixed form — upstream returns `pub_key_expr`.
///
/// # Safety
/// `this_` must be null or a valid loaned cache.
#[no_mangle]
pub unsafe extern "C" fn ze_publication_cache_keyexpr(
    this_: *const ze_loaned_publication_cache_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { pub_cache_state(this_) } {
            Some(state) => state.keyexpr.as_loaned(),
            None => std::ptr::null(),
        }
    })
}

/// Borrow a publication cache (zenoh-c `ze_publication_cache_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned cache.
#[no_mangle]
pub unsafe extern "C" fn ze_publication_cache_loan(
    this_: *const ze_owned_publication_cache_t,
) -> *const ze_loaned_publication_cache_t {
    this_ as *const ze_loaned_publication_cache_t
}

/// Gravestone a publication cache (zenoh-c `ze_internal_publication_cache_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_publication_cache_null(
    this_: *mut ze_owned_publication_cache_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = ze_owned_publication_cache_t::null_value() };
}

/// Is this cache live (zenoh-c `ze_internal_publication_cache_check`)?
///
/// # Safety
/// `this_` must be null or a valid owned cache.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_publication_cache_check(
    this_: *const ze_owned_publication_cache_t,
) -> bool {
    if this_.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    !unsafe { (*this_).handle }.is_null()
}

/// Undeclare a publication cache (zenoh-c `ze_undeclare_publication_cache`).
///
/// # Safety
/// `this_` must be null or a valid moved cache.
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_publication_cache(
    this_: *mut ze_moved_publication_cache_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*this_)._this };
        let handle = std::mem::replace(&mut owned.handle, std::ptr::null_mut());
        if handle.is_null() {
            return Z_OK;
        }
        // SAFETY: the handle is a `Box<PubCacheState>` this crate leaked, taken
        // exactly once by the `replace` above. Its `Drop` undeclares both halves.
        drop(unsafe { Box::from_raw(handle as *mut PubCacheState) });
        Z_OK
    })
}

/// Drop a publication cache (zenoh-c `ze_publication_cache_drop`) — undeclare,
/// discarding the result, exactly as upstream defines it.
///
/// # Safety
/// As [`ze_undeclare_publication_cache`].
#[no_mangle]
pub unsafe extern "C" fn ze_publication_cache_drop(this_: *mut ze_moved_publication_cache_t) {
    // SAFETY: the caller's contract, delegated.
    let _ = unsafe { ze_undeclare_publication_cache(this_) };
}

// ── The querying subscriber ───────────────────────────────────────────────────

/// The owned side: the subscriber, plus what a later
/// [`ze_querying_subscriber_get`] needs to issue another query.
struct QueryingSubState {
    sub: crate::abi::z_owned_subscriber_t,
    /// The user callback, shared between the live subscriber and every query's
    /// reply forwarding. `Arc` because both sides call it and neither owns it.
    user: Arc<crate::sub::CClosure>,
    session: *const z_loaned_session_t,
    keyexpr: DeclaredKeyexpr,
}

// SAFETY: `session` is a borrowed loaned-session pointer whose target outlives
// this state by the C contract (a session must not be closed while a subscriber
// declared on it is live), and every other field is already Send + Sync.
unsafe impl Send for QueryingSubState {}
// SAFETY: as above — the state is only ever read through a shared reference.
unsafe impl Sync for QueryingSubState {}

impl Drop for QueryingSubState {
    fn drop(&mut self) {
        let mut moved = crate::abi::z_moved_subscriber_t {
            _this: std::mem::replace(
                &mut self.sub,
                crate::abi::z_owned_subscriber_t::null_value(),
            ),
        };
        // SAFETY: this state's own live subscriber, moved out exactly once.
        unsafe { crate::sub::z_subscriber_drop(&mut moved) };
    }
}

/// Read the state behind a loaned querying subscriber.
///
/// # Safety
/// `this_` must be null or a valid loaned querying subscriber whose handle slot
/// holds a live `QueryingSubState` pointer.
unsafe fn querying_sub_state<'a>(
    this_: *const ze_loaned_querying_subscriber_t,
) -> Option<&'a QueryingSubState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(unsafe { &*(handle as *const QueryingSubState) })
}

/// Forward one OK reply's sample into the user's sample callback.
///
/// # Safety
/// Called by the get plane with a valid loaned reply and an `Arc<CClosure>` raw
/// pointer as context.
unsafe extern "C" fn forward_reply_to_sample(
    reply: *mut crate::abi::z_loaned_reply_t,
    context: *mut c_void,
) {
    if reply.is_null() || context.is_null() {
        return;
    }
    // SAFETY: the context is the `Arc<CClosure>` pointer installed below;
    // borrowed for this call only.
    let closure = unsafe { &*(context as *const crate::sub::CClosure) };
    // SAFETY: the caller's contract.
    if !unsafe { crate::get::z_reply_is_ok(reply) } {
        return;
    }
    // SAFETY: as above.
    let sample = unsafe { crate::get::z_reply_ok(reply) };
    if sample.is_null() {
        return;
    }
    let Some(call) = closure.call else {
        return;
    };
    let ctx = closure.context.0;
    // SAFETY: the C callback owns the call; a panic unwinding across the
    // `extern "C"` boundary is UB, so it is caught here as every other callback
    // trampoline in this crate does.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(sample, ctx);
    }));
}

/// Release the `Arc<CClosure>` a reply trampoline context holds.
///
/// # Safety
/// `context` must come from `Arc::into_raw` on an `Arc<CClosure>`, released once.
unsafe extern "C" fn reply_context_drop(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    drop(unsafe { Arc::from_raw(context as *const crate::sub::CClosure) });
}

/// Issue one query whose OK replies are forwarded into `user`.
///
/// # Safety
/// `session` and `selector` must be valid; `options` must be null or valid.
unsafe fn issue_forwarding_get(
    session: *const z_loaned_session_t,
    selector: *const z_loaned_keyexpr_t,
    user: &Arc<crate::sub::CClosure>,
    options: *mut crate::get::z_get_options_t,
) -> ZResult {
    let mut closure = crate::abi::z_owned_closure_reply_t::from_parts(
        Arc::into_raw(user.clone()) as *mut c_void,
        Some(forward_reply_to_sample),
    );
    closure.drop = Some(reply_context_drop);
    let mut moved = crate::abi::z_moved_closure_reply_t { _this: closure };
    // SAFETY: the caller's contract plus the locals built here.
    unsafe { crate::get::z_get(session, selector, std::ptr::null(), &mut moved, options) }
}

/// Declare a querying subscriber (zenoh-c `ze_declare_querying_subscriber`,
/// `zenoh_commons.h:6120-6125`).
///
/// # Safety
/// `session` must be a valid loaned session; `querying_subscriber` must be valid
/// and writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure; `options` must be null or a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_querying_subscriber(
    session: *const z_loaned_session_t,
    querying_subscriber: *mut ze_owned_querying_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_querying_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if querying_subscriber.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *querying_subscriber = ze_owned_querying_subscriber_t::null_value() };

        // Consume the moved closure FIRST, as every declare in this crate does:
        // from here the `CClosure` owns the C `drop(context)` responsibility, so
        // an early return still frees the caller's context.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let user = Arc::new(crate::sub::CClosure::new(
            owned.context,
            owned.call,
            owned.drop,
        ));
        *owned = z_owned_closure_sample_t::null_value();

        // SAFETY: the caller's contract.
        let Some(ke) = (unsafe { keyexpr_str(key_expr) }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();

        // The LIVE half: an ordinary subscriber carrying the caller's origin.
        let mut sub_closure = z_owned_closure_sample_t::from_parts(
            Arc::into_raw(user.clone()) as *mut c_void,
            Some(forward_sample),
        );
        sub_closure.drop = Some(reply_context_drop);
        let mut moved_sub_closure = z_moved_closure_sample_t { _this: sub_closure };
        // SAFETY: the default writer assigns the whole struct.
        let mut sub_opts = unsafe {
            let mut slot = std::mem::MaybeUninit::<crate::sub::z_subscriber_options_t>::uninit();
            crate::sub::z_subscriber_options_default(slot.as_mut_ptr());
            slot.assume_init()
        };
        // SAFETY: the caller's contract for the options struct.
        if !options.is_null() {
            sub_opts.allowed_origin = unsafe { (*options).allowed_origin };
        }
        let mut sub = crate::abi::z_owned_subscriber_t::null_value();
        // SAFETY: the caller's session handle plus locals built here.
        let rc = unsafe {
            crate::sub::z_declare_subscriber(
                session,
                &mut sub,
                key_expr,
                &mut moved_sub_closure,
                &mut sub_opts,
            )
        };
        if rc != Z_OK {
            return rc;
        }

        let mut boxed = Box::new(QueryingSubState {
            sub,
            user: user.clone(),
            session,
            keyexpr: DeclaredKeyexpr::new(ke),
        });
        boxed.keyexpr.bind();
        let handle = Box::into_raw(boxed);
        // SAFETY: checked non-null above.
        unsafe { (*querying_subscriber).handle = handle as Handle };

        // The HISTORY half, issued AFTER the subscriber is live so a sample
        // published between the two is not lost. Upstream orders it the same way.
        // SAFETY: the pointers are the caller's plus this call's own state.
        let selector = unsafe { querying_selector(options) }.unwrap_or(key_expr);
        let mut get_opts = unsafe { querying_get_options(options) };
        // SAFETY: as above.
        let _ = unsafe { issue_forwarding_get(session, selector, &user, &mut get_opts) };
        Z_OK
    })
}

/// Forward a live sample into the shared user closure.
///
/// # Safety
/// Called by the subscriber plane with a valid loaned sample and an
/// `Arc<CClosure>` raw pointer as context.
unsafe extern "C" fn forward_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    if sample.is_null() || context.is_null() {
        return;
    }
    // SAFETY: as `forward_reply_to_sample`.
    let closure = unsafe { &*(context as *const crate::sub::CClosure) };
    let Some(call) = closure.call else {
        return;
    };
    let ctx = closure.context.0;
    // SAFETY: as `forward_reply_to_sample`.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(sample, ctx);
    }));
}

/// The query selector an options struct names, or `None` for "the subscriber's
/// own keyexpr".
///
/// # Safety
/// `options` must be null or valid.
unsafe fn querying_selector(
    options: *const ze_querying_subscriber_options_t,
) -> Option<*const z_loaned_keyexpr_t> {
    if options.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let selector = unsafe { (*options).query_selector };
    if selector.is_null() {
        None
    } else {
        Some(selector)
    }
}

/// Fold the query half of a `ze_querying_subscriber_options_t` into a
/// `z_get_options_t`.
///
/// # Safety
/// `options` must be null or valid.
unsafe fn querying_get_options(
    options: *const ze_querying_subscriber_options_t,
) -> crate::get::z_get_options_t {
    // SAFETY: the default writer assigns the whole struct.
    let mut out = unsafe {
        let mut slot = std::mem::MaybeUninit::<crate::get::z_get_options_t>::uninit();
        crate::get::z_get_options_default(slot.as_mut_ptr());
        slot.assume_init()
    };
    if options.is_null() {
        return out;
    }
    // SAFETY: the caller's contract, for every read below.
    unsafe {
        out.target = (*options).query_target;
        // Read FIELD-WISE: `z_query_consolidation_t` is not `Copy`, and this
        // struct is borrowed through a raw pointer the caller still owns.
        out.consolidation = crate::get::z_query_consolidation_t {
            mode: (*options).query_consolidation.mode,
        };
        out.accept_replies = (*options).query_accept_replies;
        // Upstream leaves the builder's own default in place for 0
        // (`querying_subscriber.rs:112-114`), so 0 must NOT be written through
        // as a zero timeout — that would be an immediate expiry, not a default.
        if (*options).query_timeout_ms != 0 {
            out.timeout_ms = (*options).query_timeout_ms;
        }
    }
    out
}

/// Declare a querying subscriber the C side never holds (zenoh-c
/// `ze_declare_background_querying_subscriber`).
///
/// # Safety
/// As [`ze_declare_querying_subscriber`], minus the out-parameter.
#[no_mangle]
pub unsafe extern "C" fn ze_declare_background_querying_subscriber(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut ze_querying_subscriber_options_t,
) -> ZResult {
    let mut sink = ze_owned_querying_subscriber_t::null_value();
    // SAFETY: the caller's contract, delegated.
    let rc =
        unsafe { ze_declare_querying_subscriber(session, &mut sink, key_expr, callback, options) };
    // Discarded, not forgotten — see the publication-cache twin for why.
    rc
}

/// Issue an ADDITIONAL query on `selector`, merging its replies into the
/// subscriber's callback (zenoh-c `ze_querying_subscriber_get`).
///
/// # Safety
/// `this_` must be null or a valid loaned querying subscriber; `selector` must be
/// null or a valid loaned keyexpr; `options` must be null or a valid get-options
/// struct.
#[no_mangle]
pub unsafe extern "C" fn ze_querying_subscriber_get(
    this_: *const ze_loaned_querying_subscriber_t,
    selector: *const z_loaned_keyexpr_t,
    options: *mut crate::get::z_get_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { querying_sub_state(this_) }) else {
            return Z_ENULL;
        };
        let target = if selector.is_null() {
            state.keyexpr.as_loaned()
        } else {
            selector
        };
        if target.is_null() {
            return Z_ENULL;
        }
        // A NULL options is upstream's "defaults", and the borrowed struct must
        // not be mutated, so the default is materialised locally.
        let mut local_opts;
        let opts = if options.is_null() {
            // SAFETY: the default writer assigns the whole struct.
            local_opts = unsafe {
                let mut slot = std::mem::MaybeUninit::<crate::get::z_get_options_t>::uninit();
                crate::get::z_get_options_default(slot.as_mut_ptr());
                slot.assume_init()
            };
            &mut local_opts as *mut _
        } else {
            options
        };
        // SAFETY: the caller's contract plus this state's own session pointer.
        unsafe { issue_forwarding_get(state.session, target, &state.user, opts) }
    })
}

/// Borrow a querying subscriber (zenoh-c `ze_querying_subscriber_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned querying subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_querying_subscriber_loan(
    this_: *const ze_owned_querying_subscriber_t,
) -> *const ze_loaned_querying_subscriber_t {
    this_ as *const ze_loaned_querying_subscriber_t
}

/// Gravestone a querying subscriber (zenoh-c
/// `ze_internal_querying_subscriber_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_querying_subscriber_null(
    this_: *mut ze_owned_querying_subscriber_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = ze_owned_querying_subscriber_t::null_value() };
}

/// Is this querying subscriber live (zenoh-c
/// `ze_internal_querying_subscriber_check`)?
///
/// # Safety
/// `this_` must be null or a valid owned querying subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_querying_subscriber_check(
    this_: *const ze_owned_querying_subscriber_t,
) -> bool {
    if this_.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    !unsafe { (*this_).handle }.is_null()
}

/// Undeclare a querying subscriber (zenoh-c
/// `ze_undeclare_querying_subscriber`).
///
/// # Safety
/// `this_` must be null or a valid moved querying subscriber.
#[no_mangle]
pub unsafe extern "C" fn ze_undeclare_querying_subscriber(
    this_: *mut ze_moved_querying_subscriber_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*this_)._this };
        let handle = std::mem::replace(&mut owned.handle, std::ptr::null_mut());
        if handle.is_null() {
            return Z_OK;
        }
        // SAFETY: a `Box<QueryingSubState>` this crate leaked, taken once.
        drop(unsafe { Box::from_raw(handle as *mut QueryingSubState) });
        Z_OK
    })
}

/// Drop a querying subscriber (zenoh-c `ze_querying_subscriber_drop`).
///
/// # Safety
/// As [`ze_undeclare_querying_subscriber`].
#[no_mangle]
pub unsafe extern "C" fn ze_querying_subscriber_drop(this_: *mut ze_moved_querying_subscriber_t) {
    // SAFETY: the caller's contract, delegated.
    let _ = unsafe { ze_undeclare_querying_subscriber(this_) };
}
