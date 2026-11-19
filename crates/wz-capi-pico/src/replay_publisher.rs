// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_replay_publisher_*`: the replay cache of a publisher, from C. The program records the
//! frames of one message as it sends them, into a ring per instance over its own storage; the
//! cache answers a query on the message's key plus the suffix the program states with what the
//! rings hold, oldest first, and, under the session's policy, holds the message's sends while it
//! answers.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `replay-cache` capability implies `unstable-api`. The ring, the
//! answer's order and the held sends are [`wz_session_core::replay_publisher`]'s; this file is
//! the pico ABI's names, result codes, queryable and ownership around it.
//!
//! # Policies
//!
//! Read from the snapshot of the session the cache is made on, once: `replay-reply-shape`
//! (`frame-per-sample`: one reply per frame as it was sent; `segmented`: each frame as the pieces
//! of the segment profile the serve door is given, every frame under the next transfer number)
//! and `replay-serve-holds-sends`.
//!
//! # Storage, session and publisher
//!
//! The rings are the program's byte area, `wz_ext_replay_publisher_storage_size` long, which the
//! cache writes when it is made and owns until it is dropped. The cache is bound to the session it
//! is made on and to the publisher it puts the message on; the program keeps both until it drops
//! the cache, and drops the cache before it undeclares the publisher or drops the session.
//!
//! # Threads
//!
//! One cache may be called from several threads, each door under its lock. A query is answered on
//! the thread the session hands it to: the snapshot is taken under the lock, the replies are sent
//! after it is let go, and the held sends go out once the last answer is over, before any later
//! send.

use core::ffi::{c_char, c_void};
use std::sync::{Arc, Mutex};

use wz_app_frame::segment_sender::{Rollover, SegmentSender};
use wz_session_core::policy::ReplayReplyShape;
use wz_session_core::replay_publisher::{
    CreateRefused, Dispatch, Phase, RecordRefused, ReplayPublisher, SendKind, Shape,
};

use crate::abi::{
    z_loaned_keyexpr_t, z_moved_bytes_t, z_owned_bytes_t, z_owned_string_t, z_view_keyexpr_t,
};
use crate::bytes::z_bytes_copy_from_buf;
use crate::e2e::{bytes_arg, clear_refusal, locked, utf8_arg, write_refusal};
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::{keyexpr_str, z_view_keyexpr_from_substr, z_view_keyexpr_loan};
use crate::pubsub::{z_loaned_publisher_t, z_publisher_put};
use crate::query::{
    z_declare_queryable, z_loaned_query_t, z_moved_closure_query_t, z_owned_closure_query_t,
    z_owned_queryable_t, z_query_keyexpr, z_query_reply, z_queryable_move, z_undeclare_queryable,
};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SESSION_CLOSED,
    Z_OK,
};
use crate::session::{session_handle, z_loaned_session_t};

/// A send of a message sent on a period: while sends are held, only the latest of its instance
/// is kept.
pub const WZ_EXT_REPLAY_SEND_PERIODIC: u8 = 0;
/// A send of an event: while sends are held, it waits in a queue of max(1, depth/2).
pub const WZ_EXT_REPLAY_SEND_EVENT: u8 = 1;

/// The frame went out.
pub const WZ_EXT_REPLAY_SENT: u8 = 0;
/// A periodic frame is held as its instance's latest.
pub const WZ_EXT_REPLAY_HELD: u8 = 1;
/// A periodic frame is held, and the one it replaced will not go out.
pub const WZ_EXT_REPLAY_HELD_REPLACED: u8 = 2;
/// An event frame waits in the queue.
pub const WZ_EXT_REPLAY_DEFERRED: u8 = 3;
/// An event frame waits in the queue, which gave up its oldest frame for it.
pub const WZ_EXT_REPLAY_DEFERRED_OVERWROTE: u8 = 4;

/// No answer is in progress, and nothing held is waiting.
pub const WZ_EXT_REPLAY_SERVING_IDLE: u8 = 0;
/// An answer is in progress.
pub const WZ_EXT_REPLAY_SERVING_ANSWERING: u8 = 1;
/// The last answer ended and the held frames are going out.
pub const WZ_EXT_REPLAY_SERVING_RELEASING: u8 = 2;
/// What `wz_ext_replay_publisher_phase` answers for a null cache or the gravestone.
pub const WZ_EXT_REPLAY_NO_CACHE: u8 = 255;

/// How a cache is laid out.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_replay_shape_t {
    /// The longest frame the cache keeps, in bytes, at least 1.
    pub frame_max: usize,
    /// How many frames each instance's ring keeps, 1 to `REPLAY_DEPTH_MAX`.
    pub depth: u32,
    /// How many instances the message has, at least 1.
    pub instances: u32,
}

/// What a cache counted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_replay_publisher_counts_t {
    /// Frames recorded.
    pub recorded: u64,
    /// Held event frames given up.
    pub deferred_overwritten: u64,
    /// Held periodic frames that did not go out.
    pub periodic_replaced: u64,
    /// Answers begun.
    pub answers: u64,
}

/// How a cache serves, under `replay-reply-shape = segmented`: the segment profile and the
/// program's values of its fields (NUL-terminated JSON, BORROWED for the call), the transfer
/// number the first answered frame carries, and the size of a piece's chunk. Not read under
/// `frame-per-sample`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_replay_serve_options_t {
    pub segment_profile: *const c_char,
    pub segment_values: *const c_char,
    pub first_transfer: u64,
    pub chunk_bytes: usize,
}

/// An owned cache: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_replay_publisher_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned cache: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_replay_publisher_t {
    pub(crate) handle: *mut c_void,
}

/// A moved cache (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_replay_publisher_t {
    pub(crate) _this: wz_ext_owned_replay_publisher_t,
}

/// What the queryable's callback and the doors share.
struct Shared {
    /// The cache; `None` once the program dropped it, so a query that comes after reads nothing of
    /// the program's storage.
    cache: Mutex<Option<ReplayPublisher<'static>>>,
    /// The segment sender of a `segmented` answer, once the cache serves.
    segments: Mutex<Option<SegmentSender>>,
    chunk_bytes: Mutex<usize>,
    shape: ReplayReplyShape,
    frame_max: usize,
    /// The program's publisher, as its loan reads.
    publisher: z_loaned_publisher_t,
}

// SAFETY: the publisher's words are the handle of a publisher the program keeps declared while
// the cache lives, and a put through them is a door pico lets any thread call; everything else is
// behind a lock.
unsafe impl Send for Shared {}
// SAFETY: as for `Send`: the only field read without a lock is the publisher's handle, which no
// door writes.
unsafe impl Sync for Shared {}

/// Behind a handle: the shared state, the session it was made on, and the queryable once it
/// serves.
struct Handle {
    shared: Arc<Shared>,
    session: z_loaned_session_t,
    queryable: Mutex<Option<z_owned_queryable_t>>,
}

impl wz_ext_owned_replay_publisher_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }
}

/// The handle behind a loaned cache; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned cache of this library.
unsafe fn handle_of<'a>(this_: *const wz_ext_loaned_replay_publisher_t) -> Option<&'a Handle> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Handle>())
}

/// The shape a C shape names.
fn shape_of(shape: &wz_ext_replay_shape_t) -> Shape {
    Shape {
        depth: shape.depth as usize,
        instances: shape.instances as usize,
        frame_max: shape.frame_max,
    }
}

/// The text of a refusal to make a cache.
fn create_text(refusal: CreateRefused) -> &'static str {
    match refusal {
        CreateRefused::DepthOutOfRange => "depth: 1 to the build's REPLAY_DEPTH_MAX",
        CreateRefused::NoInstance => "instances: at least 1",
        CreateRefused::FrameMaxOutOfRange => "frame_max: at least 1 and below 2^32 - 1",
        CreateRefused::TooLarge => "the shape's storage does not fit the address space",
        CreateRefused::StorageShort => {
            "storage: shorter than wz_ext_replay_publisher_storage_size gives"
        }
    }
}

/// The code of a refusal to record.
fn record_code(refusal: RecordRefused) -> ZResult {
    match refusal {
        RecordRefused::NoSuchInstance | RecordRefused::FrameTooLong => Z_EINVAL,
    }
}

/// The C form of what a send did.
fn dispatch_code(dispatch: Dispatch) -> u8 {
    match dispatch {
        Dispatch::Now => WZ_EXT_REPLAY_SENT,
        Dispatch::Held { replaced: false } => WZ_EXT_REPLAY_HELD,
        Dispatch::Held { replaced: true } => WZ_EXT_REPLAY_HELD_REPLACED,
        Dispatch::Deferred { overwrote: false } => WZ_EXT_REPLAY_DEFERRED,
        Dispatch::Deferred { overwrote: true } => WZ_EXT_REPLAY_DEFERRED_OVERWROTE,
    }
}

/// The C form of a phase.
fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::Idle => WZ_EXT_REPLAY_SERVING_IDLE,
        Phase::Serving => WZ_EXT_REPLAY_SERVING_ANSWERING,
        Phase::Releasing => WZ_EXT_REPLAY_SERVING_RELEASING,
    }
}

/// Copy `bytes` into an owned payload, moved into `put`.
///
/// # Safety
/// `put` is a door that consumes the moved payload on every path.
unsafe fn with_payload(bytes: &[u8], put: impl FnOnce(*mut z_moved_bytes_t) -> ZResult) -> ZResult {
    let mut payload = z_owned_bytes_t::null_value();
    let copied = z_bytes_copy_from_buf(&mut payload, bytes.as_ptr(), bytes.len());
    if copied != Z_OK {
        return copied;
    }
    let mut moved = z_moved_bytes_t { _this: payload };
    put(&mut moved)
}

impl Shared {
    /// Put `frame` on the program's publisher.
    fn put(&self, frame: &[u8]) -> ZResult {
        // SAFETY: the program keeps its publisher declared while the cache lives (the module
        // doc), and the put consumes the payload on every path.
        unsafe {
            with_payload(frame, |payload| {
                z_publisher_put(&self.publisher, payload, core::ptr::null())
            })
        }
    }

    /// An answer is over: end it, and when it was the last, send what was held, oldest first,
    /// until nothing is left. The lock is let go for each put, so a send in between is held
    /// behind what is still waiting.
    fn end_answer(&self) {
        if let Some(cache) = locked(&self.cache).as_mut() {
            cache.end_answer();
        }
        let mut out = vec![0u8; self.frame_max];
        loop {
            let next = match locked(&self.cache).as_mut() {
                Some(cache) => cache.next_held(&mut out),
                None => None,
            };
            let Some(len) = next else {
                return;
            };
            let _ = self.put(&out[..len]);
        }
    }

    /// Answer `query` with the snapshot of the rings, as the shape says, then end the answer.
    ///
    /// # Safety
    /// `query` is the loaned query the queryable's callback was handed.
    unsafe fn answer(&self, query: *const z_loaned_query_t) {
        let frames: Vec<Vec<u8>> = {
            let mut cache = locked(&self.cache);
            let Some(cache) = cache.as_mut() else {
                return;
            };
            let mut order = vec![0usize; cache.shape().ring_cells()];
            let listed = cache.begin_answer(&mut order);
            order[..listed]
                .iter()
                .map(|&cell| cache.frame(cell).to_vec())
                .collect()
        };
        let keyexpr = z_query_keyexpr(query);
        let reply = |bytes: &[u8]| -> Result<(), ZResult> {
            match with_payload(bytes, |payload| {
                z_query_reply(query, keyexpr, payload, core::ptr::null())
            }) {
                Z_OK => Ok(()),
                code => Err(code),
            }
        };
        match self.shape {
            ReplayReplyShape::FramePerSample => {
                for frame in &frames {
                    if reply(frame.as_slice()).is_err() {
                        break;
                    }
                }
            }
            ReplayReplyShape::Segmented => {
                let chunk = *locked(&self.chunk_bytes);
                let mut segments = locked(&self.segments);
                if let Some(sender) = segments.as_mut() {
                    for frame in &frames {
                        if sender.split(frame, chunk, &reply).is_err() {
                            break;
                        }
                    }
                }
            }
        }
        self.end_answer();
    }
}

/// The queryable's callback: answer the query.
unsafe extern "C" fn on_query(query: *const z_loaned_query_t, context: *mut c_void) {
    let shared = &*context.cast_const().cast::<Shared>();
    let _ = crate::ffi::catch(|| shared.answer(query));
}

/// The queryable's drop: release its share of the state.
unsafe extern "C" fn on_query_drop(context: *mut c_void) {
    drop(Arc::from_raw(context.cast_const().cast::<Shared>()));
}

/// How many bytes of storage a cache of `shape` takes; 0 for a null shape, one with no depth, no
/// instance or no frame room, and one whose size overflows.
///
/// # Safety
/// `shape` is null or valid.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_storage_size(
    shape: *const wz_ext_replay_shape_t,
) -> usize {
    guard_val(0, || {
        if shape.is_null() {
            return 0;
        }
        let shape = shape_of(&*shape);
        if shape.depth == 0 || shape.instances == 0 || shape.frame_max == 0 {
            return 0;
        }
        shape.storage_bytes().unwrap_or(0)
    })
}

/// A replay cache of `shape` over the program's `storage`, made on `session` (whose policies it
/// reads, once) and putting the message on `publisher`. It records and answers nothing until the
/// program records a frame and serves.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and the reason on `_Z_ERR_CONFIG_INVALID_VALUE`.
///
/// Returns `Z_ERR_NULL` for a null `this_`, session, publisher, shape or storage;
/// `Z_ERR_SESSION_CLOSED` for a closed session; `_Z_ERR_CONFIG_INVALID_VALUE` for a shape out of
/// range or storage shorter than `wz_ext_replay_publisher_storage_size`; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `session` and `publisher` are null or loans of this library, kept until
/// the cache is dropped; `storage` is writable for `storage_len` bytes, left to the cache until it
/// is dropped; `shape` is null or valid; `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_new(
    this_: *mut wz_ext_owned_replay_publisher_t,
    session: *const z_loaned_session_t,
    publisher: *const z_loaned_publisher_t,
    storage: *mut u8,
    storage_len: usize,
    shape: *const wz_ext_replay_shape_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        *this_ = wz_ext_owned_replay_publisher_t::null_value();
        if publisher.is_null() || shape.is_null() || storage.is_null() {
            return Z_ERR_NULL;
        }
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        if handle.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let policy = &handle.ext.policy;
        let shape = shape_of(&*shape);
        let area: &'static mut [u8] = core::slice::from_raw_parts_mut(storage, storage_len);
        let cache = match ReplayPublisher::new(area, shape, policy.replay_serve_holds_sends()) {
            Ok(cache) => cache,
            Err(why) => {
                write_refusal(refusal, create_text(why));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        let shared = Arc::new(Shared {
            cache: Mutex::new(Some(cache)),
            segments: Mutex::new(None),
            chunk_bytes: Mutex::new(0),
            shape: policy.replay_reply_shape(),
            frame_max: shape.frame_max,
            publisher: z_loaned_publisher_t {
                handle: (*publisher).handle,
                _pad: (*publisher)._pad,
            },
        });
        let handle = Box::new(Handle {
            shared,
            session: z_loaned_session_t {
                _val: (*session)._val,
                _cnt: (*session)._cnt,
            },
            queryable: Mutex::new(None),
        });
        (*this_).handle = Box::into_raw(handle).cast::<c_void>();
        Z_OK
    })
}

/// Record `frame`, sent at `time_ms` (the program's clock, which orders an answer) on instance
/// `instance`, without sending it: for a program that sends the frame itself.
///
/// Returns `Z_OK`; `Z_EINVAL` for an instance the cache does not have or a frame longer than its
/// `frame_max` (nothing recorded); `Z_ERR_NULL` for a null cache, the gravestone, or a null frame
/// with a length.
///
/// # Safety
/// `this_` is null or a loaned cache; `frame` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_record(
    this_: *const wz_ext_loaned_replay_publisher_t,
    instance: usize,
    time_ms: u64,
    frame: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if frame.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let mut cache = locked(&handle.shared.cache);
        let Some(cache) = cache.as_mut() else {
            return Z_ERR_NULL;
        };
        match cache.record(instance, time_ms, bytes_arg(frame, len)) {
            Ok(_) => Z_OK,
            Err(why) => record_code(why),
        }
    })
}

/// Record `frame`, sent at `time_ms` on instance `instance`, and put it on the cache's publisher,
/// or, while an answer is served under `replay-serve-holds-sends = on`, hold it: a
/// `WZ_EXT_REPLAY_SEND_PERIODIC` frame as its instance's latest, a `WZ_EXT_REPLAY_SEND_EVENT` one
/// in the queue. A held frame goes out once the last answer is over. `dispatch` may be null; it
/// receives a `WZ_EXT_REPLAY_SENT`, `_HELD`, `_HELD_REPLACED`, `_DEFERRED` or `_DEFERRED_OVERWROTE`
/// value.
///
/// The frame is recorded before it is put, whether or not the put succeeds. Returns `Z_OK` when it
/// was put or held; the put's code when the put failed; `Z_EINVAL` for an instance the cache does
/// not have, a frame longer than its `frame_max` or a kind this library does not know (nothing
/// recorded); `Z_ERR_NULL` for a null cache, the gravestone, or a null frame with a length.
///
/// # Safety
/// `this_` is null or a loaned cache; `frame` is readable for `len` bytes; `dispatch` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_put(
    this_: *const wz_ext_loaned_replay_publisher_t,
    instance: usize,
    time_ms: u64,
    frame: *const u8,
    len: usize,
    kind: u8,
    dispatch: *mut u8,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if frame.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let kind = match kind {
            WZ_EXT_REPLAY_SEND_PERIODIC => SendKind::Periodic,
            WZ_EXT_REPLAY_SEND_EVENT => SendKind::Event,
            _ => return Z_EINVAL,
        };
        let frame = bytes_arg(frame, len);
        let decided = match locked(&handle.shared.cache).as_mut() {
            Some(cache) => cache.send(instance, time_ms, frame, kind),
            None => return Z_ERR_NULL,
        };
        let decided = match decided {
            Ok(decided) => decided,
            Err(why) => return record_code(why),
        };
        if !dispatch.is_null() {
            *dispatch = dispatch_code(decided);
        }
        match decided {
            Dispatch::Now => handle.shared.put(frame),
            Dispatch::Held { .. } | Dispatch::Deferred { .. } => Z_OK,
        }
    })
}

/// Fill in the default serve options: no segment profile, chunks of 0 bytes.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_serve_options_default(
    this_: *mut wz_ext_replay_serve_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_replay_serve_options_t {
            segment_profile: core::ptr::null(),
            segment_values: core::ptr::null(),
            first_transfer: 0,
            chunk_bytes: 0,
        };
    }
}

/// Serve the cache: declare, on the cache's session, a queryable on `keyexpr` followed by
/// `suffix` (the program's data, NUL-terminated, appended as it is), which answers each query with
/// the rings' frames in ascending (time, instance, sequence) order, then the final. Under
/// `replay-reply-shape = segmented`, `options` names the segment profile each frame is answered as
/// the pieces of; under `frame-per-sample` it is not read and may be null.
///
/// `refusal` may be null; when it is not, it holds the gravestone on success and the reason on
/// `_Z_ERR_CONFIG_INVALID_VALUE`. Returns `Z_ERR_NULL` for a null cache, keyexpr or suffix, the
/// gravestone, or under `segmented` null options, profile or values; `Z_EINVAL` for a suffix or
/// text that is not UTF-8, a cache that serves already, or a chunk size of 0 under `segmented`;
/// `Z_ERR_INVALID` for a suffixed key that is not a key expression; `_Z_ERR_CONFIG_INVALID_VALUE`
/// for a segment profile or values refused; otherwise what `z_declare_queryable` answers.
///
/// # Safety
/// `this_` is null or a loaned cache; `keyexpr` is null or a loaned keyexpr; `suffix` is null or a
/// NUL-terminated C string; `options` is null or valid, its texts null or NUL-terminated;
/// `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_serve(
    this_: *const wz_ext_loaned_replay_publisher_t,
    keyexpr: *const z_loaned_keyexpr_t,
    suffix: *const c_char,
    options: *const wz_ext_replay_serve_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if keyexpr.is_null() || suffix.is_null() {
            return Z_ERR_NULL;
        }
        let (Some(key), Some(suffix)) = (keyexpr_str(keyexpr), utf8_arg(suffix)) else {
            return Z_EINVAL;
        };
        let served = format!("{key}{suffix}");
        if wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(&served).is_err() {
            return Z_ERR_INVALID;
        }
        let mut queryable = locked(&handle.queryable);
        if queryable.is_some() {
            return Z_EINVAL;
        }
        let shared = &handle.shared;
        if shared.shape == ReplayReplyShape::Segmented {
            if options.is_null() {
                return Z_ERR_NULL;
            }
            let options = *options;
            if options.segment_profile.is_null() || options.segment_values.is_null() {
                return Z_ERR_NULL;
            }
            if options.chunk_bytes == 0 {
                return Z_EINVAL;
            }
            let (Some(profile), Some(values)) = (
                utf8_arg(options.segment_profile),
                utf8_arg(options.segment_values),
            ) else {
                return Z_EINVAL;
            };
            match SegmentSender::new(profile, values, options.first_transfer, Rollover::Restart) {
                Ok(sender) => *locked(&shared.segments) = Some(sender),
                Err(why) => {
                    write_refusal(refusal, &why.to_string());
                    return Z_ERR_CONFIG_INVALID_VALUE;
                }
            }
            *locked(&shared.chunk_bytes) = options.chunk_bytes;
        }
        let mut view: z_view_keyexpr_t = core::mem::zeroed();
        let made =
            z_view_keyexpr_from_substr(&mut view, served.as_ptr().cast::<c_char>(), served.len());
        if made != Z_OK {
            return made;
        }
        let mut closure = z_moved_closure_query_t {
            _this: z_owned_closure_query_t {
                context: Arc::into_raw(Arc::clone(shared))
                    .cast_mut()
                    .cast::<c_void>(),
                call: Some(on_query),
                drop: Some(on_query_drop),
            },
        };
        let mut declared: z_owned_queryable_t = core::mem::zeroed();
        // The closure is consumed on every path: a refusal runs its drop, which lets go of the
        // share handed to it above.
        let code = z_declare_queryable(
            &handle.session,
            &mut declared,
            z_view_keyexpr_loan(&view),
            &mut closure,
            core::ptr::null(),
        );
        if code == Z_OK {
            *queryable = Some(declared);
        }
        code
    })
}

/// Where the cache stands: `WZ_EXT_REPLAY_SERVING_IDLE`, `_ANSWERING` or `_RELEASING`, or
/// `WZ_EXT_REPLAY_NO_CACHE` for a null cache or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned cache.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_phase(
    this_: *const wz_ext_loaned_replay_publisher_t,
) -> u8 {
    guard_val(WZ_EXT_REPLAY_NO_CACHE, || {
        let Some(handle) = handle_of(this_) else {
            return WZ_EXT_REPLAY_NO_CACHE;
        };
        match locked(&handle.shared.cache).as_ref() {
            Some(cache) => phase_code(cache.phase()),
            None => WZ_EXT_REPLAY_NO_CACHE,
        }
    })
}

/// What the cache counted, written to `out`. `Z_ERR_NULL` for a null cache, the gravestone or a
/// null `out`.
///
/// # Safety
/// `this_` is null or a loaned cache; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_counts(
    this_: *const wz_ext_loaned_replay_publisher_t,
    out: *mut wz_ext_replay_publisher_counts_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        let counts = match locked(&handle.shared.cache).as_ref() {
            Some(cache) => cache.counts(),
            None => return Z_ERR_NULL,
        };
        *out = wz_ext_replay_publisher_counts_t {
            recorded: counts.recorded,
            deferred_overwritten: counts.deferred_overwritten,
            periodic_replaced: counts.periodic_replaced,
            answers: counts.answers,
        };
        Z_OK
    })
}

/// Borrow a cache. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned cache.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_loan(
    this_: *const wz_ext_owned_replay_publisher_t,
) -> *const wz_ext_loaned_replay_publisher_t {
    this_.cast::<wz_ext_loaned_replay_publisher_t>()
}

/// The moved form of a cache, for `wz_ext_replay_publisher_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned cache.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_move(
    this_: *mut wz_ext_owned_replay_publisher_t,
) -> *mut wz_ext_moved_replay_publisher_t {
    this_.cast::<wz_ext_moved_replay_publisher_t>()
}

/// Stop serving, release the cache and leave the gravestone: the queryable is undeclared, and the
/// storage is the program's again once this returns (a query still being answered reads nothing
/// of it after). A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved cache.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_publisher_drop(this_: *mut wz_ext_moved_replay_publisher_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let raw = core::mem::replace(&mut (*this_)._this.handle, core::ptr::null_mut());
        if raw.is_null() {
            return Z_OK;
        }
        let handle = Box::from_raw(raw.cast::<Handle>());
        if let Some(mut queryable) = locked(&handle.queryable).take() {
            z_undeclare_queryable(z_queryable_move(&mut queryable));
        }
        // An answer still in progress holds its own share of the state: it finds no cache from
        // here, and the program's storage is no longer referenced.
        *locked(&handle.shared.cache) = None;
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_replay_publisher_null(
    this_: *mut wz_ext_owned_replay_publisher_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_replay_publisher_t::null_value();
    }
}

/// Whether the slot holds a cache.
///
/// # Safety
/// `this_` is null or an owned cache.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_replay_publisher_check(
    this_: *const wz_ext_owned_replay_publisher_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dispatch_has_a_code_of_its_own() {
        let codes = [
            dispatch_code(Dispatch::Now),
            dispatch_code(Dispatch::Held { replaced: false }),
            dispatch_code(Dispatch::Held { replaced: true }),
            dispatch_code(Dispatch::Deferred { overwrote: false }),
            dispatch_code(Dispatch::Deferred { overwrote: true }),
        ];
        assert_eq!(
            codes,
            [
                WZ_EXT_REPLAY_SENT,
                WZ_EXT_REPLAY_HELD,
                WZ_EXT_REPLAY_HELD_REPLACED,
                WZ_EXT_REPLAY_DEFERRED,
                WZ_EXT_REPLAY_DEFERRED_OVERWROTE
            ]
        );
    }

    #[test]
    fn the_storage_size_is_the_model_s_and_zero_for_a_shape_refused() {
        let shape = wz_ext_replay_shape_t {
            frame_max: 12,
            depth: 3,
            instances: 2,
        };
        // SAFETY: a local shape, and a null one.
        unsafe {
            assert_eq!(
                wz_ext_replay_publisher_storage_size(&shape),
                shape_of(&shape).storage_bytes().unwrap()
            );
            assert_eq!(wz_ext_replay_publisher_storage_size(core::ptr::null()), 0);
            let none = wz_ext_replay_shape_t { depth: 0, ..shape };
            assert_eq!(wz_ext_replay_publisher_storage_size(&none), 0);
        }
    }

    #[test]
    fn a_cache_with_no_session_is_refused_and_leaves_the_gravestone() {
        let shape = wz_ext_replay_shape_t {
            frame_max: 4,
            depth: 1,
            instances: 1,
        };
        let mut storage = [0u8; 64];
        let mut stale = 0u8;
        // SAFETY: every pointer is null or a local the call may write; no session is named.
        unsafe {
            let mut this = wz_ext_owned_replay_publisher_t {
                handle: core::ptr::addr_of_mut!(stale).cast::<c_void>(),
            };
            assert_eq!(
                wz_ext_replay_publisher_new(
                    &mut this,
                    core::ptr::null(),
                    core::ptr::null(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &shape,
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL
            );
            assert!(!wz_ext_internal_replay_publisher_check(&this));
            assert_eq!(
                wz_ext_replay_publisher_phase(wz_ext_replay_publisher_loan(&this)),
                WZ_EXT_REPLAY_NO_CACHE
            );
            assert_eq!(
                wz_ext_replay_publisher_record(
                    wz_ext_replay_publisher_loan(&this),
                    0,
                    0,
                    b"x".as_ptr(),
                    1
                ),
                Z_ERR_NULL
            );
            wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&mut this));
            wz_ext_replay_publisher_drop(core::ptr::null_mut());
        }
    }
}
