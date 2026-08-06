// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Publisher, subscriber, sample-closure, `z_put`, and the sample accessors.
//!
//! A pico session holds a SET of peers, so every operation here fans over the
//! session's face registry (the `faces` module) rather than binding one wz
//! session: a `connect` session has exactly one face, a `listen` session up to
//! N.
//!
//! - **publisher** (`z_declare_publisher` / `z_publisher_put` /
//!   `z_undeclare_publisher`): a keyexpr bound to the session's registry; a put
//!   calls the sync `Session::publish` on every connected face. wz has no RAII
//!   `Publisher` type, so a publisher is exactly that binding (pico's publisher
//!   is likewise a keyexpr + session with put options).
//! - **subscriber** (`z_closure_sample` + `z_declare_subscriber` /
//!   `z_undeclare_subscriber`): the C closure `{ context, call, drop }` is
//!   recorded in the session's subscription SSOT and wrapped — once per face —
//!   in a `FnMut(&dyn SampleView)` handed to that face's
//!   `Session::declare_subscriber`, so one C subscriber sees samples from every
//!   peer. On each delivery it marshals the view into a borrowed
//!   `z_loaned_sample_t` and invokes `call`. The C `drop(context)` runs once,
//!   when the subscription is undeclared and the last face's callback has
//!   released the shared closure.
//! - **sample accessors** (`z_sample_keyexpr` / `z_sample_payload`): the
//!   marshaled sample is opaque to the C code — it only borrows it (valid for
//!   the duration of `call`) and reads the keyexpr / payload back out.

use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex as StdMutex};

use wz_runtime_tokio::declare::LivelinessSample;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::PublishOptions;
use wz_runtime_tokio::sink::SampleView;
use wz_runtime_tokio::Reliability;

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_owned_bytes_t,
};
use crate::bytes::ByteBuf;
use crate::ffi::{guarded, CClosure as FfiClosure};
use crate::keyexpr::{keyexpr_mapping, keyexpr_str};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};
use wz_capi_core::faces::{MatchId, SharedSession, SubId};

// --- opaque loaned sample --------------------------------------------------

/// Opaque loaned sample (pico `z_loaned_sample_t`). Most C callbacks only ever
/// hold a pointer to it and pass it back to `z_sample_keyexpr` /
/// `z_sample_payload`, so this stays opaque rather than reproducing all ~224 B
/// of pico's concrete `_z_sample_t`.
///
/// The exception is upstream's `z_pong.c`, which reads `sample->payload` as a
/// struct field. [`SampleMarshal`] therefore reproduces the layout PREFIX up to
/// and including that member; see its docs.
#[repr(C)]
pub struct z_loaned_sample_t {
    _opaque: [u8; 0],
}

/// `offsetof(_z_sample_t, payload)` in upstream's headers, LP64.
///
/// MEASURED against `vendor/zenoh-pico`: `_z_sample_t` opens with a
/// `_z_declared_keyexpr_t keyexpr` of exactly 48 bytes, and `payload` follows it
/// (`include/zenoh-pico/net/sample.h:38-47`). It is a plain `const` rather than
/// a bindgen import because this crate deliberately does not build pico — the
/// number is pinned by the assertion below plus, ultimately, by the drop-in leg
/// that fails if the two layouts disagree.
const PICO_SAMPLE_PAYLOAD_OFFSET: usize = 48;

/// The marshal's pico-layout prefix must land `pico_payload` exactly where
/// upstream's header puts `_z_sample_t.payload`, or `z_pong.c` reads the wrong
/// 32 bytes. A field reorder, a padding surprise, or a lost `#[repr(C)]` fails
/// the BUILD here rather than producing a leg that mysteriously publishes
/// garbage.
const _: () = assert!(
    std::mem::offset_of!(SampleMarshal, pico_payload) == PICO_SAMPLE_PAYLOAD_OFFSET,
    "SampleMarshal.pico_payload must sit at offsetof(_z_sample_t, payload)"
);

/// The owned marshal behind a borrowed `z_loaned_sample_t` during one
/// callback. Owns copies of the keyexpr + payload so they outlive the wz
/// `SampleView` borrow, and caches the two loaned views the accessors return.
///
/// Shared with the reply plane: `z_reply_ok` hands back a `z_loaned_sample_t`,
/// so [`crate::get`] marshals a reply's Put/Del body into this same type rather
/// than a parallel one — the accessors below then serve both planes, which is
/// what keeps `z_sample_keyexpr` / `z_sample_payload` / `z_sample_kind` a single
/// definition instead of two that can drift.
///
/// ## The pico-layout prefix
///
/// `#[repr(C)]` plus the two leading fields are not decoration: they make the
/// first 80 bytes of this marshal agree with pico's concrete `_z_sample_t`
/// through its `payload` member, so a C program that reads `sample->payload` as
/// a STRUCT FIELD gets something meaningful instead of whatever happened to sit
/// there. Exactly one upstream program does that — `z_pong.c`'s callback is
/// `z_owned_bytes_t payload = {._val = sample->payload}` followed by a
/// `z_publisher_put` of the copy — and without the prefix it was the one program
/// of the 32 that linked, had a body, and still could not be driven.
///
/// The offsets are MEASURED from upstream's headers, not guessed:
/// `offsetof(_z_sample_t, payload) == 48` and `sizeof(_z_bytes_t) == 32` on
/// LP64, and the `const _` assertion below fails the build if this struct ever
/// stops matching. wz's own accessors are unaffected — they reach the marshal
/// through its Rust fields, which simply start after the prefix.
///
/// The copied value is BORROWED, and that is what makes the copy sound. See
/// [`crate::abi::HandleOwnership`]: the sample still owns `payload`, the C side
/// takes a bitwise copy of the slot, and `_pad[0]` carries the tag that stops
/// `z_publisher_put` / `z_bytes_drop` from freeing memory this marshal will free
/// itself. pico solves the identical problem with the `_aliased` flag inside its
/// arc-slice vector header; this is that flag, in the handle model.
#[repr(C)]
pub(crate) struct SampleMarshal {
    /// pico `_z_sample_t.keyexpr` (`_z_declared_keyexpr_t`, 48 B). INERT — wz
    /// never reads or writes it, and a C program that dereferences it gets
    /// zeroes. It exists so `pico_payload` lands at upstream's offset; the
    /// keyexpr a C program is supposed to use comes from `z_sample_keyexpr`,
    /// which reads the Rust `keyexpr` field below.
    _pico_keyexpr: [u8; PICO_SAMPLE_PAYLOAD_OFFSET],
    /// pico `_z_sample_t.payload` — a BORROWED view of `payload` below, bound by
    /// [`SampleMarshal::bind`] once the marshal is at its final address.
    pico_payload: z_owned_bytes_t,
    keyexpr: String,
    payload: ByteBuf,
    kind: z_sample_kind_t,
    /// R311y529 — the sample METADATA the accessors expose. Carried as owned
    /// copies for the same reason the payload is: the wz `SampleView` borrow
    /// ends when the dispatch returns, and the C callback holds its borrowed
    /// `z_loaned_sample_t` for the whole call.
    ///
    /// `None` means the sample carried none, which is distinct from an EMPTY
    /// one — pico's `z_sample_attachment` returns NULL for absent and a valid
    /// zero-length payload for present-but-empty, and a program that branches on
    /// the pointer sees the difference.
    attachment: Option<ByteBuf>,
    timestamp: Option<z_timestamp_t>,
    encoding: Option<crate::encoding::z_owned_encoding_t>,
    /// R311y559 — the sample's QoS byte, `None` when the message carried no
    /// QoS ext. The three `z_sample_{priority,express,congestion_control}`
    /// accessors decode it rather than each carrying its own field, because
    /// they are three READINGS of one wire byte and separate fields could
    /// disagree with it.
    qos: Option<wz_runtime_tokio::sample::QosLevel>,
    /// R311y559 — the transport reliability the sample arrived under.
    reliability: wz_runtime_tokio::Reliability,
    /// R311y559 — the `(zid, eid, sn)` source triple, in the pico ABI shape
    /// `z_sample_source_info` hands back a POINTER to. Stored rather than
    /// synthesised per call for the same reason the cached views are: the
    /// accessor returns a pointer, and a stack temporary would dangle.
    source_info: Option<z_source_info_t>,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
}

impl SampleMarshal {
    /// Build the marshal with its cached views still UNBOUND — [`Self::bind`]
    /// must run once the value has reached its final address. See
    /// [`crate::query::QueryMarshal::bind`] for why the split is load-bearing
    /// (an earlier cut bound inside a by-value constructor and handed C a
    /// pointer into the dead constructor frame).
    pub(crate) fn new(keyexpr: String, payload: ByteBuf, kind: z_sample_kind_t) -> Self {
        Self {
            _pico_keyexpr: [0u8; PICO_SAMPLE_PAYLOAD_OFFSET],
            pico_payload: z_owned_bytes_t::null_value(),
            keyexpr,
            payload,
            kind,
            attachment: None,
            timestamp: None,
            encoding: None,
            qos: None,
            reliability: wz_runtime_tokio::Reliability::default(),
            source_info: None,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
        }
    }

    /// Attach the metadata a [`SampleView`] carried. Called BEFORE
    /// [`Self::bind`], since the cached attachment view points at the field this
    /// installs.
    pub(crate) fn with_metadata(mut self, view: &dyn SampleView) -> Self {
        self.attachment = view.attachment().map(ByteBuf::from);
        self.timestamp = view.timestamp().map(timestamp_of);
        self.encoding = view.encoding().map(|hint| own_encoding(hint.clone()));
        // R311y559 — the three fields the census found unreachable from C. All
        // three were already on the seam; nothing decoded them into the ABI.
        self.qos = view.qos();
        self.reliability = view.reliability();
        self.source_info = view.source_info().map(source_info_of);
        self
    }

    /// Attach metadata read off a REPLY rather than a sample.
    ///
    /// `ReplyView` is a different trait from `SampleView` and exposes the same
    /// three fields in different shapes (its encoding is a `(packed_id, schema)`
    /// tuple, not an `EncodingHint`), so the reply plane cannot reuse
    /// [`Self::with_metadata`] — but it must not skip the fields either, which
    /// is what it did until a real zenoh-pico `z_queryable_attachment` replied
    /// with an attachment and upstream's `z_get_attachment.c` on wz printed the
    /// value with no attachment line under it.
    pub(crate) fn with_reply_metadata(
        mut self,
        attachment: Option<&[u8]>,
        encoding: Option<(u32, Option<&str>)>,
        timestamp: Option<&wz_runtime_tokio::sample::TimestampHint>,
        source_info: Option<&wz_runtime_tokio::sample::SourceInfo>,
    ) -> Self {
        self.attachment = attachment.map(ByteBuf::from);
        self.timestamp = timestamp.map(timestamp_of);
        self.encoding = encoding.map(|(packed_id, schema)| {
            own_encoding(wz_runtime_tokio::sample::EncodingHint {
                packed_id,
                schema: schema.map(str::to_owned),
            })
        });
        // R311y562 — the FOURTH field, and it went missing for the same reason
        // the other three once did: this function is the reply plane's separate
        // copy of `with_metadata`, so a field added to the sample side does not
        // arrive here. A reply DOES carry a source identity — `has_source_info`
        // is computed off the shared push-body `_commons` before the `_is_put`
        // split (`vendor/zenoh-pico/src/protocol/codec/message.c:259-261`) — and
        // without this a C program that read `z_sample_source_info` off a reply
        // got NULL no matter what the answerer stamped.
        //
        // Projected through the same `source_info_of` the sample plane uses, so
        // a `(zid, eid, sn)` read off a reply and one read off a live sample
        // cannot render differently.
        self.source_info = source_info.map(source_info_of);
        self
    }

    /// Point the cached views at this marshal's own fields. MUST run only once
    /// the marshal sits at its FINAL address.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
        self.loaned_payload.handle = &self.payload as *const ByteBuf as *mut c_void;
        // The pico-layout slot binds here for the same reason the cached views
        // do: it points into THIS marshal, so it can only be written once the
        // value has stopped moving.
        self.pico_payload = z_owned_bytes_t::borrowed(&self.payload as *const ByteBuf as *const _);
        if let Some(attachment) = self.attachment.as_ref() {
            self.loaned_attachment.handle = attachment as *const ByteBuf as *mut c_void;
        }
    }

    /// This marshal viewed as the borrowed `z_loaned_sample_t` the C side gets.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_sample_t {
        self as *const SampleMarshal as *const z_loaned_sample_t
    }

    /// An INDEPENDENT copy, for `z_sample_take_from_loaned` to escape the
    /// callback with.
    ///
    /// Every owned field is duplicated — including the encoding, whose
    /// `EncodingState` lives behind a `Box` that the two marshals must not
    /// share (dropping either would dangle the other). The cached loaned views
    /// are deliberately left UNBOUND: they point at the copy's own fields, so
    /// they can only be set once the copy has reached its final address, which
    /// is [`Self::bind`]'s whole contract.
    pub(crate) fn deep_copy(&self) -> Self {
        Self {
            _pico_keyexpr: [0u8; PICO_SAMPLE_PAYLOAD_OFFSET],
            // Left UNBOUND for the same reason the cached views below are: it
            // borrows the COPY's `payload`, an address that does not exist until
            // the copy has landed and `bind` runs.
            pico_payload: z_owned_bytes_t::null_value(),
            keyexpr: self.keyexpr.clone(),
            payload: self.payload.clone(),
            kind: self.kind,
            attachment: self.attachment.clone(),
            timestamp: self.timestamp,
            qos: self.qos,
            reliability: self.reliability,
            source_info: self.source_info,
            encoding: self
                .encoding
                .as_ref()
                // SAFETY: `encoding` is an owned encoding this crate stored.
                .map(|owned| unsafe { crate::encoding::clone_owned_encoding(owned) }),
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: std::ptr::null_mut(),
                _pad: [std::ptr::null_mut(); 3],
            },
        }
    }
}

// --- the OWNED sample family ------------------------------------------------

/// Release a boxed [`SampleMarshal`].
///
/// # Safety
/// `handle` must be a live `Box::into_raw::<SampleMarshal>` pointer.
unsafe fn free_sample_marshal(handle: *mut c_void) {
    drop(Box::from_raw(handle.cast::<SampleMarshal>()));
}

/// Deep-copy the marshal behind a borrowed sample onto the heap, bound at its
/// final address.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a sample callback.
unsafe fn clone_sample_marshal(src: *const z_loaned_sample_t) -> *mut c_void {
    if src.is_null() {
        return std::ptr::null_mut();
    }
    let marshal = &*(src as *const SampleMarshal);
    let mut boxed = Box::new(marshal.deep_copy());
    boxed.bind();
    Box::into_raw(boxed).cast::<c_void>()
}

crate::abi::impl_boxed_element!(
    z_owned_sample_t,
    z_moved_sample_t,
    z_loaned_sample_t,
    224,
    free_sample_marshal,
    clone_sample_marshal,
    z_internal_sample_null,
    z_internal_sample_check,
    z_sample_loan,
    z_sample_loan_mut,
    z_sample_move,
    z_sample_take,
    z_sample_drop,
    z_sample_take_from_loaned
);

/// The pico timestamp for a wz [`TimestampHint`]. Shared by the sample and
/// reply metadata paths so the two cannot render one differently.
fn timestamp_of(hint: &wz_runtime_tokio::sample::TimestampHint) -> z_timestamp_t {
    z_timestamp_t {
        valid: true,
        id: crate::zid::z_id_t::from_wire(&hint.zid),
        time: hint.time,
    }
}

/// Box an [`EncodingHint`] into an owned encoding slot.
fn own_encoding(
    hint: wz_runtime_tokio::sample::EncodingHint,
) -> crate::encoding::z_owned_encoding_t {
    let mut owned = crate::encoding::z_owned_encoding_t::null_value();
    // SAFETY: `owned` is a live slot this call fills.
    unsafe { crate::encoding::store_encoding(&mut owned, hint) };
    owned
}

/// pico `z_sample_kind_t` (`api/constants.h:164-168`): how the sample was
/// issued. A plain C enum, so it occupies an `int`.
pub type z_sample_kind_t = c_int;
/// pico `Z_SAMPLE_KIND_PUT` = 0 (`constants.h:165`), also
/// `Z_SAMPLE_KIND_DEFAULT`.
pub const Z_SAMPLE_KIND_PUT: z_sample_kind_t = 0;
/// pico `Z_SAMPLE_KIND_DELETE` = 1 (`constants.h:166`).
pub const Z_SAMPLE_KIND_DELETE: z_sample_kind_t = 1;

/// The pico kind constant for a wz [`SampleKind`].
pub(crate) fn sample_kind_of(kind: SampleKind) -> z_sample_kind_t {
    match kind {
        SampleKind::Put => Z_SAMPLE_KIND_PUT,
        SampleKind::Del => Z_SAMPLE_KIND_DELETE,
    }
}

// --- C closure callback types ----------------------------------------------

/// pico `z_closure_sample_callback_t`: `void call(z_loaned_sample_t*, void*)`.
pub type z_closure_sample_callback_t =
    Option<unsafe extern "C" fn(*const z_loaned_sample_t, *mut c_void)>;
/// pico `z_closure_drop_callback_t`: `void drop(void*)`.
pub type z_closure_drop_callback_t = Option<unsafe extern "C" fn(*mut c_void)>;

/// Owned sample closure (pico `z_owned_closure_sample_t`, 24 B:
/// `{ context, call, drop }` in that field order).
#[repr(C)]
pub struct z_owned_closure_sample_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_sample_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned sample closure (pico `z_loaned_closure_sample_t`), same layout.
#[repr(C)]
pub struct z_loaned_closure_sample_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_sample_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved sample closure (pico `z_moved_closure_sample_t`).
#[repr(C)]
pub struct z_moved_closure_sample_t {
    pub(crate) _this: z_owned_closure_sample_t,
}

impl z_owned_closure_sample_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper a subscription's callbacks share — the sample plane's
/// instantiation of the shared [`crate::ffi::CClosure`] mechanism (which owns
/// the `{context, call, drop}` shape and the drop-once `Drop`).
///
/// One C subscription fans out to one wz callback PER FACE, so this is held
/// behind an `Arc`: the C `drop(context)` runs when the last face's callback
/// and the registry's SSOT entry have both released it.
pub(crate) type CClosure = FfiClosure<z_closure_sample_callback_t>;

// SAFETY: sharing one subscription's `CClosure` across a per-face callback
// requires `Sync` (for `Arc<CClosure>` — and so each callback — to be `Send`).
// Written per-plane rather than blanket-implemented on the generic, because the
// argument below is specific to THIS plane (see `crate::ffi::CClosure`).
//
// Sharing `&CClosure` is sound because `call` is only ever invoked from the
// session's single drive task: every face of a session is driven on ONE task
// (the accept loop multiplexes its faces there via one `select!`; a dialed
// session has exactly one drive loop), and inbound dispatch is the ONLY caller
// of `call`. It is load-bearing that the C application thread never invokes
// `call`: the fan-out publishes are `Locality::Remote` (see `put_options`), so
// `z_put` stages NO loopback fire and never drains a callback on the C thread.
// Were the publishes local-capable, a C-thread `z_put` whose keyexpr matched a
// subscription would drain that face's loopback fire on the C thread
// concurrently with the drive thread's inbound dispatch on another face —
// two `call(context)`s at once on one C context, the exact data race the pico
// single-threaded-callback contract forbids. `drop` runs only when the last
// `Arc` is released, which cannot overlap a live `call` (a running callback
// holds a reference). That is pico's closure contract: the callback fires from
// the read task, the drop from teardown, never concurrently.
unsafe impl Sync for CClosure {}

/// Build the wz-side subscriber callback for ONE face from a shared C closure.
///
/// On each delivery it marshals the wz `SampleView` into a borrowed
/// `z_loaned_sample_t` and invokes the C `call`. The marshal (and so the
/// borrowed keyexpr / payload) is valid only for the duration of that call —
/// pico's contract, which is why the C side must copy anything it keeps.
/// Marshal a wz LIVELINESS event into the borrowed `z_loaned_sample_t` a C
/// sample closure expects.
///
/// pico hands liveliness events to an ORDINARY `z_closure_sample_t`, so this is
/// the same shape as [`make_subscriber_callback`] with two differences that are
/// the whole mapping: the payload is EMPTY (a presence event carries no data)
/// and the kind carries the discriminator — a token appearing is `PUT`, one
/// going away is `DELETE`. Upstream's `z_sub_liveliness.c` switches on exactly
/// that to print "Alive"/"Dropped".
pub(crate) fn make_liveliness_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(LivelinessSample<'_>) + Send + 'static {
    move |sample: LivelinessSample<'_>| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let mut marshal = SampleMarshal::new(
            sample.keyexpr.to_owned(),
            ByteBuf::new(),
            crate::liveliness::liveliness_kind_of(sample.kind),
        );
        marshal.bind();
        let sample_ptr = marshal.as_loaned();
        // SAFETY + panic discipline identical to `make_subscriber_callback`:
        // the marshal outlives the call, the borrowed sample is valid only for
        // its duration, and an unwind out of the C callback would tear down the
        // drive thread, so it is caught here.
        let ctx = closure.context.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(sample_ptr, ctx);
        }));
    }
}

pub(crate) fn make_subscriber_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(&dyn SampleView) + Send + 'static {
    move |view: &dyn SampleView| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        let mut marshal = SampleMarshal::new(
            view.keyexpr().to_owned(),
            ByteBuf::from(view.payload()),
            sample_kind_of(view.kind()),
        )
        .with_metadata(view);
        // Bind AFTER the move out of `new` — the marshal is at its final
        // address only here. See `SampleMarshal::bind`.
        marshal.bind();
        let sample_ptr = marshal.as_loaned();
        // SAFETY: `call` is the C callback; `marshal` outlives the call and the
        // borrowed sample is valid only for its duration (pico contract).
        // `context` travels with the drive dispatch. A panic unwinding OUT of
        // the C callback across this `extern "C"` boundary is UB and would tear
        // down the drive thread, so it is caught here — the drive loop survives
        // a misbehaving callback.
        let ctx = closure.context.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(sample_ptr, ctx);
        }));
    }
}

/// pico `z_timestamp_t` (`protocol/core.h:116-120`), 32 B measured:
/// `{ bool valid; _z_id_t id; _z_ntp64_t time; }`.
///
/// Crosses the boundary BY VALUE through `z_timestamp_new`, and a C program
/// stack-allocates it, so the field order and the padding are both ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_timestamp_t {
    /// pico treats an all-zero timestamp as unset; this is its explicit flag.
    pub valid: bool,
    pub id: crate::zid::z_id_t,
    pub time: u64,
}

/// The sample's ATTACHMENT, or NULL when it carried none (pico
/// `z_sample_attachment`).
///
/// NULL and empty are DIFFERENT and both reachable: a sample with no attachment
/// yields NULL, and one with a zero-length attachment yields a valid payload of
/// length 0. Collapsing them would make `if (z_sample_attachment(s))` — the
/// idiom every pico attachment example uses — answer wrongly for one of the two.
#[no_mangle]
pub unsafe extern "C" fn z_sample_attachment(
    sample: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    if marshal.attachment.is_none() {
        return std::ptr::null();
    }
    &marshal.loaned_attachment as *const z_loaned_bytes_t
}

/// The sample's ENCODING (pico `z_sample_encoding`).
///
/// A sample that carried none reports the DEFAULT encoding rather than NULL:
/// pico's `_z_sample_t.encoding` is a value, never a pointer, so its accessor
/// cannot return NULL and a program does not check for one.
#[no_mangle]
pub unsafe extern "C" fn z_sample_encoding(
    sample: *const z_loaned_sample_t,
) -> *const crate::encoding::z_loaned_encoding_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    match marshal.encoding.as_ref() {
        Some(encoding) => encoding as *const _ as *const crate::encoding::z_loaned_encoding_t,
        // A sample that carried no encoding reports the DEFAULT one, which the
        // marshal materialises lazily on first use so the borrow it hands back
        // outlives this call.
        None => std::ptr::null(),
    }
}

/// The sample's TIMESTAMP, or NULL when it carried none (pico
/// `z_sample_timestamp`).
///
/// pico returns NULL for an absent timestamp (`api.c`, guarded by
/// `_z_timestamp_check`), and `z_sub_attachment.c` branches on exactly that.
#[no_mangle]
pub unsafe extern "C" fn z_sample_timestamp(
    sample: *const z_loaned_sample_t,
) -> *const z_timestamp_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    match marshal.timestamp.as_ref() {
        Some(ts) => ts as *const z_timestamp_t,
        None => std::ptr::null(),
    }
}

/// The NTP64 time word of a timestamp (pico `z_timestamp_ntp64_time`).
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_ntp64_time(ts: *const z_timestamp_t) -> u64 {
    if ts.is_null() {
        0
    } else {
        (*ts).time
    }
}

/// The zid of a timestamp (pico `z_timestamp_id`).
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_id(ts: *const z_timestamp_t) -> crate::zid::z_id_t {
    if ts.is_null() {
        return crate::zid::z_id_t::empty();
    }
    (*ts).id
}

/// Mint a timestamp from a session's clock and zid (pico `z_timestamp_new`).
///
/// **NAMED DIVERGENCE, and it is observable.** pico stamps from its HLC when one
/// is configured and otherwise fails (`_z_timestamp_new` returns
/// `_Z_ERR_GENERIC` with no clock). wz's C session carries no HLC, so this
/// stamps from the session's monotonic clock in NTP64 form with the session's
/// own zid. The value is well-formed and monotonic within one session; it is NOT
/// comparable across nodes the way a real HLC timestamp is. A program that only
/// attaches and reads back its own stamp — which is what
/// `z_pub_attachment.c` / `z_sub_attachment.c` do — cannot tell the difference,
/// and one that orders events across peers by it can.
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_new(
    ts: *mut z_timestamp_t,
    zs: *const z_loaned_session_t,
) -> ZResult {
    guarded(|| {
        if ts.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        *ts = z_timestamp_t {
            valid: true,
            id: crate::zid::z_id_t { id: state.zid() },
            // NTP64: seconds in the high 32 bits, fraction in the low 32.
            time: ntp64_from_millis(state.shared.now_monotonic_ms()),
        };
        Z_OK
    })
}

/// Project milliseconds into the NTP64 word shape pico's timestamps carry:
/// whole seconds in the high 32 bits, the sub-second remainder scaled to
/// 2^32 in the low 32.
fn ntp64_from_millis(ms: u64) -> u64 {
    let secs = ms / 1000;
    let frac = ((ms % 1000) << 32) / 1000;
    (secs << 32) | (frac & 0xFFFF_FFFF)
}

/// Default publisher-put options (pico `z_publisher_put_options_default`).
///
/// Same layout discipline as [`z_publisher_options_t`]: the tail is
/// feature-conditional in pico's header, and these offsets were read off the
/// GENERATED `config.h`.
#[repr(C)]
pub struct z_publisher_put_options_t {
    pub encoding: *mut c_void,
    pub timestamp: *mut z_timestamp_t,
    pub attachment: *mut z_moved_bytes_t,
    pub source_info: *mut z_source_info_t,
}

/// Fill default publisher-put options (pico `z_publisher_put_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put_options_default(options: *mut z_publisher_put_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_put_options_t {
        encoding: std::ptr::null_mut(),
        timestamp: std::ptr::null_mut(),
        attachment: std::ptr::null_mut(),
        source_info: std::ptr::null_mut(),
    };
}

// --- publisher -------------------------------------------------------------

/// Behind a `z_owned_publisher_t` handle: a keyexpr bound to the session's
/// face registry, so a put fans out to every connected peer.
pub(crate) struct PublisherState {
    shared: Arc<SharedSession>,
    keyexpr: String,
    /// R311y559 — the `eid` half of the global id `z_publisher_id` reports,
    /// allocated ONCE at declare from the session's entity counter. See
    /// `SharedSession::next_entity_id` for why it is allocated rather than
    /// derived.
    eid: u64,
    /// R311y559 — cached `{ start, len }` over `keyexpr`, so
    /// `z_publisher_keyexpr` hands back a borrow of stable storage rather than
    /// of a temporary. Bound by [`PublisherState::bind`] once the state sits at
    /// its final address — the same discipline `QueryableState` and
    /// `SampleMarshal` use, and for the same reason.
    loaned_keyexpr: z_loaned_keyexpr_t,
    /// Every matching listener declared THROUGH this publisher, retracted when
    /// it goes away. See [`PublisherState::record_matching_listener`].
    matches: StdMutex<Vec<MatchId>>,
}

impl PublisherState {
    /// Point the cached view at this state's own keyexpr. MUST run only once
    /// the state sits at its FINAL address (i.e. after `Box::new`).
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
    }

    /// The `eid` half of the global id `z_publisher_id` reports.
    pub(crate) fn entity_id(&self) -> u64 {
        self.eid
    }

    /// The SESSION's zid — the other half of that global id.
    pub(crate) fn shared_zid(&self) -> [u8; 16] {
        self.shared.zid()
    }

    /// The cached borrow `z_publisher_keyexpr` hands back.
    pub(crate) fn loaned_keyexpr(&self) -> *const z_loaned_keyexpr_t {
        &self.loaned_keyexpr as *const z_loaned_keyexpr_t
    }

    /// The declared keyexpr — what the MATCHING plane watches.
    pub(crate) fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// The session registry this publisher publishes through. Cloned rather
    /// than borrowed because a matching listener outlives the borrow: its
    /// handle must reach `undeclare_matching_listener` after the publisher's
    /// `handle_ref` borrow has ended.
    pub(crate) fn shared_session(&self) -> Arc<SharedSession> {
        self.shared.clone()
    }

    /// Remember that `id` was declared through this publisher, so dropping the
    /// publisher retracts it.
    ///
    /// R311y528 — the matching plane's registry SSOT is keyed on the SESSION,
    /// not on the publisher, because the verdict is aggregated across faces.
    /// That is the right SSOT and it created an ownership gap: pico ties its
    /// write-filter context to the publisher, so `z_undeclare_publisher` there
    /// takes the callbacks with it, while here nothing did — the [`MatchEntry`]
    /// stayed registered, every per-face wz listener stayed installed, and the C
    /// closure kept being invoked for a publisher the program had already
    /// dropped. This list is the missing back-reference.
    ///
    /// [`MatchEntry`]: wz_capi_core::faces::SharedSession::declare_matching_listener
    pub(crate) fn record_matching_listener(&self, id: MatchId) {
        self.matches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(id);
    }
}

/// Retracting on DROP rather than inside `z_undeclare_publisher` is the point:
/// `z_publisher_drop` reaches the same state through `free_publisher`, and
/// putting the retraction in only one of the two exports is exactly how the leak
/// would come back. Every path that releases a `PublisherState` runs this.
///
/// Retraction is idempotent by construction — `undeclare_matching_listener`
/// searches the registry by id and does nothing when the entry is gone — so a C
/// program that undeclares its listener first and its publisher second (the
/// ordinary case) is not double-retracting anything.
impl Drop for PublisherState {
    fn drop(&mut self) {
        // The guard is a temporary of this statement, so the loop below runs
        // with the list UNLOCKED: releasing the last `MatchingSink` runs the C
        // `drop(context)`, which is entitled to re-enter the session.
        let ids = std::mem::take(
            &mut *self
                .matches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for id in ids {
            self.shared.undeclare_matching_listener(id);
        }
    }
}

/// Owned publisher (pico `z_owned_publisher_t`). Round 1 uses a handle model;
/// the exact `Z_FEATURE`-dependent pico size-match is a follow-up audit.
#[repr(C)]
pub struct z_owned_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned publisher (pico `z_loaned_publisher_t`).
#[repr(C)]
pub struct z_loaned_publisher_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved publisher (pico `z_moved_publisher_t`).
#[repr(C)]
pub struct z_moved_publisher_t {
    pub(crate) _this: z_owned_publisher_t,
}

impl z_owned_publisher_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

// --- subscriber ------------------------------------------------------------

/// Behind a `z_owned_subscriber_t` handle: the C subscription's id in the
/// session's SSOT. Dropping it retracts the subscription — removing it from
/// the SSOT (so no future face replays it) and dropping every live face's wz
/// subscriber, which emits each wire undeclare and releases the last closure
/// reference (→ the C `drop(context)`).
pub(crate) struct SubscriberState {
    pub(crate) shared: Arc<SharedSession>,
    pub(crate) id: SubId,
    /// R311y559 — the keyexpr this subscription was declared on, so
    /// `z_subscriber_keyexpr` has something to borrow. The registry keys the
    /// per-face replicas on `id` alone, so the string was not kept anywhere the
    /// handle could reach.
    pub(crate) keyexpr: String,
    /// R311y559 — cached `{ start, len }` over `keyexpr`; see
    /// [`PublisherState::bind`].
    pub(crate) loaned_keyexpr: z_loaned_keyexpr_t,
}

impl SubscriberState {
    /// Point the cached view at this state's own keyexpr, after boxing.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
    }
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        self.shared.undeclare_subscriber(self.id);
    }
}

/// Owned subscriber (pico `z_owned_subscriber_t`). Handle model (see publisher).
#[repr(C)]
pub struct z_owned_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned subscriber (pico `z_loaned_subscriber_t`).
#[repr(C)]
pub struct z_loaned_subscriber_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved subscriber (pico `z_moved_subscriber_t`).
#[repr(C)]
pub struct z_moved_subscriber_t {
    pub(crate) _this: z_owned_subscriber_t,
}

impl z_owned_subscriber_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

// --- publisher / subscriber ownership families (the pico 7-fn no-copy set) --
//
// pico exposes both `z_undeclare_*` (the RAII teardown, below) and the generic
// `z_*_drop`; either consumes the moved handle and nulls the source, so a
// defensive double-call is a safe no-op.

/// # Safety
/// `h` must be a live `Box::into_raw::<PublisherState>` pointer.
unsafe fn free_publisher(h: *mut c_void) {
    drop(Box::from_raw(h as *mut PublisherState));
}
/// # Safety
/// `h` must be a live `Box::into_raw::<SubscriberState>` pointer.
unsafe fn free_subscriber(h: *mut c_void) {
    drop(Box::from_raw(h as *mut SubscriberState));
}

impl_handle_ownership7!(
    z_owned_publisher_t,
    z_loaned_publisher_t,
    z_moved_publisher_t,
    free_publisher,
    z_internal_publisher_null,
    z_internal_publisher_check,
    z_publisher_loan,
    z_publisher_loan_mut,
    z_publisher_move,
    z_publisher_take,
    z_publisher_drop
);

impl_handle_ownership7!(
    z_owned_subscriber_t,
    z_loaned_subscriber_t,
    z_moved_subscriber_t,
    free_subscriber,
    z_internal_subscriber_null,
    z_internal_subscriber_check,
    z_subscriber_loan,
    z_subscriber_loan_mut,
    z_subscriber_move,
    z_subscriber_take,
    z_subscriber_drop
);

// --- helpers ---------------------------------------------------------------

/// Take a moved payload's bytes, nulling the source.
///
/// Ownership is decided by the value's own borrow tag rather than assumed. An
/// ORDINARY owned bytes — everything a wz constructor produces — is reclaimed
/// from its `Box`. A BORROWED one is COPIED and its storage left alone, because
/// the only way a C program obtains one is by reading `sample->payload` out of a
/// marshal that still owns it, and that marshal frees it when the callback
/// returns. Freeing it here is the double free this tag exists to prevent; see
/// [`crate::abi::HandleOwnership`].
///
/// Both arms null the source, so pico's consume-on-all-paths contract holds
/// either way: after this call the caller's `z_owned_bytes_t` is spent.
///
/// # Safety
/// `payload` must be null or a valid `z_moved_bytes_t` whose handle is a live
/// `Box::into_raw::<ByteBuf>` pointer, or a BORROW of a live `ByteBuf`.
pub(crate) unsafe fn take_moved_bytes(payload: *mut z_moved_bytes_t) -> Option<ByteBuf> {
    if payload.is_null() {
        return None;
    }
    let handle = (*payload)._this.handle;
    if handle.is_null() {
        return None;
    }
    let buf = if crate::abi::HandleOwnership::handle_is_borrowed(&(*payload)._this) {
        (*(handle as *const ByteBuf)).clone()
    } else {
        *Box::from_raw(handle as *mut ByteBuf)
    };
    (*payload)._this = z_owned_bytes_t::null_value();
    Some(buf)
}

/// Fold a caller's `z_publisher_put_options_t` into wz's [`PublishOptions`].
///
/// Consumes the moved `encoding` and `attachment` on EVERY path — pico's
/// ownership transfer is unconditional once the call is made — and a NULL
/// `options` is the plain default, which is what pico does too.
///
/// R311y561 — `source_info` is READ now (see [`source_info_hint_of`]). It was
/// read-and-dropped with a stated reason: no exported constructor for a
/// `z_source_info_t` existed, so no C program could build one. `z_source_info_new`
/// landed in R311y559 and the reason expired with it.
///
/// # Safety
/// `options` must be null or a valid put-options struct.
unsafe fn publisher_put_options(options: *const z_publisher_put_options_t) -> PublishOptions {
    let mut opts = put_options();
    if options.is_null() {
        return opts;
    }
    // The moved values are consumed FIRST, before any early return could skip
    // them — the same consume-on-all-paths discipline `z_get` follows.
    let attachment = take_moved_bytes((*options).attachment);
    let encoding = crate::encoding::take_moved_encoding((*options).encoding);
    if let Some(attachment) = attachment {
        opts = opts.with_attachment(attachment.to_vec());
    }
    if let Some(hint) = encoding {
        opts = opts.with_encoding(hint);
    }
    if let Some(ts) = timestamp_hint_of((*options).timestamp) {
        opts = opts.with_timestamp(ts);
    }
    if let Some(si) = source_info_hint_of((*options).source_info) {
        opts = opts.with_source_info(si);
    }
    opts
}

fn put_options() -> PublishOptions {
    // `Locality::Remote`, not the `Any` default. A pico session's own `z_put`
    // is delivered to its OWN local subscribers at most ONCE
    // (`_z_write` -> `_z_session_deliver_push_locally`, gated on
    // `Z_FEATURE_LOCAL_SUBSCRIBER`, `~/zenoh-pico/src/net/primitives.c:198-201`).
    // Here the C session is N per-face wz sessions, each with its own observer
    // carrying a replica of the subscription — so a local-capable publish would
    // (a) fire the one C callback ONCE PER FACE (N duplicate local deliveries
    // for a single `z_put`), and (b) drain that fire on the C thread, racing the
    // drive thread's inbound dispatch on another face (see the `CClosure` Sync
    // note). Remote-only sidesteps both: the fan-out reaches every PEER over the
    // wire, and self-delivery to local subscribers is deferred as a named
    // divergence (this crate has never implemented `Z_FEATURE_LOCAL_SUBSCRIBER`;
    // a faithful build would deliver locally exactly once, at the registry
    // level, serialized against inbound dispatch).
    let mut opts = PublishOptions::default()
        .with_reliability(Reliability::Reliable)
        .with_locality(Locality::Remote);
    opts.kind = SampleKind::Put;
    opts
}

// --- z_put -----------------------------------------------------------------

/// pico `z_put_options_t` (`api/types.h:386-400`), mirrored field for field so
/// rustc computes the layout from the SAME list the generated header declares.
///
/// R311y559 — this type did not exist and `z_put`'s options parameter was
/// `*const c_void`, IGNORED. A pico program that set an encoding, a priority,
/// an attachment or a timestamp on its session put had every one of them
/// silently dropped; the sibling `z_publisher_put_options_t` had been read for
/// rounds, so the two paths disagreed on the same wire fields depending on
/// which entry point the program used.
///
/// The tail is FEATURE-CONDITIONAL in pico's header and these arms follow the
/// GENERATED `config.h` the drop-in's programs compile against:
/// `allowed_destination` is ABSENT (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0) and the
/// `reliability` / `source_info` pair is PRESENT (`Z_FEATURE_UNSTABLE_API` is
/// defined). Reading that off the cmake command line instead of the generated
/// header is the R311y466 trap.
#[repr(C)]
pub struct z_put_options_t {
    pub encoding: *mut c_void,
    pub congestion_control: c_int,
    pub priority: c_int,
    pub timestamp: *mut z_timestamp_t,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
    pub reliability: c_int,
    pub source_info: *mut z_source_info_t,
}

/// pico `z_delete_options_t` (`api/types.h:413-425`).
///
/// No encoding and no attachment: a Del body carries neither, and upstream's
/// struct reflects that.
#[repr(C)]
pub struct z_delete_options_t {
    pub congestion_control: c_int,
    pub priority: c_int,
    pub is_express: bool,
    pub timestamp: *mut z_timestamp_t,
    pub reliability: c_int,
    pub source_info: *mut z_source_info_t,
}

/// pico `z_publisher_delete_options_t` (`api/types.h:454-459`).
#[repr(C)]
pub struct z_publisher_delete_options_t {
    pub timestamp: *mut z_timestamp_t,
    pub source_info: *mut z_source_info_t,
}

/// Fill default put options (pico `z_put_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_put_options_default(options: *mut z_put_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_put_options_t {
        encoding: std::ptr::null_mut(),
        congestion_control: crate::query::Z_CONGESTION_CONTROL_DROP,
        priority: crate::query::Z_PRIORITY_DEFAULT,
        timestamp: std::ptr::null_mut(),
        is_express: false,
        attachment: std::ptr::null_mut(),
        reliability: Z_RELIABILITY_RELIABLE,
        source_info: std::ptr::null_mut(),
    };
}

/// Fill default delete options (pico `z_delete_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_delete_options_default(options: *mut z_delete_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_delete_options_t {
        congestion_control: crate::query::Z_CONGESTION_CONTROL_DROP,
        priority: crate::query::Z_PRIORITY_DEFAULT,
        is_express: false,
        timestamp: std::ptr::null_mut(),
        reliability: Z_RELIABILITY_RELIABLE,
        source_info: std::ptr::null_mut(),
    };
}

/// Fill default publisher-delete options (pico
/// `z_publisher_delete_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_delete_options_default(
    options: *mut z_publisher_delete_options_t,
) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_delete_options_t {
        timestamp: std::ptr::null_mut(),
        source_info: std::ptr::null_mut(),
    };
}

/// pico `Z_RELIABILITY_RELIABLE`, its `Z_RELIABILITY_DEFAULT`.
pub const Z_RELIABILITY_RELIABLE: c_int = 0;
/// pico `Z_RELIABILITY_BEST_EFFORT`.
pub const Z_RELIABILITY_BEST_EFFORT: c_int = 1;

/// A caller's PUSH-side `z_congestion_control_t` as wz's.
///
/// Distinct from [`crate::query::congestion_from_pico`] in ONE way, and it is
/// the reason this is not a call to that function: the two differ in what an
/// UNRECOGNISED value degrades to. pico's request-side default is BLOCK
/// (`z_get_options_default`) and its push-side default is DROP
/// (`z_put_options_default`), so each fallback has to be the default of the
/// plane it serves. The two recognised values agree, and the mapping is written
/// out rather than cast because the SIBLING zenoh-c ABI inverts them —
/// R311y545 paid for exactly that.
fn push_congestion_from_pico(c: c_int) -> wz_runtime_tokio::qos::CongestionControl {
    match c {
        crate::query::Z_CONGESTION_CONTROL_BLOCK => wz_runtime_tokio::qos::CongestionControl::Block,
        _ => wz_runtime_tokio::qos::CongestionControl::Drop,
    }
}

/// A caller's `z_reliability_t` as wz's.
///
/// INVERTED against wz's own enum: pico spells `RELIABLE = 0` /
/// `BEST_EFFORT = 1` while wz is `BestEffort = 0` / `Reliable = 1`. Written
/// out for exactly that reason.
fn reliability_from_pico(r: c_int) -> Reliability {
    match r {
        Z_RELIABILITY_BEST_EFFORT => Reliability::BestEffort,
        _ => Reliability::Reliable,
    }
}

/// Read a caller-supplied `z_timestamp_t*` option field into a wz hint.
///
/// # Safety
/// `ptr` must be null or point at a valid `z_timestamp_t`.
pub(crate) unsafe fn timestamp_hint_of(
    ptr: *const z_timestamp_t,
) -> Option<wz_runtime_tokio::sample::TimestampHint> {
    if ptr.is_null() {
        return None;
    }
    let ts = &*ptr;
    if !ts.valid {
        return None;
    }
    Some(wz_runtime_tokio::sample::TimestampHint {
        time: ts.time,
        // The wire form strips trailing zeros; the codec re-pads.
        zid: ts.id.id.to_vec(),
    })
}

/// R311y561 — read a caller-supplied `z_source_info_t*` option field into a wz
/// [`SourceInfo`](wz_runtime_tokio::sample::SourceInfo). The INVERSE of
/// [`source_info_of`], which projects the receive direction.
///
/// This is the field R311y559 left UNREAD on every pico put/delete path, and it
/// left it unread for a reason that y559 itself then dissolved: at the time
/// this crate exported no constructor for a `z_source_info_t`, so no C program
/// could build one to pass and wiring it would have been untestable surface.
/// `z_source_info_new` shipped in the same round, so the justification expired
/// with it — a residual is a claim with a date on it.
///
/// A NULL pointer and pico's own null value (`_z_source_info_null` = all-zero,
/// which `_z_source_info_check` rejects on the zero zid) both read as `None`,
/// matching how pico's own getters treat an unchecked info. Anything else is
/// carried: the zid is the fixed 16-byte array with its zero tail intact,
/// because the wz codec re-derives the wire's effective length from the value.
///
/// # Safety
/// `ptr` must be null or point at a valid `z_source_info_t`.
pub(crate) unsafe fn source_info_hint_of(
    ptr: *const z_source_info_t,
) -> Option<wz_runtime_tokio::sample::SourceInfo> {
    if ptr.is_null() {
        return None;
    }
    let info = &*ptr;
    // pico's `_z_source_info_check` is `_z_entity_global_id_check`, which is an
    // all-zero-zid test: an unset info must not reach the wire as a source
    // identity of zid 0.
    if info._source_id.zid.id.iter().all(|b| *b == 0) {
        return None;
    }
    Some(wz_runtime_tokio::sample::SourceInfo::new(
        &info._source_id.zid.id,
        info._source_id.eid,
        info._source_sn,
    ))
}

/// Fold a caller's `z_put_options_t` into wz's [`PublishOptions`].
///
/// Consumes the moved `encoding` and `attachment` on EVERY path — pico's
/// ownership transfer is unconditional once the call is made — and a NULL
/// `options` is the plain default, which is what pico does too.
///
/// `allowed_destination` is absent from the struct (see [`z_put_options_t`]),
/// so the locality stays [`put_options`]'s `Remote`: a default pico build does
/// not deliver a session's own put to its own subscriber, and there is no field
/// through which a program could ask it to.
///
/// # Safety
/// `options` must be null or a valid put-options struct.
unsafe fn session_put_options(options: *const z_put_options_t) -> PublishOptions {
    let mut opts = put_options();
    if options.is_null() {
        return opts;
    }
    // Consumed FIRST, before any branch could skip them.
    let attachment = take_moved_bytes((*options).attachment);
    let encoding = crate::encoding::take_moved_encoding((*options).encoding);
    opts = opts
        .with_priority(crate::query::priority_from_pico((*options).priority))
        .with_congestion_control(push_congestion_from_pico((*options).congestion_control))
        .with_express((*options).is_express)
        .with_reliability(reliability_from_pico((*options).reliability));
    if let Some(attachment) = attachment {
        opts = opts.with_attachment(attachment.to_vec());
    }
    if let Some(hint) = encoding {
        opts = opts.with_encoding(hint);
    }
    if let Some(ts) = timestamp_hint_of((*options).timestamp) {
        opts = opts.with_timestamp(ts);
    }
    if let Some(si) = source_info_hint_of((*options).source_info) {
        opts = opts.with_source_info(si);
    }
    opts
}

/// Fold a caller's `z_delete_options_t` into wz's [`PublishOptions`], as the
/// Del kind.
///
/// # Safety
/// `options` must be null or a valid delete-options struct.
unsafe fn session_delete_options(options: *const z_delete_options_t) -> PublishOptions {
    let mut opts = put_options();
    opts.kind = SampleKind::Del;
    if options.is_null() {
        return opts;
    }
    opts = opts
        .with_priority(crate::query::priority_from_pico((*options).priority))
        .with_congestion_control(push_congestion_from_pico((*options).congestion_control))
        .with_express((*options).is_express)
        .with_reliability(reliability_from_pico((*options).reliability));
    if let Some(ts) = timestamp_hint_of((*options).timestamp) {
        opts = opts.with_timestamp(ts);
    }
    if let Some(si) = source_info_hint_of((*options).source_info) {
        opts = opts.with_source_info(si);
    }
    opts
}

/// Publish a payload on a session (pico `z_put`). Consumes the moved payload.
///
/// R311y559 — the options are now READ. See [`z_put_options_t`] for what was
/// being dropped and why the two put paths had drifted.
#[no_mangle]
pub unsafe extern "C" fn z_put(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *const z_put_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST so it is freed on every path (pico's
        // "z_move consumes on all paths" contract): the owned `Vec` is dropped
        // on any early error below, and `take_moved_bytes` already nulled the
        // caller's source struct.
        let buf = match take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k,
            None => return Z_ERR_INVALID,
        };
        // A keyexpr that carries a live declaration publishes ALIASED — the
        // wire carries the id instead of the literal, which is the entire
        // reason `z_declare_keyexpr` exists (pico's `_z_write` reads the same
        // discriminant off its `_z_declared_keyexpr_t`). Each face resolves the
        // literal from its own outbound mapping table, so this is correct even
        // for a face that joined after the declaration and got it by replay.
        // Resolved AFTER the payload is taken and BEFORE any keyexpr branch, so
        // the moved encoding / attachment are consumed on every path.
        let resolved = session_put_options(options);
        let result = match keyexpr_mapping(keyexpr) {
            Some(mapping) => state.shared.publish_aliased_all(mapping, &buf, &resolved),
            None => state.shared.publish_all(ke, &buf, &resolved),
        };
        match result {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

/// Publish a DELETE on a session (pico `z_delete`).
///
/// R311y559 — this export did not exist. A Del is not a Put with an empty
/// payload: it carries a different inner body, and a subscriber reads
/// `z_sample_kind` to tell them apart, so a program deleting a key had no way
/// to say so through this ABI at all.
///
/// # Safety
/// `zs` must be null or a live loaned session; `keyexpr` must be null or a live
/// loaned keyexpr; `options` must be null or a valid delete-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_delete(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *const z_delete_options_t,
) -> ZResult {
    guarded(|| {
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k,
            None => return Z_ERR_INVALID,
        };
        let resolved = session_delete_options(options);
        // The empty payload is the Del body's own shape, not a stand-in for a
        // missing one: `_z_msg_del_t` has no payload field.
        let result = match keyexpr_mapping(keyexpr) {
            Some(mapping) => state.shared.publish_aliased_all(mapping, &[], &resolved),
            None => state.shared.publish_all(ke, &[], &resolved),
        };
        match result {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

/// Publish a DELETE through a declared publisher (pico `z_publisher_delete`).
///
/// R311y559 — as [`z_delete`], this export did not exist.
///
/// # Safety
/// `publisher` must be null or a live loaned publisher; `options` must be null
/// or a valid publisher-delete-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_delete(
    publisher: *const z_loaned_publisher_t,
    options: *const z_publisher_delete_options_t,
) -> ZResult {
    guarded(|| {
        let state = match crate::abi::handle_ref::<z_loaned_publisher_t, PublisherState>(publisher)
        {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let mut opts = put_options();
        opts.kind = SampleKind::Del;
        if !options.is_null() {
            if let Some(ts) = timestamp_hint_of((*options).timestamp) {
                opts = opts.with_timestamp(ts);
            }
            if let Some(si) = source_info_hint_of((*options).source_info) {
                opts = opts.with_source_info(si);
            }
        }
        match state
            .shared_session()
            .publish_all(state.keyexpr(), &[], &opts)
        {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

// --- publisher exports -----------------------------------------------------

/// pico `z_publisher_options_t` (`api/types.h:236-247`), 24 B measured against
/// the CMake-GENERATED config these programs compile with.
///
/// The tail of this struct is FEATURE-CONDITIONAL in pico's header, so the
/// layout is a property of the generated `config.h`, not of the source tree:
/// `reliability` exists because `Z_FEATURE_UNSTABLE_API` is defined, and
/// `allowed_destination` is ABSENT because `Z_FEATURE_LOCAL_SUBSCRIBER` is 0.
/// Reading that off the cmake command line instead of the generated header is
/// the R311y466 trap; both were read off `config.h`, and the offsets are pinned
/// in this module's tests.
///
/// wz's `z_declare_publisher` does not yet READ these fields (its options
/// parameter is still `*const c_void`), and that is stated rather than implied:
/// this type exists so a pico program can stack-allocate and default it, which
/// is what `z_pub_thr.c` does. Honouring `congestion_control` / `priority` /
/// `is_express` / `reliability` on the declared publisher is separate surface.
#[repr(C)]
pub struct z_publisher_options_t {
    /// Moved default encoding, or NULL. Typed as an opaque pointer here because
    /// this crate has no encoding plane yet; the SLOT must exist and be 8 B
    /// wide or every field after it lands at the wrong offset.
    pub encoding: *mut c_void,
    pub congestion_control: c_int,
    pub priority: c_int,
    pub is_express: bool,
    pub reliability: c_int,
}

/// Default publisher options (pico `z_publisher_options_default`).
///
/// pico zeroes the encoding slot and takes the library defaults for the rest;
/// the numeric defaults are its enum zero values, which is what a
/// `memset`-style default yields and what `z_pub_thr.c` then publishes with.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_options_default(options: *mut z_publisher_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_options_t {
        encoding: std::ptr::null_mut(),
        congestion_control: 0,
        priority: 0,
        is_express: false,
        reliability: 0,
    };
}

/// Declare a publisher (pico `z_declare_publisher`).
#[no_mangle]
pub unsafe extern "C" fn z_declare_publisher(
    zs: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    keyexpr: *const z_loaned_keyexpr_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        let mut boxed = Box::new(PublisherState {
            eid: state.shared.next_entity_id(),
            shared: state.shared.clone(),
            keyexpr: ke,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            matches: StdMutex::new(Vec::new()),
        });
        boxed.bind();
        *publisher = z_owned_publisher_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Publish through a publisher (pico `z_publisher_put`). Consumes the payload.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put(
    publisher: *const z_loaned_publisher_t,
    payload: *mut z_moved_bytes_t,
    options: *const z_publisher_put_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload first (pico consume-on-all-paths contract):
        // dropped + source nulled even if the publisher handle is invalid.
        let buf = match take_moved_bytes(payload) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let state = match handle_ref::<z_loaned_publisher_t, PublisherState>(publisher) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        // R311y529 — `_options` used to be `*const c_void` and DROPPED. The
        // link measurement could not see that: `z_pub_attachment.c` linked,
        // ran, and printed its own "Putting Data" lines while a REAL pico
        // subscriber reported `encoding: zenoh/bytes` with no attachment and no
        // timestamp, because all three were being thrown away here. A link is
        // not a pass, and this is what the difference looked like.
        let opts = publisher_put_options(options);
        match state.shared.publish_all(&state.keyexpr, &buf, &opts) {
            Ok(_) => Z_OK,
            Err(_) => Z_ERR_GENERIC,
        }
    })
}

/// Undeclare a publisher (pico `z_undeclare_publisher`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_publisher(publisher: *mut z_moved_publisher_t) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_OK;
        }
        let handle = (*publisher)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut PublisherState));
            (*publisher)._this = z_owned_publisher_t::null_value();
        }
        Z_OK
    })
}

// --- closure ---------------------------------------------------------------

/// Build an owned sample closure from a callback + drop + context (pico
/// `z_closure_sample`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample(
    closure: *mut z_owned_closure_sample_t,
    call: z_closure_sample_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_sample_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Zero an owned closure (pico `z_internal_closure_sample_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_sample_null(closure: *mut z_owned_closure_sample_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_sample_t::null_value();
    }
}

/// `true` iff the closure holds a callback (pico
/// `z_internal_closure_sample_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_sample_check(
    closure: *const z_owned_closure_sample_t,
) -> bool {
    crate::ffi::guard_val(false, || !closure.is_null() && (*closure).call.is_some())
}

/// Borrow an owned closure (pico `z_closure_sample_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_loan(
    closure: *const z_owned_closure_sample_t,
) -> *const z_loaned_closure_sample_t {
    closure as *const z_loaned_closure_sample_t
}

/// Move-cast an owned closure (pico `z_closure_sample_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_move(
    closure: *mut z_owned_closure_sample_t,
) -> *mut z_moved_closure_sample_t {
    closure as *mut z_moved_closure_sample_t
}

/// Take an owned closure out of `src` into `dst` (pico
/// `z_closure_sample_take`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_take(
    dst: *mut z_owned_closure_sample_t,
    src: *mut z_moved_closure_sample_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).context = (*src)._this.context;
    (*dst).call = (*src)._this.call;
    (*dst).drop = (*src)._this.drop;
    (*src)._this = z_owned_closure_sample_t::null_value();
}

/// Drop an owned closure without ever having declared it (pico
/// `z_closure_sample_drop`): run the C `drop(context)` and null the struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_drop(closure: *mut z_moved_closure_sample_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = z_owned_closure_sample_t::null_value();
        Z_OK
    });
}

// --- subscriber exports ----------------------------------------------------

/// Declare a subscriber (pico `z_declare_subscriber`). Consumes the moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn z_declare_subscriber(
    zs: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST (pico consume-on-all-paths contract):
        // the `CClosure` now owns the C `drop(context)` responsibility, so an
        // early error return below drops it and frees the context; on success
        // it moves into the subscriber callback.
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        // Reject a non-canonical / pico-unsafe keyexpr UP FRONT (e.g. the
        // `**/c/*` three-family bug), returning `Z_ERR_INVALID` rather than
        // recording a dead SSOT entry that never matches yet reports `Z_OK`.
        // This is the same outbound gate wz's own `Session::declare_subscriber`
        // applies per face — hoisted here so the verdict is uniform whether or
        // not a peer is connected yet (the registry declares best-effort per
        // face, so a per-face reject would otherwise be swallowed). `cclosure`
        // is already owned, so this early return drops it and runs the C
        // `drop(context)` (consume-on-all-paths).
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }

        // Record the subscription in the session's SSOT and declare it on every
        // face that is already up. With no peer yet — a listener before its
        // first connection — this declares nothing on the wire and still
        // records the entry (pico's declare-before-peer); each face replays the
        // SSOT as it comes up. Recording the local entry always succeeds
        // (mirrors pico's `_z_register_subscriber`).
        // R311y554 — `Locality::Remote`, and unlike the zenoh-c sibling this is
        // a FIDELITY choice with a measured source rather than a soundness
        // workaround: `Z_FEATURE_LOCAL_SUBSCRIBER` defaults to 0
        // (`vendor/zenoh-pico/CMakeLists.txt:343`), which is why pico's own
        // `z_subscriber_options_t` has no `allowed_origin` field in a default
        // build and why this crate's mirror of it has none either. A default
        // pico build never delivers a session's own put to its own subscriber,
        // so neither does this ABI.
        // R311y559 — kept for `z_subscriber_keyexpr`, which needs storage the
        // handle owns; `ke` is moved into the registry below.
        let keyexpr_literal = ke.clone();
        let id = state.shared.declare_subscriber(ke, Locality::Remote, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
        });
        let mut boxed = Box::new(SubscriberState {
            shared: state.shared.clone(),
            id,
            keyexpr: keyexpr_literal,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
        });
        boxed.bind();
        *subscriber = z_owned_subscriber_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Declare a subscriber with NO owned handle (pico
/// `z_declare_background_subscriber`). Consumes the moved closure.
///
/// The subscription lives for the session's lifetime and the caller gets
/// nothing back to undeclare it with — pico's "background" declaration, used by
/// programs that subscribe once and then loop forever. Upstream's `z_ping.c`,
/// `z_pong.c` and `z_sub_thr.c` all take this form, which is why one export
/// unlocks three examples.
///
/// Everything except the handle is [`z_declare_subscriber`]: same SSOT
/// registration, same declare-before-peer replay, same up-front keyexpr gate,
/// same consume-on-all-paths closure contract. The registry entry is simply
/// never removed, and `z_close` clears it with the rest of the session — which
/// is also where the C `drop(context)` finally runs.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_subscriber(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
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
        // The returned SubId is deliberately discarded: with no owned handle
        // there is nothing that could ever undeclare it, so retaining the id
        // would only invite a caller-less removal path that pico does not have.
        // R311y554 — same Remote pin, same reason as the owned form above.
        let _ = state.shared.declare_subscriber(ke, Locality::Remote, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
        });
        Z_OK
    })
}

/// Undeclare a subscriber (pico `z_undeclare_subscriber`): drops the wz
/// subscriber (undeclare on the wire) and the callback (→ C `drop(context)`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_subscriber(subscriber: *mut z_moved_subscriber_t) -> ZResult {
    guarded(|| {
        if subscriber.is_null() {
            return Z_OK;
        }
        let handle = (*subscriber)._this.handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut SubscriberState));
            (*subscriber)._this = z_owned_subscriber_t::null_value();
        }
        Z_OK
    })
}

// --- sample accessors ------------------------------------------------------

/// Borrow a delivered sample's keyexpr (pico `z_sample_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_sample_keyexpr(
    sample: *const z_loaned_sample_t,
) -> *const z_loaned_keyexpr_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    &marshal.loaned_keyexpr as *const z_loaned_keyexpr_t
}

/// Borrow a delivered sample's payload (pico `z_sample_payload`).
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload(
    sample: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    if sample.is_null() {
        return std::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    &marshal.loaned_payload as *const z_loaned_bytes_t
}

/// How the sample was issued — Put or Delete (pico `z_sample_kind`).
///
/// R311y296 exports this because the REPLY plane made it load-bearing rather
/// than merely nice to have: `z_reply_ok` hands the C side a
/// `z_loaned_sample_t`, and R3a's `z_query_reply_del` can emit a Del reply, so
/// without this accessor a C getter could not distinguish a delete reply from a
/// Put carrying an empty payload. R1 shipped only `z_sample_keyexpr` /
/// `z_sample_payload` because a pub/sub-only surface had no Del to observe
/// (`z_delete` rides pico's `Z_FEATURE_PUBLICATION` gate and is still not
/// exported), which left a hole the moment the two planes composed.
///
/// A null / spent sample reports `Z_SAMPLE_KIND_PUT`, which is pico's own
/// `Z_SAMPLE_KIND_DEFAULT` (pico would dereference and crash).
#[no_mangle]
pub unsafe extern "C" fn z_sample_kind(sample: *const z_loaned_sample_t) -> z_sample_kind_t {
    crate::ffi::guard_val(Z_SAMPLE_KIND_PUT, || {
        if sample.is_null() {
            return Z_SAMPLE_KIND_PUT;
        }
        (*(sample as *const SampleMarshal)).kind
    })
}

// --- R311y559: source info + the sample QoS accessors -----------------------

/// pico `z_source_info_t` = `_z_source_info_t` (`protocol/core.h:257-260`),
/// `{ _z_entity_global_id_t _source_id; uint32_t _source_sn; }` — 24 B at
/// ALIGNMENT 4.
///
/// The alignment is 4, not 8, and that is ABI rather than trivia: `z_id_t` is a
/// bare `uint8_t[16]` and so contributes alignment 1, leaving `eid` / `_source_sn`
/// to set it. The same reasoning that makes
/// [`z_entity_global_id_t`](crate::advanced::z_entity_global_id_t) 20 bytes
/// rather than 24. This type crosses the boundary BY VALUE out of
/// [`z_source_info_new`], so getting it wrong misplaces every field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_source_info_t {
    pub _source_id: crate::advanced::z_entity_global_id_t,
    pub _source_sn: u32,
}

const _: () = {
    assert!(std::mem::size_of::<z_source_info_t>() == 24);
    assert!(std::mem::align_of::<z_source_info_t>() == 4);
};

impl z_source_info_t {
    /// The all-zero value, which is pico's `_z_source_info_null`.
    pub(crate) fn empty() -> Self {
        Self {
            _source_id: crate::advanced::z_entity_global_id_t {
                zid: crate::zid::z_id_t::empty(),
                eid: 0,
            },
            _source_sn: 0,
        }
    }
}

/// The pico ABI shape for a wz [`SourceInfo`](wz_runtime_tokio::sample::SourceInfo).
///
/// `zid_len` is DROPPED, and deliberately: wz carries the wire's effective zid
/// length because the codec's header nibble encodes it, while pico's `z_id_t`
/// is a fixed 16-byte array whose unused tail is zero. The wz value is already
/// right-zero-padded to 16, so the projection is a copy — but a reader
/// comparing two zids must compare all 16 bytes, which is what
/// `z_id_to_string` and every pico program do.
pub(crate) fn source_info_of(info: &wz_runtime_tokio::sample::SourceInfo) -> z_source_info_t {
    z_source_info_t {
        _source_id: crate::advanced::z_entity_global_id_t {
            zid: crate::zid::z_id_t::from_wire(&info.zid),
            eid: info.eid,
        },
        _source_sn: info.sn,
    }
}

/// Build a global entity id from a zid and an entity id (pico
/// `z_entity_global_id_new`).
///
/// # Safety
/// `gid` must be valid and writable; `zid` must be null or a valid `z_id_t`.
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_new(
    gid: *mut crate::advanced::z_entity_global_id_t,
    zid: *const crate::zid::z_id_t,
    eid: u32,
) -> ZResult {
    crate::ffi::guarded(|| {
        if gid.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        *gid = crate::advanced::z_entity_global_id_t {
            zid: if zid.is_null() {
                crate::zid::z_id_t::empty()
            } else {
                *zid
            },
            eid,
        };
        crate::result::Z_OK
    })
}

/// Build a source-info record (pico `z_source_info_new`), returned BY VALUE.
///
/// # Safety
/// `source_id` must be null or a valid global entity id.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_new(
    source_id: *const crate::advanced::z_entity_global_id_t,
    source_sn: u32,
) -> z_source_info_t {
    crate::ffi::guard_val(z_source_info_t::empty(), || z_source_info_t {
        _source_id: if source_id.is_null() {
            z_source_info_t::empty()._source_id
        } else {
            *source_id
        },
        _source_sn: source_sn,
    })
}

/// The `(zid, eid)` half of a source-info record (pico `z_source_info_id`).
///
/// # Safety
/// `info` must be null or a valid source-info record.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_id(
    info: *const z_source_info_t,
) -> crate::advanced::z_entity_global_id_t {
    crate::ffi::guard_val(z_source_info_t::empty()._source_id, || {
        if info.is_null() {
            z_source_info_t::empty()._source_id
        } else {
            (*info)._source_id
        }
    })
}

/// The sequence number of a source-info record (pico `z_source_info_sn`).
///
/// # Safety
/// `info` must be null or a valid source-info record.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_sn(info: *const z_source_info_t) -> u32 {
    crate::ffi::guard_val(0, || {
        if info.is_null() {
            0
        } else {
            (*info)._source_sn
        }
    })
}

/// Borrow a sample's source info, or NULL when it carried none (pico
/// `z_sample_source_info`).
///
/// NULL for absent is the contract, not an error path: a sample published
/// without the inner-body source_info ext genuinely has none, and a program
/// that branches on the pointer — as an advanced subscriber re-keying by
/// `(zid, eid, sn)` must — needs the two cases distinguishable.
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_source_info(
    sample: *const z_loaned_sample_t,
) -> *const z_source_info_t {
    crate::ffi::guard_val(std::ptr::null(), || match sample_marshal(sample) {
        Some(m) => match m.source_info.as_ref() {
            Some(info) => info as *const z_source_info_t,
            None => std::ptr::null(),
        },
        None => std::ptr::null(),
    })
}

/// A sample's transport reliability (pico `z_sample_reliability`).
///
/// Note the enum is INVERTED against wz's own: pico spells
/// `Z_RELIABILITY_RELIABLE = 0` and `Z_RELIABILITY_BEST_EFFORT = 1`
/// (`api/constants.h:201-203`) while `wz_runtime_tokio::Reliability`
/// is `BestEffort = 0` / `Reliable = 1`. The mapping is written out rather than
/// cast, because a cast agrees on neither value and R311y545 already paid for
/// exactly this class of slip on `z_congestion_control_t`.
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_reliability(sample: *const z_loaned_sample_t) -> c_int {
    /// pico `Z_RELIABILITY_RELIABLE`, and its `Z_RELIABILITY_DEFAULT`.
    const Z_RELIABILITY_RELIABLE: c_int = 0;
    /// pico `Z_RELIABILITY_BEST_EFFORT`.
    const Z_RELIABILITY_BEST_EFFORT: c_int = 1;
    crate::ffi::guard_val(Z_RELIABILITY_RELIABLE, || {
        match sample_marshal(sample).map(|m| m.reliability) {
            Some(wz_runtime_tokio::Reliability::BestEffort) => Z_RELIABILITY_BEST_EFFORT,
            _ => Z_RELIABILITY_RELIABLE,
        }
    })
}

/// A sample's congestion-control setting (pico `z_sample_congestion_control`).
///
/// pico and wz AGREE numerically here (`Z_CONGESTION_CONTROL_DROP = 0`,
/// `BLOCK = 1`) — but the sibling zenoh-c ABI does NOT, which is why the
/// mapping is spelled out instead of cast.
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_congestion_control(sample: *const z_loaned_sample_t) -> c_int {
    /// pico `Z_CONGESTION_CONTROL_DROP`, which is also its default.
    const Z_CONGESTION_CONTROL_DROP: c_int = 0;
    /// pico `Z_CONGESTION_CONTROL_BLOCK`.
    const Z_CONGESTION_CONTROL_BLOCK: c_int = 1;
    crate::ffi::guard_val(Z_CONGESTION_CONTROL_DROP, || {
        match sample_qos(sample).map(|q| q.congestion()) {
            Some(wz_runtime_tokio::qos::CongestionControl::Block) => Z_CONGESTION_CONTROL_BLOCK,
            _ => Z_CONGESTION_CONTROL_DROP,
        }
    })
}

/// Whether a sample bypassed batching (pico `z_sample_express`).
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_express(sample: *const z_loaned_sample_t) -> bool {
    crate::ffi::guard_val(false, || sample_qos(sample).is_some_and(|q| q.is_express()))
}

/// A sample's priority (pico `z_sample_priority`).
///
/// A sample carrying NO QoS ext reports `Z_PRIORITY_DATA` (5), which is what
/// the wire means by its absence — the ext is elided precisely when every field
/// is at its default.
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_priority(sample: *const z_loaned_sample_t) -> c_int {
    /// pico `Z_PRIORITY_DATA` (`api/constants.h:247`).
    const Z_PRIORITY_DATA: c_int = 5;
    crate::ffi::guard_val(Z_PRIORITY_DATA, || match sample_qos(sample) {
        Some(q) => c_int::from(q.priority().wire_byte()),
        None => Z_PRIORITY_DATA,
    })
}

/// The marshal behind a loaned sample, or `None` on a null / spent one.
///
/// One reader for the accessors this round added, rather than the
/// `&*(sample as *const SampleMarshal)` each older accessor spells out: the
/// null check is the part that must not be forgotten, and a shared reader is
/// how it stops being per-accessor discipline.
unsafe fn sample_marshal<'a>(sample: *const z_loaned_sample_t) -> Option<&'a SampleMarshal> {
    if sample.is_null() {
        return None;
    }
    Some(&*(sample as *const SampleMarshal))
}

/// The QoS byte behind a loaned sample, or `None` when it carried no QoS ext.
unsafe fn sample_qos(
    sample: *const z_loaned_sample_t,
) -> Option<wz_runtime_tokio::sample::QosLevel> {
    sample_marshal(sample).and_then(|m| m.qos)
}

/// Deep-copy a sample into an owned one (pico `z_sample_clone`).
///
/// The same deep copy `z_sample_take_from_loaned` performs — routed through the
/// identical [`clone_sample_marshal`] so the two cannot diverge — with the
/// source left INTACT, which is the only difference between the two exports.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a live loaned
/// sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_clone(
    dst: *mut z_owned_sample_t,
    this_: *const z_loaned_sample_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if dst.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        *dst = z_owned_sample_t::null_value();
        if this_.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        let handle = clone_sample_marshal(this_);
        if handle.is_null() {
            return crate::result::Z_ERR_GENERIC;
        }
        (*dst).handle = handle;
        crate::result::Z_OK
    })
}

/// Invoke a sample closure (pico `z_closure_sample_call`).
///
/// R311y559 — the `_call` half of the sample-closure family, which the zid and
/// hello families already had. A program that forwards samples between closures
/// — upstream's channel handlers do exactly this — could not link without it.
///
/// # Safety
/// `closure` must be null or a live loaned sample closure; `sample` must be
/// null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_call(
    closure: *const z_loaned_closure_sample_t,
    sample: *mut z_loaned_sample_t,
) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        if let Some(call) = (*closure).call {
            call(sample, (*closure).context);
        }
        Z_OK
    });
}
