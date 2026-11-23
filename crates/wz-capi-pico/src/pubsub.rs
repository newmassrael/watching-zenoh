// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

use alloc::sync::Arc;
use core::ffi::{c_int, c_void};

#[cfg(feature = "liveliness")]
use wz_session_core::declare::liveliness_sample::LivelinessSample;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::SampleKind;
use wz_session_core::sink::SampleView;

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_owned_bytes_t,
};
use crate::bytes::{ByteBuf, NoRoom};
use crate::ffi::{guarded, CClosure as FfiClosure};
use crate::keyexpr::{declared_of, keyexpr_str, wire_key_of, DeclaredKeyexpr};
use crate::option_fields::unstable_option_fields;
use crate::prelude::*;
use crate::result::{
    ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SESSION_CLOSED,
    Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_ERR_TIMESTAMP_GENERATION_FAILED, Z_ERR_TRANSPORT_TX_FAILED, Z_OK,
};
use crate::session::{engine_of, engine_ref, session_handle, z_loaned_session_t, Engine};
use crate::write_filter::{PicoSession, WriteFilter};
use wz_capi_port::{FanoutError, FilterPlane, FilteredPut, SubId, WireKey};

/// What a put, a delete or a publisher's put answers its caller for what the engine did with it:
/// a publication its queue profile dropped behind a held conduit is pico's failed send
/// (`Z_ERR_TRANSPORT_TX_FAILED`, which pico's put answers when its held transmit lock dropped the
/// message), one the session's own subscribers had no room for pico's resource error
/// (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`), and any other refusal the generic error.
fn publish_code(sent: Result<usize, FanoutError>) -> ZResult {
    match sent {
        Ok(_) => Z_OK,
        Err(FanoutError::HeldConduit) => Z_ERR_TRANSPORT_TX_FAILED,
        Err(FanoutError::LocalNoRoom) => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        Err(_) => Z_ERR_GENERIC,
    }
}

#[cfg(test)]
mod publish_code_tests {
    use super::publish_code;
    use crate::result::{
        Z_ERR_GENERIC, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_ERR_TRANSPORT_TX_FAILED, Z_OK,
    };
    use wz_capi_port::FanoutError;

    /// A publication dropped behind a held conduit answers pico's code for a failed send; one the
    /// engine sent answers `Z_OK` whatever reached it, and any other refusal the generic error.
    #[test]
    fn a_drop_behind_a_held_conduit_answers_picos_failed_send() {
        assert_eq!(
            publish_code(Err(FanoutError::HeldConduit)),
            Z_ERR_TRANSPORT_TX_FAILED
        );
        assert_eq!(publish_code(Ok(0)), Z_OK);
        assert_eq!(publish_code(Ok(2)), Z_OK);
        assert_eq!(
            publish_code(Err(FanoutError::ExceedsCapacity)),
            Z_ERR_GENERIC
        );
        assert_eq!(
            publish_code(Err(FanoutError::LocalNoRoom)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
    }
}

// --- opaque loaned sample --------------------------------------------------

/// Opaque loaned sample (pico `z_loaned_sample_t`). Most C callbacks only ever
/// hold a pointer to it and pass it back to `z_sample_keyexpr` /
/// `z_sample_payload`, so this stays opaque rather than reproducing all ~224 B
/// of pico's concrete `_z_sample_t`.
///
/// The exception is upstream's `z_pong.c`, which reads `sample->payload` as a
/// struct field. `SampleMarshal` therefore reproduces the layout PREFIX up to
/// and including that member; see its docs.
#[repr(C)]
pub struct z_loaned_sample_t {
    _opaque: [u8; 0],
}

/// `offsetof(_z_sample_t, payload)` in upstream's headers: six words, 48 B on a 64-bit host
/// and 24 B on a 32-bit one.
///
/// MEASURED against `vendor/zenoh-pico` on a 64-bit host: `_z_sample_t` opens with a
/// `_z_declared_keyexpr_t keyexpr` of exactly 48 bytes, and `payload` follows it
/// (`include/zenoh-pico/net/sample.h:38-47`). That key is six words on any host: its
/// declaration's rc (a value pointer and a count pointer) and its `_z_string_t` (a slice:
/// a length, a start and the two pointers of its delete context), all pointers and `size_t`
/// (`include/zenoh-pico/session/keyexpr.h` @ `_z_declared_keyexpr_t`), so a 32-bit
/// program reads `payload` 24 bytes in, not 48. It is a plain `const` rather than
/// a bindgen import because this crate deliberately does not build pico — the
/// number is pinned by the assertion below plus, ultimately, by the drop-in leg
/// that fails if the two layouts disagree.
const PICO_SAMPLE_PAYLOAD_OFFSET: usize = 6 * core::mem::size_of::<*const c_void>();

/// The marshal's pico-layout prefix must land `pico_payload` exactly where
/// upstream's header puts `_z_sample_t.payload`, or `z_pong.c` reads the wrong
/// 32 bytes. A field reorder, a padding surprise, or a lost `#[repr(C)]` fails
/// the BUILD here rather than producing a leg that mysteriously publishes
/// garbage.
const _: () = assert!(
    core::mem::offset_of!(SampleMarshal, pico_payload) == PICO_SAMPLE_PAYLOAD_OFFSET,
    "SampleMarshal.pico_payload must sit at offsetof(_z_sample_t, payload)"
);

/// The marshal behind a borrowed `z_loaned_sample_t` during one callback, and
/// behind an owned sample. A subscriber's callback reads the keyexpr, payload and
/// attachment where the wz `SampleView` holds them ([`SampleMarshal::lent`]);
/// a reply's and an owned sample's are copies of their own. It caches the
/// loaned views the accessors return.
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
    /// pico `_z_sample_t.keyexpr` (`_z_declared_keyexpr_t`, six words). INERT — wz
    /// never reads or writes it, and a C program that dereferences it gets
    /// zeroes. It exists so `pico_payload` lands at upstream's offset; the
    /// keyexpr a C program is supposed to use comes from `z_sample_keyexpr`,
    /// which reads the Rust `keyexpr` field below.
    _pico_keyexpr: [u8; PICO_SAMPLE_PAYLOAD_OFFSET],
    /// pico `_z_sample_t.payload` — a BORROWED view of `payload` below, bound by
    /// [`SampleMarshal::bind`] once the marshal is at its final address.
    pico_payload: z_owned_bytes_t,
    keyexpr: KeyText,
    payload: ByteBuf,
    kind: z_sample_kind_t,
    /// R311y529 — the sample METADATA the accessors expose. Held for the
    /// whole call the C callback holds its borrowed `z_loaned_sample_t`: the
    /// attachment as the payload is, lent or owned; the rest as values.
    ///
    /// `None` means the sample carried none, which is distinct from an EMPTY
    /// one — pico's `z_sample_attachment` returns NULL for absent and a valid
    /// zero-length payload for present-but-empty, and a program that branches on
    /// the pointer sees the difference.
    attachment: Option<ByteBuf>,
    timestamp: Option<z_timestamp_t>,
    /// The encoding the sample carried, held in the marshal rather than boxed apart from it: the
    /// owned encoding `z_sample_encoding` hands out is `loaned_encoding`, whose handle
    /// [`Self::bind`] points here, so a sample's encoding costs no allocation of its own and is
    /// let go of with the marshal.
    encoding: Option<crate::encoding::EncodingState>,
    /// R311y559 — the sample's QoS byte, `None` when the message carried no
    /// QoS ext. The three `z_sample_{priority,express,congestion_control}`
    /// accessors decode it rather than each carrying its own field, because
    /// they are three READINGS of one wire byte and separate fields could
    /// disagree with it.
    qos: Option<wz_session_core::sample::QosLevel>,
    /// R311y559 — the transport reliability the sample arrived under.
    reliability: Reliability,
    /// R311y559 — the `(zid, eid, sn)` source triple, in the pico ABI shape
    /// `z_sample_source_info` hands back a POINTER to. Stored rather than
    /// synthesised per call for the same reason the cached views are: the
    /// accessor returns a pointer, and a stack temporary would dangle.
    source_info: Option<z_source_info_t>,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    loaned_encoding: crate::encoding::z_loaned_encoding_t,
}

/// Where a marshal's key lies.
enum KeyText {
    /// Text of the marshal's own: a reply's, a token's, a sample kept past its callback.
    Owned(String),
    /// The key of the view a subscriber's callback is handed, read where the view holds it for
    /// that one call ([`SampleMarshal::lent`]).
    Lent(*const str),
}

impl KeyText {
    fn as_str(&self) -> &str {
        match self {
            Self::Owned(text) => text,
            // SAFETY: a lent key outlives the marshal that holds it (`SampleMarshal::lent`).
            Self::Lent(text) => unsafe { &**text },
        }
    }
}

impl SampleMarshal {
    /// Build the marshal with its cached views still UNBOUND — [`Self::bind`]
    /// must run once the value has reached its final address. See
    /// [`crate::query::QueryMarshal::bind`] for why the split is load-bearing
    /// (an earlier cut bound inside a by-value constructor and handed C a
    /// pointer into the dead constructor frame). Its callers are a get's reply and a liveliness
    /// event; a subscriber's sample goes through [`Self::lent`].
    #[cfg(any(feature = "query", feature = "liveliness"))]
    pub(crate) fn new(keyexpr: String, payload: ByteBuf, kind: z_sample_kind_t) -> Self {
        Self::keyed(KeyText::Owned(keyexpr), payload, kind)
    }

    /// The marshal a subscriber's callback is handed for `view`: its key, its payload and its
    /// attachment read where the view holds them, with nothing copied or allocated for them, as
    /// zenoh-pico hands its callback the sample its receive decoded, without copying it
    /// (`vendor/zenoh-pico/src/session/subscription.c` @ `_z_sample_steal_data(&sample`). What
    /// is kept past the call is copied when it is kept: a clone of the payload ([`ByteBuf`]) and
    /// an owned sample ([`Self::deep_copy`]). Its cached views are unbound, as [`Self::new`]'s.
    ///
    /// # Safety
    /// The marshal is dropped before the borrow of `view` ends.
    pub(crate) unsafe fn lent(view: &dyn SampleView) -> Self {
        let mut marshal = Self::keyed(
            KeyText::Lent(view.keyexpr() as *const str),
            ByteBuf::lent(view.payload()),
            sample_kind_of(view.kind()),
        );
        if let Some(attachment) = view.attachment() {
            marshal.attachment = Some(ByteBuf::lent(attachment));
        }
        marshal.with_metadata(view)
    }

    /// [`Self::new`] for a key held as `keyexpr`.
    fn keyed(keyexpr: KeyText, payload: ByteBuf, kind: z_sample_kind_t) -> Self {
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
            reliability: Reliability::default(),
            source_info: None,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_encoding: crate::encoding::z_loaned_encoding_t::unbound(),
        }
    }

    /// Attach the metadata a [`SampleView`] carried besides its attachment, which
    /// [`Self::lent`] reads where it lies.
    fn with_metadata(mut self, view: &dyn SampleView) -> Self {
        // Read where the view holds them first: a view of the session's delivery lane carries no
        // hint, only the parts.
        self.timestamp = view
            .timestamp_parts()
            .map(|(time, zid)| timestamp_from(time, zid))
            .or_else(|| view.timestamp().map(timestamp_of));
        self.encoding = view
            .encoding_parts()
            .map(
                |(packed_id, schema)| wz_session_core::sample::EncodingHint {
                    packed_id,
                    schema: schema.map(<[u8]>::to_vec),
                },
            )
            .or_else(|| view.encoding().cloned())
            .map(|hint| crate::encoding::EncodingState { hint });
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
    ///
    /// # Safety
    /// The marshal is dropped before the borrow of `attachment` ends, as the reply's is.
    #[cfg(feature = "query")]
    pub(crate) unsafe fn with_reply_metadata(
        mut self,
        attachment: Option<&[u8]>,
        encoding: Option<(u32, Option<&[u8]>)>,
        timestamp: Option<(u64, &[u8])>,
        source_info: Option<&wz_session_core::sample::SourceInfo>,
    ) -> Self {
        // Read where the reply holds it, as a subscriber's sample's is ([`Self::lent`]).
        self.attachment = attachment.map(|attachment| ByteBuf::lent(attachment));
        self.timestamp = timestamp.map(|(time, zid)| timestamp_from(time, zid));
        self.encoding = encoding.map(|(packed_id, schema)| crate::encoding::EncodingState {
            hint: wz_session_core::sample::EncodingHint {
                packed_id,
                schema: schema.map(<[u8]>::to_vec),
            },
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
        let keyexpr = self.keyexpr.as_str();
        self.loaned_keyexpr = z_loaned_keyexpr_t::borrowed(keyexpr.as_ptr(), keyexpr.len());
        self.loaned_payload.handle = &self.payload as *const ByteBuf as *mut c_void;
        // The pico-layout slot binds here for the same reason the cached views
        // do: it points into THIS marshal, so it can only be written once the
        // value has stopped moving.
        self.pico_payload = z_owned_bytes_t::borrowed(&self.payload as *const ByteBuf as *const _);
        if let Some(attachment) = self.attachment.as_ref() {
            self.loaned_attachment.handle = attachment as *const ByteBuf as *mut c_void;
        }
        if let Some(encoding) = self.encoding.as_ref() {
            self.loaned_encoding.handle =
                encoding as *const crate::encoding::EncodingState as *mut c_void;
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
    pub(crate) fn deep_copy(&self) -> Result<Self, NoRoom> {
        let payload = self.payload.try_clone()?;
        let attachment = match &self.attachment {
            Some(attachment) => Some(attachment.try_clone()?),
            None => None,
        };
        Ok(Self {
            _pico_keyexpr: [0u8; PICO_SAMPLE_PAYLOAD_OFFSET],
            // Left UNBOUND for the same reason the cached views below are: it
            // borrows the COPY's `payload`, an address that does not exist until
            // the copy has landed and `bind` runs.
            pico_payload: z_owned_bytes_t::null_value(),
            keyexpr: KeyText::Owned(self.keyexpr.as_str().to_owned()),
            // A lent payload's clone, and its attachment's, is a copy (`ByteBuf::try_clone`).
            payload,
            kind: self.kind,
            attachment,
            timestamp: self.timestamp,
            qos: self.qos,
            reliability: self.reliability,
            source_info: self.source_info,
            encoding: self
                .encoding
                .as_ref()
                .map(|state| crate::encoding::EncodingState {
                    hint: state.hint.clone(),
                }),
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_encoding: crate::encoding::z_loaned_encoding_t::unbound(),
        })
    }
}

// --- the OWNED sample family ------------------------------------------------

/// Release an owned [`SampleMarshal`].
///
/// # Safety
/// `handle` must be a live `SampleMarshal` handle.
unsafe fn free_sample_marshal(handle: *mut c_void) {
    crate::object_slot::release(handle.cast::<SampleMarshal>());
}

/// Deep-copy the marshal behind a borrowed sample into a place of its own, bound at its final
/// address. `Z_ERR_GENERIC` for a null `src`, `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the pool of
/// samples is full.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a sample callback.
unsafe fn clone_sample_marshal(src: *const z_loaned_sample_t) -> Result<*mut c_void, ZResult> {
    if src.is_null() {
        return Err(crate::result::Z_ERR_GENERIC);
    }
    let marshal = &*(src as *const SampleMarshal);
    let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Sample) else {
        return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
    };
    let copy = marshal.deep_copy().map_err(NoRoom::code)?;
    let owned = slot.fill(copy);
    (*owned).bind();
    Ok(owned.cast::<c_void>())
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
fn timestamp_of(hint: &wz_session_core::sample::TimestampHint) -> z_timestamp_t {
    timestamp_from(hint.time, &hint.zid)
}

/// A timestamp of time word `time` and id prefix `zid`, as they lie on the wire.
fn timestamp_from(time: u64, zid: &[u8]) -> z_timestamp_t {
    z_timestamp_t {
        valid: true,
        id: crate::zid::z_id_t::from_wire(zid),
        time,
    }
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
            context: core::ptr::null_mut(),
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
// Sharing `&CClosure` is sound because the closure is two C pointers that Rust
// only reads, and WHO calls `call` is pico's contract, which this ABI keeps in
// each arm:
//
// - Without `local-subscriber`, `call` is only ever invoked from the session's
//   drive task: inbound dispatch is the ONLY caller, because every publish is
//   `Locality::Remote` (see `put_options`) and `z_put` stages no loopback fire.
//   That is pico's default build, whose callbacks run on its read task alone.
// - With `local-subscriber`, a session's own put also delivers to its own
//   subscriber inside the call, on the calling thread, while the drive task may
//   be delivering a peer's sample to the same subscriber. pico does exactly
//   that: `_z_session_deliver_push_locally` runs on the thread that called
//   `z_put`, and `_z_trigger_subscriptions_impl` calls the callback after
//   releasing the session mutex (`vendor/zenoh-pico/src/session/subscription.c`
//   @ `sub_info->_callback(&sample, sub_info->_arg);`), so the read task can be
//   in the same callback at once. A program built with that switch is written
//   for it; what it shares between the two calls is its own to guard, as it is
//   against pico.
//
// `drop` runs only when the last `Arc` is released, which cannot overlap a live
// `call` (a running callback holds a reference).
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
#[cfg(feature = "liveliness")]
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
        let _in_callback = crate::ffi::InCallback::enter();
        let _ = crate::ffi::catch(|| unsafe {
            call(sample_ptr, ctx);
        });
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
        // SAFETY: the marshal is dropped at the end of this call, inside the borrow of `view`.
        let mut marshal = unsafe { SampleMarshal::lent(view) };
        // Bind AFTER the move out of `lent` — the marshal is at its final
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
        let _in_callback = crate::ffi::InCallback::enter();
        let _ = crate::ffi::catch(|| unsafe {
            call(sample_ptr, ctx);
        });
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
        return core::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    if marshal.attachment.is_none() {
        return core::ptr::null();
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
        return core::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    if marshal.encoding.is_none() {
        return core::ptr::null();
    }
    &marshal.loaned_encoding as *const crate::encoding::z_loaned_encoding_t
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
        return core::ptr::null();
    }
    let marshal = &*(sample as *const SampleMarshal);
    match marshal.timestamp.as_ref() {
        Some(ts) => ts as *const z_timestamp_t,
        None => core::ptr::null(),
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

/// The wall clock as an NTP64 word, through the host's [`EpochSource`]: the tokio engine's
/// runtime's where that engine is built in, the cooperative engine's host's otherwise (the
/// process's on a host, the board's in a Zephyr image). A clock set before 1970, or a board that
/// does not know the date yet, reads as the epoch itself.
///
/// [`EpochSource`]: wz_session_core::epoch::EpochSource
fn wall_clock_ntp64() -> u64 {
    #[cfg(feature = "engine-tokio")]
    {
        wz_capi_core::runtime::timestamp_source::wall_clock_ntp64()
    }
    #[cfg(not(feature = "engine-tokio"))]
    {
        use wz_session_core::epoch::EpochSource;
        crate::coop_host::epoch()
            .try_now_ntp64()
            .map_or(0, |ntp| ntp.as_word())
    }
}

/// Mint a timestamp from a session's clock and zid (pico `z_timestamp_new`).
///
/// pico's reads the time since the epoch, gives it when it is later than the last time the session
/// gave and the last plus one otherwise, and pairs it with the session's zid
/// (`vendor/zenoh-pico/src/api/api.c` @ `z_result_t z_timestamp_new(`); it applies no policy, and
/// fails only when the time cannot be read or the session already gave the greatest time there is
/// (`Z_ERR_TIMESTAMP_GENERATION_FAILED`). This reads one of two clocks and then applies pico's rule
/// through the session's last time given:
///
/// - with a registered clock, the session's node clock, which reads that clock and applies no
///   stamping policy: the `clock-quality-stamping` policy is the stamper's (the data the node
///   stamps), not a program's that asks for the time;
/// - with nothing registered, the wall clock.
///
/// A program may register a clock and remove it while the session is open, so one session's stamps
/// can come from both; the one last time given is what keeps them strictly increasing across that,
/// as pico's keeps them across a clock that steps back. The session's advanced publisher stamps its
/// samples through the same last time given, as pico's stamps them with this function, and the
/// session's node clock learns every time given (`SessionTime`).
#[no_mangle]
pub unsafe extern "C" fn z_timestamp_new(
    ts: *mut z_timestamp_t,
    zs: *const z_loaned_session_t,
) -> ZResult {
    guarded(|| {
        if ts.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_handle(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        // pico clears the timestamp before it reads the clock, so one it refuses is not valid.
        *ts = z_timestamp_t {
            valid: false,
            id: crate::zid::z_id_t::empty(),
            time: 0,
        };
        // A registered clock that cannot say what time it is leaves no time to give: pico's own
        // answer to a time it cannot read, and the system clock is not the fallback of a clock the
        // program chose.
        #[cfg(feature = "clock-source")]
        let reading = if wz_node_time::clock_registry::GLOBAL.is_empty() {
            Some(wall_clock_ntp64())
        } else {
            clock_reading(&state.ext.hlc)
        };
        #[cfg(not(feature = "clock-source"))]
        let reading = Some(wall_clock_ntp64());
        match session_timestamp(reading, &state.ext.time, state.drive.zid()) {
            Ok(given) => {
                *ts = given;
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// What [`z_timestamp_new`] gives a session whose times given are `session_time` and whose id is
/// `zid`, for a clock that reads `reading` (`None` when it cannot say what time it is): pico's rule
/// (`vendor/zenoh-pico/src/api/api.c` @ `if (time > s->_last_timestamp) {`), with pico's codes for
/// a time that cannot be read and for a session with no greater time left to give.
fn session_timestamp(
    reading: Option<u64>,
    session_time: &crate::last_timestamp::SessionTime,
    zid: [u8; crate::zid::Z_ID_SIZE],
) -> Result<z_timestamp_t, ZResult> {
    let reading = reading.ok_or(Z_ERR_GENERIC)?;
    let time = session_time
        .give(reading)
        .ok_or(Z_ERR_TIMESTAMP_GENERATION_FAILED)?;
    Ok(z_timestamp_t {
        valid: true,
        id: crate::zid::z_id_t { id: zid },
        time,
    })
}

#[cfg(test)]
mod session_timestamp_tests {
    use super::session_timestamp;
    use crate::last_timestamp::SessionTime;
    use crate::result::{Z_ERR_GENERIC, Z_ERR_TIMESTAMP_GENERATION_FAILED};

    const ZID: [u8; crate::zid::Z_ID_SIZE] = [0x3a; crate::zid::Z_ID_SIZE];

    fn time_of(reading: Option<u64>, last: &SessionTime) -> u64 {
        match session_timestamp(reading, last, ZID) {
            Ok(given) => {
                assert!(given.valid, "a given timestamp is valid");
                assert_eq!(given.id.id, ZID, "and carries the session's zid");
                given.time
            }
            Err(code) => panic!("refused with {code}"),
        }
    }

    /// The wall clock reads the same word twice (two calls within its resolution): the second
    /// stamp is the first plus one, not a duplicate.
    #[test]
    fn a_wall_clock_that_reads_the_same_twice_gives_strictly_increasing_stamps() {
        let last = SessionTime::new();
        let wall = 0x6900_0000_8000_0000;
        let first = time_of(Some(wall), &last);
        let second = time_of(Some(wall), &last);
        assert_eq!(first, wall);
        assert_eq!(second, wall + 1);
    }

    /// A registered clock ahead of the wall clock is removed while the session is open: the wall
    /// clock's next reading is behind the last stamp, and the stamp goes on from the last one
    /// given rather than back to the wall clock.
    #[test]
    fn a_stamp_after_a_clock_ahead_is_removed_does_not_go_back() {
        let last = SessionTime::new();
        let wall = 0x6900_0000_0000_0000;
        let registered = 0xEE6B_2800_0000_0010;
        assert_eq!(time_of(Some(wall), &last), wall);
        assert_eq!(time_of(Some(registered), &last), registered);
        assert_eq!(time_of(Some(wall + 5), &last), registered + 1);
    }

    /// A clock that cannot say what time it is gives no stamp, with pico's generic code, and
    /// leaves the last time given as it was.
    #[test]
    fn a_clock_that_cannot_be_read_is_refused_and_moves_nothing() {
        let last = SessionTime::new();
        assert_eq!(time_of(Some(50), &last), 50);
        assert_eq!(
            session_timestamp(None, &last, ZID).err(),
            Some(Z_ERR_GENERIC)
        );
        assert_eq!(time_of(Some(50), &last), 51);
    }

    /// A session that gave the greatest time there is has none greater to give, and says so with
    /// pico's own code.
    #[test]
    fn a_session_with_no_greater_time_left_is_refused_with_picos_code() {
        let last = SessionTime::new();
        assert_eq!(time_of(Some(u64::MAX), &last), u64::MAX);
        assert_eq!(
            session_timestamp(Some(u64::MAX), &last, ZID).err(),
            Some(Z_ERR_TIMESTAMP_GENERATION_FAILED)
        );
    }
}

/// A program's stamps (`z_timestamp_new`) and the session's advanced publisher's are one order:
/// both pass through the session's last time given, which the node clock learns.
#[cfg(all(test, feature = "advanced"))]
mod one_session_time_tests {
    use alloc::vec::Vec;

    use wz_node_time::node_clock::{NodeHlc, TimestampingEnabled};
    use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};
    use wz_session_core::ntp64::Ntp64;
    use wz_session_core::WhatAmI;

    use super::session_timestamp;
    use crate::last_timestamp::SessionTime;

    const ZID: [u8; crate::zid::Z_ID_SIZE] = [0x4b; crate::zid::Z_ID_SIZE];

    /// The seconds the session's node clock reads.
    const CLOCK_SECS: u64 = 1_000_000;

    /// A clock of the program's that stands still, so every step forward is the clocks' order and
    /// not time passing.
    struct StandingClock;

    impl EpochSource for StandingClock {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            Ok(SinceEpoch {
                secs: CLOCK_SECS,
                nanos: 0,
            })
        }
    }

    fn node_clock() -> NodeHlc {
        NodeHlc::for_node_over_source_by(
            &ZID,
            WhatAmI::Peer,
            TimestampingEnabled::all(true),
            StandingClock,
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        )
        .with_trusted_only_stamping(false)
    }

    /// What `z_timestamp_new` gives for a clock that reads `reading`.
    fn program(reading: Option<u64>, time: &SessionTime) -> u64 {
        session_timestamp(reading, time, ZID)
            .expect("the program is given a time")
            .time
    }

    /// What the advanced publisher stamps a sample with: the node clock's proposal, as the
    /// composite takes it, ordered as the pico plane orders it. Both words, the proposal first.
    fn sample(hlc: &NodeHlc, time: &SessionTime) -> (u64, u64) {
        let proposed = hlc.stamp().expect("a clock under `always` stamps").time;
        let given = time
            .order_data_stamp(proposed)
            .expect("the session has time left");
        (proposed, given)
    }

    /// A session that already gave the greatest time there is refuses a sample, as pico refuses
    /// the put whose `z_timestamp_new` failed.
    #[test]
    fn a_session_with_no_time_left_refuses_a_sample() {
        let hlc = node_clock();
        let time = SessionTime::new().learned_by(hlc.clone());
        assert_eq!(program(Some(u64::MAX), &time), u64::MAX);
        let proposed = hlc.stamp().expect("a clock under `always` stamps").time;
        assert_eq!(
            time.order_data_stamp(proposed),
            Err(wz_session_core::publish_options::PublishError::TimestampExhausted)
        );
    }

    /// A program stamp from the wall clock, a sample, a program stamp from the node clock (a
    /// registered clock is read through it), the wall clock again far behind once the clock is
    /// removed, and a sample: each strictly after the one before, and each sample is the node
    /// clock's own proposal, because the clock learned every program stamp before it.
    #[test]
    fn a_programs_and_a_publishers_stamps_are_one_order_across_a_change_of_clock() {
        let hlc = node_clock();
        let time = SessionTime::new().learned_by(hlc.clone());
        let clock = Ntp64::from_unix(CLOCK_SECS, 0).as_word();
        let within_bound = hlc.max_delta_word().expect("the node holds a clock") / 2;

        let p1 = program(Some(clock + within_bound), &time);
        assert_eq!(p1, clock + within_bound, "the wall clock, as it reads");
        let (proposed, d1) = sample(&hlc, &time);
        assert!(
            proposed > p1,
            "the node clock learned the program's stamp: {proposed} after {p1}"
        );
        assert_eq!(d1, proposed, "and the sample carries the clock's own time");

        let p2 = program(hlc.clock_stamp().map(|stamp| stamp.time), &time);
        assert!(
            p2 > d1,
            "the node clock read for the program: {p2} after {d1}"
        );

        let p3 = program(Some(clock - 3_600 * (1u64 << 32)), &time);
        assert_eq!(p3, p2 + 1, "the wall clock is behind: the stamp goes on");
        let (proposed, d2) = sample(&hlc, &time);
        assert!(
            proposed > p3,
            "the node clock learned that stamp too: {proposed} after {p3}"
        );
        assert_eq!(d2, proposed);
    }

    /// A time the node clock cannot learn (further ahead of its reading than it accepts) still
    /// orders the next sample: the last time given steps in where the clock could not.
    #[test]
    fn a_sample_after_a_stamp_the_clock_could_not_learn_still_comes_after_it() {
        let hlc = node_clock();
        let time = SessionTime::new().learned_by(hlc.clone());
        let clock = Ntp64::from_unix(CLOCK_SECS, 0).as_word();
        let beyond_bound = hlc.max_delta_word().expect("the node holds a clock") * 4;

        let p1 = program(Some(clock + beyond_bound), &time);
        let (proposed, d1) = sample(&hlc, &time);
        assert!(proposed < p1, "the clock did not learn it: {proposed} {p1}");
        assert_eq!(d1, p1 + 1);
    }

    /// Programs and publishers stamping one session from threads of their own are each given
    /// times no other stamp of the session has, and each thread's own go forward.
    #[test]
    fn programs_and_publishers_on_threads_are_given_distinct_increasing_times() {
        const EACH: usize = 1_000;
        let hlc = node_clock();
        let time = SessionTime::new().learned_by(hlc.clone());
        let wall = Ntp64::from_unix(CLOCK_SECS, 0).as_word();
        let mut threads = Vec::new();
        for _ in 0..4 {
            let program_time = time.clone();
            threads.push(std::thread::spawn(move || {
                (0..EACH)
                    .map(|_| program(Some(wall), &program_time))
                    .collect::<Vec<u64>>()
            }));
            let sample_time = time.clone();
            let publisher = hlc.clone();
            threads.push(std::thread::spawn(move || {
                (0..EACH)
                    .map(|_| sample(&publisher, &sample_time).1)
                    .collect::<Vec<u64>>()
            }));
        }
        let mut all = Vec::new();
        for thread in threads {
            let mine = thread.join().expect("the stamping thread ends");
            assert!(
                mine.windows(2).all(|pair| pair[0] < pair[1]),
                "one thread's stamps go forward"
            );
            all.extend(mine);
        }
        all.sort_unstable();
        assert!(
            all.windows(2).all(|pair| pair[0] < pair[1]),
            "no two stamps of the session are the same time"
        );
        assert_eq!(all.len(), 8 * EACH);
    }
}

/// What [`z_timestamp_new`] reads, before the session's last time given is applied, when a clock is
/// registered: the session's node clock's next time, with no stamping policy applied, or `None`
/// when the clock cannot say what time it is.
#[cfg(feature = "clock-source")]
fn clock_reading(hlc: &wz_node_time::node_clock::NodeHlc) -> Option<u64> {
    hlc.clock_stamp().map(|stamp| stamp.time)
}

#[cfg(all(test, feature = "clock-source"))]
mod clock_reading_tests {
    use wz_node_time::node_clock::{NodeHlc, TimestampingEnabled};
    use wz_node_time::timestamp_source::SystemEpoch;
    use wz_session_core::WhatAmI;

    use super::clock_reading;

    /// A node whose clock is not trusted stamps none of its data under `trusted-only`, and a
    /// program that asks for the time is given the clock's all the same: one clock, so what the
    /// program is given and what the node stamps once the clock is trusted interleave.
    #[test]
    fn a_trusted_only_session_gives_a_program_the_time_of_the_clock_it_stamps_data_with() {
        let zid = [0x5c; crate::zid::Z_ID_SIZE];
        let hlc = NodeHlc::for_node_over_source_by(
            &zid,
            WhatAmI::Peer,
            TimestampingEnabled::all(true),
            SystemEpoch,
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        )
        .with_trusted_only_stamping(true);
        assert!(
            hlc.stamp().is_none(),
            "no reference reported: no data is stamped"
        );
        let first = clock_reading(&hlc).expect("the program is given the time");
        assert!(hlc.report_sync_acquired());
        let stamped = hlc.stamp().expect("a trusted clock stamps data").time;
        let second = clock_reading(&hlc).expect("and given it again");
        assert!(
            first < stamped && stamped < second,
            "one clock: {first} {stamped} {second}"
        );
    }

    /// A node that holds no clock has no time to give from it.
    #[test]
    fn a_session_with_no_clock_gives_no_time_from_it() {
        assert!(clock_reading(&NodeHlc::disabled()).is_none());
    }
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
    #[cfg(feature = "unstable-api")]
    pub source_info: *mut z_source_info_t,
}

unstable_option_fields!(z_publisher_put_options_t {
    source_info: *mut z_source_info_t = core::ptr::null_mut(),
});

/// Fill default publisher-put options (pico `z_publisher_put_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put_options_default(options: *mut z_publisher_put_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_put_options_t {
        encoding: core::ptr::null_mut(),
        timestamp: core::ptr::null_mut(),
        attachment: core::ptr::null_mut(),
        #[cfg(feature = "unstable-api")]
        source_info: core::ptr::null_mut(),
    };
}

// --- publisher -------------------------------------------------------------

/// A pico publisher with no C handle around it: a key, the declaration made for
/// it, the write filter and the entity id.
///
/// The part of `z_declare_publisher` that is the PUBLISHER, separated from the
/// part that is a handle handed to C (`PublisherState`). The split is what lets
/// a composite declare its publishers the way pico does — an advanced publisher
/// is a `z_declare_publisher` and another one for its beacon
/// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `_Z_RETURN_IF_ERR(z_declare_publisher(zs, &pub->_val._publisher, keyexpr, &opt.publisher_options));`)
/// — without building a C handle it never hands out, and lets it keep them on a
/// task, which a value holding raw pointers into its own storage cannot do.
pub(crate) struct PlainPublisher {
    shared: Arc<Engine>,
    /// R2962 — pico's write filter for this publisher: the Interest it asks its
    /// peers, and the state that decides whether a put or delete is SENT.
    /// Declared BEFORE `key`, so it drops first: the Interest is retracted while
    /// the declaration it names still stands, which is upstream's order
    /// (`_z_undeclare_publisher` clears the filter, then the key).
    filter: WriteFilter,
    /// R2959 — the publisher's key WITH the declaration pico makes for it:
    /// `_z_declare_publisher` runs `_z_declared_keyexpr_declare` on the key
    /// (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `_Z_CLEAN_RETURN_IF_ERR(_z_declared_keyexpr_declare(zn, &publisher->_key, keyexpr),`),
    /// and every put then rides the declared id. Dropping the state drops the
    /// key, which retracts the declaration AFTER the publisher itself is gone —
    /// upstream's order.
    key: DeclaredKeyexpr,
    /// R311y559 — the `eid` half of the global id `z_publisher_id` reports,
    /// allocated ONCE at declare from the session's entity counter. See
    /// `SharedSession::next_entity_id` for why it is allocated rather than
    /// derived. Only the unstable API reports it, so only `unstable-api` keeps it.
    #[cfg(feature = "unstable-api")]
    eid: wz_session_core::wire_id::EntityId,
    /// What it was declared with, applied to every put and delete it makes
    /// ([`PublisherQos`]).
    declared: PublisherQos,
    /// The facts a put that brings nothing of its own is sent from, worked out ONCE
    /// at declare from the QoS above ([`PublishOptions::plain_put_params`]), and the
    /// id the key is named by when its declaration covers the whole key. Both
    /// `Some` is what lets [`PlainPublisher::publish_plain`] skip the per-put clone
    /// of the options and the per-put look-up of the key's wire form.
    plain: Option<(
        wz_session_core::publish_options::PlainPutParams,
        wz_session_core::wire_id::ExprId,
    )>,
}

/// What a pico publisher is declared with, and sends with on every put and
/// delete it makes: its default encoding, congestion control, priority, express
/// flag and reliability.
///
/// pico stores them in the publisher at declare
/// (`vendor/zenoh-pico/src/net/primitives.c` @
/// `publisher->_congestion_control = congestion_control;`) and `z_publisher_put`
/// and `z_publisher_delete` send with THOSE (`vendor/zenoh-pico/src/api/api.c` @
/// `ret = _z_write(session, &pub->_key, payload_bytes, &encoding, Z_SAMPLE_KIND_PUT, pub->_congestion_control,`):
/// the put and delete options carry a timestamp, an attachment and a source
/// info, and no priority, no congestion control, no express flag and no
/// reliability, so there is nothing else for a publisher's QoS to come from. The
/// encoding is the one exception, a put's own encoding winning when it has one.
///
/// The publisher owns the values rather than each caller composing them into the
/// options it passes, so an advanced publisher, which pico builds out of a plain
/// one, cannot send a publisher's samples with different QoS than the publisher
/// it wraps.
#[derive(Clone, Debug)]
pub(crate) struct PublisherQos {
    encoding: Option<wz_session_core::sample::EncodingHint>,
    congestion_control: wz_session_core::qos::CongestionControl,
    priority: wz_session_core::qos::Priority,
    is_express: bool,
    reliability: Reliability,
    /// Where its samples may go: `allowed_destination` with `local-subscriber`
    /// (`publisher->_allowed_destination` upstream), remote only without it.
    destination: Locality,
}

impl PublisherQos {
    /// pico's `z_publisher_options_default`, which is what a NULL options
    /// pointer means (`vendor/zenoh-pico/src/api/api.c` @
    /// `z_publisher_options_default(&opt);`) and what the heartbeat publisher of
    /// an advanced publisher is declared with.
    pub(crate) fn pico_default() -> Self {
        Self {
            encoding: None,
            congestion_control: push_congestion_from_pico(crate::qos::Z_CONGESTION_CONTROL_DROP),
            priority: crate::qos::priority_from_pico(crate::qos::Z_PRIORITY_DEFAULT),
            is_express: false,
            reliability: reliability_from_pico(Z_RELIABILITY_RELIABLE),
            destination: crate::locality::default_locality!("local-subscriber"),
        }
    }

    /// Whether the publisher's write filter and matching status count the session's
    /// own subscribers: pico's `ctx->allow_local`, which only a publisher whose
    /// destination admits session-local traffic has.
    pub(crate) fn counts_local(&self) -> bool {
        self.destination.allows_local()
    }

    /// What one C `z_publisher_options_t` declares, consuming its moved
    /// encoding: pico steals it at declare (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `publisher->_encoding = encoding == NULL ? _z_encoding_null() : _z_encoding_steal(encoding);`),
    /// so the caller's slot is empty afterwards whatever else the declare does. A
    /// NULL pointer is the default.
    ///
    /// # Safety
    /// `options` must be null or a valid publisher-options struct.
    pub(crate) unsafe fn declared_by(options: *const z_publisher_options_t) -> Self {
        if options.is_null() {
            return Self::pico_default();
        }
        let options = &*options;
        Self {
            encoding: crate::encoding::take_moved_encoding(options.encoding),
            congestion_control: push_congestion_from_pico(options.congestion_control),
            priority: crate::qos::priority_from_pico(options.priority),
            is_express: options.is_express,
            reliability: reliability_from_pico(options.reliability()),
            destination: options.allowed_destination(),
        }
    }

    /// `opts` as this publisher sends it: its QoS on top of whatever the call
    /// carried, and its encoding when the call carried none.
    fn apply(&self, opts: &PublishOptions) -> PublishOptions {
        let mut out = opts
            .clone()
            .with_priority(self.priority)
            .with_congestion_control(self.congestion_control)
            .with_express(self.is_express)
            .with_reliability(self.reliability)
            .with_locality(self.destination);
        if out.encoding.is_none() {
            if let Some(encoding) = self.encoding.clone() {
                out = out.with_encoding(encoding);
            }
        }
        out
    }
}

impl PlainPublisher {
    /// Declare a publisher on `keyexpr`: its key's declaration, then the write
    /// filter that names it — pico's order in `z_declare_publisher`.
    ///
    /// `existing` is the caller's own key when it is already a declaration
    /// (`declared_of`), which is shared rather than declared again. `declared` is
    /// what the publisher then sends every sample with.
    pub(crate) fn declare(
        session: &PicoSession,
        keyexpr: &str,
        existing: Option<&DeclaredKeyexpr>,
        declared: PublisherQos,
    ) -> Result<Self, ZResult> {
        let key = DeclaredKeyexpr::declare(&session.engine, keyexpr, existing)?;
        // The publisher's entity id comes off the session's one counter before its filter's
        // Interest takes the next, whether or not this build reports the id: pico's
        // `_z_declare_publisher` takes it (`vendor/zenoh-pico/src/net/primitives.c` @
        // `publisher->_id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`) before `z_declare_publisher`
        // creates the filter, and a group the Interest goes to reads the id. A session that
        // has handed out every id refuses the publisher with the code a refused declaration
        // gets here.
        let eid = session.engine.next_entity_id().ok_or(Z_ERR_GENERIC)?;
        #[cfg(not(feature = "unstable-api"))]
        let _ = eid;
        // R2962 — the filter is created AFTER the key, because its Interest names
        // the key's declaration (pico's order: `_z_declared_keyexpr_declare`, then
        // `_z_write_filter_create`, in `z_declare_publisher`).
        let filter = WriteFilter::declare(
            session,
            FilterPlane::Subscribers,
            &key,
            declared.counts_local(),
        )?;
        let plain = declared
            .apply(&put_options())
            .plain_put_params()
            .zip(key.whole_key_mapping(Arc::as_ref(&session.engine)));
        Ok(Self {
            #[cfg(feature = "unstable-api")]
            eid,
            shared: session.engine.clone(),
            filter,
            key,
            declared,
            plain,
        })
    }

    /// [`Self::publish`] for a put that brings no options of its own: sent from the
    /// facts worked out at declare when this publisher has them, and through the
    /// general path when it has not, or when this node's own subscriber wants the
    /// put or a face stamps what it sends (`put_plain_declared` answers `None`
    /// then, with nothing sent).
    pub(crate) fn publish_plain(&self, payload: &[u8]) -> ZResult {
        // pico's session check comes first, before the write filter
        // (`_z_publisher_put_impl`, `Z_FEATURE_SESSION_CHECK`).
        if self.shared.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let Some((params, mapping)) = &self.plain else {
            return self.publish(payload, &put_options());
        };
        match self
            .filter
            .put_plain(self.key.literal(), *mapping, payload, params)
        {
            FilteredPut::Suppressed => Z_OK,
            FilteredPut::Sent(sent) => publish_code(sent),
            // Nothing was sent, and the put is wanted: the filter said so, or the session holds
            // a multicast group the filter does not hold the put back from.
            FilteredPut::NotPlain => self.publish_filtered(payload, &put_options()),
        }
    }

    /// Publish on this publisher's key, in its declared wire form and with the
    /// QoS it was declared with ([`PublisherQos`]) — unless its write filter says
    /// nothing matches, in which case NOTHING is sent and the call still answers
    /// `Z_OK`, as `z_publisher_put` / `z_publisher_delete` do upstream
    /// (`vendor/zenoh-pico/src/api/api.c` @
    /// `!_z_write_filter_active(&pub->_filter)`). A session that holds a multicast group
    /// sends whatever the filter says, as upstream's multicast transport does
    /// ([`WriteFilter::holds_back`]).
    pub(crate) fn publish(&self, payload: &[u8], opts: &PublishOptions) -> ZResult {
        // A put or a delete on a publisher whose session was closed answers
        // `_Z_ERR_SESSION_CLOSED`, as pico's do under `Z_FEATURE_SESSION_CHECK` (on by
        // default), and before the write filter is consulted.
        if self.shared.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        if self.filter.holds_back() {
            return Z_OK;
        }
        self.publish_filtered(payload, opts)
    }

    /// [`Self::publish`] once the write filter has said the put is wanted.
    fn publish_filtered(&self, payload: &[u8], opts: &PublishOptions) -> ZResult {
        let wire = self.key.wire(Arc::as_ref(&self.shared));
        let opts = self.declared.apply(opts);
        publish_code(
            self.shared
                .publish_on_wire_all(self.key.literal(), &wire, payload, &opts),
        )
    }

    /// The `eid` half of the global id `z_publisher_id` reports.
    #[cfg(feature = "advanced")]
    pub(crate) fn entity_id(&self) -> wz_session_core::wire_id::EntityId {
        self.eid
    }

    /// The publisher's key with its declaration.
    #[cfg(feature = "advanced")]
    pub(crate) fn key(&self) -> &DeclaredKeyexpr {
        &self.key
    }

    /// pico's matching status of the publisher: whether its write filter has a match
    /// (`!_z_write_filter_active`).
    pub(crate) fn filter_matches(&self) -> bool {
        !self.filter.active()
    }

    /// The publisher's write filter: its matching listeners are declared on it
    /// ([`WriteFilter::declare_matching_listener`]), and it retracts them when the publisher
    /// goes, as pico's filter takes its callbacks with it at `z_undeclare_publisher`.
    pub(crate) fn filter(&self) -> &WriteFilter {
        &self.filter
    }
}

/// Behind a `z_owned_publisher_t` handle: a keyexpr bound to the session's
/// face registry, so a put fans out to every connected peer.
pub(crate) struct PublisherState {
    core: PlainPublisher,
    /// R311y559 — cached loan of `key`, so `z_publisher_keyexpr` hands back a
    /// borrow of stable storage rather than of a temporary. Bound by
    /// [`PublisherState::bind`] once the state sits at its final address — the
    /// same discipline `QueryableState` and `SampleMarshal` use, and for the
    /// same reason. R2959 — it carries the declaration, as pico's loan of
    /// `&pub->_key` does, so a put on it aliases.
    loaned_keyexpr: z_loaned_keyexpr_t,
}

impl PublisherState {
    /// Point the cached view at this state's own keyexpr. MUST run only once
    /// the state sits at its FINAL address (i.e. after `Box::new`).
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr = self.core.key.loaned();
    }

    /// Publish on this publisher's key — [`PlainPublisher::publish`].
    fn publish(&self, payload: &[u8], opts: &PublishOptions) -> ZResult {
        self.core.publish(payload, opts)
    }

    /// [`Self::publish`] for a put that carries nothing of its own — [`PlainPublisher::publish_plain`].
    fn publish_plain(&self, payload: &[u8]) -> ZResult {
        self.core.publish_plain(payload)
    }

    /// The `eid` half of the global id `z_publisher_id` reports.
    #[cfg(feature = "unstable-api")]
    pub(crate) fn entity_id(&self) -> wz_session_core::wire_id::EntityId {
        self.core.eid
    }

    /// The SESSION's zid — the other half of that global id.
    #[cfg(feature = "unstable-api")]
    pub(crate) fn shared_zid(&self) -> [u8; 16] {
        self.core.shared.zid()
    }

    /// The cached borrow `z_publisher_keyexpr` hands back.
    pub(crate) fn loaned_keyexpr(&self) -> *const z_loaned_keyexpr_t {
        &self.loaned_keyexpr as *const z_loaned_keyexpr_t
    }

    /// pico's matching status: whether the write filter has a match, which is
    /// `!_z_write_filter_active`.
    pub(crate) fn filter_matches(&self) -> bool {
        self.core.filter_matches()
    }

    /// The publisher's write filter, which its matching listeners are declared on.
    pub(crate) fn filter(&self) -> &WriteFilter {
        self.core.filter()
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
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 3],
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
    pub(crate) shared: Arc<Engine>,
    pub(crate) id: SubId,
    /// R311y559 — the keyexpr this subscription was declared on, so
    /// `z_subscriber_keyexpr` has something to borrow. The registry keys the
    /// per-face replicas on `id` alone, so the string was not kept anywhere the
    /// handle could reach.
    ///
    /// R2959 — WITH the declaration pico makes for the subscription's own key:
    /// the non-wild prefix for an ordinary subscriber, the whole key for a
    /// liveliness one (see the two declare sites). Dropping the state retracts
    /// it after the subscription, which is upstream's order.
    pub(crate) key: DeclaredKeyexpr,
    /// R311y559 — cached loan of `key`; see [`PublisherState::bind`].
    pub(crate) loaned_keyexpr: z_loaned_keyexpr_t,
    /// Opens when the subscriber's closure has run its `drop(context)`. An undeclare waits on it
    /// after the engine let go, so it returns only when no callback is still running (pico's
    /// `_z_sync_group_wait`), and the program may free what the callback reads.
    pub(crate) released: Arc<crate::ffi::ReleaseLatch>,
}

impl SubscriberState {
    /// Point the cached view at this state's own keyexpr, after boxing.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr = self.key.loaned();
    }
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        self.shared.undeclare_subscriber(self.id);
        self.released.wait();
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
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 3],
        }
    }
}

// --- publisher / subscriber ownership families (the pico 7-fn no-copy set) --
//
// pico exposes both `z_undeclare_*` (the RAII teardown, below) and the generic
// `z_*_drop`; either consumes the moved handle and nulls the source, so a
// defensive double-call is a safe no-op.

/// # Safety
/// `h` must be a live `PublisherState` handle.
unsafe fn free_publisher(h: *mut c_void) {
    crate::object_slot::release(h as *mut PublisherState);
}
/// # Safety
/// `h` must be a live `SubscriberState` handle.
unsafe fn free_subscriber(h: *mut c_void) {
    crate::object_slot::release(h as *mut SubscriberState);
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

/// Take a moved payload's bytes, nulling the source: `Ok(None)` for a null one.
///
/// Ownership is decided by the value's own borrow tag rather than assumed. An
/// ORDINARY owned bytes — everything a wz constructor produces — is reclaimed
/// from its place. A BORROWED one is CLONED and its storage left alone, because
/// the only way a C program obtains one is by reading `sample->payload` out of a
/// marshal that still owns it, and that marshal frees it when the callback
/// returns. Freeing it here is the double free this tag exists to prevent; see
/// [`crate::abi::HandleOwnership`]. A clone of a payload the marshal reads where it lies is a
/// copy, which can be refused for want of room (`Err`).
///
/// Every arm nulls the source, so pico's consume-on-all-paths contract holds
/// either way: after this call the caller's `z_owned_bytes_t` is spent.
///
/// # Safety
/// `payload` must be null or a valid `z_moved_bytes_t` whose handle is a live
/// payload a constructor of this crate placed, or a BORROW of a live `ByteBuf`.
pub(crate) unsafe fn take_moved_bytes(
    payload: *mut z_moved_bytes_t,
) -> Result<Option<ByteBuf>, NoRoom> {
    if payload.is_null() {
        return Ok(None);
    }
    let handle = (*payload)._this.handle;
    if handle.is_null() {
        return Ok(None);
    }
    let borrowed = crate::abi::HandleOwnership::handle_is_borrowed(&(*payload)._this);
    (*payload)._this = z_owned_bytes_t::null_value();
    if borrowed {
        (*(handle as *const ByteBuf)).try_clone().map(Some)
    } else {
        Ok(Some(crate::bytes::unbox_bytes(handle as *mut ByteBuf)))
    }
}

/// Consume a moved payload without reading it, nulling the source: what an option whose bytes the
/// wire does not carry is owed. A borrowed payload is its marshal's, and is left to it.
///
/// # Safety
/// As [`take_moved_bytes`].
pub(crate) unsafe fn drop_moved_bytes(payload: *mut z_moved_bytes_t) {
    if payload.is_null() {
        return;
    }
    let handle = (*payload)._this.handle;
    if handle.is_null() {
        return;
    }
    let borrowed = crate::abi::HandleOwnership::handle_is_borrowed(&(*payload)._this);
    (*payload)._this = z_owned_bytes_t::null_value();
    if !borrowed {
        drop(crate::bytes::unbox_bytes(handle as *mut ByteBuf));
    }
}

/// Take a moved payload's bytes as a `Vec`, nulling the source: what an option that carries an
/// attachment reads, which is copied into the options it builds. A borrowed payload is read where
/// its marshal holds it, which this call outlives, and copied nowhere else.
///
/// # Safety
/// As [`take_moved_bytes`].
pub(crate) unsafe fn take_moved_bytes_to_vec(payload: *mut z_moved_bytes_t) -> Option<Vec<u8>> {
    if payload.is_null() {
        return None;
    }
    let handle = (*payload)._this.handle;
    if handle.is_null() {
        return None;
    }
    let borrowed = crate::abi::HandleOwnership::handle_is_borrowed(&(*payload)._this);
    (*payload)._this = z_owned_bytes_t::null_value();
    if borrowed {
        Some((*(handle as *const ByteBuf)).to_vec())
    } else {
        Some(crate::bytes::unbox_bytes(handle as *mut ByteBuf).to_vec())
    }
}

/// Fold a caller's `z_publisher_put_options_t` into wz's [`PublishOptions`], or
/// `None` when it carries nothing: a NULL `options`, which is the plain default
/// as it is in pico, or one whose every field is empty. The put then sends from
/// what its publisher was declared with, and no options are built for it.
///
/// Consumes the moved `encoding` and `attachment` on EVERY path — pico's
/// ownership transfer is unconditional once the call is made.
///
/// R311y561 — `source_info` is READ now (see [`source_info_hint_of`]). It was
/// read-and-dropped with a stated reason: no exported constructor for a
/// `z_source_info_t` existed, so no C program could build one. `z_source_info_new`
/// landed in R311y559 and the reason expired with it.
///
/// # Safety
/// `options` must be null or a valid put-options struct.
unsafe fn publisher_put_options(
    options: *const z_publisher_put_options_t,
) -> Option<PublishOptions> {
    if options.is_null() {
        return None;
    }
    let (opts, carried) = PutCarried {
        encoding: (*options).encoding,
        timestamp: (*options).timestamp,
        attachment: (*options).attachment,
        source_info: (*options).source_info(),
    }
    .fold(put_options());
    carried.then_some(opts)
}

/// What a put's options carry beside its QoS, read the same way from `z_put_options_t` and
/// `z_publisher_put_options_t`: the moved encoding and attachment, the timestamp, and the source
/// info (null where the struct has no such field).
struct PutCarried {
    encoding: *mut c_void,
    timestamp: *mut z_timestamp_t,
    attachment: *mut z_moved_bytes_t,
    source_info: *mut z_source_info_t,
}

impl PutCarried {
    /// `opts` with what the options carry, and whether they carried anything. The moved encoding
    /// and attachment are consumed on every path. One body for both put doors, out of line so
    /// that neither export holds a copy of it.
    ///
    /// # Safety
    /// Each field must be null or valid as the options struct it was read from requires.
    #[inline(never)]
    unsafe fn fold(self, mut opts: PublishOptions) -> (PublishOptions, bool) {
        let attachment = take_moved_bytes_to_vec(self.attachment);
        let encoding = crate::encoding::take_moved_encoding(self.encoding);
        let timestamp = timestamp_hint_of(self.timestamp);
        let source_info = source_info_hint_of(self.source_info);
        let carried = attachment.is_some()
            || encoding.is_some()
            || timestamp.is_some()
            || source_info.is_some();
        if let Some(attachment) = attachment {
            opts = opts.with_attachment(attachment);
        }
        if let Some(hint) = encoding {
            opts = opts.with_encoding(hint);
        }
        if let Some(ts) = timestamp {
            opts = opts.with_timestamp(ts);
        }
        // A source info is read only where the option field exists, and the setter it reaches is
        // linked only there: without the unstable API the field is pico's absent value.
        #[cfg(feature = "unstable-api")]
        if let Some(si) = source_info {
            opts = opts.with_source_info(si);
        }
        (opts, carried)
    }
}

/// The options a put starts from: reliable, and the destination
/// `z_put_options_default` gives, which is what a NULL options pointer means.
///
/// The destination is `Locality::Remote` without `local-subscriber`: a pico session's
/// own put reaches its own subscribers only through `_z_session_deliver_push_locally`,
/// which `_z_write` calls only when `Z_FEATURE_LOCAL_SUBSCRIBER` compiles it in
/// (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_session_deliver_push_locally`). With the
/// switch it is `Any`, and the session's own subscribers are reached ONCE, through the
/// registry's local plane (faces take the remote half, the plane the local one), inside
/// the call and on the calling thread, which is where pico delivers them.
fn put_options() -> PublishOptions {
    let mut opts = PublishOptions::default()
        .with_reliability(Reliability::Reliable)
        .with_locality(crate::locality::default_locality!("local-subscriber"));
    opts.kind = SampleKind::Put;
    opts
}

#[cfg(test)]
mod put_options_tests {
    use super::{
        publisher_put_options, z_publisher_put_options_default, z_publisher_put_options_t,
        z_timestamp_t,
    };

    /// A publisher's put whose options carry nothing has no options built for it, NULL ones and
    /// default ones alike, and is sent from what its publisher was declared with; one whose
    /// options carry a timestamp has them built, the timestamp in them.
    #[test]
    fn put_options_that_carry_nothing_fold_to_none() {
        // SAFETY: each pointer handed over is null or points at a live value of its type, which
        // outlives the call.
        unsafe {
            assert!(publisher_put_options(core::ptr::null()).is_none());
            let mut options = core::mem::MaybeUninit::<z_publisher_put_options_t>::uninit();
            z_publisher_put_options_default(options.as_mut_ptr());
            let mut options = options.assume_init();
            assert!(
                publisher_put_options(&options).is_none(),
                "default options carry nothing"
            );
            let mut stamp = z_timestamp_t {
                valid: true,
                id: crate::zid::z_id_t {
                    id: [7; crate::zid::Z_ID_SIZE],
                },
                time: 42,
            };
            options.timestamp = &mut stamp;
            let carried = publisher_put_options(&options).expect("a timestamp is carried");
            assert_eq!(carried.timestamp.as_ref().map(|ts| ts.time), Some(42));
        }
    }

    /// Both put doors fold their options through one body: a moved attachment and a timestamp
    /// are carried into the options a session's put and a publisher's put are sent with, the QoS
    /// a session's put states beside them is kept, and the caller's moved bytes are spent.
    #[test]
    fn both_put_doors_carry_a_moved_attachment_and_spend_it() {
        use super::{session_put_options, z_put_options_default, z_put_options_t};
        use crate::abi::{z_moved_bytes_t, z_owned_bytes_t};
        let moved = |bytes: &[u8]| {
            let mut owned = z_owned_bytes_t::null_value();
            // SAFETY: `owned` is writable and `bytes` readable for its length.
            let copied = unsafe {
                crate::bytes::z_bytes_copy_from_buf(&mut owned, bytes.as_ptr(), bytes.len())
            };
            assert_eq!(copied, crate::result::Z_OK);
            z_moved_bytes_t { _this: owned }
        };
        let mut stamp = z_timestamp_t {
            valid: true,
            id: crate::zid::z_id_t {
                id: [7; crate::zid::Z_ID_SIZE],
            },
            time: 42,
        };
        // SAFETY: each pointer handed over is null or points at a live value of its type, which
        // outlives the call.
        unsafe {
            let mut attachment = moved(b"session");
            let mut put = core::mem::MaybeUninit::<z_put_options_t>::uninit();
            z_put_options_default(put.as_mut_ptr());
            let mut put = put.assume_init();
            put.attachment = &mut attachment;
            put.timestamp = &mut stamp;
            put.is_express = true;
            let carried = session_put_options(&put);
            assert_eq!(carried.attachment.as_deref(), Some(&b"session"[..]));
            assert_eq!(carried.timestamp.as_ref().map(|ts| ts.time), Some(42));
            assert_eq!(
                carried.qos.map(|qos| qos.is_express()),
                Some(true),
                "the QoS beside the carried values is kept"
            );
            assert!(attachment._this.handle.is_null(), "the attachment is spent");

            let mut attachment = moved(b"publisher");
            let mut options = core::mem::MaybeUninit::<z_publisher_put_options_t>::uninit();
            z_publisher_put_options_default(options.as_mut_ptr());
            let mut options = options.assume_init();
            options.attachment = &mut attachment;
            let carried = publisher_put_options(&options).expect("an attachment is carried");
            assert_eq!(carried.attachment.as_deref(), Some(&b"publisher"[..]));
            assert!(carried.timestamp.is_none());
            assert!(attachment._this.handle.is_null(), "the attachment is spent");
        }
    }

    /// With the unstable API a put's source info option is carried into the options it is sent
    /// with, and pico's all-zero value is carried as none.
    #[cfg(feature = "unstable-api")]
    #[test]
    fn a_source_info_option_is_carried_with_the_unstable_api() {
        use super::z_source_info_t;
        let mut info = z_source_info_t {
            _source_id: crate::entity::z_entity_global_id_t {
                zid: crate::zid::z_id_t {
                    id: [0xa1; crate::zid::Z_ID_SIZE],
                },
                eid: 0x5150,
            },
            _source_sn: 9001,
        };
        // SAFETY: each pointer handed over points at a live value of its type, which outlives
        // the call.
        unsafe {
            let mut options = core::mem::MaybeUninit::<z_publisher_put_options_t>::uninit();
            z_publisher_put_options_default(options.as_mut_ptr());
            let mut options = options.assume_init();
            options.source_info = &mut info;
            let carried = publisher_put_options(&options).expect("a source info is carried");
            let source = carried.source_info.expect("the source info");
            assert_eq!((source.eid, source.sn), (0x5150, 9001));
            assert_eq!(source.zid, [0xa1; 16]);
            let mut unset = z_source_info_t::empty();
            options.source_info = &mut unset;
            assert!(
                publisher_put_options(&options).is_none(),
                "pico's null source info is no source info"
            );
        }
    }

    /// Without the unstable API the option structs have no source info field, and the options
    /// a session's put and delete are sent with carry none.
    #[cfg(not(feature = "unstable-api"))]
    #[test]
    fn without_the_unstable_api_no_put_or_delete_carries_a_source_info() {
        use super::{
            session_delete_options, session_put_options, z_delete_options_default,
            z_delete_options_t, z_put_options_default, z_put_options_t,
        };
        // SAFETY: each pointer handed over is null or points at a live value of its type, which
        // outlives the call.
        unsafe {
            let mut put = core::mem::MaybeUninit::<z_put_options_t>::uninit();
            z_put_options_default(put.as_mut_ptr());
            let put = put.assume_init();
            assert!(session_put_options(&put).source_info.is_none());
            assert!(session_put_options(core::ptr::null()).source_info.is_none());
            let mut delete = core::mem::MaybeUninit::<z_delete_options_t>::uninit();
            z_delete_options_default(delete.as_mut_ptr());
            let delete = delete.assume_init();
            assert!(session_delete_options(&delete).source_info.is_none());
        }
    }
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
/// `allowed_destination` is ABSENT (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0), and the
/// `reliability` / `source_info` pair is present exactly when the build has
/// `unstable-api` (`Z_FEATURE_UNSTABLE_API` defined, as in the reference build;
/// undefined in upstream's default). Reading that off the cmake command line
/// instead of the generated header is the R311y466 trap.
#[repr(C)]
pub struct z_put_options_t {
    pub encoding: *mut c_void,
    pub congestion_control: crate::qos::z_congestion_control_t,
    pub priority: crate::qos::z_priority_t,
    pub timestamp: *mut z_timestamp_t,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
    #[cfg(feature = "local-subscriber")]
    pub allowed_destination: crate::locality::z_locality_t,
    #[cfg(feature = "unstable-api")]
    pub reliability: z_reliability_t,
    #[cfg(feature = "unstable-api")]
    pub source_info: *mut z_source_info_t,
}

crate::locality::locality_option_field!(z_put_options_t, allowed_destination, "local-subscriber");

// `source_info` has no accessor here: a session's put reads it only with `unstable-api`, where the
// field exists and is read as itself.
unstable_option_fields!(z_put_options_t {
    reliability: z_reliability_t = Z_RELIABILITY_RELIABLE,
});

/// pico `z_delete_options_t` (`api/types.h:413-425`).
///
/// No encoding and no attachment: a Del body carries neither, and upstream's
/// struct reflects that.
#[repr(C)]
pub struct z_delete_options_t {
    pub congestion_control: crate::qos::z_congestion_control_t,
    pub priority: crate::qos::z_priority_t,
    pub is_express: bool,
    pub timestamp: *mut z_timestamp_t,
    #[cfg(feature = "local-subscriber")]
    pub allowed_destination: crate::locality::z_locality_t,
    #[cfg(feature = "unstable-api")]
    pub reliability: z_reliability_t,
    #[cfg(feature = "unstable-api")]
    pub source_info: *mut z_source_info_t,
}

crate::locality::locality_option_field!(
    z_delete_options_t,
    allowed_destination,
    "local-subscriber"
);

// `source_info` is read only with `unstable-api`, as the put's is.
unstable_option_fields!(z_delete_options_t {
    reliability: z_reliability_t = Z_RELIABILITY_RELIABLE,
});

/// pico `z_publisher_delete_options_t` (`api/types.h:454-459`).
#[repr(C)]
pub struct z_publisher_delete_options_t {
    pub timestamp: *mut z_timestamp_t,
    #[cfg(feature = "unstable-api")]
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
        encoding: core::ptr::null_mut(),
        congestion_control: crate::qos::Z_CONGESTION_CONTROL_DROP,
        priority: crate::qos::Z_PRIORITY_DEFAULT,
        timestamp: core::ptr::null_mut(),
        is_express: false,
        attachment: core::ptr::null_mut(),
        #[cfg(feature = "local-subscriber")]
        allowed_destination: crate::locality::Z_LOCALITY_ANY,
        #[cfg(feature = "unstable-api")]
        reliability: Z_RELIABILITY_RELIABLE,
        #[cfg(feature = "unstable-api")]
        source_info: core::ptr::null_mut(),
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
        congestion_control: crate::qos::Z_CONGESTION_CONTROL_DROP,
        priority: crate::qos::Z_PRIORITY_DEFAULT,
        is_express: false,
        timestamp: core::ptr::null_mut(),
        #[cfg(feature = "local-subscriber")]
        allowed_destination: crate::locality::Z_LOCALITY_ANY,
        #[cfg(feature = "unstable-api")]
        reliability: Z_RELIABILITY_RELIABLE,
        #[cfg(feature = "unstable-api")]
        source_info: core::ptr::null_mut(),
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
        timestamp: core::ptr::null_mut(),
        #[cfg(feature = "unstable-api")]
        source_info: core::ptr::null_mut(),
    };
}

/// pico `z_reliability_t`, as wide as the target's C ABI makes it (`crate::c_enum`).
pub type z_reliability_t = crate::c_enum::PicoEnum;
/// pico `Z_RELIABILITY_RELIABLE`, its `Z_RELIABILITY_DEFAULT`.
pub const Z_RELIABILITY_RELIABLE: z_reliability_t = 0;
/// pico `Z_RELIABILITY_BEST_EFFORT`.
pub const Z_RELIABILITY_BEST_EFFORT: z_reliability_t = 1;

/// A caller's PUSH-side `z_congestion_control_t` as wz's.
///
/// Distinct from [`crate::qos::congestion_from_pico`] in ONE way, and it is
/// the reason this is not a call to that function: the two differ in what an
/// UNRECOGNISED value degrades to. pico's request-side default is BLOCK
/// (`z_get_options_default`) and its push-side default is DROP
/// (`z_put_options_default`), so each fallback has to be the default of the
/// plane it serves. The two recognised values agree, and the mapping is written
/// out rather than cast because the SIBLING zenoh-c ABI inverts them —
/// R311y545 paid for exactly that.
fn push_congestion_from_pico(
    c: crate::qos::z_congestion_control_t,
) -> wz_session_core::qos::CongestionControl {
    match c {
        crate::qos::Z_CONGESTION_CONTROL_BLOCK => wz_session_core::qos::CongestionControl::Block,
        _ => wz_session_core::qos::CongestionControl::Drop,
    }
}

/// A caller's `z_reliability_t` as wz's.
///
/// INVERTED against wz's own enum: pico spells `RELIABLE = 0` /
/// `BEST_EFFORT = 1` while wz is `BestEffort = 0` / `Reliable = 1`. Written
/// out for exactly that reason.
fn reliability_from_pico(r: z_reliability_t) -> Reliability {
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
) -> Option<wz_session_core::sample::TimestampHint> {
    if ptr.is_null() {
        return None;
    }
    let ts = &*ptr;
    if !ts.valid {
        return None;
    }
    Some(wz_session_core::sample::TimestampHint {
        time: ts.time,
        // The wire form strips trailing zeros; the codec re-pads.
        zid: ts.id.id.to_vec(),
    })
}

/// R311y561 — read a caller-supplied `z_source_info_t*` option field into a wz
/// [`SourceInfo`](wz_session_core::sample::SourceInfo). The INVERSE of
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
) -> Option<wz_session_core::sample::SourceInfo> {
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
    Some(wz_session_core::sample::SourceInfo::new(
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
/// `allowed_destination` is the struct's own with `local-subscriber`. Without it
/// the field is absent (see [`z_put_options_t`]) and the locality stays
/// [`put_options`]'s `Remote`: a default pico build does not deliver a session's
/// own put to its own subscriber, and there is no field through which a program
/// could ask it to.
///
/// # Safety
/// `options` must be null or a valid put-options struct.
unsafe fn session_put_options(options: *const z_put_options_t) -> PublishOptions {
    let opts = put_options();
    if options.is_null() {
        return opts;
    }
    // The moved values are consumed first, before anything else is read.
    #[cfg(feature = "unstable-api")]
    let source_info = (*options).source_info;
    #[cfg(not(feature = "unstable-api"))]
    let source_info = core::ptr::null_mut();
    let (opts, _) = PutCarried {
        encoding: (*options).encoding,
        timestamp: (*options).timestamp,
        attachment: (*options).attachment,
        source_info,
    }
    .fold(opts);
    opts.with_priority(crate::qos::priority_from_pico((*options).priority))
        .with_congestion_control(push_congestion_from_pico((*options).congestion_control))
        .with_express((*options).is_express)
        .with_reliability(reliability_from_pico((*options).reliability()))
        .with_locality((*options).allowed_destination())
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
        .with_priority(crate::qos::priority_from_pico((*options).priority))
        .with_congestion_control(push_congestion_from_pico((*options).congestion_control))
        .with_express((*options).is_express)
        .with_reliability(reliability_from_pico((*options).reliability()))
        .with_locality((*options).allowed_destination());
    if let Some(ts) = timestamp_hint_of((*options).timestamp) {
        opts = opts.with_timestamp(ts);
    }
    #[cfg(feature = "unstable-api")]
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
            Ok(Some(b)) => b,
            Ok(None) => return Z_ERR_NULL,
            Err(no_room) => return no_room.code(),
        };
        let state = match session_handle(zs) {
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
        // R2959 — the key's own wire form: its declaration's id plus the rest
        // of the key when it is this session's, which a PREFIX declaration now
        // makes a real case rather than only the whole-key one.
        let engine = engine_ref(state);
        let Some(wire) = wire_key_of(keyexpr, engine) else {
            return Z_ERR_INVALID;
        };
        publish_code(engine.publish_on_wire_all(ke, &wire, &buf, &resolved))
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
        let state = match session_handle(zs) {
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
        let engine = engine_ref(state);
        let Some(wire) = wire_key_of(keyexpr, engine) else {
            return Z_ERR_INVALID;
        };
        publish_code(engine.publish_on_wire_all(ke, &wire, &[], &resolved))
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
            #[cfg(feature = "unstable-api")]
            if let Some(si) = source_info_hint_of((*options).source_info) {
                opts = opts.with_source_info(si);
            }
        }
        state.publish(&[], &opts)
    })
}

// --- publisher exports -----------------------------------------------------

/// pico `z_publisher_options_t` (`api/types.h:236-247`), 24 B measured against
/// the CMake-GENERATED config these programs compile with.
///
/// The tail of this struct is FEATURE-CONDITIONAL in pico's header, so the
/// layout is a property of the generated `config.h`, not of the source tree:
/// `reliability` exists when the build has `unstable-api` (`Z_FEATURE_UNSTABLE_API`
/// defined, as in the reference build), and `allowed_destination` is ABSENT
/// because `Z_FEATURE_LOCAL_SUBSCRIBER` is 0.
/// Reading that off the cmake command line instead of the generated header is
/// the R311y466 trap; both were read off `config.h`, and the offsets are pinned
/// in this module's tests.
///
/// `z_declare_publisher` READS these fields and the publisher then sends every
/// put and delete with them (`PublisherQos`), as pico's does. The struct is
/// also what an advanced publisher's options embed
/// ([`crate::advanced::ze_advanced_publisher_options_t`]), so the two are one
/// layout.
#[repr(C)]
pub struct z_publisher_options_t {
    /// Moved default encoding, or NULL. Typed as an opaque pointer here because
    /// the moved wrapper is only ever read through
    /// `crate::encoding::take_moved_encoding`; the SLOT must exist and be 8 B
    /// wide or every field after it lands at the wrong offset.
    pub encoding: *mut c_void,
    pub congestion_control: crate::qos::z_congestion_control_t,
    pub priority: crate::qos::z_priority_t,
    pub is_express: bool,
    #[cfg(feature = "unstable-api")]
    pub reliability: z_reliability_t,
    #[cfg(feature = "local-subscriber")]
    pub allowed_destination: crate::locality::z_locality_t,
}

unstable_option_fields!(z_publisher_options_t {
    reliability: z_reliability_t = Z_RELIABILITY_RELIABLE,
});

crate::locality::locality_option_field!(
    z_publisher_options_t,
    allowed_destination,
    "local-subscriber"
);

/// Default publisher options (pico `z_publisher_options_default`,
/// `vendor/zenoh-pico/src/api/api.c` @
/// `options->congestion_control = z_internal_congestion_control_default_push();`).
///
/// No encoding, DROP, `Z_PRIORITY_DEFAULT` (Data, 5 — not the enum's zero, which
/// is pico's control priority), not express, reliable. The values used to be
/// written as "the enum's zero values", which was right for three of the four
/// and wrong for the priority; nothing showed it while the declare ignored them.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_options_default(options: *mut z_publisher_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_publisher_options_t {
        encoding: core::ptr::null_mut(),
        congestion_control: crate::qos::Z_CONGESTION_CONTROL_DROP,
        priority: crate::qos::Z_PRIORITY_DEFAULT,
        is_express: false,
        #[cfg(feature = "unstable-api")]
        reliability: Z_RELIABILITY_RELIABLE,
        #[cfg(feature = "local-subscriber")]
        allowed_destination: crate::locality::Z_LOCALITY_ANY,
    };
}

/// Declare a publisher (pico `z_declare_publisher`). Consumes the options'
/// moved encoding on every path once `publisher` is a valid out-parameter, as
/// pico's declare steals it before anything can fail.
#[no_mangle]
pub unsafe extern "C" fn z_declare_publisher(
    zs: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *const z_publisher_options_t,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_ERR_NULL;
        }
        // FIRST, before any early return could skip it: the moved encoding.
        let declared = PublisherQos::declared_by(options);
        let state = match session_handle(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let Some(ke) = keyexpr_str(keyexpr) else {
            return Z_ERR_INVALID;
        };
        // The publisher's place is taken before it is declared, so a full pool refuses the
        // declaration and nothing is declared.
        let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Publisher) else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        let core = match PlainPublisher::declare(
            &PicoSession::of(state),
            ke,
            declared_of(keyexpr),
            declared,
        ) {
            Ok(core) => core,
            Err(rc) => return rc,
        };
        let state = slot.fill(PublisherState {
            core,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
        });
        (*state).bind();
        *publisher = z_owned_publisher_t {
            handle: state as *mut c_void,
            _pad: [core::ptr::null_mut(); 3],
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
            Ok(Some(b)) => b,
            Ok(None) => return Z_ERR_NULL,
            Err(no_room) => return no_room.code(),
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
        match publisher_put_options(options) {
            Some(opts) => state.publish(&buf, &opts),
            None => state.publish_plain(&buf),
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
            crate::object_slot::release(handle as *mut PublisherState);
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

/// The wire form a subscriber on `keyexpr` is announced in: the CALLER's key
/// (see the declare site for why it is not the subscription's own), keeping
/// alive both the caller's declaration, if it named one, and the declaration
/// of the subscription's own `key` — the registry entry is the only holder a
/// background subscriber has. The key's text is not held: nothing reads it here.
///
/// # Safety
/// `keyexpr` must be null or a live loaned keyexpr.
unsafe fn subscriber_wire(
    keyexpr: *const z_loaned_keyexpr_t,
    shared: &Engine,
    key: &DeclaredKeyexpr,
) -> Option<WireKey> {
    let wire = wire_key_of(keyexpr, shared)?;
    let anchor: Arc<dyn Send + Sync> = Arc::new((
        key.declaration_hold(),
        declared_of(keyexpr).and_then(DeclaredKeyexpr::declaration_hold),
    ));
    Some(wire.keeping(anchor))
}

/// The traffic a subscriber declared with `options` admits: its `allowed_origin` with
/// `local-subscriber`, `Z_LOCALITY_ANY` for NULL options there (what
/// `z_subscriber_options_default` writes), and remote only without the switch.
///
/// # Safety
/// `options` must be null or valid.
unsafe fn subscriber_origin(options: *const crate::session::z_subscriber_options_t) -> Locality {
    if options.is_null() {
        crate::locality::default_locality!("local-subscriber")
    } else {
        (*options).allowed_origin()
    }
}

/// Declare a subscriber (pico `z_declare_subscriber`). Consumes the moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn z_declare_subscriber(
    zs: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *const crate::session::z_subscriber_options_t,
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

        let state = match session_handle(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        // A closed session takes no declaration; the closure this call consumed runs its drop.
        if state.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
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
        if wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        // The subscriber's place is taken before anything is declared, so a full pool refuses
        // the declaration and declares nothing; the closure runs its drop as on every refusal.
        let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Subscriber)
        else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };

        // Record the subscription in the session's SSOT and declare it on every
        // face that is already up. With no peer yet — a listener before its
        // first connection — this declares nothing on the wire and still
        // records the entry (pico's declare-before-peer); each face replays the
        // SSOT as it comes up. Recording the local entry always succeeds
        // (mirrors pico's `_z_register_subscriber`).
        // R311y554 — the origin is the caller's `allowed_origin` with
        // `local-subscriber`, and `Locality::Remote` without it: a FIDELITY
        // choice with a measured source rather than a soundness workaround.
        // `Z_FEATURE_LOCAL_SUBSCRIBER` defaults to 0 upstream, which is why
        // pico's own `z_subscriber_options_t` has no `allowed_origin` field in a
        // default build; a default pico build never delivers a session's own
        // put to its own subscriber, so neither does that arm of this ABI.
        // R2959 — pico's two keys for one subscriber, and they are NOT the same
        // one. The subscription's own key gets the NON-WILD PREFIX declared,
        // and that declaration goes on the wire FIRST
        // (`vendor/zenoh-pico/src/net/primitives.c` @
        // `_Z_CLEAN_RETURN_IF_ERR(_z_declared_keyexpr_declare_non_wild_prefix(zn, &s._key, keyexpr),`);
        // the `DeclSubscriber` is then announced on the CALLER's key, a literal
        // for a view (`_z_declared_keyexpr_alias_to_wire(keyexpr, ...)` a few
        // lines on). Measured on the wire by
        // `pico_keyexpr_declaration_twice_and_diff.rs`: `DeclKexpr = demo/kd/sub`
        // then `DeclSubscriber on "demo/kd/sub/**"`.
        let engine = engine_of(state);
        let key = match DeclaredKeyexpr::declare_non_wild_prefix(&engine, &ke, declared_of(keyexpr))
        {
            Ok(key) => key,
            Err(rc) => return rc,
        };
        let Some(wire) = subscriber_wire(keyexpr, Arc::as_ref(&engine), &key) else {
            return Z_ERR_INVALID;
        };
        // A peer or router-hat session retracts the subscription naming ITS key
        // (`_z_undeclare_subscriber`), which is the prefix declaration above and
        // not the caller's key the announce went out on.
        let retraction = key.retraction_naming(&PicoSession::of(state));
        let released = cclosure.release_latch();
        // A session that holds no more subscribers, its table at the limit it opened under or
        // its declaration ids spent, refuses the subscriber as pico refuses an entity it cannot
        // hold; the engine dropped the sink, so the closure's drop has run.
        let Some(id) =
            engine.declare_subscriber_on_wire(&ke, wire, subscriber_origin(options), retraction, {
                let closure = Arc::new(cclosure);
                Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
            })
        else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        let state = slot.fill(SubscriberState {
            shared: engine,
            id,
            key,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            released,
        });
        (*state).bind();
        *subscriber = z_owned_subscriber_t {
            handle: state as *mut c_void,
            _pad: [core::ptr::null_mut(); 3],
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
    options: *const crate::session::z_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_handle(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        // A closed session takes no declaration; the closure this call consumed runs its drop.
        if state.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        if wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        // The returned SubId is deliberately discarded: with no owned handle
        // there is nothing that could ever undeclare it, so retaining the id
        // would only invite a caller-less removal path that pico does not have.
        // R311y554 — same Remote pin, same reason as the owned form above.
        // R2959 — and the same two keys: the declaration lives in the registry
        // entry, which is the only holder a handle-less subscriber has.
        let engine = engine_of(state);
        let key = match DeclaredKeyexpr::declare_non_wild_prefix(&engine, &ke, declared_of(keyexpr))
        {
            Ok(key) => key,
            Err(rc) => return rc,
        };
        let Some(wire) = subscriber_wire(keyexpr, Arc::as_ref(&engine), &key) else {
            return Z_ERR_INVALID;
        };
        // Named before the key is dropped: the entry keeps it alive through
        // `wire`'s anchor (see `subscriber_wire`), so the id it names stays
        // declared for as long as the entry can retract.
        let retraction = key.retraction_naming(&PicoSession::of(state));
        drop(key);
        // No handle will undeclare this one, so the session's close waits for it.
        state.keep_background(cclosure.release_latch());
        match engine.declare_subscriber_on_wire(
            &ke,
            wire,
            subscriber_origin(options),
            retraction,
            {
                let closure = Arc::new(cclosure);
                Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
            },
        ) {
            Some(_) => Z_OK,
            // As the owned form above refuses it.
            None => crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY,
        }
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
            crate::object_slot::release(handle as *mut SubscriberState);
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
        return core::ptr::null();
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
        return core::ptr::null();
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
/// [`z_entity_global_id_t`](crate::entity::z_entity_global_id_t) 20 bytes
/// rather than 24. This type crosses the boundary BY VALUE out of
/// [`z_source_info_new`], so getting it wrong misplaces every field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_source_info_t {
    pub _source_id: crate::entity::z_entity_global_id_t,
    pub _source_sn: u32,
}

const _: () = {
    assert!(core::mem::size_of::<z_source_info_t>() == 24);
    assert!(core::mem::align_of::<z_source_info_t>() == 4);
};

impl z_source_info_t {
    /// The all-zero value, which is pico's `_z_source_info_null`.
    pub(crate) fn empty() -> Self {
        Self {
            _source_id: crate::entity::z_entity_global_id_t {
                zid: crate::zid::z_id_t::empty(),
                eid: 0,
            },
            _source_sn: 0,
        }
    }
}

/// The pico ABI shape for a wz [`SourceInfo`](wz_session_core::sample::SourceInfo).
///
/// `zid_len` is DROPPED, and deliberately: wz carries the wire's effective zid
/// length because the codec's header nibble encodes it, while pico's `z_id_t`
/// is a fixed 16-byte array whose unused tail is zero. The wz value is already
/// right-zero-padded to 16, so the projection is a copy — but a reader
/// comparing two zids must compare all 16 bytes, which is what
/// `z_id_to_string` and every pico program do.
pub(crate) fn source_info_of(info: &wz_session_core::sample::SourceInfo) -> z_source_info_t {
    z_source_info_t {
        _source_id: crate::entity::z_entity_global_id_t {
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
    gid: *mut crate::entity::z_entity_global_id_t,
    zid: *const crate::zid::z_id_t,
    eid: u32,
) -> ZResult {
    crate::ffi::guarded(|| {
        if gid.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        *gid = crate::entity::z_entity_global_id_t {
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
    source_id: *const crate::entity::z_entity_global_id_t,
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
) -> crate::entity::z_entity_global_id_t {
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
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_sample_source_info(
    sample: *const z_loaned_sample_t,
) -> *const z_source_info_t {
    crate::ffi::guard_val(core::ptr::null(), || match sample_marshal(sample) {
        Some(m) => match m.source_info.as_ref() {
            Some(info) => info as *const z_source_info_t,
            None => core::ptr::null(),
        },
        None => core::ptr::null(),
    })
}

/// A sample's transport reliability (pico `z_sample_reliability`).
///
/// Note the enum is INVERTED against wz's own: pico spells
/// `Z_RELIABILITY_RELIABLE = 0` and `Z_RELIABILITY_BEST_EFFORT = 1`
/// (`api/constants.h:201-203`) while `Reliability`
/// is `BestEffort = 0` / `Reliable = 1`. The mapping is written out rather than
/// cast, because a cast agrees on neither value and R311y545 already paid for
/// exactly this class of slip on `z_congestion_control_t`.
///
/// # Safety
/// `sample` must be null or a live loaned sample.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_sample_reliability(sample: *const z_loaned_sample_t) -> c_int {
    /// pico `Z_RELIABILITY_RELIABLE`, and its `Z_RELIABILITY_DEFAULT`.
    const Z_RELIABILITY_RELIABLE: c_int = 0;
    /// pico `Z_RELIABILITY_BEST_EFFORT`.
    const Z_RELIABILITY_BEST_EFFORT: c_int = 1;
    crate::ffi::guard_val(Z_RELIABILITY_RELIABLE, || {
        match sample_marshal(sample).map(|m| m.reliability) {
            Some(Reliability::BestEffort) => Z_RELIABILITY_BEST_EFFORT,
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
        // R2946 — `BlockFirst` reports DROP, as pico itself would: its QoS byte
        // decode reads the `nodrop` bit alone (`_z_n_qos_get_congestion_control`),
        // and zenoh's block-first byte carries `nodrop` clear. Named rather than
        // left to the wildcard, so the pico ABI's answer is a decision and not
        // whatever a new variant happened to fall into.
        match sample_qos(sample).map(|q| q.congestion()) {
            Some(wz_session_core::qos::CongestionControl::Block) => Z_CONGESTION_CONTROL_BLOCK,
            Some(wz_session_core::qos::CongestionControl::BlockFirst)
            | Some(wz_session_core::qos::CongestionControl::Drop)
            | None => Z_CONGESTION_CONTROL_DROP,
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
) -> Option<wz_session_core::sample::QosLevel> {
    sample_marshal(sample).and_then(|m| m.qos)
}

/// Deep-copy a sample into an owned one (pico `z_sample_clone`).
///
/// The same deep copy `z_sample_take_from_loaned` performs — routed through the
/// identical `clone_sample_marshal` so the two cannot diverge — with the
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
        match clone_sample_marshal(this_) {
            Ok(handle) => {
                (*dst).handle = handle;
                crate::result::Z_OK
            }
            Err(code) => code,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// pico's `_z_declared_keyexpr_t` field for field, as its header declares it: the
    /// declaration's rc (`_z_keyexpr_wire_declaration_rc_t`, a value pointer and a count
    /// pointer) and the key's `_z_string_t`, a `_z_slice_t` of a length, a start and a delete
    /// context of two pointers.
    #[allow(dead_code)]
    #[repr(C)]
    struct PicoDeclaredKeyexpr {
        declaration_val: *mut c_void,
        declaration_cnt: *mut c_void,
        len: usize,
        start: *const u8,
        deleter: *mut c_void,
        context: *mut c_void,
    }

    /// A program reads `sample->payload` right after the declared key, which is that key's size
    /// on the program's own target: 48 B on a 64-bit host and 24 B on a 32-bit one. The marshal
    /// has to put its payload view there, or a 32-bit program reads the zeroes of the inert key.
    #[test]
    fn the_payload_view_sits_where_a_program_of_this_target_reads_it() {
        assert_eq!(
            PICO_SAMPLE_PAYLOAD_OFFSET,
            core::mem::size_of::<PicoDeclaredKeyexpr>()
        );
        assert_eq!(
            core::mem::offset_of!(SampleMarshal, pico_payload),
            core::mem::size_of::<PicoDeclaredKeyexpr>()
        );
    }

    /// A view a subscriber's callback is handed, over bytes the test holds.
    struct HeldView<'a> {
        key: &'a str,
        payload: &'a [u8],
        attachment: &'a [u8],
    }

    impl SampleView for HeldView<'_> {
        fn keyexpr(&self) -> &str {
            self.key
        }
        fn payload(&self) -> &[u8] {
            self.payload
        }
        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn attachment(&self) -> Option<&[u8]> {
            Some(self.attachment)
        }
    }

    /// Where a C callback found the key, the payload and the attachment of its sample.
    #[derive(Default)]
    struct Found {
        key: usize,
        payload: usize,
        attachment: usize,
    }

    unsafe extern "C" fn note_where(sample: *const z_loaned_sample_t, context: *mut c_void) {
        let found = &mut *(context as *mut Found);
        found.key = (*z_sample_keyexpr(sample))._start as usize;
        let payload = &*((*z_sample_payload(sample)).handle as *const ByteBuf);
        found.payload = payload.as_slice().as_ptr() as usize;
        let attachment = &*((*z_sample_attachment(sample)).handle as *const ByteBuf);
        found.attachment = attachment.as_slice().as_ptr() as usize;
    }

    /// A subscriber's callback reads the key, the payload and the attachment where the view holds
    /// them: none of the three is copied to hand the program its sample.
    #[test]
    fn a_subscriber_callback_reads_its_sample_where_the_view_holds_it() {
        let view = HeldView {
            key: "demo/lent",
            payload: b"payload",
            attachment: b"attachment",
        };
        let mut found = Found::default();
        let context = (&mut found as *mut Found).cast::<c_void>();
        let mut callback =
            make_subscriber_callback(Arc::new(CClosure::new(context, Some(note_where), None)));
        callback(&view);
        drop(callback);
        assert_eq!(found.key, view.key.as_ptr() as usize);
        assert_eq!(found.payload, view.payload.as_ptr() as usize);
        assert_eq!(found.attachment, view.attachment.as_ptr() as usize);
    }

    /// What outlives the callback holds bytes of its own: an owned sample, and a clone of the
    /// payload, copy what the view lent, and read the same.
    #[test]
    fn a_sample_kept_past_its_callback_copies_what_the_view_lent() {
        let view = HeldView {
            key: "demo/lent",
            payload: b"payload",
            attachment: b"attachment",
        };
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { SampleMarshal::lent(&view) };
        marshal.bind();
        let kept = marshal.deep_copy().expect("room for the copy");
        let clone = marshal.payload.try_clone().expect("room for the copy");
        drop(marshal);
        assert_eq!(kept.keyexpr.as_str(), "demo/lent");
        assert_ne!(kept.keyexpr.as_str().as_ptr(), view.key.as_ptr());
        assert_eq!(kept.payload.as_slice(), b"payload");
        assert_ne!(kept.payload.as_slice().as_ptr(), view.payload.as_ptr());
        let attachment = kept.attachment.as_ref().expect("the view carried one");
        assert_eq!(attachment.as_slice(), b"attachment");
        assert_ne!(attachment.as_slice().as_ptr(), view.attachment.as_ptr());
        assert_eq!(clone.as_slice(), b"payload");
        assert_ne!(clone.as_slice().as_ptr(), view.payload.as_ptr());
    }

    /// A view whose sample carries an encoding with a schema, where the view holds it.
    struct EncodedView<'a> {
        schema: &'a [u8],
    }

    impl SampleView for EncodedView<'_> {
        fn keyexpr(&self) -> &str {
            "demo/encoded"
        }
        fn payload(&self) -> &[u8] {
            b"x"
        }
        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
            Some((7, Some(self.schema)))
        }
    }

    /// The encoding a sample carried is held in its marshal: the owned encoding
    /// `z_sample_encoding` hands out points inside the marshal, so the sample's encoding took no
    /// allocation of its own, and it reads what the view carried. A sample kept past its callback
    /// holds an encoding of its own, which reads the same once the marshal it was copied from is
    /// gone; a sample that carried none hands out none.
    #[test]
    fn a_samples_encoding_is_held_in_its_marshal() {
        let view = EncodedView { schema: b"utf8" };
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { SampleMarshal::lent(&view) };
        marshal.bind();
        // SAFETY: a sample this crate marshalled and bound.
        let loaned = unsafe { z_sample_encoding(marshal.as_loaned()) };
        assert!(!loaned.is_null(), "the sample carried an encoding");
        // SAFETY: the loaned encoding the accessor handed out, of the live marshal.
        let handle = unsafe { (*loaned).handle } as usize;
        let start = &marshal as *const SampleMarshal as usize;
        assert!(
            (start..start + core::mem::size_of::<SampleMarshal>()).contains(&handle),
            "the encoding lies in the marshal, not in a box of its own"
        );
        // SAFETY: as above.
        let hint = unsafe { crate::encoding::encoding_hint(loaned) }.expect("bound");
        assert_eq!(
            (hint.packed_id, hint.schema.as_deref()),
            (7, Some(&b"utf8"[..]))
        );
        let mut kept = marshal.deep_copy().expect("room for the copy");
        drop(marshal);
        kept.bind();
        // SAFETY: the kept copy, bound at its final address.
        let kept_loaned = unsafe { z_sample_encoding(kept.as_loaned()) };
        // SAFETY: the loaned encoding of the live copy.
        let kept_hint = unsafe { crate::encoding::encoding_hint(kept_loaned) }.expect("kept");
        assert_eq!(
            (kept_hint.packed_id, kept_hint.schema.as_deref()),
            (7, Some(&b"utf8"[..]))
        );

        let plain = HeldView {
            key: "demo/plain",
            payload: b"x",
            attachment: b"",
        };
        // SAFETY: the marshal is dropped before `plain`.
        let mut none = unsafe { SampleMarshal::lent(&plain) };
        none.bind();
        // SAFETY: a sample this crate marshalled and bound.
        let carried = unsafe { z_sample_encoding(none.as_loaned()) };
        assert!(carried.is_null(), "no encoding carried, none handed out");
    }
}
