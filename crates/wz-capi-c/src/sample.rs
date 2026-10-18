// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sample a subscriber callback receives, and the four accessors
//! `z_sub.c` reads it with.
//!
//! ## The marshal IS the loaned sample
//!
//! wz delivers a [`SampleView`] that borrows the decoded frame, and its lifetime
//! ends when the callback returns. The C side gets a `z_loaned_sample_t*` and is
//! documented to copy anything it keeps, so the borrow is legal — but the wz view
//! borrows a buffer the drive loop is about to reuse, so the fields are COPIED
//! into a [`SampleMarshal`] that lives for exactly the duration of the call and
//! the C pointer is aimed at that.
//!
//! ## `bind` is separate from `new`, and the split is load-bearing
//!
//! The marshal caches loaned views that point at its OWN fields. A by-value
//! constructor returns before the value reaches its final address, so binding
//! inside `new` would hand C pointers into the dead constructor frame. `new`
//! therefore leaves the cached views unbound and [`SampleMarshal::bind`] runs
//! once the marshal is where it will stay. The sibling pico ABI records the same
//! discipline for the same reason, having once got it wrong.

use std::ffi::c_void;

use wz_runtime_tokio::sample::{EncodingHint, QosLevel, SampleKind};
use wz_runtime_tokio::sink::SampleView;

use crate::abi::{
    z_loaned_bytes_t, z_loaned_encoding_t, z_loaned_keyexpr_t, z_loaned_sample_t, z_sample_kind_t,
    z_view_string_t, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::bytes::{BytesState, Payload};
use crate::encoding::EncodingState;
use crate::ffi::guard_val;
use crate::keyexpr::KeyexprState;
use crate::publisher::{
    z_congestion_control_t, z_priority_t, Z_CONGESTION_CONTROL_BLOCK, Z_PRIORITY_DATA,
};
use crate::string::view_string_over;

/// The zenoh-c kind constant for a wz [`SampleKind`].
pub(crate) fn sample_kind_of(kind: SampleKind) -> z_sample_kind_t {
    match kind {
        SampleKind::Put => Z_SAMPLE_KIND_PUT,
        SampleKind::Del => Z_SAMPLE_KIND_DELETE,
    }
}

/// The OPTIONAL half of a sample's metadata, passed by NAME rather than by
/// position.
///
/// R311y568. [`SampleMarshal::new`] had grown to six positional arguments, four
/// of them `Option<_>`, and the two this round adds would have made eight — a
/// shape where transposing two `None`s compiles and silently drops a field. The
/// tree already reached for this remedy once, on the reply side: y563's
/// [`ReplyMeta`](wz_runtime_tokio::query_sink::ReplyMeta) exists because the
/// alternative was one flush arm per field COMBINATION.
///
/// [`Self::from_view`] is the other half of the argument, and the more important
/// one. Three of this crate's four marshal sites copy their fields out of a
/// [`SampleView`], and before this round each named the accessors itself — so a
/// field added to the view was carried at whichever sites its author edited.
/// That is the y563 "one witness, two folds" shape; reading the view in ONE
/// place makes the next field's fan-out a single edit.
#[derive(Default)]
pub(crate) struct SampleMeta {
    attachment: Option<Vec<u8>>,
    timestamp: Option<crate::timestamp::z_timestamp_t>,
    source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    /// R311y568 — the value encoding (the inner `MsgPut` E-flag), what
    /// `z_sample_encoding` reports.
    encoding: Option<EncodingHint>,
    /// R311y568 — the outer QoS ext, which `z_sample_priority` /
    /// `z_sample_congestion_control` / `z_sample_express` decode three different
    /// sub-fields of. Held RAW rather than split into three, because the wire
    /// carries one byte and splitting it here would let the three accessors
    /// disagree about an absent ext.
    qos: Option<QosLevel>,
    /// R311y568 — the LINK-layer reliability of the frame that carried this
    /// sample, what `z_sample_reliability` reports.
    ///
    /// Not part of the QoS ext: `SampleView::reliability()` is an unconditional
    /// accessor because it is a property of the carrying frame rather than of
    /// the body, which is why it is a separate field here.
    reliability: Option<wz_runtime_tokio::Reliability>,
}

impl SampleMeta {
    /// Every optional field a [`SampleView`] carries, read in one place.
    pub(crate) fn from_view(view: &dyn SampleView) -> Self {
        Self {
            attachment: view.attachment().map(<[u8]>::to_vec),
            timestamp: view
                .timestamp()
                .map(crate::timestamp::z_timestamp_t::from_hint),
            source_info: view.source_info().cloned(),
            encoding: view.encoding().cloned(),
            qos: view.qos(),
            reliability: Some(view.reliability()),
        }
    }

    /// Override the attachment — for a marshal built from a view whose payload
    /// split differs (a reply's Err arm).
    #[must_use]
    pub(crate) fn with_attachment(mut self, attachment: Option<Vec<u8>>) -> Self {
        self.attachment = attachment;
        self
    }

    /// Set the timestamp.
    #[must_use]
    pub(crate) fn with_timestamp(
        mut self,
        timestamp: Option<crate::timestamp::z_timestamp_t>,
    ) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the source identity.
    #[must_use]
    pub(crate) fn with_source_info(
        mut self,
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    ) -> Self {
        self.source_info = source_info;
        self
    }

    /// Set the value encoding.
    #[must_use]
    pub(crate) fn with_encoding(mut self, encoding: Option<EncodingHint>) -> Self {
        self.encoding = encoding;
        self
    }
}

/// The owned copy behind a borrowed `z_loaned_sample_t` for one callback.
///
/// Holds the payload and keyexpr in the SAME state types the rest of the ABI
/// uses ([`BytesState`] / [`KeyexprState`]), so `z_sample_payload` hands back a
/// loaned bytes that `z_bytes_to_string` reads with no special case — one
/// meaning for a handle slot across the whole crate.
pub(crate) struct SampleMarshal {
    keyexpr: KeyexprState,
    payload: BytesState,
    attachment: Option<BytesState>,
    kind: z_sample_kind_t,
    /// R311y557 — the sample's own timestamp, or `None` when it carries none.
    ///
    /// Stored BY VALUE inside the marshal (24 bytes, `Copy`) rather than behind
    /// a box, because `z_sample_timestamp` hands out a borrowed pointer to it
    /// and that pointer's lifetime is the marshal's — the same contract
    /// `z_sample_attachment` has, reached the same way.
    timestamp: Option<crate::timestamp::z_timestamp_t>,
    /// R311y563 — the sample's `(zid, eid, sn)`, or `None` when it carries
    /// none. Stored as the wz type and VIEWED through `source_info_c` rather
    /// than boxed: `z_sample_source_info` hands out a borrowed pointer whose
    /// lifetime is the marshal's, the same contract `z_sample_timestamp` has.
    source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    /// The C view `z_sample_source_info` returns a pointer to. R2239 — a VALUE
    /// since zenoh-c 1.10.0 retired the owned/loaned split; there is nothing to
    /// free either way, and now nothing to loan from either.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    source_info_c: crate::source_info::z_source_info_t,
    /// R311y568 — the sample's value encoding, ALWAYS present.
    ///
    /// `Option` would be the obvious shape and it is the wrong one: upstream's
    /// `z_sample_encoding` returns `const z_loaned_encoding_t*` off a Rust
    /// `Encoding` VALUE, so it can never be NULL and no C program checks it.
    /// A sample that carried no E-flag therefore reports the DEFAULT encoding,
    /// which is what the absent flag means on the wire.
    encoding: EncodingState,
    /// R311y568 — the outer QoS ext byte, or `None` when the sample carried no
    /// ext at all. The three accessors each report the wire's meaning for an
    /// absent ext, which is not the same value for all three.
    qos: Option<QosLevel>,
    /// R311y568 — the carrying frame's link-layer reliability.
    reliability: Option<wz_runtime_tokio::Reliability>,
    /// Whether the fields above are those of a plain Put ([`SampleView::is_plain_put`]): a
    /// Put with no attachment, timestamp, source info or encoding. Only [`Self::reload`] sets
    /// it, from the sample it loaded; a marshal that was built, not reloaded, says no.
    plain: bool,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    /// The loaned view `z_sample_encoding` returns, aimed at this marshal's own
    /// [`Self::encoding`] — the same borrow contract `loaned_payload` has.
    loaned_encoding: z_loaned_encoding_t,
}

impl SampleMarshal {
    /// Build the marshal with its cached views still UNBOUND. See the module
    /// note for why that is not an oversight.
    pub(crate) fn new(
        keyexpr: String,
        payload: impl Into<Payload>,
        kind: z_sample_kind_t,
        meta: SampleMeta,
    ) -> Self {
        Self {
            keyexpr: KeyexprState::new(keyexpr),
            payload: BytesState::of(payload.into()),
            attachment: meta.attachment.map(BytesState::whole),
            kind,
            timestamp: meta.timestamp,
            source_info: meta.source_info,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info_c: crate::source_info::z_source_info_t::empty(),
            encoding: match meta.encoding.as_ref() {
                Some(hint) => EncodingState::from_hint(hint),
                None => EncodingState::default_encoding(),
            },
            qos: meta.qos,
            reliability: meta.reliability,
            plain: false,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            loaned_encoding: z_loaned_encoding_t::null_value(),
        }
    }

    /// Point the cached views at this marshal's own fields. MUST run only once
    /// the marshal sits at its FINAL address.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::from_handle(&self.keyexpr as *const KeyexprState as *mut c_void);
        self.loaned_payload =
            z_loaned_bytes_t::from_handle(&self.payload as *const BytesState as *mut c_void);
        self.loaned_attachment = match self.attachment.as_ref() {
            Some(state) => z_loaned_bytes_t::from_handle(state as *const BytesState as *mut c_void),
            None => z_loaned_bytes_t::null_value(),
        };
        self.loaned_encoding =
            z_loaned_encoding_t::from_handle(&self.encoding as *const EncodingState as *mut c_void);
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        {
            self.source_info_c = match self.source_info.as_ref() {
                Some(info) => crate::source_info::z_source_info_t::from_runtime(info),
                None => crate::source_info::z_source_info_t::empty(),
            };
        }
    }

    /// R311y568 — the sample's source identity, for the REPLY plane's
    /// `z_reply_replier_id`, which reads the responder's `(zid, eid)` out of the
    /// same field `z_sample_source_info` exposes.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub(crate) fn source_info(&self) -> Option<&wz_runtime_tokio::sample::SourceInfo> {
        self.source_info.as_ref()
    }

    /// This marshal viewed as the borrowed `z_loaned_sample_t` the C side gets.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_sample_t {
        self as *const SampleMarshal as *const z_loaned_sample_t
    }

    /// Make this marshal the copy of `view`, in place: every field [`Self::new`] and
    /// [`SampleMeta::from_view`] would set, assigned over the previous sample's, with the
    /// keyexpr's text and the payload's boundary list reusing their storage, and the
    /// cached views bound again. The marshal must already sit at its final address (it
    /// was bound once), which is what a kept, boxed one does.
    ///
    /// What a subscriber's callback does for every message is this and not a build and a
    /// drop of a whole marshal.
    fn reload(&mut self, view: &dyn SampleView) {
        // The stream's common case, a plain Put after a plain Put, asks the view ONE question
        // and not six: everything it varies in comes back together.
        if self.plain {
            if let Some(facts) = view.plain_facts() {
                if !facts.key_unchanged {
                    self.keyexpr.keyexpr.clear();
                    self.keyexpr.keyexpr.push_str(view.keyexpr());
                    self.keyexpr.mapping = None;
                }
                let payload = Payload::Shared(facts.payload);
                match facts.single_run_len {
                    Some(len) => self.payload.reset_single(payload, len),
                    None => self.payload.reset(payload),
                }
                self.qos = facts.qos;
                self.reliability = Some(facts.reliability);
                return;
            }
        }
        // The text of the last key stays when the caller says this sample's is the same.
        if !view.keyexpr_unchanged() {
            self.keyexpr.keyexpr.clear();
            self.keyexpr.keyexpr.push_str(view.keyexpr());
            self.keyexpr.mapping = None;
        }
        self.payload.reset(payload_of(view));
        // A plain Put after a plain Put differs from it in the QoS and the reliability and in
        // nothing else: the other fields are already what the general path below would write.
        let plain = view.is_plain_put();
        if plain && self.plain {
            self.qos = view.qos();
            self.reliability = Some(view.reliability());
            return;
        }
        self.plain = plain;
        // A stream's samples carry no attachment and no source info, and the default encoding,
        // sample after sample, so each of those is written only when this sample differs from
        // the last: assigning "nothing" over "nothing" was the larger part of this function.
        // The cached views point at the fields, which do not move, so they are bound again
        // only when a field's presence or value changed under one of them.
        let mut rebind = false;
        match view.attachment() {
            Some(bytes) => {
                self.attachment = Some(BytesState::whole(bytes.to_vec()));
                rebind = true;
            }
            None => rebind |= self.attachment.take().is_some(),
        }
        self.kind = sample_kind_of(view.kind());
        self.timestamp = view
            .timestamp()
            .map(crate::timestamp::z_timestamp_t::from_hint);
        match view.source_info() {
            Some(info) => {
                self.source_info = Some(info.clone());
                rebind = true;
            }
            None => rebind |= self.source_info.take().is_some(),
        }
        match view.encoding() {
            Some(hint) => self.encoding = EncodingState::from_hint(hint),
            None if !self.encoding.is_default() => {
                self.encoding = EncodingState::default_encoding()
            }
            None => {}
        }
        self.qos = view.qos();
        self.reliability = Some(view.reliability());
        if rebind {
            self.bind();
        }
    }
}

/// The payload a marshal holds for `view`: a second reference to the storage the session
/// delivered it in when the view has one, a copy of the bytes when it has not.
fn payload_of(view: &dyn SampleView) -> Payload {
    match view.payload_shared_owned() {
        Some(shared) => Payload::Shared(shared),
        None => Payload::Owned(view.payload().to_vec()),
    }
}

/// The marshal a subscriber's callback keeps from one sample to the next
/// ([`SampleMarshal::reload`]), made when the first sample arrives and boxed so the
/// views it points at itself stay where they were bound.
///
/// `Send` because the callback that owns it is: it is touched only from inside that
/// callback, which the subscriber's deferred cell runs one call at a time, and the
/// pointers in it aim at the box it lives in.
pub(crate) struct MarshalCache(Option<Box<SampleMarshal>>);

// SAFETY: see the type's note: one owner, one call at a time, pointers into its own box.
unsafe impl Send for MarshalCache {}

impl MarshalCache {
    pub(crate) const fn new() -> Self {
        Self(None)
    }

    /// [`with_marshalled`] over the kept marshal. The payload is let go when `body` returns,
    /// so the frame it shares is not held until the next sample arrives (a frame buffer
    /// that comes back to its pool only when the last reference drops would otherwise
    /// stay out of it, for as long as the subscription is quiet).
    pub(crate) fn with_view<R>(
        &mut self,
        view: &dyn SampleView,
        body: impl FnOnce(*const z_loaned_sample_t) -> R,
    ) -> R {
        let marshal = match self.0.as_mut() {
            Some(kept) => {
                kept.reload(view);
                kept
            }
            None => {
                let mut fresh = Box::new(SampleMarshal::new(
                    view.keyexpr().to_owned(),
                    payload_of(view),
                    sample_kind_of(view.kind()),
                    SampleMeta::from_view(view),
                ));
                fresh.bind();
                self.0.insert(fresh)
            }
        };
        let result = body(marshal.as_loaned());
        marshal.payload.release();
        result
    }
}

/// Read the marshal behind a loaned sample.
///
/// # Safety
/// `this_` must be null, or a pointer this crate produced with
/// [`SampleMarshal::as_loaned`] and whose marshal is still alive — which, per
/// zenoh-c's contract, means "inside the callback it was handed to".
unsafe fn marshal<'a>(this_: *const z_loaned_sample_t) -> Option<&'a SampleMarshal> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(this_ as *const SampleMarshal) })
}

/// Borrow a delivered sample's keyexpr (zenoh-c `z_sample_keyexpr`).
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_keyexpr(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => &m.loaned_keyexpr as *const z_loaned_keyexpr_t,
            None => std::ptr::null(),
        }
    })
}

/// Mutably borrow a delivered sample's payload (zenoh-c
/// `z_sample_payload_mut`).
///
/// UNGATED upstream — it is declared on the no-unstable header too
/// (`zenoh_commons.h:4638` there, `:4393` on the shared-memory oracle) — so it
/// is exported on every arm even though the corpus reaches it only through
/// `z_sub_shm.c`, which hands the result straight to
/// `z_bytes_as_mut_loaned_shm`.
///
/// The pointer is taken with `addr_of_mut!` rather than by reborrowing a shared
/// reference: handing back a `*mut` derived from a `&` would be a provenance
/// laundering the caller is entitled to write through.
///
/// # Safety
/// `this_` must be null or a live loaned sample. The returned pointer borrows
/// the sample and is valid for as long as it is.
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload_mut(
    this_: *mut z_loaned_sample_t,
) -> *mut z_loaned_bytes_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        let m = this_ as *mut SampleMarshal;
        // SAFETY: the caller's contract — `this_` aims at a live `SampleMarshal`,
        // and the field projection creates no intermediate reference.
        unsafe { std::ptr::addr_of_mut!((*m).loaned_payload) }
    })
}

/// Borrow a delivered sample's payload (zenoh-c `z_sample_payload`).
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => &m.loaned_payload as *const z_loaned_bytes_t,
            None => std::ptr::null(),
        }
    })
}

/// How the sample was issued (zenoh-c `z_sample_kind`).
///
/// A gravestone reads as PUT, matching upstream's own default for the field.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_kind(this_: *const z_loaned_sample_t) -> z_sample_kind_t {
    guard_val(Z_SAMPLE_KIND_PUT, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { marshal(this_) }.map_or(Z_SAMPLE_KIND_PUT, |m| m.kind)
    })
}

/// Borrow a delivered sample's attachment, or NULL when it carries none
/// (zenoh-c `z_sample_attachment`).
///
/// NULL is the ABSENCE signal upstream specifies and `z_sub.c` branches on, so
/// this deliberately does not hand back an empty-but-present blob: a publisher
/// that attached zero bytes and one that attached nothing are different events,
/// and flattening them would make the C side print an attachment that was never
/// sent.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_attachment(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) if m.attachment.is_some() => &m.loaned_attachment as *const z_loaned_bytes_t,
            _ => std::ptr::null(),
        }
    })
}

/// Borrow a delivered sample's timestamp, or NULL when it carries none
/// (zenoh-c `z_sample_timestamp`).
///
/// R311y557. NULL is not an error and is the ordinary answer: a sample is
/// stamped only when its publisher set `z_put_options_t::timestamp` or the
/// node clock is stamping, and upstream returns NULL for the rest. The pointer
/// borrows the marshal, exactly as [`z_sample_attachment`] does.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_timestamp(
    this_: *const z_loaned_sample_t,
) -> *const crate::timestamp::z_timestamp_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => match m.timestamp.as_ref() {
                Some(ts) => ts as *const crate::timestamp::z_timestamp_t,
                None => std::ptr::null(),
            },
            None => std::ptr::null(),
        }
    })
}

/// Borrow a delivered sample's source info, or NULL when it carries none
/// (zenoh-c `z_sample_source_info`, `zenoh_commons.h:4657`).
///
/// R311y563 — the READ half of the source-info family, and it is separately
/// omittable from the SEND half: without it a C program has no way to observe
/// what arrived, so the option folds this round wired would be unfalsifiable.
/// The pointer borrows the marshal, exactly as [`z_sample_timestamp`] does.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
/// UNSTABLE-gated, as upstream declares it: the prototype sits behind
/// `#if defined(Z_FEATURE_UNSTABLE_API)` (`zenoh_commons.h:4410`), so a
/// no-unstable build must not export it either — a symbol wz defines and the
/// reference does not is the mirror image of the census gap, and the drop-in
/// claim is about matching the reference, not exceeding it here.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_sample_source_info(
    this_: *const z_loaned_sample_t,
) -> *const crate::source_info::z_source_info_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) if m.source_info.is_some() => {
                &m.source_info_c as *const crate::source_info::z_source_info_t
            }
            _ => std::ptr::null(),
        }
    })
}

// --- R311y568: the four metadata accessors the census found missing ---------
//
// Every one of them is a symbol the real `libzenohc.so` defines and this cdylib
// did not, so a C program naming any of them failed at LINK time. None was
// reachable by a behavioural leg for exactly that reason.

/// The sample's value ENCODING (zenoh-c `z_sample_encoding`).
///
/// NEVER null for a live sample — see [`SampleMarshal::encoding`] for why the
/// absent-E-flag case reports the default rather than NULL. Upstream's return
/// type is non-optional in Rust, so a C program does not check.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_encoding(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_encoding_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => &m.loaned_encoding as *const z_loaned_encoding_t,
            None => std::ptr::null(),
        }
    })
}

/// The sample's congestion-control setting (zenoh-c
/// `z_sample_congestion_control`).
///
/// zenoh-c's constants are the REVERSE of zenoh-pico's — `BLOCK = 0` here and
/// `DROP = 0` there ([`crate::publisher`]) — so this maps through the named
/// constants rather than casting the wz enum's discriminant. The sibling pico
/// ABI records the same trap from the other side.
///
/// An absent QoS ext reports BLOCK, which is what the wire means by eliding it:
/// zenoh's default is `CongestionControl::Block` for a Put, and the ext is
/// omitted precisely when every field sits at its default.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_congestion_control(
    this_: *const z_loaned_sample_t,
) -> z_congestion_control_t {
    guard_val(Z_CONGESTION_CONTROL_BLOCK, || {
        // SAFETY: the caller's contract, delegated.
        // R2946 — through the one typed-to-C mapping, so a `BlockFirst` sample
        // reports `BLOCK_FIRST` rather than falling into the `Block` default.
        match unsafe { marshal(this_) }
            .and_then(|m| m.qos)
            .map(|qos| qos.congestion())
        {
            Some(congestion) => crate::publisher::congestion_to_c(congestion),
            None => Z_CONGESTION_CONTROL_BLOCK,
        }
    })
}

/// Whether the sample bypassed batching (zenoh-c `z_sample_express`).
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_express(this_: *const z_loaned_sample_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { marshal(this_) }
            .and_then(|m| m.qos)
            .is_some_and(|qos| qos.is_express())
    })
}

/// The sample's PRIORITY (zenoh-c `z_sample_priority`).
///
/// An absent QoS ext reports `Z_PRIORITY_DATA` (5) — the wire's meaning for the
/// elided ext, and the same answer the pico ABI gives for the same reason.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_priority(this_: *const z_loaned_sample_t) -> z_priority_t {
    guard_val(Z_PRIORITY_DATA, || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) }.and_then(|m| m.qos) {
            Some(qos) => z_priority_t::from(qos.priority().wire_byte()),
            None => Z_PRIORITY_DATA,
        }
    })
}

/// The link-layer RELIABILITY of the frame that carried this sample (zenoh-c
/// `z_sample_reliability`).
///
/// UNSTABLE-gated, as upstream gates it. A sample with no recorded reliability —
/// a synthetic marshal, or a liveliness transition — reports the DEFAULT, which
/// is what [`z_reliability_default`](crate::publisher::z_reliability_default)
/// answers.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_sample_reliability(
    this_: *const z_loaned_sample_t,
) -> crate::publisher::z_reliability_t {
    guard_val(crate::publisher::Z_RELIABILITY_RELIABLE, || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) }.and_then(|m| m.reliability) {
            Some(wz_runtime_tokio::Reliability::BestEffort) => {
                crate::publisher::Z_RELIABILITY_BEST_EFFORT
            }
            _ => crate::publisher::Z_RELIABILITY_RELIABLE,
        }
    })
}

/// Construct a non-owned string over a keyexpr (zenoh-c
/// `z_keyexpr_as_view_string`).
///
/// Lives here rather than in [`crate::keyexpr`] because it is a SAMPLE-plane
/// read: the only keyexpr a caller has to view is the one it just received, and
/// the borrow it hands out is valid for exactly as long as that sample is —
/// which is the marshal's lifetime, not the view's.
///
/// # Safety
/// `this_` must be null or a valid loaned keyexpr; `out_string` must be valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_as_view_string(
    this_: *const z_loaned_keyexpr_t,
    out_string: *mut z_view_string_t,
) {
    guard_val((), || {
        if out_string.is_null() {
            return;
        }
        // Written before the read so a caller that ignores a gravestone keyexpr
        // sees an empty string rather than a stale stack value.
        unsafe { *out_string = z_view_string_t::null_value() };
        // SAFETY: the caller's contract.
        if let Some(text) = unsafe { crate::keyexpr::keyexpr_str(this_) } {
            unsafe { *out_string = view_string_over(text) };
        }
    });
}

/// Marshal one wz [`SampleView`] and run `body` with the borrowed
/// `z_loaned_sample_t` the C side expects.
///
/// The marshal is a local, so the borrow it hands out ends when this returns —
/// which is exactly zenoh-c's contract for a callback argument.
///
/// The one-shot form of what [`MarshalCache::with_view`] does with a kept marshal; the tests
/// use it to read a single sample, and the subscriber's callback uses the kept one.
#[cfg(test)]
pub(crate) fn with_marshalled<R>(
    view: &dyn SampleView,
    body: impl FnOnce(*const z_loaned_sample_t) -> R,
) -> R {
    // R311y568 — every optional field the view carries, read through the ONE
    // place that names its accessors ([`SampleMeta::from_view`]). Before this
    // round the three metadata fields were named here, and the encoding + QoS
    // this round adds would have been a fourth and fifth transcription.
    // R3052 -- a payload the session delivered where it received it stays there: the
    // marshal holds a second reference to the frame, or to the chunk of shared memory
    // a peer sent, for the length of the callback, and a C program that escapes the
    // sample keeps it. Only a view with no shareable payload (a sample the C side
    // built itself, a test's) is copied.
    let mut marshal = SampleMarshal::new(
        view.keyexpr().to_owned(),
        payload_of(view),
        sample_kind_of(view.kind()),
        SampleMeta::from_view(view),
    );
    // Bind AFTER the move out of `new` — the marshal is at its final address
    // only here. See `SampleMarshal::bind`.
    marshal.bind();
    body(marshal.as_loaned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::z_bytes_to_string;
    use crate::string::{z_string_data, z_string_drop, z_string_len, z_view_string_loan};
    use wz_runtime_tokio::Reliability;

    /// A `SampleView` that can carry an attachment.
    ///
    /// `BorrowedSample` — the crate's own loose-bytes view — keeps the trait's
    /// `attachment() -> None` default, so it cannot exercise the PRESENT arm at
    /// all. The unit under test is this crate's marshalling of the trait, so the
    /// view is defined here rather than the accessor being tested only against
    /// the one implementation that can never return `Some`.
    struct View<'a> {
        keyexpr: &'a str,
        payload: &'a [u8],
        kind: SampleKind,
        attachment: Option<&'a [u8]>,
    }

    impl SampleView for View<'_> {
        fn keyexpr(&self) -> &str {
            self.keyexpr
        }
        fn payload(&self) -> &[u8] {
            self.payload
        }
        fn kind(&self) -> SampleKind {
            self.kind
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn attachment(&self) -> Option<&[u8]> {
            self.attachment
        }
    }

    /// Read a loaned bytes back the way upstream's `z_sub.c` does.
    fn to_string(bytes: *const z_loaned_bytes_t) -> Vec<u8> {
        let mut owned = crate::abi::z_owned_string_t::null_value();
        // SAFETY: `bytes` is a live loaned bytes from the marshal below, and
        // `owned` is a valid, writable local.
        let rc = unsafe { z_bytes_to_string(bytes, &mut owned) };
        assert_eq!(
            rc,
            crate::result::Z_OK,
            "z_bytes_to_string rejected a live payload"
        );
        // SAFETY: `owned` was just constructed by the call above.
        let out = unsafe {
            let loaned = crate::string::z_string_loan(&owned);
            std::slice::from_raw_parts(z_string_data(loaned) as *const u8, z_string_len(loaned))
                .to_vec()
        };
        let mut moved = crate::abi::z_moved_string_t { _this: owned };
        // SAFETY: `moved` wraps the owned string this test built; dropped once.
        unsafe { z_string_drop(&mut moved) };
        out
    }

    /// The accessors reproduce what the view carried — the PRESENT-attachment
    /// arm included, which no foreign CLI on this machine can drive (the only
    /// pico example that attaches, `z_pub_attachment`, publishes through a
    /// declared publisher, and that path delivers nothing even pico-to-pico in
    /// the topology the interop legs use — measured, R311y500).
    #[test]
    fn the_accessors_reproduce_a_sample_that_carries_an_attachment() {
        let view = View {
            keyexpr: "demo/capic/att",
            payload: b"BODY",
            kind: SampleKind::Put,
            attachment: Some(b"ATTACHED"),
        };
        with_marshalled(&view, |sample| {
            // SAFETY: `sample` is the marshal's borrowed view, live for this call.
            unsafe {
                assert_eq!(z_sample_kind(sample), Z_SAMPLE_KIND_PUT);
                assert_eq!(to_string(z_sample_payload(sample)), b"BODY");

                let att = z_sample_attachment(sample);
                assert!(
                    !att.is_null(),
                    "an attachment was carried but reported absent"
                );
                assert_eq!(to_string(att), b"ATTACHED");

                let mut view_string = crate::abi::z_view_string_t::null_value();
                z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view_string);
                let loaned = z_view_string_loan(&view_string);
                let text = std::slice::from_raw_parts(
                    z_string_data(loaned) as *const u8,
                    z_string_len(loaned),
                );
                assert_eq!(text, b"demo/capic/att");
            }
        });
    }

    /// A marshal kept from one sample to the next reads as the sample it was last loaded
    /// with and as nothing of the one before: the key, the payload, the attachment (present
    /// for one sample, absent for the next, present again) and the kind each follow the
    /// sample, through the SAME marshal, which is what the subscriber's callback does.
    #[test]
    fn a_kept_marshal_reads_as_the_sample_it_was_last_loaded_with() {
        let samples = [
            ("a/one", &b"ONE"[..], Some(&b"ATT"[..])),
            ("b/two/longer", &b"TWO22"[..], None),
            ("c", &b""[..], None),
            ("a/one", &b"ONE"[..], Some(&b"ATT"[..])),
        ];
        let mut kept = MarshalCache::new();
        for (key, payload, attachment) in samples {
            let view = View {
                keyexpr: key,
                payload,
                kind: SampleKind::Put,
                attachment,
            };
            kept.with_view(&view, |sample| {
                // SAFETY: `sample` is the kept marshal's borrowed view, live for this call.
                unsafe {
                    assert_eq!(to_string(z_sample_payload(sample)), payload, "{key}");
                    let att = z_sample_attachment(sample);
                    match attachment {
                        Some(bytes) => assert_eq!(to_string(att), bytes, "{key}"),
                        None => assert!(att.is_null(), "{key}: a stale attachment"),
                    }
                    let mut view_string = crate::abi::z_view_string_t::null_value();
                    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view_string);
                    let loaned = z_view_string_loan(&view_string);
                    let text = std::slice::from_raw_parts(
                        z_string_data(loaned) as *const u8,
                        z_string_len(loaned),
                    );
                    assert_eq!(text, key.as_bytes());
                }
            });
        }
    }

    /// A view that can carry an encoding and a source info, the two metadata a kept marshal
    /// now writes only when a sample differs from the one before it.
    struct RichView<'a> {
        keyexpr: &'a str,
        payload: &'a [u8],
        encoding: Option<EncodingHint>,
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    }

    impl SampleView for RichView<'_> {
        fn keyexpr(&self) -> &str {
            self.keyexpr
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
        fn encoding(&self) -> Option<&EncodingHint> {
            self.encoding.as_ref()
        }
        fn source_info(&self) -> Option<&wz_runtime_tokio::sample::SourceInfo> {
            self.source_info.as_ref()
        }
    }

    /// The encoding a sample reports, rendered, as a C program reads it.
    unsafe fn encoding_text(sample: *const z_loaned_sample_t) -> Vec<u8> {
        let mut out = crate::abi::z_owned_string_t::null_value();
        crate::encoding::z_encoding_to_string(z_sample_encoding(sample), &mut out);
        let loaned = crate::string::z_string_loan(&out);
        let text =
            std::slice::from_raw_parts(z_string_data(loaned) as *const u8, z_string_len(loaned))
                .to_vec();
        let mut moved = crate::abi::z_moved_string_t { _this: out };
        z_string_drop(&mut moved);
        text
    }

    /// A kept marshal writes the encoding and the source info only when a sample differs from
    /// the last, and reads as each sample all the same: a sample that has them, one that has
    /// none after it, the same one again, and a different one. The first sample's absence is
    /// the default encoding, which is what an absent E-flag means.
    #[test]
    fn a_kept_marshal_follows_the_encoding_and_the_source_info_of_each_sample() {
        use wz_runtime_tokio::sample::SourceInfo;
        let text = EncodingHint {
            packed_id: wz_capi_core::encoding_ids::lookup_id("text/plain")
                .map(|id| (id as u32) << 1)
                .expect("text/plain is in the table"),
            schema: None,
        };
        let samples = [
            (None, None),
            (Some(text.clone()), Some(SourceInfo::new(&[7; 4], 3, 11))),
            (None, None),
            (Some(text.clone()), Some(SourceInfo::new(&[7; 4], 3, 12))),
            (Some(text), None),
            (None, Some(SourceInfo::new(&[9; 2], 1, 99))),
            (None, None),
        ];
        let mut kept = MarshalCache::new();
        for (index, (encoding, source_info)) in samples.into_iter().enumerate() {
            let view = RichView {
                keyexpr: "k",
                payload: b"p",
                encoding: encoding.clone(),
                source_info,
            };
            let want = match encoding.as_ref() {
                Some(hint) => wz_capi_core::encoding_ids::hint_to_string_in(
                    hint,
                    wz_capi_core::encoding_ids::EncodingDialect::ZenohC,
                )
                .into_bytes(),
                None => b"zenoh/bytes".to_vec(),
            };
            kept.with_view(&view, |sample| {
                // SAFETY: `sample` is the kept marshal's borrowed view, live for this call.
                unsafe {
                    assert_eq!(encoding_text(sample), want, "sample {index}: its encoding");
                    // The accessor is the unstable API's: without it the source info is kept
                    // and not readable.
                    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
                    {
                        let info = z_sample_source_info(sample);
                        match view.source_info.as_ref() {
                            Some(expected) => {
                                assert!(
                                    !info.is_null(),
                                    "sample {index}: source info carried but absent"
                                );
                                assert_eq!(
                                    crate::source_info::z_source_info_sn(info),
                                    expected.sn,
                                    "sample {index}: its source sequence number"
                                );
                            }
                            None => {
                                assert!(info.is_null(), "sample {index}: a stale source info")
                            }
                        }
                    }
                }
            });
        }
    }

    /// A view whose caller says whether its key is the last one's. A view that says it is has
    /// no key to read: a kept marshal that read it anyway would panic here.
    struct KeyedView {
        key: &'static str,
        unchanged: bool,
    }

    impl SampleView for KeyedView {
        fn keyexpr(&self) -> &str {
            assert!(!self.unchanged, "the key of an unchanged sample was read");
            self.key
        }
        fn payload(&self) -> &[u8] {
            b"p"
        }
        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn keyexpr_unchanged(&self) -> bool {
            self.unchanged
        }
    }

    /// A kept marshal keeps the last key's text when the caller says the next sample has the
    /// same one, and rewrites it when the caller does not, through every change of key.
    #[test]
    fn a_kept_marshal_leaves_the_key_alone_when_the_caller_says_it_is_the_same() {
        let samples = [
            ("a", false),
            ("a", true),
            ("a", true),
            ("longer/key", false),
            ("longer/key", true),
            ("a", false),
            ("a", true),
        ];
        let mut kept = MarshalCache::new();
        for (index, (key, unchanged)) in samples.into_iter().enumerate() {
            kept.with_view(&KeyedView { key, unchanged }, |sample| {
                // SAFETY: `sample` is the kept marshal's borrowed view, live for this call.
                unsafe {
                    let mut view_string = crate::abi::z_view_string_t::null_value();
                    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view_string);
                    let loaned = z_view_string_loan(&view_string);
                    let text = std::slice::from_raw_parts(
                        z_string_data(loaned) as *const u8,
                        z_string_len(loaned),
                    );
                    assert_eq!(text, key.as_bytes(), "sample {index}");
                }
            });
        }
    }

    /// A view that is a plain Put when `plain` says so, and carries whatever else it was built
    /// with when it does not, with a QoS of its own.
    struct MixedView {
        plain: bool,
        qos: Option<QosLevel>,
        delete: bool,
        attachment: Option<&'static [u8]>,
        encoding: Option<EncodingHint>,
        source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
    }

    impl SampleView for MixedView {
        fn keyexpr(&self) -> &str {
            "k"
        }
        fn payload(&self) -> &[u8] {
            b"p"
        }
        fn kind(&self) -> SampleKind {
            if self.delete {
                SampleKind::Del
            } else {
                SampleKind::Put
            }
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn qos(&self) -> Option<QosLevel> {
            self.qos
        }
        fn attachment(&self) -> Option<&[u8]> {
            self.attachment
        }
        fn encoding(&self) -> Option<&EncodingHint> {
            self.encoding.as_ref()
        }
        fn source_info(&self) -> Option<&wz_runtime_tokio::sample::SourceInfo> {
            self.source_info.as_ref()
        }
        fn is_plain_put(&self) -> bool {
            self.plain
        }
    }

    /// A kept marshal that skips the fields a plain Put does not vary reads, after a plain Put
    /// that follows a plain Put, a sample that has none of them and its own QoS, and after a
    /// sample that is not plain follows it, nothing of what that one carried.
    #[test]
    fn a_kept_marshal_follows_plain_puts_and_the_samples_between_them() {
        use wz_runtime_tokio::sample::SourceInfo;
        let text = EncodingHint {
            packed_id: wz_capi_core::encoding_ids::lookup_id("text/plain")
                .map(|id| (id as u32) << 1)
                .expect("text/plain is in the table"),
            schema: None,
        };
        let plain = |qos| MixedView {
            plain: true,
            qos,
            delete: false,
            attachment: None,
            encoding: None,
            source_info: None,
        };
        let rich = |delete, attachment, encoding, source_info| MixedView {
            plain: false,
            qos: None,
            delete,
            attachment,
            encoding,
            source_info,
        };
        let views = [
            plain(Some(QosLevel::from_raw(0x1a))),
            plain(Some(QosLevel::from_raw(0x05))),
            plain(None),
            rich(
                true,
                Some(&b"ATT"[..]),
                Some(text.clone()),
                Some(SourceInfo::new(&[7; 4], 3, 11)),
            ),
            plain(Some(QosLevel::from_raw(0x1a))),
            plain(Some(QosLevel::from_raw(0x05))),
            rich(false, None, None, Some(SourceInfo::new(&[9; 2], 1, 2))),
            plain(None),
            rich(false, Some(&b"X"[..]), None, None),
            rich(false, None, Some(text), None),
            plain(Some(QosLevel::from_raw(0x1a))),
        ];
        let mut kept = MarshalCache::new();
        for (index, view) in views.iter().enumerate() {
            kept.with_view(view, |sample| {
                // SAFETY: `sample` is the kept marshal's borrowed view, live for this call.
                let m = unsafe { marshal(sample) }.expect("a live sample");
                assert_eq!(m.qos, view.qos, "sample {index}: its QoS");
                assert_eq!(
                    m.attachment.is_some(),
                    view.attachment.is_some(),
                    "sample {index}: its attachment"
                );
                assert_eq!(
                    m.source_info.is_some(),
                    view.source_info.is_some(),
                    "sample {index}: its source info"
                );
                assert_eq!(
                    m.encoding.is_default(),
                    view.encoding.is_none(),
                    "sample {index}: its encoding"
                );
                let want = if view.delete {
                    Z_SAMPLE_KIND_DELETE
                } else {
                    Z_SAMPLE_KIND_PUT
                };
                assert_eq!(m.kind, want, "sample {index}: its kind");
                assert!(m.timestamp.is_none(), "sample {index}: no timestamp");
            });
        }
    }

    /// Real plain samples of a frame (the kind a subscriber's callback is handed) through a
    /// kept marshal: the key text, the payload and its one boundary, the QoS and the
    /// reliability follow each sample through the one-question path, across a change of key,
    /// an empty payload, a payload the frame was not said to hold as one run, and a sample
    /// that is not plain between two that are.
    #[test]
    fn a_kept_marshal_follows_real_plain_samples_of_a_frame() {
        use wz_runtime_tokio::sink::PlainSample;
        let frame = wz_runtime_tokio::RxBytes::from(b"0123456789abcdef".to_vec());
        let q = |raw: u8| Some(QosLevel::from_raw(raw));
        // (key, payload range, qos, key unchanged, frame said to be one run)
        let plain_steps: [(&str, (u32, u32), Option<QosLevel>, bool, bool); 8] = [
            ("a/b", (0, 4), q(0x1a), false, true),
            ("a/b", (4, 10), q(0x05), true, true),
            ("a/b", (10, 10), None, true, true),
            ("a/b", (10, 16), q(0x1a), true, true),
            ("cc", (2, 6), None, false, true),
            ("cc", (6, 12), q(0x01), true, false),
            ("cc", (0, 1), q(0x01), true, true),
            ("a/b", (3, 9), None, false, true),
        ];
        let mut kept = MarshalCache::new();
        let mut index = 0;
        for (key, range, qos, unchanged, single) in plain_steps {
            // After the fourth, a sample that is not plain comes between.
            if index == 4 {
                let rich = MixedView {
                    plain: false,
                    qos: None,
                    delete: false,
                    attachment: Some(b"ATT"),
                    encoding: None,
                    source_info: None,
                };
                kept.with_view(&rich, |sample| {
                    // SAFETY: `sample` is the kept marshal's borrowed view, live for this call.
                    let m = unsafe { marshal(sample) }.expect("a live sample");
                    assert!(m.attachment.is_some(), "the rich sample's attachment");
                });
            }
            let mut sample = PlainSample::new(key, &frame, range, Reliability::Reliable, qos);
            if unchanged && index != 4 {
                sample = sample.with_unchanged_key();
            }
            if single {
                sample = sample.with_single_run_frame();
            }
            kept.with_view(&sample, |loaned| {
                // SAFETY: `loaned` is the kept marshal's borrowed view, live for this call.
                let m = unsafe { marshal(loaned) }.expect("a live sample");
                let want = &frame.as_slice()[range.0 as usize..range.1 as usize];
                assert_eq!(m.keyexpr.keyexpr, key, "step {index}: its key");
                assert_eq!(&*m.payload.payload, want, "step {index}: its payload");
                let bounds: &[usize] = m.payload.bounds.as_slice();
                if want.is_empty() {
                    assert!(
                        bounds.is_empty(),
                        "step {index}: an empty payload has no slice"
                    );
                } else {
                    assert_eq!(bounds, [want.len()], "step {index}: one slice, its length");
                }
                assert_eq!(m.qos, qos, "step {index}: its QoS");
                assert!(m.attachment.is_none(), "step {index}: a stale attachment");
                assert_eq!(m.kind, Z_SAMPLE_KIND_PUT, "step {index}: its kind");
            });
            index += 1;
        }
    }

    /// NULL is the absence signal upstream's `z_sub.c` branches on, so a sample
    /// with no attachment must not hand back an empty-but-present blob. This is
    /// the arm the interop legs DO cover (they publish without attachments), and
    /// it is asserted here too so the pair is one test away from each other.
    #[test]
    fn a_sample_without_an_attachment_reports_null_not_an_empty_blob() {
        let view = View {
            keyexpr: "demo/capic/plain",
            payload: b"",
            kind: SampleKind::Del,
            attachment: None,
        };
        with_marshalled(&view, |sample| {
            // SAFETY: as above.
            unsafe {
                assert_eq!(z_sample_kind(sample), Z_SAMPLE_KIND_DELETE);
                assert!(
                    z_sample_attachment(sample).is_null(),
                    "no attachment was carried, so the accessor must report NULL — an \
                     empty blob would make upstream print an attachment never sent"
                );
            }
        });
    }

    /// A gravestone must not be dereferenced. Every accessor takes the pointer
    /// the C side was handed, and a C program that keeps one past its callback is
    /// the case upstream documents as its own error — but NULL is reachable
    /// through ordinary use (a failed declare), so it is answered rather than
    /// trusted.
    #[test]
    fn the_accessors_answer_a_null_sample_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(z_sample_keyexpr(std::ptr::null()).is_null());
            assert!(z_sample_payload(std::ptr::null()).is_null());
            assert!(z_sample_attachment(std::ptr::null()).is_null());
            assert_eq!(z_sample_kind(std::ptr::null()), Z_SAMPLE_KIND_PUT);
        }
    }
}

// --- R311y539: the OWNED sample --------------------------------------------

impl SampleMarshal {
    /// An INDEPENDENT copy with its cached views still UNBOUND, for a sample
    /// that must outlive the callback it was delivered to.
    ///
    /// The views are deliberately left unbound rather than copied: they hold
    /// the ADDRESS of the source marshal's fields, and copying them would aim
    /// the new sample's accessors at the old marshal — a use-after-free the
    /// moment the callback returns. [`Self::bind`] re-aims them at the copy's
    /// own fields once it is at its final address.
    pub(crate) fn deep_copy(&self) -> Self {
        Self {
            keyexpr: KeyexprState::new(self.keyexpr.keyexpr.clone()),
            payload: BytesState::of(self.payload.payload.clone()),
            attachment: self
                .attachment
                .as_ref()
                .map(|state| BytesState::of(state.payload.clone())),
            kind: self.kind,
            // `Copy`, and owned by value — the deep copy carries the same
            // 24 bytes rather than a pointer into the source marshal, so a
            // sample that outlives its callback keeps its own timestamp.
            timestamp: self.timestamp,
            // CLONED for the same reason the timestamp is copied: the deep copy
            // must own its identity, not borrow the source marshal's.
            source_info: self.source_info.clone(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info_c: crate::source_info::z_source_info_t::empty(),
            // A copy that OWNS its label. Cloning the `Cow` would share a
            // `Borrowed` static (fine) or duplicate an `Owned` (also fine) —
            // what must not happen is the copy pointing into the source
            // marshal's allocation, which is why this goes through the state's
            // own clone rather than the loaned view.
            encoding: self.encoding.deep_copy(),
            qos: self.qos,
            reliability: self.reliability,
            plain: false,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
            loaned_encoding: z_loaned_encoding_t::null_value(),
        }
    }
}

/// Escape a borrowed sample onto the heap, bound at its final address — what a
/// sample CHANNEL does when the callback hands it a sample.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a sample callback.
pub(crate) unsafe fn escape_sample(src: *const z_loaned_sample_t) -> crate::abi::Handle {
    // SAFETY: the caller's contract, delegated.
    let Some(m) = (unsafe { marshal(src) }) else {
        return std::ptr::null_mut();
    };
    let mut boxed = Box::new(m.deep_copy());
    boxed.bind();
    Box::into_raw(boxed) as crate::abi::Handle
}

/// A sample copied out of a callback and kept, bound at its final address and
/// owned by whoever holds the value.
///
/// [`escape_sample`] is the same copy handed to C as a `z_owned_sample_t`; this is
/// it for code inside the crate that has to hold a sample past its callback and
/// give it back to a user closure later, which wants a `z_loaned_sample_t`. The
/// zenoh-ext querying subscriber is the first such holder: it parks live samples
/// and replies until the queries in flight have ended.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub(crate) struct EscapedSample(Box<SampleMarshal>);

// SAFETY: the box is owned by this value alone and its cached views point only
// into itself, so moving the value to another thread moves the whole closed
// object. Whoever holds one reaches it through one lock at a time.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
unsafe impl Send for EscapedSample {}

#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
impl EscapedSample {
    /// A deep copy of a borrowed sample, or `None` for a null one.
    ///
    /// # Safety
    /// `src` must be null or a pointer this crate handed to a sample callback.
    pub(crate) unsafe fn copy_of(src: *const z_loaned_sample_t) -> Option<Self> {
        // SAFETY: the caller's contract.
        let source = unsafe { marshal(src) }?;
        let mut copy = Box::new(source.deep_copy());
        copy.bind();
        Some(Self(copy))
    }

    /// The sample's own timestamp, or `None` when it carries none.
    pub(crate) fn timestamp(&self) -> Option<crate::timestamp::z_timestamp_t> {
        self.0.timestamp
    }

    /// Give the sample a timestamp. `z_sample_timestamp` points into the marshal,
    /// so a caller that reads it afterwards sees this one.
    pub(crate) fn stamp(&mut self, timestamp: crate::timestamp::z_timestamp_t) {
        self.0.timestamp = Some(timestamp);
    }

    /// The borrowed sample a user closure is called with.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_sample_t {
        self.0.as_loaned()
    }
}

/// Borrow an owned sample (zenoh-c `z_sample_loan`).
///
/// The handle IS the marshal pointer the accessors read, so this reads slot 0
/// rather than casting the owned struct.
///
/// # Safety
/// `this_` must be null or a valid owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_loan(
    this_: *const crate::abi::z_owned_sample_t,
) -> *const z_loaned_sample_t {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *const z_loaned_sample_t }
    })
}

/// Mutably borrow an owned sample (zenoh-c `z_sample_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_loan_mut(
    this_: *mut crate::abi::z_owned_sample_t,
) -> *mut z_loaned_sample_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *mut z_loaned_sample_t }
    })
}

/// Take ownership of a mutably borrowed sample (zenoh-c
/// `z_sample_take_from_loaned`).
///
/// ## A COPY, and the divergence is deliberate
///
/// Upstream MOVES the Rust `Sample` out of the loaned slot, leaving it
/// moved-from. wz cannot: a `z_loaned_sample_t*` in this crate is a pointer at a
/// [`SampleMarshal`] whose STORAGE belongs to someone else — the dispatcher's
/// stack frame inside [`with_marshalled`], or a `Box` behind a live
/// `z_owned_sample_t` — and nothing in the pointer says which. Stealing the
/// marshal would leave either a dangling owned value or a freed stack slot.
///
/// So this deep-copies, through the same [`escape_sample`] every channel handler
/// uses. The C contract is unaffected: `dst` is a valid owned sample and `src`
/// must not be used again, which is exactly what upstream promises. The one
/// thing a caller could observe is `src` still reading as live afterwards — and
/// there is no `z_internal_loaned_sample_check` for a caller to ask with, so the
/// difference is unobservable through the ABI rather than merely unlikely to be
/// noticed.
///
/// # Safety
/// `dst` must be null or valid and writable; `src` must be null or a live loaned
/// sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_take_from_loaned(
    dst: *mut crate::abi::z_owned_sample_t,
    src: *mut z_loaned_sample_t,
) {
    // SAFETY: the caller's contract, delegated — a mutable loan is a valid
    // immutable one, and the copy reads only.
    unsafe { z_sample_clone(dst, src as *const z_loaned_sample_t) };
}

/// Deep-copy a borrowed sample into an owned one (zenoh-c `z_sample_clone`).
///
/// # Safety
/// `dst` must be null or valid and writable; `this_` must be null or a live
/// loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_clone(
    dst: *mut crate::abi::z_owned_sample_t,
    this_: *const z_loaned_sample_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // The gravestone first, so a caller that clones a null sample sees an
        // empty owned value rather than a stale stack one.
        // SAFETY: the caller's contract.
        unsafe { *dst = crate::abi::z_owned_sample_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let handle = unsafe { escape_sample(this_) };
        if !handle.is_null() {
            // SAFETY: as above.
            unsafe { *dst = crate::abi::z_owned_sample_t::from_handle(handle) };
        }
    });
}

/// `true` iff the owned sample holds a live marshal (zenoh-c
/// `z_internal_sample_check`).
///
/// # Safety
/// `this_` must be null or a valid owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_internal_sample_check(
    this_: *const crate::abi::z_owned_sample_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned sample (zenoh-c `z_internal_sample_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_internal_sample_null(this_: *mut crate::abi::z_owned_sample_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_sample_t::null_value() };
    }
}

/// Free an owned sample (zenoh-c `z_sample_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_drop(this_: *mut crate::abi::z_moved_sample_t) {
    let _ = crate::ffi::guarded(|| {
        if this_.is_null() {
            return crate::result::Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<SampleMarshal>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut SampleMarshal) });
            unsafe { (*this_)._this = crate::abi::z_owned_sample_t::null_value() };
        }
        crate::result::Z_OK
    });
}

#[cfg(test)]
mod owned_tests {
    use super::*;
    use wz_runtime_tokio::Reliability;

    /// A `SampleView` the escape test can build without a session.
    struct View;

    impl SampleView for View {
        fn keyexpr(&self) -> &str {
            "demo/owned"
        }
        fn payload(&self) -> &[u8] {
            b"BODY"
        }
        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn attachment(&self) -> Option<&[u8]> {
            Some(b"ATT")
        }
    }

    /// An escaped sample OUTLIVES the callback and still reads correctly.
    ///
    /// The damage this guards is specific: `deep_copy` leaves the cached loaned
    /// views UNBOUND on purpose, and copying them instead would leave the
    /// escaped sample's accessors pointing into the callback's dead frame. This
    /// test reads the copy AFTER `with_marshalled` has returned, which is
    /// exactly when that would surface.
    #[test]
    fn an_escaped_sample_outlives_the_callback_that_delivered_it() {
        let mut owned = crate::abi::z_owned_sample_t::null_value();
        with_marshalled(&View, |sample| {
            // SAFETY: `sample` is live for this call.
            unsafe { z_sample_clone(&mut owned, sample) };
        });
        // SAFETY: `owned` is a live heap marshal, independent of the frame
        // above, which has now returned.
        unsafe {
            assert!(z_internal_sample_check(&owned));
            let loaned = z_sample_loan(&owned);
            assert_eq!(z_sample_kind(loaned), Z_SAMPLE_KIND_PUT);

            let mut view_string = crate::abi::z_view_string_t::null_value();
            z_keyexpr_as_view_string(z_sample_keyexpr(loaned), &mut view_string);
            let ls = crate::string::z_view_string_loan(&view_string);
            assert_eq!(
                std::slice::from_raw_parts(
                    crate::string::z_string_data(ls) as *const u8,
                    crate::string::z_string_len(ls)
                ),
                b"demo/owned"
            );
            assert_eq!(
                crate::bytes::bytes_slice(z_sample_payload(loaned)).unwrap(),
                b"BODY"
            );
            assert_eq!(
                crate::bytes::bytes_slice(z_sample_attachment(loaned)).unwrap(),
                b"ATT"
            );

            let mut moved = crate::abi::z_moved_sample_t { _this: owned };
            z_sample_drop(&mut moved);
            assert!(!z_internal_sample_check(&moved._this));
            // Idempotent — the slot was nulled.
            z_sample_drop(&mut moved);
        }
    }

    /// Cloning a NULL sample yields a gravestone, not a dereference.
    #[test]
    fn cloning_a_null_sample_yields_a_gravestone() {
        let mut owned = crate::abi::z_owned_sample_t::from_handle(1 as crate::abi::Handle);
        // SAFETY: passing NULL is exactly what this guard exists for.
        unsafe {
            z_sample_clone(&mut owned, std::ptr::null());
            assert!(!z_internal_sample_check(&owned));
            assert!(z_sample_loan(std::ptr::null()).is_null());
        }
    }
}
