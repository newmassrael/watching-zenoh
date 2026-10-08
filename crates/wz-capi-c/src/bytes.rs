// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Payload bytes.
//!
//! `z_bytes_from_static_str` is the one upstream's `z_put.c` calls, and its
//! contract is that the string is `'static` so nothing needs copying. wz copies
//! anyway: the payload has to reach a bounded wire codec on another thread, and
//! a borrow whose lifetime is asserted by the CALLER is not something this side
//! can verify. Copying is the safe direction — a caller who honours the static
//! contract loses only an allocation.

use std::ffi::{c_char, c_int, c_void, CStr};

use crate::abi::{z_loaned_bytes_t, z_moved_bytes_t, z_owned_bytes_t, z_owned_string_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::owned_string_from;

/// The owned payload behind a bytes handle.
///
/// ## `bounds` exists because upstream's payload is a LIST of slices
///
/// zenoh's `ZBytes` is a sequence of buffers, not one contiguous run, and
/// `z_bytes_get_slice_iterator` walks that sequence — so a payload built by
/// three `z_bytes_writer_append` calls yields THREE slices upstream, and
/// `z_bytes.c` prints one line per slice. Collapsing them to one is observable
/// in that program's stdout even though `z_bytes_len` and `z_bytes_to_string`
/// agree either way.
///
/// wz keeps the payload CONTIGUOUS (every wire path wants one run of bytes) and
/// records the slice boundaries as END offsets alongside it. `bounds` is empty
/// exactly when the payload is, matching upstream's zero-slice empty value;
/// otherwise its last element is `payload.len()`.
pub(crate) struct BytesState {
    pub(crate) payload: Payload,
    pub(crate) bounds: Vec<usize>,
    /// The `z_loaned_shm_t` this payload answers `z_bytes_as_loaned_shm` with, made the
    /// first time it is asked and kept for as long as the payload lives, because
    /// the loan is a pointer the caller holds (R3052). `None` inside is a payload
    /// that is not a chunk of shared memory.
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    pub(crate) shm_loan: std::sync::OnceLock<Option<crate::shm::ReceivedShm>>,
}

/// The bytes of a payload: a buffer of its own, or the bytes a session delivered
/// where it received them (R3052).
///
/// The second is what a sample from the wire is: a range of the frame it arrived in,
/// or of the chunk of shared memory a peer sent, shared by reference count the way
/// upstream's `ZBytes` shares its slices. A sample the C side keeps is then a second
/// reference to that storage and not a copy of it, and a payload that is a chunk of
/// shared memory can SAY so ([`Payload::shared_memory`]), which a copy cannot.
/// Every read goes through [`core::ops::Deref`] to `[u8]`, whichever it is.
#[derive(Clone)]
pub(crate) enum Payload {
    Owned(Vec<u8>),
    Shared(wz_runtime_tokio::RxBytes),
    /// A chunk of a provider of THIS process, kept as the chunk (R3059): the payload a
    /// program builds from a buffer with `z_bytes_from_shm`. It reads as its bytes like
    /// any other, and a put of it sends the chunk's descriptor to a peer that negotiated
    /// shared memory and the bytes to one that did not, which a copy cannot do.
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    Issued(std::sync::Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>),
}

impl core::ops::Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Payload::Owned(bytes) => bytes,
            Payload::Shared(bytes) => bytes.as_slice(),
            #[cfg(all(
                feature = "zenoh-c-shared-memory",
                not(feature = "zenoh-c-no-unstable-api")
            ))]
            Payload::Issued(chunk) => chunk.bytes(),
        }
    }
}

impl From<Vec<u8>> for Payload {
    fn from(bytes: Vec<u8>) -> Self {
        Payload::Owned(bytes)
    }
}

impl Payload {
    /// The bytes as an owned `Vec`: moved out when owned, copied when shared.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            Payload::Owned(bytes) => bytes,
            Payload::Shared(bytes) => bytes.into_vec(),
            #[cfg(all(
                feature = "zenoh-c-shared-memory",
                not(feature = "zenoh-c-no-unstable-api")
            ))]
            Payload::Issued(chunk) => chunk.bytes().to_vec(),
        }
    }
}

impl BytesState {
    /// A payload that is ONE slice — every constructor except the writer's.
    pub(crate) fn whole(payload: Vec<u8>) -> Self {
        Self::of(Payload::Owned(payload))
    }

    /// A payload as it arrived: ONE slice, whatever holds it, unless what holds it is a list of
    /// slices kept apart (R3124), whose boundaries are those slices'.
    pub(crate) fn of(payload: Payload) -> Self {
        let bounds = match &payload {
            Payload::Shared(bytes) => bytes
                .slices()
                .scan(0usize, |end, slice| {
                    *end += slice.len();
                    Some(*end)
                })
                .collect(),
            _ if payload.is_empty() => Vec::new(),
            _ => vec![payload.len()],
        };
        Self::from_parts(payload, bounds)
    }

    /// A payload with its slice boundaries named.
    pub(crate) fn from_parts(payload: Payload, bounds: Vec<usize>) -> Self {
        Self {
            payload,
            bounds,
            #[cfg(all(
                feature = "zenoh-c-shared-memory",
                not(feature = "zenoh-c-no-unstable-api")
            ))]
            shm_loan: std::sync::OnceLock::new(),
        }
    }

    /// The `index`-th slice, or `None` past the end.
    ///
    /// R3124 -- of a payload that arrived as several slices kept apart it is the slice itself,
    /// the page it lies in, as upstream's `z_bytes_slice_iterator` walks the slices of a
    /// `ZBytes`; reading the payload as one run is what joins them.
    pub(crate) fn slice(&self, index: usize) -> Option<&[u8]> {
        if let Payload::Shared(bytes) = &self.payload {
            if bytes.slice_count() > 1 {
                return bytes.slices().nth(index);
            }
        }
        let end = *self.bounds.get(index)?;
        let start = if index == 0 {
            0
        } else {
            self.bounds[index - 1]
        };
        self.payload.get(start..end)
    }
}

/// Read the bytes behind a LOANED handle.
///
/// Every loaned bytes in this crate — the one `z_sample_payload` hands out and
/// the one `z_sample_attachment` does — points at a [`BytesState`], so there is
/// one meaning for the handle slot and this one reader serves all of them.
///
/// # Safety
/// `this_` must be null, or a valid loaned bytes whose handle slot holds a live
/// `BytesState` pointer.
pub(crate) unsafe fn bytes_slice<'a>(this_: *const z_loaned_bytes_t) -> Option<&'a [u8]> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `BytesState`, either leaked by this crate or
    // borrowed from a `SampleMarshal` that outlives the callback.
    Some(&unsafe { &*(handle as *const BytesState) }.payload)
}

/// The [`BytesState`] behind a LOANED handle, for a caller that needs more of it
/// than its bytes (R3052: whether the payload is a chunk of shared memory).
///
/// # Safety
/// `this_` must be null, or a valid loaned bytes whose handle slot holds a live
/// `BytesState` pointer.
#[cfg(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
))]
pub(crate) unsafe fn bytes_state<'a>(this_: *const z_loaned_bytes_t) -> Option<&'a BytesState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as `bytes_slice`.
    Some(unsafe { &*(handle as *const BytesState) })
}

/// Take the payload out of a MOVED bytes, leaving a gravestone.
///
/// `z_put` consumes its payload, so this both reads and invalidates — a
/// defensive later `z_bytes_drop` on the same value is then a safe no-op.
///
/// # Safety
/// `moved` must be null or a valid moved bytes whose handle is live.
pub(crate) unsafe fn take_payload(moved: *mut z_moved_bytes_t) -> Option<Vec<u8>> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*moved)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<BytesState>` this crate leaked; reclaimed here.
    let state = unsafe { Box::from_raw(handle as *mut BytesState) };
    unsafe { (*moved)._this = z_owned_bytes_t::null_value() };
    Some(state.payload.into_vec())
}

/// A payload on its way out: the bytes to send, or a chunk of shared memory whose
/// descriptor a peer that negotiated it is sent instead (R3059).
///
/// The two put entry points take one, and so does `z_query_reply` since R3062, because those
/// are the sends with a path that can carry a descriptor; every other consumer of a payload
/// calls [`take_payload`] and gets the bytes whatever the payload was built from.
pub(crate) enum Outbound {
    Bytes(Vec<u8>),
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    Chunk(std::sync::Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>),
}

impl Outbound {
    /// The bytes this payload holds, whichever way it is held: what a path that cannot
    /// carry a descriptor sends, and what the descriptor stands in for on one that can.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Outbound::Bytes(bytes) => bytes,
            #[cfg(all(
                feature = "zenoh-c-shared-memory",
                not(feature = "zenoh-c-no-unstable-api")
            ))]
            Outbound::Chunk(chunk) => chunk.bytes(),
        }
    }
}

/// Take the payload out of a MOVED bytes for a put, leaving a gravestone, keeping a chunk
/// of shared memory a chunk.
///
/// # Safety
/// `moved` must be null or a valid moved bytes whose handle is live.
pub(crate) unsafe fn take_outbound(moved: *mut z_moved_bytes_t) -> Option<Outbound> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*moved)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<BytesState>` this crate leaked; reclaimed here.
    let state = unsafe { Box::from_raw(handle as *mut BytesState) };
    unsafe { (*moved)._this = z_owned_bytes_t::null_value() };
    match state.payload {
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        Payload::Issued(chunk) => Some(Outbound::Chunk(chunk)),
        other => Some(Outbound::Bytes(other.into_vec())),
    }
}

/// The chunk of shared memory a query's value is, when it is one (R3059): the value
/// `z_get` and `z_querier_get` carry as a descriptor to a peer that negotiated shared
/// memory. `None` whenever the value is bytes, and on a build without that axis there is
/// no chunk to be, so the type is uninhabited and the arm that would use it cannot exist.
#[cfg(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
))]
pub(crate) type ValueChunk =
    Option<std::sync::Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>>;
/// See the shared-memory spelling: there is no chunk on this arm.
#[cfg(not(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
)))]
pub(crate) type ValueChunk = Option<std::convert::Infallible>;

/// Take the VALUE of a query out of a MOVED bytes, leaving a gravestone: the bytes to
/// carry, or the chunk they are. At most one of the two is `Some`; both are `None` for an
/// absent value.
///
/// The sibling of [`take_outbound`] for the query side, which splits its answer in two
/// because a query's bytes live in its options and its chunk goes beside them.
///
/// # Safety
/// `moved` must be null or a valid moved bytes whose handle is live.
pub(crate) unsafe fn take_query_value(
    moved: *mut z_moved_bytes_t,
) -> (Option<Vec<u8>>, ValueChunk) {
    // SAFETY: the caller's contract.
    match unsafe { take_outbound(moved) } {
        None => (None, None),
        Some(Outbound::Bytes(bytes)) => (Some(bytes), None),
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        Some(Outbound::Chunk(chunk)) => (None, Some(chunk)),
    }
}

/// Publish `payload` on `keyexpr` over every face: under the declared id when the key was
/// declared (`mapping`), literally otherwise, and as the chunk's descriptor where the
/// payload is a chunk and a face negotiated shared memory.
///
/// The one place the two put entry points decide how a payload goes out, so a declared key
/// and a payload in shared memory are both honoured wherever they meet.
///
/// R3069 -- the payload is CONSUMED, because the put is: `z_put` takes its payload by move
/// and a chunk is handed on to the local leg, whose subscriber's callback runs inside this
/// call and must find the buffer's one holder in the sample and not a second beside the put's
/// own.
pub(crate) fn publish_outbound(
    shared: &wz_capi_core::faces::SharedSession,
    keyexpr: &str,
    mapping: Option<u64>,
    payload: Outbound,
    opts: &wz_runtime_tokio::session::PublishOptions,
) -> Result<usize, wz_capi_core::faces::FanoutError> {
    match (payload, mapping) {
        (Outbound::Bytes(bytes), Some(mapping)) => {
            shared.publish_aliased_all(mapping, None, &bytes, opts)
        }
        (Outbound::Bytes(bytes), None) => shared.publish_all(keyexpr, &bytes, opts),
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        (Outbound::Chunk(chunk), Some(mapping)) => {
            shared.publish_shm_aliased_all(mapping, None, chunk, opts)
        }
        #[cfg(all(
            feature = "zenoh-c-shared-memory",
            not(feature = "zenoh-c-no-unstable-api")
        ))]
        (Outbound::Chunk(chunk), None) => shared.publish_shm_all(keyexpr, chunk, opts),
    }
}

/// Build a payload from a NUL-terminated string (zenoh-c
/// `z_bytes_from_static_str`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_str(
    this_: *mut z_owned_bytes_t,
    str_: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || str_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(str_) }).to_str() else {
            return Z_EPARSE;
        };
        let handle = Box::into_raw(Box::new(BytesState::whole(text.as_bytes().to_vec()))) as Handle;
        unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    })
}

/// Build a payload by COPYING a NUL-terminated string (zenoh-c
/// `z_bytes_copy_from_str`).
///
/// The sibling of [`z_bytes_from_static_str`], and here the two are the same
/// implementation because wz copies either way — see the module note for why the
/// static contract cannot be honoured on this side.
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_str(
    this_: *mut z_owned_bytes_t,
    str_: *const c_char,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_bytes_from_static_str(this_, str_) }
}

/// Build a payload by TAKING OWNERSHIP of a caller buffer (zenoh-c
/// `z_bytes_from_buf`).
///
/// wz copies the bytes and then invokes the caller's `deleter` IMMEDIATELY, on
/// every path including the failure ones. That is not a shortcut: upstream's
/// ownership transfer is unconditional, so a path that skipped the deleter would
/// LEAK the caller's buffer — a divergence visible only in their code. The
/// sibling `wz-capi-pico` records the same decision for the same reason.
///
/// # Safety
/// `this_` must be valid and writable; `data` must be null or point at `len`
/// readable bytes; `deleter` must be null or a valid C function pointer, and owns
/// `data` after this call.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_buf(
    this_: *mut z_owned_bytes_t,
    data: *mut u8,
    len: usize,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    let rc = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // A null buffer with a non-zero length is the caller's error; a null
        // buffer with length 0 is the legitimate empty payload.
        let payload = if data.is_null() {
            if len != 0 {
                return Z_ENULL;
            }
            Vec::new()
        } else {
            // SAFETY: the caller's contract — `len` readable bytes at `data`.
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        let handle = Box::into_raw(Box::new(BytesState::whole(payload))) as Handle;
        unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    });
    // UNCONDITIONAL, and outside the `guarded` body so it runs even on the error
    // returns above.
    if let Some(free) = deleter {
        // SAFETY: upstream's contract — the deleter owns `data` from here, and an
        // unwind across the C boundary is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            free(data as *mut c_void, context);
        }));
    }
    rc
}

/// Deep-copy a payload (zenoh-c `z_bytes_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_clone(dst: *mut z_owned_bytes_t, this_: *const z_loaned_bytes_t) {
    let _ = guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        unsafe { *dst = z_owned_bytes_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            // Upstream returns void here, so a null source leaves the gravestone
            // already written above rather than reporting anything.
            return Z_ENULL;
        };
        let handle = Box::into_raw(Box::new(BytesState::whole(bytes.to_vec()))) as Handle;
        unsafe { *dst = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    });
}

/// Borrow a payload (zenoh-c `z_bytes_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_loan(this_: *const z_owned_bytes_t) -> *const z_loaned_bytes_t {
    this_ as *const z_loaned_bytes_t
}

/// Mutably borrow a payload (zenoh-c `z_bytes_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_loan_mut(this_: *mut z_owned_bytes_t) -> *mut z_loaned_bytes_t {
    this_ as *mut z_loaned_bytes_t
}

/// The payload's length in bytes (zenoh-c `z_bytes_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_len(this_: *const z_loaned_bytes_t) -> usize {
    crate::ffi::guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { bytes_slice(this_) }.map_or(0, <[u8]>::len)
    })
}

/// `true` iff the owned bytes holds a live payload (zenoh-c
/// `z_internal_bytes_check`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_check(this_: *const z_owned_bytes_t) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned bytes (zenoh-c `z_internal_bytes_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_null(this_: *mut z_owned_bytes_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
    }
}

/// Construct the empty payload (zenoh-c `z_bytes_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_empty(this_: *mut z_owned_bytes_t) {
    if this_.is_null() {
        return;
    }
    let handle = Box::into_raw(Box::new(BytesState::whole(Vec::new()))) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
}

/// Copy the payload into an owned string (zenoh-c `z_bytes_to_string`).
///
/// The bytes ARE validated as UTF-8 (R3061): a payload that is not text is refused with
/// `Z_EINVAL` and `dst` left as the gravestone, which is what the real library does
/// (`z_bytes_to_string` @ `Err(e) => {` writes `CStringOwned::gravestone()` and returns
/// `result::Z_EINVAL`). Until R3061 this function copied any bytes and said so was
/// deliberate, on the ground that upstream "prints a byte run with `%.*s`" and refusing
/// would make wz refuse a sample zenoh-c delivers. That premise was never measured, and the
/// measurement (one C program on both libraries, bytes `a 0xff 0xfe b`) is the opposite:
/// the real library answers `-1`, wz answered `0` with the four bytes. A program that
/// branches on the code, as upstream's examples do, took the success arm on wz for a
/// payload the real library calls an error. A program that wants the raw run reads it with
/// [`z_bytes_to_slice`], which takes any bytes on both.
///
/// An embedded NUL is valid UTF-8 and is copied, as on the real library; the string carries
/// bytes and a length.
///
/// # Safety
/// `this_` must be null or a valid loaned bytes; `dst` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_string(
    this_: *const z_loaned_bytes_t,
    dst: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        // Initialised before any fallible work, so a caller that ignores the code
        // sees an empty string rather than a stale stack value.
        unsafe { *dst = z_owned_string_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            return Z_ENULL;
        };
        if std::str::from_utf8(bytes).is_err() {
            return Z_EINVAL;
        }
        unsafe { *dst = owned_string_from(bytes) };
        Z_OK
    })
}

/// Free a payload and reset it to its gravestone state (zenoh-c
/// `z_bytes_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_drop(this_: *mut z_moved_bytes_t) {
    // SAFETY: the caller's contract, delegated — `take_payload` nulls the slot,
    // so a double drop is a no-op.
    let _ = unsafe { take_payload(this_) };
}

// --- R311y539: the reader / writer / slice-iterator plane -------------------

/// Build a payload by COPYING a caller buffer (zenoh-c `z_bytes_copy_from_buf`).
///
/// The COPYING sibling of [`z_bytes_from_buf`]: no deleter, because the caller
/// keeps its buffer.
///
/// # Safety
/// `this_` must be valid and writable; `data` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_buf(
    this_: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        let payload = if data.is_null() {
            if len != 0 {
                return Z_ENULL;
            }
            Vec::new()
        } else {
            // SAFETY: the caller's contract — `len` readable bytes at `data`.
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        let handle = Box::into_raw(Box::new(BytesState::whole(payload))) as Handle;
        unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    })
}

// --- R311y568: the six remaining constructors + the emptiness predicate ------
//
// Every one is a symbol the real `libzenohc.so` defines and this cdylib did not,
// so a C program naming any of them failed at LINK time. They fall into three
// shapes and the file already has one of each: a COPY from a borrowed thing, a
// TAKE of a moved owned thing, and the static-buffer variant whose contract wz
// cannot honour and therefore copies (see the module note).

/// Install `payload` into `this_`, gravestoning it first.
///
/// The tail every constructor in this section shares. It exists because the
/// three-line `Box::into_raw` / `from_handle` sequence was already written out
/// five times in this file, and six more copies is where one of them ends up
/// missing the gravestone — which a caller who ignores the return code reads as
/// a live payload sitting on a stale stack value.
///
/// # Safety
/// `this_` must be non-null, valid and writable.
unsafe fn install_payload(this_: *mut z_owned_bytes_t, payload: Vec<u8>) {
    let handle = Box::into_raw(Box::new(BytesState::whole(payload))) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
}

/// Build a payload by COPYING a loaned SLICE (zenoh-c
/// `z_bytes_copy_from_slice`).
///
/// # Safety
/// `this_` must be valid and writable; `slice` must be null or a valid loaned
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_slice(
    this_: *mut z_owned_bytes_t,
    slice: *const crate::abi::z_loaned_slice_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // A null slice yields the EMPTY payload rather than a gravestone:
        // upstream's signature returns `void`, so a caller has no way to learn
        // that construction failed and would go on to loan a dead value.
        // SAFETY: the caller's contract.
        let bytes = unsafe { crate::slice::loaned_slice_bytes(slice) }.unwrap_or(&[]);
        // SAFETY: `this_` is non-null and writable.
        unsafe { install_payload(this_, bytes.to_vec()) };
        Z_OK
    });
}

/// Build a payload by COPYING a loaned STRING (zenoh-c
/// `z_bytes_copy_from_string`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or a valid loaned
/// string.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_string(
    this_: *mut z_owned_bytes_t,
    str_: *const crate::abi::z_loaned_string_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // The string's own `len` EXCLUDES wz's trailing NUL (see
        // `crate::string`), so the payload is the text and not the terminator —
        // which is what upstream's `z_bytes_copy_from_string` puts on the wire.
        // SAFETY: the caller's contract.
        let bytes = unsafe { crate::string::loaned_string_bytes(str_) }.unwrap_or(&[]);
        // SAFETY: `this_` is non-null and writable.
        unsafe { install_payload(this_, bytes.to_vec()) };
        Z_OK
    });
}

/// Build a payload by CONSUMING an owned slice (zenoh-c `z_bytes_from_slice`).
///
/// # Safety
/// `this_` must be valid and writable; `slice` must be null or a valid moved
/// slice, which is consumed.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_slice(
    this_: *mut z_owned_bytes_t,
    slice: *mut crate::abi::z_moved_slice_t,
) {
    let _ = guarded(|| {
        // The move is UNCONDITIONAL and happens first, so an early return still
        // consumes what upstream would have consumed — the same discipline
        // `z_bytes_from_buf` states for its deleter.
        // SAFETY: the caller's contract.
        let taken = unsafe { crate::slice::take_moved_slice(slice) };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // SAFETY: `this_` is non-null and writable.
        unsafe { install_payload(this_, taken.unwrap_or_default()) };
        Z_OK
    });
}

/// Build a payload by CONSUMING an owned string (zenoh-c
/// `z_bytes_from_string`).
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or a valid moved string,
/// which is consumed.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_string(
    this_: *mut z_owned_bytes_t,
    s: *mut crate::abi::z_moved_string_t,
) {
    let _ = guarded(|| {
        // Unconditional, for the reason given in `z_bytes_from_slice`.
        // SAFETY: the caller's contract.
        let taken = unsafe { crate::string::take_moved_string(s) };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // SAFETY: `this_` is non-null and writable.
        unsafe { install_payload(this_, taken.unwrap_or_default()) };
        Z_OK
    });
}

/// Build a payload over a caller buffer with STATIC lifetime (zenoh-c
/// `z_bytes_from_static_buf`).
///
/// wz COPIES, exactly as [`z_bytes_from_static_str`] does and for the same
/// reason the module note gives: the wz payload path owns its bytes, so a
/// zero-copy borrow of the caller's buffer is not representable. The divergence
/// is a copy the caller does not pay for upstream and is unobservable through the
/// ABI — upstream's contract only PERMITS the borrow, it does not let the caller
/// detect one.
///
/// # Safety
/// `this_` must be valid and writable; `data` must be null or point at `len`
/// readable bytes that live for the program's duration.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_buf(
    this_: *mut z_owned_bytes_t,
    data: *mut u8,
    len: usize,
) -> ZResult {
    // SAFETY: the caller's contract, delegated — a `'static` buffer is a valid
    // readable one, and the copying twin makes no further demand of it.
    unsafe { z_bytes_copy_from_buf(this_, data as *const u8, len) }
}

/// Build a payload by TAKING OWNERSHIP of a caller STRING (zenoh-c
/// `z_bytes_from_str`).
///
/// The string sibling of [`z_bytes_from_buf`], with the same unconditional
/// deleter discipline: wz copies the text and runs the caller's `deleter` on
/// every path, because upstream's ownership transfer is unconditional and a
/// skipped deleter would leak the caller's buffer.
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or NUL-terminated;
/// `deleter` must be null or a valid C function pointer, and owns `str_` after
/// this call.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_str(
    this_: *mut z_owned_bytes_t,
    str_: *mut c_char,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    let rc = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        if str_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — NUL-terminated.
        let bytes = unsafe { CStr::from_ptr(str_) }.to_bytes().to_vec();
        // SAFETY: `this_` is non-null and writable.
        unsafe { install_payload(this_, bytes) };
        Z_OK
    });
    // UNCONDITIONAL, outside the `guarded` body so it runs on the error returns
    // above too.
    if let Some(free) = deleter {
        // SAFETY: upstream's contract — the deleter owns `str_` from here, and
        // an unwind across the C boundary is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            free(str_ as *mut c_void, context);
        }));
    }
    rc
}

/// `true` iff the payload carries no bytes (zenoh-c `z_bytes_is_empty`).
///
/// A gravestone reads as EMPTY, which is upstream's answer for a null loan and
/// the same convention [`crate::slice::z_slice_is_empty`] follows.
///
/// # Safety
/// `this_` must be null or a valid loaned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_is_empty(this_: *const z_loaned_bytes_t) -> bool {
    crate::ffi::guard_val(true, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { bytes_slice(this_) }.map_or(true, <[u8]>::is_empty)
    })
}

/// Borrow the payload as a contiguous VIEW slice, without copying (zenoh-c
/// `z_bytes_get_contiguous_view`).
///
/// ## wz always succeeds here, and that is a superset rather than a shortcut
///
/// Upstream fails when the `ZBytes` is a sequence of several buffers, because
/// there is no single run to point at. wz's payload IS contiguous by
/// construction — see [`BytesState`], which keeps one `Vec<u8>` and records the
/// slice boundaries alongside it — so the case upstream refuses cannot arise.
///
/// A caller that checks the return code is served correctly either way; one that
/// relies on the FAILURE (to detect a multi-slice payload) should be asking
/// [`z_bytes_get_slice_iterator`] instead, which reports the boundaries wz does
/// keep.
///
/// UNSTABLE-gated, as upstream gates it.
///
/// # Safety
/// `this_` must be null or a valid loaned bytes that outlives every use of the
/// view; `view` must be null or valid and writable.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_contiguous_view(
    this_: *const z_loaned_bytes_t,
    view: *mut crate::abi::z_view_slice_t,
) -> ZResult {
    guarded(|| {
        if view.is_null() {
            return Z_ENULL;
        }
        // Gravestoned before any fallible work, so a caller that ignores the
        // code loans an empty view rather than a stale stack value.
        // SAFETY: the caller's contract.
        unsafe { *view = crate::abi::z_view_slice_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            return Z_ENULL;
        };
        // A BORROW of the payload this crate owns — the caller's own
        // `z_owned_bytes_t` is what keeps it alive, which is upstream's contract
        // for this view too.
        // SAFETY: as above.
        unsafe { *view = crate::slice::view_slice_over(bytes) };
        Z_OK
    })
}

/// Copy the payload into an owned SLICE (zenoh-c `z_bytes_to_slice`) — the
/// bytes-shaped twin of [`z_bytes_to_string`].
///
/// # Safety
/// `this_` must be null or a valid loaned bytes; `dst` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_slice(
    this_: *const z_loaned_bytes_t,
    dst: *mut crate::abi::z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        // Initialised before any fallible work, so a caller that ignores the
        // code sees an empty slice rather than a stale stack value.
        unsafe { *dst = crate::abi::z_owned_slice_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            return Z_ENULL;
        };
        unsafe { *dst = crate::slice::owned_slice_from(bytes) };
        Z_OK
    })
}

/// A cursor over a payload (zenoh-c `z_bytes_reader_t`, 24 bytes).
///
/// Returned BY VALUE into a C stack slot and never dropped — upstream exports no
/// `z_bytes_reader_drop` — so this must own nothing. It BORROWS the payload it
/// was built from, and the C program's own `z_owned_bytes_t` is what keeps that
/// alive. Only the SIZE is ABI; C never inspects the fields, it only takes the
/// address.
#[repr(C)]
pub struct z_bytes_reader_t {
    pub(crate) ptr: *const u8,
    pub(crate) len: usize,
    pub(crate) pos: usize,
}

const _: () = {
    assert!(std::mem::size_of::<z_bytes_reader_t>() == 24);
    assert!(std::mem::align_of::<z_bytes_reader_t>() == 8);
};

/// Build a reader over a payload (zenoh-c `z_bytes_get_reader`).
///
/// # Safety
/// `data` must be null or a valid loaned bytes that outlives every use of the
/// returned reader.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_reader(data: *const z_loaned_bytes_t) -> z_bytes_reader_t {
    // SAFETY: the caller's contract, delegated.
    let bytes = unsafe { bytes_slice(data) }.unwrap_or(&[]);
    z_bytes_reader_t {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        pos: 0,
    }
}

/// Read up to `len` bytes out of a reader, returning how many were copied
/// (zenoh-c `z_bytes_reader_read`).
///
/// # Safety
/// `this_` must be null or a valid reader whose payload is still alive; `dst`
/// must be null or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_read(
    this_: *mut z_bytes_reader_t,
    dst: *mut u8,
    len: usize,
) -> usize {
    crate::ffi::guard_val(0, || {
        if this_.is_null() || dst.is_null() || len == 0 {
            return 0;
        }
        // SAFETY: the caller's contract.
        let reader = unsafe { &mut *this_ };
        if reader.ptr.is_null() || reader.pos >= reader.len {
            return 0;
        }
        let n = len.min(reader.len - reader.pos);
        // SAFETY: `n` bytes remain in the borrowed payload and `dst` is writable
        // for `len >= n`.
        unsafe { std::ptr::copy_nonoverlapping(reader.ptr.add(reader.pos), dst, n) };
        reader.pos += n;
        n
    })
}

/// How many bytes the reader has NOT yet handed out (zenoh-c
/// `z_bytes_reader_remaining`).
///
/// # Safety
/// `this_` must be null or a valid reader whose payload is still alive.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_remaining(this_: *const z_bytes_reader_t) -> usize {
    crate::ffi::guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        let reader = unsafe { &*this_ };
        reader.len.saturating_sub(reader.pos)
    })
}

/// The reader's current offset (zenoh-c `z_bytes_reader_tell`).
///
/// `int64_t` upstream, and a payload past `i64::MAX` cannot exist in an address
/// space, so the conversion is total in practice; it saturates rather than
/// wrapping so the failure would be a stuck cursor rather than a negative one.
///
/// # Safety
/// `this_` must be null or a valid reader.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_tell(this_: *const z_bytes_reader_t) -> i64 {
    crate::ffi::guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        i64::try_from(unsafe { &*this_ }.pos).unwrap_or(i64::MAX)
    })
}

/// Move the reader's cursor (zenoh-c `z_bytes_reader_seek`).
///
/// `origin` follows C's `fseek`: `SEEK_SET` (0) from the start, `SEEK_CUR` (1)
/// from the current position, `SEEK_END` (2) from the end. Seeking OUT of the
/// payload is refused with `Z_EINVAL` and leaves the cursor untouched, which is
/// upstream's behaviour — a reader left past its end would make
/// [`z_bytes_reader_remaining`] and [`z_bytes_reader_read`] disagree about
/// whether anything is left.
///
/// # Safety
/// `this_` must be null or a valid reader.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_seek(
    this_: *mut z_bytes_reader_t,
    offset: i64,
    origin: c_int,
) -> ZResult {
    /// C `SEEK_SET`.
    const SEEK_SET: c_int = 0;
    /// C `SEEK_CUR`.
    const SEEK_CUR: c_int = 1;
    /// C `SEEK_END`.
    const SEEK_END: c_int = 2;
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let reader = unsafe { &mut *this_ };
        // The arithmetic runs in `i64` precisely so an out-of-range seek is
        // DETECTED rather than wrapping into a plausible `usize`.
        let base = match origin {
            SEEK_SET => 0i64,
            SEEK_CUR => i64::try_from(reader.pos).unwrap_or(i64::MAX),
            SEEK_END => i64::try_from(reader.len).unwrap_or(i64::MAX),
            _ => return Z_EINVAL,
        };
        let Some(target) = base.checked_add(offset) else {
            return Z_EINVAL;
        };
        let Ok(target) = usize::try_from(target) else {
            return Z_EINVAL;
        };
        if target > reader.len {
            return Z_EINVAL;
        }
        reader.pos = target;
        Z_OK
    })
}

/// A cursor over a payload's SLICES (zenoh-c `z_bytes_slice_iterator_t`, 24
/// bytes). Borrowing and never dropped, like [`z_bytes_reader_t`].
#[repr(C)]
pub struct z_bytes_slice_iterator_t {
    pub(crate) state: *const c_void,
    pub(crate) index: usize,
    pub(crate) _reserved: usize,
}

const _: () = {
    assert!(std::mem::size_of::<z_bytes_slice_iterator_t>() == 24);
    assert!(std::mem::align_of::<z_bytes_slice_iterator_t>() == 8);
};

/// Build a slice iterator over a payload (zenoh-c
/// `z_bytes_get_slice_iterator`).
///
/// # Safety
/// `this_` must be null or a valid loaned bytes that outlives the iterator.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_slice_iterator(
    this_: *const z_loaned_bytes_t,
) -> z_bytes_slice_iterator_t {
    let state = if this_.is_null() {
        std::ptr::null()
    } else {
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *const c_void }
    };
    z_bytes_slice_iterator_t {
        state,
        index: 0,
        _reserved: 0,
    }
}

/// Advance a slice iterator, writing the next slice into `slice` and returning
/// whether there was one (zenoh-c `z_bytes_slice_iterator_next`).
///
/// The slice written is a VIEW borrowing the payload, so it must not outlive it
/// — upstream's own `z_bytes.c` reads it and drops it within the loop body.
///
/// # Safety
/// `this_` must be null or a valid iterator whose payload is still alive;
/// `slice` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_slice_iterator_next(
    this_: *mut z_bytes_slice_iterator_t,
    slice: *mut crate::abi::z_view_slice_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        if this_.is_null() || slice.is_null() {
            return false;
        }
        // SAFETY: the caller's contract.
        let it = unsafe { &mut *this_ };
        if it.state.is_null() {
            return false;
        }
        // SAFETY: a live `BytesState` the iterator borrows from its payload.
        let state = unsafe { &*(it.state as *const BytesState) };
        let Some(bytes) = state.slice(it.index) else {
            return false;
        };
        it.index += 1;
        // SAFETY: the caller's contract — `slice` is writable.
        unsafe { *slice = crate::slice::view_slice_over(bytes) };
        true
    })
}

/// Behind a `z_owned_bytes_writer_t` / `ze_owned_serializer_t`: the accumulating
/// buffer and the slice boundaries it will hand the finished payload.
///
/// One type for both, and that is an ABI fact rather than a convenience:
/// upstream's serializer wraps a writer at offset 0, so a program is free to
/// hand one to the other's functions. Two handle representations would corrupt
/// memory the first time it did.
pub(crate) struct WriterState {
    /// Bytes written so far.
    pub(crate) buf: Vec<u8>,
    /// End offsets of the slices SEALED by `z_bytes_writer_append`. Bytes past
    /// the last one are the still-open run `write_all` extends.
    pub(crate) sealed: Vec<usize>,
}

impl WriterState {
    pub(crate) fn new_empty() -> Self {
        Self {
            buf: Vec::new(),
            sealed: Vec::new(),
        }
    }

    /// Seal the currently open run, if any — what `append` does before adding
    /// the appended payload's own slices.
    fn seal(&mut self) {
        let open_from = self.sealed.last().copied().unwrap_or(0);
        if self.buf.len() > open_from {
            self.sealed.push(self.buf.len());
        }
    }

    /// The finished payload: any still-open run becomes a final slice.
    fn finish(mut self) -> BytesState {
        self.seal();
        BytesState::from_parts(Payload::Owned(self.buf), self.sealed)
    }
}

/// Read the [`WriterState`] behind a loaned writer / serializer.
///
/// # Safety
/// `handle` must be null or a live `Box::into_raw::<WriterState>` pointer.
pub(crate) unsafe fn writer_state<'a>(handle: Handle) -> Option<&'a mut WriterState> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract. The C closure contract makes a writer
    // single-owner: it is reached only through the one `z_owned_bytes_writer_t`
    // the caller stack-allocated.
    Some(unsafe { &mut *(handle as *mut WriterState) })
}

/// Construct an empty writer (zenoh-c `z_bytes_writer_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_empty(
    this_: *mut crate::abi::z_owned_bytes_writer_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        let handle = Box::into_raw(Box::new(WriterState::new_empty())) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_bytes_writer_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a writer mutably (zenoh-c `z_bytes_writer_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned writer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_loan_mut(
    this_: *mut crate::abi::z_owned_bytes_writer_t,
) -> *mut crate::abi::z_loaned_bytes_writer_t {
    this_ as *mut crate::abi::z_loaned_bytes_writer_t
}

/// Borrow a writer (zenoh-c `z_bytes_writer_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned writer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_loan(
    this_: *const crate::abi::z_owned_bytes_writer_t,
) -> *const crate::abi::z_loaned_bytes_writer_t {
    this_ as *const crate::abi::z_loaned_bytes_writer_t
}

/// Append raw bytes to the writer's OPEN run (zenoh-c
/// `z_bytes_writer_write_all`).
///
/// Two consecutive `write_all` calls produce ONE slice, which is upstream's
/// behaviour and what `z_bytes.c`'s reader section depends on: it writes 3 bytes
/// then 2 and reads all 5 back in a single `z_bytes_reader_read`.
///
/// # Safety
/// `this_` must be null or a valid loaned writer; `src` must be null or point at
/// `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_write_all(
    this_: *mut crate::abi::z_loaned_bytes_writer_t,
    src: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(state) = (unsafe { writer_state(handle) }) else {
            return Z_ENULL;
        };
        if len == 0 {
            return Z_OK;
        }
        if src.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — `len` readable bytes at `src`.
        state
            .buf
            .extend_from_slice(unsafe { std::slice::from_raw_parts(src, len) });
        Z_OK
    })
}

/// Append a whole payload as its own SLICE (zenoh-c `z_bytes_writer_append`),
/// consuming it.
///
/// The slice boundary is the point of this call as distinct from
/// [`z_bytes_writer_write_all`] — `z_bytes.c` appends three payloads and then
/// iterates the result expecting three slices back.
///
/// # Safety
/// `this_` must be null or a valid loaned writer; `bytes` must be null or a
/// valid moved bytes, which is consumed.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_append(
    this_: *mut crate::abi::z_loaned_bytes_writer_t,
    bytes: *mut z_moved_bytes_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST and on every path, matching upstream's
        // unconditional ownership transfer: a path that skipped it would leak
        // the caller's payload.
        // SAFETY: the caller's contract.
        let taken = unsafe { take_payload_state(bytes) };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(state) = (unsafe { writer_state(handle) }) else {
            return Z_ENULL;
        };
        let Some(incoming) = taken else {
            return Z_ENULL;
        };
        state.seal();
        let base = state.buf.len();
        state.buf.extend_from_slice(&incoming.payload);
        // The appended payload's OWN slice arrangement is preserved, so
        // appending a three-slice payload adds three slices rather than one.
        for end in &incoming.bounds {
            state.sealed.push(base + end);
        }
        Z_OK
    })
}

/// Take the whole [`BytesState`] out of a MOVED bytes, leaving a gravestone.
///
/// The slice-aware sibling of [`take_payload`], which discards the boundaries
/// because its callers ([`z_put`](crate::put)) want one contiguous run.
///
/// # Safety
/// `moved` must be null or a valid moved bytes.
pub(crate) unsafe fn take_payload_state(moved: *mut z_moved_bytes_t) -> Option<BytesState> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*moved)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<BytesState>` this crate leaked; reclaimed here.
    let state = unsafe { Box::from_raw(handle as *mut BytesState) };
    unsafe { (*moved)._this = z_owned_bytes_t::null_value() };
    Some(*state)
}

/// Finish a writer into a payload (zenoh-c `z_bytes_writer_finish`), consuming
/// the writer.
///
/// # Safety
/// `this_` must be null or a valid moved writer; `bytes` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_finish(
    this_: *mut crate::abi::z_moved_bytes_writer_t,
    bytes: *mut z_owned_bytes_t,
) {
    let _ = guarded(|| {
        if !bytes.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *bytes = z_owned_bytes_t::null_value() };
        }
        // SAFETY: the caller's contract, delegated — the slot is nulled, so a
        // later `z_bytes_writer_drop` is a no-op.
        let Some(state) = (unsafe { take_writer(this_) }) else {
            return Z_ENULL;
        };
        if bytes.is_null() {
            return Z_ENULL;
        }
        let handle = Box::into_raw(Box::new(state.finish())) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *bytes = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    });
}

/// Reclaim the [`WriterState`] behind a moved writer, nulling the slot.
///
/// # Safety
/// `moved` must be null or a valid moved writer.
pub(crate) unsafe fn take_writer(
    moved: *mut crate::abi::z_moved_bytes_writer_t,
) -> Option<WriterState> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*moved)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<WriterState>` this crate leaked.
    let state = unsafe { Box::from_raw(handle as *mut WriterState) };
    unsafe { (*moved)._this = crate::abi::z_owned_bytes_writer_t::null_value() };
    Some(*state)
}

/// Free a writer (zenoh-c `z_bytes_writer_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved writer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_drop(this_: *mut crate::abi::z_moved_bytes_writer_t) {
    // SAFETY: the caller's contract, delegated — `take_writer` nulls the slot.
    let _ = unsafe { take_writer(this_) };
}

/// `true` iff the owned writer holds a live state (zenoh-c
/// `z_internal_bytes_writer_check`).
///
/// # Safety
/// `this_` must be null or a valid owned writer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_writer_check(
    this_: *const crate::abi::z_owned_bytes_writer_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned writer (zenoh-c `z_internal_bytes_writer_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned writer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_writer_null(
    this_: *mut crate::abi::z_owned_bytes_writer_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_bytes_writer_t::null_value() };
    }
}

/// R3124 -- a payload that arrived as several slices kept apart is several slices to the C
/// iterator, each the page it lies in, as upstream's `z_bytes_slice_iterator` walks a `ZBytes`
/// built from a `ZBuf`.
#[cfg(test)]
mod received_slices_tests {
    use super::*;
    use std::sync::Arc;
    use wz_runtime_tokio::{RxBytes, RxStorage};

    struct Page(Vec<u8>);

    impl RxStorage for Page {
        fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    fn page(bytes: &[u8]) -> (Arc<dyn RxStorage>, RxBytes) {
        let storage: Arc<dyn RxStorage> = Arc::new(Page(bytes.to_vec()));
        let whole = RxBytes::shared(storage.clone(), 0..bytes.len()).expect("the whole page");
        (storage, whole)
    }

    #[test]
    fn a_payload_of_two_received_slices_iterates_as_two_pages() {
        let (first, a) = page(b"abc");
        let (second, b) = page(b"de");
        let state = BytesState::of(Payload::Shared(RxBytes::sliced(vec![a, b])));

        assert_eq!(state.bounds, [3, 5], "two slices, ending where each ends");
        assert_eq!(
            state.slice(0).expect("a first slice").as_ptr(),
            first.as_slice().as_ptr(),
            "the first slice IS its page"
        );
        assert_eq!(
            state.slice(1).expect("a second slice").as_ptr(),
            second.as_slice().as_ptr(),
            "and so is the second"
        );
        assert!(state.slice(2).is_none(), "there are two");
        assert_eq!(&*state.payload, b"abcde", "read as one run, the two joined");
    }

    #[test]
    fn a_payload_of_one_received_slice_is_one_slice() {
        let (storage, one) = page(b"abc");
        let state = BytesState::of(Payload::Shared(one));
        assert_eq!(state.bounds, [3]);
        assert_eq!(
            state.slice(0).expect("the slice").as_ptr(),
            storage.as_slice().as_ptr()
        );
        assert!(state.slice(1).is_none());
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    /// The three-append payload iterates as THREE slices, and the two-write one
    /// as ONE. That pair is the whole reason [`BytesState::bounds`] exists: a
    /// collapsed arrangement passes every length and string check and still
    /// makes upstream's `z_bytes.c` print one line where it prints three.
    #[test]
    fn appends_are_separate_slices_and_consecutive_writes_are_one() {
        // SAFETY: every pointer below is a live local this test owns.
        unsafe {
            let mut writer = crate::abi::z_owned_bytes_writer_t::null_value();
            assert_eq!(z_bytes_writer_empty(&mut writer), Z_OK);
            let w = z_bytes_writer_loan_mut(&mut writer);
            let src = [0u8, 1, 2, 3, 4];
            assert_eq!(z_bytes_writer_write_all(w, src.as_ptr(), 3), Z_OK);
            assert_eq!(z_bytes_writer_write_all(w, src.as_ptr().add(3), 2), Z_OK);

            let mut b1 = z_owned_bytes_t::null_value();
            assert_eq!(z_bytes_from_static_str(&mut b1, c"abc".as_ptr()), Z_OK);
            let mut moved_b1 = z_moved_bytes_t { _this: b1 };
            assert_eq!(z_bytes_writer_append(w, &mut moved_b1), Z_OK);

            let mut payload = z_owned_bytes_t::null_value();
            let mut moved_w = crate::abi::z_moved_bytes_writer_t { _this: writer };
            z_bytes_writer_finish(&mut moved_w, &mut payload);
            let loaned = z_bytes_loan(&payload);
            assert_eq!(z_bytes_len(loaned), 8);

            let mut it = z_bytes_get_slice_iterator(loaned);
            let mut seen: Vec<Vec<u8>> = Vec::new();
            let mut view = crate::abi::z_view_slice_t::null_value();
            while z_bytes_slice_iterator_next(&mut it, &mut view) {
                let l = crate::slice::z_view_slice_loan(&view);
                seen.push(
                    std::slice::from_raw_parts(
                        crate::slice::z_slice_data(l),
                        crate::slice::z_slice_len(l),
                    )
                    .to_vec(),
                );
            }
            assert_eq!(
                seen,
                vec![vec![0u8, 1, 2, 3, 4], b"abc".to_vec()],
                "two consecutive write_all calls are ONE slice and an append is its own"
            );

            // The reader reads across the slice boundary, as `z_bytes.c` does.
            let mut reader = z_bytes_get_reader(loaned);
            let mut out = [0u8; 8];
            assert_eq!(z_bytes_reader_read(&mut reader, out.as_mut_ptr(), 8), 8);
            assert_eq!(&out, b"\x00\x01\x02\x03\x04abc");
            assert_eq!(
                z_bytes_reader_read(&mut reader, out.as_mut_ptr(), 8),
                0,
                "a drained reader reports 0, it does not re-read"
            );

            let mut moved_p = z_moved_bytes_t { _this: payload };
            z_bytes_drop(&mut moved_p);
        }
    }

    /// R3061 -- `z_bytes_to_string` is a text conversion: bytes that are not UTF-8 are
    /// refused with `Z_EINVAL` and the destination is left as the gravestone, and an
    /// embedded NUL is text. The measured answers of the real library, one C program on both
    /// (`zenoh_c_bytes_to_string_twice_and_diff`); the slice conversion beside it is the
    /// control that the refusal is the string's and not the payload's.
    #[test]
    fn capi_c_to_string_refuses_bytes_that_are_not_utf8() {
        let convert = |data: &[u8]| {
            // SAFETY: live locals; the payload and the string are dropped before return.
            unsafe {
                let mut payload = z_owned_bytes_t::null_value();
                assert_eq!(
                    z_bytes_copy_from_buf(&mut payload, data.as_ptr(), data.len()),
                    Z_OK
                );
                let mut text = z_owned_string_t::null_value();
                let rc = z_bytes_to_string(z_bytes_loan(&payload), &mut text);
                let len = if rc == Z_OK {
                    crate::string::z_string_len(crate::string::z_string_loan(&text))
                } else {
                    assert!(
                        text.ptr.is_null() && text.len == 0,
                        "a refused conversion leaves the gravestone"
                    );
                    0
                };
                if rc == Z_OK {
                    let mut moved_text = crate::abi::z_moved_string_t { _this: text };
                    crate::string::z_string_drop(&mut moved_text);
                }
                let mut slice = crate::abi::z_owned_slice_t::null_value();
                let slice_rc = z_bytes_to_slice(z_bytes_loan(&payload), &mut slice);
                let mut moved_slice = crate::abi::z_moved_slice_t { _this: slice };
                crate::slice::z_slice_drop(&mut moved_slice);
                let mut moved = z_moved_bytes_t { _this: payload };
                z_bytes_drop(&mut moved);
                (rc, len, slice_rc)
            }
        };
        assert_eq!(convert(b"abc"), (Z_OK, 3, Z_OK));
        assert_eq!(
            convert(&[b'a', 0xff, 0xfe, b'b']),
            (Z_EINVAL, 0, Z_OK),
            "invalid UTF-8 is not a string, and it is still bytes"
        );
        assert_eq!(
            convert(&[b'a', 0, b'b']),
            (Z_OK, 3, Z_OK),
            "an embedded NUL is valid UTF-8 and is copied"
        );
    }

    /// An EMPTY payload has zero slices, matching upstream's empty `ZBytes` —
    /// not one slice of length zero, which would make the iterator yield an
    /// element that upstream does not.
    #[test]
    fn an_empty_payload_iterates_zero_times() {
        // SAFETY: live locals.
        unsafe {
            let mut payload = z_owned_bytes_t::null_value();
            z_bytes_empty(&mut payload);
            let mut it = z_bytes_get_slice_iterator(z_bytes_loan(&payload));
            let mut view = crate::abi::z_view_slice_t::null_value();
            assert!(!z_bytes_slice_iterator_next(&mut it, &mut view));
            let mut moved = z_moved_bytes_t { _this: payload };
            z_bytes_drop(&mut moved);
        }
    }
}
