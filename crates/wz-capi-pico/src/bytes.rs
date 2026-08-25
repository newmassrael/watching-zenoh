// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_bytes_*`, `z_slice_*`, `z_string_*` — the payload value types.
//!
//! `z_bytes_t` is the wire payload (`z_put` / `z_publisher_put` consume it and
//! the subscriber callback reads it back). A subscriber reads a delivered
//! payload the pico way: `z_sample_payload` → `z_bytes_to_slice` →
//! `z_slice_data` / `z_slice_len` (or `z_bytes_to_string` → `z_string_data` /
//! `z_string_len`).
//!
//! bytes and slice use the handle model (owned == loaned layout, `loan` is a
//! cast; the accessor reads the heap `Vec<u8>`). string uses the borrowed-view
//! model: an owned string holds a heap `StringState` and hands out a cached
//! `{ start, len }` self-view on `loan`, so `z_loaned_string_t` is the same
//! borrowed shape a view string (from `z_keyexpr_as_view_string`) produces.

use std::ffi::{c_char, c_void, CStr};

use crate::abi::{
    handle_ref, impl_value_ownership, z_loaned_bytes_t, z_loaned_slice_t, z_loaned_string_t,
    z_moved_bytes_t, z_moved_slice_t, z_moved_string_t, z_owned_bytes_t, z_owned_slice_t,
    z_owned_string_t, z_view_slice_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

// --- payloads -------------------------------------------------------------

/// Behind a `z_owned_bytes_t` / `z_owned_slice_t` handle: the raw bytes, plus
/// the SEGMENT boundaries a `z_bytes_writer_append` left in them.
///
/// The bytes alone would be enough for every wire path and every reader — and
/// they were, until upstream's own `z_bytes.c` walked a payload with
/// `z_bytes_get_slice_iterator` and printed one 9-byte slice on wz where the
/// real zenoh-pico printed three of 3. pico's `_z_bytes_t` is a VECTOR of
/// arc-slices and `z_bytes_writer_append` moves a whole payload in as its own
/// slice, so appending three payloads leaves three slices a program can walk.
/// wz's contiguous buffer lost that structure, and only a foreign oracle could
/// show it: every other observable (length, content, `z_bytes_to_string`, the
/// reader) is identical either way.
///
/// So the buffer stays CONTIGUOUS — every consumer that wants bytes still gets
/// one `&[u8]` with no gather — and the boundaries ride alongside it as end
/// offsets. `bounds` empty means "one implicit segment covering all the data"
/// (or none, when the data is empty), which is the state every inbound sample
/// and every single-shot constructor is in; only the writer ever populates it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ByteBuf {
    data: Vec<u8>,
    /// END offset of each segment. Either empty (the implicit single segment)
    /// or ending at `data.len()`.
    bounds: Vec<usize>,
}

impl ByteBuf {
    /// An empty payload with no segments.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether the payload is ONE slice, which is what
    /// `z_bytes_get_contiguous_view` requires.
    ///
    /// wz's storage is always one `Vec`, so a naive answer would be "always" —
    /// and that would be WRONG against a real pico, whose `_z_bytes_t` is a
    /// vector of arc-slices and whose `z_bytes_get_contiguous_view` fails once
    /// there is more than one. The question the export asks is about the
    /// payload's SEGMENT structure, not about wz's allocator, so it is answered
    /// from `bounds` — the same field the slice iterator walks, and the same
    /// field the R311y532 foreign oracle showed wz had been discarding.
    pub(crate) fn is_contiguous(&self) -> bool {
        self.bounds.len() <= 1
    }

    /// The `idx`-th segment, or `None` past the end — what
    /// `z_bytes_slice_iterator_next` yields.
    pub(crate) fn segment(&self, idx: usize) -> Option<&[u8]> {
        if self.bounds.is_empty() {
            return (idx == 0 && !self.data.is_empty()).then_some(self.data.as_slice());
        }
        let start = if idx == 0 {
            0
        } else {
            *self.bounds.get(idx - 1)?
        };
        let end = *self.bounds.get(idx)?;
        self.data.get(start..end)
    }

    /// Append another payload AS ITS OWN SEGMENTS (pico
    /// `z_bytes_writer_append`, which moves the source's slice list in).
    ///
    /// The first append on a buffer that already holds unsegmented bytes has to
    /// close that implicit segment first, or the existing content would silently
    /// merge into the newly appended one.
    pub(crate) fn append_segments(&mut self, other: &ByteBuf) {
        if self.bounds.is_empty() && !self.data.is_empty() {
            self.bounds.push(self.data.len());
        }
        let mut idx = 0usize;
        while let Some(segment) = other.segment(idx) {
            self.data.extend_from_slice(segment);
            self.bounds.push(self.data.len());
            idx += 1;
        }
    }

    /// Append raw bytes to the CURRENT segment (pico
    /// `z_bytes_writer_write_all`, which writes into the buffer rather than
    /// adding a slice).
    pub(crate) fn write_all(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        if let Some(last) = self.bounds.last_mut() {
            *last = self.data.len();
        }
    }
}

impl core::ops::Deref for ByteBuf {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.data
    }
}

impl core::ops::DerefMut for ByteBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl From<Vec<u8>> for ByteBuf {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            bounds: Vec::new(),
        }
    }
}

impl From<&[u8]> for ByteBuf {
    fn from(data: &[u8]) -> Self {
        Self::from(data.to_vec())
    }
}

/// Behind a `z_owned_string_t` handle. `data` is NUL-terminated so a C caller
/// treating `z_string_data` as a C string is safe; `len` is the logical
/// length (excluding the terminator). `self_view` is the cached borrowed
/// `{ start, len }` that `z_string_loan` returns (stable: it points at
/// `data`'s heap buffer, which does not move when the box does).
pub(crate) struct StringState {
    /// Owns the NUL-terminated heap buffer that `self_view` borrows. Never
    /// read directly — kept alive for the borrow and freed on drop.
    #[allow(dead_code)]
    data: Vec<u8>,
    self_view: z_loaned_string_t,
}

/// Behind a `z_owned_slice_t` handle. Mirrors [`StringState`]: `data` owns the
/// heap buffer and `self_view` is the cached borrowed `{ start, len }` that
/// `z_slice_loan` returns (stable — it points at `data`'s heap buffer, which
/// does not move when the box does).
///
/// No NUL terminator, unlike the string: a slice is binary and pico's
/// `z_slice_data` is not a C-string contract.
pub(crate) struct SliceState {
    /// Owns the heap buffer that `self_view` borrows. Never read directly —
    /// kept alive for the borrow and freed on drop.
    #[allow(dead_code)]
    data: Vec<u8>,
    self_view: z_loaned_slice_t,
}

impl SliceState {
    /// The bytes this state owns, read through the SAME cached view
    /// `z_slice_data` / `z_slice_len` hand to C — so a caller reading them in
    /// Rust and a caller reading them in C cannot see different lengths.
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: `self_view` is built from `data`'s own pointer and length in
        // `boxed`, and `data` is never reallocated afterwards.
        unsafe { crate::abi::view_bytes(self.self_view._start, self.self_view._len) }.unwrap_or(&[])
    }

    fn boxed(buf: ByteBuf) -> Box<SliceState> {
        let buf = buf.data;
        let len = buf.len();
        let start = buf.as_ptr();
        Box::new(SliceState {
            data: buf,
            self_view: z_loaned_slice_t {
                _start: start,
                _len: len,
            },
        })
    }
}

impl StringState {
    /// The string's LOGICAL bytes — the NUL terminator excluded, exactly as
    /// `z_string_len` reports and for the same reason as [`SliceState::bytes`].
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: as `SliceState::bytes`.
        unsafe { crate::abi::view_bytes(self.self_view._start, self.self_view._len) }.unwrap_or(&[])
    }

    fn boxed(bytes: &[u8]) -> Box<StringState> {
        let mut data = Vec::with_capacity(bytes.len() + 1);
        data.extend_from_slice(bytes);
        data.push(0);
        let len = bytes.len();
        let start = data.as_ptr();
        Box::new(StringState {
            data,
            self_view: z_loaned_string_t {
                _start: start,
                _len: len,
            },
        })
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<ByteBuf>` pointer.
unsafe fn free_bytes(h: *mut c_void) {
    drop(Box::from_raw(h as *mut ByteBuf));
}
/// # Safety
/// `h` must be a live `Box::into_raw::<SliceState>` pointer.
unsafe fn free_slice(h: *mut c_void) {
    drop(Box::from_raw(h as *mut SliceState));
}

impl_value_ownership!(
    z_owned_bytes_t,
    z_loaned_bytes_t,
    z_moved_bytes_t,
    free_bytes,
    z_internal_bytes_null,
    z_internal_bytes_check,
    z_bytes_loan,
    z_bytes_loan_mut,
    z_bytes_move,
    z_bytes_take,
    z_bytes_drop,
    z_bytes_take_from_loaned
);

// The slice ownership family is HAND-WRITTEN rather than emitted by
// `impl_value_ownership!`, because that macro's `loan` is a pointer
// reinterpretation of the owned struct — correct only while owned and loaned
// share a layout. slice's loaned form is a `{ start, len }` borrow pair (see
// [`crate::abi`]), so `loan` must hand back the state's cached self-view, and
// `take_from_loaned` must COPY the borrowed bytes (a borrow carries no
// transferable handle). This is the same family string writes out for the same
// reason.

/// Zero an owned slice (pico `z_internal_slice_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_null(obj: *mut z_owned_slice_t) {
    if !obj.is_null() {
        *obj = z_owned_slice_t::null_value();
    }
}

/// `true` iff the owned slice holds a live handle (pico
/// `z_internal_slice_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_check(obj: *const z_owned_slice_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow an owned slice immutably (pico `z_slice_loan`). Returns the state's
/// cached `{ start, len }` self-view.
#[no_mangle]
pub unsafe extern "C" fn z_slice_loan(obj: *const z_owned_slice_t) -> *const z_loaned_slice_t {
    guard_val(std::ptr::null(), || {
        match handle_ref::<z_owned_slice_t, SliceState>(obj) {
            Some(state) => &state.self_view as *const z_loaned_slice_t,
            None => std::ptr::null(),
        }
    })
}

/// Borrow an owned slice mutably (pico `z_slice_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_loan_mut(obj: *mut z_owned_slice_t) -> *mut z_loaned_slice_t {
    if obj.is_null() || (*obj).handle.is_null() {
        return std::ptr::null_mut();
    }
    let state = &mut *((*obj).handle as *mut SliceState);
    &mut state.self_view as *mut z_loaned_slice_t
}

/// Move-cast an owned slice (pico `z_slice_move`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_move(obj: *mut z_owned_slice_t) -> *mut z_moved_slice_t {
    obj as *mut z_moved_slice_t
}

/// Take an owned slice out of `src` into `dst` (pico `z_slice_take`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_take(dst: *mut z_owned_slice_t, src: *mut z_moved_slice_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_slice_t::null_value();
}

/// Drop an owned slice (pico `z_slice_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_drop(obj: *mut z_moved_slice_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let h = (*obj)._this.handle;
        if !h.is_null() {
            free_slice(h);
            (*obj)._this = z_owned_slice_t::null_value();
        }
        Z_OK
    });
}

/// Adopt a loaned slice into an owned one, emptying the source view (pico
/// `z_slice_take_from_loaned`). Same copy-and-clear contract as
/// [`z_string_take_from_loaned`], including its caveat about being applied to
/// an owned slice's own self-view.
#[no_mangle]
pub unsafe extern "C" fn z_slice_take_from_loaned(
    dst: *mut z_owned_slice_t,
    src: *mut z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        store_slice(dst, ByteBuf::from(std::slice::from_raw_parts(start, len)));
        (*src)._start = std::ptr::null();
        (*src)._len = 0;
        Z_OK
    })
}

// --- helpers to box a payload into an owned value -------------------------

unsafe fn store_bytes(dst: *mut z_owned_bytes_t, buf: ByteBuf) {
    *dst = z_owned_bytes_t {
        handle: Box::into_raw(Box::new(buf)) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}
unsafe fn store_slice(dst: *mut z_owned_slice_t, buf: ByteBuf) {
    *dst = z_owned_slice_t {
        handle: Box::into_raw(SliceState::boxed(buf)) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}
/// Build an empty payload (pico `z_bytes_empty`).
///
/// Distinct from a NULL one: a program that builds an empty payload and attaches
/// it gets a present-but-zero-length attachment, which `z_sample_attachment`
/// reports as non-NULL. See that accessor for why the two must not collapse.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_empty(bytes: *mut z_owned_bytes_t) {
    if bytes.is_null() {
        return;
    }
    store_bytes(bytes, ByteBuf::new());
}

/// Adopt a caller-allocated C string into an owned string (pico
/// `z_string_from_str`).
///
/// pico TAKES OWNERSHIP and calls `deleter(value, context)` when the string is
/// dropped. wz COPIES the bytes into its own `StringState` and runs the deleter
/// **immediately**, because the copy means the caller's buffer is no longer
/// referenced.
///
/// That is a named divergence with one observable consequence, stated rather
/// than buried: a program whose deleter has side effects sees them at
/// construction rather than at drop. Running it immediately is the choice that
/// keeps the ownership contract honest — the alternative, holding the pointer to
/// honour the deleter's timing, would make the owned string borrow a buffer wz
/// does not control for the rest of its life.
#[no_mangle]
pub unsafe extern "C" fn z_string_from_str(
    str_out: *mut z_owned_string_t,
    value: *mut std::ffi::c_char,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_owned_string_t::null_value();
        if value.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::ffi::CStr::from_ptr(value).to_bytes().to_vec();
        store_string(str_out, StringState::boxed(&bytes));
        // The copy is complete, so the caller's buffer is released now.
        if let Some(free) = deleter {
            free(value as *mut c_void, context);
        }
        Z_OK
    })
}

pub(crate) unsafe fn store_owned_bytes(dst: *mut z_owned_bytes_t, buf: ByteBuf) {
    store_bytes(dst, buf);
}

pub(crate) unsafe fn store_owned_slice(dst: *mut z_owned_slice_t, buf: ByteBuf) {
    store_slice(dst, buf);
}

pub(crate) unsafe fn store_owned_string(dst: *mut z_owned_string_t, bytes: &[u8]) {
    store_string(dst, StringState::boxed(bytes));
}

unsafe fn store_string(dst: *mut z_owned_string_t, s: Box<StringState>) {
    *dst = z_owned_string_t {
        handle: Box::into_raw(s) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}

/// Read the raw bytes behind a loaned bytes/slice value (both wrap `ByteBuf`).
pub(crate) unsafe fn bytes_ref<'a>(ptr: *const z_loaned_bytes_t) -> Option<&'a ByteBuf> {
    handle_ref::<z_loaned_bytes_t, ByteBuf>(ptr)
}

// --- bytes constructors ---------------------------------------------------

/// Copy a buffer into an owned payload (pico `z_bytes_copy_from_buf`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_buf(
    bytes: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let buf = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        store_bytes(bytes, ByteBuf::from(buf));
        Z_OK
    })
}

/// Copy a C string's bytes into an owned payload (pico `z_bytes_copy_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_str(
    bytes: *mut z_owned_bytes_t,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let buf = CStr::from_ptr(value).to_bytes().to_vec();
        store_bytes(bytes, ByteBuf::from(buf));
        Z_OK
    })
}

/// Build a payload from a statically allocated C string (pico
/// `z_bytes_from_static_str`).
///
/// pico's contract is ALIASING: the payload borrows the caller's static
/// storage and never frees it, which is why the name says `static` and why
/// there is no failure mode for allocation. wz COPIES instead, because this
/// crate's payload model is an owning [`ByteBuf`] (`Vec<u8>`) shared by every
/// consumer — a borrowing variant would have to widen `ByteBuf` into a
/// two-arm owned/aliased type and re-audit every reader of it.
///
/// The divergence is confined to cost, not to observable behaviour: the C
/// contract only requires the bytes to remain readable for the payload's
/// lifetime, and an owned copy satisfies that strictly more safely than an
/// alias (it survives even a caller that violates the `static` precondition).
/// What a program CAN observe is the copy itself, so a pico program that
/// passes a very large static buffer pays an allocation here that real pico
/// does not. Recorded as a named divergence rather than hidden behind the
/// shared name.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_str(
    bytes: *mut z_owned_bytes_t,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let buf = CStr::from_ptr(value).to_bytes().to_vec();
        store_bytes(bytes, ByteBuf::from(buf));
        Z_OK
    })
}

// --- conversions ----------------------------------------------------------

/// Copy a payload into an owned slice (pico `z_bytes_to_slice`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_slice(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            Some(buf) => {
                store_slice(dst, buf.clone());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Copy a payload into an owned string (pico `z_bytes_to_string`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_string(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            Some(buf) => {
                store_string(dst, StringState::boxed(buf));
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

// --- slice accessors ------------------------------------------------------

/// Pointer to a slice's bytes (pico `z_slice_data`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_data(slice: *const z_loaned_slice_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if slice.is_null() {
            return std::ptr::null();
        }
        (*slice)._start
    })
}

/// Length of a slice (pico `z_slice_len`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_len(slice: *const z_loaned_slice_t) -> usize {
    guard_val(0, || {
        if slice.is_null() {
            return 0;
        }
        (*slice)._len
    })
}

// --- string ownership + accessors -----------------------------------------

/// Zero an owned string (pico `z_internal_string_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_null(obj: *mut z_owned_string_t) {
    if !obj.is_null() {
        *obj = z_owned_string_t::null_value();
    }
}

/// `true` iff the owned string holds a live handle (pico
/// `z_internal_string_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_check(obj: *const z_owned_string_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow an owned string immutably (pico `z_string_loan`). Returns the
/// state's cached `{ start, len }` self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_loan(obj: *const z_owned_string_t) -> *const z_loaned_string_t {
    guard_val(std::ptr::null(), || {
        match handle_ref::<z_owned_string_t, StringState>(obj) {
            Some(state) => &state.self_view as *const z_loaned_string_t,
            None => std::ptr::null(),
        }
    })
}

/// Borrow an owned string mutably (pico `z_string_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_string_loan_mut(obj: *mut z_owned_string_t) -> *mut z_loaned_string_t {
    if obj.is_null() || (*obj).handle.is_null() {
        return std::ptr::null_mut();
    }
    let state = &mut *((*obj).handle as *mut StringState);
    &mut state.self_view as *mut z_loaned_string_t
}

/// Move-cast an owned string (pico `z_string_move`).
#[no_mangle]
pub unsafe extern "C" fn z_string_move(obj: *mut z_owned_string_t) -> *mut z_moved_string_t {
    obj as *mut z_moved_string_t
}

/// Take an owned string out of `src` into `dst` (pico `z_string_take`).
#[no_mangle]
pub unsafe extern "C" fn z_string_take(dst: *mut z_owned_string_t, src: *mut z_moved_string_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_string_t::null_value();
}

/// Drop an owned string (pico `z_string_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_string_drop(obj: *mut z_moved_string_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let h = (*obj)._this.handle;
        if !h.is_null() {
            drop(Box::from_raw(h as *mut StringState));
            (*obj)._this = z_owned_string_t::null_value();
        }
        Z_OK
    });
}

/// Pointer to a string's (NUL-terminated) bytes (pico `z_string_data`).
#[no_mangle]
pub unsafe extern "C" fn z_string_data(string: *const z_loaned_string_t) -> *const c_char {
    guard_val(std::ptr::null(), || {
        if string.is_null() {
            std::ptr::null()
        } else {
            (*string)._start as *const c_char
        }
    })
}

/// Logical length of a string, excluding the NUL terminator (pico
/// `z_string_len`).
#[no_mangle]
pub unsafe extern "C" fn z_string_len(string: *const z_loaned_string_t) -> usize {
    guard_val(0, || if string.is_null() { 0 } else { (*string)._len })
}

/// Adopt a loaned string into an owned one, emptying the source view (pico
/// `z_string_take_from_loaned`). The string loaned form is a borrowed
/// `{ start, len }`, so "take" copies the borrowed bytes into a fresh owned
/// `StringState` (there is no transferable handle in a borrow) and clears the
/// source view.
///
/// Caveat: if `src` was obtained via `z_string_loan[_mut]` on an owned string,
/// it points at that owned string's cached self-view; clearing it here leaves
/// that owned string's subsequent `z_string_loan` returning an empty
/// `{ null, 0 }` view (the owned `StringState` box is untouched and still
/// freed on drop — no leak, no double-free). Idiomatic pico "take from loaned"
/// is applied to a fresh loaned handle, not an owned string's self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_take_from_loaned(
    dst: *mut z_owned_string_t,
    src: *mut z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::slice::from_raw_parts(start, len);
        store_string(dst, StringState::boxed(bytes));
        (*src)._start = std::ptr::null();
        (*src)._len = 0;
        Z_OK
    })
}

// --- clone (deep copy) ----------------------------------------------------

/// Deep-copy a payload (pico `z_bytes_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_clone(
    dst: *mut z_owned_bytes_t,
    src: *const z_loaned_bytes_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(src) {
            Some(buf) => {
                store_bytes(dst, buf.clone());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

// --- the view-slice family + the slice iterator ----------------------------

/// Build a view slice borrowing the caller's buffer (pico
/// `z_view_slice_from_buf`). No copy and no ownership: the caller keeps `data`
/// alive for the view's lifetime.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_from_buf(
    slice: *mut z_view_slice_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if slice.is_null() || data.is_null() {
            return Z_ERR_NULL;
        }
        *slice = z_view_slice_t {
            _start: data,
            _len: len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Empty a view slice (pico `z_view_slice_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_empty(slice: *mut z_view_slice_t) {
    if slice.is_null() {
        return;
    }
    *slice = z_view_slice_t {
        _start: std::ptr::null(),
        _len: 0,
        _pad: [0usize; 2],
    };
}

/// `true` iff the view slice is empty (pico `z_view_slice_is_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_is_empty(slice: *const z_view_slice_t) -> bool {
    guard_val(true, || slice.is_null() || (*slice)._len == 0)
}

/// Borrow a view slice immutably (pico `z_view_slice_loan`). A pointer
/// reinterpretation: slots 0/1 of a view ARE the loaned `{ start, len }`.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_loan(
    slice: *const z_view_slice_t,
) -> *const z_loaned_slice_t {
    slice as *const z_loaned_slice_t
}

/// Borrow a view slice mutably (pico `z_view_slice_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_loan_mut(
    slice: *mut z_view_slice_t,
) -> *mut z_loaned_slice_t {
    slice as *mut z_loaned_slice_t
}

/// pico `z_bytes_slice_iterator_t` (`api/types.h:84-87`), 16 B measured:
/// `{ const _z_bytes_t *_bytes; size_t _slice_idx; }`.
///
/// Crosses the boundary BY VALUE out of [`z_bytes_get_slice_iterator`] and is
/// stack-allocated by the C caller, so the field order and size are ABI.
#[repr(C)]
pub struct z_bytes_slice_iterator_t {
    pub(crate) _bytes: *const z_loaned_bytes_t,
    pub(crate) _slice_idx: usize,
}

/// Start iterating a payload's underlying slices (pico
/// `z_bytes_get_slice_iterator`).
///
/// The slices are the SEGMENTS a `z_bytes_writer_append` left behind (see
/// [`ByteBuf`]), so upstream's own `z_bytes.c` walks the same three slices on
/// wz that it walks on the real zenoh-pico.
///
/// An earlier cut of this function yielded ONE slice covering the whole payload
/// and argued it was faithful, on the grounds that upstream documents "no
/// guarantee is provided on the internal slices arrangement... the only provided
/// guarantee is on the bytes order" (`api/primitives.h:774-777`). That is what
/// the header says and it was still the wrong call: the two implementations
/// printed different output for the same program, and a drop-in is judged by
/// what the program prints, not by what the header permits.
///
/// An EMPTY payload yields nothing, matching pico's empty svec.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_slice_iterator(
    bytes: *const z_loaned_bytes_t,
) -> z_bytes_slice_iterator_t {
    z_bytes_slice_iterator_t {
        _bytes: bytes,
        _slice_idx: 0,
    }
}

/// Advance a slice iterator, filling `out` with a view of the next slice (pico
/// `z_bytes_slice_iterator_next`). `false` at the end.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_slice_iterator_next(
    iter: *mut z_bytes_slice_iterator_t,
    out: *mut z_view_slice_t,
) -> bool {
    guard_val(false, || {
        if iter.is_null() || out.is_null() {
            return false;
        }
        let Some(buf) = bytes_ref((*iter)._bytes) else {
            return false;
        };
        let Some(segment) = buf.segment((*iter)._slice_idx) else {
            return false;
        };
        (*iter)._slice_idx += 1;
        *out = z_view_slice_t {
            _start: segment.as_ptr(),
            _len: segment.len(),
            _pad: [0usize; 2],
        };
        true
    })
}

/// Deep-copy a slice (pico `z_slice_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_clone(
    dst: *mut z_owned_slice_t,
    src: *const z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        if src.is_null() || (*src)._start.is_null() {
            return Z_ERR_NULL;
        }
        store_slice(
            dst,
            ByteBuf::from(std::slice::from_raw_parts((*src)._start, (*src)._len)),
        );
        Z_OK
    })
}

/// Deep-copy a string (pico `z_string_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_string_clone(
    dst: *mut z_owned_string_t,
    src: *const z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::slice::from_raw_parts(start, len);
        store_string(dst, StringState::boxed(bytes));
        Z_OK
    })
}

// --- R311y559: the rest of the container surface ----------------------------
//
// Everything below is a symbol the REAL `libzenohpico.so` defines and this
// cdylib did not, found by `wz-integration-tests/tests/pico_abi_symbol_census.rs`.
// A drop-in is a claim about the linker before it is a claim about behaviour: a
// program naming any of these did not fail a comparison, it failed to LINK, and
// no behavioural leg in this tree could reach it. They are ordinary members of
// the families already above and reuse the same state types.

/// Total payload length in bytes (pico `z_bytes_len`).
///
/// Across ALL segments, not the first one: a `ByteBuf` may be a multi-segment
/// gather (a fragmented receive, an `append_segments`), and upstream's
/// `_z_bytes_len` sums the arc-slice vector. Reading only segment 0 would agree
/// on every single-segment payload — which is every payload a wz-authored test
/// builds — and under-report exactly the case the field exists for.
///
/// # Safety
/// `bytes` must be null or a live loaned payload.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_len(bytes: *const z_loaned_bytes_t) -> usize {
    guard_val(0, || bytes_ref(bytes).map_or(0, |buf| buf.data.len()))
}

/// Whether a payload carries no bytes (pico `z_bytes_is_empty`).
///
/// # Safety
/// As [`z_bytes_len`].
#[no_mangle]
pub unsafe extern "C" fn z_bytes_is_empty(bytes: *const z_loaned_bytes_t) -> bool {
    guard_val(true, || z_bytes_len(bytes) == 0)
}

/// Copy a loaned slice's bytes into an owned payload (pico
/// `z_bytes_copy_from_slice`).
///
/// # Safety
/// `bytes` must be valid and writable; `slice` must be null or a live loaned
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_slice(
    bytes: *mut z_owned_bytes_t,
    slice: *const z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        z_bytes_copy_from_buf(bytes, (*slice)._start, (*slice)._len)
    })
}

/// Move an owned slice into an owned payload (pico `z_bytes_from_slice`),
/// consuming the slice.
///
/// The slice is CONSUMED on every path, success or not — upstream's ownership
/// transfer is unconditional once the call is made, so an early return that
/// skipped the drop would leak the caller's value.
///
/// # Safety
/// `bytes` must be valid and writable; `slice` must be null or a valid moved
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_slice(
    bytes: *mut z_owned_bytes_t,
    slice: *mut z_moved_slice_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            // Still consume, per the paragraph above.
            z_slice_drop(slice);
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        let rc = if slice.is_null() {
            Z_ERR_NULL
        } else {
            match handle_ref::<z_owned_slice_t, SliceState>(&(*slice)._this) {
                Some(state) => {
                    store_bytes(bytes, ByteBuf::from(state.bytes().to_vec()));
                    Z_OK
                }
                None => Z_ERR_NULL,
            }
        };
        z_slice_drop(slice);
        rc
    })
}

/// Copy a loaned string's bytes into an owned payload (pico
/// `z_bytes_copy_from_string`). The NUL terminator is NOT copied — a payload's
/// length is the string's logical length.
///
/// # Safety
/// `bytes` must be valid and writable; `s` must be null or a live loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_string(
    bytes: *mut z_owned_bytes_t,
    s: *const z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        if s.is_null() {
            return Z_ERR_NULL;
        }
        z_bytes_copy_from_buf(bytes, (*s)._start, (*s)._len)
    })
}

/// Move an owned string into an owned payload (pico `z_bytes_from_string`),
/// consuming the string.
///
/// # Safety
/// `bytes` must be valid and writable; `s` must be null or a valid moved string.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_string(
    bytes: *mut z_owned_bytes_t,
    s: *mut z_moved_string_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            z_string_drop(s);
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        let rc = if s.is_null() {
            Z_ERR_NULL
        } else {
            match handle_ref::<z_owned_string_t, StringState>(&(*s)._this) {
                Some(state) => {
                    store_bytes(bytes, ByteBuf::from(state.bytes().to_vec()));
                    Z_OK
                }
                None => Z_ERR_NULL,
            }
        };
        z_string_drop(s);
        rc
    })
}

/// Adopt a caller-allocated C string into an owned payload (pico
/// `z_bytes_from_str`).
///
/// COPIES and runs the deleter immediately, for the identical reason
/// [`z_string_from_str`] does — see that function for the named divergence and
/// its one observable consequence.
///
/// # Safety
/// `bytes` must be valid and writable; `value` must be null or a live
/// NUL-terminated string the deleter can release.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_str(
    bytes: *mut z_owned_bytes_t,
    value: *mut c_char,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let rc = z_bytes_copy_from_str(bytes, value);
        if let Some(free) = deleter {
            free(value as *mut c_void, context);
        }
        rc
    })
}

/// Point a view slice at the payload's bytes WITHOUT copying (pico
/// `z_bytes_get_contiguous_view`, unstable).
///
/// Fails with `Z_ERR_INVALID` on a payload that is not contiguous, which is
/// upstream's contract and not a limitation of this implementation: the export
/// exists precisely so a caller can distinguish "I can read this in place" from
/// "I must gather it", and returning a view over a copy would answer the
/// question wrongly while looking like it worked.
///
/// # Safety
/// `bytes` must be null or a live loaned payload; `view` must be valid and
/// writable, and must not outlive `bytes`.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_contiguous_view(
    bytes: *const z_loaned_bytes_t,
    view: *mut z_view_slice_t,
) -> ZResult {
    guarded(|| {
        if view.is_null() {
            return Z_ERR_NULL;
        }
        z_view_slice_empty(view);
        let Some(buf) = bytes_ref(bytes) else {
            return Z_ERR_NULL;
        };
        if !buf.is_contiguous() {
            return crate::result::Z_ERR_INVALID;
        }
        z_view_slice_from_buf(view, buf.data.as_ptr(), buf.data.len())
    })
}

// --- slice constructors ------------------------------------------------------

/// Copy a buffer into an owned slice (pico `z_slice_copy_from_buf`).
///
/// # Safety
/// `slice` must be valid and writable; `data` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_slice_copy_from_buf(
    slice: *mut z_owned_slice_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        *slice = z_owned_slice_t::null_value();
        if data.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let bytes = if len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        store_slice(slice, ByteBuf::from(bytes));
        Z_OK
    })
}

/// Adopt a caller-owned buffer into an owned slice (pico `z_slice_from_buf`).
///
/// Copies and runs the deleter immediately, as [`z_bytes_from_buf`] does.
///
/// # Safety
/// `slice` must be valid and writable; `data` must be null or point at `len`
/// readable bytes the deleter can release.
#[no_mangle]
pub unsafe extern "C" fn z_slice_from_buf(
    slice: *mut z_owned_slice_t,
    data: *mut u8,
    len: usize,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let rc = z_slice_copy_from_buf(slice, data, len);
        if let Some(free) = deleter {
            free(data as *mut c_void, context);
        }
        rc
    })
}

/// Build an EMPTY owned slice (pico `z_slice_empty`).
///
/// Present-but-zero-length, not null — the same distinction
/// [`z_bytes_empty`] documents, and for the same reason.
///
/// # Safety
/// `slice` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_slice_empty(slice: *mut z_owned_slice_t) {
    let _ = guarded(|| {
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        store_slice(slice, ByteBuf::new());
        Z_OK
    });
}

/// Whether a loaned slice carries no bytes (pico `z_slice_is_empty`).
///
/// # Safety
/// `slice` must be null or a live loaned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_is_empty(slice: *const z_loaned_slice_t) -> bool {
    guard_val(true, || z_slice_len(slice) == 0)
}

// --- string constructors + accessors -----------------------------------------

/// Build an EMPTY owned string (pico `z_string_empty`).
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_string_empty(str_out: *mut z_owned_string_t) {
    let _ = guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        store_string(str_out, StringState::boxed(&[]));
        Z_OK
    });
}

/// Whether a loaned string is zero-length (pico `z_string_is_empty`).
///
/// # Safety
/// `str_in` must be null or a live loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_is_empty(str_in: *const z_loaned_string_t) -> bool {
    guard_val(true, || z_string_len(str_in) == 0)
}

/// Copy a NUL-terminated C string into an owned string (pico
/// `z_string_copy_from_str`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_str(
    str_out: *mut z_owned_string_t,
    value: *const c_char,
) -> ZResult {
    let len = if value.is_null() {
        0
    } else {
        CStr::from_ptr(value).to_bytes().len()
    };
    z_string_copy_from_substr(str_out, value, len)
}

/// Copy an explicitly-sized substring into an owned string (pico
/// `z_string_copy_from_substr`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_substr(
    str_out: *mut z_owned_string_t,
    value: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_owned_string_t::null_value();
        if value.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(value as *const u8, len)
        };
        store_string(str_out, StringState::boxed(bytes));
        Z_OK
    })
}

/// Reinterpret a loaned string as a loaned slice (pico `z_string_as_slice`).
///
/// A pointer reinterpretation, not a copy: both loaned forms are the SAME
/// `{ start, len }` borrow pair (see [`crate::abi`]), which is exactly why
/// upstream can hand back a `const z_loaned_slice_t *` into the string's own
/// storage. The NUL terminator is excluded, because `_len` is the logical
/// length.
///
/// # Safety
/// `str_in` must be null or a live loaned string; the result must not outlive
/// it.
#[no_mangle]
pub unsafe extern "C" fn z_string_as_slice(
    str_in: *const z_loaned_string_t,
) -> *const z_loaned_slice_t {
    str_in as *const z_loaned_slice_t
}

// --- the view-string family ---------------------------------------------------

/// Point a view string at a NUL-terminated C string (pico
/// `z_view_string_from_str`). No copy: the caller keeps `value` alive.
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or a valid
/// NUL-terminated string that outlives the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_str(
    str_out: *mut z_view_string_t,
    value: *const c_char,
) -> ZResult {
    let len = if value.is_null() {
        0
    } else {
        CStr::from_ptr(value).to_bytes().len()
    };
    z_view_string_from_substr(str_out, value, len)
}

/// Point a view string at an explicitly-sized substring (pico
/// `z_view_string_from_substr`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or point at `len`
/// readable bytes that outlive the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_substr(
    str_out: *mut z_view_string_t,
    value: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        z_view_string_empty(str_out);
        if value.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_view_string_t {
            _start: value as *const u8,
            _len: len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Zero a view string (pico `z_view_string_empty`).
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_empty(str_out: *mut z_view_string_t) {
    if str_out.is_null() {
        return;
    }
    *str_out = z_view_string_t {
        _start: std::ptr::null(),
        _len: 0,
        _pad: [0usize; 2],
    };
}

/// Whether a view string points at nothing (pico `z_view_string_is_empty`).
///
/// # Safety
/// `str_in` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_is_empty(str_in: *const z_view_string_t) -> bool {
    guard_val(true, || {
        str_in.is_null() || (*str_in)._start.is_null() || (*str_in)._len == 0
    })
}

/// Mutably borrow a view string (pico `z_view_string_loan_mut`) — the offset-0
/// reinterpretation its immutable sibling already uses.
///
/// # Safety
/// `str_in` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_loan_mut(
    str_in: *mut z_view_string_t,
) -> *mut z_loaned_string_t {
    str_in as *mut z_loaned_string_t
}
