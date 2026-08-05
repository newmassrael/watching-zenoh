// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `ze_serializer` / `ze_deserializer` codec.
//!
//! ## A serializer IS a writer, and that is an ABI fact
//!
//! Upstream's serializer wraps a bytes writer at offset 0 and its header's
//! `static inline` helpers take the address of that inner field and hand it to
//! the exported writer functions. So a C program COMPILES code that passes a
//! serializer-shaped pointer to `z_bytes_writer_write_all`. This module
//! therefore shares ONE [`WriterState`](crate::bytes::WriterState) behind one
//! handle representation with [`crate::bytes`] — if the two had different handle
//! shapes, that inline helper would corrupt memory silently.
//!
//! ## The deserializer is a BORROW, so it is POD and never freed
//!
//! `ze_deserializer_from_bytes` returns BY VALUE into a C stack slot and
//! upstream exports no drop for it, so it must own nothing. It borrows the
//! payload it was built from and the C program's own `z_owned_bytes_t` is what
//! keeps that alive. Only the SIZE is ABI; C never inspects the fields.
//!
//! ## The format is upstream's, and it is not self-describing
//!
//! Two shapes, and mixing them up produces bytes that decode as garbage on a
//! real peer rather than failing here:
//!
//! - ARITHMETIC types are FIXED-WIDTH LITTLE-ENDIAN. `int32` is four bytes,
//!   `uint64` is eight, `float` is its IEEE-754 bit pattern in four.
//! - LENGTHS — a sequence length, and the length prefixing a string — are VLE
//!   (`zint`), which is [`wz_capi_core::codec`], the same encoder the zenoh-pico
//!   ABI serializes with. One implementation, both ABIs, because both are read
//!   by the same foreign peers.

use std::ffi::{c_char, CStr};

use wz_capi_core::codec::{decode_zint, encode_zint, VLE_LEN};

use crate::abi::{
    z_loaned_bytes_t, z_loaned_string_t, z_owned_bytes_t, z_owned_string_t, ze_loaned_serializer_t,
    ze_moved_serializer_t, ze_owned_serializer_t, Handle,
};
use crate::bytes::{bytes_slice, writer_state, WriterState};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EDESERIALIZE, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::owned_string_from;

/// A cursor over a serialized payload (zenoh-c `ze_deserializer_t`, 24 bytes).
///
/// The same shape as [`crate::bytes::z_bytes_reader_t`] and for the same reason
/// — upstream's deserializer wraps a reader at offset 0.
#[repr(C)]
pub struct ze_deserializer_t {
    pub(crate) ptr: *const u8,
    pub(crate) len: usize,
    pub(crate) pos: usize,
}

const _: () = {
    assert!(std::mem::size_of::<ze_deserializer_t>() == 24);
    assert!(std::mem::align_of::<ze_deserializer_t>() == 8);
};

impl ze_deserializer_t {
    /// The bytes still unread.
    fn rest(&self) -> &[u8] {
        if self.ptr.is_null() || self.pos >= self.len {
            return &[];
        }
        // SAFETY: `ptr`/`len` describe the payload this deserializer borrows,
        // whose lifetime is the C caller's obligation, and `pos <= len`.
        unsafe { std::slice::from_raw_parts(self.ptr.add(self.pos), self.len - self.pos) }
    }

    /// Consume exactly `n` bytes, or `None` when fewer remain.
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let rest = self.rest();
        if rest.len() < n {
            return None;
        }
        // Re-derive the borrow from the raw pointer so the returned slice is
        // not tied to `&mut self`.
        // SAFETY: as `rest`, bounded by the check above.
        let out = unsafe { std::slice::from_raw_parts(self.ptr.add(self.pos), n) };
        self.pos += n;
        Some(out)
    }

    /// Consume a VLE length.
    fn take_zint(&mut self) -> Option<u64> {
        let (v, used) = decode_zint(self.rest())?;
        self.pos += used;
        Some(v)
    }
}

/// Append a VLE length to a serializer's buffer.
fn push_zint(state: &mut WriterState, v: u64) {
    let mut buf = [0u8; VLE_LEN];
    let n = encode_zint(&mut buf, v);
    state.buf.extend_from_slice(&buf[..n]);
}

/// Resolve the [`WriterState`] behind a loaned serializer.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
unsafe fn serializer_state<'a>(this_: *mut ze_loaned_serializer_t) -> Option<&'a mut WriterState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract, delegated.
    unsafe { writer_state((*this_).handle) }
}

/// Run `body` against a loaned serializer's state, mapping absence onto
/// `Z_ENULL` — the shape every `ze_serializer_serialize_*` below shares.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
unsafe fn with_serializer(
    this_: *mut ze_loaned_serializer_t,
    body: impl FnOnce(&mut WriterState),
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { serializer_state(this_) }) else {
            return Z_ENULL;
        };
        body(state);
        Z_OK
    })
}

/// Construct an empty serializer (zenoh-c `ze_serializer_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_empty(this_: *mut ze_owned_serializer_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        let handle = Box::into_raw(Box::new(WriterState::new_empty())) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_serializer_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a serializer mutably (zenoh-c `ze_serializer_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_loan_mut(
    this_: *mut ze_owned_serializer_t,
) -> *mut ze_loaned_serializer_t {
    this_ as *mut ze_loaned_serializer_t
}

/// Borrow a serializer (zenoh-c `ze_serializer_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_loan(
    this_: *const ze_owned_serializer_t,
) -> *const ze_loaned_serializer_t {
    this_ as *const ze_loaned_serializer_t
}

/// Finish a serializer into a payload (zenoh-c `ze_serializer_finish`),
/// consuming it.
///
/// # Safety
/// `this_` must be null or a valid moved serializer; `bytes` must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_finish(
    this_: *mut ze_moved_serializer_t,
    bytes: *mut z_owned_bytes_t,
) {
    // The serializer and the writer share one state type and one handle
    // representation (see the module doc), so this is the writer's finish with
    // the pointer retyped — not a parallel implementation that could drift.
    // SAFETY: the caller's contract; the two moved types have identical layout
    // and both carry a `Box<WriterState>` handle in slot 0.
    unsafe {
        crate::bytes::z_bytes_writer_finish(this_ as *mut crate::abi::z_moved_bytes_writer_t, bytes)
    }
}

/// Free a serializer (zenoh-c `ze_serializer_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_drop(this_: *mut ze_moved_serializer_t) {
    // SAFETY: as `ze_serializer_finish` — one state type, one handle shape.
    unsafe { crate::bytes::z_bytes_writer_drop(this_ as *mut crate::abi::z_moved_bytes_writer_t) }
}

/// `true` iff the owned serializer holds a live state (zenoh-c
/// `ze_internal_serializer_check`).
///
/// # Safety
/// `this_` must be null or a valid owned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_serializer_check(this_: *const ze_owned_serializer_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned serializer (zenoh-c `ze_internal_serializer_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_internal_serializer_null(this_: *mut ze_owned_serializer_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = ze_owned_serializer_t::null_value() };
    }
}

/// Serialize a sequence LENGTH (zenoh-c
/// `ze_serializer_serialize_sequence_length`) — a bare VLE, no element type.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_sequence_length(
    this_: *mut ze_loaned_serializer_t,
    len: usize,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { with_serializer(this_, |state| push_zint(state, len as u64)) }
}

/// Serialize an `int32` (zenoh-c `ze_serializer_serialize_int32`) — FIXED-WIDTH
/// little-endian, not VLE.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_int32(
    this_: *mut ze_loaned_serializer_t,
    val: i32,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        with_serializer(this_, |state| {
            state.buf.extend_from_slice(&val.to_le_bytes())
        })
    }
}

/// Serialize a `uint32` into a fresh payload (zenoh-c `ze_serialize_uint32`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_uint32(this_: *mut z_owned_bytes_t, val: u32) -> ZResult {
    // SAFETY: the caller's contract — a four-byte little-endian payload, the
    // same bytes `ze_serializer_serialize_uint32` would write.
    unsafe { crate::bytes::z_bytes_copy_from_buf(this_, val.to_le_bytes().as_ptr(), 4) }
}

/// Serialize a `uint32` (zenoh-c `ze_serializer_serialize_uint32`).
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_uint32(
    this_: *mut ze_loaned_serializer_t,
    val: u32,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        with_serializer(this_, |state| {
            state.buf.extend_from_slice(&val.to_le_bytes())
        })
    }
}

/// Serialize a `uint64` (zenoh-c `ze_serializer_serialize_uint64`).
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_uint64(
    this_: *mut ze_loaned_serializer_t,
    val: u64,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        with_serializer(this_, |state| {
            state.buf.extend_from_slice(&val.to_le_bytes())
        })
    }
}

/// Serialize a `float` (zenoh-c `ze_serializer_serialize_float`) — its IEEE-754
/// bit pattern, little-endian.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_float(
    this_: *mut ze_loaned_serializer_t,
    val: f32,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        with_serializer(this_, |state| {
            state.buf.extend_from_slice(&val.to_le_bytes())
        })
    }
}

/// Serialize a byte run with its VLE length — the shared body of the two string
/// exports.
///
/// # Safety
/// `this_` must be null or a valid loaned serializer.
unsafe fn serialize_bytes(this_: *mut ze_loaned_serializer_t, bytes: &[u8]) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        with_serializer(this_, |state| {
            push_zint(state, bytes.len() as u64);
            state.buf.extend_from_slice(bytes);
        })
    }
}

/// Serialize a NUL-terminated string (zenoh-c `ze_serializer_serialize_str`).
///
/// # Safety
/// `this_` must be null or a valid loaned serializer; `str_` must be null or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_str(
    this_: *mut ze_loaned_serializer_t,
    str_: *const c_char,
) -> ZResult {
    if str_.is_null() {
        return Z_ENULL;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { CStr::from_ptr(str_) }.to_bytes();
    // SAFETY: delegated.
    unsafe { serialize_bytes(this_, bytes) }
}

/// Serialize a loaned string (zenoh-c `ze_serializer_serialize_string`).
///
/// # Safety
/// `this_` must be null or a valid loaned serializer; `str_` must be null or a
/// valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_string(
    this_: *mut ze_loaned_serializer_t,
    str_: *const z_loaned_string_t,
) -> ZResult {
    if str_.is_null() {
        return Z_ENULL;
    }
    // SAFETY: the caller's contract — a live loaned string.
    let (ptr, len) = unsafe { ((*str_).ptr, (*str_).len) };
    let bytes = if ptr.is_null() {
        &[][..]
    } else {
        // SAFETY: `ptr`/`len` describe the string's buffer.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };
    // SAFETY: delegated.
    unsafe { serialize_bytes(this_, bytes) }
}

/// Build a deserializer over a payload (zenoh-c `ze_deserializer_from_bytes`).
///
/// # Safety
/// `this_` must be null or a valid loaned bytes that outlives the deserializer.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_from_bytes(
    this_: *const z_loaned_bytes_t,
) -> ze_deserializer_t {
    // SAFETY: the caller's contract, delegated.
    let bytes = unsafe { bytes_slice(this_) }.unwrap_or(&[]);
    ze_deserializer_t {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        pos: 0,
    }
}

/// Read a fixed-width little-endian value — the shared body of the arithmetic
/// deserializers.
///
/// # Safety
/// `this_` must be null or a valid deserializer; `dst` must be null or writable.
unsafe fn deserialize_le<const N: usize, T>(
    this_: *mut ze_deserializer_t,
    dst: *mut T,
    from: impl FnOnce([u8; N]) -> T,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || dst.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let de = unsafe { &mut *this_ };
        let Some(bytes) = de.take(N) else {
            return Z_EDESERIALIZE;
        };
        let mut raw = [0u8; N];
        raw.copy_from_slice(bytes);
        // SAFETY: the caller's contract — `dst` is writable.
        unsafe { *dst = from(raw) };
        Z_OK
    })
}

/// Deserialize a sequence LENGTH (zenoh-c
/// `ze_deserializer_deserialize_sequence_length`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `len` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_sequence_length(
    this_: *mut ze_deserializer_t,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || len.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let de = unsafe { &mut *this_ };
        let Some(v) = de.take_zint() else {
            return Z_EDESERIALIZE;
        };
        // A length that does not fit the host's `size_t` is a malformed payload,
        // not a value to truncate into a plausible-looking small number.
        let Ok(v) = usize::try_from(v) else {
            return Z_EDESERIALIZE;
        };
        // SAFETY: the caller's contract.
        unsafe { *len = v };
        Z_OK
    })
}

/// Deserialize an `int32` (zenoh-c `ze_deserializer_deserialize_int32`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `dst` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_int32(
    this_: *mut ze_deserializer_t,
    dst: *mut i32,
) -> ZResult {
    // SAFETY: delegated.
    unsafe { deserialize_le::<4, i32>(this_, dst, i32::from_le_bytes) }
}

/// Deserialize a `uint32` (zenoh-c `ze_deserializer_deserialize_uint32`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `dst` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_uint32(
    this_: *mut ze_deserializer_t,
    dst: *mut u32,
) -> ZResult {
    // SAFETY: delegated.
    unsafe { deserialize_le::<4, u32>(this_, dst, u32::from_le_bytes) }
}

/// Deserialize a `uint64` (zenoh-c `ze_deserializer_deserialize_uint64`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `dst` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_uint64(
    this_: *mut ze_deserializer_t,
    dst: *mut u64,
) -> ZResult {
    // SAFETY: delegated.
    unsafe { deserialize_le::<8, u64>(this_, dst, u64::from_le_bytes) }
}

/// Deserialize a `float` (zenoh-c `ze_deserializer_deserialize_float`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `dst` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_float(
    this_: *mut ze_deserializer_t,
    dst: *mut f32,
) -> ZResult {
    // SAFETY: delegated.
    unsafe { deserialize_le::<4, f32>(this_, dst, f32::from_le_bytes) }
}

/// Deserialize a string into an owned one (zenoh-c
/// `ze_deserializer_deserialize_string`).
///
/// # Safety
/// `this_` must be null or a valid deserializer; `str_` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_string(
    this_: *mut ze_deserializer_t,
    str_: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || str_.is_null() {
            return Z_ENULL;
        }
        // Written before any fallible work, so a caller that ignores the code
        // sees an empty string rather than a stale stack value.
        // SAFETY: the caller's contract.
        unsafe { *str_ = z_owned_string_t::null_value() };
        // SAFETY: the caller's contract.
        let de = unsafe { &mut *this_ };
        // A failed LENGTH read must not advance the cursor, so the length is
        // decoded against a copy and committed only once the body is there too.
        let mut probe = ze_deserializer_t {
            ptr: de.ptr,
            len: de.len,
            pos: de.pos,
        };
        let Some(n) = probe.take_zint() else {
            return Z_EDESERIALIZE;
        };
        let Ok(n) = usize::try_from(n) else {
            return Z_EDESERIALIZE;
        };
        let Some(bytes) = probe.take(n) else {
            return Z_EDESERIALIZE;
        };
        // SAFETY: the caller's contract.
        unsafe { *str_ = owned_string_from(bytes) };
        de.pos = probe.pos;
        Z_OK
    })
}

/// Deserialize a `uint32` straight out of a payload (zenoh-c
/// `ze_deserialize_uint32`).
///
/// # Safety
/// `this_` must be null or a valid loaned bytes; `dst` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserialize_uint32(
    this_: *const z_loaned_bytes_t,
    dst: *mut u32,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            return Z_ENULL;
        };
        // Upstream rejects a payload that is not EXACTLY the value: a longer one
        // is a different type, not a value with a tail to ignore.
        if bytes.len() != 4 {
            return Z_EPARSE;
        };
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        // SAFETY: the caller's contract.
        unsafe { *dst = u32::from_le_bytes(raw) };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{z_moved_bytes_t, ze_moved_serializer_t};

    /// The sequence of writes `z_bytes.c`'s custom-struct section makes,
    /// deserialized back — and, crucially, the BYTES it produces asserted
    /// against the format rule rather than only against this file's own reader.
    ///
    /// A round trip is permutation-invariant over a self-consistent codec: an
    /// implementation that wrote every integer as VLE would round-trip
    /// perfectly here and be unreadable by a real peer. So the byte layout is
    /// spelled out: fixed-width LE for arithmetic, VLE for lengths.
    #[test]
    fn the_serializer_writes_fixed_width_arithmetic_and_vle_lengths() {
        // SAFETY: every pointer below is a live local this test owns.
        unsafe {
            let mut ser = ze_owned_serializer_t::null_value();
            assert_eq!(ze_serializer_empty(&mut ser), Z_OK);
            let s = ze_serializer_loan_mut(&mut ser);
            assert_eq!(ze_serializer_serialize_float(s, 1.0f32), Z_OK);
            assert_eq!(ze_serializer_serialize_sequence_length(s, 2), Z_OK);
            assert_eq!(ze_serializer_serialize_uint64(s, 1), Z_OK);
            assert_eq!(ze_serializer_serialize_int32(s, -2), Z_OK);
            assert_eq!(ze_serializer_serialize_str(s, c"test".as_ptr()), Z_OK);

            let mut payload = z_owned_bytes_t::null_value();
            let mut moved = ze_moved_serializer_t { _this: ser };
            ze_serializer_finish(&mut moved, &mut payload);

            let loaned = crate::bytes::z_bytes_loan(&payload);
            let bytes = crate::bytes::bytes_slice(loaned).expect("a finished payload");
            let mut expect: Vec<u8> = Vec::new();
            expect.extend_from_slice(&1.0f32.to_le_bytes()); // float: 4 LE bytes
            expect.push(2); // sequence length: VLE, one byte here
            expect.extend_from_slice(&1u64.to_le_bytes()); // uint64: 8 LE bytes
            expect.extend_from_slice(&(-2i32).to_le_bytes()); // int32: 4 LE bytes
            expect.push(4); // string length: VLE
            expect.extend_from_slice(b"test");
            assert_eq!(
                bytes,
                &expect[..],
                "the serialized bytes are the format, not merely something this \
                 file's own reader accepts"
            );

            // And the deserializer reads them back in the same order.
            let mut de = ze_deserializer_from_bytes(loaned);
            let (mut f, mut n, mut u, mut i) = (0f32, 0usize, 0u64, 0i32);
            let mut text = z_owned_string_t::null_value();
            assert_eq!(ze_deserializer_deserialize_float(&mut de, &mut f), Z_OK);
            assert_eq!(
                ze_deserializer_deserialize_sequence_length(&mut de, &mut n),
                Z_OK
            );
            assert_eq!(ze_deserializer_deserialize_uint64(&mut de, &mut u), Z_OK);
            assert_eq!(ze_deserializer_deserialize_int32(&mut de, &mut i), Z_OK);
            assert_eq!(ze_deserializer_deserialize_string(&mut de, &mut text), Z_OK);
            assert_eq!((f, n, u, i), (1.0f32, 2, 1u64, -2i32));
            let ls = crate::string::z_string_loan(&text);
            assert_eq!(
                std::slice::from_raw_parts(
                    crate::string::z_string_data(ls) as *const u8,
                    crate::string::z_string_len(ls)
                ),
                b"test"
            );

            // Drained: the next read reports a deserialize failure rather than
            // inventing a value.
            assert_eq!(
                ze_deserializer_deserialize_int32(&mut de, &mut i),
                Z_EDESERIALIZE
            );

            let mut ms = crate::abi::z_moved_string_t { _this: text };
            crate::string::z_string_drop(&mut ms);
            let mut mp = z_moved_bytes_t { _this: payload };
            crate::bytes::z_bytes_drop(&mut mp);
        }
    }

    /// `ze_serialize_uint32` writes the same four bytes the serializer would,
    /// and `ze_deserialize_uint32` refuses a payload that is not exactly one
    /// value — the pair `z_bytes.c`'s arithmetic section drives.
    #[test]
    fn the_standalone_uint32_pair_round_trips_and_rejects_a_wrong_length() {
        // SAFETY: live locals.
        unsafe {
            let mut payload = z_owned_bytes_t::null_value();
            assert_eq!(ze_serialize_uint32(&mut payload, 1234), Z_OK);
            let loaned = crate::bytes::z_bytes_loan(&payload);
            assert_eq!(
                crate::bytes::bytes_slice(loaned).unwrap(),
                &1234u32.to_le_bytes()[..]
            );
            let mut out = 0u32;
            assert_eq!(ze_deserialize_uint32(loaned, &mut out), Z_OK);
            assert_eq!(out, 1234);
            let mut mp = z_moved_bytes_t { _this: payload };
            crate::bytes::z_bytes_drop(&mut mp);

            let mut short = z_owned_bytes_t::null_value();
            assert_eq!(
                crate::bytes::z_bytes_copy_from_buf(&mut short, [1u8, 2].as_ptr(), 2),
                Z_OK
            );
            assert_eq!(
                ze_deserialize_uint32(crate::bytes::z_bytes_loan(&short), &mut out),
                Z_EPARSE
            );
            let mut ms = z_moved_bytes_t { _this: short };
            crate::bytes::z_bytes_drop(&mut ms);
        }
    }

    /// A truncated string does not half-consume the cursor: the length decodes
    /// but the body is short, and a caller that retries after appending must
    /// not find the length already eaten.
    #[test]
    fn a_truncated_string_leaves_the_cursor_where_it_was() {
        // SAFETY: live locals.
        unsafe {
            let mut payload = z_owned_bytes_t::null_value();
            // VLE length 4, then only two body bytes.
            assert_eq!(
                crate::bytes::z_bytes_copy_from_buf(&mut payload, [4u8, b'a', b'b'].as_ptr(), 3),
                Z_OK
            );
            let mut de = ze_deserializer_from_bytes(crate::bytes::z_bytes_loan(&payload));
            let before = de.pos;
            let mut text = z_owned_string_t::null_value();
            assert_eq!(
                ze_deserializer_deserialize_string(&mut de, &mut text),
                Z_EDESERIALIZE
            );
            assert_eq!(de.pos, before, "a failed read must not consume the length");
            let mut mp = z_moved_bytes_t { _this: payload };
            crate::bytes::z_bytes_drop(&mut mp);
        }
    }
}
