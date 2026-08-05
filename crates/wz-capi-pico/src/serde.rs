// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The BYTES WRITER / READER plane and the `ze_serializer` / `ze_deserializer`
//! codec built on it.
//!
//! ## A serializer IS a writer, and that is an ABI fact, not a shortcut
//!
//! pico defines `_ze_serializer_t { _z_bytes_writer_t _writer; }` and its header
//! carries `static inline` helpers — `ze_serializer_serialize_uint32`,
//! `_float`, `_int32`, … — whose bodies read
//! `z_bytes_writer_write_all(&serializer->_writer, …)`. So a C program COMPILES
//! code that takes the address of a field inside this type and hands it to an
//! exported writer function. Measured: `offsetof(_ze_serializer_t, _writer)` is
//! **0**, so `&s->_writer` is bit-identical to `s`.
//!
//! That is what makes the design here sound rather than convenient: one
//! [`WriterState`] behind one handle representation, shared by
//! `z_owned_bytes_writer_t` and `ze_owned_serializer_t` alike. If the two had
//! different handle shapes, every inline helper in pico's header would hand the
//! writer functions a serializer-shaped pointer and corrupt memory silently. The
//! offsets are pinned in this module's tests for exactly that reason.
//!
//! The same holds one level down: `ze_deserializer_t { z_bytes_reader_t _reader; }`
//! with `_reader` at offset 0, and the inline deserialize helpers pass
//! `&deserializer->_reader` to `z_bytes_reader_read`.
//!
//! ## The reader is a BORROW, so it is POD and never freed
//!
//! `z_bytes_get_reader` and `ze_deserializer_from_bytes` return BY VALUE into a
//! C stack slot, and pico exports no `drop` for either — so neither may own
//! anything. Both are plain 32-byte PODs borrowing the payload they were built
//! from, and the C program's own `z_owned_bytes_t` is what keeps that alive.
//! Their internal layout is wz's own (C never inspects the fields, only takes
//! the address); only the SIZE is ABI.
//!
//! ## The format is upstream's, and it is not self-describing
//!
//! `ze_serializer_serialize_buf` writes a VLE length then the raw bytes
//! (`src/api/serialization.c:72-76`); strings are that same shape over their
//! UTF-8; a sequence length is the bare VLE. Arithmetic types are written as
//! FIXED-WIDTH LITTLE-ENDIAN, not VLE — `ze_serializer_serialize_uint32` is a
//! `_z_host_le_store32` and a 4-byte `write_all`. Mixing those two up produces
//! bytes that decode as garbage on a real peer, so the wire shape is pinned
//! against `libzenohpico.so` rather than against this crate's own reader.

use std::ffi::{c_char, c_void, CStr};

use crate::abi::{
    impl_handle_ownership7, z_loaned_bytes_t, z_moved_bytes_t, z_owned_bytes_t, z_owned_slice_t,
    z_owned_string_t,
};
use crate::bytes::{bytes_ref, store_owned_bytes, store_owned_slice, store_owned_string, ByteBuf};
use crate::codec::{decode_zint, encode_zint, VLE_LEN};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_NULL, Z_OK};

/// Behind a `z_owned_bytes_writer_t` / `ze_owned_serializer_t`: the accumulating
/// buffer. One type for both, because pico's serializer is literally a writer.
///
/// A [`ByteBuf`] rather than a bare `Vec<u8>` so the SEGMENT boundaries a
/// `z_bytes_writer_append` leaves survive `z_bytes_writer_finish` into the
/// payload — which is what upstream's own `z_bytes.c` then walks with
/// `z_bytes_get_slice_iterator`.
pub(crate) type WriterState = ByteBuf;

/// Owned bytes writer (pico `z_owned_bytes_writer_t`, 40 B measured).
#[repr(C)]
pub struct z_owned_bytes_writer_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Loaned bytes writer (pico `z_loaned_bytes_writer_t`), same footprint.
#[repr(C)]
pub struct z_loaned_bytes_writer_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Moved bytes writer (pico `z_moved_bytes_writer_t`).
#[repr(C)]
pub struct z_moved_bytes_writer_t {
    pub(crate) _this: z_owned_bytes_writer_t,
}

impl z_owned_bytes_writer_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 4],
        }
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<WriterState>` pointer.
unsafe fn free_writer(h: *mut c_void) {
    drop(Box::from_raw(h as *mut WriterState));
}

impl_handle_ownership7!(
    z_owned_bytes_writer_t,
    z_loaned_bytes_writer_t,
    z_moved_bytes_writer_t,
    free_writer,
    z_internal_bytes_writer_null,
    z_internal_bytes_writer_check,
    z_bytes_writer_loan,
    z_bytes_writer_loan_mut,
    z_bytes_writer_move,
    z_bytes_writer_take,
    z_bytes_writer_drop
);

/// Owned serializer (pico `ze_owned_serializer_t`, 40 B measured).
///
/// The SAME handle representation as [`z_owned_bytes_writer_t`] — see the module
/// doc for why that is load-bearing rather than tidy.
#[repr(C)]
pub struct ze_owned_serializer_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Loaned serializer (pico `ze_loaned_serializer_t`).
#[repr(C)]
pub struct ze_loaned_serializer_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Moved serializer (pico `ze_moved_serializer_t`).
#[repr(C)]
pub struct ze_moved_serializer_t {
    pub(crate) _this: ze_owned_serializer_t,
}

impl ze_owned_serializer_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 4],
        }
    }
}

impl_handle_ownership7!(
    ze_owned_serializer_t,
    ze_loaned_serializer_t,
    ze_moved_serializer_t,
    free_writer,
    ze_internal_serializer_null,
    ze_internal_serializer_check,
    ze_serializer_loan,
    ze_serializer_loan_mut,
    ze_serializer_move,
    ze_serializer_take,
    ze_serializer_drop
);

/// Borrow the accumulating buffer behind a loaned writer or serializer.
///
/// # Safety
/// `ptr` must be a live loaned writer/serializer handle.
unsafe fn writer_mut<'a>(ptr: *mut c_void) -> Option<&'a mut WriterState> {
    let handle = handle_of(ptr)?;
    Some(&mut *(handle as *mut WriterState))
}

/// The inner handle pointer of any of this module's 40-byte handle types.
///
/// # Safety
/// `ptr` must be null or point at a value whose first field is the handle.
unsafe fn handle_of(ptr: *mut c_void) -> Option<*mut c_void> {
    if ptr.is_null() {
        return None;
    }
    let handle = *(ptr as *const *mut c_void);
    (!handle.is_null()).then_some(handle)
}

// --- writer ----------------------------------------------------------------

/// Start an empty writer (pico `z_bytes_writer_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_empty(writer: *mut z_owned_bytes_writer_t) -> ZResult {
    guarded(|| {
        if writer.is_null() {
            return Z_ERR_NULL;
        }
        *writer = z_owned_bytes_writer_t {
            handle: Box::into_raw(Box::new(WriterState::new())) as *mut c_void,
            _pad: [std::ptr::null_mut(); 4],
        };
        Z_OK
    })
}

/// Append raw bytes (pico `z_bytes_writer_write_all`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_write_all(
    writer: *mut z_loaned_bytes_writer_t,
    src: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        let buf = match writer_mut(writer as *mut c_void) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        if len == 0 {
            return Z_OK;
        }
        if src.is_null() {
            return Z_ERR_NULL;
        }
        buf.write_all(std::slice::from_raw_parts(src, len));
        Z_OK
    })
}

/// Append a moved payload's bytes (pico `z_bytes_writer_append`), consuming it.
///
/// **NAMED DIVERGENCE.** pico's `z_owned_bytes_t` is a LIST of slices, so
/// appending three payloads leaves three slices a program can walk with
/// `z_bytes_get_slice_iterator`. wz's C bytes are one contiguous buffer, so the
/// appended content is concatenated and the boundaries are lost. The BYTES are
/// identical either way — every wire path, every `z_bytes_to_string`, every
/// reader read sees the same octets — and only slice-boundary introspection can
/// tell the two apart. Carried as an open item rather than papered over.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_append(
    writer: *mut z_loaned_bytes_writer_t,
    bytes: *mut z_moved_bytes_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload FIRST, so an invalid writer still frees it
        // (pico's move is unconditional once the call is made).
        let taken = crate::pubsub::take_moved_bytes(bytes);
        let buf = match writer_mut(writer as *mut c_void) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        match taken {
            Some(payload) => {
                // APPEND, not write: pico moves the source payload in as its
                // own slice(s), and `z_bytes.c` walks the result expecting to
                // see them back.
                buf.append_segments(&payload);
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Finish a writer into an owned payload (pico `z_bytes_writer_finish`),
/// consuming the writer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_finish(
    writer: *mut z_moved_bytes_writer_t,
    bytes: *mut z_owned_bytes_t,
) {
    let _ = guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let collected = take_writer_handle(writer as *mut c_void).unwrap_or_default();
        store_owned_bytes(bytes, collected);
        Z_OK
    });
}

/// Take the accumulated buffer out of a moved writer/serializer, nulling the
/// source so its handle is released exactly once.
///
/// # Safety
/// `moved` must be null or a valid moved writer/serializer.
unsafe fn take_writer_handle(moved: *mut c_void) -> Option<WriterState> {
    if moved.is_null() {
        return None;
    }
    let slot = moved as *mut *mut c_void;
    let handle = *slot;
    if handle.is_null() {
        return None;
    }
    *slot = std::ptr::null_mut();
    Some(*Box::from_raw(handle as *mut WriterState))
}

// --- serializer ------------------------------------------------------------

/// Start an empty serializer (pico `ze_serializer_empty`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_empty(serializer: *mut ze_owned_serializer_t) -> ZResult {
    guarded(|| {
        if serializer.is_null() {
            return Z_ERR_NULL;
        }
        *serializer = ze_owned_serializer_t {
            handle: Box::into_raw(Box::new(WriterState::new())) as *mut c_void,
            _pad: [std::ptr::null_mut(); 4],
        };
        Z_OK
    })
}

/// Finish a serializer into an owned payload (pico `ze_serializer_finish`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_finish(
    serializer: *mut ze_moved_serializer_t,
    bytes: *mut z_owned_bytes_t,
) {
    let _ = guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let collected = take_writer_handle(serializer as *mut c_void).unwrap_or_default();
        store_owned_bytes(bytes, collected);
        Z_OK
    });
}

/// Write a bare VLE length (pico `ze_serializer_serialize_sequence_length`).
///
/// This is the element COUNT of a following sequence, written with no payload of
/// its own — which is why a program pairs it with its own loop rather than with
/// a single serialize call.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_sequence_length(
    serializer: *mut ze_loaned_serializer_t,
    len: usize,
) -> ZResult {
    guarded(|| {
        let buf = match writer_mut(serializer as *mut c_void) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        let mut vle = [0u8; VLE_LEN];
        let n = encode_zint(&mut vle, len as u64);
        buf.write_all(&vle[..n]);
        Z_OK
    })
}

/// Write a length-prefixed byte run (pico `ze_serializer_serialize_buf`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_buf(
    serializer: *mut ze_loaned_serializer_t,
    val: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if len != 0 && val.is_null() {
            return Z_ERR_NULL;
        }
        let rc = ze_serializer_serialize_sequence_length(serializer, len);
        if rc != Z_OK {
            return rc;
        }
        let buf = match writer_mut(serializer as *mut c_void) {
            Some(b) => b,
            None => return Z_ERR_NULL,
        };
        if len != 0 {
            buf.write_all(std::slice::from_raw_parts(val, len));
        }
        Z_OK
    })
}

/// Write a length-prefixed slice (pico `ze_serializer_serialize_slice`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_slice(
    serializer: *mut ze_loaned_serializer_t,
    val: *const crate::abi::z_loaned_slice_t,
) -> ZResult {
    let data = crate::bytes::z_slice_data(val);
    let len = crate::bytes::z_slice_len(val);
    ze_serializer_serialize_buf(serializer, data, len)
}

/// Write a length-prefixed substring (pico `ze_serializer_serialize_substr`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_substr(
    serializer: *mut ze_loaned_serializer_t,
    start: *const c_char,
    len: usize,
) -> ZResult {
    ze_serializer_serialize_buf(serializer, start as *const u8, len)
}

/// Write a length-prefixed NUL-terminated string (pico
/// `ze_serializer_serialize_str`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_str(
    serializer: *mut ze_loaned_serializer_t,
    val: *const c_char,
) -> ZResult {
    if val.is_null() {
        return ze_serializer_serialize_buf(serializer, std::ptr::null(), 0);
    }
    let bytes = CStr::from_ptr(val).to_bytes();
    ze_serializer_serialize_buf(serializer, bytes.as_ptr(), bytes.len())
}

/// Write a length-prefixed owned string (pico `ze_serializer_serialize_string`).
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_serialize_string(
    serializer: *mut ze_loaned_serializer_t,
    val: *const crate::abi::z_loaned_string_t,
) -> ZResult {
    let data = crate::bytes::z_string_data(val);
    let len = crate::bytes::z_string_len(val);
    ze_serializer_serialize_buf(serializer, data as *const u8, len)
}

// --- reader ----------------------------------------------------------------

/// pico `z_bytes_reader_t`, 32 B measured — a BORROW of a payload, returned by
/// value and never dropped.
///
/// The fields are wz's own: C only ever takes this value's ADDRESS and hands it
/// to an exported function, so nothing outside this crate reads them. Only the
/// size is ABI, and it is pinned below.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_bytes_reader_t {
    pub(crate) data: *const u8,
    pub(crate) len: usize,
    pub(crate) pos: usize,
    pub(crate) _reserved: usize,
}

impl z_bytes_reader_t {
    fn empty() -> Self {
        Self {
            data: std::ptr::null(),
            len: 0,
            pos: 0,
            _reserved: 0,
        }
    }

    /// The not-yet-consumed tail.
    ///
    /// # Safety
    /// `data` must be valid for `len` bytes.
    unsafe fn remaining(&self) -> &[u8] {
        if self.data.is_null() || self.pos >= self.len {
            return &[];
        }
        std::slice::from_raw_parts(self.data.add(self.pos), self.len - self.pos)
    }
}

/// Build a reader over a payload (pico `z_bytes_get_reader`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_reader(bytes: *const z_loaned_bytes_t) -> z_bytes_reader_t {
    guard_val(z_bytes_reader_t::empty(), || match bytes_ref(bytes) {
        Some(buf) => z_bytes_reader_t {
            data: buf.as_ptr(),
            len: buf.len(),
            pos: 0,
            _reserved: 0,
        },
        None => z_bytes_reader_t::empty(),
    })
}

/// Read up to `len` bytes, advancing the reader (pico `z_bytes_reader_read`).
/// Returns the count actually read.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_read(
    reader: *mut z_bytes_reader_t,
    dst: *mut u8,
    len: usize,
) -> usize {
    guard_val(0, || {
        if reader.is_null() || (len != 0 && dst.is_null()) {
            return 0;
        }
        let available = (*reader).remaining();
        let n = len.min(available.len());
        if n != 0 {
            std::ptr::copy_nonoverlapping(available.as_ptr(), dst, n);
            (*reader).pos += n;
        }
        n
    })
}

/// Bytes not yet consumed (pico `z_bytes_reader_remaining`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_remaining(reader: *const z_bytes_reader_t) -> usize {
    guard_val(0, || {
        if reader.is_null() {
            return 0;
        }
        (*reader).remaining().len()
    })
}

/// Reposition the reader (pico `z_bytes_reader_seek`). `origin` follows C's
/// `SEEK_SET` / `SEEK_CUR` / `SEEK_END`.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_seek(
    reader: *mut z_bytes_reader_t,
    offset: i64,
    origin: std::ffi::c_int,
) -> ZResult {
    guarded(|| {
        if reader.is_null() {
            return Z_ERR_NULL;
        }
        let base = match origin {
            0 => 0i64,                 // SEEK_SET
            1 => (*reader).pos as i64, // SEEK_CUR
            2 => (*reader).len as i64, // SEEK_END
            _ => return crate::result::Z_ERR_INVALID,
        };
        let target = base.saturating_add(offset);
        // Out of range is an ERROR rather than a clamp: a program that seeks
        // past the end has lost track of the format, and silently landing at the
        // end would make the next read return 0 as if the data were merely
        // exhausted.
        if target < 0 || target > (*reader).len as i64 {
            return Z_ERR_GENERIC;
        }
        (*reader).pos = target as usize;
        Z_OK
    })
}

/// Current read offset (pico `z_bytes_reader_tell`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_reader_tell(reader: *const z_bytes_reader_t) -> i64 {
    guard_val(-1, || {
        if reader.is_null() {
            return -1;
        }
        (*reader).pos as i64
    })
}

// --- deserializer ----------------------------------------------------------

/// pico `ze_deserializer_t`, 32 B measured — `{ z_bytes_reader_t _reader }` with
/// the reader at offset 0, so pico's inline deserialize helpers can pass
/// `&deserializer->_reader` straight to [`z_bytes_reader_read`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ze_deserializer_t {
    pub(crate) _reader: z_bytes_reader_t,
}

/// Build a deserializer over a payload (pico `ze_deserializer_from_bytes`).
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_from_bytes(
    bytes: *const z_loaned_bytes_t,
) -> ze_deserializer_t {
    ze_deserializer_t {
        _reader: z_bytes_get_reader(bytes),
    }
}

/// Whether everything has been consumed (pico `ze_deserializer_is_done`).
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_is_done(deserializer: *const ze_deserializer_t) -> bool {
    guard_val(true, || {
        if deserializer.is_null() {
            return true;
        }
        (*deserializer)._reader.remaining().is_empty()
    })
}

/// Read a bare VLE length (pico `ze_deserializer_deserialize_sequence_length`).
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_sequence_length(
    deserializer: *mut ze_deserializer_t,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if deserializer.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        let reader = &mut (*deserializer)._reader;
        match decode_zint(reader.remaining()) {
            Some((value, used)) => {
                reader.pos += used;
                *len = value as usize;
                Z_OK
            }
            // Truncated input: reported rather than guessed, so a malformed
            // payload cannot be read as a plausible count.
            None => Z_ERR_GENERIC,
        }
    })
}

/// Read a length-prefixed byte run into an owned slice (pico
/// `ze_deserializer_deserialize_slice`).
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_slice(
    deserializer: *mut ze_deserializer_t,
    val: *mut z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        if val.is_null() {
            return Z_ERR_NULL;
        }
        match take_length_prefixed(deserializer) {
            Some(bytes) => {
                store_owned_slice(val, bytes);
                Z_OK
            }
            None => Z_ERR_GENERIC,
        }
    })
}

/// Read a length-prefixed byte run into an owned string (pico
/// `ze_deserializer_deserialize_string`).
#[no_mangle]
pub unsafe extern "C" fn ze_deserializer_deserialize_string(
    deserializer: *mut ze_deserializer_t,
    val: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if val.is_null() {
            return Z_ERR_NULL;
        }
        match take_length_prefixed(deserializer) {
            Some(bytes) => {
                store_owned_string(val, &bytes);
                Z_OK
            }
            None => Z_ERR_GENERIC,
        }
    })
}

/// Read one `<vle len><len bytes>` record, advancing the reader only when the
/// WHOLE record is present.
///
/// The all-or-nothing advance matters: pico's deserializer reports
/// `_Z_ERR_DID_NOT_READ` and leaves the position alone, so a program that
/// retries after a short read sees the same record rather than a shifted one.
///
/// # Safety
/// `deserializer` must be null or valid.
unsafe fn take_length_prefixed(deserializer: *mut ze_deserializer_t) -> Option<ByteBuf> {
    if deserializer.is_null() {
        return None;
    }
    let reader = &mut (*deserializer)._reader;
    let remaining = reader.remaining();
    let (len, used) = decode_zint(remaining)?;
    let len = len as usize;
    let body = remaining.get(used..used + len)?;
    let out = ByteBuf::from(body);
    reader.pos += used + len;
    Some(out)
}

// --- arithmetic ------------------------------------------------------------

/// The `ze_serialize_<t>` / `ze_deserialize_<t>` pair for one fixed-width type.
///
/// pico writes these LITTLE-ENDIAN and FIXED WIDTH — not VLE — via
/// `_z_host_le_store*` and a raw `write_all` (`api/serialization.h:125`). The
/// deserialize half additionally requires the payload to be FULLY consumed
/// (`Z_EDESERIALIZE` otherwise, `api/serialization.c:159-166`), which is what
/// makes `ze_deserialize_uint32` on a longer payload an error rather than a
/// silent prefix read.
macro_rules! impl_arithmetic {
    ($ser:ident, $de:ident, $ty:ty) => {
        #[doc = concat!("Serialize one `", stringify!($ty), "` into a fresh payload (pico `", stringify!($ser), "`).")]
        #[no_mangle]
        pub unsafe extern "C" fn $ser(bytes: *mut z_owned_bytes_t, data: $ty) -> ZResult {
            guarded(|| {
                if bytes.is_null() {
                    return Z_ERR_NULL;
                }
                store_owned_bytes(bytes, ByteBuf::from(data.to_le_bytes().as_slice()));
                Z_OK
            })
        }

        #[doc = concat!("Deserialize one `", stringify!($ty), "` from a whole payload (pico `", stringify!($de), "`).")]
        #[no_mangle]
        pub unsafe extern "C" fn $de(bytes: *const z_loaned_bytes_t, data: *mut $ty) -> ZResult {
            guarded(|| {
                if data.is_null() {
                    return Z_ERR_NULL;
                }
                let buf = match bytes_ref(bytes) {
                    Some(b) => b,
                    None => return Z_ERR_NULL,
                };
                const N: usize = std::mem::size_of::<$ty>();
                // Exactly N bytes: a longer payload is an ERROR, mirroring
                // pico's is-done check, not a prefix read.
                if buf.len() != N {
                    return Z_ERR_GENERIC;
                }
                let mut raw = [0u8; N];
                raw.copy_from_slice(&buf[..N]);
                *data = <$ty>::from_le_bytes(raw);
                Z_OK
            })
        }
    };
}

impl_arithmetic!(ze_serialize_uint8, ze_deserialize_uint8, u8);
impl_arithmetic!(ze_serialize_uint16, ze_deserialize_uint16, u16);
impl_arithmetic!(ze_serialize_uint32, ze_deserialize_uint32, u32);
impl_arithmetic!(ze_serialize_uint64, ze_deserialize_uint64, u64);
impl_arithmetic!(ze_serialize_int8, ze_deserialize_int8, i8);
impl_arithmetic!(ze_serialize_int16, ze_deserialize_int16, i16);
impl_arithmetic!(ze_serialize_int32, ze_deserialize_int32, i32);
impl_arithmetic!(ze_serialize_int64, ze_deserialize_int64, i64);
impl_arithmetic!(ze_serialize_float, ze_deserialize_float, f32);
impl_arithmetic!(ze_serialize_double, ze_deserialize_double, f64);

/// Adopt a loaned writer into an owned one, emptying the source (pico
/// `z_bytes_writer_take_from_loaned`).
///
/// R311y559 — a symbol the census found missing. Hand-written rather than
/// emitted by [`impl_value_ownership`](crate::abi::impl_value_ownership)
/// because that macro clears a THREE-slot pad and the writer carries four; an
/// under-wide clear would leave a stale pointer word in the source the caller
/// is entitled to reuse. Same reason, same shape as
/// [`z_encoding_take_from_loaned`](crate::encoding::z_encoding_take_from_loaned).
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned writer
/// this crate produced.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_writer_take_from_loaned(
    dst: *mut z_owned_bytes_writer_t,
    src: *mut z_loaned_bytes_writer_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_bytes_writer_t {
            handle: (*src).handle,
            _pad: (*src)._pad,
        };
        (*src).handle = std::ptr::null_mut();
        (*src)._pad = [std::ptr::null_mut(); 4];
        Z_OK
    })
}

// --- R311y559: the one-shot serialize / deserialize helpers ----------------
//
// Upstream's `ze_serialize_*` / `ze_deserialize_*` are the SINGLE-VALUE forms
// of the serializer family already above: each builds (or consumes) a whole
// payload holding exactly one value. They are written as compositions of the
// serializer rather than as parallel encoders, so the wire format has ONE
// definition — a second encoder here would be a copy that drifts, and the
// R311y532 slice-arrangement finding is what that drift looks like when only a
// foreign oracle can see it.

/// Serialize a length-prefixed byte buffer as a whole payload (pico
/// `ze_serialize_buf`).
///
/// # Safety
/// `bytes` must be valid and writable; `data` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_buf(
    bytes: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    one_shot(bytes, |serializer| {
        ze_serializer_serialize_buf(serializer, data, len)
    })
}

/// Serialize a loaned slice as a whole payload (pico `ze_serialize_slice`).
///
/// # Safety
/// `bytes` must be valid and writable; `slice` must be null or a live loaned
/// slice.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_slice(
    bytes: *mut z_owned_bytes_t,
    slice: *const crate::abi::z_loaned_slice_t,
) -> ZResult {
    one_shot(bytes, |serializer| {
        ze_serializer_serialize_slice(serializer, slice)
    })
}

/// Serialize a NUL-terminated string as a whole payload (pico
/// `ze_serialize_str`).
///
/// # Safety
/// `bytes` must be valid and writable; `value` must be null or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_str(
    bytes: *mut z_owned_bytes_t,
    value: *const std::ffi::c_char,
) -> ZResult {
    one_shot(bytes, |serializer| {
        ze_serializer_serialize_str(serializer, value)
    })
}

/// Serialize an explicitly-sized substring as a whole payload (pico
/// `ze_serialize_substr`).
///
/// # Safety
/// `bytes` must be valid and writable; `start` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_substr(
    bytes: *mut z_owned_bytes_t,
    start: *const std::ffi::c_char,
    len: usize,
) -> ZResult {
    one_shot(bytes, |serializer| {
        ze_serializer_serialize_substr(serializer, start, len)
    })
}

/// Serialize a loaned string as a whole payload (pico `ze_serialize_string`).
///
/// # Safety
/// `bytes` must be valid and writable; `s` must be null or a live loaned
/// string.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_string(
    bytes: *mut z_owned_bytes_t,
    s: *const crate::abi::z_loaned_string_t,
) -> ZResult {
    one_shot(bytes, |serializer| {
        ze_serializer_serialize_string(serializer, s)
    })
}

/// Serialize a boolean as a whole payload (pico `ze_serialize_bool`).
///
/// ONE byte, 0 or 1 — zenoh's serializer encodes a bool as a plain octet with
/// no length prefix, unlike every other value in this family. Written out
/// rather than routed through the length-prefixed buffer form for exactly that
/// reason.
///
/// # Safety
/// `bytes` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ze_serialize_bool(bytes: *mut z_owned_bytes_t, val: bool) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let octet: [u8; 1] = [u8::from(val)];
        crate::bytes::z_bytes_copy_from_buf(bytes, octet.as_ptr(), 1)
    })
}

/// Build a payload by running `body` against a fresh serializer, then finishing
/// it into `bytes`.
///
/// Shared by every `ze_serialize_*` above so the "null the destination, build,
/// finish" sequence — and its failure path — cannot drift between them.
///
/// # Safety
/// `bytes` must be null or valid and writable.
unsafe fn one_shot(
    bytes: *mut z_owned_bytes_t,
    body: impl FnOnce(*mut ze_loaned_serializer_t) -> ZResult,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        let mut serializer = ze_owned_serializer_t::null_value();
        let rc = ze_serializer_empty(&mut serializer);
        if rc != Z_OK {
            return rc;
        }
        let rc = body(ze_serializer_loan_mut(&mut serializer));
        if rc != Z_OK {
            // Release the half-built serializer rather than leaking it; the
            // caller sees a null payload, which `z_internal_bytes_check`
            // reports as absent.
            ze_serializer_drop(ze_serializer_move(&mut serializer));
            return rc;
        }
        ze_serializer_finish(ze_serializer_move(&mut serializer), bytes);
        Z_OK
    })
}

/// Read one length-prefixed slice out of a whole payload (pico
/// `ze_deserialize_slice`).
///
/// # Safety
/// `bytes` must be null or a live loaned payload; `dst` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserialize_slice(
    bytes: *const z_loaned_bytes_t,
    dst: *mut crate::abi::z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        let mut deserializer = ze_deserializer_from_bytes(bytes);
        ze_deserializer_deserialize_slice(&mut deserializer, dst)
    })
}

/// Read one length-prefixed string out of a whole payload (pico
/// `ze_deserialize_string`).
///
/// # Safety
/// `bytes` must be null or a live loaned payload; `str_out` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserialize_string(
    bytes: *const z_loaned_bytes_t,
    str_out: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        let mut deserializer = ze_deserializer_from_bytes(bytes);
        ze_deserializer_deserialize_string(&mut deserializer, str_out)
    })
}

/// Read a boolean out of a whole payload (pico `ze_deserialize_bool`).
///
/// The mirror of [`ze_serialize_bool`]: one octet, and any non-zero value reads
/// as `true`. A payload of a different length is REJECTED rather than
/// truncated — a caller asking for a bool and being handed a 4-byte value has
/// a type mismatch, not a bool.
///
/// # Safety
/// `bytes` must be null or a live loaned payload; `dst` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn ze_deserialize_bool(
    bytes: *const z_loaned_bytes_t,
    dst: *mut bool,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = false;
        let Some(buf) = crate::bytes::bytes_ref(bytes) else {
            return Z_ERR_NULL;
        };
        match buf.as_slice() {
            [octet] => {
                *dst = *octet != 0;
                Z_OK
            }
            _ => crate::result::Z_ERR_INVALID,
        }
    })
}

/// Adopt a loaned serializer into an owned one, emptying the source (pico
/// `ze_serializer_take_from_loaned`).
///
/// Hand-written for the same reason
/// [`z_bytes_writer_take_from_loaned`] is: the shared macro clears a
/// THREE-slot pad and this type carries four.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned
/// serializer this crate produced.
#[no_mangle]
pub unsafe extern "C" fn ze_serializer_take_from_loaned(
    dst: *mut ze_owned_serializer_t,
    src: *mut ze_loaned_serializer_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *dst = ze_owned_serializer_t {
            handle: (*src).handle,
            _pad: (*src)._pad,
        };
        (*src).handle = std::ptr::null_mut();
        (*src)._pad = [std::ptr::null_mut(); 4];
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI a C program stack-allocates, and — the part that is easy to miss
    /// — the OFFSETS pico's `static inline` helpers depend on. Those helpers
    /// pass `&serializer->_writer` and `&deserializer->_reader` to exported
    /// functions, so a non-zero offset here is silent memory corruption rather
    /// than a link error.
    #[test]
    fn serde_abi_matches_pico() {
        assert_eq!(std::mem::size_of::<z_owned_bytes_writer_t>(), 40);
        assert_eq!(std::mem::size_of::<z_moved_bytes_writer_t>(), 40);
        assert_eq!(std::mem::size_of::<ze_owned_serializer_t>(), 40);
        assert_eq!(std::mem::size_of::<ze_moved_serializer_t>(), 40);
        assert_eq!(std::mem::size_of::<z_bytes_reader_t>(), 32);
        assert_eq!(std::mem::size_of::<ze_deserializer_t>(), 32);

        let d = ze_deserializer_t {
            _reader: z_bytes_reader_t::empty(),
        };
        assert_eq!(
            &d._reader as *const _ as usize - &d as *const _ as usize,
            0,
            "pico's inline deserialize helpers pass &deserializer->_reader"
        );
    }

    /// A serializer handle and a writer handle must be interchangeable at the
    /// ABI, because pico's header hands one to the other's functions.
    #[test]
    fn a_serializer_is_a_writer() {
        unsafe {
            let mut serializer = ze_owned_serializer_t::null_value();
            assert_eq!(ze_serializer_empty(&mut serializer), Z_OK);
            // Exactly what `ze_serializer_serialize_float` does in pico's
            // header: take the address of the serializer's first field and call
            // the WRITER function with it.
            let as_writer = &mut serializer as *mut _ as *mut z_loaned_bytes_writer_t;
            let payload = [1u8, 2, 3];
            assert_eq!(
                z_bytes_writer_write_all(as_writer, payload.as_ptr(), payload.len()),
                Z_OK
            );
            let mut bytes = std::mem::zeroed();
            ze_serializer_finish(
                &mut serializer as *mut _ as *mut ze_moved_serializer_t,
                &mut bytes,
            );
            let buf = bytes_ref(crate::bytes::z_bytes_loan(&bytes)).expect("payload");
            assert_eq!(buf.as_slice(), &[1, 2, 3]);
        }
    }

    /// The `<vle len><bytes>` shape, and that the reader consumes exactly what
    /// the writer produced.
    #[test]
    fn a_string_round_trips_through_the_length_prefix() {
        unsafe {
            let mut serializer = ze_owned_serializer_t::null_value();
            assert_eq!(ze_serializer_empty(&mut serializer), Z_OK);
            let loaned = &mut serializer as *mut _ as *mut ze_loaned_serializer_t;
            assert_eq!(ze_serializer_serialize_sequence_length(loaned, 2), Z_OK);
            assert_eq!(ze_serializer_serialize_str(loaned, c"alpha".as_ptr()), Z_OK);
            assert_eq!(ze_serializer_serialize_str(loaned, c"beta".as_ptr()), Z_OK);

            let mut bytes = std::mem::zeroed();
            ze_serializer_finish(
                &mut serializer as *mut _ as *mut ze_moved_serializer_t,
                &mut bytes,
            );

            // 1 (count) + 1+5 + 1+4 = 12 bytes, all length-prefixed.
            let buf = bytes_ref(crate::bytes::z_bytes_loan(&bytes)).expect("payload");
            assert_eq!(buf.len(), 12, "unexpected wire length: {buf:?}");

            let mut d = ze_deserializer_from_bytes(crate::bytes::z_bytes_loan(&bytes));
            let mut count = 0usize;
            assert_eq!(
                ze_deserializer_deserialize_sequence_length(&mut d, &mut count),
                Z_OK
            );
            assert_eq!(count, 2);
            for expected in ["alpha", "beta"] {
                let mut s = std::mem::zeroed();
                assert_eq!(ze_deserializer_deserialize_string(&mut d, &mut s), Z_OK);
                let ls = crate::bytes::z_string_loan(&s);
                let data = crate::bytes::z_string_data(ls);
                let len = crate::bytes::z_string_len(ls);
                let got = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len))
                    .unwrap();
                assert_eq!(got, expected);
            }
            assert!(
                ze_deserializer_is_done(&d),
                "the reader must land exactly at the end"
            );
        }
    }

    /// A truncated record does NOT advance the reader — pico reports the error
    /// and leaves the position, so a retry sees the same record.
    #[test]
    fn a_truncated_record_leaves_the_reader_where_it_was() {
        unsafe {
            // `<len=9>` followed by only 2 bytes.
            let mut bytes = std::mem::zeroed();
            store_owned_bytes(&mut bytes, ByteBuf::from(vec![9u8, 0xAA, 0xBB]));
            let mut d = ze_deserializer_from_bytes(crate::bytes::z_bytes_loan(&bytes));
            let before = d._reader.pos;
            let mut s = std::mem::zeroed();
            assert_ne!(
                ze_deserializer_deserialize_string(&mut d, &mut s),
                Z_OK,
                "a short record must be an error"
            );
            assert_eq!(d._reader.pos, before, "the reader must not have advanced");
        }
    }

    /// The arithmetic pair is FIXED-WIDTH LITTLE-ENDIAN, and the deserialize
    /// half rejects a payload that is not exactly the type's width.
    #[test]
    fn arithmetic_is_fixed_width_little_endian() {
        unsafe {
            let mut bytes = std::mem::zeroed();
            assert_eq!(ze_serialize_uint32(&mut bytes, 0x0403_0201), Z_OK);
            let buf = bytes_ref(crate::bytes::z_bytes_loan(&bytes)).expect("payload");
            assert_eq!(
                buf.as_slice(),
                &[0x01, 0x02, 0x03, 0x04],
                "uint32 must be 4 raw LE bytes, not a VLE"
            );

            let mut out = 0u32;
            assert_eq!(
                ze_deserialize_uint32(crate::bytes::z_bytes_loan(&bytes), &mut out),
                Z_OK
            );
            assert_eq!(out, 0x0403_0201);

            let mut longer = std::mem::zeroed();
            store_owned_bytes(&mut longer, ByteBuf::from(vec![1u8, 2, 3, 4, 5]));
            assert_ne!(
                ze_deserialize_uint32(crate::bytes::z_bytes_loan(&longer), &mut out),
                Z_OK,
                "a payload longer than the type must be rejected, not truncated"
            );
        }
    }
}
