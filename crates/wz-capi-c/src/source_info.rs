// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y563 — the zenoh-c `source_info` family: the owned/loaned/moved type
//! plus its seven functions, and the reason six option structs could not read
//! their `source_info` field until now.
//!
//! ## Why this is not the pico family under another name
//!
//! zenoh-pico's `z_source_info_t` is a PLAIN struct passed by pointer: a C
//! program declares one on its stack, `z_source_info_new` fills it in place,
//! and the option field is a borrow the callee reads and forgets. wz mirrored
//! that at R311y559 in twenty lines.
//!
//! zenoh-c's is an OWNED OPAQUE with a move semantics: `z_source_info_new`
//! constructs into a `z_owned_source_info_t`, the option field is a
//! `z_moved_source_info_t*` the callee CONSUMES, and reading it back needs a
//! `z_source_info_loan` to a distinct `z_loaned_source_info_t`. So the shape is
//! the whole owned family — `_new` / `_loan` / `_drop` / `_id` / `_sn` /
//! `z_internal_source_info_check` / `_null` — not a struct plus a getter, which
//! is why "mirror the pico work" understated it.
//!
//! ## The alignment, which is the one fact that shapes the type
//!
//! `z_owned_source_info_t` is `ALIGN(4) { uint8_t _0[32] }`
//! (`zenoh_opaque.h:588-590`), and the loaned form is identical (`:768-770`).
//! FOUR, not eight — every other opaque family in this crate is align 8, which
//! is why [`crate::abi`]'s `define_opaque!` hard-asserts that and cannot be
//! reused here.
//!
//! A Rust struct with a `*mut c_void` field is align 8 and `#[repr(align(4))]`
//! cannot lower that — alignment attributes only raise. So the handle is stored
//! as BYTES inside the blob and read back with `from_ne_bytes`, which is
//! unaligned-safe by construction. That is not a workaround for the compiler:
//! align 4 means a C program may legally place one of these at an address that
//! is 4- but not 8-aligned (inside a packed or 4-aligned aggregate), and a
//! pointer-typed field would then be an unaligned load that happens to work on
//! x86-64 and is undefined everywhere.

use std::ffi::c_void;

use wz_runtime_tokio::sample::SourceInfo;

use crate::advanced::z_entity_global_id_t;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ENULL, Z_OK};
use crate::zid::Z_ID_SIZE;

/// The C footprint of the whole family: 32 bytes at align 4.
const SOURCE_INFO_SIZE: usize = 32;

/// How many leading bytes of the blob hold our handle.
const HANDLE_BYTES: usize = std::mem::size_of::<usize>();

/// zenoh-c `z_owned_source_info_t` (`zenoh_opaque.h:588-590`) — 32 bytes at
/// ALIGNMENT 4.
///
/// The first [`HANDLE_BYTES`] carry a `Box<SourceInfo>` pointer as raw bytes
/// (see the module note on why not a pointer field); the rest is zero padding
/// to upstream's size. All-zero is the gravestone, which is what
/// `z_internal_source_info_null` writes and what `z_internal_source_info_check`
/// reports as absent.
#[repr(C, align(4))]
pub struct z_owned_source_info_t {
    pub(crate) _0: [u8; SOURCE_INFO_SIZE],
}

/// zenoh-c `z_loaned_source_info_t` (`zenoh_opaque.h:768-770`) — the same
/// layout, so `z_source_info_loan` is a pointer cast.
#[repr(C, align(4))]
pub struct z_loaned_source_info_t {
    pub(crate) _0: [u8; SOURCE_INFO_SIZE],
}

/// zenoh-c `z_moved_source_info_t` — literally
/// `struct { z_owned_source_info_t _this; }`.
#[repr(C)]
pub struct z_moved_source_info_t {
    pub(crate) _this: z_owned_source_info_t,
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_source_info_t>() == SOURCE_INFO_SIZE);
    assert!(std::mem::align_of::<z_owned_source_info_t>() == 4);
    assert!(std::mem::size_of::<z_loaned_source_info_t>() == SOURCE_INFO_SIZE);
    assert!(std::mem::align_of::<z_loaned_source_info_t>() == 4);
    // The moved wrapper is a newtype; it must not add a byte.
    assert!(std::mem::size_of::<z_moved_source_info_t>() == SOURCE_INFO_SIZE);
};

impl z_owned_source_info_t {
    /// The gravestone: all zero, which is upstream's own null representation
    /// and what a failed [`z_source_info_new`] leaves behind.
    pub(crate) fn null_value() -> Self {
        Self {
            _0: [0u8; SOURCE_INFO_SIZE],
        }
    }

    /// Pack a `Box::into_raw` pointer into the blob's leading bytes.
    pub(crate) fn from_boxed(info: Box<SourceInfo>) -> Self {
        let mut this = Self::null_value();
        let bits = Box::into_raw(info) as usize;
        this._0[..HANDLE_BYTES].copy_from_slice(&bits.to_ne_bytes());
        this
    }

    /// The handle, or `None` when this value is a gravestone.
    pub(crate) fn handle(&self) -> Option<*mut SourceInfo> {
        let mut bytes = [0u8; HANDLE_BYTES];
        bytes.copy_from_slice(&self._0[..HANDLE_BYTES]);
        let bits = usize::from_ne_bytes(bytes);
        if bits == 0 {
            None
        } else {
            Some(bits as *mut SourceInfo)
        }
    }
}

impl z_loaned_source_info_t {
    /// The gravestone: all zero.
    pub(crate) fn null_value() -> Self {
        Self {
            _0: [0u8; SOURCE_INFO_SIZE],
        }
    }

    /// A loaned view over a [`SourceInfo`] the CALLER owns — the sample
    /// marshal's own field, not a box.
    ///
    /// Sound because the loaned form is the only one a C program can obtain
    /// from a sample, and the two functions that would free the pointee
    /// (`z_source_info_drop` / [`take_moved_source_info`]) both take an OWNED
    /// value. There is no path from a loaned view to a `Box::from_raw`.
    pub(crate) fn from_borrowed(info: &SourceInfo) -> Self {
        let mut this = Self::null_value();
        let bits = info as *const SourceInfo as usize;
        this._0[..HANDLE_BYTES].copy_from_slice(&bits.to_ne_bytes());
        this
    }

    /// The handle behind a loaned view. Same slot as the owned form, because
    /// the two share a layout.
    pub(crate) fn handle(&self) -> Option<*mut SourceInfo> {
        let mut bytes = [0u8; HANDLE_BYTES];
        bytes.copy_from_slice(&self._0[..HANDLE_BYTES]);
        let bits = usize::from_ne_bytes(bytes);
        if bits == 0 {
            None
        } else {
            Some(bits as *mut SourceInfo)
        }
    }
}

/// Borrow the [`SourceInfo`] behind a loaned pointer.
///
/// # Safety
/// `this_` must be null or a live loaned source info.
pub(crate) unsafe fn loaned_ref<'a>(
    this_: *const z_loaned_source_info_t,
) -> Option<&'a SourceInfo> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle() }?;
    // SAFETY: the handle came from `Box::into_raw` in `z_source_info_new` and
    // is only freed by `z_source_info_drop`, which nulls the slot.
    Some(unsafe { &*handle })
}

/// R311y563 — CONSUME a caller's `z_moved_source_info_t*` option field into a wz
/// [`SourceInfo`].
///
/// The zenoh-c option fields are MOVED, not borrowed: upstream's
/// `z_put_options_t::source_info` is a `z_moved_source_info_t*` and the callee
/// takes ownership. So every fold must run this on EVERY path — including the
/// error ones — exactly as it already does for the moved payload / attachment,
/// or the caller's value leaks and its `z_owned_source_info_t` stays non-null,
/// which is worse than a leak because ownership becomes ambiguous.
///
/// A NULL pointer, a gravestone value, and an all-zero zid all read as absent.
/// The last of those matches zenoh's own `_z_source_info_check`, which is a
/// zero-zid test: an unset identity must not reach the wire as "a publisher
/// whose zid is 0".
///
/// # Safety
/// `moved` must be null or a valid moved source info.
pub(crate) unsafe fn take_moved_source_info(
    moved: *mut z_moved_source_info_t,
) -> Option<SourceInfo> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let owned = unsafe { &mut (*moved)._this };
    let handle = owned.handle();
    *owned = z_owned_source_info_t::null_value();
    let handle = handle?;
    // SAFETY: the handle came from `Box::into_raw`; taking it back here is the
    // move the C signature promises.
    let info = unsafe { Box::from_raw(handle) };
    if info.zid_prefix().iter().all(|b| *b == 0) {
        return None;
    }
    Some(*info)
}

/// Construct a source info (zenoh-c `z_source_info_new`,
/// `zenoh_commons.h:5213`).
///
/// # Safety
/// `this_` must be a valid, writable owned slot; `source_id` must be null or a
/// valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_new(
    this_: *mut z_owned_source_info_t,
    source_id: *const z_entity_global_id_t,
    source_sn: u32,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // Write the gravestone FIRST, so an early return still leaves the
        // caller's slot in a state `z_internal_source_info_check` can read.
        // SAFETY: checked non-null.
        unsafe { *this_ = z_owned_source_info_t::null_value() };
        if source_id.is_null() {
            return Z_ENULL;
        }
        // SAFETY: checked non-null.
        let gid = unsafe { &*source_id };
        let info = SourceInfo::new(&gid.zid.id, gid.eid, source_sn);
        // SAFETY: checked non-null.
        unsafe { *this_ = z_owned_source_info_t::from_boxed(Box::new(info)) };
        Z_OK
    })
}

/// Borrow a source info (zenoh-c `z_source_info_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_loan(
    this_: *const z_owned_source_info_t,
) -> *const z_loaned_source_info_t {
    this_ as *const z_loaned_source_info_t
}

/// The `(zid, eid)` half of a source info (zenoh-c `z_source_info_id`).
///
/// Returns the all-zero id for a gravestone, which is what upstream's own
/// accessor reports for one.
///
/// # Safety
/// `this_` must be null or a valid loaned source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_id(
    this_: *const z_loaned_source_info_t,
) -> z_entity_global_id_t {
    let empty = z_entity_global_id_t {
        zid: crate::zid::z_id_t {
            id: [0u8; Z_ID_SIZE],
        },
        eid: 0,
    };
    guard_val(empty, || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { loaned_ref(this_) } {
            Some(info) => {
                let mut zid = [0u8; Z_ID_SIZE];
                // The wire form strips trailing zeros; re-pad LEFT-aligned, the
                // same convention `z_timestamp_t::_id` follows.
                let prefix = info.zid_prefix();
                let n = prefix.len().min(Z_ID_SIZE);
                zid[..n].copy_from_slice(&prefix[..n]);
                z_entity_global_id_t {
                    zid: crate::zid::z_id_t { id: zid },
                    eid: info.eid,
                }
            }
            None => empty,
        }
    })
}

/// The sequence number of a source info (zenoh-c `z_source_info_sn`).
///
/// # Safety
/// `this_` must be null or a valid loaned source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_sn(this_: *const z_loaned_source_info_t) -> u32 {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { loaned_ref(this_) }.map_or(0, |info| info.sn)
    })
}

/// Free a source info and reset the source slot to a gravestone (zenoh-c
/// `z_source_info_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_drop(this_: *mut z_moved_source_info_t) {
    guarded(|| {
        // SAFETY: the caller's contract, delegated. `take_moved_source_info`
        // nulls the source and RECLAIMS THE BOX — that reclaim is the free, and
        // it happens inside the call rather than at this binding. `let _ =`
        // rather than `drop(..)`: the returned `SourceInfo` owns no heap of its
        // own, so clippy is right that dropping it does nothing, and writing
        // `drop` would suggest the free happens here when it does not.
        let _ = unsafe { take_moved_source_info(this_) };
        Z_OK
    });
}

/// Whether an owned source info holds a live value (zenoh-c
/// `z_internal_source_info_check`).
///
/// # Safety
/// `this_` must be null or a valid owned source info.
#[no_mangle]
pub unsafe extern "C" fn z_internal_source_info_check(this_: *const z_owned_source_info_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).handle() }.is_some()
    })
}

/// Zero an owned source info (zenoh-c `z_internal_source_info_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned source info.
#[no_mangle]
pub unsafe extern "C" fn z_internal_source_info_null(this_: *mut z_owned_source_info_t) {
    if !this_.is_null() {
        // SAFETY: checked non-null.
        unsafe { *this_ = z_owned_source_info_t::null_value() };
    }
}

/// A `*mut c_void` view of the moved pointer, for the option structs that
/// declared their field opaque before this family existed.
///
/// Not a compatibility shim: `z_put_options_t::source_info` and its five
/// siblings are typed `*mut z_moved_source_info_t` now. This exists because
/// `z_source_info_drop`'s `guarded` wrapper wants a `ZResult` and the cast is
/// clearer named than inline.
#[allow(dead_code)]
pub(crate) fn as_moved(ptr: *mut c_void) -> *mut z_moved_source_info_t {
    ptr as *mut z_moved_source_info_t
}
