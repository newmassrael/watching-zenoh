// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c owned / loaned / moved struct layouts, and the compile-time
//! assertions that pin them.
//!
//! ## Opaque blobs, which is what makes this tractable
//!
//! zenoh-c's owned types are `ALIGN(8)` structs wrapping a fixed-size
//! `uint8_t[N]` (`zenoh_opaque.h`) — the C side stack-allocates them and never
//! reads inside. A drop-in must therefore match the SIZE and ALIGNMENT exactly
//! and is otherwise free to lay out its own contents, which is why this file
//! stores a Rust handle in the leading pointer slot and zero-pads the rest.
//!
//! An ABI is not copyrightable expression, so reproducing the layout contract is
//! a clean-room reproduction, not a copy of zenoh-c's EPL/Apache sources.
//!
//! ## Why the numbers are ASSERTED here and MEASURED in the lane
//!
//! The sizes below are transcribed, and transcribed numbers rot: `zenoh_opaque.h`
//! is generated per zenoh-c version and per `Z_FEATURE_*` set, so a different
//! installation can legitimately disagree. The const assertions in this file
//! catch a mistake in THIS file. They cannot catch the header moving underneath —
//! only reading the installed header can, which is Layer C1bc's job (it compares
//! these numbers against `zenoh_opaque.h` and against `sizeof` as a C compiler
//! sees it, and fails loudly on drift).
//!
//! Two gates, because they answer different questions: "is this file
//! self-consistent" and "is this file still true of the ABI".
//!
//! ## The footprints are FEATURE-DEPENDENT, which was measured, not assumed
//!
//! zenoh-c's published standalone archive is built WITH `Z_FEATURE_UNSTABLE_API`;
//! a build without it is a different ABI, and not only in the option structs:
//!
//! | type (LP64)                        | unstable | no-unstable |
//! |------------------------------------|---------:|------------:|
//! | `z_owned_session_t` / `z_loaned_*` |        8 |           8 |
//! | `z_owned_bytes_t` / `z_loaned_*`   |   **40** |      **32** |
//! | `z_view_keyexpr_t` / `z_loaned_*`  |       32 |          32 |
//! | `z_owned_config_t` / `z_loaned_*`  |     1960 |        1960 |
//!
//! So "wz is a zenoh-c drop-in" is not a complete sentence — it has to name the
//! build. The DEFAULT here is the published archive's (unstable), because that is
//! what a consumer installs and what CI provisions; the
//! `zenoh-c-no-unstable-api` feature selects the other. Layer C1cc reads
//! `Z_FEATURE_UNSTABLE_API` out of the INSTALLED header and says which one this
//! cdylib was built for when they disagree.
//!
//! This was found by provisioning the release archive beside a hand-built local
//! install and measuring both — not by reading, which had produced the single
//! hardcoded 32 this table replaces.

use std::ffi::c_void;

/// A raw pointer used as an FFI handle slot. Null = "gravestone / not present",
/// which is zenoh-c's own word for a moved-from or failed-to-construct value.
pub(crate) type Handle = *mut c_void;

/// Declare one zenoh-c owned/loaned/moved family whose C footprint is `$size`
/// bytes at align 8.
///
/// The padding is expressed in `Handle`-sized units and checked against `$size`
/// by a const assertion, so a wrong pad count is a compile error rather than a
/// struct that merely looks right.
macro_rules! define_opaque {
    ($Owned:ident, $Loaned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Loaned view — the SAME layout, so `loan` is a pointer cast and the
        /// handle sits at offset 0 either way.
        #[repr(C)]
        pub struct $Loaned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Moved wrapper — zenoh-c's `z_moved_X_t` is literally
        /// `struct { z_owned_X_t _this; }`.
        #[repr(C)]
        pub struct $Moved {
            pub(crate) _this: $Owned,
        }

        impl $Owned {
            /// The gravestone value: a null handle and zeroed padding.
            #[inline]
            pub(crate) fn null_value() -> Self {
                Self {
                    handle: std::ptr::null_mut(),
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }

            /// Wrap a `Box::into_raw` pointer.
            #[inline]
            pub(crate) fn from_handle(handle: Handle) -> Self {
                Self {
                    handle,
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }
        }

        const _: () = {
            assert!(std::mem::size_of::<$Owned>() == $size);
            assert!(std::mem::align_of::<$Owned>() == 8);
            assert!(std::mem::size_of::<$Loaned>() == $size);
            assert!(std::mem::align_of::<$Loaned>() == 8);
            // The moved wrapper is a newtype, so it must not add a byte.
            assert!(std::mem::size_of::<$Moved>() == $size);
        };
    };
}

define_opaque!(z_owned_session_t, z_loaned_session_t, z_moved_session_t, 8);
// `z_owned_bytes_t` is 40 bytes in the published (unstable-API) build and 32
// without it — see the module table. The default matches the archive CI
// provisions. A `//` comment, not `///`: a doc comment on a macro INVOCATION
// documents nothing and is a hard error under `warnings = "deny"`.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
define_opaque!(z_owned_bytes_t, z_loaned_bytes_t, z_moved_bytes_t, 40);
#[cfg(feature = "zenoh-c-no-unstable-api")]
define_opaque!(z_owned_bytes_t, z_loaned_bytes_t, z_moved_bytes_t, 32);
define_opaque!(z_owned_config_t, z_loaned_config_t, z_moved_config_t, 1960);

/// The VIEW keyexpr — a borrowed keyexpr the C side stack-allocates.
///
/// A separate family from the owned one because zenoh-c names it separately and
/// `z_put.c` uses only this shape; the owned/moved keyexpr arrives with a later
/// slice.
#[repr(C)]
pub struct z_view_keyexpr_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; 32 - std::mem::size_of::<Handle>()],
}

/// The loaned keyexpr `z_view_keyexpr_loan` hands back.
#[repr(C)]
pub struct z_loaned_keyexpr_t {
    pub(crate) handle: Handle,
    pub(crate) _pad: [u8; 32 - std::mem::size_of::<Handle>()],
}

impl z_view_keyexpr_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 32 - std::mem::size_of::<Handle>()],
        }
    }

    #[inline]
    pub(crate) fn from_handle(handle: Handle) -> Self {
        Self {
            handle,
            _pad: [0u8; 32 - std::mem::size_of::<Handle>()],
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_view_keyexpr_t>() == 32);
    assert!(std::mem::align_of::<z_view_keyexpr_t>() == 8);
    assert!(std::mem::size_of::<z_loaned_keyexpr_t>() == 32);
    assert!(std::mem::align_of::<z_loaned_keyexpr_t>() == 8);
};

/// The layout numbers this build asserts, in a form a gate can READ back out of
/// the compiled cdylib rather than re-transcribing.
///
/// Exported because the alternative is a second hand-maintained copy of the
/// table in a test — the shape this project has repeatedly found drifts. The
/// lane reads these, reads `zenoh_opaque.h`, and compares; neither side is a
/// list someone remembered to update.
#[repr(C)]
pub struct wz_capi_c_layout_t {
    /// `size_of::<z_owned_session_t>()`.
    pub session: usize,
    /// `size_of::<z_owned_bytes_t>()`.
    pub bytes: usize,
    /// `size_of::<z_view_keyexpr_t>()`.
    pub keyexpr: usize,
    /// `size_of::<z_owned_config_t>()`.
    pub config: usize,
    /// The alignment every one of them shares.
    pub align: usize,
}

/// Report this build's owned-type footprints — the drop-in's half of the layout
/// gate.
///
/// # Safety
/// Writes five `usize`s through `out`, which must be a valid, aligned
/// `wz_capi_c_layout_t`. Null is ignored.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_layout(out: *mut wz_capi_c_layout_t) {
    if out.is_null() {
        return;
    }
    // SAFETY: the caller's contract — a valid, aligned out-param.
    unsafe {
        *out = wz_capi_c_layout_t {
            session: std::mem::size_of::<z_owned_session_t>(),
            bytes: std::mem::size_of::<z_owned_bytes_t>(),
            keyexpr: std::mem::size_of::<z_view_keyexpr_t>(),
            config: std::mem::size_of::<z_owned_config_t>(),
            align: std::mem::align_of::<z_owned_session_t>(),
        };
    }
}
