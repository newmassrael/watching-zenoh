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

        // The two constructors are generated for the LOANED type as well as the
        // owned one. Not symmetry for its own sake: a borrowed view minted by a
        // marshal (`z_sample_payload`, `z_sample_keyexpr`) is a loaned value that
        // has to be BUILT, and the alternative is hand-writing the same two
        // functions per type with the pad arithmetic re-derived each time — the
        // shape a const assertion catches only after someone gets it wrong.
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

        impl $Loaned {
            /// The gravestone value: a null handle and zeroed padding.
            #[inline]
            #[allow(dead_code)]
            pub(crate) fn null_value() -> Self {
                Self {
                    handle: std::ptr::null_mut(),
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }

            /// Borrow whatever lives behind `handle` — the pointee's lifetime is
            /// the caller's obligation.
            #[inline]
            #[allow(dead_code)]
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
// The subscriber family — 48 bytes at align 8, and `z_sub.c` stack-allocates
// the owned one, so this is a size the C side genuinely depends on. Unlike
// `z_owned_bytes_t` it does NOT move with `Z_FEATURE_UNSTABLE_API` (measured on
// both oracle builds), so there is one arm rather than two.
define_opaque!(
    z_owned_subscriber_t,
    z_loaned_subscriber_t,
    z_moved_subscriber_t,
    48
);

/// The borrowed sample a subscriber callback receives.
///
/// A zero-sized TAG rather than a `define_opaque!` family, and the difference is
/// load-bearing: the C side never stack-allocates a `z_loaned_sample_t` — it only
/// ever receives a `z_loaned_sample_t*` from the callback and hands it back to the
/// accessors. So wz points that pointer straight at its own
/// [`SampleMarshal`](crate::sample::SampleMarshal) and the accessors cast back,
/// which keeps the marshal's fields directly reachable instead of hidden behind a
/// handle slot the C side would then be free to mis-size.
///
/// `z_owned_sample_t` (184 bytes, and genuinely stack-allocated by
/// `z_storage.c` / the reply plane) is deliberately NOT defined in this slice —
/// it arrives with the family that produces one.
#[repr(C)]
pub struct z_loaned_sample_t {
    _opaque: [u8; 0],
}

/// zenoh-c's `z_sample_kind_t` (`zenoh_commons.h:200-209`): how the sample was
/// issued. A C enum with two values, so it occupies a `c_int`-sized 4 bytes —
/// checked below rather than assumed.
pub type z_sample_kind_t = std::ffi::c_int;
/// `Z_SAMPLE_KIND_PUT` = 0.
pub const Z_SAMPLE_KIND_PUT: z_sample_kind_t = 0;
/// `Z_SAMPLE_KIND_DELETE` = 1.
pub const Z_SAMPLE_KIND_DELETE: z_sample_kind_t = 1;

const _: () = {
    assert!(std::mem::size_of::<z_sample_kind_t>() == 4);
};

/// One string representation shared by all three of zenoh-c's string types.
///
/// `z_string_loan` and `z_view_string_loan` are both plain pointer casts
/// upstream — an owned string and a view string must therefore be READABLE as
/// the same loaned shape. Giving the three types one repr is what makes those
/// casts honest here instead of two layouts that happen to agree today.
///
/// `owned` is the freeing handle: non-null for `z_owned_string_t` (a leaked
/// `Box<Vec<u8>>`), null for a view, which borrows. That is the entire
/// difference between the two.
#[repr(C)]
pub struct StringRepr {
    pub(crate) ptr: *const u8,
    pub(crate) len: usize,
    pub(crate) owned: Handle,
    pub(crate) _pad: usize,
}

impl StringRepr {
    /// The gravestone: an empty, non-owning string.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            ptr: std::ptr::null(),
            len: 0,
            owned: std::ptr::null_mut(),
            _pad: 0,
        }
    }
}

/// Owned string (zenoh-c `z_owned_string_t`) — frees its buffer on drop.
pub type z_owned_string_t = StringRepr;
/// Loaned string (zenoh-c `z_loaned_string_t`) — what both loan casts produce.
pub type z_loaned_string_t = StringRepr;
/// Borrowed string view (zenoh-c `z_view_string_t`) — never frees.
pub type z_view_string_t = StringRepr;

/// Moved string (zenoh-c `z_moved_string_t`).
#[repr(C)]
pub struct z_moved_string_t {
    pub(crate) _this: z_owned_string_t,
}

const _: () = {
    assert!(std::mem::size_of::<StringRepr>() == 32);
    assert!(std::mem::align_of::<StringRepr>() == 8);
    assert!(std::mem::size_of::<z_moved_string_t>() == 32);
};

/// The C callback a sample closure carries (`zenoh_commons.h:583`).
///
/// Nullable, because zenoh-c's gravestone closure has a null `_call` and calling
/// one is specified as a no-op.
pub type z_closure_sample_callback_t =
    Option<unsafe extern "C" fn(sample: *const z_loaned_sample_t, context: *mut c_void)>;

/// The C drop a closure carries (`zenoh_commons.h:584`). Also nullable.
pub type z_closure_drop_callback_t = Option<unsafe extern "C" fn(context: *mut c_void)>;

/// Owned sample closure (zenoh-c `z_owned_closure_sample_t`).
///
/// TRANSPARENT, not opaque, and that is upstream's choice rather than a
/// simplification here: `zenoh_commons.h:581-585` declares the three fields
/// inline because the C side constructs the value itself through the `z_closure`
/// macro. So this must match FIELD FOR FIELD, not merely in total size.
#[repr(C)]
pub struct z_owned_closure_sample_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_sample_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved sample closure (zenoh-c `z_moved_closure_sample_t`).
#[repr(C)]
pub struct z_moved_closure_sample_t {
    pub(crate) _this: z_owned_closure_sample_t,
}

impl z_owned_closure_sample_t {
    /// The gravestone: no context, no callbacks.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_closure_sample_t>() == 24);
    assert!(std::mem::align_of::<z_owned_closure_sample_t>() == 8);
    assert!(std::mem::size_of::<z_moved_closure_sample_t>() == 24);
};

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

impl z_loaned_keyexpr_t {
    /// The gravestone value.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 32 - std::mem::size_of::<Handle>()],
        }
    }

    /// Borrow the `KeyexprState` behind `handle` — its lifetime is the caller's
    /// obligation. This is how a `SampleMarshal` publishes the keyexpr it owns.
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
    /// `size_of::<z_owned_subscriber_t>()`.
    pub subscriber: usize,
    /// `size_of::<z_owned_string_t>()`.
    pub string: usize,
    /// `size_of::<z_owned_closure_sample_t>()`.
    pub closure_sample: usize,
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
            subscriber: std::mem::size_of::<z_owned_subscriber_t>(),
            string: std::mem::size_of::<z_owned_string_t>(),
            closure_sample: std::mem::size_of::<z_owned_closure_sample_t>(),
        };
    }
}
