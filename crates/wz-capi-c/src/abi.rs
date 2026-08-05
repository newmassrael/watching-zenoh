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
//! ## The footprints are FEATURE-DEPENDENT — and R311y540 MEASURED which ones
//!
//! This section said, from R311y498 until R311y540, that zenoh-c's published
//! standalone archive is built WITH `Z_FEATURE_UNSTABLE_API` and that
//! `z_owned_bytes_t` is 40 bytes there against 32 without. **Both halves were
//! wrong**, and the way they were wrong is instructive: the OBSERVATION (two
//! builds exist, and their type sizes differ) was right, while the ATTRIBUTION
//! (which build is which, and which type moves) was not — the failure mode this
//! project has hit repeatedly.
//!
//! What is true, measured by running UPSTREAM'S OWN opaque-type generator
//! (`build-resources/opaque-types`, which emits `type: X, align: N, size: M` as
//! compilation errors) under zenoh-c's PINNED toolchain and the exact feature
//! list the archive's `zenoh_configure.h` declares:
//!
//! - The published archive is the **no-unstable** build. Its
//!   `zenoh_configure.h` has no `Z_FEATURE_UNSTABLE_API` line at all, and
//!   `install-zenoh-c.sh` installs that archive — so the arm CI provisions is
//!   the one the `zenoh-c-no-unstable-api` feature selects, NOT the default.
//! - `z_owned_bytes_t` is **32 on BOTH arms**. There is no 40-byte
//!   `z_owned_bytes_t` at zenoh-c 1.5.0 under either arm.
//! - Exactly **four** opaque types move with `Z_FEATURE_UNSTABLE_API`:
//!
//! | type (LP64)                          | no-unstable | unstable |
//! |--------------------------------------|------------:|---------:|
//! | `z_owned_sample_t` / `z_loaned_*`    |         184 |  **216** |
//! | `z_owned_reply_t` / `z_loaned_*`     |         184 |  **240** |
//!
//! The generator is a VALIDATED oracle rather than an assumed one: its
//! no-unstable arm reproduces the installed `zenoh_opaque.h` on **62 of 62**
//! types. Getting there took removing two variables — the exact feature list
//! (which turned out not to matter: `zenoh/default` and the archive's list give
//! identical tables) and the TOOLCHAIN (which did: `z_owned_task_t` is 32 under
//! the pinned 1.85.0 and 24 under 1.97.0, and that single disagreement was the
//! whole gap).
//!
//! So "wz is a zenoh-c drop-in" is still not a complete sentence — it has to
//! name the build — but the sentence now names the right builds. Layer C1cc
//! reads `Z_FEATURE_UNSTABLE_API` out of the INSTALLED header and selects the
//! matching cdylib arm, which means the arm the installed oracle is NOT gets
//! measured by nothing. That is why `scripts/check-capi-c-opaque-arms.sh`
//! exists: it drives upstream's generator for BOTH arms and compares each
//! against a cdylib built for it.

use std::ffi::c_void;

/// `true` when this build targets a zenoh-c compiled WITH
/// `Z_FEATURE_UNSTABLE_API`. That is the DEFAULT arm; the
/// `zenoh-c-no-unstable-api` feature selects the other.
const UNSTABLE: bool = !cfg!(feature = "zenoh-c-no-unstable-api");
/// `true` when this build targets a zenoh-c compiled WITH
/// `Z_FEATURE_SHARED_MEMORY`. OFF by default, because the published archive
/// (what `install-zenoh-c.sh` provisions) is built without it.
const SHM: bool = cfg!(feature = "zenoh-c-shared-memory");

// The eight sizes that MOVE across the two-axis feature space, written as
// explicit measured constants rather than arithmetic on a base. Every number
// below came out of upstream's own opaque-type generator under zenoh-c's pinned
// toolchain (R311y540); `scripts/check-capi-c-opaque-arms.sh` re-measures them.
//
// The two axes are INDEPENDENT and their deltas ADD — `z_owned_sample_t` is 184
// plain, +16 for shared-memory, +32 for unstable and +48 for both — but the
// deltas are per-type (8 for most, 16 for sample and reply), so expressing them
// as one shared constant would be a coincidence waiting to break.
const BYTES_SIZE: usize = if SHM { 40 } else { 32 };
const PUBLISHER_SIZE: usize = if SHM { 112 } else { 104 };
pub(crate) const ENCODING_SIZE: usize = if SHM { 48 } else { 40 };
const QUERY_SIZE: usize = if SHM { 144 } else { 136 };
const BYTES_WRITER_SIZE: usize = if SHM { 64 } else { 56 };
const SERIALIZER_SIZE: usize = BYTES_WRITER_SIZE;
const SAMPLE_SIZE: usize = 184 + if SHM { 16 } else { 0 } + if UNSTABLE { 32 } else { 0 };
const REPLY_SIZE: usize = 184 + if SHM { 16 } else { 0 } + if UNSTABLE { 56 } else { 0 };

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
            ///
            /// `allow(dead_code)`: some families are RECEIVE-ONLY in this ABI —
            /// `z_owned_hello_t` is one, because upstream only ever hands a
            /// hello to a callback and this slice ships no hello channel to
            /// escape one into. The type still has to exist (a C program may
            /// declare and null one), and its `null_value` stays checked.
            #[inline]
            #[allow(dead_code)]
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

/// Declare only the OWNED + MOVED half of a family, for the types whose loaned
/// form is a zero-sized TAG rather than a stack-allocatable struct.
///
/// `z_owned_sample_t` / `z_owned_query_t` / `z_owned_reply_t` are all
/// stack-allocated by the C side, so their SIZE is ABI — but the matching
/// `z_loaned_*` is only ever seen as a pointer, and this crate aims that pointer
/// straight at its own marshal (see [`z_loaned_sample_t`]). Emitting a loaned
/// blob for them too would define a type nothing constructs.
macro_rules! define_opaque_owned {
    ($Owned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
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
            assert!(std::mem::size_of::<$Moved>() == $size);
        };
    };
}

define_opaque!(z_owned_session_t, z_loaned_session_t, z_moved_session_t, 8);
// `z_owned_bytes_t` moves with SHARED-MEMORY, not with unstable — 32 without,
// 40 with, on both unstable arms. The 40 the two-arm split here used to
// attribute to `Z_FEATURE_UNSTABLE_API` was real; it was the SHM number. A `//`
// comment, not `///`: a doc comment on a macro INVOCATION documents nothing and
// is a hard error under `warnings = "deny"`.
define_opaque!(
    z_owned_bytes_t,
    z_loaned_bytes_t,
    z_moved_bytes_t,
    BYTES_SIZE
);
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
// The liveliness token family — 16 bytes at align 8 (`zenoh_opaque.h:345-347`),
// and `z_liveliness.c` stack-allocates the owned one.
define_opaque!(
    z_owned_liveliness_token_t,
    z_loaned_liveliness_token_t,
    z_moved_liveliness_token_t,
    16
);
// The encoding family — 40 bytes at align 8 (`zenoh_opaque.h:232-234`).
// `z_pub.c` stack-allocates the owned one to hold a clone of a constant.
define_opaque!(
    z_owned_encoding_t,
    z_loaned_encoding_t,
    z_moved_encoding_t,
    ENCODING_SIZE
);
// The publisher family — 104 bytes at align 8 (`zenoh_opaque.h:226-228`).
// `z_pub.c` / `z_pong.c` / `z_pub_thr.c` all stack-allocate the owned one, so
// this is the largest size the C side depends on outside the config.
define_opaque!(
    z_owned_publisher_t,
    z_loaned_publisher_t,
    z_moved_publisher_t,
    PUBLISHER_SIZE
);

// --- the planes R311y539 adds -----------------------------------------------
//
// Sizes MEASURED against this installation's `zenoh_opaque.h` by a C compiler
// (the layout gate re-measures every one of them on every run). The
// `Z_FEATURE_UNSTABLE_API` arm is NOT split for any of these: only one oracle
// build exists on this machine, so a second arm would be a TRANSCRIBED number
// with nothing to check it — the failure mode this file's own header warns
// about. See the crate's residual list.

// The owned sample — one of the FOUR types that move with
// `Z_FEATURE_UNSTABLE_API` (184 without, 216 with; measured R311y540). Its
// handle points at a heap `SampleMarshal`, which is the SAME type the borrowed
// `z_loaned_sample_t` aims at, so every existing sample accessor serves the
// owned form with no second path. `z_pull.c` / `z_storage.c` stack-allocate it,
// so the size is a size the C side genuinely depends on.
define_opaque_owned!(z_owned_sample_t, z_moved_sample_t, SAMPLE_SIZE);
// The queryable family — 48 bytes; `z_queryable.c` stack-allocates the owned one.
define_opaque!(
    z_owned_queryable_t,
    z_loaned_queryable_t,
    z_moved_queryable_t,
    48
);
// The querier family — 80 bytes; `z_querier.c` stack-allocates the owned one.
define_opaque!(z_owned_querier_t, z_loaned_querier_t, z_moved_querier_t, 80);
// The owned query — 136 bytes; `z_queryable_with_channels.c` stack-allocates it
// to receive an ESCAPED query off its fifo.
define_opaque_owned!(z_owned_query_t, z_moved_query_t, QUERY_SIZE);
// The owned reply — the other moving pair (184 without `Z_FEATURE_UNSTABLE_API`,
// 240 with). Every channel-based get stack-allocates it.
define_opaque_owned!(z_owned_reply_t, z_moved_reply_t, REPLY_SIZE);
// The reply ERROR is BORROW-ONLY here: `z_reply_err` hands back a pointer into
// the reply's own marshal, so there is no owned form to construct and none is
// declared. Upstream's `z_owned_reply_err_t` (72 bytes) arrives with the family
// that produces one — a reply-error channel, which no example in the corpus
// uses.
// The hello family — 48 bytes; `z_scout.c` never stack-allocates one (the
// callback receives a pointer), but the owned form is what a hello channel
// would hand back and the size is measured either way.
define_opaque!(z_owned_hello_t, z_loaned_hello_t, z_moved_hello_t, 48);
// The string-array family — 24 bytes; `z_scout.c` stack-allocates the owned one
// for `z_hello_locators`.
define_opaque!(
    z_owned_string_array_t,
    z_loaned_string_array_t,
    z_moved_string_array_t,
    24
);
// The bytes WRITER — 56 bytes; `z_bytes.c` stack-allocates the owned one.
define_opaque!(
    z_owned_bytes_writer_t,
    z_loaned_bytes_writer_t,
    z_moved_bytes_writer_t,
    BYTES_WRITER_SIZE
);
// The SERIALIZER — 56 bytes, and the same handle representation as the writer.
// That is an ABI fact rather than a convenience: upstream's serializer wraps a
// writer at offset 0, so a program is free to hand one to the other's
// functions.
define_opaque!(
    ze_owned_serializer_t,
    ze_loaned_serializer_t,
    ze_moved_serializer_t,
    SERIALIZER_SIZE
);
// The three CHANNEL handlers — 8 bytes each, a bare handle with no padding.
define_opaque!(
    z_owned_fifo_handler_reply_t,
    z_loaned_fifo_handler_reply_t,
    z_moved_fifo_handler_reply_t,
    8
);
define_opaque!(
    z_owned_fifo_handler_query_t,
    z_loaned_fifo_handler_query_t,
    z_moved_fifo_handler_query_t,
    8
);
define_opaque!(
    z_owned_ring_handler_sample_t,
    z_loaned_ring_handler_sample_t,
    z_moved_ring_handler_sample_t,
    8
);
// The MUTEX family — 24 bytes at align 8; `z_ping.c` / `z_storage.c`
// stack-allocate the owned one.
define_opaque!(z_owned_mutex_t, z_loaned_mutex_t, z_moved_mutex_t, 24);

/// The CONDVAR, which is the one type here that cannot hold a pointer.
///
/// `z_owned_condvar_t` is 8 bytes at align **4** and `z_loaned_condvar_t` is
/// **4** — measured, and the loaned one is the constraint: a pointer does not
/// fit in it at all, so the handle-in-slot-0 shape every other family uses is
/// structurally unavailable. A `u32` key into a process-wide registry is what
/// remains, and `z_condvar_loan` is still a plain cast because the key sits at
/// offset 0 of both.
#[repr(C)]
pub struct z_owned_condvar_t {
    pub(crate) key: u32,
    pub(crate) _pad: u32,
}

/// The 4-byte borrowed condvar (`z_loaned_condvar_t`).
#[repr(C)]
pub struct z_loaned_condvar_t {
    pub(crate) key: u32,
}

/// Moved condvar (`z_moved_condvar_t`).
#[repr(C)]
pub struct z_moved_condvar_t {
    pub(crate) _this: z_owned_condvar_t,
}

impl z_owned_condvar_t {
    /// The gravestone: key 0, which the registry never issues.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self { key: 0, _pad: 0 }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_condvar_t>() == 8);
    assert!(std::mem::align_of::<z_owned_condvar_t>() == 4);
    assert!(std::mem::size_of::<z_loaned_condvar_t>() == 4);
    assert!(std::mem::align_of::<z_loaned_condvar_t>() == 4);
    assert!(std::mem::size_of::<z_moved_condvar_t>() == 8);
};

/// One slice representation shared by all three of zenoh-c's slice types, for
/// exactly the reason [`StringRepr`] is shared by the string ones: both loans
/// are pointer casts upstream, so an owned slice and a view slice must be
/// READABLE as the same loaned shape.
///
/// `owned` is the freeing handle — a leaked `Box<Vec<u8>>` for
/// `z_owned_slice_t`, null for a view.
#[repr(C)]
pub struct SliceRepr {
    pub(crate) ptr: *const u8,
    pub(crate) len: usize,
    pub(crate) owned: Handle,
    pub(crate) _pad: usize,
}

impl SliceRepr {
    /// The gravestone: an empty, non-owning slice.
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

/// Owned slice (zenoh-c `z_owned_slice_t`) — frees its buffer on drop.
pub type z_owned_slice_t = SliceRepr;
/// Loaned slice (zenoh-c `z_loaned_slice_t`) — what both loan casts produce.
pub type z_loaned_slice_t = SliceRepr;
/// Borrowed slice view (zenoh-c `z_view_slice_t`) — never frees.
pub type z_view_slice_t = SliceRepr;

/// Moved slice (zenoh-c `z_moved_slice_t`).
#[repr(C)]
pub struct z_moved_slice_t {
    pub(crate) _this: z_owned_slice_t,
}

const _: () = {
    assert!(std::mem::size_of::<SliceRepr>() == 32);
    assert!(std::mem::align_of::<SliceRepr>() == 8);
    assert!(std::mem::size_of::<z_moved_slice_t>() == 32);
};

/// The borrowed query a queryable callback receives.
///
/// A zero-sized TAG, for the same reason [`z_loaned_sample_t`] is: the C side
/// never stack-allocates one — it receives a `z_loaned_query_t*` and hands it
/// back to the accessors — so the pointer aims straight at wz's own
/// [`QueryMarshal`](crate::query::QueryMarshal). The 136-byte `z_owned_query_t`
/// above is the type that IS stack-allocated, and it carries a handle to the
/// same marshal.
#[repr(C)]
pub struct z_loaned_query_t {
    _opaque: [u8; 0],
}

/// The borrowed reply a get callback receives — the same tag shape, for the
/// same reason.
#[repr(C)]
pub struct z_loaned_reply_t {
    _opaque: [u8; 0],
}

/// The borrowed reply ERROR `z_reply_err` hands back.
#[repr(C)]
pub struct z_loaned_reply_err_t {
    _opaque: [u8; 0],
}

/// The C callback a QUERY closure carries (`zenoh_commons.h:551`).
pub type z_closure_query_callback_t =
    Option<unsafe extern "C" fn(query: *mut z_loaned_query_t, context: *mut c_void)>;

/// Owned query closure (zenoh-c `z_owned_closure_query_t`) — TRANSPARENT
/// upstream, so it matches field for field.
#[repr(C)]
pub struct z_owned_closure_query_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_query_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved query closure (zenoh-c `z_moved_closure_query_t`).
#[repr(C)]
pub struct z_moved_closure_query_t {
    pub(crate) _this: z_owned_closure_query_t,
}

impl z_owned_closure_query_t {
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

/// The C callback a REPLY closure carries (`zenoh_commons.h:567`).
pub type z_closure_reply_callback_t =
    Option<unsafe extern "C" fn(reply: *mut z_loaned_reply_t, context: *mut c_void)>;

/// Owned reply closure (zenoh-c `z_owned_closure_reply_t`), transparent.
#[repr(C)]
pub struct z_owned_closure_reply_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_reply_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved reply closure (zenoh-c `z_moved_closure_reply_t`).
#[repr(C)]
pub struct z_moved_closure_reply_t {
    pub(crate) _this: z_owned_closure_reply_t,
}

impl z_owned_closure_reply_t {
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

/// The C callback a HELLO closure carries (`zenoh_commons.h:499`).
pub type z_closure_hello_callback_t =
    Option<unsafe extern "C" fn(hello: *mut z_loaned_hello_t, context: *mut c_void)>;

/// Owned hello closure (zenoh-c `z_owned_closure_hello_t`), transparent.
#[repr(C)]
pub struct z_owned_closure_hello_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_hello_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved hello closure (zenoh-c `z_moved_closure_hello_t`).
#[repr(C)]
pub struct z_moved_closure_hello_t {
    pub(crate) _this: z_owned_closure_hello_t,
}

impl z_owned_closure_hello_t {
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
    assert!(std::mem::size_of::<z_owned_closure_query_t>() == 24);
    assert!(std::mem::size_of::<z_owned_closure_reply_t>() == 24);
    assert!(std::mem::size_of::<z_owned_closure_hello_t>() == 24);
    assert!(std::mem::align_of::<z_owned_closure_query_t>() == 8);
};

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
/// [`z_owned_sample_t`] (184 bytes, genuinely stack-allocated by `z_pull.c` and
/// `z_storage.c`) is defined above and stores a handle to a HEAP marshal of the
/// same type — so a loan is `handle as *const z_loaned_sample_t` and every
/// accessor below serves both forms unchanged.
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
/// ## Why an ARRAY and not a struct (changed R311y539)
///
/// Until R311y539 this was a `#[repr(C)]` struct the test declared a parallel
/// copy of. That shape has a failure mode the comment on the test itself named:
/// the cdylib writes through the caller's pointer, so a test copy NARROWER than
/// the exported struct is a stack overwrite in the test process — silent, and
/// worse than the drift it stands in for. Widening the table by twenty-odd
/// entries in one round makes that a question of when, not whether.
///
/// The array form removes the hazard structurally. The caller says how many
/// slots it has; this writes at most that many and returns the TRUE count, so a
/// width disagreement surfaces as an assertion on a returned integer instead of
/// as memory corruption. The names live in [`WZ_CAPI_C_LAYOUT_NAMES`] and are
/// read out of the same artifact, so the gate never re-transcribes them either.
/// ## Why the table SPLITS in two (R311y543)
///
/// `WZ_CAPI_C_LAYOUT_NAMES_BASE` is what every arm has. The `ze_advanced_*`
/// plane is `#if defined(Z_FEATURE_UNSTABLE_API)` in upstream's header, so on a
/// no-unstable build those types do not exist to compare against — putting them
/// in one flat table would make the gate assert a size against a header that
/// declares nothing of the name. The split lets the C probe append exactly the
/// same half when (and only when) the oracle's `zenoh_configure.h` defines the
/// feature, which is the condition the cdylib arm is chosen by anyway.
pub const WZ_CAPI_C_LAYOUT_NAMES_BASE: &[&str] = &[
    "z_owned_session_t",
    "z_owned_bytes_t",
    "z_view_keyexpr_t",
    "z_owned_config_t",
    "align",
    "z_owned_subscriber_t",
    "z_owned_string_t",
    "z_owned_closure_sample_t",
    "z_owned_liveliness_token_t",
    "z_owned_publisher_t",
    "z_publisher_options_t",
    "z_publisher_put_options_t",
    "z_owned_encoding_t",
    "z_owned_closure_zid_t",
    "z_owned_closure_matching_status_t",
    "z_id_t",
    "z_id_t/align",
    "z_clock_t",
    "z_liveliness_subscriber_options_t",
    "z_matching_status_t",
    // R311y539 — the query / reply / channel / sync / serialization planes.
    "z_owned_sample_t",
    "z_owned_queryable_t",
    "z_owned_querier_t",
    "z_owned_query_t",
    "z_owned_reply_t",
    "z_owned_hello_t",
    "z_owned_string_array_t",
    "z_owned_bytes_writer_t",
    "ze_owned_serializer_t",
    "z_owned_fifo_handler_reply_t",
    "z_owned_fifo_handler_query_t",
    "z_owned_ring_handler_sample_t",
    "z_owned_mutex_t",
    "z_owned_condvar_t",
    "z_owned_condvar_t/align",
    "z_loaned_condvar_t",
    "z_loaned_condvar_t/align",
    "z_owned_slice_t",
    "z_owned_closure_query_t",
    "z_owned_closure_reply_t",
    "z_owned_closure_hello_t",
    "z_bytes_reader_t",
    "z_bytes_slice_iterator_t",
    "ze_deserializer_t",
    "z_get_options_t",
    "z_queryable_options_t",
    "z_query_reply_options_t",
    "z_liveliness_get_options_t",
    "z_querier_options_t",
    "z_querier_get_options_t",
    "z_scout_options_t",
    // R311y543 — the base subscriber options. NOT unstable-gated in upstream's
    // header (present on both installed oracles), and it is the struct
    // `ze_advanced_subscriber_options_t` embeds at offset 0.
    "z_subscriber_options_t",
    // R311y545 — the SESSION-level put / delete options. Newly DECLARED this
    // round (both entry points took `void*` before), and both are transparent
    // and stack-allocated by the C side, so they belong to this gate for the
    // same reason `z_publisher_options_t` does.
    "z_put_options_t",
    "z_delete_options_t",
];

/// The `Z_FEATURE_UNSTABLE_API`-only half of the table — the `ze_advanced_*`
/// plane [`crate::advanced`] declares. Empty on the no-unstable arm, where
/// upstream declares none of these types.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const WZ_CAPI_C_LAYOUT_NAMES_UNSTABLE: &[&str] = &[
    "z_entity_global_id_t",
    // The ALIGNMENT is the tell for this one — 4, not 8 — so it is pinned
    // beside the size rather than left to be implied by it.
    "z_entity_global_id_t/align",
    "ze_miss_t",
    "ze_owned_closure_miss_t",
    "ze_owned_advanced_publisher_t",
    "ze_owned_advanced_subscriber_t",
    "ze_owned_sample_miss_listener_t",
    "ze_advanced_publisher_cache_options_t",
    "ze_advanced_publisher_sample_miss_detection_options_t",
    "ze_advanced_publisher_options_t",
    "ze_advanced_publisher_put_options_t",
    "ze_advanced_subscriber_history_options_t",
    "ze_advanced_subscriber_last_sample_miss_detection_options_t",
    "ze_advanced_subscriber_recovery_options_t",
    "ze_advanced_subscriber_options_t",
];

/// The no-unstable arm's unstable half: empty, because upstream's header
/// declares none of those types there.
#[cfg(feature = "zenoh-c-no-unstable-api")]
pub const WZ_CAPI_C_LAYOUT_NAMES_UNSTABLE: &[&str] = &[];

/// The `Z_FEATURE_SHARED_MEMORY` **and** `Z_FEATURE_UNSTABLE_API` half — the
/// provider / buffer plane [`crate::shm`] declares. Upstream gates every one of
/// these on BOTH features together, so this is a third half rather than a
/// second axis folded into the unstable one.
#[cfg(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
))]
pub const WZ_CAPI_C_LAYOUT_NAMES_SHM: &[&str] = &[
    "z_owned_shm_t",
    "z_owned_shm_mut_t",
    "z_owned_shm_provider_t",
    "z_alloc_alignment_t",
    "z_buf_layout_alloc_result_t",
    "z_buf_alloc_result_t",
];

/// Empty on every arm whose header declares no SHM plane.
#[cfg(not(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
)))]
pub const WZ_CAPI_C_LAYOUT_NAMES_SHM: &[&str] = &[];

/// The full name table for THIS build: base half, then unstable, then SHM.
pub fn layout_names() -> Vec<&'static str> {
    WZ_CAPI_C_LAYOUT_NAMES_BASE
        .iter()
        .chain(WZ_CAPI_C_LAYOUT_NAMES_UNSTABLE.iter())
        .chain(WZ_CAPI_C_LAYOUT_NAMES_SHM.iter())
        .copied()
        .collect()
}

/// This build's footprint table, in [`layout_names`] order.
fn layout_values() -> Vec<usize> {
    use std::mem::{align_of, size_of};
    #[allow(unused_mut)]
    let mut values: Vec<usize> = vec![
        size_of::<z_owned_session_t>(),
        size_of::<z_owned_bytes_t>(),
        size_of::<z_view_keyexpr_t>(),
        size_of::<z_owned_config_t>(),
        align_of::<z_owned_session_t>(),
        size_of::<z_owned_subscriber_t>(),
        size_of::<z_owned_string_t>(),
        size_of::<z_owned_closure_sample_t>(),
        size_of::<z_owned_liveliness_token_t>(),
        size_of::<z_owned_publisher_t>(),
        size_of::<crate::publisher::z_publisher_options_t>(),
        size_of::<crate::publisher::z_publisher_put_options_t>(),
        size_of::<z_owned_encoding_t>(),
        size_of::<crate::zid::z_owned_closure_zid_t>(),
        size_of::<crate::matching::z_owned_closure_matching_status_t>(),
        size_of::<crate::zid::z_id_t>(),
        align_of::<crate::zid::z_id_t>(),
        size_of::<crate::platform::z_clock_t>(),
        size_of::<crate::liveliness::z_liveliness_subscriber_options_t>(),
        size_of::<crate::matching::z_matching_status_t>(),
        size_of::<z_owned_sample_t>(),
        size_of::<z_owned_queryable_t>(),
        size_of::<z_owned_querier_t>(),
        size_of::<z_owned_query_t>(),
        size_of::<z_owned_reply_t>(),
        size_of::<z_owned_hello_t>(),
        size_of::<z_owned_string_array_t>(),
        size_of::<z_owned_bytes_writer_t>(),
        size_of::<ze_owned_serializer_t>(),
        size_of::<z_owned_fifo_handler_reply_t>(),
        size_of::<z_owned_fifo_handler_query_t>(),
        size_of::<z_owned_ring_handler_sample_t>(),
        size_of::<z_owned_mutex_t>(),
        size_of::<z_owned_condvar_t>(),
        align_of::<z_owned_condvar_t>(),
        size_of::<z_loaned_condvar_t>(),
        align_of::<z_loaned_condvar_t>(),
        size_of::<z_owned_slice_t>(),
        size_of::<z_owned_closure_query_t>(),
        size_of::<z_owned_closure_reply_t>(),
        size_of::<z_owned_closure_hello_t>(),
        size_of::<crate::bytes::z_bytes_reader_t>(),
        size_of::<crate::bytes::z_bytes_slice_iterator_t>(),
        size_of::<crate::serde::ze_deserializer_t>(),
        size_of::<crate::get::z_get_options_t>(),
        size_of::<crate::query::z_queryable_options_t>(),
        size_of::<crate::query::z_query_reply_options_t>(),
        size_of::<crate::liveliness::z_liveliness_get_options_t>(),
        size_of::<crate::querier::z_querier_options_t>(),
        size_of::<crate::querier::z_querier_get_options_t>(),
        size_of::<crate::scout::z_scout_options_t>(),
        size_of::<crate::sub::z_subscriber_options_t>(),
        size_of::<crate::put::z_put_options_t>(),
        size_of::<crate::put::z_delete_options_t>(),
    ];
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    values.extend_from_slice(&[
        size_of::<crate::advanced::z_entity_global_id_t>(),
        align_of::<crate::advanced::z_entity_global_id_t>(),
        size_of::<crate::advanced::ze_miss_t>(),
        size_of::<crate::advanced::ze_owned_closure_miss_t>(),
        size_of::<crate::advanced::ze_owned_advanced_publisher_t>(),
        size_of::<crate::advanced::ze_owned_advanced_subscriber_t>(),
        size_of::<crate::advanced::ze_owned_sample_miss_listener_t>(),
        size_of::<crate::advanced::ze_advanced_publisher_cache_options_t>(),
        size_of::<crate::advanced::ze_advanced_publisher_sample_miss_detection_options_t>(),
        size_of::<crate::advanced::ze_advanced_publisher_options_t>(),
        size_of::<crate::advanced::ze_advanced_publisher_put_options_t>(),
        size_of::<crate::advanced::ze_advanced_subscriber_history_options_t>(),
        size_of::<crate::advanced::ze_advanced_subscriber_last_sample_miss_detection_options_t>(),
        size_of::<crate::advanced::ze_advanced_subscriber_recovery_options_t>(),
        size_of::<crate::advanced::ze_advanced_subscriber_options_t>(),
    ]);
    #[cfg(all(
        feature = "zenoh-c-shared-memory",
        not(feature = "zenoh-c-no-unstable-api")
    ))]
    values.extend_from_slice(&[
        size_of::<crate::shm::z_owned_shm_t>(),
        size_of::<crate::shm::z_owned_shm_mut_t>(),
        size_of::<crate::shm::z_owned_shm_provider_t>(),
        size_of::<crate::shm::z_alloc_alignment_t>(),
        size_of::<crate::shm::z_buf_layout_alloc_result_t>(),
        size_of::<crate::shm::z_buf_alloc_result_t>(),
    ]);
    values
}

/// The NUL-terminated name of layout entry `index`, or NULL past the end.
///
/// R311y540. Exported so a gate written in another language reads the names out
/// of the SAME artifact it reads the values from. The alternative is a second
/// copy of [`WZ_CAPI_C_LAYOUT_NAMES`] in the tool, which is the drift hazard the
/// array form of `wz_capi_c_layout` was introduced to remove — putting it back
/// one language over would have undone that.
///
/// The strings are `'static` and NUL-terminated here rather than in the const
/// table, so the table itself stays readable as plain Rust.
///
/// # Safety
/// Takes no pointers; the returned pointer is `'static` and must not be freed.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_layout_name(index: usize) -> *const std::ffi::c_char {
    use std::sync::OnceLock;
    static NUL_TERMINATED: OnceLock<Vec<std::ffi::CString>> = OnceLock::new();
    let table = NUL_TERMINATED.get_or_init(|| {
        layout_names()
            .into_iter()
            // The names are ASCII literals in this file, so the only way this
            // could fail is an embedded NUL nobody can write by accident.
            .map(|name| std::ffi::CString::new(name).expect("a layout name has no interior NUL"))
            .collect()
    });
    table
        .get(index)
        .map_or(std::ptr::null(), |name| name.as_ptr())
}

/// Report this build's footprints — the drop-in's half of the layout gate.
///
/// Writes at most `cap` entries through `out` (ignored when null) and returns
/// the number this build actually has. A caller whose buffer is short gets a
/// truncated prefix and a count that says so; it never gets its frame written
/// past.
///
/// # Safety
/// `out` must be null, or valid and writable for `cap` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_layout(out: *mut usize, cap: usize) -> usize {
    let values = layout_values();
    if !out.is_null() {
        let n = cap.min(values.len());
        // SAFETY: the caller's contract bounds `out` at `cap`, and `n <= cap`.
        unsafe { std::ptr::copy_nonoverlapping(values.as_ptr(), out, n) };
    }
    values.len()
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// The names and the values are two lists that must stay the same length.
    ///
    /// Until R311y543 `layout_values` was an array SIZED from the names, so a
    /// forgotten value failed to compile. The two-half split (base + unstable)
    /// gives up that coupling — a `Vec` has no length in its type — so the
    /// length equality is asserted here instead, and it is the check that
    /// catches an entry added to one half and forgotten in the other.
    ///
    /// The distinctness half catches the other mistake: a name added and a
    /// value added in the WRONG position, which compiles and would silently
    /// compare `z_owned_mutex_t` against a condvar. Duplicate names are what
    /// that looks like.
    #[test]
    fn every_layout_entry_has_a_distinct_name() {
        let names = layout_names();
        let mut seen = std::collections::BTreeSet::new();
        for name in &names {
            assert!(seen.insert(*name), "duplicate layout entry name: {name}");
        }
        assert_eq!(
            names.len(),
            layout_values().len(),
            "the name table and the value table disagree on length — an entry \
             was added to one half and forgotten in the other"
        );
        assert_eq!(seen.len(), layout_values().len());
    }

    /// The names a C-side gate reads through `wz_capi_c_layout_name` must BE
    /// the names this build has, at the same indices — the export is the only
    /// thing standing between the arms gate and a second, drifting copy of the
    /// table.
    #[test]
    fn the_exported_names_match_the_table_index_for_index() {
        let names = layout_names();
        for (i, expected) in names.iter().enumerate() {
            // SAFETY: `i` is in range and the returned pointer is 'static.
            let ptr = unsafe { wz_capi_c_layout_name(i) };
            assert!(
                !ptr.is_null(),
                "entry {i} ({expected}) exported a NULL name"
            );
            // SAFETY: a 'static NUL-terminated ASCII literal from this file.
            let got = unsafe { std::ffi::CStr::from_ptr(ptr) };
            assert_eq!(got.to_str().expect("ASCII"), *expected);
        }
        // SAFETY: one past the end is the documented end-of-table signal.
        assert!(unsafe { wz_capi_c_layout_name(names.len()) }.is_null());
    }

    /// A short buffer is TRUNCATED, not overrun, and the true count still comes
    /// back. This is the property the struct form did not have.
    #[test]
    fn a_short_buffer_is_truncated_and_the_true_count_is_returned() {
        let mut buf = [usize::MAX; 4];
        // SAFETY: `buf` is a valid, writable 4-slot array and `cap` says so.
        let total = unsafe { wz_capi_c_layout(buf.as_mut_ptr(), 3) };
        assert_eq!(total, layout_names().len());
        assert_eq!(buf[0], std::mem::size_of::<z_owned_session_t>());
        assert_eq!(
            buf[3],
            usize::MAX,
            "the fourth slot was outside `cap` and must not have been written"
        );
        // SAFETY: null is the documented "count only" call.
        assert_eq!(unsafe { wz_capi_c_layout(std::ptr::null_mut(), 0) }, total);
    }
}
