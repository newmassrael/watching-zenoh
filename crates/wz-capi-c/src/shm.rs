// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_shm_*` — the shared-memory PROVIDER and BUFFER plane at the zenoh-c ABI.
//!
//! ## What upstream's SHM API is two of, and which half this is
//!
//! zenoh's shared memory is two mechanisms wearing one name, and the corpus
//! reaches them separately:
//!
//! 1. **A buffer allocator.** A provider owns a segment; a program allocates a
//!    chunk out of it, writes into the chunk, and hands the chunk to zenoh as a
//!    payload. Six upstream examples do exactly this and nothing more:
//!    `z_pub_shm`, `z_pub_shm_thr`, `z_get_shm`, `z_ping_shm`, `z_queryable_shm`,
//!    and the allocating half of `z_sub_shm`.
//! 2. **A transport optimisation.** When two peers on the same host negotiate
//!    SHM support, a payload backed by a segment travels as a REFERENCE — the
//!    receiver maps the same pages instead of copying. When they do not, zenoh
//!    serialises the bytes and the receiver sees an ordinary payload.
//!
//! This module implements (1) completely, and (2) on the receiving side and, since
//! R3059, on the sending side for the two puts; the difference is stated here rather
//! than left for a reader to infer from a symbol list.
//!
//! - **Receiving (R3052).** On a build with the `zenoh-c-shared-memory` feature the
//!   session offers shared memory at its handshake whenever
//!   `transport/shared_memory/enabled` is on, which upstream defaults to. A payload
//!   a peer put on the wire as a chunk of its own segment arrives as a range of
//!   that segment, mapped and not copied, and [`z_bytes_as_loaned_shm`] and
//!   [`z_bytes_as_mut_loaned_shm`] answer for it as upstream's do: the mutable view
//!   only while this payload is the chunk's sole holder.
//! - **Sending (R3059, R3060): `z_put`, `z_publisher_put`, `z_get` and
//!   `z_querier_get`.** The provider allocates out of a real segment (R3058), and
//!   [`z_bytes_from_shm`] KEEPS the chunk of one: the payload is the chunk,
//!   [`z_bytes_as_loaned_shm`] says so for it, and a put of it sends the chunk's
//!   descriptor to every peer that negotiated shared memory and the bytes to every peer
//!   that did not, on a literal key and on a declared one alike; a get or a querier
//!   whose VALUE is a chunk does the same with the value. Upstream's own `z_pub_shm.c`
//!   reaches upstream's own `z_sub_shm`, and the derived `z_get_shm` upstream's own
//!   `z_queryable_shm`, as a shared-memory buffer through it
//!   (`zenoh_c_shm_and_advanced_on_wz_capi_c`, legs 7 to 10). A subscriber of the
//!   PUBLISHING session is handed the chunk as well, as upstream hands it
//!   (`zenoh_c_shm_local_delivery_twice_and_diff`).
//! - **A queryable's value (R3061).** The VALUE a queryable is handed is the chunk too,
//!   whether the query came from a peer that sent it through shared memory or from its
//!   own session's get or querier: `z_bytes_as_loaned_shm(z_query_payload(..))` answers a
//!   buffer, as upstream's does (`zenoh_c_shm_query_local_twice_and_diff` and leg 11 of
//!   `zenoh_c_shm_and_advanced_on_wz_capi_c`, whose getter is upstream's own `z_get_shm`).
//!   What is still bytes: a query's reply and the advanced publisher's put, which take the
//!   chunk's bytes whatever it was built from. A buffer received from a peer is copied
//!   when it is built into a payload, because its memory is the peer's segment and not
//!   one of this process's providers.
//!
//! ⚠ R2970 corrected two sentences that said this ABI's SHM fallback was upstream's
//! and the reason the two arms of the drop-in test agree. They were wrong then, and
//! R3052 is the round the session stopped declining: before it, the arms of
//! `z_sub_shm.c` agreed on `RAW` because the publisher in that leg is a zenoh-pico
//! CLI, which negotiates no SHM at all, and a publisher that DID negotiate was
//! answered `RAW` by wz and `SHM (MUT)` by the real library (the second leg of
//! `zenoh_c_shm_and_advanced_on_wz_capi_c`, measured red before the change). See
//! `crate::session`'s `session_offer`.
//!
//! ## The provider is the runtime's, because upstream's lifecycle is observable
//!
//! `z_pub_shm.c` creates a 4096-byte provider and allocates a 1024-byte chunk
//! once per second, forever. What makes that loop run is not that a dropped chunk
//! is free again: in upstream's provider it is NOT, until a collection takes it
//! off the provider's busy list, and the policy a spelling names decides whether
//! that collection happens (`z_shm_provider_alloc` does not collect,
//! `z_shm_provider_alloc_gc` and the spellings after it do). The built-in pool is
//! carved by the allocator upstream's default backend uses, so which pools can be
//! made (1000 bytes or fewer cannot), how many chunks of each size a pool holds
//! and which aligned requests it refuses are upstream's answers rather than
//! this crate's. All of that lives in `wz_runtime_tokio::shm_provider`, and the
//! differential `zenoh_c_shm_provider_allocation_twice_and_diff` measures it on
//! this ABI and on the real library from one C program.
//! (`z_shm_provider_available` does NOT report what is left, on purpose: R2957
//! measured upstream's default POSIX backend answering `0` there, and the built-in
//! pool answers the same.)
//!
//! Before R3058 this module carried an allocator of its own over process memory,
//! which freed a chunk the moment its owner dropped it and served a pool sized
//! exactly at the payload. Each was a difference from the real library that a
//! program could observe, and `z_get_shm.c` shows the second: it ran on this ABI and
//! aborts on upstream's (`zenoh_c_shm_and_advanced_on_wz_capi_c` leg 5).
//!
//! The segment is a real POSIX `/dev/shm` mapping now, which is what lets the
//! runtime put one of its chunks on the wire as a descriptor. A C program's own
//! allocator (`z_shm_provider_new` over callbacks) is a [`ForeignBackend`] that
//! implements the runtime's backend trait, so the two kinds of provider share one
//! set of allocation semantics and differ only in where the memory comes from.
//!
//! ## Gating
//!
//! Every declaration below is
//! `#if (defined(Z_FEATURE_SHARED_MEMORY) && defined(Z_FEATURE_UNSTABLE_API))`
//! upstream, so the module carries the same two-feature `cfg` — see
//! [`crate`](crate). On any other arm these symbols would name types no header
//! declares.

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

use crate::abi::{z_loaned_bytes_t, z_owned_bytes_t, Handle};
use crate::bytes::BytesState;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EUNAVAILABLE, Z_OK};
use wz_runtime_tokio::shm_clients::{ShmClientSet, ShmDataClient, ShmDataSegment};

/// `z_owned_shm_t` / `z_loaned_shm_t` / `z_owned_shm_mut_t` /
/// `z_loaned_shm_mut_t` — 80 bytes at align 8, measured by upstream's own
/// opaque-type generator on the shared-memory + unstable arm.
const SHM_SIZE: usize = 80;
/// `z_owned_shm_provider_t` / `z_loaned_shm_provider_t` — 104 bytes at align 8.
const SHM_PROVIDER_SIZE: usize = 104;

// ---------------------------------------------------------------------------
// the enums
// ---------------------------------------------------------------------------

/// zenoh-c `zc_buf_layout_alloc_status_t` (`zenoh_opaque.h:94-108`) — a plain C
/// enum, so `c_int`-sized.
pub type zc_buf_layout_alloc_status_t = std::ffi::c_int;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_OK` = 0.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_OK: zc_buf_layout_alloc_status_t = 0;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR` = 1.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR: zc_buf_layout_alloc_status_t = 1;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR` = 2.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR: zc_buf_layout_alloc_status_t = 2;

/// zenoh-c `zc_buf_alloc_status_t` (`zenoh_opaque.h:70-82`).
pub type zc_buf_alloc_status_t = std::ffi::c_int;
/// `ZC_BUF_ALLOC_STATUS_OK` = 0.
pub const ZC_BUF_ALLOC_STATUS_OK: zc_buf_alloc_status_t = 0;
/// `ZC_BUF_ALLOC_STATUS_ALLOC_ERROR` = 1.
pub const ZC_BUF_ALLOC_STATUS_ALLOC_ERROR: zc_buf_alloc_status_t = 1;

/// R2957 — zenoh-c `z_shm_provider_state` (`zenoh_commons.h` @
/// `typedef enum z_shm_provider_state {`).
pub type z_shm_provider_state = std::ffi::c_int;
/// `Z_SHM_PROVIDER_STATE_DISABLED` = 0 — disabled by configuration.
pub const Z_SHM_PROVIDER_STATE_DISABLED: z_shm_provider_state = 0;
/// `Z_SHM_PROVIDER_STATE_INITIALIZING` = 1 — concurrently initializing.
pub const Z_SHM_PROVIDER_STATE_INITIALIZING: z_shm_provider_state = 1;
/// `Z_SHM_PROVIDER_STATE_READY` = 2.
pub const Z_SHM_PROVIDER_STATE_READY: z_shm_provider_state = 2;
/// `Z_SHM_PROVIDER_STATE_ERROR` = 3 — initializing failed.
pub const Z_SHM_PROVIDER_STATE_ERROR: z_shm_provider_state = 3;

/// zenoh-c `z_alloc_error_t` (`zenoh_opaque.h:24-43`).
pub type z_alloc_error_t = std::ffi::c_int;
/// `Z_ALLOC_ERROR_NEED_DEFRAGMENT` = 0.
pub const Z_ALLOC_ERROR_NEED_DEFRAGMENT: z_alloc_error_t = 0;
/// `Z_ALLOC_ERROR_OUT_OF_MEMORY` = 1.
pub const Z_ALLOC_ERROR_OUT_OF_MEMORY: z_alloc_error_t = 1;
/// `Z_ALLOC_ERROR_OTHER` = 2.
pub const Z_ALLOC_ERROR_OTHER: z_alloc_error_t = 2;

/// zenoh-c `z_layout_error_t` (`zenoh_opaque.h:48-63`).
pub type z_layout_error_t = std::ffi::c_int;
/// `Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS` = 0.
pub const Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS: z_layout_error_t = 0;
/// `Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT` = 1.
pub const Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT: z_layout_error_t = 1;

// ---------------------------------------------------------------------------
// the chunk
// ---------------------------------------------------------------------------

/// Where one chunk's bytes live, and who gives them back.
///
/// R3058 -- TWO arms, and the allocator is no longer one of them. A chunk a provider
/// of this process issued is the runtime's
/// [`ShmBackedPayload`](wz_runtime_tokio::shm_provider::ShmBackedPayload) whichever
/// backend made it (the built-in pool, or a C program's callbacks), so the lifecycle
/// is the runtime's: the chunk is on its provider's busy list, a descriptor of it can
/// go on the wire, and its memory goes back to the backend when every holder has let
/// go and the provider is asked to collect. What used to stand here was an arm per
/// allocator, each returning memory in its own `Drop`, which could not do any of those.
enum ChunkBacking {
    /// A chunk of a provider of this process. The `Arc` is what makes a
    /// `z_shm_t` copy a SHARED buffer, as upstream's is: the buffer is writable again
    /// only when this is the last holder.
    ///
    /// `outside` is how many of the `Arc`'s holders are NOT buffers a C program holds: `0`
    /// for a chunk straight from a provider, `1` for a view of a payload built from one
    /// (R3059), where the payload keeps the chunk alive so that a put can send it. The
    /// buffers are the holders left over, and the chunk is writable when exactly one is.
    Issued {
        payload: Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>,
        outside: usize,
    },
    /// R3052 -- the bytes of a payload a peer sent as a chunk of shared memory, which
    /// this session delivered as a range of the mapped chunk and not as a copy.
    /// Nothing here allocates or frees: the reference the sender took for this
    /// receiver goes back when the last range of the bytes drops, which this chunk
    /// holding one is what defers.
    ///
    /// `holders` is a token every buffer made from ONE received payload shares: the
    /// slot's own count sees the sender and this receiver and nothing finer, so the
    /// buffers of one payload that are alive in this process are counted by it, and a
    /// received buffer is writable only while it is the only one (R3058).
    Received {
        bytes: wz_runtime_tokio::RxBytes,
        holders: Arc<()>,
    },
}

/// One chunk, owned or shared. Dropping it lets go of its hold on the memory; the
/// memory goes back to its provider's backend when the provider collects it.
struct ShmChunk {
    backing: ChunkBacking,
    len: usize,
}

impl ShmChunk {
    /// A chunk a provider issued.
    fn issued(payload: wz_runtime_tokio::shm_provider::ShmBackedPayload) -> Box<Self> {
        let len = payload.len();
        Box::new(Self {
            backing: ChunkBacking::Issued {
                payload: Arc::new(payload),
                outside: 0,
            },
            len,
        })
    }

    /// The chunk's bytes.
    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        match &self.backing {
            ChunkBacking::Issued { payload, .. } => payload.bytes(),
            ChunkBacking::Received { bytes, .. } => bytes.as_slice(),
        }
    }

    /// The chunk's bytes, mutably.
    fn as_mut_ptr(&self) -> *mut u8 {
        match &self.backing {
            ChunkBacking::Issued { payload, .. } => payload.as_mut_ptr(),
            // The page a peer sent, mapped writable when it can be. A chunk that
            // cannot be written answers its read-only address, which no caller
            // writes through because `may_write` was false for it.
            ChunkBacking::Received { bytes, .. } => bytes
                .shm_writable_ptr()
                .unwrap_or(bytes.as_slice().as_ptr() as *mut u8),
        }
    }

    /// Whether this chunk may be written through now: upstream's conversion of a
    /// shared buffer to a mutable one, which succeeds only for the SOLE holder
    /// (`commons/zenoh-shm/src/api/buffer/zshmmut.rs` @
    /// `impl TryFrom<&mut zshm> for &mut zshmmut {`).
    ///
    /// A chunk of this process's provider is the sole holder when no copy of it is
    /// alive here and no descriptor of it is in flight, which the slot's own count says;
    /// one a peer sent, when this receiver holds the only reference and the page maps
    /// writable.
    fn may_write(&self) -> bool {
        match &self.backing {
            ChunkBacking::Issued { payload, outside } => {
                Arc::strong_count(payload) == outside + 1 && payload.is_unique()
            }
            ChunkBacking::Received { bytes, holders } => {
                Arc::strong_count(holders) == 1
                    && bytes.shm_chunk().is_some_and(|view| view.is_unique())
                    && bytes.shm_writable_ptr().is_some()
            }
        }
    }

    /// A second holder of the same chunk: upstream's `z_shm_clone`, a reference copy.
    fn shared(&self) -> Box<Self> {
        let backing = match &self.backing {
            ChunkBacking::Issued { payload, outside } => ChunkBacking::Issued {
                payload: payload.clone(),
                outside: *outside,
            },
            ChunkBacking::Received { bytes, holders } => ChunkBacking::Received {
                bytes: bytes.clone(),
                holders: holders.clone(),
            },
        };
        Box::new(Self {
            backing,
            len: self.len,
        })
    }
}

/// The `z_owned_shm_t` a payload that is a chunk of shared memory lends to the C
/// side, owned by the payload's [`crate::bytes::BytesState`] (R3052).
///
/// The loan `z_bytes_as_loaned_shm` returns is a POINTER to this value, so it has to
/// live as long as the payload does, and it is the payload that frees it.
pub(crate) struct ReceivedShm {
    owned: z_owned_shm_t,
}

// SAFETY: the handle is a `Box<ShmChunk>` this value owns and frees in `Drop`, and a
// `ShmChunk` is `Send + Sync` through what it holds: an `Arc` of a segment, a
// foreign backend behind an `Arc`, or the shareable bytes a session delivered.
unsafe impl Send for ReceivedShm {}
// SAFETY: as above; the chunk behind the handle is only read through shared
// references.
unsafe impl Sync for ReceivedShm {}

impl Drop for ReceivedShm {
    fn drop(&mut self) {
        if !self.owned.handle.is_null() {
            // SAFETY: a live `Box<ShmChunk>` made by `received_shm`, freed only here.
            drop(unsafe { Box::from_raw(self.owned.handle as *mut ShmChunk) });
        }
    }
}

/// The shared-memory chunk a payload is, as a loan, or `None` when the payload is
/// a buffer of its own or a range of anything that is not a chunk of shared memory.
///
/// A chunk is either one a peer sent (a range of the mapped chunk, R3052) or one this
/// process's provider issued and a payload was built from (R3059); the loan answers for
/// both, and what differs is which holder it stands for.
fn received_shm(state: &crate::bytes::BytesState) -> Option<*mut z_loaned_shm_t> {
    let loan = state
        .shm_loan
        .get_or_init(|| {
            let chunk = match &state.payload {
                crate::bytes::Payload::Shared(bytes) if bytes.is_shared_memory() => ShmChunk {
                    backing: ChunkBacking::Received {
                        bytes: bytes.clone(),
                        holders: Arc::new(()),
                    },
                    len: bytes.len(),
                },
                crate::bytes::Payload::Issued(payload) => ShmChunk {
                    // The payload is one holder of the chunk and is not a buffer, so the
                    // loan it lends is the sole buffer exactly while nothing else is.
                    backing: ChunkBacking::Issued {
                        payload: payload.clone(),
                        outside: 1,
                    },
                    len: payload.len(),
                },
                _ => return None,
            };
            let chunk = Box::new(chunk);
            Some(ReceivedShm {
                owned: z_owned_shm_t::from_handle(Box::into_raw(chunk) as Handle),
            })
        })
        .as_ref()?;
    Some(&loan.owned as *const z_owned_shm_t as *mut z_loaned_shm_t)
}

// ---------------------------------------------------------------------------
// the opaque handles
// ---------------------------------------------------------------------------

/// Declare one `{owned, loaned, moved}` SHM family at `$size` bytes / align 8,
/// with the handle in slot 0 — the same shape [`crate::abi`]'s `define_opaque!`
/// produces, repeated here because these families are `cfg`-gated and that
/// macro's invocations are not.
macro_rules! define_shm_opaque {
    // R2289 — the OWNED + MOVED half on its own, for a family upstream gives no
    // `_loan`: `z_chunk_alloc_result_t` has no `z_loaned_` spelling in any
    // header and no function that would take one, and declaring the type anyway
    // would put a name in wz's surface that the reference does not have.
    ($Owned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Moved wrapper — upstream's `z_moved_X_t` is `struct { z_owned_X_t; }`.
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
    ($Owned:ident, $Loaned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Loaned view — the same layout, so `loan` is a pointer cast.
        #[repr(C)]
        pub struct $Loaned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Moved wrapper — upstream's `z_moved_X_t` is `struct { z_owned_X_t; }`.
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
            assert!(std::mem::size_of::<$Moved>() == $size);
        };
    };
}

/// zenoh-c `z_owned_memory_layout_t` (`zenoh_opaque.h`: `ALIGN(8) uint8_t
/// _0[16]`) — MEASURED off the shm-arm header, which is the only arm that
/// declares it.
const MEMORY_LAYOUT_SIZE: usize = 16;

define_shm_opaque!(
    z_owned_memory_layout_t,
    z_loaned_memory_layout_t,
    z_moved_memory_layout_t,
    MEMORY_LAYOUT_SIZE
);

/// zenoh-c `z_owned_precomputed_layout_t` (`zenoh_opaque.h`: `ALIGN(8) uint8_t
/// _0[40]`) — MEASURED off the shm-arm header.
const PRECOMPUTED_LAYOUT_SIZE: usize = 40;

define_shm_opaque!(
    z_owned_precomputed_layout_t,
    z_loaned_precomputed_layout_t,
    z_moved_precomputed_layout_t,
    PRECOMPUTED_LAYOUT_SIZE
);

/// zenoh-c makes `z_owned_alloc_layout_t` a TYPEDEF of
/// `z_owned_precomputed_layout_t`, so wz does the same rather than declaring a
/// second type that would have to be kept identical by hand.
pub type z_owned_alloc_layout_t = z_owned_precomputed_layout_t;
/// See [`z_owned_alloc_layout_t`].
pub type z_loaned_alloc_layout_t = z_loaned_precomputed_layout_t;
/// See [`z_owned_alloc_layout_t`].
pub type z_moved_alloc_layout_t = z_moved_precomputed_layout_t;

define_shm_opaque!(z_owned_shm_t, z_loaned_shm_t, z_moved_shm_t, SHM_SIZE);
define_shm_opaque!(
    z_owned_shm_mut_t,
    z_loaned_shm_mut_t,
    z_moved_shm_mut_t,
    SHM_SIZE
);
define_shm_opaque!(
    z_owned_shm_provider_t,
    z_loaned_shm_provider_t,
    z_moved_shm_provider_t,
    SHM_PROVIDER_SIZE
);
// R2957 — the SHARED provider: upstream's `Arc<ShmProvider>` behind the same
// 104-byte shape (`zenoh_opaque.h` @ `typedef struct ALIGN(8) z_owned_shared_shm_provider_t {`).
// Its handle is the same `Box<Provider>` a plain provider's is, and that is the
// whole design: `Provider` is already a handle onto `Arc`-shared state, so a
// shallow copy is a second box of the same provider, and `loan_as` — "use this
// where a provider is expected" — is a pointer cast every provider function
// already reads.
define_shm_opaque!(
    z_owned_shared_shm_provider_t,
    z_loaned_shared_shm_provider_t,
    z_moved_shared_shm_provider_t,
    SHM_PROVIDER_SIZE
);

/// zenoh-c `z_alloc_alignment_t` (`zenoh_opaque.h:181-183`): a power-of-two
/// exponent in ONE byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_alloc_alignment_t {
    /// `1 << pow` is the required alignment.
    pub pow: u8,
}

/// zenoh-c `z_buf_layout_alloc_result_t` (`zenoh_opaque.h:837-842`) —
/// TRANSPARENT, so it is mirrored field for field and Rust computes the layout.
#[repr(C)]
pub struct z_buf_layout_alloc_result_t {
    /// Which of the three outcomes this is.
    pub status: zc_buf_layout_alloc_status_t,
    /// The buffer, valid when `status` is OK and a gravestone otherwise.
    pub buf: z_owned_shm_mut_t,
    /// Meaningful when `status` is `ALLOC_ERROR`.
    pub alloc_error: z_alloc_error_t,
    /// Meaningful when `status` is `LAYOUT_ERROR`.
    pub layout_error: z_layout_error_t,
}

/// zenoh-c `z_buf_alloc_result_t` (`zenoh_opaque.h:123-127`).
#[repr(C)]
pub struct z_buf_alloc_result_t {
    /// Which of the two outcomes this is.
    pub status: zc_buf_alloc_status_t,
    /// The buffer, valid when `status` is OK.
    pub buf: z_owned_shm_mut_t,
    /// Meaningful when `status` is `ALLOC_ERROR`.
    pub error: z_alloc_error_t,
}

// ---------------------------------------------------------------------------
// handle plumbing
// ---------------------------------------------------------------------------

/// Read the backend behind a loaned provider.
///
/// # Safety
/// `this_` must be null, or a valid loaned provider whose handle slot holds a
/// live [`Provider`] pointer.
unsafe fn provider_of<'a>(this_: *const z_loaned_shm_provider_t) -> Option<&'a Provider> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<Provider>` this crate leaked.
    Some(unsafe { &*(handle as *const Provider) })
}

/// Mint an owned provider handle from a backend.
fn provider_handle(provider: Provider) -> Handle {
    Box::into_raw(Box::new(provider)) as Handle
}

/// A provider handle: the runtime's [`ShmProvider`], and whether its callbacks may run
/// concurrently.
///
/// R3058 -- until this round a provider was an ALLOCATOR of this crate's own, in two
/// arms (a process-memory free list, and an adapter over a C program's callbacks), and a
/// chunk of either was ordinary memory returned in its own `Drop`. Upstream's provider
/// is the thing that owns the lifecycle of what it issues, and the runtime now has it:
/// the built-in pool is the runtime's POSIX backend (a real `/dev/shm` segment, which is
/// what lets a chunk go on the wire as a descriptor) and a C program's allocator is a
/// [`ForeignBackend`] implementing the same backend trait. There is one provider type
/// and one set of allocation semantics, which is why the difference between the two is
/// only where the memory comes from.
///
/// The `threadsafe` flag changes what the callbacks are allowed to do, not where the
/// memory is: the `_async` spellings refuse a provider whose caller did not promise it,
/// as upstream's non-threadsafe provider is `!Sync`.
#[derive(Clone)]
struct Provider {
    shm: wz_runtime_tokio::shm_provider::ShmProvider,
    threadsafe: bool,
}

/// Why an allocation through this ABI failed, in the two vocabularies the C result
/// carries.
enum AllocFailure {
    /// The backend could not serve the request.
    Alloc(z_alloc_error_t),
    /// The layout was refused: malformed, or not one this provider can serve.
    Layout(z_layout_error_t),
}

/// The allocation policies zenoh-c composes, by the name of the function that
/// selects them (`zenoh-c/src/shm/provider/shm_provider.rs` @
/// `alloc::<Defragment<UnsafeGarbageCollect>>(`).
///
/// `UnsafeGarbageCollect` -- upstream's collecting spellings use the UNSAFE collection,
/// which also takes a chunk the watchdog invalidated (`shm_provider_impl.rs` @
/// `pub(crate) type UnsafeGarbageCollect = GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>;`).
mod policy {
    use wz_runtime_tokio::shm_provider::AllocPolicy;

    pub(super) fn just_alloc() -> AllocPolicy {
        AllocPolicy::JustAlloc
    }

    pub(super) fn gc() -> AllocPolicy {
        AllocPolicy::GarbageCollect {
            inner: Box::new(AllocPolicy::JustAlloc),
            alt: Box::new(AllocPolicy::JustAlloc),
            safe: false,
        }
    }

    pub(super) fn gc_defrag() -> AllocPolicy {
        AllocPolicy::defragment(gc(), AllocPolicy::JustAlloc)
    }

    /// `Deallocate<ConstUsize<100>, Defragment<UnsafeGarbageCollect>>`: the alternative
    /// defaults to the inner policy.
    pub(super) fn gc_defrag_dealloc() -> AllocPolicy {
        AllocPolicy::deallocate(100, gc_defrag(), gc_defrag())
    }

    pub(super) fn gc_defrag_blocking() -> AllocPolicy {
        AllocPolicy::block_on(gc_defrag())
    }
}

impl Provider {
    /// A provider over the built-in POSIX pool of `layout`, or why none could be made.
    fn pool(layout: &wz_runtime_tokio::shm_backend::MemoryLayout) -> std::io::Result<Self> {
        Ok(Self {
            shm: wz_runtime_tokio::shm_provider::ShmProvider::pool(layout)?,
            threadsafe: true,
        })
    }

    /// Allocate `size` bytes at the alignment `alignment` names, under `policy`.
    fn alloc(
        &self,
        size: usize,
        alignment: z_alloc_alignment_t,
        policy: &wz_runtime_tokio::shm_provider::AllocPolicy,
    ) -> Result<Box<ShmChunk>, AllocFailure> {
        use wz_runtime_tokio::shm_backend::{
            AllocAlignment, AllocError, LayoutAllocError, LayoutError, MemoryLayout,
        };
        // A layout that cannot be made is a LAYOUT error, not an allocation one: upstream
        // splits the two statuses for exactly this.
        let layout = AllocAlignment::new(alignment.pow)
            .and_then(|alignment| MemoryLayout::new(size, alignment))
            .map_err(|_| AllocFailure::Layout(Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS))?;
        match self.shm.alloc(layout, policy) {
            Ok(payload) => Ok(ShmChunk::issued(payload)),
            Err(LayoutAllocError::Alloc(e)) => Err(AllocFailure::Alloc(match e {
                AllocError::NeedDefragment => Z_ALLOC_ERROR_NEED_DEFRAGMENT,
                AllocError::OutOfMemory => Z_ALLOC_ERROR_OUT_OF_MEMORY,
                AllocError::Other => Z_ALLOC_ERROR_OTHER,
            })),
            Err(LayoutAllocError::Layout(e)) => Err(AllocFailure::Layout(match e {
                LayoutError::IncorrectLayoutArgs => Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
                LayoutError::ProviderIncompatibleLayout => {
                    Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT
                }
            })),
        }
    }

    /// Bytes still allocatable, as the BACKEND reports them: `0` for the built-in pool
    /// (upstream's default POSIX backend does not account), and a C-supplied backend
    /// answers for itself.
    fn available(&self) -> usize {
        self.shm.available()
    }

    /// Defragment, reporting what that leaves reachable.
    fn defragment(&self) -> usize {
        self.shm.defragment()
    }

    /// Take home every chunk nobody holds and report the largest, by the UNSAFE
    /// collection zenoh-c's `z_shm_provider_garbage_collect` runs.
    fn garbage_collect(&self) -> usize {
        // SAFETY: the C ABI promises upstream's contract, which is the caller's: nothing
        // may be reading a chunk its watchdog invalidated. That is zenoh-c's own
        // signature and its own warning, restated, not weakened.
        unsafe { self.shm.garbage_collect_unsafe() }
    }

    /// Whether the caller promised this provider's callbacks may run
    /// concurrently — what the `_async` spellings refuse on. TRUE for the built-in
    /// pool, which sits behind a mutex.
    fn is_threadsafe(&self) -> bool {
        self.threadsafe
    }
}

/// Read the chunk behind a loaned SHM buffer, in either mutability spelling.
///
/// The two loaned types are separate C types with the SAME layout and the same
/// handle contents, which is what lets [`z_shm_try_reloan_mut`] hand one back as
/// the other with a cast rather than a conversion.
///
/// # Safety
/// `handle` must be null or a live `Box::into_raw::<ShmChunk>` pointer.
unsafe fn chunk<'a>(handle: Handle) -> Option<&'a ShmChunk> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(handle as *const ShmChunk) })
}

// ---------------------------------------------------------------------------
// the provider
// ---------------------------------------------------------------------------

/// Create a provider owning a `size`-byte segment (zenoh-c
/// `z_shm_provider_default_new`, `zenoh_commons.h:4789-4790`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_default_new(
    this_: *mut z_owned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
        // Upstream builds this from `size` as a layout at byte alignment, and refuses with
        // `Z_EINVAL` whatever goes wrong: a size of zero is no layout, and a pool too small
        // for its allocator to claim is no pool (1000 bytes or fewer, MEASURED on the real
        // library).
        let built = wz_runtime_tokio::shm_backend::MemoryLayout::of_size(size)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|layout| Provider::pool(&layout));
        let Ok(provider) = built else {
            return Z_EINVAL;
        };
        let handle = provider_handle(provider);
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_provider_t::from_handle(handle) };
        Z_OK
    })
}

/// The shared body of every `z_shm_provider_alloc*` spelling.
///
/// `blocking` selects upstream's `BlockOn` policy: wait for another thread to
/// release a chunk rather than reporting failure. That is a faithful
/// reproduction and it has upstream's consequence — a SINGLE-threaded program
/// which exhausts its segment and then asks for more waits forever, because the
/// only thread that could free anything is the one now waiting. The
/// non-blocking spellings report `ALLOC_ERROR` instead, which is what a program
/// that cannot tolerate that should call.
///
/// # Safety
/// `out` must be valid and writable; `provider` must be null or a valid loaned
/// provider.
unsafe fn provider_alloc(
    out: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    policy: &wz_runtime_tokio::shm_provider::AllocPolicy,
) {
    if out.is_null() {
        return;
    }
    // Write the failure shape FIRST, so every early return below leaves the
    // caller a well-formed result rather than the uninitialised stack struct
    // `z_pub_shm.c` hands in.
    // SAFETY: the caller's contract.
    unsafe {
        (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
        (*out).buf = z_owned_shm_mut_t::null_value();
        (*out).alloc_error = Z_ALLOC_ERROR_OTHER;
        (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
    }
    // SAFETY: the caller's contract.
    let Some(backend) = (unsafe { provider_of(provider) }) else {
        return;
    };
    match backend.alloc(size, alignment, policy) {
        Ok(chunk) => {
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_OK;
                (*out).buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                (*out).alloc_error = Z_ALLOC_ERROR_OTHER;
                (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
            }
        }
        Err(AllocFailure::Alloc(reason)) => {
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
                (*out).alloc_error = reason;
            }
        }
        // A layout that cannot be made, or that this provider cannot serve, is a LAYOUT
        // error and not an allocation one: upstream splits the two statuses for exactly
        // this.
        Err(AllocFailure::Layout(reason)) => {
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR;
                (*out).layout_error = reason;
            }
        }
    }
}

/// The default alignment upstream's unaligned spellings imply: byte alignment.
const ALIGN_BYTE: z_alloc_alignment_t = z_alloc_alignment_t { pow: 0 };

/// Allocate a buffer (zenoh-c `z_shm_provider_alloc`,
/// `zenoh_commons.h:4647-4649`).
///
/// # Safety
/// `out_result` must be valid and writable; `provider` must be null or a valid
/// loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe {
            provider_alloc(
                out_result,
                provider,
                size,
                ALIGN_BYTE,
                &policy::just_alloc(),
            )
        };
    });
}

/// Allocate an ALIGNED buffer (zenoh-c `z_shm_provider_alloc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, &policy::just_alloc()) };
    });
}

/// Allocate, reclaiming released chunks first (zenoh-c
/// `z_shm_provider_alloc_gc`).
///
/// A chunk its owner has dropped is NOT back in the pool until a collection takes it,
/// as upstream's is not (R3058; this spelling used to be identical to the plain one
/// because the old allocator freed a chunk in its own `Drop`, which upstream's does not
/// do). A request the pool cannot serve is retried once after a collection, and only if
/// that collection freed a chunk at least as large as the request. The collection is the
/// UNSAFE one, as zenoh-c's is: it also takes a chunk the watchdog invalidated.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, &policy::gc()) };
    });
}

/// Allocate, reclaiming and defragmenting first (zenoh-c
/// `z_shm_provider_alloc_gc_defrag`): the collecting policy, then a defragmentation when
/// the backend asks for one. The built-in pool never asks (its allocator has no such
/// status), so the second step is for a backend a C program supplies.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, &policy::gc_defrag()) };
    });
}

/// Allocate, reclaiming and defragmenting, and BLOCK rather than fail (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_blocking`, `zenoh_commons.h:4739-4741`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_blocking(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe {
            provider_alloc(
                out_result,
                provider,
                size,
                ALIGN_BYTE,
                &policy::gc_defrag_blocking(),
            )
        };
    });
}

// ---------------------------------------------------------------------------
// the PRECOMPUTED LAYOUT — R2265 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// A layout BOUND TO A PROVIDER: `(provider, size, alignment)` decided once and
// allocated from many times. `z_memory_layout_t` (R2263) is the unbound half —
// a `(size, alignment)` pair with no provider — and this is what upstream hands
// a program that wants to skip re-deriving the layout on every allocation.
//
// ⛔ `z_owned_alloc_layout_t` IS `z_owned_precomputed_layout_t`. Upstream makes
// the first a `typedef` of the second (`zenoh_opaque.h`), so the twenty-two
// functions the census lists under two family names are ONE type under two
// spellings, and every `z_alloc_layout_*` below delegates to its
// `z_precomputed_layout_*` twin rather than reimplementing it. A reader who
// took the census grouping for two planes would build the same thing twice.
//
// ⚠ The result type is `z_buf_alloc_result_t`, NOT the
// `z_buf_layout_alloc_result_t` the provider entry points fill. That is
// upstream's own distinction and it is load-bearing: a precomputed layout was
// already validated when it was built, so an allocation through it can fail to
// ALLOCATE but can no longer fail to LAYOUT — which is exactly the arm the
// narrower result type drops.

/// What an owned precomputed layout's handle points at.
struct PrecomputedLayoutState {
    /// The BACKEND, not the provider handle: a layout outlives the
    /// `z_owned_shm_provider_t` it was built from (`z_pub_shm.c` relies on it),
    /// so it holds its own reference to the allocator rather than a pointer to
    /// the caller's box.
    provider: Provider,
    size: usize,
    alignment: z_alloc_alignment_t,
}

/// Borrow the state behind a loaned precomputed layout.
///
/// # Safety
/// `this_` must be null or a live loaned layout whose handle this crate minted.
#[inline]
unsafe fn precomputed_state<'a>(
    this_: *const z_loaned_precomputed_layout_t,
) -> Option<&'a PrecomputedLayoutState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<PrecomputedLayoutState>` this module leaked.
    Some(unsafe { &*(handle as *const PrecomputedLayoutState) })
}

/// Build a layout bound to `provider`, shared by all four constructor names.
///
/// # Safety
/// `this_` must be null or writable; `provider` null or a live loaned provider.
unsafe fn precomputed_new(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    if this_.is_null() {
        return Z_ENULL;
    }
    // Gravestone first, so a refusal never leaves the caller's stack value.
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_precomputed_layout_t::null_value() };
    // SAFETY: the caller's contract, delegated.
    let Some(backend) = (unsafe { provider_of(provider) }) else {
        return Z_ENULL;
    };
    // The SAME two refusals `z_memory_layout_new` makes, and for the same
    // reason: a layout is a precondition, so a nonsense one must not become an
    // allocation failure later that cannot say what was wrong.
    if size == 0 || usize::from(alignment.pow) >= usize::BITS as usize {
        return Z_EINVAL;
    }
    // And the provider's own refusal, at the same moment: upstream computes the layout
    // the provider will allocate by when it builds a precomputed one
    // (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
    // `.map_err(|_| ZLayoutError::ProviderIncompatibleLayout)?;`), so a layout this
    // provider cannot serve fails HERE with `Z_EINVAL`
    // (`zenoh-c/src/shm/provider/precomputed_layout_impl.rs` @ `provider.alloc_layout(mem_layout)`)
    // and not as an allocation failure later.
    {
        use wz_runtime_tokio::shm_backend::{AllocAlignment, MemoryLayout};
        let served = AllocAlignment::new(alignment.pow)
            .and_then(|alignment| MemoryLayout::new(size, alignment))
            .map_err(|_| ())
            .and_then(|layout| backend.shm.layout_for(layout).map_err(|_| ()));
        if served.is_err() {
            return Z_EINVAL;
        }
    }
    let state = PrecomputedLayoutState {
        provider: backend.clone(),
        size,
        alignment,
    };
    let handle = Box::into_raw(Box::new(state)) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_precomputed_layout_t::from_handle(handle) };
    Z_OK
}

/// Allocate through a precomputed layout, shared by all ten alloc spellings.
///
/// # Safety
/// `out_result` must be null or writable; `layout` null or a live loaned layout.
unsafe fn precomputed_alloc(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_precomputed_layout_t,
    policy: &wz_runtime_tokio::shm_provider::AllocPolicy,
) {
    if out_result.is_null() {
        return;
    }
    // The failure shape first, as `provider_alloc` does and for the same
    // reason — the C side hands in an uninitialised stack struct.
    // SAFETY: the caller's contract.
    unsafe {
        (*out_result).status = ZC_BUF_ALLOC_STATUS_ALLOC_ERROR;
        (*out_result).buf = z_owned_shm_mut_t::null_value();
        (*out_result).error = Z_ALLOC_ERROR_OTHER;
    }
    // SAFETY: the caller's contract, delegated.
    let Some(state) = (unsafe { precomputed_state(layout) }) else {
        return;
    };
    // Allocate through the PROVIDER path, so there is one allocator and one
    // blocking policy rather than a second copy that could drift from it. The
    // wider result is then narrowed: a layout-error arm cannot be reached from
    // here, because `precomputed_new` refused those inputs when the layout was
    // built.
    let mut wide = z_buf_layout_alloc_result_t {
        status: ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR,
        buf: z_owned_shm_mut_t::null_value(),
        alloc_error: Z_ALLOC_ERROR_OTHER,
        layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
    };
    let provider = z_owned_shm_provider_t::from_handle(provider_handle(state.provider.clone()));
    // SAFETY: `wide` is a live local and `provider` a live owned provider.
    unsafe {
        provider_alloc(
            &mut wide,
            z_shm_provider_loan(&provider),
            state.size,
            state.alignment,
            policy,
        )
    };
    let mut moved = z_moved_shm_provider_t { _this: provider };
    // SAFETY: dropped exactly once; the pool itself is kept alive by the layout's own
    // handle on the provider.
    unsafe { z_shm_provider_drop(&mut moved) };

    if wide.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
        // SAFETY: `out_result` was checked non-null above.
        unsafe {
            (*out_result).status = ZC_BUF_ALLOC_STATUS_OK;
            (*out_result).buf = wide.buf;
        }
    } else {
        // SAFETY: as above.
        unsafe { (*out_result).error = wide.alloc_error };
    }
}

/// Emit one alloc spelling for each of the two family names.
macro_rules! precomputed_alloc_spelling {
    ($precomputed:ident, $alloc_layout:ident, $policy:expr, $what:literal) => {
        #[doc = concat!("Allocate through a precomputed layout, ", $what, " (zenoh-c `")]
        #[doc = stringify!($precomputed)]
        /// `).
        ///
        /// # Safety
        /// `out_result` must be null or writable; `layout` null or live.
        #[no_mangle]
        pub unsafe extern "C" fn $precomputed(
            out_result: *mut z_buf_alloc_result_t,
            layout: *const z_loaned_precomputed_layout_t,
        ) {
            guard_val((), || {
                // SAFETY: the caller's contract, delegated.
                unsafe { precomputed_alloc(out_result, layout, &$policy) };
            });
        }

        #[doc = concat!("The `alloc_layout` spelling of [`", stringify!($precomputed), "`] (zenoh-c `")]
        #[doc = stringify!($alloc_layout)]
        /// `).
        ///
        /// Upstream typedefs the two layout types together, so this is the same
        /// function under the name the older API used.
        ///
        /// # Safety
        /// As its twin.
        #[no_mangle]
        pub unsafe extern "C" fn $alloc_layout(
            out_result: *mut z_buf_alloc_result_t,
            layout: *const z_loaned_alloc_layout_t,
        ) {
            guard_val((), || {
                // SAFETY: the caller's contract, delegated.
                unsafe { precomputed_alloc(out_result, layout, &$policy) };
            });
        }
    };
}

precomputed_alloc_spelling!(
    z_precomputed_layout_alloc,
    z_alloc_layout_alloc,
    policy::just_alloc(),
    "failing rather than waiting"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc,
    z_alloc_layout_alloc_gc,
    policy::gc(),
    "reclaiming first"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag,
    z_alloc_layout_alloc_gc_defrag,
    policy::gc_defrag(),
    "reclaiming and defragmenting"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag_blocking,
    z_alloc_layout_alloc_gc_defrag_blocking,
    policy::gc_defrag_blocking(),
    "blocking rather than failing"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag_dealloc,
    z_alloc_layout_alloc_gc_defrag_dealloc,
    policy::gc_defrag_dealloc(),
    "taking back the newest chunk, held or not, as the last resort"
);

/// Build a precomputed layout at the provider's default alignment (zenoh-c
/// `z_alloc_layout_new`).
///
/// # Safety
/// `this_` must be null or writable; `provider` null or live.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_new(
    this_: *mut z_owned_alloc_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, ALIGN_BYTE) }
    })
}

/// Build a precomputed layout at the caller's alignment (zenoh-c
/// `z_alloc_layout_with_alignment_new`).
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_with_alignment_new(
    this_: *mut z_owned_alloc_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, alignment) }
    })
}

/// Build a precomputed layout from a provider (zenoh-c
/// `z_shm_provider_alloc_layout`) — the provider-side spelling of
/// [`z_alloc_layout_new`].
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_layout(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, ALIGN_BYTE) }
    })
}

/// The aligned twin of [`z_shm_provider_alloc_layout`] (zenoh-c
/// `z_shm_provider_alloc_layout_aligned`).
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_layout_aligned(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, alignment) }
    })
}

/// Borrow an owned precomputed layout (zenoh-c `z_precomputed_layout_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_loan(
    this_: *const z_owned_precomputed_layout_t,
) -> *const z_loaned_precomputed_layout_t {
    this_.cast()
}

/// The `alloc_layout` spelling of [`z_precomputed_layout_loan`] (zenoh-c
/// `z_alloc_layout_loan`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_loan(
    this_: *const z_owned_alloc_layout_t,
) -> *const z_loaned_alloc_layout_t {
    this_.cast()
}

/// Free a precomputed layout, shared by both drop names.
///
/// # Safety
/// `this_` must be null or a valid moved layout whose handle is live.
#[inline]
unsafe fn precomputed_drop(this_: *mut z_moved_precomputed_layout_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let taken = unsafe {
        std::mem::replace(
            &mut (*this_)._this,
            z_owned_precomputed_layout_t::null_value(),
        )
    };
    if !taken.handle.is_null() {
        // SAFETY: a `Box<PrecomputedLayoutState>` this module leaked, dropped
        // once because the source was gravestoned above.
        drop(unsafe { Box::from_raw(taken.handle as *mut PrecomputedLayoutState) });
    }
}

/// Free a precomputed layout (zenoh-c `z_precomputed_layout_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_drop(this_: *mut z_moved_precomputed_layout_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_drop(this_) };
    });
}

/// The `alloc_layout` spelling of [`z_precomputed_layout_drop`] (zenoh-c
/// `z_alloc_layout_drop`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_drop(this_: *mut z_moved_alloc_layout_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_drop(this_) };
    });
}

/// `true` iff the owned layout holds a live handle (zenoh-c
/// `z_internal_precomputed_layout_check`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_internal_precomputed_layout_check(
    this_: *const z_owned_precomputed_layout_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// The `alloc_layout` spelling (zenoh-c `z_internal_alloc_layout_check`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_internal_alloc_layout_check(
    this_: *const z_owned_alloc_layout_t,
) -> bool {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_internal_precomputed_layout_check(this_) }
}

/// Gravestone an owned layout (zenoh-c `z_internal_precomputed_layout_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_precomputed_layout_null(
    this_: *mut z_owned_precomputed_layout_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_precomputed_layout_t::null_value() };
    }
}

/// The `alloc_layout` spelling (zenoh-c `z_internal_alloc_layout_null`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_internal_alloc_layout_null(this_: *mut z_owned_alloc_layout_t) {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_internal_precomputed_layout_null(this_) };
}

// --- R2264 (open-debt item 607): the ALIGNED and DEALLOC spellings ----------
//
// Upstream's provider surface is one allocation with three independent axes —
// the reclaim policy (gc / gc+defrag / gc+defrag+dealloc), whether it BLOCKS,
// and whether the caller names an alignment — and it spells every reachable
// combination as its own symbol. wz already had the unaligned column; these
// five are the rest of the grid that needs no machinery wz does not have.
//
// ⛔ THE ALIGNMENT IS NOT DECORATION HERE, and that is why these are not
// aliases of the five above: `provider_alloc` already takes an alignment and
// the existing entry points all pass `ALIGN_BYTE`. Each function below passes
// the CALLER'S, so a program that asks for 64-byte alignment gets it — which
// `z_shm_provider_alloc_aligned` already proved reachable on the non-gc path.
//
// `dealloc` is upstream's THIRD reclaim step: when collecting and defragmenting
// both fail, take back the NEWEST chunk whether or not anything still holds it,
// up to a hundred times (R3058; this was "identical to the defrag twin" while the
// allocator freed a chunk in its own `Drop`, and there was nothing left to take).

/// Allocate at the caller's alignment, reclaiming first (zenoh-c
/// `z_shm_provider_alloc_gc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, &policy::gc()) };
    });
}

/// Allocate at the caller's alignment, reclaiming and defragmenting (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, &policy::gc_defrag()) };
    });
}

/// Allocate at the caller's alignment and BLOCK rather than fail (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_blocking_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_blocking_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe {
            provider_alloc(
                out_result,
                provider,
                size,
                alignment,
                &policy::gc_defrag_blocking(),
            )
        };
    });
}

/// Allocate, reclaiming, defragmenting and force-releasing (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_dealloc`): when everything else fails, the newest
/// chunk is taken back whether or not it is held. The caller owns the consequence --
/// a holder may be reading a chunk that has been given to another.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_dealloc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe {
            provider_alloc(
                out_result,
                provider,
                size,
                ALIGN_BYTE,
                &policy::gc_defrag_dealloc(),
            )
        };
    });
}

/// The aligned twin of [`z_shm_provider_alloc_gc_defrag_dealloc`] (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_dealloc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_dealloc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe {
            provider_alloc(
                out_result,
                provider,
                size,
                alignment,
                &policy::gc_defrag_dealloc(),
            )
        };
    });
}

/// Bytes still allocatable from this provider (zenoh-c
/// `z_shm_provider_available`).
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_available(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        match unsafe { provider_of(provider) } {
            Some(backend) => backend.available(),
            None => 0,
        }
    })
}

/// Reclaim released chunks (zenoh-c `z_shm_provider_garbage_collect`), reporting
/// the size of the largest chunk that came home.
///
/// A chunk comes home when nothing holds it any more -- its owner has dropped it and no
/// receiver still holds a reference to the descriptor it sent -- and, as zenoh-c's
/// does, the collection is the UNSAFE one, which also takes a chunk the watchdog
/// invalidated (`zenoh-c/src/shm/provider/shm_provider.rs` @
/// `unsafe { garbage_collect_unsafe(provider) }`).
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_garbage_collect(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        match unsafe { provider_of(provider) } {
            Some(backend) => backend.garbage_collect(),
            None => 0,
        }
    })
}

/// Defragment the provider (zenoh-c `z_shm_provider_defragment`), reporting
/// what the BACKEND reports: `0` for the built-in pool, as upstream's default
/// POSIX backend answers (R2957, [`Provider::available`]); a C-supplied
/// backend answers for itself.
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_defragment(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        match unsafe { provider_of(provider) } {
            Some(backend) => backend.defragment(),
            None => 0,
        }
    })
}

/// Borrow a provider (zenoh-c `z_shm_provider_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_loan(
    this_: *const z_owned_shm_provider_t,
) -> *const z_loaned_shm_provider_t {
    this_ as *const z_loaned_shm_provider_t
}

// R311y568 — REMOVED: z_shm_provider_loan_mut.
//
// Upstream declares no such function on EITHER arm (0 hits across every header
// in both oracles), so wz was exporting a `z_`-prefixed symbol that is not part
// of the zenoh-c ABI. Nothing in the tree called it and no C program compiled
// against upstream's header could name it; what it did was make wz's exported
// surface a superset of the reference's, which is a different library wearing
// the same names. Found by the census's REVERSE direction, added the same round
// — the forward ratchet had been green over it since the plane landed.

/// Drop a provider (zenoh-c `z_shm_provider_drop`).
///
/// Buffers still outstanding keep the segment alive — they hold their own `Arc`
/// — which is what makes `z_pub_shm.c`'s teardown order safe.
///
/// # Safety
/// `this_` must be null or a valid moved provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_drop(this_: *mut z_moved_shm_provider_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Provider>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut Provider) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_provider_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned provider (zenoh-c `z_internal_shm_provider_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_provider_null(this_: *mut z_owned_shm_provider_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
    }
}

/// `true` iff the owned provider holds a live handle (zenoh-c
/// `z_internal_shm_provider_check`).
///
/// # Safety
/// `this_` must be null or a valid owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_provider_check(
    this_: *const z_owned_shm_provider_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the SESSION's provider — R2957
// ---------------------------------------------------------------------------
//
// Upstream's runtime owns one provider when BOTH `transport/shared_memory` and
// its `transport_optimization` are enabled, sized `pool_size`, and builds it
// LAZILY on a blocking task the first time anything asks
// (`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn try_get_provider(&self) -> ProviderInitState {`).
// `z_obtain_shm_provider` is that ask made from C. The provider is this
// crate's own segment allocator, as every other provider here is; what upstream
// ALSO uses it for — promoting large messages into SHM implicitly — is not
// built, which is why only `enabled` and `pool_size` are honoured
// (`wz_runtime_tokio::zenoh_config::C_ABI_SESSION_HONOURED_KEYS`).

/// Where the session's provider is in its life, upstream's
/// `ProviderInitStateInner` without the configuration it no longer needs.
enum SessionProviderInit {
    /// Enabled and never asked for: the next ask starts building it.
    Idle,
    /// Being built on its own thread.
    Initializing,
    /// Built.
    Ready(Provider),
    /// The build failed: a pool too small for its allocator to claim, or no
    /// `/dev/shm` to make it in. Upstream's `ProviderInitState::Error`, and it stays so.
    Failed,
}

/// The zenoh-c session's shared-memory state, attached to its `SessionState`
/// at open ([`wz_capi_core::drive::SessionState::set_abi_extension`]).
pub(crate) struct SessionShm {
    /// `None` when disabled by configuration; else the pool size in bytes.
    pool_size: Option<usize>,
    state: Mutex<SessionProviderInit>,
    ready: Condvar,
}

impl SessionShm {
    /// The session's shared-memory state as its config states it:
    /// `transport/shared_memory/enabled` and its `transport_optimization`
    /// both, as upstream's `ShmContext::new` requires, and `pool_size`.
    pub(crate) fn from_config(
        shared_memory: bool,
        optimization: bool,
        pool_size: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool_size: (shared_memory && optimization).then_some(pool_size as usize),
            state: Mutex::new(SessionProviderInit::Idle),
            ready: Condvar::new(),
        })
    }

    /// Ask for the provider: upstream's `try_get_provider`, which answers
    /// what the state is NOW and starts the build on the first ask.
    fn try_get(self: &Arc<Self>) -> (z_shm_provider_state, Option<Provider>) {
        let Some(pool_size) = self.pool_size else {
            return (Z_SHM_PROVIDER_STATE_DISABLED, None);
        };
        let Ok(mut state) = self.state.lock() else {
            return (Z_SHM_PROVIDER_STATE_ERROR, None);
        };
        match &*state {
            SessionProviderInit::Ready(provider) => {
                (Z_SHM_PROVIDER_STATE_READY, Some(provider.clone()))
            }
            SessionProviderInit::Initializing => (Z_SHM_PROVIDER_STATE_INITIALIZING, None),
            SessionProviderInit::Failed => (Z_SHM_PROVIDER_STATE_ERROR, None),
            SessionProviderInit::Idle => {
                *state = SessionProviderInit::Initializing;
                let this = Arc::clone(self);
                let spawned = std::thread::Builder::new()
                    .name("wz-shm-provider-init".into())
                    .spawn(move || {
                        let built = wz_runtime_tokio::shm_backend::MemoryLayout::of_size(pool_size)
                            .map_err(|e| std::io::Error::other(e.to_string()))
                            .and_then(|layout| Provider::pool(&layout));
                        if let Ok(mut state) = this.state.lock() {
                            *state = match built {
                                Ok(provider) => SessionProviderInit::Ready(provider),
                                Err(_) => SessionProviderInit::Failed,
                            };
                        }
                        this.ready.notify_all();
                    });
                if spawned.is_err() {
                    // Upstream's `Error`: the build could not run. Back to
                    // `Idle`, so a later ask tries again rather than hanging.
                    *state = SessionProviderInit::Idle;
                    return (Z_SHM_PROVIDER_STATE_ERROR, None);
                }
                (Z_SHM_PROVIDER_STATE_INITIALIZING, None)
            }
        }
    }

    /// Wait for a build that has started: upstream's blocking `recv` on the
    /// initializer.
    fn wait_ready(&self) -> Option<Provider> {
        let mut state = self.state.lock().ok()?;
        loop {
            match &*state {
                SessionProviderInit::Ready(provider) => return Some(provider.clone()),
                SessionProviderInit::Idle | SessionProviderInit::Failed => return None,
                SessionProviderInit::Initializing => state = self.ready.wait(state).ok()?,
            }
        }
    }
}

/// Obtain the session's own provider (zenoh-c `z_obtain_shm_provider`,
/// `zenoh-c/src/session.rs` @ `pub extern "C" fn z_obtain_shm_provider(`).
///
/// Upstream's four answers, in upstream's order: disabled by configuration;
/// still initializing, which a `blocking` call waits out; ready, the one
/// `Z_OK` and the one that writes `out_provider`; and an error. `out_state` is
/// written on every path, `out_provider` only on `Z_OK`, as upstream's.
///
/// # Safety
/// `this_` must be null or a valid loaned session; `out_provider` and
/// `out_state` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_obtain_shm_provider(
    this_: *const crate::abi::z_loaned_session_t,
    blocking: bool,
    out_provider: *mut z_owned_shared_shm_provider_t,
    out_state: *mut z_shm_provider_state,
) -> ZResult {
    guarded(|| {
        if out_provider.is_null() || out_state.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(session) = (unsafe { crate::session::session_state(this_) }) else {
            // SAFETY: checked non-null above.
            unsafe { *out_state = Z_SHM_PROVIDER_STATE_DISABLED };
            return Z_ENULL;
        };
        let Some(shm) = session.abi_extension::<Arc<SessionShm>>() else {
            // SAFETY: checked non-null above.
            unsafe { *out_state = Z_SHM_PROVIDER_STATE_DISABLED };
            return Z_EUNAVAILABLE;
        };
        let (mut state, mut provider) = shm.try_get();
        if state == Z_SHM_PROVIDER_STATE_INITIALIZING && blocking {
            provider = shm.wait_ready();
            state = if provider.is_some() {
                Z_SHM_PROVIDER_STATE_READY
            } else {
                Z_SHM_PROVIDER_STATE_ERROR
            };
        }
        // SAFETY: checked non-null above.
        unsafe { *out_state = state };
        match provider {
            Some(provider) => {
                let handle = Box::into_raw(Box::new(provider)) as Handle;
                // SAFETY: checked non-null above.
                unsafe { *out_provider = z_owned_shared_shm_provider_t::from_handle(handle) };
                Z_OK
            }
            None => Z_EUNAVAILABLE,
        }
    })
}

// ---------------------------------------------------------------------------
// the SHARED provider — R2957
// ---------------------------------------------------------------------------

/// Borrow a shared provider (zenoh-c `z_shared_shm_provider_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned shared provider.
#[no_mangle]
pub unsafe extern "C" fn z_shared_shm_provider_loan(
    this_: *const z_owned_shared_shm_provider_t,
) -> *const z_loaned_shared_shm_provider_t {
    this_ as *const z_loaned_shared_shm_provider_t
}

/// Use a shared provider where a provider is expected (zenoh-c
/// `z_shared_shm_provider_loan_as`): the same handle, so every provider
/// function reads it unchanged.
///
/// # Safety
/// `this_` must be null or a valid loaned shared provider.
#[no_mangle]
pub unsafe extern "C" fn z_shared_shm_provider_loan_as(
    this_: *const z_loaned_shared_shm_provider_t,
) -> *const z_loaned_shm_provider_t {
    this_ as *const z_loaned_shm_provider_t
}

/// Shallow-copy a shared provider (zenoh-c `z_shared_shm_provider_clone`):
/// both copies allocate from, and keep alive, the one backend.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a live loan.
#[no_mangle]
pub unsafe extern "C" fn z_shared_shm_provider_clone(
    dst: *mut z_owned_shared_shm_provider_t,
    this_: *const z_loaned_shared_shm_provider_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract; `loan_as` is a cast, so the provider
        // reader applies to a shared loan as it does to a plain one.
        let copy = unsafe { provider_of(this_ as *const z_loaned_shm_provider_t) }
            .map(|provider| Box::into_raw(Box::new(provider.clone())) as Handle);
        // SAFETY: `dst` was checked non-null above.
        unsafe {
            *dst = match copy {
                Some(handle) => z_owned_shared_shm_provider_t::from_handle(handle),
                None => z_owned_shared_shm_provider_t::null_value(),
            }
        };
    })
}

/// Drop a shared provider (zenoh-c `z_shared_shm_provider_drop`); the backend
/// goes when its last copy, and its last outstanding buffer, does.
///
/// # Safety
/// `this_` must be null or a valid moved shared provider.
#[no_mangle]
pub unsafe extern "C" fn z_shared_shm_provider_drop(this_: *mut z_moved_shared_shm_provider_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Provider>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut Provider) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shared_shm_provider_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned shared provider (zenoh-c `z_internal_shared_shm_provider_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned shared provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shared_shm_provider_null(
    this_: *mut z_owned_shared_shm_provider_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shared_shm_provider_t::null_value() };
    }
}

/// `true` iff the owned shared provider holds a live handle (zenoh-c
/// `z_internal_shared_shm_provider_check`).
///
/// # Safety
/// `this_` must be null or a valid owned shared provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shared_shm_provider_check(
    this_: *const z_owned_shared_shm_provider_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Remove the POSIX shm segments no process holds any more (zenoh-c
/// `zc_cleanup_orphaned_shm_segments`).
///
/// R2954 — the segment protocol's own cleanup,
/// [`wz_runtime_tokio::posix_shm::cleanup_orphaned_segments`]: upstream's rule
/// over every `/dev/shm/{id}.zenoh`, whoever made it, and a no-op off Linux as
/// upstream's is. It acts on the SYSTEM's segments, not this crate's: this
/// ABI's own providers are process memory and leave nothing in `/dev/shm`,
/// but a crashed zenoh process — this workspace's SHM transport, or upstream's
/// — does, and that is what the call is for.
#[no_mangle]
pub extern "C" fn zc_cleanup_orphaned_shm_segments() {
    let _ = guarded(|| {
        wz_runtime_tokio::posix_shm::cleanup_orphaned_segments();
        Z_OK
    });
}

// ---------------------------------------------------------------------------
// the MEMORY LAYOUT — R2263 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// A `(size, alignment)` pair, and nothing else. It is the most self-contained
// of the eighty-four symbols item 607 covers: no provider, no segment, no
// allocation — which is why this round takes it whole and leaves the layout
// family that DOES allocate (`z_alloc_layout_*` / `z_precomputed_layout_*`,
// which upstream makes ALIASES of one type) to a round that can witness an
// allocation end to end.
//
// ⚠ The C type is 16 bytes at align 8 and holds a `usize` plus a byte, so wz
// stores its state behind the same handle every sibling here uses rather than
// packing the two inline. The alternative would make this the one type in the
// module whose loan is not a pointer cast.

/// What an owned memory layout's handle points at.
struct MemoryLayoutState {
    size: usize,
    alignment: z_alloc_alignment_t,
}

/// Borrow the state behind a loaned memory layout.
///
/// # Safety
/// `this_` must be null or a live loaned layout whose handle this crate minted.
#[inline]
unsafe fn memory_layout_state<'a>(
    this_: *const z_loaned_memory_layout_t,
) -> Option<&'a MemoryLayoutState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<MemoryLayoutState>` this module leaked.
    Some(unsafe { &*(handle as *const MemoryLayoutState) })
}

/// Construct a memory layout (zenoh-c `z_memory_layout_new`).
///
/// ⛔ REFUSES a zero size and a non-power-of-two alignment, which upstream also
/// refuses — its `AllocLayout::new` returns a `LayoutError` for both. A layout
/// is a PRECONDITION for an allocation, so accepting a nonsense one here would
/// move the failure to a later call that cannot explain it.
///
/// `z_alloc_alignment_t` carries a power-of-two EXPONENT rather than the
/// alignment itself, so every representable value is already a power of two;
/// what is refused is an exponent so large that `1 << pow` does not fit a
/// `usize`, which is the same boundary upstream's `AllocAlignment` checks.
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_new(
    this_: *mut z_owned_memory_layout_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // Written before the checks so a refused layout leaves a gravestone
        // rather than the caller's uninitialised stack value.
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::null_value() };
        if size == 0 {
            return Z_EINVAL;
        }
        if usize::from(alignment.pow) >= usize::BITS as usize {
            return Z_EINVAL;
        }
        let state = MemoryLayoutState { size, alignment };
        let handle = Box::into_raw(Box::new(state)) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::from_handle(handle) };
        Z_OK
    })
}

/// Read a layout's `(size, alignment)` back (zenoh-c `z_memory_layout_get_data`).
///
/// Both outputs are written independently, so a caller that wants one passes
/// NULL for the other — upstream's signature takes two pointers and says
/// nothing about them being required together.
///
/// # Safety
/// `this_` must be null or a live loaned layout; each output must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_get_data(
    this_: *const z_loaned_memory_layout_t,
    out_size: *mut usize,
    out_alignment: *mut z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { memory_layout_state(this_) }) else {
            return;
        };
        if !out_size.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_size = state.size };
        }
        if !out_alignment.is_null() {
            // SAFETY: as above.
            unsafe { *out_alignment = state.alignment };
        }
    });
}

/// Borrow an owned memory layout (zenoh-c `z_memory_layout_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_loan(
    this_: *const z_owned_memory_layout_t,
) -> *const z_loaned_memory_layout_t {
    this_.cast()
}

/// Free a memory layout (zenoh-c `z_memory_layout_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved layout whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_drop(this_: *mut z_moved_memory_layout_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(&mut (*this_)._this, z_owned_memory_layout_t::null_value())
        };
        if !taken.handle.is_null() {
            // SAFETY: a `Box<MemoryLayoutState>` this module leaked, dropped
            // once because the source was gravestoned above.
            drop(unsafe { Box::from_raw(taken.handle as *mut MemoryLayoutState) });
        }
    });
}

/// Gravestone an owned memory layout (zenoh-c `z_internal_memory_layout_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_memory_layout_null(this_: *mut z_owned_memory_layout_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::null_value() };
    }
}

/// `true` iff the owned layout holds a live handle (zenoh-c
/// `z_internal_memory_layout_check`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_internal_memory_layout_check(
    this_: *const z_owned_memory_layout_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the MUTABLE buffer
// ---------------------------------------------------------------------------

/// A mutable buffer's bytes (zenoh-c `z_shm_mut_data_mut`,
/// `zenoh_commons.h:4591`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutable buffer. The returned pointer
/// is valid for `z_shm_mut_len` bytes and for as long as the buffer is.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_data_mut(this_: *mut z_loaned_shm_mut_t) -> *mut u8 {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_mut_ptr(),
            None => std::ptr::null_mut(),
        }
    })
}

/// A mutable buffer's bytes, read-only (zenoh-c `z_shm_mut_data`).
///
/// # Safety
/// As [`z_shm_mut_data_mut`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_data(this_: *const z_loaned_shm_mut_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_slice().as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// A mutable buffer's length (zenoh-c `z_shm_mut_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_len(this_: *const z_loaned_shm_mut_t) -> usize {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { chunk((*this_).handle) }.map_or(0, |c| c.len)
    })
}

/// Borrow a mutable buffer (zenoh-c `z_shm_mut_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_loan(
    this_: *const z_owned_shm_mut_t,
) -> *const z_loaned_shm_mut_t {
    this_ as *const z_loaned_shm_mut_t
}

/// Mutably borrow a mutable buffer (zenoh-c `z_shm_mut_loan_mut`,
/// `zenoh_commons.h:4623`).
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_loan_mut(
    this_: *mut z_owned_shm_mut_t,
) -> *mut z_loaned_shm_mut_t {
    this_ as *mut z_loaned_shm_mut_t
}

/// Drop a mutable buffer (zenoh-c `z_shm_mut_drop`), returning its range to the
/// segment.
///
/// # Safety
/// `this_` must be null or a valid moved mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_drop(this_: *mut z_moved_shm_mut_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ShmChunk>` this crate leaked; its `Drop`
            // releases the range and wakes any blocked allocation.
            drop(unsafe { Box::from_raw(handle as *mut ShmChunk) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_mut_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned mutable buffer (zenoh-c `z_internal_shm_mut_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_mut_null(this_: *mut z_owned_shm_mut_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_mut_t::null_value() };
    }
}

/// `true` iff the owned mutable buffer holds a live handle.
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_mut_check(this_: *const z_owned_shm_mut_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the IMMUTABLE buffer
// ---------------------------------------------------------------------------

/// Freeze a mutable buffer into an immutable one (zenoh-c `z_shm_from_mut`,
/// `zenoh_commons.h:4550-4551`). The source is consumed.
///
/// The chunk itself does not move and nothing about it changes: the same handle is
/// now named by the immutable type, and it is WRITABLE AGAIN
/// ([`z_shm_try_reloan_mut`]) for as long as it is the sole holder -- no copy of it
/// alive here, no descriptor of it in flight. That is upstream's rule, and the point of
/// the freeze is to permit reference copies ([`z_shm_clone`]), not to relocate bytes.
///
/// # Safety
/// `this_` must be valid and writable; `that` must be null or a valid moved
/// mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_from_mut(this_: *mut z_owned_shm_t, that: *mut z_moved_shm_mut_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_t::null_value() };
        if that.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*that)._this.handle };
        // SAFETY: the caller's contract — consumed on every path, so the source
        // is nulled whether or not it carried a live chunk.
        unsafe { (*that)._this = z_owned_shm_mut_t::null_value() };
        if handle.is_null() {
            return;
        }
        // The handle is a live `Box<ShmChunk>` this crate leaked, and it keeps being one:
        // it is re-named, not re-made, so nothing is released here.
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_t::from_handle(handle) };
    });
}

/// An immutable buffer's bytes (zenoh-c `z_shm_data`).
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_data(this_: *const z_loaned_shm_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_slice().as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// An immutable buffer's length (zenoh-c `z_shm_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_len(this_: *const z_loaned_shm_t) -> usize {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { chunk((*this_).handle) }.map_or(0, |c| c.len)
    })
}

/// Borrow an immutable buffer (zenoh-c `z_shm_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_loan(this_: *const z_owned_shm_t) -> *const z_loaned_shm_t {
    this_ as *const z_loaned_shm_t
}

/// Mutably borrow an immutable buffer (zenoh-c `z_shm_loan_mut`) — the borrow is
/// mutable, the buffer's frozen status is not.
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_loan_mut(this_: *mut z_owned_shm_t) -> *mut z_loaned_shm_t {
    this_ as *mut z_loaned_shm_t
}

/// Try to recover MUTABLE access to a borrowed buffer (zenoh-c
/// `z_shm_try_reloan_mut`, `zenoh_commons.h:4871`).
///
/// NULL while some other party still holds the chunk -- a copy of it alive here
/// ([`z_shm_clone`]), a descriptor of it in flight or a receiver reading it -- or, for a
/// chunk that came off the wire, when its page maps read-only here. That is what
/// `z_sub_shm.c` distinguishes `SHM (MUT)` from `SHM (IMMUT)` by (R3052), and since R3058 it
/// is the same rule for a chunk this process allocated: freezing one with
/// [`z_shm_from_mut`] does not make it read-only, sharing it does.
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_try_reloan_mut(
    this_: *mut z_loaned_shm_t,
) -> *mut z_loaned_shm_mut_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            // The two loaned types have identical layout and identical handle
            // contents, so the recovery is a cast — see `chunk`.
            Some(c) if c.may_write() => this_ as *mut z_loaned_shm_mut_t,
            _ => std::ptr::null_mut(),
        }
    })
}

/// Try to take an OWNED immutable buffer back as an OWNED mutable one (zenoh-c
/// `z_shm_mut_try_from_immut`, `zenoh_commons.h:5909-5911`).
///
/// The three-argument shape is upstream's and it is what makes the refusal
/// non-destructive: `that` is CONSUMED on every path, and on failure the buffer
/// reappears in `immut` so the caller has not lost it. Success leaves `immut` a
/// gravestone; failure leaves `this_` one.
///
/// The predicate is the SAME one [`z_shm_try_mut`] answers with --
/// [`ShmChunk::may_write`], the chunk's sole holder -- because both calls ask one
/// question ("may this buffer be written again?") and a second, disagreeing answer to
/// it would be a bug the two could not both be right about.
///
/// R3058 -- this used to be a MEASURED DIVERGENCE (R2294): upstream succeeds when the
/// buffer is uniquely owned, and wz froze a buffer with a flag, so through the C surface
/// the call always refused. A buffer is now a reference-counted chunk as upstream's is,
/// and a `z_shm_from_mut` result that nothing else holds is taken back.
///
/// # Safety
/// `this_` must be null or valid and writable; `that` must be null or a valid
/// moved buffer; `immut` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_try_from_immut(
    this_: *mut z_owned_shm_mut_t,
    that: *mut z_moved_shm_t,
    immut: *mut z_owned_shm_t,
) -> ZResult {
    guarded(|| {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_shm_mut_t::null_value() };
        }
        if !immut.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *immut = z_owned_shm_t::null_value() };
        }
        if that.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*that)._this.handle };
        // Consumed on every path, exactly as `z_shm_from_mut` consumes its
        // source: the caller's `that` is dead whether or not the recovery took.
        // SAFETY: the caller's contract.
        unsafe { (*that)._this = z_owned_shm_t::null_value() };
        if handle.is_null() {
            return Z_ENULL;
        }
        // SAFETY: a live `Box<ShmChunk>` this crate leaked.
        let recovered = unsafe { &*(handle as *const ShmChunk) }.may_write();
        if recovered {
            if this_.is_null() {
                return Z_ENULL;
            }
            // SAFETY: `this_` was checked non-null just above.
            unsafe { *this_ = z_owned_shm_mut_t::from_handle(handle) };
            return Z_OK;
        }
        if immut.is_null() {
            // Nowhere to hand it back to. Dropping is the only alternative to
            // leaking, and it is what the caller asked for by passing null.
            // SAFETY: a live `Box<ShmChunk>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut ShmChunk) });
            return Z_ENULL;
        }
        // SAFETY: `immut` was checked non-null just above.
        unsafe { *immut = z_owned_shm_t::from_handle(handle) };
        Z_EINVAL
    })
}

/// Try to recover MUTABLE access to an OWNED buffer (zenoh-c `z_shm_try_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_try_mut(this_: *mut z_owned_shm_t) -> *mut z_loaned_shm_mut_t {
    // SAFETY: the caller's contract, delegated — the owned and loaned forms have
    // the same layout, which is what `z_shm_loan_mut` already relies on.
    unsafe { z_shm_try_reloan_mut(this_ as *mut z_loaned_shm_t) }
}

/// Drop an immutable buffer (zenoh-c `z_shm_drop`, `zenoh_commons.h:4542`).
///
/// # Safety
/// `this_` must be null or a valid moved buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_drop(this_: *mut z_moved_shm_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ShmChunk>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut ShmChunk) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned buffer (zenoh-c `z_internal_shm_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_null(this_: *mut z_owned_shm_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_t::null_value() };
    }
}

/// `true` iff the owned buffer holds a live handle (zenoh-c
/// `z_internal_shm_check`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_check(this_: *const z_owned_shm_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Take a second reference to an immutable buffer (zenoh-c `z_shm_clone`): "a shallow
/// SHM reference copy" (`zenoh-c/src/shm/buffer/zshm.rs` @ `let copy = this.to_owned();`).
///
/// R3058 -- this used to allocate a new chunk and copy the bytes, which cost room in the
/// pool upstream's does not and could fail where upstream's cannot. The copy is now the
/// SAME chunk with one more holder: nothing is allocated, and the buffer is writable
/// again ([`z_shm_try_reloan_mut`]) only once every copy has been dropped.
///
/// # Safety
/// `out` must be valid and writable; `this_` must be null or a valid loaned
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_clone(out: *mut z_owned_shm_t, this_: *const z_loaned_shm_t) {
    guard_val((), || {
        if out.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = z_owned_shm_t::null_value() };
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let Some(source) = (unsafe { chunk((*this_).handle) }) else {
            return;
        };
        let copy = source.shared();
        // SAFETY: `out` was checked non-null above.
        unsafe { *out = z_owned_shm_t::from_handle(Box::into_raw(copy) as Handle) };
    });
}

// ---------------------------------------------------------------------------
// the bytes bridge
// ---------------------------------------------------------------------------

/// Build a payload from an immutable SHM buffer (zenoh-c `z_bytes_from_shm`,
/// `zenoh_commons.h:1531-1532`). The buffer is consumed.
///
/// R3059 -- a chunk of a provider of THIS process stays a chunk: the payload holds it, so
/// a put of the payload sends its descriptor to a peer that negotiated shared memory, and
/// the bytes to one that did not. The chunk goes back to its provider when the payload,
/// every receiver and every copy have let go and the provider is asked to collect, which
/// is what keeps `z_pub_shm.c`'s forever-loop running on a 4096-byte provider.
///
/// A buffer received FROM a peer is copied: its memory is the peer's segment and not one
/// this process's providers issued, so there is no descriptor of ours to send for it.
///
/// # Safety
/// `this_` must be valid and writable; `shm` must be null or a valid moved
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_shm(
    this_: *mut z_owned_bytes_t,
    shm: *mut z_moved_shm_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        if shm.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*shm)._this.handle };
        // SAFETY: consumed on every path.
        unsafe { (*shm)._this = z_owned_shm_t::null_value() };
        if handle.is_null() {
            return Z_ENULL;
        }
        // SAFETY: a live `Box<ShmChunk>`; dropped at the end of this scope,
        // which releases the range.
        let boxed = unsafe { Box::from_raw(handle as *mut ShmChunk) };
        let payload = match &boxed.backing {
            ChunkBacking::Issued { payload, .. } => crate::bytes::Payload::Issued(payload.clone()),
            ChunkBacking::Received { .. } => {
                crate::bytes::Payload::Owned(boxed.as_slice().to_vec())
            }
        };
        drop(boxed);
        let state = Box::into_raw(Box::new(BytesState::of(payload))) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_bytes_t::from_handle(state) };
        Z_OK
    })
}

/// Build a payload from a MUTABLE SHM buffer (zenoh-c `z_bytes_from_shm_mut`,
/// `zenoh_commons.h:1540-1541`). The buffer is consumed.
///
/// # Safety
/// `this_` must be valid and writable; `shm` must be null or a valid moved
/// mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_shm_mut(
    this_: *mut z_owned_bytes_t,
    shm: *mut z_moved_shm_mut_t,
) -> ZResult {
    // The two moved types have identical layout and identical handle contents,
    // so the mutable spelling is the immutable one with a cast rather than a
    // second copy of the body.
    // SAFETY: the caller's contract, delegated.
    unsafe { z_bytes_from_shm(this_, shm as *mut z_moved_shm_t) }
}

/// Try to view a payload as an immutable SHM buffer (zenoh-c
/// `z_bytes_as_loaned_shm`, `zenoh_commons.h:1452-1453`).
///
/// `Z_OK` with `*dst` the buffer when the payload IS a chunk of shared memory: one a peer
/// sent, which a session that negotiated shared memory delivers as a range of the
/// mapped chunk and not as a copy (R3052), or one this side built from a buffer of its
/// own provider ([`z_bytes_from_shm`] keeps it, R3059). Every other payload is `Z_EINVAL`
/// with `*dst` left NULL.
///
/// # Safety
/// `this_` must be null or a valid loaned payload; `dst` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_as_loaned_shm(
    this_: *const z_loaned_bytes_t,
    dst: *mut *const z_loaned_shm_t,
) -> ZResult {
    guarded(|| {
        if !dst.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = std::ptr::null() };
        }
        // Dereferenced so a gravestone payload is distinguished from a live one
        // that merely carries no SHM: a function that ignored its argument would
        // give the same answer for a null pointer.
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { crate::bytes::bytes_state(this_) }) else {
            return Z_ENULL;
        };
        match received_shm(state) {
            Some(loan) => {
                if !dst.is_null() {
                    // SAFETY: the caller's contract.
                    unsafe { *dst = loan as *const z_loaned_shm_t };
                }
                Z_OK
            }
            None => Z_EINVAL,
        }
    })
}

/// Take an OWNED immutable SHM buffer out of a payload (zenoh-c
/// `z_bytes_to_owned_shm`).
///
/// The owned twin of [`z_bytes_as_loaned_shm`], and it answers the same question the
/// same way: `Z_OK` with an owned, immutable buffer that is a second reference to the
/// chunk when the payload is a chunk of shared memory a peer sent, `Z_EINVAL` with
/// `*dst` a gravestone when it is not (R3052).
///
/// # Safety
/// `this_` must be null or a valid loaned payload; `dst` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_owned_shm(
    this_: *const z_loaned_bytes_t,
    dst: *mut z_owned_shm_t,
) -> ZResult {
    guarded(|| {
        if !dst.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = z_owned_shm_t::null_value() };
        }
        // Dereferenced for the reason `z_bytes_as_loaned_shm` gives: a function
        // that ignored its argument would answer the same for a null pointer,
        // and then the refusal would say nothing about the payload.
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { crate::bytes::bytes_state(this_) }) else {
            return Z_ENULL;
        };
        // A payload that is not a chunk of shared memory has no buffer to take.
        let Some(lent) = received_shm(state) else {
            return Z_EINVAL;
        };
        if dst.is_null() {
            return Z_OK;
        }
        // A second reference to a chunk the payload still holds: it shares the holders of
        // the buffer the payload lends, so the two count as two and neither is writable
        // until the other is dropped, which is upstream's owned conversion.
        // SAFETY: `received_shm` answers a loan whose handle is a live `Box<ShmChunk>` of
        // the payload's own, that the payload keeps alive.
        let Some(lent) = (unsafe { chunk((*lent).handle) }) else {
            return Z_EINVAL;
        };
        // SAFETY: `dst` was checked non-null above.
        unsafe { *dst = z_owned_shm_t::from_handle(Box::into_raw(lent.shared()) as Handle) };
        Z_OK
    })
}

/// Try to view a payload as a MUTABLE SHM buffer (zenoh-c
/// `z_bytes_as_mut_loaned_shm`, `zenoh_commons.h:1464-1465`).
///
/// `Z_OK` for every payload that is a chunk of shared memory, as for
/// [`z_bytes_as_loaned_shm`]; whether the buffer may then be WRITTEN is the next
/// question, which [`z_shm_try_reloan_mut`] answers (`z_sub_shm.c` asks it to print
/// `SHM (MUT)` or `SHM (IMMUT)`).
///
/// # Safety
/// As [`z_bytes_as_loaned_shm`].
#[no_mangle]
pub unsafe extern "C" fn z_bytes_as_mut_loaned_shm(
    this_: *mut z_loaned_bytes_t,
    dst: *mut *mut z_loaned_shm_t,
) -> ZResult {
    guarded(|| {
        if !dst.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = std::ptr::null_mut() };
        }
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { crate::bytes::bytes_state(this_ as *const z_loaned_bytes_t) })
        else {
            return Z_ENULL;
        };
        match received_shm(state) {
            Some(loan) => {
                if !dst.is_null() {
                    // SAFETY: the caller's contract.
                    unsafe { *dst = loan };
                }
                Z_OK
            }
            None => Z_EINVAL,
        }
    })
}

// ---------------------------------------------------------------------------
// the C-SUPPLIED BACKEND — R2289 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// Everything above answers "wz owns a segment and hands pieces of it out". This
// section answers the other half of upstream's provider surface: a C program
// supplies the allocator, and zenoh-c calls INTO it. The plane is taken whole
// rather than a verb at a time, for R2259's reason — the value types
// (`z_ptr_in_segment_t`, `z_chunk_alloc_result_t`) exist ONLY to cross the
// callback boundary, so shipping them without `z_shm_provider_new` would leave
// a header promising a link that goes nowhere.
//
// What the plane is, and why these twenty symbols are one thing:
//
//   * `zc_context_t` / `zc_threadsafe_context_t` — the C-owned state every
//     callback is handed back, with the destructor wz owes it. NOT symbols;
//     they are the reason the rest could not be built before.
//   * `z_ptr_in_segment_*` (6) — a pointer plus the segment context that keeps
//     it valid. Upstream's is `(*mut u8, Arc<dyn Segment>)`, so a clone SHARES
//     the segment and the destructor fires once; wz's is the same shape.
//   * `z_chunk_alloc_result_*` (5) — what `alloc_fn` writes: an allocated chunk
//     or an alloc error. The one type the callback returns.
//   * `z_shm_provider_new` / `_threadsafe_new` / `_map` (3) — install a backend,
//     and hand a chunk it allocated back as a buffer.
//   * `z_posix_shm_provider_new` / `_with_layout_new` (2) — upstream's named
//     spellings of the BUILT-IN backend, the second sized by a memory layout.
//   * the four `_async` spellings — the only place the threadsafe / not
//     distinction is OBSERVABLE, which is why they are in this round and not a
//     later one. Without them `z_shm_provider_new` and
//     `z_shm_provider_threadsafe_new` would differ only in a flag nothing reads,
//     and a stored-but-unread flag is a dead arm.
//
// ⚠ THREE named divergences from upstream, each of them a deliberate strictening
// rather than a shortcut, and each witnessed by a test in `foreign_backend_tests`:
//
//   1. wz gravestones the `z_owned_chunk_alloc_result_t` BEFORE calling
//      `alloc_fn`. Upstream passes `MaybeUninit` and calls `assume_init()`, so a
//      callback that writes nothing has it reading uninitialised memory; here it
//      reads a gravestone and the allocation fails cleanly.
//   2. A BLOCKING allocation against a provider that has NOTHING outstanding
//      fails instead of waiting. Upstream's `BlockOn` waits for a buffer release
//      that, with no live buffer, can never come — a deadlock rather than a
//      wait. The provider keeps the busy list that makes the difference sayable,
//      and the runtime documents this as the only place its `BlockOn` differs.
//   3. The `_async` spellings CLONE the provider (an `Arc` bump) rather than
//      requiring the `&'static` upstream's signature demands, so a caller that
//      drops the provider handle while the allocation is in flight is not a
//      use-after-free.

/// zenoh-c `z_segment_id_t` (`zenoh_opaque.h:290`).
pub type z_segment_id_t = u32;
/// zenoh-c `z_chunk_id_t` (`zenoh_opaque.h:297`).
pub type z_chunk_id_t = u32;
/// zenoh-c `z_protocol_id_t` (`zenoh_opaque.h:910`).
pub type z_protocol_id_t = u32;

/// zenoh-c `zc_context_t` (`zenoh_opaque.h:975-978`) — a C-owned pointer and the
/// destructor wz must run for it.
///
/// The NON-thread-safe spelling: upstream's own header promises that callbacks
/// sharing one instance are never executed concurrently, which is why
/// [`ForeignBackend`] serialises them.
#[repr(C)]
pub struct zc_context_t {
    /// The caller's state, handed back to every callback.
    pub context: *mut c_void,
    /// Run once, when the last holder of this context drops.
    pub delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// zenoh-c `zc_threadsafe_context_data_t` (`zenoh_opaque.h:157-159`).
///
/// A one-field struct rather than a bare pointer because upstream nests it, and
/// the nesting is what makes `zc_threadsafe_context_t` a different C type from
/// `zc_context_t` at the same size.
#[repr(C)]
pub struct zc_threadsafe_context_data_t {
    /// The caller's state.
    pub ptr: *mut c_void,
}

/// zenoh-c `zc_threadsafe_context_t` (`zenoh_opaque.h:177-180`).
///
/// The caller PROMISES the associated callbacks are thread-safe, and that
/// promise is the only difference between [`z_shm_provider_new`] and
/// [`z_shm_provider_threadsafe_new`] — see [`Provider::is_threadsafe`] for what
/// reads it.
#[repr(C)]
pub struct zc_threadsafe_context_t {
    /// The caller's state.
    pub context: zc_threadsafe_context_data_t,
    /// Run once, when the last holder of this context drops.
    pub delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// zenoh-c `z_chunk_descriptor_t` (`zenoh_opaque.h`) — how a backend NAMES one
/// of its chunks.
///
/// `free_fn` is handed this rather than the pointer, so it is the part a chunk
/// must carry for its whole life.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_chunk_descriptor_t {
    /// Which of the backend's segments.
    pub segment: z_segment_id_t,
    /// Which chunk within it.
    pub chunk: z_chunk_id_t,
    /// The chunk's capacity in bytes.
    pub len: usize,
}

/// zenoh-c `z_allocated_chunk_t` (`zenoh_opaque.h:322-325`).
///
/// ⚠ `descriptpr` is upstream's spelling, typo and all. It is kept because a
/// reader diffing this file against `zenoh_opaque.h` must see the same field
/// name; the name crosses no ABI boundary, so correcting it here would buy
/// nothing and cost that.
#[repr(C)]
pub struct z_allocated_chunk_t {
    /// How the backend names this chunk.
    pub descriptpr: z_chunk_descriptor_t,
    /// The pointer, MOVED: taking a chunk gravestones the caller's value.
    pub ptr: *mut z_moved_ptr_in_segment_t,
}

/// zenoh-c `zc_shm_provider_backend_callbacks_t` — the whole allocator, as six
/// function pointers.
///
/// Mirrored field for field and in upstream's order: this struct is passed BY
/// VALUE across the ABI, so a reordering here is a wild call rather than a
/// compile error. `wz_capi_c_layout` carries its footprint for that reason.
#[repr(C)]
pub struct zc_shm_provider_backend_callbacks_t {
    /// Allocate for `layout`, writing an owned result.
    pub alloc_fn: Option<
        unsafe extern "C" fn(
            *mut z_owned_chunk_alloc_result_t,
            *const z_loaned_memory_layout_t,
            *mut c_void,
        ),
    >,
    /// Release a chunk this backend allocated.
    pub free_fn: Option<unsafe extern "C" fn(*const z_chunk_descriptor_t, *mut c_void)>,
    /// Defragment, reporting what that made reachable.
    pub defragment_fn: Option<unsafe extern "C" fn(*mut c_void) -> usize>,
    /// Bytes still allocatable.
    pub available_fn: Option<unsafe extern "C" fn(*mut c_void) -> usize>,
    /// Adjust a layout in place to one this backend can serve.
    pub layout_for_fn: Option<unsafe extern "C" fn(*mut z_owned_memory_layout_t, *mut c_void)>,
    /// This backend's SHM protocol id.
    pub id_fn: Option<unsafe extern "C" fn(*mut c_void) -> z_protocol_id_t>,
}

/// zenoh-c `z_owned_ptr_in_segment_t` (`zenoh_opaque.h:314-316`): 24 bytes at
/// align 8 — upstream stores a pointer plus a fat `Arc<dyn Segment>`.
const PTR_IN_SEGMENT_SIZE: usize = 24;

define_shm_opaque!(
    z_owned_ptr_in_segment_t,
    z_loaned_ptr_in_segment_t,
    z_moved_ptr_in_segment_t,
    PTR_IN_SEGMENT_SIZE
);

/// zenoh-c `z_owned_chunk_alloc_result_t` (`zenoh_opaque.h`): 48 bytes at
/// align 8.
const CHUNK_ALLOC_RESULT_SIZE: usize = 48;

define_shm_opaque!(
    z_owned_chunk_alloc_result_t,
    z_moved_chunk_alloc_result_t,
    CHUNK_ALLOC_RESULT_SIZE
);

/// A C-owned context and the destructor wz owes it.
///
/// One type for both spellings: `zc_context_t` and `zc_threadsafe_context_t`
/// differ in what the CALLER promises, not in what wz has to store, and the
/// promise is recorded separately (see [`ForeignBackend::threadsafe`]) so this
/// stays one destructor and one place that runs it.
struct DroppableContext {
    ptr: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Drop for DroppableContext {
    fn drop(&mut self) {
        if let Some(delete_fn) = self.delete_fn {
            // SAFETY: the caller handed this pair over together and upstream's
            // header states the contract — `delete_fn` runs once, after the last
            // associated callback returns. Holding the context behind an `Arc`
            // is what makes "the last" well defined here.
            unsafe { delete_fn(self.ptr) };
        }
    }
}

// SAFETY: the pointer is opaque to wz; it is only ever handed back to the
// caller's own callbacks. Whether those may run on another thread is the
// caller's promise, recorded in `ForeignBackend::threadsafe` and enforced there
// by serialising when the promise was not made.
unsafe impl Send for DroppableContext {}
// SAFETY: as above.
unsafe impl Sync for DroppableContext {}

/// What an owned `z_owned_ptr_in_segment_t`'s handle points at.
///
/// The context is `Arc`-shared, which is the whole content of
/// [`z_ptr_in_segment_clone`] being a SHALLOW copy: two pointers into one
/// segment, and the segment released once when the second of them goes.
struct PtrInSegment {
    ptr: *mut u8,
    /// Kept for its `Drop`, not for reading.
    _segment: Arc<DroppableContext>,
}

impl PtrInSegment {
    /// A shallow copy: the same address, one more owner of the segment.
    fn shallow_clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            _segment: self._segment.clone(),
        }
    }
}

/// What an owned `z_owned_chunk_alloc_result_t`'s handle points at: upstream's
/// `Result<AllocatedChunk, ZAllocError>`.
enum ChunkAllocResult {
    /// The backend allocated a chunk.
    Ok {
        descriptor: z_chunk_descriptor_t,
        ptr: PtrInSegment,
    },
    /// The backend could not, and said why.
    Err(z_alloc_error_t),
}

/// A backend the C caller supplied, as a backend of the runtime's provider.
///
/// R3058 -- this used to be a second allocator of this crate's own, with its own
/// blocking loop, its own count of live chunks and its own condition variable, beside the
/// built-in one. It is the runtime's backend trait now, so a C program's chunks are
/// issued, watched, held and collected by the same provider as the built-in pool's, and
/// what a callback has to do is the six things upstream's `DynamicShmProviderBackend`
/// does (`zenoh-c/src/shm/provider/shm_provider_backend.rs` @
/// `pub struct DynamicShmProviderBackend<TContext>`): allocate, free, defragment, report
/// what is available, adapt a layout, and name its protocol.
struct ForeignBackend {
    context: Arc<DroppableContext>,
    callbacks: zc_shm_provider_backend_callbacks_t,
    /// `true` when the caller used [`z_shm_provider_threadsafe_new`].
    threadsafe: bool,
    /// Held across every callback when `threadsafe` is false.
    ///
    /// Upstream keeps the same promise a different way — its non-threadsafe
    /// provider is `!Sync`, so RUST cannot share it — which does not reach a C
    /// caller with two threads and one `z_loaned_shm_provider_t`. wz's callbacks
    /// are reachable from C on any thread, so the promise the header prints is
    /// kept here by holding this.
    serialise: Mutex<()>,
}

impl ForeignBackend {
    /// Run `f` with the caller's context pointer, serialised when the caller did
    /// not promise thread safety.
    fn with_context<T>(&self, f: impl FnOnce(*mut c_void) -> T) -> T {
        if self.threadsafe {
            f(self.context.ptr)
        } else {
            let _guard = self.serialise.lock().unwrap_or_else(|e| e.into_inner());
            f(self.context.ptr)
        }
    }
}

impl wz_runtime_tokio::shm_backend::ShmProviderBackend for ForeignBackend {
    /// `id_fn`, the protocol every chunk of this backend carries in its header and so the
    /// client a receiver reads it through. A backend with no `id_fn` cannot be a valid C
    /// struct (upstream's field is not optional), and answers `0` -- which is the POSIX
    /// protocol, so it is also refused at allocation (see `alloc`).
    fn id(&self) -> wz_runtime_tokio::shm_backend::ProtocolId {
        match self.callbacks.id_fn {
            // SAFETY: `ctx` is the caller's own pointer.
            Some(f) => self.with_context(|ctx| unsafe { f(ctx) }),
            None => 0,
        }
    }

    /// One call into `alloc_fn`, with the result decoded.
    fn alloc(
        &self,
        layout: &wz_runtime_tokio::shm_backend::MemoryLayout,
    ) -> Result<
        wz_runtime_tokio::shm_backend::AllocatedChunk,
        wz_runtime_tokio::shm_backend::AllocError,
    > {
        use wz_runtime_tokio::shm_backend::{
            AllocError, AllocatedChunk, ChunkDescriptor, PtrInSegment as RuntimePtr,
        };
        let (Some(alloc_fn), Some(_)) = (self.callbacks.alloc_fn, self.callbacks.id_fn) else {
            return Err(AllocError::Other);
        };
        let size = layout.size().get();
        let layout_handle =
            z_owned_memory_layout_t::from_handle(Box::into_raw(Box::new(MemoryLayoutState {
                size,
                alignment: z_alloc_alignment_t {
                    pow: layout.alignment().pow(),
                },
            })) as Handle);
        // Divergence 1: a GRAVESTONE, not `MaybeUninit`. A callback that writes
        // nothing then leaves a readable "no result" rather than whatever was on
        // the stack.
        let mut out = z_owned_chunk_alloc_result_t::null_value();
        self.with_context(|ctx| {
            // SAFETY: `out` and `layout_handle` are live locals this frame owns, and
            // `ctx` is the caller's own pointer.
            unsafe {
                alloc_fn(
                    &mut out,
                    &layout_handle as *const z_owned_memory_layout_t
                        as *const z_loaned_memory_layout_t,
                    ctx,
                )
            }
        });
        let mut moved_layout = z_moved_memory_layout_t {
            _this: layout_handle,
        };
        // SAFETY: dropped exactly once; the callback borrowed it and does not
        // own it, which is what `_loaned_` says.
        unsafe { z_memory_layout_drop(&mut moved_layout) };

        let handle = out.handle;
        out = z_owned_chunk_alloc_result_t::null_value();
        let _ = out;
        if handle.is_null() {
            return Err(AllocError::Other);
        }
        // SAFETY: a live `Box<ChunkAllocResult>` minted by this module's own
        // constructors, which are the only way a callback can fill this out.
        let result = unsafe { Box::from_raw(handle as *mut ChunkAllocResult) };
        let (descriptor, ptr) = match *result {
            ChunkAllocResult::Ok { descriptor, ptr } => (descriptor, ptr),
            ChunkAllocResult::Err(reason) => {
                return Err(match reason {
                    Z_ALLOC_ERROR_NEED_DEFRAGMENT => AllocError::NeedDefragment,
                    Z_ALLOC_ERROR_OUT_OF_MEMORY => AllocError::OutOfMemory,
                    _ => AllocError::Other,
                })
            }
        };
        let described = std::num::NonZeroUsize::new(descriptor.len);
        let Some(len) = described.filter(|len| len.get() >= size && !ptr.ptr.is_null()) else {
            // The backend said OK and delivered less than was asked for, or
            // nothing. Reported rather than trusted: the buffer plane hands this
            // pointer and length straight to the caller.
            self.free_descriptor(&descriptor);
            return Err(AllocError::Other);
        };
        Ok(AllocatedChunk {
            descriptor: ChunkDescriptor {
                segment: descriptor.segment,
                chunk: descriptor.chunk,
                len,
            },
            data: RuntimePtr::new(ptr.ptr, ptr._segment),
        })
    }

    /// Hand a chunk back to the backend that issued it.
    fn free(&self, chunk: &wz_runtime_tokio::shm_backend::ChunkDescriptor) {
        self.free_descriptor(&z_chunk_descriptor_t {
            segment: chunk.segment,
            chunk: chunk.chunk,
            len: chunk.len.get(),
        });
    }

    /// `defragment_fn`, or 0 when the caller supplied none.
    fn defragment(&self) -> usize {
        match self.callbacks.defragment_fn {
            // SAFETY: `ctx` is the caller's own pointer.
            Some(f) => self.with_context(|ctx| unsafe { f(ctx) }),
            None => 0,
        }
    }

    /// `available_fn`, or 0 when the caller supplied none.
    fn available(&self) -> usize {
        match self.callbacks.available_fn {
            // SAFETY: `ctx` is the caller's own pointer.
            Some(f) => self.with_context(|ctx| unsafe { f(ctx) }),
            None => 0,
        }
    }

    /// `layout_for_fn`: the callback adapts the layout in place, and drops it to refuse
    /// (`zenoh-c/src/shm/provider/shm_provider_backend.rs` @
    /// `layout.ok_or(ZLayoutError::ProviderIncompatibleLayout)`). A backend without one
    /// serves the layout as it is.
    fn layout_for(
        &self,
        layout: wz_runtime_tokio::shm_backend::MemoryLayout,
    ) -> Result<
        wz_runtime_tokio::shm_backend::MemoryLayout,
        wz_runtime_tokio::shm_backend::LayoutError,
    > {
        use wz_runtime_tokio::shm_backend::{AllocAlignment, LayoutError, MemoryLayout};
        let Some(layout_for_fn) = self.callbacks.layout_for_fn else {
            return Ok(layout);
        };
        let mut owned =
            z_owned_memory_layout_t::from_handle(Box::into_raw(Box::new(MemoryLayoutState {
                size: layout.size().get(),
                alignment: z_alloc_alignment_t {
                    pow: layout.alignment().pow(),
                },
            })) as Handle);
        // SAFETY: `owned` is a live local this frame owns and `ctx` is the caller's own
        // pointer.
        self.with_context(|ctx| unsafe { layout_for_fn(&mut owned, ctx) });
        if owned.handle.is_null() {
            // The callback dropped the layout: it will not serve this one.
            return Err(LayoutError::ProviderIncompatibleLayout);
        }
        // SAFETY: a live `Box<MemoryLayoutState>` this module minted, taken back exactly
        // once.
        let state = unsafe { Box::from_raw(owned.handle as *mut MemoryLayoutState) };
        AllocAlignment::new(state.alignment.pow)
            .and_then(|alignment| MemoryLayout::new(state.size, alignment))
            .map_err(|_| LayoutError::ProviderIncompatibleLayout)
    }
}

impl ForeignBackend {
    /// `free_fn` on a descriptor, or nothing when the caller supplied none.
    fn free_descriptor(&self, descriptor: &z_chunk_descriptor_t) {
        if let Some(free_fn) = self.callbacks.free_fn {
            // SAFETY: the descriptor is a live borrow and `ctx` the caller's own pointer.
            self.with_context(|ctx| unsafe { free_fn(descriptor, ctx) });
        }
    }
}

/// Borrow the state behind a loaned pointer-in-segment.
///
/// # Safety
/// `this_` must be null or a live loaned value whose handle this crate minted.
#[inline]
unsafe fn ptr_in_segment<'a>(this_: *const z_loaned_ptr_in_segment_t) -> Option<&'a PtrInSegment> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<PtrInSegment>` this module leaked.
    Some(unsafe { &*(handle as *const PtrInSegment) })
}

/// Construct a pointer in an SHM segment (zenoh-c `z_ptr_in_segment_new`,
/// `zenoh_commons.h:4911-4915`). The context is CONSUMED.
///
/// # Safety
/// `this_` must be null or writable. `ptr` is the caller's, and `segment` names
/// state whose `delete_fn` wz runs once the last copy of this value is gone.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_new(
    this_: *mut z_owned_ptr_in_segment_t,
    ptr: *mut u8,
    segment: zc_threadsafe_context_t,
) {
    let context = Arc::new(DroppableContext {
        ptr: segment.context.ptr,
        delete_fn: segment.delete_fn,
    });
    guard_val((), || {
        if this_.is_null() {
            // The context is still consumed — it was passed by value, so
            // returning without dropping it would leak the caller's state with
            // no way to reach it again.
            return;
        }
        let state = PtrInSegment {
            ptr,
            _segment: context,
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ = z_owned_ptr_in_segment_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
    });
}

/// Zero an owned pointer-in-segment (zenoh-c
/// `z_internal_ptr_in_segment_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_ptr_in_segment_null(this_: *mut z_owned_ptr_in_segment_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_ptr_in_segment_t::null_value() };
    }
}

/// `true` iff the value holds a live pointer (zenoh-c
/// `z_internal_ptr_in_segment_check`).
///
/// # Safety
/// `this_` must be null or a valid owned value.
#[no_mangle]
pub unsafe extern "C" fn z_internal_ptr_in_segment_check(
    this_: *const z_owned_ptr_in_segment_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Borrow a pointer-in-segment (zenoh-c `z_ptr_in_segment_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_loan(
    this_: *const z_owned_ptr_in_segment_t,
) -> *const z_loaned_ptr_in_segment_t {
    this_ as *const z_loaned_ptr_in_segment_t
}

/// SHALLOW-copy a pointer-in-segment (zenoh-c `z_ptr_in_segment_clone`).
///
/// The copy is the SAME address with one more owner of the segment, which is
/// what upstream's `Arc<dyn Segment>` gives and what makes the destructor fire
/// exactly once however many copies were taken.
///
/// # Safety
/// `out` must be null or writable; `this_` null or a valid loaned value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_clone(
    out: *mut z_owned_ptr_in_segment_t,
    this_: *const z_loaned_ptr_in_segment_t,
) {
    guard_val((), || {
        if out.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = z_owned_ptr_in_segment_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(source) = (unsafe { ptr_in_segment(this_) }) else {
            return;
        };
        let copy = source.shallow_clone();
        // SAFETY: `out` was checked non-null above.
        unsafe {
            *out = z_owned_ptr_in_segment_t::from_handle(Box::into_raw(Box::new(copy)) as Handle)
        };
    });
}

/// Drop a pointer-in-segment (zenoh-c `z_ptr_in_segment_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_drop(this_: *mut z_moved_ptr_in_segment_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<PtrInSegment>` this module leaked.
            drop(unsafe { Box::from_raw(handle as *mut PtrInSegment) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_ptr_in_segment_t::null_value() };
        }
        Z_OK
    });
}

/// Take the pointer out of a moved value, leaving a gravestone.
///
/// Shared by [`z_chunk_alloc_result_new_ok`] and [`z_shm_provider_map`], which
/// are the two places upstream's `z_allocated_chunk_t` is consumed.
///
/// # Safety
/// `this_` must be null or a valid moved value.
unsafe fn take_ptr_in_segment(this_: *mut z_moved_ptr_in_segment_t) -> Option<PtrInSegment> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    unsafe { (*this_)._this = z_owned_ptr_in_segment_t::null_value() };
    // SAFETY: a live `Box<PtrInSegment>` this module leaked.
    Some(*unsafe { Box::from_raw(handle as *mut PtrInSegment) })
}

/// Report a successful backend allocation (zenoh-c
/// `z_chunk_alloc_result_new_ok`). The chunk's pointer is CONSUMED.
///
/// # Safety
/// `this_` must be null or writable, and `allocated_chunk.ptr` null or a valid
/// moved pointer-in-segment.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_new_ok(
    this_: *mut z_owned_chunk_alloc_result_t,
    allocated_chunk: z_allocated_chunk_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(ptr) = (unsafe { take_ptr_in_segment(allocated_chunk.ptr) }) else {
            // A chunk with no pointer is not a chunk. Refused HERE rather than
            // at the allocation that would use it, which could not say what was
            // wrong.
            if !this_.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *this_ = z_owned_chunk_alloc_result_t::null_value() };
            }
            return Z_EINVAL;
        };
        if this_.is_null() {
            return Z_ENULL;
        }
        let state = ChunkAllocResult::Ok {
            descriptor: allocated_chunk.descriptpr,
            ptr,
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ =
                z_owned_chunk_alloc_result_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
        Z_OK
    })
}

/// Report a failed backend allocation (zenoh-c
/// `z_chunk_alloc_result_new_error`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_new_error(
    this_: *mut z_owned_chunk_alloc_result_t,
    alloc_error: z_alloc_error_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let state = ChunkAllocResult::Err(alloc_error);
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ =
                z_owned_chunk_alloc_result_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
    });
}

/// Zero an owned chunk-alloc result (zenoh-c
/// `z_internal_chunk_alloc_result_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_chunk_alloc_result_null(
    this_: *mut z_owned_chunk_alloc_result_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_chunk_alloc_result_t::null_value() };
    }
}

/// `true` iff the result holds an outcome (zenoh-c
/// `z_internal_chunk_alloc_result_check`).
///
/// # Safety
/// `this_` must be null or a valid owned result.
#[no_mangle]
pub unsafe extern "C" fn z_internal_chunk_alloc_result_check(
    this_: *const z_owned_chunk_alloc_result_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Drop a chunk-alloc result (zenoh-c `z_chunk_alloc_result_drop`).
///
/// ⚠ Dropping an `Ok` result drops the pointer-in-segment it holds, which
/// releases that segment's context if this was the last copy. It does NOT call
/// the backend's `free_fn`: the chunk was never handed to a provider, so nothing
/// took ownership of it.
///
/// # Safety
/// `this_` must be null or a valid moved result.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_drop(this_: *mut z_moved_chunk_alloc_result_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ChunkAllocResult>` this module leaked.
            drop(unsafe { Box::from_raw(handle as *mut ChunkAllocResult) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_chunk_alloc_result_t::null_value() };
        }
        Z_OK
    });
}

/// Install a C-supplied backend (zenoh-c `z_shm_provider_new`,
/// `zenoh_commons.h:6134-6137`). The context is CONSUMED.
///
/// The callbacks are SERIALISED — see [`ForeignBackend::serialise`] for why that
/// is what upstream's header promises rather than a wz addition.
///
/// # Safety
/// `this_` must be null or writable; the callbacks must be valid for as long as
/// any buffer from this provider is alive.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_new(
    this_: *mut z_owned_shm_provider_t,
    context: zc_context_t,
    callbacks: zc_shm_provider_backend_callbacks_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { foreign_provider_new(this_, context.context, context.delete_fn, callbacks, false) };
}

/// Install a C-supplied backend whose callbacks the caller promises are
/// thread-safe (zenoh-c `z_shm_provider_threadsafe_new`). The context is
/// CONSUMED.
///
/// The promise is what the `_async` spellings require: a provider built here
/// accepts [`z_shm_provider_alloc_gc_defrag_async`], one built by
/// [`z_shm_provider_new`] refuses it with `Z_EINVAL`.
///
/// # Safety
/// As [`z_shm_provider_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_threadsafe_new(
    this_: *mut z_owned_shm_provider_t,
    context: zc_threadsafe_context_t,
    callbacks: zc_shm_provider_backend_callbacks_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        foreign_provider_new(
            this_,
            context.context.ptr,
            context.delete_fn,
            callbacks,
            true,
        )
    };
}

/// The shared body of the two foreign-backend constructors.
///
/// # Safety
/// As [`z_shm_provider_new`].
unsafe fn foreign_provider_new(
    this_: *mut z_owned_shm_provider_t,
    context: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
    callbacks: zc_shm_provider_backend_callbacks_t,
    threadsafe: bool,
) {
    let backend = Arc::new(ForeignBackend {
        context: Arc::new(DroppableContext {
            ptr: context,
            delete_fn,
        }),
        callbacks,
        threadsafe,
        serialise: Mutex::new(()),
    });
    guard_val((), || {
        if this_.is_null() {
            // The context is consumed either way — `backend` drops here and its
            // `delete_fn` runs, rather than leaking state the caller can no
            // longer reach.
            return;
        }
        let provider = Provider {
            shm: wz_runtime_tokio::shm_provider::ShmProvider::new(backend),
            threadsafe,
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_provider_t::from_handle(provider_handle(provider)) };
    });
}

/// Create a provider on the built-in POSIX backend (zenoh-c
/// `z_posix_shm_provider_new`, `zenoh_commons.h:4792-4793`).
///
/// Identical to [`z_shm_provider_default_new`] here, and upstream agrees: its
/// `default_backend` IS the POSIX one, and both constructors produce the same
/// `CSHMProvider::Posix` arm. The two names exist because upstream's default may
/// one day not be POSIX, and a program that needs the POSIX one specifically can
/// say so.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_posix_shm_provider_new(
    this_: *mut z_owned_shm_provider_t,
    size: usize,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_shm_provider_default_new(this_, size) }
}

/// Create a POSIX-backend provider sized and ALIGNED by a memory layout
/// (zenoh-c `z_posix_shm_provider_with_layout_new`).
///
/// The layout's alignment reaches the segment's BASE, not just the offsets
/// inside it — the R2264 finding, applied to the one constructor that lets a
/// caller ask for more than a page.
///
/// # Safety
/// `this_` must be valid and writable; `layout` null or a valid loaned layout.
#[no_mangle]
pub unsafe extern "C" fn z_posix_shm_provider_with_layout_new(
    this_: *mut z_owned_shm_provider_t,
    layout: *const z_loaned_memory_layout_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { memory_layout_state(layout) }) else {
            return Z_ENULL;
        };
        use wz_runtime_tokio::shm_backend::{AllocAlignment, MemoryLayout};
        // The layout is the pool's size AND the alignment every chunk of it is freed at
        // and every request is extended to, which is what makes a provider built here
        // serve an aligned request a default provider refuses.
        let built = AllocAlignment::new(state.alignment.pow)
            .and_then(|alignment| MemoryLayout::new(state.size, alignment))
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|layout| Provider::pool(&layout));
        let Ok(provider) = built else {
            return Z_EINVAL;
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_provider_t::from_handle(provider_handle(provider)) };
        Z_OK
    })
}

/// Hand a chunk the BACKEND allocated back as a buffer (zenoh-c
/// `z_shm_provider_map`). The chunk's pointer is CONSUMED.
///
/// Served by EVERY provider, as upstream's is (`zenoh-c/src/shm/provider/shm_provider_impl.rs` @
/// `super::shm_provider::CSHMProvider::Posix(provider) => provider.map(chunk, len),`). R3058
/// corrects the earlier note that said a built-in provider refuses it because "upstream
/// refuses the same call": it does not. What the built-in pool adds is a check upstream's
/// has not: the chunk must lie in the pool's own segment, at the address its offset names,
/// because the provider will hand the range back to its allocator when it collects, and an
/// allocator given a range it never issued corrupts itself.
///
/// # Safety
/// `out_result` must be null or writable; `provider` null or a valid loaned
/// provider; `allocated_chunk.ptr` null or a valid moved pointer-in-segment.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_map(
    out_result: *mut z_owned_shm_mut_t,
    provider: *const z_loaned_shm_provider_t,
    allocated_chunk: z_allocated_chunk_t,
    len: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract. Taken FIRST and unconditionally: the
        // chunk was passed by value, so every exit below owns it.
        let ptr = unsafe { take_ptr_in_segment(allocated_chunk.ptr) };
        if !out_result.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_result = z_owned_shm_mut_t::null_value() };
        }
        let Some(ptr) = ptr else {
            return Z_EINVAL;
        };
        if out_result.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(backend) = (unsafe { provider_of(provider) }) else {
            return Z_EINVAL;
        };
        let descriptor = allocated_chunk.descriptpr;
        let Some(described) = std::num::NonZeroUsize::new(descriptor.len) else {
            return Z_EINVAL;
        };
        if ptr.ptr.is_null() || len == 0 || len > descriptor.len {
            return Z_EINVAL;
        }
        let chunk = wz_runtime_tokio::shm_backend::AllocatedChunk {
            descriptor: wz_runtime_tokio::shm_backend::ChunkDescriptor {
                segment: descriptor.segment,
                chunk: descriptor.chunk,
                len: described,
            },
            data: wz_runtime_tokio::shm_backend::PtrInSegment::new(ptr.ptr, ptr._segment),
        };
        match backend.shm.map(chunk, len) {
            Ok(payload) => {
                let chunk = ShmChunk::issued(payload);
                // SAFETY: `out_result` was checked non-null above.
                unsafe {
                    *out_result = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle)
                };
                Z_OK
            }
            Err(_) => Z_EINVAL,
        }
    })
}

/// A raw pointer an allocation thread carries.
///
/// The C caller owns the storage and upstream's signature says so with
/// `&'static mut`; wz cannot express that through a raw pointer, so the promise
/// is restated here and the wrapper is what lets the pointer cross the spawn.
struct AsyncOut<T>(*mut T);
// SAFETY: the C caller promised the storage outlives the callback, which is the
// same contract upstream's `&'static mut` states. wz adds nothing to it and
// takes nothing away.
unsafe impl<T> Send for AsyncOut<T> {}

/// The caller's result context, carried to the allocation thread.
struct AsyncContext {
    ptr: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}
// SAFETY: the caller used the THREADSAFE context spelling, which is exactly the
// promise that its state may be touched from another thread.
unsafe impl Send for AsyncContext {}

impl Drop for AsyncContext {
    fn drop(&mut self) {
        if let Some(delete_fn) = self.delete_fn {
            // SAFETY: run once, after the result callback has returned.
            unsafe { delete_fn(self.ptr) };
        }
    }
}

/// The shared body of the two provider `_async` spellings.
///
/// # Safety
/// `out_result` must outlive the callback; `provider` null or a valid loaned
/// provider.
unsafe fn provider_alloc_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    result_context: AsyncContext,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    guarded(|| {
        if out_result.is_null() || result_callback.is_none() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(backend) = (unsafe { provider_of(provider) }) else {
            return Z_ENULL;
        };
        if !backend.is_threadsafe() {
            // Upstream's own answer for a non-threadsafe provider, and the only
            // place the two constructors differ observably.
            return Z_EINVAL;
        }
        // Divergence 3: the BACKEND is cloned, so the caller may drop the
        // provider handle while this is in flight.
        let backend = backend.clone();
        let out = AsyncOut(out_result);
        let callback = result_callback;
        std::thread::spawn(move || {
            let out = out;
            let context = result_context;
            let mut wide = z_buf_layout_alloc_result_t {
                status: ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR,
                buf: z_owned_shm_mut_t::null_value(),
                alloc_error: Z_ALLOC_ERROR_OTHER,
                layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
            };
            match backend.alloc(size, alignment, &policy::gc_defrag_blocking()) {
                Ok(chunk) => {
                    wide.status = ZC_BUF_LAYOUT_ALLOC_STATUS_OK;
                    wide.buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                }
                Err(AllocFailure::Alloc(reason)) => wide.alloc_error = reason,
                Err(AllocFailure::Layout(reason)) => {
                    wide.status = ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR;
                    wide.layout_error = reason;
                }
            }
            // SAFETY: the caller's storage, which outlives this callback by the
            // contract restated on `AsyncOut`.
            unsafe { *out.0 = wide };
            if let Some(callback) = callback {
                // SAFETY: as above; the context is the caller's own.
                unsafe { callback(context.ptr, out.0) };
            }
        });
        Z_OK
    })
}

/// Allocate on another thread, calling back with the result (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_async`). The context is CONSUMED.
///
/// # Safety
/// As [`provider_alloc_async`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    // SAFETY: the caller's contract, delegated.
    unsafe {
        provider_alloc_async(
            out_result,
            provider,
            size,
            ALIGN_BYTE,
            context,
            result_callback,
        )
    }
}

/// The aligned twin of [`z_shm_provider_alloc_gc_defrag_async`] (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_aligned_async`). The context is CONSUMED.
///
/// # Safety
/// As [`provider_alloc_async`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_aligned_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    // SAFETY: the caller's contract, delegated.
    unsafe {
        provider_alloc_async(
            out_result,
            provider,
            size,
            alignment,
            context,
            result_callback,
        )
    }
}

/// Allocate through a precomputed layout on another thread (zenoh-c
/// `z_precomputed_layout_threadsafe_alloc_gc_defrag_async`). The context is
/// CONSUMED.
///
/// `Z_EINVAL` when the layout's provider is not threadsafe, which is the same
/// refusal [`z_shm_provider_alloc_gc_defrag_async`] makes and for the same
/// reason: the layout carries the backend, so it carries the promise too.
///
/// # Safety
/// `out_result` must outlive the callback; `layout` null or a valid loaned
/// layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_threadsafe_alloc_gc_defrag_async(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_precomputed_layout_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    guarded(|| {
        if out_result.is_null() || result_callback.is_none() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { precomputed_state(layout) }) else {
            return Z_ENULL;
        };
        if !state.provider.is_threadsafe() {
            return Z_EINVAL;
        }
        let backend = state.provider.clone();
        let (size, alignment) = (state.size, state.alignment);
        let out = AsyncOut(out_result);
        let callback = result_callback;
        std::thread::spawn(move || {
            let out = out;
            let context = context;
            let mut narrow = z_buf_alloc_result_t {
                status: ZC_BUF_ALLOC_STATUS_ALLOC_ERROR,
                buf: z_owned_shm_mut_t::null_value(),
                error: Z_ALLOC_ERROR_OTHER,
            };
            match backend.alloc(size, alignment, &policy::gc_defrag_blocking()) {
                Ok(chunk) => {
                    narrow.status = ZC_BUF_ALLOC_STATUS_OK;
                    narrow.buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                }
                Err(AllocFailure::Alloc(reason)) => narrow.error = reason,
                // The layout was validated when it was built, so this arm is not reached
                // with a layout this crate made; if it is, the narrow result has nowhere
                // to say so but `OTHER`.
                Err(AllocFailure::Layout(_)) => narrow.error = Z_ALLOC_ERROR_OTHER,
            }
            // SAFETY: the caller's storage, per `AsyncOut`.
            unsafe { *out.0 = narrow };
            if let Some(callback) = callback {
                // SAFETY: as above.
                unsafe { callback(context.ptr, out.0) };
            }
        });
        Z_OK
    })
}

/// The `alloc_layout` spelling of
/// [`z_precomputed_layout_threadsafe_alloc_gc_defrag_async`] (zenoh-c
/// `z_alloc_layout_threadsafe_alloc_gc_defrag_async`).
///
/// ⛔ Upstream makes `z_owned_alloc_layout_t` a TYPEDEF of
/// `z_owned_precomputed_layout_t`, so this is one implementation under two
/// names — see the layout section for the whole family.
///
/// # Safety
/// As [`z_precomputed_layout_threadsafe_alloc_gc_defrag_async`].
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_threadsafe_alloc_gc_defrag_async(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_alloc_layout_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_alloc_result_t)>,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        z_precomputed_layout_threadsafe_alloc_gc_defrag_async(
            out_result,
            layout,
            result_context,
            result_callback,
        )
    }
}

const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<z_alloc_alignment_t>() == 1);
    assert!(size_of::<z_buf_layout_alloc_result_t>() == 96);
    assert!(align_of::<z_buf_layout_alloc_result_t>() == 8);
    assert!(size_of::<z_buf_alloc_result_t>() == 96);
    // R2289 — the by-VALUE structs of the backend plane. These cross the ABI as
    // arguments rather than behind a handle, so a field this file added or
    // reordered is a wild call at run time and nothing else would catch it.
    assert!(size_of::<zc_context_t>() == 16);
    assert!(size_of::<zc_threadsafe_context_t>() == 16);
    assert!(size_of::<z_chunk_descriptor_t>() == 16);
    assert!(size_of::<z_allocated_chunk_t>() == 24);
    assert!(size_of::<zc_shm_provider_backend_callbacks_t>() == 48);
};

#[cfg(test)]
mod precomputed_layout_tests {
    use super::*;

    /// # Safety
    /// The returned provider is the caller's to drop.
    unsafe fn provider(total: usize) -> z_owned_shm_provider_t {
        let mut p = z_owned_shm_provider_t::null_value();
        assert_eq!(z_shm_provider_default_new(&mut p, total), Z_OK);
        p
    }

    /// ⛔⛔ SKEW THE SEGMENT FIRST, or the alignment assertion is VACUOUS.
    ///
    /// A segment's base is page-aligned, so a FIRST allocation can satisfy an
    /// alignment by accident (it did, before R3058, when the pool kept no headers
    /// and the first chunk sat at offset 0). MEASURED in R2264: a
    /// mutation that made `precomputed_new` store `ALIGN_BYTE` instead of the
    /// caller's alignment PASSED the first draft of these tests. Claiming one
    /// odd byte first moves the pool's next free address off the boundary, so the
    /// next allocation is aligned only if the code aligns it.
    ///
    /// The returned buffer must be held for the duration — dropping it puts the
    /// byte on the provider's busy list, which a collection later empties.
    ///
    /// # Safety
    /// `p` must be a live owned provider.
    pub(super) unsafe fn skew(p: &z_owned_shm_provider_t) -> z_owned_shm_mut_t {
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and `p` is live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(p), 1) };
        assert_eq!(
            out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
            "the skew allocation must succeed or the fixture proves nothing"
        );
        out.buf
    }

    /// R2265 — a layout allocates at the size AND alignment it was built with,
    /// through every one of the ten alloc spellings.
    ///
    /// ⛔ The assertion is on the ADDRESS and the LENGTH, not on the status.
    /// R2264 measured what a status-only test misses: five aligned entry points
    /// were green while returning `addr % 64 == 48`. A layout that forgot its
    /// alignment, or that allocated its provider's default size instead of its
    /// own, would pass `status == OK` on all ten of these.
    #[test]
    fn a_layout_allocates_at_its_own_size_and_alignment() {
        const POW: u8 = 6;
        // A multiple of the alignment: a layout whose size is not one is no layout.
        const SIZE: usize = 320;
        type Alloc =
            unsafe extern "C" fn(*mut z_buf_alloc_result_t, *const z_loaned_precomputed_layout_t);
        let spellings: [(&str, Alloc); 10] = [
            ("precomputed_alloc", z_precomputed_layout_alloc),
            ("precomputed_alloc_gc", z_precomputed_layout_alloc_gc),
            (
                "precomputed_alloc_gc_defrag",
                z_precomputed_layout_alloc_gc_defrag,
            ),
            (
                "precomputed_alloc_gc_defrag_blocking",
                z_precomputed_layout_alloc_gc_defrag_blocking,
            ),
            (
                "precomputed_alloc_gc_defrag_dealloc",
                z_precomputed_layout_alloc_gc_defrag_dealloc,
            ),
            ("alloc_layout_alloc", z_alloc_layout_alloc),
            ("alloc_layout_alloc_gc", z_alloc_layout_alloc_gc),
            (
                "alloc_layout_alloc_gc_defrag",
                z_alloc_layout_alloc_gc_defrag,
            ),
            (
                "alloc_layout_alloc_gc_defrag_blocking",
                z_alloc_layout_alloc_gc_defrag_blocking,
            ),
            (
                "alloc_layout_alloc_gc_defrag_dealloc",
                z_alloc_layout_alloc_gc_defrag_dealloc,
            ),
        ];
        for (name, f) in spellings {
            // SAFETY: a live provider this frame owns, built to serve the alignment.
            let mut p = unsafe { super::aligned_alloc_tests::aligned_provider(64 * 1024, POW) };
            // SAFETY: `p` is live; the buffer is held until the end of the
            // iteration so the pool stays skewed.
            let skewed = unsafe { skew(&p) };
            let mut layout = z_owned_precomputed_layout_t::null_value();
            // SAFETY: `layout` is writable and `p` is live.
            assert_eq!(
                unsafe {
                    z_alloc_layout_with_alignment_new(
                        &mut layout,
                        z_shm_provider_loan(&p),
                        SIZE,
                        z_alloc_alignment_t { pow: POW },
                    )
                },
                Z_OK,
                "{name}: the layout must build"
            );
            assert!(unsafe { z_internal_precomputed_layout_check(&layout) });

            let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` is writable and `layout` is live.
            unsafe { f(&mut out, z_precomputed_layout_loan(&layout)) };
            assert_eq!(out.status, ZC_BUF_ALLOC_STATUS_OK, "{name}: must allocate");
            // SAFETY: the status says the buffer is live.
            let loaned = unsafe { z_shm_mut_loan(&out.buf) };
            let data = unsafe { z_shm_mut_data(loaned) };
            assert!(!data.is_null(), "{name}: OK with no data");
            assert_eq!(
                unsafe { z_shm_mut_len(loaned) },
                SIZE,
                "{name}: allocated a length that is not the layout's"
            );
            assert_eq!(
                data as usize % (1usize << POW),
                0,
                "{name}: the layout's alignment did not reach the allocation"
            );

            let mut moved = z_moved_shm_mut_t { _this: out.buf };
            // SAFETY: dropped once.
            unsafe { z_shm_mut_drop(&mut moved) };
            let mut moved_skew = z_moved_shm_mut_t { _this: skewed };
            // SAFETY: dropped once, after the assertions it was holding open.
            unsafe { z_shm_mut_drop(&mut moved_skew) };
            let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
            // SAFETY: as above.
            unsafe { z_precomputed_layout_drop(&mut moved_l) };
            assert!(!unsafe { z_internal_precomputed_layout_check(&moved_l._this) });
            let mut moved_p = z_moved_shm_provider_t { _this: p };
            // SAFETY: as above.
            unsafe { z_shm_provider_drop(&mut moved_p) };
            p = z_owned_shm_provider_t::null_value();
            let _ = p;
        }
    }

    /// A layout OUTLIVES the provider handle it was built from, and still
    /// allocates.
    ///
    /// The layout holds its own handle on the provider, not a pointer to the
    /// caller's box, and this is the only assertion that can tell those apart: a layout
    /// that kept a raw pointer into the provider would allocate fine until the provider
    /// was dropped and then read freed memory.
    #[test]
    fn a_layout_outlives_the_provider_handle() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(8192) };
        let mut layout = z_owned_precomputed_layout_t::null_value();
        // SAFETY: both are live.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 128) },
            Z_OK
        );
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: dropped once; the layout keeps the segment alive.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;

        let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `layout` is still live.
        unsafe { z_precomputed_layout_alloc(&mut out, z_precomputed_layout_loan(&layout)) };
        assert_eq!(
            out.status, ZC_BUF_ALLOC_STATUS_OK,
            "the layout must still allocate after its provider handle is gone"
        );
        let mut moved = z_moved_shm_mut_t { _this: out.buf };
        // SAFETY: dropped once.
        unsafe { z_shm_mut_drop(&mut moved) };
        let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
        // SAFETY: as above.
        unsafe { z_precomputed_layout_drop(&mut moved_l) };
    }

    /// A nonsense layout is refused at construction, and NULL is tolerated
    /// everywhere.
    #[test]
    fn a_nonsense_layout_is_refused_and_null_is_tolerated() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(4096) };
        let mut layout = z_owned_precomputed_layout_t::null_value();
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 0) },
            Z_EINVAL,
            "a zero-size layout is not a layout"
        );
        assert!(!unsafe { z_internal_alloc_layout_check(&layout) });
        assert_eq!(
            unsafe {
                z_alloc_layout_with_alignment_new(
                    &mut layout,
                    z_shm_provider_loan(&p),
                    64,
                    z_alloc_alignment_t {
                        pow: usize::BITS as u8,
                    },
                )
            },
            Z_EINVAL
        );
        // A layout with no provider is refused too.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, std::ptr::null(), 64) },
            Z_ENULL
        );
        // CONTROL: the same size against the same provider is accepted.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 64) },
            Z_OK
        );

        // NULL everywhere else.
        assert!(!unsafe { z_internal_precomputed_layout_check(std::ptr::null()) });
        let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
        unsafe { z_precomputed_layout_alloc(&mut out, std::ptr::null()) };
        assert_eq!(
            out.status, ZC_BUF_ALLOC_STATUS_ALLOC_ERROR,
            "a null layout must leave a well-formed failure, not the caller's stack"
        );
        unsafe { z_precomputed_layout_drop(std::ptr::null_mut()) };
        unsafe { z_alloc_layout_drop(std::ptr::null_mut()) };

        let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
        // SAFETY: dropped once.
        unsafe { z_precomputed_layout_drop(&mut moved_l) };
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: as above.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;
    }
}

#[cfg(test)]
mod aligned_alloc_tests {
    use super::*;

    /// # Safety
    /// The returned provider is the caller's to drop.
    unsafe fn provider(total: usize) -> z_owned_shm_provider_t {
        let mut p = z_owned_shm_provider_t::null_value();
        assert_eq!(z_shm_provider_default_new(&mut p, total), Z_OK);
        p
    }

    /// A provider built to serve requests aligned to `1 << pow`, which is what an
    /// aligned request needs: a default provider is built at byte alignment and refuses
    /// one as the provider's incompatibility, as the real library does (MEASURED).
    ///
    /// # Safety
    /// The returned provider is the caller's to drop.
    pub(super) unsafe fn aligned_provider(total: usize, pow: u8) -> z_owned_shm_provider_t {
        let mut layout = z_owned_memory_layout_t::null_value();
        assert_eq!(
            z_memory_layout_new(&mut layout, total, z_alloc_alignment_t { pow }),
            Z_OK
        );
        let mut p = z_owned_shm_provider_t::null_value();
        assert_eq!(
            z_posix_shm_provider_with_layout_new(&mut p, z_memory_layout_loan(&layout)),
            Z_OK
        );
        let mut moved = z_moved_memory_layout_t { _this: layout };
        z_memory_layout_drop(&mut moved);
        p
    }

    /// R2264 — the CALLER's alignment reaches the allocator on every one of the
    /// new aligned spellings.
    ///
    /// This is the assertion that separates them from aliases of the unaligned
    /// five: those pass `ALIGN_BYTE`, so a new entry point that forgot to
    /// forward its argument would still allocate, still return OK, and still
    /// pass any test that only checked the status. The address is what tells.
    #[test]
    fn every_aligned_spelling_honours_the_callers_alignment() {
        const POW: u8 = 6; // 64 bytes
        let align = z_alloc_alignment_t { pow: POW };
        type Aligned = unsafe extern "C" fn(
            *mut z_buf_layout_alloc_result_t,
            *const z_loaned_shm_provider_t,
            usize,
            z_alloc_alignment_t,
        );
        let spellings: [(&str, Aligned); 4] = [
            ("alloc_gc_aligned", z_shm_provider_alloc_gc_aligned),
            (
                "alloc_gc_defrag_aligned",
                z_shm_provider_alloc_gc_defrag_aligned,
            ),
            (
                "alloc_gc_defrag_blocking_aligned",
                z_shm_provider_alloc_gc_defrag_blocking_aligned,
            ),
            (
                "alloc_gc_defrag_dealloc_aligned",
                z_shm_provider_alloc_gc_defrag_dealloc_aligned,
            ),
        ];
        for (name, f) in spellings {
            // SAFETY: a live provider this frame owns.
            let mut p = unsafe { aligned_provider(64 * 1024, POW) };
            // ⛔ R2265 — SKEW FIRST. R2264 wrote this test when segments were
            // alignment-1, so a wrong answer showed up as `addr % 64 == 48`.
            // Page-aligning the segment (the repair R2264 itself made) turned
            // the FIRST allocation into one that satisfies any alignment by
            // accident, which would have made this assertion vacuous from the
            // next round on. Claiming one odd byte first is what keeps it real.
            let skewed = unsafe { super::precomputed_layout_tests::skew(&p) };
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` is writable and `p` is live.
            unsafe { f(&mut out, z_shm_provider_loan(&p), 128, align) };
            assert_eq!(
                out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
                "{name} must allocate from a fresh 64K provider"
            );
            // SAFETY: the status says the buffer is live.
            let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
            assert!(!data.is_null(), "{name} returned OK with no data");
            assert_eq!(
                data as usize % (1usize << POW),
                0,
                "{name} did not honour the caller's alignment — it is forwarding \
                 ALIGN_BYTE like its unaligned twin"
            );
            let mut moved = z_moved_shm_mut_t { _this: out.buf };
            // SAFETY: dropped once.
            unsafe { z_shm_mut_drop(&mut moved) };
            let mut moved_skew = z_moved_shm_mut_t { _this: skewed };
            // SAFETY: as above.
            unsafe { z_shm_mut_drop(&mut moved_skew) };
            let mut moved_p = z_moved_shm_provider_t { _this: p };
            // SAFETY: as above.
            unsafe { z_shm_provider_drop(&mut moved_p) };
            p = z_owned_shm_provider_t::null_value();
            let _ = p;
        }
    }

    /// The two DEALLOC spellings allocate, which is the claim their name makes
    /// about wz: there is no third reclaim step, but the entry point works.
    #[test]
    fn the_dealloc_spellings_allocate() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(64 * 1024) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and `p` is live.
        unsafe { z_shm_provider_alloc_gc_defrag_dealloc(&mut out, z_shm_provider_loan(&p), 256) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        let mut moved = z_moved_shm_mut_t { _this: out.buf };
        // SAFETY: dropped once.
        unsafe { z_shm_mut_drop(&mut moved) };
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: as above.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;
    }
}

#[cfg(test)]
mod memory_layout_tests {
    use super::*;

    /// A layout round-trips its `(size, alignment)` through the C accessors.
    ///
    /// Both fields are asserted with DISTINCT values, and the alignment is a
    /// non-zero exponent: a layout that stored only the size, or that dropped
    /// the exponent, would pass a test that checked one of them or that used
    /// `pow = 0`.
    #[test]
    fn a_layout_round_trips_its_size_and_alignment() {
        let mut owned = z_owned_memory_layout_t::null_value();
        assert!(!unsafe { z_internal_memory_layout_check(&owned) });
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 4096, z_alloc_alignment_t { pow: 6 }) },
            Z_OK
        );
        assert!(unsafe { z_internal_memory_layout_check(&owned) });

        let loaned = unsafe { z_memory_layout_loan(&owned) };
        let mut size = 0usize;
        let mut alignment = z_alloc_alignment_t { pow: 0 };
        unsafe { z_memory_layout_get_data(loaned, &mut size, &mut alignment) };
        assert_eq!(size, 4096);
        assert_eq!(alignment.pow, 6);

        // Each output is independently optional — upstream's signature says
        // nothing about them being required together.
        let mut only_size = 0usize;
        unsafe { z_memory_layout_get_data(loaned, &mut only_size, std::ptr::null_mut()) };
        assert_eq!(only_size, 4096);

        let mut moved = z_moved_memory_layout_t { _this: owned };
        unsafe { z_memory_layout_drop(&mut moved) };
        assert!(!unsafe { z_internal_memory_layout_check(&moved._this) });
    }

    /// A nonsense layout is REFUSED at construction, with a gravestone left
    /// behind rather than the caller's stack value.
    ///
    /// This is the half a stub gets wrong: returning `Z_OK` for a zero size
    /// moves the failure to the allocation that uses the layout, which cannot
    /// say what was wrong with it.
    #[test]
    fn a_nonsense_layout_is_refused_at_construction() {
        let mut owned = z_owned_memory_layout_t::null_value();
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 0, z_alloc_alignment_t { pow: 3 }) },
            Z_EINVAL,
            "a zero-size layout is not a layout"
        );
        assert!(
            !unsafe { z_internal_memory_layout_check(&owned) },
            "and the refusal must leave a gravestone"
        );

        // An exponent at or past the pointer width cannot name an alignment.
        assert_eq!(
            unsafe {
                z_memory_layout_new(
                    &mut owned,
                    64,
                    z_alloc_alignment_t {
                        pow: usize::BITS as u8,
                    },
                )
            },
            Z_EINVAL
        );
        assert!(!unsafe { z_internal_memory_layout_check(&owned) });

        // CONTROL: the same size with a representable exponent is accepted, so
        // the refusals above are about the values and not about the function.
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 64, z_alloc_alignment_t { pow: 3 }) },
            Z_OK
        );
        let mut moved = z_moved_memory_layout_t { _this: owned };
        unsafe { z_memory_layout_drop(&mut moved) };
    }

    /// Every accessor tolerates NULL, and a gravestone reads as absent.
    #[test]
    fn the_accessors_answer_without_dereferencing_null() {
        assert!(!unsafe { z_internal_memory_layout_check(std::ptr::null()) });
        assert_eq!(
            unsafe { z_memory_layout_new(std::ptr::null_mut(), 8, z_alloc_alignment_t { pow: 0 }) },
            Z_ENULL
        );
        let mut size = 7usize;
        unsafe { z_memory_layout_get_data(std::ptr::null(), &mut size, std::ptr::null_mut()) };
        assert_eq!(size, 7, "a null layout must not write the outputs");
        unsafe { z_memory_layout_drop(std::ptr::null_mut()) };

        let mut grave = z_owned_memory_layout_t::null_value();
        let loaned = unsafe { z_memory_layout_loan(&grave) };
        unsafe { z_memory_layout_get_data(loaned, &mut size, std::ptr::null_mut()) };
        assert_eq!(size, 7, "a gravestone carries no data to read");
        unsafe { z_internal_memory_layout_null(&mut grave) };
        assert!(!unsafe { z_internal_memory_layout_check(&grave) });
    }
}

#[cfg(test)]
mod pool_provider_tests {
    //! R3058 -- the built-in provider through the exported entry points, now that it is the
    //! runtime's pool and not an allocator of this crate. What a pool holds and when a chunk
    //! comes home are the runtime's facts and are tested there; these are the C ABI's answers
    //! about them, and they were READ OFF THE REAL LIBRARY (the differential that records
    //! them is `zenoh_c_shm_provider_allocation_twice_and_diff`).

    use super::*;

    /// A default provider of `size` bytes, or `None` where the real library refuses.
    fn provider(size: usize) -> Option<z_owned_shm_provider_t> {
        let mut p = z_owned_shm_provider_t::null_value();
        // SAFETY: `p` is a live local.
        let rc = unsafe { z_shm_provider_default_new(&mut p, size) };
        (rc == Z_OK).then_some(p)
    }

    fn alloc_with(
        p: &z_owned_shm_provider_t,
        size: usize,
        spelling: unsafe extern "C" fn(
            *mut z_buf_layout_alloc_result_t,
            *const z_loaned_shm_provider_t,
            usize,
        ),
    ) -> z_buf_layout_alloc_result_t {
        let mut out = z_buf_layout_alloc_result_t {
            status: ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR,
            buf: z_owned_shm_mut_t::null_value(),
            alloc_error: Z_ALLOC_ERROR_OTHER,
            layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
        };
        // SAFETY: `out` is a live local and `p` a live provider.
        unsafe { spelling(&mut out, z_shm_provider_loan(p), size) };
        out
    }

    fn release(result: z_buf_layout_alloc_result_t) {
        if result.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
            let mut buf = result.buf;
            // SAFETY: a live buffer, dropped once.
            unsafe { z_shm_mut_drop(&mut buf as *mut z_owned_shm_mut_t as *mut z_moved_shm_mut_t) };
        }
    }

    fn drop_provider(mut p: z_owned_shm_provider_t) {
        // SAFETY: a live provider, dropped once.
        unsafe {
            z_shm_provider_drop(
                &mut p as *mut z_owned_shm_provider_t as *mut z_moved_shm_provider_t,
            )
        };
    }

    /// THE PROPERTY `z_pub_shm.c` DEPENDS ON: a provider whose chunks are released serves
    /// the SAME request forever, through the collecting spelling the example calls. A
    /// pool that leaked would fail on the third iteration (two 1024-byte chunks fill a
    /// 4096-byte provider), which is exactly the shape of bug a single-shot test does not
    /// see.
    #[test]
    fn a_released_chunk_is_reusable_indefinitely_through_the_collecting_spelling() {
        let p = provider(4096).expect("a 4096-byte provider is made");
        for round in 0..64 {
            let chunk = alloc_with(&p, 1024, z_shm_provider_alloc_gc_defrag_blocking);
            assert_eq!(
                chunk.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
                "round {round}: the previous chunk was dropped and the collecting spelling takes it"
            );
            release(chunk);
        }
        drop_provider(p);
    }

    /// A dropped chunk is NOT back in the pool until a collection takes it, which is what the
    /// real library does and the old allocator did not: the plain spelling is refused while the
    /// collecting one is served.
    #[test]
    fn a_dropped_chunk_waits_for_a_collection() {
        let p = provider(4096).expect("a provider");
        let a = alloc_with(&p, 1024, z_shm_provider_alloc);
        let b = alloc_with(&p, 1024, z_shm_provider_alloc);
        assert_eq!(
            (a.status, b.status),
            (ZC_BUF_LAYOUT_ALLOC_STATUS_OK, ZC_BUF_LAYOUT_ALLOC_STATUS_OK)
        );
        release(a);
        let plain = alloc_with(&p, 1024, z_shm_provider_alloc);
        assert_eq!(plain.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        assert_eq!(plain.alloc_error, Z_ALLOC_ERROR_OUT_OF_MEMORY);
        // SAFETY: a live provider.
        assert_eq!(
            unsafe { z_shm_provider_garbage_collect(z_shm_provider_loan(&p)) },
            1024,
            "the collection reports the largest chunk it took"
        );
        let again = alloc_with(&p, 1024, z_shm_provider_alloc);
        assert_eq!(again.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        release(again);
        release(b);
        drop_provider(p);
    }

    /// The pools the real library makes and refuses: 1000 bytes or fewer, and zero, are
    /// refused; 4096 and 5000 are made.
    #[test]
    fn a_pool_is_made_or_refused_as_the_real_library_does() {
        for size in [0usize, 1, 64, 300, 1000] {
            assert!(provider(size).is_none(), "{size} bytes is refused");
        }
        for size in [4096usize, 5000] {
            drop_provider(provider(size).unwrap_or_else(|| panic!("{size} bytes is made")));
        }
    }

    /// An aligned request is served at its alignment by a provider built to serve it, and
    /// refused as the PROVIDER's incompatibility by a default one.
    #[test]
    fn an_aligned_request_needs_a_provider_built_for_it() {
        let default = provider(4096).expect("a provider");
        let mut out = z_buf_layout_alloc_result_t {
            status: ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
            buf: z_owned_shm_mut_t::null_value(),
            alloc_error: Z_ALLOC_ERROR_OTHER,
            layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
        };
        // SAFETY: a live provider and a live result.
        unsafe {
            z_shm_provider_alloc_aligned(
                &mut out,
                z_shm_provider_loan(&default),
                64,
                z_alloc_alignment_t { pow: 5 },
            )
        };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR);
        assert_eq!(
            out.layout_error,
            Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT
        );
        drop_provider(default);
    }
}

#[cfg(test)]
mod immutability_recovery_tests {
    //! R2294 (open-debt item 607) — `z_shm_mut_try_from_immut` and
    //! `z_bytes_to_owned_shm`, the two strays of the SHM residue that need
    //! neither a session-owned provider nor the SHM client chain.
    //!
    //! Both arms of the recovery are driven, and since R3058 BOTH are reachable through the
    //! C surface, as upstream's are: a buffer is recoverable while it is the sole holder
    //! (nothing else alive here, no descriptor in flight) and refused while it is shared,
    //! which a `z_shm_clone` is. The earlier version of this module built a chunk by hand
    //! to reach the succeeding arm, because every buffer the crate produced was frozen by a
    //! flag; the flag is gone and the fixture is an ordinary allocation.

    use super::*;
    // The payload half of the bridge lives in `bytes`, and this module drives
    // it through the same exported entry points a C program would.
    use crate::abi::z_moved_bytes_t;
    use crate::bytes::{z_bytes_drop, z_bytes_loan, z_bytes_loan_mut};

    /// A 4096-byte provider and an OWNED immutable buffer of 8 bytes out of it, frozen by
    /// `z_shm_from_mut` as a C program freezes one.
    fn owned_shm() -> (Provider, z_owned_shm_t) {
        let layout = wz_runtime_tokio::shm_backend::MemoryLayout::of_size(4096).expect("a layout");
        let provider = Provider::pool(&layout).expect("a pool");
        let chunk = provider
            .alloc(8, ALIGN_BYTE, &policy::just_alloc())
            .unwrap_or_else(|_| panic!("8 bytes fit in a fresh pool"));
        let mut mutable = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
        let mut frozen = z_owned_shm_t::null_value();
        // SAFETY: both are live locals; the buffer is consumed.
        unsafe {
            z_shm_from_mut(
                &mut frozen,
                &mut mutable as *mut z_owned_shm_mut_t as *mut z_moved_shm_mut_t,
            )
        };
        (provider, frozen)
    }

    /// THE REFUSING ARM: a buffer that is SHARED is refused, and the refusal HANDS IT BACK
    /// rather than dropping it.
    ///
    /// The returned buffer is the point. A refusal that consumed `that` and
    /// wrote nothing to `immut` would drop a holder, and the caller — who
    /// still believes it owns a buffer — would have neither the mutable one it
    /// asked for nor the immutable one it started with. The provider's own
    /// accounting says the chunk is still out: a collection finds nothing to take
    /// until every holder has let go.
    #[test]
    fn a_shared_buffer_is_refused_and_handed_back() {
        let (provider, mut owned) = owned_shm();
        let mut copy = z_owned_shm_t::null_value();
        // SAFETY: a live buffer and a live out-parameter.
        unsafe { z_shm_clone(&mut copy, z_shm_loan(&owned)) };
        assert!(
            unsafe { z_internal_shm_check(&copy) },
            "the fixture must hold a second reference, else the buffer is not shared"
        );
        assert_eq!(provider.garbage_collect(), 0, "the chunk is held by two");

        let mut out = z_owned_shm_mut_t::null_value();
        let mut back = z_owned_shm_t::null_value();
        // SAFETY: all three are live locals.
        let rc = unsafe {
            z_shm_mut_try_from_immut(
                &mut out,
                &mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t,
                &mut back,
            )
        };

        assert_eq!(rc, Z_EINVAL, "a shared buffer cannot become mutable");
        assert!(
            !unsafe { z_internal_shm_mut_check(&out) },
            "the mutable out-parameter must be a gravestone on refusal"
        );
        assert!(
            unsafe { z_internal_shm_check(&back) },
            "the buffer must come BACK — a refusal that swallowed it would lose \
             memory the caller still believes it holds"
        );
        assert!(
            !unsafe { z_internal_shm_check(&owned) },
            "`that` is consumed on every path, refusal included"
        );
        assert_eq!(
            provider.garbage_collect(),
            0,
            "the chunk is still out: it moved to `immut`, it was not dropped"
        );

        // SAFETY: both dropped once.
        unsafe { z_shm_drop(&mut back as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        unsafe { z_shm_drop(&mut copy as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        assert_eq!(
            provider.garbage_collect(),
            8,
            "and dropping the LAST holder is what lets the collection take the chunk"
        );
    }

    /// THE OTHER ARM: a buffer nothing else holds is recovered, and `immut` is left a
    /// gravestone.
    ///
    /// Without this the refusal above would be the whole test, and a wz that refused
    /// unconditionally would pass it. That is the vacuity item 625 is about, in the one
    /// place this round could have walked into it.
    #[test]
    fn a_buffer_nothing_else_holds_is_recovered() {
        let (provider, mut owned) = owned_shm();

        let mut out = z_owned_shm_mut_t::null_value();
        let mut back = z_owned_shm_t::null_value();
        // SAFETY: all three are live locals.
        let rc = unsafe {
            z_shm_mut_try_from_immut(
                &mut out,
                &mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t,
                &mut back,
            )
        };

        assert_eq!(rc, Z_OK, "the sole holder of a buffer may write it again");
        assert!(
            unsafe { z_internal_shm_mut_check(&out) },
            "the recovered buffer must be live"
        );
        assert!(
            !unsafe { z_internal_shm_check(&back) },
            "success leaves the hand-back parameter a gravestone — the buffer is \
             in `this_`, and a live `immut` too would be two owners of one chunk"
        );
        assert_eq!(
            provider.garbage_collect(),
            0,
            "recovery moves the SAME chunk; it neither allocates a second one nor frees this"
        );

        // SAFETY: dropped once, through the recovered handle.
        unsafe { z_shm_mut_drop(&mut out as *mut z_owned_shm_mut_t as *mut z_moved_shm_mut_t) };
        assert_eq!(provider.garbage_collect(), 8);
    }

    /// Freezing a buffer keeps the bytes where they are and keeps it WRITABLE for as long
    /// as it is the sole holder: a copy makes it read-only and dropping the copy makes it
    /// writable again. This is `z_sub_shm.c`'s `SHM (MUT)` / `SHM (IMMUT)` question
    /// asked of a buffer this process allocated.
    #[test]
    fn a_frozen_buffer_is_writable_exactly_while_it_is_the_sole_holder() {
        let (provider, mut owned) = owned_shm();
        // SAFETY: a live owned buffer.
        let sole = unsafe { z_shm_try_mut(&mut owned) };
        assert!(
            !sole.is_null(),
            "a frozen buffer nothing else holds is writable"
        );

        let mut copy = z_owned_shm_t::null_value();
        // SAFETY: a live buffer and a live out-parameter.
        unsafe { z_shm_clone(&mut copy, z_shm_loan(&owned)) };
        // SAFETY: both live.
        assert!(
            unsafe { z_shm_try_mut(&mut owned) }.is_null(),
            "shared, so read-only"
        );
        assert!(
            unsafe { z_shm_try_mut(&mut copy) }.is_null(),
            "from either side"
        );

        // SAFETY: dropped once.
        unsafe { z_shm_drop(&mut copy as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        // SAFETY: a live owned buffer.
        assert!(
            !unsafe { z_shm_try_mut(&mut owned) }.is_null(),
            "the copy let go, so the buffer is the sole holder again"
        );
        // SAFETY: dropped once.
        unsafe { z_shm_drop(&mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        assert_eq!(provider.garbage_collect(), 8);
    }

    /// A copy shares the bytes and allocates nothing: the copy's address is the original's,
    /// and a pool one chunk fills still has no room for another after the copy (it needed none).
    #[test]
    fn a_clone_is_a_second_holder_of_the_same_bytes() {
        let (provider, owned) = owned_shm();
        let mut copy = z_owned_shm_t::null_value();
        // SAFETY: a live buffer and a live out-parameter.
        unsafe { z_shm_clone(&mut copy, z_shm_loan(&owned)) };
        // SAFETY: both live.
        let (a, b) = unsafe {
            (
                z_shm_data(z_shm_loan(&owned)),
                z_shm_data(z_shm_loan(&copy)),
            )
        };
        assert_eq!(a, b, "a reference copy has the original's address");
        let mut owned = owned;
        // SAFETY: both dropped once.
        unsafe { z_shm_drop(&mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        unsafe { z_shm_drop(&mut copy as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        assert_eq!(provider.garbage_collect(), 8);
    }

    /// R3059 -- a payload built from a buffer of this process's provider IS that chunk, and
    /// says so. Until this round `z_bytes_from_shm` copied the bytes and let go of the chunk,
    /// so no payload this side built could be a chunk of shared memory and a put could only
    /// send bytes; the answer was `Z_EINVAL` (R2294), and it was true of the copy.
    ///
    /// The chunk stays out of the pool while the payload holds it, the buffer taken back out
    /// of the payload is the SAME memory, and the chunk goes home only when the payload and
    /// that buffer have both let go.
    #[test]
    fn a_payload_built_from_an_shm_buffer_is_the_chunk_and_says_so() {
        let (provider, mut owned) = owned_shm();
        let address = unsafe { z_shm_data(z_shm_loan(&owned)) };
        let mut payload = z_owned_bytes_t::null_value();
        // SAFETY: both are live locals.
        let rc = unsafe {
            z_bytes_from_shm(
                &mut payload,
                &mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t,
            )
        };
        assert_eq!(rc, Z_OK, "the payload must have been built");
        assert!(
            !unsafe { z_internal_shm_check(&owned) },
            "the buffer is consumed"
        );
        assert_eq!(
            provider.garbage_collect(),
            0,
            "`z_bytes_from_shm` kept the chunk: nothing is free for a collection to take"
        );

        let mut dst = z_owned_shm_t::null_value();
        // SAFETY: the payload is live and `dst` is writable.
        let rc = unsafe { z_bytes_to_owned_shm(z_bytes_loan(&payload), &mut dst) };
        assert_eq!(rc, Z_OK, "the payload is a chunk of shared memory");
        assert_eq!(
            unsafe { z_shm_data(z_shm_loan(&dst)) },
            address,
            "and the buffer it gives back is the memory the program wrote, not a copy of it"
        );

        // SAFETY: both dropped once.
        unsafe { z_shm_drop(&mut dst as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        assert_eq!(provider.garbage_collect(), 0, "the payload still holds it");
        unsafe { z_bytes_drop(&mut payload as *mut z_owned_bytes_t as *mut z_moved_bytes_t) };
        assert_eq!(
            provider.garbage_collect(),
            8,
            "and the last holder letting go is what lets the collection take it home"
        );
    }

    /// A payload that is a chunk is writable through its own loan only while that loan is
    /// the sole buffer: the payload is a holder of the chunk and not a buffer, so it does
    /// not count against its own loan, and a buffer taken out of it does.
    #[test]
    fn a_payload_that_is_a_chunk_is_writable_exactly_while_its_loan_is_the_only_buffer() {
        let (provider, mut owned) = owned_shm();
        let mut payload = z_owned_bytes_t::null_value();
        // SAFETY: both are live locals.
        unsafe {
            z_bytes_from_shm(
                &mut payload,
                &mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t,
            )
        };
        let mut loan: *mut z_loaned_shm_t = std::ptr::null_mut();
        // SAFETY: a live payload and a writable out-pointer.
        let rc = unsafe { z_bytes_as_mut_loaned_shm(z_bytes_loan_mut(&mut payload), &mut loan) };
        assert_eq!(rc, Z_OK);
        // SAFETY: a live loan.
        assert!(
            !unsafe { z_shm_try_reloan_mut(loan) }.is_null(),
            "nothing else holds the chunk but the payload that lends the loan"
        );

        let mut second = z_owned_shm_t::null_value();
        // SAFETY: a live payload and a writable destination.
        assert_eq!(
            unsafe { z_bytes_to_owned_shm(z_bytes_loan(&payload), &mut second) },
            Z_OK
        );
        // SAFETY: the same live loan.
        assert!(
            unsafe { z_shm_try_reloan_mut(loan) }.is_null(),
            "a second buffer exists, so the chunk is shared"
        );
        // SAFETY: dropped once.
        unsafe { z_shm_drop(&mut second as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        // SAFETY: the same live loan.
        assert!(
            !unsafe { z_shm_try_reloan_mut(loan) }.is_null(),
            "and it is writable again when the second one has let go"
        );
        unsafe { z_bytes_drop(&mut payload as *mut z_owned_bytes_t as *mut z_moved_bytes_t) };
        assert_eq!(provider.garbage_collect(), 8);
    }

    /// R2294 -- `z_bytes_to_owned_shm` refuses a payload that is NOT a chunk, and the refusal
    /// is ABOUT THE PAYLOAD rather than about the argument being null. The payload here is
    /// bytes a program wrote, which is every payload that is not built from a buffer.
    #[test]
    fn a_payload_of_plain_bytes_is_not_shm_backed() {
        let mut payload = z_owned_bytes_t::null_value();
        // SAFETY: a live local.
        assert_eq!(
            unsafe { crate::bytes::z_bytes_copy_from_buf(&mut payload, b"plain".as_ptr(), 5) },
            Z_OK
        );
        let mut dst = z_owned_shm_t::null_value();
        // SAFETY: the payload is live and `dst` is writable.
        let rc = unsafe { z_bytes_to_owned_shm(z_bytes_loan(&payload), &mut dst) };
        assert_eq!(rc, Z_EINVAL, "plain bytes are not a chunk of shared memory");
        assert!(
            !unsafe { z_internal_shm_check(&dst) },
            "a refused conversion must leave a gravestone, not an uninitialised \
             struct a C caller would then drop"
        );
        // SAFETY: dropped once.
        unsafe { z_bytes_drop(&mut payload as *mut z_owned_bytes_t as *mut z_moved_bytes_t) };
    }

    /// The discriminator for the refusal above: a NULL payload answers
    /// `Z_ENULL`, not `Z_EINVAL`.
    ///
    /// Without it, a `z_bytes_to_owned_shm` that ignored its argument entirely
    /// and returned `Z_EINVAL` unconditionally would pass — and the test above
    /// would be asserting about a function that never looked at the payload.
    #[test]
    fn the_conversion_distinguishes_a_null_payload_from_a_live_one() {
        let mut dst = z_owned_shm_t::null_value();
        // SAFETY: `dst` is writable; the payload pointer is deliberately null.
        let rc = unsafe { z_bytes_to_owned_shm(std::ptr::null(), &mut dst) };
        assert_eq!(
            rc, Z_ENULL,
            "a null payload is a different refusal from a live one that carries \
             no SHM"
        );
    }
}

#[cfg(test)]
mod received_chunk_tests {
    //! R3052 -- what the C side is told about a payload that ARRIVED as a chunk of
    //! shared memory, driven through the exported entry points a C program calls.
    //!
    //! The storage is a test double that answers what a mapped chunk answers, because
    //! the two things a C program can learn are decided by two answers the double
    //! controls: whether the chunk is a chunk of shared memory at all, and whether
    //! this receiver holds the only reference to it. The integration leg runs the real
    //! thing against the real publisher and sees ONE of the combinations; the others
    //! are reachable only here.

    use super::*;
    use crate::abi::z_moved_bytes_t;
    use crate::bytes::{z_bytes_drop, z_bytes_loan, z_bytes_loan_mut, Payload};
    use std::sync::atomic::{AtomicBool, Ordering};
    use wz_runtime_tokio::{RxBytes, RxStorage, ShmChunkView};

    /// A received chunk of shared memory, as far as the C side can tell. The bytes are
    /// never written through the pointer it hands out; the tests compare the pointer.
    struct LentChunk {
        bytes: Vec<u8>,
        unique: AtomicBool,
        mapped_writable: bool,
    }

    impl RxStorage for LentChunk {
        fn as_slice(&self) -> &[u8] {
            &self.bytes
        }

        fn shm_chunk(&self) -> Option<&dyn ShmChunkView> {
            Some(self)
        }
    }

    impl ShmChunkView for LentChunk {
        fn is_unique(&self) -> bool {
            self.unique.load(Ordering::SeqCst)
        }

        fn writable_ptr(&self) -> Option<*mut u8> {
            self.mapped_writable
                .then_some(self.bytes.as_ptr() as *mut u8)
        }
    }

    fn chunk(unique: bool, mapped_writable: bool) -> Arc<LentChunk> {
        Arc::new(LentChunk {
            bytes: b"0123456789".to_vec(),
            unique: AtomicBool::new(unique),
            mapped_writable,
        })
    }

    /// A payload that is the whole of `storage`, as a C program holds one.
    fn payload_over(storage: Arc<dyn RxStorage>) -> z_owned_bytes_t {
        let len = storage.as_slice().len();
        let bytes = RxBytes::shared(storage, 0..len).expect("the range is the whole storage");
        let state = BytesState::of(Payload::Shared(bytes));
        z_owned_bytes_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
    }

    fn drop_payload(mut payload: z_owned_bytes_t) {
        // SAFETY: a live payload, dropped once.
        unsafe { z_bytes_drop(&mut payload as *mut z_owned_bytes_t as *mut z_moved_bytes_t) };
    }

    /// THE POSITIVE ANSWER, and it is the payload's own: `z_bytes_as_loaned_shm` is
    /// `Z_OK` for a chunk a peer sent, the buffer it lends is that chunk's bytes and
    /// not a copy, and asking twice lends the same buffer, which a C program holding the
    /// first pointer depends on.
    #[test]
    fn a_payload_that_is_a_chunk_of_shared_memory_is_loaned_as_that_chunk() {
        let storage = chunk(true, true);
        let payload = payload_over(storage.clone());

        let mut first: *const z_loaned_shm_t = std::ptr::null();
        let mut second: *const z_loaned_shm_t = std::ptr::null();
        // SAFETY: a live payload and writable out-pointers.
        let (rc1, rc2) = unsafe {
            (
                z_bytes_as_loaned_shm(z_bytes_loan(&payload), &mut first),
                z_bytes_as_loaned_shm(z_bytes_loan(&payload), &mut second),
            )
        };
        assert_eq!((rc1, rc2), (Z_OK, Z_OK));
        assert!(!first.is_null(), "a Z_OK that lends nothing is no answer");
        assert_eq!(
            first, second,
            "the loan is one buffer for the payload's life"
        );
        // SAFETY: `first` is a live loan of the payload.
        let (len, data) = unsafe { (z_shm_len(first), z_shm_data(first)) };
        assert_eq!(len, 10);
        assert_eq!(
            data,
            storage.bytes.as_ptr(),
            "the buffer IS the chunk's memory; a copy would have an address of its own"
        );

        drop_payload(payload);
    }

    /// THE REFUSAL: a range of lent storage that is not a chunk of shared memory (a
    /// frame, a pool slot) and a payload of a buffer's own are both `Z_EINVAL` with
    /// nothing lent. This is the control of the test above: it fails only if the
    /// answer ignores WHAT the payload is.
    #[test]
    fn a_payload_that_is_not_a_chunk_of_shared_memory_is_refused() {
        let frame: Arc<dyn RxStorage> = Arc::new(b"0123456789".to_vec());
        let ranged = payload_over(frame);
        let mut owned = z_owned_bytes_t::null_value();
        // SAFETY: `owned` is a live local.
        let rc = unsafe { crate::bytes::z_bytes_copy_from_buf(&mut owned, b"abc".as_ptr(), 3) };
        assert_eq!(rc, Z_OK, "the owned payload must have been built");

        for (what, payload) in [("a range of a frame", &ranged), ("a buffer", &owned)] {
            let mut dst: *const z_loaned_shm_t = std::ptr::NonNull::dangling().as_ptr();
            // SAFETY: a live payload and a writable out-pointer.
            let rc = unsafe { z_bytes_as_loaned_shm(z_bytes_loan(payload), &mut dst) };
            assert_eq!(rc, Z_EINVAL, "{what} is not shared memory");
            assert!(
                dst.is_null(),
                "a refusal must not leave a stale loan: {what}"
            );
        }

        drop_payload(ranged);
        drop_payload(owned);
    }

    /// `SHM (MUT)` or `SHM (IMMUT)`, which is the question `z_sub_shm.c` exists to
    /// ask: the mutable view is granted only while this receiver holds the ONLY
    /// reference to the chunk AND the page maps writable, and the answer follows the
    /// chunk as the sender lets go, not as it stood when the payload arrived.
    #[test]
    fn the_mutable_view_is_granted_only_to_the_sole_holder_of_a_writable_chunk() {
        // (unique, mapped writable, may the C side write?)
        let cases = [
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ];
        for (unique, mapped_writable, granted) in cases {
            let storage = chunk(unique, mapped_writable);
            let mut payload = payload_over(storage.clone());
            let mut loan: *mut z_loaned_shm_t = std::ptr::null_mut();
            // SAFETY: a live payload and a writable out-pointer.
            let rc =
                unsafe { z_bytes_as_mut_loaned_shm(z_bytes_loan_mut(&mut payload), &mut loan) };
            assert_eq!(rc, Z_OK, "the buffer is lent either way");

            // SAFETY: `loan` is a live loan of the payload.
            let reloaned = unsafe { z_shm_try_reloan_mut(loan) };
            assert_eq!(
                !reloaned.is_null(),
                granted,
                "unique={unique} mapped_writable={mapped_writable}"
            );
            if granted {
                // SAFETY: a live mutable loan; only the address is read.
                let ptr = unsafe { z_shm_mut_data_mut(reloaned) };
                assert_eq!(ptr as *const u8, storage.bytes.as_ptr());
            }
            drop_payload(payload);
        }
    }

    /// The sender letting go takes the answer from IMMUT to MUT on the SAME loan.
    #[test]
    fn the_answer_follows_the_chunk_when_the_sender_lets_go() {
        let storage = chunk(false, true);
        let mut payload = payload_over(storage.clone());
        let mut loan: *mut z_loaned_shm_t = std::ptr::null_mut();
        // SAFETY: a live payload and a writable out-pointer.
        let rc = unsafe { z_bytes_as_mut_loaned_shm(z_bytes_loan_mut(&mut payload), &mut loan) };
        assert_eq!(rc, Z_OK);
        // SAFETY: a live loan.
        assert!(
            unsafe { z_shm_try_reloan_mut(loan) }.is_null(),
            "shared: IMMUT"
        );

        storage.unique.store(true, Ordering::SeqCst);
        // SAFETY: the same live loan.
        assert!(
            !unsafe { z_shm_try_reloan_mut(loan) }.is_null(),
            "the sender let go: MUT"
        );
        drop_payload(payload);
    }

    /// `z_bytes_to_owned_shm` hands out a SECOND reference that is immutable however
    /// unique the chunk is, and every reference the C side took is given back with the
    /// payload and the buffers it owns: the chunk's last holder going away is what
    /// releases the sender's reference, so a leak here is a chunk the sender never gets
    /// back.
    #[test]
    fn an_owned_buffer_is_a_second_immutable_reference_and_all_of_them_are_given_back() {
        let storage = chunk(true, true);
        assert_eq!(Arc::strong_count(&storage), 1);
        let payload = payload_over(storage.clone());
        assert_eq!(Arc::strong_count(&storage), 2, "the payload's range");

        let mut owned = z_owned_shm_t::null_value();
        // SAFETY: a live payload and a writable destination.
        let rc = unsafe { z_bytes_to_owned_shm(z_bytes_loan(&payload), &mut owned) };
        assert_eq!(rc, Z_OK);
        assert!(unsafe { z_internal_shm_check(&owned) });
        assert_eq!(
            Arc::strong_count(&storage),
            4,
            "the owned buffer's, and the payload's own loan the conversion made first: the \
             two share one holder token, which is how neither is writable while the other lives"
        );
        // SAFETY: a live owned buffer.
        assert_eq!(unsafe { z_shm_len(z_shm_loan(&owned)) }, 10);
        // SAFETY: a live owned buffer.
        let mutable = unsafe { z_shm_try_reloan_mut(z_shm_loan_mut(&mut owned)) };
        assert!(
            mutable.is_null(),
            "an owned conversion is the immutable one, even for a unique chunk"
        );

        let mut loan: *const z_loaned_shm_t = std::ptr::null();
        // SAFETY: a live payload and a writable out-pointer.
        assert_eq!(
            unsafe { z_bytes_as_loaned_shm(z_bytes_loan(&payload), &mut loan) },
            Z_OK
        );
        assert_eq!(Arc::strong_count(&storage), 4, "and the payload's own loan");

        // SAFETY: dropped once each.
        unsafe { z_shm_drop(&mut owned as *mut z_owned_shm_t as *mut z_moved_shm_t) };
        assert_eq!(Arc::strong_count(&storage), 3);
        drop_payload(payload);
        assert_eq!(
            Arc::strong_count(&storage),
            1,
            "the payload took its loan with it; nothing of the chunk is left held"
        );
    }
}

#[cfg(test)]
mod foreign_backend_tests {
    //! R2289 (open-debt item 607) — the C-SUPPLIED backend, driven the way a C
    //! program drives it.
    //!
    //! Every test here goes through the exported entry points and a backend
    //! written as six `extern "C"` callbacks over one opaque context, because
    //! that is the only shape in which the plane's claim is testable: wz calls
    //! OUT, and a test that called wz's internals instead would be asserting
    //! about a function nobody reaches.
    //!
    //! The harness records what it was asked and what it was told, so each test
    //! can assert the two directions separately — that the request reached the
    //! backend intact, and that the backend's answer reached the caller intact.
    //! Status codes alone would pass for a wz that allocated out of its OWN
    //! segment and never called the callbacks at all, which is why every
    //! allocation test also asserts the returned pointer lies inside the
    //! BACKEND's arena.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Wait, bounded, until `done` holds.
    ///
    /// A provider's backend is released by whichever thread lets go of its LAST reference,
    /// and the process-wide sweep of orphaned providers takes a short-lived reference to each
    /// while it looks. Beside the other tests of this crate, which create providers on their
    /// own threads, that thread can be a sweeper's, a moment after the drop that orphaned the
    /// provider returned. What is owed is that the backend is released EXACTLY once and that it
    /// is released at all; it is not owed to this thread before the drop returns, and a test
    /// that asserted the instant would be a coin that lands wrong under load.
    fn eventually(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The segment id this backend stamps into every descriptor, so a test can
    /// tell its own descriptors from a zeroed struct.
    const SEGMENT_ID: z_segment_id_t = 7;
    /// How long the concurrency probe waits for a second caller before deciding
    /// there is not going to be one.
    const PEER_WAIT: Duration = Duration::from_millis(400);
    /// What `defragment_fn` returns: a number no wz book-keeping path could
    /// produce, so an answer that did not come from the backend is visible.
    const DEFRAGMENT_ANSWER: usize = 0xDEF7A6;

    /// The book-keeping the callbacks share.
    struct HarnessState {
        /// Which slots of the arena are handed out.
        used: Vec<bool>,
        alloc_calls: usize,
        free_calls: usize,
        defragment_calls: usize,
        available_calls: usize,
        /// The `(size, alignment exponent)` of every layout `alloc_fn` saw.
        layouts_seen: Vec<(usize, u8)>,
        /// Every descriptor `free_fn` was handed.
        freed: Vec<(z_segment_id_t, z_chunk_id_t, usize)>,
        in_flight: usize,
        concurrent_max: usize,
    }

    /// A backend a C program could have written, with the counters a test needs.
    struct Harness {
        /// The memory this backend hands out. The `Box` is what owns it; the raw
        /// pointer is what the callbacks compute chunk addresses from while the
        /// book-keeping is locked.
        _arena: Box<[u8]>,
        arena: *mut u8,
        slot_len: usize,
        state: Mutex<HarnessState>,
        peer: Condvar,
        /// Bumped by this backend's own `delete_fn`.
        deleted: Arc<AtomicUsize>,
        /// Bumped when a chunk's segment context is released.
        segment_drops: Arc<AtomicUsize>,
        /// When set, `alloc_fn` waits for a second caller so a test can see
        /// whether wz let one in.
        probe_concurrency: bool,
        /// When set, every allocation fails — for the blocking-path tests.
        always_fail: bool,
        /// When set, `alloc_fn` hands out a slot even when it is SMALLER than
        /// the request — a misbehaving backend, which is the only way to reach
        /// wz's check that the chunk covers what was asked for.
        ///
        /// ⚠ Added after the first draft of `a_backend_that_under_delivers…`
        /// PASSED with wz's check deleted: the harness refused the oversized
        /// request itself, so the branch under test was never entered and the
        /// test was measuring nothing.
        under_deliver: bool,
    }

    // SAFETY: the arena is owned for the harness's whole life and every chunk
    // handed out of it is a distinct range; `state` serialises the book-keeping.
    unsafe impl Send for Harness {}
    // SAFETY: as above.
    unsafe impl Sync for Harness {}

    impl Harness {
        fn new(slots: usize, slot_len: usize) -> Box<Self> {
            let mut arena = vec![0u8; slots * slot_len].into_boxed_slice();
            let ptr = arena.as_mut_ptr();
            Box::new(Self {
                _arena: arena,
                arena: ptr,
                slot_len,
                state: Mutex::new(HarnessState {
                    used: vec![false; slots],
                    alloc_calls: 0,
                    free_calls: 0,
                    defragment_calls: 0,
                    available_calls: 0,
                    layouts_seen: Vec::new(),
                    freed: Vec::new(),
                    in_flight: 0,
                    concurrent_max: 0,
                }),
                peer: Condvar::new(),
                deleted: Arc::new(AtomicUsize::new(0)),
                segment_drops: Arc::new(AtomicUsize::new(0)),
                probe_concurrency: false,
                always_fail: false,
                under_deliver: false,
            })
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HarnessState> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// The address of slot `n`.
        fn slot_ptr(&self, n: usize) -> *mut u8 {
            // SAFETY: `n` is a slot index this harness handed out.
            unsafe { self.arena.add(n * self.slot_len) }
        }

        /// Whether `p` points inside this backend's arena — the assertion that
        /// separates "wz called the backend" from "wz allocated its own memory
        /// and returned a plausible status".
        fn owns(&self, p: *const u8, len: usize) -> bool {
            let base = self.arena as usize;
            let end = base + self._arena.len();
            let p = p as usize;
            p >= base && p + len <= end
        }
    }

    /// What a chunk's segment context points at: nothing but a counter to bump
    /// when wz releases it.
    struct SegmentTag(Arc<AtomicUsize>);

    unsafe extern "C" fn segment_delete(ctx: *mut c_void) {
        // SAFETY: the pointer this module handed to `z_ptr_in_segment_new`.
        let tag = unsafe { Box::from_raw(ctx as *mut SegmentTag) };
        tag.0.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn backend_delete(ctx: *mut c_void) {
        // SAFETY: the pointer this module handed to the provider constructor.
        let harness = unsafe { Box::from_raw(ctx as *mut Harness) };
        harness.deleted.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn backend_alloc(
        out: *mut z_owned_chunk_alloc_result_t,
        layout: *const z_loaned_memory_layout_t,
        ctx: *mut c_void,
    ) {
        // SAFETY: the harness pointer, alive for the provider's whole life.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut size = 0usize;
        let mut alignment = z_alloc_alignment_t { pow: 0 };
        // SAFETY: `layout` is the loaned layout wz built for this call.
        unsafe { z_memory_layout_get_data(layout, &mut size, &mut alignment) };

        let mut state = harness.lock();
        state.alloc_calls += 1;
        state.layouts_seen.push((size, alignment.pow));
        state.in_flight += 1;
        state.concurrent_max = state.concurrent_max.max(state.in_flight);
        harness.peer.notify_all();
        if harness.probe_concurrency {
            // Wait, briefly, for a second caller. Two threads that wz let in
            // together both see `in_flight == 2`; two that wz serialised each
            // time out alone.
            while state.in_flight < 2 {
                let (guard, timeout) = harness
                    .peer
                    .wait_timeout(state, PEER_WAIT)
                    .unwrap_or_else(|e| e.into_inner());
                state = guard;
                if timeout.timed_out() {
                    break;
                }
            }
        }
        state.in_flight -= 1;

        let slot = if harness.always_fail {
            None
        } else {
            state
                .used
                .iter()
                .position(|used| !used)
                .filter(|_| harness.under_deliver || size <= harness.slot_len)
        };
        let Some(slot) = slot else {
            drop(state);
            // SAFETY: `out` is wz's own gravestoned local.
            unsafe { z_chunk_alloc_result_new_error(out, Z_ALLOC_ERROR_OUT_OF_MEMORY) };
            return;
        };
        state.used[slot] = true;
        drop(state);

        let tag = Box::into_raw(Box::new(SegmentTag(harness.segment_drops.clone())));
        let mut ptr = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: `ptr` is a live local and the context pair is well formed.
        unsafe {
            z_ptr_in_segment_new(
                &mut ptr,
                harness.slot_ptr(slot),
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        let mut moved = z_moved_ptr_in_segment_t { _this: ptr };
        // SAFETY: `out` is wz's gravestoned local and `moved` a live local whose
        // pointer this call consumes.
        unsafe {
            z_chunk_alloc_result_new_ok(
                out,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: slot as z_chunk_id_t,
                        len: harness.slot_len,
                    },
                    ptr: &mut moved,
                },
            )
        };
    }

    unsafe extern "C" fn backend_free(chunk: *const z_chunk_descriptor_t, ctx: *mut c_void) {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        // SAFETY: wz hands back a live descriptor.
        let desc = unsafe { *chunk };
        let mut state = harness.lock();
        state.free_calls += 1;
        state.freed.push((desc.segment, desc.chunk, desc.len));
        if let Some(used) = state.used.get_mut(desc.chunk as usize) {
            *used = false;
        }
    }

    unsafe extern "C" fn backend_defragment(ctx: *mut c_void) -> usize {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut state = harness.lock();
        state.defragment_calls += 1;
        // A number nothing else in the harness produces, so a wz that answered
        // from its own book-keeping instead of calling here is visible.
        DEFRAGMENT_ANSWER
    }

    unsafe extern "C" fn backend_available(ctx: *mut c_void) -> usize {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut state = harness.lock();
        state.available_calls += 1;
        state.used.iter().filter(|used| !**used).count() * harness.slot_len
    }

    unsafe extern "C" fn backend_layout_for(
        _layout: *mut z_owned_memory_layout_t,
        _ctx: *mut c_void,
    ) {
        // This backend serves any layout it is given unchanged.
    }

    unsafe extern "C" fn backend_id(_ctx: *mut c_void) -> z_protocol_id_t {
        0x77
    }

    fn callbacks() -> zc_shm_provider_backend_callbacks_t {
        zc_shm_provider_backend_callbacks_t {
            alloc_fn: Some(backend_alloc),
            free_fn: Some(backend_free),
            defragment_fn: Some(backend_defragment),
            available_fn: Some(backend_available),
            layout_for_fn: Some(backend_layout_for),
            id_fn: Some(backend_id),
        }
    }

    /// Install `harness` as a provider, returning the provider and a borrow of
    /// the harness that stays valid until the provider is dropped.
    ///
    /// # Safety
    /// The caller must drop the returned provider before reading the harness's
    /// `deleted` counter through anything but the `Arc` it was cloned from.
    unsafe fn install(
        harness: Box<Harness>,
        threadsafe: bool,
    ) -> (z_owned_shm_provider_t, &'static Harness) {
        let deleted = harness.deleted.clone();
        let _ = deleted;
        let raw = Box::into_raw(harness);
        // SAFETY: the box outlives the provider, which is what `delete_fn`
        // enforces — it is the only thing that frees it.
        let borrow = unsafe { &*raw };
        let mut provider = z_owned_shm_provider_t::null_value();
        if threadsafe {
            // SAFETY: `provider` is a live local.
            unsafe {
                z_shm_provider_threadsafe_new(
                    &mut provider,
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: raw as *mut c_void,
                        },
                        delete_fn: Some(backend_delete),
                    },
                    callbacks(),
                )
            };
        } else {
            // SAFETY: as above.
            unsafe {
                z_shm_provider_new(
                    &mut provider,
                    zc_context_t {
                        context: raw as *mut c_void,
                        delete_fn: Some(backend_delete),
                    },
                    callbacks(),
                )
            };
        }
        assert!(unsafe { z_internal_shm_provider_check(&provider) });
        (provider, borrow)
    }

    /// Drop a provider once.
    ///
    /// # Safety
    /// `provider` must be live.
    unsafe fn drop_provider(provider: z_owned_shm_provider_t) {
        let mut moved = z_moved_shm_provider_t { _this: provider };
        // SAFETY: dropped exactly once.
        unsafe { z_shm_provider_drop(&mut moved) };
    }

    /// Drop a mutable buffer once.
    ///
    /// # Safety
    /// `buf` must be live.
    unsafe fn drop_buf(buf: z_owned_shm_mut_t) {
        let mut moved = z_moved_shm_mut_t { _this: buf };
        // SAFETY: dropped exactly once.
        unsafe { z_shm_mut_drop(&mut moved) };
    }

    /// The whole round trip: the request reaches the backend as a layout, the
    /// backend's memory reaches the caller, and the release reaches the backend
    /// as the descriptor it issued.
    ///
    /// Each of the four assertions fails on a different wrong implementation: a
    /// wz that never called `alloc_fn`, one that called it and returned its own
    /// memory, one that lost the descriptor, and one that never called
    /// `free_fn`.
    #[test]
    fn a_foreign_backend_serves_the_allocation_and_the_release() {
        // SAFETY: the provider owns the harness until it is dropped.
        let (provider, harness) = unsafe { install(Harness::new(4, 256), false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);

        // SAFETY: the status says the buffer is live.
        let loaned = unsafe { z_shm_mut_loan_mut(&mut out.buf) };
        // SAFETY: as above.
        let data = unsafe { z_shm_mut_data_mut(loaned) };
        assert!(
            harness.owns(data, 64),
            "the buffer must be the BACKEND's memory — a pointer outside its \
             arena means wz allocated its own and never asked"
        );
        // SAFETY: 64 bytes of the backend's own arena, exclusively ours.
        unsafe { std::ptr::write_bytes(data, 0xA5, 64) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_mut_len(loaned) }, 64);
        // SAFETY: as above.
        let read = unsafe { std::slice::from_raw_parts(z_shm_mut_data(loaned), 64) };
        assert!(read.iter().all(|b| *b == 0xA5), "the bytes must flow back");

        {
            let state = harness.lock();
            assert_eq!(state.alloc_calls, 1);
            assert_eq!(
                state.layouts_seen,
                vec![(64usize, 0u8)],
                "the caller's size must reach the backend as a layout"
            );
            assert_eq!(state.free_calls, 0, "nothing is released while it is held");
        }

        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        assert_eq!(
            harness.lock().free_calls,
            0,
            "a dropped chunk is on the provider's busy list, not yet the backend's \
             again: the backend is told when a COLLECTION takes it (R3058)"
        );
        // SAFETY: the provider is live.
        let largest = unsafe { z_shm_provider_garbage_collect(z_shm_provider_loan(&provider)) };
        assert_eq!(
            largest, 256,
            "the collection reports the chunk it took home"
        );
        {
            let state = harness.lock();
            assert_eq!(state.free_calls, 1);
            assert_eq!(
                state.freed,
                vec![(SEGMENT_ID, 0, 256)],
                "the backend must get back the descriptor it issued, not a \
                 reconstruction"
            );
        }
        assert_eq!(
            harness.segment_drops.load(Ordering::SeqCst),
            1,
            "the chunk's segment context is released with the chunk"
        );

        let deleted = harness.deleted.clone();
        // SAFETY: dropped once; `harness` must not be read after this.
        unsafe { drop_provider(provider) };
        eventually("the provider owes the context a delete_fn", || {
            deleted.load(Ordering::SeqCst) >= 1
        });
        assert_eq!(
            deleted.load(Ordering::SeqCst),
            1,
            "the provider owes the context exactly one delete_fn"
        );
    }

    /// `available` and `defragment` are the BACKEND's answers, not wz's.
    ///
    /// Both return values a wz book-keeping path could not produce, so an
    /// implementation that answered from its own free list rather than calling
    /// out fails here rather than looking plausible.
    #[test]
    fn available_and_defragment_are_answered_by_the_backend() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(4, 256), false) };
        // SAFETY: the provider is live.
        let loan = unsafe { z_shm_provider_loan(&provider) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_provider_available(loan) }, 4 * 256);
        // SAFETY: as above.
        assert_eq!(
            unsafe { z_shm_provider_defragment(loan) },
            DEFRAGMENT_ANSWER
        );
        {
            let state = harness.lock();
            assert_eq!(state.available_calls, 1);
            assert_eq!(state.defragment_calls, 1);
        }

        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, loan, 16) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: the provider is live.
        assert_eq!(
            unsafe { z_shm_provider_available(loan) },
            3 * 256,
            "the backend's own accounting must be what is reported"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The caller's ALIGNMENT reaches the backend, and it reaches it as an
    /// exponent rather than being flattened to the default.
    #[test]
    fn the_callers_alignment_reaches_the_backend() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 512), false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe {
            z_shm_provider_alloc_aligned(
                &mut out,
                z_shm_provider_loan(&provider),
                128,
                z_alloc_alignment_t { pow: 6 },
            )
        };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        assert_eq!(
            harness.lock().layouts_seen,
            vec![(128usize, 6u8)],
            "an entry point that forwarded ALIGN_BYTE would show pow = 0 here"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The BACKEND's error code is what the caller sees.
    ///
    /// wz's own exhaustion answer is `Z_ALLOC_ERROR_OUT_OF_MEMORY` too, so the
    /// discriminating half is the second request: this backend refuses an
    /// oversized request with the same code while `available` still reports room,
    /// which wz's native allocator would call a defragmentation problem.
    #[test]
    fn the_backends_refusal_is_the_callers_refusal() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(1, 128), false) };
        // SAFETY: the provider is live.
        let loan = unsafe { z_shm_provider_loan(&provider) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, loan, 4096) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        assert_eq!(out.alloc_error, Z_ALLOC_ERROR_OUT_OF_MEMORY);
        assert_eq!(
            harness.lock().alloc_calls,
            1,
            "the refusal must come from the backend, not from a size check wz \
             made on its behalf"
        );
        // SAFETY: the provider is live.
        assert_eq!(unsafe { z_shm_provider_available(loan) }, 128);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A backend that says OK and delivers a chunk SMALLER than was asked for is
    /// refused, and the chunk is handed back rather than leaked.
    ///
    /// The buffer plane passes this pointer and length straight to the caller,
    /// so trusting the backend here would hand a C program a 64-byte window on
    /// a 16-byte chunk.
    #[test]
    fn a_backend_that_under_delivers_is_refused_and_the_chunk_returned() {
        let mut harness = Harness::new(1, 16);
        // The backend hands out a 16-byte slot for a 64-byte request. Without
        // this the harness refuses the request ITSELF and wz's check is never
        // reached — which is how the first draft of this test passed with that
        // check deleted.
        harness.under_deliver = true;
        // SAFETY: the provider owns the harness.
        let (provider, borrow) = unsafe { install(harness, false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(
            borrow.lock().alloc_calls,
            1,
            "the backend must have been ASKED — a refusal wz made on its own \
             would leave this at zero and the rest of the test vacuous"
        );
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        assert!(
            !unsafe { z_internal_shm_mut_check(&out.buf) },
            "a refused allocation must leave a gravestone"
        );
        assert_eq!(
            borrow.lock().freed,
            vec![(SEGMENT_ID, 0, 16)],
            "the chunk wz refused must go back to the backend, not be dropped"
        );
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A blocking allocation with NOTHING outstanding fails instead of waiting
    /// — divergence 2 — and the CONTROL shows the waiting path is live.
    ///
    /// Without the control this test would pass on a wz that never blocked at
    /// all, which is the failure it is meant to be about.
    #[test]
    fn a_blocking_request_waits_only_when_a_release_can_come() {
        // Nothing outstanding: the call must return rather than wait forever.
        let mut harness = Harness::new(1, 64);
        harness.always_fail = true;
        // SAFETY: the provider owns the harness.
        let (provider, _borrow) = unsafe { install(harness, false) };
        let (tx, rx) = mpsc::channel();
        let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
        std::thread::spawn(move || {
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: the provider outlives this thread — the test joins on the
            // channel before dropping it.
            unsafe {
                z_shm_provider_alloc_gc_defrag_blocking(
                    &mut out,
                    loan as *const z_loaned_shm_provider_t,
                    32,
                )
            };
            let status = out.status;
            if status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                // SAFETY: dropped once, on the thread that made it.
                unsafe { drop_buf(out.buf) };
            }
            let _ = tx.send(status);
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR),
            "a blocking allocation with no live chunk has nothing to wait for"
        );
        // SAFETY: dropped once, after the thread signalled.
        unsafe { drop_provider(provider) };

        // CONTROL: with a chunk outstanding, the same call WAITS and then
        // succeeds when that chunk is released.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(1, 64), false) };
        let mut held: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `held` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut held, z_shm_provider_loan(&provider), 32) };
        assert_eq!(held.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);

        let (tx, rx) = mpsc::channel();
        let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
        let waiter = std::thread::spawn(move || {
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            unsafe {
                z_shm_provider_alloc_gc_defrag_blocking(
                    &mut out,
                    loan as *const z_loaned_shm_provider_t,
                    32,
                )
            };
            let status = out.status;
            if status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                // SAFETY: dropped once, on the thread that made it.
                unsafe { drop_buf(out.buf) };
            }
            let _ = tx.send(status);
        });
        // The waiter cannot succeed while the only slot is held.
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "the blocking call must WAIT while a release is still possible"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(held.buf) };
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_OK),
            "the release must wake the waiter"
        );
        waiter.join().expect("the waiting thread finished");
        assert!(harness.lock().alloc_calls >= 2);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A pointer-in-segment CLONE shares the segment: the destructor runs once,
    /// after the last copy.
    ///
    /// A deep copy would run it twice and a copy that dropped the context would
    /// run it early — the intermediate assertion is what tells those apart.
    #[test]
    fn a_pointer_in_segment_clone_shares_its_segment() {
        let drops = Arc::new(AtomicUsize::new(0));
        let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
        let mut byte = 0u8;
        let mut owned = z_owned_ptr_in_segment_t::null_value();
        assert!(!unsafe { z_internal_ptr_in_segment_check(&owned) });
        // SAFETY: `owned` is a live local and the context pair well formed.
        unsafe {
            z_ptr_in_segment_new(
                &mut owned,
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        assert!(unsafe { z_internal_ptr_in_segment_check(&owned) });

        let mut copy = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: both are live locals.
        unsafe { z_ptr_in_segment_clone(&mut copy, z_ptr_in_segment_loan(&owned)) };
        assert!(unsafe { z_internal_ptr_in_segment_check(&copy) });

        let mut moved = z_moved_ptr_in_segment_t { _this: owned };
        // SAFETY: dropped once.
        unsafe { z_ptr_in_segment_drop(&mut moved) };
        assert!(!unsafe { z_internal_ptr_in_segment_check(&moved._this) });
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the segment is still held by the clone"
        );

        let mut moved_copy = z_moved_ptr_in_segment_t { _this: copy };
        // SAFETY: dropped once.
        unsafe { z_ptr_in_segment_drop(&mut moved_copy) };
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "and released exactly once when the last copy goes"
        );

        // NULL is tolerated everywhere.
        assert!(!unsafe { z_internal_ptr_in_segment_check(std::ptr::null()) });
        unsafe { z_ptr_in_segment_drop(std::ptr::null_mut()) };
        let mut grave = z_owned_ptr_in_segment_t::null_value();
        unsafe { z_ptr_in_segment_clone(&mut grave, std::ptr::null()) };
        assert!(!unsafe { z_internal_ptr_in_segment_check(&grave) });
        unsafe { z_internal_ptr_in_segment_null(&mut grave) };
    }

    /// A chunk-alloc result carries EITHER outcome, and taking the chunk
    /// gravestones the caller's pointer.
    #[test]
    fn a_chunk_alloc_result_carries_either_outcome() {
        let drops = Arc::new(AtomicUsize::new(0));
        let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
        let mut byte = 0u8;
        let mut ptr = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: `ptr` is a live local.
        unsafe {
            z_ptr_in_segment_new(
                &mut ptr,
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        let mut moved = z_moved_ptr_in_segment_t { _this: ptr };

        let mut ok = z_owned_chunk_alloc_result_t::null_value();
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&ok) });
        // SAFETY: both are live locals; the pointer is consumed.
        let rc = unsafe {
            z_chunk_alloc_result_new_ok(
                &mut ok,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 3,
                        len: 32,
                    },
                    ptr: &mut moved,
                },
            )
        };
        assert_eq!(rc, Z_OK);
        assert!(unsafe { z_internal_chunk_alloc_result_check(&ok) });
        assert!(
            !unsafe { z_internal_ptr_in_segment_check(&moved._this) },
            "taking the chunk must gravestone the caller's pointer, or it will \
             be dropped twice"
        );

        // A second take of the SAME (now empty) pointer is refused.
        let mut again = z_owned_chunk_alloc_result_t::null_value();
        // SAFETY: `moved` is a live gravestone.
        let rc = unsafe {
            z_chunk_alloc_result_new_ok(
                &mut again,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 3,
                        len: 32,
                    },
                    ptr: &mut moved,
                },
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&again) });

        let mut moved_ok = z_moved_chunk_alloc_result_t { _this: ok };
        // SAFETY: dropped once.
        unsafe { z_chunk_alloc_result_drop(&mut moved_ok) };
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&moved_ok._this) });
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "dropping the result releases the pointer it took"
        );

        let mut err = z_owned_chunk_alloc_result_t::null_value();
        // SAFETY: a live local.
        unsafe { z_chunk_alloc_result_new_error(&mut err, Z_ALLOC_ERROR_NEED_DEFRAGMENT) };
        assert!(unsafe { z_internal_chunk_alloc_result_check(&err) });
        let mut moved_err = z_moved_chunk_alloc_result_t { _this: err };
        // SAFETY: dropped once.
        unsafe { z_chunk_alloc_result_drop(&mut moved_err) };

        // NULL is tolerated.
        assert!(!unsafe { z_internal_chunk_alloc_result_check(std::ptr::null()) });
        unsafe { z_chunk_alloc_result_drop(std::ptr::null_mut()) };
        unsafe { z_chunk_alloc_result_new_error(std::ptr::null_mut(), Z_ALLOC_ERROR_OTHER) };
        let mut grave = z_owned_chunk_alloc_result_t::null_value();
        unsafe { z_internal_chunk_alloc_result_null(&mut grave) };
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&grave) });
    }

    /// `z_shm_provider_map` adopts a chunk the BACKEND allocated, and refuses
    /// one aimed at a provider that could not have issued it.
    #[test]
    fn map_adopts_a_backend_chunk_and_refuses_a_native_provider() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 128), false) };
        let drops = Arc::new(AtomicUsize::new(0));

        let make_chunk = |slot: usize| {
            let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
            let mut ptr = z_owned_ptr_in_segment_t::null_value();
            // SAFETY: `ptr` is a live local.
            unsafe {
                z_ptr_in_segment_new(
                    &mut ptr,
                    harness.slot_ptr(slot),
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: tag as *mut c_void,
                        },
                        delete_fn: Some(segment_delete),
                    },
                )
            };
            z_moved_ptr_in_segment_t { _this: ptr }
        };

        let mut moved = make_chunk(0);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: all three are live locals.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&provider),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 0,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                96,
            )
        };
        assert_eq!(rc, Z_OK);
        // SAFETY: the result says the buffer is live.
        let loaned = unsafe { z_shm_mut_loan(&buf) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_mut_len(loaned) }, 96);
        // SAFETY: as above.
        assert_eq!(
            unsafe { z_shm_mut_data(loaned) },
            harness.slot_ptr(0) as *const u8,
            "the mapped buffer must be the chunk's own memory"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(buf) };
        // SAFETY: the provider is live.
        unsafe { z_shm_provider_garbage_collect(z_shm_provider_loan(&provider)) };
        assert_eq!(
            harness.lock().freed,
            vec![(SEGMENT_ID, 0, 128)],
            "a mapped chunk is released to the backend like an allocated one, when a \
             collection takes it"
        );

        // A length beyond the chunk is refused.
        let mut moved = make_chunk(1);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: as above.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&provider),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 1,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                129,
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(!unsafe { z_internal_shm_mut_check(&buf) });

        // The built-in pool cannot have issued this descriptor, and says so.
        let mut native = z_owned_shm_provider_t::null_value();
        assert_eq!(
            unsafe { z_shm_provider_default_new(&mut native, 4096) },
            Z_OK
        );
        let mut moved = make_chunk(1);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: as above.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&native),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 1,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                96,
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(
            !unsafe { z_internal_ptr_in_segment_check(&moved._this) },
            "the pointer was passed by value, so a refusal must still consume it"
        );
        // SAFETY: dropped once each.
        unsafe { drop_provider(native) };
        unsafe { drop_provider(provider) };
    }

    /// The `_async` spellings are the only place the two constructors differ,
    /// and they differ in BOTH directions: refused on a non-threadsafe provider,
    /// served on a threadsafe one.
    #[test]
    fn the_async_spellings_split_on_the_threadsafe_promise() {
        struct Signals {
            called: mpsc::Sender<isize>,
            deleted: mpsc::Sender<()>,
        }
        unsafe extern "C" fn on_result(ctx: *mut c_void, result: *mut z_buf_layout_alloc_result_t) {
            // SAFETY: the context this test handed to the async call.
            let signals = unsafe { &*(ctx as *const Signals) };
            // SAFETY: wz wrote the caller's own storage before calling back.
            let status = unsafe { (*result).status };
            let _ = signals.called.send(status as isize);
        }
        unsafe extern "C" fn on_delete(ctx: *mut c_void) {
            // SAFETY: as above; this is the last use of the context.
            let signals = unsafe { Box::from_raw(ctx as *mut Signals) };
            let _ = signals.deleted.send(());
        }

        // The NON-threadsafe provider refuses, and still consumes the context.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 256), false) };
        let (called_tx, called_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let signals = Box::into_raw(Box::new(Signals {
            called: called_tx,
            deleted: deleted_tx,
        }));
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        let rc = unsafe {
            z_shm_provider_alloc_gc_defrag_async(
                &mut out,
                z_shm_provider_loan(&provider),
                64,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: signals as *mut c_void,
                    },
                    delete_fn: Some(on_delete),
                },
                Some(on_result),
            )
        };
        assert_eq!(
            rc, Z_EINVAL,
            "a provider built by z_shm_provider_new made no thread-safety promise"
        );
        assert_eq!(
            deleted_rx.recv_timeout(Duration::from_secs(5)),
            Ok(()),
            "the context is passed by value, so a refusal must still delete it"
        );
        assert_eq!(
            called_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected),
            "a refused async call must not run the result callback"
        );
        assert_eq!(harness.lock().alloc_calls, 0);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };

        // The THREADSAFE provider serves it, and the alignment travels.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 256), true) };
        let (called_tx, called_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let signals = Box::into_raw(Box::new(Signals {
            called: called_tx,
            deleted: deleted_tx,
        }));
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` outlives the callback — the test waits for both signals
        // before this frame ends.
        let rc = unsafe {
            z_shm_provider_alloc_gc_defrag_aligned_async(
                &mut out,
                z_shm_provider_loan(&provider),
                64,
                z_alloc_alignment_t { pow: 5 },
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: signals as *mut c_void,
                    },
                    delete_fn: Some(on_delete),
                },
                Some(on_result),
            )
        };
        assert_eq!(rc, Z_OK);
        assert_eq!(
            called_rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_OK as isize)
        );
        assert_eq!(deleted_rx.recv_timeout(Duration::from_secs(5)), Ok(()));
        assert_eq!(
            harness.lock().layouts_seen,
            vec![(64usize, 5u8)],
            "the async spelling must forward the caller's alignment too"
        );
        // SAFETY: the status said the buffer is live, and nothing touches `out`
        // after both signals.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The LAYOUT `_async` spellings split the same way, and the two names are
    /// one implementation.
    #[test]
    fn the_layout_async_spellings_split_on_the_same_promise() {
        struct Signals {
            called: mpsc::Sender<isize>,
            deleted: mpsc::Sender<()>,
        }
        unsafe extern "C" fn on_result(ctx: *mut c_void, result: *mut z_buf_alloc_result_t) {
            // SAFETY: the context this test handed to the async call.
            let signals = unsafe { &*(ctx as *const Signals) };
            // SAFETY: wz wrote the caller's own storage before calling back.
            let status = unsafe { (*result).status };
            let _ = signals.called.send(status as isize);
        }
        unsafe extern "C" fn on_delete(ctx: *mut c_void) {
            // SAFETY: as above; the last use of the context.
            let signals = unsafe { Box::from_raw(ctx as *mut Signals) };
            let _ = signals.deleted.send(());
        }

        for (threadsafe, expected) in [(false, Z_EINVAL), (true, Z_OK)] {
            // SAFETY: the provider owns the harness.
            let (provider, _harness) = unsafe { install(Harness::new(2, 256), threadsafe) };
            let mut layout = z_owned_precomputed_layout_t::null_value();
            // SAFETY: both are live locals.
            assert_eq!(
                unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&provider), 48) },
                Z_OK
            );
            let (called_tx, called_rx) = mpsc::channel();
            let (deleted_tx, deleted_rx) = mpsc::channel();
            let signals = Box::into_raw(Box::new(Signals {
                called: called_tx,
                deleted: deleted_tx,
            }));
            let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` outlives the callback — both signals are awaited
            // before this iteration ends.
            let rc = unsafe {
                z_alloc_layout_threadsafe_alloc_gc_defrag_async(
                    &mut out,
                    z_alloc_layout_loan(&layout),
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: signals as *mut c_void,
                        },
                        delete_fn: Some(on_delete),
                    },
                    Some(on_result),
                )
            };
            assert_eq!(rc, expected, "threadsafe = {threadsafe}");
            assert_eq!(deleted_rx.recv_timeout(Duration::from_secs(5)), Ok(()));
            if expected == Z_OK {
                assert_eq!(
                    called_rx.recv_timeout(Duration::from_secs(5)),
                    Ok(ZC_BUF_ALLOC_STATUS_OK as isize)
                );
                // SAFETY: the status said the buffer is live.
                unsafe { drop_buf(out.buf) };
            } else {
                assert_eq!(called_rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
            }
            let mut moved = z_moved_precomputed_layout_t { _this: layout };
            // SAFETY: dropped once.
            unsafe { z_precomputed_layout_drop(&mut moved) };
            // SAFETY: dropped once.
            unsafe { drop_provider(provider) };
        }
    }

    /// A NON-threadsafe backend's callbacks are serialised; a threadsafe one's
    /// are not.
    ///
    /// The second half is the CONTROL and it is what makes the first half mean
    /// anything: `concurrent_max == 1` is also what a wz that ran both calls on
    /// one thread would report, and a probe that could never observe 2 would
    /// pass on any implementation at all.
    #[test]
    fn a_non_threadsafe_backend_sees_one_callback_at_a_time() {
        for (threadsafe, expected_max) in [(false, 1usize), (true, 2usize)] {
            let mut harness = Harness::new(4, 128);
            harness.probe_concurrency = true;
            // SAFETY: the provider owns the harness.
            let (provider, borrow) = unsafe { install(harness, threadsafe) };
            let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
            let threads: Vec<_> = (0..2)
                .map(|_| {
                    std::thread::spawn(move || {
                        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
                        // SAFETY: the provider outlives every thread — they are
                        // joined below.
                        unsafe {
                            z_shm_provider_alloc(
                                &mut out,
                                loan as *const z_loaned_shm_provider_t,
                                32,
                            )
                        };
                        if out.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                            // SAFETY: dropped once, on the thread that made it.
                            unsafe { drop_buf(out.buf) };
                        }
                    })
                })
                .collect();
            for thread in threads {
                thread.join().expect("an allocating thread finished");
            }
            assert_eq!(
                borrow.lock().concurrent_max,
                expected_max,
                "threadsafe = {threadsafe}"
            );
            // SAFETY: dropped once, after every thread joined.
            unsafe { drop_provider(provider) };
        }
    }

    /// The two POSIX constructors: `_new` is the default backend under its other
    /// name, and `_with_layout_new` carries the layout's ALIGNMENT into the
    /// segment's base.
    ///
    /// ⚠ The address assertion alone would be probabilistic — a 4096-aligned
    /// allocation is sometimes 8192-aligned by luck — so the segment's own
    /// alignment is asserted as well. That one is deterministic, and it is the
    /// half a constructor that ignored the layout fails.
    #[test]
    fn the_posix_constructors_size_and_align_their_segment() {
        let mut plain = z_owned_shm_provider_t::null_value();
        assert_eq!(unsafe { z_posix_shm_provider_new(&mut plain, 4096) }, Z_OK);
        // The constructor's SIZING is what this half is about, read where it lives: a pool
        // of 4096 bytes serves two chunks of 1024 and refuses a third (the real library's
        // count, MEASURED), and `available()` says nothing about it because the default
        // backend does not account.
        let mut held = Vec::new();
        for _ in 0..2 {
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` is writable and the provider live.
            unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&plain), 1024) };
            assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
            held.push(out);
        }
        let mut third: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe { z_shm_provider_alloc(&mut third, z_shm_provider_loan(&plain), 1024) };
        assert_eq!(third.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        for out in held {
            // SAFETY: dropped once each.
            unsafe { drop_buf(out.buf) };
        }
        // SAFETY: dropped once.
        unsafe { drop_provider(plain) };

        const POW: u8 = 13; // 8192, deliberately wider than a page's usual placement
        let mut layout = z_owned_memory_layout_t::null_value();
        assert_eq!(
            unsafe {
                z_memory_layout_new(&mut layout, 64 * 1024, z_alloc_alignment_t { pow: POW })
            },
            Z_OK
        );
        let mut provider = z_owned_shm_provider_t::null_value();
        // SAFETY: both are live locals.
        assert_eq!(
            unsafe {
                z_posix_shm_provider_with_layout_new(&mut provider, z_memory_layout_loan(&layout))
            },
            Z_OK
        );
        // SAFETY: the provider is live and this crate minted its handle.
        let backend =
            unsafe { provider_of(z_shm_provider_loan(&provider)) }.expect("a live provider");
        // The layout's ALIGNMENT is the pool's: a request is extended to it, so a hundred
        // bytes become one aligned unit. A constructor that ignored the layout would leave
        // the request as it was.
        let served = backend
            .shm
            .layout_for(wz_runtime_tokio::shm_backend::MemoryLayout::of_size(100).expect("layout"))
            .expect("a pool serves a small layout");
        assert_eq!(served.alignment().pow(), POW);
        assert_eq!(served.size().get(), 1usize << POW);

        // And an allocation at that alignment reaches an aligned ADDRESS, with a
        // skew first so the answer is not the base's by accident.
        let mut skew: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `skew` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut skew, z_shm_provider_loan(&provider), 1) };
        assert_eq!(skew.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe {
            // A size that is a multiple of the alignment: any other is no layout.
            z_shm_provider_alloc_aligned(
                &mut out,
                z_shm_provider_loan(&provider),
                1usize << POW,
                z_alloc_alignment_t { pow: POW },
            )
        };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: the status says the buffer is live.
        let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
        assert_eq!(data as usize % (1usize << POW), 0);
        // SAFETY: dropped once each.
        unsafe { drop_buf(out.buf) };
        unsafe { drop_buf(skew.buf) };
        unsafe { drop_provider(provider) };
        let mut moved = z_moved_memory_layout_t { _this: layout };
        // SAFETY: dropped once.
        unsafe { z_memory_layout_drop(&mut moved) };

        // NULL and a nonsense layout are refused.
        let mut grave = z_owned_shm_provider_t::null_value();
        assert_eq!(
            unsafe { z_posix_shm_provider_with_layout_new(&mut grave, std::ptr::null()) },
            Z_ENULL
        );
        assert!(!unsafe { z_internal_shm_provider_check(&grave) });
        assert_eq!(
            unsafe { z_posix_shm_provider_new(std::ptr::null_mut(), 8) },
            Z_ENULL
        );
    }

    /// A foreign provider's BUFFER outlives the provider handle, and the
    /// backend is not released until the last buffer is gone.
    ///
    /// `z_pub_shm.c`'s teardown order relies on this for the built-in pool;
    /// the foreign one has the sharper version of it, because releasing the
    /// context early would run a C destructor over memory a live buffer still
    /// points into.
    #[test]
    fn a_foreign_buffer_outlives_its_provider_handle() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 128), false) };
        let deleted = harness.deleted.clone();
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
        assert_eq!(
            deleted.load(Ordering::SeqCst),
            0,
            "a live buffer still holds the backend"
        );
        // SAFETY: the buffer is still live, and so is the memory behind it.
        let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
        // SAFETY: 64 bytes of the backend's arena, still ours.
        assert_eq!(unsafe { std::slice::from_raw_parts(data, 64) }.len(), 64);
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        eventually("the last buffer's drop releases the backend", || {
            deleted.load(Ordering::SeqCst) >= 1
        });
        assert_eq!(deleted.load(Ordering::SeqCst), 1);
    }

    /// A NULL `this_` still consumes the context both constructors take by
    /// value, so a caller that passed a bad output does not leak its own state.
    #[test]
    fn a_refused_constructor_still_deletes_the_context() {
        let deleted = Arc::new(AtomicUsize::new(0));
        struct Tag(Arc<AtomicUsize>);
        unsafe extern "C" fn tag_delete(ctx: *mut c_void) {
            // SAFETY: the pointer this test handed over.
            let tag = unsafe { Box::from_raw(ctx as *mut Tag) };
            tag.0.fetch_add(1, Ordering::SeqCst);
        }
        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        // SAFETY: a deliberate null output.
        unsafe {
            z_shm_provider_new(
                std::ptr::null_mut(),
                zc_context_t {
                    context: tag as *mut c_void,
                    delete_fn: Some(tag_delete),
                },
                callbacks(),
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 1);

        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        // SAFETY: as above.
        unsafe {
            z_shm_provider_threadsafe_new(
                std::ptr::null_mut(),
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(tag_delete),
                },
                callbacks(),
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 2);

        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        let mut byte = 0u8;
        // SAFETY: as above.
        unsafe {
            z_ptr_in_segment_new(
                std::ptr::null_mut(),
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(tag_delete),
                },
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 3);
    }
}

// ---------------------------------------------------------------------------
// R2299 (open-debt item 607) — the SHM CLIENT REGISTRY
// ---------------------------------------------------------------------------
//
// The provider plane above is the ALLOCATING half: a program asks wz for a
// chunk and writes into it. This is the ATTACHING half — how a process that
// did NOT create a segment gets at its bytes, which is what a receiver does.
//
// ## The chain, and why it is one plane rather than four
//
// Upstream splits it across four types that only mean something together:
//
//   `z_owned_shm_client_t`        one protocol's "attach to segment N"
//   `zc_owned_shm_client_list_t`  a list of those, being assembled
//   `z_owned_shm_client_storage_t`the resolved registry, protocol id -> client
//   `z_shm_segment_t`             what an attach returns: a `map_fn` per chunk
//
// A client alone has no caller, a list alone is never consulted, and a storage
// with no clients resolves nothing. Splitting them across rounds would put
// three dead arms in the surface and call it progress -- the class R2288 named.
// So the round takes the chain, and the round's witness drives it end to end:
// register a client for a protocol id, resolve the list into a storage, attach
// a segment through the storage, and read bytes back out of `map_fn`.
//
// ## What makes this NOT a dead arm, measured rather than argued
//
// `z_posix_shm_client_new` is the POSIX member of the default client set, and
// wz already owns a POSIX segment naming convention: `wz-runtime-tokio`'s
// `shm_provider.rs` @ `fn shm_path` maps a `segment_id` to
// `/dev/shm/wz-shm-{id:08x}.wz`, and its `PosixShmResolver` opens exactly that.
// wz's POSIX client attaches by THE SAME rule, so a segment one half of this
// workspace publishes is one the other half can read. The test proves that with
// a real `/dev/shm` file rather than a mock.
//
// ⚠ The item 607 premise this round REFUTED, recorded where the next reader of
// this plane will be standing: the register said the client half's witness is
// weak "unless wz negotiates SHM transport". wz DOES negotiate it --
// `wz-session-core/src/drive.rs` @ `ShmChallengeRejected` is a live driver arm
// that runs `shm_recv_init_syn` / `shm_recv_init_ack` and lets BOTH roles
// decide `is_shm` at the Open phase, and `wz-runtime-tokio/src/shm_auth_segment.rs`
// publishes a real POSIX auth segment for it. What is inert is the PAYLOAD
// path (`wz-session-core/src/extshm.rs` says so in its own banner: R3a landed
// the codec and the trait, R3b never wired the RX resolver). The two are
// different sentences, and the register had merged them.
//
// ⚠ R3052: the PAYLOAD path is no longer inert. The RX resolver was wired in R3050
// (`resolve_shared` hands a received chunk over as a range of its mapped segment) and
// this ABI's receiving side reads it, so a received shared-memory payload is a
// payload the C program can loan. The sending side is the part still left (module
// note). The paragraph above is what was true when the register item was settled.
//
// ## Divergence, named because it is a promise this plane cannot keep silently
//
// Upstream's storage is consumed by a SESSION (`z_open_with_custom_shm_clients`).
// wz's session does not take one yet, so today the storage's only reader is
// [`z_shm_client_storage_attach`] -- wz's own entry point, which the tests
// drive and which the session will call when the RX path lands. It is `pub` and
// not `#[no_mangle]`: it is not ABI, because upstream has no such symbol.

/// zenoh-c `z_owned_shm_client_t` (`zenoh_opaque.h:763-765`) — 16 bytes at
/// align 8. No `z_loaned_` spelling exists upstream, so none is declared here.
const SHM_CLIENT_SIZE: usize = 16;
/// zenoh-c `zc_owned_shm_client_list_t` / `zc_loaned_shm_client_list_t`
/// (`zenoh_opaque.h:1032-1034`, `:932-934`) — 24 bytes at align 8.
const SHM_CLIENT_LIST_SIZE: usize = 24;
/// zenoh-c `z_owned_shm_client_storage_t` / `z_loaned_shm_client_storage_t`
/// (`zenoh_opaque.h:770-772`, `:822-824`) — 8 bytes at align 8.
const SHM_CLIENT_STORAGE_SIZE: usize = 8;

define_shm_opaque!(z_owned_shm_client_t, z_moved_shm_client_t, SHM_CLIENT_SIZE);
define_shm_opaque!(
    zc_owned_shm_client_list_t,
    zc_loaned_shm_client_list_t,
    zc_moved_shm_client_list_t,
    SHM_CLIENT_LIST_SIZE
);
define_shm_opaque!(
    z_owned_shm_client_storage_t,
    z_loaned_shm_client_storage_t,
    z_moved_shm_client_storage_t,
    SHM_CLIENT_STORAGE_SIZE
);

/// zenoh-c `zc_shm_segment_callbacks_t` (`zenoh_opaque.h:886-891`).
///
/// One entry point: turn a chunk id into a pointer into the attached segment.
/// Upstream has no length here, and neither does wz -- the descriptor that
/// named the chunk carried it.
#[repr(C)]
pub struct zc_shm_segment_callbacks_t {
    /// Obtain the region of memory a chunk id names.
    pub map_fn: Option<unsafe extern "C" fn(z_chunk_id_t, *mut c_void) -> *mut u8>,
}

/// zenoh-c `z_shm_segment_t` (`zenoh_opaque.h:897-901`) — an attached segment,
/// as a context plus the one callback that reads it.
///
/// This is BY VALUE in upstream's `attach_fn` out-parameter, so it is a plain
/// `#[repr(C)]` struct rather than an opaque handle.
#[repr(C)]
pub struct z_shm_segment_t {
    /// The state the attacher wants handed back to `map_fn`.
    pub context: zc_threadsafe_context_t,
    /// How to map one chunk of this segment.
    pub callbacks: zc_shm_segment_callbacks_t,
}

/// zenoh-c `zc_shm_client_callbacks_t` (`zenoh_opaque.h:917-926`).
#[repr(C)]
pub struct zc_shm_client_callbacks_t {
    /// Attach to a particular shared-memory segment. `true` on success, with
    /// `out_segment` written.
    pub attach_fn:
        Option<unsafe extern "C" fn(*mut z_shm_segment_t, z_segment_id_t, *mut c_void) -> bool>,
    /// The protocol id this client implements.
    pub id_fn: Option<unsafe extern "C" fn(*mut c_void) -> z_protocol_id_t>,
}

/// An attached segment, owned by wz for as long as something can map it.
///
/// The context is `Arc`-shared for the same reason [`PtrInSegment`]'s is: the
/// attacher's `delete_fn` must not run while a mapped pointer is still in use.
pub struct AttachedSegment {
    context: Arc<DroppableContext>,
    map_fn: Option<unsafe extern "C" fn(z_chunk_id_t, *mut c_void) -> *mut u8>,
}

impl AttachedSegment {
    /// The address of one chunk, or null when the segment cannot map it.
    ///
    /// R2973 — `pub(crate)`, not `pub`. This crate's contract under
    /// `zenoh-c-shared-memory` is a C ABI, and the census that holds that claim
    /// (`OFF_AXIS`'s `ABI_CONTRACT` reading) refuses a strictly-`pub` fn with no
    /// `#[no_mangle]`: a Rust caller can name it. Nothing outside this file did
    /// (the type is not named anywhere else in the workspace), so the claim was
    /// false only by an accident of spelling. The census could not see it until
    /// it read whole attributes, because the module's gate spans several lines.
    ///
    /// R3065 -- the session maps through it: a session opened over a client storage
    /// ([`z_open_with_custom_shm_clients`]) reads every chunk of a client's protocol with it, so
    /// this is no longer a path built ahead of its consumer, and the `allow(dead_code)` that said
    /// it was is gone.
    pub(crate) fn map(&self, chunk: z_chunk_id_t) -> *mut u8 {
        let Some(map_fn) = self.map_fn else {
            return std::ptr::null_mut();
        };
        // SAFETY: the context pointer is the attacher's own, held alive by the
        // `Arc` for at least as long as this call, and `map_fn` was handed over
        // together with it.
        unsafe { map_fn(chunk, self.context.ptr) }
    }
}

/// What an owned `z_owned_shm_client_t`'s handle points at.
struct ShmClientState {
    context: Arc<DroppableContext>,
    callbacks: zc_shm_client_callbacks_t,
    /// R3065 -- whether this is wz's own POSIX client, which the runtime reader has built in and
    /// maps itself (that mapping also serves writes), rather than a client whose callbacks the
    /// reader calls. Marked at construction because a function pointer is not a thing to compare.
    builtin_posix: bool,
}

impl ShmClientState {
    /// The protocol id this client answers for.
    ///
    /// A client with no `id_fn` cannot be routed to, so it reports the reserved
    /// id 0 and [`z_shm_client_storage_new`] refuses it rather than filing it
    /// under a number it did not choose.
    fn protocol(&self) -> z_protocol_id_t {
        let Some(id_fn) = self.callbacks.id_fn else {
            return 0;
        };
        // SAFETY: as `AttachedSegment::map`.
        unsafe { id_fn(self.context.ptr) }
    }

    /// One attach attempt.
    fn attach(&self, segment: z_segment_id_t) -> Option<AttachedSegment> {
        let attach_fn = self.callbacks.attach_fn?;
        let mut out = z_shm_segment_t {
            context: zc_threadsafe_context_t {
                context: zc_threadsafe_context_data_t {
                    ptr: std::ptr::null_mut(),
                },
                delete_fn: None,
            },
            callbacks: zc_shm_segment_callbacks_t { map_fn: None },
        };
        // The gravestone above is the same divergence the provider plane names
        // (divergence 1): upstream hands the callback a `MaybeUninit`, so a
        // callback that returns `true` without writing has upstream reading
        // uninitialised memory. Here it reads a null `map_fn` and every later
        // map returns null.
        //
        // SAFETY: `out` is a live local, and the context pointer is the
        // caller's own.
        if !unsafe { attach_fn(&mut out, segment, self.context.ptr) } {
            return None;
        }
        Some(AttachedSegment {
            context: Arc::new(DroppableContext {
                ptr: out.context.context.ptr,
                delete_fn: out.delete_fn_of(),
            }),
            map_fn: out.callbacks.map_fn,
        })
    }
}

impl z_shm_segment_t {
    /// The destructor the attacher supplied, if any.
    fn delete_fn_of(&self) -> Option<unsafe extern "C" fn(*mut c_void)> {
        self.context.delete_fn
    }
}

/// What an owned `zc_owned_shm_client_list_t`'s handle points at: clients in
/// the order they were added.
struct ShmClientListState {
    clients: Vec<Arc<ShmClientState>>,
}

/// What an owned `z_owned_shm_client_storage_t`'s handle points at: the
/// resolved registry.
///
/// `Arc` because [`z_shm_client_storage_clone`] is a SHALLOW copy upstream --
/// two handles naming one registry, released once when the second goes.
struct ShmClientStorageState {
    by_protocol: Vec<(z_protocol_id_t, Arc<ShmClientState>)>,
}

impl ShmClientStorageState {
    /// The client registered for `protocol`, if one is.
    fn client(&self, protocol: z_protocol_id_t) -> Option<&Arc<ShmClientState>> {
        self.by_protocol
            .iter()
            .find(|(id, _)| *id == protocol)
            .map(|(_, c)| c)
    }
}

/// Attach `segment` through whichever client `storage` has for `protocol`.
///
/// wz's own entry point for ONE attach, which this file's tests drive to witness the registry.
/// R3065: it is no longer the storage's only reader. A session opened over a storage reads
/// through [`storage_clients`], which hands the runtime's reader every client at once; this
/// stays as the single-attach view the registry tests are written against. Not `#[no_mangle]`:
/// upstream has no such symbol, and inventing one would put a name in wz's surface the reference
/// lacks, which the census reads as a defect in the other direction.
///
/// R2973 — `pub(crate)`, for the reason this crate's contract under the feature is a C ABI: a
/// strictly-`pub` fn with no `#[no_mangle]` is a Rust path a caller can name. Its callers are this
/// file's tests, so a non-test build has no reader for it and it carries `allow(dead_code)`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn z_shm_client_storage_attach(
    storage: &z_loaned_shm_client_storage_t,
    protocol: z_protocol_id_t,
    segment: z_segment_id_t,
) -> Option<AttachedSegment> {
    let state = storage_state(storage)?;
    state.client(protocol)?.attach(segment)
}

/// R3065 -- a C client as the runtime reader's client: its `attach_fn` attaches the segment, and
/// what it attaches is mapped through the `map_fn` it supplied.
struct CClient(Arc<ShmClientState>);

/// R3065 -- a segment a C client attached, as the runtime reader's segment.
struct CSegment(AttachedSegment);

impl ShmDataSegment for CSegment {
    fn map(&self, chunk: u32) -> *mut u8 {
        self.0.map(chunk)
    }
}

impl ShmDataClient for CClient {
    fn protocol(&self) -> u32 {
        self.0.protocol()
    }

    fn attach(&self, segment: u32) -> Option<Arc<dyn ShmDataSegment>> {
        self.0
            .attach(segment)
            .map(|attached| Arc::new(CSegment(attached)) as Arc<dyn ShmDataSegment>)
    }
}

/// R3065 -- the reader a storage stands for: wz's built-in POSIX client when the storage holds it,
/// and every other client as a client of the runtime's reader. This is the storage's reader, which
/// until now was a test: a session opened over it reads what its peers send through these
/// clients and advertises exactly their protocols.
///
/// `None` when the storage is not a live loan, or its clients cannot form a set (two for one
/// protocol, which `z_shm_client_storage_new` refuses, so a storage built through the ABI cannot
/// reach it).
pub(crate) fn storage_clients(
    storage: &z_loaned_shm_client_storage_t,
) -> Option<Arc<ShmClientSet>> {
    let state = storage_state(storage)?;
    let mut posix = false;
    let mut clients: Vec<Arc<dyn ShmDataClient>> = Vec::new();
    for (_, client) in &state.by_protocol {
        if client.builtin_posix {
            posix = true;
        } else {
            clients.push(Arc::new(CClient(client.clone())));
        }
    }
    ShmClientSet::new(posix, clients).ok().map(Arc::new)
}

/// Constructs and opens a session over a client storage (zenoh-c `z_open_with_custom_shm_clients`,
/// `zenoh_commons.h`): `z_open`, with the storage's clients as the session's shared-memory reader.
///
/// What the reader holds is what the session RESOLVES and what it ADVERTISES: a peer's sender is
/// told, in the segment this session publishes, that it may send descriptors of exactly the
/// storage's protocols, and sends bytes for any other. A storage built without the default client
/// set cannot read POSIX memory, and its session says so.
///
/// Like `z_open` it consumes the config and leaves the session in its gravestone state on failure.
///
/// # Safety
/// `this_` must be valid and writable; `config` must be a valid moved config; `shm_clients` must be
/// a live loaned storage.
#[no_mangle]
pub unsafe extern "C" fn z_open_with_custom_shm_clients(
    this_: *mut crate::abi::z_owned_session_t,
    config: *mut crate::abi::z_moved_config_t,
    shm_clients: *const z_loaned_shm_client_storage_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, before any fallible work, as `z_open` writes it.
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_session_t::null_value() };
        if shm_clients.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract -- a live loan.
        let Some(set) = storage_clients(unsafe { &*shm_clients }) else {
            return Z_EINVAL;
        };
        // SAFETY: the caller's contract, delegated.
        unsafe { crate::session::open_session(this_, config, Some(set)) }
    })
}

/// The default clients every `z_ref_shm_client_storage_global` storage shares, made once: upstream's
/// global storage is ONE `Arc` that every reference clones, so two references name the same
/// clients.
fn global_clients() -> &'static [(z_protocol_id_t, Arc<ShmClientState>)] {
    static GLOBAL: std::sync::OnceLock<Vec<(z_protocol_id_t, Arc<ShmClientState>)>> =
        std::sync::OnceLock::new();
    GLOBAL.get_or_init(|| vec![(POSIX_PROTOCOL_ID, Arc::new(default_posix_client()))])
}

/// Reference the global client storage (zenoh-c `z_ref_shm_client_storage_global`): the storage
/// every session that is not given one reads through, which holds the default client set.
///
/// A reference, not a copy of the clients: what it holds is the process's one set, so a program
/// that opens a session over it (`z_open_with_custom_shm_clients`) reads exactly as `z_open` does.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_ref_shm_client_storage_global(this_: *mut z_owned_shm_client_storage_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let handle = Box::into_raw(Box::new(ShmClientStorageState {
            by_protocol: global_clients().to_vec(),
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_storage_t::from_handle(handle) };
    })
}

/// The registry behind a loaned storage handle.
fn storage_state(storage: &z_loaned_shm_client_storage_t) -> Option<&ShmClientStorageState> {
    if storage.handle.is_null() {
        return None;
    }
    // SAFETY: a non-null handle in this family was made by `Box::into_raw` of a
    // `ShmClientStorageState` and is not freed while a loan exists.
    Some(unsafe { &*(storage.handle as *const ShmClientStorageState) })
}

/// A POSIX segment this process has mapped read-only.
///
/// The naming rule is wz's OWN, not an invention of this module:
/// `wz-runtime-tokio`'s `shm_provider.rs` @ `fn shm_path` publishes at
/// `/dev/shm/wz-shm-{id:08x}.wz` and its `PosixShmResolver` opens exactly that.
/// Repeating the rule here rather than depending on that crate's private
/// function is deliberate -- it is a WIRE-side convention shared by two
/// independent halves, and a test in this module pins the two spellings
/// together so a change to either is a red rather than a silent divergence.
struct PosixSegment {
    base: *mut u8,
    len: usize,
}

impl PosixSegment {
    /// wz's segment path for `segment_id`.
    fn path(segment_id: z_segment_id_t) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/dev/shm/wz-shm-{segment_id:08x}.wz"))
    }

    /// Map the segment read-only, or `None` when it is not there.
    fn open(segment_id: z_segment_id_t) -> Option<Self> {
        let file = std::fs::File::open(Self::path(segment_id)).ok()?;
        let len = file.metadata().ok()?.len() as usize;
        if len == 0 {
            return None;
        }
        // SAFETY: a read-only shared view of a same-host segment the peer owns.
        // The `mmap` outlives every `map_fn` call because `delete_fn` runs only
        // after the last holder of the context drops, and the file descriptor is
        // not needed past the call (Linux keeps the mapping alive).
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                std::os::unix::io::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return None;
        }
        Some(Self {
            base: base as *mut u8,
            len,
        })
    }

    /// The segment's first byte.
    fn base(&self) -> *mut u8 {
        self.base
    }
}

impl Drop for PosixSegment {
    fn drop(&mut self) {
        if self.base.is_null() || self.len == 0 {
            return;
        }
        // SAFETY: `base`/`len` are exactly what `mmap` returned in `open`, and
        // nothing maps this segment twice.
        unsafe { libc::munmap(self.base as *mut c_void, self.len) };
    }
}

// SAFETY: the mapping is read-only and immutable for this type's whole life;
// `map_fn` hands out a raw pointer whose use is the caller's contract, which is
// the same promise every other pointer in this module carries.
unsafe impl Send for PosixSegment {}
// SAFETY: as above.
unsafe impl Sync for PosixSegment {}

/// wz's POSIX protocol id.
///
/// Upstream's POSIX client uses `0`, and wz matches it so the default client
/// set means the same thing on both sides. It is a value the wire never
/// carries in this build -- see the divergence note -- but it IS what a C
/// program comparing against `z_posix_shm_client_new`'s id will read.
const POSIX_PROTOCOL_ID: z_protocol_id_t = 0;

/// Create a client for a C-supplied protocol (zenoh-c `z_shm_client_new`,
/// `zenoh_commons.h:5744-5746`).
///
/// # Safety
/// `this_` must be valid and writable; `context` and `callbacks` must satisfy
/// upstream's contract (the context outlives every callback, `delete_fn` runs
/// once).
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_new(
    this_: *mut z_owned_shm_client_t,
    context: zc_threadsafe_context_t,
    callbacks: zc_shm_client_callbacks_t,
) {
    let dropped = DroppableContext {
        ptr: context.context.ptr,
        delete_fn: context.delete_fn,
    };
    guard_val((), || {
        if this_.is_null() {
            // The context still has to be released: a null out-pointer is
            // the caller's mistake, not a reason to leak their state.
            drop(dropped);
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_t::null_value() };
        let handle = Box::into_raw(Box::new(ShmClientState {
            context: Arc::new(dropped),
            callbacks,
            builtin_posix: false,
        })) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_client_t::from_handle(handle) };
    })
}

/// Create the POSIX client (zenoh-c `z_posix_shm_client_new`,
/// `zenoh_commons.h:4784`).
///
/// It attaches by wz's own segment naming -- `wz-runtime-tokio`'s
/// `shm_provider.rs` @ `fn shm_path` -- so a segment either half of this
/// workspace publishes is one this client can read.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_posix_shm_client_new(this_: *mut z_owned_shm_client_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_t::null_value() };
        let handle = Box::into_raw(Box::new(ShmClientState {
            context: Arc::new(DroppableContext {
                ptr: std::ptr::null_mut(),
                delete_fn: None,
            }),
            callbacks: zc_shm_client_callbacks_t {
                attach_fn: Some(posix_attach),
                id_fn: Some(posix_id),
            },
            builtin_posix: true,
        })) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_client_t::from_handle(handle) };
    })
}

/// The POSIX client's protocol id.
///
/// # Safety
/// Called only through [`ShmClientState::protocol`] with this client's own
/// context, which is null and unread.
unsafe extern "C" fn posix_id(_context: *mut c_void) -> z_protocol_id_t {
    POSIX_PROTOCOL_ID
}

/// Map a POSIX segment by wz's naming rule.
///
/// # Safety
/// `out_segment` must be valid and writable; called only through
/// [`ShmClientState::attach`], which supplies a live local.
unsafe extern "C" fn posix_attach(
    out_segment: *mut z_shm_segment_t,
    segment_id: z_segment_id_t,
    _context: *mut c_void,
) -> bool {
    if out_segment.is_null() {
        return false;
    }
    let Some(mapped) = PosixSegment::open(segment_id) else {
        return false;
    };
    let boxed = Box::into_raw(Box::new(mapped)) as *mut c_void;
    // SAFETY: the caller's contract -- a writable out-parameter.
    unsafe {
        *out_segment = z_shm_segment_t {
            context: zc_threadsafe_context_t {
                context: zc_threadsafe_context_data_t { ptr: boxed },
                delete_fn: Some(posix_segment_delete),
            },
            callbacks: zc_shm_segment_callbacks_t {
                map_fn: Some(posix_map),
            },
        }
    };
    true
}

/// Release a mapped POSIX segment.
///
/// # Safety
/// `context` must be the `Box::into_raw`ed [`PosixSegment`] [`posix_attach`]
/// wrote, run once (the `DroppableContext` contract).
unsafe extern "C" fn posix_segment_delete(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(context as *mut PosixSegment) });
}

/// The address of a chunk inside a mapped POSIX segment.
///
/// wz's scoped model is ONE payload per segment (`extshm.rs` collapses
/// upstream's `MetadataDescriptor{id,index}` to a single `segment_id`), so
/// every chunk id names offset 0. A non-zero id is not an error -- upstream
/// lets a backend number its chunks however it likes -- it is simply an
/// address this segment does not have, and null is what says so.
///
/// # Safety
/// `context` must be the [`PosixSegment`] [`posix_attach`] wrote.
unsafe extern "C" fn posix_map(chunk: z_chunk_id_t, context: *mut c_void) -> *mut u8 {
    if context.is_null() || chunk != 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller's contract; the segment outlives this call because
    // `delete_fn` runs only after the last holder of the context drops.
    unsafe { &*(context as *const PosixSegment) }.base()
}

/// Add `client` to `this_` (zenoh-c `zc_shm_client_list_add_client`,
/// `zenoh_commons.h:7170-7171`).
///
/// # Safety
/// `this_` must be a live loan; `client` must be a valid moved client.
#[no_mangle]
pub unsafe extern "C" fn zc_shm_client_list_add_client(
    this_: *mut zc_loaned_shm_client_list_t,
    client: *mut z_moved_shm_client_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || client.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let taken =
            unsafe { std::mem::replace(&mut (*client)._this, z_owned_shm_client_t::null_value()) };
        if taken.handle.is_null() {
            return Z_EINVAL;
        }
        // SAFETY: a non-null handle in this family was `Box::into_raw`ed here.
        let state = unsafe { Box::from_raw(taken.handle as *mut ShmClientState) };
        // SAFETY: the caller's contract -- a live loan.
        let list = unsafe { &mut *this_ };
        let Some(list_state) = list_state_mut(list) else {
            return Z_EINVAL;
        };
        list_state.clients.push(Arc::from(state));
        Z_OK
    })
}

/// The list behind a loaned handle.
fn list_state_mut(list: &mut zc_loaned_shm_client_list_t) -> Option<&mut ShmClientListState> {
    if list.handle.is_null() {
        return None;
    }
    // SAFETY: a non-null handle in this family was made by `Box::into_raw` of a
    // `ShmClientListState` and is not freed while a loan exists.
    Some(unsafe { &mut *(list.handle as *mut ShmClientListState) })
}

/// The list behind a loaned handle, shared.
fn list_state(list: &zc_loaned_shm_client_list_t) -> Option<&ShmClientListState> {
    if list.handle.is_null() {
        return None;
    }
    // SAFETY: as `list_state_mut`.
    Some(unsafe { &*(list.handle as *const ShmClientListState) })
}

/// Create an empty client list (zenoh-c `zc_shm_client_list_new`,
/// `zenoh_commons.h:7203`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_shm_client_list_new(this_: *mut zc_owned_shm_client_list_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let handle = Box::into_raw(Box::new(ShmClientListState {
            clients: Vec::new(),
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = zc_owned_shm_client_list_t::from_handle(handle) };
    })
}

/// Resolve `clients` into a storage (zenoh-c `z_shm_client_storage_new`,
/// `zenoh_commons.h:5779-5781`).
///
/// A client whose `id_fn` is absent reports the reserved id 0 and is REFUSED
/// rather than filed under a number it did not choose -- see
/// [`ShmClientState::protocol`]. A duplicate protocol id is refused for the
/// same reason: upstream's header states the contract that two incompatible
/// implementations must never share a `ProtocolID`, and silently keeping one
/// of them would decide for the caller which.
///
/// # Safety
/// `this_` must be valid and writable; `clients` must be a live loan.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_storage_new(
    this_: *mut z_owned_shm_client_storage_t,
    clients: *const zc_loaned_shm_client_list_t,
    add_default_client_set: bool,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_storage_t::null_value() };
        if clients.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract -- a live loan.
        let Some(list) = list_state(unsafe { &*clients }) else {
            return Z_EINVAL;
        };
        let mut by_protocol: Vec<(z_protocol_id_t, Arc<ShmClientState>)> = Vec::new();
        if add_default_client_set {
            by_protocol.push((POSIX_PROTOCOL_ID, Arc::new(default_posix_client())));
        }
        for client in &list.clients {
            let protocol = client.protocol();
            if protocol == 0 && client.callbacks.id_fn.is_none() {
                return Z_EINVAL;
            }
            if by_protocol.iter().any(|(id, _)| *id == protocol) {
                return Z_EINVAL;
            }
            by_protocol.push((protocol, client.clone()));
        }
        let handle = Box::into_raw(Box::new(ShmClientStorageState { by_protocol })) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_client_storage_t::from_handle(handle) };
        Z_OK
    })
}

/// The POSIX client, as the default client set's single member.
fn default_posix_client() -> ShmClientState {
    ShmClientState {
        context: Arc::new(DroppableContext {
            ptr: std::ptr::null_mut(),
            delete_fn: None,
        }),
        callbacks: zc_shm_client_callbacks_t {
            attach_fn: Some(posix_attach),
            id_fn: Some(posix_id),
        },
        builtin_posix: true,
    }
}

/// Create a storage holding only the default client set (zenoh-c
/// `z_shm_client_storage_new_default`, `zenoh_commons.h:5789`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_storage_new_default(
    this_: *mut z_owned_shm_client_storage_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let handle = Box::into_raw(Box::new(ShmClientStorageState {
            by_protocol: vec![(POSIX_PROTOCOL_ID, Arc::new(default_posix_client()))],
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_storage_t::from_handle(handle) };
    })
}

/// Shallow-copy a storage (zenoh-c `z_shm_client_storage_clone`,
/// `zenoh_commons.h:5752-5753`).
///
/// SHALLOW is the contract: the two handles name one registry, and each client
/// is released once, when the second handle goes.
///
/// # Safety
/// `this_` must be valid and writable; `from` must be a live loan.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_storage_clone(
    this_: *mut z_owned_shm_client_storage_t,
    from: *const z_loaned_shm_client_storage_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_client_storage_t::null_value() };
        if from.is_null() {
            return;
        }
        // SAFETY: the caller's contract -- a live loan.
        let Some(src) = storage_state(unsafe { &*from }) else {
            return;
        };
        let handle = Box::into_raw(Box::new(ShmClientStorageState {
            by_protocol: src.by_protocol.clone(),
        })) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_client_storage_t::from_handle(handle) };
    })
}

/// Borrow a client list (zenoh-c `zc_shm_client_list_loan`,
/// `zenoh_commons.h:7187`).
///
/// # Safety
/// `this_` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn zc_shm_client_list_loan(
    this_: *const zc_owned_shm_client_list_t,
) -> *const zc_loaned_shm_client_list_t {
    this_ as *const zc_loaned_shm_client_list_t
}

/// Borrow a client list mutably (zenoh-c `zc_shm_client_list_loan_mut`,
/// `zenoh_commons.h:7195`).
///
/// # Safety
/// `this_` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn zc_shm_client_list_loan_mut(
    this_: *mut zc_owned_shm_client_list_t,
) -> *mut zc_loaned_shm_client_list_t {
    this_ as *mut zc_loaned_shm_client_list_t
}

/// Borrow a storage (zenoh-c `z_shm_client_storage_loan`,
/// `zenoh_commons.h:5771`).
///
/// # Safety
/// `this_` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_storage_loan(
    this_: *const z_owned_shm_client_storage_t,
) -> *const z_loaned_shm_client_storage_t {
    this_ as *const z_loaned_shm_client_storage_t
}

/// Release a client (zenoh-c `z_shm_client_drop`, `zenoh_commons.h:5736`).
///
/// # Safety
/// `this_` must be a valid moved client or null.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_drop(this_: *mut z_moved_shm_client_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken =
            unsafe { std::mem::replace(&mut (*this_)._this, z_owned_shm_client_t::null_value()) };
        if taken.handle.is_null() {
            return;
        }
        // SAFETY: a non-null handle here was `Box::into_raw`ed by a
        // constructor in this family and is dropped exactly once.
        drop(unsafe { Box::from_raw(taken.handle as *mut ShmClientState) });
    })
}

/// Release a client list, and every client still in it (zenoh-c
/// `zc_shm_client_list_drop`, `zenoh_commons.h:7179`).
///
/// # Safety
/// `this_` must be a valid moved list or null.
#[no_mangle]
pub unsafe extern "C" fn zc_shm_client_list_drop(this_: *mut zc_moved_shm_client_list_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                zc_owned_shm_client_list_t::null_value(),
            )
        };
        if taken.handle.is_null() {
            return;
        }
        // SAFETY: as `z_shm_client_drop`.
        drop(unsafe { Box::from_raw(taken.handle as *mut ShmClientListState) });
    })
}

/// Release a storage (zenoh-c `z_shm_client_storage_drop`,
/// `zenoh_commons.h:5763`).
///
/// # Safety
/// `this_` must be a valid moved storage or null.
#[no_mangle]
pub unsafe extern "C" fn z_shm_client_storage_drop(this_: *mut z_moved_shm_client_storage_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                z_owned_shm_client_storage_t::null_value(),
            )
        };
        if taken.handle.is_null() {
            return;
        }
        // SAFETY: as `z_shm_client_drop`.
        drop(unsafe { Box::from_raw(taken.handle as *mut ShmClientStorageState) });
    })
}

/// `z_internal_shm_client_check` (`zenoh_commons.h:4003`).
///
/// # Safety
/// `this_` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_client_check(this_: *const z_owned_shm_client_t) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

/// `z_internal_shm_client_null` (`zenoh_commons.h:4011`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_client_null(this_: *mut z_owned_shm_client_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_shm_client_t::null_value() };
}

/// `zc_internal_shm_client_list_check` (`zenoh_commons.h:7149`).
///
/// # Safety
/// `this_` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_shm_client_list_check(
    this_: *const zc_owned_shm_client_list_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

/// `zc_internal_shm_client_list_null` (`zenoh_commons.h:7157`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_shm_client_list_null(this_: *mut zc_owned_shm_client_list_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = zc_owned_shm_client_list_t::null_value() };
}

/// `z_internal_shm_client_storage_check` (`zenoh_commons.h:4019`).
///
/// # Safety
/// `this_` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_client_storage_check(
    this_: *const z_owned_shm_client_storage_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

/// `z_internal_shm_client_storage_null` (`zenoh_commons.h:4027`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_client_storage_null(
    this_: *mut z_owned_shm_client_storage_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_shm_client_storage_t::null_value() };
}

#[cfg(test)]
mod client_registry_tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A segment file at wz's naming rule, removed when the guard drops.
    ///
    /// The fixture WRITES the input rather than borrowing one a session made,
    /// which is the shape R2289 and R2294 both had to reach for: the producing
    /// half is not reachable from this crate's build (`session-extshm` is not
    /// among the features `wz-capi-c` enables), so a test that waited for one
    /// would be measuring nothing.
    struct SegmentFile(std::path::PathBuf);

    impl SegmentFile {
        fn create(id: z_segment_id_t, bytes: &[u8]) -> Self {
            let path = PosixSegment::path(id);
            let mut f = std::fs::File::create(&path).expect("create the /dev/shm segment");
            f.write_all(bytes).expect("write the segment");
            Self(path)
        }
    }

    impl Drop for SegmentFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// wz's TWO halves spell the segment path the same way.
    ///
    /// `wz-runtime-tokio`'s `shm_provider.rs` @ `fn shm_path` is the publisher's
    /// spelling and [`PosixSegment::path`] is the attacher's. They are separate
    /// crates with no shared constant, so this pins the format string itself --
    /// a change to either half is a red here rather than a segment that exists
    /// and cannot be found.
    #[test]
    fn both_halves_name_a_segment_the_same_way() {
        assert_eq!(
            PosixSegment::path(0x0000_002a),
            std::path::PathBuf::from("/dev/shm/wz-shm-0000002a.wz"),
            "the attacher's rule is `wz-shm-{{id:08x}}.wz`, which is what \
             wz-runtime-tokio's `shm_path` publishes at"
        );
    }

    /// The default client set attaches a real /dev/shm segment and its bytes
    /// come back through `map_fn`.
    ///
    /// This is the plane's REASON: a storage is not a container of clients, it
    /// is the thing that turns a protocol id and a segment id into an address.
    #[test]
    fn the_default_client_set_maps_a_real_segment() {
        let payload = b"attached-through-the-registry";
        let _seg = SegmentFile::create(0x00ab_cdef, payload);

        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: a live local out-parameter.
        unsafe { z_shm_client_storage_new_default(&mut storage) };
        // SAFETY: as above.
        assert!(unsafe { z_internal_shm_client_storage_check(&storage) });

        // SAFETY: `storage` is live and holds a registry.
        let loaned = unsafe { &*z_shm_client_storage_loan(&storage) };
        let attached = z_shm_client_storage_attach(loaned, POSIX_PROTOCOL_ID, 0x00ab_cdef)
            .expect("the POSIX client attaches a segment that is there");
        let base = attached.map(0);
        assert!(!base.is_null(), "chunk 0 is the segment's first byte");
        // SAFETY: `base` points into a live mapping of at least `payload.len()`.
        let seen = unsafe { std::slice::from_raw_parts(base, payload.len()) };
        assert_eq!(seen, payload, "the bytes come off the shared page");

        // SAFETY: a live owned value, moved exactly once.
        unsafe { z_shm_client_storage_drop(&mut storage as *mut _ as *mut _) };
    }

    /// Attaching a segment that is NOT there fails rather than returning a
    /// mapping of nothing.
    #[test]
    fn attaching_an_absent_segment_fails() {
        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: a live local out-parameter.
        unsafe { z_shm_client_storage_new_default(&mut storage) };
        // SAFETY: `storage` is live.
        let loaned = unsafe { &*z_shm_client_storage_loan(&storage) };
        assert!(
            z_shm_client_storage_attach(loaned, POSIX_PROTOCOL_ID, 0xffff_fffe).is_none(),
            "no file, no attach"
        );
        // SAFETY: a live owned value, moved exactly once.
        unsafe { z_shm_client_storage_drop(&mut storage as *mut _ as *mut _) };
    }

    /// The state a C-supplied client is handed back.
    struct Ctx {
        id: z_protocol_id_t,
        attaches: Arc<AtomicU32>,
        maps: Arc<AtomicU32>,
        byte: u8,
    }

    unsafe extern "C" fn ctx_delete(p: *mut c_void) {
        if !p.is_null() {
            // SAFETY: the pointer this test handed over.
            drop(unsafe { Box::from_raw(p as *mut Ctx) });
        }
    }

    unsafe extern "C" fn ctx_id(p: *mut c_void) -> z_protocol_id_t {
        // SAFETY: this test's own context.
        unsafe { &*(p as *const Ctx) }.id
    }

    unsafe extern "C" fn ctx_map(_chunk: z_chunk_id_t, p: *mut c_void) -> *mut u8 {
        // SAFETY: this test's own context.
        let ctx = unsafe { &*(p as *const Ctx) };
        ctx.maps.fetch_add(1, Ordering::SeqCst);
        &ctx.byte as *const u8 as *mut u8
    }

    unsafe extern "C" fn ctx_attach(
        out: *mut z_shm_segment_t,
        _segment: z_segment_id_t,
        p: *mut c_void,
    ) -> bool {
        // SAFETY: this test's own context, and a live out-parameter.
        let ctx = unsafe { &*(p as *const Ctx) };
        ctx.attaches.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the caller supplies a writable out-parameter.
        unsafe {
            *out = z_shm_segment_t {
                context: zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t { ptr: p },
                    delete_fn: None,
                },
                callbacks: zc_shm_segment_callbacks_t {
                    map_fn: Some(ctx_map),
                },
            }
        };
        true
    }

    /// An `attach_fn` that reports success WITHOUT writing the out-parameter.
    ///
    /// Upstream hands the callback a `MaybeUninit`, so this shape has it reading
    /// uninitialised memory. wz writes a gravestone first -- divergence 1 of the
    /// provider plane, repeated here because the same callback contract applies.
    unsafe extern "C" fn silent_attach(
        _out: *mut z_shm_segment_t,
        _segment: z_segment_id_t,
        _p: *mut c_void,
    ) -> bool {
        true
    }

    fn client_for(
        id: z_protocol_id_t,
        attaches: &Arc<AtomicU32>,
        maps: &Arc<AtomicU32>,
    ) -> z_owned_shm_client_t {
        client_with(id, attaches, maps, Some(ctx_attach))
    }

    fn client_with(
        id: z_protocol_id_t,
        attaches: &Arc<AtomicU32>,
        maps: &Arc<AtomicU32>,
        attach_fn: Option<
            unsafe extern "C" fn(*mut z_shm_segment_t, z_segment_id_t, *mut c_void) -> bool,
        >,
    ) -> z_owned_shm_client_t {
        let ctx = Box::into_raw(Box::new(Ctx {
            id,
            attaches: attaches.clone(),
            maps: maps.clone(),
            byte: 0x5a,
        })) as *mut c_void;
        let mut client = z_owned_shm_client_t::null_value();
        // SAFETY: a live local out-parameter and a context this test owns.
        unsafe {
            z_shm_client_new(
                &mut client,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t { ptr: ctx },
                    delete_fn: Some(ctx_delete),
                },
                zc_shm_client_callbacks_t {
                    attach_fn,
                    id_fn: Some(ctx_id),
                },
            )
        };
        client
    }

    /// A C-supplied client is routed to BY ITS PROTOCOL ID, and the default
    /// client set does not swallow it.
    ///
    /// Two ids, two clients, one storage: the assertion is that each id reaches
    /// its own client. A registry that returned the first entry for everything
    /// would pass a one-client test and fail this one.
    #[test]
    fn the_storage_routes_by_protocol_id() {
        let attaches = Arc::new(AtomicU32::new(0));
        let maps = Arc::new(AtomicU32::new(0));
        let mut client = client_for(7, &attaches, &maps);

        let mut list = zc_owned_shm_client_list_t::null_value();
        // SAFETY: a live local out-parameter.
        unsafe { zc_shm_client_list_new(&mut list) };
        // SAFETY: as above.
        assert!(unsafe { zc_internal_shm_client_list_check(&list) });
        // SAFETY: a live list and a client moved exactly once.
        let rc = unsafe {
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut client as *mut _ as *mut z_moved_shm_client_t,
            )
        };
        assert_eq!(rc, Z_OK);
        // SAFETY: the move left a gravestone behind.
        assert!(!unsafe { z_internal_shm_client_check(&client) });

        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        let rc =
            unsafe { z_shm_client_storage_new(&mut storage, zc_shm_client_list_loan(&list), true) };
        assert_eq!(rc, Z_OK);

        // SAFETY: `storage` is live.
        let loaned = unsafe { &*z_shm_client_storage_loan(&storage) };
        let attached = z_shm_client_storage_attach(loaned, 7, 1).expect("protocol 7 is registered");
        assert_eq!(attaches.load(Ordering::SeqCst), 1, "the C client attached");
        let base = attached.map(0);
        assert_eq!(maps.load(Ordering::SeqCst), 1, "its own `map_fn` ran");
        // SAFETY: `base` is the context's live byte.
        assert_eq!(unsafe { *base }, 0x5a);

        assert!(
            z_shm_client_storage_attach(loaned, 9, 1).is_none(),
            "an unregistered protocol resolves to nothing"
        );
        assert!(
            z_shm_client_storage_attach(loaned, POSIX_PROTOCOL_ID, 0xffff_fffd).is_none(),
            "the default set is still there and still answers for its own id"
        );
        assert_eq!(
            attaches.load(Ordering::SeqCst),
            1,
            "neither miss reached the C client"
        );

        // SAFETY: live owned values, each moved exactly once.
        unsafe {
            z_shm_client_storage_drop(&mut storage as *mut _ as *mut _);
            zc_shm_client_list_drop(&mut list as *mut _ as *mut _);
        }
    }

    /// A client whose `attach_fn` returns `true` without writing gets a
    /// gravestone, not uninitialised memory: every later map is null.
    #[test]
    fn a_silent_attach_maps_nothing() {
        let attaches = Arc::new(AtomicU32::new(0));
        let maps = Arc::new(AtomicU32::new(0));
        let mut client = client_with(11, &attaches, &maps, Some(silent_attach));
        let mut list = zc_owned_shm_client_list_t::null_value();
        // SAFETY: live locals.
        unsafe {
            zc_shm_client_list_new(&mut list);
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut client as *mut _ as *mut z_moved_shm_client_t,
            );
        }
        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        unsafe { z_shm_client_storage_new(&mut storage, zc_shm_client_list_loan(&list), false) };
        // SAFETY: `storage` is live.
        let loaned = unsafe { &*z_shm_client_storage_loan(&storage) };
        let attached = z_shm_client_storage_attach(loaned, 11, 1).expect("it said true");
        assert!(
            attached.map(0).is_null(),
            "a segment whose `map_fn` was never written maps nothing"
        );
        assert_eq!(maps.load(Ordering::SeqCst), 0, "no callback ran");

        // SAFETY: live owned values, each moved exactly once.
        unsafe {
            z_shm_client_storage_drop(&mut storage as *mut _ as *mut _);
            zc_shm_client_list_drop(&mut list as *mut _ as *mut _);
        }
    }

    /// Two clients claiming ONE protocol id are refused, and so is a client
    /// with no `id_fn`.
    ///
    /// Upstream's header states the contract in the other direction ("it is up
    /// to user to make sure that incompatible implementations never use the
    /// same ProtocolID"). wz can CHECK it, and refusing is the only answer that
    /// does not silently pick one of them for the caller.
    #[test]
    fn a_duplicate_protocol_id_is_refused() {
        let attaches = Arc::new(AtomicU32::new(0));
        let maps = Arc::new(AtomicU32::new(0));
        let mut a = client_for(3, &attaches, &maps);
        let mut b = client_for(3, &attaches, &maps);
        let mut list = zc_owned_shm_client_list_t::null_value();
        // SAFETY: live locals.
        unsafe {
            zc_shm_client_list_new(&mut list);
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut a as *mut _ as *mut z_moved_shm_client_t,
            );
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut b as *mut _ as *mut z_moved_shm_client_t,
            );
        }
        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        let rc = unsafe {
            z_shm_client_storage_new(&mut storage, zc_shm_client_list_loan(&list), false)
        };
        assert_eq!(rc, Z_EINVAL, "two clients, one id");
        // SAFETY: as above.
        assert!(
            !unsafe { z_internal_shm_client_storage_check(&storage) },
            "the refusal leaves a gravestone, not a half-built registry"
        );

        // SAFETY: a live owned value, moved exactly once.
        unsafe { zc_shm_client_list_drop(&mut list as *mut _ as *mut _) };
    }

    /// The default client set OWNS the POSIX id, so a C client cannot take it.
    #[test]
    fn the_default_set_reserves_the_posix_id() {
        let attaches = Arc::new(AtomicU32::new(0));
        let maps = Arc::new(AtomicU32::new(0));
        let mut client = client_for(POSIX_PROTOCOL_ID, &attaches, &maps);
        let mut list = zc_owned_shm_client_list_t::null_value();
        // SAFETY: live locals.
        unsafe {
            zc_shm_client_list_new(&mut list);
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut client as *mut _ as *mut z_moved_shm_client_t,
            );
        }
        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        let with_default =
            unsafe { z_shm_client_storage_new(&mut storage, zc_shm_client_list_loan(&list), true) };
        assert_eq!(with_default, Z_EINVAL, "the default set is already at id 0");

        // WITHOUT the default set the same list resolves -- which is what makes
        // the assertion above about the DEFAULT SET rather than about the id.
        let mut storage2 = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        let without = unsafe {
            z_shm_client_storage_new(&mut storage2, zc_shm_client_list_loan(&list), false)
        };
        assert_eq!(without, Z_OK);

        // SAFETY: live owned values, each moved exactly once.
        unsafe {
            z_shm_client_storage_drop(&mut storage2 as *mut _ as *mut _);
            zc_shm_client_list_drop(&mut list as *mut _ as *mut _);
        }
    }

    /// A cloned storage is the SAME registry, and each client is released once.
    #[test]
    fn a_clone_is_shallow_and_releases_once() {
        static DELETED: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn counting_delete(p: *mut c_void) {
            DELETED.fetch_add(1, Ordering::SeqCst);
            if !p.is_null() {
                // SAFETY: the pointer this test handed over.
                drop(unsafe { Box::from_raw(p as *mut Ctx) });
            }
        }

        DELETED.store(0, Ordering::SeqCst);
        let ctx = Box::into_raw(Box::new(Ctx {
            id: 5,
            attaches: Arc::new(AtomicU32::new(0)),
            maps: Arc::new(AtomicU32::new(0)),
            byte: 1,
        })) as *mut c_void;
        let mut client = z_owned_shm_client_t::null_value();
        // SAFETY: live locals.
        unsafe {
            z_shm_client_new(
                &mut client,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t { ptr: ctx },
                    delete_fn: Some(counting_delete),
                },
                zc_shm_client_callbacks_t {
                    attach_fn: Some(ctx_attach),
                    id_fn: Some(ctx_id),
                },
            )
        };
        let mut list = zc_owned_shm_client_list_t::null_value();
        // SAFETY: live locals.
        unsafe {
            zc_shm_client_list_new(&mut list);
            zc_shm_client_list_add_client(
                zc_shm_client_list_loan_mut(&mut list),
                &mut client as *mut _ as *mut z_moved_shm_client_t,
            );
        }
        let mut storage = z_owned_shm_client_storage_t::null_value();
        // SAFETY: live locals.
        unsafe { z_shm_client_storage_new(&mut storage, zc_shm_client_list_loan(&list), false) };
        let mut copy = z_owned_shm_client_storage_t::null_value();
        // SAFETY: `storage` is live.
        unsafe { z_shm_client_storage_clone(&mut copy, z_shm_client_storage_loan(&storage)) };
        // SAFETY: as above.
        assert!(unsafe { z_internal_shm_client_storage_check(&copy) });

        // SAFETY: `copy` names the same registry.
        let loaned = unsafe { &*z_shm_client_storage_loan(&copy) };
        assert!(
            z_shm_client_storage_attach(loaned, 5, 1).is_some(),
            "the copy resolves what the original did"
        );

        // SAFETY: live owned values, each moved exactly once.
        unsafe { z_shm_client_storage_drop(&mut storage as *mut _ as *mut _) };
        assert_eq!(
            DELETED.load(Ordering::SeqCst),
            0,
            "the copy still holds the client"
        );
        // SAFETY: as above.
        unsafe {
            z_shm_client_storage_drop(&mut copy as *mut _ as *mut _);
            zc_shm_client_list_drop(&mut list as *mut _ as *mut _);
        }
        assert_eq!(
            DELETED.load(Ordering::SeqCst),
            1,
            "released exactly once, when the last holder went"
        );
    }

    /// Every null-tolerant entry point survives a null argument.
    #[test]
    fn null_arguments_are_survivable() {
        // SAFETY: each of these is documented to tolerate null.
        unsafe {
            z_shm_client_drop(std::ptr::null_mut());
            zc_shm_client_list_drop(std::ptr::null_mut());
            z_shm_client_storage_drop(std::ptr::null_mut());
            z_internal_shm_client_null(std::ptr::null_mut());
            zc_internal_shm_client_list_null(std::ptr::null_mut());
            z_internal_shm_client_storage_null(std::ptr::null_mut());
            z_posix_shm_client_new(std::ptr::null_mut());
            zc_shm_client_list_new(std::ptr::null_mut());
            z_shm_client_storage_new_default(std::ptr::null_mut());
            assert!(!z_internal_shm_client_check(std::ptr::null()));
            assert!(!zc_internal_shm_client_list_check(std::ptr::null()));
            assert!(!z_internal_shm_client_storage_check(std::ptr::null()));
            assert_eq!(
                z_shm_client_storage_new(std::ptr::null_mut(), std::ptr::null(), false),
                Z_ENULL
            );
            assert_eq!(
                zc_shm_client_list_add_client(std::ptr::null_mut(), std::ptr::null_mut()),
                Z_ENULL
            );
        }
    }

    /// A null out-pointer still releases the context the caller handed over.
    ///
    /// The leak this pins is invisible to every other test: the client is never
    /// built, so nothing ever drops it, and only the caller's `delete_fn` can
    /// say the state came back.
    #[test]
    fn a_null_out_pointer_still_releases_the_context() {
        static FREED: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn freeing_delete(p: *mut c_void) {
            FREED.fetch_add(1, Ordering::SeqCst);
            if !p.is_null() {
                // SAFETY: the pointer this test handed over.
                drop(unsafe { Box::from_raw(p as *mut u8) });
            }
        }

        FREED.store(0, Ordering::SeqCst);
        let state = Box::into_raw(Box::new(0u8)) as *mut c_void;
        // SAFETY: a null out-pointer is documented as survivable.
        unsafe {
            z_shm_client_new(
                std::ptr::null_mut(),
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t { ptr: state },
                    delete_fn: Some(freeing_delete),
                },
                zc_shm_client_callbacks_t {
                    attach_fn: None,
                    id_fn: None,
                },
            )
        };
        assert_eq!(FREED.load(Ordering::SeqCst), 1);
    }
}
