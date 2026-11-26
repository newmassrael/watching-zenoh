// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_object_pool_*`: the doors through which a program reserves the process pools itself, and
//! reads what they hold (`crate::process_pool`, where the pools and their counts are described).
//!
//! Doors wz has and zenoh-pico does not, so each is `zext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `object-pool` capability implies `unstable-api`. The pools
//! themselves are not the doors': a library without the tokio engine has them whether or not it has
//! the doors, reserved by its first object from the build's limits, so a build without the unstable
//! surface makes no allocation for its objects either.
//!
//! # Reserving
//!
//! A program that states its own counts reserves the pools before its first object: from the heap
//! in one allocation (`zext_object_pool_reserve`) or, with the `object-pool-region` capability,
//! over memory it hands over (`zext_object_pool_place`), whose size `zext_object_pool_bytes`
//! answers. A reservation is all or nothing: a refused one leaves no pool and touches no memory.
//! The counts are read as the pools' module says: the entity counts per session, bounded by the
//! limits a session opens under; every other count as stated, zero being none, so a program that
//! reserves its own pools states the configs it makes, the hellos it keeps and the bytes its
//! payloads carry as well.
//!
//! The counts carry their own size (`struct_size`), because a count is added at the end of the
//! struct as the library learns to pool another object: a program compiled before it hands a
//! shorter struct, whose bytes past its size are not the library's to read. A count past
//! `struct_size` is read as zero, which for an entity is its limit's bound, as it was before the
//! count was added.
//!
//! # Reading
//!
//! The pools are reported by size class (`zext_object_pool_class`), the pools whose slots a
//! class holds together, the kinds' and the payload blocks': the class's largest slot, their slots
//! and the bytes those take (a slot is its object's own size, so the slots of one class differ),
//! those in use, the most in use at once and the objects refused for want of a free slot. A
//! payload refused is counted in the class of the smallest pool of payload blocks that holds it,
//! or of its own bytes when none does. A pool whose slots are larger than the largest class is
//! reported by none.
//!
//! # Payload blocks
//!
//! The bytes the payloads, strings and slices a program holds carry lie in three pools of fixed
//! blocks, small, middle and largest, whose counts the program states
//! (`small_payload_blocks`, `medium_payload_blocks`, `large_payload_blocks`). The sizes are the
//! build's: `PAYLOAD_SMALL_BLOCK_BYTES`, `PAYLOAD_MEDIUM_BLOCK_BYTES`, and a largest block that
//! holds the largest message a session of the build delivers. `payload_bytes`, which stated one
//! area of blocks split and joined in halves, is refused with `Z_EINVAL` when it is not zero: its
//! bytes say nothing of how many blocks of each size they are, and are not read as if they did.
//!
//! # Releasing
//!
//! `zext_object_pool_release` gives the pools up when no object is held in them: the heap's
//! memory is freed and the program's is the program's again. The next object reserves the build's
//! pools again, unless the program reserves its own first.

#[cfg(feature = "object-pool-region")]
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;
#[cfg(feature = "object-pool-region")]
use core::ptr::NonNull;

use crate::ffi::guarded;
use crate::process_pool::{self, Counts, Plan, Refused, Unplanned};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};
use crate::sized::{Out, SizedOut};

/// How many size classes the pools are reported by, the largest slot of the smallest 16 bytes and
/// each one's twice the one before's, up to 16 KiB.
pub const ZEXT_OBJECT_POOL_CLASSES: usize = process_pool::CLASSES;

/// How many of each object the program holds at once, as it states them to reserve the pools.
///
/// The entity counts (`publishers` to `liveliness_subscribers`, `queriers`, `keyexprs`, `gets`,
/// `liveliness_gets`, `matching_listeners`, `decl_watches`, `transport_events_listeners` and
/// `link_events_listeners`) are per session; the rest are for all sessions together. Zero is read as the module says: the bound of the session's limit where one bounds
/// the object, none where none does. Every field is a `usize`, so the struct has no padding and a
/// count lies whole before `struct_size` or past it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct zext_object_pool_counts_t {
    /// The bytes of the struct the program was compiled with, `sizeof` of it: the counts past them
    /// are read as zero, and a size short of the counts up to `encodings` is refused.
    pub struct_size: usize,
    /// Sessions open at once: an open past them is refused as out of memory, before it dials.
    pub sessions: usize,
    /// Publishers of each session.
    pub publishers: usize,
    /// Subscribers of each session, at most its `MAX_SUBSCRIPTIONS`.
    pub subscribers: usize,
    /// Queryables of each session, at most its `MAX_QUERYABLES`.
    pub queryables: usize,
    /// Liveliness tokens of each session, at most its `MAX_LOCAL_TOKENS`.
    pub liveliness_tokens: usize,
    /// Liveliness subscribers of each session (an advanced subscriber's detection of publishers
    /// among them), at most its `MAX_LIVELINESS_SUBSCRIPTIONS`.
    pub liveliness_subscribers: usize,
    /// Owned samples: taken out of a callback, cloned, or held in a channel.
    pub samples: usize,
    /// Owned replies and reply errors.
    pub replies: usize,
    /// Owned queries, each holding its query open until it is dropped.
    pub queries: usize,
    /// Accepted with any value and of no effect: an owned payload (`z_owned_bytes_t`) lies in its
    /// own value and takes no slot of the pools, only a payload block for its bytes. Kept so that a
    /// program's struct keeps its layout and a program that states it is not refused.
    pub bytes: usize,
    /// Configs (`z_owned_config_t`), each from `z_config_default` or `z_config_clone` to its
    /// move into an open or a scout, or its drop.
    pub configs: usize,
    /// Hellos the program keeps (`z_hello_clone`).
    pub hellos: usize,
    /// Zero. A count of bytes of payload is no count of blocks of the three pools of payload
    /// blocks (`small_payload_blocks` and the two after it), so one not zero is refused with
    /// `Z_EINVAL` by every door that reads counts.
    pub payload_bytes: usize,
    /// Queriers of each session, at most its `MAX_QUERIERS`.
    pub queriers: usize,
    /// Key expressions of each session the program holds declared (`z_declare_keyexpr`), at most
    /// its `MAX_DECLARED_KEYEXPRS`.
    pub keyexprs: usize,
    /// Encodings (`z_owned_encoding_t`), each with room for a schema of
    /// `MAX_ENCODING_SCHEMA_BYTES`, from `z_encoding_from_str` or `z_encoding_clone` to its move
    /// into the call it describes or its drop; a declared publisher keeps the one it was given.
    pub encodings: usize,
    /// Gets each session holds pending, its queriers' among them, at most its
    /// `MAX_PENDING_QUERIES`. The first count read only when `struct_size` holds it.
    pub gets: usize,
    /// Liveliness gets each session holds pending, at most its `MAX_PENDING_LIVELINESS_GETS`.
    pub liveliness_gets: usize,
    /// Matching listeners of each session, its publishers' and queriers' together, at most its
    /// `MAX_MATCHING_LISTENERS`.
    pub matching_listeners: usize,
    /// Declaration watches of each session, at most its `MAX_DECL_WATCHES`; none taken in a build
    /// without the declaration watch.
    pub decl_watches: usize,
    /// Transport events listeners of each session, at most its `MAX_TRANSPORT_EVENTS_LISTENERS`;
    /// none taken in a build without `connectivity`.
    pub transport_events_listeners: usize,
    /// Link events listeners of each session, at most its `MAX_LINK_EVENTS_LISTENERS`; none taken
    /// in a build without `connectivity`.
    pub link_events_listeners: usize,
    /// Blocks of `PAYLOAD_SMALL_BLOCK_BYTES` bytes, the smallest pool of payload blocks, for all
    /// sessions together.
    pub small_payload_blocks: usize,
    /// Blocks of `PAYLOAD_MEDIUM_BLOCK_BYTES` bytes, the middle pool of payload blocks.
    pub medium_payload_blocks: usize,
    /// Blocks of the largest pool of payload blocks, each holding the largest message a session of
    /// the build delivers and its 16-byte head.
    pub large_payload_blocks: usize,
}

/// The bytes of the counts every program states, `struct_size` to `encodings`: the struct as it was
/// when it took its size, so a `struct_size` under it is no struct of this door.
const COUNTS_BASE_BYTES: usize = offset_of!(zext_object_pool_counts_t, gets);

/// The bytes of one count of the struct: a word of the host.
const WORD_BYTES: usize = size_of::<usize>();

impl Default for zext_object_pool_counts_t {
    /// No count stated, in a struct of this build's size.
    fn default() -> Self {
        Self {
            struct_size: size_of::<Self>(),
            sessions: 0,
            publishers: 0,
            subscribers: 0,
            queryables: 0,
            liveliness_tokens: 0,
            liveliness_subscribers: 0,
            samples: 0,
            replies: 0,
            queries: 0,
            bytes: 0,
            configs: 0,
            hellos: 0,
            payload_bytes: 0,
            queriers: 0,
            keyexprs: 0,
            encodings: 0,
            gets: 0,
            liveliness_gets: 0,
            matching_listeners: 0,
            decl_watches: 0,
            transport_events_listeners: 0,
            link_events_listeners: 0,
            small_payload_blocks: 0,
            medium_payload_blocks: 0,
            large_payload_blocks: 0,
        }
    }
}

impl zext_object_pool_counts_t {
    /// The counts as the pools read them.
    fn counts(&self) -> Counts {
        Counts {
            sessions: self.sessions,
            publishers: self.publishers,
            subscribers: self.subscribers,
            queryables: self.queryables,
            liveliness_tokens: self.liveliness_tokens,
            liveliness_subscribers: self.liveliness_subscribers,
            samples: self.samples,
            replies: self.replies,
            queries: self.queries,
            configs: self.configs,
            hellos: self.hellos,
            queriers: self.queriers,
            keyexprs: self.keyexprs,
            payload_blocks: [
                self.small_payload_blocks,
                self.medium_payload_blocks,
                self.large_payload_blocks,
            ],
            encodings: self.encodings,
            gets: self.gets,
            liveliness_gets: self.liveliness_gets,
            matching_listeners: self.matching_listeners,
            decl_watches: self.decl_watches,
            transport_events_listeners: self.transport_events_listeners,
            // At the bound of the session's `MAX_ADVANCED_PUBLISHERS` and
            // `MAX_ADVANCED_SUBSCRIBERS`, which the program states no count of.
            advanced_publishers: 0,
            advanced_subscribers: 0,
            link_events_listeners: self.link_events_listeners,
        }
    }
}

/// The pools of one size class, the kinds whose slots it holds together, as
/// `zext_object_pool_class` reports them, into a struct the program sized (`crate::sized`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct zext_object_pool_class_t {
    /// The bytes of the struct the program was compiled with; the door sets it to the bytes it
    /// wrote.
    pub struct_size: usize,
    /// The class's largest slot: each slot it reports holds an object of at most this many bytes.
    pub slot_bytes: usize,
    /// Its slots; zero while no pool is reserved.
    pub slots: usize,
    /// The slots holding an object now.
    pub in_use: usize,
    /// The most slots that held an object at once since the reservation.
    pub high_water: usize,
    /// The objects it refused for want of a free slot since the reservation.
    pub refused: usize,
    /// The bytes its slots take, each slot its object's own size; zero while no pool is reserved.
    pub bytes: usize,
}

impl Default for zext_object_pool_class_t {
    /// Nothing reported, in a struct of this build's size.
    fn default() -> Self {
        Self {
            struct_size: core::mem::size_of::<Self>(),
            slot_bytes: 0,
            slots: 0,
            in_use: 0,
            high_water: 0,
            refused: 0,
            bytes: 0,
        }
    }
}

// SAFETY: `#[repr(C)]`, `struct_size` first.
unsafe impl SizedOut for zext_object_pool_class_t {
    const BASE: usize = core::mem::size_of::<Self>();
}

/// The code a door answers for counts that make no pools.
fn code_of(unplanned: Unplanned) -> ZResult {
    match unplanned {
        Unplanned::Unbounded | Unplanned::Empty => Z_ERR_CONFIG_INVALID_VALUE,
        Unplanned::TooLarge => Z_ERR_SYSTEM_OUT_OF_MEMORY,
    }
}

/// The code a door answers for a reservation it did not make.
fn refused_code(refused: Refused) -> ZResult {
    match refused {
        Refused::Reserved => Z_EINVAL,
        Refused::NoMemory => Z_ERR_SYSTEM_OUT_OF_MEMORY,
    }
}

/// The counts the program states at `counts`, read no further than its `struct_size`: a count past
/// it, or past this build's struct, is zero. `Z_ERR_NULL` for a null `counts`, `Z_EINVAL` for a
/// `struct_size` under [`COUNTS_BASE_BYTES`].
///
/// # Safety
/// `counts` is null or points at a struct of at least `struct_size` readable bytes, `struct_size`
/// its first field.
unsafe fn stated(
    counts: *const zext_object_pool_counts_t,
) -> Result<zext_object_pool_counts_t, ZResult> {
    if counts.is_null() {
        return Err(Z_ERR_NULL);
    }
    // `struct_size` is the first word: read alone, as the struct may be shorter than this build's,
    // and unaligned, so the read holds whatever address the program hands.
    let declared = counts.cast::<usize>().read_unaligned();
    if declared < COUNTS_BASE_BYTES {
        return Err(Z_EINVAL);
    }
    // A count the struct holds only in part is not read: the bytes of the whole words that fit, a
    // word's bytes being a power of two.
    let bytes = declared.min(size_of::<zext_object_pool_counts_t>()) & !(WORD_BYTES - 1);
    let mut read = zext_object_pool_counts_t::default();
    // Copied as bytes, which need no alignment of the program's struct.
    ptr::copy_nonoverlapping(
        counts.cast::<u8>(),
        ptr::addr_of_mut!(read).cast::<u8>(),
        bytes,
    );
    Ok(read)
}

/// The pools `counts` make; `Z_EINVAL` for counts that state payload bytes, which no pool reads.
///
/// # Safety
/// As [`stated`].
unsafe fn planned(counts: *const zext_object_pool_counts_t) -> Result<Plan, ZResult> {
    let stated = stated(counts)?;
    if stated.payload_bytes != 0 {
        return Err(Z_EINVAL);
    }
    process_pool::plan_of(&stated.counts()).map_err(code_of)
}

/// The bytes the pools of `counts` take, in `out_bytes` (zero on every error): what memory a
/// program hands `zext_object_pool_place`. `Z_OK`; `Z_ERR_NULL` for a NULL argument;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make no pool (a count left at zero whose limit
/// holds no bound, or no slot at all); `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for more than the address
/// space holds; `Z_EINVAL` for a `struct_size` short of the counts up to `encodings`, or for a
/// `payload_bytes` not zero.
#[no_mangle]
pub unsafe extern "C" fn zext_object_pool_bytes(
    counts: *const zext_object_pool_counts_t,
    out_bytes: *mut usize,
) -> ZResult {
    guarded(|| {
        if out_bytes.is_null() {
            return Z_ERR_NULL;
        }
        *out_bytes = 0;
        match planned(counts).and_then(|plan| plan.bytes().map_err(code_of)) {
            Ok(bytes) => {
                *out_bytes = bytes;
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Reserve the pools of `counts` from the heap, in one allocation. `Z_OK`; `Z_ERR_NULL` for a
/// NULL `counts`; `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make no pool;
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the heap has not the memory; `Z_EINVAL` when pools are
/// reserved already, for a `struct_size` short of the counts up to `encodings`, or for a
/// `payload_bytes` not zero. Every refusal
/// leaves the heap as it was.
#[no_mangle]
pub unsafe extern "C" fn zext_object_pool_reserve(
    counts: *const zext_object_pool_counts_t,
) -> ZResult {
    guarded(|| match planned(counts) {
        Ok(plan) => process_pool::reserve(&plan).map_or_else(refused_code, |()| Z_OK),
        Err(code) => code,
    })
}

/// Reserve the pools of `counts` over the `len` bytes the program hands over at `base`, which
/// the library uses until `zext_object_pool_release` and the program must not touch meanwhile.
/// `Z_OK`; `Z_ERR_NULL` for a NULL argument; `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make
/// no pool; `Z_EINVAL` for a `base` not aligned to 16 bytes, when pools are reserved already, or
/// for a `struct_size` short of the counts up to `encodings` or a `payload_bytes` not zero;
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for a `len` under what `zext_object_pool_bytes` answers. A
/// refused call writes nothing at `base`.
#[cfg(feature = "object-pool-region")]
#[no_mangle]
pub unsafe extern "C" fn zext_object_pool_place(
    base: *mut c_void,
    len: usize,
    counts: *const zext_object_pool_counts_t,
) -> ZResult {
    guarded(|| {
        let Some(base) = NonNull::new(base.cast::<u8>()) else {
            return Z_ERR_NULL;
        };
        let plan = match planned(counts) {
            Ok(plan) => plan,
            Err(code) => return code,
        };
        if base.as_ptr() as usize % process_pool::SLOT_ALIGN != 0 {
            return Z_EINVAL;
        }
        match plan.bytes() {
            Ok(bytes) if bytes <= len => {}
            _ => return Z_ERR_SYSTEM_OUT_OF_MEMORY,
        }
        // SAFETY: the program hands the memory over, aligned and long enough, for the pools alone.
        process_pool::place(base, &plan).map_or_else(refused_code, |()| Z_OK)
    })
}

/// The pools of size class `class` together (`0` to `ZEXT_OBJECT_POOL_CLASSES - 1`, the largest
/// slot of each twice the one before's), in `out`: its largest slot, and while pools are reserved
/// their slots and the bytes those take, those in use, the most in use at once and the objects they
/// refused. `Z_OK`;
/// `Z_ERR_NULL` for a NULL `out`; `Z_EINVAL` for a `class` past the last, or for a `struct_size`
/// short of the struct, nothing written then.
#[no_mangle]
pub unsafe extern "C" fn zext_object_pool_class(
    class: usize,
    out: *mut zext_object_pool_class_t,
) -> ZResult {
    guarded(|| {
        let out = match Out::of(out) {
            Ok(out) => out,
            Err(code) => return code,
        };
        if class >= ZEXT_OBJECT_POOL_CLASSES {
            return Z_EINVAL;
        }
        let report = process_pool::report(class);
        out.put(&zext_object_pool_class_t {
            struct_size: 0,
            slot_bytes: report.slot_bytes,
            slots: report.slots,
            in_use: report.in_use,
            high_water: report.high_water,
            refused: report.refused,
            bytes: report.bytes,
        });
        Z_OK
    })
}

/// Give the pools up, so that the next object reserves the build's again: the heap's memory is
/// freed, a program's is the program's again. `Z_OK`, also when none are reserved; `Z_EINVAL`
/// while an object is held in them, which keeps them.
#[no_mangle]
pub extern "C" fn zext_object_pool_release() -> ZResult {
    guarded(|| {
        if process_pool::release() {
            Z_OK
        } else {
            Z_EINVAL
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each count a program states is read into the count of the same object, and the count of
    /// payloads, which take no slot, into none.
    #[test]
    fn every_count_the_program_states_is_read() {
        let stated = zext_object_pool_counts_t {
            struct_size: size_of::<zext_object_pool_counts_t>(),
            sessions: 1,
            publishers: 2,
            subscribers: 3,
            queryables: 4,
            liveliness_tokens: 5,
            liveliness_subscribers: 6,
            samples: 7,
            replies: 8,
            queries: 9,
            bytes: 10,
            configs: 11,
            hellos: 12,
            payload_bytes: 13,
            queriers: 14,
            keyexprs: 15,
            encodings: 16,
            gets: 17,
            liveliness_gets: 18,
            matching_listeners: 19,
            decl_watches: 20,
            transport_events_listeners: 21,
            link_events_listeners: 22,
            small_payload_blocks: 23,
            medium_payload_blocks: 24,
            large_payload_blocks: 25,
        };
        assert_eq!(
            stated.counts(),
            Counts {
                sessions: 1,
                publishers: 2,
                subscribers: 3,
                queryables: 4,
                liveliness_tokens: 5,
                liveliness_subscribers: 6,
                samples: 7,
                replies: 8,
                queries: 9,
                configs: 11,
                hellos: 12,
                queriers: 14,
                keyexprs: 15,
                payload_blocks: [23, 24, 25],
                encodings: 16,
                gets: 17,
                liveliness_gets: 18,
                matching_listeners: 19,
                decl_watches: 20,
                transport_events_listeners: 21,
                advanced_publishers: 0,
                advanced_subscribers: 0,
                link_events_listeners: 22,
            }
        );
    }

    /// The count of payloads is accepted whatever it is and changes nothing the counts make: a
    /// payload takes no slot. Turned red by a `counts` that reads `bytes` into any count.
    #[test]
    fn the_count_of_payloads_changes_nothing() {
        let none = zext_object_pool_counts_t {
            bytes: 0,
            ..every_count(size_of::<zext_object_pool_counts_t>())
        };
        let most = zext_object_pool_counts_t {
            bytes: usize::MAX,
            ..none
        };
        assert_eq!(most.counts(), none.counts());
    }

    /// Counts with every field stated and a nonzero sentinel in each, as a program compiled with
    /// this build's struct would hand them; `struct_size` set by the caller.
    fn every_count(struct_size: usize) -> zext_object_pool_counts_t {
        zext_object_pool_counts_t {
            struct_size,
            sessions: 1,
            publishers: 2,
            subscribers: 3,
            queryables: 4,
            liveliness_tokens: 5,
            liveliness_subscribers: 6,
            samples: 7,
            replies: 8,
            queries: 9,
            bytes: 10,
            configs: 11,
            hellos: 12,
            payload_bytes: 13,
            queriers: 14,
            keyexprs: 15,
            encodings: 16,
            gets: 17,
            liveliness_gets: 18,
            matching_listeners: 19,
            decl_watches: 20,
            transport_events_listeners: 21,
            link_events_listeners: 22,
            small_payload_blocks: 23,
            medium_payload_blocks: 24,
            large_payload_blocks: 25,
        }
    }

    /// The base is the struct up to `encodings`, the counts every program states.
    #[test]
    fn the_base_ends_where_the_counts_added_later_begin() {
        assert_eq!(COUNTS_BASE_BYTES, 17 * size_of::<usize>());
        assert_eq!(
            size_of::<zext_object_pool_counts_t>(),
            COUNTS_BASE_BYTES + 9 * size_of::<usize>()
        );
        assert_eq!(
            zext_object_pool_counts_t::default().struct_size,
            size_of::<zext_object_pool_counts_t>()
        );
    }

    /// A program compiled before `gets` was added hands a struct that ends at `encodings`: its
    /// counts are read, and the bytes past its size, which are not its struct's, are not, so the
    /// nine later counts read as zero (their limits' bounds, and no payload blocks).
    #[test]
    fn an_older_struct_has_only_its_own_counts_read() {
        let older = every_count(COUNTS_BASE_BYTES);
        // SAFETY: `older` is a live, aligned struct of at least its `struct_size`.
        let read = unsafe { stated(&older) }.expect("a struct of the base size is read");
        assert_eq!(
            read,
            zext_object_pool_counts_t {
                gets: 0,
                liveliness_gets: 0,
                matching_listeners: 0,
                decl_watches: 0,
                transport_events_listeners: 0,
                link_events_listeners: 0,
                small_payload_blocks: 0,
                medium_payload_blocks: 0,
                large_payload_blocks: 0,
                ..every_count(COUNTS_BASE_BYTES)
            }
        );
        // One count past the base: `gets` is the program's, the five after it are not.
        let one_more = COUNTS_BASE_BYTES + size_of::<usize>();
        // SAFETY: as above.
        let read = unsafe { stated(&every_count(one_more)) }.expect("read");
        assert_eq!((read.gets, read.liveliness_gets), (17, 0));
        // A size that holds part of a count does not have that count read.
        let part = COUNTS_BASE_BYTES + size_of::<usize>() / 2;
        // SAFETY: as above.
        let read = unsafe { stated(&every_count(part)) }.expect("read");
        assert_eq!(read.gets, 0);
    }

    /// A struct of this build's size, or of a later build's larger one, has every count this build
    /// knows read, and nothing past this build's struct.
    #[test]
    fn a_struct_of_this_size_or_larger_has_every_count_read() {
        let full = size_of::<zext_object_pool_counts_t>();
        // SAFETY: `every_count` is a live struct of this build's size.
        let read = unsafe { stated(&every_count(full)) }.expect("read");
        assert_eq!(read, every_count(full));

        #[repr(C)]
        struct Later {
            counts: zext_object_pool_counts_t,
            added: usize,
        }
        let later = Later {
            counts: every_count(full + size_of::<usize>()),
            added: 99,
        };
        assert_eq!(later.added, 99);
        // SAFETY: `later` holds `struct_size` bytes from its first field on.
        let read = unsafe { stated(ptr::addr_of!(later).cast()) }.expect("read");
        assert_eq!(read, every_count(full + size_of::<usize>()));
        assert_eq!(read.counts(), every_count(full).counts());
    }

    /// A `struct_size` short of the base, zero among them, is refused by every door that reads
    /// counts, which sizes and reserves nothing; a null struct is refused as null.
    #[test]
    fn a_struct_short_of_the_base_is_refused() {
        for short in [
            0,
            1,
            COUNTS_BASE_BYTES - size_of::<usize>(),
            COUNTS_BASE_BYTES - 1,
        ] {
            let counts = every_count(short);
            // SAFETY: `counts` is a live struct, longer than the size it states.
            assert_eq!(unsafe { stated(&counts) }, Err(Z_EINVAL), "{short}");
            let mut bytes = 7usize;
            // SAFETY: both arguments are live locals.
            let code = unsafe { zext_object_pool_bytes(&counts, &mut bytes) };
            assert_eq!((code, bytes), (Z_EINVAL, 0), "{short}");
        }
        // SAFETY: a null pointer is the case under test.
        assert_eq!(unsafe { stated(ptr::null()) }, Err(Z_ERR_NULL));
    }

    /// The report of a class is refused, untouched, to a struct a byte short of the struct.
    /// Turned red by a write before the size is read.
    #[test]
    fn a_class_report_short_of_the_struct_is_refused_untouched() {
        crate::sized::a_short_struct_is_refused_untouched::<zext_object_pool_class_t, _>(
            |out| {
                // SAFETY: `out` is a live struct of this build's size.
                unsafe { zext_object_pool_class(0, out) }
            },
            Z_EINVAL,
        );
    }

    /// Counts that make no pool answer an invalid value, and counts past the address space no
    /// memory; a reservation refused for pools held already answers `Z_EINVAL`.
    #[test]
    fn each_refusal_answers_its_code() {
        assert_eq!(code_of(Unplanned::Unbounded), Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(code_of(Unplanned::Empty), Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(code_of(Unplanned::TooLarge), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert_eq!(refused_code(Refused::Reserved), Z_EINVAL);
        assert_eq!(refused_code(Refused::NoMemory), Z_ERR_SYSTEM_OUT_OF_MEMORY);
    }

    /// Counts that state payload bytes are refused with `Z_EINVAL` by every door that reads counts,
    /// which sizes and reserves nothing, rather than read as blocks of some size; the same counts
    /// with no payload bytes are planned, their payload blocks among the bytes. Turned red by a
    /// door that reads the bytes, or ignores them, or by a plan that leaves the blocks out.
    #[test]
    fn counts_that_state_payload_bytes_are_refused() {
        let full = size_of::<zext_object_pool_counts_t>();
        let stating = every_count(full);
        assert_ne!(stating.payload_bytes, 0);
        let mut bytes = 7usize;
        // SAFETY: both arguments are live locals.
        let code = unsafe { zext_object_pool_bytes(&stating, &mut bytes) };
        assert_eq!((code, bytes), (Z_EINVAL, 0));
        // SAFETY: a live local; refused before anything is reserved.
        assert_eq!(unsafe { zext_object_pool_reserve(&stating) }, Z_EINVAL);

        let blocks = zext_object_pool_counts_t {
            payload_bytes: 0,
            ..stating
        };
        let none = zext_object_pool_counts_t {
            small_payload_blocks: 0,
            medium_payload_blocks: 0,
            large_payload_blocks: 0,
            ..blocks
        };
        // SAFETY: live locals.
        let with = unsafe { planned(&blocks) }.expect("planned");
        // SAFETY: live locals.
        let without = unsafe { planned(&none) }.expect("planned");
        let grown = with.bytes().expect("bytes") - without.bytes().expect("bytes");
        assert!(grown >= 25 * process_pool::LARGEST_BLOCK, "{grown}");
    }

    /// Counts of nothing are refused by the door that sizes them, which writes zero.
    #[test]
    fn counts_of_nothing_are_refused_and_size_nothing() {
        let nothing = zext_object_pool_counts_t::default();
        let mut bytes = 7usize;
        // SAFETY: both arguments are live locals.
        let code = unsafe { zext_object_pool_bytes(&nothing, &mut bytes) };
        assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(bytes, 0);
    }
}
