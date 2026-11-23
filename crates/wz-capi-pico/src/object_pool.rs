// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_object_pool_*`: the doors through which a program reserves the process pools itself, and
//! reads what they hold (`crate::process_pool`, where the pools and their counts are described).
//!
//! Doors wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `object-pool` capability implies `unstable-api`. The pools
//! themselves are not the doors': a library without the tokio engine has them whether or not it has
//! the doors, reserved by its first object from the build's limits, so a build without the unstable
//! surface makes no allocation for its objects either.
//!
//! # Reserving
//!
//! A program that states its own counts reserves the pools before its first object: from the heap
//! in one allocation (`wz_ext_object_pool_reserve`) or, with the `object-pool-region` capability,
//! over memory it hands over (`wz_ext_object_pool_place`), whose size `wz_ext_object_pool_bytes`
//! answers. A reservation is all or nothing: a refused one leaves no pool and touches no memory.
//! The counts are read as the pools' module says: the entity counts per session, bounded by the
//! limits a session opens under; every other count as stated, zero being none, so a program that
//! reserves its own pools states the configs it makes and the hellos it keeps as well.
//!
//! # Reading
//!
//! The pools are reported by slot size (`wz_ext_object_pool_class`), the kinds of one size
//! together: their slots, those in use, the most in use at once and the objects refused for want of
//! a free slot. A pool whose slots are larger than the largest class (a config of the build's text)
//! is reported by none.
//!
//! # Releasing
//!
//! `wz_ext_object_pool_release` gives the pools up when no object is held in them: the heap's
//! memory is freed and the program's is the program's again. The next object reserves the build's
//! pools again, unless the program reserves its own first.

#[cfg(feature = "object-pool-region")]
use core::ffi::c_void;
#[cfg(feature = "object-pool-region")]
use core::ptr::NonNull;

use crate::ffi::guarded;
use crate::process_pool::{self, Counts, Plan, Refused, Unplanned};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};

/// How many slot sizes there are, the smallest 16 bytes and each one twice the one before, up to
/// 16 KiB: the classes the pools are reported by.
pub const WZ_EXT_OBJECT_POOL_CLASSES: usize = process_pool::CLASSES;

/// How many of each object the program holds at once, as it states them to reserve the pools.
///
/// The entity counts (`publishers` to `liveliness_subscribers`) are per session; the rest are for
/// all sessions together. Zero is read as the module says: the bound of the session's limit where
/// one bounds the object, none where none does.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_object_pool_counts_t {
    /// Open sessions.
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
    /// Owned payloads (`z_owned_bytes_t`).
    pub bytes: usize,
    /// Configs (`z_owned_config_t`), each from `z_config_default` or `z_config_clone` to its
    /// move into an open or a scout, or its drop.
    pub configs: usize,
    /// Hellos the program keeps (`z_hello_clone`).
    pub hellos: usize,
}

impl wz_ext_object_pool_counts_t {
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
            bytes: self.bytes,
            configs: self.configs,
            hellos: self.hellos,
        }
    }
}

/// The pools of one slot size, the kinds of that size together, as `wz_ext_object_pool_class`
/// reports them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_object_pool_class_t {
    /// The bytes of each of its slots.
    pub slot_bytes: usize,
    /// Its slots; zero while no pool is reserved.
    pub slots: usize,
    /// The slots holding an object now.
    pub in_use: usize,
    /// The most slots that held an object at once since the reservation.
    pub high_water: usize,
    /// The objects it refused for want of a free slot since the reservation.
    pub refused: usize,
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

/// The pools `counts` make.
///
/// # Safety
/// `counts` is null or points at a valid `wz_ext_object_pool_counts_t`.
unsafe fn planned(counts: *const wz_ext_object_pool_counts_t) -> Result<Plan, ZResult> {
    if counts.is_null() {
        return Err(Z_ERR_NULL);
    }
    process_pool::plan_of(&(*counts).counts()).map_err(code_of)
}

/// The bytes the pools of `counts` take, in `out_bytes` (zero on every error): what memory a
/// program hands `wz_ext_object_pool_place`. `Z_OK`; `Z_ERR_NULL` for a NULL argument;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make no pool (a count left at zero whose limit
/// holds no bound, or no slot at all); `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for more than the address
/// space holds.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_bytes(
    counts: *const wz_ext_object_pool_counts_t,
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
/// reserved already. Every refusal leaves the heap as it was.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_reserve(
    counts: *const wz_ext_object_pool_counts_t,
) -> ZResult {
    guarded(|| match planned(counts) {
        Ok(plan) => process_pool::reserve(&plan).map_or_else(refused_code, |()| Z_OK),
        Err(code) => code,
    })
}

/// Reserve the pools of `counts` over the `len` bytes the program hands over at `base`, which
/// the library uses until `wz_ext_object_pool_release` and the program must not touch meanwhile.
/// `Z_OK`; `Z_ERR_NULL` for a NULL argument; `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make
/// no pool; `Z_EINVAL` for a `base` not aligned to 16 bytes, or when pools are reserved already;
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for a `len` under what `wz_ext_object_pool_bytes` answers. A
/// refused call writes nothing at `base`.
#[cfg(feature = "object-pool-region")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_place(
    base: *mut c_void,
    len: usize,
    counts: *const wz_ext_object_pool_counts_t,
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

/// The pools of size class `class` together (`0` to `WZ_EXT_OBJECT_POOL_CLASSES - 1`, the slot of
/// each twice the one before's), in `out`: its slot size, and while pools are reserved their
/// slots, those in use, the most in use at once and the objects they refused. `Z_OK`;
/// `Z_ERR_NULL` for a NULL `out`; `Z_EINVAL` for a `class` past the last.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_class(
    class: usize,
    out: *mut wz_ext_object_pool_class_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        if class >= WZ_EXT_OBJECT_POOL_CLASSES {
            return Z_EINVAL;
        }
        let report = process_pool::report(class);
        *out = wz_ext_object_pool_class_t {
            slot_bytes: report.slot_bytes,
            slots: report.slots,
            in_use: report.in_use,
            high_water: report.high_water,
            refused: report.refused,
        };
        Z_OK
    })
}

/// Give the pools up, so that the next object reserves the build's again: the heap's memory is
/// freed, a program's is the program's again. `Z_OK`, also when none are reserved; `Z_EINVAL`
/// while an object is held in them, which keeps them.
#[no_mangle]
pub extern "C" fn wz_ext_object_pool_release() -> ZResult {
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

    /// Each count a program states is read into the count of the same object.
    #[test]
    fn every_count_the_program_states_is_read() {
        let stated = wz_ext_object_pool_counts_t {
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
                bytes: 10,
                configs: 11,
                hellos: 12,
            }
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

    /// Counts of nothing are refused by the door that sizes them, which writes zero.
    #[test]
    fn counts_of_nothing_are_refused_and_size_nothing() {
        let nothing = wz_ext_object_pool_counts_t::default();
        let mut bytes = 7usize;
        // SAFETY: both arguments are live locals.
        let code = unsafe { wz_ext_object_pool_bytes(&nothing, &mut bytes) };
        assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(bytes, 0);
    }
}
