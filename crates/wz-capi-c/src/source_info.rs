// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c `source_info` family: one 24-byte VALUE type and its three
//! functions.
//!
//! ## R2239 — this used to be an owned family, and upstream retired that shape
//!
//! At zenoh-c 1.5.0 `z_source_info_t` was an OWNED OPAQUE with move semantics:
//! `z_source_info_new` constructed into a `z_owned_source_info_t`, every option
//! field was a `z_moved_source_info_t*` the callee CONSUMED, and reading one
//! back needed `z_source_info_loan` to a distinct loaned type. R311y563
//! mirrored all seven functions of it.
//!
//! zenoh-c 1.10.0 collapsed that to a plain value. Measured against the pinned
//! oracle rather than read off a changelog:
//!
//! - `zenoh_opaque.h` declares `ALIGN(4) z_source_info_t { uint8_t _0[24]; }`
//!   and NO owned / loaned / moved sibling;
//! - `z_source_info_new` RETURNS one by value
//!   (`z_source_info_new(const z_entity_global_id_t*, uint32_t)`);
//! - `z_source_info_id` / `_sn` take a `const z_source_info_t*`;
//! - the six option structs carry `const struct z_source_info_t *source_info`,
//!   a BORROW rather than a move;
//! - `nm -D` on the pinned `libzenohc.so` defines no `z_source_info_drop`,
//!   `z_source_info_loan`, `z_internal_source_info_check` or `_null`.
//!
//! So the four functions this module used to export were four symbols wz
//! defined and the reference did not — which
//! `zenoh_c_abi_symbol_census.rs::wz_exports_nothing_the_reference_does_not`
//! reads as a surface that is not the ABI it claims to be, and rightly.
//!
//! ## The alignment is still the fact that shapes the type
//!
//! FOUR, not eight, which is why [`crate::abi`]'s `define_opaque!` — which
//! hard-asserts align 8 — cannot be reused here. As a value type that costs
//! nothing: the fields ARE the content, so there is no handle whose alignment
//! could be wrong. That is the second thing the collapse bought, after the four
//! symbols.

use wz_runtime_tokio::sample::SourceInfo;

use crate::advanced::z_entity_global_id_t;
use crate::ffi::guard_val;
use crate::zid::Z_ID_SIZE;

/// zenoh-c `z_source_info_t` — 24 bytes at ALIGNMENT 4, carried BY VALUE.
///
/// Upstream declares it opaque, so the field split here is wz's own; what is
/// ABI is the footprint, which `zenoh_c_abi_symbol_census.rs` and the arms gate
/// both measure. Splitting it into the fields it actually holds beats a
/// `[u8; 24]` blob for the ordinary reason: the accessors below read fields
/// instead of decoding bytes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct z_source_info_t {
    /// The source zid, right-zero-padded to 16 bytes exactly as `z_id_t` is.
    pub(crate) zid: [u8; Z_ID_SIZE],
    /// The source entity id.
    pub(crate) eid: u32,
    /// The source sequence number.
    pub(crate) sn: u32,
}

const _: () = {
    assert!(std::mem::size_of::<z_source_info_t>() == 24);
    assert!(std::mem::align_of::<z_source_info_t>() == 4);
};

impl z_source_info_t {
    /// The all-zero value, which is what an absent source info reads as.
    ///
    /// Upstream has no gravestone for a value type — absence is a NULL pointer
    /// in the option field — so this is wz's own filler for the slot a sample
    /// marshal keeps whether or not the sample carried one.
    pub(crate) fn empty() -> Self {
        Self {
            zid: [0u8; Z_ID_SIZE],
            eid: 0,
            sn: 0,
        }
    }

    /// The C form of a runtime source info.
    pub(crate) fn from_runtime(info: &SourceInfo) -> Self {
        let mut zid = [0u8; Z_ID_SIZE];
        // The wire form strips trailing zeros; re-pad LEFT-aligned, the same
        // convention `z_timestamp_t::_id` follows.
        let prefix = info.zid_prefix();
        let n = prefix.len().min(Z_ID_SIZE);
        zid[..n].copy_from_slice(&prefix[..n]);
        Self {
            zid,
            eid: info.eid,
            sn: info.sn,
        }
    }

    /// The runtime form, or `None` for an all-zero zid.
    ///
    /// An all-zero zid is not a source: `SourceInfo::default()` uses
    /// `zid_len = 0` as exactly that sentinel, and a caller who zeroed the
    /// struct rather than filling it means "none".
    pub(crate) fn to_runtime(self) -> Option<SourceInfo> {
        let len = self.zid.iter().rposition(|b| *b != 0).map(|i| i + 1)?;
        Some(SourceInfo::new(&self.zid[..len], self.eid, self.sn))
    }
}

/// Read an option struct's borrowed `source_info` field.
///
/// The BORROW is the 1.10.0 shape: upstream types the field
/// `const z_source_info_t *`, so the callee copies what it needs and leaves the
/// caller's value alone. The pre-1.10.0 sibling of this function was
/// `take_moved_source_info`, which nulled the caller's slot and reclaimed a
/// box — the move semantics upstream retired.
///
/// # Safety
/// `ptr` must be null or a valid, readable `z_source_info_t`.
pub(crate) unsafe fn borrowed_source_info(ptr: *const z_source_info_t) -> Option<SourceInfo> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    unsafe { *ptr }.to_runtime()
}

/// Construct a source info (zenoh-c `z_source_info_new`).
///
/// Returns BY VALUE, which is upstream's 1.10.0 signature. A null `source_id`
/// yields the all-zero value rather than a diagnostic: the C signature has no
/// result channel, and every accessor reads that value as absent.
///
/// # Safety
/// `source_id` must be null or a valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_new(
    source_id: *const z_entity_global_id_t,
    source_sn: u32,
) -> z_source_info_t {
    guard_val(z_source_info_t::empty(), || {
        if source_id.is_null() {
            return z_source_info_t::empty();
        }
        // SAFETY: checked non-null.
        let gid = unsafe { &*source_id };
        z_source_info_t {
            zid: gid.zid.id,
            eid: gid.eid,
            sn: source_sn,
        }
    })
}

/// The `(zid, eid)` half of a source info (zenoh-c `z_source_info_id`).
///
/// # Safety
/// `this_` must be null or a valid source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_id(this_: *const z_source_info_t) -> z_entity_global_id_t {
    let empty = z_entity_global_id_t {
        zid: crate::zid::z_id_t {
            id: [0u8; Z_ID_SIZE],
        },
        eid: 0,
    };
    guard_val(empty, || {
        if this_.is_null() {
            return empty;
        }
        // SAFETY: checked non-null.
        let info = unsafe { &*this_ };
        z_entity_global_id_t {
            zid: crate::zid::z_id_t { id: info.zid },
            eid: info.eid,
        }
    })
}

/// The sequence number of a source info (zenoh-c `z_source_info_sn`).
///
/// # Safety
/// `this_` must be null or a valid source info.
#[no_mangle]
pub unsafe extern "C" fn z_source_info_sn(this_: *const z_source_info_t) -> u32 {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: checked non-null.
        unsafe { (*this_).sn }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two conversions are inverse for a real source info.
    #[test]
    fn the_c_value_round_trips_a_runtime_source_info() {
        let info = SourceInfo::new(&[1, 2, 3, 4], 7, 99);
        let c = z_source_info_t::from_runtime(&info);
        let back = c.to_runtime().expect("a non-zero zid is a source");
        assert_eq!(back.zid_prefix(), &[1, 2, 3, 4]);
        assert_eq!(back.eid, 7);
        assert_eq!(back.sn, 99);
    }

    /// An all-zero value is ABSENCE, not a source with a zero zid.
    ///
    /// The distinction is load-bearing: a sample marshal keeps this slot
    /// whether or not the sample carried a source, so a conversion that
    /// answered `Some` for the filler would stamp a zero source onto every
    /// outbound message built from one.
    #[test]
    fn an_all_zero_value_is_absence() {
        assert!(z_source_info_t::empty().to_runtime().is_none());
        // And a zid that is zero only in its TAIL is still a source.
        let tail = z_source_info_t {
            zid: [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            eid: 1,
            sn: 2,
        };
        assert_eq!(
            tail.to_runtime()
                .expect("a one-byte zid is a source")
                .zid_prefix(),
            &[9]
        );
    }

    /// A null argument answers the empty value rather than dereferencing.
    #[test]
    fn the_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            let made = z_source_info_new(std::ptr::null(), 5);
            assert!(made.to_runtime().is_none());
            assert_eq!(z_source_info_sn(std::ptr::null()), 0);
            assert_eq!(z_source_info_id(std::ptr::null()).eid, 0);
        }
    }
}
