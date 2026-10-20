// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_entity_global_id_t`, the id every entity of a session reports and a source info carries.
//!
//! Its own module, not part of [`crate::advanced`], because it is not the advanced plane's: a
//! publisher, a subscriber, a queryable, a querier and the source info of a put all read it, and
//! a build that leaves the advanced plane out still answers them. Like the plane it came from, it
//! exists only on the unstable arms: upstream declares it behind `Z_FEATURE_UNSTABLE_API`.

use crate::ffi::guard_val;
use crate::zid::z_id_t;

/// zenoh-c `z_entity_global_id_t` (`zenoh_opaque.h:522-524`): 20 bytes at
/// ALIGNMENT 4.
///
/// Opaque upstream, but the alignment is the tell — 4, not 8 — and a
/// `{ z_id_t; uint32_t }` is exactly what produces it: [`z_id_t`] is a bare
/// `uint8_t[16]` so it contributes alignment 1, and the `eid` alone sets the
/// struct's alignment. It crosses the boundary BY VALUE inside `ze_miss_t` and
/// as [`z_entity_global_id_zid`]'s argument, so both facts are ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_entity_global_id_t {
    /// The zid half.
    pub zid: z_id_t,
    /// The entity id half.
    pub eid: u32,
}

impl z_entity_global_id_t {
    /// The EMPTY id a gravestoned entity reports.
    ///
    /// R311y568 — named once. Five accessors now answer this question
    /// (`z_publisher_id` / `z_subscriber_id` / `z_queryable_id` /
    /// `z_querier_id` / the `ze_advanced_*` pair), and each of them needs the
    /// empty value on TWO paths — the panic fallback and the null-handle arm —
    /// so open-coding it would be ten copies of one literal.
    pub(crate) fn empty() -> Self {
        Self {
            zid: z_id_t::empty(),
            eid: 0,
        }
    }

    /// The id for an entity of `shared` whose per-entity identity is the
    /// address `handle`.
    ///
    /// The zid half is the SESSION's, which is what upstream reports too — a
    /// publisher or subscriber is not a separate node. The eid half is the
    /// handle's own address, narrowed: a per-entity value that is stable for the
    /// entity's life and distinct between live entities, which is the whole
    /// contract an entity id carries here.
    pub(crate) fn for_entity(
        shared: &wz_capi_core::faces::SharedSession,
        handle: *const std::ffi::c_void,
    ) -> Self {
        Self {
            zid: z_id_t { id: shared.zid() },
            eid: (handle as usize as u64 & u64::from(u32::MAX)) as u32,
        }
    }
}

/// The zid half of a global entity id (zenoh-c `z_entity_global_id_zid`,
/// `zenoh_commons.h:2643`).
///
/// # Safety
/// `this_` must be null or a valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_zid(this_: *const z_entity_global_id_t) -> z_id_t {
    guard_val(z_id_t::empty(), || {
        if this_.is_null() {
            return z_id_t::empty();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).zid }
    })
}

/// The entity-id half of a global entity id (zenoh-c `z_entity_global_id_eid`,
/// `zenoh_commons.h:2635`).
///
/// # Safety
/// `this_` must be null or a valid entity global id.
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_eid(this_: *const z_entity_global_id_t) -> u32 {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).eid }
    })
}
