// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_entity_global_id_t` — the identity of one entity of a node.
//!
//! A core type of pico's protocol layer, not of the advanced plane: a publisher, a
//! subscriber, a queryable and the source of a reply each carry one. It lives here so a build
//! without the `advanced` feature still has it.

use crate::zid::z_id_t;

/// pico `z_entity_global_id_t` (`protocol/core.h:83-86`), 20 B / align 4
/// measured: `{ z_id_t zid; uint32_t eid; }`.
///
/// `z_id_t` is a bare `uint8_t[16]`, so it is 1-aligned and the struct's
/// alignment comes from `eid` alone — which is why this is 20 bytes and not
/// the 24 an 8-aligned reading would predict. It crosses the boundary BY VALUE
/// inside `ze_miss_t`, so both facts are ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_entity_global_id_t {
    pub zid: z_id_t,
    pub eid: u32,
}

/// The zid half of a global entity id (pico `z_entity_global_id_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_zid(gid: *const z_entity_global_id_t) -> z_id_t {
    if gid.is_null() {
        return z_id_t::empty();
    }
    (*gid).zid
}

/// The eid half of a global entity id (pico `z_entity_global_id_eid`).
#[no_mangle]
pub unsafe extern "C" fn z_entity_global_id_eid(gid: *const z_entity_global_id_t) -> u32 {
    if gid.is_null() {
        return 0;
    }
    (*gid).eid
}

// Compile-time byte-compat guard, MEASURED against the pinned pico headers with a real C
// compiler: a drift is a stack smash in the caller's frame, not a Rust error.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<z_entity_global_id_t>() == 20);
    assert!(align_of::<z_entity_global_id_t>() == 4);
};
