// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! pico's enum-typed QoS option fields: `z_congestion_control_t` and `z_priority_t`.
//!
//! Core types of the publication path (a put, a delete, a publisher carry both), so they live
//! here and not in the query module, which a build without the query plane leaves out.
//!
//! pico's two types are plain C enums, so each occupies an `int` in the option structs.

use std::ffi::c_int;

pub type z_congestion_control_t = c_int;
pub type z_priority_t = c_int;

/// pico `Z_CONGESTION_CONTROL_BLOCK` (`api/constants.h:216`) — the value pico's
/// `z_query_reply_options_default` writes (`src/api/api.c:2118,2181`). NOT 0:
/// that is `Z_CONGESTION_CONTROL_DROP`, a different documented default.
pub(crate) const Z_CONGESTION_CONTROL_BLOCK: z_congestion_control_t = 1;

/// pico `Z_PRIORITY_DEFAULT` = `Z_PRIORITY_DATA` = 5 (`api/constants.h:247-250`).
pub(crate) const Z_PRIORITY_DEFAULT: z_priority_t = 5;

/// pico `Z_CONGESTION_CONTROL_DROP` (`api/constants.h:215`) = 0. Named because
/// this file's sibling ABI (`wz-capi-c`) INVERTS both values, and R311y545 paid
/// for reading one crate's constant while writing the other's — the two enums
/// look identical and are not.
pub(crate) const Z_CONGESTION_CONTROL_DROP: z_congestion_control_t = 0;

/// pico's `z_congestion_control_t` as wz's typed [`CongestionControl`].
///
/// R311y551. pico has no `BLOCK_FIRST`, so the mapping is total over its enum;
/// an out-of-range value takes pico's own request-side default (BLOCK) rather
/// than panicking, matching the permissive-decode spirit of
/// [`priority_from_pico`].
///
/// [`CongestionControl`]: wz_session_core::qos::CongestionControl
#[cfg(any(feature = "query", feature = "advanced"))]
pub(crate) fn congestion_from_pico(
    c: z_congestion_control_t,
) -> wz_session_core::qos::CongestionControl {
    use wz_session_core::qos::CongestionControl;
    match c {
        Z_CONGESTION_CONTROL_DROP => CongestionControl::Drop,
        // BLOCK (1) and anything unrecognised — pico's `z_get_options_default`
        // writes BLOCK, so an unknown int degrades to the default rather than
        // silently downgrading delivery.
        _ => CongestionControl::Block,
    }
}

/// pico's `z_priority_t` as wz's typed [`Priority`].
///
/// R311y551. pico's enum spans 1..=7 (`Z_PRIORITY_REAL_TIME` .. `BACKGROUND`);
/// wire priority 0 (`Control`) is zenoh's own control traffic and has no pico
/// spelling, so it is accepted on the wire and never produced from a C option.
/// Anything outside 0..=7 cannot fit the 3-bit field and clamps to the default.
///
/// [`Priority`]: wz_session_core::qos::Priority
pub(crate) fn priority_from_pico(p: z_priority_t) -> wz_session_core::qos::Priority {
    use wz_session_core::qos::Priority;
    match u8::try_from(p) {
        Ok(byte) if byte <= 7 => Priority::from_wire(byte),
        _ => Priority::DEFAULT,
    }
}
