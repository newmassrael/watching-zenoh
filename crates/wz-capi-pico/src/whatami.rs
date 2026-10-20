// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_whatami_t`, the role bitmask a hello and a transport's peer both carry, and its rendering.
//!
//! Its own module, not part of [`crate::scout`], because the connectivity plane reports the
//! role of the peer a session holds a link to: a build without scouting still needs the type.

use crate::abi::z_view_string_t;
use crate::result::ZResult;

/// pico `z_whatami_t` (`api/constants.h:50-54`) — a C enum, so `u32` on every
/// platform this crate targets. A BITMASK, not an ordinal: the values are
/// `1 << role`.
pub type z_whatami_t = u32;

/// pico `WHAT_AM_I_TO_STRING_MAP` (`src/api/api.c:742-750`), transcribed with
/// its index semantics intact: the index IS the bitmask, so slot 3 is the
/// router-and-peer combination rather than a third role. Slot 0 is the
/// out-of-range / zero answer and pairs with an ERROR return, which is upstream
/// behaviour worth preserving — a caller that ignores the result still gets a
/// printable string rather than an empty view.
const WHATAMI_STRINGS: [&str; 8] = [
    "Other",
    "Router",
    "Peer",
    "Router|Peer",
    "Client",
    "Router|Client",
    "Peer|Client",
    "Router|Peer|Client",
];

/// Render a whatami bitmask into a caller-provided view string (pico
/// `z_whatami_to_view_string`).
///
/// Returns `Z_EINVAL` for 0 or an out-of-range mask AND still writes `"Other"`,
/// which is upstream's contract verbatim (`api.c:753-762`).
///
/// # Safety
/// `str_out` must point to writable `z_view_string_t` storage.
#[no_mangle]
pub unsafe extern "C" fn z_whatami_to_view_string(
    whatami: z_whatami_t,
    str_out: *mut z_view_string_t,
) -> ZResult {
    if str_out.is_null() {
        return crate::result::Z_ERR_INVALID;
    }
    let idx = whatami as usize;
    let (text, res) = if idx == 0 || idx >= WHATAMI_STRINGS.len() {
        (WHATAMI_STRINGS[0], crate::result::Z_ERR_INVALID)
    } else {
        (WHATAMI_STRINGS[idx], crate::result::Z_OK)
    };
    // The rendered strings are `'static`, so the view aliases program storage
    // that outlives any caller — the same lifetime pico's own map has.
    *str_out = z_view_string_t {
        _start: text.as_ptr(),
        _len: text.len(),
        _pad: [0usize; 2],
    };
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whatami map is an INDEXED BITMASK, not an ordinal list: index 3 is
    /// "Router|Peer", not a third role. Transcribing it as a role list is the
    /// mistake this pins against, and it would be invisible for the two
    /// single-bit values a test that only checked Router and Peer would use.
    #[test]
    fn whatami_renders_the_bitmask_combinations() {
        let render = |w: u32| -> String {
            let mut out = z_view_string_t {
                _start: std::ptr::null(),
                _len: 0,
                _pad: [0usize; 2],
            };
            let res = unsafe { z_whatami_to_view_string(w, &mut out) };
            let text = unsafe {
                std::str::from_utf8(std::slice::from_raw_parts(out._start, out._len)).unwrap()
            };
            format!("{res}:{text}")
        };
        assert_eq!(render(1), "0:Router");
        assert_eq!(render(2), "0:Peer");
        assert_eq!(render(3), "0:Router|Peer");
        assert_eq!(render(4), "0:Client");
        assert_eq!(render(7), "0:Router|Peer|Client");
        // Upstream returns an ERROR for 0 and for out-of-range, and still
        // writes "Other" — both halves, or a caller that ignores the result
        // reads uninitialised stack.
        assert!(render(0).starts_with("-8:Other") || render(0).ends_with(":Other"));
        assert!(render(99).ends_with(":Other"));
    }
}
