// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that read text a person typed: selectors, key expressions,
//! declarations and a transport message described as JSON
//! (`wz_dissect_selector_*`, `wz_dissect_keyexpr_*`,
//! `wz_dissect_declarations_diagnose` / `_match`, `wz_dissect_transport_build`),
//! and once each, the doors that take no input at all.
//!
//! Input: the door (one byte), the framing (one byte), then up to two texts,
//! each to a NUL.
//!
//! | door | arguments |
//! |------|-----------|
//! | 0    | `selector_diagnose(text 1)` |
//! | 1    | `selector_bind(text 1, text 2 or null when it is empty)` |
//! | 2    | `keyexpr_diagnose(text 1)` |
//! | 3    | `keyexpr_relate(text 1, text 2)` |
//! | 4    | `declarations_diagnose(text 1)` |
//! | 5    | `declarations_match(text 1, text 2)` |
//! | 6    | `transport_build(text 1, framing)` |

#![no_main]

use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_capi_replay::wz_replay_emission_layout;
use wz_fuzz::{string_door, Reader};

static NO_INPUT: Once = Once::new();

/// The doors that take no input answer the same every time, so they are asked
/// once a process; a crash there is still a crash of this target.
fn no_input_doors() {
    string_door("readable_surfaces", |o| unsafe {
        wz_dissect_readable_surfaces(o)
    });
    string_door("selector_fields", |o| unsafe {
        wz_dissect_selector_fields(o)
    });
    for cap in [0usize, 1, 64] {
        let mut out = vec![0usize; cap];
        // SAFETY: `out` holds `cap` writable `usize`.
        let _ = unsafe { wz_dissect_record_layout(out.as_mut_ptr(), cap) };
        let _ = unsafe { wz_replay_emission_layout(out.as_mut_ptr(), cap) };
    }
}

fuzz_target!(|data: &[u8]| {
    NO_INPUT.call_once(no_input_doors);
    let mut r = Reader::new(data);
    let door = r.u8() % 7;
    let framing = i32::from(r.u8() % 4);
    let first = r.c_field();
    let second_bytes = r.field().to_vec();
    let second = std::ffi::CString::new(second_bytes.clone()).unwrap();
    let (a, b) = (first.as_ptr(), second.as_ptr());
    let b_or_null = if second_bytes.is_empty() {
        core::ptr::null()
    } else {
        b
    };

    // SAFETY (every call): each string is NUL-terminated, or null where the
    // door allows it, and outlives the call; `o` is writable.
    match door {
        0 => string_door("selector_diagnose", |o| unsafe {
            wz_dissect_selector_diagnose(a, o)
        }),
        1 => string_door("selector_bind", |o| unsafe {
            wz_dissect_selector_bind(a, b_or_null, o)
        }),
        2 => string_door("keyexpr_diagnose", |o| unsafe {
            wz_dissect_keyexpr_diagnose(a, o)
        }),
        3 => string_door("keyexpr_relate", |o| unsafe {
            wz_dissect_keyexpr_relate(a, b, o)
        }),
        4 => string_door("declarations_diagnose", |o| unsafe {
            wz_dissect_declarations_diagnose(a, o)
        }),
        5 => string_door("declarations_match", |o| unsafe {
            wz_dissect_declarations_match(a, b, o)
        }),
        _ => string_door("transport_build", |o| unsafe {
            wz_dissect_transport_build(a, framing, o)
        }),
    }
});
