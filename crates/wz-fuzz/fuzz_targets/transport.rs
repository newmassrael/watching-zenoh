// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that read one transport message from bytes a consumer holds:
//! `wz_dissect_transport_message`, `wz_dissect_transport_message_in` and
//! `wz_dissect_transport_layout`.
//!
//! Input: four bytes of arguments, the session context (JSON, to a NUL), a
//! sequence-number ring word (to a NUL), then the message bytes.
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the framing: each constant, or the fuzzer's byte |
//! | 1    | the ring: one of the four words, null, or the fuzzer's word |
//! | 2, 3 | the offset the message is read at (`base`) |

#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_fuzz::{string_door, Reader};

const RINGS: [&str; 4] = ["8bit", "16bit", "32bit", "64bit"];

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let framing = match r.u8() {
        f @ 0..=2 => i32::from(f),
        f => i32::from(f as i8),
    };
    let ring_pick = r.u8();
    let base = usize::from(r.u16());
    let context = r.c_field();
    let free_ring = r.c_field();
    let bytes = r.rest();
    let ring = match ring_pick % 6 {
        n @ 0..=3 => Some(CString::new(RINGS[usize::from(n)]).unwrap()),
        4 => None,
        _ => Some(free_ring),
    };
    let ring_ptr = ring.as_ref().map_or(core::ptr::null(), |r| r.as_ptr());
    let (b, n) = (bytes.as_ptr(), bytes.len());

    // SAFETY (every call): `b` points at `n` readable bytes, every string is
    // NUL-terminated or null where the door allows it, and `o` is writable.
    string_door("transport_message", |o| unsafe {
        wz_dissect_transport_message(b, n, base, o)
    });
    string_door("transport_message_in", |o| unsafe {
        wz_dissect_transport_message_in(context.as_ptr(), b, n, base, o)
    });
    string_door("transport_layout", |o| unsafe {
        wz_dissect_transport_layout(b, n, framing, ring_ptr, o)
    });
});
