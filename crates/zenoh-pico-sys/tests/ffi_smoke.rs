// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! FFI smoke test against vendored zenoh-pico (1.9.0+, pin 3b3ab65c).
//!
//! Proves that the three-stage Phase 2 walking-skeleton FFI chain is
//! sound:
//!
//!   1. `cmake` build-dep invokes `vendor/zenoh-pico/CMakeLists.txt`
//!      and produces `libzenohpico.a` under the install prefix.
//!
//!   2. `bindgen` parses `vendor/zenoh-pico/include/zenoh-pico.h`
//!      with the platform macro set and emits Rust FFI declarations
//!      for the allowlisted entry points (`_z_id_t`, `_z_id_len`).
//!
//!   3. Cargo's `rustc-link-search` + `rustc-link-lib=static`
//!      directives wire the linker to pull `_z_id_len` from
//!      `libzenohpico.a` into the test binary.
//!
//! Test vector chosen to exercise the only piece of state-bearing
//! C code in `_z_id_len` (see `vendor/zenoh-pico/src/protocol/core.c:35-45`):
//! a strip-trailing-zeros loop over a 16-byte `_z_id_t.id` buffer.
//! Three cases cover the loop's branches:
//!   - all-zero  → 0 (loop strips every byte)
//!   - mixed     → position of last non-zero byte + 1
//!   - all-non-zero → 16 (loop exits at the first byte)

use zenoh_pico_sys::{_z_id_len, _z_id_t};

#[test]
fn id_len_all_zero() {
    let id = _z_id_t { id: [0u8; 16] };
    // Safety: _z_id_len takes the struct by value; the caller's copy
    // is fully initialized above.
    let n = unsafe { _z_id_len(id) };
    assert_eq!(n, 0, "all-zero id reports length 0");
}

#[test]
fn id_len_partial_trailing_zeros() {
    // Last non-zero byte is at index 4 (value 5); _z_id_len returns
    // index + 1 = 5.
    let id = _z_id_t {
        id: [1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    let n = unsafe { _z_id_len(id) };
    assert_eq!(n, 5, "id with last-nonzero at index 4 reports length 5");
}

#[test]
fn id_len_all_nonzero() {
    let id = _z_id_t {
        id: [0xFF; 16],
    };
    let n = unsafe { _z_id_len(id) };
    assert_eq!(n, 16, "all-nonzero id reports full 16-byte length");
}

#[test]
fn id_len_trailing_nonzero_in_middle() {
    // Last non-zero byte is at index 9; rest are zero.
    let id = _z_id_t {
        id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0, 0, 0, 0, 0, 0],
    };
    let n = unsafe { _z_id_len(id) };
    assert_eq!(n, 10, "trailing nonzero at index 9 reports length 10");
}
