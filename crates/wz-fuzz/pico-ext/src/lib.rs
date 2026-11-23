// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the fuzz targets of the pico C ABI's own doors (`wz_ext_*`) share: a reader that turns
//! the fuzzer's bytes into a door's arguments, the reading of a string a door hands out, and the
//! check of a door's answer against the codes its documentation states.
//!
//! The targets call each door as a C program does, through the library built as the release
//! package builds it (`../Cargo.toml` says how the features are chosen), and hold every answer to
//! the door's own documentation in `crates/wz-capi-pico/src`.

use std::ffi::CString;

use wz_capi_pico::result::ZResult;
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

/// The fuzzer's bytes, read front to back. Every read past the end answers zero or empty, so any
/// input is a whole set of arguments.
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn u8(&mut self) -> u8 {
        match self.data.split_first() {
            Some((&b, rest)) => {
                self.data = rest;
                b
            }
            None => 0,
        }
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    pub fn u64(&mut self) -> u64 {
        u64::from(self.u32()) | (u64::from(self.u32()) << 32)
    }

    /// The bytes up to the next NUL (which is consumed), or to the end: the natural cut for a C
    /// string, which cannot hold a NUL.
    pub fn field(&mut self) -> &'a [u8] {
        match self.data.iter().position(|&b| b == 0) {
            Some(at) => {
                let field = &self.data[..at];
                self.data = &self.data[at + 1..];
                field
            }
            None => core::mem::take(&mut self.data),
        }
    }

    /// The next field as a C string.
    pub fn c_field(&mut self) -> CString {
        CString::new(self.field()).expect("a field holds no NUL")
    }

    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.data)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A string slot holding the gravestone, as a C program declares one before a door writes it.
pub fn empty_string() -> z_owned_string_t {
    // SAFETY: an all-zero string slot is the gravestone every door writes first.
    unsafe { core::mem::zeroed() }
}

/// The text of a string slot a door wrote, which is then dropped; empty for the gravestone. A
/// string a door hands out is UTF-8 (every one is made from a Rust string), so one that is not is
/// a defect of the door named `door`.
///
/// # Safety
/// `out` holds a string a door wrote, or the gravestone.
pub unsafe fn take_string(door: &str, out: &mut z_owned_string_t) -> String {
    if !z_internal_string_check(out) {
        return String::new();
    }
    let loaned = z_string_loan(out);
    let len = z_string_len(loaned);
    let text = if len == 0 {
        String::new()
    } else {
        let bytes = core::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), len);
        core::str::from_utf8(bytes)
            .unwrap_or_else(|e| panic!("{door}: handed out text that is not UTF-8: {e}"))
            .to_owned()
    };
    z_string_drop(z_string_move(out));
    text
}

/// Hold `rc`, the answer of the door named `door`, to the codes its documentation states.
pub fn stated(door: &str, rc: ZResult, codes: &[ZResult]) {
    assert!(
        codes.contains(&rc),
        "{door}: answered {rc}, a code its documentation does not state ({codes:?})"
    );
}
