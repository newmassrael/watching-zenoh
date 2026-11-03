// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What every fuzz target shares: a reader that turns the fuzzer's bytes into
//! a door's arguments, and the contract each door's answer is held to.
//!
//! A target passes when no door crashes, reads or writes out of bounds, leaks
//! or answers outside its contract. The contract is the one the doors' own
//! documentation states, and only that:
//!
//! - every answer is one of the codes the crate defines;
//! - a string door that answers OK hands out a string, and every string it
//!   hands out is UTF-8 JSON and is given back with `wz_dissect_string_free`;
//! - a buffer door (`out`, `cap`, `needed`) states the same `needed` whether it
//!   is asked for the length alone or for the bytes, fills a buffer of exactly
//!   that size, writes nothing into a buffer one short of it, and, where its
//!   documentation says so, states zero on every failure.

use core::ffi::{c_char, c_int, CStr};
use core::mem::MaybeUninit;

use wz_capi_dissect::{wz_dissect_string_free, WZ_DISSECT_ERR_CANCELLED, WZ_DISSECT_OK};
use wz_capi_replay::{WZ_REPLAY_ERR_BUFFER_TOO_SMALL, WZ_REPLAY_OK};

/// The byte a buffer is filled with before a door is asked to write into it,
/// so that a write a door was not allowed to make is seen.
const UNWRITTEN: u8 = 0xA5;

/// The most elements a buffer door is handed room for. A door that states more
/// is still held to its `needed`; only the fill is skipped, so a fuzz input
/// cannot make the harness itself run out of memory.
const MAX_FILL: usize = 1 << 22;

/// The fuzzer's bytes, read front to back. Every read past the end answers
/// zero or empty, so any input is a whole set of arguments.
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

    /// Up to `n` bytes.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.data.split_at(n.min(self.data.len()));
        self.data = tail;
        head
    }

    /// The bytes up to the next NUL (which is consumed), or to the end: the
    /// natural cut for a C string, which cannot hold a NUL.
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
    pub fn c_field(&mut self) -> std::ffi::CString {
        std::ffi::CString::new(self.field()).expect("a field holds no NUL")
    }

    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.data)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Whether `rc` is a code `wz-capi-dissect` defines.
pub fn is_dissect_code(rc: c_int) -> bool {
    (WZ_DISSECT_ERR_CANCELLED..=WZ_DISSECT_OK).contains(&rc)
}

/// Whether `rc` is a code `wz-capi-replay` defines.
pub fn is_replay_code(rc: c_int) -> bool {
    (WZ_REPLAY_ERR_BUFFER_TOO_SMALL..=WZ_REPLAY_OK).contains(&rc)
}

/// Hold a string door's answer to its contract and give the string back.
/// `out` must have been null before the call, so a door that wrote nothing
/// leaves nothing to free.
///
/// # Safety
/// `out` is null or a string the door handed out and nobody freed.
pub unsafe fn string_answer(door: &str, rc: c_int, out: *mut c_char) {
    assert!(
        is_dissect_code(rc),
        "{door}: answered {rc}, a code the crate does not define"
    );
    if rc == WZ_DISSECT_OK {
        assert!(
            !out.is_null(),
            "{door}: answered OK and handed out no string"
        );
    }
    if out.is_null() {
        return;
    }
    // SAFETY: the door handed out a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(out) }.to_str();
    let text =
        text.unwrap_or_else(|e| panic!("{door}: handed out a string that is not UTF-8: {e}"));
    if let Err(e) = serde_json::from_str::<serde_json::Value>(text) {
        panic!("{door}: handed out a string that is not JSON ({e}): {text}");
    }
    // SAFETY: handed out by this crate and not freed yet.
    unsafe { wz_dissect_string_free(out) };
}

/// Call a string door and hold its answer to the contract.
pub fn string_door(door: &str, call: impl FnOnce(*mut *mut c_char) -> c_int) {
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = call(&mut out);
    // SAFETY: `out` started null and only the door wrote it.
    unsafe { string_answer(door, rc, out) };
}

/// What a buffer door states about failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Its documentation says `needed` is zero on every failure.
    NeedsZero,
    /// Its documentation says nothing of `needed` on failure.
    Unstated,
}

/// Hold a buffer door (`out`, `cap`, `needed`) to the never-truncate contract:
/// the length alone, then a buffer of exactly that length, then one a unit
/// short, which must stay as it was. Answers the filled buffer when the door
/// answered OK and the fill was within [`MAX_FILL`].
pub fn buffer_door<T: Copy>(
    door: &str,
    on_failure: OnFailure,
    mut call: impl FnMut(*mut T, usize, &mut usize) -> c_int,
) -> Option<Vec<T>> {
    let mut needed = usize::MAX;
    let rc = call(core::ptr::null_mut(), 0, &mut needed);
    assert!(
        is_dissect_code(rc),
        "{door}: answered {rc}, a code the crate does not define"
    );
    if rc != WZ_DISSECT_OK {
        if on_failure == OnFailure::NeedsZero {
            assert_eq!(
                needed, 0,
                "{door}: failed with {rc} and stated needed = {needed}, not zero"
            );
        }
        return None;
    }
    if needed > MAX_FILL {
        return None;
    }
    let mut full = unwritten::<T>(needed);
    let mut again = usize::MAX;
    let rc = call(full.as_mut_ptr().cast(), needed, &mut again);
    assert_eq!(
        rc, WZ_DISSECT_OK,
        "{door}: answered OK for the length and {rc} for the bytes"
    );
    assert_eq!(
        again, needed,
        "{door}: stated {needed} for the length and {again} with the buffer"
    );
    if needed > 0 {
        let mut short = unwritten::<T>(needed - 1);
        let mut third = usize::MAX;
        let rc = call(short.as_mut_ptr().cast(), needed - 1, &mut third);
        assert!(
            is_dissect_code(rc),
            "{door}: answered {rc} for a short buffer"
        );
        assert_eq!(
            third, needed,
            "{door}: stated {third} for a short buffer, {needed} before"
        );
        assert!(
            untouched(&short),
            "{door}: wrote into a buffer one short of the {needed} it stated"
        );
    }
    // SAFETY: the door answered OK with `needed` and filled exactly that many,
    // and every `T` here is plain integers, for which any bytes are a value.
    Some(
        full.into_iter()
            .map(|v| unsafe { v.assume_init() })
            .collect(),
    )
}

fn unwritten<T>(n: usize) -> Vec<MaybeUninit<T>> {
    let mut v = Vec::with_capacity(n);
    // SAFETY: `n` elements of capacity, each set to the fill byte before use.
    unsafe {
        core::ptr::write_bytes(v.as_mut_ptr(), UNWRITTEN, n);
        v.set_len(n);
    }
    v
}

fn untouched<T>(v: &[MaybeUninit<T>]) -> bool {
    // SAFETY: every byte was written with the fill byte by `unwritten`.
    let bytes =
        unsafe { core::slice::from_raw_parts(v.as_ptr().cast::<u8>(), core::mem::size_of_val(v)) };
    bytes.iter().all(|&b| b == UNWRITTEN)
}

/// The capture limits a door is handed: each preset the crate defines, and a
/// value it does not, which must be refused rather than read.
pub fn limits(pick: u8) -> c_int {
    match pick % 3 {
        0 => wz_capi_dissect::WZ_DISSECT_LIMITS_NONE,
        1 => wz_capi_dissect::WZ_DISSECT_LIMITS_LIVE_TAP,
        _ => 7,
    }
}

/// A link type for the doors that take one: the ones the reader knows, a
/// private one, and whatever the fuzzer wrote.
pub fn link_type(pick: u8, raw: u32) -> u32 {
    match pick % 8 {
        0 => 1,   // Ethernet
        1 => 101, // raw IP
        2 => 113, // Linux cooked
        3 => 276, // Linux cooked v2
        4 => 228, // IPv4
        5 => 147, // the first private link type
        6 => 0,   // BSD loopback
        _ => raw,
    }
}

/// The frame of a wrap document that built one, from its `"frame"` hex. A
/// document that did not build one answers `None`; a frame that is not whole
/// hex is a defect of the door that wrote it.
pub fn frame_of(doc: &str) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(doc).ok()?;
    if value.get("ok")? != &serde_json::Value::Bool(true) {
        return None;
    }
    let hex = value.get("frame")?.as_str()?;
    let digits = hex.as_bytes();
    assert!(
        digits.len() % 2 == 0,
        "e2e_wrap: a frame of odd hex length: {hex}"
    );
    let nibble = |c: u8| {
        (c as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("e2e_wrap: a frame that is not hex: {hex}")) as u8
    };
    Some(
        digits
            .chunks(2)
            .map(|pair| nibble(pair[0]) << 4 | nibble(pair[1]))
            .collect(),
    )
}

/// Selectors a door is handed beside the fuzzer's own: valid ones that reach
/// the filtering, and the empty one, which selects everything.
pub const SELECTORS: &[&str] = &[
    "",
    "kind == put",
    "key == demo/**",
    "key === x",
    "kind == query",
    "flow == 1",
];

/// Declarations a door is handed beside the fuzzer's own.
pub const DECLARATIONS: &[&str] = &[
    "",
    "demo/**=protobuf",
    "demo/**=protobuf\ndemo/a=json",
    "not a declaration",
];
