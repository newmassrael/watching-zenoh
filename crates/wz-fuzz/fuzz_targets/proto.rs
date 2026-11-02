// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that read a `.proto` schema a person supplies:
//! `wz_dissect_proto_messages`, `_describe`, `_encode` and
//! `wz_dissect_declarations_from_proto`, all four over the same files.
//!
//! Input: the root file's index (one byte; one past the last file is asked
//! too), then texts each to a NUL: the root message, the values (JSON), the
//! key pattern, and then up to eight files as a name and a text each.

#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_fuzz::{string_door, Reader};

const MAX_FILES: usize = 8;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let root_pick = usize::from(r.u8());
    let root_message = r.c_field();
    let values = r.c_field();
    let key_pattern = r.c_field();
    let mut names: Vec<CString> = Vec::new();
    let mut texts: Vec<&[u8]> = Vec::new();
    while !r.is_empty() && names.len() < MAX_FILES {
        names.push(r.c_field());
        texts.push(r.field());
    }
    let files: Vec<WzDissectProtoFile> = names
        .iter()
        .zip(&texts)
        .map(|(name, text)| WzDissectProtoFile {
            name: name.as_ptr(),
            text: text.as_ptr(),
            text_len: text.len(),
        })
        .collect();
    let (f, count) = (files.as_ptr(), files.len());
    let root_file = root_pick % (count + 1);
    let (root, vals, key) = (root_message.as_ptr(), values.as_ptr(), key_pattern.as_ptr());

    // SAFETY (every call): `f` points at `count` files whose names are
    // NUL-terminated and whose texts are readable for their lengths, all alive
    // for the call; every other string is NUL-terminated; `o` is writable.
    string_door("proto_messages", |o| unsafe {
        wz_dissect_proto_messages(f, count, o)
    });
    string_door("proto_describe", |o| unsafe {
        wz_dissect_proto_describe(root, f, count, root_file, o)
    });
    string_door("proto_encode", |o| unsafe {
        wz_dissect_proto_encode(root, f, count, root_file, vals, o)
    });
    string_door("declarations_from_proto", |o| unsafe {
        wz_dissect_declarations_from_proto(key, root, f, count, root_file, o)
    });
});
