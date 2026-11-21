// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_proto_file_t`: one `.proto` file as a program hands it to a door that reads a schema,
//! the instance keys' (`crate::instance_key`) and the message payloads'
//! (`crate::message_payload`), and the one reading of a list of them into the schema reader's
//! files. Declared in `wz_ext.h` with the instance keys, which had it first.

use alloc::vec::Vec;
use core::ffi::c_char;

use wz_app_frame::proto_schema::ProtoFile;

use crate::e2e::utf8_arg;
use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL};

/// One `.proto` file, as the program hands it over: the name other files import it by and its
/// text, both NUL-terminated UTF-8, BORROWED for the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_proto_file_t {
    pub name: *const c_char,
    pub text: *const c_char,
}

/// The `count` files at `files`, as the schema reader takes them, borrowing the program's text.
///
/// `Z_ERR_NULL` for a null `files` with a count, or a file with a null name or text; `Z_EINVAL`
/// for a name or a text that is not UTF-8.
///
/// # Safety
/// `files` is null or readable for `count` entries, each holding NUL-terminated C strings that
/// stay valid for `'a`.
pub(crate) unsafe fn proto_files<'a>(
    files: *const wz_ext_proto_file_t,
    count: usize,
) -> Result<Vec<ProtoFile<'a>>, ZResult> {
    if files.is_null() && count != 0 {
        return Err(Z_ERR_NULL);
    }
    let given: &[wz_ext_proto_file_t] = if count == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(files, count)
    };
    let mut out = Vec::with_capacity(given.len());
    for file in given {
        if file.name.is_null() || file.text.is_null() {
            return Err(Z_ERR_NULL);
        }
        let (Some(name), Some(text)) = (utf8_arg(file.name), utf8_arg(file.text)) else {
            return Err(Z_EINVAL);
        };
        out.push(ProtoFile {
            name,
            text: text.as_bytes(),
        });
    }
    Ok(out)
}
