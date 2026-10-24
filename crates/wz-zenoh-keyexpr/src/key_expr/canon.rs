// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Canonization: the rewriting that makes two spellings of one set of keys the same string.
//!
//! Three rules, each from the language's definition:
//! * any contiguous run of `$*` inside a chunk is one `$*`, and a chunk that is only `$*` is `*`;
//! * a maximal run of consecutive chunks that are each `*` or `**` is rewritten as its `*` chunks
//!   followed by one `**` when it had any `**` (so `**/**` is `**` and `**/*` is `*/**`).

use alloc::{string::String, vec::Vec};

/// A string-like value whose key expression spelling can be rewritten into canon form in place.
pub trait Canonize {
    /// Rewrite `self` into canon form.
    fn canonize(&mut self);
}

/// One chunk with its runs of `$*` collapsed, and a lone `$*` turned into `*`.
fn canonize_chunk(chunk: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    let mut i = 0;
    while i < chunk.len() {
        if chunk[i..].starts_with(b"$*") {
            out.extend_from_slice(b"$*");
            i += 2;
            while chunk[i..].starts_with(b"$*") {
                i += 2;
            }
        } else {
            out.push(chunk[i]);
            i += 1;
        }
    }
    if &out[start..] == b"$*" {
        out.truncate(start);
        out.push(b'*');
    }
}

/// The canonized spelling of `bytes`.
fn canonized(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    // The pending run of wildcard chunks: how many `*`, and whether a `**` was among them.
    let mut singles = 0usize;
    let mut double = false;
    let mut first = true;
    let flush = |out: &mut Vec<u8>, singles: &mut usize, double: &mut bool, first: &mut bool| {
        let mut separate = |out: &mut Vec<u8>| {
            if !*first {
                out.push(b'/');
            }
            *first = false;
        };
        for _ in 0..*singles {
            separate(out);
            out.push(b'*');
        }
        if *double {
            separate(out);
            out.extend_from_slice(b"**");
        }
        *singles = 0;
        *double = false;
    };
    for chunk in bytes.split(|c| *c == b'/') {
        let mut canon = Vec::with_capacity(chunk.len());
        canonize_chunk(chunk, &mut canon);
        match canon.as_slice() {
            b"*" => singles += 1,
            b"**" => double = true,
            _ => {
                flush(&mut out, &mut singles, &mut double, &mut first);
                if !first {
                    out.push(b'/');
                }
                first = false;
                out.extend_from_slice(&canon);
            }
        }
    }
    flush(&mut out, &mut singles, &mut double, &mut first);
    out
}

impl Canonize for &mut str {
    /// Canonize in place: the string shrinks to its canon form and the bytes it no longer covers
    /// are zeroed.
    fn canonize(&mut self) {
        // SAFETY: the canon form is valid UTF-8 (it is built from whole chunks of a valid string
        // and ASCII separators), and the bytes after it are overwritten with NULs, which are valid.
        let bytes = unsafe { self.as_bytes_mut() };
        let canon = canonized(bytes);
        bytes[..canon.len()].copy_from_slice(&canon);
        bytes[canon.len()..].fill(b'\0');
        *self = &mut core::mem::take(self)[..canon.len()];
    }
}

impl Canonize for String {
    /// Canonize in place: the string is replaced by its canon form.
    fn canonize(&mut self) {
        let canon = canonized(self.as_bytes());
        // SAFETY: as above, the canon form is valid UTF-8.
        *self = unsafe { String::from_utf8_unchecked(canon) };
    }
}
