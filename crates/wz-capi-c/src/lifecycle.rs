// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A NODE'S LIFECYCLE VERBS FROM THE LIBRARY A CLIENT LINKS: the key a verb is asked by, and the
//! answer read back.
//!
//! # Why these are doors
//!
//! A consumer that asks a node to open, close, reset or report on a peer makes the key
//! `@/<of>/<whatami>/session/<verb>/[<generation>/|passive/]<about>` and reads the reply. Until
//! now the key was made only by the generator of a declared node's queriers (`wz_node.py`) and the
//! reply read only by the node's own console line, so a client that asks with `z_get` had to write
//! a second maker of the key and a second reader of the reply, which disagree with the first where
//! the spelling is unusual. Both are here as the one Rust copy each:
//! `wz_session_core::lifecycle_wire::VerbWords` writes the key, held with the generator to one file
//! of vectors, and `wz_session_core::lifecycle_wire::Answer` reads a reply in band and a line the
//! node's control channel answers, as the node's `HOST-WZ-VERDICT` line reads it.
//!
//! # No allocation, no session
//!
//! Both are pure calls over the caller's memory: the key into the caller's buffer, the reading
//! into the caller's struct, every word in it a static C string this library owns.

use core::ffi::{c_char, CStr};

use wz_session_core::lifecycle_wire::{
    AnswerReading, VerbWords, READING_ERROR, READING_UNREADABLE, READING_VERDICT, READING_WHOAMI,
    VERB_KEY_MAX_BYTES,
};
use wz_session_core::text_out::FixedText;

use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};

/// The bytes a key buffer needs: the longest key and its NUL.
pub const WZ_CAPI_C_LIFECYCLE_KEY_MAX: usize = VERB_KEY_MAX_BYTES + 1;

/// The words a verb's key is made from. Every pointer is a NUL-terminated C string.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_capi_c_lifecycle_words_t {
    /// `open`, `close`, `reset` or `status`.
    pub verb: *const c_char,
    /// The zid of the node asked, lower-case hex as `z_id_to_string` prints it.
    pub of: *const c_char,
    /// The zid of the peer the verb is about, spelled the same way.
    pub about: *const c_char,
    /// `client`, `peer` or `router`; NULL is `client`.
    pub whatami: *const c_char,
    /// Whether `generation` is given: a reset takes one, every other verb none.
    pub has_generation: bool,
    /// A reset's generation.
    pub generation: u64,
    /// `dial` or `passive` (an open's); NULL is `dial`.
    pub mode: *const c_char,
}

/// What an answer was read as.
pub type wz_capi_c_lifecycle_kind_t = i32;
/// The bytes are no document a node writes: empty, another document, or cut short.
pub const WZ_CAPI_C_LIFECYCLE_UNREADABLE: wz_capi_c_lifecycle_kind_t = READING_UNREADABLE;
/// A verb's verdict on a peer, in band or on the control channel.
pub const WZ_CAPI_C_LIFECYCLE_VERDICT: wz_capi_c_lifecycle_kind_t = READING_VERDICT;
/// The control channel's answer to `whoami`: the node's zid.
pub const WZ_CAPI_C_LIFECYCLE_WHOAMI: wz_capi_c_lifecycle_kind_t = READING_WHOAMI;
/// The control channel's answer to a line that is no command.
pub const WZ_CAPI_C_LIFECYCLE_ERROR: wz_capi_c_lifecycle_kind_t = READING_ERROR;

/// An answer read back: `lifecycle_wire::AnswerReading`, the one C reading of an answer, which
/// `wz_dissect_lifecycle_read` hands out too. Every `const char *` is a static string this
/// library owns, or NULL where the kind does not carry it; a `has_` flag says whether the number
/// beside it was in the answer.
pub type wz_capi_c_lifecycle_read_t = AnswerReading;

/// A C string argument as UTF-8, NULL as `default`, or `None` when it is not UTF-8.
///
/// # Safety
/// `ptr` is NULL or a NUL-terminated C string.
unsafe fn text_or(ptr: *const c_char, default: &str) -> Option<&str> {
    if ptr.is_null() {
        return Some(default);
    }
    // SAFETY: caller contract.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Make the key a lifecycle verb is asked by, from its words, into `out` (`out_len` bytes, NUL
/// included; `WZ_CAPI_C_LIFECYCLE_KEY_MAX` always suffices). The key is
/// `@/<of>/<whatami>/session/<verb>/<about>`, with `<generation>/` before `<about>` for a reset and
/// `passive/` for an open whose mode is `passive`: the key a declared node's querier stated with
/// the same words asks.
///
/// Returns `Z_OK`, or `Z_EINVAL` when the words make no key, with `*refusal` (when it is not NULL)
/// set to the reason's word (`no-such-verb`, `no-such-role`, `no-such-mode`, `of-is-no-zid`,
/// `about-is-no-zid`, `reset-takes-a-generation`, `only-reset-takes-a-generation`,
/// `only-open-is-passive`), or `Z_ENULL` for a NULL `words`, `verb`, `of`, `about` or `out`, or a
/// word that is not UTF-8. A buffer shorter than the key is `Z_EINVAL` with `*refusal` NULL.
/// Nothing is written to `out` on a refusal.
///
/// # Safety
/// `words` points to a readable struct whose strings are NUL-terminated or NULL where allowed;
/// `out` is writable for `out_len` bytes; `refusal` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_lifecycle_key(
    words: *const wz_capi_c_lifecycle_words_t,
    out: *mut c_char,
    out_len: usize,
    refusal: *mut *const c_char,
) -> ZResult {
    let say = |why: *const c_char| {
        if !refusal.is_null() {
            // SAFETY: caller contract.
            unsafe { *refusal = why };
        }
    };
    say(core::ptr::null());
    if words.is_null() || out.is_null() {
        return Z_ENULL;
    }
    // SAFETY: caller contract.
    let w = unsafe { &*words };
    if w.verb.is_null() || w.of.is_null() || w.about.is_null() {
        return Z_ENULL;
    }
    // SAFETY: caller contract, and the three required pointers were checked above.
    let read = unsafe {
        (
            text_or(w.verb, ""),
            text_or(w.of, ""),
            text_or(w.about, ""),
            text_or(w.whatami, "client"),
            text_or(w.mode, "dial"),
        )
    };
    let (Some(verb), Some(of), Some(about), Some(whatami), Some(mode)) = read else {
        return Z_ENULL;
    };
    let words = VerbWords {
        verb,
        of,
        about,
        whatami,
        generation: w.has_generation.then_some(w.generation),
        mode,
    };
    let mut key: FixedText<VERB_KEY_MAX_BYTES> = FixedText::new();
    if let Err(why) = words.write(&mut key) {
        say(why.c_words().as_ptr());
        return Z_EINVAL;
    }
    let Ok(key) = key.finish() else {
        // VERB_KEY_MAX_BYTES is the longest key the writer writes.
        return Z_EINVAL;
    };
    if out_len < key.len() + 1 {
        return Z_EINVAL;
    }
    // SAFETY: `out` is writable for `out_len` bytes, which hold the key and its NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(key.as_ptr().cast::<c_char>(), out, key.len());
        *out.add(key.len()) = 0;
    }
    Z_OK
}

/// Read an answer a node gave: the bytes of a verb's reply in band, or one line its control
/// channel answered with (its line end cut). `out` is filled from scratch: `kind` says what the
/// bytes were, and every member the kind does not carry is NULL, 0 or false.
///
/// An answer that is no document a node writes (empty, another document, a word outside the
/// closed sets, a document cut short) is `WZ_CAPI_C_LIFECYCLE_UNREADABLE`; that is a reading and
/// not an error, so the call still returns `Z_OK`. Only the node's own spelling is read
/// (`lifecycle_wire::Answer::read`): its members in the order the node writes them, `verdict`
/// first, with no white space, so the same members in another order are unreadable. `Z_ENULL`
/// for a NULL `out`, or a NULL `bytes` with a non-zero `len`.
///
/// # Safety
/// `bytes` is readable for `len` bytes (or NULL with `len` 0), `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_lifecycle_read(
    bytes: *const u8,
    len: usize,
    out: *mut wz_capi_c_lifecycle_read_t,
) -> ZResult {
    if out.is_null() || (bytes.is_null() && len != 0) {
        return Z_ENULL;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: caller contract.
        unsafe { core::slice::from_raw_parts(bytes, len) }
    };
    // SAFETY: caller contract.
    unsafe { *out = AnswerReading::of(bytes) };
    Z_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use wz_session_core::lifecycle_wire::RefusedReason;

    fn key(words: wz_capi_c_lifecycle_words_t) -> Result<String, Option<String>> {
        let mut out = [0 as c_char; WZ_CAPI_C_LIFECYCLE_KEY_MAX];
        let mut why: *const c_char = core::ptr::null();
        let rc = unsafe { wz_capi_c_lifecycle_key(&words, out.as_mut_ptr(), out.len(), &mut why) };
        if rc == Z_OK {
            Ok(unsafe { CStr::from_ptr(out.as_ptr()) }
                .to_str()
                .expect("utf-8")
                .to_owned())
        } else {
            assert_eq!(rc, Z_EINVAL);
            Err((!why.is_null()).then(|| {
                unsafe { CStr::from_ptr(why) }
                    .to_str()
                    .expect("utf-8")
                    .to_owned()
            }))
        }
    }

    fn words(verb: &CStr) -> wz_capi_c_lifecycle_words_t {
        wz_capi_c_lifecycle_words_t {
            verb: verb.as_ptr(),
            of: c"a1b2".as_ptr(),
            about: c"c3d4".as_ptr(),
            whatami: core::ptr::null(),
            has_generation: false,
            generation: 0,
            mode: core::ptr::null(),
        }
    }

    /// The vectors the generator and the Rust writer are held to, through the C door.
    #[test]
    fn the_door_makes_every_vectors_key() {
        let vectors = include_str!("../../../scripts/lib/verb_key_vectors.txt");
        let mut seen = 0;
        for line in vectors
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let f: Vec<&str> = line.split(' ').collect();
            let cs: Vec<CString> = f
                .iter()
                .map(|s| CString::new(*s).expect("no NUL"))
                .collect();
            let w = wz_capi_c_lifecycle_words_t {
                verb: cs[0].as_ptr(),
                of: cs[1].as_ptr(),
                about: cs[2].as_ptr(),
                whatami: cs[3].as_ptr(),
                has_generation: f[4] != "-",
                generation: f[4].parse().unwrap_or(0),
                mode: cs[5].as_ptr(),
            };
            assert_eq!(key(w).as_deref(), Ok(f[6]), "{line}");
            seen += 1;
        }
        assert!(seen >= 7);
    }

    /// The header's key buffer size is this library's. The size is read off
    /// its `#define` line, so a checkout that ends lines with CRLF reads the
    /// same number.
    #[test]
    fn the_headers_key_buffer_is_the_librarys() {
        let header = include_str!("../include/wz_capi_c.h");
        let defined: Vec<usize> = header
            .lines()
            .filter_map(|line| line.strip_prefix("#define WZ_CAPI_C_LIFECYCLE_KEY_MAX "))
            .map(|n| n.trim().parse().expect("the define is a plain integer"))
            .collect();
        assert_eq!(
            defined,
            [WZ_CAPI_C_LIFECYCLE_KEY_MAX],
            "the header defines WZ_CAPI_C_LIFECYCLE_KEY_MAX once, as this library's size"
        );
    }

    #[test]
    fn defaults_refusals_and_a_short_buffer() {
        assert_eq!(
            key(words(c"close")).as_deref(),
            Ok("@/a1b2/client/session/close/c3d4")
        );
        let mut reset = words(c"reset");
        assert_eq!(key(reset), Err(Some("reset-takes-a-generation".into())));
        reset.has_generation = true;
        reset.generation = 3;
        assert_eq!(
            key(reset).as_deref(),
            Ok("@/a1b2/client/session/reset/3/c3d4")
        );
        let mut passive = words(c"close");
        passive.mode = c"passive".as_ptr();
        assert_eq!(key(passive), Err(Some("only-open-is-passive".into())));
        assert_eq!(key(words(c"hold")), Err(Some("no-such-verb".into())));

        let mut short = [0 as c_char; 8];
        let rc = unsafe {
            wz_capi_c_lifecycle_key(
                &words(c"close"),
                short.as_mut_ptr(),
                short.len(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert_eq!(short, [0; 8], "nothing written");
        let rc = unsafe {
            wz_capi_c_lifecycle_key(
                core::ptr::null(),
                short.as_mut_ptr(),
                8,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Z_ENULL);
    }

    fn read(bytes: &[u8]) -> wz_capi_c_lifecycle_read_t {
        let mut out = core::mem::MaybeUninit::<wz_capi_c_lifecycle_read_t>::uninit();
        let rc = unsafe { wz_capi_c_lifecycle_read(bytes.as_ptr(), bytes.len(), out.as_mut_ptr()) };
        assert_eq!(rc, Z_OK);
        unsafe { out.assume_init() }
    }

    fn text(ptr: *const c_char) -> &'static str {
        assert!(!ptr.is_null());
        unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf-8")
    }

    #[test]
    fn every_answer_reads_with_its_members_and_anything_else_is_unreadable() {
        let closing = read(br#"{"verdict":"closing","links":2}"#);
        assert_eq!(closing.kind, WZ_CAPI_C_LIFECYCLE_VERDICT);
        assert_eq!(text(closing.verdict), "closing");
        assert!(closing.has_links && closing.links == 2);
        assert!(closing.reason.is_null() && !closing.has_generation);

        for reason in RefusedReason::ALL {
            let doc = format!(
                "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                reason.words()
            );
            let refused = read(doc.as_bytes());
            assert_eq!(text(refused.verdict), "refused");
            assert_eq!(
                text(refused.reason),
                reason.words(),
                "the vocabulary's bytes"
            );
        }

        let status = read(
            br#"{"verdict":"status","links":{"open":1,"closing":0},"intent":true,"machines":[]}"#,
        );
        assert!(status.has_held && status.open == 1 && status.closing == 0);
        assert!(status.has_intent && status.intent);

        let whoami = read(br#"{"zid":"a1b2"}"#);
        assert_eq!(whoami.kind, WZ_CAPI_C_LIFECYCLE_WHOAMI);
        assert_eq!(
            unsafe { CStr::from_ptr(whoami.zid.as_ptr()) }.to_str(),
            Ok("a1b2")
        );

        let error = read(br#"{"error":"line-too-long"}"#);
        assert_eq!(error.kind, WZ_CAPI_C_LIFECYCLE_ERROR);
        assert_eq!(text(error.error), "line-too-long");

        // Only the node's own spelling: the same members in another order, or with white space,
        // are no document a node writes.
        let reordered =
            br#"{"reason":"the last chunk of the key is not a zid","verdict":"refused"}"#;
        let spaced = br#"{"verdict": "closing","links":1}"#;
        for other in [
            &b""[..],
            b"{}",
            br#"{"verdict":"closing""#,
            b"\xff",
            reordered,
            spaced,
        ] {
            let r = read(other);
            assert_eq!(r.kind, WZ_CAPI_C_LIFECYCLE_UNREADABLE, "{other:?}");
            assert!(r.verdict.is_null() && r.error.is_null() && r.zid[0] == 0);
        }
        let rc = unsafe { wz_capi_c_lifecycle_read(core::ptr::null(), 0, core::ptr::null_mut()) };
        assert_eq!(rc, Z_ENULL);
    }
}
