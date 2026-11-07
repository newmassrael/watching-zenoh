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
use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::OnceLock;

use wz_session_core::lifecycle_wire::{
    Answer, ControlError, KeyRefusal, RefusedReason, VerbWords, VERB_KEY_MAX_BYTES, VERDICT_WORDS,
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
pub const WZ_CAPI_C_LIFECYCLE_UNREADABLE: wz_capi_c_lifecycle_kind_t = 0;
/// A verb's verdict on a peer, in band or on the control channel.
pub const WZ_CAPI_C_LIFECYCLE_VERDICT: wz_capi_c_lifecycle_kind_t = 1;
/// The control channel's answer to `whoami`: the node's zid.
pub const WZ_CAPI_C_LIFECYCLE_WHOAMI: wz_capi_c_lifecycle_kind_t = 2;
/// The control channel's answer to a line that is no command.
pub const WZ_CAPI_C_LIFECYCLE_ERROR: wz_capi_c_lifecycle_kind_t = 3;

/// An answer read back. Every `const char *` is a static string this library owns, or NULL where
/// the kind does not carry it; a `has_` flag says whether the number beside it was in the answer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_capi_c_lifecycle_read_t {
    /// What the bytes were read as.
    pub kind: wz_capi_c_lifecycle_kind_t,
    /// The verdict word, on a verdict.
    pub verdict: *const c_char,
    /// The refusal's sentence, on `refused`: the words of the vocabulary's `verdicts.reasons`.
    pub reason: *const c_char,
    /// The error word, on an error.
    pub error: *const c_char,
    /// Whether `links` is given.
    pub has_links: bool,
    /// The links a `closing` or `resetting` call ordered closed.
    pub links: u32,
    /// Whether `generation` is given.
    pub has_generation: bool,
    /// The latest generation taken for the peer, on `duplicate`.
    pub generation: u64,
    /// Whether `open` and `closing` are given.
    pub has_held: bool,
    /// The node's open links to the peer, on `status`.
    pub open: u32,
    /// The node's links to the peer a close was ordered for, on `status`.
    pub closing: u32,
    /// Whether `intent` is given.
    pub has_intent: bool,
    /// Whether a machine holds the peer in the node's intent, on `status`.
    pub intent: bool,
    /// The node's zid on `whoami`, NUL-terminated; empty otherwise.
    pub zid: [c_char; 33],
}

/// Every word an answer or a refusal can carry, as a C string this library holds for good: the
/// verdict words, the refusal sentences, the control channel's error words and the key's refusals.
/// Derived from the Rust sets, so no word is spelled a second time here.
fn c_word(word: &str) -> *const c_char {
    static WORDS: OnceLock<BTreeMap<&'static str, CString>> = OnceLock::new();
    let words = WORDS.get_or_init(|| {
        let all = VERDICT_WORDS
            .into_iter()
            .chain(RefusedReason::ALL.map(RefusedReason::words))
            .chain(ControlError::ALL.map(ControlError::words))
            .chain(KeyRefusal::ALL.map(KeyRefusal::words));
        all.map(|w| (w, CString::new(w).expect("a word holds no NUL")))
            .collect()
    });
    words
        .get(word)
        .map_or(core::ptr::null(), |text| text.as_ptr())
}

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
        say(c_word(why.words()));
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
/// not an error, so the call still returns `Z_OK`. `Z_ENULL` for a NULL `out`, or a NULL `bytes`
/// with a non-zero `len`.
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
    let mut read = wz_capi_c_lifecycle_read_t {
        kind: WZ_CAPI_C_LIFECYCLE_UNREADABLE,
        verdict: core::ptr::null(),
        reason: core::ptr::null(),
        error: core::ptr::null(),
        has_links: false,
        links: 0,
        has_generation: false,
        generation: 0,
        has_held: false,
        open: 0,
        closing: 0,
        has_intent: false,
        intent: false,
        zid: [0; 33],
    };
    match Answer::read(bytes) {
        None => {}
        Some(Answer::Verdict(verdict)) => {
            read.kind = WZ_CAPI_C_LIFECYCLE_VERDICT;
            read.verdict = c_word(verdict.verdict);
            read.reason = verdict
                .reason
                .map_or(core::ptr::null(), |r| c_word(r.words()));
            if let Some(links) = verdict.links {
                (read.has_links, read.links) = (true, links);
            }
            if let Some(generation) = verdict.generation {
                (read.has_generation, read.generation) = (true, generation);
            }
            if let Some(held) = verdict.held {
                (read.has_held, read.open, read.closing) = (true, held.open, held.closing);
            }
            if let Some(intent) = verdict.intent {
                (read.has_intent, read.intent) = (true, intent);
            }
        }
        Some(Answer::Whoami(zid)) => {
            read.kind = WZ_CAPI_C_LIFECYCLE_WHOAMI;
            // A zid read here is at most 32 lower-case hex digits.
            for (slot, byte) in read.zid.iter_mut().zip(zid.bytes()) {
                *slot = byte as c_char;
            }
        }
        Some(Answer::Error(error)) => {
            read.kind = WZ_CAPI_C_LIFECYCLE_ERROR;
            read.error = c_word(error.words());
        }
    }
    // SAFETY: caller contract.
    unsafe { *out = read };
    Z_OK
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The header's key buffer size is this library's.
    #[test]
    fn the_headers_key_buffer_is_the_librarys() {
        let header = include_str!("../include/wz_capi_c.h");
        let line = format!("#define WZ_CAPI_C_LIFECYCLE_KEY_MAX {WZ_CAPI_C_LIFECYCLE_KEY_MAX}\n");
        assert!(header.contains(&line), "the header states {line:?}");
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

        for other in [&b""[..], b"{}", br#"{"verdict":"closing""#, b"\xff"] {
            let r = read(other);
            assert_eq!(r.kind, WZ_CAPI_C_LIFECYCLE_UNREADABLE, "{other:?}");
            assert!(r.verdict.is_null() && r.error.is_null() && r.zid[0] == 0);
        }
        let rc = unsafe { wz_capi_c_lifecycle_read(core::ptr::null(), 0, core::ptr::null_mut()) };
        assert_eq!(rc, Z_ENULL);
    }
}
