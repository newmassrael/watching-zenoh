// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SENTENCE A NODE OFFERS, held to its soundness property over every
//! capture the fuzzer makes: `wz_dissect_selector_term` over each node of the
//! field document `wz_dissect_pcap_fields_where_limited` renders, each sentence
//! held to what the record level proved, and the document rendered again under
//! a cover of the sentences.
//!
//! This target is the one in the crate that holds a door to a PROPERTY and not
//! only to its contract. For every record and every node of its tree with a
//! `selector_path`, the node's sentence must select the record and its
//! exclusion must not (`wz_capture::selector_term::soundness`, the one oracle
//! the library's own tests are held to as well). The document level runs
//! through the C doors exactly as a consumer calls them; the record level
//! reads the same capture through the library, under the same limits, where
//! the record trees are.
//!
//! Input: the `pcap` target's layout, eight bytes of arguments and then the
//! file, so every input that target's corpus grows is an input of this one
//! (`scripts/fuzz.sh` reads that corpus here too). Of the arguments only byte
//! 0 is read, and only for the two limits presets a door accepts: a preset the
//! door refuses renders no document, and the property would hold over nothing.
//! The `pcap` target is where a refused preset is fuzzed.

#![no_main]

use std::ffi::{c_char, CStr, CString};

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_capture::selector_term::soundness::{hold, Doors};
use wz_capture::selector_term::Verb;
use wz_capture::{Dissection, DissectionLimits};
use wz_fuzz::Reader;

/// The C doors over one capture.
struct CDoors<'a> {
    file: &'a [u8],
    limits: i32,
}

/// The string a door handed out, given back.
fn take(out: *mut c_char) -> String {
    // SAFETY: a door that answered OK handed out a NUL-terminated string that
    // is ours until it is freed, which is the next line.
    let text = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("every document is UTF-8")
        .to_owned();
    // SAFETY: as above; freed once.
    unsafe { wz_dissect_string_free(out) };
    text
}

impl Doors for CDoors<'_> {
    fn document(&mut self, selector: &str) -> Option<String> {
        let selector = CString::new(selector).ok()?;
        let mut out: *mut c_char = core::ptr::null_mut();
        // SAFETY: `file` is readable for its length, `selector` and the
        // declarations are NUL-terminated, `out` is a local. A row cap of 0
        // is unbounded.
        let rc = unsafe {
            wz_dissect_pcap_fields_where_limited(
                self.file.as_ptr(),
                self.file.len(),
                0,
                selector.as_ptr(),
                c"".as_ptr(),
                self.limits,
                &mut out,
            )
        };
        (rc == WZ_DISSECT_OK).then(|| take(out))
    }

    fn term(&mut self, node: &str, verb: Verb) -> String {
        let node = CString::new(node).expect("a document holds no NUL");
        let mut out: *mut c_char = core::ptr::null_mut();
        // SAFETY: `node` is NUL-terminated, the selector may be null, `out` is
        // a local.
        let rc = unsafe {
            wz_dissect_selector_term(node.as_ptr(), verb.code(), core::ptr::null(), &mut out)
        };
        assert_eq!(
            rc, WZ_DISSECT_OK,
            "a node object is never an argument error"
        );
        take(out)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    // The door's preset and the library's, the same limits on both levels.
    let (limits, preset) = if r.u8() % 2 == 0 {
        (WZ_DISSECT_LIMITS_NONE, DissectionLimits::default())
    } else {
        (WZ_DISSECT_LIMITS_LIVE_TAP, DissectionLimits::for_live_tap())
    };
    let _pcap_arguments = r.bytes(7);
    let file = r.rest();
    let Ok(d) = Dissection::from_capture_bounded(file, preset) else {
        return;
    };
    let held = hold(&mut CDoors { file, limits }, &d);
    assert!(held.holds(), "the sentences are not sound: {held}");
});
