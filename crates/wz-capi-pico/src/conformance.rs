// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The conformance digest of this build (docs/build-configuration.md, decision C15).
//!
//! `wz_config.py --conformance-statement pico CONFIG` (and its presets and original routes)
//! prints what a build of this library is: every capability the pico ABI exports with whether the
//! build has it, every limit and policy with its value, and the digest of those values. The build
//! script (`wz-conformance-build`) reads the same answers from what this crate is compiled with and
//! puts the digest here, so a tester holding a statement asks the library which build it is and
//! compares the two. Equal digests are the same build; a different one names a library that is not
//! the build the statement describes.

include!(concat!(env!("OUT_DIR"), "/conformance_digest.rs"));

/// The conformance digest of this build: `sha256:` and 64 lowercase hex digits, NUL-terminated,
/// static for the life of the program. Present in every build.
#[no_mangle]
pub extern "C" fn wz_ext_conformance_digest() -> *const core::ffi::c_char {
    CONFORMANCE_DIGEST.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_sha256_in_lowercase_hex() {
        let text = CONFORMANCE_DIGEST.to_str().expect("ASCII");
        let hex = text.strip_prefix("sha256:").expect("the sha256: prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn the_build_script_read_the_features_this_crate_was_compiled_with() {
        assert_eq!(STATED_FEATURES, COMPILED_FEATURES);
        assert!(!STATED_FEATURES.is_empty());
    }

    #[test]
    fn the_door_hands_out_the_digest() {
        // SAFETY: the door returns a pointer to a static NUL-terminated string.
        let handed = unsafe { core::ffi::CStr::from_ptr(wz_ext_conformance_digest()) };
        assert_eq!(handed, CONFORMANCE_DIGEST);
    }
}
