// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.11 filesystem storage — the key <-> relative-path translation.
//!
//! R2573, and it is the FIRST leg of a redesign the owner chose rather than a
//! knob round. wz's filesystem storage stores every key as a hashed flat file
//! (`filesystem_storage.rs` @ `fn allocate_filename`, which returns
//! `k<hex16(fnv1a64(key))>`), so a stored key has no path, no extension and no
//! directory structure. Upstream's fs backend is the opposite artifact: it
//! mirrors the key space onto a real directory tree, which is what gives its
//! `follow_links` and `keep_mime_types` properties anything to act on. Those
//! two are not unimplemented knobs here -- they are consequences of a SHAPE,
//! and this module is the first piece of that shape.
//!
//! It is deliberately pure: string and path translation with no IO, so the
//! rules can be pinned by test before any storage is rewired to them. Nothing
//! calls it yet, and that is stated rather than hidden -- the storage switches
//! over in a later round, and doing both at once would mean the mapping's
//! first exercise was also its first regression surface.
//!
//! ## The contract, read from the counterparty at the matching version
//!
//! `zenoh-backend-filesystem` 1.10.1, which is the tag matching this tree's
//! zenoh pin (1.10.1). Its rules, each checked at its own definition:
//!
//! - the translation is IDENTITY on unix and swaps the separator on windows;
//! - a key that is a PREFIX of another key cannot be stored as written,
//!   because one name would have to be both a file and a directory. The FILE
//!   takes a suffix, and reading back strips it;
//! - the read-back trim also strips ONE leading separator.
//!
//! ⚠ Upstream's module is not reachable from this tree's citation gate: its
//! paths begin `zenoh-backend-filesystem/`, and the gate's roots are the zenoh
//! monorepo's top-level directories (`zenoh` followed by `/`, not `-`). So the
//! rules above are DESCRIBED with their symbol names rather than written as
//! `path` @ `needle` citations that would sit in no budget and be graded by
//! nothing. The symbols are `zpath_to_fspath`, `fspath_to_zpath`,
//! `CONFLICT_SUFFIX`, `get_conflict_resolved_keyexpr` and
//! `get_trimmed_keyexpr`, all in that crate's files-management module.

use std::borrow::Cow;

/// The suffix a key takes when its own name is also a directory.
///
/// Byte-for-byte upstream's `CONFLICT_SUFFIX`. It is deliberately not a
/// "nice" extension: it has to be a string no real key ends with, because a
/// key that genuinely ended in it would round-trip to the wrong key.
pub const CONFLICT_SUFFIX: &str = ".##z";

/// Translate a zenoh key into the relative path that holds it.
///
/// Identity on unix -- a key IS a relative path there, which is the whole
/// reason the mirror works at all. The `Cow` is not decoration: it keeps the
/// unix arm allocation-free while letting the windows arm own a rewritten
/// string, which is upstream's own split.
#[cfg(not(windows))]
pub fn zkey_to_relpath(zkey: &str) -> Cow<'_, str> {
    Cow::Borrowed(zkey)
}

/// Translate a zenoh key into the relative path that holds it.
#[cfg(windows)]
pub fn zkey_to_relpath(zkey: &str) -> Cow<'_, str> {
    Cow::Owned(zkey.replace('/', r"\"))
}

/// The inverse of [`zkey_to_relpath`].
#[cfg(not(windows))]
pub fn relpath_to_zkey(relpath: &str) -> Cow<'_, str> {
    Cow::Borrowed(relpath)
}

/// The inverse of [`zkey_to_relpath`].
#[cfg(windows)]
pub fn relpath_to_zkey(relpath: &str) -> Cow<'_, str> {
    Cow::Owned(relpath.replace(std::path::MAIN_SEPARATOR, "/"))
}

/// The name a key takes when a directory already claims its unsuffixed form.
pub fn conflict_resolved(zkey: &str) -> String {
    let mut s = String::with_capacity(zkey.len() + CONFLICT_SUFFIX.len());
    s.push_str(zkey);
    s.push_str(CONFLICT_SUFFIX);
    s
}

/// Undo [`conflict_resolved`], then drop one leading separator.
///
/// Both halves are upstream's, in upstream's order. The leading-separator trim
/// is second because a key may carry both.
pub fn trimmed_key(zkey: &str) -> &str {
    let k = zkey.strip_suffix(CONFLICT_SUFFIX).unwrap_or(zkey);
    k.strip_prefix('/').unwrap_or(k)
}

/// Whether a key may be joined onto the store's base directory at all.
///
/// ⚠ A NAMED DIVERGENCE, in the safe direction, and the reason is that wz and
/// upstream do not receive the same thing. Upstream reaches its mapping only
/// through a validated `keyexpr`; wz's storage backend takes `Option<&str>`
/// straight off its own API, so the guarantee upstream inherits from its type
/// does not exist here. A key containing a parent-directory chunk would
/// otherwise escape the base directory when joined -- the mapping is identity
/// on unix, so nothing else stands between a key and the filesystem.
///
/// This REFUSES rather than sanitises. A sanitising mapping would silently
/// store one key's data under another key's path, and a storage that answers a
/// different key than it was asked is worse than one that refuses.
pub fn is_confinable(zkey: &str) -> bool {
    if zkey.is_empty() || zkey.starts_with('/') {
        return false;
    }
    // Reject on the SEPARATED chunks, not with a substring search: a chunk
    // legitimately containing dots (`a..b`, `..c`) is not a traversal, and a
    // `contains("..")` would refuse those while a chunk-wise test accepts them
    // and still refuses the one chunk that traverses.
    !zkey
        .split('/')
        .any(|chunk| chunk.is_empty() || chunk == ".." || chunk == ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_its_own_relative_path_and_round_trips() {
        for k in ["a", "a/b", "demo/example/x", "a/b/c/d/e"] {
            let rel = zkey_to_relpath(k);
            assert_eq!(relpath_to_zkey(&rel), k, "round trip for {k:?}");
        }
    }

    #[test]
    fn the_conflict_suffix_round_trips_through_the_trim() {
        let k = "demo/example";
        let stored = conflict_resolved(k);
        assert_eq!(stored, "demo/example.##z");
        assert_eq!(trimmed_key(&stored), k);
    }

    #[test]
    fn the_trim_takes_the_suffix_and_then_one_leading_separator() {
        // Both halves, in upstream's order, on one input that carries both.
        assert_eq!(trimmed_key("/demo/example.##z"), "demo/example");
        // ... and each alone, so a passing test above cannot be one arm only.
        assert_eq!(trimmed_key("/demo/example"), "demo/example");
        assert_eq!(trimmed_key("demo/example.##z"), "demo/example");
        assert_eq!(trimmed_key("demo/example"), "demo/example");
    }

    #[test]
    fn the_trim_removes_exactly_one_leading_separator() {
        // A second separator is part of the key's first chunk, not decoration.
        assert_eq!(trimmed_key("//demo"), "/demo");
    }

    #[test]
    fn a_traversing_key_is_refused_and_a_dotted_one_is_not() {
        // The whole point of testing chunk-wise rather than by substring.
        assert!(!is_confinable("a/../../etc/passwd"));
        assert!(!is_confinable(".."));
        assert!(!is_confinable("a/.."));
        assert!(!is_confinable("a/./b"));
        assert!(!is_confinable("/absolute"));
        assert!(!is_confinable(""));
        assert!(!is_confinable("a//b"));
        // Dots that are not a traversal survive, which a `contains("..")`
        // implementation would wrongly refuse.
        assert!(is_confinable("a..b"));
        assert!(is_confinable("..c"));
        assert!(is_confinable("a/b..c/d"));
        assert!(is_confinable("demo/example/x"));
    }

    #[test]
    fn a_key_ending_in_the_suffix_is_the_shape_the_suffix_cannot_survive() {
        // Recorded rather than fixed, because upstream has the same property:
        // the trim cannot tell a real key ending in the suffix from a stored
        // conflict form. The test pins the CONSEQUENCE so a later round that
        // changes the suffix sees what it is trading.
        let awkward = "demo/example.##z";
        assert_eq!(trimmed_key(awkward), "demo/example");
    }
}
