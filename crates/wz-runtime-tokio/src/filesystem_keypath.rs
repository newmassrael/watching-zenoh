// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.11 filesystem storage — the key <-> relative-path translation.
//!
//! R2573, and it is the FIRST leg of a redesign the owner chose rather than a
//! knob round. wz's filesystem storage stored every key as a hashed flat file
//! (the R311y279 layout: one `k<hex16(fnv1a64(key))>` record per key in one
//! directory), so a stored key had no path, no extension and no directory
//! structure. Upstream's fs backend is the opposite artifact: it mirrors the key
//! space onto a real directory tree, which is what gives its `follow_links` and
//! `keep_mime_types` properties anything to act on. Those two are not
//! unimplemented knobs -- they are consequences of a SHAPE, and this module is
//! the first piece of that shape.
//!
//! It is deliberately pure: string and path translation with no IO. R2573 built
//! and pinned it before anything called it, so the storage's switch-over would
//! move onto a fixed contract; R2801 is that switch-over, and
//! [`crate::filesystem_storage`] now places every value by these rules.
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
//! `get_trimmed_keyexpr`, all in that crate's files-management module, and
//! `ROOT_KEY` in its library root.
//!
//! ## What a directory walk may read as a key (R2801)
//!
//! Upstream lists a storage by walking its directory and keeping a file only
//! when its relative path, trimmed, is a key expression -- `keyexpr::new`, whose
//! rules are read at the zenoh pin in
//! `commons/zenoh-keyexpr/src/key_expr/borrowed.rs` @ `impl<'a> TryFrom<&'a str> for &'a keyexpr {`
//! -- AND that key intersects `**`. The second test is not a formality: `**`
//! never reaches a chunk that begins with `@` (a VERBATIM chunk), which is what
//! keeps [`ROOT_KEY`](crate::filesystem_keypath::ROOT_KEY) out of the listing,
//! and what lets this backend keep its own staging area
//! ([`STAGING_DIR`](crate::filesystem_keypath::STAGING_DIR)) inside the tree
//! without either implementation reading it back as data.
//! [`is_listable_key`](crate::filesystem_keypath::is_listable_key) is the two
//! tests together. (Full paths because a `//!` link resolves from the crate
//! root, where none of the three is in scope -- R2800's lesson, paid again.)

use std::borrow::Cow;

use wz_session_core::keyexpr_match::keyexpr_intersect_patterns;

/// The file that holds the `None` key -- the value a strip-configured storage
/// keeps AT its mount point. Byte-for-byte upstream's `ROOT_KEY`, and a
/// verbatim chunk on purpose: a walk's `**` never lists it, so it is read back
/// by name and never as an ordinary key.
pub const ROOT_KEY: &str = "@root";

/// The directory, directly under a storage's base directory, where this
/// backend writes a value before renaming it into place.
///
/// ⚠ wz's, not upstream's: upstream writes a file in place, which truncates the
/// previous value first, so a crash mid-write loses it. wz writes here, fsyncs,
/// and renames, so the key's path only ever names a complete value. The name is
/// a verbatim chunk for the reason [`ROOT_KEY`] is -- zenohd walks straight
/// into it (it skips only the data-info directory by name) and still never
/// lists what a crash left behind, because `**` does not reach it.
pub const STAGING_DIR: &str = "@wz_staging";

/// The suffix a key takes when its own name is also a directory.
///
/// Byte-for-byte upstream's `CONFLICT_SUFFIX`. It is deliberately not a
/// "nice" extension: it has to be a string no real key ends with, because a
/// key that genuinely ended in it would round-trip to the wrong key -- and it
/// is one, because `#` may not appear in a key expression at all ([`is_keyexpr`]).
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

/// Whether `value` is a key expression by zenoh's own test — a port of
/// `keyexpr::new`, rule for rule, from the pin (see the module note).
///
/// A port rather than wz's canonizer, because the two answer different
/// questions: `keyexpr_canon` bounds its output at 256 bytes for the MCU
/// profiles, and a file several directories deep is a longer key than that
/// with nothing wrong with it. Upstream's walk admits it, so this does.
pub fn is_keyexpr(value: &str) -> bool {
    // Emptiness and a trailing slash are not caught by the scan below.
    if value.is_empty() || value.ends_with('/') {
        return false;
    }
    let bytes = value.as_bytes();
    let mut chunk_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // Every special character sorts at or below '/', except '?'.
            c if c > b'/' && c != b'?' => i += 1,
            b'/' if i == chunk_start => return false,
            b'/' => {
                i += 1;
                chunk_start = i;
            }
            // A '*' must open its chunk, and be `*` or `**` alone in it.
            b'*' if i != chunk_start => return false,
            b'*' => match bytes.get(i + 1) {
                None => break,
                Some(&b'/') => {
                    i += 2;
                    chunk_start = i;
                }
                Some(&b'*') => match bytes.get(i + 2) {
                    None => break,
                    // `**` may not be followed by `*` or `**`.
                    Some(&b'/') if matches!(bytes.get(i + 3), Some(&b'*')) => return false,
                    Some(&b'/') => {
                        i += 3;
                        chunk_start = i;
                    }
                    _ => return false,
                },
                _ => return false,
            },
            // A '$' must be `$*`, not followed by another '$', and not alone.
            b'$' if bytes.get(i + 1) != Some(&b'*') => return false,
            b'$' => match bytes.get(i + 2) {
                Some(&b'$') => return false,
                Some(&b'/') | None if i == chunk_start => return false,
                None => break,
                _ => i += 2,
            },
            b'#' | b'?' => return false,
            _ => i += 1,
        }
    }
    true
}

/// Whether a directory walk reads `zkey` back as a stored key: it must be a
/// key expression AND intersect `**`, which is upstream's listing filter (see
/// the module note). The intersection is wz's own
/// [`keyexpr_intersect_patterns`], so "`**` does not reach a verbatim chunk" is
/// answered by the rule the query path uses rather than restated here.
pub fn is_listable_key(zkey: &str) -> bool {
    if !is_keyexpr(zkey) {
        return false;
    }
    let chunks: Vec<&str> = zkey.split('/').collect();
    keyexpr_intersect_patterns(&["**"], &chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_keyexpr_takes_upstreams_rules_one_by_one() {
        for ok in [
            "a", "a/b/c", "a/*/c", "a/**/c", "**", "a/$*b", "a/b$*", "@root", "..", "a..b",
        ] {
            assert!(is_keyexpr(ok), "{ok:?} is a key expression");
        }
        for bad in [
            // A conflict-suffixed name: the suffix is built from `#`, which no
            // key may contain. See the last test in this module.
            "a/b.##z",
            "",
            "a/",
            "/a",
            "a//b",
            "a*",
            "a/b*c",
            "**/**",
            "a/**/*",
            "a/**/**/b",
            "$*",
            "a/$*",
            "a/$*/b",
            "a$",
            "a$b",
            "a$*$*b",
            "a#b",
            "a?b",
        ] {
            assert!(!is_keyexpr(bad), "{bad:?} is not a key expression");
        }
    }

    #[test]
    fn is_keyexpr_has_no_length_bound() {
        // The reason this is a port and not wz's 256-byte canonizer.
        let deep = "segment/".repeat(64) + "leaf";
        assert!(deep.len() > 256);
        assert!(is_keyexpr(&deep));
    }

    #[test]
    fn a_walk_lists_keys_and_never_a_verbatim_chunk() {
        assert!(is_listable_key("demo/a"));
        assert!(is_listable_key("wild/*/x"));
        // The root slot and the staging area are the reason the rule exists.
        assert!(!is_listable_key(ROOT_KEY));
        assert!(!is_listable_key(&format!("{STAGING_DIR}/tmp.1.0")));
        // A verbatim chunk anywhere, not only first.
        assert!(!is_listable_key("a/@b/c"));
        // And a path that is no key at all.
        assert!(!is_listable_key("a#b"));
    }

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

    /// R2573 wrote this test as "the shape the suffix cannot survive": a real
    /// key ending in the suffix would trim to a DIFFERENT key, and it recorded
    /// that as a property upstream shares.
    ///
    /// R2801 REFUTES the premise, found by porting `keyexpr::new`: the suffix is
    /// `.##z`, `#` is one of the two characters a key expression may never
    /// contain, so no key ends in it. That is WHY upstream trims before it
    /// validates -- a conflict-suffixed path is not a key until the suffix is
    /// gone -- and it is what makes the trim unambiguous for every real key.
    /// The residue lives one layer up and is closed there: wz's backend takes
    /// `Option<&str>` rather than a validated key, so
    /// `FilesystemStorage::key_path` refuses a key that is not a key expression,
    /// and this string can no longer be placed at all.
    #[test]
    fn no_key_can_end_in_the_suffix_so_the_trim_is_unambiguous() {
        let awkward = "demo/example.##z";
        assert!(!is_keyexpr(awkward), "`#` is forbidden in a key expression");
        assert!(is_keyexpr(trimmed_key(awkward)));
        assert_eq!(trimmed_key(awkward), "demo/example");
    }
}
