// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Ungated keyexpr non-wild-prefix SSOT — the shared core behind §5.24 storage
//! strip-prefix ([`crate::storage_strip_prefix`]) and §5.21 routing-namespace
//! ([`crate::namespace`]).
//!
//! [`strip_nonwild_prefix`] is the wz port of zenoh's
//! `keyexpr::strip_nonwild_prefix`
//! (`commons/zenoh-keyexpr/src/key_expr/borrowed.rs:292`): strip a NON-WILD
//! prefix from a possibly-WILD `target` keyexpr at CHUNK boundaries, returning
//! the longest matching suffix (a sub-slice of `target`, no allocation). The
//! wild-target handling (`**` / `*` / `$*`) is what distinguishes it from a
//! plain string strip and is required by the namespace INGRESS path: a peer's
//! inbound subscription/queryable declaration may itself be wild (e.g. a remote
//! `**` arriving on a `<ns>`-namespaced session must strip to `**`). A concrete
//! (wildcard-free) target reduces to a literal chunk-boundary strip, which is
//! exactly what the storage mount-prefix transform needs — so the two domains
//! share ONE chunk-walk SSOT instead of open-coding the chunk boundary twice.
//!
//! [`NonWildKeyExpr`] makes "a prefix with no wildcard chunk" unrepresentable
//! by construction (the wz analog of zenoh's `nonwild_keyexpr` /
//! `OwnedNonWildKeyExpr`, `borrowed.rs:902`). It replaces the open-coded
//! runtime `.contains('*')` check that [`crate::storage_strip_prefix`] used, so
//! both consumers validate non-wildness through ONE typed gate.
//!
//! @verbatim (`@`): wz does NOT implement @verbatim chunk semantics ANYWHERE —
//! `keyexpr_match` / `keyexpr_canon` are uniformly @-blind (treat `@` as an
//! ordinary byte; see `crates/wz-integration-tests/tests/
//! layer3_keyexpr_intersect.rs:31`). To stay CONSISTENT with the rest of the wz
//! keyexpr stack, this port likewise treats `@` as ordinary — zenoh's two
//! @verbatim guards (`is_chunk_matching`'s verbatim-only-matches-verbatim rule
//! and the `**`-must-not-cross-`@` stop-loop) are intentionally OMITTED. Both
//! guards key off the PREFIX, so results differ from zenoh only when the prefix
//! (the namespace / mount prefix) itself contains an `@` chunk — an `@` in the
//! target alone never diverges (confirmed by differential fuzz). Making strip
//! @-aware while the matcher stays @-blind would be the WORSE choice (an
//! internally inconsistent keyexpr stack where a sample strips one way and
//! matches another); full @verbatim support is a re-openable stack-wide atom
//! (canon + match + strip together), not a namespace-local concern.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString as _};

/// A keyexpr prefix proven to contain no wildcard chunk (`*`, `**`, or the `$*`
/// dollar-star), the wz analog of zenoh's `nonwild_keyexpr`. Built once via
/// [`NonWildKeyExpr::new`]; the no-wildcard invariant then holds by
/// construction at every use site (storage strip-prefix, namespace prefix),
/// replacing scattered runtime `.contains('*')` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonWildKeyExpr<'a>(&'a str);

/// Why [`NonWildKeyExpr::new`] rejected a candidate prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonWildError {
    /// Empty string — not a valid keyexpr prefix.
    Empty,
    /// Contains a wildcard. `*` is the sole wildcard marker and also the lead
    /// byte of the `$*` dollar-star, so a single `*` scan covers every wild
    /// chunk zenoh's `nonwild_keyexpr` forbids (matches the prior storage
    /// `.contains('*')` check and zenoh `is_wild`, `borrowed.rs:133`).
    Wild,
}

impl<'a> NonWildKeyExpr<'a> {
    /// Validate that `s` is a non-empty string with no wildcard, returning the
    /// proven-non-wild newtype. `const` so a static namespace literal can be
    /// validated at compile time.
    pub const fn new(s: &'a str) -> Result<Self, NonWildError> {
        if s.is_empty() {
            return Err(NonWildError::Empty);
        }
        // `str::contains` is not `const`; scan bytes for '*' directly. ASCII '*'
        // (0x2A) is a single byte and cannot occur inside a multi-byte UTF-8
        // sequence (continuation/lead bytes are all >= 0x80), so a raw byte scan
        // is correct on arbitrary UTF-8.
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'*' {
                return Err(NonWildError::Wild);
            }
            i += 1;
        }
        Ok(NonWildKeyExpr(s))
    }

    /// The validated prefix as a string slice.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// Strip the non-wild `prefix` from `target` at chunk boundaries, returning the
/// longest matching suffix, or `None` if `target` is not under `prefix`. The wz
/// port of zenoh `keyexpr::strip_nonwild_prefix` (`borrowed.rs:292`), @-blind
/// (see module docs).
///
/// `target` MAY contain wildcards (`**` / `*` / `$*`); the result is a chunk-
/// aligned sub-slice of `target` (no allocation). `target == prefix` yields
/// `None` — a keyexpr cannot be empty — matching zenoh (`borrowed.rs:386`).
pub fn strip_nonwild_prefix<'t>(target: &'t str, prefix: NonWildKeyExpr<'_>) -> Option<&'t str> {
    let tail = strip_inner(target.as_bytes(), prefix.0.as_bytes())?;
    // Every slice `strip_inner` returns is a chunk-aligned suffix of the valid
    // UTF-8 `target` (it only ever splits on the ASCII byte '/'), so it is valid
    // UTF-8; the `.ok()` cannot fail and is kept only to avoid `unsafe`.
    core::str::from_utf8(tail).ok()
}

/// Match a single wildcard-bearing `target` chunk against a non-wild `prefix`
/// chunk (no `/` in either). Port of zenoh's private `is_chunk_matching`
/// (`borrowed.rs:293`) with the `@`-verbatim guard omitted (see module docs).
fn is_chunk_matching(target: &[u8], prefix: &[u8]) -> bool {
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut tprev = b'/';
    while ti < target.len() && pi < prefix.len() {
        if target[ti] == b'*' {
            if tprev == b'*' || ti + 1 == target.len() {
                // a `**` chunk, or a trailing single `*` — matches anything.
                return true;
            } else if tprev == b'$' {
                // `$*` partial: try to anchor the remainder at each prefix offset.
                let mut i = pi;
                while i < prefix.len() - 1 {
                    if is_chunk_matching(&target[ti + 1..], &prefix[i..]) {
                        return true;
                    }
                    i += 1;
                }
            }
        } else if target[ti] == prefix[pi] {
            pi += 1;
        } else if target[ti] != b'$' {
            // ordinary char that does not match, and not the `$` of a `$*`.
            return false;
        }
        tprev = target[ti];
        ti += 1;
    }
    if pi != prefix.len() {
        // prefix not consumed entirely.
        return false;
    }
    ti == target.len() || (ti + 2 == target.len() && target[ti] == b'$')
}

/// Chunk-walk core. Port of zenoh's private `strip_nonwild_prefix_inner`
/// (`borrowed.rs:331`) with the `@`-verbatim branch collapsed to its no-`@`
/// arm (see module docs).
fn strip_inner<'t>(target: &'t [u8], prefix: &[u8]) -> Option<&'t [u8]> {
    let mut ti = 0usize;
    let mut pi = 0usize;
    while ti < target.len() && pi < prefix.len() {
        let te = ti
            + target[ti..]
                .iter()
                .position(|&c| c == b'/')
                .unwrap_or(target.len() - ti);
        let pe = pi
            + prefix[pi..]
                .iter()
                .position(|&c| c == b'/')
                .unwrap_or(prefix.len() - pi);
        let tchunk = &target[ti..te];
        if tchunk.len() == 2 && tchunk[0] == b'*' {
            // `**`: @-blind, it matches every remaining prefix chunk, so keep the
            // `**` and the rest of `target` as the suffix.
            return Some(&target[ti..]);
        }
        if te == target.len() {
            // target has no more chunks than prefix and the last is non-`**`, so
            // it cannot fully cover prefix.
            return None;
        }
        if !is_chunk_matching(tchunk, &prefix[pi..pe]) {
            return None;
        }
        if pe == prefix.len() {
            // prefix fully matched; the suffix starts after this target chunk.
            return Some(&target[(te + 1)..]);
        }
        ti = te + 1;
        pi = pe + 1;
    }
    None
}

/// Owned validated non-wild keyexpr — the namespace VALUE a participant holds
/// for the life of the session (the wz analog of zenoh's `OwnedNonWildKeyExpr`,
/// `commons/zenoh-config/src/lib.rs:841` `Option<OwnedNonWildKeyExpr>`).
/// Validated once at construction; the invariant then holds without re-checking.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedNonWildKeyExpr(String);

#[cfg(feature = "alloc")]
impl OwnedNonWildKeyExpr {
    /// Validate and own `s` as a non-wild keyexpr.
    pub fn new(s: &str) -> Result<Self, NonWildError> {
        // Validate through the borrowed gate (single non-wild SSOT).
        NonWildKeyExpr::new(s)?;
        Ok(OwnedNonWildKeyExpr(s.to_string()))
    }

    /// Borrow as the validated non-wild newtype (zero re-validation).
    pub fn as_nonwild(&self) -> NonWildKeyExpr<'_> {
        NonWildKeyExpr(self.0.as_str())
    }

    /// The owned prefix as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Egress prepend: `<ns>/<suffix>`, or just `<ns>` when `suffix` is empty
    /// (the namespace-only declaration). Port of zenoh `handle_namespace_egress`
    /// (`net/routing/namespace.rs:48-52`).
    pub fn prepend(&self, suffix: &str) -> String {
        if suffix.is_empty() {
            self.0.clone()
        } else {
            let mut out = String::with_capacity(self.0.len() + 1 + suffix.len());
            out.push_str(&self.0);
            out.push('/');
            out.push_str(suffix);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonwild_rejects_empty_and_wild() {
        assert_eq!(NonWildKeyExpr::new(""), Err(NonWildError::Empty));
        assert_eq!(NonWildKeyExpr::new("a/*"), Err(NonWildError::Wild));
        assert_eq!(NonWildKeyExpr::new("a/**"), Err(NonWildError::Wild));
        assert_eq!(NonWildKeyExpr::new("a/b$*"), Err(NonWildError::Wild));
        assert_eq!(
            NonWildKeyExpr::new("a/b/c").map(|n| n.as_str()),
            Ok("a/b/c")
        );
        // `@` is NOT a wildcard — a verbatim prefix is a valid non-wild prefix.
        assert_eq!(
            NonWildKeyExpr::new("@demo/x").map(|n| n.as_str()),
            Ok("@demo/x")
        );
    }

    /// The non-`@` subset of zenoh's `test_keyexpr_strip_nonwild_prefix`
    /// (`commons/zenoh-keyexpr/src/key_expr/borrowed.rs:1000`) — these MUST match
    /// zenoh byte-for-byte (the faithfulness oracle).
    #[test]
    fn strip_matches_zenoh_oracle_nonverbatim() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("demo/example/test/**", "demo/example/test", Some("**")),
            ("demo/example/**", "demo/example/test", Some("**")),
            ("**", "demo/example/test", Some("**")),
            ("*/example/test/1", "demo/example/test", Some("1")),
            ("demo/*/test/1", "demo/example/test", Some("1")),
            ("*/*/test/1", "demo/example/test", Some("1")),
            ("*/*/*/1", "demo/example/test", Some("1")),
            ("*/test/1", "demo/example/test", None),
            ("*/*/1", "demo/example/test", None),
            ("*/*/**", "demo/example/test", Some("**")),
            (
                "demo/example/test/**/x$*/**",
                "demo/example/test",
                Some("**/x$*/**"),
            ),
            ("demo/**/xyz", "demo/example/test", Some("**/xyz")),
            ("demo/**/test/**", "demo/example/test", Some("**/test/**")),
            (
                "demo/**/ex$*/*/xyz",
                "demo/example/test",
                Some("**/ex$*/*/xyz"),
            ),
            (
                "demo/**/ex$*/t$*/xyz",
                "demo/example/test",
                Some("**/ex$*/t$*/xyz"),
            ),
            (
                "demo/**/te$*/*/xyz",
                "demo/example/test",
                Some("**/te$*/*/xyz"),
            ),
            ("demo/example/test", "demo/example/test", None),
            ("demo/example/test1/something", "demo/example/test", None),
            (
                "demo/example/test$*/something",
                "demo/example/test",
                Some("something"),
            ),
        ];
        for &(target, prefix, expected) in cases {
            let nw = NonWildKeyExpr::new(prefix).unwrap();
            assert_eq!(
                strip_nonwild_prefix(target, nw),
                expected,
                "strip({target:?}, {prefix:?})"
            );
        }
    }

    /// Concrete (wildcard-free) targets — the storage strip-prefix domain. The
    /// chunk-walk core must give the same chunk-boundary answers the literal
    /// storage strip did.
    #[test]
    fn strip_concrete_targets_chunk_boundary() {
        let nw = NonWildKeyExpr::new("home").unwrap();
        // chunk-boundary: `home2/x` is NOT under `home`.
        assert_eq!(strip_nonwild_prefix("home2/x", nw), None);
        assert_eq!(strip_nonwild_prefix("away/x", nw), None);
        assert_eq!(strip_nonwild_prefix("home/x", nw), Some("x"));
        let nw2 = NonWildKeyExpr::new("home/kitchen").unwrap();
        assert_eq!(strip_nonwild_prefix("home/kitchen/temp", nw2), Some("temp"));
        // exact equality -> None (cannot strip to an empty keyexpr).
        assert_eq!(strip_nonwild_prefix("home/kitchen", nw2), None);
    }

    /// @-blind divergence from zenoh: wz treats `@` as ordinary, so a `*`/`**`
    /// chunk DOES cross a `@verbatim` chunk (zenoh returns `None` for these).
    /// Documents the deliberate stack-wide @-blind choice (see module docs).
    #[test]
    fn strip_at_is_treated_as_ordinary() {
        // zenoh: None (verbatim `@demo` not matchable by `*`). wz @-blind: matches.
        let nw = NonWildKeyExpr::new("@demo/example/test").unwrap();
        assert_eq!(
            strip_nonwild_prefix("*/example/test/something", nw),
            Some("something")
        );
        // A literal `@` prefix still strips literally (this agrees with zenoh).
        assert_eq!(
            strip_nonwild_prefix("@demo/x", NonWildKeyExpr::new("@demo").unwrap()),
            Some("x")
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_prepend_and_validate() {
        let ns = OwnedNonWildKeyExpr::new("myns/sub").unwrap();
        assert_eq!(ns.prepend("foo/bar"), "myns/sub/foo/bar");
        // empty suffix -> the namespace-only declaration.
        assert_eq!(ns.prepend(""), "myns/sub");
        assert_eq!(ns.as_nonwild().as_str(), "myns/sub");
        assert_eq!(OwnedNonWildKeyExpr::new("a/*"), Err(NonWildError::Wild));
    }

    /// prepend then strip round-trips for non-wild and wild suffixes (the
    /// egress->ingress symmetry the namespace decorator relies on).
    #[cfg(feature = "alloc")]
    #[test]
    fn prepend_strip_roundtrip() {
        let ns = OwnedNonWildKeyExpr::new("myns").unwrap();
        for suffix in ["foo/bar", "**", "a/*/c", "x$*/y"] {
            let wire = ns.prepend(suffix);
            assert_eq!(
                strip_nonwild_prefix(&wire, ns.as_nonwild()),
                Some(suffix),
                "roundtrip {suffix:?}"
            );
        }
    }
}
