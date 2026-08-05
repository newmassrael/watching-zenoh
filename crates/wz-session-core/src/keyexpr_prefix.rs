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
//! @verbatim (`@`): IMPLEMENTED since R311y543, and this note used to say the
//! opposite.
//!
//! It said wz "does NOT implement @verbatim chunk semantics ANYWHERE", that this
//! port therefore omitted zenoh's two guards on purpose, and that full support
//! was "a re-openable stack-wide atom (canon + match + strip together), not a
//! namespace-local concern". That reasoning was sound and its conclusion — that
//! strip must not go @-aware while the matcher stayed @-blind — is why the two
//! moved in the SAME round rather than one of them alone.
//!
//! What re-opened it was a measurement rather than a review. Upstream's
//! `z_advanced_sub.c` on `demo/capic/**`, against a real zenoh-pico advanced
//! publisher, was handed zenoh's own `@adv/pub/<zid>/<eid>/_` beacon traffic
//! alongside its data, where the real `libzenohc.so` on the identical wire was
//! handed the data alone. A user subscription receiving the router's internal
//! namespace is not a stylistic difference, so
//! [`crate::keyexpr_match::is_verbatim_chunk`] landed there and both of zenoh's
//! guards landed here: `is_chunk_matching`'s verbatim-only-matches-verbatim rule
//! (`borrowed.rs:297-300`) and the `**`-must-not-cross-`@` stop-loop
//! (`borrowed.rs:350-384`).
//!
//! `keyexpr_canon` is unchanged and does not need to change: canonicity is a
//! grammar question and `@` is an ordinary byte to the grammar. The atom that
//! was carried was match + strip, and it is those two that closed.

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
/// (`borrowed.rs:293`), INCLUDING its `@`-verbatim guard since R311y543.
fn is_chunk_matching(target: &[u8], prefix: &[u8]) -> bool {
    // zenoh `borrowed.rs:297-300`: a verbatim chunk is matched only by a
    // verbatim chunk. The byte-equality of the two is then decided by the walk
    // below exactly as for any other pair, so `@demo` still strips `@demo`.
    if prefix.first() == Some(&b'@') && target.first() != Some(&b'@') {
        return false;
    }
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
/// (`borrowed.rs:331`), INCLUDING its `@`-verbatim branch since R311y543.
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
            // `**` — and the answer depends on whether the REMAINING PREFIX has
            // a verbatim chunk, which is zenoh `borrowed.rs:350-384`.
            let remaining = &prefix[pi..];
            let Some(mut p) = remaining.iter().position(|&c| c == b'@') else {
                // No `@` left to cross: `**` covers every remaining prefix chunk
                // and the suffix is `**` plus the rest of the target.
                return Some(&target[ti..]);
            };
            if te + 1 >= target.len() {
                // `**` is the LAST target chunk and it may not reach a verbatim
                // chunk, so there is nothing left to cover the prefix with.
                return None;
            }
            // Walk `p` backwards a chunk at a time, letting `**` absorb as many
            // NON-verbatim prefix chunks as it can before the verbatim one.
            loop {
                if let Some(tail) = strip_inner(&target[(te + 1)..], &remaining[p..]) {
                    return Some(tail);
                }
                if p == 0 {
                    return None;
                }
                p -= 2;
                while p > 0 && remaining[p - 1] != b'/' {
                    p -= 1;
                }
            }
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

    /// R311y543 — the @verbatim half, which was a DIVERGENCE until this round.
    ///
    /// This test used to be named `strip_at_is_treated_as_ordinary` and asserted
    /// the opposite of every case below, documenting wz's stack-wide @-blindness
    /// as deliberate. It stopped being defensible when the matcher went @-aware:
    /// a keyexpr stack where a sample strips one way and matches another is the
    /// internally-inconsistent state the module note said would be the worse
    /// choice, so the strip path moved with it.
    #[test]
    fn strip_refuses_to_cross_a_verbatim_chunk() {
        // A `*` does not match a verbatim chunk (zenoh `borrowed.rs:297-300`).
        let nw = NonWildKeyExpr::new("@demo/example/test").unwrap();
        assert_eq!(strip_nonwild_prefix("*/example/test/something", nw), None);
        // Nor does a `**`, whichever side of the verbatim chunk it starts on.
        assert_eq!(strip_nonwild_prefix("**", nw), None);
        assert_eq!(strip_nonwild_prefix("**/something", nw), None);
        // A literal `@` chunk still strips literally — the rule is "only a
        // verbatim chunk matches a verbatim chunk", not "verbatim never matches".
        assert_eq!(
            strip_nonwild_prefix("@demo/x", NonWildKeyExpr::new("@demo").unwrap()),
            Some("x")
        );
        // And a `**` still covers the NON-verbatim chunks that precede one: the
        // prefix `demo/@adv` is reached by absorbing `demo` and then matching
        // `@adv` byte for byte. Without this case the fix could be "refuse any
        // prefix containing @" and the assertions above would all still pass.
        assert_eq!(
            strip_nonwild_prefix("**/@adv/x", NonWildKeyExpr::new("demo/@adv").unwrap()),
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
