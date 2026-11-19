//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.2, file
// src/key_expr/borrowed.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

#[cfg(feature = "internal")]
use alloc::vec::Vec;
use alloc::{
    borrow::{Borrow, ToOwned},
    format,
    string::String,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
    ops::{Deref, Div},
};

use zenoh_result::{anyhow, bail, zerror, Error as ZError, ZResult};

use super::{canon::Canonize, OwnedKeyExpr, OwnedNonWildKeyExpr};

/// A [`str`] newtype that is statically known to be a valid key expression.
///
/// The exact key expression specification can be found [here](https://github.com/eclipse-zenoh/roadmap/blob/main/rfcs/ALL/Key%20Expressions.md). Here are the major lines:
/// * Key expressions are conceptually a `/`-separated list of UTF-8 string typed chunks. These chunks are not allowed to be empty.
/// * Key expressions must be valid UTF-8 strings.
///   Be aware that Zenoh does not perform UTF normalization for you, so get familiar with that concept if your key expression contains glyphs that may have several unicode representation, such as accented characters.
/// * Key expressions may never start or end with `'/'`, nor contain `"//"` or any of the following characters: `#$?`
/// * Key expression must be in canon-form (this ensure that key expressions representing the same set are always the same string).
///   Note that safe constructors will perform canonization for you if this can be done without extraneous allocations.
///
/// Since Key Expressions define sets of keys, you may want to be aware of the hierarchy of relations between such sets:
/// * Trivially, two sets can have no elements in common: `a/**` and `b/**` for example define two disjoint sets of keys.
/// * Two sets [intersect](keyexpr::intersects()) if they have at least one element in common. `a/*` intersects `*/a` on `a/a` for example.
/// * One set A [includes](keyexpr::includes()) the other set B if all of B's elements are in A: `a/*/**` includes `a/b/**`
/// * Two sets A and B are equal if all A includes B and B includes A. The Key Expression language is designed so that string equality is equivalent to set equality.
#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct keyexpr(str);

impl keyexpr {
    /// Equivalent to `<&keyexpr as TryFrom>::try_from(t)`.
    ///
    /// Will return an Err if `t` isn't a valid key expression.
    /// Note that to be considered a valid key expression, a string MUST be canon.
    ///
    /// [`keyexpr::autocanonize`] is an alternative constructor that will canonize the passed expression before constructing it.
    pub fn new<'a, T, E>(t: &'a T) -> Result<&'a Self, E>
    where
        &'a Self: TryFrom<&'a T, Error = E>,
        T: ?Sized,
    {
        t.try_into()
    }

    /// Canonizes the passed value before returning it as a `&keyexpr`.
    ///
    /// Will return Err if the passed value isn't a valid key expression despite canonization.
    ///
    /// Note that this function does not allocate, and will instead mutate the passed value in place during canonization.
    pub fn autocanonize<'a, T, E>(t: &'a mut T) -> Result<&'a Self, E>
    where
        &'a Self: TryFrom<&'a T, Error = E>,
        T: Canonize + ?Sized,
    {
        t.canonize();
        Self::new(t)
    }

    /// Returns `true` if the `keyexpr`s intersect, i.e. there exists at least one key which is contained in both of the sets defined by `self` and `other`.
    pub fn intersects(&self, other: &Self) -> bool {
        wz_session_core::keyexpr_match::keyexpr_intersects(self.as_str(), other.as_str())
    }

    /// Returns `true` if `self` includes `other`, i.e. the set defined by `self` contains every key belonging to the set defined by `other`.
    pub fn includes(&self, other: &Self) -> bool {
        wz_session_core::keyexpr_match::keyexpr_includes(self.as_str(), other.as_str())
    }

    /// Returns the relation between `self` and `other` from `self`'s point of view ([`SetIntersectionLevel::Includes`] signifies that `self` includes `other`).
    ///
    /// Note that this is slower than [`keyexpr::intersects`] and [`keyexpr::includes`], so you should favor these methods for most applications.
    #[cfg(feature = "unstable")]
    pub fn relation_to(&self, other: &Self) -> SetIntersectionLevel {
        use SetIntersectionLevel::*;
        if self.intersects(other) {
            if self == other {
                Equals
            } else if self.includes(other) {
                Includes
            } else {
                Intersects
            }
        } else {
            Disjoint
        }
    }

    /// Joins both sides, inserting a `/` in between them.
    ///
    /// This should be your preferred method when concatenating path segments.
    ///
    /// This is notably useful for workspaces:
    /// ```rust
    /// # use core::convert::TryFrom;
    /// # use zenoh_keyexpr::OwnedKeyExpr;
    /// # let get_workspace = || OwnedKeyExpr::try_from("some/workspace").unwrap();
    /// let workspace: OwnedKeyExpr = get_workspace();
    /// let topic = workspace.join("some/topic").unwrap();
    /// ```
    ///
    /// If `other` is of type `&keyexpr`, you may use `self / other` instead, as the joining becomes infallible.
    pub fn join<S: AsRef<str> + ?Sized>(&self, other: &S) -> ZResult<OwnedKeyExpr> {
        OwnedKeyExpr::autocanonize(format!("{}/{}", self, other.as_ref()))
    }

    /// Whether `self` contains a wildcard character (`*`).
    pub(crate) fn is_wild_impl(&self) -> bool {
        self.0.contains(super::SINGLE_WILD as char)
    }

    /// Whether `self` is exactly `**`.
    pub(crate) const fn is_double_wild(&self) -> bool {
        let bytes = self.0.as_bytes();
        bytes.len() == 2 && bytes[0] == b'*'
    }

    /// Returns `true` if `self` contains any wildcard character (`**` or `$*`).
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub fn is_wild(&self) -> bool {
        self.is_wild_impl()
    }

    /// The chunks of the key expression.
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub const fn chunks(&self) -> Chunks<'_> {
        self.chunks_impl()
    }

    /// Returns the longest prefix of `self` that doesn't contain any wildcard character (`**` or `$*`).
    ///
    /// NOTE: this operation can typically be used in a backend implementation, at creation of a Storage to get the keys prefix,
    /// and then in `zenoh_backend_traits::Storage::on_sample()` this prefix has to be stripped from all received
    /// `Sample::key_expr` to retrieve the corresponding key.
    ///
    /// # Examples:
    /// ```
    /// # use zenoh_keyexpr::keyexpr;
    /// assert_eq!(
    ///     Some(keyexpr::new("demo/example").unwrap()),
    ///     keyexpr::new("demo/example/**").unwrap().get_nonwild_prefix());
    /// assert_eq!(
    ///     Some(keyexpr::new("demo").unwrap()),
    ///     keyexpr::new("demo/**/test/**").unwrap().get_nonwild_prefix());
    /// assert_eq!(
    ///     Some(keyexpr::new("demo/example/test").unwrap()),
    ///     keyexpr::new("demo/example/test").unwrap().get_nonwild_prefix());
    /// assert_eq!(
    ///     Some(keyexpr::new("demo").unwrap()),
    ///     keyexpr::new("demo/ex$*/**").unwrap().get_nonwild_prefix());
    /// assert_eq!(
    ///     None,
    ///     keyexpr::new("**").unwrap().get_nonwild_prefix());
    /// assert_eq!(
    ///     None,
    ///     keyexpr::new("dem$*").unwrap().get_nonwild_prefix());
    /// ```
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub fn get_nonwild_prefix(&self) -> Option<&keyexpr> {
        match self.0.find('*') {
            Some(i) => match self.0[..i].rfind('/') {
                // SAFETY: upheld by the surrounding invariants and prior validation.
                Some(j) => unsafe { Some(keyexpr::from_str_unchecked(&self.0[..j])) },
                None => None, // wildcard in the first segment => no invariant prefix
            },
            None => Some(self), // no wildcard => return self
        }
    }

    /// Remove the specified `prefix` from `self`.
    /// The result is a list of `keyexpr`, since there might be several ways for the prefix to match the beginning of the `self` key expression.
    /// For instance, if `self` is `"a/**/c/*" and `prefix` is `a/b/c` then:
    ///   - the `prefix` matches `"a/**/c"` leading to a result of `"*"` when stripped from `self`
    ///   - the `prefix` matches `"a/**"` leading to a result of `"**/c/*"` when stripped from `self`
    ///
    /// So the result is `["*", "**/c/*"]`.
    /// If `prefix` cannot match the beginning of `self`, an empty list is reuturned.
    ///
    /// See below more examples.
    ///
    /// NOTE: this operation can typically used in a backend implementation, within the `zenoh_backend_traits::Storage::on_query()` implementation,
    /// to transform the received `Query::selector()`'s `key_expr` into a list of key selectors
    /// that will match all the relevant stored keys (that correspond to keys stripped from the prefix).
    ///
    /// # Examples:
    /// ```
    /// # use zenoh_keyexpr::keyexpr;
    /// assert_eq!(
    ///     ["abc"],
    ///     keyexpr::new("demo/example/test/abc").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["**"],
    ///     keyexpr::new("demo/example/test/**").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["**"],
    ///     keyexpr::new("demo/example/**").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["**"],
    ///     keyexpr::new("**").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["**/xyz"],
    ///     keyexpr::new("demo/**/xyz").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["**"],
    ///     keyexpr::new("demo/**/test/**").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["xyz", "**/ex$*/*/xyz"],
    ///     keyexpr::new("demo/**/ex$*/*/xyz").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert_eq!(
    ///     ["*", "**/test/*"],
    ///     keyexpr::new("demo/**/test/*").unwrap().strip_prefix(keyexpr::new("demo/example/test").unwrap()).as_slice()
    /// );
    /// assert!(
    ///     keyexpr::new("demo/example/test/**").unwrap().strip_prefix(keyexpr::new("not/a/prefix").unwrap()).is_empty()
    /// );
    /// ```
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub fn strip_prefix(&self, prefix: &Self) -> Vec<&keyexpr> {
        // The cuts of `self` are tried from the longest to the shortest, and the list is kept free
        // of a remainder another one includes. That order and `swap_remove` decide the order of the
        // list, which a caller that matches on its slice sees, so both are upstream's.
        let text = self.as_str();
        let mut result: Vec<&keyexpr> = Vec::new();
        'cuts: for i in (0..=text.len()).rev() {
            let at_a_cut = if i == text.len() {
                text.ends_with("**")
            } else {
                text.as_bytes()[i] == b'/'
            };
            if !at_a_cut {
                continue;
            }
            // SAFETY: `i` is the end of `self` or the place of a `/`, never 0 (a key expression
            // does not start with `/`), so the head is a non-empty run of whole chunks of a canon
            // key expression; every rule of the language holds within a chunk or between two
            // neighbouring chunks, so such a run is a canon key expression.
            let head = unsafe { keyexpr::from_str_unchecked(&text[..i]) };
            if !head.intersects(prefix) {
                continue;
            }
            // A head that ends with `**` may have matched the prefix with fewer chunks than it has,
            // so that `**` stays with the remainder.
            let rest = if head.as_str().ends_with("**") {
                &text[i - 2..]
            } else {
                &text[i + 1..]
            };
            // SAFETY: `rest` starts at a chunk (after a `/`, or at the `**` chunk that ends the
            // head) and runs to the end, so it is a non-empty run of whole chunks, which is a canon
            // key expression for the reason above.
            let rest = unsafe { keyexpr::from_str_unchecked(rest) };
            // `**` includes every remainder: it is the whole answer.
            if rest.as_str() == "**" {
                result.clear();
                result.push(rest);
                return result;
            }
            for j in (0..result.len()).rev() {
                if result[j].includes(rest) {
                    continue 'cuts;
                }
                if rest.includes(result[j]) {
                    result.swap_remove(j);
                }
            }
            result.push(rest);
        }
        result
    }

    /// Remove the specified namespace `prefix` from `self`.
    ///
    /// This method works essentially like [`keyexpr::strip_prefix()`], but returns only the longest possible suffix.
    /// Prefix can not contain '*' character.
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub fn strip_nonwild_prefix(&self, prefix: &nonwild_keyexpr) -> Option<&keyexpr> {
        /// Whether the chunk `target`, which may hold wildcards, matches the verbatim chunk
        /// `prefix`.
        fn is_chunk_matching(target: &[u8], prefix: &[u8]) -> bool {
            let mut target_idx: usize = 0;
            let mut prefix_idx: usize = 0;
            let mut target_prev: u8 = b'/';
            if prefix.first() == Some(&b'@') && target.first() != Some(&b'@') {
                // verbatim chunk can only be matched by verbatim chunk
                return false;
            }

            while target_idx < target.len() && prefix_idx < prefix.len() {
                if target[target_idx] == b'*' {
                    if target_prev == b'*' || target_idx + 1 == target.len() {
                        // either a ** wild chunk or a single * chunk at the end of the string - this matches anything
                        return true;
                    } else if target_prev == b'$' {
                        for i in prefix_idx..prefix.len() - 1 {
                            if is_chunk_matching(&target[target_idx + 1..], &prefix[i..]) {
                                return true;
                            }
                        }
                    }
                } else if target[target_idx] == prefix[prefix_idx] {
                    prefix_idx += 1;
                } else if target[target_idx] != b'$' {
                    // non-special character, which do not match the one in prefix
                    return false;
                }
                target_prev = target[target_idx];
                target_idx += 1;
            }
            if prefix_idx != prefix.len() {
                // prefix was not matched entirely
                return false;
            }
            target_idx == target.len()
                || (target_idx + 2 == target.len() && target[target_idx] == b'$')
        }

        /// The suffix of `target_bytes` left once `prefix_bytes` is matched from its start, chunk
        /// by chunk, or `None` when it does not match.
        fn strip_nonwild_prefix_inner<'a>(
            target_bytes: &'a [u8],
            prefix_bytes: &[u8],
        ) -> Option<&'a keyexpr> {
            let mut target_idx = 0;
            let mut prefix_idx = 0;

            while target_idx < target_bytes.len() && prefix_idx < prefix_bytes.len() {
                let target_end = target_idx
                    + target_bytes[target_idx..]
                        .iter()
                        .position(|&i| i == b'/')
                        .unwrap_or(target_bytes.len() - target_idx);
                let prefix_end = prefix_idx
                    + prefix_bytes[prefix_idx..]
                        .iter()
                        .position(|&i| i == b'/')
                        .unwrap_or(prefix_bytes.len() - prefix_idx);
                let target_chunk = &target_bytes[target_idx..target_end];
                if target_chunk.len() == 2 && target_chunk[0] == b'*' {
                    let remaining_prefix = &prefix_bytes[prefix_idx..];
                    return match remaining_prefix.iter().position(|&x| x == b'@') {
                        Some(mut p) => {
                            if target_end + 1 >= target_bytes.len() {
                                // "**" is the last chunk, and it is not allowed to match @verbatim chunks, so we stop here
                                None
                            } else {
                                loop {
                                    // try to use "**" to match as many non-verbatim chunks as possible
                                    if let Some(ke) = strip_nonwild_prefix_inner(
                                        &target_bytes[(target_end + 1)..],
                                        &remaining_prefix[p..],
                                    ) {
                                        return Some(ke);
                                    } else if p == 0 {
                                        // "**" is not allowed to match @verbatim chunks
                                        return None;
                                    } else {
                                        // search for the beginning of the next chunk from the end.
                                        // The search above finds any `@`, and one that is the second
                                        // byte of the first chunk leaves no chunk to back off to: the
                                        // `**` then takes none of the prefix, where upstream's
                                        // `p -= 2` overflows (a panic in a build that checks, an
                                        // out-of-bounds index in one that wraps).
                                        p = p.saturating_sub(2);
                                        while p > 0 && remaining_prefix[p - 1] != b'/' {
                                            p -= 1;
                                        }
                                    }
                                }
                            }
                        }
                        // SAFETY: `target_idx` is the start of a chunk of a key expression, so
                        // what follows it is a non-empty run of whole chunks, a key expression.
                        None => unsafe {
                            // "**" can match all remaining non-verbatim chunks
                            Some(keyexpr::from_str_unchecked(core::str::from_utf8_unchecked(
                                &target_bytes[target_idx..],
                            )))
                        },
                    };
                }
                if target_end == target_bytes.len() {
                    // target contains no more chunks than prefix and the last one is non double-wild - so it can not match
                    return None;
                }
                let prefix_chunk = &prefix_bytes[prefix_idx..prefix_end];
                if !is_chunk_matching(target_chunk, prefix_chunk) {
                    return None;
                }
                if prefix_end == prefix_bytes.len() {
                    // SAFETY: `target_end` is the place of a `/` (the end of the target was
                    // refused above), so what follows it is a non-empty run of whole chunks of a
                    // key expression, a key expression.
                    return unsafe {
                        Some(keyexpr::from_str_unchecked(core::str::from_utf8_unchecked(
                            &target_bytes[(target_end + 1)..],
                        )))
                    };
                }
                target_idx = target_end + 1;
                prefix_idx = prefix_end + 1;
            }
            None
        }

        strip_nonwild_prefix_inner(self.as_str().as_bytes(), prefix.as_str().as_bytes())
    }

    /// The chunks of the key expression.
    pub(crate) const fn chunks_impl(&self) -> Chunks<'_> {
        Chunks {
            inner: self.as_str(),
        }
    }

    /// The key expression as a `&str`.
    pub const fn as_str(&self) -> &str {
        &self.0
    }

    /// Constructs a `&keyexpr` without checking it.
    ///
    /// # Safety
    /// `s` must be a valid, canon key expression.
    pub const unsafe fn from_str_unchecked(s: &str) -> &Self {
        // SAFETY: `keyexpr` is `repr(transparent)` over `str`.
        unsafe { core::mem::transmute(s) }
    }

    /// Constructs a `&keyexpr` from bytes without checking them.
    ///
    /// # Safety
    /// `s` must be the UTF-8 bytes of a valid, canon key expression.
    pub unsafe fn from_slice_unchecked(s: &[u8]) -> &Self {
        // SAFETY: `keyexpr` is `repr(transparent)` over `str`, and the caller guarantees the bytes.
        unsafe { core::mem::transmute(s) }
    }
}

/// An iterator over the chunks of a key expression, each as a `&keyexpr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Chunks<'a> {
    inner: &'a str,
}

impl<'a> Chunks<'a> {
    /// The chunks that remain, as one key expression, or `None` when none remain.
    pub const fn as_keyexpr(self) -> Option<&'a keyexpr> {
        match self.inner.is_empty() {
            true => None,
            // SAFETY: what remains of a key expression, from a chunk boundary, is a key expression.
            _ => Some(unsafe { keyexpr::from_str_unchecked(self.inner) }),
        }
    }

    /// The next chunk, without consuming it.
    pub fn peek(&self) -> Option<&keyexpr> {
        if self.inner.is_empty() {
            None
        } else {
            let end = self.inner.find('/').unwrap_or(self.inner.len());
            // SAFETY: a chunk of a key expression is a key expression.
            Some(unsafe { keyexpr::from_str_unchecked(&self.inner[..end]) })
        }
    }

    /// The last chunk, without consuming it.
    pub fn peek_back(&self) -> Option<&keyexpr> {
        if self.inner.is_empty() {
            None
        } else {
            let start = self.inner.rfind('/').map_or(0, |i| i + 1);
            // SAFETY: a chunk of a key expression is a key expression.
            Some(unsafe { keyexpr::from_str_unchecked(&self.inner[start..]) })
        }
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a keyexpr;
    fn next(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            return None;
        }
        let (next, rest) = self.inner.split_once('/').unwrap_or((self.inner, ""));
        self.inner = rest;
        // SAFETY: a chunk of a key expression is a key expression.
        Some(unsafe { keyexpr::from_str_unchecked(next) })
    }
}

impl DoubleEndedIterator for Chunks<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            return None;
        }
        let (rest, next) = self.inner.rsplit_once('/').unwrap_or(("", self.inner));
        self.inner = rest;
        // SAFETY: a chunk of a key expression is a key expression.
        Some(unsafe { keyexpr::from_str_unchecked(next) })
    }
}

impl Div for &keyexpr {
    type Output = OwnedKeyExpr;
    fn div(self, rhs: Self) -> Self::Output {
        self.join(rhs).unwrap() // Joining 2 key expressions should always result in a canonizable string.
    }
}

/// The relation between two sets of keys, from the first one's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(feature = "unstable")]
pub enum SetIntersectionLevel {
    /// No key is in both sets.
    Disjoint,
    /// Some key is in both sets, and neither includes the other.
    Intersects,
    /// The first set includes the second.
    Includes,
    /// The sets are equal.
    Equals,
}

impl fmt::Debug for keyexpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ke`{}`", self.as_ref())
    }
}

impl fmt::Display for keyexpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

/// What makes a string not a key expression. The discriminant is the error number of the error raised.
#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyExprError {
    LoneDollarStar = -1,
    SingleStarAfterDoubleStar = -2,
    DoubleStarAfterDoubleStar = -3,
    EmptyChunk = -4,
    StarInChunk = -5,
    DollarAfterDollar = -6,
    SharpOrQMark = -7,
    UnboundDollar = -8,
}

impl KeyExprError {
    #[cold]
    fn into_err(self, s: &str) -> ZError {
        let error = match &self {
            Self::LoneDollarStar => anyhow!("Invalid Key Expr `{s}`: empty chunks are forbidden, as well as leading and trailing slashes"),
            Self::SingleStarAfterDoubleStar => anyhow!("Invalid Key Expr `{s}`: `**/*` must be replaced by `*/**` to reach canon-form"),
            Self::DoubleStarAfterDoubleStar => anyhow!("Invalid Key Expr `{s}`: `**/**` must be replaced by `**` to reach canon-form"),
            Self::EmptyChunk => anyhow!("Invalid Key Expr `{s}`: empty chunks are forbidden, as well as leading and trailing slashes"),
            Self::StarInChunk => anyhow!("Invalid Key Expr `{s}`: `*` may only be preceded by `/` or `$`"),
            Self::DollarAfterDollar => anyhow!("Invalid Key Expr `{s}`: `$` is not allowed after `$*`"),
            Self::SharpOrQMark => anyhow!("Invalid Key Expr `{s}`: `#` and `?` are forbidden characters"),
            Self::UnboundDollar => anyhow!("Invalid Key Expr `{s}`: `$` is only allowed in `$*`")
        };
        zerror!((self) error).into()
    }
}

/// The fault of `value` as a key expression, if it has one. The chunks are examined in order and the
/// first fault is the one reported, with the faults of one chunk examined left to right.
pub(crate) fn check(value: &str) -> Result<(), KeyExprError> {
    use KeyExprError::*;
    // Neither an empty string nor a trailing slash is seen by the walk over the chunks.
    if value.is_empty() || value.ends_with('/') {
        return Err(EmptyChunk);
    }
    let bytes = value.as_bytes();
    let mut start = 0;
    loop {
        let end = bytes[start..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(bytes.len(), |p| start + p);
        check_chunk(bytes, start, end)?;
        if end == bytes.len() {
            return Ok(());
        }
        start = end + 1;
    }
}

/// The fault of the chunk `bytes[start..end]`, if any. `bytes` is the whole key expression, because
/// the chunk after a `**` decides which fault a `**/*` is.
fn check_chunk(bytes: &[u8], start: usize, end: usize) -> Result<(), KeyExprError> {
    use KeyExprError::*;
    let chunk = &bytes[start..end];
    if chunk.is_empty() {
        return Err(EmptyChunk);
    }
    if chunk[0] == b'*' {
        return match chunk {
            b"*" => Ok(()),
            b"**" if bytes.get(end) == Some(&b'/') && bytes.get(end + 1) == Some(&b'*') => {
                // A `**` chunk followed by a wildcard chunk. Which fault depends on what that next
                // chunk is, read from the two bytes after its first.
                Err(match (bytes.get(start + 4), bytes.get(start + 5)) {
                    (None | Some(&b'/'), _) => SingleStarAfterDoubleStar,
                    (Some(&b'*'), None | Some(&b'/')) => DoubleStarAfterDoubleStar,
                    _ => StarInChunk,
                })
            }
            b"**" => Ok(()),
            _ => Err(StarInChunk),
        };
    }
    let mut i = 0;
    while i < chunk.len() {
        match chunk[i] {
            // A `*` that does not open the chunk.
            b'*' => return Err(StarInChunk),
            b'$' => {
                if chunk.get(i + 1) != Some(&b'*') {
                    return Err(UnboundDollar);
                }
                match chunk.get(i + 2) {
                    Some(&b'$') => return Err(DollarAfterDollar),
                    // A chunk that is only `$*`.
                    None if i == 0 => return Err(LoneDollarStar),
                    _ => i += 2,
                }
            }
            b'#' | b'?' => return Err(SharpOrQMark),
            _ => i += 1,
        }
    }
    Ok(())
}

impl<'a> TryFrom<&'a str> for &'a keyexpr {
    type Error = ZError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        check(value).map_err(|e| e.into_err(value))?;
        // SAFETY: the string was just checked.
        Ok(unsafe { keyexpr::from_str_unchecked(value) })
    }
}

impl<'a> TryFrom<&'a mut str> for &'a keyexpr {
    type Error = ZError;
    fn try_from(value: &'a mut str) -> Result<Self, Self::Error> {
        (value as &'a str).try_into()
    }
}

impl<'a> TryFrom<&'a mut String> for &'a keyexpr {
    type Error = ZError;
    fn try_from(value: &'a mut String) -> Result<Self, Self::Error> {
        (value.as_str()).try_into()
    }
}

impl<'a> TryFrom<&'a String> for &'a keyexpr {
    type Error = ZError;
    fn try_from(value: &'a String) -> Result<Self, Self::Error> {
        (value.as_str()).try_into()
    }
}

impl<'a> TryFrom<&'a &'a str> for &'a keyexpr {
    type Error = ZError;
    fn try_from(value: &'a &'a str) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl<'a> TryFrom<&'a &'a mut str> for &'a keyexpr {
    type Error = ZError;
    fn try_from(value: &'a &'a mut str) -> Result<Self, Self::Error> {
        keyexpr::new(*value)
    }
}

impl Deref for keyexpr {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for keyexpr {
    fn as_ref(&self) -> &str {
        self
    }
}

impl PartialEq<str> for keyexpr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<keyexpr> for str {
    fn eq(&self, other: &keyexpr) -> bool {
        self == other.as_str()
    }
}

impl Borrow<keyexpr> for OwnedKeyExpr {
    fn borrow(&self) -> &keyexpr {
        self
    }
}

impl ToOwned for keyexpr {
    type Owned = OwnedKeyExpr;
    fn to_owned(&self) -> Self::Owned {
        OwnedKeyExpr::from(self)
    }
}

/// A [`keyexpr`] that holds no wildcard chunk.
#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct nonwild_keyexpr(keyexpr);

impl nonwild_keyexpr {
    /// Equivalent to `<&nonwild_keyexpr as TryFrom>::try_from(t)`.
    ///
    /// Will return an Err if `t` isn't a valid key expression, or has a wildcard.
    pub fn new<'a, T, E>(t: &'a T) -> Result<&'a Self, ZError>
    where
        &'a keyexpr: TryFrom<&'a T, Error = E>,
        E: Into<ZError>,
        T: ?Sized,
    {
        let ke: &'a keyexpr = t.try_into().map_err(|e: E| e.into())?;
        ke.try_into()
    }

    /// Constructs a `&nonwild_keyexpr` without checking it.
    ///
    /// # Safety
    /// `s` must be a valid, canon key expression with no wildcard.
    pub const unsafe fn from_str_unchecked(s: &str) -> &Self {
        // SAFETY: `nonwild_keyexpr` is `repr(transparent)` over `keyexpr`, over `str`.
        unsafe { core::mem::transmute(s) }
    }
}

impl Deref for nonwild_keyexpr {
    type Target = keyexpr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> TryFrom<&'a keyexpr> for &'a nonwild_keyexpr {
    type Error = ZError;
    fn try_from(value: &'a keyexpr) -> Result<Self, Self::Error> {
        if value.is_wild_impl() {
            bail!("nonwild_keyexpr can not contain any wild chunks")
        }
        // SAFETY: the key expression holds no `*`, and the type is a transparent wrapper.
        Ok(unsafe { core::mem::transmute::<&keyexpr, &nonwild_keyexpr>(value) })
    }
}

impl Borrow<nonwild_keyexpr> for OwnedNonWildKeyExpr {
    fn borrow(&self) -> &nonwild_keyexpr {
        self
    }
}

impl ToOwned for nonwild_keyexpr {
    type Owned = OwnedNonWildKeyExpr;
    fn to_owned(&self) -> Self::Owned {
        OwnedNonWildKeyExpr::from(self)
    }
}
