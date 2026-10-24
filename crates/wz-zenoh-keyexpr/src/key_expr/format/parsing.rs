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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.1, file
// src/key_expr/format/parsing.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! Parsing a key expression with a format: which part of the key expression each spec takes.
//!
//! The search order IS the behaviour here, because a format may parse a key expression in several
//! ways and which one a caller gets is the one this order finds first. It is the documented one:
//! specs are greedy and evaluated left to right, so the leftmost spec takes as much as it can while
//! the rest can still be parsed, `**` in the key expression may be taken by one spec and still be
//! available to the next, and a spec whose pattern is `**` may take nothing.

use alloc::vec::Vec;

use zenoh_result::{bail, ZResult};

use super::{IKeFormatStorage, KeFormat, Segment};
use crate::key_expr::keyexpr;

/// The result of parsing a key expression with a [`KeFormat`]: the part each spec took.
pub struct Parsed<'s, Storage: IKeFormatStorage<'s>> {
    format: &'s KeFormat<'s, Storage>,
    results: Storage::ValuesStorage<Option<&'s keyexpr>>,
}

impl<'s, Storage: IKeFormatStorage<'s>> core::fmt::Debug for Parsed<'s, Storage> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parsed")
            .field("format", &self.format)
            .field("results_len", &self.results.as_ref().len())
            .finish()
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> Parsed<'s, Storage> {
    /// Access the `id` element.
    ///
    /// The returned string is guaranteed to either be an empty string or a valid key expression.
    ///
    /// # Errors
    /// If `id` is not part of `self`'s specs.
    pub fn get(&self, id: &str) -> ZResult<&'s str> {
        let Some(i) = self
            .format
            .storage
            .segments()
            .iter()
            .position(|s| s.spec.id() == id)
        else {
            bail!("{} has no {id} field", self.format)
        };
        Ok(self.results.as_ref()[i].map_or("", keyexpr::as_str))
    }

    /// The raw values for each spec, in left-to-right order.
    pub fn values(&self) -> &[Option<&'s keyexpr>] {
        self.results.as_ref()
    }

    /// Iterates over id-value pairs.
    pub fn iter(&'s self) -> Iter<'s, Storage> {
        self.into_iter()
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> IntoIterator for &'s Parsed<'s, Storage> {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = Iter<'s, Storage>;
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            parsed: self,
            start: 0,
            end: self.format.storage.segments().len(),
        }
    }
}

/// An iterator over the id-value pairs of a [`Parsed`].
pub struct Iter<'s, Storage: IKeFormatStorage<'s>> {
    parsed: &'s Parsed<'s, Storage>,
    start: usize,
    end: usize,
}

impl<'s, Storage: IKeFormatStorage<'s>> core::fmt::Debug for Iter<'s, Storage> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Iter")
            .field("parsed", &"..")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> Iterator for Iter<'s, Storage> {
    type Item = (&'s str, Option<&'s keyexpr>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let id = self.parsed.format.storage.segments()[self.start].spec.id();
            let ke = self.parsed.results.as_ref()[self.start];
            self.start += 1;
            Some((id, ke))
        } else {
            None
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.start += n;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let result = self.end - self.start;
        (result, Some(result))
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> ExactSizeIterator for Iter<'s, Storage> {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> DoubleEndedIterator for Iter<'s, Storage> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            self.end -= 1;
            let id = self.parsed.format.storage.segments()[self.end].spec.id();
            let ke = self.parsed.results.as_ref()[self.end];
            Some((id, ke))
        } else {
            None
        }
    }
}

/// The ways to cut a key expression in two at a chunk boundary, left to right. A `**` chunk is in
/// BOTH halves of the cut that takes it: it may be consumed by what is on the left and is still
/// there for what is on the right, and the cut after it is the same cut. A cut with an empty half
/// is not one.
fn splits_ltr(ke: &keyexpr) -> Vec<(&keyexpr, &keyexpr)> {
    let text = ke.as_str();
    // `starts[b]` is the offset of chunk `b`, and `ends[b]` the offset just after it.
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut at = 0;
    for chunk in text.split('/') {
        starts.push(at);
        at += chunk.len();
        ends.push(at);
        at += 1;
    }
    let n = starts.len();
    let mut out = Vec::new();
    let mut b = 0;
    while b < n {
        let chunk = &text[starts[b]..ends[b]];
        if chunk == "**" {
            // SAFETY: a run of whole chunks of a key expression is a key expression.
            out.push(unsafe {
                (
                    keyexpr::from_str_unchecked(&text[..ends[b]]),
                    keyexpr::from_str_unchecked(&text[starts[b]..]),
                )
            });
            b += 2;
        } else {
            if b >= 1 {
                // SAFETY: as above.
                out.push(unsafe {
                    (
                        keyexpr::from_str_unchecked(&text[..ends[b - 1]]),
                        keyexpr::from_str_unchecked(&text[starts[b]..]),
                    )
                });
            }
            b += 1;
        }
    }
    out
}

/// The same cuts, right to left.
fn splits_rtl(ke: &keyexpr) -> Vec<(&keyexpr, &keyexpr)> {
    let mut cuts = splits_ltr(ke);
    cuts.reverse();
    cuts
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> KeFormat<'s, Storage> {
    /// Parses `target` according to `self`. The returned [`Parsed`] object can be used to extract the values of the fields in `self` from `target`.
    ///
    /// Parsing is greedy and done left-to-right. Please refer to [`KeFormat`]'s documentation for more details.
    ///
    /// # Errors
    /// If `target` does not intersect with `self`, an error is returned.
    pub fn parse(&'s self, target: &'s keyexpr) -> ZResult<Parsed<'s, Storage>> {
        let segments = self.storage.segments();
        if segments.is_empty() {
            // A format with no spec is a key expression, and what it parses is whether it meets
            // the target.
            // SAFETY: the suffix of a format with no spec is a key expression.
            let whole = unsafe { keyexpr::from_str_unchecked(self.suffix) };
            if !target.intersects(whole) {
                bail!("{target} does not intersect with {self}")
            }
            return Ok(Parsed {
                format: self,
                results: self.storage.values_storage(|_| None),
            });
        }
        let mut results = self.storage.values_storage(|_| None);
        let results_mut = results.as_mut();
        debug_assert_eq!(segments.len(), results_mut.len());
        let found = 'a: {
            match self.suffix.as_bytes() {
                [] => do_parse(Some(target), segments, results_mut),
                [b'/', suffix @ ..] => {
                    // SAFETY: what follows the slash of the suffix is a key expression.
                    let suffix = unsafe { keyexpr::from_slice_unchecked(suffix) };
                    for (target, candidate) in splits_rtl(target) {
                        if suffix.intersects(candidate)
                            && do_parse(Some(target), segments, results_mut)
                        {
                            break 'a true;
                        }
                    }
                    suffix.intersects(target) && do_parse(None, segments, results_mut)
                }
                // A suffix is empty or starts with a slash after a spec.
                _ => false,
            }
        };
        if found {
            Ok(Parsed {
                format: self,
                results,
            })
        } else {
            bail!("{target} does not intersect with {self}")
        }
    }
}

/// Assign `target` (`None` for nothing left) to `segments`, writing the parts into `results`.
/// Whether it could be done.
fn do_parse<'a>(
    target: Option<&'a keyexpr>,
    segments: &[Segment],
    results: &mut [Option<&'a keyexpr>],
) -> bool {
    match (segments, results) {
        // No spec left: what remains must be nothing, or a `**`, which may be taken as nothing.
        ([], []) => target.map_or(true, keyexpr::is_double_wild),
        ([segment, segments @ ..], [result, results @ ..]) => {
            let prefix = segment.prefix();
            let pattern = segment.pattern();
            // Nothing left of the target: this segment fits only if its pattern is `**` and its
            // prefix is empty (a prefix is never `**`), and so must every segment after it.
            let Some(target) = target else {
                if prefix.is_none() && pattern.is_double_wild() {
                    *result = None;
                    return !segments.iter().zip(results).any(|(segment, result)| {
                        *result = None;
                        segment.prefix().is_some() || !segment.pattern().is_double_wild()
                    });
                } else {
                    return false;
                }
            };
            // The spec takes a part of `target` (the whole of it, or a part cut from its right),
            // and the segments after it must parse what is left.
            macro_rules! try_intersect {
                ($target: expr) => {{
                    let target: &'a keyexpr = $target;
                    if pattern.intersects(target)
                        && do_parse(target.is_double_wild().then_some(target), segments, results)
                    {
                        *result = Some(target);
                        return true;
                    }
                    for (candidate, rest) in splits_rtl(target) {
                        if pattern.intersects(candidate) && do_parse(Some(rest), segments, results)
                        {
                            *result = Some(candidate);
                            return true;
                        }
                    }
                    if pattern.is_double_wild() && do_parse(Some(target), segments, results) {
                        *result = None;
                        return true;
                    }
                }};
            }
            // A prefix that can be compressed to nothing leaves the whole target to the spec.
            if prefix.is_none() {
                try_intersect!(target);
            }
            // The prefix takes a part cut from the left of `target`, as many cuts as it could
            // possibly consume.
            for (candidate, rest) in splits_ltr(target).into_iter().take(match prefix {
                None => 1,
                Some(prefix) => (prefix.bytes().filter(|&c| c == b'/').count() + 1) * 3,
            }) {
                if prefix.map_or(candidate.is_double_wild(), |prefix| {
                    prefix.intersects(candidate)
                }) {
                    try_intersect!(rest);
                }
            }
            pattern.is_double_wild()
                && prefix.is_some_and(|prefix| prefix.intersects(target))
                && do_parse(None, segments, results)
        }
        _ => false,
    }
}
