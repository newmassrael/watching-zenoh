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
// src/key_expr/format/support.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! The pieces a format is made of: its specs, its segments, and the storages that hold the segments.

use alloc::{boxed::Box, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    mem::MaybeUninit,
};

use zenoh_result::{bail, zerror, Error};

use crate::key_expr::keyexpr;

/// One specification of a format, `id:pattern` or `id:pattern#default`, as the text between the
/// braces and the offsets of its parts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Spec<'a> {
    pub(crate) spec: &'a str,
    /// The offset of the `:` that ends the id.
    pub(crate) id_end: u16,
    /// The offset of the `#` that ends the pattern, or `u16::MAX` when there is no default.
    pub(crate) pattern_end: u16,
}

impl<'a> TryFrom<&'a str> for Spec<'a> {
    type Error = Error;
    fn try_from(spec: &'a str) -> Result<Self, Self::Error> {
        let Some(id_end) = spec.find(':') else {
            bail!("Spec {spec} didn't contain `:`")
        };
        let pattern_start = id_end + 1;
        // The offset of the `#` in the whole spec, the same measure as `id_end`, which is what
        // `pattern` and `default` slice by.
        let pattern_end = spec[pattern_start..]
            .find('#')
            .map_or(u16::MAX as usize, |at| pattern_start + at);
        if pattern_start < spec.len() {
            let Ok(id_end) = id_end.try_into() else {
                bail!("Spec {spec} contains an id longer than {}", u16::MAX)
            };
            if pattern_end > u16::MAX as usize {
                bail!("Spec {spec} contains a pattern longer than {}", u16::MAX)
            }
            Ok(Self {
                spec,
                id_end,
                pattern_end: pattern_end as u16,
            })
        } else {
            bail!("Spec {spec} has an empty pattern")
        }
    }
}

impl Spec<'_> {
    pub fn id(&self) -> &str {
        &self.spec[..self.id_end as usize]
    }

    pub fn pattern(&self) -> &keyexpr {
        let text = if self.pattern_end != u16::MAX {
            &self.spec[(self.id_end + 1) as usize..self.pattern_end as usize]
        } else {
            &self.spec[(self.id_end + 1) as usize..]
        };
        // SAFETY: the pattern was checked to be a key expression when the format was built.
        unsafe { keyexpr::from_str_unchecked(text) }
    }

    pub fn default(&self) -> Option<&keyexpr> {
        let pattern_end = self.pattern_end as usize;
        (self.spec.len() > pattern_end)
            // SAFETY: a default was checked to be a key expression when the format was built.
            .then(|| unsafe { keyexpr::from_str_unchecked(&self.spec[(pattern_end + 1)..]) })
    }
}

impl core::fmt::Debug for Spec<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::fmt::Display for Spec<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let spec = self.spec;
        if spec.contains('}') {
            write!(f, "$#{{{spec}}}#")
        } else {
            write!(f, "${{{spec}}}")
        }
    }
}

/// A spec and what precedes it in a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Segment<'a> {
    /// What precedes a spec in a [`KeFormat`](super::KeFormat).
    /// It may be:
    /// - empty if the spec is the first thing in the format.
    /// - `/` if the spec comes right after another spec.
    /// - a valid keyexpr followed by `/` if the spec comes after a keyexpr.
    pub(crate) prefix: &'a str,
    pub(crate) spec: Spec<'a>,
}

impl Segment<'_> {
    /// The key expression that precedes the spec, if there is one.
    pub fn prefix(&self) -> Option<&keyexpr> {
        match self.prefix {
            "" | "/" => None,
            // SAFETY: the prefix was checked, and what is left of it without its slashes is a
            // key expression.
            _ => Some(unsafe {
                keyexpr::from_str_unchecked(trim_suffix_slash(trim_prefix_slash(self.prefix)))
            }),
        }
    }

    /// The id of the spec.
    pub fn id(&self) -> &str {
        self.spec.id()
    }

    /// The pattern of the spec.
    pub fn pattern(&self) -> &keyexpr {
        self.spec.pattern()
    }

    /// The default of the spec, if it has one.
    pub fn default(&self) -> Option<&keyexpr> {
        self.spec.default()
    }
}

/// A construction in progress: complete, partial or failed.
#[derive(Debug)]
pub enum IterativeConstructor<Complete, Partial, Error> {
    Complete(Complete),
    Partial(Partial),
    Error(Error),
}

/// A storage for the segments of a format.
pub trait IKeFormatStorage<'s>: Sized {
    /// The state of a construction that is not finished.
    type PartialConstruct;
    /// What a construction that failed reports.
    type ConstructionError: core::fmt::Display;
    /// Begin a construction.
    fn new_constructor(
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError>;
    /// Add a segment to a construction.
    fn add_segment(
        constructor: IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError>,
        segment: Segment<'s>,
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError>;
    /// The segments.
    fn segments(&self) -> &[Segment<'s>];
    /// The segments, mutably.
    fn segments_mut(&mut self) -> &mut [Segment<'s>];
    /// The segment of the spec `id`.
    fn segment(&self, id: &str) -> Option<&Segment<'s>> {
        self.segments().iter().find(|s| s.spec.id() == id)
    }
    /// The segment of the spec `id`, mutably.
    fn segment_mut(&mut self, id: &str) -> Option<&mut Segment<'s>> {
        self.segments_mut().iter_mut().find(|s| s.spec.id() == id)
    }
    /// A storage of one `T` per segment.
    type ValuesStorage<T>: AsMut<[T]> + AsRef<[T]>;
    /// A storage of one `T` per segment, each made by `f` from the segment's index.
    fn values_storage<T, F: FnMut(usize) -> T>(&self, f: F) -> Self::ValuesStorage<T>;
}

impl<'s, const N: usize> IKeFormatStorage<'s> for [Segment<'s>; N] {
    type PartialConstruct = ([MaybeUninit<Segment<'s>>; N], u16);
    type ConstructionError = Error;

    fn new_constructor(
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError> {
        if N > u16::MAX as usize {
            IterativeConstructor::Error(
                zerror!(
                    "[Segments; {N}] unsupported because {N} is too big (max: {}).",
                    u16::MAX
                )
                .into(),
            )
        } else {
            IterativeConstructor::Partial(([MaybeUninit::uninit(); N], 0))
        }
    }

    fn add_segment(
        constructor: IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError>,
        segment: Segment<'s>,
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError> {
        match constructor {
            IterativeConstructor::Complete(_) => IterativeConstructor::Error(
                zerror!("Attempted to add more than {N} segments to [Segment<'s>; {N}]").into(),
            ),
            IterativeConstructor::Partial((mut this, n)) => {
                let mut n = n as usize;
                this[n] = MaybeUninit::new(segment);
                n += 1;
                if n == N {
                    // SAFETY: the `N` slots were all written, one per call.
                    IterativeConstructor::Complete(this.map(|e| unsafe { e.assume_init() }))
                } else {
                    IterativeConstructor::Partial((this, n as u16))
                }
            }
            IterativeConstructor::Error(e) => IterativeConstructor::Error(e),
        }
    }

    fn segments(&self) -> &[Segment<'s>] {
        self
    }

    fn segments_mut(&mut self) -> &mut [Segment<'s>] {
        self
    }

    type ValuesStorage<T> = [T; N];

    fn values_storage<T, F: FnMut(usize) -> T>(&self, f: F) -> Self::ValuesStorage<T> {
        core::array::from_fn(f)
    }
}

impl<'s> IKeFormatStorage<'s> for Vec<Segment<'s>> {
    type PartialConstruct = core::convert::Infallible;
    type ConstructionError = core::convert::Infallible;

    fn new_constructor(
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError> {
        IterativeConstructor::Complete(Self::new())
    }

    fn add_segment(
        constructor: IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError>,
        segment: Segment<'s>,
    ) -> IterativeConstructor<Self, Self::PartialConstruct, Self::ConstructionError> {
        match constructor {
            IterativeConstructor::Complete(mut this) => {
                this.push(segment);
                IterativeConstructor::Complete(this)
            }
            // Both other states carry `Infallible`, which has no value.
            IterativeConstructor::Partial(never) | IterativeConstructor::Error(never) => {
                match never {}
            }
        }
    }

    fn segments(&self) -> &[Segment<'s>] {
        self
    }

    fn segments_mut(&mut self) -> &mut [Segment<'s>] {
        self
    }

    type ValuesStorage<T> = Box<[T]>;

    fn values_storage<T, F: FnMut(usize) -> T>(&self, f: F) -> Self::ValuesStorage<T> {
        (0..self.len()).map(f).collect()
    }
}

/// `target` without a leading slash, if it has one.
pub(crate) fn trim_prefix_slash(target: &str) -> &str {
    &target[matches!(target.as_bytes().first(), Some(b'/')) as usize..]
}

/// `target` without a trailing slash, if it has one.
pub(crate) fn trim_suffix_slash(target: &str) -> &str {
    &target[..(target.len() - matches!(target.as_bytes().last(), Some(b'/')) as usize)]
}
