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
// src/key_expr/format/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! # Building and parsing Key Expressions
//! A common issue in REST API is the association of meaning to sections of the URL, and respecting that API in a convenient manner.
//! The same issue arises naturally when designing a KE space, and [`KeFormat`] was designed to help you with this,
//! both in constructing and in parsing KEs that fit the formats you've defined.
//!
//! ## The format syntax
//! KE formats are defined following a syntax that extends the [`keyexpr`] syntax. In addition to existing chunk types, KE formats support "specification" chunks.
//! These chunks must follow the one of the following syntaxes: `${id:pattern}`, `${id:pattern#default}`, `$#{id:pattern}#`, or `$#{id:pattern#default}#`, where:
//! - `id` is the chunk identifier: it cannot contain the `:` character, and is used to name the chunk in accessors.
//! - `pattern` must be a valid KE (and therefore cannot contain `#`) and defines the range of values that the chunk may adopt.
//! - `default` (optional) is used as the chunk value when formatting if the builder wasn't supplied with a value for `id`.
//!
//! ## Formatting
//! To use a format to build a Key Expression, its [formatter](KeFormat::formatter) must be constructed.
//!
//! A formatter functions like as an `id`-value map which can be [`KeFormatter::build`] into a [`OwnedKeyExpr`] once all specs have a value.
//!
//! The formatter will notably prevent you from setting values for a spec that isn't included by its pattern.
//!
//! ## Parsing
//! [`KeFormat`] can also be used to parse any [`keyexpr`] that intersects with it, using [`KeFormat::parse`].
//!
//! The parser will then assign subsections of the [`keyexpr`] to each spec, and the resulting [`Parsed`] result can then be queried
//! for each spec's assigned value.
//!
//! Specs are considered greedy and evaluated left-to-right: if your format would allow ambiguous parsings, chunks will be consumed
//! by the leftmost specs first. For example `${a:**}/-/${b:**}` parsing `hey/-/-/there` would assign `hey/-` to `a` and `there` to `b`,
//! (even though you might have expected `a` to only consume `hey` and `b` to consume the remaining `-/there`).
//!
//! A good way to avoid ambiguities when working with formats that contain multiple `**` specs is to separate such specs using verbatim chunks
//! (chunks that start with an `@`), as `**` is incapable of consuming these chunks.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display},
    num::NonZeroU32,
};

use zenoh_result::{bail, zerror, Error, IError, ZResult};

use super::{keyexpr, OwnedKeyExpr};

mod support;
pub use support::{IKeFormatStorage, Segment};
use support::{IterativeConstructor, Spec};

mod parsing;
pub use parsing::{Iter, Parsed};

#[cfg(test)]
mod tests;

/// # Building and parsing Key Expressions
/// A format is a key expression with specs in it, `${id:pattern}`: [`KeFormat::formatter`] builds
/// key expressions from values for the ids, and [`KeFormat::parse`] reads the values back from a
/// key expression that intersects the format. See the [module](self) for the syntax and for how
/// ambiguous parsings are settled.
#[derive(Clone, Copy, Hash)]
pub struct KeFormat<'s, Storage: IKeFormatStorage<'s> + 's = Vec<Segment<'s>>> {
    /// The [`[Segment]`](Segment)s of the format.
    storage: Storage,
    /// The end of the format. It may be one of 3 cases:
    /// - An empty string, in which case the format ends with the last segment.
    /// - A keyexpr preceded by `/`.
    /// - A keyexpr, in the case the format contains no specs.
    suffix: &'s str,
}

impl<'s, Storage: IKeFormatStorage<'s>> Debug for KeFormat<'s, Storage> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self}")
    }
}

impl<'s> KeFormat<'s, Vec<Segment<'s>>> {
    /// Construct a new [`KeFormat`], using a vector to store its state-machine and parser results.
    pub fn new<S: AsRef<str> + ?Sized>(value: &'s S) -> ZResult<Self> {
        value.as_ref().try_into()
    }

    /// Construct a new [`KeFormat`], using a stack-allocated array to store its state-machine and parser results.
    /// `N` is simply the number of specifications in `value`. If this number of specs isn't known at compile-time, use [`KeFormat::new`] instead.
    /// If you know `value` at compile time, using `kedefine` instead is advised,
    /// as it will provide more features and construct higher performance formats than this constructor.
    pub fn noalloc_new<const N: usize>(value: &'s str) -> ZResult<KeFormat<'s, [Segment<'s>; N]>> {
        value.try_into()
    }
}

/// The support of the `keformat` family of macros, which build a format at compile time from the
/// offsets of its parts.
pub mod macro_support {
    use super::*;

    /// DO NOT USE THIS
    /// This is a support structure for [`const_new`], which is only meant to be used through the `zenoh::keformat` macro.
    #[doc(hidden)]
    #[derive(Debug, Clone, Copy)]
    pub struct SegmentBuilder {
        pub segment_start: usize,
        pub prefix_end: usize,
        pub spec_start: usize,
        pub id_end: u16,
        pub pattern_end: u16,
        pub spec_end: usize,
        pub segment_end: usize,
    }

    /// # Safety
    /// DO NOT USE THIS, EVER
    /// This is a support function which is only meant to be used through the `zenoh::keformat` macro
    #[doc(hidden)]
    pub unsafe fn specs<'s>(this: &KeFormat<'s, Vec<Segment<'s>>>) -> Vec<SegmentBuilder> {
        let segments = this.storage.segments();
        if segments.is_empty() {
            return Vec::new();
        }
        let source_start = segments[0].prefix.as_ptr() as usize;
        segments
            .iter()
            .map(|segment| {
                let segment_start = segment.prefix.as_ptr() as usize - source_start;
                let prefix_end = segment_start + segment.prefix.len();
                let spec_start = segment.spec.spec.as_ptr() as usize - source_start;
                let spec_end = spec_start + segment.spec.spec.len();
                let segment_end = spec_end + spec_start - prefix_end - 1;
                SegmentBuilder {
                    segment_start,
                    prefix_end,
                    spec_start,
                    id_end: segment.spec.id_end,
                    pattern_end: segment.spec.pattern_end,
                    spec_end,
                    segment_end,
                }
            })
            .collect()
    }

    /// # Safety
    /// DO NOT USE THIS, EVER
    /// This is a support function which is only meant to be used through the `zenoh::keformat` macro
    #[doc(hidden)]
    pub const unsafe fn const_new<const N: usize>(
        source: &'static str,
        segments: [SegmentBuilder; N],
    ) -> KeFormat<'static, [Segment<'static>; N]> {
        /// # Safety
        /// `start..end` must be in-bounds for `source`, and delimit UTF-8 boundaries.
        const unsafe fn substr(source: &'static str, start: usize, end: usize) -> &'static str {
            // SAFETY: guaranteed by `const_new` caller and macro-generated offsets.
            unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                    source.as_ptr().add(start),
                    end - start,
                ))
            }
        }
        let mut storage = [Segment {
            prefix: "",
            spec: Spec {
                spec: "",
                id_end: 0,
                pattern_end: 0,
            },
        }; N];
        let mut suffix_start = 0;
        let mut i = 0;
        while i < N {
            let segment = segments[i];
            // SAFETY: macro-generated indices point to valid UTF-8 segment boundaries.
            let prefix = unsafe { substr(source, segment.segment_start, segment.prefix_end) };
            let spec = Spec {
                // SAFETY: macro-generated indices point to valid UTF-8 segment boundaries.
                spec: unsafe { substr(source, segment.spec_start, segment.spec_end) },
                id_end: segment.id_end,
                pattern_end: segment.pattern_end,
            };
            storage[i] = Segment { prefix, spec };
            suffix_start = segment.segment_end;
            i += 1;
        }
        // SAFETY: `suffix_start` is derived from macro-generated segment ends.
        let suffix = unsafe { substr(source, suffix_start, source.len()) };
        KeFormat { storage, suffix }
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> KeFormat<'s, Storage> {
    /// Constructs a new formatter for the format.
    pub fn formatter(&'s self) -> KeFormatter<'s, Storage> {
        KeFormatter {
            format: self,
            buffer: String::new(),
            values: Storage::values_storage(&self.storage, |_| None),
        }
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> TryFrom<&'s String> for KeFormat<'s, Storage> {
    type Error = Error;
    fn try_from(value: &'s String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> TryFrom<&'s str> for KeFormat<'s, Storage> {
    type Error = Error;
    fn try_from(value: &'s str) -> Result<Self, Self::Error> {
        let mut storage = Storage::new_constructor();
        let mut segment_start = 0;
        let mut i = 0;
        let bytes = value.as_bytes();
        while i < bytes.len() {
            if bytes[i] != b'$' {
                i += 1;
                continue;
            }
            let prefix_end = i;
            i += 1;
            // What follows the `$`: `{` opens a spec closed by `}`, `#{` one closed by `}#`, and
            // `*` is the `$*` of a key expression and not a spec.
            let (terminator, spec_start) = match bytes.get(i) {
                Some(b'{') => ("}", i + 1),
                Some(b'*') => {
                    i += 1;
                    continue;
                }
                Some(b'#') if bytes.get(i + 1) == Some(&b'{') => ("}#", i + 2),
                Some(c) => bail!(
                    "Invalid KeFormat: {value} contains `${}` which is not legal in KEs or formats",
                    *c as char
                ),
                None => bail!(
                    "Invalid KeFormat: {value} contains `$` which is not legal in KEs or formats"
                ),
            };
            let rest = &value[spec_start..];
            let Some(spec_len) = rest.find(terminator) else {
                bail!("Invalid KeFormat: {value} contains an unterminated spec")
            };
            let spec_text = &rest[..spec_len];
            let spec = match Spec::try_from(spec_text) {
                Ok(spec) => spec,
                Err(e) => {
                    bail!(e => "Invalid KeFormat: {value} contains an invalid spec: {spec_text}")
                }
            };
            let segment_end = spec_len + spec_start + terminator.len();
            if prefix_end != 0 && bytes[prefix_end - 1] != b'/' {
                bail!("Invalid KeFormat: a spec in {value} is preceded a non-`/` character")
            }
            if !matches!(bytes.get(segment_end), None | Some(b'/')) {
                bail!("Invalid KeFormat: a spec in {value} is followed by a non-`/` character")
            }
            // The pattern is a key expression; this can be made more flexible later.
            keyexpr::new(spec.pattern().as_str())?;
            let prefix = &value[segment_start..prefix_end];
            if prefix.contains('*') {
                bail!("Invalid KeFormat: wildcards are only allowed in specs when writing formats")
            }
            storage = match Storage::add_segment(storage, Segment { prefix, spec }) {
                IterativeConstructor::Error(e) => {
                    bail!(
                        "Couldn't construct KeFormat because its Storage's add_segment failed: {e}"
                    )
                }
                s => s,
            };
            segment_start = segment_end;
            i = segment_end;
        }
        let IterativeConstructor::Complete(storage) = storage else {
            bail!("Couldn't construct KeFormat because its Storage construction was only partial after adding the last segment.")
        };
        let segments = storage.segments();
        for (n, segment) in segments.iter().enumerate() {
            if segments[(n + 1)..]
                .iter()
                .any(|s| s.spec.id() == segment.spec.id())
            {
                bail!("Invalid KeFormat: {value} contains duplicated ids")
            }
        }
        let suffix = &value[segment_start..];
        if suffix.contains('*') {
            bail!("Invalid KeFormat: wildcards are only allowed in specs when writing formats")
        }
        Ok(KeFormat { storage, suffix })
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> core::convert::TryFrom<&KeFormat<'s, Storage>>
    for String
{
    type Error = core::fmt::Error;
    fn try_from(value: &KeFormat<'s, Storage>) -> Result<Self, Self::Error> {
        use core::fmt::Write;
        let mut s = String::new();
        for segment in value.storage.segments() {
            s += segment.prefix;
            write!(&mut s, "{}", segment.spec.pattern())?;
        }
        s += value.suffix;
        Ok(s)
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> core::convert::TryFrom<&KeFormat<'s, Storage>>
    for OwnedKeyExpr
{
    type Error = Error;
    fn try_from(value: &KeFormat<'s, Storage>) -> Result<Self, Self::Error> {
        let s: String = value
            .try_into()
            .map_err(|e| zerror!("failed to write into String: {e}"))?;
        OwnedKeyExpr::autocanonize(s)
    }
}

impl<'s, Storage: IKeFormatStorage<'s> + 's> core::fmt::Display for KeFormat<'s, Storage> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for segment in self.storage.segments() {
            write!(f, "{}{}", segment.prefix, segment.spec)?;
        }
        write!(f, "{}", self.suffix)
    }
}

/// A `u32` that is never `u32::MAX`, so that `Option` of it takes no more room than a `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonMaxU32(NonZeroU32);

impl NonMaxU32 {
    fn new(value: u32) -> Option<Self> {
        NonZeroU32::new(!value).map(NonMaxU32)
    }
    fn get(&self) -> u32 {
        !self.0.get()
    }
}

/// An active formatter for a [`KeFormat`].
#[derive(Clone)]
pub struct KeFormatter<'s, Storage: IKeFormatStorage<'s>> {
    format: &'s KeFormat<'s, Storage>,
    buffer: String,
    values: Storage::ValuesStorage<Option<(u32, NonMaxU32)>>,
}

impl<'s, Storage: IKeFormatStorage<'s>> core::fmt::Debug for KeFormatter<'s, Storage> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let values = self.values.as_ref();
        let segments = self.format.storage.segments();
        for i in 0..values.len() {
            let Segment { prefix, spec } = segments[i];
            let value =
                values[i].map(|(start, end)| &self.buffer[start as usize..end.get() as usize]);
            let id = spec.id();
            let pattern = spec.pattern();
            let sharp = if id.contains('}')
                || pattern.contains('}')
                || value.map_or_else(
                    || spec.default().is_some_and(|v| v.contains('}')),
                    |v| v.contains('}'),
                ) {
                "#"
            } else {
                ""
            };
            write!(f, "{prefix}${sharp}{{{id}:{pattern}")?;
            if let Some(value) = value {
                write!(f, "={value}")?
            } else if let Some(default) = spec.default() {
                write!(f, "#{default}")?
            };
            write!(f, "}}{sharp}")?;
        }
        write!(f, "{}", self.format.suffix)
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> TryFrom<&KeFormatter<'s, Storage>> for OwnedKeyExpr {
    type Error = Error;

    fn try_from(value: &KeFormatter<'s, Storage>) -> Result<Self, Self::Error> {
        let values = value.values.as_ref();
        let segments = value.format.storage.segments();
        // Each part is the segment's prefix and then its value, or its default, or an error.
        let mut ans = String::new();
        let mut concatenate = |s: &str| {
            let skip_slash = matches!(ans.as_bytes().last(), None | Some(b'/'))
                && s.as_bytes().first() == Some(&b'/');
            ans += &s[skip_slash as usize..];
        };
        for (i, segment) in segments.iter().enumerate() {
            concatenate(segment.prefix);
            if let Some((start, end)) = values[i] {
                concatenate(&value.buffer[start as usize..end.get() as usize])
            } else if let Some(default) = segment.spec.default() {
                concatenate(default)
            } else {
                bail!("Missing field `{}` in {value:?}", segment.spec.id())
            }
        }
        concatenate(value.format.suffix);
        if ans.ends_with('/') {
            ans.pop();
        }
        OwnedKeyExpr::autocanonize(ans)
    }
}

impl<'s, Storage: IKeFormatStorage<'s>> TryFrom<&mut KeFormatter<'s, Storage>> for OwnedKeyExpr {
    type Error = Error;

    fn try_from(value: &mut KeFormatter<'s, Storage>) -> Result<Self, Self::Error> {
        (&*value).try_into()
    }
}

/// Why a value could not be set on a formatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatSetError {
    /// The format has no spec of that id.
    InvalidId,
    /// The value is not a key expression that the spec's pattern includes.
    PatternNotMatched,
}

impl core::fmt::Display for FormatSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl IError for FormatSetError {}

impl<'s, Storage: IKeFormatStorage<'s>> KeFormatter<'s, Storage> {
    /// Access the formatter's format
    pub fn format(&self) -> &KeFormat<'s, Storage> {
        self.format
    }

    /// Clear the formatter of previously set values, without deallocating its internal formatting buffer.
    pub fn clear(&mut self) -> &mut Self {
        self.buffer.clear();
        for value in self.values.as_mut() {
            *value = None
        }
        self
    }

    /// Build a key-expression according to the format and the currently set values.
    /// This doesn't clear the formatter of already set values, allowing to reuse the builder and only
    /// change a subset of its properties before building a new key-expression again.
    pub fn build(&self) -> ZResult<OwnedKeyExpr> {
        self.try_into()
    }

    /// Access the current value for `id`.
    pub fn get(&self, id: &str) -> Option<&str> {
        let segments = self.format.storage.segments();
        segments
            .iter()
            .position(|s| s.spec.id() == id)
            .and_then(|i| {
                self.values.as_ref()[i]
                    .map(|(start, end)| &self.buffer[start as usize..end.get() as usize])
            })
    }

    /// Set a new value for `id` using `S`'s [`Display`] formatting.
    /// # Errors
    /// If the result of `format!("{value}")` is neither:
    /// - A valid key expression that is included by the pattern for `id`
    /// - An empty string, on the condition that `id`'s pattern is `**`
    pub fn set<S: Display>(&mut self, id: &str, value: S) -> Result<&mut Self, FormatSetError> {
        use core::fmt::Write;
        let segments = self.format.storage.segments();
        let Some(i) = segments.iter().position(|s| s.spec.id() == id) else {
            return Err(FormatSetError::InvalidId);
        };
        let values = self.values.as_mut();
        // A value set before is removed from the buffer, and the ones after it move down.
        if let Some((start, end)) = values[i].take() {
            let end = end.get();
            let shift = end - start;
            self.buffer.replace_range(start as usize..end as usize, "");
            for (s, e) in values.iter_mut().flatten() {
                if *s < start {
                    continue;
                }
                *s -= shift;
                *e = NonMaxU32::new(e.get() - shift).unwrap()
            }
        }
        let pattern = segments[i].spec.pattern();
        let start = self.buffer.len();
        write!(&mut self.buffer, "{value}").unwrap(); // Writing on `&mut String` is infallible.
        let mut set_value = || {
            let end = self.buffer.len();
            if start == end {
                if !pattern.is_double_wild() {
                    return Err(());
                }
            } else {
                let Ok(ke) = keyexpr::new(&self.buffer[start..end]) else {
                    return Err(());
                };
                if !pattern.includes(ke) {
                    return Err(());
                }
            }
            values[i] = Some((
                start as u32,
                NonMaxU32::new(end.try_into().map_err(|_| ())?).ok_or(())?,
            ));
            Ok(())
        };
        match set_value() {
            Ok(()) => Ok(self),
            Err(()) => {
                self.buffer.truncate(start);
                Err(FormatSetError::PatternNotMatched)
            }
        }
    }
}

/// A [`KeFormat`] that owns its format-string.
#[derive(Debug)]
pub struct OwnedKeFormat<Storage: IKeFormatStorage<'static> + 'static = Vec<Segment<'static>>> {
    _owner: Box<str>,
    format: KeFormat<'static, Storage>,
}

impl<Storage: IKeFormatStorage<'static> + 'static> core::ops::Deref for OwnedKeFormat<Storage> {
    type Target = KeFormat<'static, Storage>;
    fn deref(&self) -> &Self::Target {
        &self.format
    }
}

impl<Storage: IKeFormatStorage<'static> + 'static> TryFrom<Box<str>> for OwnedKeFormat<Storage> {
    type Error = <KeFormat<'static, Storage> as TryFrom<&'static str>>::Error;
    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        let owner = value;
        // SAFETY: the format borrows the heap allocation of `owner`, which stays where it is when
        // the box moves, is never mutated, and is dropped after the format (field order).
        let format: KeFormat<'static, Storage> =
            unsafe { core::mem::transmute::<&str, &'static str>(&owner) }.try_into()?;
        Ok(Self {
            _owner: owner,
            format,
        })
    }
}

impl<Storage: IKeFormatStorage<'static> + 'static> TryFrom<String> for OwnedKeFormat<Storage> {
    type Error = <KeFormat<'static, Storage> as TryFrom<&'static str>>::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.into_boxed_str().try_into()
    }
}

impl<Storage: IKeFormatStorage<'static> + 'static> core::str::FromStr for OwnedKeFormat<Storage> {
    type Err = <KeFormat<'static, Storage> as TryFrom<&'static str>>::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Box::<str>::from(s).try_into()
    }
}

impl<'s, S1: IKeFormatStorage<'s> + 's, S2: IKeFormatStorage<'s> + 's> PartialEq<KeFormat<'s, S2>>
    for KeFormat<'s, S1>
{
    fn eq(&self, other: &KeFormat<'s, S2>) -> bool {
        self.suffix == other.suffix && self.storage.segments() == other.storage.segments()
    }
}
