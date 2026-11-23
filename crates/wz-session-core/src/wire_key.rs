// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key expression a network message names, in the form the wire carries it: an id of the
//! receiver's mapping, a suffix after it, or the whole key as text under the id `0` that names
//! no mapping (`commons/zenoh-protocol/src/core/wire_expr.rs` @ `pub struct WireExpr<'a>`).
//!
//! The id `0` with no text names no key at all, which no message a session builds may carry.
//! [`WireKey`] has no value for it: a builder that takes one cannot be handed that case, and the
//! refusal of an id and a suffix that spell it is made once, where the two are put together
//! ([`WireKey::from_parts`]).

use core::num::NonZeroU16;

use crate::wire_id::ExprId;

/// An id of the receiver's mapping: an [`ExprId`] that is not `0`.
pub type MappedId = NonZeroU16;

// The id of a mapping is the scope the wire carries, at its width.
const _: () = assert!(core::mem::size_of::<MappedId>() == core::mem::size_of::<ExprId>());

/// A key expression as a message names it: never no key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WireKey<'a> {
    /// The whole key as text, under the id `0`. The text is not empty.
    Literal(KeyText<'a>),
    /// The key the receiver's mapping holds under the id.
    Id(MappedId),
    /// The key the receiver's mapping holds under the id, then the suffix, which is not empty.
    IdSuffix(MappedId, KeyText<'a>),
}

/// Text a key carries on the wire, a literal or a suffix: not empty, since an empty literal names
/// no key and an empty suffix is no suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyText<'a>(&'a str);

impl<'a> KeyText<'a> {
    /// `text` as a literal key, or `None` when it is empty.
    pub const fn new(text: &'a str) -> Option<Self> {
        if text.is_empty() {
            None
        } else {
            Some(Self(text))
        }
    }

    /// The text.
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl<'a> WireKey<'a> {
    /// The literal key `text`, or `None` when it is empty.
    pub const fn literal(text: &'a str) -> Option<Self> {
        match KeyText::new(text) {
            Some(text) => Some(Self::Literal(text)),
            None => None,
        }
    }

    /// The key the receiver's mapping holds under `id`, then `suffix` when there is one.
    pub const fn mapped(id: MappedId, suffix: Option<KeyText<'a>>) -> Self {
        match suffix {
            Some(suffix) => Self::IdSuffix(id, suffix),
            None => Self::Id(id),
        }
    }

    /// The key an id and a suffix name on the wire, `(0, Some(text))` being the literal
    /// `text` and an empty suffix no suffix; `None` for the id `0` with no text (or an empty
    /// one), which names no key.
    pub const fn from_parts(id: ExprId, suffix: Option<&'a str>) -> Option<Self> {
        let suffix = match suffix {
            Some(text) => KeyText::new(text),
            None => None,
        };
        match (NonZeroU16::new(id), suffix) {
            (None, Some(text)) => Some(Self::Literal(text)),
            (None, None) => None,
            (Some(id), suffix) => Some(Self::mapped(id, suffix)),
        }
    }

    /// The id the wire carries: `0` for a literal.
    pub const fn id(self) -> ExprId {
        match self {
            Self::Literal(_) => 0,
            Self::Id(id) | Self::IdSuffix(id, _) => id.get(),
        }
    }

    /// The text the wire carries after the id, when there is any.
    pub const fn suffix(self) -> Option<&'a str> {
        match self {
            Self::Literal(text) => Some(text.as_str()),
            Self::Id(_) => None,
            Self::IdSuffix(_, suffix) => Some(suffix.as_str()),
        }
    }
}

/// A [`WireKey`] that holds its text: what a builder keeps until it writes the message. Made
/// from a [`WireKey`] alone, so it holds no key a [`WireKey`] cannot be.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WireKeyBuf(HeldKey);

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum HeldKey {
    Literal(alloc::string::String),
    Id(MappedId),
    IdSuffix(MappedId, alloc::string::String),
}

#[cfg(feature = "alloc")]
impl WireKeyBuf {
    /// The literal key `text`, held as it is given, or `None` when it is empty.
    pub fn literal(text: alloc::string::String) -> Option<Self> {
        if text.is_empty() {
            None
        } else {
            Some(Self(HeldKey::Literal(text)))
        }
    }

    /// The key it holds, borrowed.
    pub fn as_key(&self) -> WireKey<'_> {
        match &self.0 {
            HeldKey::Literal(text) => WireKey::Literal(KeyText(text)),
            HeldKey::Id(id) => WireKey::Id(*id),
            HeldKey::IdSuffix(id, suffix) => WireKey::IdSuffix(*id, KeyText(suffix)),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<WireKey<'_>> for WireKeyBuf {
    fn from(key: WireKey<'_>) -> Self {
        Self(match key {
            WireKey::Literal(text) => HeldKey::Literal(text.as_str().into()),
            WireKey::Id(id) => HeldKey::Id(id),
            WireKey::IdSuffix(id, suffix) => HeldKey::IdSuffix(id, suffix.as_str().into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id `0` with no text, or with an empty one, is no key; every other pair is the key
    /// the wire reads, and reads back as the same pair, an empty suffix as none.
    #[test]
    fn only_the_pair_that_names_no_key_is_refused() {
        assert_eq!(WireKey::from_parts(0, None), None);
        assert_eq!(WireKey::from_parts(0, Some("")), None);
        assert_eq!(WireKey::literal(""), None);
        let cases: [(ExprId, Option<&str>); 3] = [(0, Some("a/b")), (7, None), (7, Some("/c"))];
        for (id, suffix) in cases {
            let key = WireKey::from_parts(id, suffix).expect("a key");
            assert_eq!((key.id(), key.suffix()), (id, suffix));
        }
        let empty_suffix = WireKey::from_parts(7, Some("")).expect("an id");
        assert_eq!((empty_suffix.id(), empty_suffix.suffix()), (7, None));
    }

    /// A held key is the key it was made from.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_held_key_reads_back_as_the_key() {
        for key in [
            WireKey::literal("a/b").expect("a literal"),
            WireKey::from_parts(3, None).expect("an id"),
            WireKey::from_parts(3, Some("x")).expect("an id and a suffix"),
        ] {
            assert_eq!(WireKeyBuf::from(key).as_key(), key);
        }
    }
}
