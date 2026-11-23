// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A key expression a session sends, as one value: its whole text, which what is checked and
//! counted of the message reads, and the form the wire names it by ([`WireKey`]), by a
//! declaration of the session's where one covers it.
//!
//! The two are one fact, so they are made together and cannot disagree: a literal from its text
//! alone ([`NamedKey::literal`]), and a key named by a declaration from its text and the
//! declaration as the table that holds it states it ([`NamedKey::under`], which takes the rest
//! of the text after the declared literal as the suffix). A [`Prefix`] is made by those tables
//! only, so no caller pairs an id with a literal of its own.

use crate::wire_key::{KeyText, MappedId, WireKey};

/// A declaration of the session's that a key may be named by: its id and the literal it names,
/// as the table that holds the declaration states them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix<'p> {
    id: MappedId,
    literal: &'p str,
}

impl<'p> Prefix<'p> {
    /// The declaration `id` of `literal`, as a table of the session's declarations holds it.
    pub(crate) const fn of(id: MappedId, literal: &'p str) -> Self {
        Self { id, literal }
    }

    /// The declaration's id.
    pub const fn id(self) -> MappedId {
        self.id
    }

    /// The literal it names.
    pub const fn literal(self) -> &'p str {
        self.literal
    }
}

/// A key a session sends: its whole text and the form the wire names it by, which agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedKey<'a> {
    text: KeyText<'a>,
    wire: WireKey<'a>,
}

impl<'a> NamedKey<'a> {
    /// `text`, named whole on the wire; `None` for an empty text, which names no key.
    pub const fn literal(text: &'a str) -> Option<Self> {
        match KeyText::new(text) {
            Some(text) => Some(Self {
                text,
                wire: WireKey::Literal(text),
            }),
            None => None,
        }
    }

    /// `text`, named by the declaration `prefix` and the rest of the text after its literal;
    /// `None` for an empty text or one that does not start with the declared literal.
    pub fn under(text: &'a str, prefix: Prefix<'_>) -> Option<Self> {
        let rest = text.strip_prefix(prefix.literal)?;
        Some(Self {
            text: KeyText::new(text)?,
            wire: WireKey::mapped(prefix.id, KeyText::new(rest)),
        })
    }

    /// The whole text.
    pub const fn text(self) -> &'a str {
        self.text.as_str()
    }

    /// The form the wire names it by.
    pub const fn wire(self) -> WireKey<'a> {
        self.wire
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal is its text on the wire; a key under a declaration is that declaration's id and
    /// the rest of the text, or the id alone when the declaration covers it all; a text that does
    /// not start with the declared literal, or an empty one, is no key.
    #[test]
    fn a_key_is_its_text_and_the_form_that_names_it() {
        let id = MappedId::new(7).unwrap();
        let prefix = Prefix::of(id, "home/");
        let literal = NamedKey::literal("home/temp").unwrap();
        assert_eq!(literal.text(), "home/temp");
        assert_eq!(literal.wire(), WireKey::literal("home/temp").unwrap());
        let under = NamedKey::under("home/temp", prefix).unwrap();
        assert_eq!(under.text(), "home/temp");
        assert_eq!(under.wire(), WireKey::mapped(id, KeyText::new("temp")));
        assert_eq!(
            NamedKey::under("home/", prefix).unwrap().wire(),
            WireKey::Id(id),
            "the declaration covers it all"
        );
        assert_eq!(NamedKey::under("away/temp", prefix), None);
        assert_eq!(NamedKey::literal(""), None);
    }
}
