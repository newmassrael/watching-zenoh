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
//!
//! [`WireKey`]: crate::wire_key::WireKey
//! [`NamedKey::literal`]: crate::named_key::NamedKey::literal
//! [`NamedKey::under`]: crate::named_key::NamedKey::under
//! [`Prefix`]: crate::named_key::Prefix

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
#[derive(Clone, Copy, Debug)]
pub struct NamedKey<'a> {
    text: KeyText<'a>,
    wire: WireKey<'a>,
    /// Whether the text passed the wire's pre-emit gate where the session's tables kept it
    /// (`Self::check_outbound`): set by those tables alone, from the judgement of the row.
    proven: bool,
}

/// Two keys are one key when their texts and wire forms are: what is known of the text is not
/// part of the key.
impl PartialEq for NamedKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.wire == other.wire
    }
}

impl Eq for NamedKey<'_> {}

impl<'a> NamedKey<'a> {
    /// `text`, named whole on the wire; `None` for an empty text, which names no key.
    pub const fn literal(text: &'a str) -> Option<Self> {
        match KeyText::new(text) {
            Some(text) => Some(Self {
                text,
                wire: WireKey::Literal(text),
                proven: false,
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
            proven: false,
        })
    }

    /// `text`, named by the declaration `declared` where that begins the text, and whole
    /// otherwise: with no declaration, or one the text does not start with. `None` for an empty
    /// text.
    // Out of line: every key a session's tables name, by a row's declaration or by an id, is
    // named through it.
    #[inline(never)]
    pub fn under_or_whole(text: &'a str, declared: Option<Prefix<'_>>) -> Option<Self> {
        declared
            .and_then(|prefix| Self::under(text, prefix))
            .or_else(|| Self::literal(text))
    }

    /// `text` named by the declaration `head` writes its Put for, with nothing after it: for a
    /// write filter's row that found the session names its key so
    /// ([`crate::session_tables::WriteFilterRow::keep_plan`]). `None` for an empty text.
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    pub(crate) fn by_head(text: &'a str, head: &crate::lent_push::PutHead) -> Option<Self> {
        Some(Self {
            text: KeyText::new(text)?,
            wire: WireKey::Id(MappedId::new(head.id())?),
            proven: false,
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

    /// This key, its text proven to pass the wire's pre-emit gate: for the session's tables, which
    /// judged it once where they kept it ([`crate::session_tables::SessionTables::named`]).
    pub(crate) const fn proven(self) -> Self {
        Self {
            proven: true,
            ..self
        }
    }

    /// Whether the text was proven to pass the wire's pre-emit gate where it was kept.
    pub const fn is_proven(self) -> bool {
        self.proven
    }

    /// The wire's pre-emit gate on the text
    /// ([`crate::keyexpr_canon::check_outbound_keyexpr_pico_safe`]), judged again only for a key
    /// not proven where it was kept: every send of a declaration reads it, so a key the tables
    /// judged when they kept it is not walked again at each link it is announced or replayed on.
    #[cfg(feature = "storage-profile")]
    pub fn check_outbound(self) -> Result<(), crate::keyexpr_canon::OutboundKeyexprError> {
        if self.proven {
            return Ok(());
        }
        crate::keyexpr_canon::check_outbound_keyexpr_pico_safe(self.text())
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

    /// A key is named under a declaration that begins it, and whole under one that does not or
    /// with none; an empty text is no key either way.
    #[test]
    fn a_key_is_named_under_its_declaration_or_whole() {
        let id = MappedId::new(7).unwrap();
        let prefix = Prefix::of(id, "home/");
        assert_eq!(
            NamedKey::under_or_whole("home/temp", Some(prefix)),
            NamedKey::under("home/temp", prefix)
        );
        assert_eq!(
            NamedKey::under_or_whole("away/temp", Some(prefix)),
            NamedKey::literal("away/temp"),
            "a declaration the text does not start with names it whole"
        );
        assert_eq!(
            NamedKey::under_or_whole("home/temp", None),
            NamedKey::literal("home/temp")
        );
        assert_eq!(NamedKey::under_or_whole("", Some(prefix)), None);
        assert_eq!(NamedKey::under_or_whole("", None), None);
    }

    /// A key made by a front end is not proven and is judged by the wire's gate, which refuses a
    /// text of the family pico aborts on; a key the tables proved is admitted with no walk, and is
    /// the same key as the unproven one. Turned red by a key proven where it was made
    /// (`NamedKey::literal`), or by the gate trusting an unproven key.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn only_a_key_the_tables_proved_skips_the_wire_gate() {
        let refused = NamedKey::literal("**/c/*").unwrap();
        assert!(!refused.is_proven());
        assert!(refused.check_outbound().is_err());
        let plain = NamedKey::literal("home/temp").unwrap();
        assert!(!plain.is_proven());
        assert!(plain.check_outbound().is_ok());
        let proven = plain.proven();
        assert!(proven.is_proven());
        assert!(proven.check_outbound().is_ok());
        assert_eq!(
            proven, plain,
            "what is known of the text is not part of the key"
        );
    }
}
