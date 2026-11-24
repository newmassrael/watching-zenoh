// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a declaration names its key on the wire, beside what it matches locally: the key an
//! entity's retraction names
//! ([`RetractionKey`](crate::declare_form::RetractionKey)), and the form and the ask of a
//! matching Interest (`InterestForm`, with `session-matching` and `declare-interest`).
//!
//! Both are wire facts a declaring C ABI chooses the way its reference library does, and both
//! were the tokio engine's (`wz-runtime-tokio`'s session module, which re-exports them). They
//! moved here when the pico C ABI over the cooperative engine (`docs/capi-pico-on-coop-engine.md`)
//! had to hand them to an engine without naming that one.

#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
use alloc::string::String;

/// The key an entity's `Undeclare*` names beside its id, in the wire form it is held under: a
/// declared prefix's id and the rest of the key, or `0` and the whole literal. A subscriber's
/// retraction and a queryable's take the same shape.
///
/// The rest is named by its length and read against the entity's own key ([`Self::names`]),
/// which every engine keeps for as long as the entity stands: so this holds no text, and handing
/// it to an engine copies none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetractionKey {
    /// The prefix's mapping id, or `0` for a literal.
    pub mapping_id: crate::wire_id::ExprId,
    /// How many bytes at the end of the key follow the prefix; not read for a literal.
    rest_len: usize,
}

impl RetractionKey {
    /// The whole key, under no declaration.
    pub const fn literal() -> Self {
        Self {
            mapping_id: 0,
            rest_len: 0,
        }
    }

    /// Declaration `mapping_id` followed by `rest`, the end of the entity's key past the declared
    /// prefix (empty when the declaration covers all of it).
    pub const fn declared(mapping_id: crate::wire_id::ExprId, rest: &str) -> Self {
        Self {
            mapping_id,
            rest_len: rest.len(),
        }
    }

    /// What the retraction names of `keyexpr`, the entity's own key: the declaration's id and the
    /// rest of the key past it, or `0` and the whole key. A key the rest does not end (shorter
    /// than it, or cut by it inside a character) is not the key this was made for, and is named
    /// whole, which every peer reads.
    pub fn names<'k>(&self, keyexpr: &'k str) -> (crate::wire_id::ExprId, &'k str) {
        if self.mapping_id == 0 {
            return (0, keyexpr);
        }
        match keyexpr
            .len()
            .checked_sub(self.rest_len)
            .and_then(|at| keyexpr.get(at..))
        {
            Some(rest) => (self.mapping_id, rest),
            None => (0, keyexpr),
        }
    }
}

/// Open-debt item 913 — the kind of entity a session announces on a multicast group or retracts
/// there. Every engine that joins groups names the same three, so the declaration each becomes
/// is built once (`declare_build::build_group_announcement`, `build_group_retraction`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupDeclaration {
    /// A subscriber.
    Subscriber,
    /// A queryable, with whether it answers a query completely.
    Queryable {
        /// The queryable's completeness, which its declaration carries.
        complete: bool,
    },
    /// A liveliness token.
    Token,
}

/// Open-debt item 913 — how a group session names a key on the group: a keyexpr it declared to
/// the group (`mapping_id`, never 0) followed by `suffix`, or the literal (`mapping_id` 0 and
/// the whole key as `suffix`). zenoh-pico names a key by a declaration on its group only when
/// its multicast declarations are on, and by the literal otherwise
/// (`vendor/zenoh-pico/src/session/keyexpr.c` @ `#if Z_FEATURE_MULTICAST_DECLARATIONS == 0`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GroupKey<'a> {
    /// The declaration the key starts with, `0` for none.
    pub mapping_id: crate::wire_id::ExprId,
    /// What follows the declaration; the whole key when `mapping_id` is 0, `None` when the
    /// declaration covers the whole key.
    pub suffix: Option<&'a str>,
}

impl<'a> GroupKey<'a> {
    /// The literal `keyexpr`, no declaration.
    pub const fn literal(keyexpr: &'a str) -> Self {
        Self {
            mapping_id: 0,
            suffix: Some(keyexpr),
        }
    }
}

/// R2962 — HOW a matching Interest names its key and what it asks of the peer, for a caller that
/// is not an engine's own declared publisher or querier.
///
/// Those ask in one fixed way: the literal keyexpr, no aggregate. A declaring C ABI asks in the
/// way its reference library does — zenoh-pico's write filter names the entity's own DECLARED key
/// (`mapping_id` plus the rest of the key as `suffix`) and, as a client, asks for aggregated
/// answers (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_create`). The session has
/// no opinion about that, so the ABI hands it in.
#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterestForm {
    /// The keyexpr declaration the Interest names, `0` for none.
    pub mapping_id: crate::wire_id::ExprId,
    /// What follows the declared prefix; the whole literal when `mapping_id` is 0.
    pub suffix: Option<String>,
    /// Ask the peer to answer aggregated (see
    /// [`build_interest_kinds_with_aggregate`](crate::interest_build::build_interest_kinds_with_aggregate)).
    pub aggregate: bool,
}

/// An [`InterestForm`] lent for one call: the rest of the key is read where the caller holds it,
/// so a declaration that names its key from its own text hands it over without a copy, and an
/// engine copies it only where it keeps one of its own.
#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterestAsk<'a> {
    /// The keyexpr declaration the Interest names, `0` for none.
    pub mapping_id: crate::wire_id::ExprId,
    /// What follows the declared prefix; the whole literal when `mapping_id` is 0.
    pub suffix: Option<&'a str>,
    /// Ask the peer to answer aggregated, as [`InterestForm::aggregate`].
    pub aggregate: bool,
}

#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
impl InterestAsk<'_> {
    /// The form an engine keeps of this ask, the rest of the key copied.
    pub fn to_form(self) -> InterestForm {
        InterestForm {
            mapping_id: self.mapping_id,
            suffix: self.suffix.map(String::from),
            aggregate: self.aggregate,
        }
    }
}

#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
impl InterestForm {
    /// This form lent as an ask, for an engine that is handed one.
    pub fn as_ask(&self) -> InterestAsk<'_> {
        InterestAsk {
            mapping_id: self.mapping_id,
            suffix: self.suffix.as_deref(),
            aggregate: self.aggregate,
        }
    }
}

#[cfg(test)]
mod retraction_tests {
    use super::RetractionKey;

    /// A literal names the whole key; a declaration names its id and the end of the key it was
    /// made from, read against the key it is handed with, an empty rest included.
    ///
    /// # Control
    ///
    /// Reading the rest from the front of the key reds the second assertion.
    #[test]
    fn a_retraction_names_the_rest_of_the_key_it_is_read_against() {
        let key = "demo/example/**";
        assert_eq!(RetractionKey::literal().names(key), (0, key));
        assert_eq!(RetractionKey::declared(4, "/**").names(key), (4, "/**"));
        assert_eq!(RetractionKey::declared(4, "").names(key), (4, ""));
        assert_eq!(RetractionKey::declared(0, "/**").names(key), (0, key));
    }

    /// A key the rest does not end is named whole: one shorter than the rest, and one the rest
    /// would cut inside a character.
    #[test]
    fn a_key_the_rest_does_not_end_is_named_whole() {
        let short = RetractionKey::declared(9, "/a/b/c/d");
        assert_eq!(short.names("x"), (0, "x"));
        let cut = RetractionKey::declared(9, "b");
        assert_eq!(cut.names("aé"), (0, "aé"));
    }
}

#[cfg(all(test, feature = "session-matching", feature = "declare-interest"))]
mod tests {
    use super::*;

    /// A form lent as an ask and kept again is the form it was, with a rest of the key or none.
    #[test]
    fn a_form_lent_as_an_ask_is_kept_as_the_same_form() {
        for form in [
            InterestForm {
                mapping_id: 7,
                suffix: Some(String::from("/tail")),
                aggregate: true,
            },
            InterestForm {
                mapping_id: 7,
                suffix: None,
                aggregate: false,
            },
        ] {
            let ask = form.as_ask();
            assert_eq!(ask.suffix, form.suffix.as_deref());
            assert_eq!(ask.to_form(), form);
        }
    }
}
