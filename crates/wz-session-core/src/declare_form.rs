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

use alloc::string::String;

/// The key an entity's `Undeclare*` names beside its id, in the wire form it is held under: a
/// declared prefix's id and the rest of the key, or `0` and the whole literal. A subscriber's
/// retraction and a queryable's take the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetractionKey {
    /// The prefix's mapping id, or `0` for a literal.
    pub mapping_id: crate::wire_id::ExprId,
    /// The rest of the key after the prefix; the whole key when `mapping_id` is `0`.
    pub suffix: String,
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
