// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requester-side reply-keyexpr contract: which replies a pending z_get
//! is willing to deliver to its caller.
//!
//! zenoh states this as a GUARANTEE of `get()` itself — "Unless explicitly
//! requested via `accept_replies`, replies are guaranteed to have key
//! expressions that match the requested selector"
//! (`zenoh/src/api/session.rs:1181`) — and enforces it in the response
//! dispatcher: `if c && !query.key_expr.intersects(&key_expr) { .. return }`
//! where `c` is `!query.parameters.reply_key_expr_any()`
//! (`zenoh/src/api/session.rs:2845-2854`). zenoh-pico enforces the same rule
//! at the same place, `if (!pen_qry->_anyke && !_z_keyexpr_intersects(
//! &pen_qry->_key, keyexpr))` (`vendor/zenoh-pico/src/session/query.c:121`),
//! and does so BEFORE its consolidation step (`:130`) — which is what pins the
//! ordering wz uses: the acceptance gate runs at the pending-table fan, ahead
//! of the [`crate::reply_sink::ConsolidatingSink`] decorator, so a reply the
//! caller may not see cannot displace one it may.
//!
//! WHY THE STATE IS THE SELECTOR PARAMETERS AND NOT A SEPARATE FLAG. `_anyke`
//! is not a wire field. Both upstreams carry the opt-out as a bare selector
//! PARAMETER ([`crate::selector_params::ANYKE_PARAM`]) so that ONE value
//! answers both sides of the exchange: the responder learns it by parsing the
//! parameters it received, and the requester's own gate reads the same list
//! back. pico spells the derivation out —
//! `pq->_anyke = _anyke_in_parameters || _anyke_option`
//! (`vendor/zenoh-pico/src/net/primitives.c:598`) — so a caller that wrote
//! `_anyke` into its parameters by hand and one that asked for
//! `ReplyKeyExpr::Any` are the same caller. Deriving the mode from the
//! parameters rather than storing a second flag is what keeps them so.
//!
//! (The two names above are code spans, not intra-doc links, and so are the
//! ones below: a `//!` module doc paired with a `///` doc on the `pub mod`
//! declaration resolves its links in the DECLARATION's scope, where this
//! module's own items are not named — the R311y819 / R311y825 C1bz class.)
//!
//! Err replies are NEVER gated, on either upstream: zenoh's `ResponseBody::Err`
//! arm calls the callback directly and never reaches the intersection check
//! (`session.rs:2790-2825`), and it cannot — an Err result carries no keyexpr
//! of its own to test. See `ReplyAcceptanceStored::admits`.

use crate::bounded::BoundedString;
use crate::caps;
use crate::keyexpr_match;
use crate::reply_sink::{ReplyKind, ReplyView};

/// The kind of reply key expressions a get accepts. Mirrors zenoh's
/// `ReplyKeyExpr` (`zenoh/src/api/query.rs:195-201`) and pico's
/// `z_reply_keyexpr_t` (`vendor/zenoh-pico/include/zenoh-pico/api/constants.h`).
///
/// [`Self::MatchingQuery`] is the default on BOTH upstreams and is the one wz
/// inherits: a caller who asks for nothing gets the guarantee.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ReplyKeyExpr {
    /// `Z_REPLY_KEYEXPR_ANY` — deliver every reply correlated to the request
    /// id, whatever it is keyed on. The opt-out, and it must be REQUESTED:
    /// it travels as the bare `_anyke` selector parameter so the responder
    /// side stops refusing such replies too.
    Any,
    /// `Z_REPLY_KEYEXPR_MATCHING_QUERY` — deliver only replies whose keyexpr
    /// intersects the queried keyexpr. The default.
    #[default]
    MatchingQuery,
}

impl ReplyKeyExpr {
    /// Read the mode a selector-parameter list expresses. The presence of the
    /// bare [`crate::selector_params::ANYKE_PARAM`] token is the whole
    /// encoding — pico's `_z_parameters_has_anyke`, zenoh's
    /// `Parameters::reply_key_expr_any`.
    pub fn from_parameters(parameters: &str) -> Self {
        if crate::selector_params::has_param(parameters, crate::selector_params::ANYKE_PARAM) {
            Self::Any
        } else {
            Self::MatchingQuery
        }
    }
}

/// What a pending registration is told about the query it belongs to, borrowed
/// at the call. The owned counterpart lives inside the pending entry
/// (`ReplyAcceptanceStored`, private); the borrowed/owned split is the R311y808 shape
/// — the caller states a policy, the table decides how to keep it.
///
/// Registration takes this by value and REQUIRES it: there is no shorter
/// overload that skips the gate. A caller that genuinely accepts anything says
/// [`Self::Any`], and that reads as the decision it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyAcceptance<'a> {
    /// No keyexpr gate — [`ReplyKeyExpr::Any`].
    Any,
    /// Gate every Put / Del reply on intersection with this keyexpr —
    /// [`ReplyKeyExpr::MatchingQuery`], the upstream default.
    Matching(&'a str),
}

impl<'a> ReplyAcceptance<'a> {
    /// Resolve `(queried keyexpr, mode)` into the policy the pending table
    /// stores. The one place the two axes meet, so a caller cannot pair
    /// [`ReplyKeyExpr::Any`] with a keyexpr and expect the keyexpr to matter.
    pub fn for_query(keyexpr: &'a str, mode: ReplyKeyExpr) -> Self {
        match mode {
            ReplyKeyExpr::Any => Self::Any,
            ReplyKeyExpr::MatchingQuery => Self::Matching(keyexpr),
        }
    }

    /// The stored form, or [`crate::registry_error::RegisterError::KeyexprTooLong`]
    /// when the queried keyexpr exceeds [`caps::MAX_KEYEXPR_BYTES`] on a
    /// no-alloc backing.
    ///
    /// Refusing is the only sound answer there: a truncated keyexpr would gate
    /// on a DIFFERENT expression than the one queried, and would do it in the
    /// dropping direction — silently withholding replies the caller is owed.
    /// The subscriber / queryable registries already refuse an over-long
    /// pattern at register time for the same reason.
    pub(crate) fn store(
        self,
    ) -> Result<ReplyAcceptanceStored, crate::registry_error::RegisterError> {
        let mut stored = ReplyAcceptanceStored {
            mode: ReplyKeyExpr::Any,
            keyexpr: BoundedString::new(),
        };
        if let Self::Matching(keyexpr) = self {
            stored.mode = ReplyKeyExpr::MatchingQuery;
            stored
                .keyexpr
                .push_str(keyexpr)
                .map_err(|_| crate::registry_error::RegisterError::KeyexprTooLong)?;
        }
        Ok(stored)
    }
}

/// The owned policy a [`crate::reply::ReplyRegistry`] pending entry keeps —
/// pico's `_z_pending_query_t::{_key, _anyke}` pair, and deliberately in pico's
/// own shape: TWO FIELDS, not a sum type.
///
/// R311y833 — the first cut made this an `enum { Any, Matching(BoundedString) }`
/// and `clippy::large_enum_variant` refused it on the profile that matters.
/// With `alloc` a [`BoundedString`] is a 24-byte heap handle and the disparity
/// is invisible; with NO alloc it is a 264-byte inline buffer beside a
/// data-less `Any`, so `--no-default-features` was the only build that could
/// see it — and Layer C1cf, which is exactly that build, is where it surfaced.
/// The struct form is the same size as the enum's largest variant, so nothing
/// is paid for the change, and it is closer to the upstream it ports.
#[derive(Debug)]
pub(crate) struct ReplyAcceptanceStored {
    /// pico's `_anyke`. [`ReplyKeyExpr::Any`] leaves `keyexpr` empty and unread.
    mode: ReplyKeyExpr,
    /// pico's `_key` — the expression the query was asked under. Empty and
    /// meaningless when `mode` is [`ReplyKeyExpr::Any`].
    keyexpr: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
}

impl ReplyAcceptanceStored {
    /// Whether this pending registration may deliver `reply` to its caller.
    ///
    /// Three arms, and the Err one is not an afterthought: an Err reply is
    /// admitted unconditionally because upstream admits it unconditionally.
    /// zenoh reaches its callback from a disjoint `ResponseBody::Err` arm that
    /// never runs the intersection test, and an Err result has no keyexpr to
    /// test against in the first place — gating it would invent a refusal
    /// neither upstream performs and would swallow the error a caller is
    /// waiting on.
    pub(crate) fn admits(&self, reply: &dyn ReplyView) -> bool {
        if self.mode == ReplyKeyExpr::Any {
            return true;
        }
        if reply.kind() == ReplyKind::Err {
            return true;
        }
        reply_keyexpr_intersects(self.keyexpr.as_str(), reply.keyexpr())
    }
}

/// Does a reply keyed `reply` belong to a query asked under `query_keyexpr`?
///
/// INTERSECTION, never string equality. The keyexpr a query is asked under is
/// routinely a PATTERN (`a/**`) while its replies carry CONCRETE keys, so
/// equality would reject the ordinary wildcard case rather than an edge one.
/// Routed through the one matching SSOT ([`keyexpr_match`]) so this cannot
/// drift from the subscriber and queryable planes.
///
/// This is the SSOT `wz-capi-pico`'s C-ABI responder gate delegates to. Before
/// R311y833 that gate was a `pub(crate)` copy inside `wz-capi-pico`, which left
/// one codebase with two getters and opposite default behaviour: the C ABI
/// enforced the contract and the native Rust `Session::query` did not.
/// The query side is split into a STACK buffer rather than a heap `Vec<&str>`
/// so the gate stays `no_alloc`: this runs once per pending entry per inbound
/// reply, and a per-message allocation is not available on the MCU profile at
/// all. A query deeper than [`keyexpr_match::MAX_KEYEXPR_CHUNKS`] is
/// conservatively a non-match on that backing, the same rule every other scan
/// in [`keyexpr_match`] takes; the alloc backing grows past the bound.
pub fn reply_keyexpr_intersects(query_keyexpr: &str, reply: &str) -> bool {
    let mut query_chunks: crate::bounded::BoundedVec<&str, { keyexpr_match::MAX_KEYEXPR_CHUNKS }> =
        crate::bounded::BoundedVec::new();
    for chunk in query_keyexpr.split('/') {
        if query_chunks.push(chunk).is_err() {
            return false;
        }
    }
    keyexpr_match::keyexpr_intersects_target(reply, &query_chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector_params::ANYKE_PARAM;

    #[test]
    fn the_default_mode_is_the_guarantee_not_the_opt_out() {
        assert_eq!(ReplyKeyExpr::default(), ReplyKeyExpr::MatchingQuery);
    }

    #[test]
    fn anyke_in_the_parameters_is_what_selects_any() {
        assert_eq!(
            ReplyKeyExpr::from_parameters(ANYKE_PARAM),
            ReplyKeyExpr::Any
        );
        assert_eq!(
            ReplyKeyExpr::from_parameters("_max=5;_anyke"),
            ReplyKeyExpr::Any
        );
        assert_eq!(
            ReplyKeyExpr::from_parameters("_max=5"),
            ReplyKeyExpr::MatchingQuery
        );
        assert_eq!(
            ReplyKeyExpr::from_parameters(""),
            ReplyKeyExpr::MatchingQuery
        );
        // The boundary rules are load-bearing: a parameter that merely
        // CONTAINS the token is not the flag.
        assert_eq!(
            ReplyKeyExpr::from_parameters("no_anyke"),
            ReplyKeyExpr::MatchingQuery
        );
        assert_eq!(
            ReplyKeyExpr::from_parameters("_anykey=1"),
            ReplyKeyExpr::MatchingQuery
        );
    }

    /// The literal case, true on EVERY subset: this is what the gate reduces to
    /// on a build that composes no wildcard atom at all.
    #[test]
    fn a_literal_query_intersects_only_its_own_key() {
        assert!(reply_keyexpr_intersects("demo/a", "demo/a"));
        assert!(!reply_keyexpr_intersects("demo/a", "demo/b"));
        assert!(!reply_keyexpr_intersects("demo/a", "other/a"));
    }

    /// The pattern case, and it is gated on the atoms that make a pattern a
    /// pattern — because on a build without them, it is NOT one.
    #[cfg(all(
        feature = "keyexpr-wildcard-double",
        feature = "keyexpr-wildcard-single"
    ))]
    #[test]
    fn a_pattern_query_intersects_a_concrete_reply() {
        assert!(reply_keyexpr_intersects("demo/**", "demo/a/b"));
        assert!(reply_keyexpr_intersects("demo/*", "demo/a"));
        assert!(!reply_keyexpr_intersects("demo/**", "other/a"));
    }

    /// R311y833 — THE COMPOSITION CONSEQUENCE, PINNED RATHER THAN LEFT SILENT.
    ///
    /// This gate judges a reply by THIS BUILD's matching rules, and a build that
    /// composes no `keyexpr-wildcard-double` has no `**` arm at all
    /// (`keyexpr_match.rs:161`) — the token is an ordinary chunk. So a node
    /// configured without that atom, which nevertheless asks a peer for
    /// `demo/**`, will REFUSE the peer's perfectly correct `demo/a/b` reply.
    ///
    /// That is deliberate and consistent rather than an oversight: the same
    /// narrowing already governs every other plane in such a build — its own
    /// subscribers on `demo/**` do not fire either, and its queryable table does
    /// not match. A gate that used wider rules than the rest of the build would
    /// admit replies that build considers unrelated, and would link the very
    /// matcher the atom exists to leave out. It IS a real divergence from
    /// upstream, which has no such axis, and it is named here rather than in
    /// prose so a future round finds it as a failing assertion if the semantics
    /// move.
    #[cfg(not(feature = "keyexpr-wildcard-double"))]
    #[test]
    fn without_the_wildcard_atom_a_double_star_query_is_a_literal_key() {
        assert!(!reply_keyexpr_intersects("demo/**", "demo/a/b"));
        assert!(reply_keyexpr_intersects("demo/**", "demo/**"));
    }

    #[test]
    fn for_query_drops_the_keyexpr_when_the_mode_is_any() {
        assert_eq!(
            ReplyAcceptance::for_query("demo/**", ReplyKeyExpr::Any),
            ReplyAcceptance::Any
        );
        assert_eq!(
            ReplyAcceptance::for_query("demo/**", ReplyKeyExpr::MatchingQuery),
            ReplyAcceptance::Matching("demo/**")
        );
    }
}
