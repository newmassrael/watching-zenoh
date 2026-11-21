// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `wz/limits` members every door that reads a document is held to, and what each kind of
//! creator resolves each one to: the limits it selects, or the refusals it meets. A door's tests
//! hand every case to the door and compare what the session it opens runs under, or the refusal,
//! with the case, so that every door reads one member as
//! [`resolve_document`](crate::policy_document::resolve_document) reads it.
//!
//! What a case expects is worked out for the build it runs in. A limit whose domain is one value
//! ([`LimitDomain::is_singleton`]) refuses every value but the build's own, so a case that states
//! another value expects that refusal there and the selection everywhere else.
//!
//! Support for the tests of the doors, which live in other crates and so reach it as a public
//! module; it is no part of the crate's interface.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::limit_binding::{
    LimitDomain, LimitEntry, LimitSpec, LimitValue, Outside, Quota, UNBOUNDED,
};
use crate::limits::{
    MaxSubscriptions, RuntimeLimits, SessionLimits, RUNTIME_LIMITS, SESSION_LIMITS,
};
use crate::policy_binding::{LimitKind, Scope};
use crate::policy_document::{Origin, Reason, Refusal};

/// What a creator resolves a case's member to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// The member is taken: each limit named holds the value beside it, and every other limit
    /// the build default.
    Selected(Vec<(&'static str, LimitValue)>),
    /// The member is refused, for these reasons, in the order the resolution finds them.
    Refused(Vec<Reason<'static>>),
}

impl Expected {
    /// Whether the member is taken.
    pub fn is_selected(&self) -> bool {
        matches!(self, Self::Selected(_))
    }

    /// The limits the member selects, each with its value; none for a refused member.
    pub fn selected(&self) -> &[(&'static str, LimitValue)] {
        match self {
            Self::Selected(selected) => selected,
            Self::Refused(_) => &[],
        }
    }

    /// `Ok` when `session` holds the value the member selects for each limit of a session and
    /// the build default for every other; otherwise the first limit that differs, as a sentence.
    /// A refused member makes no snapshot, so any snapshot is an `Err` here.
    pub fn check_session(&self, session: &SessionLimits) -> Result<(), String> {
        self.check(&SESSION_LIMITS, &SessionLimits::defaults(), session)
    }

    /// [`Self::check_session`] for the limits of a runtime.
    pub fn check_runtime(&self, runtime: &RuntimeLimits) -> Result<(), String> {
        self.check(&RUNTIME_LIMITS, &RuntimeLimits::defaults(), runtime)
    }

    fn check<S: 'static>(
        &self,
        table: &[LimitEntry<S>],
        defaults: &S,
        held: &S,
    ) -> Result<(), String> {
        let selected = match self {
            Self::Selected(selected) => selected,
            Self::Refused(reasons) => {
                return Err(format!(
                    "the case expects the refusals {reasons:?}, and a snapshot was made"
                ))
            }
        };
        for entry in table {
            let id = entry.id();
            let want = selected
                .iter()
                .find(|(limit, _)| *limit == id)
                .map_or_else(|| entry.value_in(defaults), |(_, value)| *value);
            let got = entry.value_in(held);
            if got != want {
                return Err(format!("`{id}` holds {got}, and the case expects {want}"));
            }
        }
        Ok(())
    }

    /// The sentences a door that names each refusal says for the member read from a document:
    /// each reason, in the document's layer. None for a member that is taken.
    pub fn refusal_texts(&self) -> Vec<String> {
        match self {
            Self::Selected(_) => Vec::new(),
            Self::Refused(reasons) => reasons
                .iter()
                .map(|reason| {
                    let refusal = Refusal {
                        layer: Origin::Document,
                        reason: *reason,
                    };
                    format!("{refusal}")
                })
                .collect(),
        }
    }
}

/// One case: a `wz/limits` member, and what each kind of creator resolves it to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitCase {
    /// What the member states, as a failure names the case.
    pub name: &'static str,
    /// The `wz/limits` member, as JSON5 text.
    pub limits: String,
    /// What a creator that holds the limits of a session alone resolves the member to
    /// ([`Base::session`](crate::policy_document::Base::session)).
    pub session: Expected,
    /// What a node, which holds the limits of a runtime too, resolves the member to
    /// ([`Base::node`](crate::policy_document::Base::node)).
    pub node: Expected,
}

impl LimitCase {
    /// The `wz` member that states the case's `wz/limits` and nothing else.
    pub fn wz_member(&self) -> String {
        format!("{{ limits: {} }}", self.limits)
    }

    /// A document whose one member is the case's `wz` member.
    pub fn document(&self) -> String {
        format!("{{ wz: {} }}", self.wz_member())
    }
}

/// Every case, each worked out for this build.
///
/// The cases that select a value state `MAX_SUBSCRIPTIONS`, a bound the machines of a session
/// read from the snapshot. A limit whose machines still read the build's value is refused by name
/// wherever it is stated, so the cases that state one take it from the tables: the first such
/// limit of a session and of a runtime, while there is one. A runtime's limit its machines read is
/// stated the same way, while there is one, and only a node takes it.
pub fn cases() -> Vec<LimitCase> {
    const SUBS: &str = MaxSubscriptions::LIMIT;
    // The build's value, which the snapshot of the build defaults holds.
    let subs = MaxSubscriptions::DEFAULT.as_value();
    let domain = MaxSubscriptions::DOMAIN;
    let (other_subs, subs_restated) = restated(SUBS, LimitKind::Bound, domain, subs);
    let unknown = Reason::UnknownLimit {
        limit: "NO_SUCH_LIMIT",
    };
    let mut cases = vec![
        alike(
            "no limit",
            String::from("{}"),
            Expected::Selected(Vec::new()),
        ),
        // The build's own value is taken whatever its domain, a domain of one value included.
        alike(
            "a limit of a session at the build's value",
            format!("{{ {SUBS}: {} }}", json5_value(subs)),
            Expected::Selected(vec![(SUBS, subs)]),
        ),
        alike(
            "a limit of a session at another value",
            format!("{{ {SUBS}: {} }}", json5_value(other_subs)),
            subs_restated,
        ),
        // A bound of `0` would admit nothing, whatever the build's domain holds.
        alike(
            "a bound stated as zero",
            format!("{{ {SUBS}: 0 }}"),
            refused(Reason::LimitOutsideDomain {
                limit: SUBS,
                value: LimitValue::Integer(0),
                why: Outside::Below { least: 1 },
            }),
        ),
        // A bound's `unbounded` is taken where the build sized no storage by it, and refused
        // where it did or keeps its own value alone.
        alike(
            "unbounded for a bound of a session",
            format!("{{ {SUBS}: \"{UNBOUNDED}\" }}"),
            match domain.check(LimitValue::Unbounded) {
                Ok(()) => Expected::Selected(vec![(SUBS, LimitValue::Unbounded)]),
                Err(why) => refused(Reason::LimitOutsideDomain {
                    limit: SUBS,
                    value: LimitValue::Unbounded,
                    why,
                }),
            },
        ),
        alike(
            "a limit the build does not have",
            String::from("{ NO_SUCH_LIMIT: 1 }"),
            refused(unknown),
        ),
        alike(
            "a limit only the build decides",
            String::from("{ MAX_TASKS: 4 }"),
            refused(Reason::LimitBuildOnly { limit: "MAX_TASKS" }),
        ),
        alike(
            "a value that is no whole number",
            format!("{{ {SUBS}: true }}"),
            refused(Reason::NotALimitValue { limit: SUBS }),
        ),
        // One refusal refuses the member whole: the limit beside it is selected nowhere.
        alike(
            "a refused limit beside one the build takes",
            format!("{{ {SUBS}: {}, NO_SUCH_LIMIT: 1 }}", json5_value(subs)),
            refused(unknown),
        ),
    ];
    // Past the most the build's domain allows: past its capacity, or, where the domain is one
    // value, another value than that one. A bound the build sized no storage by has no such
    // count: the one past the largest is the quota no bound is held as.
    if let Some(past) = past(domain) {
        cases.push(alike(
            "a limit of a session past its domain",
            format!("{{ {SUBS}: {past} }}"),
            refused(outside(SUBS, domain, LimitValue::Integer(past))),
        ));
    }
    // Refused by name before its scope or its value is asked, whatever the creator holds.
    let session = SessionLimits::defaults();
    if let Some(entry) = SESSION_LIMITS
        .iter()
        .find(|entry| !entry.read_from_snapshot())
    {
        let limit = entry.id();
        cases.push(alike(
            "a limit of a session no machine reads",
            format!("{{ {limit}: {} }}", json5_value(entry.value_in(&session))),
            refused(Reason::LimitNotRead { limit }),
        ));
    }
    let runtime = RuntimeLimits::defaults();
    if let Some(entry) = RUNTIME_LIMITS
        .iter()
        .find(|entry| !entry.read_from_snapshot())
    {
        let limit = entry.id();
        cases.push(alike(
            "a limit of a runtime no machine reads",
            format!("{{ {limit}: {} }}", json5_value(entry.value_in(&runtime))),
            refused(Reason::LimitNotRead { limit }),
        ));
    }
    // Refused by its scope before its value is read, whatever the value.
    if let Some(entry) = RUNTIME_LIMITS
        .iter()
        .find(|entry| entry.read_from_snapshot())
    {
        let limit = entry.id();
        let held = entry.value_in(&runtime);
        let (other, node) = restated(limit, entry.kind(), entry.domain(), held);
        cases.push(LimitCase {
            name: "a limit of a runtime at another value",
            limits: format!("{{ {limit}: {} }}", json5_value(other)),
            session: refused(Reason::LimitWrongScope {
                limit,
                scope: Scope::Runtime,
            }),
            node,
        });
    }
    cases
}

/// `value` as a member of `wz/limits` states it: the number, or `unbounded` as a string.
pub fn json5_value(value: LimitValue) -> String {
    match value {
        LimitValue::Unbounded => format!("\"{UNBOUNDED}\""),
        LimitValue::Integer(value) => format!("{value}"),
    }
}

/// A case every creator resolves alike.
fn alike(name: &'static str, limits: String, expected: Expected) -> LimitCase {
    LimitCase {
        name,
        limits,
        session: expected.clone(),
        node: expected,
    }
}

fn refused(reason: Reason<'static>) -> Expected {
    Expected::Refused(vec![reason])
}

/// A value of the limit `limit` other than `held`, the build's, and what a creator that holds
/// its snapshot resolves a statement of it to: the value selected, or, where the build's domain
/// holds no other value a layer may state, the refusal of the next one, which names why.
fn restated(
    limit: &'static str,
    kind: LimitKind,
    domain: LimitDomain,
    held: LimitValue,
) -> (LimitValue, Expected) {
    let neighbours = match held {
        LimitValue::Integer(value) => [value.checked_add(1), value.checked_sub(1)],
        LimitValue::Unbounded => [Some(1), Some(2)],
    };
    // A bound of `0` is refused whatever the domain holds.
    let stateable = |value: usize| {
        let value = LimitValue::Integer(value);
        value != held
            && domain.contains(value)
            && !(kind == LimitKind::Bound && value == LimitValue::Integer(0))
    };
    if let Some(other) = neighbours
        .into_iter()
        .flatten()
        .find(|value| stateable(*value))
    {
        let other = LimitValue::Integer(other);
        return (other, Expected::Selected(vec![(limit, other)]));
    }
    let other = LimitValue::Integer(match held {
        LimitValue::Integer(value) => value.saturating_add(1),
        LimitValue::Unbounded => 1,
    });
    (other, refused(outside(limit, domain, other)))
}

/// The count one past the most `domain` allows, where that count is not the quota no bound is
/// held as.
fn past(domain: LimitDomain) -> Option<usize> {
    domain
        .integers()
        .and_then(|(_, most)| most.checked_add(1))
        .filter(|past| !Quota::at_most(*past).is_unbounded())
}

/// The refusal of `value` for the limit `limit`, whose domain leaves it out.
fn outside(limit: &'static str, domain: LimitDomain, value: LimitValue) -> Reason<'static> {
    match domain.check(value) {
        Err(why) => Reason::LimitOutsideDomain { limit, value, why },
        Ok(()) => panic!("the domain of `{limit}` holds `{value}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json5::parse;
    use crate::policy::SessionPolicy;
    use crate::policy_document::{resolve_document, Base};
    use std::string::ToString;

    /// Each case is what the reader of a document resolves its document to, for a creator that
    /// holds a session's limits alone and for a node: the limits it selects, from the document,
    /// over the build defaults, or the refusals it meets, in their order and with their words.
    #[test]
    fn each_case_is_what_the_reader_of_a_document_resolves_it_to() {
        let policy = SessionPolicy::defaults();
        for case in cases() {
            let document = case.document();
            let tree = parse(&document).expect("each case is JSON5");
            for (base, expected) in [
                (Base::session(policy), &case.session),
                (Base::node(policy), &case.node),
            ] {
                let name = case.name;
                match (resolve_document(base, &tree), expected) {
                    (Ok(resolved), Expected::Selected(selected)) => {
                        let limits = resolved.limits;
                        expected
                            .check_session(&limits.session)
                            .unwrap_or_else(|why| panic!("{name}: {why}"));
                        expected
                            .check_runtime(&limits.runtime)
                            .unwrap_or_else(|why| panic!("{name}: {why}"));
                        for (limit, _) in selected {
                            assert_eq!(
                                limits.provenance.origin(limit),
                                Some(Origin::Document),
                                "{name}: {limit}"
                            );
                        }
                        assert_eq!(resolved.policy, policy, "{name}");
                    }
                    (Err(refusals), Expected::Refused(reasons)) => {
                        let found: Vec<Reason<'_>> =
                            refusals.iter().map(|refusal| refusal.reason).collect();
                        assert_eq!(found, *reasons, "{name}");
                        let texts: Vec<String> = refusals.iter().map(ToString::to_string).collect();
                        assert_eq!(texts, expected.refusal_texts(), "{name}");
                    }
                    (Ok(_), Expected::Refused(reasons)) => {
                        panic!("{name}: taken, and the case expects {reasons:?}")
                    }
                    (Err(refusals), Expected::Selected(_)) => {
                        panic!("{name}: refused, and the case expects it taken: {refusals}")
                    }
                }
            }
        }
    }

    /// A check finds a snapshot that differs from the case in one limit, and a snapshot made for
    /// a refused case.
    #[test]
    fn a_check_names_the_limit_a_snapshot_holds_apart_from_the_case() {
        let nothing = Expected::Selected(Vec::new());
        assert_eq!(nothing.check_session(&SessionLimits::defaults()), Ok(()));
        assert_eq!(nothing.check_runtime(&RuntimeLimits::defaults()), Ok(()));
        let other = match SessionLimits::defaults().max_subscriptions().most() {
            Some(most) => LimitValue::Integer(most + 1),
            None => LimitValue::Integer(1),
        };
        let apart = Expected::Selected(vec![("MAX_SUBSCRIPTIONS", other)]);
        let why = apart
            .check_session(&SessionLimits::defaults())
            .expect_err("the snapshot holds the build's value");
        assert!(why.starts_with("`MAX_SUBSCRIPTIONS` holds"), "{why}");
        let unknown = refused(Reason::UnknownLimit {
            limit: "NO_SUCH_LIMIT",
        });
        assert!(unknown.check_session(&SessionLimits::defaults()).is_err());
        assert!(!unknown.is_selected());
        assert!(unknown.selected().is_empty());
        assert_eq!(
            unknown.refusal_texts(),
            [
                "the document states the limit `NO_SUCH_LIMIT`, and the build has no limit \
              `NO_SUCH_LIMIT`"
            ]
        );
    }

    /// Every case names the creator kinds apart only where a runtime's limit its machines read is
    /// stated, and a build whose domain of a limit is one value expects the refusal of another.
    #[test]
    fn a_domain_of_one_value_expects_the_refusal_of_another() {
        let all = cases();
        let find = |name: &str| all.iter().find(|case| case.name == name);
        let another = find("a limit of a session at another value").expect("declared");
        assert_eq!(
            another.session.is_selected(),
            !MaxSubscriptions::DOMAIN.is_singleton()
        );
        let read = RUNTIME_LIMITS
            .iter()
            .find(|entry| entry.read_from_snapshot());
        let runtime = find("a limit of a runtime at another value");
        assert_eq!(runtime.is_some(), read.is_some());
        if let (Some(runtime), Some(entry)) = (runtime, read) {
            assert!(!runtime.session.is_selected());
            assert_eq!(runtime.node.is_selected(), !entry.domain().is_singleton());
        }
        for case in &all {
            if Some(case) != runtime {
                assert_eq!(case.session, case.node, "{}", case.name);
            }
        }
    }

    /// Every limit a case selects is one whose machines read it from the snapshot: a case never
    /// expects a value to be taken that no machine would read.
    #[test]
    fn every_limit_a_case_selects_is_read_from_the_snapshot() {
        let read = |limit: &str| {
            SESSION_LIMITS
                .iter()
                .any(|entry| entry.id() == limit && entry.read_from_snapshot())
                || RUNTIME_LIMITS
                    .iter()
                    .any(|entry| entry.id() == limit && entry.read_from_snapshot())
        };
        assert!(read(MaxSubscriptions::LIMIT));
        for case in cases() {
            for &(limit, _) in case.session.selected().iter().chain(case.node.selected()) {
                assert!(read(limit), "{}: {limit}", case.name);
            }
        }
    }

    /// While a limit of a session or of a runtime is one whose machines read the build's value,
    /// a case states it, and every creator refuses it by name.
    #[test]
    fn a_limit_no_machine_reads_is_refused_by_name_at_every_base() {
        let all = cases();
        let tables = [
            (
                "a limit of a session no machine reads",
                SESSION_LIMITS
                    .iter()
                    .find(|entry| !entry.read_from_snapshot())
                    .map(LimitEntry::id),
            ),
            (
                "a limit of a runtime no machine reads",
                RUNTIME_LIMITS
                    .iter()
                    .find(|entry| !entry.read_from_snapshot())
                    .map(LimitEntry::id),
            ),
        ];
        for (name, unread) in tables {
            let case = all.iter().find(|case| case.name == name);
            assert_eq!(case.is_some(), unread.is_some(), "{name}");
            if let (Some(case), Some(limit)) = (case, unread) {
                let expected = refused(Reason::LimitNotRead { limit });
                assert_eq!(case.session, expected, "{name}");
                assert_eq!(case.node, expected, "{name}");
                assert!(case.limits.contains(limit), "{name}");
            }
        }
    }

    /// A value is written as a member of `wz/limits` states it, which the reader reads back.
    #[test]
    fn a_value_is_written_as_the_reader_reads_it() {
        assert_eq!(json5_value(LimitValue::Integer(16)), "16");
        assert_eq!(json5_value(LimitValue::Unbounded), "\"unbounded\"");
    }
}
