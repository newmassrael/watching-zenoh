// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The open stage of the policies: the values a document states, composed in layers over the
//! snapshot a creator starts from, into one snapshot and where each of its values came from.
//!
//! # Layers
//!
//! A creator resolves its snapshot from layers, the lowest first, a later one overriding an
//! earlier one:
//!
//! 1. the snapshot it starts from, the build defaults ([`Origin::BuildDefault`]);
//! 2. a named profile, a set of policy values the declaration states (`[[profile]]` of
//!    `deploy/wz-config.toml`, generated into `PROFILES`), which the document names by
//!    `wz/profile` ([`Origin::Profile`]);
//! 3. the document's own `wz/policies` members ([`Origin::Document`]);
//! 4. what the open's caller states beside the document ([`Origin::Api`]).
//!
//! [`resolve`] takes the layers as a slice, so a caller states the ones it has.
//!
//! # All or nothing
//!
//! Every statement of every layer is checked: that its policy exists, that the layer states it
//! once, that a stage after the build may decide it, that it names a value of the policy, and
//! that the build's domain allows that value, which the field's `select_*` decides. The layers
//! are composed into a snapshot of the resolver's own, which the caller gets only when no
//! statement was refused: one refusal refuses the whole document, and a partly applied
//! configuration never reaches a creator. Every refusal found is reported, up to
//! [`MAX_REPORTED`], with a count of the rest ([`Refusals`]), so the core needs no heap.
//!
//! # The document
//!
//! With `alloc`, `statements_from_json5` reads the `wz` member of a parsed JSON5 document (the
//! zenoh configuration a node is opened with) into the profile it names and its statements, and
//! `resolve_document` resolves them over a base. `resolve_document_under` adds what the open's
//! caller states beside the document ([`Overrides`]), the same way for every ABI. `wz/limits` is
//! refused by name: the limits a document may state are not read at the open by this build.

use core::fmt;

use crate::policy::{SessionPolicy, POLICIES, POLICY_COUNT, PROFILES};
use crate::policy_binding::{Binding, PolicyEntry, SelectError, ValueSet};

/// Where a policy's value in a snapshot came from: the layer that stated it last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The snapshot the resolution started from, the build defaults: no layer stated it.
    BuildDefault,
    /// The named profile, by its id.
    Profile(&'static str),
    /// The document's own `wz/policies`.
    Document,
    /// What the open's caller stated beside the document.
    Api,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildDefault => f.write_str("the build defaults"),
            Self::Profile(id) => write!(f, "the profile `{id}`"),
            Self::Document => f.write_str("the document"),
            Self::Api => f.write_str("the open's overrides"),
        }
    }
}

/// One statement of a layer: a policy, by its id, and the value it is to take, by the value's id.
/// Both are borrowed from whatever the layer was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    /// The policy's id, as the declaration spells it.
    pub policy: &'a str,
    /// The value's id, as the declaration spells it.
    pub value: &'a str,
}

impl<'a> Statement<'a> {
    /// `policy` is to take `value`.
    pub const fn new(policy: &'a str, value: &'a str) -> Self {
        Self { policy, value }
    }
}

/// One layer: the statements of one origin, in the order it states them.
#[derive(Clone, Copy, Debug)]
pub struct Layer<'s, 'a> {
    /// Where the statements come from; the origin of each value they set.
    pub origin: Origin,
    /// What the layer states.
    pub statements: &'s [Statement<'a>],
}

/// What the open's caller states beside the document ([`Origin::Api`]): a profile that stands in
/// for the one the document names, and statements over the document's own. The default states
/// nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overrides<'s, 'a> {
    /// The id of the profile the caller names, if it names one.
    pub profile: Option<&'a str>,
    /// What the caller states, each policy once.
    pub statements: &'s [Statement<'a>],
}

/// A named set of policy values the declaration states (`[[profile]]`), which a document starts
/// from by naming its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The profile's id, as a document names it.
    pub id: &'static str,
    /// The values the profile states.
    pub statements: &'static [Statement<'static>],
}

impl Profile {
    /// The profile of the build whose id is `id`.
    pub fn find(id: &str) -> Option<&'static Profile> {
        PROFILES.iter().find(|profile| profile.id == id)
    }

    /// The profile as a layer, whose values take [`Origin::Profile`].
    pub const fn layer(&self) -> Layer<'static, 'static> {
        Layer {
            origin: Origin::Profile(self.id),
            statements: self.statements,
        }
    }
}

/// Where each policy's value in a snapshot came from, in the order of the generated `POLICIES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    origins: [Origin; POLICY_COUNT],
}

impl Provenance {
    /// Every value from the build defaults.
    pub const fn build_defaults() -> Self {
        Self {
            origins: [Origin::BuildDefault; POLICY_COUNT],
        }
    }

    /// Where the value of the policy whose id is `policy` came from, or `None` for an id that
    /// names no policy.
    pub fn origin(&self, policy: &str) -> Option<Origin> {
        POLICIES
            .iter()
            .position(|entry| entry.id() == policy)
            .map(|index| self.origins[index])
    }

    /// Each policy with the origin of its value, in the order of the generated `POLICIES`.
    pub fn iter(&self) -> impl Iterator<Item = (&'static PolicyEntry, Origin)> + '_ {
        POLICIES.iter().zip(self.origins.iter().copied())
    }
}

/// A snapshot a creator resolved, and where each of its values came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The snapshot the creator hands its machines.
    pub policy: SessionPolicy,
    /// Where each value of `policy` came from.
    pub provenance: Provenance,
}

impl Resolved {
    /// `base` with no layer over it: every value from the build defaults.
    pub const fn unchanged(base: SessionPolicy) -> Self {
        Self {
            policy: base,
            provenance: Provenance::build_defaults(),
        }
    }
}

/// Why a statement, or a part of the document that holds the statements, was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason<'a> {
    /// The statement names no policy of the build.
    UnknownPolicy {
        /// The id the statement names.
        policy: &'a str,
        /// The value it states.
        value: &'a str,
    },
    /// The statement names a value the policy does not have.
    UnknownValue {
        /// The policy.
        policy: &'static str,
        /// The value stated.
        value: &'a str,
        /// The values the policy has.
        values: &'static [&'static str],
    },
    /// The build's domain of the policy leaves the value out: the field's `select_*` refused it.
    OutsideDomain {
        /// The policy.
        policy: &'static str,
        /// The value stated.
        value: &'a str,
        /// The values the build allows.
        domain: ValueSet,
    },
    /// The policy is decided by the build alone ([`Binding::Build`]).
    BuildBound {
        /// The policy.
        policy: &'static str,
        /// The value stated.
        value: &'a str,
    },
    /// The layer states the policy again; the statement refused is the later one.
    StatedTwice {
        /// The policy.
        policy: &'static str,
        /// The value the later statement states.
        value: &'a str,
    },
    /// A member that holds a value's id holds something other than a string.
    NotAString {
        /// The member's parent, `wz` or `wz/policies`.
        within: &'static str,
        /// The member's key.
        member: &'a str,
    },
    /// A member that holds other members holds something other than an object.
    NotAnObject {
        /// The member, `wz` or `wz/policies`.
        member: &'static str,
    },
    /// `wz/profile` names no profile of the build.
    UnknownProfile {
        /// The id it names.
        profile: &'a str,
    },
    /// `wz` holds a member wz does not read.
    UnknownMember {
        /// The member's key.
        member: &'a str,
    },
    /// `wz/limits`: the limits a document may state are not read at the open by this build.
    LimitsNotRead,
    /// A member of the document's `wz` tree is stated more than once; JSON5 allows it, and a
    /// later one may not silently win.
    MemberStatedTwice {
        /// The member, `wz`, `wz/profile` or `wz/policies`.
        member: &'static str,
    },
}

/// A refusal: the layer it was found in, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal<'a> {
    /// The layer that stated what was refused.
    pub layer: Origin,
    /// Why it was refused.
    pub reason: Reason<'a>,
}

impl fmt::Display for Refusal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let layer = self.layer;
        match self.reason {
            Reason::UnknownPolicy { policy, value } => write!(
                f,
                "{layer} states `{policy}` = `{value}`, and the build has no policy `{policy}`"
            ),
            Reason::UnknownValue {
                policy,
                value,
                values,
            } => {
                write!(
                    f,
                    "{layer} states `{policy}` = `{value}`, and `{policy}` has no value `{value}` \
                     (its values: "
                )?;
                write_ids(f, values.iter().copied())?;
                f.write_str(")")
            }
            Reason::OutsideDomain {
                policy,
                value,
                domain,
            } => write!(
                f,
                "{layer} states `{policy}` = `{value}`, and the build leaves `{value}` out of the \
                 domain of `{policy}` (it allows {domain})"
            ),
            Reason::BuildBound { policy, value } => write!(
                f,
                "{layer} states `{policy}` = `{value}`, and only the build decides `{policy}`"
            ),
            Reason::StatedTwice { policy, value } => write!(
                f,
                "{layer} states `{policy}` again, as `{value}`; a layer states a policy once"
            ),
            Reason::NotAString { within, member } => write!(
                f,
                "{layer} states `{within}/{member}` as something other than a string"
            ),
            Reason::NotAnObject { member } => write!(
                f,
                "{layer} states `{member}` as something other than an object"
            ),
            Reason::UnknownProfile { profile } => {
                write!(
                    f,
                    "{layer} names the profile `{profile}`, and the build has no such profile \
                     (its profiles: "
                )?;
                write_ids(f, PROFILES.iter().map(|known| known.id))?;
                f.write_str(")")
            }
            Reason::UnknownMember { member } => write!(
                f,
                "{layer} states `wz/{member}`, which wz does not read (it reads `wz/profile` and \
                 `wz/policies`)"
            ),
            Reason::LimitsNotRead => write!(
                f,
                "{layer} states `wz/limits`, which this build does not read at the open"
            ),
            Reason::MemberStatedTwice { member } => {
                write!(f, "{layer} states `{member}` more than once")
            }
        }
    }
}

impl core::error::Error for Refusal<'_> {}

/// Each id in backticks, separated by commas, or `none` when there is none.
fn write_ids<'i>(
    f: &mut fmt::Formatter<'_>,
    ids: impl IntoIterator<Item = &'i str>,
) -> fmt::Result {
    let mut ids = ids.into_iter();
    match ids.next() {
        None => f.write_str("none"),
        Some(first) => {
            write!(f, "`{first}`")?;
            ids.try_for_each(|id| write!(f, ", `{id}`"))
        }
    }
}

/// How many refusals [`Refusals`] holds; it counts the rest.
pub const MAX_REPORTED: usize = 8;

/// Every refusal a resolution found: the first [`MAX_REPORTED`] of them, in the order they were
/// found, and how many more there were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusals<'a> {
    reported: [Option<Refusal<'a>>; MAX_REPORTED],
    found: usize,
}

impl<'a> Refusals<'a> {
    pub(crate) const fn new() -> Self {
        Self {
            reported: [None; MAX_REPORTED],
            found: 0,
        }
    }

    pub(crate) fn push(&mut self, refusal: Refusal<'a>) {
        if let Some(slot) = self.reported.get_mut(self.found) {
            *slot = Some(refusal);
        }
        self.found += 1;
    }

    /// How many refusals were found, those held and those only counted.
    pub const fn found(&self) -> usize {
        self.found
    }

    /// Whether none was found.
    pub const fn is_empty(&self) -> bool {
        self.found == 0
    }

    /// How many were found past the [`MAX_REPORTED`] held.
    pub const fn unreported(&self) -> usize {
        self.found.saturating_sub(MAX_REPORTED)
    }

    /// The refusals held, in the order they were found.
    pub fn iter(&self) -> impl Iterator<Item = &Refusal<'a>> {
        self.reported.iter().flatten()
    }
}

impl fmt::Display for Refusals<'_> {
    /// Each refusal held, separated by `; `, and how many more were found.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, refusal) in self.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{refusal}")?;
        }
        match self.unreported() {
            0 => Ok(()),
            more => write!(f, "; and {more} more"),
        }
    }
}

impl core::error::Error for Refusals<'_> {}

/// `base` with `layers` over it, the lowest first: the snapshot and where each value came from,
/// or every refusal found when any statement is refused.
// The refusals are held inline because the core has no heap to box them in.
#[allow(clippy::result_large_err)]
pub fn resolve<'a>(
    base: SessionPolicy,
    layers: &[Layer<'_, 'a>],
) -> Result<Resolved, Refusals<'a>> {
    let mut refusals = Refusals::new();
    let resolved = compose(&POLICIES, base, layers, &mut refusals);
    if refusals.is_empty() {
        Ok(resolved)
    } else {
        Err(refusals)
    }
}

/// `layers` over `base` by the policies of `table`, each refusal pushed onto `refusals`. What it
/// returns is the caller's to drop when a refusal was pushed.
fn compose<'a>(
    table: &[PolicyEntry; POLICY_COUNT],
    base: SessionPolicy,
    layers: &[Layer<'_, 'a>],
    refusals: &mut Refusals<'a>,
) -> Resolved {
    let mut resolved = Resolved::unchanged(base);
    for layer in layers {
        for (at, statement) in layer.statements.iter().enumerate() {
            if let Err(reason) = apply(table, &mut resolved, layer, at, statement) {
                refusals.push(Refusal {
                    layer: layer.origin,
                    reason,
                });
            }
        }
    }
    resolved
}

/// The statement at `at` of `layer` applied to `resolved`, which a refusal leaves as it was.
fn apply<'a>(
    table: &[PolicyEntry; POLICY_COUNT],
    resolved: &mut Resolved,
    layer: &Layer<'_, 'a>,
    at: usize,
    statement: &Statement<'a>,
) -> Result<(), Reason<'a>> {
    let (policy, value) = (statement.policy, statement.value);
    let Some(index) = table.iter().position(|entry| entry.id() == policy) else {
        return Err(Reason::UnknownPolicy { policy, value });
    };
    let entry = &table[index];
    let id = entry.id();
    if layer.statements[..at]
        .iter()
        .any(|earlier| earlier.policy == policy)
    {
        return Err(Reason::StatedTwice { policy: id, value });
    }
    if entry.binding() == Binding::Build {
        return Err(Reason::BuildBound { policy: id, value });
    }
    match entry.select(&mut resolved.policy, value) {
        Ok(()) => {
            resolved.provenance.origins[index] = layer.origin;
            Ok(())
        }
        Err(SelectError::NoSuchValue) => Err(Reason::UnknownValue {
            policy: id,
            value,
            values: entry.values(),
        }),
        Err(SelectError::OutsideDomain(domain)) => Err(Reason::OutsideDomain {
            policy: id,
            value,
            domain,
        }),
    }
}

/// `base` with what a caller states and no document: the profile `overrides` names, then its
/// statements ([`Origin::Api`]). It answers what `resolve_document_under` answers for a document
/// with no `wz` member, without reading a document, so a build that is handed none links no
/// reader of one.
// The refusals are held inline because the core has no heap to box them in.
#[allow(clippy::result_large_err)]
pub fn resolve_under<'a>(
    base: SessionPolicy,
    overrides: Overrides<'_, 'a>,
) -> Result<Resolved, Refusals<'a>> {
    let mut refusals = Refusals::new();
    let stated = find_profile(overrides.profile, Origin::Api, &mut refusals);
    let api = Layer {
        origin: Origin::Api,
        statements: overrides.statements,
    };
    let resolved = match stated {
        Some(profile) => compose(&POLICIES, base, &[profile.layer(), api], &mut refusals),
        None => compose(&POLICIES, base, &[api], &mut refusals),
    };
    if refusals.is_empty() {
        Ok(resolved)
    } else {
        Err(refusals)
    }
}

/// The profile of the build whose id is `id`, or `None` when `id` is; an id the build has no
/// profile for is refused in `layer`, the layer that named it.
fn find_profile<'a>(
    id: Option<&'a str>,
    layer: Origin,
    refusals: &mut Refusals<'a>,
) -> Option<&'static Profile> {
    let id = id?;
    let found = Profile::find(id);
    if found.is_none() {
        refusals.push(Refusal {
            layer,
            reason: Reason::UnknownProfile { profile: id },
        });
    }
    found
}

#[cfg(feature = "alloc")]
pub use from_json5::{
    resolve_document, resolve_document_under, statements_from_json5, DocumentStatements,
};

#[cfg(feature = "alloc")]
mod from_json5 {
    use alloc::vec::Vec;

    use super::{
        compose, find_profile, Layer, Origin, Overrides, Reason, Refusal, Refusals, Resolved,
        Statement,
    };
    use crate::json5::Json5Value;
    use crate::policy::{SessionPolicy, POLICIES, POLICY_COUNT};
    use crate::policy_binding::PolicyEntry;

    /// What the `wz` member of a document states: the profile it names and the statements of
    /// its `wz/policies`, in the document's order.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct DocumentStatements<'a> {
        /// The id `wz/profile` names, if it names one.
        pub profile: Option<&'a str>,
        /// The members of `wz/policies`, each a policy's id and a value's id.
        pub statements: Vec<Statement<'a>>,
    }

    /// The profile and the statements the `wz` member of `tree` states, or every refusal of its
    /// shape: a `wz` or `wz/policies` that is not an object, a value that is not a string, a
    /// member of `wz` other than `profile` and `policies` (`limits` refused by name), a member
    /// stated twice. A document with no `wz` member states nothing. Whether the policies, the
    /// values and the profile exist is for [`resolve_document`].
    // The refusals are held inline because the core has no heap to box them in.
    #[allow(clippy::result_large_err)]
    pub fn statements_from_json5(
        tree: &Json5Value,
    ) -> Result<DocumentStatements<'_>, Refusals<'_>> {
        let mut refusals = Refusals::new();
        let read = read_wz(tree, &mut refusals);
        if refusals.is_empty() {
            Ok(read)
        } else {
            Err(refusals)
        }
    }

    /// `base` with the profile the `wz` member of `tree` names and then its own policies over
    /// it ([`super::resolve`]), or every refusal found, of the document's shape and of its
    /// statements. A document with no `wz` member is `base`, every value from the build
    /// defaults.
    // The refusals are held inline because the core has no heap to box them in.
    #[allow(clippy::result_large_err)]
    pub fn resolve_document(
        base: SessionPolicy,
        tree: &Json5Value,
    ) -> Result<Resolved, Refusals<'_>> {
        resolve_document_in(&POLICIES, base, tree, Overrides::default())
    }

    /// [`resolve_document`] with what the open's caller states over the document: the profile
    /// `overrides` names stands in for the one the document names, and its statements are the
    /// last layer ([`Origin::Api`]). A profile either names that the build does not have is
    /// refused in the layer that named it, the document's one too when `overrides` names
    /// another: the document is judged whole whatever is stated over it.
    // The refusals are held inline because the core has no heap to box them in.
    #[allow(clippy::result_large_err)]
    pub fn resolve_document_under<'a>(
        base: SessionPolicy,
        tree: &'a Json5Value,
        overrides: Overrides<'_, 'a>,
    ) -> Result<Resolved, Refusals<'a>> {
        resolve_document_in(&POLICIES, base, tree, overrides)
    }

    // The policies are a parameter so a test can resolve with a policy the build does not have.
    #[allow(clippy::result_large_err)]
    pub(super) fn resolve_document_in<'a>(
        table: &[PolicyEntry; POLICY_COUNT],
        base: SessionPolicy,
        tree: &'a Json5Value,
        overrides: Overrides<'_, 'a>,
    ) -> Result<Resolved, Refusals<'a>> {
        let mut refusals = Refusals::new();
        let read = read_wz(tree, &mut refusals);
        let named = find_profile(read.profile, Origin::Document, &mut refusals);
        let stated = find_profile(overrides.profile, Origin::Api, &mut refusals);
        let document = Layer {
            origin: Origin::Document,
            statements: &read.statements,
        };
        let api = Layer {
            origin: Origin::Api,
            statements: overrides.statements,
        };
        let resolved = match stated.or(named) {
            Some(profile) => compose(
                table,
                base,
                &[profile.layer(), document, api],
                &mut refusals,
            ),
            None => compose(table, base, &[document, api], &mut refusals),
        };
        if refusals.is_empty() {
            Ok(resolved)
        } else {
            Err(refusals)
        }
    }

    /// The members of the document's `wz` tree already read, so a second one is refused.
    #[derive(Default)]
    struct Seen {
        wz: bool,
        profile: bool,
        policies: bool,
    }

    fn refuse<'a>(refusals: &mut Refusals<'a>, reason: Reason<'a>) {
        refusals.push(Refusal {
            layer: Origin::Document,
            reason,
        });
    }

    /// Every `wz` member of `tree` read, each refusal of its shape pushed onto `refusals`.
    fn read_wz<'a>(tree: &'a Json5Value, refusals: &mut Refusals<'a>) -> DocumentStatements<'a> {
        let mut read = DocumentStatements::default();
        let Json5Value::Object(members) = tree else {
            return read;
        };
        let mut seen = Seen::default();
        for (key, wz) in members {
            if key != "wz" {
                continue;
            }
            if seen.wz {
                refuse(refusals, Reason::MemberStatedTwice { member: "wz" });
            }
            seen.wz = true;
            match wz {
                Json5Value::Object(wz_members) => {
                    read_wz_members(wz_members, &mut seen, &mut read, refusals);
                }
                _ => refuse(refusals, Reason::NotAnObject { member: "wz" }),
            }
        }
        read
    }

    fn read_wz_members<'a>(
        members: &'a [(alloc::string::String, Json5Value)],
        seen: &mut Seen,
        read: &mut DocumentStatements<'a>,
        refusals: &mut Refusals<'a>,
    ) {
        for (key, value) in members {
            match key.as_str() {
                "profile" => {
                    if seen.profile {
                        refuse(
                            refusals,
                            Reason::MemberStatedTwice {
                                member: "wz/profile",
                            },
                        );
                    }
                    seen.profile = true;
                    match value {
                        Json5Value::String(id) => {
                            if read.profile.is_none() {
                                read.profile = Some(id.as_str());
                            }
                        }
                        _ => refuse(
                            refusals,
                            Reason::NotAString {
                                within: "wz",
                                member: "profile",
                            },
                        ),
                    }
                }
                "policies" => {
                    if seen.policies {
                        refuse(
                            refusals,
                            Reason::MemberStatedTwice {
                                member: "wz/policies",
                            },
                        );
                    }
                    seen.policies = true;
                    let Json5Value::Object(stated) = value else {
                        refuse(
                            refusals,
                            Reason::NotAnObject {
                                member: "wz/policies",
                            },
                        );
                        continue;
                    };
                    for (policy, value) in stated {
                        match value {
                            Json5Value::String(text) => read
                                .statements
                                .push(Statement::new(policy.as_str(), text.as_str())),
                            _ => refuse(
                                refusals,
                                Reason::NotAString {
                                    within: "wz/policies",
                                    member: policy.as_str(),
                                },
                            ),
                        }
                    }
                }
                "limits" => refuse(refusals, Reason::LimitsNotRead),
                other => refuse(refusals, Reason::UnknownMember { member: other }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EventRingFull, KeySet, SubscriberOverload};
    use crate::policy_binding::{
        Bound, Domain, Mutability, OutsideDomain, PolicyField, PolicyValue, Scope, Wire,
    };
    use std::format;
    use std::vec::Vec;

    /// A two-value policy whose build allows only `On`, its default: a domain of one value, built
    /// as `policy_binding`'s tests build one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Pinned {
        Off,
        On,
    }

    impl PolicyValue for Pinned {
        const POLICY: &'static str = "test-pinned";
        const ALL: &'static [Self] = &[Self::Off, Self::On];
        const IDS: &'static [&'static str] = &["off", "on"];
        const DOMAIN: Domain<Self> = Domain::from_allowed(&[false, true]);
        const DEFAULT: Self = Self::On;
        const SCOPE: Scope = Scope::Session;
        const BINDING: Binding = Binding::Open;
        const MUTABILITY: Mutability = Mutability::Fixed;
        const WIRE: Wire = Wire::None;
        const BOUNDARY: Option<&'static str> = None;

        fn index(self) -> usize {
            self as usize
        }
    }

    /// No field of the snapshot holds it, so it is selected into a `Bound` of its own, which
    /// refuses what its domain leaves out as a field's `select_*` does.
    impl PolicyField for Pinned {
        fn select_in(_policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
            Bound::<Self, 1>::select(value).map(|_| ())
        }

        fn held_in(_policy: &SessionPolicy) -> Self {
            Self::DEFAULT
        }
    }

    /// A policy only the build decides, every value of it allowed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BuildOnly {
        Off,
        On,
    }

    impl PolicyValue for BuildOnly {
        const POLICY: &'static str = "test-build-only";
        const ALL: &'static [Self] = &[Self::Off, Self::On];
        const IDS: &'static [&'static str] = &["off", "on"];
        const DOMAIN: Domain<Self> = Domain::from_allowed(&[true, true]);
        const DEFAULT: Self = Self::Off;
        const SCOPE: Scope = Scope::Runtime;
        const BINDING: Binding = Binding::Build;
        const MUTABILITY: Mutability = Mutability::Fixed;
        const WIRE: Wire = Wire::None;
        const BOUNDARY: Option<&'static str> = None;

        fn index(self) -> usize {
            self as usize
        }
    }

    impl PolicyField for BuildOnly {
        fn select_in(_policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
            Bound::<Self, 1>::select(value).map(|_| ())
        }

        fn held_in(_policy: &SessionPolicy) -> Self {
            Self::DEFAULT
        }
    }

    /// The build's policies with the first replaced by `entry`.
    fn table_with(entry: PolicyEntry) -> [PolicyEntry; POLICY_COUNT] {
        let mut table = POLICIES;
        table[0] = entry;
        table
    }

    fn document<'s, 'a>(statements: &'s [Statement<'a>]) -> Layer<'s, 'a> {
        Layer {
            origin: Origin::Document,
            statements,
        }
    }

    /// The one refusal of `refusals`.
    fn only<'a>(refusals: &Refusals<'a>) -> Refusal<'a> {
        assert_eq!(refusals.found(), 1, "{refusals}");
        *refusals.iter().next().expect("one refusal")
    }

    /// A value of `P` other than its build default that the build's domain allows, if any.
    fn another<P: PolicyValue>() -> Option<P> {
        P::ALL
            .iter()
            .copied()
            .find(|value| *value != P::DEFAULT && P::DOMAIN.contains(*value))
    }

    fn id_of<P: PolicyValue>(value: P) -> &'static str {
        P::IDS[value.index()]
    }

    #[test]
    fn no_layer_is_the_base_with_every_value_from_the_build_defaults() {
        let base = SessionPolicy::defaults();
        let resolved = resolve(base, &[]).expect("nothing to refuse");
        assert_eq!(resolved, Resolved::unchanged(base));
        assert!(resolved
            .provenance
            .iter()
            .all(|(_, origin)| origin == Origin::BuildDefault));
        assert_eq!(resolved.provenance.iter().count(), POLICY_COUNT);
    }

    #[test]
    fn a_policy_the_build_does_not_have_is_refused_by_its_id() {
        let stated = [Statement::new("no-such-policy", "on")];
        let refusals = resolve(SessionPolicy::defaults(), &[document(&stated)]).unwrap_err();
        let refusal = only(&refusals);
        assert_eq!(refusal.layer, Origin::Document);
        assert_eq!(
            refusal.reason,
            Reason::UnknownPolicy {
                policy: "no-such-policy",
                value: "on"
            }
        );
        assert_eq!(
            format!("{refusal}"),
            "the document states `no-such-policy` = `on`, and the build has no policy \
             `no-such-policy`"
        );
    }

    #[test]
    fn a_value_the_policy_does_not_have_is_refused_with_its_values() {
        let stated = [Statement::new("subscriber-overload", "sometimes")];
        let refusals = resolve(SessionPolicy::defaults(), &[document(&stated)]).unwrap_err();
        let refusal = only(&refusals);
        assert_eq!(
            refusal.reason,
            Reason::UnknownValue {
                policy: "subscriber-overload",
                value: "sometimes",
                values: <SubscriberOverload as PolicyValue>::IDS,
            }
        );
        assert_eq!(
            format!("{refusal}"),
            "the document states `subscriber-overload` = `sometimes`, and `subscriber-overload` \
             has no value `sometimes` (its values: `block`, `reject`, `keep-latest`)"
        );
    }

    /// The domain is the field's: the statement goes through its `select_*`, whose
    /// `OutsideDomain` is carried with the policy's id.
    #[test]
    fn a_value_outside_a_one_value_domain_is_refused_naming_the_domain() {
        let table = table_with(PolicyEntry::of::<Pinned>());
        let mut refusals = Refusals::new();
        let stated = [Statement::new("test-pinned", "off")];
        compose(
            &table,
            SessionPolicy::defaults(),
            &[document(&stated)],
            &mut refusals,
        );
        let refusal = only(&refusals);
        let Reason::OutsideDomain {
            policy,
            value,
            domain,
        } = refusal.reason
        else {
            panic!("not outside the domain: {refusal:?}");
        };
        assert_eq!((policy, value), ("test-pinned", "off"));
        assert_eq!(domain.iter().collect::<Vec<_>>(), ["on"]);
        assert_eq!(
            format!("{refusal}"),
            "the document states `test-pinned` = `off`, and the build leaves `off` out of the \
             domain of `test-pinned` (it allows `on`)"
        );
        // The one value the domain holds is taken.
        let mut refusals = Refusals::new();
        let stated = [Statement::new("test-pinned", "on")];
        compose(
            &table,
            SessionPolicy::defaults(),
            &[document(&stated)],
            &mut refusals,
        );
        assert!(refusals.is_empty(), "{refusals}");
    }

    #[test]
    fn a_policy_only_the_build_decides_is_refused() {
        let table = table_with(PolicyEntry::of::<BuildOnly>());
        let mut refusals = Refusals::new();
        let stated = [Statement::new("test-build-only", "on")];
        compose(
            &table,
            SessionPolicy::defaults(),
            &[document(&stated)],
            &mut refusals,
        );
        let refusal = only(&refusals);
        assert_eq!(
            refusal.reason,
            Reason::BuildBound {
                policy: "test-build-only",
                value: "on"
            }
        );
        assert_eq!(
            format!("{refusal}"),
            "the document states `test-build-only` = `on`, and only the build decides \
             `test-build-only`"
        );
    }

    /// The later statement is refused, not taken; the same policy in two layers is an override.
    #[test]
    fn a_policy_stated_twice_in_one_layer_is_refused() {
        let stated = [
            Statement::new("key-set", "open"),
            Statement::new("event-ring-full", "overwrite-oldest"),
            Statement::new("key-set", "closed"),
        ];
        let refusals = resolve(SessionPolicy::defaults(), &[document(&stated)]).unwrap_err();
        let refusal = only(&refusals);
        assert_eq!(
            refusal.reason,
            Reason::StatedTwice {
                policy: "key-set",
                value: "closed"
            }
        );
        assert_eq!(
            format!("{refusal}"),
            "the document states `key-set` again, as `closed`; a layer states a policy once"
        );
        let open = [Statement::new("key-set", "open")];
        let api = Layer {
            origin: Origin::Api,
            statements: &open,
        };
        let resolved =
            resolve(SessionPolicy::defaults(), &[document(&open), api]).expect("two layers");
        assert_eq!(resolved.provenance.origin("key-set"), Some(Origin::Api));
        assert_eq!(resolved.policy.key_set(), KeySet::Open);
    }

    /// The document overrides the profile, the profile the build defaults, and each value
    /// records the layer that stated it last.
    #[test]
    fn a_later_layer_overrides_an_earlier_one_and_each_value_records_it() {
        let (Some(overload), Some(ring)) =
            (another::<SubscriberOverload>(), another::<EventRingFull>())
        else {
            // The build allows one value of each: there is nothing to override with.
            return;
        };
        let profile = [
            Statement::new("subscriber-overload", id_of(overload)),
            Statement::new("event-ring-full", id_of(ring)),
        ];
        let doc = [Statement::new(
            "subscriber-overload",
            id_of(SubscriberOverload::DEFAULT),
        )];
        let layers = [
            Layer {
                origin: Origin::Profile("test"),
                statements: &profile,
            },
            document(&doc),
        ];
        let resolved = resolve(SessionPolicy::defaults(), &layers).expect("every value allowed");
        assert_eq!(
            resolved.policy.subscriber_overload(),
            SubscriberOverload::DEFAULT
        );
        assert_eq!(resolved.policy.event_ring_full(), ring);
        assert_eq!(resolved.policy.key_set(), KeySet::DEFAULT);
        let origin = |policy| resolved.provenance.origin(policy);
        assert_eq!(origin("subscriber-overload"), Some(Origin::Document));
        assert_eq!(origin("event-ring-full"), Some(Origin::Profile("test")));
        assert_eq!(origin("key-set"), Some(Origin::BuildDefault));
        assert_eq!(origin("no-such-policy"), None);
    }

    /// One refused statement refuses the document: the statement beside it, which alone would
    /// change the snapshot, reaches no snapshot.
    #[test]
    fn one_refused_statement_refuses_the_whole_document() {
        let Some(ring) = another::<EventRingFull>() else {
            return;
        };
        let good = [Statement::new("event-ring-full", id_of(ring))];
        let alone = resolve(SessionPolicy::defaults(), &[document(&good)]).expect("allowed");
        assert_eq!(alone.policy.event_ring_full(), ring);
        let with_bad = [
            Statement::new("event-ring-full", id_of(ring)),
            Statement::new("key-set", "ajar"),
        ];
        let refusals = resolve(SessionPolicy::defaults(), &[document(&with_bad)]).unwrap_err();
        assert_eq!(refusals.found(), 1);
        assert!(matches!(
            only(&refusals).reason,
            Reason::UnknownValue {
                policy: "key-set",
                ..
            }
        ));
    }

    #[test]
    fn every_refusal_is_reported_and_those_past_the_bound_are_counted() {
        let stated = [
            Statement::new("unknown-0", "on"),
            Statement::new("unknown-1", "on"),
            Statement::new("unknown-2", "on"),
            Statement::new("unknown-3", "on"),
            Statement::new("unknown-4", "on"),
            Statement::new("unknown-5", "on"),
            Statement::new("unknown-6", "on"),
            Statement::new("unknown-7", "on"),
            Statement::new("unknown-8", "on"),
            Statement::new("key-set", "ajar"),
        ];
        let refusals = resolve(SessionPolicy::defaults(), &[document(&stated)]).unwrap_err();
        assert_eq!(refusals.found(), 10);
        assert_eq!(refusals.iter().count(), MAX_REPORTED);
        assert_eq!(refusals.unreported(), 2);
        let held: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
        assert_eq!(
            held[0],
            Reason::UnknownPolicy {
                policy: "unknown-0",
                value: "on"
            }
        );
        assert_eq!(
            held[MAX_REPORTED - 1],
            Reason::UnknownPolicy {
                policy: "unknown-7",
                value: "on"
            }
        );
        let text = format!("{refusals}");
        assert!(
            text.contains("no policy `unknown-0`; the document"),
            "{text}"
        );
        assert!(text.ends_with("; and 2 more"), "{text}");
    }

    /// Each entry of the table names its policy and reaches its field: the value a snapshot holds
    /// is read back by its id, and a value the policy does not have is refused before the field.
    #[test]
    fn each_entry_names_its_policy_and_reaches_its_field() {
        let defaults = SessionPolicy::defaults();
        for (index, entry) in POLICIES.iter().enumerate() {
            assert!(
                POLICIES[..index]
                    .iter()
                    .all(|other| other.id() != entry.id()),
                "{} is in the table twice",
                entry.id()
            );
            let held = entry.value_in(&defaults);
            assert!(entry.values().contains(&held), "{}", entry.id());
            assert!(entry.domain().contains(held), "{}", entry.id());
            let mut policy = defaults;
            assert_eq!(entry.select(&mut policy, held), Ok(()), "{}", entry.id());
            assert_eq!(policy, defaults, "{}", entry.id());
            assert_eq!(
                entry.select(&mut policy, "no-such-value"),
                Err(SelectError::NoSuchValue)
            );
        }
        let entry = POLICIES
            .iter()
            .find(|entry| entry.id() == "subscriber-overload")
            .expect("declared");
        if let Some(other) = another::<SubscriberOverload>() {
            let mut policy = defaults;
            assert_eq!(entry.select(&mut policy, id_of(other)), Ok(()));
            assert_eq!(policy.subscriber_overload(), other);
            assert_eq!(entry.value_in(&policy), id_of(other));
        }
    }

    /// The `upstream` profile states every policy once, each at a value the policy has.
    #[test]
    fn the_upstream_profile_states_every_policy_once() {
        let upstream = Profile::find("upstream").expect("declared");
        assert_eq!(upstream.statements.len(), POLICY_COUNT);
        for (statement, entry) in upstream.statements.iter().zip(POLICIES.iter()) {
            assert_eq!(statement.policy, entry.id());
            assert!(entry.values().contains(&statement.value), "{statement:?}");
        }
        assert_eq!(
            upstream.layer().origin,
            Origin::Profile("upstream"),
            "a profile's values take its origin"
        );
        assert_eq!(Profile::find("no-such-profile"), None);
    }

    #[test]
    fn an_empty_value_set_reads_as_no_value() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Nothing {
            Off,
            On,
        }

        impl PolicyValue for Nothing {
            const POLICY: &'static str = "test-nothing";
            const ALL: &'static [Self] = &[Self::Off, Self::On];
            const IDS: &'static [&'static str] = &["off", "on"];
            const DOMAIN: Domain<Self> = Domain::from_allowed(&[false, false]);
            const DEFAULT: Self = Self::Off;
            const SCOPE: Scope = Scope::Session;
            const BINDING: Binding = Binding::Open;
            const MUTABILITY: Mutability = Mutability::Fixed;
            const WIRE: Wire = Wire::None;
            const BOUNDARY: Option<&'static str> = None;

            fn index(self) -> usize {
                self as usize
            }
        }

        impl PolicyField for Nothing {
            fn select_in(
                _policy: &mut SessionPolicy,
                value: Self,
            ) -> Result<(), OutsideDomain<Self>> {
                Bound::<Self, 1>::select(value).map(|_| ())
            }

            fn held_in(_policy: &SessionPolicy) -> Self {
                Self::DEFAULT
            }
        }

        let entry = PolicyEntry::of::<Nothing>();
        assert_eq!(format!("{}", entry.domain()), "no value");
        assert_eq!(format!("{}", PolicyEntry::of::<Pinned>().domain()), "`on`");
        assert_eq!(
            format!("{}", PolicyEntry::of::<BuildOnly>().domain()),
            "`off`, `on`"
        );
    }

    #[cfg(feature = "alloc")]
    mod from_a_json5_tree {
        use super::*;
        use crate::json5::parse;

        #[test]
        fn a_document_with_no_wz_member_is_the_base() {
            let tree = parse(r#"{ mode: "peer", connect: { endpoints: [] } }"#).unwrap();
            let base = SessionPolicy::defaults();
            assert_eq!(resolve_document(base, &tree), Ok(Resolved::unchanged(base)));
            assert_eq!(
                statements_from_json5(&tree),
                Ok(DocumentStatements::default())
            );
            let empty = parse(r#"{ wz: {} }"#).unwrap();
            assert_eq!(
                resolve_document(base, &empty),
                Ok(Resolved::unchanged(base))
            );
        }

        #[test]
        fn the_wz_member_is_read_into_its_profile_and_statements() {
            let tree = parse(
                r#"{ wz: { profile: "upstream", policies: { "key-set": "open", "sn-resolution": "bits-32" } } }"#,
            )
            .unwrap();
            let read = statements_from_json5(&tree).expect("well formed");
            assert_eq!(read.profile, Some("upstream"));
            assert_eq!(
                read.statements,
                [
                    Statement::new("key-set", "open"),
                    Statement::new("sn-resolution", "bits-32")
                ]
            );
        }

        /// The profile is the layer below the document's own policies; a policy neither states
        /// keeps the build default.
        #[test]
        fn a_named_profile_is_read_below_the_documents_policies() {
            let upstream = Profile::find("upstream").expect("declared");
            let allowed = upstream.statements.iter().all(|statement| {
                POLICIES
                    .iter()
                    .find(|entry| entry.id() == statement.policy)
                    .is_some_and(|entry| entry.domain().contains(statement.value))
            });
            let tree = parse(r#"{ wz: { profile: "upstream", policies: { "key-set": "open" } } }"#)
                .unwrap();
            let resolved = resolve_document(SessionPolicy::defaults(), &tree);
            if !allowed {
                // The build leaves an upstream value out of a domain: the profile is refused.
                assert!(resolved.is_err());
                return;
            }
            let resolved = resolved.expect("every upstream value allowed");
            let origin = |policy| resolved.provenance.origin(policy);
            assert_eq!(origin("key-set"), Some(Origin::Document));
            assert_eq!(origin("event-ring-full"), Some(Origin::Profile("upstream")));
            for statement in upstream.statements {
                let entry = POLICIES
                    .iter()
                    .find(|entry| entry.id() == statement.policy)
                    .expect("declared");
                if statement.policy != "key-set" {
                    assert_eq!(entry.value_in(&resolved.policy), statement.value);
                }
            }
        }

        #[test]
        fn a_profile_the_build_does_not_have_is_refused() {
            let tree = parse(r#"{ wz: { profile: "no-such-profile" } }"#).unwrap();
            let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
            let refusal = only(&refusals);
            assert_eq!(
                refusal.reason,
                Reason::UnknownProfile {
                    profile: "no-such-profile"
                }
            );
            assert_eq!(
                format!("{refusal}"),
                "the document names the profile `no-such-profile`, and the build has no such \
                 profile (its profiles: `upstream`)"
            );
        }

        #[test]
        fn a_member_of_wz_it_does_not_read_is_refused_and_limits_by_name() {
            let tree = parse(r#"{ wz: { limits: { MAX_A: 4 }, colour: "blue" } }"#).unwrap();
            let refusals = statements_from_json5(&tree).unwrap_err();
            let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
            assert_eq!(
                reasons,
                [
                    Reason::LimitsNotRead,
                    Reason::UnknownMember { member: "colour" }
                ]
            );
            let text = format!("{refusals}");
            assert!(
                text.contains("states `wz/limits`, which this build does not read at the open"),
                "{text}"
            );
            assert!(
                text.contains("states `wz/colour`, which wz does not read"),
                "{text}"
            );
        }

        #[test]
        fn a_value_that_is_not_a_string_is_refused() {
            let tree = parse(r#"{ wz: { profile: 1, policies: { "key-set": true } } }"#).unwrap();
            let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
            let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
            assert_eq!(
                reasons,
                [
                    Reason::NotAString {
                        within: "wz",
                        member: "profile"
                    },
                    Reason::NotAString {
                        within: "wz/policies",
                        member: "key-set"
                    }
                ]
            );
            assert!(format!("{refusals}")
                .contains("states `wz/policies/key-set` as something other than a string"));
        }

        #[test]
        fn a_wz_or_policies_that_is_not_an_object_is_refused() {
            let tree = parse(r#"{ wz: "upstream" }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(refusal.reason, Reason::NotAnObject { member: "wz" });
            let tree = parse(r#"{ wz: { policies: ["key-set", "open"] } }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(
                refusal.reason,
                Reason::NotAnObject {
                    member: "wz/policies"
                }
            );
            assert_eq!(
                format!("{refusal}"),
                "the document states `wz/policies` as something other than an object"
            );
        }

        /// JSON5 keeps a member stated twice, and the later one must not win unnoticed.
        #[test]
        fn a_policy_or_a_member_stated_twice_in_the_document_is_refused() {
            let tree = parse(r#"{ wz: { policies: { "key-set": "open", "key-set": "closed" } } }"#)
                .unwrap();
            let refusal = only(&resolve_document(SessionPolicy::defaults(), &tree).unwrap_err());
            assert_eq!(
                refusal.reason,
                Reason::StatedTwice {
                    policy: "key-set",
                    value: "closed"
                }
            );
            let tree = parse(r#"{ wz: { profile: "upstream" }, wz: {} }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(refusal.reason, Reason::MemberStatedTwice { member: "wz" });
            let tree = parse(r#"{ wz: { profile: "upstream", profile: "upstream" } }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(
                refusal.reason,
                Reason::MemberStatedTwice {
                    member: "wz/profile"
                }
            );
        }

        /// A refusal of the document's shape and one of its statements are both reported.
        #[test]
        fn a_refusal_of_shape_does_not_hide_one_of_a_statement() {
            let tree =
                parse(r#"{ wz: { colour: "blue", policies: { "key-set": "ajar" } } }"#).unwrap();
            let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
            assert_eq!(refusals.found(), 2, "{refusals}");
            let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
            assert_eq!(reasons[0], Reason::UnknownMember { member: "colour" });
            assert!(matches!(
                reasons[1],
                Reason::UnknownValue {
                    policy: "key-set",
                    value: "ajar",
                    ..
                }
            ));
        }

        /// Whether the build's domains allow every value the `upstream` profile states, so that
        /// a resolution that reads the profile is not refused for it.
        fn upstream_allowed() -> bool {
            let upstream = Profile::find("upstream").expect("declared");
            upstream.statements.iter().all(|statement| {
                POLICIES
                    .iter()
                    .find(|entry| entry.id() == statement.policy)
                    .is_some_and(|entry| entry.domain().contains(statement.value))
            })
        }

        /// The open's statements are the last layer: over the document's own, each value they
        /// set recorded as the API's, and a policy neither states keeps the build default.
        #[test]
        fn the_overrides_are_read_over_the_documents_policies() {
            let Some(ring) = another::<EventRingFull>() else {
                return;
            };
            let text = format!(
                r#"{{ wz: {{ policies: {{ "event-ring-full": "{}" }} }} }}"#,
                id_of(ring)
            );
            let tree = parse(&text).unwrap();
            let base = SessionPolicy::defaults();
            let document = resolve_document_under(base, &tree, Overrides::default())
                .expect("the document alone");
            assert_eq!(document.policy.event_ring_full(), ring);
            assert_eq!(
                document.provenance.origin("event-ring-full"),
                Some(Origin::Document)
            );
            let stated = [Statement::new(
                "event-ring-full",
                id_of(EventRingFull::DEFAULT),
            )];
            let overrides = Overrides {
                profile: None,
                statements: &stated,
            };
            let resolved = resolve_document_under(base, &tree, overrides).expect("allowed");
            assert_eq!(resolved.policy.event_ring_full(), EventRingFull::DEFAULT);
            assert_eq!(
                resolved.provenance.origin("event-ring-full"),
                Some(Origin::Api)
            );
            assert_eq!(
                resolved.provenance.origin("key-set"),
                Some(Origin::BuildDefault)
            );
        }

        /// A caller handed no document resolves as one handed a document with no `wz` member:
        /// `resolve_under` and the reader answer the same snapshot, the same provenance and the
        /// same refusals, for no statement, a statement, a profile and a profile the build does
        /// not have. Turned red by a path that composes the caller's layers apart from the
        /// reader's.
        #[test]
        fn no_document_resolves_as_a_document_with_no_wz_member() {
            let empty = parse("{}").unwrap();
            let base = SessionPolicy::defaults();
            let ring = another::<EventRingFull>().unwrap_or(EventRingFull::DEFAULT);
            let stated = [Statement::new("event-ring-full", id_of(ring))];
            let cases = [
                Overrides::default(),
                Overrides {
                    profile: None,
                    statements: &stated,
                },
                Overrides {
                    profile: Some("upstream"),
                    statements: &[],
                },
                Overrides {
                    profile: Some("no-such-profile"),
                    statements: &stated,
                },
            ];
            for overrides in cases {
                let through_reader = resolve_document_under(base, &empty, overrides);
                let without = super::super::resolve_under(base, overrides);
                assert_eq!(
                    through_reader.as_ref().ok(),
                    without.as_ref().ok(),
                    "{overrides:?}"
                );
                assert_eq!(
                    through_reader.err().map(|refused| format!("{refused}")),
                    without.err().map(|refused| format!("{refused}")),
                    "{overrides:?}"
                );
            }
        }

        /// The profile the open names is read below the document's policies, as the document's
        /// own would be.
        #[test]
        fn the_profile_the_overrides_name_is_read_below_the_document() {
            let tree = parse(r#"{ wz: { policies: { "key-set": "open" } } }"#).unwrap();
            let overrides = Overrides {
                profile: Some("upstream"),
                statements: &[],
            };
            let resolved = resolve_document_under(SessionPolicy::defaults(), &tree, overrides);
            if !upstream_allowed() {
                assert!(resolved.is_err());
                return;
            }
            let resolved = resolved.expect("every upstream value allowed");
            let origin = |policy| resolved.provenance.origin(policy);
            assert_eq!(origin("key-set"), Some(Origin::Document));
            assert_eq!(origin("event-ring-full"), Some(Origin::Profile("upstream")));
        }

        /// The open's profile stands in for the document's, so it is the one looked up: an
        /// unknown one is refused in the open's layer even where the document names a profile
        /// the build has.
        #[test]
        fn a_profile_the_overrides_name_and_the_build_does_not_have_is_refused_as_theirs() {
            let tree = parse(r#"{ wz: { profile: "upstream" } }"#).unwrap();
            let overrides = Overrides {
                profile: Some("no-such-profile"),
                statements: &[],
            };
            let refusals =
                resolve_document_under(SessionPolicy::defaults(), &tree, overrides).unwrap_err();
            let refusal = only(&refusals);
            assert_eq!(refusal.layer, Origin::Api);
            assert_eq!(
                refusal.reason,
                Reason::UnknownProfile {
                    profile: "no-such-profile"
                }
            );
            assert!(
                format!("{refusal}").starts_with(
                    "the open's overrides names the profile `no-such-profile`, and the build \
                     has no such profile"
                ),
                "{refusal}"
            );
        }

        /// The document is judged whole whatever the open states over it: a profile it names
        /// that the build does not have is refused although the open names another.
        #[test]
        fn the_documents_unknown_profile_is_refused_though_the_overrides_name_one() {
            let tree = parse(r#"{ wz: { profile: "no-such-profile" } }"#).unwrap();
            let overrides = Overrides {
                profile: Some("upstream"),
                statements: &[],
            };
            let refusals =
                resolve_document_under(SessionPolicy::defaults(), &tree, overrides).unwrap_err();
            let reasons: Vec<_> = refusals
                .iter()
                .map(|refusal| (refusal.layer, refusal.reason))
                .collect();
            assert_eq!(
                reasons[0],
                (
                    Origin::Document,
                    Reason::UnknownProfile {
                        profile: "no-such-profile"
                    }
                )
            );
        }

        /// The open's layer states a policy once, as every layer does.
        #[test]
        fn a_policy_the_overrides_state_twice_is_refused() {
            let tree = parse(r#"{ mode: "peer" }"#).unwrap();
            let default = id_of(KeySet::DEFAULT);
            let stated = [
                Statement::new("key-set", default),
                Statement::new("key-set", default),
            ];
            let overrides = Overrides {
                profile: None,
                statements: &stated,
            };
            let refusals =
                resolve_document_under(SessionPolicy::defaults(), &tree, overrides).unwrap_err();
            let refusal = only(&refusals);
            assert_eq!(refusal.layer, Origin::Api);
            assert_eq!(
                refusal.reason,
                Reason::StatedTwice {
                    policy: "key-set",
                    value: default
                }
            );
        }

        /// No override is the document alone: [`resolve_document`] is the same resolution.
        #[test]
        fn no_override_is_the_document_alone() {
            let tree = parse(r#"{ wz: { policies: { "key-set": "open" } } }"#).unwrap();
            let base = SessionPolicy::defaults();
            assert_eq!(
                resolve_document_under(base, &tree, Overrides::default()),
                resolve_document(base, &tree)
            );
        }

        /// The policies of `resolve_document_in` are its parameter: a policy only the build
        /// decides is refused from the document as from any layer.
        #[test]
        fn a_document_that_states_a_policy_only_the_build_decides_is_refused() {
            let table = table_with(PolicyEntry::of::<BuildOnly>());
            let tree = parse(r#"{ wz: { policies: { "test-build-only": "on" } } }"#).unwrap();
            let refusals = from_json5::resolve_document_in(
                &table,
                SessionPolicy::defaults(),
                &tree,
                Overrides::default(),
            )
            .unwrap_err();
            assert_eq!(
                only(&refusals).reason,
                Reason::BuildBound {
                    policy: "test-build-only",
                    value: "on"
                }
            );
        }
    }
}
