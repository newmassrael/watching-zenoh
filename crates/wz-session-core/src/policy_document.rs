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
//! # Limits
//!
//! The same resolution composes the limits a stage after the build may decide
//! ([`crate::limits`]): the document's `wz/limits` states a limit by its id, as an integer or
//! `unbounded`, and what the open's caller states beside the document ([`Overrides::limits`]) is
//! the layer over it. No profile states a limit. A limit is selected into the snapshot that holds
//! it, [`SessionLimits`] or [`RuntimeLimits`], through its field's `select_*`, which refuses a
//! value the build's domain leaves out, and a bound stated as `0`, which would admit nothing, is
//! refused too. A limit only the build sizes (a capacity alone) is refused by name, as is a limit
//! whose machines still read the build's value rather than the snapshot
//! ([`LimitEntry::read_from_snapshot`]): its value would be taken and never read. A limit of a
//! runtime is refused to a creator that holds a session's limits alone ([`Base`]). The policies
//! and the limits are one resolution: one refusal of either refuses both.
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
//! caller states beside the document ([`Overrides`]), the same way for every ABI.
//!
//! `wz/key-ids` states the key ids every node of a deployment shares: `dictionary`, a list of
//! `{ id, key }`, and `links`, a list of `{ locator, form }` that states the key-wire form of one
//! endpoint apart from the session's. A build with the `shared-key-ids` capability reads it into
//! the statements' `key_ids` (`crate::shared_key_ids::KeyIdsAtOpen`), and its refusals
//! ([`KeyIdsReason`]) are found by the same reader, so they refuse the document as a refused
//! policy does. A build without the capability refuses the member by name.

use core::fmt;

use crate::keyexpr_canon::KeyexprRefusal;
use crate::limit_binding::{write_outside, LimitEntry, LimitValue, Outside, UNBOUNDED};
use crate::limits::{
    RuntimeLimits, SessionLimits, CAPACITY_LIMITS, RUNTIME_LIMITS, RUNTIME_LIMIT_COUNT,
    SESSION_LIMITS, SESSION_LIMIT_COUNT,
};
use crate::policy::{KeyWireForm, SessionPolicy, POLICIES, POLICY_COUNT, PROFILES};
use crate::policy_binding::{
    Binding, LimitKind, PolicyEntry, PolicyValue, Scope, SelectError, ValueSet,
};

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

/// One limit a layer states: a limit, by its id as the layer spells it, and the value it is to
/// take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitStatement<'a> {
    /// The limit's id, as the declaration spells it.
    pub limit: &'a str,
    /// The value: an integer, or `unbounded`.
    pub value: LimitValue,
}

impl<'a> LimitStatement<'a> {
    /// `limit` is to take `value`.
    pub const fn new(limit: &'a str, value: LimitValue) -> Self {
        Self { limit, value }
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
    /// The limits the caller states, each limit once.
    pub limits: &'s [LimitStatement<'a>],
}

/// What a resolution starts from: the snapshot of the policies, and the snapshots of the limits
/// the creator holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base {
    /// The policies.
    pub policy: SessionPolicy,
    /// The limits of a session.
    pub session_limits: SessionLimits,
    /// The limits of a node or runtime, where the creator holds them. A creator that holds a
    /// session's limits alone states `None`, and a runtime's limit a layer states is refused
    /// ([`Reason::LimitWrongScope`]).
    pub runtime_limits: Option<RuntimeLimits>,
}

impl Base {
    /// `policy` and the build defaults of a session's limits, for a creator that holds no
    /// runtime's limits.
    pub const fn session(policy: SessionPolicy) -> Self {
        Self {
            policy,
            session_limits: SessionLimits::defaults(),
            runtime_limits: None,
        }
    }

    /// `policy` and the build defaults of a session's limits and a runtime's, for the node that
    /// holds both.
    pub const fn node(policy: SessionPolicy) -> Self {
        Self {
            policy,
            session_limits: SessionLimits::defaults(),
            runtime_limits: Some(RuntimeLimits::defaults()),
        }
    }
}

impl From<SessionPolicy> for Base {
    /// [`Base::session`]: a creator that names only the policies holds a session's limits alone.
    fn from(policy: SessionPolicy) -> Self {
        Self::session(policy)
    }
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
    /// The limits, resolved with the policies.
    pub limits: ResolvedLimits,
}

impl Resolved {
    /// `base` with no layer over it, and the build defaults of the limits: every value from the
    /// build defaults.
    pub const fn unchanged(base: SessionPolicy) -> Self {
        Self {
            policy: base,
            provenance: Provenance::build_defaults(),
            limits: ResolvedLimits::unchanged(SessionLimits::defaults(), RuntimeLimits::defaults()),
        }
    }
}

/// The layer a limit's value came from. No profile states a limit, so one of these three stands
/// for its [`Origin`] in a byte, where an `Origin` would take a word and a pointer per limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LimitOrigin {
    BuildDefault,
    /// Only the reader of a document states it, which a build without `alloc` does not have.
    #[cfg(feature = "alloc")]
    Document,
    Api,
}

impl LimitOrigin {
    const fn origin(self) -> Origin {
        match self {
            Self::BuildDefault => Origin::BuildDefault,
            #[cfg(feature = "alloc")]
            Self::Document => Origin::Document,
            Self::Api => Origin::Api,
        }
    }
}

/// Where each limit's value in the snapshots came from, in the order of the generated
/// `SESSION_LIMITS` and then `RUNTIME_LIMITS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitProvenance {
    session: [LimitOrigin; SESSION_LIMIT_COUNT],
    runtime: [LimitOrigin; RUNTIME_LIMIT_COUNT],
}

impl LimitProvenance {
    /// Every value from the build defaults.
    pub const fn build_defaults() -> Self {
        Self {
            session: [LimitOrigin::BuildDefault; SESSION_LIMIT_COUNT],
            runtime: [LimitOrigin::BuildDefault; RUNTIME_LIMIT_COUNT],
        }
    }

    /// Where the value of the limit whose id is `limit` came from, or `None` for an id that
    /// names no limit of either snapshot.
    pub fn origin(&self, limit: &str) -> Option<Origin> {
        match FoundLimit::find(limit)? {
            FoundLimit::Session(index) => Some(self.session[index].origin()),
            FoundLimit::Runtime(index) => Some(self.runtime[index].origin()),
            FoundLimit::Capacity(_) => None,
        }
    }

    /// Each limit, by its id, with the origin of its value: those of `SESSION_LIMITS` and then
    /// those of `RUNTIME_LIMITS`, each in the order of its table.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, Origin)> + '_ {
        let session = SESSION_LIMITS
            .iter()
            .map(LimitEntry::id)
            .zip(self.session.iter().map(|stated| stated.origin()));
        let runtime = RUNTIME_LIMITS
            .iter()
            .map(LimitEntry::id)
            .zip(self.runtime.iter().map(|stated| stated.origin()));
        session.chain(runtime)
    }
}

/// The limits a creator resolved: the snapshot of a session's, the snapshot of a runtime's, and
/// where each of their values came from. A creator that holds no runtime's limits gets the
/// runtime's build defaults, which no layer may change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedLimits {
    /// The limits of a session.
    pub session: SessionLimits,
    /// The limits of a node or runtime.
    pub runtime: RuntimeLimits,
    /// Where each value of `session` and `runtime` came from.
    pub provenance: LimitProvenance,
}

impl ResolvedLimits {
    /// `session` and `runtime` with no layer over them: every value from the build defaults.
    pub const fn unchanged(session: SessionLimits, runtime: RuntimeLimits) -> Self {
        Self {
            session,
            runtime,
            provenance: LimitProvenance::build_defaults(),
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
    /// A member of the document's `wz` tree is stated more than once; JSON5 allows it, and a
    /// later one may not silently win.
    MemberStatedTwice {
        /// The member: `wz`, `wz/profile`, `wz/policies`, `wz/limits`, `wz/key-ids` or one of
        /// the two members of `wz/key-ids`.
        member: &'static str,
    },
    /// The statement names no limit of the build.
    UnknownLimit {
        /// The id the statement names.
        limit: &'a str,
    },
    /// The limit is a capacity alone: the build sizes storage by it, and no later stage decides
    /// it.
    LimitBuildOnly {
        /// The limit.
        limit: &'static str,
    },
    /// The machines of the limit's scope read the build's value and not the snapshot their
    /// creator hands them, so a stated value would be taken and never read.
    LimitNotRead {
        /// The limit.
        limit: &'static str,
    },
    /// The value is one the build's domain of the limit leaves out, or `0` for a bound, which
    /// would admit nothing.
    LimitOutsideDomain {
        /// The limit.
        limit: &'static str,
        /// The value stated.
        value: LimitValue,
        /// Why the value is outside.
        why: Outside,
    },
    /// The limit is held by a scope the creator holds no snapshot of: a runtime's limit stated
    /// to a creator that holds a session's limits alone.
    LimitWrongScope {
        /// The limit.
        limit: &'static str,
        /// The scope whose snapshot holds it.
        scope: Scope,
    },
    /// A member of `wz/limits` holds something other than a whole number a `usize` holds or
    /// `unbounded`: a bool, an object, a negative or fractional number, or other text.
    NotALimitValue {
        /// The member's key.
        limit: &'a str,
    },
    /// The layer states the limit again; the statement refused is the later one.
    LimitStatedTwice {
        /// The limit.
        limit: &'static str,
    },
    /// `wz/key-ids`, or a part of it, is refused.
    KeyIds(KeyIdsReason<'a>),
}

/// Why `wz/key-ids`, or a part of it, was refused. An entry is named by its place in its list,
/// counted from 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyIdsReason<'a> {
    /// The build was made without the `shared-key-ids` capability, which reads the member.
    NotInBuild,
    /// `wz/key-ids` holds a member other than `dictionary` and `links`.
    UnknownMember {
        /// The member's key.
        member: &'a str,
    },
    /// `dictionary` or `links` holds something other than an array.
    NotAnArray {
        /// The member, `wz/key-ids/dictionary` or `wz/key-ids/links`.
        member: &'static str,
    },
    /// An entry of a list is something other than an object.
    EntryNotAnObject {
        /// The list.
        member: &'static str,
        /// The entry's place in it.
        at: usize,
    },
    /// An entry of a list lacks one of its fields.
    MissingField {
        /// The list.
        member: &'static str,
        /// The entry's place in it.
        at: usize,
        /// The field it lacks.
        field: &'static str,
    },
    /// An entry of a list states a field the entries of that list do not have.
    UnknownField {
        /// The list.
        member: &'static str,
        /// The entry's place in it.
        at: usize,
        /// The field's key.
        field: &'a str,
    },
    /// An entry of a list states one of its fields more than once.
    FieldStatedTwice {
        /// The list.
        member: &'static str,
        /// The entry's place in it.
        at: usize,
        /// The field.
        field: &'static str,
    },
    /// A field that holds text holds something else.
    NotAString {
        /// The list.
        member: &'static str,
        /// The entry's place in it.
        at: usize,
        /// The field.
        field: &'static str,
    },
    /// The `id` of a dictionary entry is not an integer from 0 to 65535, the ids a wireexpr has.
    NotAnId {
        /// The entry's place in the dictionary.
        at: usize,
    },
    /// A dictionary entry names id 0, which is the literal's and no key's.
    ZeroId {
        /// The entry's place in the dictionary.
        at: usize,
    },
    /// Two dictionary entries name the same id.
    DuplicateId {
        /// The id.
        id: u16,
    },
    /// Two dictionary entries name the same key.
    DuplicateKey {
        /// The key.
        key: &'a str,
    },
    /// A dictionary entry names a text that is not a canonical key expression.
    NotAKeyExpr {
        /// The entry's place in the dictionary.
        at: usize,
        /// The text.
        key: &'a str,
        /// Where and why the text stops being one.
        refusal: KeyexprRefusal,
    },
    /// The dictionary has more entries than the `MAX_SHARED_KEY_IDS` the document resolves to:
    /// the one it states, or the build's.
    TooMany {
        /// How many it has.
        stated: usize,
        /// How many the limit admits.
        limit: usize,
    },
    /// A link entry names an empty locator, which no endpoint is.
    EmptyLocator {
        /// The entry's place in the links.
        at: usize,
    },
    /// A link entry names a form `key-wire-form` does not have.
    UnknownForm {
        /// The endpoint.
        locator: &'a str,
        /// The form stated.
        form: &'a str,
    },
    /// A link entry names a form the build's domain of `key-wire-form` leaves out.
    FormOutsideDomain {
        /// The endpoint.
        locator: &'a str,
        /// The form stated.
        form: &'a str,
    },
    /// Two link entries name the same locator.
    LinkStatedTwice {
        /// The locator.
        locator: &'a str,
    },
}

impl fmt::Display for KeyIdsReason<'_> {
    /// What the layer states and why it is refused, as the words after the layer's name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DICTIONARY: &str = "wz/key-ids/dictionary";
        const FORM: &str = <KeyWireForm as PolicyValue>::POLICY;
        match *self {
            Self::NotInBuild => f.write_str(
                "states `wz/key-ids`, which a build without the `shared-key-ids` capability does \
                 not read",
            ),
            Self::UnknownMember { member } => write!(
                f,
                "states `wz/key-ids/{member}`, which wz does not read (it reads `dictionary` and \
                 `links`)"
            ),
            Self::NotAnArray { member } => {
                write!(f, "states `{member}` as something other than an array")
            }
            Self::EntryNotAnObject { member, at } => write!(
                f,
                "states entry {at} of `{member}` as something other than an object"
            ),
            Self::MissingField { member, at, field } => {
                write!(f, "states entry {at} of `{member}` without its `{field}`")
            }
            Self::UnknownField { member, at, field } => write!(
                f,
                "states `{field}` in entry {at} of `{member}`, which such an entry does not have"
            ),
            Self::FieldStatedTwice { member, at, field } => write!(
                f,
                "states `{field}` more than once in entry {at} of `{member}`"
            ),
            Self::NotAString { member, at, field } => write!(
                f,
                "states the `{field}` of entry {at} of `{member}` as something other than a string"
            ),
            Self::NotAnId { at } => write!(
                f,
                "states the `id` of entry {at} of `{DICTIONARY}` as something other than an \
                 integer from 0 to 65535"
            ),
            Self::ZeroId { at } => write!(
                f,
                "states id 0 in entry {at} of `{DICTIONARY}`, and no key may have it"
            ),
            Self::DuplicateId { id } => {
                write!(f, "states the id {id} more than once in `{DICTIONARY}`")
            }
            Self::DuplicateKey { key } => {
                write!(f, "states the key `{key}` more than once in `{DICTIONARY}`")
            }
            Self::NotAKeyExpr { at, key, refusal } => write!(
                f,
                "states `{key}` in entry {at} of `{DICTIONARY}`, which is not a canonical key \
                 expression ({:?} at byte {})",
                refusal.fault, refusal.offset
            ),
            Self::TooMany { stated, limit } => write!(
                f,
                "states {stated} entries in `{DICTIONARY}`, and the session's limit admits \
                 {limit} (MAX_SHARED_KEY_IDS)"
            ),
            Self::EmptyLocator { at } => write!(
                f,
                "states an empty `locator` in entry {at} of `wz/key-ids/links`"
            ),
            Self::UnknownForm { locator, form } => {
                write!(
                    f,
                    "states the key-wire form `{form}` for `{locator}`, and `{FORM}` has no \
                     value `{form}` (its values: "
                )?;
                write_ids(f, <KeyWireForm as PolicyValue>::IDS.iter().copied())?;
                f.write_str(")")
            }
            Self::FormOutsideDomain { locator, form } => write!(
                f,
                "states the key-wire form `{form}` for `{locator}`, and the build leaves `{form}` \
                 out of the domain of `{FORM}` (it allows {})",
                PolicyEntry::of::<KeyWireForm>().domain()
            ),
            Self::LinkStatedTwice { locator } => write!(
                f,
                "states the key-wire form of `{locator}` more than once in `wz/key-ids/links`"
            ),
        }
    }
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
                "{layer} states `wz/{member}`, which wz does not read (it reads `wz/profile`, \
                 `wz/policies`, `wz/limits` and `wz/key-ids`)"
            ),
            Reason::MemberStatedTwice { member } => {
                write!(f, "{layer} states `{member}` more than once")
            }
            Reason::UnknownLimit { limit } => write!(
                f,
                "{layer} states the limit `{limit}`, and the build has no limit `{limit}`"
            ),
            Reason::LimitBuildOnly { limit } => write!(
                f,
                "{layer} states the limit `{limit}`, and only the build decides `{limit}`: it \
                 sizes storage by it"
            ),
            Reason::LimitNotRead { limit } => write!(
                f,
                "{layer} states the limit `{limit}`, and the machines of this build do not read \
                 `{limit}` from a statement yet; they run with the build's value"
            ),
            Reason::LimitOutsideDomain { limit, value, why } => {
                write!(f, "{layer} states the limit `{limit}` = `{value}`, and ")?;
                write_outside(f, limit, value, why)
            }
            Reason::LimitWrongScope { limit, scope } => write!(
                f,
                "{layer} states the limit `{limit}`, which each {} holds, and this creator \
                 holds the limits of a session alone",
                scope.id()
            ),
            Reason::NotALimitValue { limit } => write!(
                f,
                "{layer} states `wz/limits/{limit}` as something other than a whole number from \
                 0 to {} or `{UNBOUNDED}`",
                usize::MAX
            ),
            Reason::LimitStatedTwice { limit } => write!(
                f,
                "{layer} states the limit `{limit}` again; a layer states a limit once"
            ),
            Reason::KeyIds(reason) => write!(f, "{layer} {reason}"),
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
    let index = select_policy(
        table,
        &mut resolved.policy,
        &layer.statements[..at],
        statement,
    )?;
    resolved.provenance.origins[index] = layer.origin;
    Ok(())
}

/// `statement`, which its layer states after `earlier`, selected in `snapshot` by the policies of
/// `table`, which a refusal leaves as it was: the place of the policy in `table`.
fn select_policy<'a>(
    table: &[PolicyEntry; POLICY_COUNT],
    snapshot: &mut SessionPolicy,
    earlier: &[Statement<'a>],
    statement: &Statement<'a>,
) -> Result<usize, Reason<'a>> {
    let (policy, value) = (statement.policy, statement.value);
    let Some(index) = table.iter().position(|entry| entry.id() == policy) else {
        return Err(Reason::UnknownPolicy { policy, value });
    };
    let entry = &table[index];
    let id = entry.id();
    if earlier.iter().any(|stated| stated.policy == policy) {
        return Err(Reason::StatedTwice { policy: id, value });
    }
    if entry.binding() == Binding::Build {
        return Err(Reason::BuildBound { policy: id, value });
    }
    match entry.select(snapshot, value) {
        Ok(()) => Ok(index),
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

/// Where a limit's id is found: a field of one of the two snapshots, by its place in that
/// snapshot's table, or a capacity alone, which neither holds.
#[derive(Clone, Copy)]
enum FoundLimit {
    Session(usize),
    Runtime(usize),
    Capacity(&'static str),
}

impl FoundLimit {
    /// Where the limit whose id is `id` is, or `None` for an id the build has no limit of.
    fn find(id: &str) -> Option<Self> {
        if let Some(index) = SESSION_LIMITS.iter().position(|entry| entry.id() == id) {
            return Some(Self::Session(index));
        }
        if let Some(index) = RUNTIME_LIMITS.iter().position(|entry| entry.id() == id) {
            return Some(Self::Runtime(index));
        }
        CAPACITY_LIMITS
            .iter()
            .copied()
            .find(|capacity| *capacity == id)
            .map(Self::Capacity)
    }

    /// The limit's id, as the declaration spells it.
    fn id(self) -> &'static str {
        match self {
            Self::Session(index) => SESSION_LIMITS[index].id(),
            Self::Runtime(index) => RUNTIME_LIMITS[index].id(),
            Self::Capacity(id) => id,
        }
    }

    /// Whether the machines of the limit's scope read it from the snapshot. A capacity alone is
    /// in no snapshot, so it is read from the build.
    fn is_read(self) -> bool {
        match self {
            Self::Session(index) => SESSION_LIMITS[index].read_from_snapshot(),
            Self::Runtime(index) => RUNTIME_LIMITS[index].read_from_snapshot(),
            Self::Capacity(_) => false,
        }
    }
}

/// The limits `layers` state, the lowest first, over the snapshots of `base`, each refusal pushed
/// onto `refusals`. What it returns is the caller's to drop when a refusal was pushed.
fn compose_limits<'a>(
    base: &Base,
    layers: &[(LimitOrigin, &[LimitStatement<'a>])],
    refusals: &mut Refusals<'a>,
) -> ResolvedLimits {
    let runtime = base.runtime_limits.unwrap_or(RuntimeLimits::BUILD);
    let mut resolved = ResolvedLimits::unchanged(base.session_limits, runtime);
    let holds_runtime = base.runtime_limits.is_some();
    for &(origin, statements) in layers {
        for (at, statement) in statements.iter().enumerate() {
            let earlier = &statements[..at];
            if let Err(reason) =
                apply_limit(&mut resolved, holds_runtime, origin, earlier, statement)
            {
                refusals.push(Refusal {
                    layer: origin.origin(),
                    reason,
                });
            }
        }
    }
    resolved
}

/// `statement` of a layer whose `origin` is given and whose statements before it are `earlier`,
/// applied to `resolved`, which a refusal leaves as it was.
fn apply_limit<'a>(
    resolved: &mut ResolvedLimits,
    holds_runtime: bool,
    origin: LimitOrigin,
    earlier: &[LimitStatement<'a>],
    statement: &LimitStatement<'a>,
) -> Result<(), Reason<'a>> {
    let runtime = holds_runtime.then_some(&mut resolved.runtime);
    match select_stated_limit(&mut resolved.session, runtime, earlier, statement)? {
        FoundLimit::Session(index) => resolved.provenance.session[index] = origin,
        FoundLimit::Runtime(index) => resolved.provenance.runtime[index] = origin,
        // A capacity is refused before anything is selected, so it is never what was selected.
        FoundLimit::Capacity(_) => {}
    }
    Ok(())
}

/// `statement`, which its layer states after `earlier`, selected in `session`, or in `runtime`
/// for a limit of a runtime when the creator holds one (`Some`), which a refusal leaves as they
/// were: where the limit was found.
fn select_stated_limit<'a>(
    session: &mut SessionLimits,
    runtime: Option<&mut RuntimeLimits>,
    earlier: &[LimitStatement<'a>],
    statement: &LimitStatement<'a>,
) -> Result<FoundLimit, Reason<'a>> {
    let (limit, value) = (statement.limit, statement.value);
    let Some(found) = FoundLimit::find(limit) else {
        return Err(Reason::UnknownLimit { limit });
    };
    let id = found.id();
    if earlier.iter().any(|stated| stated.limit == limit) {
        return Err(Reason::LimitStatedTwice { limit: id });
    }
    match found {
        FoundLimit::Capacity(_) => return Err(Reason::LimitBuildOnly { limit: id }),
        // Before the scope and the value: a limit no machine reads is refused whatever is stated.
        _ if !found.is_read() => return Err(Reason::LimitNotRead { limit: id }),
        FoundLimit::Session(index) => select_limit(&SESSION_LIMITS[index], session, value)?,
        FoundLimit::Runtime(index) => match runtime {
            Some(runtime) => select_limit(&RUNTIME_LIMITS[index], runtime, value)?,
            None => {
                return Err(Reason::LimitWrongScope {
                    limit: id,
                    scope: Scope::Runtime,
                })
            }
        },
    }
    Ok(found)
}

/// `value` selected in `snapshot` through `entry`, which refuses what the build's domain leaves
/// out and leaves `snapshot` as it was. A bound stated as `0` is refused first: a quota of `0` is
/// what a build that sizes a table of no rows runs with, and a layer that states it would admit
/// nothing.
fn select_limit<'a, S: 'static>(
    entry: &LimitEntry<S>,
    snapshot: &mut S,
    value: LimitValue,
) -> Result<(), Reason<'a>> {
    if entry.kind() == LimitKind::Bound && value == LimitValue::Integer(0) {
        return Err(Reason::LimitOutsideDomain {
            limit: entry.id(),
            value,
            why: Outside::Below { least: 1 },
        });
    }
    match entry.select(snapshot, value) {
        Some(selected) => selected.map_err(|refused| Reason::LimitOutsideDomain {
            limit: refused.limit,
            value: refused.value,
            why: refused.why,
        }),
        // Refused before a value is selected (`apply_limit`); a caller that skips that order is
        // refused the same way rather than accepted.
        None => Err(Reason::LimitNotRead { limit: entry.id() }),
    }
}

/// `base` with what a caller states and no document: the profile `overrides` names, then its
/// statements and its limits ([`Origin::Api`]). It answers what `resolve_document_under` answers
/// for a document with no `wz` member, without reading a document, so a build that is handed none
/// links no reader of one.
// The refusals are held inline because the core has no heap to box them in.
#[allow(clippy::result_large_err)]
pub fn resolve_under<'a>(
    base: impl Into<Base>,
    overrides: Overrides<'_, 'a>,
) -> Result<Resolved, Refusals<'a>> {
    let base = base.into();
    let mut refusals = Refusals::new();
    let stated = find_profile(overrides.profile, Origin::Api, &mut refusals);
    let api = Layer {
        origin: Origin::Api,
        statements: overrides.statements,
    };
    let mut resolved = match stated {
        Some(profile) => compose(
            &POLICIES,
            base.policy,
            &[profile.layer(), api],
            &mut refusals,
        ),
        None => compose(&POLICIES, base.policy, &[api], &mut refusals),
    };
    resolved.limits = compose_limits(
        &base,
        &[(LimitOrigin::Api, overrides.limits)],
        &mut refusals,
    );
    if refusals.is_empty() {
        Ok(resolved)
    } else {
        Err(refusals)
    }
}

/// What the `wz` member of a document states, read by a caller that keeps no tree of it: the
/// profile it names, the statements of its `wz/policies` and those of its `wz/limits`, each in
/// the document's order. `Default` is a document with no `wz` member.
#[derive(Clone, Copy, Debug, Default)]
pub struct DocumentLayers<'s, 'a> {
    /// The id `wz/profile` names, if it names one.
    pub profile: Option<&'a str>,
    /// The members of `wz/policies`.
    pub statements: &'s [Statement<'a>],
    /// The members of `wz/limits`.
    pub limits: &'s [LimitStatement<'a>],
}

/// `base` with the document's layers and what the caller states over them, as
/// `resolve_document_under` resolves a document whose `wz` member states `document`: the
/// profile `overrides` names, else the document's, then the document's statements
/// ([`Origin::Document`]), then the caller's ([`Origin::Api`]), and the two layers of limits over
/// the limits of `base`. For a reader that walks the document and keeps what it states in storage
/// of its own, with no tree; the key ids a document states are that reader's to judge.
// The refusals are held inline because the core has no heap to box them in.
#[allow(clippy::result_large_err)]
pub fn resolve_layers_under<'a>(
    base: impl Into<Base>,
    document: DocumentLayers<'_, 'a>,
    overrides: Overrides<'_, 'a>,
) -> Result<Resolved, Refusals<'a>> {
    let mut refusals = Refusals::new();
    let resolved = compose_document(&POLICIES, base.into(), document, overrides, &mut refusals);
    if refusals.is_empty() {
        Ok(resolved)
    } else {
        Err(refusals)
    }
}

/// `document` and then `overrides` over `base` by the policies of `table`, each refusal pushed
/// onto `refusals`: a profile either names that the build does not have is refused in the layer
/// that named it, the document's one too when `overrides` names another.
fn compose_document<'a>(
    table: &[PolicyEntry; POLICY_COUNT],
    base: Base,
    document: DocumentLayers<'_, 'a>,
    overrides: Overrides<'_, 'a>,
    refusals: &mut Refusals<'a>,
) -> Resolved {
    let named = find_profile(document.profile, Origin::Document, refusals);
    let stated = find_profile(overrides.profile, Origin::Api, refusals);
    let stated_in_document = Layer {
        origin: Origin::Document,
        statements: document.statements,
    };
    let api = Layer {
        origin: Origin::Api,
        statements: overrides.statements,
    };
    let mut resolved = match stated.or(named) {
        Some(profile) => compose(
            table,
            base.policy,
            &[profile.layer(), stated_in_document, api],
            refusals,
        ),
        None => compose(table, base.policy, &[stated_in_document, api], refusals),
    };
    resolved.limits = compose_limits(
        &base,
        &[
            (LimitOrigin::Document, document.limits),
            (LimitOrigin::Api, overrides.limits),
        ],
        refusals,
    );
    resolved
}

/// [`resolve_under`] for a creator that keeps no record of where each value came from, written
/// where its snapshots lie: the profile `overrides` names and then its statements over `policy`,
/// and its limits over `limits`, the snapshot of a session's, for a creator that holds no
/// runtime's limits ([`Base::session`]). Over the same snapshots it accepts what `resolve_under`
/// accepts and writes the snapshots that resolves.
///
/// No [`Resolved`] and no [`Refusals`] is made: the origin of every policy and limit and room
/// for eight refusals are what make a resolution heavy on the stack of an open that is to stay
/// shallow. The first refusal ends the resolution and is answered; what was written by then is no
/// resolution, and the caller drops it.
// The refusal is held inline because the core has no heap to box it in.
#[allow(clippy::result_large_err)]
pub fn resolve_under_into<'a>(
    overrides: Overrides<'_, 'a>,
    policy: &mut SessionPolicy,
    limits: &mut SessionLimits,
) -> Result<(), Refusal<'a>> {
    if let Some(id) = overrides.profile {
        let Some(profile) = Profile::find(id) else {
            return Err(Refusal {
                layer: Origin::Api,
                reason: Reason::UnknownProfile { profile: id },
            });
        };
        write_layer(&POLICIES, policy, &profile.layer())?;
    }
    let api = Layer {
        origin: Origin::Api,
        statements: overrides.statements,
    };
    write_layer(&POLICIES, policy, &api)?;
    for (at, statement) in overrides.limits.iter().enumerate() {
        select_stated_limit(limits, None, &overrides.limits[..at], statement).map_err(
            |reason| Refusal {
                layer: Origin::Api,
                reason,
            },
        )?;
    }
    Ok(())
}

/// Each statement of `layer` selected in `snapshot` by the policies of `table`, in its order, up
/// to the first that is refused, which is answered.
// The refusal is held inline because the core has no heap to box it in.
#[allow(clippy::result_large_err)]
fn write_layer<'a>(
    table: &[PolicyEntry; POLICY_COUNT],
    snapshot: &mut SessionPolicy,
    layer: &Layer<'_, 'a>,
) -> Result<(), Refusal<'a>> {
    for (at, statement) in layer.statements.iter().enumerate() {
        select_policy(table, snapshot, &layer.statements[..at], statement).map_err(|reason| {
            Refusal {
                layer: layer.origin,
                reason,
            }
        })?;
    }
    Ok(())
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

    #[cfg(not(feature = "shared-key-ids"))]
    use super::KeyIdsReason;
    use super::{
        compose_document, Base, DocumentLayers, LimitStatement, Origin, Overrides, Reason, Refusal,
        Refusals, Resolved, Statement,
    };
    use crate::json5::{number_as_u64, Json5Value};
    use crate::limit_binding::{LimitValue, UNBOUNDED};
    use crate::policy::{POLICIES, POLICY_COUNT};
    use crate::policy_binding::PolicyEntry;

    /// What the `wz` member of a document states: the profile it names, the statements of its
    /// `wz/policies` and of its `wz/limits`, each in the document's order, and the key ids of its
    /// `wz/key-ids`.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct DocumentStatements<'a> {
        /// The id `wz/profile` names, if it names one.
        pub profile: Option<&'a str>,
        /// The members of `wz/policies`, each a policy's id and a value's id.
        pub statements: Vec<Statement<'a>>,
        /// The members of `wz/limits`, each a limit's id and its value.
        pub limits: Vec<LimitStatement<'a>>,
        /// The dictionary and the endpoints' key-wire forms `wz/key-ids` states; nothing when
        /// the document states no such member.
        #[cfg(feature = "shared-key-ids")]
        pub key_ids: crate::shared_key_ids::KeyIdsAtOpen,
    }

    /// The profile and the statements the `wz` member of `tree` states, or every refusal of its
    /// shape: a `wz`, `wz/policies` or `wz/limits` that is not an object, a policy's value that
    /// is not a string, a limit's value that is neither a whole number nor `unbounded`, a member
    /// of `wz` other than `profile`, `policies`, `limits` and `key-ids`, a member stated twice,
    /// and every refusal of `wz/key-ids` ([`super::KeyIdsReason`]). A document with no `wz`
    /// member states nothing. Whether the policies, the limits, the values and the profile exist
    /// is for [`resolve_document`].
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
    /// it ([`super::resolve`]), and its own limits over the limits of `base`, or every refusal
    /// found, of the document's shape and of its statements. A document with no `wz` member is
    /// `base`, every value from the build defaults. A `SessionPolicy` is a base that holds a
    /// session's limits alone ([`Base::session`]).
    // The refusals are held inline because the core has no heap to box them in.
    #[allow(clippy::result_large_err)]
    pub fn resolve_document(
        base: impl Into<Base>,
        tree: &Json5Value,
    ) -> Result<Resolved, Refusals<'_>> {
        resolve_document_in(&POLICIES, base.into(), tree, Overrides::default())
    }

    /// [`resolve_document`] with what the open's caller states over the document: the profile
    /// `overrides` names stands in for the one the document names, and its statements and its
    /// limits are the last layer ([`Origin::Api`]). A profile either names that the build does
    /// not have is refused in the layer that named it, the document's one too when `overrides`
    /// names another: the document is judged whole whatever is stated over it.
    // The refusals are held inline because the core has no heap to box them in.
    #[allow(clippy::result_large_err)]
    pub fn resolve_document_under<'a>(
        base: impl Into<Base>,
        tree: &'a Json5Value,
        overrides: Overrides<'_, 'a>,
    ) -> Result<Resolved, Refusals<'a>> {
        resolve_document_in(&POLICIES, base.into(), tree, overrides)
    }

    // The policies are a parameter so a test can resolve with a policy the build does not have.
    #[allow(clippy::result_large_err)]
    pub(super) fn resolve_document_in<'a>(
        table: &[PolicyEntry; POLICY_COUNT],
        base: Base,
        tree: &'a Json5Value,
        overrides: Overrides<'_, 'a>,
    ) -> Result<Resolved, Refusals<'a>> {
        let mut refusals = Refusals::new();
        let read = read_wz(tree, &mut refusals);
        let document = DocumentLayers {
            profile: read.profile,
            statements: &read.statements,
            limits: &read.limits,
        };
        let resolved = compose_document(table, base, document, overrides, &mut refusals);
        // The reader of `wz/key-ids` cannot count the dictionary against a limit the same
        // document may state; the composed limits can.
        #[cfg(feature = "shared-key-ids")]
        if let Err(crate::shared_key_ids::KeyIdsRefused::TooMany { stated, limit }) =
            read.key_ids.check_limits(&resolved.limits.session)
        {
            refusals.push(Refusal {
                layer: Origin::Document,
                reason: Reason::KeyIds(super::KeyIdsReason::TooMany { stated, limit }),
            });
        }
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
        limits: bool,
        key_ids: bool,
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
                "key-ids" => {
                    if seen.key_ids {
                        refuse(
                            refusals,
                            Reason::MemberStatedTwice {
                                member: "wz/key-ids",
                            },
                        );
                    }
                    seen.key_ids = true;
                    #[cfg(feature = "shared-key-ids")]
                    {
                        read.key_ids = crate::shared_key_ids::read_document_member(
                            value,
                            crate::shared_key_ids::form_in_domain,
                            refusals,
                        );
                    }
                    #[cfg(not(feature = "shared-key-ids"))]
                    refuse(refusals, Reason::KeyIds(KeyIdsReason::NotInBuild));
                }
                "limits" => {
                    if seen.limits {
                        refuse(
                            refusals,
                            Reason::MemberStatedTwice {
                                member: "wz/limits",
                            },
                        );
                    }
                    seen.limits = true;
                    let Json5Value::Object(stated) = value else {
                        refuse(
                            refusals,
                            Reason::NotAnObject {
                                member: "wz/limits",
                            },
                        );
                        continue;
                    };
                    for (limit, value) in stated {
                        match limit_value(value) {
                            Some(value) => {
                                read.limits.push(LimitStatement::new(limit.as_str(), value))
                            }
                            None => refuse(
                                refusals,
                                Reason::NotALimitValue {
                                    limit: limit.as_str(),
                                },
                            ),
                        }
                    }
                }
                other => refuse(refusals, Reason::UnknownMember { member: other }),
            }
        }
    }

    /// The value a member of `wz/limits` states: a whole number a `usize` holds, read as every
    /// number of the configuration is ([`number_as_u64`]), or `unbounded`. `None` for anything
    /// else.
    fn limit_value(value: &Json5Value) -> Option<LimitValue> {
        match value {
            Json5Value::Number(text) => number_as_u64(text)
                .and_then(|number| usize::try_from(number).ok())
                .map(LimitValue::Integer),
            Json5Value::String(text) if text == UNBOUNDED => Some(LimitValue::Unbounded),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit_binding::{LimitSpec, Quota};
    use crate::limits::MaxSubscriptions;
    use crate::policy::{EventRingFull, KeySet, SubscriberOverload};
    use crate::policy_binding::{
        Bound, Domain, Mutability, OutsideDomain, PolicyField, PolicyValue, Scope, Wire,
    };
    use std::format;
    use std::string::String;
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

    /// The build's value of `MAX_SUBSCRIPTIONS`, a bound the machines of a session read from
    /// the snapshot.
    fn subscriptions() -> Quota {
        SessionLimits::defaults().max_subscriptions()
    }

    /// A count of `MAX_SUBSCRIPTIONS` other than the build's, inside its domain wherever the
    /// build allows more than its own value.
    fn other_subscriptions() -> usize {
        if subscriptions() == Quota::at_most(3) {
            4
        } else {
            3
        }
    }

    /// The first limit of `table` whose machines still read the build's value.
    fn unread<S: 'static>(table: &'static [LimitEntry<S>]) -> &'static LimitEntry<S> {
        table
            .iter()
            .find(|entry| !entry.read_from_snapshot())
            .expect("a limit whose machines read the build's value")
    }

    /// The open's limits, and nothing else.
    fn limits_alone<'s, 'a>(limits: &'s [LimitStatement<'a>]) -> Overrides<'s, 'a> {
        Overrides {
            limits,
            ..Overrides::default()
        }
    }

    #[test]
    fn no_limit_stated_is_every_limit_at_the_build_defaults() {
        let resolved = resolve_under(SessionPolicy::defaults(), Overrides::default())
            .expect("nothing to refuse");
        assert_eq!(resolved, Resolved::unchanged(SessionPolicy::defaults()));
        assert_eq!(resolved.limits.session, SessionLimits::defaults());
        assert_eq!(resolved.limits.runtime, RuntimeLimits::defaults());
        assert!(resolved
            .limits
            .provenance
            .iter()
            .all(|(_, origin)| origin == Origin::BuildDefault));
        assert_eq!(
            resolved.limits.provenance.iter().count(),
            SESSION_LIMIT_COUNT + RUNTIME_LIMIT_COUNT
        );
        assert_eq!(resolved.limits.provenance.origin("MAX_TASKS"), None);
        assert_eq!(resolved.limits.provenance.origin("NO_SUCH_LIMIT"), None);
    }

    /// A limit the open states is selected into the session's snapshot and recorded as the
    /// API's; a limit it does not state keeps the build default.
    #[test]
    fn a_limit_the_open_states_is_selected_and_records_the_api() {
        let other = other_subscriptions();
        let stated = [LimitStatement::new(
            "MAX_SUBSCRIPTIONS",
            LimitValue::Integer(other),
        )];
        let resolved = resolve_under(SessionPolicy::defaults(), limits_alone(&stated));
        if MaxSubscriptions::DOMAIN.is_singleton() {
            // A build that keeps its own value alone refuses another, naming its own.
            assert_eq!(
                only(&resolved.unwrap_err()).reason,
                Reason::LimitOutsideDomain {
                    limit: "MAX_SUBSCRIPTIONS",
                    value: LimitValue::Integer(other),
                    why: Outside::Pinned {
                        only: subscriptions().as_value()
                    },
                }
            );
            return;
        }
        let resolved = resolved.expect("inside the domain");
        assert_eq!(
            resolved.limits.session.max_subscriptions(),
            Quota::at_most(other)
        );
        let origin = |limit| resolved.limits.provenance.origin(limit);
        assert_eq!(origin("MAX_SUBSCRIPTIONS"), Some(Origin::Api));
        assert_eq!(origin("MAX_QUERYABLES"), Some(Origin::BuildDefault));
        assert_eq!(resolved.limits.runtime, RuntimeLimits::defaults());
        assert_eq!(resolved.policy, SessionPolicy::defaults());
    }

    /// The open's statement of a limit whose machines still read the build's value is refused by
    /// name, whatever the value and before the scope is asked, and the open selects nothing; a
    /// limit they read from the snapshot is selected and recorded as the open's.
    #[test]
    fn a_limit_no_machine_reads_is_refused_to_the_open_and_a_read_one_is_selected() {
        let session = unread(&SESSION_LIMITS).id();
        let runtime = unread(&RUNTIME_LIMITS).id();
        let stated = [
            LimitStatement::new(session, LimitValue::Unbounded),
            LimitStatement::new(runtime, LimitValue::Integer(1)),
        ];
        let refusals = resolve_under(SessionPolicy::defaults(), limits_alone(&stated)).unwrap_err();
        let found: Vec<_> = refusals
            .iter()
            .map(|refusal| (refusal.layer, refusal.reason))
            .collect();
        assert_eq!(
            found,
            [
                (Origin::Api, Reason::LimitNotRead { limit: session }),
                (Origin::Api, Reason::LimitNotRead { limit: runtime }),
            ]
        );
        assert_eq!(
            format!("{}", refusals.iter().next().expect("two refusals")),
            format!(
                "the open's overrides states the limit `{session}`, and the machines of this \
                 build do not read `{session}` from a statement yet; they run with the build's \
                 value"
            )
        );
        assert!(SESSION_LIMITS
            .iter()
            .any(|entry| entry.id() == "MAX_SUBSCRIPTIONS" && entry.read_from_snapshot()));
        let read = [LimitStatement::new(
            "MAX_SUBSCRIPTIONS",
            subscriptions().as_value(),
        )];
        let resolved = resolve_under(SessionPolicy::defaults(), limits_alone(&read))
            .expect("the build's own value of a limit the machines read");
        let origin = |limit| resolved.limits.provenance.origin(limit);
        assert_eq!(origin("MAX_SUBSCRIPTIONS"), Some(Origin::Api));
        assert_eq!(origin(session), Some(Origin::BuildDefault));
        assert_eq!(resolved.limits.session, SessionLimits::defaults());
    }

    /// Each refusal of a limit statement names the limit, and the domain's reason where the
    /// value is outside it. A refusal leaves nothing selected: the resolution answers no
    /// snapshot.
    #[test]
    fn each_limit_refusal_names_the_limit_and_why() {
        let session = unread(&SESSION_LIMITS).id();
        let runtime = unread(&RUNTIME_LIMITS).id();
        let build = subscriptions().as_value();
        let stated = [
            LimitStatement::new("NO_SUCH_LIMIT", LimitValue::Integer(4)),
            LimitStatement::new("MAX_TASKS", LimitValue::Integer(4)),
            LimitStatement::new(session, LimitValue::Integer(4)),
            LimitStatement::new("QUERIER_MAX_PENDING_QUERIES", LimitValue::Integer(0)),
            LimitStatement::new("MAX_SUBSCRIPTIONS", build),
            LimitStatement::new("MAX_SUBSCRIPTIONS", build),
            LimitStatement::new(runtime, LimitValue::Integer(500)),
        ];
        let refusals = resolve_under(SessionPolicy::defaults(), limits_alone(&stated)).unwrap_err();
        assert!(refusals.iter().all(|refusal| refusal.layer == Origin::Api));
        let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
        assert_eq!(
            reasons,
            [
                Reason::UnknownLimit {
                    limit: "NO_SUCH_LIMIT"
                },
                Reason::LimitBuildOnly { limit: "MAX_TASKS" },
                Reason::LimitNotRead { limit: session },
                Reason::LimitOutsideDomain {
                    limit: "QUERIER_MAX_PENDING_QUERIES",
                    value: LimitValue::Integer(0),
                    why: Outside::Below { least: 1 },
                },
                Reason::LimitStatedTwice {
                    limit: "MAX_SUBSCRIPTIONS"
                },
                Reason::LimitNotRead { limit: runtime },
            ]
        );
        let text: Vec<_> = refusals
            .iter()
            .map(|refusal| format!("{refusal}"))
            .collect();
        let not_read = |limit: &str| {
            format!(
                "the open's overrides states the limit `{limit}`, and the machines of this build \
                 do not read `{limit}` from a statement yet; they run with the build's value"
            )
        };
        assert_eq!(
            text,
            [
                String::from(
                    "the open's overrides states the limit `NO_SUCH_LIMIT`, and the build has no \
                     limit `NO_SUCH_LIMIT`"
                ),
                String::from(
                    "the open's overrides states the limit `MAX_TASKS`, and only the build \
                     decides `MAX_TASKS`: it sizes storage by it"
                ),
                not_read(session),
                String::from(
                    "the open's overrides states the limit `QUERIER_MAX_PENDING_QUERIES` = `0`, \
                     and the limit `QUERIER_MAX_PENDING_QUERIES` is at least 1; `0` is less"
                ),
                String::from(
                    "the open's overrides states the limit `MAX_SUBSCRIPTIONS` again; a layer \
                     states a limit once"
                ),
                not_read(runtime),
            ]
        );
    }

    /// A value the build's domain leaves out is refused with the domain's reason: outside the
    /// declared range, or, where the build keeps its own value alone, another value; and a
    /// parameter is never `unbounded`. The document's reader selects through the parameter's
    /// entry, and each refusal leaves the snapshot as it was.
    #[test]
    fn a_limit_value_outside_the_domain_is_refused_with_the_domains_reason() {
        let entry = SESSION_LIMITS
            .iter()
            .find(|entry| entry.id() == "PICO_TX_QUEUE_SIZE")
            .expect("declared");
        assert!(
            entry.read_from_snapshot(),
            "the case is a parameter read from the snapshot"
        );
        assert_eq!(entry.kind(), LimitKind::Parameter);
        let build = entry.value_in(&SessionLimits::defaults());
        let pinned = entry.domain().is_singleton();
        let mut snapshot = SessionLimits::defaults();
        for (value, open) in [
            (
                LimitValue::Integer(17),
                Outside::OutsideRange { least: 1, most: 16 },
            ),
            (LimitValue::Unbounded, Outside::UnboundedParameter),
        ] {
            let why = if pinned {
                Outside::Pinned { only: build }
            } else {
                open
            };
            assert_eq!(
                select_limit(entry, &mut snapshot, value),
                Err(Reason::LimitOutsideDomain {
                    limit: "PICO_TX_QUEUE_SIZE",
                    value,
                    why,
                })
            );
        }
        assert_eq!(snapshot, SessionLimits::defaults());
        let refusal = Refusal {
            layer: Origin::Api,
            reason: Reason::LimitOutsideDomain {
                limit: "PICO_TX_QUEUE_SIZE",
                value: LimitValue::Unbounded,
                why: Outside::UnboundedParameter,
            },
        };
        assert_eq!(
            format!("{refusal}"),
            "the open's overrides states the limit `PICO_TX_QUEUE_SIZE` = `unbounded`, and the \
             limit `PICO_TX_QUEUE_SIZE` is a parameter, which is never `unbounded`"
        );
    }

    /// A node holds a runtime's limits: it selects into the runtime's snapshot each one whose
    /// machines read the snapshot, and refuses by name each one whose machines do not.
    #[test]
    fn a_node_selects_a_runtime_limit_into_the_runtimes_snapshot() {
        let base = Base::node(SessionPolicy::defaults());
        let runtime = RuntimeLimits::defaults();
        for entry in RUNTIME_LIMITS.iter() {
            let limit = entry.id();
            let build = entry.value_in(&runtime);
            let stated = [LimitStatement::new(limit, build)];
            let resolved = resolve_under(base, limits_alone(&stated));
            if !entry.read_from_snapshot() {
                assert_eq!(
                    only(&resolved.unwrap_err()).reason,
                    Reason::LimitNotRead { limit },
                    "{limit}"
                );
                continue;
            }
            // A bound stated as `0` is refused whatever the build's value.
            if entry.kind() == LimitKind::Bound && build == LimitValue::Integer(0) {
                continue;
            }
            let resolved = resolved.unwrap_or_else(|refused| panic!("{limit}: {refused}"));
            assert_eq!(resolved.limits.runtime, runtime, "{limit}");
            assert_eq!(
                resolved.limits.session,
                SessionLimits::defaults(),
                "{limit}"
            );
            assert_eq!(
                resolved.limits.provenance.origin(limit),
                Some(Origin::Api),
                "{limit}"
            );
        }
    }

    /// Every capacity alone is in neither snapshot, and a layer that states one is refused by
    /// name, whatever creator resolves it.
    #[test]
    fn a_capacity_alone_is_in_neither_snapshot_and_is_refused_by_name() {
        assert!(CAPACITY_LIMITS.contains(&"MAX_TASKS"));
        for capacity in CAPACITY_LIMITS.iter().copied() {
            assert!(
                SESSION_LIMITS.iter().all(|entry| entry.id() != capacity),
                "{capacity}"
            );
            assert!(
                RUNTIME_LIMITS.iter().all(|entry| entry.id() != capacity),
                "{capacity}"
            );
            let stated = [LimitStatement::new(capacity, LimitValue::Integer(1))];
            let refusals =
                resolve_under(Base::node(SessionPolicy::defaults()), limits_alone(&stated))
                    .unwrap_err();
            assert_eq!(
                only(&refusals).reason,
                Reason::LimitBuildOnly { limit: capacity }
            );
        }
    }

    /// Every limit whose machines read the snapshot takes the build's own value from a layer, and
    /// every other is refused by name, its build's value too. A limit whose domain is one value (a
    /// target with no operating system, or `WZ_LIMIT_DOMAINS=defaults`) refuses every other, and
    /// a refusal of a kept value names the value the build keeps.
    #[test]
    fn a_limit_takes_the_builds_value_and_one_of_one_value_refuses_every_other() {
        let base = Base::node(SessionPolicy::defaults());
        let runtime_limits = RuntimeLimits::defaults();
        let session = SESSION_LIMITS.iter().map(|entry| {
            let held = entry.value_in(&base.session_limits);
            let read = entry.read_from_snapshot();
            (entry.id(), entry.kind(), entry.domain(), held, read)
        });
        let runtime = RUNTIME_LIMITS.iter().map(|entry| {
            let held = entry.value_in(&runtime_limits);
            let read = entry.read_from_snapshot();
            (entry.id(), entry.kind(), entry.domain(), held, read)
        });
        for (limit, kind, domain, build, read) in session.chain(runtime) {
            if !read {
                let same = [LimitStatement::new(limit, build)];
                let refusals = resolve_under(base, limits_alone(&same)).unwrap_err();
                assert_eq!(
                    only(&refusals).reason,
                    Reason::LimitNotRead { limit },
                    "{limit}"
                );
                continue;
            }
            // A bound stated as `0` is refused whatever the build's value.
            let refused_as_zero = kind == LimitKind::Bound && build == LimitValue::Integer(0);
            if !refused_as_zero {
                let same = [LimitStatement::new(limit, build)];
                let resolved = resolve_under(base, limits_alone(&same))
                    .unwrap_or_else(|refused| panic!("{limit}: {refused}"));
                assert_eq!(
                    resolved.limits.provenance.origin(limit),
                    Some(Origin::Api),
                    "{limit}"
                );
                assert_eq!(resolved.limits.session, base.session_limits, "{limit}");
                assert_eq!(resolved.limits.runtime, runtime_limits, "{limit}");
            }
            if !domain.is_singleton() {
                continue;
            }
            let other = match build {
                LimitValue::Integer(value) => LimitValue::Integer(value + 1),
                LimitValue::Unbounded => LimitValue::Integer(1),
            };
            let another = [LimitStatement::new(limit, other)];
            let refusals = resolve_under(base, limits_alone(&another)).unwrap_err();
            let Reason::LimitOutsideDomain {
                limit: named,
                value,
                why,
            } = only(&refusals).reason
            else {
                panic!("{limit}: {refusals}");
            };
            assert_eq!((named, value), (limit, other));
            if let Outside::Pinned { only: kept } = why {
                assert_eq!(kept, build, "{limit}");
            }
        }
    }

    /// The resolution written into the snapshots answers what `resolve_under` answers for a
    /// session's creator: the same snapshots when it accepts, and the first of its refusals when
    /// it refuses, for no statement, a policy, a profile, a profile the build does not have, a
    /// policy stated twice, a refused policy beside a limit, a limit, a limit the build does not
    /// have, a limit no machine reads and a runtime's limit. Turned red by a path that selects
    /// otherwise than the resolution that records where each value came from.
    #[test]
    fn a_resolution_written_into_the_snapshots_answers_what_resolve_under_answers() {
        let base = SessionPolicy::defaults();
        let ring = another::<EventRingFull>().unwrap_or(EventRingFull::DEFAULT);
        let stated = [Statement::new("event-ring-full", id_of(ring))];
        let twice = [
            Statement::new("event-ring-full", id_of(ring)),
            Statement::new("event-ring-full", id_of(EventRingFull::DEFAULT)),
        ];
        let no_such_policy = [Statement::new("no-such-policy", "on")];
        let limit = [LimitStatement::new(
            "MAX_SUBSCRIPTIONS",
            LimitValue::Integer(other_subscriptions()),
        )];
        let no_such_limit = [LimitStatement::new("NO_SUCH_LIMIT", LimitValue::Integer(1))];
        let not_read = [LimitStatement::new(
            unread(&SESSION_LIMITS).id(),
            LimitValue::Integer(1),
        )];
        let tasks = [LimitStatement::new("MAX_TASKS", LimitValue::Integer(4))];
        let cases = [
            Overrides::default(),
            Overrides {
                profile: None,
                statements: &stated,
                limits: &[],
            },
            Overrides {
                profile: Some("upstream"),
                statements: &[],
                limits: &[],
            },
            Overrides {
                profile: Some("no-such-profile"),
                statements: &stated,
                limits: &[],
            },
            Overrides {
                profile: None,
                statements: &twice,
                limits: &[],
            },
            Overrides {
                profile: None,
                statements: &no_such_policy,
                limits: &limit,
            },
            limits_alone(&limit),
            limits_alone(&no_such_limit),
            limits_alone(&not_read),
            limits_alone(&tasks),
        ];
        for overrides in cases {
            let recorded = resolve_under(base, overrides);
            let mut policy = base;
            let mut limits = SessionLimits::defaults();
            let written = resolve_under_into(overrides, &mut policy, &mut limits);
            match recorded {
                Ok(resolved) => {
                    assert_eq!(written, Ok(()), "{overrides:?}");
                    assert_eq!(policy, resolved.policy, "{overrides:?}");
                    assert_eq!(limits, resolved.limits.session, "{overrides:?}");
                }
                Err(refusals) => assert_eq!(
                    written,
                    Err(*refusals.iter().next().expect("a refusal is held")),
                    "{overrides:?}"
                ),
            }
        }
        // CONTROL: a value stated over the build default is written into the snapshot.
        if ring != EventRingFull::DEFAULT {
            let mut policy = base;
            let mut limits = SessionLimits::defaults();
            let overrides = Overrides {
                profile: None,
                statements: &stated,
                limits: &[],
            };
            assert_eq!(
                resolve_under_into(overrides, &mut policy, &mut limits),
                Ok(())
            );
            assert_ne!(policy, base, "the statement moved the snapshot");
        }
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
        fn a_member_of_wz_it_does_not_read_is_refused() {
            let tree = parse(r#"{ wz: { limits: {}, colour: "blue" } }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(refusal.reason, Reason::UnknownMember { member: "colour" });
            assert_eq!(
                format!("{refusal}"),
                "the document states `wz/colour`, which wz does not read (it reads `wz/profile`, \
                 `wz/policies`, `wz/limits` and `wz/key-ids`)"
            );
        }

        /// `wz/limits` is read into its statements, each a limit's id and its value, and the
        /// resolution selects each into the snapshot that holds it, recorded as the document's.
        #[test]
        fn the_limits_the_document_states_are_read_and_selected() {
            let other = other_subscriptions();
            let text = format!(
                r#"{{ wz: {{ limits: {{ MAX_SUBSCRIPTIONS: {other}, QUERIER_MAX_PENDING_QUERIES: "unbounded" }} }} }}"#
            );
            let tree = parse(&text).unwrap();
            let read = statements_from_json5(&tree).expect("well formed");
            assert_eq!(
                read.limits,
                [
                    LimitStatement::new("MAX_SUBSCRIPTIONS", LimitValue::Integer(other)),
                    LimitStatement::new("QUERIER_MAX_PENDING_QUERIES", LimitValue::Unbounded),
                ]
            );
            let resolved = resolve_document(SessionPolicy::defaults(), &tree);
            if MaxSubscriptions::DOMAIN.is_singleton() {
                // A build that keeps its own value alone refuses another, naming its own.
                let refusals = resolved.unwrap_err();
                let pinned = Reason::LimitOutsideDomain {
                    limit: "MAX_SUBSCRIPTIONS",
                    value: LimitValue::Integer(other),
                    why: Outside::Pinned {
                        only: subscriptions().as_value(),
                    },
                };
                assert!(
                    refusals.iter().any(|refusal| refusal.reason == pinned),
                    "{refusals}"
                );
                return;
            }
            let resolved = resolved.expect("inside the domains");
            assert_eq!(
                resolved.limits.session.max_subscriptions(),
                Quota::at_most(other)
            );
            assert_eq!(
                resolved.limits.session.querier_max_pending_queries(),
                Quota::UNBOUNDED
            );
            let origin = |limit| resolved.limits.provenance.origin(limit);
            assert_eq!(origin("MAX_SUBSCRIPTIONS"), Some(Origin::Document));
            assert_eq!(
                origin("QUERIER_MAX_PENDING_QUERIES"),
                Some(Origin::Document)
            );
            assert_eq!(origin("MAX_QUERYABLES"), Some(Origin::BuildDefault));
            assert_eq!(resolved.policy, SessionPolicy::defaults());
            assert_eq!(resolved.provenance, Provenance::build_defaults());
        }

        /// A member of `wz/limits` that is neither a whole number a `usize` holds nor
        /// `unbounded` is refused by the reader, before any limit is looked up.
        #[test]
        fn a_limit_value_that_is_no_whole_number_or_unbounded_is_refused() {
            let tree = parse(
                r#"{ wz: { limits: { A: true, B: -1, C: 1.5, D: "lots", E: {}, F: 18446744073709551616, G: null } } }"#,
            )
            .unwrap();
            let refusals = statements_from_json5(&tree).unwrap_err();
            let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
            let expected: Vec<_> = ["A", "B", "C", "D", "E", "F", "G"]
                .into_iter()
                .map(|limit| Reason::NotALimitValue { limit })
                .collect();
            assert_eq!(reasons, expected);
            assert_eq!(
                format!("{}", refusals.iter().next().expect("one refusal")),
                format!(
                    "the document states `wz/limits/A` as something other than a whole number \
                     from 0 to {} or `unbounded`",
                    usize::MAX
                )
            );
            // The resolution reports the reader's refusals and selects nothing.
            assert_eq!(
                resolve_document(SessionPolicy::defaults(), &tree).unwrap_err(),
                refusals
            );
            let tree = parse(r#"{ wz: { limits: [4] } }"#).unwrap();
            let refusal = only(&statements_from_json5(&tree).unwrap_err());
            assert_eq!(
                refusal.reason,
                Reason::NotAnObject {
                    member: "wz/limits"
                }
            );
        }

        /// JSON5 keeps `wz/limits` stated twice, and the later one must not win unnoticed.
        #[test]
        fn a_second_wz_limits_is_refused() {
            let tree = parse(r#"{ wz: { limits: {}, limits: {} } }"#).unwrap();
            let refusal = only(&resolve_document(SessionPolicy::defaults(), &tree).unwrap_err());
            assert_eq!(
                refusal.reason,
                Reason::MemberStatedTwice {
                    member: "wz/limits"
                }
            );
            assert_eq!(
                format!("{refusal}"),
                "the document states `wz/limits` more than once"
            );
        }

        /// The document states a limit once, as it states a policy once.
        #[test]
        fn a_limit_the_document_states_twice_is_refused() {
            let tree = parse(
                r#"{ wz: { limits: { QUERIER_MAX_PENDING_QUERIES: "unbounded", QUERIER_MAX_PENDING_QUERIES: "unbounded" } } }"#,
            )
            .unwrap();
            let refusal = only(&resolve_document(SessionPolicy::defaults(), &tree).unwrap_err());
            assert_eq!(refusal.layer, Origin::Document);
            assert_eq!(
                refusal.reason,
                Reason::LimitStatedTwice {
                    limit: "QUERIER_MAX_PENDING_QUERIES"
                }
            );
        }

        /// One resolution judges the policies and the limits: a refused limit refuses the
        /// document a good policy is in, and both refusals are reported.
        #[test]
        fn a_refused_limit_and_a_refused_policy_refuse_the_document_together() {
            let tree = parse(
                r#"{ wz: { policies: { "key-set": "ajar" }, limits: { NO_SUCH_LIMIT: 1, MAX_TASKS: 2 } } }"#,
            )
            .unwrap();
            let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
            let reasons: Vec<_> = refusals.iter().map(|refusal| refusal.reason).collect();
            assert_eq!(reasons.len(), 3, "{refusals}");
            assert!(matches!(
                reasons[0],
                Reason::UnknownValue {
                    policy: "key-set",
                    ..
                }
            ));
            assert_eq!(
                reasons[1..],
                [
                    Reason::UnknownLimit {
                        limit: "NO_SUCH_LIMIT"
                    },
                    Reason::LimitBuildOnly { limit: "MAX_TASKS" }
                ]
            );
        }

        /// The open's limits are the layer over the document's: a limit both state takes the
        /// open's value, recorded as the API's, and one only the document states keeps the
        /// document's.
        #[test]
        fn the_overrides_limits_are_read_over_the_documents() {
            let (document, api) = (other_subscriptions(), subscriptions());
            let text = format!(
                r#"{{ wz: {{ limits: {{ MAX_SUBSCRIPTIONS: {document}, QUERIER_MAX_PENDING_QUERIES: "unbounded" }} }} }}"#
            );
            let tree = parse(&text).unwrap();
            let stated = [LimitStatement::new("MAX_SUBSCRIPTIONS", api.as_value())];
            let overrides = Overrides {
                limits: &stated,
                ..Overrides::default()
            };
            let resolved = resolve_document_under(SessionPolicy::defaults(), &tree, overrides);
            if MaxSubscriptions::DOMAIN.is_singleton() {
                // The document's value is not the build's, and the build allows its own alone.
                assert!(resolved.is_err());
                return;
            }
            let resolved = resolved.expect("inside the domains");
            assert_eq!(resolved.limits.session.max_subscriptions(), api);
            let origin = |limit| resolved.limits.provenance.origin(limit);
            assert_eq!(origin("MAX_SUBSCRIPTIONS"), Some(Origin::Api));
            assert_eq!(
                origin("QUERIER_MAX_PENDING_QUERIES"),
                Some(Origin::Document)
            );
            // The document alone keeps its own.
            let alone = resolve_document(SessionPolicy::defaults(), &tree).expect("allowed");
            assert_eq!(
                alone.limits.session.max_subscriptions(),
                Quota::at_most(document)
            );
        }

        /// A runtime's limit in a document is refused to a creator that holds a session's limits
        /// alone, and read by a node, where the node's machines read it from the snapshot; where
        /// they do not, both refuse it by name before its scope is asked.
        #[test]
        fn a_runtime_limit_in_the_document_is_read_by_the_node_alone() {
            let runtime = RuntimeLimits::defaults();
            for entry in RUNTIME_LIMITS.iter() {
                let limit = entry.id();
                let build = entry.value_in(&runtime);
                // A bound stated as `0` is refused whatever the build's value.
                if entry.kind() == LimitKind::Bound && build == LimitValue::Integer(0) {
                    continue;
                }
                let value = match build {
                    LimitValue::Unbounded => format!("\"{UNBOUNDED}\""),
                    LimitValue::Integer(value) => format!("{value}"),
                };
                let tree =
                    parse(&format!("{{ wz: {{ limits: {{ {limit}: {value} }} }} }}")).unwrap();
                let session =
                    only(&resolve_document(SessionPolicy::defaults(), &tree).unwrap_err());
                let node = resolve_document(Base::node(SessionPolicy::defaults()), &tree);
                if !entry.read_from_snapshot() {
                    assert_eq!(session.reason, Reason::LimitNotRead { limit }, "{limit}");
                    assert_eq!(
                        only(&node.unwrap_err()).reason,
                        Reason::LimitNotRead { limit },
                        "{limit}"
                    );
                    continue;
                }
                assert_eq!(
                    session.reason,
                    Reason::LimitWrongScope {
                        limit,
                        scope: Scope::Runtime
                    },
                    "{limit}"
                );
                let node = node.unwrap_or_else(|refused| panic!("{limit}: {refused}"));
                assert_eq!(node.limits.runtime, runtime, "{limit}");
                assert_eq!(
                    node.limits.provenance.origin(limit),
                    Some(Origin::Document),
                    "{limit}"
                );
            }
        }

        /// The document's statement of a limit whose machines still read the build's value is
        /// refused by name, and with it the document; a limit they read from the snapshot is
        /// selected and recorded as the document's.
        #[test]
        fn a_limit_no_machine_reads_is_refused_to_the_document_and_a_read_one_is_selected() {
            let limit = unread(&SESSION_LIMITS).id();
            let tree = parse(&format!(
                r#"{{ wz: {{ limits: {{ {limit}: 1, QUERIER_MAX_PENDING_QUERIES: "unbounded" }} }} }}"#
            ))
            .unwrap();
            let refusal = only(&resolve_document(SessionPolicy::defaults(), &tree).unwrap_err());
            assert_eq!(refusal.layer, Origin::Document);
            assert_eq!(refusal.reason, Reason::LimitNotRead { limit });
            assert_eq!(
                format!("{refusal}"),
                format!(
                    "the document states the limit `{limit}`, and the machines of this build do \
                     not read `{limit}` from a statement yet; they run with the build's value"
                )
            );
            let tree = parse(r#"{ wz: { limits: { QUERIER_MAX_PENDING_QUERIES: "unbounded" } } }"#)
                .unwrap();
            let resolved = resolve_document(SessionPolicy::defaults(), &tree)
                .expect("a limit the machines read, at a value its domain holds");
            assert_eq!(
                resolved.limits.session.querier_max_pending_queries(),
                Quota::UNBOUNDED
            );
            let origin = |id| resolved.limits.provenance.origin(id);
            assert_eq!(
                origin("QUERIER_MAX_PENDING_QUERIES"),
                Some(Origin::Document)
            );
            assert_eq!(origin(limit), Some(Origin::BuildDefault));
        }

        /// A build without the capability refuses `wz/key-ids` by name, whatever it holds, and
        /// with it the whole document.
        #[cfg(not(feature = "shared-key-ids"))]
        #[test]
        fn key_ids_are_refused_by_name_in_a_build_without_the_capability() {
            let tree =
                parse(r#"{ wz: { "key-ids": { dictionary: [ { id: 40, key: "lab/rig" } ] } } }"#)
                    .unwrap();
            let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
            let refusal = only(&refusals);
            assert_eq!(refusal.reason, Reason::KeyIds(KeyIdsReason::NotInBuild));
            assert_eq!(
                format!("{refusal}"),
                "the document states `wz/key-ids`, which a build without the `shared-key-ids` \
                 capability does not read"
            );
            assert_eq!(
                statements_from_json5(&tree).unwrap_err(),
                refusals,
                "the shape reader refuses it the same"
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
                limits: &[],
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

        /// The layers a reader that keeps no tree read resolve as the tree they came from does:
        /// the same snapshots and provenance for a document's policy and limit under the caller's
        /// statement, and a refusal of a profile the document names and the build does not have,
        /// though the caller names another. Turned red by a composition of the layers other than
        /// `resolve_document_under`'s.
        #[test]
        fn layers_read_without_a_tree_resolve_as_their_document_does() {
            let Some(ring) = another::<EventRingFull>() else {
                return;
            };
            let text = format!(
                r#"{{ wz: {{ policies: {{ "event-ring-full": "{}" }}, limits: {{ MAX_SUBSCRIPTIONS: 3 }} }} }}"#,
                id_of(ring)
            );
            let tree = parse(&text).unwrap();
            let read = statements_from_json5(&tree).expect("well formed");
            let layers = DocumentLayers {
                profile: read.profile,
                statements: &read.statements,
                limits: &read.limits,
            };
            let base = SessionPolicy::defaults();
            let stated = [Statement::new(
                "event-ring-full",
                id_of(EventRingFull::DEFAULT),
            )];
            for overrides in [
                Overrides::default(),
                Overrides {
                    profile: None,
                    statements: &stated,
                    limits: &[],
                },
            ] {
                assert_eq!(
                    resolve_layers_under(base, layers, overrides),
                    resolve_document_under(base, &tree, overrides)
                );
            }
            let resolved =
                resolve_layers_under(base, layers, Overrides::default()).expect("allowed");
            assert_eq!(resolved.policy.event_ring_full(), ring);
            assert_eq!(
                resolved.provenance.origin("event-ring-full"),
                Some(Origin::Document)
            );
            let unknown = DocumentLayers {
                profile: Some("no-such-profile"),
                ..DocumentLayers::default()
            };
            let named = Overrides {
                profile: Some("upstream"),
                ..Overrides::default()
            };
            assert!(resolve_layers_under(base, unknown, named).is_err());
        }

        /// A caller handed no document resolves as one handed a document with no `wz` member:
        /// `resolve_under` and the reader answer the same snapshot, the same provenance and the
        /// same refusals, for no statement, a statement, a profile, a profile the build does not
        /// have, a limit, a limit the build does not have and a limit no machine reads. Turned red by a path that composes
        /// the caller's layers apart from the reader's.
        #[test]
        fn no_document_resolves_as_a_document_with_no_wz_member() {
            let empty = parse("{}").unwrap();
            let base = SessionPolicy::defaults();
            let ring = another::<EventRingFull>().unwrap_or(EventRingFull::DEFAULT);
            let stated = [Statement::new("event-ring-full", id_of(ring))];
            let limit = [LimitStatement::new(
                "MAX_SUBSCRIPTIONS",
                LimitValue::Integer(other_subscriptions()),
            )];
            let no_such_limit = [LimitStatement::new("NO_SUCH_LIMIT", LimitValue::Integer(1))];
            let not_read = [LimitStatement::new(
                unread(&SESSION_LIMITS).id(),
                LimitValue::Integer(1),
            )];
            let cases = [
                limits_alone(&limit),
                limits_alone(&no_such_limit),
                limits_alone(&not_read),
                Overrides::default(),
                Overrides {
                    profile: None,
                    statements: &stated,
                    limits: &[],
                },
                Overrides {
                    profile: Some("upstream"),
                    statements: &[],
                    limits: &[],
                },
                Overrides {
                    profile: Some("no-such-profile"),
                    statements: &stated,
                    limits: &[],
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
                limits: &[],
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
                limits: &[],
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
                limits: &[],
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
                limits: &[],
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
                Base::session(SessionPolicy::defaults()),
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
