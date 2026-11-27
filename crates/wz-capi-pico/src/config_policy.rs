// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_config_policy`, `zext_config_profile` and `zext_config_document`: the policies
//! and the limits a config states for the session [`z_open`](crate::session::z_open) opens from
//! it.
//!
//! pico's config is a set of numbered keys and has none for wz's policies, so these are doors wz
//! has and zenoh-pico does not: `zext_*`, declared in `zext.h`. The first two are in a build
//! with the `config-policy` capability, which a build that names nothing has and the zenoh-pico
//! preset leaves out; `zext_config_document` is in a build with the `config-document` capability,
//! since it links a JSON5 reader. An MCU image whose domain of a policy holds one value refuses
//! every other value of it by name.
//!
//! A build without `config-policy` has no statement to resolve: its config states nothing of its
//! policies, and a session opens under the build's policies and limits, with no resolver linked.
//!
//! What the doors state is kept in the config (`PolicyStatements`) and composed by the open,
//! lowest first, through [`policy_document::resolve_document_under`], the reader the other ABIs
//! compose a document and their open's statements with, or, for a config handed no document,
//! through [`policy_document::resolve_under`], which answers the same without reading one:
//!
//! 1. the build defaults;
//! 2. the profile `zext_config_profile` named, else the one the document names;
//! 3. the `zext/policies` of the document `zext_config_document` was handed
//!    ([`policy_document::Origin::Document`]);
//! 4. the statements of `zext_config_policy` ([`policy_document::Origin::Api`]).
//!
//! The `zext/limits` of the document are resolved in the same resolution, over the limits a session
//! of this ABI opens under (`crate::session::opening_limits`, zenoh-pico's): a pico session holds
//! no runtime's limits, so a runtime's limit the document states is refused, as a limit the build
//! does not have is.
//!
//! The runtime is the process's (`wz_capi_port::runtime_limits`): its limits are stated by
//! `zext_runtime_limits_document`, from the `zext/limits` of a document of their own, before the
//! first machine of the process that reads them is made.
//!
//! Each door checks its change the way the open will compose it, so a change the build would
//! refuse is refused when it is made, with `Z_ERR_CONFIG_INVALID_VALUE`, and leaves the config as
//! it was. The document is the zenoh JSON5 document the zenoh-c ABI reads, of which only the `zext`
//! member is read here, so one document gives both ABIs the same policies.
//!
//! [`policy_document::resolve_document_under`]: wz_session_core::policy_document::resolve_document_under
//! [`policy_document::resolve_under`]: wz_session_core::policy_document::resolve_under
//! [`policy_document::Origin::Document`]: wz_session_core::policy_document::Origin::Document
//! [`policy_document::Origin::Api`]: wz_session_core::policy_document::Origin::Api

#[cfg(feature = "config-policy")]
use core::ffi::{c_char, CStr};

#[cfg(feature = "config-document")]
use wz_session_core::caps;
#[cfg(feature = "config-document")]
use wz_session_core::json5::number_as_u64;
#[cfg(feature = "config-document")]
use wz_session_core::json5_lex::{Json5Error, Json5Keyword, Json5Str, Lexer};
#[cfg(feature = "config-document")]
use wz_session_core::limit_binding::{LimitValue, UNBOUNDED};
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "config-document")]
use wz_session_core::limits::{RuntimeLimits, RUNTIME_LIMITS, RUNTIME_LIMIT_COUNT, SESSION_LIMITS};
use wz_session_core::policy::SessionPolicy;
#[cfg(any(feature = "config-document", all(test, feature = "config-policy")))]
use wz_session_core::policy::POLICIES;
#[cfg(feature = "config-document")]
use wz_session_core::policy::PROFILES;
#[cfg(any(test, feature = "config-document"))]
use wz_session_core::policy_document::Resolved;
#[cfg(feature = "config-policy")]
use wz_session_core::policy_document::{self, Overrides, PolicySet, Profile, Stated, Statement};
#[cfg(feature = "config-document")]
use wz_session_core::policy_document::{DocumentLayers, LimitSet, LimitStatement, StatedLimits};
#[cfg(feature = "config-document")]
use wz_session_core::policy_document::{
    DocumentTransport, DOCUMENT_VERSION, EXT_MEMBER, RETIRED_MEMBER,
};

#[cfg(feature = "config-policy")]
use crate::abi::z_loaned_config_t;
#[cfg(feature = "config-policy")]
use crate::config::ConfigState;
#[cfg(feature = "config-policy")]
use crate::ffi::guarded;
use crate::result::ZResult;
#[cfg(feature = "config-document")]
use crate::result::Z_EINVAL;
#[cfg(feature = "config-policy")]
use crate::result::{Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};

/// What a build without the doors states about a config's policies: nothing, so the open runs a
/// session under the build's policies and limits and links no resolver of a statement.
#[cfg(not(feature = "config-policy"))]
#[derive(Clone, Default)]
pub(crate) struct PolicyStatements;

#[cfg(not(feature = "config-policy"))]
impl PolicyStatements {
    /// A config that stated nothing: what a scout opens under, and the tests.
    #[cfg(any(test, feature = "scout", feature = "scout-mcu"))]
    pub(crate) const fn none() -> Self {
        Self
    }

    /// `policy` and `limits` as they are: the build's, which no statement can move here.
    #[inline(always)]
    pub(crate) fn compose_into(
        &self,
        _policy: &mut SessionPolicy,
        _limits: &mut SessionLimits,
    ) -> Result<(), ZResult> {
        Ok(())
    }

    /// `base` with no layer over it, and the limits a session opens under
    /// (`crate::session::opening_limits`).
    #[cfg(test)]
    pub(crate) fn compose(&self, base: SessionPolicy) -> Result<Resolved, ZResult> {
        let mut resolved = Resolved::unchanged(base);
        resolved.limits.session = crate::session::opening_limits();
        Ok(resolved)
    }

    /// No key ids: a config handed no document states none, and only `config-document`, which
    /// brings the doors, hands one.
    #[cfg(feature = "shared-key-ids")]
    pub(crate) fn document_key_ids(
        &self,
    ) -> Result<wz_session_core::shared_key_ids::KeyIdsAtOpen, ZResult> {
        Ok(Default::default())
    }

    /// No address of the node's own: a config handed no document states none, and only
    /// `config-document`, which brings the doors, hands one.
    #[inline(always)]
    pub(crate) fn document_owned_address(&self) -> Option<[u8; 4]> {
        None
    }

    /// No transport: a config handed no document states none.
    #[cfg(feature = "app-transport")]
    pub(crate) fn document_transport(
        &self,
    ) -> Option<wz_session_core::policy_document::DocumentTransport> {
        None
    }
}

/// What a config's doors stated about its policies, as they stated it: the open judges and
/// composes it ([`Self::compose`]). The profile and the statements are the build's own ids, found
/// by the door in the build's tables, so a config keeps them in no memory of its own.
#[cfg(feature = "config-policy")]
#[derive(Clone, Default)]
pub(crate) struct PolicyStatements {
    /// The id of the profile `zext_config_profile` named; it replaces the profile the document
    /// names.
    profile: Option<&'static str>,
    /// What the `zext` member of the document `zext_config_document` was handed states.
    #[cfg(feature = "config-document")]
    document: DocumentRows,
    /// The statements of `zext_config_policy`, by the build's table.
    api: PolicySet,
}

#[cfg(feature = "config-policy")]
impl PolicyStatements {
    /// A config that stated nothing: what a scout opens under, and the tests.
    #[cfg(any(test, feature = "scout", feature = "scout-mcu"))]
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// The layers written over `policy` and the limits the document states over `limits`, the
    /// snapshot of a session's ([`policy_document::resolve_under_into`]), or
    /// `Z_ERR_CONFIG_INVALID_VALUE` when `Self::compose` refuses them: what an open hands its
    /// engine, without the record of where each value came from, which this ABI reports nowhere.
    /// On a refusal what was written is no resolution, and the caller drops it.
    pub(crate) fn compose_into(
        &self,
        policy: &mut SessionPolicy,
        limits: &mut SessionLimits,
    ) -> Result<(), ZResult> {
        let overrides = Overrides {
            profile: self.profile,
            statements: Stated::Set(&self.api),
            ..Overrides::default()
        };
        // The layers of a document resolve into a record of where each value came from; the two
        // snapshots are taken from it.
        #[cfg(feature = "config-document")]
        if !self.document.states_nothing() {
            let base = policy_document::Base {
                policy: *policy,
                session_limits: *limits,
                runtime_limits: None,
            };
            let resolved = self.document.resolve_under(base, overrides)?;
            *policy = resolved.policy;
            *limits = resolved.limits.session;
            return Ok(());
        }
        policy_document::resolve_under_into(overrides, policy, limits)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// `base` with the layers over it, and the limits the document states over the limits a session
    /// opens under (`crate::session::opening_limits`), or `Z_ERR_CONFIG_INVALID_VALUE`
    /// when any statement of any layer is refused, a document whose shape is refused, a profile
    /// the build does not have and a limit of a runtime among them. Where each value came from is
    /// read by the tests alone: the open and the doors resolve through [`Self::compose_into`].
    #[cfg(test)]
    pub(crate) fn compose(&self, base: SessionPolicy) -> Result<Resolved, ZResult> {
        let base = policy_document::Base {
            policy: base,
            session_limits: crate::session::opening_limits(),
            runtime_limits: None,
        };
        let overrides = Overrides {
            profile: self.profile,
            statements: Stated::Set(&self.api),
            ..Overrides::default()
        };
        #[cfg(feature = "config-document")]
        if !self.document.states_nothing() {
            return self.document.resolve_under(base, overrides);
        }
        // A config handed no document is resolved as one with no `zext` member, without the reader
        // of a document (`policy_document::resolve_under`), which a build with no document door
        // then does not link.
        policy_document::resolve_under(base, overrides).map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The key ids the `zext/key-ids` of the document `zext_config_document` was handed states,
    /// which its door read, or none when the config was handed no document.
    #[cfg(feature = "shared-key-ids")]
    pub(crate) fn document_key_ids(
        &self,
    ) -> Result<wz_session_core::shared_key_ids::KeyIdsAtOpen, ZResult> {
        #[cfg(feature = "config-document")]
        let stated = self.document.key_ids.clone();
        #[cfg(not(feature = "config-document"))]
        let stated = Default::default();
        Ok(stated)
    }

    /// The node's own address the `zext/owned-address` of the document `zext_config_document` was
    /// handed states, which its door read, or none when the config was handed no document.
    #[cfg(feature = "config-document")]
    pub(crate) fn document_owned_address(&self) -> Option<[u8; 4]> {
        self.document.owned_address
    }

    /// See the twin with the document door: a build without it hands no document, so it states
    /// no address.
    #[cfg(not(feature = "config-document"))]
    pub(crate) fn document_owned_address(&self) -> Option<[u8; 4]> {
        None
    }

    /// What the `zext/transport` of the document `zext_config_document` was handed states the
    /// links of the session open on, which the open holds to the transport the config is handed
    /// (`crate::session::transport_refused`); none when the config was handed no document.
    #[cfg(all(feature = "app-transport", feature = "config-document"))]
    pub(crate) fn document_transport(&self) -> Option<DocumentTransport> {
        self.document.transport
    }

    /// No transport: a build without the document door is handed no document to state one.
    #[cfg(all(feature = "app-transport", not(feature = "config-document")))]
    pub(crate) fn document_transport(
        &self,
    ) -> Option<wz_session_core::policy_document::DocumentTransport> {
        None
    }

    /// `policy` is to take `value` in the API layer; an earlier statement of the policy is
    /// replaced. A policy the build does not have, or a value the policy does not have, is
    /// `Z_ERR_CONFIG_INVALID_VALUE`, the code the open's resolution gives it.
    fn state_policy(&mut self, policy: &str, value: &str) -> Result<(), ZResult> {
        self.api
            .state(Statement::new(policy, value))
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The profile of the build whose id is `id` is the one the sessions start from; a profile
    /// the build does not have is `Z_ERR_CONFIG_INVALID_VALUE`, the code the open's resolution
    /// gives it.
    fn state_profile(&mut self, id: &str) -> Result<(), ZResult> {
        let profile = Profile::find(id).ok_or(Z_ERR_CONFIG_INVALID_VALUE)?;
        self.profile = Some(profile.id);
        Ok(())
    }

    /// Statements of the API layer for a test of what the open does with those it refuses: a
    /// policy only the build decides, or a value the build's domain leaves out
    /// ([`Against::Refused`]). The test build keeps every value of every policy
    /// (`policy-selection`, the crate's dev-dependency) and has neither, so there it is the
    /// statement of a second value of a policy whose domain keeps two, which the resolution admits
    /// ([`Against::Admitted`]); Layer C1pc runs the tests again over a build whose policies keep
    /// their defaults alone, where each is refused. A build that refuses nothing and keeps no
    /// second value of any policy has nothing to state, and fails the test that asks.
    #[cfg(test)]
    pub(crate) fn against_the_resolution() -> Against {
        use wz_session_core::policy_binding::Binding;
        let refused = POLICIES.iter().find_map(|entry| {
            let value = if entry.binding() == Binding::Build {
                entry.values().first().copied()
            } else {
                entry
                    .values()
                    .iter()
                    .copied()
                    .find(|value| !entry.domain().contains(value))
            }?;
            Some((entry.id(), value))
        });
        let ((policy, value), refuses) = match refused {
            Some(statement) => (statement, true),
            None => {
                let admitted = POLICIES.iter().find_map(|entry| {
                    let mut allowed = entry.domain().iter();
                    allowed.next()?;
                    Some((entry.id(), allowed.next()?))
                });
                let admitted = admitted
                    .expect("a build that refuses no statement keeps two values of a policy");
                (admitted, false)
            }
        };
        let mut statements = Self::default();
        statements
            .api
            .state(Statement::new(policy, value))
            .expect("the set holds a statement of a policy of the build's own table");
        if refuses {
            Against::Refused(statements)
        } else {
            Against::Admitted(statements)
        }
    }
}

/// What the open's resolution does with the statements [`PolicyStatements::against_the_resolution`]
/// hands a test.
#[cfg(test)]
pub(crate) enum Against {
    /// Statements the set holds and the resolution refuses.
    Refused(PolicyStatements),
    /// A statement the resolution admits, in a build that refuses none.
    Admitted(PolicyStatements),
}

/// What the `zext` member of the document `zext_config_document` was handed states, read by the
/// door into the build's own ids with no tree kept: the profile, the statements of `zext/policies`
/// and those of `zext/limits`, each held by the build's table, the key ids of `zext/key-ids`, and
/// the node's own address `zext/owned-address` states. `Default` is a document with no `zext`
/// member, which states nothing.
#[cfg(feature = "config-document")]
#[derive(Clone, Default)]
struct DocumentRows {
    profile: Option<&'static str>,
    statements: PolicySet,
    limits: LimitSet,
    /// What `zext/transport` states, which the open judges; a session's statement, so a runtime's
    /// document that states it is refused.
    transport: Option<DocumentTransport>,
    #[cfg(feature = "shared-key-ids")]
    key_ids: wz_session_core::shared_key_ids::KeyIdsAtOpen,
    owned_address: Option<[u8; 4]>,
}

/// A document the reader refuses: `Z_ERR_CONFIG_INVALID_VALUE` at the door.
#[cfg(feature = "config-document")]
struct Refused;

/// The limits of a runtime the `zext/limits` of a runtime's document states, each once, in the
/// document's order: what `zext_runtime_limits_document` resolves over the build's. Each id is
/// the build's own, from its table, so the rows keep no text of the document, and the table has a
/// row for each, so they never run out.
#[cfg(feature = "config-document")]
struct RuntimeRows {
    stated: [LimitStatement<'static>; RUNTIME_LIMIT_COUNT],
    len: usize,
}

#[cfg(feature = "config-document")]
impl RuntimeRows {
    /// Rows that state nothing.
    const fn new() -> Self {
        Self {
            stated: [LimitStatement::new("", LimitValue::Unbounded); RUNTIME_LIMIT_COUNT],
            len: 0,
        }
    }

    /// What the rows state, in the document's order.
    fn stated(&self) -> &[LimitStatement<'static>] {
        self.stated.get(..self.len).unwrap_or_default()
    }

    /// `limit`, an id of the build's table, is to take `value`; a limit stated twice is refused,
    /// as the resolution refuses a limit a layer states twice.
    fn state(&mut self, limit: &'static str, value: LimitValue) -> Result<(), Refused> {
        if self.stated().iter().any(|held| held.limit == limit) {
            return Err(Refused);
        }
        let (Some(row), Some(next)) = (self.stated.get_mut(self.len), self.len.checked_add(1))
        else {
            return Err(Refused);
        };
        *row = LimitStatement::new(limit, value);
        self.len = next;
        Ok(())
    }

    /// The runtime's limits the rows state over the build's, as a node resolves a document that
    /// states them and nothing else ([`policy_document::resolve_layers_under`]), or
    /// `Z_ERR_CONFIG_INVALID_VALUE`.
    fn resolve(&self) -> Result<RuntimeLimits, ZResult> {
        let layers = DocumentLayers {
            limits: StatedLimits::Read(self.stated()),
            ..DocumentLayers::default()
        };
        policy_document::resolve_layers_under(
            policy_document::Base::node(SessionPolicy::defaults()),
            layers,
            Overrides::default(),
        )
        .map(|resolved| resolved.limits.runtime)
        .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }
}

#[cfg(feature = "config-document")]
impl From<Json5Error> for Refused {
    fn from(_: Json5Error) -> Self {
        Self
    }
}

/// The members of the `zext` member already read, so a second one is refused.
#[cfg(feature = "config-document")]
#[derive(Default)]
struct Seen {
    version: bool,
    transport: bool,
    profile: bool,
    policies: bool,
    limits: bool,
    key_ids: bool,
    owned_address: bool,
}

/// The longest text an IPv4 address is written in, `255.255.255.255`.
#[cfg(feature = "config-document")]
const IPV4_TEXT_MAX: usize = 15;

/// The text of a string member decoded into the room an IPv4 address takes, or `Refused` for one
/// longer than any address is written in, which names none.
#[cfg(feature = "config-document")]
struct AddressText {
    bytes: [u8; IPV4_TEXT_MAX],
    len: usize,
}

#[cfg(feature = "config-document")]
impl core::fmt::Write for AddressText {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        let room = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
        room.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// `zext/version`: a whole number, the version of the document's format this build reads
/// ([`DOCUMENT_VERSION`]); any other is refused, as the document's resolution refuses it.
#[cfg(feature = "config-document")]
fn read_version(lex: &mut Lexer<'_>) -> Result<(), Refused> {
    if !lex.at_number() || number_as_u64(lex.number()?) != Some(DOCUMENT_VERSION) {
        return Err(Refused);
    }
    Ok(())
}

/// The first reading of a member: a second one is refused, as the document's resolution refuses
/// a member stated twice.
#[cfg(feature = "config-document")]
fn first(seen: &mut bool) -> Result<(), Refused> {
    if core::mem::replace(seen, true) {
        Err(Refused)
    } else {
        Ok(())
    }
}

/// Into an object whose `{` is next, or `Refused` for a value that is not an object.
#[cfg(feature = "config-document")]
fn open_object(lex: &mut Lexer<'_>) -> Result<(), Refused> {
    if lex.peek() != Some(b'{') {
        return Err(Refused);
    }
    lex.bump();
    Ok(())
}

/// The name of the next member of an open object, past its `:`, or `None` past the object's `}`.
#[cfg(feature = "config-document")]
fn next_member<'t>(lex: &mut Lexer<'t>) -> Result<Option<Json5Str<'t>>, Refused> {
    lex.skip_trivia()?;
    match lex.peek() {
        Some(b'}') => {
            lex.bump();
            return Ok(None);
        }
        None => return Err(Refused),
        _ => {}
    }
    let name = lex.member_name()?;
    lex.skip_trivia()?;
    lex.consume(b':', ": after a member name")?;
    lex.skip_trivia()?;
    Ok(Some(name))
}

/// Past a member's value: its `,`, or the object's `}`, which the next [`next_member`] reads.
#[cfg(feature = "config-document")]
fn after_member(lex: &mut Lexer<'_>) -> Result<(), Refused> {
    lex.skip_trivia()?;
    match lex.peek() {
        Some(b',') => {
            lex.bump();
            Ok(())
        }
        Some(b'}') => Ok(()),
        _ => Err(Refused),
    }
}

#[cfg(feature = "config-document")]
impl DocumentRows {
    /// How deep a member of the document's object may nest, the object being the first level: a
    /// build whose document depth leaves no room for one fails to compile.
    const MEMBER_DEPTH: usize = caps::CONFIG_DOCUMENT_DEPTH - 1;

    /// How deep a member of the `zext` member may nest, two levels below the document's object.
    #[cfg(feature = "shared-key-ids")]
    const EXT_MEMBER_DEPTH: usize = caps::CONFIG_DOCUMENT_DEPTH - 2;

    /// Whether the document states nothing, so a config resolves as one handed none.
    fn states_nothing(&self) -> bool {
        let stated = self.profile.is_some()
            || !self.statements.is_empty()
            || !self.limits.is_empty()
            || self.owned_address.is_some()
            || self.transport.is_some();
        #[cfg(feature = "shared-key-ids")]
        let stated =
            stated || self.key_ids != wz_session_core::shared_key_ids::KeyIdsAtOpen::default();
        !stated
    }

    /// `base` with the document's layers and `overrides` over them
    /// ([`policy_document::resolve_layers_under`]), and the key ids it states counted against the
    /// limits that resolves, or `Z_ERR_CONFIG_INVALID_VALUE`.
    fn resolve_under(
        &self,
        base: policy_document::Base,
        overrides: Overrides<'_, 'static>,
    ) -> Result<Resolved, ZResult> {
        let layers = DocumentLayers {
            profile: self.profile,
            statements: Stated::Set(&self.statements),
            limits: StatedLimits::Set(&self.limits),
        };
        let resolved = policy_document::resolve_layers_under(base, layers, overrides)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
        #[cfg(feature = "shared-key-ids")]
        self.key_ids
            .check_limits(&resolved.limits.session)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
        Ok(resolved)
    }

    /// The rows the zenoh document `text` states, in place of what they held, or
    /// `Z_ERR_CONFIG_INVALID_VALUE`: the document is walked once, keeping no tree, and only its
    /// `zext` member is read; every other member is stepped over and still checked, at most
    /// `CONFIG_DOCUMENT_DEPTH` deep, the outermost object being 1.
    fn read(&mut self, text: &str, runtime: Option<&mut RuntimeRows>) -> Result<(), ZResult> {
        self.profile = None;
        self.statements = PolicySet::new();
        self.limits = LimitSet::new();
        self.transport = None;
        #[cfg(feature = "shared-key-ids")]
        {
            self.key_ids = Default::default();
        }
        self.owned_address = None;
        self.read_document(&mut Lexer::new(text), runtime)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The whole document: an object, each of whose `zext` members is read, and nothing after it.
    fn read_document(
        &mut self,
        lex: &mut Lexer<'_>,
        mut runtime: Option<&mut RuntimeRows>,
    ) -> Result<(), Refused> {
        lex.skip_trivia()?;
        open_object(lex)?;
        let mut seen_member = false;
        while let Some(name) = next_member(lex)? {
            if name.eq_str(EXT_MEMBER) {
                self.read_ext_member(lex, &mut seen_member, runtime.as_deref_mut())?;
            } else if name.eq_str(RETIRED_MEMBER) {
                // Refused rather than stepped over as a member of zenoh's, which would drop what
                // it states unread; the other ABIs' reader refuses it by the same name.
                return Err(Refused);
            } else {
                lex.skip_value(Self::MEMBER_DEPTH)?;
            }
            after_member(lex)?;
        }
        lex.skip_trivia()?;
        if lex.at_end() {
            Ok(())
        } else {
            Err(Refused)
        }
    }

    /// One `zext` member: an object, or `null`, zenoh's spelling of a member left unset, which
    /// states nothing as the zenoh-c ABI's reader of the same document takes it.
    fn read_ext_member(
        &mut self,
        lex: &mut Lexer<'_>,
        seen_member: &mut bool,
        mut runtime: Option<&mut RuntimeRows>,
    ) -> Result<(), Refused> {
        if lex.peek() != Some(b'{') {
            let unset = !lex.at_string()
                && !lex.at_number()
                && lex.peek() != Some(b'[')
                && lex.keyword()? == Json5Keyword::Null;
            return if unset { Ok(()) } else { Err(Refused) };
        }
        first(seen_member)?;
        open_object(lex)?;
        let mut seen = Seen::default();
        while let Some(name) = next_member(lex)? {
            if name.eq_str("version") {
                first(&mut seen.version)?;
                read_version(lex)?;
            } else if name.eq_str("transport") {
                first(&mut seen.transport)?;
                self.read_transport(lex)?;
            } else if name.eq_str("profile") {
                first(&mut seen.profile)?;
                self.read_profile(lex)?;
            } else if name.eq_str("policies") {
                first(&mut seen.policies)?;
                self.read_policies(lex)?;
            } else if name.eq_str("limits") {
                first(&mut seen.limits)?;
                self.read_limits(lex, runtime.as_deref_mut())?;
            } else if name.eq_str("key-ids") {
                first(&mut seen.key_ids)?;
                // Read where it lies, into the rows of its entries, by the rules of the reader
                // the other ABIs read it with: the member nests below `zext`, two levels down.
                #[cfg(feature = "shared-key-ids")]
                {
                    self.key_ids = wz_session_core::shared_key_ids::read_member_in(
                        lex,
                        Self::EXT_MEMBER_DEPTH,
                        wz_session_core::shared_key_ids::form_in_domain,
                    )
                    .map_err(|_| Refused)?;
                }
                // A build without the capability refuses the member by name.
                #[cfg(not(feature = "shared-key-ids"))]
                return Err(Refused);
            } else if name.eq_str("owned-address") {
                first(&mut seen.owned_address)?;
                self.read_owned_address(lex)?;
            } else {
                return Err(Refused);
            }
            after_member(lex)?;
        }
        Ok(())
    }

    /// `zext/owned-address`: the node's own IPv4 address, as the reader of the other ABIs reads it
    /// (`wz_session_core::zid_derivation::parse_owned_address`), so text that is no address of a
    /// node is refused alike.
    fn read_owned_address(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
        if !lex.at_string() {
            return Err(Refused);
        }
        let mut text = AddressText {
            bytes: [0; IPV4_TEXT_MAX],
            len: 0,
        };
        lex.string()?.decode_into(&mut text)?;
        let text = text
            .bytes
            .get(..text.len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .ok_or(Refused)?;
        let address =
            wz_session_core::zid_derivation::parse_owned_address(text).map_err(|_| Refused)?;
        self.owned_address = Some(address);
        Ok(())
    }

    /// `zext/transport`: `system`, or `application` in a build that carries a transport of the
    /// program's (`app-transport`); whether the open is handed one is the open's to judge. A build
    /// without one refuses `application` here, as no open of it could carry it.
    fn read_transport(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
        if !lex.at_string() {
            return Err(Refused);
        }
        let id = lex.string()?;
        let transport = DocumentTransport::IDS
            .iter()
            .copied()
            .find(|known| id.eq_str(known))
            .and_then(DocumentTransport::from_id)
            .ok_or(Refused)?;
        #[cfg(not(feature = "app-transport"))]
        if transport == DocumentTransport::Application {
            return Err(Refused);
        }
        self.transport = Some(transport);
        Ok(())
    }

    /// `zext/profile`: the id of a profile of the build.
    fn read_profile(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
        if !lex.at_string() {
            return Err(Refused);
        }
        let id = lex.string()?;
        let profile = PROFILES
            .iter()
            .find(|profile| id.eq_str(profile.id))
            .ok_or(Refused)?;
        self.profile = Some(profile.id);
        Ok(())
    }

    /// `zext/policies`: an object of a policy's id and a value's id, each a string, each policy of
    /// the build once.
    fn read_policies(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
        open_object(lex)?;
        while let Some(policy) = next_member(lex)? {
            if !lex.at_string() {
                return Err(Refused);
            }
            let value = lex.string()?;
            let entry = POLICIES
                .iter()
                .find(|entry| policy.eq_str(entry.id()))
                .ok_or(Refused)?;
            let value = entry
                .values()
                .iter()
                .copied()
                .find(|known| value.eq_str(known))
                .ok_or(Refused)?;
            if self.statements.holds(entry.id()) {
                return Err(Refused);
            }
            self.statements
                .state(Statement::new(entry.id(), value))
                .map_err(|_| Refused)?;
            after_member(lex)?;
        }
        Ok(())
    }

    /// `zext/limits`: an object of a limit's id and its value, a whole number a `usize` holds or
    /// `unbounded`, each limit once. A limit of a runtime is read into `runtime`, the rows of a
    /// runtime's document, and refused in a config's (`None`), as a session holds none.
    fn read_limits(
        &mut self,
        lex: &mut Lexer<'_>,
        mut runtime: Option<&mut RuntimeRows>,
    ) -> Result<(), Refused> {
        open_object(lex)?;
        while let Some(limit) = next_member(lex)? {
            let value = if lex.at_number() {
                number_as_u64(lex.number()?)
                    .and_then(|number| usize::try_from(number).ok())
                    .map(LimitValue::Integer)
                    .ok_or(Refused)?
            } else if lex.at_string() && lex.string()?.eq_str(UNBOUNDED) {
                LimitValue::Unbounded
            } else {
                return Err(Refused);
            };
            if let Some(entry) = SESSION_LIMITS.iter().find(|entry| limit.eq_str(entry.id())) {
                self.limits
                    .state(LimitStatement::new(entry.id(), value))
                    .map_err(|_| Refused)?;
            } else {
                let rows = runtime.as_deref_mut().ok_or(Refused)?;
                let entry = RUNTIME_LIMITS
                    .iter()
                    .find(|entry| limit.eq_str(entry.id()))
                    .ok_or(Refused)?;
                rows.state(entry.id(), value)?;
            }
            after_member(lex)?;
        }
        Ok(())
    }
}

/// `change` made to the policies `config` states, kept only when the open would compose the
/// result ([`crate::session::resolve_snapshots`]); a refused change leaves the config as it was.
///
/// # Safety
/// `config` must be null or a live loaned config.
#[cfg(feature = "config-policy")]
unsafe fn amend(
    config: *mut z_loaned_config_t,
    change: impl FnOnce(&mut PolicyStatements) -> Result<(), ZResult>,
) -> ZResult {
    if config.is_null() || (*config).handle.is_null() {
        return Z_ERR_NULL;
    }
    let state = &mut *((*config).handle as *mut ConfigState);
    let mut candidate = state.policies.clone();
    if let Err(code) = change(&mut candidate) {
        return code;
    }
    match crate::session::resolve_snapshots(&candidate) {
        Ok(_) => {
            state.policies = candidate;
            Z_OK
        }
        Err(code) => code,
    }
}

/// The text of a C string argument, `Z_ERR_NULL` for a null one and `Z_ERR_CONFIG_INVALID_VALUE`
/// for one that is not UTF-8, which names no policy, value or profile.
///
/// # Safety
/// `text` must be null or a NUL-terminated string that outlives `'a`.
#[cfg(feature = "config-policy")]
unsafe fn text_of<'a>(text: *const c_char) -> Result<&'a str, ZResult> {
    if text.is_null() {
        return Err(Z_ERR_NULL);
    }
    CStr::from_ptr(text)
        .to_str()
        .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
}

/// States that the policy whose id is `policy` is to take the value whose id is `value` in the
/// sessions opened from `config`, over the profile and the document: the API layer. A second
/// statement of the same policy replaces the first. A policy the build does not have, a value the
/// policy does not have, a value the build's domain leaves out and a policy only the build decides
/// are refused with `Z_ERR_CONFIG_INVALID_VALUE`, and the config is left as it was.
///
/// # Safety
/// `config` must be null or a live loaned config; `policy` and `value` must be null or
/// NUL-terminated strings.
#[cfg(feature = "config-policy")]
#[no_mangle]
pub unsafe extern "C" fn zext_config_policy(
    config: *mut z_loaned_config_t,
    policy: *const c_char,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            let (policy, value) = (text_of(policy)?, text_of(value)?);
            statements.state_policy(policy, value)
        })
    })
}

/// Names the profile the sessions opened from `config` start from, in place of the one its
/// document names; a second call replaces the first. A profile the build does not have, or one
/// that states a value the build refuses, is refused with `Z_ERR_CONFIG_INVALID_VALUE`, and the
/// config is left as it was.
///
/// # Safety
/// `config` must be null or a live loaned config; `profile` must be null or a NUL-terminated
/// string.
#[cfg(feature = "config-policy")]
#[no_mangle]
pub unsafe extern "C" fn zext_config_profile(
    config: *mut z_loaned_config_t,
    profile: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            statements.state_profile(text_of(profile)?)
        })
    })
}

/// Hands `config` a zenoh JSON5 document, of which the `zext` member is read: the profile it names,
/// its `zext/policies`, its `zext/limits`, the limits of a session it states, and, in a build with
/// the `shared-key-ids` capability, its `zext/key-ids`, the key ids every node shares, under what
/// `zext_config_key_ids` and `zext_config_key_wire_form_for` state. The rest of the document
/// is not read, so the document a zenoh-c program opens with configures these sessions alike. A
/// second call replaces the first. Text that is no JSON5 object, a `zext` member whose shape is
/// refused (one that is not an object, a value that is not a string, a limit's value that is
/// neither a whole number nor `unbounded`, a member wz does not read, `zext/key-ids` in a build
/// without the capability, a member stated twice), a member `wz`, the name the `zext` member had
/// before, a profile or a limit the build does not have, a limit only the build decides, a limit of
/// a runtime, a statement the build refuses, a refused part of `zext/key-ids`, a `zext/version`
/// other than the one this build reads, and a `zext/transport` that is neither `system` nor, in a
/// build with the `app-transport` capability, `application` are refused with
/// `Z_ERR_CONFIG_INVALID_VALUE`, and the config is left as it was. A document that states
/// `application` opens only a config handed the program's transport (`zext_config_transport`).
///
/// The door walks the document once and keeps no tree: what the `zext` member states is kept as
/// the build's own ids, and a document nested deeper than `CONFIG_DOCUMENT_DEPTH` (the outermost
/// object being 1) is refused with `Z_ERR_CONFIG_INVALID_VALUE`.
///
/// In a build with the `config-document` capability alone: the door links a JSON5 reader that a
/// build stating its policies through [`zext_config_policy`] and [`zext_config_profile`] does
/// not need.
///
/// # Safety
/// `config` must be null or a live loaned config; `json5` must be null or a NUL-terminated string.
#[cfg(feature = "config-document")]
#[no_mangle]
pub unsafe extern "C" fn zext_config_document(
    config: *mut z_loaned_config_t,
    json5: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            statements.document.read(text_of(json5)?, None)
        })
    })
}

/// The runtime's limits the `zext/limits` of the zenoh document `text` states, over the build's, or
/// `Z_ERR_CONFIG_INVALID_VALUE`. The document states the process's runtime and nothing of a
/// session: a profile, a policy, key ids and a limit of a session are its config's to state, and
/// are refused here with everything the reader of a node's document refuses.
///
/// Read by the walker of `zext_config_document`, with no tree and at most
/// `CONFIG_DOCUMENT_DEPTH` deep, so the two doors read one document by one set of rules and the
/// build links one reader of it.
#[cfg(feature = "config-document")]
fn runtime_limits_of(text: &str) -> Result<RuntimeLimits, ZResult> {
    let mut document = DocumentRows::default();
    let mut runtime = RuntimeRows::new();
    document.read(text, Some(&mut runtime))?;
    if !document.states_nothing() {
        return Err(Z_ERR_CONFIG_INVALID_VALUE);
    }
    runtime.resolve()
}

/// States the limits of the process's runtime from a zenoh JSON5 document, of which the
/// `zext/limits` member is read: the limits of the machines the process makes apart from any
/// session, its supervisor of checkpoints (`SUPERVISION_CHECKPOINTS`), its message catalogs
/// (`MESSAGE_CATALOG_ENTRIES`) and its reception supervisors (`E2E_SUPERVISED_STREAMS`), each at
/// most the build's value. A limit the document does not state keeps the build's value, and a
/// second call replaces the first.
///
/// The process's first machine of those takes the limits: the first call of a
/// `zext_supervision_*` door, `zext_stream_supervisor_new` or `zext_message_catalog_new`.
/// A call after it is refused with `Z_EINVAL` and the process keeps the limits it took.
///
/// Text that is no JSON5 object, a document nested deeper than `CONFIG_DOCUMENT_DEPTH` (the
/// outermost object being 1), a `zext` member whose shape is refused, a profile, a policy, key ids,
/// a limit of a session, a limit the build does not have, a limit only the build decides and a
/// value the build's domain leaves out or that is over the build's value are refused with
/// `Z_ERR_CONFIG_INVALID_VALUE`, whenever the call comes, and the process keeps what it held. A
/// null `json5` is `Z_ERR_NULL`.
///
/// In a build with the `config-document` capability alone, as `zext_config_document` is.
///
/// # Safety
/// `json5` must be null or a NUL-terminated string.
#[cfg(feature = "config-document")]
#[no_mangle]
pub unsafe extern "C" fn zext_runtime_limits_document(json5: *const c_char) -> ZResult {
    use wz_capi_port::runtime_limits::{self, StateRefused};

    guarded(|| {
        let limits = match text_of(json5).and_then(runtime_limits_of) {
            Ok(limits) => limits,
            Err(code) => return code,
        };
        match runtime_limits::state(&limits) {
            Ok(_) => Z_OK,
            Err(StateRefused::Limit(_)) => Z_ERR_CONFIG_INVALID_VALUE,
            Err(StateRefused::Taken) => Z_EINVAL,
        }
    })
}

#[cfg(all(test, feature = "config-policy"))]
mod tests {
    use super::*;
    use crate::abi::z_owned_config_t;
    use crate::config::{z_config_default, z_config_drop, z_config_loan_mut, z_config_move};
    #[cfg(feature = "config-document")]
    use crate::prelude::*;
    use crate::session::{resolve_policy, resolve_snapshots};
    use alloc::ffi::CString;
    #[cfg(feature = "config-document")]
    use wz_session_core::json5::{self, Json5Value};
    use wz_session_core::policy_binding::{Binding, PolicyEntry};
    use wz_session_core::policy_document::Origin;

    /// A config made by `z_config_default`, which the test drops.
    struct Config(z_owned_config_t);

    impl Config {
        fn new() -> Self {
            let mut owned = z_owned_config_t::null_value();
            // SAFETY: `owned` is a live local.
            assert_eq!(unsafe { z_config_default(&mut owned) }, Z_OK);
            Self(owned)
        }

        fn loaned(&mut self) -> *mut z_loaned_config_t {
            // SAFETY: the owned config is live.
            unsafe { z_config_loan_mut(&mut self.0) }
        }

        fn policy(&mut self, policy: &str, value: &str) -> ZResult {
            let (policy, value) = (CString::new(policy).unwrap(), CString::new(value).unwrap());
            // SAFETY: a live config and two live strings.
            unsafe { zext_config_policy(self.loaned(), policy.as_ptr(), value.as_ptr()) }
        }

        fn profile(&mut self, profile: &str) -> ZResult {
            let profile = CString::new(profile).unwrap();
            // SAFETY: a live config and a live string.
            unsafe { zext_config_profile(self.loaned(), profile.as_ptr()) }
        }

        #[cfg(feature = "config-document")]
        fn document(&mut self, text: &str) -> ZResult {
            let text = CString::new(text).unwrap();
            // SAFETY: a live config and a live string.
            unsafe { zext_config_document(self.loaned(), text.as_ptr()) }
        }

        fn state(&self) -> &ConfigState {
            // SAFETY: the owned config is live and holds a `ConfigState`.
            unsafe { &*(self.0.handle as *const ConfigState) }
        }

        /// What an open of the config resolves.
        fn resolved(&self) -> Resolved {
            resolve_policy(&self.state().policies).expect("the doors keep what the open composes")
        }
    }

    impl Drop for Config {
        fn drop(&mut self) {
            // SAFETY: the owned config is live or already null.
            unsafe { z_config_drop(z_config_move(&mut self.0)) }
        }
    }

    /// The policies a later stage may decide.
    fn decidable() -> impl Iterator<Item = &'static PolicyEntry> {
        POLICIES
            .iter()
            .filter(|entry| entry.binding() != Binding::Build)
    }

    /// A policy a later stage may decide and the first value the build allows it.
    fn one_allowed() -> (&'static PolicyEntry, &'static str) {
        decidable()
            .find_map(|entry| Some((entry, entry.domain().iter().next()?)))
            .expect("a policy a document may state")
    }

    /// A policy a later stage may decide whose build domain holds two values, and the two.
    fn two_allowed() -> Option<(&'static PolicyEntry, &'static str, &'static str)> {
        decidable().find_map(|entry| {
            let mut allowed = entry.domain().iter();
            Some((entry, allowed.next()?, allowed.next()?))
        })
    }

    /// The standard profile, when the build allows every value it states.
    fn standard_allowed() -> Option<&'static Profile> {
        let standard = Profile::find("standard").expect("declared");
        standard
            .statements
            .iter()
            .all(|statement| {
                POLICIES
                    .iter()
                    .find(|entry| entry.id() == statement.policy)
                    .is_some_and(|entry| entry.domain().contains(statement.value))
            })
            .then_some(standard)
    }

    /// What a config that states nothing resolves: the build's policies, each from the build
    /// defaults, over the limits every session of this ABI opens under
    /// (`crate::session::opening_limits`), not the build's.
    fn stating_nothing() -> Resolved {
        let mut resolved = Resolved::unchanged(SessionPolicy::defaults());
        resolved.limits.session = crate::session::opening_limits();
        resolved
    }

    /// What the resolution of a session of this ABI starts from: the build's policies and the
    /// limits a session opens under, with no runtime's limits, which a pico session does not hold.
    #[cfg(feature = "config-document")]
    fn opening_base() -> policy_document::Base {
        policy_document::Base {
            policy: SessionPolicy::defaults(),
            session_limits: crate::session::opening_limits(),
            runtime_limits: None,
        }
    }

    /// The `zext` members of the zenoh document `text`, gathered in their order as the members of a
    /// document of their own, or `Z_ERR_CONFIG_INVALID_VALUE` for text that is no JSON5 object. A
    /// `zext: null` states nothing, as the zenoh-c ABI's reader of the same document takes it; a
    /// member under the retired name is gathered whatever it holds, for the reader to refuse.
    #[cfg(feature = "config-document")]
    fn ext_members(text: &str) -> Result<Json5Value, ZResult> {
        let Ok(Json5Value::Object(members)) = json5::parse(text) else {
            return Err(Z_ERR_CONFIG_INVALID_VALUE);
        };
        Ok(Json5Value::Object(
            members
                .into_iter()
                .filter(|(key, value)| {
                    key == RETIRED_MEMBER
                        || (key == EXT_MEMBER && !matches!(value, Json5Value::Null))
                })
                .collect(),
        ))
    }

    /// What the runtime's door answers for `text` when its document is read as a tree, by the
    /// reader of a node's document the other ABIs read it with: the reference the door's walker is
    /// held to.
    #[cfg(feature = "config-document")]
    fn runtime_limits_by_tree(text: &str) -> Result<RuntimeLimits, ZResult> {
        let document = ext_members(text)?;
        let read = policy_document::statements_from_json5(&document)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
        let of_a_session = read.profile.is_some()
            || read.transport.is_some()
            || !read.statements.is_empty()
            || read.limits.iter().any(|stated| {
                SESSION_LIMITS
                    .iter()
                    .any(|entry| entry.id() == stated.limit)
            });
        #[cfg(feature = "shared-key-ids")]
        let of_a_session = of_a_session
            || read.key_ids != wz_session_core::shared_key_ids::KeyIdsAtOpen::default();
        let of_a_session = of_a_session || read.owned_address.is_some();
        if of_a_session {
            return Err(Z_ERR_CONFIG_INVALID_VALUE);
        }
        policy_document::resolve_document(
            policy_document::Base::node(SessionPolicy::defaults()),
            &document,
        )
        .map(|resolved| resolved.limits.runtime)
        .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    #[cfg(feature = "config-document")]
    fn policies_document(statements: &[(&str, &str)]) -> String {
        let members: Vec<String> = statements
            .iter()
            .map(|(policy, value)| format!("\"{policy}\": \"{value}\""))
            .collect();
        format!(
            "{{ mode: \"peer\", zext: {{ policies: {{ {} }} }} }}",
            members.join(", ")
        )
    }

    /// A config that states nothing resolves the build's policies and the limits every session of
    /// this ABI opens under (`crate::session::opening_limits`), no value from any layer. Turned
    /// red by a resolution that starts from the build's limits instead.
    #[test]
    fn a_config_that_states_nothing_opens_under_the_opening_limits() {
        let expected = stating_nothing();
        let config = Config::new();
        assert_eq!(config.resolved(), expected);
        assert_eq!(resolve_policy(&PolicyStatements::none()), Ok(expected));
    }

    /// What the open and the doors resolve for a config is what the record of where each value
    /// came from resolves: the two snapshots of a config that states nothing and of one whose
    /// door kept a statement, and the same code for a statement no door would keep. Turned red by
    /// an open that resolves its snapshots by another path than the record.
    #[test]
    fn the_open_resolves_the_snapshots_the_record_of_origins_resolves() {
        assert_eq!(
            resolve_snapshots(&PolicyStatements::none()),
            Ok((SessionPolicy::defaults(), crate::session::opening_limits()))
        );
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), value), Z_OK);
        let recorded = config.resolved();
        assert_eq!(
            resolve_snapshots(&config.state().policies),
            Ok((recorded.policy, recorded.limits.session))
        );
        match PolicyStatements::against_the_resolution() {
            Against::Refused(refused) => {
                assert_eq!(
                    resolve_policy(&refused).map(|_| ()),
                    Err(Z_ERR_CONFIG_INVALID_VALUE),
                    "CONTROL: the record refuses it"
                );
                assert_eq!(resolve_snapshots(&refused), Err(Z_ERR_CONFIG_INVALID_VALUE));
            }
            // A build whose every value the resolution admits: the record admits it, and the
            // open resolves what the record resolves.
            Against::Admitted(admitted) => assert_eq!(
                resolve_snapshots(&admitted),
                resolve_policy(&admitted)
                    .map(|resolved| (resolved.policy, resolved.limits.session))
            ),
        }
    }

    /// The policy door refuses what the build refuses, by the same code, and a refused statement
    /// leaves the earlier one standing.
    #[test]
    fn the_policy_door_refuses_what_the_build_refuses_and_changes_nothing() {
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), value), Z_OK);
        assert_eq!(
            config.policy("no-such-policy", value),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            config.policy(entry.id(), "no-such-value"),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        // A value the policy has and the build's domain leaves out, where the build has one.
        if let Some((outside, left_out)) = decidable().find_map(|entry| {
            let left_out = entry
                .values()
                .iter()
                .copied()
                .find(|value| !entry.domain().contains(value))?;
            Some((entry, left_out))
        }) {
            assert_eq!(
                config.policy(outside.id(), left_out),
                Z_ERR_CONFIG_INVALID_VALUE
            );
        }
        // A policy only the build decides, where the build has one.
        if let Some(bound) = POLICIES
            .iter()
            .find(|entry| entry.binding() == Binding::Build)
        {
            assert_eq!(
                config.policy(bound.id(), bound.values()[0]),
                Z_ERR_CONFIG_INVALID_VALUE
            );
        }
        let resolved = config.resolved();
        assert_eq!(entry.value_in(&resolved.policy), value);
        assert_eq!(resolved.provenance.origin(entry.id()), Some(Origin::Api));
        assert_eq!(config.state().policies.api.len(), 1, "only the kept one");
    }

    #[test]
    fn a_door_refuses_a_null_config_or_argument() {
        let (entry, value) = one_allowed();
        let (policy, value) = (
            CString::new(entry.id()).unwrap(),
            CString::new(value).unwrap(),
        );
        let mut config = Config::new();
        // SAFETY: each pointer is null or live.
        unsafe {
            assert_eq!(
                zext_config_policy(core::ptr::null_mut(), policy.as_ptr(), value.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                zext_config_policy(config.loaned(), core::ptr::null(), value.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                zext_config_policy(config.loaned(), policy.as_ptr(), core::ptr::null()),
                Z_ERR_NULL
            );
            assert_eq!(
                zext_config_profile(core::ptr::null_mut(), policy.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                zext_config_profile(config.loaned(), core::ptr::null()),
                Z_ERR_NULL
            );
            #[cfg(feature = "config-document")]
            assert_eq!(
                zext_config_document(config.loaned(), core::ptr::null()),
                Z_ERR_NULL
            );
        }
        assert!(config.state().policies.api.is_empty());
    }

    /// A second statement of a policy replaces the first rather than being refused as one stated
    /// twice.
    #[test]
    fn a_second_statement_of_a_policy_replaces_the_first() {
        let Some((entry, first, second)) = two_allowed() else {
            // The build allows one value of every policy: there is nothing to replace with.
            return;
        };
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), first), Z_OK);
        assert_eq!(config.policy(entry.id(), second), Z_OK);
        assert_eq!(entry.value_in(&config.resolved().policy), second);
        assert_eq!(config.state().policies.api.len(), 1);
    }

    /// A statement and a profile the doors keep are the build's own ids, not copies of the text the
    /// caller handed, so a config holds them in no memory of its own. Turned red by a door that
    /// keeps a copy of what it is handed.
    #[test]
    fn the_doors_keep_the_builds_own_ids() {
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), value), Z_OK);
        let held = config
            .state()
            .policies
            .api
            .value_of(entry.id())
            .expect("a statement kept");
        assert!(entry
            .values()
            .iter()
            .any(|known| core::ptr::eq(*known, held)));
        if standard_allowed().is_some() {
            assert_eq!(config.profile("standard"), Z_OK);
            let kept = config.state().policies.profile.expect("a profile kept");
            let declared = Profile::find("standard").expect("declared");
            assert!(core::ptr::eq(kept, declared.id));
        }
    }

    #[test]
    fn the_profile_door_refuses_a_profile_the_build_does_not_have() {
        let mut config = Config::new();
        let standard = standard_allowed();
        match standard {
            Some(_) => assert_eq!(config.profile("standard"), Z_OK),
            // The build leaves a value the profile states out of a domain.
            None => assert_eq!(config.profile("standard"), Z_ERR_CONFIG_INVALID_VALUE),
        }
        assert_eq!(
            config.profile("no-such-profile"),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        let resolved = config.resolved();
        let expected = match standard {
            Some(_) => Origin::Profile("standard"),
            None => Origin::BuildDefault,
        };
        assert!(resolved
            .provenance
            .iter()
            .all(|(_, origin)| origin == expected));
    }

    /// Every shape step 4a refuses in a document's `zext` member, and text that is no JSON5 object,
    /// is refused by the document door, which keeps the document it held.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_refuses_each_refused_shape_and_keeps_the_last_document() {
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        assert_eq!(
            config.document(&policies_document(&[(entry.id(), value)])),
            Z_OK
        );
        let refused = [
            String::from("{ zext: "),
            String::from("[1, 2]"),
            String::from("{ zext: \"standard\" }"),
            String::from("{ zext: { policies: [\"a\", \"b\"] } }"),
            String::from("{ zext: { profile: 1 } }"),
            String::from("{ zext: { limits: { NO_SUCH_LIMIT: 4 } } }"),
            String::from("{ zext: { limits: [4] } }"),
            String::from("{ zext: { colour: \"blue\" } }"),
            String::from("{ zext: { profile: \"no-such-profile\" } }"),
            String::from("{ zext: {}, zext: {} }"),
            String::from("{ wz: {} }"),
            String::from("{ wz: null }"),
            policies_document(&[("no-such-policy", value)]),
            policies_document(&[(entry.id(), "no-such-value")]),
            policies_document(&[(entry.id(), value), (entry.id(), value)]),
        ];
        for text in &refused {
            assert_eq!(config.document(text), Z_ERR_CONFIG_INVALID_VALUE, "{text}");
        }
        let resolved = config.resolved();
        assert_eq!(entry.value_in(&resolved.policy), value);
        assert_eq!(
            resolved.provenance.origin(entry.id()),
            Some(Origin::Document)
        );
    }

    /// The member is read under `zext`, and the same statements under the retired name `wz` are
    /// refused, a `null` too, leaving the config as it was. Turned red by a door that steps over
    /// the retired name as a member of zenoh's, or reads it as the member.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_reads_zext_and_refuses_the_retired_member() {
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        let taken = policies_document(&[(entry.id(), value)]);
        assert!(taken.contains("zext:"), "{taken}");
        assert_eq!(config.document(&taken), Z_OK);
        let retired = taken.replace("zext:", "wz:");
        assert_eq!(
            config.document(&retired),
            Z_ERR_CONFIG_INVALID_VALUE,
            "{retired}"
        );
        assert_eq!(config.document("{ wz: null }"), Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(entry.value_in(&config.resolved().policy), value);
    }

    /// The document door takes the version this build reads and refuses any other, and takes
    /// `zext/transport` as `system`, or as `application` in a build that carries the program's
    /// transport; a value of neither, one that is no string, and either member stated twice are
    /// refused. Turned red by a door that steps over either member, or takes a version it does
    /// not read.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_reads_the_version_and_the_transport() {
        let mut config = Config::new();
        assert_eq!(config.document("{ zext: { version: 1 } }"), Z_OK);
        assert_eq!(config.document("{ zext: { transport: \"system\" } }"), Z_OK);
        for refused in [
            "{ zext: { version: 2 } }",
            "{ zext: { version: \"1\" } }",
            "{ zext: { version: 1, version: 1 } }",
            "{ zext: { transport: \"carrier-pigeon\" } }",
            "{ zext: { transport: 1 } }",
            "{ zext: { transport: \"system\", transport: \"system\" } }",
        ] {
            assert_eq!(
                config.document(refused),
                Z_ERR_CONFIG_INVALID_VALUE,
                "{refused}"
            );
        }
        let application = config.document("{ zext: { transport: \"application\" } }");
        if cfg!(feature = "app-transport") {
            assert_eq!(application, Z_OK);
        } else {
            assert_eq!(application, Z_ERR_CONFIG_INVALID_VALUE);
        }
    }

    /// The open is refused for a document that asks for the program's transport while the config
    /// is handed none, and not for one that states the system's sockets. Turned red by an open
    /// that opens such a config on the system's sockets.
    #[cfg(all(feature = "config-document", feature = "app-transport"))]
    #[test]
    fn an_open_without_the_program_transport_its_document_asks_for_is_refused() {
        let mut config = Config::new();
        assert_eq!(config.document("{ zext: { transport: \"system\" } }"), Z_OK);
        assert_eq!(crate::session::transport_refused(config.state()), None);
        assert_eq!(
            config.document("{ zext: { transport: \"application\" } }"),
            Z_OK
        );
        assert_eq!(
            crate::session::transport_refused(config.state()),
            Some(Z_ERR_CONFIG_INVALID_VALUE)
        );
    }

    /// A build without the `shared-key-ids` capability refuses a document that states key ids,
    /// by name, and keeps the config as it was.
    #[cfg(all(feature = "config-document", not(feature = "shared-key-ids")))]
    #[test]
    fn the_document_door_refuses_key_ids_without_the_capability() {
        let mut config = Config::new();
        assert_eq!(
            config.document(
                r#"{ zext: { "key-ids": { dictionary: [ { id: 40, key: "lab/rig" } ] } } }"#
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(config.resolved(), stating_nothing());
    }

    /// The door reads `zext/key-ids` where it lies, into the rows of its entries, as the tree
    /// reader the other ABIs read it with reads it; a refused part of it refuses the document, and
    /// the config keeps the key ids it held. Turned red by a door whose reader drops a link or an
    /// entry, or keeps what a refused document stated.
    #[cfg(all(feature = "config-document", feature = "shared-key-ids"))]
    #[test]
    fn the_document_door_reads_key_ids_as_the_tree_reader_does() {
        let text = r#"{ mode: "peer", zext: { "key-ids": {
            dictionary: [ { id: 40, key: "lab/rig" }, { key: 'lab/rig/alpha', id: 0x29 } ],
            links: [ { locator: "tcp/192.0.2.7:7447", form: "declared" } ] } } }"#;
        let mut config = Config::new();
        assert_eq!(config.document(text), Z_OK);
        let tree = policy_document::statements_from_json5(&ext_members(text).expect("an object"))
            .expect("well formed")
            .key_ids;
        assert!(
            tree.ids.is_some() && !tree.links.is_empty(),
            "CONTROL: the document states a dictionary and a link"
        );
        let read = |config: &Config| {
            config
                .state()
                .policies
                .document_key_ids()
                .expect("the door's rows")
        };
        assert_eq!(read(&config), tree);

        assert_eq!(
            config.document(
                r#"{ zext: { "key-ids": { dictionary: [ { id: 0, key: "lab/a" } ] } } }"#
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            read(&config),
            tree,
            "a refused document keeps the key ids the config held"
        );
    }

    /// The door reads `zext/owned-address` as the tree reader does: the address of a node is kept
    /// for the open and states no policy, and text that is no IPv4 address of a node, a value that
    /// is not a string and the member stated twice are refused with the config left as it was. A
    /// runtime's document states no address, which is a session's.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_reads_the_owned_address_as_the_tree_reader_does() {
        let text = r#"{ mode: "client", zext: { "owned-address": "127.0.0.1" } }"#;
        let tree = policy_document::statements_from_json5(&ext_members(text).expect("an object"))
            .expect("well formed")
            .owned_address;
        assert_eq!(
            tree,
            Some([127, 0, 0, 1]),
            "CONTROL: the tree reader reads it"
        );
        let mut config = Config::new();
        assert_eq!(config.state().policies.document_owned_address(), None);
        assert_eq!(config.document(text), Z_OK);
        assert_eq!(config.state().policies.document_owned_address(), tree);
        assert_eq!(
            config.resolved(),
            stating_nothing(),
            "the address states no policy"
        );
        for refused in [
            r#"{ zext: { "owned-address": "127.0.0" } }"#,
            r#"{ zext: { "owned-address": "127.0.0.1.1" } }"#,
            r#"{ zext: { "owned-address": "255.255.255.255.255" } }"#,
            r#"{ zext: { "owned-address": "0.0.0.0" } }"#,
            r#"{ zext: { "owned-address": "239.1.2.3" } }"#,
            r#"{ zext: { "owned-address": 2130706433 } }"#,
            r#"{ zext: { "owned-address": "10.0.0.1", "owned-address": "10.0.0.2" } }"#,
        ] {
            assert!(
                policy_document::statements_from_json5(&ext_members(refused).expect("an object"))
                    .is_err(),
                "CONTROL: the tree reader refuses {refused}"
            );
            assert_eq!(
                config.document(refused),
                Z_ERR_CONFIG_INVALID_VALUE,
                "{refused}"
            );
            assert_eq!(
                config.state().policies.document_owned_address(),
                tree,
                "a refused document keeps the address the config held: {refused}"
            );
        }
        assert_eq!(
            config.document(r#"{ mode: "client" }"#),
            Z_OK,
            "a document that states no address"
        );
        assert_eq!(
            config.state().policies.document_owned_address(),
            None,
            "replaces the one that stated it"
        );
        assert_eq!(
            runtime_limits_of(r#"{ zext: { "owned-address": "127.0.0.1" } }"#).err(),
            Some(Z_ERR_CONFIG_INVALID_VALUE),
            "a runtime's document states no address of a session"
        );
    }

    /// A document with no `zext` member, or a `zext: null`, states nothing: the config resolves as
    /// one handed no document, over the limits a session of this ABI opens under. Turned red by a
    /// door that keeps such a document as a layer, or resolves it over the build's limits.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_document_without_a_wz_member_states_nothing() {
        for text in ["{ mode: \"peer\" }", "{ mode: \"peer\", zext: null }"] {
            let mut config = Config::new();
            assert_eq!(config.document(text), Z_OK, "{text}");
            assert_eq!(config.resolved(), stating_nothing(), "{text}");
        }
    }

    /// The door keeps what a document's `zext` member states as rows of the build's own ids and no
    /// tree: the policy's and the limit's ids are the build's, not the document's text, and a limit
    /// stated twice is refused with the config kept as it was. Turned red by a door that keeps the
    /// document, or copies its text.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_is_kept_as_the_builds_own_ids() {
        let (entry, value) = one_allowed();
        let mut config = Config::new();
        let text = format!(
            "{{ mode: \"peer\", connect: {{ endpoints: [\"tcp/10.0.0.1:7447\"] }}, \
             zext: {{ policies: {{ \"{}\": \"{value}\" }}, limits: {{ MAX_SUBSCRIPTIONS: 1 }} }} }}",
            entry.id()
        );
        assert_eq!(config.document(&text), Z_OK);
        let document = &config.state().policies.document;
        let statement = document
            .statements
            .value_of(entry.id())
            .expect("a statement kept");
        assert!(entry
            .values()
            .iter()
            .any(|known| core::ptr::eq(*known, statement)));
        assert_eq!(
            document.limits.value_of("MAX_SUBSCRIPTIONS"),
            Some(LimitValue::Integer(1))
        );
        assert_eq!(
            config.document("{ zext: { limits: { MAX_SUBSCRIPTIONS: 1, MAX_SUBSCRIPTIONS: 1 } } }"),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        let kept = &config.state().policies.document;
        assert_eq!(kept.statements.len(), 1, "the config keeps what it held");
        assert_eq!(
            kept.limits.value_of("MAX_SUBSCRIPTIONS"),
            Some(LimitValue::Integer(1))
        );
    }

    /// A document nested `CONFIG_DOCUMENT_DEPTH` deep is read, and one a level deeper is refused
    /// with the config kept as it was, though the nesting is in a member the door does not read.
    /// Turned red by a reader that steps over a member with no bound, or with another.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_document_past_its_depth_is_refused() {
        // The outermost object is 1, and each `{ a: .. }` in the member's value one more.
        let nested = |depth: usize| {
            format!(
                "{{ mode: \"peer\", deep: {}{{}}{} }}",
                "{ a: ".repeat(depth - 2),
                " }".repeat(depth - 2)
            )
        };
        let mut config = Config::new();
        assert_eq!(config.document(&nested(caps::CONFIG_DOCUMENT_DEPTH)), Z_OK);
        let (entry, value) = one_allowed();
        assert_eq!(
            config.document(&policies_document(&[(entry.id(), value)])),
            Z_OK
        );
        assert_eq!(
            config.document(&nested(caps::CONFIG_DOCUMENT_DEPTH + 1)),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            config.state().policies.document.statements.len(),
            1,
            "the config keeps what it held"
        );
    }

    /// The door's statement wins over the document's, the document's over the profile's, whatever
    /// order the doors were called in, and each value records the layer it came from.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_door_overrides_the_document_which_overrides_the_profile() {
        let (Some((entry, in_document, in_door)), Some(_)) = (two_allowed(), standard_allowed())
        else {
            // The build allows one value of every policy, or refuses the profile.
            return;
        };
        let (other, other_value) = decidable()
            .filter(|candidate| candidate.id() != entry.id())
            .find_map(|candidate| Some((candidate, candidate.domain().iter().next()?)))
            .expect("a second policy a document may state");
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), in_door), Z_OK);
        assert_eq!(
            config.document(&policies_document(&[
                (entry.id(), in_document),
                (other.id(), other_value)
            ])),
            Z_OK
        );
        assert_eq!(config.profile("standard"), Z_OK);
        let resolved = config.resolved();
        assert_eq!(entry.value_in(&resolved.policy), in_door);
        assert_eq!(other.value_in(&resolved.policy), other_value);
        for (policy, origin) in resolved.provenance.iter() {
            let expected = if policy.id() == entry.id() {
                Origin::Api
            } else if policy.id() == other.id() {
                Origin::Document
            } else {
                Origin::Profile("standard")
            };
            assert_eq!(origin, expected, "{}", policy.id());
        }
    }

    /// A document handed in place of an earlier one replaces the document layer alone: the door's
    /// statement stays on top, a policy only the earlier document stated falls back to the build
    /// default, and the result is the one of the same layers stated in the other order. Turned red
    /// by a document door that clears the door's statements, or keeps the earlier document's.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_replaced_document_leaves_the_doors_statement_on_top() {
        let Some((entry, in_document, in_door)) = two_allowed() else {
            // The build allows one value of every policy.
            return;
        };
        let (other, other_value) = decidable()
            .filter(|candidate| candidate.id() != entry.id())
            .find_map(|candidate| Some((candidate, candidate.domain().iter().next()?)))
            .expect("a second policy a document may state");
        let replacing = policies_document(&[(entry.id(), in_document)]);
        let mut config = Config::new();
        assert_eq!(config.policy(entry.id(), in_door), Z_OK);
        assert_eq!(
            config.document(&policies_document(&[
                (entry.id(), in_document),
                (other.id(), other_value)
            ])),
            Z_OK
        );
        assert_eq!(
            config.resolved().provenance.origin(other.id()),
            Some(Origin::Document),
            "CONTROL: the earlier document is a layer"
        );
        assert_eq!(config.document(&replacing), Z_OK);
        let resolved = config.resolved();
        assert_eq!(entry.value_in(&resolved.policy), in_door);
        assert_eq!(resolved.provenance.origin(entry.id()), Some(Origin::Api));
        assert_eq!(
            resolved.provenance.origin(other.id()),
            Some(Origin::BuildDefault)
        );
        assert_eq!(
            other.value_in(&resolved.policy),
            other.value_in(&SessionPolicy::defaults())
        );
        let mut reversed = Config::new();
        assert_eq!(reversed.document(&replacing), Z_OK);
        assert_eq!(reversed.policy(entry.id(), in_door), Z_OK);
        let again = reversed.resolved();
        assert_eq!(again.policy, resolved.policy);
        let origins = |resolved: &Resolved| {
            resolved
                .provenance
                .iter()
                .map(|(_, origin)| origin)
                .collect::<Vec<_>>()
        };
        assert_eq!(origins(&again), origins(&resolved));
    }

    /// With no profile door, the profile the document names is the layer below its policies.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_documents_profile_stands_when_the_door_names_none() {
        if standard_allowed().is_none() {
            assert_eq!(
                Config::new().document("{ zext: { profile: \"standard\" } }"),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            return;
        }
        let mut config = Config::new();
        assert_eq!(config.document("{ zext: { profile: \"standard\" } }"), Z_OK);
        assert!(config
            .resolved()
            .provenance
            .iter()
            .all(|(_, origin)| origin == Origin::Profile("standard")));
    }

    /// One document, through this door and through the reader of the zenoh document over the
    /// limits a session of this ABI opens under, resolves to one snapshot with one provenance; the
    /// zenoh-c ABI's reader of the same document gives the same policies from the same layers, each
    /// ABI keeping the limits it opens under. Turned red by a door that resolves over other limits
    /// than the open's, or reads the policies apart from the zenoh reader.
    #[cfg(feature = "config-document")]
    #[test]
    fn one_document_resolves_as_the_zenoh_reader_resolves_it() {
        let (entry, value) = match two_allowed() {
            Some((entry, _, second)) => (entry, second),
            None => one_allowed(),
        };
        let profile = if standard_allowed().is_some() {
            "profile: \"standard\", "
        } else {
            ""
        };
        let text = format!(
            "{{ mode: \"peer\", zext: {{ {profile}policies: {{ \"{}\": \"{value}\" }} }} }}",
            entry.id()
        );
        let mut config = Config::new();
        assert_eq!(config.document(&text), Z_OK);
        let through_door = config.resolved();
        let tree = json5::parse(&text).expect("JSON5");
        assert_eq!(
            Ok(through_door),
            policy_document::resolve_document(opening_base(), &tree)
        );
        assert_eq!(entry.value_in(&through_door.policy), value);
        #[cfg(all(feature = "engine-tokio", feature = "scout"))]
        {
            // A node of the zenoh-c ABI opens under the build's limits and a session of this one
            // under zenoh-pico's, so the limits are compared above, over this ABI's own.
            let zenoh = wz_capi_core::runtime::zenoh_config::ZenohNodeConfig::from_json5(&text)
                .expect("the zenoh reader takes the document");
            assert_eq!(zenoh.config.policies.policy, through_door.policy);
            assert_eq!(zenoh.config.policies.provenance, through_door.provenance);
        }
    }

    /// The document door reads each member of the corpus every door is held to as the reader of a
    /// document does for a creator that holds a session's limits: the open composes the limits a
    /// taken member selects over the limits a session of this ABI opens under, and a refused member
    /// is refused with the doors' code and leaves the config as it was. Turned red by a door that
    /// selects a limit the member does not state, or resolves over the build's limits.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_reads_each_limits_member_of_the_corpus_as_a_session_does() {
        use wz_session_core::limit_corpus::{cases, Expected};

        for case in cases() {
            let text = format!("{{ mode: \"peer\", zext: {} }}", case.ext_member());
            let mut config = Config::new();
            let code = config.document(&text);
            match &case.session {
                Expected::Selected(selected) => {
                    assert_eq!(code, Z_OK, "{}", case.name);
                    let resolved = config.resolved();
                    if let Err(why) = case.session.check_session_over(
                        &crate::session::opening_limits(),
                        &resolved.limits.session,
                    ) {
                        panic!("{}: {why}", case.name);
                    }
                    for (limit, _) in selected {
                        assert_eq!(
                            resolved.limits.provenance.origin(limit),
                            Some(Origin::Document),
                            "{}: {limit}",
                            case.name
                        );
                    }
                    let tree = json5::parse(&text).expect("JSON5");
                    assert_eq!(
                        Ok(resolved),
                        policy_document::resolve_document(opening_base(), &tree),
                        "{}",
                        case.name
                    );
                }
                Expected::Refused(_) => {
                    assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE, "{}", case.name);
                    assert_eq!(config.resolved(), stating_nothing(), "{}", case.name);
                }
            }
        }
    }

    /// The runtime's document states the process's runtime alone: a session's limit, a policy, a
    /// profile, text that is no document and no text are refused, before the process is asked,
    /// so whatever the process holds the refusal is the same and changes nothing.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_runtime_document_refuses_what_a_session_states() {
        let door = |text: &str| {
            let text = CString::new(text).unwrap();
            // SAFETY: a live string.
            unsafe { zext_runtime_limits_document(text.as_ptr()) }
        };
        let held = wz_capi_port::runtime_limits::held();
        for text in [
            "{ zext: { limits: { MAX_SUBSCRIPTIONS: 1 } } }",
            "{ zext: { profile: \"standard\" } }",
            "not a document",
            "{ zext: { limits: { NO_SUCH_LIMIT: 1 } } }",
        ] {
            assert_eq!(door(text), Z_ERR_CONFIG_INVALID_VALUE, "{text}");
        }
        let (entry, value) = one_allowed();
        assert_eq!(
            door(&policies_document(&[(entry.id(), value)])),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        // SAFETY: a null pointer, which the door refuses.
        assert_eq!(
            unsafe { zext_runtime_limits_document(core::ptr::null()) },
            Z_ERR_NULL
        );
        assert_eq!(wz_capi_port::runtime_limits::held(), held);
    }

    /// The runtime's door reads its document by the rules of the tree reader of a node's document:
    /// each member of the corpus every door is held to, and each shape of the `zext` member,
    /// answers what the tree answers, and the shapes below are taken or refused as listed. Turned
    /// red by a walker that takes a limit of a session, a profile, a policy or key ids, that
    /// refuses an empty `zext/policies` or `zext/key-ids` the tree takes, or that takes a runtime's
    /// limit stated twice.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_runtime_document_is_read_as_the_tree_reader_reads_it() {
        use wz_session_core::limit_corpus::{cases, json5_value};

        for case in cases() {
            let text = case.document();
            assert_eq!(
                runtime_limits_of(&text),
                runtime_limits_by_tree(&text),
                "{}",
                case.name
            );
        }

        let mut taken: Vec<String> = [
            "{ mode: \"peer\" }",
            "{ zext: null }",
            "{ zext: {} }",
            "{ zext: { policies: {} } }",
            "{ zext: { limits: {} } }",
            "{ zext: { limits: {} }, zext: null }",
            "{ zext: { version: 1 } }",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut refused: Vec<String> = [
            "{ zext: {}, zext: {} }",
            "{ zext: true }",
            "{ zext: { limits: {}, limits: {} } }",
            "{ zext: { policies: {}, policies: {} } }",
            "{ zext: { other: 1 } }",
            "{ zext: {} } {}",
            "{ wz: {} }",
            "{ wz: null }",
            "{ zext: {}, wz: { limits: {} } }",
            "{ zext: { transport: \"system\" } }",
            "{ zext: { version: 2 } }",
            "{ zext: { \"key-ids\": { dictionary: [ { id: 1, key: \"lab/a\" } ] } } }",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        #[cfg(feature = "shared-key-ids")]
        taken.extend([
            String::from("{ zext: { \"key-ids\": {} } }"),
            String::from("{ zext: { \"key-ids\": { dictionary: [], links: [] } } }"),
        ]);
        #[cfg(not(feature = "shared-key-ids"))]
        refused.push(String::from("{ zext: { \"key-ids\": {} } }"));
        let runtime = RuntimeLimits::defaults();
        if let Some(entry) = RUNTIME_LIMITS
            .iter()
            .find(|entry| entry.read_from_snapshot())
        {
            let (limit, value) = (entry.id(), json5_value(entry.value_in(&runtime)));
            taken.push(format!("{{ zext: {{ limits: {{ {limit}: {value} }} }} }}"));
            refused.push(format!(
                "{{ zext: {{ limits: {{ {limit}: {value}, {limit}: {value} }} }} }}"
            ));
            refused.push(format!("{{ zext: {{ limits: {{ {limit}: \"many\" }} }} }}"));
        }
        for text in &taken {
            assert!(runtime_limits_of(text).is_ok(), "{text}");
            assert_eq!(
                runtime_limits_of(text),
                runtime_limits_by_tree(text),
                "{text}"
            );
        }
        for text in &refused {
            assert_eq!(
                runtime_limits_of(text),
                Err(Z_ERR_CONFIG_INVALID_VALUE),
                "{text}"
            );
            assert_eq!(
                runtime_limits_by_tree(text),
                Err(Z_ERR_CONFIG_INVALID_VALUE),
                "{text}"
            );
        }
    }

    /// The runtime's document is held to the depth a config's is: nested `CONFIG_DOCUMENT_DEPTH`
    /// deep it is read, and a level deeper it is refused, though the nesting is in a member neither
    /// door reads. Turned red by a runtime's door that reads its document with no bound, as the
    /// tree reader does.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_runtime_document_past_its_depth_is_refused() {
        // The outermost object is 1, and each `{ a: .. }` in the member's value one more.
        let nested = |depth: usize| {
            format!(
                "{{ mode: \"peer\", deep: {}{{}}{} }}",
                "{ a: ".repeat(depth - 2),
                " }".repeat(depth - 2)
            )
        };
        assert_eq!(
            runtime_limits_of(&nested(caps::CONFIG_DOCUMENT_DEPTH)),
            Ok(RuntimeLimits::defaults())
        );
        assert_eq!(
            runtime_limits_of(&nested(caps::CONFIG_DOCUMENT_DEPTH + 1)),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
    }

    /// A value over the build's of each limit the process's machines read is refused, by the
    /// limit's name where the build's domain holds the value and by the domain where it does not.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_runtime_limit_over_the_builds_value_is_refused_by_name() {
        use wz_session_core::caps;
        use wz_session_core::process_limits::ProcessRows;

        let held = wz_capi_port::runtime_limits::held();
        for (limit, build) in [
            ("SUPERVISION_CHECKPOINTS", caps::SUPERVISION_CHECKPOINTS),
            ("MESSAGE_CATALOG_ENTRIES", caps::MESSAGE_CATALOG_ENTRIES),
            ("E2E_SUPERVISED_STREAMS", caps::E2E_SUPERVISED_STREAMS),
        ] {
            let text = format!("{{ zext: {{ limits: {{ {limit}: {} }} }} }}", build + 1);
            match runtime_limits_of(&text) {
                Ok(limits) => assert_eq!(
                    ProcessRows::of(&limits).map_err(|refused| refused.limit),
                    Err(limit)
                ),
                Err(code) => assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE, "{limit}"),
            }
            let text = CString::new(text).unwrap();
            // SAFETY: a live string.
            let code = unsafe { zext_runtime_limits_document(text.as_ptr()) };
            assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE, "{limit}");
        }
        assert_eq!(wz_capi_port::runtime_limits::held(), held);
    }

    /// A runtime's document that lowers each limit gives each machine the lowered rows, and each
    /// machine refuses the one past them.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_runtime_document_that_lowers_each_limit_is_honoured_by_its_machines() {
        use wz_session_core::limit_binding::LimitSpec;
        use wz_session_core::limits::{
            E2eSupervisedStreams, MessageCatalogEntries, SupervisionCheckpoints,
        };
        use wz_session_core::process_limits::ProcessRows;

        // A build whose domain keeps the build's value alone of a limit refuses any other.
        if SupervisionCheckpoints::DOMAIN.is_singleton()
            || MessageCatalogEntries::DOMAIN.is_singleton()
            || E2eSupervisedStreams::DOMAIN.is_singleton()
        {
            return;
        }
        let limits = runtime_limits_of(
            "{ zext: { limits: { SUPERVISION_CHECKPOINTS: 1, MESSAGE_CATALOG_ENTRIES: 1, \
             E2E_SUPERVISED_STREAMS: 1 } } }",
        )
        .expect("one is inside every domain");
        let rows = ProcessRows::of(&limits).expect("one is under every build's value");
        assert_eq!(
            rows,
            ProcessRows {
                supervision_checkpoints: 1,
                message_catalog_entries: 1,
                e2e_supervised_streams: 1,
            }
        );
        #[cfg(feature = "supervision")]
        {
            use wz_session_core::supervisor::{BuildSupervisor, StartRefused};
            let mut supervisor = BuildSupervisor::of_snapshots(&SessionPolicy::defaults(), &rows);
            assert_eq!(supervisor.start(0, 0, 5), Ok(()));
            assert_eq!(
                supervisor.start(1, 0, 5),
                Err(StartRefused::NoSuchCheckpoint)
            );
        }
        #[cfg(feature = "e2e-supervision")]
        {
            use wz_session_core::stream_supervisor::{
                AddRefused, Notify, StreamSlot, StreamSupervisor,
            };
            let mut slots = [StreamSlot::EMPTY; 4];
            let mut supervisor = StreamSupervisor::new(
                &mut slots,
                &mut [],
                0,
                0,
                Notify::StatusOnly,
                rows.e2e_supervised_streams,
            )
            .expect("the storage is the program's");
            assert_eq!(supervisor.add(10, 1, 1, false), Ok(0));
            assert_eq!(supervisor.add(10, 1, 1, false), Err(AddRefused::Full));
        }
        #[cfg(feature = "message-catalog")]
        {
            use wz_app_frame::message_catalog::{limits_with_messages, Catalog, RefusalKind};
            let two = "{nodes: [{name: 'a'}], messages: [\
                       {key_expr: 'k/one', id: 1, publishers: ['a'], subscribers: []}, \
                       {key_expr: 'k/two', id: 2, publishers: ['a'], subscribers: []}]}";
            match Catalog::parse(two, limits_with_messages(rows.message_catalog_entries)) {
                Ok(_) => panic!("two messages are read where one is lent"),
                Err(refused) => assert_eq!(refused.kind, RefusalKind::TooManyMessages),
            }
        }
    }

    /// The open refuses a config whose statements the build refuses, with the doors' code, and
    /// opens nothing.
    #[test]
    fn a_refused_statement_fails_the_open_and_opens_nothing() {
        let refused = match PolicyStatements::against_the_resolution() {
            Against::Refused(refused) => refused,
            // A build whose every value the resolution admits refuses no statement to the open.
            Against::Admitted(admitted) => {
                assert!(
                    resolve_policy(&admitted).is_ok(),
                    "the resolution admits it"
                );
                return;
            }
        };
        let mut config = Config::new();
        // SAFETY: the owned config is live and holds a `ConfigState`.
        unsafe {
            (*(config.0.handle as *mut ConfigState)).policies = refused;
        }
        let mut session = crate::session::z_owned_session_t {
            _val: core::ptr::null_mut(),
            _cnt: core::ptr::null_mut(),
        };
        // SAFETY: a live session slot and a live config, which the open consumes.
        let rc = unsafe {
            crate::session::z_open(
                &mut session,
                z_config_move(&mut config.0),
                core::ptr::null(),
            )
        };
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(session._val.is_null(), "no session was opened");
        assert!(config.0.handle.is_null(), "the open consumed the config");
    }
}

#[cfg(test)]
mod build_default_tests {
    use super::PolicyStatements;
    use wz_session_core::policy::SessionPolicy;

    /// A config that states nothing opens under the build's policies and the limits a session of
    /// this ABI opens under: through the resolver in a build with the doors, and with no resolver
    /// in one without them, so the two builds open such a config alike.
    #[test]
    fn a_config_that_states_nothing_opens_under_the_builds_policies_and_limits() {
        assert_eq!(
            crate::session::resolve_snapshots(&PolicyStatements::none()),
            Ok((SessionPolicy::defaults(), crate::session::opening_limits()))
        );
    }

    /// Without the doors a config holds nothing of its policies.
    #[cfg(not(feature = "config-policy"))]
    #[test]
    fn without_the_doors_a_config_holds_no_statement() {
        assert_eq!(core::mem::size_of::<PolicyStatements>(), 0);
    }
}
