// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_config_policy`, `wz_ext_config_profile` and `wz_ext_config_document`: the policies
//! and the limits a config states for the session [`z_open`](crate::session::z_open) opens from
//! it.
//!
//! pico's config is a set of numbered keys and has none for wz's policies, so these are doors wz
//! has and zenoh-pico does not: `wz_ext_*`, declared in `wz_ext.h`. The first two are in a build
//! with the `config-policy` capability, which a build that names nothing has and the zenoh-pico
//! preset leaves out; `wz_ext_config_document` is in a build with the `config-document` capability,
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
//! 2. the profile `wz_ext_config_profile` named, else the one the document names;
//! 3. the `wz/policies` of the document `wz_ext_config_document` was handed
//!    ([`policy_document::Origin::Document`]);
//! 4. the statements of `wz_ext_config_policy` ([`policy_document::Origin::Api`]).
//!
//! The `wz/limits` of the document are resolved in the same resolution, over the build defaults
//! of a session's limits: a pico session holds no runtime's limits, so a runtime's limit the
//! document states is refused, as a limit the build does not have is.
//!
//! The runtime is the process's (`wz_capi_port::runtime_limits`): its limits are stated by
//! `wz_ext_runtime_limits_document`, from the `wz/limits` of a document of their own, before the
//! first machine of the process that reads them is made.
//!
//! Each door checks its change the way the open will compose it, so a change the build would
//! refuse is refused when it is made, with `Z_ERR_CONFIG_INVALID_VALUE`, and leaves the config as
//! it was. The document is the zenoh JSON5 document the zenoh-c ABI reads, of which only the `wz`
//! member is read here, so one document gives both ABIs the same policies.

#[cfg(feature = "config-policy")]
use core::ffi::{c_char, CStr};

#[cfg(feature = "config-document")]
use wz_session_core::caps;
#[cfg(feature = "config-document")]
use wz_session_core::json5::{self, number_as_u64, Json5Value};
#[cfg(feature = "config-document")]
use wz_session_core::json5_lex::{Json5Error, Json5Keyword, Json5Str, Lexer};
#[cfg(feature = "config-document")]
use wz_session_core::limit_binding::{LimitValue, UNBOUNDED};
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "config-document")]
use wz_session_core::limits::{RuntimeLimits, SESSION_LIMITS};
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

/// The top-level member of a zenoh document that holds wz's own statements.
#[cfg(feature = "config-document")]
const WZ_MEMBER: &str = "wz";

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
}

/// What a config's doors stated about its policies, as they stated it: the open judges and
/// composes it ([`Self::compose`]). The profile and the statements are the build's own ids, found
/// by the door in the build's tables, so a config keeps them in no memory of its own.
#[cfg(feature = "config-policy")]
#[derive(Clone, Default)]
pub(crate) struct PolicyStatements {
    /// The id of the profile `wz_ext_config_profile` named; it replaces the profile the document
    /// names.
    profile: Option<&'static str>,
    /// What the `wz` member of the document `wz_ext_config_document` was handed states.
    #[cfg(feature = "config-document")]
    document: DocumentRows,
    /// The statements of `wz_ext_config_policy`, by the build's table.
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
        // A config handed no document is resolved as one with no `wz` member, without the reader
        // of a document (`policy_document::resolve_under`), which a build with no document door
        // then does not link.
        policy_document::resolve_under(base, overrides).map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The key ids the `wz/key-ids` of the document `wz_ext_config_document` was handed states,
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

    /// Statements of the API layer that the set holds and the resolution refuses, for a test of
    /// what the open does with them: a policy only the build decides, or a value the build's
    /// domain leaves out. `None` for a build with neither; a policy or a value the build does not
    /// have the set cannot hold.
    #[cfg(test)]
    pub(crate) fn refused_by_the_resolution() -> Option<Self> {
        use wz_session_core::policy_binding::Binding;
        let (policy, value) = POLICIES.iter().find_map(|entry| {
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
        })?;
        let mut statements = Self::default();
        statements.api.state(Statement::new(policy, value)).ok()?;
        Some(statements)
    }
}

/// The `wz` members of the zenoh document `text`, gathered in their order as the members of a
/// document of their own, or `Z_ERR_CONFIG_INVALID_VALUE` for text that is no JSON5 object. A
/// `wz: null` states nothing: zenoh's spelling of a member left unset, as the zenoh-c ABI's reader
/// of the same document takes it.
#[cfg(feature = "config-document")]
fn wz_members(text: &str) -> Result<Json5Value, ZResult> {
    let Ok(Json5Value::Object(members)) = json5::parse(text) else {
        return Err(Z_ERR_CONFIG_INVALID_VALUE);
    };
    Ok(Json5Value::Object(
        members
            .into_iter()
            .filter(|(key, value)| key == WZ_MEMBER && !matches!(value, Json5Value::Null))
            .collect(),
    ))
}

/// What the `wz` member of the document `wz_ext_config_document` was handed states, read by the
/// door into the build's own ids with no tree kept: the profile, the statements of `wz/policies`
/// and those of `wz/limits`, each held by the build's table, and the key ids of `wz/key-ids`. `Default` is a document with no `wz` member, which states nothing.
#[cfg(feature = "config-document")]
#[derive(Clone, Default)]
struct DocumentRows {
    profile: Option<&'static str>,
    statements: PolicySet,
    limits: LimitSet,
    #[cfg(feature = "shared-key-ids")]
    key_ids: wz_session_core::shared_key_ids::KeyIdsAtOpen,
}

/// A document the reader refuses: `Z_ERR_CONFIG_INVALID_VALUE` at the door.
#[cfg(feature = "config-document")]
struct Refused;

#[cfg(feature = "config-document")]
impl From<Json5Error> for Refused {
    fn from(_: Json5Error) -> Self {
        Self
    }
}

/// The members of the `wz` member already read, so a second one is refused.
#[cfg(feature = "config-document")]
#[derive(Default)]
struct Seen {
    profile: bool,
    policies: bool,
    limits: bool,
    key_ids: bool,
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
    lex.expect(b':', ": after a member name")?;
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
    /// Whether the document states nothing, so a config resolves as one handed none.
    fn states_nothing(&self) -> bool {
        let stated =
            self.profile.is_some() || !self.statements.is_empty() || !self.limits.is_empty();
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
    /// `wz` member is read; every other member is stepped over and still checked, at most
    /// `CONFIG_DOCUMENT_DEPTH` deep, the outermost object being 1.
    fn read(&mut self, text: &str) -> Result<(), ZResult> {
        self.profile = None;
        self.statements = PolicySet::new();
        self.limits = LimitSet::new();
        #[cfg(feature = "shared-key-ids")]
        {
            self.key_ids = Default::default();
        }
        self.read_document(&mut Lexer::new(text))
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The whole document: an object, each of whose `wz` members is read, and nothing after it.
    fn read_document(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
        lex.skip_trivia()?;
        open_object(lex)?;
        let mut seen_wz = false;
        while let Some(name) = next_member(lex)? {
            if name.eq_str(WZ_MEMBER) {
                self.read_wz(lex, &mut seen_wz)?;
            } else {
                lex.skip_value(caps::CONFIG_DOCUMENT_DEPTH - 1)?;
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

    /// One `wz` member: an object, or `null`, zenoh's spelling of a member left unset, which
    /// states nothing as the zenoh-c ABI's reader of the same document takes it.
    fn read_wz(&mut self, lex: &mut Lexer<'_>, seen_wz: &mut bool) -> Result<(), Refused> {
        if lex.peek() != Some(b'{') {
            let unset = !lex.at_string()
                && !lex.at_number()
                && lex.peek() != Some(b'[')
                && lex.keyword()? == Json5Keyword::Null;
            return if unset { Ok(()) } else { Err(Refused) };
        }
        first(seen_wz)?;
        open_object(lex)?;
        let mut seen = Seen::default();
        while let Some(name) = next_member(lex)? {
            if name.eq_str("profile") {
                first(&mut seen.profile)?;
                self.read_profile(lex)?;
            } else if name.eq_str("policies") {
                first(&mut seen.policies)?;
                self.read_policies(lex)?;
            } else if name.eq_str("limits") {
                first(&mut seen.limits)?;
                self.read_limits(lex)?;
            } else if name.eq_str("key-ids") {
                first(&mut seen.key_ids)?;
                // Read where it lies, into the rows of its entries, by the rules of the reader
                // the other ABIs read it with: the member nests below `wz`, two levels down.
                #[cfg(feature = "shared-key-ids")]
                {
                    self.key_ids = wz_session_core::shared_key_ids::read_member_in(
                        lex,
                        caps::CONFIG_DOCUMENT_DEPTH - 2,
                        wz_session_core::shared_key_ids::form_in_domain,
                    )
                    .map_err(|_| Refused)?;
                }
                // A build without the capability refuses the member by name.
                #[cfg(not(feature = "shared-key-ids"))]
                return Err(Refused);
            } else {
                return Err(Refused);
            }
            after_member(lex)?;
        }
        Ok(())
    }

    /// `wz/profile`: the id of a profile of the build.
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

    /// `wz/policies`: an object of a policy's id and a value's id, each a string, each policy of
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

    /// `wz/limits`: an object of a limit of a session's id and its value, a whole number a
    /// `usize` holds or `unbounded`, each limit once. A limit of a runtime is refused, as a
    /// session holds none.
    fn read_limits(&mut self, lex: &mut Lexer<'_>) -> Result<(), Refused> {
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
            let entry = SESSION_LIMITS
                .iter()
                .find(|entry| limit.eq_str(entry.id()))
                .ok_or(Refused)?;
            self.limits
                .state(LimitStatement::new(entry.id(), value))
                .map_err(|_| Refused)?;
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
pub unsafe extern "C" fn wz_ext_config_policy(
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
pub unsafe extern "C" fn wz_ext_config_profile(
    config: *mut z_loaned_config_t,
    profile: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            statements.state_profile(text_of(profile)?)
        })
    })
}

/// Hands `config` a zenoh JSON5 document, of which the `wz` member is read: the profile it names,
/// its `wz/policies`, its `wz/limits`, the limits of a session it states, and, in a build with
/// the `shared-key-ids` capability, its `wz/key-ids`, the key ids every node shares, under what
/// `wz_ext_config_key_ids` and `wz_ext_config_key_wire_form_for` state. The rest of the document
/// is not read, so the document a zenoh-c program opens with configures these sessions alike. A
/// second call replaces the first. Text that is no JSON5 object, a `wz` member whose shape is
/// refused (one that is not an object, a value that is not a string, a limit's value that is
/// neither a whole number nor `unbounded`, a member wz does not read, `wz/key-ids` in a build
/// without the capability, a member stated twice), a profile or a limit the build does not have,
/// a limit only the build decides, a limit of a runtime, a statement the build refuses and a
/// refused part of `wz/key-ids` are refused with `Z_ERR_CONFIG_INVALID_VALUE`, and the config is
/// left as it was.
///
/// The door walks the document once and keeps no tree: what the `wz` member states is kept as
/// the build's own ids, and a document nested deeper than `CONFIG_DOCUMENT_DEPTH` (the outermost
/// object being 1) is refused with `Z_ERR_CONFIG_INVALID_VALUE`.
///
/// In a build with the `config-document` capability alone: the door links a JSON5 reader that a
/// build stating its policies through [`wz_ext_config_policy`] and [`wz_ext_config_profile`] does
/// not need.
///
/// # Safety
/// `config` must be null or a live loaned config; `json5` must be null or a NUL-terminated string.
#[cfg(feature = "config-document")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_document(
    config: *mut z_loaned_config_t,
    json5: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            statements.document.read(text_of(json5)?)
        })
    })
}

/// The runtime's limits the `wz/limits` of the zenoh document `text` states, over the build's, or
/// `Z_ERR_CONFIG_INVALID_VALUE`. The document states the process's runtime and nothing of a
/// session: a profile, a policy, key ids and a limit of a session are its config's to state, and
/// are refused here with everything the reader of a node's document refuses.
#[cfg(feature = "config-document")]
fn runtime_limits_of(text: &str) -> Result<RuntimeLimits, ZResult> {
    let document = wz_members(text)?;
    let read = policy_document::statements_from_json5(&document)
        .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)?;
    let of_a_session = read.profile.is_some()
        || !read.statements.is_empty()
        || read.limits.iter().any(|stated| {
            wz_session_core::limits::SESSION_LIMITS
                .iter()
                .any(|entry| entry.id() == stated.limit)
        });
    #[cfg(feature = "shared-key-ids")]
    let of_a_session =
        of_a_session || read.key_ids != wz_session_core::shared_key_ids::KeyIdsAtOpen::default();
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

/// States the limits of the process's runtime from a zenoh JSON5 document, of which the
/// `wz/limits` member is read: the limits of the machines the process makes apart from any session,
/// its supervisor of checkpoints (`SUPERVISION_CHECKPOINTS`), its message catalogs
/// (`MESSAGE_CATALOG_ENTRIES`) and its reception supervisors (`E2E_SUPERVISED_STREAMS`), each at
/// most the build's value. A limit the document does not state keeps the build's value, and a
/// second call replaces the first.
///
/// The process's first machine of those takes the limits: the first call of a
/// `wz_ext_supervision_*` door, `wz_ext_stream_supervisor_new` or `wz_ext_message_catalog_new`.
/// A call after it is refused with `Z_EINVAL` and the process keeps the limits it took.
///
/// Text that is no JSON5 object, a `wz` member whose shape is refused, a profile, a policy, key
/// ids, a limit of a session, a limit the build does not have, a limit only the build decides and
/// a value the build's domain leaves out or that is over the build's value are refused with
/// `Z_ERR_CONFIG_INVALID_VALUE`, whenever the call comes, and the process keeps what it held. A
/// null `json5` is `Z_ERR_NULL`.
///
/// In a build with the `config-document` capability alone, as `wz_ext_config_document` is.
///
/// # Safety
/// `json5` must be null or a NUL-terminated string.
#[cfg(feature = "config-document")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_runtime_limits_document(json5: *const c_char) -> ZResult {
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
            unsafe { wz_ext_config_policy(self.loaned(), policy.as_ptr(), value.as_ptr()) }
        }

        fn profile(&mut self, profile: &str) -> ZResult {
            let profile = CString::new(profile).unwrap();
            // SAFETY: a live config and a live string.
            unsafe { wz_ext_config_profile(self.loaned(), profile.as_ptr()) }
        }

        #[cfg(feature = "config-document")]
        fn document(&mut self, text: &str) -> ZResult {
            let text = CString::new(text).unwrap();
            // SAFETY: a live config and a live string.
            unsafe { wz_ext_config_document(self.loaned(), text.as_ptr()) }
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

    /// The upstream profile, when the build allows every value it states.
    fn upstream_allowed() -> Option<&'static Profile> {
        let upstream = Profile::find("upstream").expect("declared");
        upstream
            .statements
            .iter()
            .all(|statement| {
                POLICIES
                    .iter()
                    .find(|entry| entry.id() == statement.policy)
                    .is_some_and(|entry| entry.domain().contains(statement.value))
            })
            .then_some(upstream)
    }

    #[cfg(feature = "config-document")]
    fn policies_document(statements: &[(&str, &str)]) -> String {
        let members: Vec<String> = statements
            .iter()
            .map(|(policy, value)| format!("\"{policy}\": \"{value}\""))
            .collect();
        format!(
            "{{ mode: \"peer\", wz: {{ policies: {{ {} }} }} }}",
            members.join(", ")
        )
    }

    /// A config that states nothing resolves the build's policies and the limits every session of
    /// this ABI opens under (`crate::session::opening_limits`), no value from any layer. Turned
    /// red by a resolution that starts from the build's limits instead.
    #[test]
    fn a_config_that_states_nothing_opens_under_the_opening_limits() {
        let mut expected = Resolved::unchanged(SessionPolicy::defaults());
        expected.limits.session = crate::session::opening_limits();
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
        // A build whose every value the resolution admits holds no refused statement.
        let Some(refused) = PolicyStatements::refused_by_the_resolution() else {
            return;
        };
        assert_eq!(
            resolve_policy(&refused).map(|_| ()),
            Err(Z_ERR_CONFIG_INVALID_VALUE),
            "CONTROL: the record refuses it"
        );
        assert_eq!(resolve_snapshots(&refused), Err(Z_ERR_CONFIG_INVALID_VALUE));
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
                wz_ext_config_policy(core::ptr::null_mut(), policy.as_ptr(), value.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_config_policy(config.loaned(), core::ptr::null(), value.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_config_policy(config.loaned(), policy.as_ptr(), core::ptr::null()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_config_profile(core::ptr::null_mut(), policy.as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_config_profile(config.loaned(), core::ptr::null()),
                Z_ERR_NULL
            );
            #[cfg(feature = "config-document")]
            assert_eq!(
                wz_ext_config_document(config.loaned(), core::ptr::null()),
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
        if upstream_allowed().is_some() {
            assert_eq!(config.profile("upstream"), Z_OK);
            let kept = config.state().policies.profile.expect("a profile kept");
            let declared = Profile::find("upstream").expect("declared");
            assert!(core::ptr::eq(kept, declared.id));
        }
    }

    #[test]
    fn the_profile_door_refuses_a_profile_the_build_does_not_have() {
        let mut config = Config::new();
        let upstream = upstream_allowed();
        match upstream {
            Some(_) => assert_eq!(config.profile("upstream"), Z_OK),
            // The build leaves a value the profile states out of a domain.
            None => assert_eq!(config.profile("upstream"), Z_ERR_CONFIG_INVALID_VALUE),
        }
        assert_eq!(
            config.profile("no-such-profile"),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        let resolved = config.resolved();
        let expected = match upstream {
            Some(_) => Origin::Profile("upstream"),
            None => Origin::BuildDefault,
        };
        assert!(resolved
            .provenance
            .iter()
            .all(|(_, origin)| origin == expected));
    }

    /// Every shape step 4a refuses in a document's `wz` member, and text that is no JSON5 object,
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
            String::from("{ wz: "),
            String::from("[1, 2]"),
            String::from("{ wz: \"upstream\" }"),
            String::from("{ wz: { policies: [\"a\", \"b\"] } }"),
            String::from("{ wz: { profile: 1 } }"),
            String::from("{ wz: { limits: { NO_SUCH_LIMIT: 4 } } }"),
            String::from("{ wz: { limits: [4] } }"),
            String::from("{ wz: { colour: \"blue\" } }"),
            String::from("{ wz: { profile: \"no-such-profile\" } }"),
            String::from("{ wz: {}, wz: {} }"),
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

    /// A build without the `shared-key-ids` capability refuses a document that states key ids,
    /// by name, and keeps the config as it was.
    #[cfg(all(feature = "config-document", not(feature = "shared-key-ids")))]
    #[test]
    fn the_document_door_refuses_key_ids_without_the_capability() {
        let mut config = Config::new();
        assert_eq!(
            config.document(
                r#"{ wz: { "key-ids": { dictionary: [ { id: 40, key: "lab/rig" } ] } } }"#
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            config.resolved(),
            Resolved::unchanged(SessionPolicy::defaults())
        );
    }

    /// The door reads `wz/key-ids` where it lies, into the rows of its entries, as the tree reader
    /// the other ABIs read it with reads it; a refused part of it refuses the document, and the
    /// config keeps the key ids it held. Turned red by a door whose reader drops a link or an
    /// entry, or keeps what a refused document stated.
    #[cfg(all(feature = "config-document", feature = "shared-key-ids"))]
    #[test]
    fn the_document_door_reads_key_ids_as_the_tree_reader_does() {
        let text = r#"{ mode: "peer", wz: { "key-ids": {
            dictionary: [ { id: 40, key: "lab/rig" }, { key: 'lab/rig/alpha', id: 0x29 } ],
            links: [ { locator: "tcp/192.0.2.7:7447", form: "declared" } ] } } }"#;
        let mut config = Config::new();
        assert_eq!(config.document(text), Z_OK);
        let tree = policy_document::statements_from_json5(&wz_members(text).expect("an object"))
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
            config
                .document(r#"{ wz: { "key-ids": { dictionary: [ { id: 0, key: "lab/a" } ] } } }"#),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            read(&config),
            tree,
            "a refused document keeps the key ids the config held"
        );
    }

    /// A document with no `wz` member, or a `wz: null`, states nothing.
    #[cfg(feature = "config-document")]
    #[test]
    fn a_document_without_a_wz_member_states_nothing() {
        for text in ["{ mode: \"peer\" }", "{ mode: \"peer\", wz: null }"] {
            let mut config = Config::new();
            assert_eq!(config.document(text), Z_OK, "{text}");
            assert_eq!(
                config.resolved(),
                Resolved::unchanged(SessionPolicy::defaults()),
                "{text}"
            );
        }
    }

    /// The door keeps what a document's `wz` member states as rows of the build's own ids and no
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
             wz: {{ policies: {{ \"{}\": \"{value}\" }}, limits: {{ MAX_SUBSCRIPTIONS: 1 }} }} }}",
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
            config.document("{ wz: { limits: { MAX_SUBSCRIPTIONS: 1, MAX_SUBSCRIPTIONS: 1 } } }"),
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
        let (Some((entry, in_document, in_door)), Some(_)) = (two_allowed(), upstream_allowed())
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
        assert_eq!(config.profile("upstream"), Z_OK);
        let resolved = config.resolved();
        assert_eq!(entry.value_in(&resolved.policy), in_door);
        assert_eq!(other.value_in(&resolved.policy), other_value);
        for (policy, origin) in resolved.provenance.iter() {
            let expected = if policy.id() == entry.id() {
                Origin::Api
            } else if policy.id() == other.id() {
                Origin::Document
            } else {
                Origin::Profile("upstream")
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
        if upstream_allowed().is_none() {
            assert_eq!(
                Config::new().document("{ wz: { profile: \"upstream\" } }"),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            return;
        }
        let mut config = Config::new();
        assert_eq!(config.document("{ wz: { profile: \"upstream\" } }"), Z_OK);
        assert!(config
            .resolved()
            .provenance
            .iter()
            .all(|(_, origin)| origin == Origin::Profile("upstream")));
    }

    /// One document, through this door and through the reader of the zenoh document, resolves to
    /// one snapshot with one provenance.
    #[cfg(feature = "config-document")]
    #[test]
    fn one_document_resolves_as_the_zenoh_reader_resolves_it() {
        let (entry, value) = match two_allowed() {
            Some((entry, _, second)) => (entry, second),
            None => one_allowed(),
        };
        let profile = if upstream_allowed().is_some() {
            "profile: \"upstream\", "
        } else {
            ""
        };
        let text = format!(
            "{{ mode: \"peer\", wz: {{ {profile}policies: {{ \"{}\": \"{value}\" }} }} }}",
            entry.id()
        );
        let mut config = Config::new();
        assert_eq!(config.document(&text), Z_OK);
        let through_door = config.resolved();
        let tree = json5::parse(&text).expect("JSON5");
        assert_eq!(
            Ok(through_door),
            policy_document::resolve_document(SessionPolicy::defaults(), &tree)
        );
        assert_eq!(entry.value_in(&through_door.policy), value);
        #[cfg(all(feature = "engine-tokio", feature = "scout"))]
        {
            let zenoh = wz_capi_core::runtime::zenoh_config::ZenohNodeConfig::from_json5(&text)
                .expect("the zenoh reader takes the document");
            assert_eq!(zenoh.config.policies, through_door);
        }
    }

    /// The document door reads each member of the corpus every door is held to as the reader of a
    /// document does for a creator that holds a session's limits: the open composes the limits a
    /// taken member selects, and a refused member is refused with the doors' code and leaves the
    /// config as it was.
    #[cfg(feature = "config-document")]
    #[test]
    fn the_document_door_reads_each_limits_member_of_the_corpus_as_a_session_does() {
        use wz_session_core::limit_corpus::{cases, Expected};

        for case in cases() {
            let text = format!("{{ mode: \"peer\", wz: {} }}", case.wz_member());
            let mut config = Config::new();
            let code = config.document(&text);
            match &case.session {
                Expected::Selected(selected) => {
                    assert_eq!(code, Z_OK, "{}", case.name);
                    let resolved = config.resolved();
                    if let Err(why) = case.session.check_session(&resolved.limits.session) {
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
                        policy_document::resolve_document(SessionPolicy::defaults(), &tree),
                        "{}",
                        case.name
                    );
                }
                Expected::Refused(_) => {
                    assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE, "{}", case.name);
                    assert_eq!(
                        config.resolved(),
                        Resolved::unchanged(SessionPolicy::defaults()),
                        "{}",
                        case.name
                    );
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
            unsafe { wz_ext_runtime_limits_document(text.as_ptr()) }
        };
        let held = wz_capi_port::runtime_limits::held();
        for text in [
            "{ wz: { limits: { MAX_SUBSCRIPTIONS: 1 } } }",
            "{ wz: { profile: \"upstream\" } }",
            "not a document",
            "{ wz: { limits: { NO_SUCH_LIMIT: 1 } } }",
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
            unsafe { wz_ext_runtime_limits_document(core::ptr::null()) },
            Z_ERR_NULL
        );
        assert_eq!(wz_capi_port::runtime_limits::held(), held);
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
            let text = format!("{{ wz: {{ limits: {{ {limit}: {} }} }} }}", build + 1);
            match runtime_limits_of(&text) {
                Ok(limits) => assert_eq!(
                    ProcessRows::of(&limits).map_err(|refused| refused.limit),
                    Err(limit)
                ),
                Err(code) => assert_eq!(code, Z_ERR_CONFIG_INVALID_VALUE, "{limit}"),
            }
            let text = CString::new(text).unwrap();
            // SAFETY: a live string.
            let code = unsafe { wz_ext_runtime_limits_document(text.as_ptr()) };
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
            "{ wz: { limits: { SUPERVISION_CHECKPOINTS: 1, MESSAGE_CATALOG_ENTRIES: 1, \
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
        // A build whose every value the resolution admits holds no refused statement.
        let Some(refused) = PolicyStatements::refused_by_the_resolution() else {
            return;
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
