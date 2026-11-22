// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_config_policy`, `wz_ext_config_profile` and `wz_ext_config_document`: the policies
//! and the limits a config states for the session [`z_open`](crate::session::z_open) opens from
//! it.
//!
//! pico's config is a set of numbered keys and has none for wz's policies, so these are doors wz
//! has and zenoh-pico does not: `wz_ext_*`, declared in `wz_ext.h`. The first two are in every
//! build; `wz_ext_config_document` is in a build with the `config-document` capability, since it
//! links a JSON5 reader. An MCU image whose domain of a policy holds one value refuses every other
//! value of it by name.
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

use core::ffi::{c_char, CStr};

#[cfg(feature = "config-document")]
use wz_session_core::json5::{self, Json5Value};
#[cfg(feature = "config-document")]
use wz_session_core::limits::RuntimeLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::policy_document::{self, Overrides, Resolved, Statement};

use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
use crate::ffi::guarded;
use crate::prelude::*;
#[cfg(feature = "config-document")]
use crate::result::Z_EINVAL;
use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};

/// The top-level member of a zenoh document that holds wz's own statements.
#[cfg(feature = "config-document")]
const WZ_MEMBER: &str = "wz";

/// What a config's doors stated about its policies, as they stated it: the open judges and
/// composes it ([`Self::compose`]).
#[derive(Clone, Default)]
pub(crate) struct PolicyStatements {
    /// The id `wz_ext_config_profile` named; it replaces the profile the document names.
    profile: Option<String>,
    /// The `wz` members of the document `wz_ext_config_document` was handed, gathered as the
    /// members of a document of their own.
    #[cfg(feature = "config-document")]
    document: Option<Json5Value>,
    /// The statements of `wz_ext_config_policy`, a policy's id and a value's id, one per policy,
    /// in the order each policy was first stated.
    api: Vec<(String, String)>,
}

impl PolicyStatements {
    /// `base` with the layers over it, and the limits the document states over the build defaults
    /// of a session's limits ([`policy_document::Base::session`]), or `Z_ERR_CONFIG_INVALID_VALUE`
    /// when any statement of any layer is refused, a document whose shape is refused, a profile
    /// the build does not have and a limit of a runtime among them.
    pub(crate) fn compose(&self, base: SessionPolicy) -> Result<Resolved, ZResult> {
        let base = policy_document::Base::session(base);
        let api: Vec<Statement<'_>> = self
            .api
            .iter()
            .map(|(policy, value)| Statement::new(policy.as_str(), value.as_str()))
            .collect();
        let overrides = Overrides {
            profile: self.profile.as_deref(),
            statements: &api,
            limits: &[],
        };
        #[cfg(feature = "config-document")]
        if let Some(document) = &self.document {
            return policy_document::resolve_document_under(base, document, overrides)
                .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE);
        }
        // A config handed no document is resolved as one with no `wz` member, without the reader
        // of a document (`policy_document::resolve_under`), which a build with no document door
        // then does not link.
        policy_document::resolve_under(base, overrides).map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
    }

    /// The key ids the `wz/key-ids` of the document `wz_ext_config_document` was handed states,
    /// read by the reader that composes its policies, or none when the config was handed no
    /// document. The door kept the document only when that reader took it whole, so a refusal
    /// here is of a config no door made, and `Z_ERR_CONFIG_INVALID_VALUE` like the policies'.
    #[cfg(feature = "shared-key-ids")]
    pub(crate) fn document_key_ids(
        &self,
    ) -> Result<wz_session_core::shared_key_ids::KeyIdsAtOpen, ZResult> {
        #[cfg(feature = "config-document")]
        if let Some(document) = &self.document {
            return policy_document::statements_from_json5(document)
                .map(|read| read.key_ids)
                .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE);
        }
        Ok(Default::default())
    }

    /// `policy` is to take `value` in the API layer; an earlier statement of the policy is
    /// replaced.
    fn state_policy(&mut self, policy: &str, value: &str) {
        match self.api.iter_mut().find(|(held, _)| held == policy) {
            Some((_, held)) => *held = value.to_owned(),
            None => self.api.push((policy.to_owned(), value.to_owned())),
        }
    }

    /// A statement no door would keep, for a test of what the open does with one.
    #[cfg(test)]
    pub(crate) fn unchecked(policy: &str, value: &str) -> Self {
        let mut statements = Self::default();
        statements.state_policy(policy, value);
        statements
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

/// `change` made to the policies `config` states, kept only when the open would compose the
/// result ([`crate::session::resolve_policy`]); a refused change leaves the config as it was.
///
/// # Safety
/// `config` must be null or a live loaned config.
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
    match crate::session::resolve_policy(&candidate) {
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
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_policy(
    config: *mut z_loaned_config_t,
    policy: *const c_char,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            let (policy, value) = (text_of(policy)?, text_of(value)?);
            statements.state_policy(policy, value);
            Ok(())
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
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_profile(
    config: *mut z_loaned_config_t,
    profile: *const c_char,
) -> ZResult {
    guarded(|| {
        amend(config, |statements| {
            statements.profile = Some(text_of(profile)?.to_owned());
            Ok(())
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
            statements.document = Some(wz_members(text_of(json5)?)?);
            Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::z_owned_config_t;
    use crate::config::{z_config_default, z_config_drop, z_config_loan_mut, z_config_move};
    use crate::session::resolve_policy;
    use alloc::ffi::CString;
    use wz_session_core::policy::POLICIES;
    use wz_session_core::policy_binding::{Binding, PolicyEntry};
    use wz_session_core::policy_document::{Origin, Profile};

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

    #[test]
    fn a_config_that_states_nothing_opens_under_the_build_defaults() {
        let config = Config::new();
        assert_eq!(
            config.resolved(),
            Resolved::unchanged(SessionPolicy::defaults())
        );
        assert_eq!(
            resolve_policy(&PolicyStatements::default()),
            Ok(Resolved::unchanged(SessionPolicy::defaults()))
        );
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
        let mut config = Config::new();
        // SAFETY: the owned config is live and holds a `ConfigState`.
        unsafe {
            (*(config.0.handle as *mut ConfigState)).policies =
                PolicyStatements::unchecked("no-such-policy", "on");
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
