// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_config_policy`, `wz_ext_config_profile` and `wz_ext_config_document`: the policies a
//! config states for the session [`z_open`](crate::session::z_open) opens from it.
//!
//! pico's config is a set of numbered keys and has none for wz's policies, so these are doors wz
//! has and zenoh-pico does not: `wz_ext_*`, declared in `wz_ext.h`. They are in every build. An
//! MCU image whose domain of a policy holds one value refuses every other value of it by name.
//!
//! What the doors state is kept in the config ([`PolicyStatements`]) and composed by the open,
//! lowest first, through [`policy_document::resolve_document_under`], the reader the other ABIs
//! compose a document and their open's statements with:
//!
//! 1. the build defaults;
//! 2. the profile `wz_ext_config_profile` named, else the one the document names;
//! 3. the `wz/policies` of the document `wz_ext_config_document` was handed
//!    ([`policy_document::Origin::Document`]);
//! 4. the statements of `wz_ext_config_policy` ([`policy_document::Origin::Api`]).
//!
//! Each door checks its change the way the open will compose it, so a change the build would
//! refuse is refused when it is made, with `Z_ERR_CONFIG_INVALID_VALUE`, and leaves the config as
//! it was. The document is the zenoh JSON5 document the zenoh-c ABI reads, of which only the `wz`
//! member is read here, so one document gives both ABIs the same policies.

use core::ffi::{c_char, CStr};

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::policy::SessionPolicy;
use wz_session_core::policy_document::{self, Overrides, Resolved, Statement};

use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
use crate::ffi::guarded;
use crate::prelude::*;
use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};

/// The top-level member of a zenoh document that holds wz's own statements.
const WZ_MEMBER: &str = "wz";

/// What a config's doors stated about its policies, as they stated it: the open judges and
/// composes it ([`Self::compose`]).
#[derive(Clone, Default)]
pub(crate) struct PolicyStatements {
    /// The id `wz_ext_config_profile` named; it replaces the profile the document names.
    profile: Option<String>,
    /// The `wz` members of the document `wz_ext_config_document` was handed, gathered as the
    /// members of a document of their own.
    document: Option<Json5Value>,
    /// The statements of `wz_ext_config_policy`, a policy's id and a value's id, one per policy,
    /// in the order each policy was first stated.
    api: Vec<(String, String)>,
}

impl PolicyStatements {
    /// `base` with the layers over it, or `Z_ERR_CONFIG_INVALID_VALUE` when any statement of any
    /// layer is refused, a document whose shape is refused and a profile the build does not have
    /// among them.
    pub(crate) fn compose(&self, base: SessionPolicy) -> Result<Resolved, ZResult> {
        // A config handed no document is resolved as one with no `wz` member, so the layers are
        // composed by one reader whether or not a document was handed.
        let no_document = Json5Value::Object(Vec::new());
        let document = self.document.as_ref().unwrap_or(&no_document);
        let api: Vec<Statement<'_>> = self
            .api
            .iter()
            .map(|(policy, value)| Statement::new(policy.as_str(), value.as_str()))
            .collect();
        let overrides = Overrides {
            profile: self.profile.as_deref(),
            statements: &api,
        };
        policy_document::resolve_document_under(base, document, overrides)
            .map_err(|_| Z_ERR_CONFIG_INVALID_VALUE)
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

/// Hands `config` a zenoh JSON5 document, of which the `wz` member is read: the profile it names
/// and its `wz/policies`. The rest of the document is not read, so the document a zenoh-c program
/// opens with configures these sessions' policies alike. A second call replaces the first. Text
/// that is no JSON5 object, a `wz` member whose shape is refused (one that is not an object, a
/// value that is not a string, a member wz does not read, `wz/limits`, a member stated twice), a
/// profile the build does not have and a statement the build refuses are refused with
/// `Z_ERR_CONFIG_INVALID_VALUE`, and the config is left as it was.
///
/// # Safety
/// `config` must be null or a live loaned config; `json5` must be null or a NUL-terminated string.
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
            String::from("{ wz: { limits: { MAX_A: 4 } } }"),
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

    /// A document with no `wz` member, or a `wz: null`, states nothing.
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
