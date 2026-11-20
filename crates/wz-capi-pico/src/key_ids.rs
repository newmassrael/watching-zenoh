// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key ids every node of a deployment shares, from C: `wz_ext_config_key_ids` hands a config
//! the dictionary, `wz_ext_config_key_wire_form_for` states the key-wire form of one endpoint apart
//! from the session's, and the open hands both to the engine.
//!
//! Doors wz has and zenoh-pico does not, so they are `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `shared-key-ids` capability implies `unstable-api`. The dictionary
//! and its rules are `wz_session_core::shared_key_ids`'s; both engines hold it, and each link of a
//! session names its keys as the form stated for its endpoint, or the session's, says.
//!
//! A config handed a document (`wz_ext_config_document`, the `config-document` capability) may
//! state the same in the document's `wz/key-ids`; what these doors state goes over it, as the
//! policy doors go over the document's policies.
//!
//! What every build has here is the open's judgement of the key-wire form ([`admit_at_open`]): a
//! session whose form, or an endpoint's, is `shared` and whose config states no dictionary is
//! refused, and so is any form but `declared` in a build without the capability. A refusal is the
//! code `z_open` answers, before anything is dialled.

#[cfg(feature = "shared-key-ids")]
use core::ffi::{c_char, CStr};

#[cfg(not(feature = "shared-key-ids"))]
use wz_session_core::policy::KeyWireForm;
use wz_session_core::policy::SessionPolicy;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{
    form_in_domain, key_wire_form_named, KeyIds, KeyIdsAtOpen, KeyIdsRefused,
};

#[cfg(feature = "shared-key-ids")]
use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
#[cfg(feature = "shared-key-ids")]
use crate::ffi::guarded;
#[cfg(feature = "shared-key-ids")]
use crate::prelude::*;
use crate::result::ZResult;
#[cfg(not(feature = "shared-key-ids"))]
use crate::result::WZ_EXT_ERR_UNSUPPORTED;
#[cfg(feature = "shared-key-ids")]
use crate::result::{WZ_EXT_ERR_POLICY_OFF, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};

/// The config behind a loaned handle, or `None` for a null one.
///
/// # Safety
/// `config` must be null or a live loaned config.
#[cfg(feature = "shared-key-ids")]
unsafe fn state_of<'c>(config: *mut z_loaned_config_t) -> Option<&'c mut ConfigState> {
    if config.is_null() || (*config).handle.is_null() {
        return None;
    }
    Some(&mut *((*config).handle as *mut ConfigState))
}

/// Hand `config` the key ids every node of the deployment shares: `count` entries, entry `i` the
/// id `ids[i]` and the key expression `keys[i]`, a NUL-terminated UTF-8 string. The session
/// `z_open` makes of the config holds the dictionary: it reads an id only the dictionary names,
/// declares no key expression under one of its ids, and names a key by one as its key-wire form
/// says. A `count` of 0 takes back a dictionary handed before. A dictionary handed here replaces
/// the one the config's document states (`wz_ext_config_document`, `wz/key-ids`); with none
/// handed here, the document's stands.
///
/// `Z_OK`; `Z_ERR_NULL` for a NULL config, a NULL array with entries, or a NULL key;
/// `Z_ERR_INVALID` for a key that is not UTF-8 or not a canonical key expression, an id of 0, and
/// an id or a key named twice; `Z_ERR_OVERFLOW` for more entries than the build's
/// `MAX_SHARED_KEY_IDS`. A refused call leaves the config as it was.
///
/// # Safety
/// `config` must be null or a live loaned config; with a `count` above 0, `ids` and `keys` must
/// each point to `count` readable elements, and every non-null key to a NUL-terminated string.
#[cfg(feature = "shared-key-ids")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_key_ids(
    config: *mut z_loaned_config_t,
    ids: *const u16,
    keys: *const *const c_char,
    count: usize,
) -> ZResult {
    guarded(|| {
        let Some(state) = state_of(config) else {
            return Z_ERR_NULL;
        };
        if count == 0 {
            state.key_ids.ids = None;
            return Z_OK;
        }
        if ids.is_null() || keys.is_null() {
            return Z_ERR_NULL;
        }
        let ids = core::slice::from_raw_parts(ids, count);
        let keys = core::slice::from_raw_parts(keys, count);
        let mut entries = Vec::with_capacity(count);
        for (id, key) in ids.iter().zip(keys) {
            if key.is_null() {
                return Z_ERR_NULL;
            }
            let Ok(text) = CStr::from_ptr(*key).to_str() else {
                return Z_ERR_INVALID;
            };
            entries.push((*id, text));
        }
        match KeyIds::new(entries) {
            Ok(dictionary) => {
                state.key_ids.ids = Some(alloc::sync::Arc::new(dictionary));
                Z_OK
            }
            Err(KeyIdsRefused::TooMany { .. }) => Z_ERR_OVERFLOW,
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// State the key-wire form of the link to `locator` apart from the session's: `form` is
/// `"declared"`, `"shared"` or `"literal"`, as the policy names its values, and `locator` an
/// endpoint the config dials or listens on, written as the config writes it. A link to an
/// endpoint no statement names takes the session's form; a second statement for one endpoint
/// replaces the first. The peer's zid is not known before the handshake, so a link is named by
/// its endpoint.
///
/// `Z_OK`; `Z_ERR_NULL` for a NULL config, locator or form; `Z_ERR_INVALID` for text that is not
/// UTF-8, an empty locator, or a form the policy has no value of; `WZ_EXT_ERR_POLICY_OFF` for a
/// form the build's domain of `key-wire-form` leaves out. A `shared` form needs the dictionary,
/// which `z_open` checks: a config that states one with no dictionary is refused there with
/// `Z_ERR_INVALID`. A refused call leaves the config as it was.
///
/// # Safety
/// `config` must be null or a live loaned config; `locator` and `form` must be null or
/// NUL-terminated strings.
#[cfg(feature = "shared-key-ids")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_key_wire_form_for(
    config: *mut z_loaned_config_t,
    locator: *const c_char,
    form: *const c_char,
) -> ZResult {
    guarded(|| {
        if locator.is_null() || form.is_null() {
            return Z_ERR_NULL;
        }
        let Some(state) = state_of(config) else {
            return Z_ERR_NULL;
        };
        let (Ok(locator), Ok(form)) = (
            CStr::from_ptr(locator).to_str(),
            CStr::from_ptr(form).to_str(),
        ) else {
            return Z_ERR_INVALID;
        };
        if locator.is_empty() {
            return Z_ERR_INVALID;
        }
        let Some(form) = key_wire_form_named(form) else {
            return Z_ERR_INVALID;
        };
        if !form_in_domain(form) {
            return WZ_EXT_ERR_POLICY_OFF;
        }
        state.key_ids.set_link(locator, form);
        Z_OK
    })
}

/// The key ids a session opened from `cfg` holds, or the code `z_open` answers. What the doors
/// state (`wz_ext_config_key_ids`, `wz_ext_config_key_wire_form_for`) goes over what the
/// `wz/key-ids` of the config's document states (`wz_ext_config_document`), the order the config's
/// policies are composed in: a dictionary handed through the door replaces the document's, and a
/// form stated for an endpoint replaces the document's for that endpoint. A `count` of 0 at the
/// door states no dictionary, so the document's stands.
///
/// `Z_ERR_INVALID` when the session's form, `policy`'s, or an endpoint's is `shared` and neither
/// states a dictionary.
#[cfg(feature = "shared-key-ids")]
pub(crate) fn admit_at_open(
    cfg: &ConfigState,
    policy: &SessionPolicy,
) -> Result<KeyIdsAtOpen, ZResult> {
    let at_open = cfg.key_ids.over(cfg.policies.document_key_ids()?);
    at_open
        .forms(policy.key_wire_form())
        .map_err(|_| Z_ERR_INVALID)?;
    Ok(at_open)
}

/// See the twin with the capability. A build without it names keys as upstream does and no other
/// way: any form but `declared` is [`WZ_EXT_ERR_UNSUPPORTED`]. A comparison the open makes in
/// line, and nothing at all where the build's domain of the policy is that one value.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
pub(crate) fn admit_at_open(cfg: &ConfigState, policy: &SessionPolicy) -> Result<(), ZResult> {
    let _ = cfg;
    if policy.key_wire_form() != KeyWireForm::Declared {
        return Err(WZ_EXT_ERR_UNSUPPORTED);
    }
    Ok(())
}

/// The key ids the cooperative engine's open is handed: those [`admit_at_open`] admitted, or
/// none in a build without the capability.
#[cfg(not(feature = "engine-tokio"))]
#[inline(always)]
pub(crate) fn coop_key_ids(
    #[cfg(feature = "shared-key-ids")] at_open: KeyIdsAtOpen,
) -> wz_capi_coop::OpenKeyIds {
    #[cfg(feature = "shared-key-ids")]
    {
        wz_capi_coop::OpenKeyIds::new(at_open)
    }
    #[cfg(not(feature = "shared-key-ids"))]
    {
        wz_capi_coop::OpenKeyIds::none()
    }
}

#[cfg(all(test, feature = "shared-key-ids"))]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::prelude::*;
    #[cfg(feature = "config-document")]
    use crate::result::Z_ERR_CONFIG_INVALID_VALUE;
    use wz_session_core::policy::KeyWireForm;

    /// `state` as the loaned config the doors are handed.
    fn loaned(state: &mut ConfigState) -> z_loaned_config_t {
        z_loaned_config_t {
            handle: state as *mut ConfigState as *mut core::ffi::c_void,
            _pad: [core::ptr::null_mut(); 3],
        }
    }

    fn policy_of(form: KeyWireForm) -> SessionPolicy {
        let mut policy = SessionPolicy::defaults();
        policy
            .select_key_wire_form(form)
            .expect("a host build allows every value of the key-wire form");
        policy
    }

    #[test]
    fn the_door_hands_the_config_its_dictionary_and_takes_it_back() {
        let mut state = ConfigState::default();
        let mut config = loaned(&mut state);
        let ids = [40u16, 41];
        let keys = [c"lab/rig".as_ptr(), c"lab/rig/alpha".as_ptr()];
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, ids.as_ptr(), keys.as_ptr(), 2) },
            Z_OK
        );
        let held = state
            .key_ids
            .ids
            .as_deref()
            .expect("the config holds the dictionary");
        assert_eq!(held.key_of(41), Some("lab/rig/alpha"));
        assert_eq!(held.id_of("lab/rig"), Some(40));

        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, core::ptr::null(), core::ptr::null(), 0) },
            Z_OK
        );
        assert!(state.key_ids.ids.is_none(), "a count of 0 takes it back");
    }

    #[test]
    fn the_door_refuses_each_fault_by_its_code_and_keeps_the_config() {
        let mut state = ConfigState::default();
        let ids = [40u16, 41];
        let good = [c"lab/rig".as_ptr(), c"lab/rig/alpha".as_ptr()];
        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, ids.as_ptr(), good.as_ptr(), 2) },
            Z_OK
        );
        let call = |state: &mut ConfigState, ids: &[u16], keys: &[*const c_char]| {
            let mut config = loaned(state);
            unsafe { wz_ext_config_key_ids(&mut config, ids.as_ptr(), keys.as_ptr(), ids.len()) }
        };
        assert_eq!(
            call(&mut state, &[0, 41], &good),
            Z_ERR_INVALID,
            "id 0 is the literal's"
        );
        assert_eq!(
            call(&mut state, &[40, 40], &good),
            Z_ERR_INVALID,
            "an id named twice"
        );
        assert_eq!(
            call(
                &mut state,
                &[40, 41],
                &[c"lab//rig".as_ptr(), c"lab/x".as_ptr()]
            ),
            Z_ERR_INVALID,
            "not a canonical key expression"
        );
        assert_eq!(
            call(
                &mut state,
                &[40, 41],
                &[c"lab/rig".as_ptr(), core::ptr::null()]
            ),
            Z_ERR_NULL
        );
        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, ids.as_ptr(), core::ptr::null(), 2) },
            Z_ERR_NULL
        );
        assert_eq!(
            unsafe { wz_ext_config_key_ids(core::ptr::null_mut(), ids.as_ptr(), good.as_ptr(), 2) },
            Z_ERR_NULL
        );
        assert_eq!(
            state
                .key_ids
                .ids
                .as_deref()
                .and_then(|held| held.key_of(41)),
            Some("lab/rig/alpha"),
            "a refused call leaves the dictionary handed before"
        );
    }

    #[test]
    fn the_form_door_states_an_endpoint_apart_and_refuses_by_code() {
        let mut state = ConfigState::default();
        let state_for = |state: &mut ConfigState, locator: *const c_char, form: *const c_char| {
            let mut config = loaned(state);
            unsafe { wz_ext_config_key_wire_form_for(&mut config, locator, form) }
        };
        let endpoint = c"tcp/192.0.2.7:7447".as_ptr();
        assert_eq!(state_for(&mut state, endpoint, c"literal".as_ptr()), Z_OK);
        assert_eq!(state_for(&mut state, endpoint, c"shared".as_ptr()), Z_OK);
        assert_eq!(
            state.key_ids.links,
            [("tcp/192.0.2.7:7447".to_owned(), KeyWireForm::Shared)],
            "a second statement for one endpoint replaces the first"
        );
        assert_eq!(
            state_for(&mut state, endpoint, c"Literal".as_ptr()),
            Z_ERR_INVALID,
            "a form the policy has no value of"
        );
        assert_eq!(
            state_for(&mut state, c"".as_ptr(), c"literal".as_ptr()),
            Z_ERR_INVALID,
            "an empty locator"
        );
        assert_eq!(
            state_for(&mut state, core::ptr::null(), c"literal".as_ptr()),
            Z_ERR_NULL
        );
        assert_eq!(
            state_for(&mut state, endpoint, core::ptr::null()),
            Z_ERR_NULL
        );
        assert_eq!(
            unsafe {
                wz_ext_config_key_wire_form_for(
                    core::ptr::null_mut(),
                    endpoint,
                    c"literal".as_ptr(),
                )
            },
            Z_ERR_NULL
        );
        assert_eq!(
            state.key_ids.links.len(),
            1,
            "a refused call leaves the config as it was"
        );
    }

    /// Whether a session opens from `state` under `form`, or the code `z_open` answers.
    fn admits(state: &ConfigState, form: KeyWireForm) -> Result<(), ZResult> {
        admit_at_open(state, &policy_of(form)).map(|_| ())
    }

    #[test]
    fn the_open_needs_a_dictionary_for_a_shared_form_only() {
        let mut state = ConfigState::default();
        assert_eq!(admits(&state, KeyWireForm::Shared), Err(Z_ERR_INVALID));
        for form in [KeyWireForm::Declared, KeyWireForm::Literal] {
            assert_eq!(admits(&state, form), Ok(()));
        }
        state
            .key_ids
            .set_link("tcp/192.0.2.7:7447", KeyWireForm::Shared);
        assert_eq!(
            admits(&state, KeyWireForm::Declared),
            Err(Z_ERR_INVALID),
            "an endpoint stated shared needs the dictionary too"
        );
        state.key_ids.ids = Some(alloc::sync::Arc::new(
            KeyIds::new([(40, "lab/rig")]).expect("valid"),
        ));
        assert_eq!(admits(&state, KeyWireForm::Shared), Ok(()));
        assert_eq!(admits(&state, KeyWireForm::Declared), Ok(()));
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Declared)),
            Ok(state.key_ids.clone()),
            "with no document the open holds what the doors stated"
        );
    }

    /// The document the tests of both C ABIs hand a config (the zenoh-c ABI's twin is in its
    /// `config` tests), and the key ids it states.
    #[cfg(feature = "config-document")]
    const DOCUMENT: &CStr = cr#"{ mode: "peer", wz: { "key-ids": {
        dictionary: [ { id: 40, key: "lab/rig" }, { id: 41, key: "lab/rig/alpha" } ],
        links: [ { locator: "tcp/192.0.2.7:7447", form: "literal" } ] } } }"#;

    #[cfg(feature = "config-document")]
    fn document_key_ids() -> KeyIdsAtOpen {
        KeyIdsAtOpen {
            ids: Some(alloc::sync::Arc::new(
                KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("valid"),
            )),
            links: alloc::vec![("tcp/192.0.2.7:7447".to_owned(), KeyWireForm::Literal)],
        }
    }

    #[cfg(feature = "config-document")]
    fn hand_document(state: &mut ConfigState, text: &CStr) -> ZResult {
        let mut config = loaned(state);
        // SAFETY: a live config and a live string.
        unsafe { crate::config_policy::wz_ext_config_document(&mut config, text.as_ptr()) }
    }

    #[cfg(feature = "config-document")]
    #[test]
    fn a_documents_key_ids_reach_the_open() {
        let mut state = ConfigState::default();
        assert_eq!(hand_document(&mut state, DOCUMENT), Z_OK);
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Shared)),
            Ok(document_key_ids()),
            "the document's dictionary makes the shared form admissible"
        );
    }

    #[cfg(feature = "config-document")]
    #[test]
    fn the_doors_statements_go_over_the_documents() {
        let mut state = ConfigState::default();
        assert_eq!(hand_document(&mut state, DOCUMENT), Z_OK);
        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe {
                wz_ext_config_key_wire_form_for(
                    &mut config,
                    c"tcp/192.0.2.7:7447".as_ptr(),
                    c"declared".as_ptr(),
                )
            },
            Z_OK
        );
        let at_open =
            admit_at_open(&state, &policy_of(KeyWireForm::Shared)).expect("the document's ids");
        assert_eq!(
            at_open.ids,
            document_key_ids().ids,
            "no dictionary through the door leaves the document's"
        );
        assert_eq!(
            at_open.links,
            [("tcp/192.0.2.7:7447".to_owned(), KeyWireForm::Declared)],
            "the door's form of an endpoint replaces the document's"
        );

        let ids = [7u16];
        let keys = [c"lab/other".as_ptr()];
        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, ids.as_ptr(), keys.as_ptr(), 1) },
            Z_OK
        );
        let at_open =
            admit_at_open(&state, &policy_of(KeyWireForm::Shared)).expect("the door's ids");
        let held = at_open.ids.as_deref().expect("a dictionary");
        assert_eq!(held.key_of(7), Some("lab/other"));
        assert_eq!(
            held.key_of(40),
            None,
            "the door's dictionary replaces the document's whole"
        );

        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, core::ptr::null(), core::ptr::null(), 0) },
            Z_OK
        );
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Shared))
                .expect("the document's ids")
                .ids,
            document_key_ids().ids,
            "a dictionary taken back at the door leaves the document's"
        );
    }

    /// One document, through this ABI's document door and through the reader of the zenoh
    /// document the zenoh-c ABI's open reads it with, gives equal key ids; the zenoh-c ABI's own
    /// test of the same text holds its open to the same value.
    #[cfg(all(
        feature = "config-document",
        feature = "engine-tokio",
        feature = "scout"
    ))]
    #[test]
    fn one_document_gives_the_key_ids_the_zenoh_reader_gives() {
        let mut state = ConfigState::default();
        assert_eq!(hand_document(&mut state, DOCUMENT), Z_OK);
        let through_door =
            admit_at_open(&state, &policy_of(KeyWireForm::Declared)).expect("admitted");
        let text = DOCUMENT.to_str().expect("UTF-8");
        let zenoh = wz_capi_core::runtime::zenoh_config::ZenohNodeConfig::from_json5(text)
            .expect("the zenoh reader takes the document");
        assert_eq!(zenoh.config.key_ids, through_door);
        assert_eq!(through_door, document_key_ids());
    }

    #[cfg(feature = "config-document")]
    #[test]
    fn a_document_whose_key_ids_are_refused_is_refused_at_the_door() {
        let mut state = ConfigState::default();
        assert_eq!(
            hand_document(
                &mut state,
                cr#"{ wz: { "key-ids": { dictionary: [ { id: 0, key: "lab/rig" } ] } } }"#
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            hand_document(
                &mut state,
                cr#"{ wz: { "key-ids": { links: [ { locator: "tcp/192.0.2.7:7447", form: "loud" } ] } } }"#
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Declared)),
            Ok(KeyIdsAtOpen::default()),
            "a refused document leaves the config as it was"
        );
    }
}
