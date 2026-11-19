// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key ids every node of a deployment shares, from C: `wz_ext_config_key_ids` hands a config
//! the dictionary, and the open hands it to the engine with the session's key-wire form.
//!
//! A door wz has and zenoh-pico does not, so it is `wz_ext_*`, declared in `wz_ext.h`, and part of
//! the unstable surface: the `shared-key-ids` capability implies `unstable-api`. The dictionary and
//! its rules are `wz_session_core::shared_key_ids`'s, and the cooperative engine holds it
//! (`wz_capi_coop::CoopEngine::open_with_key_ids`).
//!
//! What every build has here is the open's judgement of the key-wire form ([`admit_at_open`]):
//! the tokio engine names keys as upstream does and holds no dictionary, so a session on it that
//! states a dictionary or a form other than `declared` is refused, and so is any form other than
//! `declared` in a build without the capability. A refusal is the code `z_open` answers, before
//! anything is dialled.

#[cfg(feature = "shared-key-ids")]
use core::ffi::{c_char, CStr};

use wz_session_core::policy::{KeyWireForm, SessionPolicy};
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIds, KeyIdsRefused};

#[cfg(feature = "shared-key-ids")]
use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
#[cfg(feature = "shared-key-ids")]
use crate::ffi::guarded;
#[cfg(feature = "shared-key-ids")]
use crate::prelude::*;
use crate::result::ZResult;
#[cfg(any(feature = "engine-tokio", not(feature = "shared-key-ids")))]
use crate::result::WZ_EXT_ERR_UNSUPPORTED;
#[cfg(feature = "shared-key-ids")]
use crate::result::{Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};

/// Hand `config` the key ids every node of the deployment shares: `count` entries, entry `i` the
/// id `ids[i]` and the key expression `keys[i]`, a NUL-terminated UTF-8 string. The session
/// `z_open` makes of the config holds the dictionary: it reads an id only the dictionary names,
/// declares no key expression under one of its ids, and names a key by one as its key-wire form
/// says. A `count` of 0 takes back a dictionary handed before.
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
        if config.is_null() || (*config).handle.is_null() {
            return Z_ERR_NULL;
        }
        let state = &mut *((*config).handle as *mut ConfigState);
        if count == 0 {
            state.key_ids = None;
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
                state.key_ids = Some(alloc::sync::Arc::new(dictionary));
                Z_OK
            }
            Err(KeyIdsRefused::TooMany { .. }) => Z_ERR_OVERFLOW,
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Whether a session may open from `cfg` under `policy`'s key-wire form on the engine this build
/// opens on, or the code `z_open` answers.
///
/// The tokio engine holds no dictionary: a dictionary stated, or a form other than `declared`, is
/// [`WZ_EXT_ERR_UNSUPPORTED`].
#[cfg(feature = "engine-tokio")]
pub(crate) fn admit_at_open(cfg: &ConfigState, policy: &SessionPolicy) -> Result<(), ZResult> {
    #[cfg(feature = "shared-key-ids")]
    let stated = cfg.key_ids.is_some();
    #[cfg(not(feature = "shared-key-ids"))]
    let stated = {
        let _ = cfg;
        false
    };
    if stated || policy.key_wire_form() != KeyWireForm::Declared {
        return Err(WZ_EXT_ERR_UNSUPPORTED);
    }
    Ok(())
}

/// See the tokio engine's twin. On the cooperative engine with the capability, `shared` needs a
/// dictionary, which is `Z_ERR_INVALID` when the config states none; the other two forms open.
#[cfg(all(not(feature = "engine-tokio"), feature = "shared-key-ids"))]
pub(crate) fn admit_at_open(cfg: &ConfigState, policy: &SessionPolicy) -> Result<(), ZResult> {
    match (policy.key_wire_form(), &cfg.key_ids) {
        (KeyWireForm::Shared, None) => Err(Z_ERR_INVALID),
        _ => Ok(()),
    }
}

/// See the tokio engine's twin. A build without the capability names keys as upstream does and
/// no other way: any form but `declared` is [`WZ_EXT_ERR_UNSUPPORTED`].
#[cfg(all(not(feature = "engine-tokio"), not(feature = "shared-key-ids")))]
pub(crate) fn admit_at_open(cfg: &ConfigState, policy: &SessionPolicy) -> Result<(), ZResult> {
    let _ = cfg;
    if policy.key_wire_form() != KeyWireForm::Declared {
        return Err(WZ_EXT_ERR_UNSUPPORTED);
    }
    Ok(())
}

/// The key ids `cfg` hands the cooperative engine's open: the dictionary the config states, or
/// none.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn coop_key_ids(cfg: &ConfigState) -> wz_capi_coop::OpenKeyIds {
    #[cfg(feature = "shared-key-ids")]
    {
        cfg.key_ids.clone().map_or_else(
            wz_capi_coop::OpenKeyIds::none,
            wz_capi_coop::OpenKeyIds::shared,
        )
    }
    #[cfg(not(feature = "shared-key-ids"))]
    {
        let _ = cfg;
        wz_capi_coop::OpenKeyIds::none()
    }
}

#[cfg(all(test, feature = "shared-key-ids"))]
mod tests {
    use super::*;

    /// `state` as the loaned config the door is handed.
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
            .as_deref()
            .expect("the config holds the dictionary");
        assert_eq!(held.key_of(41), Some("lab/rig/alpha"));
        assert_eq!(held.id_of("lab/rig"), Some(40));

        let mut config = loaned(&mut state);
        assert_eq!(
            unsafe { wz_ext_config_key_ids(&mut config, core::ptr::null(), core::ptr::null(), 0) },
            Z_OK
        );
        assert!(state.key_ids.is_none(), "a count of 0 takes it back");
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
            state.key_ids.as_deref().and_then(|held| held.key_of(41)),
            Some("lab/rig/alpha"),
            "a refused call leaves the dictionary handed before"
        );
    }

    #[cfg(feature = "engine-tokio")]
    #[test]
    fn the_tokio_engine_refuses_a_dictionary_and_every_form_but_declared() {
        let mut state = ConfigState::default();
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Declared)),
            Ok(())
        );
        for form in [KeyWireForm::Shared, KeyWireForm::Literal] {
            assert_eq!(
                admit_at_open(&state, &policy_of(form)),
                Err(WZ_EXT_ERR_UNSUPPORTED)
            );
        }
        state.key_ids = Some(alloc::sync::Arc::new(
            KeyIds::new([(40, "lab/rig")]).expect("valid"),
        ));
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Declared)),
            Err(WZ_EXT_ERR_UNSUPPORTED),
            "a dictionary the engine would not hold"
        );
    }

    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn the_cooperative_engine_needs_a_dictionary_for_the_shared_form_only() {
        let mut state = ConfigState::default();
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Shared)),
            Err(Z_ERR_INVALID)
        );
        for form in [KeyWireForm::Declared, KeyWireForm::Literal] {
            assert_eq!(admit_at_open(&state, &policy_of(form)), Ok(()));
        }
        state.key_ids = Some(alloc::sync::Arc::new(
            KeyIds::new([(40, "lab/rig")]).expect("valid"),
        ));
        assert_eq!(
            admit_at_open(&state, &policy_of(KeyWireForm::Shared)),
            Ok(())
        );
    }
}
