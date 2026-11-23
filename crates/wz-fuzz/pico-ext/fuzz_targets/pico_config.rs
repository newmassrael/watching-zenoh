// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that state a config's policies, limits and key ids from code and from a zenoh
//! document (`wz_ext_config_policy`, `_profile`, `_document`, `wz_ext_runtime_limits_document`,
//! `wz_ext_config_key_ids`, `_key_wire_form_for`), and the door that reads what an open of the
//! config would ask of the system (`wz_ext_config_device_requires`), over one config the fuzzer
//! states things to.
//!
//! Input: the operations, each a unit behind its two-byte little-endian length whose first byte
//! chooses it; the rest of the unit is the operation's text:
//!
//! | op % 8 | operation |
//! |--------|-----------|
//! | 0      | the rest is a zenoh JSON5 document handed to the config |
//! | 1      | a policy and its value (each to a NUL) are stated |
//! | 2      | a profile (to a NUL) is named |
//! | 3      | key ids: a count (modulo `MOST_KEY_IDS`), then each id (two bytes) and its key (to a NUL) |
//! | 4      | a link's key-wire form: a locator and a form (each to a NUL) |
//! | 5      | the rest is a document of the process's runtime limits |
//! | 6      | a locator (to a NUL) is inserted under the config key `op / 8` chooses |
//! | 7      | the config is asked what an open would ask of the system |
//!
//! Held beside not crashing: each door answers a code its documentation states; a statement made
//! again answers what it answered the first time, as the second replaces the first; what an open
//! would ask of the system is UTF-8 text; and a clone of the config answers that question as the
//! config does.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::config_policy::{
    wz_ext_config_document, wz_ext_config_policy, wz_ext_config_profile,
    wz_ext_runtime_limits_document,
};
use wz_capi_pico::device_requires::wz_ext_config_device_requires;
use wz_capi_pico::key_ids::{wz_ext_config_key_ids, wz_ext_config_key_wire_form_for};
use wz_capi_pico::result::{
    ZResult, WZ_EXT_ERR_POLICY_OFF, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID, Z_OK,
};
use wz_capi_pico::{
    z_config_clone, z_config_default, z_config_drop, z_config_loan, z_config_loan_mut,
    z_config_move, z_loaned_config_t, z_owned_config_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY,
};
use wz_fuzz_ingress_common::units;
use wz_fuzz_pico_ext::{empty_string, stated, take_string, Reader};

/// The most key ids one statement names: the door judges each entry alike.
const MOST_KEY_IDS: u8 = 9;

fuzz_target!(|data: &[u8]| {
    let mut config: z_owned_config_t = unsafe { core::mem::zeroed() };
    // SAFETY: `config` is writable.
    assert_eq!(
        unsafe { z_config_default(&mut config) },
        Z_OK,
        "z_config_default"
    );

    for unit in units(data) {
        let Some((&op, rest)) = unit.split_first() else {
            continue;
        };
        let loan = unsafe { z_config_loan_mut(&mut config) };
        let mut r = Reader::new(rest);
        match op % 8 {
            0 => {
                let text = r.c_field();
                twice(
                    "config_document",
                    &[Z_OK, Z_ERR_CONFIG_INVALID_VALUE],
                    || {
                        // SAFETY: `loan` is a live config; `text` is NUL-terminated.
                        unsafe { wz_ext_config_document(loan, text.as_ptr()) }
                    },
                );
            }
            1 => {
                let (policy, value) = (r.c_field(), r.c_field());
                twice("config_policy", &[Z_OK, Z_ERR_CONFIG_INVALID_VALUE], || {
                    // SAFETY: as above.
                    unsafe { wz_ext_config_policy(loan, policy.as_ptr(), value.as_ptr()) }
                });
            }
            2 => {
                let profile = r.c_field();
                twice(
                    "config_profile",
                    &[Z_OK, Z_ERR_CONFIG_INVALID_VALUE],
                    || {
                        // SAFETY: as above.
                        unsafe { wz_ext_config_profile(loan, profile.as_ptr()) }
                    },
                );
            }
            3 => key_ids(loan, &mut r),
            4 => {
                let (locator, form) = (r.c_field(), r.c_field());
                let rc = twice(
                    "config_key_wire_form_for",
                    &[Z_OK, Z_ERR_INVALID, WZ_EXT_ERR_POLICY_OFF],
                    // SAFETY: as above.
                    || unsafe {
                        wz_ext_config_key_wire_form_for(loan, locator.as_ptr(), form.as_ptr())
                    },
                );
                if locator.as_bytes().is_empty() {
                    assert_eq!(
                        rc, Z_ERR_INVALID,
                        "config_key_wire_form_for: an empty locator answered {rc}"
                    );
                }
            }
            5 => {
                let text = r.c_field();
                // No machine of the process takes its runtime's limits in this target, so the
                // door never answers that they were taken.
                twice(
                    "runtime_limits_document",
                    &[Z_OK, Z_ERR_CONFIG_INVALID_VALUE],
                    || {
                        // SAFETY: `text` is NUL-terminated.
                        unsafe { wz_ext_runtime_limits_document(text.as_ptr()) }
                    },
                );
            }
            6 => {
                let key = [Z_CONFIG_MODE_KEY, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY]
                    [usize::from(op / 8) % 3];
                let value = r.c_field();
                // The config's own keys are zenoh-pico's, held by its own tests; what is read
                // here is what the doors above make of a config that names locators.
                // SAFETY: as above.
                let _ = unsafe { zp_config_insert(loan, key, value.as_ptr()) };
            }
            _ => {
                let _ = requirement(unsafe { z_config_loan(&config) });
            }
        }
    }

    let mut copy: z_owned_config_t = unsafe { core::mem::zeroed() };
    // SAFETY: `copy` is writable; `config` is a live config.
    let rc = unsafe { z_config_clone(&mut copy, z_config_loan(&config)) };
    assert_eq!(rc, Z_OK, "z_config_clone: a live config answered {rc}");
    let (theirs, ours) = unsafe {
        (
            requirement(z_config_loan(&copy)),
            requirement(z_config_loan(&config)),
        )
    };
    assert_eq!(
        theirs, ours,
        "a clone of the config is asked of the system otherwise"
    );
    // SAFETY: two owned configs, each dropped once.
    unsafe {
        z_config_drop(z_config_move(&mut copy));
        z_config_drop(z_config_move(&mut config));
    }
});

/// Make a statement twice, holding the first answer to `codes` and the second to the first.
fn twice(door: &str, codes: &[ZResult], mut call: impl FnMut() -> ZResult) -> ZResult {
    let first = call();
    stated(door, first, codes);
    let second = call();
    assert_eq!(
        second, first,
        "{door}: made again, answered {second} after {first}"
    );
    first
}

fn key_ids(loan: *mut z_loaned_config_t, r: &mut Reader<'_>) {
    let count = usize::from(r.u8() % MOST_KEY_IDS);
    let mut ids = Vec::with_capacity(count);
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(r.u16());
        keys.push(r.c_field());
    }
    let pointers: Vec<_> = keys.iter().map(|key| key.as_ptr()).collect();
    let rc = twice("config_key_ids", &[Z_OK, Z_ERR_INVALID], || {
        // SAFETY: `ids` and `pointers` hold `count` entries each, every key NUL-terminated.
        unsafe { wz_ext_config_key_ids(loan, ids.as_ptr(), pointers.as_ptr(), count) }
    });
    if count == 0 {
        assert_eq!(
            rc, Z_OK,
            "config_key_ids: taking the dictionary back answered {rc}"
        );
    }
}

/// What an open of the config would ask of the system: the code and the text.
fn requirement(config: *const z_loaned_config_t) -> (ZResult, String) {
    let mut out = empty_string();
    // SAFETY: `config` is a live loaned config; `out` is writable.
    let rc = unsafe { wz_ext_config_device_requires(config, &mut out) };
    let text = unsafe { take_string("config_device_requires", &mut out) };
    if rc == Z_OK {
        assert!(
            text.starts_with('{') && text.ends_with('}'),
            "config_device_requires: an answer that is no JSON object: {text}"
        );
    }
    (rc, text)
}
