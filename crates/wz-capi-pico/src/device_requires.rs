// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_config_device_requires`: what pico's open of a config would ask of the operating system
//! (docs/target-build-contract.md T9), one JSON object with the manifest's keys.
//!
//! A door wz has and zenoh-pico does not, so it is `wz_ext_*` and declared in `wz_ext.h`
//! (docs/build-configuration.md, decision C10), and part of the unstable surface: a build without
//! `unstable-api` (the size-measured client builds) carries none of it.
//!
//! It reads the config as [`z_open`](crate::session::z_open) does ([`open_config`], the TLS
//! material, pico's group rule) into the engine-neutral facts of `wz_session_core::facilities`, and
//! refuses what `z_open` refuses, with the same code. pico's open makes one attempt at its one
//! locator and fails when it cannot dial or bind it, and scouts only when neither locator is
//! given, which is then the only way to a node.

use wz_session_core::facilities::{device_requires, OpenFacts, Scouting};
#[cfg(not(feature = "peer"))]
use wz_session_core::WhatAmI;

use crate::abi::{z_loaned_config_t, z_owned_string_t};
use crate::config::ConfigState;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};
use crate::session::{open_config, tls_files_named, OpenConfig};

/// What an open of `config` would ask of the operating system, as one JSON object:
/// `{"requires": [...], "may_require": [...] or null, "unknown": [...]}`, the keys and the
/// facility words of the target-build manifest. A config `z_open` would refuse returns that
/// refusal's code with the reason in the string. The config is read, not consumed.
///
/// # Safety
/// `config` must be null or a live loaned config; `out_requirement` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_device_requires(
    config: *const z_loaned_config_t,
    out_requirement: *mut z_owned_string_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if out_requirement.is_null() {
            return Z_ERR_NULL;
        }
        *out_requirement = z_owned_string_t::null_value();
        if config.is_null() || (*config).handle.is_null() {
            return Z_ERR_NULL;
        }
        let cfg = &*((*config).handle as *const ConfigState);
        let (code, text) = match requirement_of(cfg) {
            Ok(json) => (Z_OK, json),
            Err((code, reason)) => (code, reason.to_owned()),
        };
        crate::bytes::store_owned_string(out_requirement, text.as_bytes());
        code
    })
}

/// The requirement of pico's open of `cfg`, or the code and reason `z_open` refuses it with.
fn requirement_of(cfg: &ConfigState) -> Result<String, (ZResult, &'static str)> {
    // The TLS material is resolved before anything else, as `z_open` resolves it: a key whose file
    // cannot be read or whose inline value cannot be decoded refuses the open.
    #[cfg(feature = "engine-tokio")]
    let files = match crate::session::resolve_tls_config(cfg) {
        Ok(_) => tls_files_named(cfg),
        Err(code) => {
            return Err((
                code,
                "the open refuses this config: a TLS key's material cannot be read",
            ))
        }
    };
    #[cfg(not(feature = "engine-tokio"))]
    let files = {
        let _ = tls_files_named;
        Vec::<String>::new()
    };
    let OpenConfig {
        connect,
        listen,
        dial_whatami,
    } = open_config(cfg);
    #[cfg(not(feature = "peer"))]
    if listen.is_some() || dial_whatami != WhatAmI::Client {
        return Err((
            crate::result::Z_ERR_INVALID,
            "the open refuses this config: a listener or the peer mode is a role this build does not have",
        ));
    }
    #[cfg(feature = "peer")]
    let _ = dial_whatami;
    // A listen endpoint that names a group is the session's one transport, and a connect locator
    // beside it opens nothing (pico adds a peer to a unicast transport only).
    #[cfg(feature = "engine-tokio")]
    let joins_a_group = listen
        .as_deref()
        .is_some_and(crate::session::is_group_endpoint);
    #[cfg(not(feature = "engine-tokio"))]
    let joins_a_group = false;
    #[cfg(not(feature = "multicast-transport"))]
    if joins_a_group {
        return Err((
            crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
            "the open refuses this config: a group is a transport this build does not have",
        ));
    }
    let scouting =
        match (&connect, &listen) {
            (None, None) if cfg!(feature = "scout") => Scouting::OnlyWay,
            (None, None) => return Err((
                crate::result::Z_ERR_SCOUT_NO_RESULTS,
                "the open refuses this config: it names no locator and the build does not scout",
            )),
            _ => Scouting::Off,
        };
    let (connect, listen, groups): (Vec<String>, Vec<String>, Vec<String>) = match listen {
        Some(group) if joins_a_group => (Vec::new(), Vec::new(), vec![group]),
        listen => (
            connect.into_iter().collect(),
            listen.into_iter().collect(),
            Vec::new(),
        ),
    };
    Ok(device_requires(&OpenFacts {
        connect: &connect,
        dial_must_succeed: true,
        listen: &listen,
        groups: groups.iter().map(String::as_str).collect(),
        bind_must_succeed: true,
        scouting,
        reads_files: !files.is_empty(),
        reads_calendar: false,
    })
    .to_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Z_CONFIG_CONNECT_KEY;

    fn config(entries: &[(u8, &str)]) -> ConfigState {
        let mut cfg = ConfigState::default();
        for (key, value) in entries {
            cfg.insert(*key, value);
        }
        cfg
    }

    #[test]
    fn a_client_dialling_an_address_requires_its_socket() {
        let got = requirement_of(&config(&[(Z_CONFIG_CONNECT_KEY, "tcp/192.0.2.1:7447")])).unwrap();
        assert_eq!(
            got,
            "{\"requires\": [\"entropy\", \"sockets-tcp\", \"threads\"], \
             \"may_require\": [\"interface-list\"], \"unknown\": []}"
        );
    }

    #[test]
    fn a_host_named_locator_requires_the_resolver() {
        let got = requirement_of(&config(&[(
            Z_CONFIG_CONNECT_KEY,
            "tcp/router.example:7447",
        )]))
        .unwrap();
        assert!(
            got.contains("\"name-resolution\", \"sockets-tcp\""),
            "{got}"
        );
    }

    #[test]
    fn no_locator_is_a_scout_or_the_open_refusal() {
        let got = requirement_of(&config(&[]));
        if cfg!(feature = "scout") {
            let got = got.unwrap();
            assert!(
                got.starts_with("{\"requires\": [\"entropy\", \"multicast\", \"sockets-udp\""),
                "{got}"
            );
        } else {
            assert_eq!(got.unwrap_err().0, crate::result::Z_ERR_SCOUT_NO_RESULTS);
        }
    }

    #[cfg(all(feature = "engine-tokio", feature = "multicast-transport"))]
    #[test]
    fn a_listened_group_requires_the_membership() {
        use crate::config::Z_CONFIG_LISTEN_KEY;
        let got = requirement_of(&config(&[(
            Z_CONFIG_LISTEN_KEY,
            "udp/224.0.0.224:7447#iface=lo",
        )]))
        .unwrap();
        assert!(got.contains("\"multicast\""), "{got}");
        assert!(got.contains("\"interface-list\""), "{got}");
    }
}
