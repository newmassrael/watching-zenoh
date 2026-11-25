// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_config_device_requires`: what pico's open of a config would ask of the operating system
//! (docs/target-build-contract.md T9), one JSON object with the manifest's keys.
//!
//! A door wz has and zenoh-pico does not, so it is `wz_ext_*` and declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers), and part of the unstable surface: a
//! build without `device-requires` (the zenoh-pico preset, the size-measured client builds)
//! carries none of it, whether or not it has pico's unstable API.
//!
//! It reads the config as [`z_open`](crate::session::z_open) does (`open_config`, the TLS
//! material, pico's group rule, each endpoint by the grammar of the engine's open) into the facts
//! of `wz_session_core::facilities`, and refuses what `z_open` refuses, with the same code.
//! pico's open makes one attempt at its one locator and fails when it cannot dial or bind it, and
//! scouts only when neither locator is given, which is then the only way to a node.

use wz_session_core::facilities::{device_requires_of, EndpointReading, ReadFacts, Scouting};
#[cfg(not(feature = "peer"))]
use wz_session_core::WhatAmI;

use crate::abi::{z_loaned_config_t, z_owned_string_t};
use crate::config::ConfigState;
use crate::prelude::*;
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
        let stored = crate::bytes::store_owned_string(out_requirement, text.as_bytes());
        // The requirement is its text, so without room for it there is none; a refusal's code
        // is the answer whether its reason found room or not.
        if code == Z_OK {
            stored
        } else {
            code
        }
    })
}

/// A refusal of the open: its code and the reason the door names.
type Refused = (ZResult, &'static str);

/// What the open does with an endpoint, which decides the grammar it is read by.
#[derive(Clone, Copy)]
enum Role {
    /// An endpoint dialled.
    Dial,
    /// A unicast endpoint listened on.
    Listen,
    /// A multicast group joined.
    Group,
}

/// The requirement of pico's open of `cfg`, or the code and reason `z_open` refuses it with.
fn requirement_of(cfg: &ConfigState) -> Result<String, Refused> {
    // The TLS material is resolved before anything else, as `z_open` resolves it: a key whose file
    // cannot be read or whose inline value cannot be decoded refuses the open. A build without a
    // TLS backend reads no certificate file, whatever its engine.
    #[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
    if let Err(code) = crate::session::resolve_tls_config(cfg) {
        return Err((
            code,
            "the open refuses this config: a TLS key's material cannot be read",
        ));
    }
    let files = tls_files_named(cfg);
    let OpenConfig {
        connect,
        listen,
        dial_whatami,
        ..
    } = open_config(cfg).map_err(|code| {
        (
            code,
            "the open refuses this config: its mode is neither client nor peer",
        )
    })?;
    crate::session::resolve_snapshots(&cfg.policies).map_err(|code| {
        (
            code,
            "the open refuses this config: the build refuses a policy it states",
        )
    })?;
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
    // beside it opens nothing (pico adds a peer to a unicast transport only). Each engine reads it
    // with `is_group_endpoint`; a build with neither the tokio engine nor `peer` refused every
    // listener above.
    #[cfg(any(feature = "engine-tokio", feature = "peer"))]
    let joins_a_group = listen.is_some_and(crate::session::is_group_endpoint);
    #[cfg(not(any(feature = "engine-tokio", feature = "peer")))]
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
    let (dials, listens, groups): (Vec<&str>, Vec<&str>, Vec<&str>) = match listen {
        Some(group) if joins_a_group => (Vec::new(), Vec::new(), vec![group]),
        listen => (
            connect.into_iter().collect(),
            listen.into_iter().collect(),
            Vec::new(),
        ),
    };
    // The cooperative engine's open judges every unicast endpoint as pico reads it before it
    // opens anything, the listener first (`open_request`), and reads what that judgement keeps
    // when it opens each link.
    #[cfg(not(feature = "engine-tokio"))]
    for endpoint in listens.iter().chain(&dials) {
        crate::endpoint::checked_endpoint(endpoint).map_err(|code| {
            (
                code,
                "the open refuses this config: pico's reading of an endpoint refuses it",
            )
        })?;
    }
    let listen = read_all(&listens, Role::Listen)?;
    let groups = read_all(&groups, Role::Group)?;
    let connect = read_all(&dials, Role::Dial)?;
    Ok(device_requires_of(&ReadFacts {
        connect,
        dial_must_succeed: true,
        listen,
        groups,
        bind_must_succeed: true,
        scouting,
        reads_files: !files.is_empty(),
        reads_calendar: false,
    })
    .to_json())
}

/// Each of `endpoints` read, in `role`, as the build's open reads it; the first the open refuses
/// refuses the config.
fn read_all(endpoints: &[&str], role: Role) -> Result<Vec<EndpointReading>, Refused> {
    endpoints
        .iter()
        .map(|endpoint| read(endpoint, role))
        .collect()
}

/// The tokio engine's runtime reads every endpoint with the grammar of every scheme the tree
/// knows, and a scheme it does not carry fails the link it opens and not the reading, so the door
/// reads with that grammar and refuses nothing here.
#[cfg(feature = "engine-tokio")]
fn read(endpoint: &str, _role: Role) -> Result<EndpointReading, Refused> {
    Ok(wz_session_core::facilities::read_any_endpoint(endpoint))
}

/// The cooperative engine's reading of one endpoint, which pico's reading already admitted
/// (`requirement_of`): a unicast endpoint is the text that reading keeps (`with_engine_text`,
/// the one the engine is handed), read by the engine's own grammar (`locator_text`), which
/// dials and listens on an address and refuses a host name, a config or metadata part and a port
/// it cannot use (a scheme the build has no link for that reading refused already); `z_open`
/// answers that refusal as a link it could not open. A group is read by the grammar its host joiner reads it with.
#[cfg(not(feature = "engine-tokio"))]
fn read(endpoint: &str, role: Role) -> Result<EndpointReading, Refused> {
    use wz_capi_coop::locator_text::{parse_listen_locator, parse_locator};
    use wz_capi_coop::LinkProto;
    use wz_session_core::facilities::Endpoint;
    use wz_session_core::locator::Proto;
    let parsed = match role {
        Role::Dial => crate::endpoint::with_engine_text(endpoint, parse_locator),
        Role::Listen => crate::endpoint::with_engine_text(endpoint, parse_listen_locator),
        Role::Group => return read_group(endpoint),
    };
    let locator = parsed.map_err(|_| {
        (
            crate::result::Z_ERR_TRANSPORT_OPEN_FAILED,
            "the open refuses this config: the engine reads no address it can open in an endpoint",
        )
    })?;
    // A link of another kind, a serial line or a pair of named FIFOs, is a request no facility of
    // the vocabulary names: the vocabulary's own reading says so, in its words.
    let Some(ip) = locator.as_ip() else {
        return Ok(wz_session_core::facilities::read_any_endpoint(endpoint));
    };
    let proto = match ip.proto {
        LinkProto::Udp => Proto::Udp,
        LinkProto::Tcp => Proto::Tcp,
        LinkProto::Tls => Proto::Tls,
    };
    Ok(Ok(Endpoint::Ip {
        proto,
        named: false,
    }))
}

/// A group as the cooperative engine reads it before its host joiner is asked
/// (`wz_session_core::group_locator::parse_group_locator`): a UDP multicast group, or a group the
/// open cannot join.
#[cfg(all(not(feature = "engine-tokio"), feature = "multicast-transport"))]
fn read_group(endpoint: &str) -> Result<EndpointReading, Refused> {
    use wz_session_core::facilities::Endpoint;
    use wz_session_core::locator::Proto;
    match wz_session_core::group_locator::parse_group_locator(endpoint) {
        Ok(group) if group.udp().is_some() => Ok(Ok(Endpoint::Ip {
            proto: Proto::Udp,
            named: false,
        })),
        _ => Err((
            crate::result::Z_ERR_TRANSPORT_OPEN_FAILED,
            "the open refuses this config: its group is not one the host joins",
        )),
    }
}

/// A build without the multicast transport has no group to read; `requirement_of` refused one
/// with this code before reading.
#[cfg(all(not(feature = "engine-tokio"), not(feature = "multicast-transport")))]
fn read_group(_endpoint: &str) -> Result<EndpointReading, Refused> {
    Err((
        crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        "the open refuses this config: a group is a transport this build does not have",
    ))
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

    /// The tokio engine's runtime resolves a host name, so the door asks for the resolver.
    #[cfg(feature = "engine-tokio")]
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

    /// A config whose policies the build refuses is refused with the open's code and reason. Only
    /// a build with the policy doors holds a statement to refuse.
    #[cfg(feature = "config-policy")]
    #[test]
    fn a_config_whose_policies_the_open_refuses_is_refused() {
        // A build whose every value the resolution admits holds no refused statement.
        let Some(refused) = crate::config_policy::PolicyStatements::refused_by_the_resolution()
        else {
            return;
        };
        let mut cfg = config(&[(Z_CONFIG_CONNECT_KEY, "tcp/192.0.2.1:7447")]);
        cfg.policies = refused;
        let (code, reason) = requirement_of(&cfg).unwrap_err();
        assert_eq!(code, crate::result::Z_ERR_CONFIG_INVALID_VALUE);
        assert!(reason.contains("policy"), "{reason}");
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

    /// Either engine joins the group a listen endpoint with an interface names.
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn a_listened_group_requires_the_membership() {
        use crate::config::Z_CONFIG_LISTEN_KEY;
        let got = requirement_of(&config(&[(
            Z_CONFIG_LISTEN_KEY,
            "udp/224.0.0.224:7447#iface=lo",
        )]))
        .unwrap();
        assert_eq!(
            got,
            "{\"requires\": [\"entropy\", \"multicast\", \"sockets-udp\", \"threads\"], \
             \"may_require\": [\"interface-list\"], \"unknown\": []}"
        );
    }

    /// The cooperative engine has no resolver: its open refuses a host name as a link it could not
    /// open, and so does the door.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn a_host_named_locator_is_refused_as_the_open_refuses_it() {
        let (code, reason) = requirement_of(&config(&[(
            Z_CONFIG_CONNECT_KEY,
            "tcp/router.example:7447",
        )]))
        .unwrap_err();
        assert_eq!(code, crate::result::Z_ERR_TRANSPORT_OPEN_FAILED);
        assert!(reason.contains("address"), "{reason}");
    }

    /// A listen endpoint the cooperative engine reads is answered with its socket.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_listener_on_an_address_requires_its_socket() {
        use crate::config::Z_CONFIG_LISTEN_KEY;
        let got = requirement_of(&config(&[(Z_CONFIG_LISTEN_KEY, "tcp/127.0.0.1:0")])).unwrap();
        assert!(
            got.starts_with("{\"requires\": [\"entropy\", \"sockets-tcp\", \"threads\"]"),
            "{got}"
        );
    }
}

/// The door against `z_open` on the same config, on the cooperative engine: each config the open
/// refuses before it opens a link the door refuses with the open's own code, and a config the open
/// opens the door answers.
#[cfg(all(test, not(feature = "engine-tokio")))]
mod against_the_open {
    use super::wz_ext_config_device_requires;
    use crate::abi::{z_owned_config_t, z_owned_string_t};
    use crate::bytes::{z_string_drop, z_string_move};
    use crate::config::{
        z_config_default, z_config_drop, z_config_loan, z_config_loan_mut, z_config_move,
        zp_config_insert, Z_CONFIG_CONNECT_KEY,
    };
    use crate::result::{ZResult, Z_OK};
    use crate::session::{z_open, z_owned_session_t, z_session_drop, z_session_move};
    use alloc::ffi::CString;

    /// A config made through the C doors, holding `entries`.
    ///
    /// # Safety
    /// The caller lets go of the config it is handed.
    unsafe fn config(entries: &[(u8, &str)]) -> z_owned_config_t {
        let mut config = z_owned_config_t::null_value();
        assert_eq!(z_config_default(&mut config), Z_OK);
        for (key, value) in entries {
            let value = CString::new(*value).expect("no NUL");
            assert_eq!(
                zp_config_insert(z_config_loan_mut(&mut config), *key, value.as_ptr()),
                Z_OK
            );
        }
        config
    }

    /// The code the door answers for a config holding `entries`.
    fn door(entries: &[(u8, &str)]) -> ZResult {
        // SAFETY: every pointer is to a live owned value of this frame, each let go of once.
        unsafe {
            let mut config = config(entries);
            let mut out = z_owned_string_t::null_value();
            let code = wz_ext_config_device_requires(z_config_loan(&config), &mut out);
            z_string_drop(z_string_move(&mut out));
            z_config_drop(z_config_move(&mut config));
            code
        }
    }

    /// The code `z_open` answers for a config holding `entries`, the session it opened let go of.
    fn open(entries: &[(u8, &str)]) -> ZResult {
        // SAFETY: every pointer is to a live owned value of this frame; the open consumes the
        // config, and dropping what it left is dropping nothing.
        unsafe {
            let mut config = config(entries);
            let mut session = core::mem::MaybeUninit::<z_owned_session_t>::uninit();
            crate::session::z_internal_session_null(session.as_mut_ptr());
            let mut session = session.assume_init();
            let code = z_open(&mut session, z_config_move(&mut config), core::ptr::null());
            if code == Z_OK {
                z_session_drop(z_session_move(&mut session));
            }
            z_config_drop(z_config_move(&mut config));
            code
        }
    }

    /// A dial the open refuses before any link: a scheme the engine has no link for, a host name
    /// it has no resolver for, a port it cannot dial, and a config pair pico's reading refuses.
    #[test]
    fn a_dial_the_open_refuses_is_refused_with_its_code() {
        for endpoint in [
            "quic/127.0.0.1:7447",
            "tcp/router.example:7447",
            "udp/127.0.0.1:0",
            "tcp/127.0.0.1:7447#tout",
        ] {
            let entries = [(Z_CONFIG_CONNECT_KEY, endpoint)];
            let opened = open(&entries);
            assert_ne!(opened, Z_OK, "z_open of {endpoint} is refused");
            assert_eq!(
                door(&entries),
                opened,
                "the door answers {endpoint} as z_open does"
            );
        }
    }

    /// A listener the open opens is answered, and one it refuses is refused with its code.
    #[cfg(feature = "peer")]
    #[test]
    fn a_listener_is_answered_as_the_open_takes_it() {
        use crate::config::Z_CONFIG_LISTEN_KEY;
        let taken = [(Z_CONFIG_LISTEN_KEY, "tcp/127.0.0.1:0")];
        assert_eq!(open(&taken), Z_OK);
        assert_eq!(door(&taken), Z_OK);
        let refused = [(Z_CONFIG_LISTEN_KEY, "quic/127.0.0.1:0")];
        let opened = open(&refused);
        assert_ne!(opened, Z_OK);
        assert_eq!(door(&refused), opened);
    }
}
