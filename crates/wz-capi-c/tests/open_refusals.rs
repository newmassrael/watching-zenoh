// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What `z_open` REFUSES, and with which code, held as a table.
//!
//! The decision from a config to an open (the role, the endpoints, the phases, the security) is
//! one value, `wz_capi_core::open_plan::OpenPlan`, and this ABI only maps its refusals onto
//! zenoh-c's two codes. This file pins that mapping row by row, through the exported `z_*`
//! symbols as a C program calls them, so a refusal that moves to the other code, or stops being a
//! refusal, fails here and not in a user's program.
//!
//! Every row is a refusal: the open returns before a socket is bound or a link dialled, so the
//! table needs no network and no port.

use std::ffi::CString;

use wz_capi_c::abi::{z_moved_config_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::{Z_EINVAL, Z_ENETWORK, Z_OK};
use wz_capi_c::session::z_open;

/// Open with `entries` inserted as json5 values, returning the result code.
unsafe fn open_code(entries: &[(&str, &str)]) -> i8 {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(*value).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK,
            "the config door took {entries:?}"
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    )
}

/// The key the config stores multicast scouting under, turned off in every row so that "nothing
/// to dial" is a refusal and not a scouting client.
const NO_SCOUTING: (&str, &str) = ("scouting/multicast/enabled", "false");

/// A config as the keys inserted into it, in order.
type Entries<'a> = &'a [(&'a str, &'a str)];

/// One row of the table: what it is, the config, and the code its open answers.
type Row<'a> = (&'a str, Entries<'a>, i8);

#[test]
fn a_config_the_open_cannot_carry_out_is_refused_with_its_code() {
    // A group no unicast link can dial: zenoh's runtime refuses it in a peer's or router's connect
    // list, and a client that has nothing else to dial has nothing.
    let group = r#"["udp/224.0.0.224:7446#iface=lo"]"#;
    let rows: &[Row] = &[
        (
            "a client with nothing to dial and no scouting",
            &[NO_SCOUTING, ("mode", "\"client\"")],
            Z_ENETWORK,
        ),
        (
            "a client that only listens",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("listen/endpoints", r#"["tcp/127.0.0.1:0"]"#),
            ],
            // Without the peer role the listener is refused first, as a config error.
            if cfg!(feature = "peer") {
                Z_ENETWORK
            } else {
                Z_EINVAL
            },
        ),
        (
            "a client whose only endpoint is a multicast group",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("connect/endpoints", group),
            ],
            Z_ENETWORK,
        ),
        (
            "a peer told to dial a multicast group",
            &[
                NO_SCOUTING,
                ("mode", "\"peer\""),
                ("connect/endpoints", group),
            ],
            if cfg!(feature = "peer") {
                Z_ENETWORK
            } else {
                Z_EINVAL
            },
        ),
        (
            "a router told to dial a multicast group",
            &[
                NO_SCOUTING,
                ("mode", "\"router\""),
                ("connect/endpoints", group),
            ],
            if cfg!(feature = "peer") {
                Z_ENETWORK
            } else {
                Z_EINVAL
            },
        ),
        (
            "qos together with lowlatency",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("connect/endpoints", r#"["tcp/127.0.0.1:1"]"#),
                ("transport/unicast/lowlatency", "true"),
            ],
            Z_ENETWORK,
        ),
        (
            "a user with no password",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("connect/endpoints", r#"["tcp/127.0.0.1:1"]"#),
                ("transport/auth/usrpwd/user", "\"someone\""),
            ],
            Z_EINVAL,
        ),
        (
            "a pubkey identity that cannot be loaded",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("connect/endpoints", r#"["tcp/127.0.0.1:1"]"#),
                (
                    "transport/auth/pubkey/public_key_file",
                    r#""/nonexistent/wz-pub.pem""#,
                ),
                (
                    "transport/auth/pubkey/private_key_file",
                    r#""/nonexistent/wz-priv.pem""#,
                ),
            ],
            Z_EINVAL,
        ),
        (
            "an access control that names a rule that does not exist",
            &[
                NO_SCOUTING,
                ("mode", "\"client\""),
                ("connect/endpoints", r#"["tcp/127.0.0.1:1"]"#),
                (
                    "access_control",
                    r#"{ enabled: true, default_permission: "deny",
                         rules: [], subjects: [],
                         policies: [ { rules: ["missing"], subjects: ["missing"] } ] }"#,
                ),
            ],
            Z_EINVAL,
        ),
    ];
    for (label, entries, expected) in rows {
        // SAFETY: a fresh zeroed owned config and session per row, as the C API is called.
        let code = unsafe { open_code(entries) };
        assert_eq!(code, *expected, "{label}");
    }
}
