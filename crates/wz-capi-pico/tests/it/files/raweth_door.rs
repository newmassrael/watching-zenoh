// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 911 — `z_open` with a `reth/` listen endpoint opens zenoh-pico's raweth
//! transport: a group over raw Ethernet on the endpoint's interface.
//!
//! The socket needs `CAP_NET_RAW`. Without it the raw socket is refused, and pico's listen of
//! the endpoint answers `_Z_ERR_TRANSPORT_OPEN_FAILED` (`vendor/zenoh-pico/src/link/link.c` @
//! `ret = _Z_ERR_TRANSPORT_OPEN_FAILED;`), its raweth link having been taken and having failed
//! to open; a build without the transport answers `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN`
//! instead, no link taking the scheme. So the code says whether the door took the endpoint
//! even where the socket cannot open, and with the capability the session opens.
#![cfg(all(feature = "raweth-transport", target_os = "linux"))]

use std::ffi::CString;

use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_move, zp_config_insert, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// pico `_Z_ERR_TRANSPORT_OPEN_FAILED` (`utils/result.h`).
const TRANSPORT_OPEN_FAILED: i8 = -102;

/// Whether this process may open a raw packet socket on `lo`.
fn may_open_a_raw_socket() -> bool {
    wz_runtime_tokio::raweth_socket::AfPacketSocket::open("lo").is_ok()
}

#[test]
fn a_reth_listen_opens_the_raweth_transport_or_fails_as_its_link_does() {
    let endpoint = CString::new("reth/02:00:00:00:00:01#iface=lo").unwrap();
    // SAFETY: the C ABI's own calls on values this test owns, in the order a C program makes.
    let rc = unsafe {
        let mut config: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut config), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut config),
                Z_CONFIG_LISTEN_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        let rc = z_open(&mut session, z_config_move(&mut config), std::ptr::null());
        if rc == Z_OK {
            z_session_drop(z_session_move(&mut session));
        }
        rc
    };
    if may_open_a_raw_socket() {
        assert_eq!(rc, Z_OK, "with CAP_NET_RAW the raweth session opens");
    } else {
        assert_eq!(
            rc, TRANSPORT_OPEN_FAILED,
            "without CAP_NET_RAW the raweth link is taken and fails to open, as pico's does"
        );
    }
}
