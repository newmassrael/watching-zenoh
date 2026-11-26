// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A pico session listens on a `unixpipe/` endpoint: its `z_open` binds a listener that holds
//! many peers off one base path, as a `tcp/` one does, on either engine.
//!
//! `transport-link-unixpipe` is a link pico has none of, off by default, so the module is gated on
//! it; a cooperative build without it refuses the scheme (`unixpipe_link_refused`). The sample
//! that crosses such a link is `unixpipe_link_roundtrip`'s.

#![cfg(feature = "peer")]

#[cfg(all(feature = "transport-link-unixpipe", unix))]
mod multiclient {
    use std::ffi::CString;

    use wz_capi_pico::{
        z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
        z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
        Z_CONFIG_LISTEN_KEY, Z_OK,
    };

    /// `z_open(listen="unixpipe/..")` succeeds, and the listener holds the request FIFO its dials
    /// invite on while it is open.
    ///
    /// The base path is short on purpose: the cooperative engine holds a base path in a row of
    /// `MAX_LOCATOR_LEN` bytes less `unixpipe/` and the longest suffix of an end's FIFO.
    ///
    /// RED reproduction: on the cooperative engine, open the session over its sockets' links
    /// alone (drop `coop_host::with_unixpipe` from `open_on_coop` in `src/session.rs`), and the
    /// `unixpipe/` locator is refused as `Unsupported`; on the tokio engine, make
    /// `BoundListener::supports_mesh_multi_peer` answer `false` for `Unixpipe`, and
    /// `drive_listen` refuses the listener at bind.
    #[test]
    fn pico_z_open_accepts_a_unixpipe_listen_at_bind() {
        let _program = crate::programs::admit();
        let base = format!("/tmp/wzpl{}", std::process::id());
        let request = format!("{base}_uplink");
        // A node a crashed run left is made again by the listen, which tolerates one.
        let endpoint = CString::new(format!("unixpipe/{base}")).expect("nul-free path");
        unsafe {
            let mut cfg: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut cfg), Z_OK);
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut cfg),
                    Z_CONFIG_LISTEN_KEY,
                    endpoint.as_ptr()
                ),
                Z_OK
            );
            let mut session: z_owned_session_t = std::mem::zeroed();
            let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
            assert_eq!(rc, Z_OK, "pico z_open(listen=unixpipe/..) must bind");
            let held = std::fs::metadata(&request).is_ok();
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
            assert!(held, "the listener holds no request FIFO at {request}");
        }

        // The listener's teardown removes the request node; best-effort here.
        let _ = std::fs::remove_file(&request);
    }
}
