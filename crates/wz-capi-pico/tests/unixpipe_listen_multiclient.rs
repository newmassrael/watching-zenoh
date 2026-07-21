// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Multi-client unixpipe listen capability, pico half (§5.27, R311y392).
//!
//! Replaces the retired `unixpipe_listen_failfast` discriminator (R311y391). That
//! test asserted pico's `z_open(listen=unixpipe/..)` was REJECTED at bind, because
//! the R311y380 single-connection unixpipe acceptor could not feed the mesh accept
//! loop. R311y392 made the unixpipe acceptor MULTI-CLIENT (a zenoh-compatible
//! invitation handshake + per-connection dedicated sub-pipe pair), so
//! `BoundListener::supports_mesh_multi_peer()` flipped `true` and `drive_listen`'s
//! bind-time guard no longer rejects it — pico can now genuinely LISTEN over
//! unixpipe, holding N inbound peers off one listener like tcp.
//!
//! `transport-link-unixpipe` is a SUPERSET feature, not a zenoh-pico-native link
//! (real pico has no unixpipe), and it is off-default — so the whole module is
//! gated on it; without it `bind_endpoint("unixpipe/..")` fails at the
//! accept-backend gate. This is the ONLY lane that opens a real
//! `BoundListener::Unixpipe` through the pico C ABI.

#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
mod multiclient {
    use std::ffi::CString;

    use wz_capi_pico::{
        z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
        z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
        Z_CONFIG_LISTEN_KEY, Z_OK,
    };

    /// `z_open(listen="unixpipe/..")` now SUCCEEDS: the multi-client acceptor makes
    /// a unixpipe listener mesh-capable, so `drive_listen`'s bind-time guard
    /// (consulting `BoundListener::supports_mesh_multi_peer`) no longer rejects it
    /// and `z_open` returns `Z_OK` — a listening pico session over unixpipe.
    ///
    /// RED reproduction (proof this binds to the flipped guard, not the vehicle):
    /// RESTORE the old rejection — make `BoundListener::supports_mesh_multi_peer`
    /// return `false` for `Unixpipe` again, or re-add a hardcoded unixpipe reject in
    /// `drive_listen` -> `tx.send(false)` -> `z_open` returns `Z_ERR_GENERIC` -> this
    /// `assert_eq!(rc, Z_OK)` fails. With the feature ON,
    /// `bind_endpoint("unixpipe/..")` genuinely binds a `BoundListener::Unixpipe`
    /// (the multi-client acceptor), so a success here is the guard's flipped
    /// verdict, not a bind fluke.
    #[test]
    fn pico_z_open_accepts_a_unixpipe_listen_at_bind() {
        let base = std::env::temp_dir()
            .join(format!("wz-capi-pico-multiclient-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Pre-clean any stale FIFO node from a crashed prior run (no-flaky).
        let _ = std::fs::remove_file(format!("{base}_uplink"));

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
            assert_eq!(
                rc, Z_OK,
                "pico z_open(listen=unixpipe/..) must SUCCEED: the multi-client \
                 acceptor makes a unixpipe listener mesh-capable (R311y392)"
            );
            // Close the listening session so its background accept loop thread does
            // not leak past the test.
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }

        // The acceptor's teardown unlinks the base request node; best-effort here.
        let _ = std::fs::remove_file(format!("{base}_uplink"));
    }
}
